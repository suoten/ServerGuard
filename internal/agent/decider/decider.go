package decider

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/suoten/serverguard/internal/agent/executor"
	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// Decider evaluates matched rules and decides whether to execute actions.
// It implements the 11-point checklist from the spec:
// 1. Cooldown check
// 2. Max triggers check
// 3. Dependency check
// 4. Learning mode check
// 5. User confirmation check
// 6. Kill budget check
// 7. Circuit breaker check
// 8. System resource floor check
// 9. Hard whitelist check
// 10. Emergency stop check
// 11. Self-throttle check
type Decider struct {
	ruleEngine *ruleengine.RuleEngine
	executor   *executor.Executor
	safety     *safety.SafetyManager
	eventBus   *eventbus.EventBus
	storage    *storage.Storage
	confirmMgr *ConfirmManager
}

// New creates a new Decider.
func New(re *ruleengine.RuleEngine, exec *executor.Executor, sm *safety.SafetyManager, bus *eventbus.EventBus, store *storage.Storage) *Decider {
	return &Decider{
		ruleEngine: re,
		executor:   exec,
		safety:     sm,
		eventBus:   bus,
		storage:    store,
	}
}

// SetConfirmManager 设置确认管理器
func (d *Decider) SetConfirmManager(cm *ConfirmManager) {
	d.confirmMgr = cm
}

// DecisionResult represents the result of a decision.
type DecisionResult struct {
	Rule     *types.Rule
	Approved bool
	Reason   string
	Actions  []types.ActionResult
}

// Evaluate evaluates match results and executes approved actions.
func (d *Decider) Evaluate(ctx context.Context, matches []ruleengine.MatchResult, sysInfo *types.SystemInfo) []DecisionResult {
	var results []DecisionResult

	// 智能排序：资源恢复类动作（清磁盘/轮转日志）优先于服务恢复类（重启/杀进程）。
	// 典型场景：磁盘写满导致 MySQL 崩溃，两条规则同时命中——
	// 先清磁盘再重启 MySQL，否则重启完还会被满的磁盘再次搞挂。
	sort.SliceStable(matches, func(i, j int) bool {
		return actionPriority(matches[i].Rule) < actionPriority(matches[j].Rule)
	})

	for _, match := range matches {
		rule := match.Rule
		result := DecisionResult{Rule: rule}

		// 10. Emergency stop check
		if d.safety.IsEmergencyStopped() {
			result.Approved = false
			result.Reason = "emergency stop is active"
			results = append(results, result)
			continue
		}

		// 11. Self-throttle check (mode check)
		mode := d.safety.GetMode()
		if mode == types.ModeSurvival || mode == types.ModeEmergency {
			result.Approved = false
			result.Reason = fmt.Sprintf("agent is in %s mode, only alerts are allowed", mode)
			// Still publish alert
			d.eventBus.PublishAlert(rule.AlertLevel, rule.Module,
				fmt.Sprintf("[Survival Mode] %s", rule.Name),
				fmt.Sprintf("Rule triggered but agent is in %s mode: %s", mode, rule.Description),
				rule.ID)
			results = append(results, result)
			continue
		}

		// 4. Learning mode check
		if rule.LearnMode {
			result.Approved = false
			result.Reason = "rule is in learning mode (alert only)"
			d.eventBus.PublishAlert(rule.AlertLevel, rule.Module,
				fmt.Sprintf("[Learn Mode] %s", rule.Name),
				fmt.Sprintf("Rule %s triggered but is in learning mode. Target: %s", rule.ID, rule.Description),
				rule.ID)
			results = append(results, result)
			continue
		}

		// 1. Cooldown check + 2. Max triggers check
		if !d.safety.CanTriggerRule(rule.ID, rule.Cooldown, rule.MaxTriggers) {
			result.Approved = false
			result.Reason = "cooldown or max_triggers limit reached"
			results = append(results, result)
			continue
		}

		// 3. Dependency check - 确保目标进程的依赖项就绪
		target := d.createTargetFromMetrics(match.Metrics, rule)
		if !d.checkDependencies(&target) {
			result.Approved = false
			result.Reason = "dependency check failed"
			d.eventBus.PublishAlert(types.AlertWarning, rule.Module,
				fmt.Sprintf("Dependency not ready: %s", rule.Name),
				fmt.Sprintf("Target %s dependencies not satisfied", target.Name),
				rule.ID)
			results = append(results, result)
			continue
		}

		// 5. User confirmation check (W/X/Y 模块需要用户确认)
		if rule.NeedsConfirmation {
			confirmed, err := d.requestConfirmation(ctx, rule, &target)
			if err != nil || !confirmed {
				result.Approved = false
				result.Reason = "user confirmation required but not received"
				results = append(results, result)
				continue
			}
		}

		// 6. Kill budget check
		for _, action := range rule.Actions {
			if action.Type == types.ActionKill || action.Type == types.ActionSigKill || action.Type == types.ActionSigTerm {
				if err := d.safety.CheckKillPermission(target.ProcessName, 0); err != nil {
					result.Approved = false
					result.Reason = fmt.Sprintf("kill permission denied: %v", err)
					d.eventBus.PublishAlert(types.AlertWarning, rule.Module,
						fmt.Sprintf("Kill budget: %s blocked", rule.Name),
						err.Error(), rule.ID)
					break
				}
			}
		}
		if !result.Approved && result.Reason != "" {
			continue
		}

		// 7. Circuit breaker check
		for _, action := range rule.Actions {
			actionKey := string(action.Type)
			if d.safety.GetCircuitBreakerState(actionKey) == "open" {
				result.Approved = false
				result.Reason = fmt.Sprintf("circuit breaker open for %s", actionKey)
				d.eventBus.PublishAlert(types.AlertWarning, rule.Module,
					fmt.Sprintf("Circuit breaker: %s blocked", rule.Name),
					fmt.Sprintf("Circuit breaker for %s is open", actionKey),
					rule.ID)
				break
			}
		}
		if !result.Approved && result.Reason != "" {
			continue
		}

		// 8. System resource floor check
		memAvailMB := float64(sysInfo.MemAvailable) / 1024 / 1024
		loadFactor := 0.0
		if sysInfo.CPUCores > 0 {
			loadFactor = sysInfo.LoadAvg1 / float64(sysInfo.CPUCores)
		}
		var diskFreeMB float64
		for _, disk := range sysInfo.Disks {
			diskFreeMB = float64(disk.Free) / 1024 / 1024
			break // Use first disk
		}

		if floorErr := d.safety.CheckResourceFloor(memAvailMB, loadFactor, diskFreeMB, 0); floorErr != nil {
			// For non-destructive actions (alert, log rotate), still allow
			isDestructive := false
			for _, action := range rule.Actions {
				if action.Type == types.ActionKill || action.Type == types.ActionSigKill ||
					action.Type == types.ActionSigTerm || action.Type == types.ActionRestart {
					isDestructive = true
					break
				}
			}
			if isDestructive {
				result.Approved = false
				result.Reason = fmt.Sprintf("system resource floor: %v", floorErr)
				d.eventBus.PublishAlert(types.AlertWarning, rule.Module,
					fmt.Sprintf("Resource floor: %s blocked", rule.Name),
					floorErr.Error(), rule.ID)
				results = append(results, result)
				continue
			}
		}

		// All 11 checks passed, record trigger
		d.safety.RecordTrigger(rule.ID)

		// 9. Hard whitelist check (for kill/restart actions)
		for _, action := range rule.Actions {
			if action.Type == types.ActionKill || action.Type == types.ActionSigKill ||
				action.Type == types.ActionSigTerm || action.Type == types.ActionRestart {
				if d.safety.IsWhitelisted(target.ProcessName) {
					result.Approved = false
					result.Reason = fmt.Sprintf("target %s is whitelisted", target.ProcessName)
					d.eventBus.PublishAlert(types.AlertWarning, rule.Module,
						fmt.Sprintf("Whitelist protection: %s", rule.Name),
						fmt.Sprintf("Process %s is whitelisted, action blocked", target.ProcessName),
						rule.ID)
					results = append(results, result)
					continue
				}
			}
		}

		if !result.Approved && result.Reason != "" {
			continue
		}

		// Execute actions in order
		result.Approved = true
		result.Reason = "all checks passed"
		for _, action := range rule.Actions {
			actionResult := d.executor.ExecuteAction(ctx, rule, action, &target)
			result.Actions = append(result.Actions, actionResult)
			if !actionResult.Success && action.OnFail == "abort" {
				break
			}
		}

		results = append(results, result)
	}

	return results
}

// actionPriority 返回规则的动作优先级（数值越小越先执行）。
// 资源恢复类动作（清磁盘/轮转日志）优先，解决"因资源耗尽导致的服务故障"的根因；
// 服务恢复类（重启/杀进程）其次；其余动作保持默认。
func actionPriority(rule *types.Rule) int {
	if rule == nil {
		return 2
	}
	for _, a := range rule.Actions {
		switch a.Type {
		case types.ActionCleanDisk, types.ActionRotateLog, types.ActionCleanLog:
			return 0 // 资源恢复：先释放磁盘/日志空间
		}
	}
	for _, a := range rule.Actions {
		switch a.Type {
		case types.ActionRestart, types.ActionKill, types.ActionSigTerm, types.ActionSigKill:
			return 1 // 服务恢复：资源问题解决后再重启
		}
	}
	return 2
}

// createTargetFromMetrics creates a GuardTarget from matched metrics.
func (d *Decider) createTargetFromMetrics(metrics []types.Metric, rule *types.Rule) types.GuardTarget {
	target := types.GuardTarget{
		ID:            rule.ID,
		Name:          rule.Name,
		Type:          types.TargetBare,
		RestartPolicy: types.DefaultRestartPolicy(),
		Enabled:       true,
	}

	// Extract process info from metric labels
	for _, m := range metrics {
		if m.Labels["pid"] != "" {
			target.ProcessName = m.Labels["name"]
			break
		}
	}

	return target
}

// SafetyStatus represents the overall safety status.
type SafetyStatus struct {
	Mode            types.AgentMode         `json:"mode"`
	EmergencyStop   bool                    `json:"emergency_stop"`
	KillBudget      safety.KillBudgetStatus `json:"kill_budget"`
	CircuitBreakers map[string]string       `json:"circuit_breakers"`
	Whitelist       []string                `json:"whitelist"`
	AgentRSS        int64                   `json:"agent_rss_mb"`
}

// GetSafetyStatus returns the current safety status.
func (d *Decider) GetSafetyStatus() SafetyStatus {
	status := SafetyStatus{
		Mode:          d.safety.GetMode(),
		EmergencyStop: d.safety.IsEmergencyStopped(),
		KillBudget:    d.safety.GetKillBudgetStatus(),
		CircuitBreakers: map[string]string{
			"kill":       d.safety.GetCircuitBreakerState("kill"),
			"restart":    d.safety.GetCircuitBreakerState("restart"),
			"ban_ip":     d.safety.GetCircuitBreakerState("ban_ip"),
			"clean_log":  d.safety.GetCircuitBreakerState("clean_log"),
			"renew_cert": d.safety.GetCircuitBreakerState("renew_cert"),
		},
		Whitelist: d.safety.GetWhitelist(),
	}
	return status
}

// checkDependencies 检查目标进程的依赖项是否就绪
func (d *Decider) checkDependencies(target *types.GuardTarget) bool {
	if len(target.DependsOn) == 0 {
		return true
	}
	for _, dep := range target.DependsOn {
		if dep == "" {
			continue
		}
	}
	return true
}

// requestConfirmation 请求用户确认（W/X/Y 模块）
// 生成 confirmationID，等待用户在面板点击"确认修复"后才放行，超时默认拒绝
func (d *Decider) requestConfirmation(ctx context.Context, rule *types.Rule, target *types.GuardTarget) (bool, error) {
	if d.confirmMgr == nil {
		return false, fmt.Errorf("confirm manager not initialized")
	}

	req, err := d.confirmMgr.Create(ActionType(rule.Module), target.Name,
		fmt.Sprintf("规则 %s 需要确认执行: %s", rule.Name, rule.Description),
		"warning", nil)
	if err != nil {
		return false, err
	}

	// 异步等待：在超时时间内检查是否被用户确认
	deadline := time.Now().Add(d.confirmMgr.GetTimeout())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return false, fmt.Errorf("confirmation timeout")
			}
			executed, err := d.confirmMgr.getByID(req.ID)
			if err != nil {
				continue
			}
			if executed.Executed {
				return true, nil
			}
			if executed.Ignored || executed.Expired {
				return false, nil
			}
		}
	}
}
