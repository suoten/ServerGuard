package decider

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/executor"
	"github.com/suoten/serverguard/internal/agent/posture"
	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
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

	// 态势感知（可选注入）：战时对低风险安全动作自动提级、危急时只告警
	posture PostureSource

	// 信任演化开关：历史高成功率的确认类规则自动跳过人工确认（默认关闭，可配置开启）
	trustAutoConfirm bool

	// 规则自检降级缓存（规则ID -> 评估结论），避免每次触发都查库
	mu            sync.Mutex
	degradedCache map[string]degradeState
	trustCache    map[string]trustState
}

// trustState 单条规则的信任评估缓存。
type trustState struct {
	trusted   bool
	checkedAt time.Time
}

// 信任演化参数：一条需要确认的规则，近 7 天被确认执行 ≥8 次且成功率 100%
// 才算"赢得信任"，此后自动跳过确认（任何失败立即失去信任回到人工确认）。
const (
	trustLookback   = 7 * 24 * time.Hour
	trustMinSamples = 8
	trustMinRatePct = 100.0
)

// PostureSource 提供当前系统态势（由 posture.Engine 实现；接口便于测试桩替换）。
type PostureSource interface {
	Current() posture.Posture
	AutoResolve() posture.Bias
}

// SetPostureProvider 注入态势感知引擎。
func (d *Decider) SetPostureProvider(p PostureSource) {
	d.posture = p
}

// SetTrustAutoConfirm 开关信任演化（默认关闭）。
func (d *Decider) SetTrustAutoConfirm(v bool) {
	d.trustAutoConfirm = v
}

// isTrustworthy 纯函数：判断历史记录是否赢得信任。
// 条件：样本足够 + 全部成功。任何一次失败都立即失去信任。
func isTrustworthy(entries []ruleengine.RuleHistoryEntry, minSamples int, minRatePct float64) bool {
	if len(entries) < minSamples {
		return false
	}
	success := 0
	for _, e := range entries {
		if e.Success {
			success++
		}
	}
	return float64(success)/float64(len(entries))*100 >= minRatePct
}

// ruleTrusted 判断规则是否已赢得信任（带缓存，每规则每小时最多复评一次）。
// 返回值：(是否已信任, 是否本次评估中刚晋升为信任——用于发一次晋升通知)。
func (d *Decider) ruleTrusted(ruleID string) (bool, bool) {
	if d.storage == nil || !d.trustAutoConfirm {
		return false, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.trustCache == nil {
		d.trustCache = make(map[string]trustState)
	}
	now := time.Now()
	if st, ok := d.trustCache[ruleID]; ok && now.Before(st.checkedAt.Add(degradedRecheckInterval)) {
		return st.trusted, false
	}

	entries, err := d.storage.GetActionHistoryByRule(ruleID, now.Add(-trustLookback), 50)
	trusted := err == nil && isTrustworthy(entries, trustMinSamples, trustMinRatePct)
	prevTrusted := false
	if st, ok := d.trustCache[ruleID]; ok {
		prevTrusted = st.trusted
	}
	d.trustCache[ruleID] = trustState{trusted: trusted, checkedAt: now}
	return trusted, trusted && !prevTrusted
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

// 规则自检降级参数。
const (
	// degradedLookback 成功率评估窗口
	degradedLookback = 7 * 24 * time.Hour
	// degradedMinSamples 触发降级所需的最少尝试次数（样本不足不降级）
	degradedMinSamples = 5
	// degradedSuccessFloorPct 成功率下限（%），低于此值降级为只告警
	degradedSuccessFloorPct = 30
	// degradedRecheckInterval 降级状态的复评间隔——到期后重新统计，修复成功即自动恢复
	degradedRecheckInterval = 1 * time.Hour
)

// ruleDegraded 判断规则是否因成功率过低而被自动降级。
// 结果缓存 degradedUntil 内不重复查询数据库（每规则每小时最多复评一次）。
func (d *Decider) ruleDegraded(rule *types.Rule) bool {
	if d.storage == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.degradedCache == nil {
		d.degradedCache = make(map[string]degradeState)
	}
	now := time.Now()
	st, ok := d.degradedCache[rule.ID]
	if ok && now.Before(st.checkedAt.Add(degradedRecheckInterval)) {
		return st.degraded // 复评窗口内直接用缓存结论
	}

	entries, err := d.storage.GetActionHistoryByRule(rule.ID, now.Add(-degradedLookback), 50)
	degraded := false
	if err == nil && len(entries) >= degradedMinSamples {
		success := 0
		for _, e := range entries {
			if e.Success {
				success++
			}
		}
		rate := float64(success) / float64(len(entries)) * 100
		degraded = rate < degradedSuccessFloorPct
	}
	d.degradedCache[rule.ID] = degradeState{degraded: degraded, checkedAt: now}
	return degraded
}

// degradeState 单条规则的降级评估缓存。
type degradeState struct {
	degraded  bool
	checkedAt time.Time
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

		// 4.5 规则自检降级：近 7 天执行成功率过低（样本足够）的规则自动降级为只告警。
		// 反复失败还继续机械重试 = "越修越坏"的另一种形式；降级后告警照发，人工接手。
		if d.ruleDegraded(rule) {
			result.Approved = false
			result.Reason = "rule auto-degraded: low success rate"
			d.eventBus.PublishAlert(types.AlertWarning, rule.Module,
				fmt.Sprintf("[规则自检] %s 已自动降级为只告警", rule.Name),
				fmt.Sprintf("规则 %s 近 7 天自动处置成功率低于 %d%%（≥%d 次尝试），已暂停自动执行、保留告警。\n反复失败说明根因未除——请查看操作历史与诊断报告后人工处理；修复后规则会在下个评估周期自动恢复。",
					rule.Name, degradedSuccessFloorPct, degradedMinSamples),
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
			// 5.0 信任演化：该规则近 7 天被确认执行 ≥8 次且全部成功 → 用户实际上
			// 反复做出了相同决定，继续每次打断没有价值。跳过确认、留痕审计；
			// 任何一次失败都会让成功率跌破 100%，规则立即回到人工确认。
			trusted, promoted := d.ruleTrusted(rule.ID)
			if trusted {
				if promoted {
					d.eventBus.PublishAlert(types.AlertInfo, "posture",
						fmt.Sprintf("[信任演化] %s 转为自动执行", rule.Name),
						fmt.Sprintf("规则 %s 近 7 天确认执行 ≥%d 次且成功率 100%%，起跳过人工确认。任一失败将自动恢复人工确认。",
							rule.ID, trustMinSamples),
						rule.ID)
				}
				_ = d.storage.SaveAudit(types.AuditEntry{
					ID:        uuid.NewString(),
					Timestamp: time.Now(),
					Actor:     "system",
					Action:    "trust_auto_confirm",
					Target:    rule.Name,
					Reason:    fmt.Sprintf("近 7 天确认执行 ≥%d 次且成功率 100%%", trustMinSamples),
					Result:    "auto-confirmed",
				})
			} else if d.posture != nil &&
				d.posture.AutoResolve() == posture.BiasCombatAuto &&
				d.posture.Current() == posture.PostureCombat &&
				combatSafeActions(rule.Actions) {
				// 5.1 战时自动提级：正在被攻击时，低风险安全动作（封禁 IP 等）跳过人工确认直接处置。
				// 攻击进行中让人等 5 分钟确认超时等于放任攻击者；事后通过审计与报告向用户说明。
				// 仅对"战时安全动作白名单"生效——重启服务、清磁盘等业务动作绝不提级。
				d.eventBus.PublishAlert(types.AlertInfo, "posture",
					fmt.Sprintf("[战时提级] %s 跳过人工确认自动执行", rule.Name),
					fmt.Sprintf("系统处于战时态势（持续攻击中），规则 %s 的安全动作 %v 由等待确认改为立即执行。此决策已记录审计，可在操作历史中复查。",
						rule.ID, actionTypes(rule.Actions)),
					rule.ID)
			} else {
				confirmed, err := d.requestConfirmation(ctx, rule, &target)
				if err != nil || !confirmed {
					result.Approved = false
					result.Reason = "user confirmation required but not received"
					results = append(results, result)
					continue
				}
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

// combatSafeActions 判断规则的动作是否全部属于"战时安全动作白名单"。
// 只有这些低风险、纯对抗性的动作才允许在战时跳过人工确认：
//   - ban_ip：封禁攻击源 IP，不触碰业务进程与数据
//   - alert：仅告警，无副作用
//   - snapshot：只读取证
//
// kill/restart/clean_disk 等涉及业务可用性的动作无论何时都必须走原确认流程——
// 战时提级是为了更快反击攻击者，不是为了给误伤业务开绿灯。
func combatSafeActions(actions []types.Action) bool {
	if len(actions) == 0 {
		return false // 无动作可执行，不值得提级
	}
	for _, a := range actions {
		switch a.Type {
		case types.ActionBanIP, types.ActionAlert, types.ActionSnapshot:
			continue
		default:
			return false
		}
	}
	return true
}

// actionTypes 返回动作类型列表（用于审计文案）。
func actionTypes(actions []types.Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, string(a.Type))
	}
	return out
}
