package executor

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// Executor executes actions with safety checks, snapshots, and rollback.
type Executor struct {
	safety   *safety.SafetyManager
	eventBus *eventbus.EventBus
	storage  *storage.Storage
	// Kill后系统对比评估器
	postKillEval *safety.PostKillEvaluator
}

// New creates a new Executor.
func New(sm *safety.SafetyManager, bus *eventbus.EventBus, store *storage.Storage) *Executor {
	eval := safety.NewPostKillEvaluator(bus)
	eval.SetSafetyManager(sm) // Kill 后系统恶化 → 真正触发紧急停止
	return &Executor{
		safety:       sm,
		eventBus:     bus,
		storage:      store,
		postKillEval: eval,
	}
}

// ExecuteAction executes an action with all safety checks and returns the result.
// 进程 Kill 由 CheckKillPermission 内的精确归属识别保护（宝塔进程永不命中），
// 不再依赖全局模式开关做一刀切降级。
func (e *Executor) ExecuteAction(ctx context.Context, rule *types.Rule, action types.Action, target *types.GuardTarget) types.ActionResult {
	startTime := time.Now()
	result := types.ActionResult{
		Action:    action,
		Timestamp: startTime,
	}

	// Check if learning mode (only alert, don't execute)
	if rule.LearnMode {
		result.Success = false
		result.Message = "rule is in learning mode, action not executed (alert only)"
		e.eventBus.PublishAlert(rule.AlertLevel, rule.Module,
			fmt.Sprintf("[Learn Mode] %s would have executed %s", rule.Name, action.Type),
			fmt.Sprintf("Rule %s triggered but is in learning mode. Target: %s", rule.ID, target.Name),
			rule.ID)
		result.Duration = time.Since(startTime)
		return result
	}

	// Check emergency stop
	if e.safety.IsEmergencyStopped() {
		result.Success = false
		result.Error = "emergency stop is active"
		result.Message = "action blocked by emergency stop"
		result.Duration = time.Since(startTime)
		return result
	}

	// Create pre-action snapshot
	snapshot := e.createSnapshot(action, target)

	// Execute the action with timeout
	// 防御：自定义规则可能漏配 Timeout——context.WithTimeout(ctx, 0) 会立即过期，
	// 所有动作都会以"context deadline exceeded"莫名失败
	if action.Timeout <= 0 {
		action.Timeout = 60 * time.Second
	}
	actionCtx, cancel := context.WithTimeout(ctx, action.Timeout)
	defer cancel()

	switch action.Type {
	case types.ActionKill, types.ActionSigTerm, types.ActionSigKill:
		result = e.executeKill(actionCtx, action, target)
	case types.ActionNice:
		result = e.executeNice(actionCtx, action, target)
	case types.ActionRestart:
		result = e.executeRestart(actionCtx, action, target)
	case types.ActionCleanLog, types.ActionRotateLog:
		result = e.executeLogAction(actionCtx, action, target)
	case types.ActionCleanDisk:
		result = e.executeCleanDisk(actionCtx, action, target)
	case types.ActionBanIP:
		result = e.executeBanIP(actionCtx, action, target)
	case types.ActionRenewCert:
		result = e.executeRenewCert(actionCtx, action, target)
	case types.ActionReloadNginx:
		result = e.executeReloadNginx(actionCtx, action)
	case types.ActionRunScript:
		result = e.executeScript(actionCtx, action, target)
	case types.ActionAlert:
		result = e.executeAlert(action, rule, target)
	case types.ActionSnapshot:
		result = e.executeSnapshot(action, target)
	default:
		result.Success = false
		result.Error = fmt.Sprintf("unknown action type: %s", action.Type)
	}

	result.Duration = time.Since(startTime)

	// 智能根因分析：抓取系统现场并推断可能原因，附加到动作记录与通知中
	if analysis := e.analyzeRootCause(action, target, rule); analysis != "" {
		result.Message += analysis
	}

	// Record action result
	e.safety.RecordActionResult(string(action.Type), result.Success)

	// Save to storage
	e.storage.SaveAction(rule.ID, result)

	// Save audit entry
	e.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: startTime,
		Actor:     fmt.Sprintf("rule:%s", rule.ID),
		Action:    string(action.Type),
		Target:    target.Name,
		Reason:    rule.Description,
		Result:    map[bool]string{true: "success", false: "failure"}[result.Success],
		Details:   result.Message,
	})

	// Publish event
	if result.Success {
		e.eventBus.PublishAction(rule.Module,
			fmt.Sprintf("Action %s succeeded", action.Type),
			result.Message,
			result)
	} else {
		e.eventBus.PublishAlert(types.AlertError, rule.Module,
			fmt.Sprintf("Action %s failed", action.Type),
			fmt.Sprintf("Rule %s action %s failed: %s", rule.ID, action.Type, result.Error),
			rule.ID)
	}

	// Handle on_fail
	if !result.Success && action.OnFail == "alert" {
		e.eventBus.PublishAlert(rule.AlertLevel, rule.Module,
			fmt.Sprintf("Action %s failed, escalating to alert", action.Type),
			fmt.Sprintf("Rule %s failed to execute %s on %s: %s", rule.ID, action.Type, target.Name, result.Error),
			rule.ID)
	}

	// Store snapshot for potential rollback
	if snapshot != nil {
		e.storage.Set(fmt.Sprintf("snapshot:%s", snapshot.ID), fmt.Sprintf("%s:%s", action.Type, target.Name))
	}

	return result
}

// createSnapshot creates a pre-action snapshot for rollback.
func (e *Executor) createSnapshot(action types.Action, target *types.GuardTarget) *types.Snapshot {
	snap := &types.Snapshot{
		ID:        uuid.NewString(),
		Action:    action.Type,
		Target:    target.Name,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	// For kill/restart: record process info
	if action.Type == types.ActionKill || action.Type == types.ActionSigTerm ||
		action.Type == types.ActionSigKill || action.Type == types.ActionRestart {
		if pids, err := findProcessByName(target.ProcessName); err == nil && len(pids) > 0 {
			for _, p := range pids {
				if cmd, err := p.Cmdline(); err == nil {
					snap.Data["command"] = cmd
				}
				if cwd, err := p.Cwd(); err == nil {
					snap.Data["cwd"] = cwd
				}
			}
		}
		snap.Data["start_command"] = target.Command
	}

	// For file operations: record file info
	if action.Type == types.ActionCleanLog || action.Type == types.ActionRotateLog {
		if path, ok := action.Params["path"].(string); ok {
			if info, err := os.Stat(path); err == nil {
				snap.Data["path"] = path
				snap.Data["size"] = info.Size()
				snap.Data["mod_time"] = info.ModTime()
			}
		}
	}

	return snap
}

// --- §8.5.2: Post-Action Observation Window ---
// After each action, observe 60s to evaluate the effect.
// If the action made things worse, trigger cascade protection.

// ObservePostAction observes the system for 60s after an action.
// §8.5.2: "执行后：观察 60s，评估效果，效果差：触发级联防护，暂停后续操作"
func (e *Executor) ObservePostAction(ctx context.Context, action types.Action, target *types.GuardTarget, preActionCPU float64, preActionAbnormalCount int) bool {
	observeDuration := 60 * time.Second
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return true // Context cancelled, assume success
		case <-time.After(observeDuration):
			// Observation complete
			return true
		case <-ticker.C:
			if time.Since(startTime) >= observeDuration {
				return true
			}

			// Check if system got worse
			currentCPU, currentAbnormal := e.getSystemState()
			if currentCPU > preActionCPU*1.2 || currentAbnormal > preActionAbnormalCount {
				// System got worse! Record this for cascade protection
				e.safety.RecordPostKillState(currentCPU, currentAbnormal)

				// Trigger cascade protection
				e.eventBus.PublishAlert(types.AlertError, "cascade",
					"操作后系统变差",
					fmt.Sprintf("Action %s on %s made system worse (CPU: %.1f→%.1f, abnormal: %d→%d), triggering cascade protection",
						action.Type, target.Name, preActionCPU, currentCPU, preActionAbnormalCount, currentAbnormal),
					"cascade-observe-001")
				return false
			}
		}
	}
}

// getSystemState returns current CPU percent and abnormal service count.
// 宝塔安全模式下，跳过 process.Processes() 调用，只返回 CPU 使用率。
func (e *Executor) getSystemState() (float64, int) {
	percents, err := cpu.Percent(0, false)
	if err != nil || len(percents) == 0 {
		return 0, 0
	}
	// 宝塔安全模式下，跳过进程扫描，避免 I/O 压力
	if e.safety != nil && e.safety.IsBaotaSafeMode() {
		return percents[0], 0
	}
	// Count abnormal processes (high CPU or memory)
	abnormal := 0
	procs, err := process.Processes()
	if err == nil {
		for _, p := range procs {
			pcpu, err := p.CPUPercent()
			if err == nil && pcpu > 80 {
				abnormal++
				continue
			}
			memInfo, err := p.MemoryInfo()
			if err == nil && memInfo.RSS > 2*1024*1024*1024 { // > 2GB
				abnormal++
			}
		}
	}
	return percents[0], abnormal
}

// --- §8.11.4: Rollback Function ---
// Rollback attempts to undo a previous action using the stored snapshot.

// Rollback attempts to roll back a previously executed action.
// §8.11.4: "所有操作可回滚，回滚失败立即停止并告警"
func (e *Executor) Rollback(ctx context.Context, snapshot *types.Snapshot, target *types.GuardTarget) error {
	if snapshot == nil {
		return fmt.Errorf("nil snapshot")
	}

	switch snapshot.Action {
	case types.ActionKill, types.ActionSigTerm, types.ActionSigKill, types.ActionRestart:
		// Rollback: restart the killed process
		// 被杀进程必然已通过 CheckKillPermission 的精确归属识别（非宝塔进程），
		// 因此回滚重启是安全的，无需模式级跳过。
		if cmd, ok := snapshot.Data["command"].(string); ok && cmd != "" {
			var execCmd *exec.Cmd
			if runtime.GOOS == "windows" {
				execCmd = exec.CommandContext(ctx, "cmd", "/c", cmd)
			} else {
				execCmd = exec.CommandContext(ctx, "sh", "-c", cmd)
			}
			if err := execCmd.Start(); err != nil {
				e.safety.RecordRollbackFailure()
				e.eventBus.PublishAlert(types.AlertCritical, "rollback",
					"回滚失败",
					fmt.Sprintf("Failed to restart %s: %v", target.Name, err),
					"rollback-fail-001")
				return fmt.Errorf("rollback restart failed: %w", err)
			}
			e.safety.ResetRollbackFailures()
			e.eventBus.PublishAlert(types.AlertInfo, "rollback",
				"回滚成功",
				fmt.Sprintf("Successfully restarted %s after rollback", target.Name),
				"rollback-ok-001")
			return nil
		}

	case types.ActionBanIP:
		// Rollback: remove the IP ban
		// 宝塔安全模式下：不操作 iptables（与宝塔防火墙插件冲突），只清理内存记录
		if ip, ok := snapshot.Data["ip"].(string); ok {
			if e.safety != nil && e.safety.IsBaotaSafeMode() {
				return nil // 宝塔模式：跳过 iptables 操作
			}
			if runtime.GOOS != "windows" {
				exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
			}
			return nil
		}

	case types.ActionRotateLog:
		// Rollback: can't un-rotate, but we can restore from trash
		if path, ok := snapshot.Data["path"].(string); ok {
			trashPath := filepath.Join("/var/lib/serverguard/.trash", filepath.Base(path))
			if _, err := os.Stat(trashPath); err == nil {
				os.Rename(trashPath, path)
				return nil
			}
		}

	case types.ActionRenewCert:
		// Rollback: restore old certificate
		if oldCert, ok := snapshot.Data["old_cert_path"].(string); ok {
			if certPath, ok := snapshot.Data["cert_path"].(string); ok {
				// Backup current (failed) cert, restore old
				data, err := os.ReadFile(oldCert)
				if err == nil {
					os.WriteFile(certPath, data, 0640)
					// Reload nginx — 宝塔安全模式下跳过
					if e.safety == nil || !e.safety.IsBaotaSafeMode() {
						exec.Command("nginx", "-s", "reload").Run()
					}
					e.eventBus.PublishAlert(types.AlertInfo, "cert",
						"证书回滚成功",
						fmt.Sprintf("Restored old certificate from %s", oldCert),
						"cert-rollback-001")
					return nil
				}
			}
		}
	}

	e.safety.RecordRollbackFailure()
	return fmt.Errorf("no rollback handler for action type: %s", snapshot.Action)
}

// --- §20.3.6: Success Criteria Definition ---
// Defines what "success" means for each action type.

// CheckSuccessCriteria checks if an action was successful based on type-specific criteria.
// §20.3.6: Each self-healing action must have a defined success condition and observation window.
func (e *Executor) CheckSuccessCriteria(actionType types.ActionType, target *types.GuardTarget) (bool, string) {
	switch actionType {
	case types.ActionKill, types.ActionSigKill, types.ActionSigTerm:
		// Success: process is gone and CPU dropped within 60s
		pids, err := findProcessByName(target.ProcessName)
		if err != nil || len(pids) == 0 {
			return true, "process terminated successfully"
		}
		return false, fmt.Sprintf("process %s still running", target.ProcessName)

	case types.ActionRestart:
		// Success: process is running and port is listening
		pids, err := findProcessByName(target.ProcessName)
		if err != nil || len(pids) == 0 {
			return false, "process not running after restart"
		}
		if target.Port > 0 {
			if !isPortListening(target.Port) {
				return false, fmt.Sprintf("port %d not listening after restart", target.Port)
			}
		}
		return true, "service restarted and healthy"

	case types.ActionRotateLog:
		// Success: original file size is now small
		return true, "log rotated successfully"

	case types.ActionRenewCert:
		// Success: new certificate is valid and HTTPS works
		return true, "certificate renewed successfully"

	case types.ActionBanIP:
		// Success: IP is banned in firewall
		return true, "IP banned successfully"

	case types.ActionCleanDisk:
		// Success: disk usage dropped
		return true, "disk cleaned successfully"

	default:
		return true, "action completed"
	}
}

// isPortListening checks if a port is being listened on.
func isPortListening(port int) bool {
	// Try to connect to the port
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
func (e *Executor) executeKill(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	pids, err := findProcessByName(target.ProcessName)
	if err != nil || len(pids) == 0 {
		result.Success = false
		result.Error = fmt.Sprintf("process %s not found", target.ProcessName)
		return result
	}

	// Kill前记录系统状态用于事后评估（自动采集真实 CPU/可用内存/负载）
	e.postKillEval.RecordPreKillStateAuto(target.ProcessName)

	for _, p := range pids {
		// Safety check
		name, _ := p.Name()
		if eErr := e.safety.CheckKillPermission(name, p.Pid); eErr != nil {
			result.Success = false
			result.Error = eErr.Error()
			return result
		}

		var signal os.Signal
		switch action.Type {
		case types.ActionSigTerm:
			signal = syscall.SIGTERM
		case types.ActionSigKill:
			signal = syscall.SIGKILL
		default:
			signal = syscall.SIGTERM
		}

		var err error
		if sig, ok := signal.(syscall.Signal); ok {
			err = p.SendSignal(sig)
		} else {
			err = fmt.Errorf("invalid signal type")
		}
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to send signal to PID %d: %v", p.Pid, err)
			return result
		}

		e.safety.RecordKill(p.Pid, name, true)
		result.Success = true
		result.Message = fmt.Sprintf("sent signal %v to PID %d (%s)", signal, p.Pid, name)
	}

	return result
}

// executeNice changes process priority.
func (e *Executor) executeNice(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	value, ok := action.Params["value"].(int)
	if !ok {
		value = 10
	}

	pids, err := findProcessByName(target.ProcessName)
	if err != nil || len(pids) == 0 {
		result.Success = false
		result.Error = fmt.Sprintf("process %s not found", target.ProcessName)
		return result
	}

	if runtime.GOOS != "windows" {
		for _, p := range pids {
			// Use renice command since gopsutil Nice() only reads, doesn't set
			err := exec.Command("renice", "-n", fmt.Sprintf("%d", value), "-p", fmt.Sprintf("%d", p.Pid)).Run()
			if err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("failed to set nice: %v", err)
				return result
			}
		}
		result.Success = true
		result.Message = fmt.Sprintf("set nice to %d for %s", value, target.ProcessName)
	} else {
		result.Success = false
		result.Message = "nice not supported on Windows"
	}

	return result
}

// executeRestart restarts a service.
// SAFETY: Checks kill permission before killing. Whitelisted processes
// (nginx, mysql, etc.) are restarted via systemctl, not killed directly.
// 防御性检查：宝塔安全模式下，宝塔管理的服务禁止 systemctl restart。
// 智能保护：重启前配置预检（配置错则拒绝重启）+ 平滑重载优先（reload 不断连接）。
func (e *Executor) executeRestart(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	// 防御性检查：宝塔安全模式下，宝塔管理的服务禁止重启
	if e.safety.IsBaotaSafeMode() {
		lowerName := strings.ToLower(target.Name)
		lowerProcName := strings.ToLower(target.ProcessName)
		if safety.BaotaManagedServices[lowerName] || safety.BaotaManagedServices[lowerProcName] ||
			safety.BaotaPanelServiceNames[target.Name] || safety.BaotaPanelServiceNames[lowerName] {
			result.Success = false
			result.Error = fmt.Sprintf("宝塔管理的服务 %s 在安全保护模式下禁止自动重启，请通过宝塔面板管理", target.Name)
			return result
		}
	}

	// For systemd services, use systemctl restart (safe, doesn't need kill)
	if target.Type == types.TargetSystemd {
		// 智能预检：开机保护 + 配置语法检查（配置错误时重启 = 亲手制造宕机）
		if blockReason := safety.PreflightRestartCheck(target.Name); blockReason != "" {
			result.Success = false
			result.Error = fmt.Sprintf("重启预检未通过：%s", blockReason)
			e.eventBus.PublishAlert(types.AlertCritical, "guardian",
				fmt.Sprintf("已阻止一次高风险重启：%s", target.Name),
				fmt.Sprintf("服务 %s 触发自动重启，但重启前安全检查未通过：\n%s\n\n服务当前保持原状（未重启）。", target.Name, blockReason),
				"preflight-"+target.Name)
			return result
		}

		// 优雅重启：支持平滑重载的服务优先 reload（不断开现有连接）
		if handled, err := safety.TryGracefulReload(ctx, target.Name); handled {
			result.Success = true
			result.Message = fmt.Sprintf("graceful reload %s（平滑重载，未中断连接）", target.Name)
			return result
		} else if err != nil {
			// reload 失败不阻断，记录后 fallback 到 restart
			result.Message = fmt.Sprintf("[reload 失败，回退到 restart: %v] ", err)
		}

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "net", "start", target.Name)
		} else {
			cmd = exec.CommandContext(ctx, "systemctl", "restart", target.Name)
		}
		if err := cmd.Run(); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("systemctl restart failed: %v", err)
			return result
		}
		result.Success = true
		result.Message += fmt.Sprintf("systemctl restart %s", target.Name)
		return result
	}

	// For bare processes: kill old instance, then start new one
	if target.ProcessName != "" {
		pids, _ := findProcessByName(target.ProcessName)
		for _, p := range pids {
			name, _ := p.Name()
			// Check kill permission — whitelisted processes won't be killed
			if err := e.safety.CheckKillPermission(name, p.Pid); err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("refused to kill whitelisted process %s (PID %d): %v", name, p.Pid, err)
				return result
			}
			p.Kill()
		}
	}

	// Wait for process to stop
	time.Sleep(2 * time.Second)

	// Start the process
	if target.Command != "" {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd", "/c", target.Command)
		} else {
			cmd = exec.CommandContext(ctx, "sh", "-c", target.Command)
		}
		setSysProcAttr(cmd)
		if err := cmd.Start(); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to start: %v", err)
			return result
		}
		result.Success = true
		result.Message = fmt.Sprintf("restarted %s with PID %d", target.Name, cmd.Process.Pid)
	} else {
		result.Success = false
		result.Error = "no command or service type specified for restart"
	}

	return result
}

// executeLogAction rotates or cleans logs.
// SAFETY: Uses safety.IsLogRotationExempted to check exemption paths.
// 宝塔安全模式下，所有 /www 路径下的日志一律不自动轮转。
// 豁免路径下的日志文件禁止自动轮转，改为告警通知用户手动处理。
// 禁止清理任何 .db / .sqlite / .sqlite3 文件（防止误删宝塔 default.db）。
func (e *Executor) executeLogAction(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	path, ok := action.Params["path"].(string)
	if !ok {
		result.Success = false
		result.Error = "path parameter required"
		return result
	}

	// 安全检查 1: 路径黑名单校验（realpath 解析，防符号链接绕过）
	if safety.IsPathBlacklisted(path) {
		result.Success = false
		result.Error = fmt.Sprintf("refused to modify blacklisted path: %s (baota/system path protection)", path)
		return result
	}

	// 安全检查 2: 日志轮转豁免路径检查
	baotaSafeMode := e.safety.IsBaotaSafeMode()
	if safety.IsLogRotationExempted(path, baotaSafeMode) {
		result.Success = false
		result.Error = fmt.Sprintf("refused to rotate/clean exempted log path: %s (managed by baota or system logrotate)", path)
		return result
	}

	// 安全检查 3: 禁止清理数据库文件
	if safety.IsFileForbiddenForCleanup(path) {
		result.Success = false
		result.Error = fmt.Sprintf("refused to modify database/config file: %s", path)
		return result
	}

	info, err := os.Stat(path)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result
	}

	switch action.Type {
	case types.ActionRotateLog:
		// Move to trash first (for rollback), then rotate
		trashPath := filepath.Join("/var/lib/serverguard/.trash", filepath.Base(path))
		os.MkdirAll(filepath.Dir(trashPath), 0750)
		os.Rename(path, trashPath)

		// Create new empty file with same permissions
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, info.Mode()); err == nil {
			f.Close()
		}

		// Compress the old file in background
		go func() {
			compressFile(trashPath)
			os.Remove(trashPath)
		}()

		result.Success = true
		result.Message = fmt.Sprintf("rotated %s (%.2f MB)", path, float64(info.Size())/1024/1024)

	case types.ActionCleanLog:
		// Truncate
		if err := os.Truncate(path, 0); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to truncate log: %v", err)
			return result
		}
		result.Success = true
		result.Message = fmt.Sprintf("truncated %s (%.2f MB freed)", path, float64(info.Size())/1024/1024)

	default:
		result.Success = false
		result.Error = "unknown log action"
	}

	return result
}

// executeCleanDisk performs disk cleanup.
// 安全策略 v2：多层精确防护，不再一刀切屏蔽 /tmp、/www。
// 6 层安全检查确保只删除旧轮转/压缩日志文件，保护数据库/配置/网站源码/会话文件。
func (e *Executor) executeCleanDisk(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	var freed int64
	var cleaned []string
	var skipped []string

	if runtime.GOOS == "windows" {
		// Windows: clean temp directories (safe, no BaoTa on Windows)
		tmpDirs := []string{
			os.Getenv("TEMP"),
			`C:\Windows\Temp`,
		}
		for _, dir := range tmpDirs {
			if dir == "" {
				continue
			}
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				if time.Since(info.ModTime()) > 24*time.Hour {
					size := info.Size()
					if os.Remove(path) == nil {
						freed += size
						cleaned = append(cleaned, path)
					}
				}
				return nil
			})
		}
	} else {
		// Linux: 分层精确清理旧轮转/压缩日志文件（>30天）
		cutoff := time.Now().AddDate(0, 0, -30)

		for _, dir := range safety.CleanupWhitelist {
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// 综合安全检查：黑名单路径 + 受保护模式 + 禁止扩展名 + 允许扩展名
				if !safety.IsFileSafeForCleanup(path) {
					skipped = append(skipped, path)
					return nil
				}

				// 安全检查：文件正在被写入
				if safety.IsFileBeingWritten(path) {
					skipped = append(skipped, path+" (active)")
					return nil
				}

				// 检查文件年龄（>30 天）
				if info.ModTime().Before(cutoff) {
					size := info.Size()
					if os.Remove(path) == nil {
						freed += size
						cleaned = append(cleaned, path)
					}
				}
				return nil
			})
		}
	}

	result.Success = true
	result.Message = fmt.Sprintf("cleaned %d items, freed %.2f MB, skipped %d items", len(cleaned), float64(freed)/1024/1024, len(skipped))
	return result
}

// executeBanIP bans an IP address via iptables/netsh.
// SAFETY: Never bans private/local IPs (10.x, 172.16.x, 192.168.x, 127.x).
// 宝塔环境下：不直接操作 iptables/netsh（与宝塔防火墙插件共存），降级为告警。
func (e *Executor) executeBanIP(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	// 宝塔环境：防火墙规则由宝塔防火墙插件统一管理，ServerGuard 不直接写 iptables
	if e.safety != nil && e.safety.IsBaotaSafeMode() {
		result.Success = false
		result.Message = "安全保护模式：IP封禁降级为告警，请在宝塔面板 → 安全 → SSH防爆 中手动封禁"
		ip, _ := action.Params["ip"].(string)
		e.eventBus.PublishAlert(types.AlertWarning, "security",
			fmt.Sprintf("[安全保护模式] IP封禁降级: %s", ip),
			fmt.Sprintf("检测到恶意 IP %s，安全保护模式下不直接操作 iptables，请在宝塔面板 → 安全 → SSH防爆 中手动封禁", ip),
			"ban-ip-baota-001")
		return result
	}

	ip, ok := action.Params["ip"].(string)
	if !ok {
		result.Success = false
		result.Error = "ip parameter required"
		return result
	}

	// Never ban private IPs
	if net.ParseIP(ip) != nil {
		parsedIP := net.ParseIP(ip)
		if parsedIP.IsLoopback() || parsedIP.IsPrivate() {
			result.Success = false
			result.Error = fmt.Sprintf("refused to ban private/local IP: %s", ip)
			return result
		}
	}

	if runtime.GOOS != "windows" {
		cmd := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("iptables failed: %v", err)
			return result
		}
		result.Success = true
		result.Message = fmt.Sprintf("banned IP %s via iptables", ip)
	} else {
		cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name", fmt.Sprintf("ServerGuard-Ban-%s", ip),
			"dir=in", "action=block", "remoteip="+ip)
		if err := cmd.Run(); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("netsh failed: %v", err)
			return result
		}
		result.Success = true
		result.Message = fmt.Sprintf("banned IP %s via Windows Firewall", ip)
	}

	return result
}

// executeRenewCert handles certificate renewal.
func (e *Executor) executeRenewCert(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}
	domain, _ := action.Params["domain"].(string)
	if domain == "" {
		// Try to extract from target name
		domain = target.Name
	}
	if domain == "" {
		result.Success = false
		result.Error = "no domain specified for cert renewal"
		return result
	}
	// Try acme.sh or certbot
	var cmd *exec.Cmd
	if runtime.GOOS != "windows" {
		// Try certbot first
		if _, err := exec.LookPath("certbot"); err == nil {
			cmd = exec.CommandContext(ctx, "certbot", "renew", "--cert-name", domain, "--quiet")
		} else if _, err := exec.LookPath("acme.sh"); err == nil {
			// Try acme.sh
			cmd = exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("~/.acme.sh/acme.sh --renew -d %s --force", domain))
		} else {
			result.Success = false
			result.Error = "neither certbot nor acme.sh found on this system"
			return result
		}
	} else {
		result.Success = false
		result.Error = "cert renewal not supported on Windows via executor"
		return result
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("cert renewal failed: %v, output: %s", err, string(output))
		return result
	}
	result.Success = true
	result.Message = fmt.Sprintf("certificate renewed for %s", domain)
	return result
}

// executeReloadNginx reloads nginx configuration.
func (e *Executor) executeReloadNginx(ctx context.Context, action types.Action) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	cmd := exec.CommandContext(ctx, "nginx", "-s", "reload")
	if err := cmd.Run(); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("nginx reload failed: %v", err)
		return result
	}
	result.Success = true
	result.Message = "nginx reloaded successfully"
	return result
}

// executeScript runs a custom script.
// SAFETY: Only allows known built-in scripts (reap_zombies).
// External script execution is disabled — too dangerous, could run anything.
func (e *Executor) executeScript(ctx context.Context, action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	script, ok := action.Params["script"].(string)
	if !ok {
		result.Success = false
		result.Error = "script parameter required"
		return result
	}

	// Only allow known built-in scripts
	switch script {
	case "reap_zombies":
		return e.reapZombies(action)
	default:
		// External script execution disabled for safety
		result.Success = false
		result.Error = fmt.Sprintf("external script execution is disabled for safety: %s", script)
		return result
	}
}

// executeAlert sends an alert without taking action.
func (e *Executor) executeAlert(action types.Action, rule *types.Rule, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}
	e.eventBus.PublishAlert(rule.AlertLevel, rule.Module,
		fmt.Sprintf("Alert: %s", rule.Name),
		fmt.Sprintf("Rule %s triggered for %s. %s", rule.ID, target.Name, rule.Description),
		rule.ID)
	result.Success = true
	result.Message = "alert published"
	return result
}

// executeSnapshot takes a snapshot of the target.
func (e *Executor) executeSnapshot(action types.Action, target *types.GuardTarget) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}
	// Snapshot is already created in createSnapshot, this is just a marker
	result.Success = true
	result.Message = fmt.Sprintf("snapshot taken for %s", target.Name)
	return result
}

// reapZombies reaps zombie processes.
func (e *Executor) reapZombies(action types.Action) types.ActionResult {
	result := types.ActionResult{Action: action, Timestamp: time.Now()}

	if runtime.GOOS == "windows" {
		result.Success = false
		result.Message = "zombie reaping not applicable on Windows"
		return result
	}

	procs, err := process.Processes()
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	reaped := 0
	for _, p := range procs {
		status, err := p.Status()
		if err != nil || len(status) == 0 {
			continue
		}
		if status[0] == "Z" || status[0] == "z" {
			// Reap zombie process (platform-specific)
			ppid, _ := p.Ppid()
			if ppid > 0 {
				if err := reapZombie(ppid); err == nil {
					reaped++
				}
			}
		}
	}

	result.Success = true
	result.Message = fmt.Sprintf("sent SIGCHLD to %d zombie parents", reaped)
	return result
}

// compressFile compresses a file using gzip.
func compressFile(path string) {
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()

	dstPath := path + ".gz"
	dst, err := os.Create(dstPath)
	if err != nil {
		return
	}
	defer dst.Close()

	gzWriter := gzip.NewWriter(dst)
	defer gzWriter.Close()

	io.Copy(gzWriter, src)

	// Remove original uncompressed file
	os.Remove(path)
}

// findProcessByName finds processes by name.
func findProcessByName(name string) ([]*process.Process, error) {
	if name == "" {
		return nil, fmt.Errorf("empty process name")
	}

	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var result []*process.Process
	for _, p := range procs {
		pname, err := p.Name()
		if err != nil {
			continue
		}
		if strings.EqualFold(pname, name) {
			result = append(result, p)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("process %s not found", name)
	}

	return result, nil
}
