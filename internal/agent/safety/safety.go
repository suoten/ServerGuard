package safety

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/config"
	"github.com/suoten/serverguard/internal/types"
)

// SafetyManager manages all safety mechanisms for destructive operations.
// Implements the 5-layer safety design from the product spec:
// Layer 1: Agent self-resource constraints (OS-level)
// Layer 2: Agent self-throttling (system state aware)
// Layer 3: Action safety valves (kill budget, circuit breaker, resource floor, hard whitelist, snapshot)
// Layer 4: Cascade failure protection
// Layer 5: Global kill switch
type SafetyManager struct {
	mu                  sync.RWMutex
	cfg                 config.SafetyConfig
	mode                types.AgentMode
	emergencyStop       bool
	emergencyStopReason string

	// Kill budget
	killHourlyCount int
	killDailyCount  int
	lastKillTime    time.Time
	killHistory     []killRecord

	// Circuit breakers (per action type)
	breakers map[string]*CircuitBreaker

	// Cascade protection
	lastActionTarget string
	lastActionTime   time.Time
	cascadeObserving bool

	// Trigger tracking (for max_triggers and cooldown)
	triggerHistory map[string][]time.Time // rule_id -> trigger times

	// Hard whitelist (system processes that can never be killed)
	hardWhitelist   map[string]bool
	customWhitelist map[string]bool

	// Auto emergency stop tracking (§8.11.6)
	panicCount                  int
	consecutiveRollbackFailures int
	preKillSysState             []sysStateSnapshot
	postKillSysState            []sysStateSnapshot

	// BaotaSafeMode 宝塔环境适配
	// 仅控制"与宝塔共存"的环境行为：防火墙/bt CLI/采集降频/日志轮转豁免等。
	// 进程 Kill 保护不走此开关 —— 由 IsBaotaProtectedProcess 精确归属识别无条件兜底。
	baotaSafeMode bool

	// 宝塔面板释压重启控制器（面板进程失控时的止损通道）
	panelRelief *PanelReliefController

	// 维护窗口判定回调（由 API 层注入，见 maintenance.go）
	maintenanceProvider MaintenanceProvider

	// V4.0 — 远程暂停（双向通知回复 "暂停" 后置 true）
	remotePaused       bool
	remotePausedReason string
	remotePausedAt     time.Time
}

type killRecord struct {
	PID       int32
	Name      string
	Timestamp time.Time
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            BreakerState // closed, open, half-open
	failureCount     int
	failureThreshold int
	resetDuration    time.Duration
	lastFailureTime  time.Time
	nextAttemptTime  time.Time
}

type BreakerState int

const (
	BreakerClosed   BreakerState = iota // 0
	BreakerOpen                         // 1
	BreakerHalfOpen                     // 2
)

func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// New creates a new SafetyManager.
func New(cfg config.SafetyConfig) *SafetyManager {
	sm := &SafetyManager{
		cfg:             cfg,
		mode:            types.ModeNormal,
		breakers:        make(map[string]*CircuitBreaker),
		triggerHistory:  make(map[string][]time.Time),
		hardWhitelist:   getDefaultHardWhitelist(),
		customWhitelist: make(map[string]bool),
		panelRelief:     NewPanelReliefController(),
	}

	// Initialize circuit breakers for each action type
	sm.breakers["kill"] = &CircuitBreaker{
		state:            BreakerClosed,
		failureThreshold: cfg.CircuitBreakerThreshold,
		resetDuration:    cfg.CircuitBreakerResetDuration.Duration(),
	}
	sm.breakers["restart"] = &CircuitBreaker{
		state:            BreakerClosed,
		failureThreshold: 3,
		resetDuration:    1 * time.Hour,
	}
	sm.breakers["ban_ip"] = &CircuitBreaker{
		state:            BreakerClosed,
		failureThreshold: 3,
		resetDuration:    1 * time.Hour,
	}
	sm.breakers["clean_log"] = &CircuitBreaker{
		state:            BreakerClosed,
		failureThreshold: 3,
		resetDuration:    30 * time.Minute,
	}
	sm.breakers["renew_cert"] = &CircuitBreaker{
		state:            BreakerClosed,
		failureThreshold: 3,
		resetDuration:    24 * time.Hour,
	}

	return sm
}

// UpdateKillBudget updates kill budget limits at runtime.
func (sm *SafetyManager) UpdateKillBudget(hourly, daily int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.cfg.KillBudgetHourly = hourly
	sm.cfg.KillBudgetDaily = daily
}

// --- Layer 2: Self-Throttling ---

// EvaluateSystemState determines the agent mode based on system resources.
// 阈值设计原则：宁可误判降频，也不冒险影响服务器性能
// 注意：这里的 CPU/内存是系统级别的（不是 Agent 自身的）
func (sm *SafetyManager) EvaluateSystemState(cpuPercent float64, memAvailableMB float64, loadFactor float64) types.AgentMode {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	switch {
	// 临界（CPU > 95% 或可用内存 < 50MB）→ 只存活+告警（对齐规划文档 §8.11）
	case cpuPercent > 95 || memAvailableMB < 50:
		sm.mode = types.ModeSurvival
	// 危险（CPU > 85% 或可用内存 < 100MB）→ 最小模式，暂停危险操作
	case cpuPercent > 85 || memAvailableMB < 100:
		sm.mode = types.ModeMinimal
	// 繁忙（CPU > 70% 或可用内存 < 200MB）→ 降频，关闭重分析
	case cpuPercent > 70 || memAvailableMB < 200:
		sm.mode = types.ModeThrottled
	default:
		sm.mode = types.ModeNormal
	}

	return sm.mode
}

// GetMode returns the current agent mode.
func (sm *SafetyManager) GetMode() types.AgentMode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.mode
}

// ShouldPauseActions returns true if the agent should pause all automatic actions.
func (sm *SafetyManager) ShouldPauseActions() bool {
	sm.mu.RLock()
	paused := sm.mode == types.ModeMinimal || sm.mode == types.ModeSurvival || sm.emergencyStop || sm.remotePaused
	p := sm.maintenanceProvider
	sm.mu.RUnlock()
	if paused {
		return true
	}
	// 维护窗口期内暂停所有自动修复动作
	if p != nil && p() {
		return true
	}
	return false
}

// ShouldPauseDangerousActions returns true if kill/restart should be paused.
func (sm *SafetyManager) ShouldPauseDangerousActions() bool {
	sm.mu.RLock()
	paused := sm.mode == types.ModeThrottled || sm.mode == types.ModeMinimal || sm.mode == types.ModeSurvival || sm.emergencyStop || sm.remotePaused
	p := sm.maintenanceProvider
	sm.mu.RUnlock()
	if paused {
		return true
	}
	// 维护窗口期内暂停危险动作
	if p != nil && p() {
		return true
	}
	return false
}

// GetCollectInterval returns the adjusted collect interval based on mode.
// Normal(默认) → Throttled(15s) → Minimal(60s) → Survival(60s 只存活) → Emergency(停止)
// 间隔对齐规划文档 §8.11 自我节流设计。
func (sm *SafetyManager) GetCollectInterval(defaultInterval time.Duration) time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	switch sm.mode {
	case types.ModeSurvival:
		return 60 * time.Second
	case types.ModeMinimal:
		return 60 * time.Second
	case types.ModeThrottled:
		return 15 * time.Second
	default:
		return defaultInterval
	}
}

// ShouldRunGuards 返回是否应执行 Guard.Check() 调用。
// Survival 模式下跳过所有 Guard.Check()，只发送心跳和紧急告警。
// Emergency 模式下同样跳过。
func (sm *SafetyManager) ShouldRunGuards() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.mode != types.ModeSurvival && sm.mode != types.ModeEmergency && !sm.emergencyStop
}

// --- Layer 3: Action Safety Valves ---

// CheckKillPermission checks if a kill action is allowed (Kill Budget + Circuit Breaker + Whitelist).
// 白名单匹配同时检查 /proc/{pid}/comm、/proc/{pid}/cmdline、/proc/{pid}/exe 软链接指向。
// 对于 python/python3 等通用进程名，通过 IsBaotaProtectedProcess 二次确认路径或父进程。
// 宝塔进程保护不依赖任何模式开关：精确归属识别无条件生效，
// 非宝塔进程在任何模式下都按预算/熔断器正常管控。
func (sm *SafetyManager) CheckKillPermission(processName string, pid int32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check emergency stop
	if sm.emergencyStop {
		return fmt.Errorf("emergency stop is active, all actions are blocked")
	}

	// Check mode
	if sm.mode == types.ModeMinimal || sm.mode == types.ModeSurvival {
		return fmt.Errorf("agent is in %s mode, kill operations are paused", sm.mode)
	}

	// Check cascade observation window
	if sm.cascadeObserving {
		return fmt.Errorf("cascade observation in progress, waiting for previous action to settle")
	}

	// Check hard whitelist (名称匹配)
	if sm.hardWhitelist[processName] {
		return fmt.Errorf("process %s is in hard whitelist, cannot be killed", processName)
	}
	if sm.customWhitelist[processName] {
		return fmt.Errorf("process %s is in custom whitelist, cannot be killed", processName)
	}

	// 宝塔白名单深度检查：读取 /proc 信息，匹配 comm / cmdline / exe，
	// 对 python/python3 二次确认路径或父进程。
	if procInfo := ReadProcInfo(pid); procInfo != nil {
		if IsBaotaProtectedProcess(procInfo) {
			return fmt.Errorf("process %s (PID %d) is in baota whitelist (comm=%s, cmdline=%s), cannot be killed",
				processName, pid, procInfo.Comm, procInfo.Cmdline)
		}
	}

	// Check PID 1 and kernel threads
	if pid <= 2 {
		return fmt.Errorf("PID %d is a system/kernel process, cannot be killed", pid)
	}

	// Check kill budget
	now := time.Now()
	// Reset hourly count
	if len(sm.killHistory) > 0 {
		oneHourAgo := now.Add(-1 * time.Hour)
		var recent []killRecord
		for _, r := range sm.killHistory {
			if r.Timestamp.After(oneHourAgo) {
				recent = append(recent, r)
			}
		}
		sm.killHistory = recent
		sm.killHourlyCount = len(recent)
	}

	if sm.killHourlyCount >= sm.cfg.KillBudgetHourly {
		return fmt.Errorf("hourly kill budget exhausted (%d/%d), pausing kill operations for 1 hour",
			sm.killHourlyCount, sm.cfg.KillBudgetHourly)
	}

	// Reset daily count
	oneDayAgo := now.Add(-24 * time.Hour)
	dailyCount := 0
	for _, r := range sm.killHistory {
		if r.Timestamp.After(oneDayAgo) {
			dailyCount++
		}
	}
	sm.killDailyCount = dailyCount

	if sm.killDailyCount >= sm.cfg.KillBudgetDaily {
		return fmt.Errorf("daily kill budget exhausted (%d/%d), pausing kill operations for the day",
			sm.killDailyCount, sm.cfg.KillBudgetDaily)
	}

	// Check kill interval
	if !sm.lastKillTime.IsZero() && now.Sub(sm.lastKillTime) < sm.cfg.KillMinInterval.Duration() {
		return fmt.Errorf("kill interval too short, last kill was %v ago, minimum %v required",
			now.Sub(sm.lastKillTime), sm.cfg.KillMinInterval.Duration())
	}

	// Check circuit breaker
	breaker := sm.breakers["kill"]
	if breaker != nil && breaker.state == BreakerOpen {
		if now.Before(breaker.nextAttemptTime) {
			return fmt.Errorf("kill circuit breaker is open, will reset at %v", breaker.nextAttemptTime)
		}
		// Move to half-open
		breaker.state = BreakerHalfOpen
	}

	return nil
}

// RecordKill records a kill action for budget tracking.
func (sm *SafetyManager) RecordKill(pid int32, name string, success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()

	if success {
		sm.killHistory = append(sm.killHistory, killRecord{
			PID:       pid,
			Name:      name,
			Timestamp: now,
		})
		sm.killHourlyCount++
		sm.killDailyCount++
		sm.lastKillTime = now
	}

	// Check for circuit breaker trigger (10 min, 3 different processes)
	tenMinAgo := now.Add(-10 * time.Minute)
	diffProcs := make(map[string]bool)
	for _, r := range sm.killHistory {
		if r.Timestamp.After(tenMinAgo) {
			diffProcs[r.Name] = true
		}
	}

	breaker := sm.breakers["kill"]
	if breaker != nil {
		if len(diffProcs) >= sm.cfg.CircuitBreakerThreshold {
			breaker.state = BreakerOpen
			breaker.lastFailureTime = now
			breaker.nextAttemptTime = now.Add(breaker.resetDuration)
		} else if success && breaker.state == BreakerHalfOpen {
			breaker.state = BreakerClosed
			breaker.failureCount = 0
		} else if !success {
			breaker.failureCount++
			if breaker.failureCount >= breaker.failureThreshold {
				breaker.state = BreakerOpen
				breaker.lastFailureTime = now
				breaker.nextAttemptTime = now.Add(breaker.resetDuration)
			}
		}
	}

	// Start cascade observation
	// 向宝塔学习：用 time.AfterFunc 代替 go+Sleep，减少 goroutine 创建
	sm.cascadeObserving = true
	sm.lastActionTarget = name
	sm.lastActionTime = now
	time.AfterFunc(sm.cfg.ObservationWindow.Duration(), func() {
		sm.mu.Lock()
		sm.cascadeObserving = false
		sm.mu.Unlock()
	})
}

// --- Layer 4: Cascade Protection ---

// ShouldSuppressCascade returns true if a cascade alert should be suppressed.
func (sm *SafetyManager) ShouldSuppressCascade(sourceProcess string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// If we recently killed a process, and now another process is showing issues,
	// it's likely a cascade effect, so suppress the secondary alert.
	if sm.cascadeObserving && sm.lastActionTarget != sourceProcess {
		return true
	}
	return false
}

// --- Layer 5: Emergency Stop ---

// TriggerEmergencyStop activates the global kill switch.
func (sm *SafetyManager) TriggerEmergencyStop(halt bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.emergencyStop = true
	if halt {
		sm.mode = types.ModeEmergency
	}
}

// ResumeFromEmergencyStop deactivates the kill switch.
func (sm *SafetyManager) ResumeFromEmergencyStop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.emergencyStop = false
	if sm.mode == types.ModeEmergency {
		sm.mode = types.ModeNormal
	}
}

// IsEmergencyStopped returns true if the emergency stop is active.
func (sm *SafetyManager) IsEmergencyStopped() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.emergencyStop
}

// --- Trigger tracking (cooldown & max_triggers) ---

// CanTriggerRule checks if a rule can trigger based on cooldown and max_triggers.
func (sm *SafetyManager) CanTriggerRule(ruleID string, cooldown time.Duration, maxTriggers int) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	history := sm.triggerHistory[ruleID]

	// Filter to last hour（写回裁剪结果，防止历史无限增长）
	oneHourAgo := now.Add(-1 * time.Hour)
	var recent []time.Time
	for _, t := range history {
		if t.After(oneHourAgo) {
			recent = append(recent, t)
		}
	}
	sm.triggerHistory[ruleID] = recent

	// Check max_triggers
	if maxTriggers > 0 && len(recent) >= maxTriggers {
		return false
	}

	// Check cooldown
	if len(recent) > 0 {
		lastTrigger := recent[len(recent)-1]
		if now.Sub(lastTrigger) < cooldown {
			return false
		}
	}

	return true
}

// RecordTrigger records that a rule was triggered.
func (sm *SafetyManager) RecordTrigger(ruleID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 只保留最近 1 小时（与 CanTriggerRule 的判定窗口一致），防止长期运行内存增长
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	history := sm.triggerHistory[ruleID]
	var recent []time.Time
	for _, t := range history {
		if t.After(oneHourAgo) {
			recent = append(recent, t)
		}
	}
	sm.triggerHistory[ruleID] = append(recent, time.Now())
}

// --- Resource Floor ---

// CheckResourceFloor checks if system resources are sufficient for destructive actions.
func (sm *SafetyManager) CheckResourceFloor(memAvailableMB float64, loadFactor float64, diskFreeMB float64, diskIOWaitPercent float64) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if int(memAvailableMB) < sm.cfg.MinAvailableMemoryMB {
		return fmt.Errorf("available memory %.0fMB < minimum %dMB, pausing destructive actions",
			memAvailableMB, sm.cfg.MinAvailableMemoryMB)
	}

	if loadFactor > sm.cfg.MaxLoadFactor {
		return fmt.Errorf("load factor %.2f > max %.2f, pausing restart operations",
			loadFactor, sm.cfg.MaxLoadFactor)
	}

	if diskIOWaitPercent > sm.cfg.MaxDiskIOWaitPercent {
		return fmt.Errorf("disk IO wait %.1f%% > max %.1f%%, pausing IO-intensive operations",
			diskIOWaitPercent, sm.cfg.MaxDiskIOWaitPercent)
	}

	if int(diskFreeMB) < sm.cfg.MinDiskAvailableMB {
		return fmt.Errorf("disk free %.0fMB < minimum %dMB, pausing write operations",
			diskFreeMB, sm.cfg.MinDiskAvailableMB)
	}

	return nil
}

// --- Whitelist Management ---

// AddToWhitelist adds a process to the custom whitelist.
func (sm *SafetyManager) AddToWhitelist(name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.customWhitelist[name] = true
}

// RemoveFromWhitelist removes a process from the custom whitelist (but not hard whitelist).
func (sm *SafetyManager) RemoveFromWhitelist(name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.customWhitelist, name)
}

// GetWhitelist returns all whitelisted processes.
func (sm *SafetyManager) GetWhitelist() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var list []string
	for name := range sm.hardWhitelist {
		list = append(list, name+" (hard)")
	}
	for name := range sm.customWhitelist {
		list = append(list, name)
	}
	return list
}

// IsWhitelisted checks if a process is whitelisted.
func (sm *SafetyManager) IsWhitelisted(name string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.hardWhitelist[name] || sm.customWhitelist[name]
}

// --- Circuit Breaker Management ---

// GetCircuitBreakerState returns the state of a circuit breaker.
func (sm *SafetyManager) GetCircuitBreakerState(actionType string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	breaker := sm.breakers[actionType]
	if breaker == nil {
		return "unknown"
	}
	return breaker.state.String()
}

// RecordActionResult records the result of an action for circuit breaker tracking.
func (sm *SafetyManager) RecordActionResult(actionType string, success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	breaker := sm.breakers[actionType]
	if breaker == nil {
		return
	}

	breaker.mu.Lock()
	defer breaker.mu.Unlock()

	if success {
		breaker.failureCount = 0
		if breaker.state == BreakerHalfOpen {
			breaker.state = BreakerClosed
		}
	} else {
		breaker.failureCount++
		breaker.lastFailureTime = time.Now()
		if breaker.failureCount >= breaker.failureThreshold {
			breaker.state = BreakerOpen
			breaker.nextAttemptTime = time.Now().Add(breaker.resetDuration)
		}
	}
}

// --- Kill Budget Status ---

// KillBudgetStatus represents the current kill budget status.
type KillBudgetStatus struct {
	HourlyUsed   int       `json:"hourly_used"`
	HourlyLimit  int       `json:"hourly_limit"`
	DailyUsed    int       `json:"daily_used"`
	DailyLimit   int       `json:"daily_limit"`
	LastKillTime time.Time `json:"last_kill_time"`
	CanKill      bool      `json:"can_kill"`
}

// GetKillBudgetStatus returns the current kill budget status.
func (sm *SafetyManager) GetKillBudgetStatus() KillBudgetStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)
	hourlyCount := 0
	for _, r := range sm.killHistory {
		if r.Timestamp.After(oneHourAgo) {
			hourlyCount++
		}
	}
	oneDayAgo := now.Add(-24 * time.Hour)
	dailyCount := 0
	for _, r := range sm.killHistory {
		if r.Timestamp.After(oneDayAgo) {
			dailyCount++
		}
	}

	canKill := hourlyCount < sm.cfg.KillBudgetHourly &&
		dailyCount < sm.cfg.KillBudgetDaily &&
		(sm.lastKillTime.IsZero() || now.Sub(sm.lastKillTime) >= sm.cfg.KillMinInterval.Duration()) &&
		!sm.emergencyStop &&
		sm.breakers["kill"] != nil && sm.breakers["kill"].state != BreakerOpen

	return KillBudgetStatus{
		HourlyUsed:   hourlyCount,
		HourlyLimit:  sm.cfg.KillBudgetHourly,
		DailyUsed:    dailyCount,
		DailyLimit:   sm.cfg.KillBudgetDaily,
		LastKillTime: sm.lastKillTime,
		CanKill:      canKill,
	}
}

// --- Auto Emergency Stop Triggers ---

// CheckAutoEmergencyStop checks conditions that should auto-trigger emergency stop.
// §8.11.6: 4 conditions that automatically activate emergency stop.
func (sm *SafetyManager) CheckAutoEmergencyStop() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	// Condition 1: > 10 kills in 1 hour
	killCount := 0
	for _, r := range sm.killHistory {
		if r.Timestamp.After(oneHourAgo) {
			killCount++
		}
	}
	if killCount > 10 {
		sm.emergencyStop = true
		sm.emergencyStopReason = fmt.Sprintf("auto: %d kills in 1 hour (> 10)", killCount)
		return true
	}

	// Condition 2: Agent Panic count > 3 per hour
	if sm.panicCount > 3 {
		sm.emergencyStop = true
		sm.emergencyStopReason = fmt.Sprintf("auto: %d panics in 1 hour (> 3)", sm.panicCount)
		return true
	}

	// Condition 3: System got worse within 5 min after a Kill
	// (CPU higher or more services abnormal after Kill)
	// 只比较最近 10 分钟内的快照：此前快照从不过期，一旦出现过一次
	// "Kill 后变差"，此后每次调用都会重新触发紧急停止（且无自动恢复），
	// 造成扫描/修复永久静默停摆。
	const killCompareWindow = 10 * time.Minute
	if len(sm.preKillSysState) > 0 && len(sm.postKillSysState) > 0 {
		for i := range sm.preKillSysState {
			pre := sm.preKillSysState[i]
			if now.Sub(pre.Timestamp) > killCompareWindow {
				continue // 过期快照不再参与判定
			}
			for j := range sm.postKillSysState {
				post := sm.postKillSysState[j]
				if post.Timestamp.Before(pre.Timestamp) || post.Timestamp.Sub(pre.Timestamp) > killCompareWindow {
					continue
				}
				if post.CPUPercent > pre.CPUPercent*1.2 || post.AbnormalServices > pre.AbnormalServices {
					sm.emergencyStop = true
					sm.emergencyStopReason = "auto: system got worse after Kill"
					return true
				}
			}
		}
	}

	// Condition 4: 3 consecutive rollback failures
	if sm.consecutiveRollbackFailures >= 3 {
		sm.emergencyStop = true
		sm.emergencyStopReason = fmt.Sprintf("auto: %d consecutive rollback failures", sm.consecutiveRollbackFailures)
		return true
	}

	return false
}

// RecordPanic records a panic occurrence for auto emergency stop tracking.
func (sm *SafetyManager) RecordPanic() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.panicCount++
}

// ResetPanicCount resets the panic counter (called hourly).
func (sm *SafetyManager) ResetPanicCount() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.panicCount = 0
}

// RecordRollbackFailure records a rollback failure.
func (sm *SafetyManager) RecordRollbackFailure() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consecutiveRollbackFailures++
}

// ResetRollbackFailures resets the consecutive rollback failure counter.
func (sm *SafetyManager) ResetRollbackFailures() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consecutiveRollbackFailures = 0
}

// RecordPreKillState records system state before a Kill for comparison.
func (sm *SafetyManager) RecordPreKillState(cpuPercent float64, abnormalServices int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.preKillSysState = append(sm.preKillSysState, sysStateSnapshot{
		CPUPercent:       cpuPercent,
		AbnormalServices: abnormalServices,
		Timestamp:        time.Now(),
	})
	// Keep only last 10
	if len(sm.preKillSysState) > 10 {
		sm.preKillSysState = sm.preKillSysState[1:]
	}
}

// RecordPostKillState records system state after a Kill for comparison.
func (sm *SafetyManager) RecordPostKillState(cpuPercent float64, abnormalServices int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.postKillSysState = append(sm.postKillSysState, sysStateSnapshot{
		CPUPercent:       cpuPercent,
		AbnormalServices: abnormalServices,
		Timestamp:        time.Now(),
	})
	if len(sm.postKillSysState) > 10 {
		sm.postKillSysState = sm.postKillSysState[1:]
	}
}

// sysStateSnapshot records system state at a point in time.
type sysStateSnapshot struct {
	CPUPercent       float64
	AbnormalServices int
	Timestamp        time.Time
}

// getDefaultHardWhitelist returns the OS-specific hard whitelist.
// These processes can NEVER be killed by ServerGuard, period.
// Linux 下合并宝塔生态全量白名单 BaotaProcessWhitelist。
func getDefaultHardWhitelist() map[string]bool {
	list := map[string]bool{
		"serverguard-agent":     true,
		"serverguard-agent.exe": true,
	}

	if runtime.GOOS == "windows" {
		// Windows system
		list["System"] = true
		list["smss.exe"] = true
		list["csrss.exe"] = true
		list["wininit.exe"] = true
		list["winlogon.exe"] = true
		list["services.exe"] = true
		list["lsass.exe"] = true
		list["svchost.exe"] = true

		// IIS and web servers
		list["w3svc"] = true
		list["iisexpress.exe"] = true
		list["nginx.exe"] = true
		list["httpd.exe"] = true

		// Windows databases
		list["sqlservr.exe"] = true
		list["mysqld.exe"] = true
		list["postgres.exe"] = true
		list["redis-server.exe"] = true

		// PHP
		list["php-cgi.exe"] = true
		list["php.exe"] = true
	} else {
		// Linux system — 合并宝塔生态全量白名单
		for _, name := range BaotaProcessWhitelist {
			list[name] = true
		}

		// 额外补充：系统进程名变体
		list["systemd-logind"] = true
		list["dbus-daemon"] = true
		list["init"] = true
		list["kthreadd"] = true
		list["docker-proxy"] = true
		list["caddy"] = true
		list["proftpd"] = true
		list["panelSite.py"] = true
	}

	return list
}

// EnsureTrashDir creates the trash directory.
func (sm *SafetyManager) EnsureTrashDir() error {
	return os.MkdirAll(sm.cfg.TrashDir, 0750)
}

// --- BaotaSafeMode 宝塔环境适配 ---

// SetBaotaSafeMode 启用或禁用宝塔环境适配。
// 适配内容仅限"与宝塔共存"的环境行为：不调用 bt CLI / 不直读面板 SQLite、
// 不直接操作 iptables（与宝塔防火墙插件共存）、日志轮转豁免 /www/ 路径、
// 采集降频与轻量探测等。
// 进程 Kill 保护不走此开关 —— 由 IsBaotaProtectedProcess 精确归属识别无条件兜底。
func (sm *SafetyManager) SetBaotaSafeMode(enabled bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.baotaSafeMode = enabled
}

// IsBaotaSafeMode 返回宝塔环境适配是否已启用。
func (sm *SafetyManager) IsBaotaSafeMode() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.baotaSafeMode
}

// PanelRelief 返回宝塔面板释压重启控制器。
func (sm *SafetyManager) PanelRelief() *PanelReliefController {
	return sm.panelRelief
}
