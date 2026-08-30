package safety

import (
	"fmt"
	"time"
)

// MaintenanceProvider 由外部（API 层）注入，用于判断当前是否处于维护窗口期。
// 维护窗口期内：所有自动修复动作暂停（ShouldPauseActions/ShouldPauseDangerousActions 返回 true），
// 但监控采集、告警记录、通知推送不受影响——"只暂停动作，不蒙上眼睛"。
type MaintenanceProvider func() bool

// SetMaintenanceProvider 注入维护窗口判定回调（线程安全）。
func (sm *SafetyManager) SetMaintenanceProvider(p MaintenanceProvider) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.maintenanceProvider = p
}

// IsInMaintenance 返回当前是否处于维护窗口期。
func (sm *SafetyManager) IsInMaintenance() bool {
	sm.mu.RLock()
	p := sm.maintenanceProvider
	sm.mu.RUnlock()
	if p == nil {
		return false
	}
	return p()
}

// SetRemotePaused 远程暂停自动修复（双向通知回复"暂停"后调用）。
// 暂停后 ShouldPauseActions 返回 true，所有自动修复动作停止执行。
// 监控采集和告警推送不受影响。
func (sm *SafetyManager) SetRemotePaused(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.remotePaused = true
	sm.remotePausedReason = reason
	sm.remotePausedAt = time.Now()
}

// ClearRemotePaused 恢复自动修复（双向通知回复"恢复"后调用）。
func (sm *SafetyManager) ClearRemotePaused() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.remotePaused = false
	sm.remotePausedReason = ""
}

// IsRemotePaused 返回当前是否被远程暂停。
func (sm *SafetyManager) IsRemotePaused() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.remotePaused
}

// RemotePausedInfo 返回远程暂停的详细信息。
func (sm *SafetyManager) RemotePausedInfo() (bool, string, time.Time) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.remotePaused, sm.remotePausedReason, sm.remotePausedAt
}

// FormatRemotePausedReason 格式化远程暂停原因（供状态面板展示）。
func (sm *SafetyManager) FormatRemotePausedReason() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if !sm.remotePaused {
		return ""
	}
	return fmt.Sprintf("远程暂停（%s，暂停于 %s）", sm.remotePausedReason, sm.remotePausedAt.Format("15:04:05"))
}

