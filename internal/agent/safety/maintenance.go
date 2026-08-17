package safety

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
