package notifier

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// EscalationManager P0 告警升级管理器。
// P0 告警 5min 未确认→升级全渠道再推送，30min 未确认→通知第二联系人。
type EscalationManager struct {
	mu            sync.Mutex
	trackedAlerts map[string]*escalationState // alertID -> state
	escalateAfter time.Duration               // 5min
	notifyAfter   time.Duration               // 30min
}

type escalationState struct {
	AlertID     string
	Alert       types.Alert
	FirstSent   time.Time
	Escalated   bool // 5min 升级
	Notified2nd bool // 30min 通知第二联系人
}

// NewEscalationManager 创建告警升级管理器。
func NewEscalationManager() *EscalationManager {
	return &EscalationManager{
		trackedAlerts: make(map[string]*escalationState),
		escalateAfter: 5 * time.Minute,
		notifyAfter:   30 * time.Minute,
	}
}

// Track 跟踪一个 P0 告警。
func (m *EscalationManager) Track(alert types.Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if alert.Level != types.AlertFatal {
		return
	}
	m.trackedAlerts[alert.ID] = &escalationState{
		AlertID:   alert.ID,
		Alert:     alert,
		FirstSent: time.Now(),
	}
}

// CheckAndEscalate 检查并执行升级，返回需要升级的告警列表。
func (m *EscalationManager) CheckAndEscalate() []types.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var toEscalate []types.Alert

	for id, state := range m.trackedAlerts {
		elapsed := now.Sub(state.FirstSent)

		if !state.Escalated && elapsed >= m.escalateAfter {
			state.Escalated = true
			toEscalate = append(toEscalate, state.Alert)
		}

		if !state.Notified2nd && elapsed >= m.notifyAfter {
			state.Notified2nd = true
			toEscalate = append(toEscalate, state.Alert)
		}

		// 超过 1h 清理
		if elapsed > 1*time.Hour {
			delete(m.trackedAlerts, id)
		}
	}

	return toEscalate
}

// MarkConfirmed 标记告警已确认。
func (m *EscalationManager) MarkConfirmed(alertID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.trackedAlerts, alertID)
}

// GetTrackedAlerts 返回被跟踪的告警。
func (m *EscalationManager) GetTrackedAlerts() []types.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []types.Alert
	for _, state := range m.trackedAlerts {
		result = append(result, state.Alert)
	}
	return result
}

// TimeZoneDelay 时区感知延迟推送。
// 凌晨 0-6 点 P2/P3 告警入延迟队列，8 点统一推送。
type TimeZoneDelay struct {
	mu         sync.Mutex
	delayQueue []types.Alert
	quietStart int // 静默开始小时（0）
	quietEnd   int // 静默结束小时（6）
	flushHour  int // 推送小时（8）
}

// NewTimeZoneDelay 创建时区感知延迟器。
func NewTimeZoneDelay() *TimeZoneDelay {
	return &TimeZoneDelay{
		quietStart: 0,
		quietEnd:   6,
		flushHour:  8,
	}
}

// ShouldDelay 判断告警是否应延迟推送。
func (t *TimeZoneDelay) ShouldDelay(alert types.Alert, now time.Time) bool {
	if alert.Level == types.AlertFatal || alert.Level == types.AlertCritical {
		return false // P0/P1 立即推送
	}
	hour := now.Hour()
	return hour >= t.quietStart && hour < t.quietEnd
}

// Enqueue 将告警入延迟队列。
func (t *TimeZoneDelay) Enqueue(alert types.Alert) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.delayQueue = append(t.delayQueue, alert)
}

// Flush 刷新延迟队列，返回应推送的告警列表。
func (t *TimeZoneDelay) Flush(now time.Time) []types.Alert {
	t.mu.Lock()
	defer t.mu.Unlock()

	if now.Hour() < t.flushHour {
		return nil
	}

	result := t.delayQueue
	t.delayQueue = nil
	return result
}

// GetQueueSize 返回延迟队列大小。
func (t *TimeZoneDelay) GetQueueSize() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.delayQueue)
}

// String 返回状态。
func (t *TimeZoneDelay) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return fmt.Sprintf("TimeZoneDelay{queue: %d alerts}", len(t.delayQueue))
}
