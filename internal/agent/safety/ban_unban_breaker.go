package safety

import (
	"fmt"
	"sync"
	"time"
)

// BanUnbanBreaker 封禁/解封振荡熔断器。
// 当某个 IP 在短时间内被反复封禁又解封时，说明封禁规则可能误判，
// 熔断器暂停对该 IP 的封禁操作，避免振荡。
type BanUnbanBreaker struct {
	mu sync.Mutex

	// 配置
	unbanThreshold  int           // 窗口内解封次数阈值（默认3）
	windowDuration  time.Duration // 统计窗口（默认10min）
	pauseDuration   time.Duration // 触发后暂停封禁时长（默认1h）

	// per-IP 状态
	ipStates map[string]*banUnbanState
}

type banUnbanState struct {
	unbanTimes    []time.Time // 窗口内解封时间记录
	pausedUntil   time.Time   // 暂停封禁截止时间
	pauseCount    int         // 历史暂停次数
}

// NewBanUnbanBreaker 创建封禁振荡熔断器。
func NewBanUnbanBreaker() *BanUnbanBreaker {
	return &BanUnbanBreaker{
		unbanThreshold: 3,
		windowDuration: 10 * time.Minute,
		pauseDuration:  1 * time.Hour,
		ipStates:       make(map[string]*banUnbanState),
	}
}

// RecordUnban 记录一次解封事件。
func (b *BanUnbanBreaker) RecordUnban(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	state := b.getOrCreateState(ip)
	now := time.Now()

	// 清理窗口外的记录
	cutoff := now.Add(-b.windowDuration)
	var recent []time.Time
	for _, t := range state.unbanTimes {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	state.unbanTimes = recent

	// 检查是否达到阈值
	if len(recent) >= b.unbanThreshold {
		state.pausedUntil = now.Add(b.pauseDuration)
		state.pauseCount++
		// 清空窗口记录，开始新一轮
		state.unbanTimes = nil
	}
}

// CanBan 检查是否允许封禁指定 IP。
func (b *BanUnbanBreaker) CanBan(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	state, ok := b.ipStates[ip]
	if !ok {
		return true
	}
	return time.Now().After(state.pausedUntil)
}

// PauseReason 返回暂停封禁的原因，若未暂停返回空字符串。
func (b *BanUnbanBreaker) PauseReason(ip string) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	state, ok := b.ipStates[ip]
	if !ok {
		return ""
	}
	if time.Now().Before(state.pausedUntil) {
		remaining := time.Until(state.pausedUntil).Round(time.Minute)
		return fmt.Sprintf("IP %s 在 %s 内被解封 %d 次，触发振荡熔断，暂停封禁 %s（剩余 %s）",
			ip, b.windowDuration, b.unbanThreshold, b.pauseDuration, remaining)
	}
	return ""
}

// getOrCreateState 获取或创建 IP 状态（调用方需持有锁）
func (b *BanUnbanBreaker) getOrCreateState(ip string) *banUnbanState {
	state, ok := b.ipStates[ip]
	if !ok {
		state = &banUnbanState{}
		b.ipStates[ip] = state
	}
	return state
}

// Cleanup 清理过期的 IP 状态记录，避免内存泄漏。
func (b *BanUnbanBreaker) Cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for ip, state := range b.ipStates {
		// 暂停已过期且无解封记录，可清理
		if now.After(state.pausedUntil) && len(state.unbanTimes) == 0 {
			delete(b.ipStates, ip)
		}
	}
}

// Stats 返回熔断器统计信息。
func (b *BanUnbanBreaker) Stats() (totalIPs int, pausedIPs int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for _, state := range b.ipStates {
		totalIPs++
		if now.Before(state.pausedUntil) {
			pausedIPs++
		}
	}
	return
}