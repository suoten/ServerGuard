package resource

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
)

// CPU误杀防护参数
const (
	cpuTriggerThreshold = 3              // 连续触发次数阈值
	cpuCooldownWindow   = 5 * time.Minute // 冷却窗口：5min 内的触发计数有效
)

// cpuTriggerState per-PID CPU 触发计数状态
type cpuTriggerState struct {
	count          int
	firstTrigger   time.Time
	lastTrigger    time.Time
	lastActionTime time.Time // 上次执行 Kill 的时间，用于冷却
}

// CPUTriggerTracker CPU 误杀防护跟踪器。
// 连续 3 次触发（在冷却窗口内）才执行 Kill，首次触发仅告警。
type CPUTriggerTracker struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus
	safety   *safety.SafetyManager
	states   map[int32]*cpuTriggerState // PID -> state
}

// NewCPUTriggerTracker 创建 CPU 触发跟踪器。
func NewCPUTriggerTracker(bus *eventbus.EventBus, sm *safety.SafetyManager) *CPUTriggerTracker {
	return &CPUTriggerTracker{
		eventBus: bus,
		safety:   sm,
		states:   make(map[int32]*cpuTriggerState),
	}
}

// CPUAction CPU 触发后应执行的动作
type CPUAction int

const (
	CPUActionAlertOnly CPUAction = iota // 仅告警
	CPUActionKill                       // 执行 Kill
)

// CheckAndAct 检查 CPU 超限并决定动作。
// 返回应执行的动作类型。连续 3 次触发才返回 Kill，否则返回 AlertOnly。
func (t *CPUTriggerTracker) CheckAndAct(pid int32, name string, cpuPercent, threshold float64) CPUAction {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	state, ok := t.states[pid]
	if !ok {
		state = &cpuTriggerState{}
		t.states[pid] = state
	}

	// 清理冷却窗口外的触发记录
	if now.Sub(state.firstTrigger) > cpuCooldownWindow {
		state.count = 0
		state.firstTrigger = time.Time{}
	}

	// 记数
	if state.count == 0 {
		state.firstTrigger = now
	}
	state.count++
	state.lastTrigger = now

	// 发布告警
	if t.eventBus != nil {
		alertMsg := fmt.Sprintf("进程 %s (PID %d) CPU 使用率 %.1f%% 超过阈值 %.0f%%（第 %d/%d 次触发）",
			name, pid, cpuPercent, threshold, state.count, cpuTriggerThreshold)
		alertTitle := fmt.Sprintf("CPU超限: %s (PID %d)", name, pid)
		if state.count < cpuTriggerThreshold {
			t.eventBus.PublishAlert(types.AlertWarning, "resource", alertTitle, alertMsg, "cpu-protect-001")
		} else {
			t.eventBus.PublishAlert(types.AlertError, "resource", alertTitle,
				alertMsg+"，将达到阈值，准备执行 Kill", "cpu-protect-001")
		}
	}

	// 判断是否达到 Kill 阈值
	if state.count >= cpuTriggerThreshold {
		// 检查 Kill 冷却（避免短时间内重复 Kill 同一进程）
		if !state.lastActionTime.IsZero() && now.Sub(state.lastActionTime) < cpuCooldownWindow {
			return CPUActionAlertOnly
		}
		state.lastActionTime = now
		// 重置计数，开始新一轮
		state.count = 0
		state.firstTrigger = time.Time{}
		return CPUActionKill
	}

	return CPUActionAlertOnly
}

// Reset 重置指定 PID 的触发计数（进程已恢复正常或已被 Kill）。
func (t *CPUTriggerTracker) Reset(pid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, pid)
}

// GetTriggerCount 返回指定 PID 的当前触发计数。
func (t *CPUTriggerTracker) GetTriggerCount(pid int32) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.states[pid]
	if !ok {
		return 0
	}
	// 检查是否在冷却窗口内
	if time.Since(state.firstTrigger) > cpuCooldownWindow {
		return 0
	}
	return state.count
}

// Cleanup 清理过期的触发状态。
func (t *CPUTriggerTracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for pid, state := range t.states {
		if now.Sub(state.lastTrigger) > cpuCooldownWindow && now.Sub(state.lastActionTime) > cpuCooldownWindow {
			delete(t.states, pid)
		}
	}
}

// CheckCPUWithProtection 带误杀防护的 CPU 检查。
// 集成到 ResourceGuard.Check 中使用。
func (t *CPUTriggerTracker) CheckCPUWithProtection(ctx context.Context, procs []types.ProcessInfo, threshold float64) []int32 {
	var toKill []int32
	for _, p := range procs {
		if p.IsSystem {
			continue
		}
		if p.CPUPercent > threshold {
			action := t.CheckAndAct(p.PID, p.Name, p.CPUPercent, threshold)
			if action == CPUActionKill {
				toKill = append(toKill, p.PID)
			}
		} else {
			// CPU 正常，重置计数
			if t.GetTriggerCount(p.PID) > 0 {
				t.Reset(p.PID)
			}
		}
	}
	return toKill
}