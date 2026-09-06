package safety

import (
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// PostKillEvaluator Kill 后系统对比评估器。
// Kill 前记录系统快照（CPU/内存/负载），5min 后对比，
// 若系统状态更差则触发自动紧急停止（Do No Harm：修完更糟说明修错了）。
type PostKillEvaluator struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus
	safety   *SafetyManager // 触发紧急停止用（SetSafetyManager 注入）

	// 待评估的 Kill 记录
	pendingEvals map[string]*pendingEval // key = evalID
}

type pendingEval struct {
	ID           string
	KillTime     time.Time
	PreKillState postKillSysState
	Target       string // 被Kill的进程名
	EvalDone     bool
}

// postKillSysState Kill 后评估用的系统状态快照
type postKillSysState struct {
	CPUPercent     float64
	MemAvailableMB float64
	LoadAvg        float64
	Timestamp      time.Time
}

// NewPostKillEvaluator 创建 Kill 后评估器。
func NewPostKillEvaluator(bus *eventbus.EventBus) *PostKillEvaluator {
	return &PostKillEvaluator{
		eventBus:     bus,
		pendingEvals: make(map[string]*pendingEval),
	}
}

// SetSafetyManager 注入安全管理器：评估发现"越修越糟"时真正触发紧急停止。
func (e *PostKillEvaluator) SetSafetyManager(sm *SafetyManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.safety = sm
}

// RecordPreKillStateAuto 自动采集当前系统状态并登记 Kill 前快照。
// 供 executor 在执行 Kill 前一行调用，无需调用方自己采集指标。
func (e *PostKillEvaluator) RecordPreKillStateAuto(target string) string {
	pre := e.captureSysState()
	if pre.Timestamp.IsZero() {
		return "" // 采集失败，跳过本轮评估（宁可少评估不发假告警）
	}
	return e.RecordPreKillState(target, pre.CPUPercent, pre.MemAvailableMB, pre.LoadAvg)
}

// RecordPreKillState 记录 Kill 前系统状态，启动 5min 定时评估。
// cpuPercent: 当前CPU使用率, memAvailableMB: 可用内存, loadAvg: 负载均值
func (e *PostKillEvaluator) RecordPreKillState(target string, cpuPercent, memAvailableMB, loadAvg float64) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	evalID := fmt.Sprintf("eval-%d", time.Now().UnixNano())
	state := postKillSysState{
		CPUPercent:     cpuPercent,
		MemAvailableMB: memAvailableMB,
		LoadAvg:        loadAvg,
		Timestamp:      time.Now(),
	}

	e.pendingEvals[evalID] = &pendingEval{
		ID:           evalID,
		KillTime:     time.Now(),
		PreKillState: state,
		Target:       target,
	}

	// 启动 5min 后的评估 Goroutine
	go e.scheduleEvaluation(evalID, 5*time.Minute)

	return evalID
}

// scheduleEvaluation 定时执行评估。
func (e *PostKillEvaluator) scheduleEvaluation(evalID string, delay time.Duration) {
	time.Sleep(delay)
	e.Evaluate(evalID)
}

// Evaluate 执行 Kill 后系统对比评估。
// currentCPU, currentMem, currentLoad: 当前系统状态
func (e *PostKillEvaluator) Evaluate(evalID string) {
	e.mu.Lock()
	eval, ok := e.pendingEvals[evalID]
	if !ok || eval.EvalDone {
		e.mu.Unlock()
		return
	}
	eval.EvalDone = true
	preState := eval.PreKillState
	target := eval.Target
	// 评估已完成，从 map 中移除，避免长期运行下 pendingEvals 无界增长
	delete(e.pendingEvals, evalID)
	e.mu.Unlock()

	// 采集当前系统状态
	currentState := e.captureSysState()

	// 采集失败（全零快照）时跳过对比——与零值比较恒为"更差"，
	// 会给每次 kill 都发假告警，比不评估危害更大
	if currentState.Timestamp.IsZero() || (currentState.CPUPercent == 0 && currentState.MemAvailableMB == 0 && currentState.LoadAvg == 0) {
		return
	}

	// 对比：如果 Kill 后系统更差，触发紧急停止
	worse := e.isSystemWorse(preState, currentState)

	if worse {
		reason := fmt.Sprintf("Kill %s 后系统状态更差: CPU %.1f→%.1f%%, 可用内存 %.0f→%.0fMB, 负载 %.2f→%.2f",
			target,
			preState.CPUPercent, currentState.CPUPercent,
			preState.MemAvailableMB, currentState.MemAvailableMB,
			preState.LoadAvg, currentState.LoadAvg,
		)
		if e.eventBus != nil {
			e.eventBus.PublishAlert(types.AlertCritical, "safety",
				"Kill后系统恶化，触发紧急停止",
				reason,
				"post-kill-eval-001")
		}
		// 真正触发紧急停止——此前只发告警不动作，"越修越糟"的兜底形同虚设
		if e.safety != nil {
			e.safety.TriggerEmergencyStop(false)
		}
	}
}

// captureSysState 采集当前系统状态快照（gopsutil）。
// 任一采集失败返回零值快照，调用方据 Timestamp/全零判断跳过评估。
func (e *PostKillEvaluator) captureSysState() postKillSysState {
	state := postKillSysState{Timestamp: time.Now()}

	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		state.CPUPercent = percents[0]
	} else {
		state.Timestamp = time.Time{}
		return state
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		state.MemAvailableMB = float64(vm.Available) / 1024 / 1024
	} else {
		state.Timestamp = time.Time{}
		return state
	}
	if avg, err := load.Avg(); err == nil {
		state.LoadAvg = avg.Load1
	}
	return state
}

// isSystemWorse 判断 Kill 后系统是否更差。
// 判定标准（满足任一即更差）：
// - CPU 使用率上升超过 20%
// - 可用内存减少超过 100MB
// - 负载上升超过 1.0
func (e *PostKillEvaluator) isSystemWorse(pre, post postKillSysState) bool {
	if post.CPUPercent > pre.CPUPercent+20 {
		return true
	}
	if post.MemAvailableMB < pre.MemAvailableMB-100 {
		return true
	}
	if post.LoadAvg > pre.LoadAvg+1.0 {
		return true
	}
	return false
}

// PendingCount 返回待评估的 Kill 记录数。
func (e *PostKillEvaluator) PendingCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := 0
	for _, eval := range e.pendingEvals {
		if !eval.EvalDone {
			count++
		}
	}
	return count
}

// Cleanup 清理已完成的评估记录。
func (e *PostKillEvaluator) Cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, eval := range e.pendingEvals {
		if eval.EvalDone && time.Since(eval.KillTime) > 30*time.Minute {
			delete(e.pendingEvals, id)
		}
	}
}
