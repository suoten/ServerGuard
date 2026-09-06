package safety

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// PostKillEvaluator Kill 后系统对比评估器。
// Kill 前记录系统快照（CPU/内存/负载），5min 后对比，
// 若系统状态更差则触发自动紧急停止。
type PostKillEvaluator struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus

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
	}
}

// captureSysState 采集当前系统状态快照。
func (e *PostKillEvaluator) captureSysState() postKillSysState {
	// 使用 runtime 采集基本信息
	// 完整实现会调用 collector 获取精确值
	return postKillSysState{
		Timestamp: time.Now(),
	}
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
