// Package posture 实现全局态势感知引擎——程序的"大脑"。
//
// 设计目标：让 Agent 知道自己什么时候该做什么、不该做什么。
// 它在 SafetyManager 的"自我节流"（4 档采集降频）之上，增加一层
// 面向任务调度的系统态势判定，回答四个问题：
//
//  1. 什么时候加大扫描强度？ —— 空闲窗口（PostureIdle）：CPU/内存宽裕且
//     无未消化告警时，安全扫描加密、预测类任务提前跑。
//  2. 什么时候收紧资源占用？ —— 资源紧张（PostureBusy）/危急（PostureCrisis）：
//     重任务推迟、维护类让路、危急时全部扫描挂起只保命。
//  3. 什么时候全力抵抗攻击？ —— 战时（PostureCombat）：检测到持续攻击信号后，
//     安全扫描提频约 3 倍，非安全任务全部让路；攻击平息并经过保持期后自动退出。
//  4. 什么时候自动处置 vs 等用户确认？ —— AutoResolve() 偏置：
//     战时对低风险安全动作自动提级（攻击不等人），危急时只告警不动作。
//
// 判定优先级（高→低）：
// 急停/Crisis(最小·存活模式) > Combat(攻击进行中) > Busy(节流模式) > Idle > Normal
package posture

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// Posture 系统态势。
type Posture string

const (
	// PostureIdle 空闲窗口：资源宽裕、无活跃威胁。适合做平时舍不得做的重活。
	PostureIdle Posture = "idle"
	// PostureNormal 常规运行：按默认节奏执行一切任务。
	PostureNormal Posture = "normal"
	// PostureBusy 资源紧张：对应 Throttled 模式或高负载。收紧资源占用。
	PostureBusy Posture = "busy"
	// PostureCrisis 危急：对应 Minimal/Survival/急停。只保命+告警，一切扫描挂起。
	PostureCrisis Posture = "crisis"
	// PostureCombat 战时：正在被攻击。全力抵抗，安全优先、其余让路。
	PostureCombat Posture = "combat"
)

// TaskClass 任务类别——不同态势下各类别有不同的调度策略。
type TaskClass string

const (
	// TaskSecurityScan 安全扫描（Y/X/W/Z 模块）。战时提频，空闲加密，危急挂起。
	TaskSecurityScan TaskClass = "security_scan"
	// TaskMaintenance 维护类（磁盘清理/日志轮转/备份校验/数据治理）。
	// 忙时与战时推迟——它们重要但不紧急。
	TaskMaintenance TaskClass = "maintenance"
	// TaskPredict 预测分析类（磁盘预测/内存泄漏采样/APM 分析）。
	// 典型的"有空再做"任务：空闲提前，紧张推迟。
	TaskPredict TaskClass = "predict"
)

// Bias 自动处置偏置——告诉 Decider 此刻"直接处理给报告"还是"等用户决定"。
type Bias int

const (
	// BiasNormal 正常：按规则配置的确认要求执行。
	BiasNormal Bias = iota
	// BiasCombatAuto 战时自动提级：低风险安全动作跳过人工确认直接处置
	// （攻击进行中，5 分钟确认超时等于放任攻击者），事后报告中说明。
	BiasCombatAuto
)

// 态势判定阈值与参数。
const (
	// idleCPUPct CPU 低于此值视为空闲候选。
	idleCPUPct = 25.0
	// idleLoadFactor 每核负载低于此值视为无压力。
	idleLoadFactor = 0.5
	// idleMinAvailMB 空闲判定要求的最低可用内存（小内存机器自适应放宽见 memFloorForIdle）。
	idleMinAvailMB = 512.0
	// idleConfirmSamples 连续 N 个采样周期满足空闲条件才进入 Idle（防抖，避免毛刺误判）。
	idleConfirmSamples = 3
	// busyLoadFactor 每核负载超过此值视为繁忙。
	busyLoadFactor = 2.0
	// combatHold 攻击信号静默后战时状态保持时长（滞后退出，防止攻停即退导致反复横跳）。
	combatHold = 15 * time.Minute
)

// Engine 态势感知引擎。并发安全。
type Engine struct {
	mu sync.Mutex

	// 最新一次系统指标（fast tick 喂入）
	cpu         float64
	memAvailMB  float64
	loadFactor  float64
	agentMode   types.AgentMode
	emergencySt bool

	// 战时状态
	attackUntil  time.Time // 战时保持到该时刻（每次攻击信号续期）
	lastAttackAt time.Time
	attackHits   int // 累计攻击信号数（诊断用）

	// 空闲防抖计数
	idleStreak int

	// 手动覆盖：用户强制锁定态势（如远程下发 posture.override），到期自动失效
	override *overrideState

	// 自主行为时间线：记录每次态势转换（容量截断，供报告/API 展示"程序做了什么"）
	timeline []TimelineEntry

	current Posture
	reason  string
	since   time.Time

	// onTransition 态势转换回调（main.go 注入：发事件+打日志，让用户看见"程序知道自己在干嘛"）
	onTransition func(from, to Posture, reason string)

	// nowFunc 时钟源（测试可注入假时钟）
	nowFunc func() time.Time
}

// New 创建引擎，初始态势 Normal。onTransition 可为 nil。
func New(onTransition func(from, to Posture, reason string)) *Engine {
	return &Engine{
		current:      PostureNormal,
		reason:       "启动默认",
		since:        time.Now(),
		agentMode:    types.ModeNormal,
		onTransition: onTransition,
		nowFunc:      time.Now,
	}
}

// now 返回当前时钟（调用方需持锁）。
func (e *Engine) now() time.Time {
	if e.nowFunc != nil {
		return e.nowFunc()
	}
	return time.Now()
}

// OverrideState 手动覆盖状态快照。
type OverrideState struct {
	Posture Posture `json:"posture"`
	Until   string  `json:"until"`
	Reason  string  `json:"reason"`
}

// overrideState 内部覆盖记录。
type overrideState struct {
	p      Posture
	until  time.Time
	reason string
}

// 合法覆盖时长上限：防止误操作把态势锁死过久（到期自动失效回归自动判定）。
const maxOverrideDuration = 24 * time.Hour

// SetOverride 手动锁定态势。用户/Hub 远程命令强制指定运行策略，
// 例如维护期间强制 normal 避免空闲判定插队，或演练时强制 combat。
// duration 超过 24h 会被夹紧；到时后自动回归自动判定。
func (e *Engine) SetOverride(p Posture, d time.Duration, reason string) {
	if d <= 0 {
		d = 30 * time.Minute
	}
	if d > maxOverrideDuration {
		d = maxOverrideDuration
	}
	e.mu.Lock()
	now := e.now()
	e.override = &overrideState{p: p, until: now.Add(d), reason: reason}
	e.mu.Unlock()

	e.recompute()
}

// ClearOverride 解除手动覆盖。
func (e *Engine) ClearOverride() {
	e.mu.Lock()
	e.override = nil
	e.mu.Unlock()

	e.recompute()
}

// TimelineEntry 自主行为时间线条目。
type TimelineEntry struct {
	At     string  `json:"at"`
	From   Posture `json:"from"`
	To     Posture `json:"to"`
	Reason string  `json:"reason"`
}

// timelineCap 时间线上限——足够回溯一天的关键决策，又不会无限增长。
const timelineCap = 200

// Timeline 返回最近的态势转换时间线（旧的在前）。
func (e *Engine) Timeline() []TimelineEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]TimelineEntry, len(e.timeline))
	copy(out, e.timeline)
	return out
}

// UpdateSystem 每 fast tick 喂入最新系统指标，并重算态势。
func (e *Engine) UpdateSystem(cpuPercent, memAvailableMB, loadFactor float64) {
	e.mu.Lock()
	e.cpu = cpuPercent
	e.memAvailMB = memAvailableMB
	e.loadFactor = loadFactor
	e.mu.Unlock()

	e.recompute()
}

// SetAgentState 同步 SafetyManager 的节流模式与急停状态（SafetyManager 是唯一裁决方，此处只读镜像）。
func (e *Engine) SetAgentState(mode types.AgentMode, emergencyStopped bool) {
	e.mu.Lock()
	e.agentMode = mode
	e.emergencySt = emergencyStopped
	e.mu.Unlock()

	e.recompute()
}

// ObserveSecurityEvent 报告一次攻击信号（来自 attackwarn/security 类 error+ 告警）。
// 每次信号都会续期战时保持窗口；持续被攻击时叠加续期但有上限封顶。
func (e *Engine) ObserveSecurityEvent(now time.Time) {
	e.mu.Lock()
	e.lastAttackAt = now
	if now.After(e.attackUntil) {
		e.attackUntil = now.Add(combatHold)
	} else {
		e.attackUntil = e.attackUntil.Add(combatHold / 2) // 持续被攻击：半额叠加
	}
	if until := now.Add(combatHold); e.attackUntil.After(until) {
		e.attackUntil = until // 封顶：不会因高频信号无限延长
	}
	e.attackHits++
	e.mu.Unlock()

	e.recompute()
}

// Current 返回当前态势。
func (e *Engine) Current() Posture {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current
}

// Reason 返回进入当前态势的原因（人话，用于日志与报告）。
func (e *Engine) Reason() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reason
}

// Since 返回当前态势的起始时间。
func (e *Engine) Since() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.since
}

// AutoResolve 返回当前自动处置偏置，供 Decider 决定"直接处理还是等用户确认"。
func (e *Engine) AutoResolve() Bias {
	if e.Current() == PostureCombat {
		return BiasCombatAuto
	}
	return BiasNormal
}

// AllowTask 判断某类别任务此刻是否允许执行。
// Crisis 下所有任务一律禁止（保命优先）；Combat 下仅安全类可跑，其余让路。
func (e *Engine) AllowTask(class TaskClass) bool {
	switch e.Current() {
	case PostureCrisis:
		return false // 保命：全部挂起——连 Agent 都快死了，扫描只会雪上加霜
	case PostureCombat:
		return class == TaskSecurityScan // 战时只做安全相关的事
	default:
		return true
	}
}

// ShouldDefer 某类别任务此刻是否应推迟（允许但不划算——把资源留给正事）。
// 推迟的任务会在态势回到 Normal/Idle 后由既有轮转自然补跑。
func (e *Engine) ShouldDefer(class TaskClass) bool {
	switch e.Current() {
	case PostureBusy, PostureCombat:
		return class != TaskSecurityScan // 紧张/战时只有安全扫描照跑，其余推迟
	case PostureCrisis:
		return true // 危急：一切推迟（AllowTask 已全禁，此处保持语义一致）
	default:
		return false
	}
}

// ScanMultiplier 返回安全扫描的间隔倍率：<1 提频，>1 降频。
//
//	Idle:   x0.5 （机器闲着，多扫两遍没坏处）
//	Normal: x1.0 （默认节奏）
//	Busy:   x2.0 （收紧，但不能完全停——安全不能断）
//	Crisis: x3.0 （名义值，实际已被 AllowTask 全禁）
//	Combat: x1/3 （全力抵抗：约 3 倍频）
func (e *Engine) ScanMultiplier() float64 {
	switch e.Current() {
	case PostureIdle:
		return 0.5
	case PostureBusy:
		return 2.0
	case PostureCrisis:
		return 3.0
	case PostureCombat:
		return 1.0 / 3.0
	default:
		return 1.0
	}
}

// Snapshot 完整态势快照（供 API/报告展示）。
type Snapshot struct {
	Posture     Posture        `json:"posture"`
	Reason      string         `json:"reason"`
	Since       string         `json:"since"`
	CPUPercent  float64        `json:"cpu_percent"`
	MemAvailMB  float64        `json:"mem_available_mb"`
	LoadFactor  float64        `json:"load_factor"`
	AgentMode   string         `json:"agent_mode"`
	UnderAttack bool           `json:"under_attack"`
	AttackHits  int            `json:"attack_signals_total"`
	AutoBias    string         `json:"auto_resolve_bias"`
	Override    *OverrideState `json:"override,omitempty"`
}

// Describe 生成当前快照。
func (e *Engine) Describe() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	bias := "normal"
	if e.current == PostureCombat {
		bias = "combat_auto"
	}
	var ov *OverrideState
	if e.override != nil && e.now().Before(e.override.until) {
		ov = &OverrideState{
			Posture: e.override.p,
			Until:   e.override.until.Format(time.RFC3339),
			Reason:  e.override.reason,
		}
	}
	return Snapshot{
		Posture:     e.current,
		Reason:      e.reason,
		Since:       e.since.Format(time.RFC3339),
		CPUPercent:  e.cpu,
		MemAvailMB:  e.memAvailMB,
		LoadFactor:  e.loadFactor,
		AgentMode:   string(e.agentMode),
		UnderAttack: e.now().Before(e.attackUntil),
		AttackHits:  e.attackHits,
		AutoBias:    bias,
		Override:    ov,
	}
}

// memFloorForIdle 空闲判定的内存门槛：小内存机器自适应放宽。
// 1G 内存的机器可用内存常年只有两三百 MB，若死守 512MB 门槛就永远进不了 Idle。
func memFloorForIdle(memAvailMB float64) float64 {
	if memAvailMB >= idleMinAvailMB {
		return idleMinAvailMB
	}
	if memAvailMB >= 256 {
		return 256 // 小内存机器：256MB 以上即视为宽裕
	}
	return -1 // 可用内存 <256MB 不可能算空闲
}

// isIdleCandidate 判断当前指标是否满足空闲候选条件（调用方需持锁）。
func (e *Engine) isIdleCandidate() bool {
	if e.memAvailMB <= 0 {
		return false // 尚未喂入真实指标（初始零值），不参与空闲判定
	}
	if e.cpu >= idleCPUPct || e.loadFactor >= idleLoadFactor {
		return false
	}
	return e.memAvailMB >= memFloorForIdle(e.memAvailMB)
}

// recompute 核心状态机：按优先级重算态势，发生转换时触发回调。
//
//	优先级：Crisis > Combat > Busy > Idle > Normal
//	Combat 压过 Busy 是有意设计：攻击造成的负载升高恰恰要靠对抗解决，
//	此时收紧安全扫描等于向攻击者投降；真正的资源地板仍由 SafetyManager 兜底。
func (e *Engine) recompute() {
	e.mu.Lock()
	now := e.now()

	// 过期覆盖先清理
	if e.override != nil && !now.Before(e.override.until) {
		e.override = nil
	}

	next := PostureNormal
	var reason string

	switch {
	// ── 0. 手动覆盖：用户意志最高（但危急仍然压过——保命永远第一）──
	case e.override != nil && e.agentMode != types.ModeSurvival && e.agentMode != types.ModeMinimal && !e.emergencySt:
		next = e.override.p
		reason = fmt.Sprintf("手动覆盖：%s（%s，%s 到期）", e.override.reason, next, e.override.until.Format("15:04:05"))

	// ── 1. 危急：急停 / Minimal / Survival —— 一切让位于保命 ──
	case e.emergencySt:
		next, reason = PostureCrisis, "紧急停止已激活"
	case e.agentMode == types.ModeSurvival || e.agentMode == types.ModeMinimal:
		next, reason = PostureCrisis,
			fmt.Sprintf("系统资源危急（mode=%s, CPU=%.0f%%, 可用内存=%.0fMB），仅保留监控与告警", e.agentMode, e.cpu, e.memAvailMB)

	// ── 2. 战时：攻击信号保持期内，全力抵抗 ──
	case now.Before(e.attackUntil):
		next, reason = PostureCombat,
			fmt.Sprintf("检测到持续攻击信号（累计 %d 次，最近 %s），安全扫描提频、非安全任务让路", e.attackHits, e.lastAttackAt.Format("15:04:05"))

	// ── 3. 紧张：Throttled 或高负载 —— 收紧资源占用 ──
	case e.agentMode == types.ModeThrottled || e.loadFactor > busyLoadFactor:
		next, reason = PostureBusy,
			fmt.Sprintf("系统繁忙（mode=%s, CPU=%.0f%%, 负载因子=%.2f），重任务推迟、扫描降密", e.agentMode, e.cpu, e.loadFactor)

	// ── 4. 空闲：资源宽裕 + 无威胁 —— 加大扫描强度（连续采样确认防抖）──
	case e.isIdleCandidate():
		e.idleStreak++
		if e.idleStreak >= idleConfirmSamples || e.current == PostureIdle {
			next = PostureIdle
			reason = fmt.Sprintf("系统空闲（CPU=%.0f%%, 负载因子=%.2f, 可用内存=%.0fMB，无攻击信号），加大扫描强度、补做推迟任务", e.cpu, e.loadFactor, e.memAvailMB)
		} else {
			// 观察中：维持原状，不提交转换
			e.mu.Unlock()
			return
		}

	// ── 5. 默认：常规节奏 ──
	default:
		next, reason = PostureNormal, "常规运行"
	}

	if next != PostureIdle {
		e.idleStreak = 0
	}

	prev := e.current
	e.current = next
	e.reason = reason
	e.since = now
	if prev != next {
		// 记录自主行为时间线（截断防膨胀）
		e.timeline = append(e.timeline, TimelineEntry{
			At:     now.Format(time.RFC3339),
			From:   prev,
			To:     next,
			Reason: reason,
		})
		if len(e.timeline) > timelineCap {
			e.timeline = e.timeline[len(e.timeline)-timelineCap:]
		}
	}
	cb := e.onTransition
	e.mu.Unlock()

	if prev != next && cb != nil {
		cb(prev, next, reason)
	}
}
