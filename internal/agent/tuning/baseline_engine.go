// Package tuning 提供告警阈值自调优能力。
//
// baseline_engine.go 实现基于历史基线的智能阈值引擎。
// 与旧版 ThresholdTuner（仅基于误报反馈微调 ±step）不同，
// BaselineEngine 通过滑动窗口收集各检测维度的指标样本，
// 计算统计分布（P50/P95/P99 百分位），动态生成阈值。
//
// 核心设计：
//  1. 历史基线学习——每轮记录各 IP 的指标（请求数、404 数、连接数等），
//     维护一个滑动窗口，计算"正常"行为的统计分布
//  2. 动态阈值——阈值 = max(默认下限, P95 * 倍率)
//     流量高峰期 P95 自然升高，阈值随之放宽；深夜低谷 P95 降低，阈值收紧
//  3. 置信度评分——单一维度达标不立即判定攻击，
//     而是多维度交叉验证计算置信度（0-100），>= 阈值才触发
//  4. 渐进式响应——首次触发只观察，连续触发才升级处置
package tuning

import (
	"math"
	"sort"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────
// 基线引擎
// ──────────────────────────────────────────────────────────────────────

// baselineWindow 基线滑动窗口保留的历史轮次数（对应约 10min × 144 = 24h）。
const baselineWindow = 144

// minBaselineSamples 达到该样本数后才启用动态阈值；不足时回退默认值。
const minBaselineSamples = 10

// BaselineSample 单次扫描中某个 IP 的指标快照。
// 不同检测器只填充各自关心的字段，其余为零。
type BaselineSample struct {
	IP           string
	Timestamp    time.Time
	DynamicReq   int  // CC: 动态请求数
	PostCount    int  // CMS爆破: POST次数
	NotFound404  int  // 目录爆破: 404数
	ConnCount    int  // DDoS: 连接数
	SSHFailCount int  // SSH暴破: 失败次数
	PortCount    int  // 端口扫描: 不同端口数
}

// ipHistory 单个 IP 的历史指标序列（环形缓冲）。
type ipHistory struct {
	samples []float64 // 指标值序列（按时间顺序追加，超出容量裁剪头部）
}

// baselineState 单个检测器类型的基线状态。
type baselineState struct {
	mu      sync.Mutex
	history map[string]*ipHistory // IP -> 指标历史
	// 全局分布（跨所有 IP 的指标值），用于冷启动时没有该 IP 历史的 fallback
	globalSamples []float64
}

// BaselineEngine 智能阈值引擎。
//
// 它替代了旧的"固定阈值 + 误报微调"模式：
//   - 旧模式：阈值 = 固定值，仅在误报反馈后 ±step 微调
//   - 新模式：阈值 = max(下限, P95(历史分布) × 倍率)
//     流量高峰时 P95 升高 → 阈值放宽 → 减少误判
//     流量低谷时 P95 降低 → 阈值收紧 → 保持敏感
//
// 线程安全。
type BaselineEngine struct {
	mu      sync.RWMutex
	states  map[string]*baselineState
	window  int
	minSamp int
}

// NewBaselineEngine 创建智能阈值引擎。
func NewBaselineEngine() *BaselineEngine {
	return &BaselineEngine{
		states:  make(map[string]*baselineState),
		window:  baselineWindow,
		minSamp: minBaselineSamples,
	}
}

// getOrCreateState 获取或创建检测器对应的基线状态（不加锁，调用方持锁）。
func (e *BaselineEngine) getOrCreateState(alertType string) *baselineState {
	st := e.states[alertType]
	if st == nil {
		st = &baselineState{
			history: make(map[string]*ipHistory),
		}
		e.states[alertType] = st
	}
	return st
}

// RecordSample 记录一轮扫描中某个 IP 的指标快照。
// 调用方应传入该轮所有 IP 的样本，引擎会自动维护滑动窗口。
func (e *BaselineEngine) RecordSample(alertType string, samples []BaselineSample) {
	e.mu.Lock()
	st := e.getOrCreateState(alertType)
	e.mu.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	for _, s := range samples {
		val := extractMetric(alertType, s)
		if val <= 0 {
			continue
		}

		// 更新该 IP 的历史
		h := st.history[s.IP]
		if h == nil {
			h = &ipHistory{samples: make([]float64, 0, e.window)}
			st.history[s.IP] = h
		}
		h.samples = append(h.samples, val)
		if len(h.samples) > e.window {
			h.samples = h.samples[len(h.samples)-e.window:]
		}

		// 更新全局分布
		st.globalSamples = append(st.globalSamples, val)
		if len(st.globalSamples) > e.window*100 { // 全局上限：窗口 × 100 个 IP
			st.globalSamples = st.globalSamples[len(st.globalSamples)-e.window*100:]
		}
	}
}

// extractMetric 从 BaselineSample 中提取与检测器类型对应的指标值。
func extractMetric(alertType string, s BaselineSample) float64 {
	switch alertType {
	case "cc_attack":
		return float64(s.DynamicReq)
	case "cms_bruteforce":
		return float64(s.PostCount)
	case "dir_bruteforce":
		return float64(s.NotFound404)
	case "ddos_suspected":
		return float64(s.ConnCount)
	case "ssh_brute_force":
		return float64(s.SSHFailCount)
	case "port_scan":
		return float64(s.PortCount)
	default:
		return 0
	}
}

// SuggestThreshold 智能阈值建议。
//
// 计算逻辑：
//  1. 如果该 IP 有足够的历史样本 → 用该 IP 的 P95 × multiplier
//  2. 如果该 IP 是新面孔但全局有足够样本 → 用全局 P95 × multiplier
//  3. 冷启动（样本不足）→ 返回 defaultValue
//
// 最终值被夹紧在 [hardMin, hardMax] 内。
// multiplier 通常为 2.0~3.0：P95 已经是"正常高峰"，乘以倍率后才算异常。
func (e *BaselineEngine) SuggestThreshold(alertType, ip string, defaultValue, hardMin, hardMax, multiplier float64) float64 {
	e.mu.RLock()
	st := e.states[alertType]
	e.mu.RUnlock()

	if st == nil {
		return clamp(defaultValue, hardMin, hardMax)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// 优先使用该 IP 的历史
	h := st.history[ip]
	if h != nil && len(h.samples) >= e.minSamp {
		p95 := percentile(h.samples, 0.95)
		if p95 > 0 {
			threshold := p95 * multiplier
			return clamp(threshold, hardMin, hardMax)
		}
	}

	// 全局 fallback
	if len(st.globalSamples) >= e.minSamp {
		p95 := percentile(st.globalSamples, 0.95)
		if p95 > 0 {
			threshold := p95 * multiplier
			return clamp(threshold, hardMin, hardMax)
		}
	}

	// 冷启动
	return clamp(defaultValue, hardMin, hardMax)
}

// IPDeviationScore 返回某 IP 当前指标相对于历史基线的偏离程度（z-score）。
// z-score > 2 通常意味着"偏离正常 2 个标准差"，是强异常信号。
// 若历史不足则返回 0（不作为判定依据）。
func (e *BaselineEngine) IPDeviationScore(alertType, ip string, currentValue float64) float64 {
	e.mu.RLock()
	st := e.states[alertType]
	e.mu.RUnlock()

	if st == nil {
		return 0
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	h := st.history[ip]
	if h == nil || len(h.samples) < e.minSamp {
		return 0
	}

	mean, std := meanStddev(h.samples)
	if std == 0 {
		if currentValue > mean {
			return 3.0 // 无方差但值高于均值，给高分
		}
		return 0
	}

	return (currentValue - mean) / std
}

// ──────────────────────────────────────────────────────────────────────
// 置信度评分系统
// ──────────────────────────────────────────────────────────────────────

// ConfidenceFactor 置信度因子：单个维度的判定结果。
type ConfidenceFactor struct {
	Name    string  // 因子名称（用于日志/详情）
	Score   float64 // 该因子的贡献分（0~100）
	Weight  float64 // 权重（0~1，所有因子权重之和应=1）
	Triggered bool  // 该维度是否命中
	Detail  string  // 命中详情
}

// ConfidenceResult 置信度评分结果。
type ConfidenceResult struct {
	Score    float64            // 加权总分（0~100）
	Factors  []ConfidenceFactor // 各因子详情
	Decision string             // 最终决策: "block" / "observe" / "ignore"
}

// ConfidenceThresholds 置信度决策阈值。
type ConfidenceThresholds struct {
	Block   float64 // >= 此分 → 直接封禁
	Observe float64 // >= 此分 → 观察（记录但不封禁）
	// < Observe → 忽略
}

// DefaultConfidenceThresholds 默认决策阈值。
//   Block = 65: 需要较强多维度证据才直接封禁
//   Observe = 35: 有一定可疑信号但证据不足时只观察不处置
var DefaultConfidenceThresholds = ConfidenceThresholds{
	Block:   65,
	Observe: 35,
}

// ScoreConfidence 多维度置信度评分。
//
// 核心理念：单一维度达标 ≠ 攻击。
// 例如：仅"请求数高"可能是正常高峰；但如果同时"URL集中度高 + 无Referer + 工具UA"，
// 多维度交叉验证的置信度才够高，才值得封禁。
//
// factors 是各维度的判定结果（已设置 Score/Weight/Triggered）。
// 只有 Triggered=true 的因子才参与计分。
// 最终决策由加权总分与 thresholds 比较得出。
func ScoreConfidence(factors []ConfidenceFactor, thresholds ConfidenceThresholds) ConfidenceResult {
	totalWeight := 0.0
	weightedSum := 0.0
	var active []ConfidenceFactor

	for _, f := range factors {
		if f.Triggered {
			weightedSum += f.Score * f.Weight
			totalWeight += f.Weight
			active = append(active, f)
		}
	}

	score := 0.0
	if totalWeight > 0 {
		// 归一化：如果只有一个因子命中但权重低，总分会被稀释
		// 这里用"实际加权分 / 理论最大分(=1.0) "直接作为百分制
		score = weightedSum
	}

	decision := "ignore"
	if score >= thresholds.Block {
		decision = "block"
	} else if score >= thresholds.Observe {
		decision = "observe"
	}

	return ConfidenceResult{
		Score:    score,
		Factors:  active,
		Decision: decision,
	}
}

// ──────────────────────────────────────────────────────────────────────
// 渐进式响应状态跟踪
// ──────────────────────────────────────────────────────────────────────

// escalationState 单个 IP+攻击类型的渐进式响应状态。
type escalationState struct {
	observeCount int       // 观察期触发次数
	lastTrigger  time.Time // 上次触发时间
	lastDecision string    // 上次决策
}

// EscalationTracker 渐进式响应追踪器。
//
// 设计哲学：
//   - 首次触发 → observe（记录但不封禁，给正常流量一个误触窗口）
//   - 观察期内再次触发 → 升级为 block（连续可疑才值得处置）
//   - 长期无触发 → 回到初始状态
//
// 这样即使置信度评分偶有波动，也不会"一次误判就封 IP"。
type EscalationTracker struct {
	mu          sync.Mutex
	states      map[string]*escalationState // key = ip + "|" + attackType
	observeWindow time.Duration             // 观察窗口：窗口内多次触发才升级
	maxObserve   int                         // 观察期最多容忍的触发次数
}

// NewEscalationTracker 创建渐进式响应追踪器。
func NewEscalationTracker() *EscalationTracker {
	return &EscalationTracker{
		states:        make(map[string]*escalationState),
		observeWindow: 30 * time.Minute,
		maxObserve:    2, // 观察期内第 3 次触发 → 升级
	}
}

// Track 追踪一次触发，返回最终应该执行的决策。
//
// 输入 confidenceDecision 是置信度评分给出的原始决策（block/observe/ignore）。
// 输出是结合历史行为后的最终决策：
//   - 原始 block → 可能降级为 observe（如果该 IP 之前从未触发，给一次缓冲）
//   - 原始 observe → 可能升级为 block（如果观察期内已多次触发）
//   - 原始 ignore → 始终 ignore
func (t *EscalationTracker) Track(ip, attackType, confidenceDecision string) string {
	key := ip + "|" + attackType
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	st := t.states[key]
	if st == nil {
		st = &escalationState{}
		t.states[key] = st
	}

	// 清理过期状态（超过观察窗口未触发）
	if now.Sub(st.lastTrigger) > t.observeWindow {
		st.observeCount = 0
	}

	st.lastTrigger = now
	st.lastDecision = confidenceDecision

	switch confidenceDecision {
	case "block":
		// 首次 block：如果该 IP 之前没有 observe 记录，降级为 observe 给一次缓冲
		// 但如果已经在 observe 期内触发过，直接 block
		if st.observeCount > 0 {
			return "block"
		}
		st.observeCount = 1
		return "observe"

	case "observe":
		st.observeCount++
		if st.observeCount >= t.maxObserve {
			return "block"
		}
		return "observe"

	default:
		return "ignore"
	}
}

// Reset 重置某 IP+攻击类型的状态（例如手动解除封禁后）。
func (t *EscalationTracker) Reset(ip, attackType string) {
	key := ip + "|" + attackType
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, key)
}

// ──────────────────────────────────────────────────────────────────────
// 统计工具函数
// ──────────────────────────────────────────────────────────────────────

// percentile 计算排序数据的 p 百分位（p ∈ [0,1]）。
// 使用线性插值法（与 numpy.percentile 默认一致）。
func percentile(data []float64, p float64) float64 {
	if len(data) == 0 {
		return 0
	}
	if len(data) == 1 {
		return data[0]
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	// 线性插值
	rank := p * float64(len(sorted)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	frac := rank - float64(lower)

	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

// meanStddev 计算均值和标准差。
func meanStddev(data []float64) (float64, float64) {
	n := len(data)
	if n == 0 {
		return 0, 0
	}

	sum := 0.0
	for _, v := range data {
		sum += v
	}
	mean := sum / float64(n)

	variance := 0.0
	for _, v := range data {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(n)
	stddev := math.Sqrt(variance)

	return mean, stddev
}

// clamp 将值夹紧在 [minVal, maxVal]。
func clamp(val, minVal, maxVal float64) float64 {
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
}
