// Package tuning 提供告警阈值自调优能力。
// 针对告警类型维护一个内存态的触发/误报滑动窗口，在安全区间内微调阈值以降低重复误报。
package tuning

import (
	"sync"
	"time"
)

// 默认调优参数。
const (
	// DefaultWindowSize 每类告警保留的最近触发/误报样本数。
	DefaultWindowSize = 20
	// DefaultFPRatio 误报率阈值，达到或超过该比例则上调阈值（降低敏感度）。
	DefaultFPRatio = 0.5
	// DefaultMinSamples 触发调优所需的最少样本数，样本不足时保持当前阈值。
	DefaultMinSamples = 3
)

// alertState 单个告警类型的调优状态。
type alertState struct {
	// window 滑动窗口，记录最近 N 次触发是否为误报（true=误报，false=正常触发）。
	window []bool
	// lastValue 上次建议的阈值，用于连续微调时保持单调性。
	lastValue float64
	// hasValue 标记 lastValue 是否已设置。
	hasValue bool
	// lastSuggest 上次进行阈值调整的时间。
	lastSuggest time.Time
	// totalSamples 累计收到的样本数（单调递增）。
	totalSamples int
	// samplesAtLastSuggest 上次建议时已收到的累计样本数。
	// 用于确保只在有新证据进入时才重新调整——
	// 否则"无误报就降阈值"会在每次读取阈值时重复扣减，把阈值漂移到下限。
	samplesAtLastSuggest int
}

// ThresholdTuner 告警阈值自调优器。
// 线程安全，阈值调整幅度小、有界，绝不超出调用方给定的 [min, max]。
type ThresholdTuner struct {
	mu         sync.Mutex
	states     map[string]*alertState
	windowSize int
	fpRatio    float64
	minSamples int
}

// NewThresholdTuner 创建阈值自调优器。
func NewThresholdTuner() *ThresholdTuner {
	return &ThresholdTuner{
		states:     make(map[string]*alertState),
		windowSize: DefaultWindowSize,
		fpRatio:    DefaultFPRatio,
		minSamples: DefaultMinSamples,
	}
}

// RecordFire 记录一次告警触发（默认视为正常触发，非误报）。
func (t *ThresholdTuner) RecordFire(alertType string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record(alertType, false)
}

// RecordFalsePositive 记录一次误报（误报比例升高会导致后续阈值上调，降低敏感度）。
func (t *ThresholdTuner) RecordFalsePositive(alertType string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record(alertType, true)
}

// record 向滑动窗口追加一个样本并裁剪至 windowSize。
// 调用方必须持有 t.mu。
func (t *ThresholdTuner) record(alertType string, isFP bool) {
	st := t.states[alertType]
	if st == nil {
		st = &alertState{}
		t.states[alertType] = st
	}
	st.window = append(st.window, isFP)
	if len(st.window) > t.windowSize {
		st.window = st.window[len(st.window)-t.windowSize:]
	}
	st.totalSamples++
}

// SuggestThreshold 根据最近样本给出新的建议阈值。
// 误报比例高于 fpRatio → 向 current+step 方向上调（降低敏感度）；
// 样本充足且完全无误报 → 向 current-step 方向回调（提高敏感度）；
// 样本不足或误报率适中 → 保持当前值。
// 返回的阈值被夹紧在 [min, max] 内。
//
// 重要：只有窗口内出现了上次建议之后的新样本才会重新计算。
// 该方法在每轮检测读取阈值时都会被调用，若无此保护，
// "无误报降阈值"会在没有新证据的情况下反复触发，把阈值漂移到下限。
func (t *ThresholdTuner) SuggestThreshold(alertType string, current, min, max, step float64) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.states[alertType]
	if st == nil {
		st = &alertState{}
		t.states[alertType] = st
	}

	// 首次使用传入的当前值，后续使用上次建议值，保证连续微调单调有界。
	base := current
	if st.hasValue {
		base = st.lastValue
	}

	newVal := base
	if len(st.window) >= t.minSamples && st.totalSamples != st.samplesAtLastSuggest {
		fp := 0
		for _, v := range st.window {
			if v {
				fp++
			}
		}
		ratio := float64(fp) / float64(len(st.window))
		if ratio >= t.fpRatio {
			newVal = base + step
		} else if fp == 0 {
			newVal = base - step
		}
	}

	if newVal < min {
		newVal = min
	}
	if newVal > max {
		newVal = max
	}

	if !st.hasValue || newVal != base || st.totalSamples != st.samplesAtLastSuggest {
		st.lastValue = newVal
		st.hasValue = true
		st.lastSuggest = time.Now()
		st.samplesAtLastSuggest = st.totalSamples
	}

	return newVal
}
