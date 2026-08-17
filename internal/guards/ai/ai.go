package ai

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// AIAnalysis implements Module J: AI-Powered Analysis
// Covers: baseline learning, trend prediction, root cause analysis
// Note: LLM is used ONLY for generating human-readable reports.
// Decision-making always goes through the rule engine, not LLM.
type AIAnalysis struct {
	mu        sync.RWMutex
	eventBus  *eventbus.EventBus
	baselines map[string]*Baseline  // metric key -> baseline
	predictions map[string]*Prediction // metric key -> prediction
	minSamples int                   // minimum samples for baseline
	maxSamples int                   // maximum samples to keep
}

// Baseline represents the learned normal range for a metric.
type Baseline struct {
	Key       string
	Mean      float64
	StdDev    float64
	Min       float64
	Max       float64
	P95       float64
	SampleCount int
	LastUpdate time.Time
	Samples   []float64
}

// Prediction represents a trend prediction for a metric.
type Prediction struct {
	Key          string
	CurrentValue float64
	PredictedValue float64
	Rate         float64 // rate of change per hour
	EstimatedTime time.Time // estimated time to reach threshold
	Threshold    float64
	Trend        string // "increasing", "decreasing", "stable"
}

// New creates a new AIAnalysis instance.
func New(bus *eventbus.EventBus) *AIAnalysis {
	return &AIAnalysis{
		eventBus:    bus,
		baselines:   make(map[string]*Baseline),
		predictions:  make(map[string]*Prediction),
		minSamples:   288, // 1 day of 5-minute samples = 288 samples
		maxSamples:   2016, // 7 days of 5-minute samples
	}
}

// UpdateBaseline updates the baseline for a metric.
// J1: Baseline Learning - learns the normal CPU/memory/network/disk IO range.
func (a *AIAnalysis) UpdateBaseline(key string, value float64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	baseline, exists := a.baselines[key]
	if !exists {
		baseline = &Baseline{
			Key:    key,
			Samples: make([]float64, 0, a.maxSamples),
		}
		a.baselines[key] = baseline
	}

	// Add sample
	baseline.Samples = append(baseline.Samples, value)
	if len(baseline.Samples) > a.maxSamples {
		baseline.Samples = baseline.Samples[1:]
	}

	// Recalculate statistics
	if len(baseline.Samples) >= a.minSamples {
		a.recalculateBaseline(baseline)
	}

	baseline.LastUpdate = time.Now()
}

// recalculateBaseline recalculates mean, std dev, percentiles.
func (a *AIAnalysis) recalculateBaseline(b *Baseline) {
	n := len(b.Samples)
	if n == 0 {
		return
	}

	// Calculate mean
	sum := 0.0
	for _, v := range b.Samples {
		sum += v
	}
	b.Mean = sum / float64(n)

	// Calculate standard deviation
	squaredSum := 0.0
	for _, v := range b.Samples {
		diff := v - b.Mean
		squaredSum += diff * diff
	}
	b.StdDev = math.Sqrt(squaredSum / float64(n))

	// Calculate min, max
	b.Min = b.Samples[0]
	b.Max = b.Samples[0]
	for _, v := range b.Samples {
		if v < b.Min {
			b.Min = v
		}
		if v > b.Max {
			b.Max = v
		}
	}

	// Calculate P95 (95th percentile)
	sorted := make([]float64, len(b.Samples))
	copy(sorted, b.Samples)
	sortFloats(sorted)
	p95Idx := int(float64(n) * 0.95)
	if p95Idx >= n {
		p95Idx = n - 1
	}
	b.P95 = sorted[p95Idx]

	b.SampleCount = n
}

// CheckAnomalies checks for baseline deviations.
func (a *AIAnalysis) CheckAnomalies(currentMetrics map[string]float64) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for key, value := range currentMetrics {
		baseline, exists := a.baselines[key]
		if !exists || baseline.SampleCount < a.minSamples {
			continue // Not enough data for baseline
		}

		// Check if value deviates from baseline
		// Use 3-sigma rule: if value > mean + 3*stddev, it's an anomaly
		threshold := baseline.Mean + 3*baseline.StdDev
		if value > threshold && threshold > 0 {
			deviationPercent := ((value - baseline.Mean) / baseline.Mean) * 100
			a.eventBus.PublishAlert(types.AlertWarning, "ai",
				fmt.Sprintf("基线偏离: %s", key),
				fmt.Sprintf("指标 %s 当前值 %.2f 超出基线范围 (均值 %.2f, P95 %.2f, 偏离 %.1f%%)",
					key, value, baseline.Mean, baseline.P95, deviationPercent),
				"baseline-deviation-001")
		}

		// Also check if value exceeds P95
		if value > baseline.P95 && baseline.P95 > 0 {
			// Mild anomaly - only alert if significantly above P95
			if value > baseline.P95*1.5 {
				a.eventBus.PublishAlert(types.AlertInfo, "ai",
					fmt.Sprintf("P95偏离: %s", key),
					fmt.Sprintf("指标 %s 超过 P95 基线 (%.2f vs P95=%.2f)", key, value, baseline.P95),
					"baseline-deviation-001")
			}
		}
	}
}

// PredictTrend predicts when a metric will reach a threshold.
// J2: Trend Prediction - linear regression / moving average.
func (a *AIAnalysis) PredictTrend(key string, threshold float64, currentMetrics []float64) *Prediction {
	if len(currentMetrics) < 10 {
		return nil // Not enough data
	}

	// Simple linear regression: y = a*x + b
	n := float64(len(currentMetrics))
	sumX := 0.0
	sumY := 0.0
	sumXY := 0.0
	sumX2 := 0.0

	for i, y := range currentMetrics {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	// Calculate slope (a) and intercept (b)
	denominator := n*sumX2 - sumX*sumX
	if denominator == 0 {
		return nil
	}
	slope := (n*sumXY - sumX*sumY) / denominator
	intercept := (sumY - slope*sumX) / n

	current := currentMetrics[len(currentMetrics)-1]
	prediction := &Prediction{
		Key:           key,
		CurrentValue:  current,
		Threshold:     threshold,
	}

	// Determine trend
	if slope > 0.01 {
		prediction.Trend = "increasing"
	} else if slope < -0.01 {
		prediction.Trend = "decreasing"
	} else {
		prediction.Trend = "stable"
	}

	// Predict when threshold will be reached
	if slope > 0 && current < threshold {
		// How many steps until we reach threshold?
		stepsToThreshold := (threshold - intercept) / slope
		if stepsToThreshold > 0 {
			// Each step is 5 minutes (collect interval)
			hoursToThreshold := stepsToThreshold * 5 / 60
			prediction.EstimatedTime = time.Now().Add(time.Duration(hoursToThreshold) * time.Hour)
			prediction.Rate = slope * 12 // per hour (5min * 12 = 1hr)
			prediction.PredictedValue = threshold

			// Alert if threshold will be reached soon
			if hoursToThreshold < 72 { // within 3 days
				a.eventBus.PublishAlert(types.AlertWarning, "ai",
					fmt.Sprintf("趋势预测: %s 将在 %.1f 小时后达到阈值", key, hoursToThreshold),
					fmt.Sprintf("指标 %s 当前 %.2f，按当前增长速率 (%.2f/hr)，预计 %s 达到阈值 %.2f",
						key, current, prediction.Rate,
						prediction.EstimatedTime.Format("2006-01-02 15:04"), threshold),
					"trend-prediction-001")
			}
		}
	} else if slope < 0 && current > threshold {
		prediction.Trend = "decreasing"
		// Resource is being freed up, this is good
	}

	a.mu.Lock()
	a.predictions[key] = prediction
	a.mu.Unlock()

	return prediction
}

// GetRootCauseAnalysis performs root cause analysis for a failure.
// J3: Root Cause Analysis - correlates logs and metrics to find the most likely cause.
// LLM is used ONLY to generate a human-readable report. Decision goes through rule engine.
func (a *AIAnalysis) GetRootCauseAnalysis(failedService string, alerts []types.Alert, metrics []types.Metric) string {
	var report string
	report = fmt.Sprintf("## 根因分析报告: %s\n\n", failedService)
	report += fmt.Sprintf("分析时间: %s\n\n", time.Now().Format(time.RFC3339))

	// Step 1: Identify correlated alerts
	report += "### 1. 关联告警\n"
	for i, alert := range alerts {
		if i >= 10 {
			report += fmt.Sprintf("... 及其他 %d 条告警\n", len(alerts)-10)
			break
		}
		report += fmt.Sprintf("- [%s] %s: %s\n", alert.Level, alert.Title, alert.Message)
	}

	// Step 2: Identify metric anomalies
	report += "\n### 2. 指标异常\n"
	for i, m := range metrics {
		if i >= 10 {
			break
		}
		report += fmt.Sprintf("- %s: %.2f %s\n", m.Name, m.Value, m.Unit)
	}

	// Step 3: Determine most likely root cause
	report += "\n### 3. 最可能的原因\n"

	// Simple rule-based root cause analysis
	if hasAlert(alerts, "cpu") {
		report += "- CPU 超限可能是根因。建议检查是否有异常进程占用 CPU。\n"
	}
	if hasAlert(alerts, "memory") {
		report += "- 内存泄漏/不足可能是根因。建议检查进程内存增长趋势。\n"
	}
	if hasAlert(alerts, "disk") {
		report += "- 磁盘空间不足可能是根因。建议清理日志/缓存。\n"
	}
	if hasAlert(alerts, "network") {
		report += "- 网络异常可能是根因。建议检查网络连通性和防火墙规则。\n"
	}
	if hasAlert(alerts, "cert") {
		report += "- SSL 证书问题可能是根因。建议检查证书有效期。\n"
	}

	report += "\n### 4. 建议操作\n"
	report += "- 1. 检查上述指标是否已恢复\n"
	report += "- 2. 查看相关服务的日志\n"
	report += "- 3. 如果问题持续，考虑手动重启服务\n"
	report += "- 4. 如需 LLM 辅助分析，请使用 `sgctl ai analyze --service <name>` 命令\n"

	report += "\n> 注意: 此报告由规则引擎生成。LLM 仅用于增强可读性，不参与决策。\n"

	return report
}

// GetBaseline returns the baseline for a metric.
func (a *AIAnalysis) GetBaseline(key string) *Baseline {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if b, exists := a.baselines[key]; exists {
		result := *b
		return &result
	}
	return nil
}

// GetPrediction returns the prediction for a metric.
func (a *AIAnalysis) GetPrediction(key string) *Prediction {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if p, exists := a.predictions[key]; exists {
		result := *p
		return &result
	}
	return nil
}

// hasAlert checks if any alert contains a keyword.
func hasAlert(alerts []types.Alert, keyword string) bool {
	for _, a := range alerts {
		if contains(a.Title, keyword) || contains(a.Message, keyword) || contains(a.Source, keyword) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// sortFloats sorts a slice of float64 in ascending order.
func sortFloats(a []float64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
