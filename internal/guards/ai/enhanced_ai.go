package ai

import (
	"fmt"
	"math"
	"sync"
	"time"
)

type BaselineLearner struct {
	mu       sync.RWMutex
	metrics  map[string]*baselineData
	learning bool
}

type baselineData struct {
	samples   []float64
	mean      float64
	stddev    float64
	learnedAt time.Time
}

func NewBaselineLearner() *BaselineLearner {
	return &BaselineLearner{
		metrics:  make(map[string]*baselineData),
		learning: true,
	}
}

func (b *BaselineLearner) AddSample(metric string, value float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.metrics[metric] == nil {
		b.metrics[metric] = &baselineData{}
	}
	data := b.metrics[metric]
	data.samples = append(data.samples, value)

	if len(data.samples) > 1000 {
		data.samples = data.samples[len(data.samples)-1000:]
	}

	b.recalculate(metric)
}

func (b *BaselineLearner) recalculate(metric string) {
	data := b.metrics[metric]
	if len(data.samples) == 0 {
		return
	}

	sum := 0.0
	for _, v := range data.samples {
		sum += v
	}
	data.mean = sum / float64(len(data.samples))

	variance := 0.0
	for _, v := range data.samples {
		diff := v - data.mean
		variance += diff * diff
	}
	data.stddev = math.Sqrt(variance / float64(len(data.samples)))
	data.learnedAt = time.Now()

	if len(data.samples) >= 100 {
		b.learning = false
	}
}

func (b *BaselineLearner) CheckAnomaly(metric string, value float64) (isAnomaly bool, confidence float64) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	data, exists := b.metrics[metric]
	if !exists || len(data.samples) < 10 {
		return false, 0
	}

	if b.learning {
		return false, 0.3
	}

	zScore := math.Abs(value-data.mean) / data.stddev
	if zScore > 3 {
		return true, 0.95
	}
	if zScore > 2 {
		return true, 0.80
	}
	return false, 0.9
}

func (b *BaselineLearner) IsLearning() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.learning
}

type TrendPredictor struct{}

func NewTrendPredictor() *TrendPredictor { return &TrendPredictor{} }

type TrendResult struct {
	PredictedTimeToFull time.Duration `json:"predicted_time_to_full"`
	Confidence          float64       `json:"confidence"`
	Method              string        `json:"method"`
}

func (p *TrendPredictor) PredictLinearRegression(values []float64, interval time.Duration, maxValue float64) (*TrendResult, error) {
	if len(values) < 2 {
		return &TrendResult{Confidence: 0, Method: "insufficient_data"}, nil
	}

	n := float64(len(values))
	sumX, sumY, sumXY, sumX2 := 0.0, 0.0, 0.0, 0.0
	for i, y := range values {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
	intercept := (sumY - slope*sumX) / n

	if slope <= 0 {
		return &TrendResult{
			PredictedTimeToFull: 0,
			Confidence:          0.8,
			Method:              "linear_regression",
		}, nil
	}

	currentValue := slope*float64(len(values)-1) + intercept
	if currentValue >= maxValue {
		return &TrendResult{PredictedTimeToFull: 0, Confidence: 0.8, Method: "linear_regression"}, nil
	}

	timeToFull := (maxValue - currentValue) / slope * float64(interval)
	return &TrendResult{
		PredictedTimeToFull: time.Duration(timeToFull),
		Confidence:          0.8,
		Method:              "linear_regression",
	}, nil
}

func (p *TrendPredictor) PredictMovingAverage(values []float64, window int) float64 {
	if len(values) < window {
		window = len(values)
	}
	if window == 0 {
		return 0
	}
	sum := 0.0
	for i := len(values) - window; i < len(values); i++ {
		sum += values[i]
	}
	return sum / float64(window)
}

type RootCauseAnalyzer struct{}

func NewRootCauseAnalyzer() *RootCauseAnalyzer { return &RootCauseAnalyzer{} }

type RootCause struct {
	Probability float64 `json:"probability"`
	Cause       string  `json:"cause"`
	Detail      string  `json:"detail"`
}

func (a *RootCauseAnalyzer) Analyze(symptoms []string) []RootCause {
	var causes []RootCause

	for _, symptom := range symptoms {
		switch {
		case containsAny(symptom, []string{"timeout", "unreachable", "connection refused"}):
			causes = append(causes, RootCause{
				Probability: 0.7,
				Cause:       "network_issue",
				Detail:      "网络连接问题，可能是防火墙、DNS或网络接口故障",
			})
		case containsAny(symptom, []string{"out of memory", "OOM", "cannot allocate"}):
			causes = append(causes, RootCause{
				Probability: 0.9,
				Cause:       "memory_exhaustion",
				Detail:      "内存耗尽，可能存在内存泄漏或配置不当",
			})
		case containsAny(symptom, []string{"disk full", "no space left"}):
			causes = append(causes, RootCause{
				Probability: 0.9,
				Cause:       "disk_full",
				Detail:      "磁盘空间不足，需要清理或扩容",
			})
		case containsAny(symptom, []string{"permission denied", "access denied"}):
			causes = append(causes, RootCause{
				Probability: 0.8,
				Cause:       "permission_issue",
				Detail:      "权限不足，检查文件/目录权限和用户组",
			})
		}
	}

	return causes
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if containsStr(s, sub) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(s[:len(sub)] == sub || containsStr(s[1:], sub)))
}

func (a *RootCauseAnalyzer) FormatReport(causes []RootCause) string {
	var sb fmt.Stringer
	_ = sb
	report := fmt.Sprintf("根因分析报告（共 %d 个可能原因）:\n", len(causes))
	for i, c := range causes {
		report += fmt.Sprintf("  %d. [%.0f%%] %s: %s\n", i+1, c.Probability*100, c.Cause, c.Detail)
	}
	return report
}
