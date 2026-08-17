package traffic

import (
	"sync"
	"time"
)

// SlowRateDetector 低速慢攻击检测器。
// 维护 per-IP 请求速率滑动窗口，检测"持续低速率但模式异常"。
type SlowRateDetector struct {
	mu         sync.Mutex
	windows    map[string]*slidingWindow // IP -> window
	windowSize time.Duration
	threshold  float64 // 基线偏离阈值
}

type slidingWindow struct {
	requests []time.Time
	baseline float64 // 基线速率
}

// NewSlowRateDetector 创建低速慢攻击检测器。
func NewSlowRateDetector() *SlowRateDetector {
	return &SlowRateDetector{
		windows:    make(map[string]*slidingWindow),
		windowSize: 5 * time.Minute,
		threshold:  3.0, // 偏离基线 3 倍
	}
}

// RecordRequest 记录一次请求。
func (d *SlowRateDetector) RecordRequest(ip string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	w, ok := d.windows[ip]
	if !ok {
		w = &slidingWindow{}
		d.windows[ip] = w
	}

	w.requests = append(w.requests, now)
	// 清理窗口外的请求
	cutoff := now.Add(-d.windowSize)
	var recent []time.Time
	for _, t := range w.requests {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	w.requests = recent

	// 更新基线（平均速率）
	if len(w.requests) > 0 {
		w.baseline = float64(len(w.requests)) / d.windowSize.Seconds()
	}
}

// DetectSlowAttack 检测指定 IP 是否为低速慢攻击。
// 返回 true 表示检测到异常。
func (d *SlowRateDetector) DetectSlowAttack(ip string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	w, ok := d.windows[ip]
	if !ok || len(w.requests) < 10 {
		return false
	}

	// 检查请求间隔是否异常均匀（机器人特征）
	intervals := make([]float64, 0, len(w.requests)-1)
	for i := 1; i < len(w.requests); i++ {
		interval := w.requests[i].Sub(w.requests[i-1]).Seconds()
		intervals = append(intervals, interval)
	}

	if len(intervals) < 2 {
		return false
	}

	// 计算间隔的标准差，如果非常均匀（低标准差）且持续请求，可能是慢攻击
	avg := average(intervals)
	stdDev := stdDeviation(intervals, avg)

	// 间隔均匀（标准差 < 均值的 10%）且持续低速率
	if stdDev < avg*0.1 && avg > 1.0 { // 间隔 > 1s 且均匀
		return true
	}

	return false
}

// GetSuspiciousIPs 返回所有可疑 IP。
func (d *SlowRateDetector) GetSuspiciousIPs(now time.Time) []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var suspicious []string
	for ip := range d.windows {
		if d.detectSlowAttackLocked(ip, now) {
			suspicious = append(suspicious, ip)
		}
	}
	return suspicious
}

func (d *SlowRateDetector) detectSlowAttackLocked(ip string, now time.Time) bool {
	w, ok := d.windows[ip]
	if !ok || len(w.requests) < 10 {
		return false
	}
	intervals := make([]float64, 0, len(w.requests)-1)
	for i := 1; i < len(w.requests); i++ {
		interval := w.requests[i].Sub(w.requests[i-1]).Seconds()
		intervals = append(intervals, interval)
	}
	if len(intervals) < 2 {
		return false
	}
	avg := average(intervals)
	stdDev := stdDeviation(intervals, avg)
	if stdDev < avg*0.1 && avg > 1.0 {
		return true
	}
	return false
}

// Cleanup 清理过期的窗口。
func (d *SlowRateDetector) Cleanup(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := now.Add(-d.windowSize)
	for ip, w := range d.windows {
		var recent []time.Time
		for _, t := range w.requests {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(d.windows, ip)
		} else {
			w.requests = recent
		}
	}
}

func average(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stdDeviation(vals []float64, avg float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sumSq := 0.0
	for _, v := range vals {
		diff := v - avg
		sumSq += diff * diff
	}
	return sqrt(sumSq / float64(len(vals)))
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}
