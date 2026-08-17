// Package anomaly 实现分时段基线异常检测。
// 学习期积累的指标历史按"周几×小时"建基线（均值+标准差），
// 运行期当前值偏离基线超过 N 个标准差且越过绝对地板时产生智能告警。
// 与固定阈值互补：阈值抓"绝对过载"，基线抓"相对异常"（如凌晨 CPU 常年 20% 突然 70%）。
package anomaly

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// 受监控的指标及其绝对地板（低于地板不告警，避免小基数噪声）
var watchedMetrics = []struct {
	Name   string  // metrics 表 name
	Label  string  // 中文名
	Floor  float64 // 绝对地板（%）
	Sigmas float64 // 偏离多少个标准差算异常
	Unit   string
}{
	{Name: "system.cpu_percent", Label: "CPU 使用率", Floor: 50, Sigmas: 3, Unit: "%"},
	{Name: "system.mem_percent", Label: "内存使用率", Floor: 60, Sigmas: 3, Unit: "%"},
	{Name: "system.swap_percent", Label: "Swap 使用率", Floor: 30, Sigmas: 4, Unit: "%"},
}

const (
	baselineDays    = 14            // 基线窗口：最近 14 天
	minSamples      = 20            // 每桶最少样本数，不足不判断
	alertCooldown   = 1 * time.Hour // 同一指标告警冷却
	rebuildInterval = 6 * time.Hour // 基线重建周期

	trendWindowSize   = 24               // 内存趋势环形缓冲：最近 24 个采样点（5s/点 ≈ 2 分钟）
	trendMinSamples   = 12               // 趋势判断最少样本（≈1 分钟数据）
	trendWatchFloor   = 80.0             // 内存超过该水位才做趋势预测（低水位不关心）
	trendMinSlopePerM = 0.2              // 增速低于 0.2%/min 视为稳定（不考虑噪声抖动）
	trendOOMLine      = 97.0             // 预测目标线：内存 97% 视为耗尽
	trendHorizonMin   = 15.0             // 预计 15 分钟内耗尽才告警
	trendCooldown     = 30 * time.Minute // OOM 趋势告警冷却
)

type bucketStat struct {
	mean, stddev float64
	count        int
}

// Detector 基线异常检测器。
type Detector struct {
	store *storage.Storage
	bus   *eventbus.EventBus
	// isLearning 返回当前是否处于学习模式（学习期只积累基线不告警）
	isLearning func() bool

	mu         sync.RWMutex
	baselines  map[string]map[int]bucketStat // metric -> bucket -> stat
	lastAlert  map[string]time.Time          // metric -> 上次告警时间
	lastBuild  time.Time
	memSamples []memSample            // 内存趋势环形缓冲（OOM 预测用）
	sites      map[string]*siteWindow // 站点延迟滑动窗口（延迟基线用）
	lastValues map[string]float64     // 各指标最近一次采集值（洞察导出用）
}

// memSample 内存使用率采样点。
type memSample struct {
	at    time.Time
	value float64
}

// New 创建检测器。isLearning 可为 nil（视为不在学习期）。
func New(store *storage.Storage, bus *eventbus.EventBus, isLearning func() bool) *Detector {
	if isLearning == nil {
		isLearning = func() bool { return false }
	}
	return &Detector{
		store:      store,
		bus:        bus,
		isLearning: isLearning,
		baselines:  make(map[string]map[int]bucketStat),
		lastAlert:  make(map[string]time.Time),
		sites:      make(map[string]*siteWindow),
		lastValues: make(map[string]float64),
	}
}

// Rebuild 从存储重建基线（6 小时一次，或样本不足时提前）。
func (d *Detector) Rebuild() {
	since := time.Now().Add(-baselineDays * 24 * time.Hour)
	rebuilt := make(map[string]map[int]bucketStat)
	for _, m := range watchedMetrics {
		stats, err := d.store.GetMetricBaselineStats(m.Name, since)
		if err != nil {
			continue
		}
		buckets := make(map[int]bucketStat, len(stats))
		for _, s := range stats {
			buckets[s.Bucket] = bucketStat{mean: s.Mean, stddev: s.Stddev, count: s.Count}
		}
		rebuilt[m.Name] = buckets
	}
	d.mu.Lock()
	d.baselines = rebuilt
	d.lastBuild = time.Now()
	d.mu.Unlock()
}

// Check 对当前采集值做基线偏离判断，异常时发布智能告警。
// 每次采集周期调用（内部有冷却控制，调用成本为内存查表）。
func (d *Detector) Check(cpuPercent, memPercent, swapPercent float64) {
	// 无论是否学习期都积累内存样本（OOM 趋势预测用）
	d.recordMemSample(memPercent)

	// 记录最近采集值（洞察导出用）
	d.mu.Lock()
	d.lastValues["system.cpu_percent"] = cpuPercent
	d.lastValues["system.mem_percent"] = memPercent
	d.lastValues["system.swap_percent"] = swapPercent
	d.mu.Unlock()

	// 学习期只积累数据不告警
	if d.isLearning() {
		return
	}

	// OOM 趋势预测：内存高速增长且预计 15 分钟内耗尽时提前告警
	d.checkOOMTrend(memPercent)

	// 基线到期重建
	d.mu.RLock()
	needBuild := time.Since(d.lastBuild) > rebuildInterval || len(d.baselines) == 0
	d.mu.RUnlock()
	if needBuild {
		d.Rebuild()
	}

	values := map[string]float64{
		"system.cpu_percent":  cpuPercent,
		"system.mem_percent":  memPercent,
		"system.swap_percent": swapPercent,
	}
	now := time.Now().UTC()
	bucket := int(now.Weekday())*24 + now.Hour()

	for _, m := range watchedMetrics {
		value := values[m.Name]
		if value < m.Floor {
			continue
		}

		d.mu.RLock()
		stat, ok := d.baselines[m.Name][bucket]
		last, alerted := d.lastAlert[m.Name]
		d.mu.RUnlock()

		if !ok || stat.count < minSamples {
			continue // 该时段样本不足，不判断（宁可漏报不可误报）
		}
		if alerted && time.Since(last) < alertCooldown {
			continue
		}

		threshold := stat.mean + m.Sigmas*stat.stddev
		// 阈值也不能低于绝对地板
		if threshold < m.Floor {
			threshold = m.Floor
		}
		if value <= threshold {
			continue
		}

		deviation := 0.0
		if stat.stddev > 0 {
			deviation = (value - stat.mean) / stat.stddev
		}
		d.mu.Lock()
		d.lastAlert[m.Name] = time.Now()
		d.mu.Unlock()

		d.bus.PublishAlert(types.AlertWarning, "baseline",
			fmt.Sprintf("基线异常：%s偏离历史正常范围", m.Label),
			fmt.Sprintf("当前值 %.1f%s，该时段（%s）近 %d 天历史均值 %.1f%s（σ=%.1f），偏离 %s 个标准差。\n这种偏离通常意味着出现了异常进程、流量突增或计划外任务，建议检查近期变更。",
				value, m.Unit,
				weekdayHourLabel(now), baselineDays,
				stat.mean, m.Unit, stat.stddev,
				fmt.Sprintf("%.1f", math.Abs(deviation))),
			"baseline-anomaly-"+m.Name)
	}
}

// recordMemSample 记录一次内存采样（环形缓冲，保留最近 trendWindowSize 个点）。
func (d *Detector) recordMemSample(v float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.memSamples = append(d.memSamples, memSample{at: time.Now(), value: v})
	if len(d.memSamples) > trendWindowSize {
		d.memSamples = d.memSamples[len(d.memSamples)-trendWindowSize:]
	}
}

// checkOOMTrend OOM 趋势预测：不等内核 OOM Killer 随机杀进程，
// 按当前增速外推内存耗尽时间，提前告警给用户留出干预窗口。
func (d *Detector) checkOOMTrend(current float64) {
	if current < trendWatchFloor {
		return
	}

	d.mu.RLock()
	n := len(d.memSamples)
	if n < trendMinSamples {
		d.mu.RUnlock()
		return
	}
	first := d.memSamples[0]
	last := d.memSamples[n-1]
	lastAlert, alerted := d.lastAlert["oom-trend"]
	d.mu.RUnlock()

	if alerted && time.Since(lastAlert) < trendCooldown {
		return
	}

	elapsedMin := last.at.Sub(first.at).Minutes()
	if elapsedMin < 0.5 {
		return // 样本时间跨度太短，不可靠
	}
	slope := (last.value - first.value) / elapsedMin // %/min
	if slope < trendMinSlopePerM {
		return // 增速平缓，不构成风险
	}

	minutesLeft := (trendOOMLine - current) / slope
	if minutesLeft > trendHorizonMin || minutesLeft < 0 {
		return
	}

	d.mu.Lock()
	d.lastAlert["oom-trend"] = time.Now()
	d.mu.Unlock()

	d.bus.PublishAlert(types.AlertWarning, "guardian",
		fmt.Sprintf("内存趋势预警：预计 %.0f 分钟后耗尽", minutesLeft),
		fmt.Sprintf("内存当前 %.1f%%，近 %.0f 分钟增速 +%.1f%%/分钟。按此速度预计 %.0f 分钟后达到 %.0f%%（内核 OOM 线）。\n建议提前处理：检查内存增长最快的进程，或主动重启内存占用高的非关键服务——避免内核 OOM Killer 随机杀进程（可能误杀 MySQL 等关键服务）。",
			current, elapsedMin, slope, minutesLeft, trendOOMLine),
		"oom-trend-forecast")
}

// weekdayHourLabel 输出"周三 14 点"格式的本地时段说明。
func weekdayHourLabel(t time.Time) string {
	local := t.Local()
	weekdays := []string{"周日", "周一", "周二", "周三", "周四", "周五", "周六"}
	return fmt.Sprintf("%s %d 点", weekdays[int(local.Weekday())], local.Hour())
}
