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
	Floor  float64 // 绝对地板（低于此值不判断；百分比指标为 %，流量类为字节/秒）
	Sigmas float64 // 偏离多少个标准差算异常
	Unit   string
}{
	{Name: "system.cpu_percent", Label: "CPU 使用率", Floor: 50, Sigmas: 3, Unit: "%"},
	{Name: "system.mem_percent", Label: "内存使用率", Floor: 60, Sigmas: 3, Unit: "%"},
	{Name: "system.swap_percent", Label: "Swap 使用率", Floor: 30, Sigmas: 4, Unit: "%"},
	// 网络流量基线：抓"流量模式突变"（如凌晨外发流量异常 = 数据泄露或挖矿矿池通信）
	{Name: "net.recv_rate", Label: "下行流量", Floor: 10 * 1024 * 1024, Sigmas: 4, Unit: "B/s"},
	{Name: "net.sent_rate", Label: "上行流量", Floor: 10 * 1024 * 1024, Sigmas: 4, Unit: "B/s"},
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
	swapSamples []memSample           // Swap 趋势环形缓冲（1G 小内存机器上 swap 暴涨往往先于 OOM）
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
	// 无论是否学习期都积累内存/Swap 样本（趋势预测用）
	d.recordMemSample(memPercent)
	d.recordSwapSample(swapPercent)

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

	// Swap 趋势预测：1G 内存机器上 swap 暴涨往往比内存曲线更早暴露内存耗尽
	d.checkSwapTrend(swapPercent)

	// 基线到期重建
	d.mu.RLock()
	needBuild := time.Since(d.lastBuild) > rebuildInterval || len(d.baselines) == 0
	d.mu.RUnlock()
	if needBuild {
		d.Rebuild()
	}

	// 向宝塔学习：不每轮都 make map，直接用变量
	now := time.Now().UTC()
	bucket := int(now.Weekday())*24 + now.Hour()

	for _, m := range watchedMetrics {
		var value float64
		switch m.Name {
		case "system.cpu_percent":
			value = cpuPercent
		case "system.mem_percent":
			value = memPercent
		case "system.swap_percent":
			value = swapPercent
		default:
			continue // 其余指标走 CheckExtra
		}
		d.evaluateMetric(m, value, bucket)
	}
}

// CheckExtra 对扩展指标（网络流量等）做基线偏离判断。
// main 循环把采集到的 net.* 指标传入，复用同一套 168 时段基线机制。
func (d *Detector) CheckExtra(extra map[string]float64) {
	if len(extra) == 0 || d.isLearning() {
		return
	}

	d.mu.RLock()
	needBuild := time.Since(d.lastBuild) > rebuildInterval || len(d.baselines) == 0
	d.mu.RUnlock()
	if needBuild {
		d.Rebuild()
	}

	now := time.Now().UTC()
	bucket := int(now.Weekday())*24 + now.Hour()

	for _, m := range watchedMetrics {
		value, ok := extra[m.Name]
		if !ok {
			continue
		}
		d.evaluateMetric(m, value, bucket)
	}
}

// evaluateMetric 单指标的基线偏离判断（Check 与 CheckExtra 共用）。
func (d *Detector) evaluateMetric(m struct {
	Name   string
	Label  string
	Floor  float64
	Sigmas float64
	Unit   string
}, value float64, bucket int) {
	if value < m.Floor {
		return
	}

	d.mu.RLock()
	stat, ok := d.baselines[m.Name][bucket]
	last, alerted := d.lastAlert[m.Name]
	d.mu.RUnlock()

	if !ok || stat.count < minSamples {
		return // 该时段样本不足，不判断（宁可漏报不可误报）
	}
	if alerted && time.Since(last) < alertCooldown {
		return
	}

	threshold := stat.mean + m.Sigmas*stat.stddev
	// 阈值也不能低于绝对地板
	if threshold < m.Floor {
		threshold = m.Floor
	}
	if value <= threshold {
		return
	}

	deviation := 0.0
	if stat.stddev > 0 {
		deviation = (value - stat.mean) / stat.stddev
	}
	d.mu.Lock()
	d.lastAlert[m.Name] = time.Now()
	d.mu.Unlock()

	unitDesc := m.Unit
	humanValue := value
	if m.Unit == "B/s" && value > 1024*1024 {
		humanValue = value / 1024 / 1024
		unitDesc = "MB/s"
	} else if m.Unit == "B/s" && value > 1024 {
		humanValue = value / 1024
		unitDesc = "KB/s"
	}

	d.bus.PublishAlert(types.AlertWarning, "baseline",
		fmt.Sprintf("基线异常：%s偏离历史正常范围", m.Label),
		fmt.Sprintf("当前值 %s，该时段（%s）近 %d 天历史均值 %.1f%s（σ=%.1f），偏离 %s 个标准差。\n这种偏离通常意味着出现了异常进程、流量突增或计划外任务，建议检查近期变更。",
			formatMetricValue(humanValue, unitDesc),
			weekdayHourLabel(time.Now()), baselineDays,
			stat.mean, m.Unit, stat.stddev,
			fmt.Sprintf("%.1f", math.Abs(deviation))),
		"baseline-anomaly-"+m.Name)
}

// formatMetricValue 数值格式化（保留一位小数）。
func formatMetricValue(v float64, unit string) string {
	return fmt.Sprintf("%.1f%s", v, unit)
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

// recordSwapSample 记录一次 Swap 采样（环形缓冲）。
func (d *Detector) recordSwapSample(v float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.swapSamples = append(d.swapSamples, memSample{at: time.Now(), value: v})
	if len(d.swapSamples) > trendWindowSize {
		d.swapSamples = d.swapSamples[len(d.swapSamples)-trendWindowSize:]
	}
}

// checkSwapTrend Swap 趋势预测：内存压力下 swap 先于物理内存耗尽被写满，
// 在 1G 小内存机器上这是比内存曲线更早的耗尽信号。
func (d *Detector) checkSwapTrend(current float64) {
	if current < 40.0 { // 低水位不关心
		return
	}

	d.mu.RLock()
	n := len(d.swapSamples)
	if n < trendMinSamples {
		d.mu.RUnlock()
		return
	}
	first := d.swapSamples[0]
	last := d.swapSamples[n-1]
	lastAlert, alerted := d.lastAlert["swap-trend"]
	d.mu.RUnlock()

	if alerted && time.Since(lastAlert) < trendCooldown {
		return
	}

	elapsedMin := last.at.Sub(first.at).Minutes()
	if elapsedMin < 0.5 {
		return
	}
	slope := (last.value - first.value) / elapsedMin // %/min
	if slope < 0.3 {
		return // 增速平缓，不构成风险
	}

	minutesLeft := (90.0 - current) / slope // swap 90% 视为接近耗尽
	if minutesLeft > trendHorizonMin || minutesLeft < 0 {
		return
	}

	d.mu.Lock()
	d.lastAlert["swap-trend"] = time.Now()
	d.mu.Unlock()

	d.bus.PublishAlert(types.AlertWarning, "guardian",
		fmt.Sprintf("Swap 趋势预警：预计 %.0f 分钟后耗尽", minutesLeft),
		fmt.Sprintf("Swap 当前 %.1f%%，近 %.0f 分钟增速 +%.1f%%/分钟。按此速度预计 %.0f 分钟后达到 90%%。\nSwap 暴涨通常意味着物理内存已不够用：请检查内存增长最快的进程，或限制/重启非关键服务——避免内核 OOM Killer 随机杀进程。",
			current, elapsedMin, slope, minutesLeft),
		"swap-trend-forecast")
}

// weekdayHourLabel 输出"周三 14 点"格式的本地时段说明。
func weekdayHourLabel(t time.Time) string {
	local := t.Local()
	weekdays := []string{"周日", "周一", "周二", "周三", "周四", "周五", "周六"}
	return fmt.Sprintf("%s %d 点", weekdays[int(local.Weekday())], local.Hour())
}
