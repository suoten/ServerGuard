// Package anomaly 智能洞察导出。
//
// 基线检测、OOM 趋势、站点延迟追踪都在后台静默运行——本文件把这些实时状态
// 导出给 API 层，让前端「智能洞察」卡片能回答用户最关心的问题：
// "现在我的服务器各项指标算不算正常？"
package anomaly

import (
	"time"
)

// MetricInsight 单指标基线状态。
type MetricInsight struct {
	Name    string  `json:"name"`    // system.cpu_percent
	Label   string  `json:"label"`   // CPU 使用率
	Unit    string  `json:"unit"`    // %
	Current float64 `json:"current"` // 最近一次采集值
	Mean    float64 `json:"mean"`    // 该时段（周几×小时）基线均值
	Stddev  float64 `json:"stddev"`  // 基线标准差
	Sigmas  float64 `json:"sigmas"`  // 当前偏离倍数（(current-mean)/stddev）
	Anomaly bool    `json:"anomaly"` // 当前是否偏离基线（超出 watchedMetrics 配置倍数）
	Ready   bool    `json:"ready"`   // 基线是否已建立（样本足够）
}

// MemTrendInsight 内存趋势预测状态。
type MemTrendInsight struct {
	Current     float64 `json:"current"`
	SlopePerMin float64 `json:"slope_per_min"` // 增速 %/min
	MinutesLeft float64 `json:"minutes_left"`  // 预计到达 97% 的分钟数，-1 表示稳定/不可预测
	Risk        bool    `json:"risk"`          // 是否处于 15 分钟耗尽风险区
	Ready       bool    `json:"ready"`         // 样本是否足够
}

// SiteLatencyInsight 站点延迟基线状态。
type SiteLatencyInsight struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	CurrentMs float64 `json:"current_ms"`
	MeanMs    float64 `json:"mean_ms"`
	Slow      bool    `json:"slow"` // 当前是否偏离自身常态
	Ready     bool    `json:"ready"`
}

// Insights 智能洞察聚合（/api/insights 响应）。
type Insights struct {
	Learning  bool                 `json:"learning"` // 学习模式中（只积累不判断）
	Metrics   []MetricInsight      `json:"metrics"`
	MemTrend  MemTrendInsight      `json:"mem_trend"`
	SlowSites []SiteLatencyInsight `json:"slow_sites"` // 仅包含变慢的站点
	UpdatedAt time.Time            `json:"updated_at"`
}

// GetInsights 导出当前智能分析状态（供 API 层调用，读锁保护）。
func (d *Detector) GetInsights() Insights {
	now := time.Now().UTC()
	bucket := int(now.Weekday())*24 + now.Hour()

	d.mu.RLock()
	defer d.mu.RUnlock()

	ins := Insights{
		Learning:  d.isLearning(),
		UpdatedAt: time.Now(),
	}

	// 1. 系统指标基线状态
	for _, m := range watchedMetrics {
		mi := MetricInsight{
			Name:    m.Name,
			Label:   m.Label,
			Unit:    m.Unit,
			Current: d.lastValues[m.Name],
		}
		if bs, ok := d.baselines[m.Name]; ok {
			if stat, ok := bs[bucket]; ok && stat.count >= minSamples {
				mi.Ready = true
				mi.Mean = stat.mean
				mi.Stddev = stat.stddev
				if stat.stddev > 0.01 {
					mi.Sigmas = (mi.Current - stat.mean) / stat.stddev
				}
				mi.Anomaly = mi.Current >= m.Floor && mi.Current > stat.mean+m.Sigmas*stat.stddev
			}
		}
		ins.Metrics = append(ins.Metrics, mi)
	}

	// 2. 内存趋势（复用 OOM 预测同源数据）
	ins.MemTrend.Current = d.lastValues["system.mem_percent"]
	if n := len(d.memSamples); n >= trendMinSamples {
		first := d.memSamples[0]
		last := d.memSamples[n-1]
		elapsedMin := last.at.Sub(first.at).Minutes()
		if elapsedMin >= 0.5 {
			ins.MemTrend.Ready = true
			slope := (last.value - first.value) / elapsedMin
			ins.MemTrend.SlopePerMin = slope
			if slope >= trendMinSlopePerM && ins.MemTrend.Current >= trendWatchFloor {
				minutesLeft := (trendOOMLine - ins.MemTrend.Current) / slope
				ins.MemTrend.MinutesLeft = minutesLeft
				ins.MemTrend.Risk = minutesLeft <= trendHorizonMin && minutesLeft >= 0
			} else {
				ins.MemTrend.MinutesLeft = -1
			}
		}
	}

	// 3. 变慢站点（仅列出偏离常态的）
	for id, w := range d.sites {
		if len(w.samples) < siteMinSamples {
			continue
		}
		var sum float64
		samples := w.samples[:len(w.samples)-1]
		for _, v := range samples {
			sum += v
		}
		mean := sum / float64(len(samples))
		current := w.samples[len(w.samples)-1]
		if current > mean*siteSpikeFactor && current >= siteFloorMs {
			ins.SlowSites = append(ins.SlowSites, SiteLatencyInsight{
				ID:        id,
				Name:      w.name,
				CurrentMs: current,
				MeanMs:    mean,
				Slow:      true,
				Ready:     true,
			})
		}
	}

	return ins
}
