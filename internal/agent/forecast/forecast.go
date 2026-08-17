// Package forecast 实现磁盘容量增长预测。
// 对最近 14 天的"挂载点×天"日均使用率做最小二乘线性回归，
// 推算写满 90% 的剩余天数，提前预警，避免"半夜磁盘写满服务崩了"的被动局面。
package forecast

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

const (
	windowDays     = 14   // 回归窗口
	minPoints      = 5    // 最少数据点，不足不预测
	minSlope       = 0.05 // 最小有效增速（%/天），低于视为稳定
	warnDays       = 7    // 剩余天数 ≤ 7 天发告警
	reportDays     = 30   // 剩余天数 ≤ 30 天写入巡检报告
	alertThreshold = 90.0 // 预测目标水位 90%
	forecastKVKey  = "disk_forecast"
	runInterval    = 6 * time.Hour // 预测周期
)

// MountForecast 单挂载点的预测结果。
type MountForecast struct {
	Mount    string  `json:"mount"`     // 挂载点
	Current  float64 `json:"current"`   // 当前日均使用率 %
	SlopePer float64 `json:"slope"`     // 增速 %/天
	DaysLeft int     `json:"days_left"` // 距 90% 剩余天数（-1 = 稳定/不增长）
	FullDate string  `json:"full_date"` // 预计到达 90% 日期（稳定时为空）
}

// Predictor 磁盘容量预测器。
type Predictor struct {
	store *storage.Storage
	bus   *eventbus.EventBus
}

// New 创建预测器。
func New(store *storage.Storage, bus *eventbus.EventBus) *Predictor {
	return &Predictor{store: store, bus: bus}
}

// RunInterval 返回建议运行周期。
func RunInterval() time.Duration { return runInterval }

// RunOnce 执行一轮预测：回归计算 → 告警 → 结果写入 KV 供 API/巡检报告使用。
func (p *Predictor) RunOnce() {
	since := time.Now().Add(-windowDays * 24 * time.Hour)
	points, err := p.store.GetDiskDailyAverages(since)
	if err != nil || len(points) == 0 {
		return
	}

	// 按挂载点分组并按日期排序
	byMount := make(map[string][]storage.DiskDailyPoint)
	for _, pt := range points {
		byMount[pt.Mount] = append(byMount[pt.Mount], pt)
	}

	var forecasts []MountForecast
	for mount, pts := range byMount {
		sort.Slice(pts, func(i, j int) bool { return pts[i].Date < pts[j].Date })
		if len(pts) < minPoints {
			continue
		}
		f := regress(mount, pts)
		forecasts = append(forecasts, f)
	}
	sort.Slice(forecasts, func(i, j int) bool {
		// 剩余天数小的排前，稳定的（-1）排最后
		a, b := forecasts[i].DaysLeft, forecasts[j].DaysLeft
		if a < 0 {
			return false
		}
		if b < 0 {
			return true
		}
		return a < b
	})

	// 写入 KV 供 /api/status 与巡检报告读取
	if data, err := json.Marshal(forecasts); err == nil {
		_ = p.store.Set(forecastKVKey, string(data))
	}

	// 紧急预测告警（每挂载点每天最多一次）
	today := time.Now().Format("2006-01-02")
	for _, f := range forecasts {
		if f.DaysLeft < 0 || f.DaysLeft > warnDays {
			continue
		}
		dedupKey := fmt.Sprintf("forecast_alerted:%s:%s", f.Mount, today)
		if v, err := p.store.Get(dedupKey); err == nil && v == "1" {
			continue
		}
		_ = p.store.Set(dedupKey, "1")

		p.bus.PublishAlert(types.AlertWarning, "forecast",
			fmt.Sprintf("磁盘写满预测：%s 预计 %d 天后达到 90%%", f.Mount, f.DaysLeft),
			fmt.Sprintf("挂载点 %s 当前使用率 %.1f%%，近 %d 天日均增长 %.2f%%/天。\n按此趋势预计 %s 左右达到 90%% 水位。\n建议：提前使用「大文件扫描」定位空间占用，清理日志/备份/临时文件，或规划扩容。%s",
				f.Mount, f.Current, windowDays, f.SlopePer, f.FullDate, collectHotspots(f.Mount)),
			"disk-forecast-"+f.Mount)
	}
}

// GetForecasts 读取最近一次预测结果（供 API 层使用）。
func GetForecasts(store *storage.Storage) []MountForecast {
	v, err := store.Get(forecastKVKey)
	if err != nil || v == "" {
		return nil
	}
	var out []MountForecast
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil
	}
	return out
}

// regress 最小二乘线性回归：x = 距首点的天数，y = 日均使用率。
func regress(mount string, pts []storage.DiskDailyPoint) MountForecast {
	n := float64(len(pts))
	day0, _ := time.Parse("2006-01-02", pts[0].Date)

	var sumX, sumY, sumXY, sumXX float64
	for _, pt := range pts {
		d, err := time.Parse("2006-01-02", pt.Date)
		if err != nil {
			continue
		}
		x := d.Sub(day0).Hours() / 24
		y := pt.UsedAvg
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	denom := n*sumXX - sumX*sumX
	if denom == 0 {
		return MountForecast{Mount: mount, Current: pts[len(pts)-1].UsedAvg, DaysLeft: -1}
	}
	slope := (n*sumXY - sumX*sumY) / denom
	current := pts[len(pts)-1].UsedAvg

	f := MountForecast{Mount: mount, Current: current, SlopePer: slope, DaysLeft: -1}
	if slope < minSlope || current >= alertThreshold {
		return f // 稳定或已超水位（已有实时阈值告警兜底）
	}
	days := (alertThreshold - current) / slope
	f.DaysLeft = int(days + 0.5)
	f.FullDate = time.Now().Add(time.Duration(days*24) * time.Hour).Format("2006-01-02")
	return f
}
