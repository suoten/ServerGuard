// Package maintwindow 提供智能变更窗口推荐能力。
// V3.9 — 分析 30 天历史负载 → 推荐"最佳维护窗口"
package maintwindow

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/storage"
)

// ────────────────────────────────────────────────
// 智能变更窗口推荐 (P44)
// 分析 30 天历史负载 → 推荐"最佳维护窗口"
// ────────────────────────────────────────────────

// TimeSlot 表示一个时间段（星期几 + 小时）
type TimeSlot struct {
	DayOfWeek  int     `json:"day_of_week"`  // 0=周日, 1=周一, ..., 6=周六
	DayName    string  `json:"day_name"`
	Hour       int     `json:"hour"`
	AvgCPU     float64 `json:"avg_cpu"`
	AvgMem     float64 `json:"avg_mem"`
	MaxCPU     float64 `json:"max_cpu"`
	SampleCount int    `json:"sample_count"`
	Score      float64 `json:"score"` // 综合评分（越低越适合变更）
}

// Recommendation 变更窗口推荐
type Recommendation struct {
	Timestamp     time.Time `json:"timestamp"`
	BestSlots     []TimeSlot `json:"best_slots"`
	AnalysisRange string    `json:"analysis_range"`
	Reason        string    `json:"reason"`
	TotalSamples  int       `json:"total_samples"`
}

// Recommender 变更窗口推荐器
type Recommender struct {
	store *storage.Storage
}

// New 创建推荐器
func New(store *storage.Storage) *Recommender {
	return &Recommender{store: store}
}

// Recommend 生成变更窗口推荐
func (r *Recommender) Recommend() (*Recommendation, error) {
	since := time.Now().Add(-30 * 24 * time.Hour)

	// 获取 30 天的 CPU 指标
	cpuMetrics, err := r.store.GetMetrics("", "system.cpu_percent", since, 50000)
	if err != nil || len(cpuMetrics) == 0 {
		return nil, fmt.Errorf("无足够历史数据（需要至少运行 1 天）")
	}

	// 获取内存指标
	memMetrics, _ := r.store.GetMetrics("", "system.mem_percent", since, 50000)

	// 按星期×小时分桶
	slots := make(map[int]*TimeSlot) // key = dayOfWeek*100 + hour
	dayNames := []string{"周日", "周一", "周二", "周三", "周四", "周五", "周六"}

	for _, m := range cpuMetrics {
		day := int(m.Timestamp.Weekday())
		hour := m.Timestamp.Hour()
		key := day*100 + hour
		if slot, ok := slots[key]; ok {
			slot.AvgCPU += m.Value
			slot.SampleCount++
			if m.Value > slot.MaxCPU {
				slot.MaxCPU = m.Value
			}
		} else {
			slots[key] = &TimeSlot{
				DayOfWeek: day,
				DayName:   dayNames[day],
				Hour:      hour,
				AvgCPU:    m.Value,
				MaxCPU:    m.Value,
				SampleCount: 1,
			}
		}
	}

	// 计算均值并匹配内存
	for _, slot := range slots {
		if slot.SampleCount > 0 {
			slot.AvgCPU /= float64(slot.SampleCount)
		}
	}

	// 匹配内存指标
	memBySlot := make(map[int]struct{ sum float64; count int })
	for _, m := range memMetrics {
		day := int(m.Timestamp.Weekday())
		hour := m.Timestamp.Hour()
		key := day*100 + hour
		v := memBySlot[key]
		v.sum += m.Value
		v.count++
		memBySlot[key] = v
	}
	for key, slot := range slots {
		if mem, ok := memBySlot[key]; ok && mem.count > 0 {
			slot.AvgMem = mem.sum / float64(mem.count)
		}
	}

	// 计算综合评分（越低越适合变更）
	// 评分 = CPU均值 * 0.5 + CPU峰值 * 0.3 + 内存均值 * 0.2
	for _, slot := range slots {
		slot.Score = slot.AvgCPU*0.5 + slot.MaxCPU*0.3 + slot.AvgMem*0.2
	}

	// 转为切片并排序
	allSlots := make([]TimeSlot, 0, len(slots))
	for _, s := range slots {
		allSlots = append(allSlots, *s)
	}
	sort.Slice(allSlots, func(i, j int) bool {
		return allSlots[i].Score < allSlots[j].Score
	})

	// 过滤：排除白天高峰时段（8-22点），优先推荐凌晨
	var nightSlots []TimeSlot
	for _, s := range allSlots {
		if s.Hour >= 0 && s.Hour <= 6 && s.SampleCount >= 3 {
			nightSlots = append(nightSlots, s)
		}
	}

	// 如果夜间数据不足，放宽到全时段
	bestSlots := nightSlots
	if len(bestSlots) < 3 {
		bestSlots = allSlots
	}

	// 取前 5 个
	if len(bestSlots) > 5 {
		bestSlots = bestSlots[:5]
	}

	// 生成推荐理由
	reason := generateReason(bestSlots, len(cpuMetrics))

	return &Recommendation{
		Timestamp:     time.Now(),
		BestSlots:     bestSlots,
		AnalysisRange: fmt.Sprintf("%s ~ %s", since.Format("01-02"), time.Now().Format("01-02")),
		Reason:        reason,
		TotalSamples:  len(cpuMetrics),
	}, nil
}

func generateReason(slots []TimeSlot, totalSamples int) string {
	if len(slots) == 0 {
		return "数据不足，建议再运行几天后查看"
	}

	var sb strings.Builder
	best := slots[0]
	sb.WriteString(fmt.Sprintf("基于近 30 天 %d 个采样点分析，", totalSamples))
	sb.WriteString(fmt.Sprintf("负载最低的时段是 %s %02d:00-%02d:00", best.DayName, best.Hour, best.Hour+1))
	sb.WriteString(fmt.Sprintf("（CPU 均值 %.0f%%，峰值 %.0f%%，内存 %.0f%%）", best.AvgCPU, best.MaxCPU, best.AvgMem))
	sb.WriteString("。建议在此时段进行系统升级、服务重启等变更操作，影响最小。")

	if len(slots) > 1 {
		sb.WriteString("\n\n备选时段：")
		for i := 1; i < len(slots); i++ {
			s := slots[i]
			sb.WriteString(fmt.Sprintf("\n  · %s %02d:00（CPU %.0f%%/峰值 %.0f%%）", s.DayName, s.Hour, s.AvgCPU, s.MaxCPU))
		}
	}

	return sb.String()
}
