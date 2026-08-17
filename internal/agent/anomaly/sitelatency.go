// Package anomaly 站点延迟基线检测。
//
// 网站"没挂但变慢"是监控盲区：HTTP 探针只判断存活，500ms 变 5s 不会触发任何告警，
// 但用户体验已经崩了。本模块为每个站点维护内存滑动窗口，学习该站点的正常响应时间，
// 偏离自身常态（而非固定阈值）时才告警——快速站点 800ms 是异常，慢站点 800ms 是日常。
package anomaly

import (
	"fmt"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

const (
	siteWindowSize  = 100           // 每站点延迟滑动窗口大小（约 50 分钟 @30s 探测间隔）
	siteMinSamples  = 30            // 最少样本数，不足只积累不判断
	siteSpikeFactor = 3.0           // 超过窗口均值倍数视为异常
	siteFloorMs     = 800.0         // 绝对下限（毫秒）：低于此值不算慢，避免低延迟站点误报
	siteConsecHits  = 3             // 需连续超限次数（避免单次毛刺）
	siteAlertCool   = 2 * time.Hour // 同一站点告警冷却
)

// siteWindow 单站点延迟滑动窗口。
type siteWindow struct {
	name      string    // 站点名（洞察导出用）
	samples   []float64 // 毫秒
	consec    int       // 连续超限次数
	lastAlert time.Time
}

// CheckSiteLatency 站点延迟基线检测：每次探测完成后调用。
// up=false（宕机）时跳过——宕机有专门告警，延迟检测只关心"活着但变慢"。
func (d *Detector) CheckSiteLatency(id, name string, up bool, latency time.Duration) {
	if !up || latency <= 0 {
		return
	}
	ms := float64(latency.Milliseconds())

	d.mu.Lock()
	w := d.sites[id]
	if w == nil {
		w = &siteWindow{}
		d.sites[id] = w
	}
	w.name = name
	w.samples = append(w.samples, ms)
	if len(w.samples) > siteWindowSize {
		w.samples = w.samples[len(w.samples)-siteWindowSize:]
	}
	samples := append([]float64(nil), w.samples...) // 拷贝供锁外计算
	consec := w.consec
	d.mu.Unlock()

	// 学习期/样本不足：只积累
	if d.isLearning() || len(samples) < siteMinSamples {
		return
	}

	// 窗口均值（剔除当前点后计算，避免自我污染）
	var sum float64
	for _, v := range samples[:len(samples)-1] {
		sum += v
	}
	mean := sum / float64(len(samples)-1)

	// 异常判定：超过均值 3 倍 且 超过绝对下限
	if ms <= mean*siteSpikeFactor || ms < siteFloorMs {
		d.mu.Lock()
		w.consec = 0
		d.mu.Unlock()
		return
	}

	consec++
	d.mu.Lock()
	w.consec = consec
	lastAlert := w.lastAlert
	d.mu.Unlock()

	if consec < siteConsecHits || time.Since(lastAlert) < siteAlertCool {
		return
	}

	d.mu.Lock()
	w.lastAlert = time.Now()
	d.mu.Unlock()

	d.bus.PublishAlert(types.AlertWarning, "baseline",
		fmt.Sprintf("网站变慢：%s 响应时间偏离常态", name),
		fmt.Sprintf("站点 %s 当前响应 %.0fms，近期平均 %.0fms（基于 %d 次探测），已连续 %d 次明显变慢。\n站点未宕机但响应严重退化，建议检查：后端服务 CPU/内存、数据库慢查询、磁盘 IO 等待、PHP-FPM 进程池是否打满。",
			name, ms, mean, len(samples), consec),
		"site-latency-"+id)
}
