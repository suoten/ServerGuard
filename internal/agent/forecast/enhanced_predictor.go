package forecast

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.0 — 内存泄漏预测器
// 跟踪进程 RSS 线性上涨趋势，提前 48h 预警 + 建议重启窗口
// 复用磁盘预测的线性回归模型，应用到进程内存维度
// ────────────────────────────────────────────────

const (
	memLeakMinPoints    = 20    // 最少采样点（约 100 分钟，5min/次）
	memLeakMinSlope     = 0.5   // 最小有效增速（MB/h），低于视为稳定
	memLeakWarnHours    = 48    // 剩余时间 ≤ 48h 发预警
	memLeakCriticalHours = 12   // 剩余时间 ≤ 12h 发紧急告警
	memLeakMaxSamples    = 288  // 保留 24 小时数据（5min/次 × 288 = 24h）
)

// ProcMemSample 进程内存采样点
type ProcMemSample struct {
	Timestamp time.Time
	RSSMB     float64 // 进程驻留内存（MB）
	PID       int32
	Name      string
}

// ProcMemForecast 进程内存预测结果
type ProcMemForecast struct {
	PID         int32   `json:"pid"`
	Name        string  `json:"name"`
	CurrentRSS  float64 `json:"current_rss_mb"` // 当前 RSS（MB）
	SlopeMBPerH float64 `json:"slope_mb_per_h"`  // 增速 MB/h
	HoursLeft   int     `json:"hours_left"`      // 距 OOM 剩余小时（-1 = 稳定）
	EstOOMTime  string  `json:"est_oom_time"`    // 预计 OOM 时间（稳定时为空）
	MaxRSSMB    float64 `json:"max_rss_mb"`      // 系统内存上限（MB）
}

// MemLeakPredictor 内存泄漏预测器
type MemLeakPredictor struct {
	mu       sync.Mutex
	bus      *eventbus.EventBus
	samples  map[int32][]ProcMemSample // PID -> samples
	maxRSSMB float64                   // 系统可用内存（MB）
}

// NewMemLeakPredictor 创建内存泄漏预测器
func NewMemLeakPredictor(bus *eventbus.EventBus, systemMemMB float64) *MemLeakPredictor {
	return &MemLeakPredictor{
		bus:      bus,
		samples:  make(map[int32][]ProcMemSample),
		maxRSSMB: systemMemMB,
	}
}

// RecordSample 记录进程内存采样
func (p *MemLeakPredictor) RecordSample(pid int32, name string, rssMB float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	sample := ProcMemSample{Timestamp: now, RSSMB: rssMB, PID: pid, Name: name}

	samples := p.samples[pid]
	samples = append(samples, sample)

	// 裁剪到最大样本数
	if len(samples) > memLeakMaxSamples {
		samples = samples[len(samples)-memLeakMaxSamples:]
	}
	p.samples[pid] = samples
}

// PredictAll 对所有跟踪的进程执行预测
func (p *MemLeakPredictor) PredictAll() []ProcMemForecast {
	p.mu.Lock()
	defer p.mu.Unlock()

	var forecasts []ProcMemForecast
	for pid, samples := range p.samples {
		if len(samples) < memLeakMinPoints {
			continue
		}
		f := p.regressMem(pid, samples)
		if f.HoursLeft >= 0 {
			forecasts = append(forecasts, f)
		}
	}
	// 按剩余时间排序（少的在前）
	sort.Slice(forecasts, func(i, j int) bool {
		if forecasts[i].HoursLeft < 0 {
			return false
		}
		if forecasts[j].HoursLeft < 0 {
			return true
		}
		return forecasts[i].HoursLeft < forecasts[j].HoursLeft
	})
	return forecasts
}

// regressMem 线性回归预测进程内存何时到达上限
func (p *MemLeakPredictor) regressMem(pid int32, samples []ProcMemSample) ProcMemForecast {
	n := len(samples)
	if n < 2 {
		return ProcMemForecast{PID: pid, HoursLeft: -1}
	}

	// x = 距首个采样点的小时数, y = RSS MB
	var sumX, sumY, sumXY, sumXX float64
	for _, s := range samples {
		x := s.Timestamp.Sub(samples[0].Timestamp).Hours()
		y := s.RSSMB
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	denom := float64(n)*sumXX - sumX*sumX
	if denom == 0 {
		return ProcMemForecast{PID: pid, HoursLeft: -1}
	}
	slope := (float64(n)*sumXY - sumX*sumY) / denom // MB/h
	intercept := (sumY - slope*sumX) / float64(n)

	currentRSS := samples[n-1].RSSMB
	name := samples[n-1].Name

	f := ProcMemForecast{
		PID:         pid,
		Name:        name,
		CurrentRSS:  currentRSS,
		SlopeMBPerH: slope,
		MaxRSSMB:    p.maxRSSMB,
	}

	// 增速太小视为稳定
	if slope < memLeakMinSlope {
		f.HoursLeft = -1
		return f
	}

	// 计算到达系统内存上限的剩余小时
	// 目标值：系统内存的 90%（留 10% 给系统）
	target := p.maxRSSMB * 0.9
	if currentRSS >= target {
		f.HoursLeft = 0
		f.EstOOMTime = "已超阈值"
	} else {
		hoursLeft := (target - intercept) / slope
		// 从当前时间算起的剩余时间
		currentX := samples[n-1].Timestamp.Sub(samples[0].Timestamp).Hours()
		remaining := hoursLeft - currentX
		if remaining < 0 {
			remaining = 0
		}
		f.HoursLeft = int(remaining)
		estTime := time.Now().Add(time.Duration(remaining) * time.Hour)
		f.EstOOMTime = estTime.Format("2006-01-02 15:04")
	}

	return f
}

// CheckAndAlert 执行预测并发布告警
func (p *MemLeakPredictor) CheckAndAlert() []ProcMemForecast {
	forecasts := p.PredictAll()
	for _, f := range forecasts {
		if f.HoursLeft < 0 {
			continue
		}

		var level types.AlertLevel
		var msg string
		if f.HoursLeft <= memLeakCriticalHours {
			level = types.AlertError
			msg = fmt.Sprintf("进程 %s (PID:%d) 内存持续增长（%.1f MB/h），预计 %d 小时后触及上限（当前 %.0f MB / 上限 %.0f MB）。建议立即在维护窗口重启该进程",
				f.Name, f.PID, f.SlopeMBPerH, f.HoursLeft, f.CurrentRSS, f.MaxRSSMB)
		} else if f.HoursLeft <= memLeakWarnHours {
			level = types.AlertWarning
			msg = fmt.Sprintf("进程 %s (PID:%d) 内存持续增长（%.1f MB/h），预计 %d 小时后触及上限（当前 %.0f MB / 上限 %.0f MB）。建议安排重启窗口",
				f.Name, f.PID, f.SlopeMBPerH, f.HoursLeft, f.CurrentRSS, f.MaxRSSMB)
		} else {
			continue // 还远，不发告警
		}

		if p.bus != nil {
			p.bus.PublishAlert(level, "forecast",
				fmt.Sprintf("内存泄漏预警: %s", f.Name),
				msg,
				fmt.Sprintf("mem-leak-%d", f.PID))
		}
	}
	return forecasts
}

// CleanupStale 清理过期的采样数据（超过 24 小时无更新）
func (p *MemLeakPredictor) CleanupStale() {
	p.mu.Lock()
	defer p.mu.Unlock()
	cutoff := time.Now().Add(-24 * time.Hour)
	for pid, samples := range p.samples {
		var recent []ProcMemSample
		for _, s := range samples {
			if s.Timestamp.After(cutoff) {
				recent = append(recent, s)
			}
		}
		if len(recent) == 0 {
			delete(p.samples, pid)
		} else {
			p.samples[pid] = recent
		}
	}
}

// GetTrackedProcCount 返回当前跟踪的进程数
func (p *MemLeakPredictor) GetTrackedProcCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.samples)
}

// ────────────────────────────────────────────────
// 证书续期失败预测器
// 监控 ACME 失败队列 + 域名到期关联，预测续期失败风险
// ────────────────────────────────────────────────

// CertRenewalRisk 证书续期风险
type CertRenewalRisk struct {
	Domain       string    `json:"domain"`
	DaysToExpiry int       `json:"days_to_expiry"`
	FailCount    int       `json:"fail_count"`     // ACME 续期失败次数
	LastFailTime time.Time `json:"last_fail_time"` // 最近一次失败时间
	RiskLevel    string    `json:"risk_level"`     // "high" / "medium" / "low"
	Reason       string    `json:"reason"`
	Suggest      string    `json:"suggest"`
}

// CertRenewalPredictor 证书续期失败预测器
type CertRenewalPredictor struct {
	mu          sync.Mutex
	bus         *eventbus.EventBus
	renewalFails map[string]*renewalFailInfo // domain -> fail info
}

type renewalFailInfo struct {
	domain       string
	failCount    int
	lastFailTime time.Time
	lastError    string
}

// NewCertRenewalPredictor 创建证书续期失败预测器
func NewCertRenewalPredictor(bus *eventbus.EventBus) *CertRenewalPredictor {
	return &CertRenewalPredictor{
		bus:          bus,
		renewalFails: make(map[string]*renewalFailInfo),
	}
}

// RecordRenewalFailure 记录一次续期失败
func (p *CertRenewalPredictor) RecordRenewalFailure(domain, errMsg string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	info, exists := p.renewalFails[domain]
	if !exists {
		info = &renewalFailInfo{domain: domain}
		p.renewalFails[domain] = info
	}
	info.failCount++
	info.lastFailTime = time.Now()
	info.lastError = errMsg
}

// RecordRenewalSuccess 记录续期成功（清除失败计数）
func (p *CertRenewalPredictor) RecordRenewalSuccess(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.renewalFails, domain)
}

// AssessRisk 评估证书续期风险
// certExpiryDays: 域名距到期天数
func (p *CertRenewalPredictor) AssessRisk(certExpiryDays map[string]int) []CertRenewalRisk {
	p.mu.Lock()
	defer p.mu.Unlock()

	var risks []CertRenewalRisk
	for domain, daysLeft := range certExpiryDays {
		failInfo, hasFail := p.renewalFails[domain]

		risk := CertRenewalRisk{
			Domain:       domain,
			DaysToExpiry: daysLeft,
		}

		switch {
		case hasFail && failInfo.failCount >= 3 && daysLeft <= 7:
			// 多次失败 + 临近到期 = 高风险
			risk.RiskLevel = "high"
			risk.FailCount = failInfo.failCount
			risk.LastFailTime = failInfo.lastFailTime
			risk.Reason = fmt.Sprintf("已连续失败 %d 次（最近：%s），距到期仅 %d 天", failInfo.failCount, failInfo.lastFailTime.Format("01-02 15:04"), daysLeft)
			risk.Suggest = "自动续期已多次失败，建议立即手动续期或更换 CA（Let's Encrypt → ZeroSSL → TrustAsia）"

		case hasFail && failInfo.failCount >= 2:
			// 多次失败但还有时间
			risk.RiskLevel = "medium"
			risk.FailCount = failInfo.failCount
			risk.LastFailTime = failInfo.lastFailTime
			risk.Reason = fmt.Sprintf("续期失败 %d 次（最近错误：%s），距到期 %d 天", failInfo.failCount, failInfo.lastError, daysLeft)
			risk.Suggest = "检查 DNS-01/HTTP-01 验证配置，确认防火墙未阻止 80/443 端口"

		case hasFail && failInfo.failCount >= 1 && daysLeft <= 14:
			risk.RiskLevel = "medium"
			risk.FailCount = failInfo.failCount
			risk.LastFailTime = failInfo.lastFailTime
			risk.Reason = fmt.Sprintf("续期失败 1 次，距到期 %d 天", daysLeft)
			risk.Suggest = "关注下次自动重试结果，如再失败需人工介入"

		case daysLeft <= 3:
			risk.RiskLevel = "high"
			risk.Reason = fmt.Sprintf("距到期仅 %d 天，无续期失败记录但需关注", daysLeft)
			risk.Suggest = "确认自动续期已触发，如即将到期仍未续期需手动介入"

		case daysLeft <= 14:
			risk.RiskLevel = "low"
			risk.Reason = fmt.Sprintf("距到期 %d 天，续期流程正常", daysLeft)
			risk.Suggest = "无需操作，自动续期将在到期前触发"

		default:
			continue // 远未到期，不报告
		}

		risks = append(risks, risk)

		// 高风险发告警
		if risk.RiskLevel == "high" && p.bus != nil {
			p.bus.PublishAlert(types.AlertError, "forecast",
				fmt.Sprintf("证书续期高风险: %s", domain),
				risk.Reason+"。建议："+risk.Suggest,
				"cert-renewal-risk-"+domain)
		}
	}

	sort.Slice(risks, func(i, j int) bool {
		// 高风险在前，同风险按到期天数升序
		if risks[i].RiskLevel != risks[j].RiskLevel {
			return riskLevelOrder(risks[i].RiskLevel) < riskLevelOrder(risks[j].RiskLevel)
		}
		return risks[i].DaysToExpiry < risks[j].DaysToExpiry
	})

	return risks
}

func riskLevelOrder(level string) int {
	switch level {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

// GetFailStats 获取续期失败统计
func (p *CertRenewalPredictor) GetFailStats() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := make(map[string]int)
	stats["total_failing_domains"] = len(p.renewalFails)
	totalFails := 0
	for _, info := range p.renewalFails {
		totalFails += info.failCount
	}
	stats["total_failures"] = totalFails
	return stats
}