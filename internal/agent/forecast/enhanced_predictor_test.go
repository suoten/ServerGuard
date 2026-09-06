package forecast

import (
	"strings"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// 内存泄漏预测器测试
// RecordSample 内部用 time.Now()，测试通过白盒直接构造带时间戳的采样序列。
// ────────────────────────────────────────────────

// seedSamples 直接注入带时间戳的采样序列（绕过 RecordSample 的 Now 时钟）。
func seedSamples(p *MemLeakPredictor, pid int32, name string, start time.Time, n int, step time.Duration, rssAt func(i int) float64) {
	samples := make([]ProcMemSample, 0, n)
	for i := 0; i < n; i++ {
		samples = append(samples, ProcMemSample{
			Timestamp: start.Add(time.Duration(i) * step),
			RSSMB:     rssAt(i),
			PID:       pid,
			Name:      name,
		})
	}
	p.samples[pid] = samples
}

// 泄漏进程：每小时涨 100MB → 必须被预测出来且剩余时间合理。
func TestMemLeak_GrowingProcessDetected(t *testing.T) {
	p := NewMemLeakPredictor(nil, 8192) // 8GB 系统
	start := time.Now().Add(-5 * time.Hour)

	// 30 个点，每 10 分钟一次，从 500MB 线性涨到 ~2950MB（≈300MB/h）
	seedSamples(p, 1001, "leaky-app", start, 30, 10*time.Minute, func(i int) float64 {
		return 500 + float64(i)*50 // 每步 +50MB，每 10 分钟 → 300MB/h
	})

	forecasts := p.PredictAll()
	if len(forecasts) != 1 {
		t.Fatalf("泄漏进程应产生 1 条预测，实际 %d", len(forecasts))
	}
	f := forecasts[0]
	if f.PID != 1001 || f.Name != "leaky-app" {
		t.Errorf("预测对象错误: pid=%d name=%s", f.PID, f.Name)
	}
	if f.SlopeMBPerH < 250 || f.SlopeMBPerH > 350 {
		t.Errorf("增速应约 300MB/h，实际 %.1f", f.SlopeMBPerH)
	}
	// 当前 RSS ≈ 2950MB，上限 8192*0.9=7373MB，剩余 ≈ (7373-2950)/300 ≈ 14.7h
	if f.HoursLeft < 10 || f.HoursLeft > 20 {
		t.Errorf("剩余时间应约 15h，实际 %d", f.HoursLeft)
	}
	if f.EstOOMTime == "" {
		t.Error("应有预计触顶时间")
	}
}

// 稳定进程（RSS 平坦）→ 不产生预测（HoursLeft=-1 被过滤）。
func TestMemLeak_StableProcessNotFlagged(t *testing.T) {
	p := NewMemLeakPredictor(nil, 8192)
	start := time.Now().Add(-5 * time.Hour)

	seedSamples(p, 2002, "stable-app", start, 30, 10*time.Minute, func(i int) float64 {
		return 500 + float64(i%2)*2 // 锯齿波动 ±2MB
	})

	if forecasts := p.PredictAll(); len(forecasts) != 0 {
		t.Errorf("稳定进程不应出现在预测中，实际 %d 条", len(forecasts))
	}
}

// 采样点不足（<20）→ 跳过预测，宁可漏报不误报。
func TestMemLeak_InsufficientPointsSkipped(t *testing.T) {
	p := NewMemLeakPredictor(nil, 8192)
	start := time.Now()

	seedSamples(p, 3003, "young-app", start, memLeakMinPoints-1, time.Minute, func(i int) float64 {
		return 500 + float64(i)*100 // 涨得再快也不报
	})

	if forecasts := p.PredictAll(); len(forecasts) != 0 {
		t.Errorf("采样不足不应预测，实际 %d 条", len(forecasts))
	}
}

// CheckAndAlert 分级：≤12h 紧急(error)、≤48h 预警(warning)、更远不发。
func TestMemLeak_AlertLevels(t *testing.T) {
	bus := eventbus.New(100)
	bus.Start()
	defer bus.Stop()
	levels := make(chan string, 10)
	bus.Subscribe(types.EventAlert, func(ev types.Event) {
		if ev.Source == "forecast" && strings.Contains(ev.Title, "内存泄漏预警") {
			levels <- string(ev.Level)
		}
	})
	p := NewMemLeakPredictor(bus, 8192)
	start := time.Now().Add(-5 * time.Hour)

	mk := func(pid int32, perStepMB float64) {
		seedSamples(p, pid, "app", start, 30, 10*time.Minute, func(i int) float64 {
			return 500 + float64(i)*perStepMB
		})
	}
	// 上限 8192*0.9 = 7373MB
	mk(4001, 180) // ≈1080MB/h → 剩余 <1h → error（紧急）
	mk(4002, 60)  // ≈360MB/h → 剩余 ≈14h → warning（预警）
	mk(4003, 5)   // ≈30MB/h → 剩余 >200h → 不发告警

	p.CheckAndAlert()

	// 总线分发是异步的：带超时地等两条告警（不能关闭 channel，晚到的分发会 panic）
	received := make(map[string]int)
	timeout := time.After(2 * time.Second)
	for len(received) < 2 {
		select {
		case lv := <-levels:
			received[lv]++
		case <-timeout:
			t.Fatalf("等待告警超时，已收到 %v", received)
		}
	}
	if received["error"] == 0 {
		t.Error("剩余 <12h 的进程应发紧急告警(error)")
	}
	if received["warning"] == 0 {
		t.Error("剩余 12-48h 的进程应发预警(warning)")
	}
}

// CleanupStale 清理 24h 无更新的进程数据。
func TestMemLeak_CleanupStale(t *testing.T) {
	p := NewMemLeakPredictor(nil, 8192)
	now := time.Now()

	p.samples[5001] = []ProcMemSample{{Timestamp: now.Add(-30 * time.Hour), RSSMB: 100, PID: 5001, Name: "dead"}}
	p.samples[5002] = []ProcMemSample{{Timestamp: now.Add(-1 * time.Hour), RSSMB: 100, PID: 5002, Name: "alive"}}

	p.CleanupStale()

	if p.GetTrackedProcCount() != 1 {
		t.Errorf("过期进程应被清理，剩余 %d 个", p.GetTrackedProcCount())
	}
	if _, ok := p.samples[5002]; !ok {
		t.Error("活跃进程数据不应被清理")
	}
}

// ────────────────────────────────────────────────
// 证书续期失败预测器测试
// ────────────────────────────────────────────────

// 多次失败 + 临近到期 = 高风险且发告警。
func TestCertRenewal_HighRisk(t *testing.T) {
	bus := eventbus.New(100)
	bus.Start()
	defer bus.Stop()
	alertSeen := make(chan bool, 1)
	bus.Subscribe(types.EventAlert, func(ev types.Event) {
		if strings.Contains(ev.Title, "证书续期高风险") {
			alertSeen <- true
		}
	})
	p := NewCertRenewalPredictor(bus)

	for i := 0; i < 3; i++ {
		p.RecordRenewalFailure("example.com", "dns-01 timeout")
	}

	risks := p.AssessRisk(map[string]int{"example.com": 5})
	if len(risks) != 1 {
		t.Fatalf("应产生 1 条风险评估，实际 %d", len(risks))
	}
	r := risks[0]
	if r.RiskLevel != "high" {
		t.Errorf("失败 3 次+距到期 5 天应为 high，实际 %s", r.RiskLevel)
	}
	if r.FailCount != 3 {
		t.Errorf("FailCount 应为 3，实际 %d", r.FailCount)
	}
	if !strings.Contains(r.Suggest, "ZeroSSL") {
		t.Errorf("建议应包含多 CA 降级路径，实际 %q", r.Suggest)
	}
	select {
	case ok := <-alertSeen:
		if !ok {
			t.Fatal("高风险应发布告警")
		}
	case <-time.After(time.Second):
		t.Fatal("高风险告警未发布")
	}
}

// 续期成功清除失败计数 → 高/中风险消除（距到期 5 天只剩 low 级提示）。
func TestCertRenewal_SuccessClearsFailures(t *testing.T) {
	p := NewCertRenewalPredictor(nil)
	p.RecordRenewalFailure("a.com", "err1")
	p.RecordRenewalFailure("a.com", "err2")
	p.RecordRenewalSuccess("a.com")

	risks := p.AssessRisk(map[string]int{"a.com": 5})
	for _, r := range risks {
		if r.RiskLevel == "high" || r.RiskLevel == "medium" {
			t.Errorf("失败计数清零后不应再报 %s 风险", r.RiskLevel)
		}
	}
}

// 远未到期且无失败 → 不产生噪音。
func TestCertRenewal_FarExpiryNoNoise(t *testing.T) {
	p := NewCertRenewalPredictor(nil)
	if risks := p.AssessRisk(map[string]int{"fresh.com": 60}); len(risks) != 0 {
		t.Errorf("距到期 60 天不应报告，实际 %d 条", len(risks))
	}
}

// 排序：高风险在前，同风险按到期天数升序。
func TestCertRenewal_SortOrder(t *testing.T) {
	p := NewCertRenewalPredictor(nil)
	p.RecordRenewalFailure("bad.com", "err")
	p.RecordRenewalFailure("bad.com", "err")

	risks := p.AssessRisk(map[string]int{
		"far.com":   10,
		"soon.com":  12,
		"bad.com":   20,
	})
	if len(risks) < 3 {
		t.Fatalf("应至少 3 条风险，实际 %d", len(risks))
	}
	if risks[0].Domain != "bad.com" {
		t.Errorf("高风险应排最前，实际第一个是 %s (%s)", risks[0].Domain, risks[0].RiskLevel)
	}
}
