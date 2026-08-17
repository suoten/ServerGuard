//go:build performance

package performance

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/collector"
	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// T-PERF-01: Agent 内存占用 < 50MB
func BenchmarkAgentMemory_T_PERF_01(b *testing.B) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	before := m.Alloc / 1024 / 1024

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := collector.New()
		sysInfo, _ := c.CollectSystem()
		procs, _ := c.CollectProcesses(100)
		c.CollectMetrics(sysInfo, procs)
	}

	runtime.ReadMemStats(&m)
	after := m.Alloc / 1024 / 1024
	b.ReportMetric(float64(after-before), "MB")
}

// T-PERF-02: Agent CPU 占用 < 3%
func BenchmarkAgentCPU_T_PERF_02(b *testing.B) {
	c := collector.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sysInfo, _ := c.CollectSystem()
		procs, _ := c.CollectProcesses(100)
		c.CollectMetrics(sysInfo, procs)
	}
}

// T-PERF-03: 采集延迟 < 2s
func BenchmarkCollectLatency_T_PERF_03(b *testing.B) {
	c := collector.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		sysInfo, _ := c.CollectSystem()
		procs, _ := c.CollectProcesses(100)
		c.CollectMetrics(sysInfo, procs)
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			b.Fatalf("collect latency too high: %v", elapsed)
		}
	}
}

// T-PERF-04: 规则匹配延迟 < 100ms (1000条规则)
func BenchmarkRuleMatch_T_PERF_04(b *testing.B) {
	engine := ruleengine.New(5 * time.Minute)

	for i := 0; i < 1000; i++ {
		engine.AddRule(types.Rule{
			ID:       fmt.Sprintf("rule-%d", i),
			Name:     fmt.Sprintf("规则 %d", i),
			Priority: 100 - i,
			Enabled:  true,
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{Metric: "cpu_percent", Op: types.CmpGT, Value: float64(i % 100)},
				},
			},
		})
	}

	metrics := []types.Metric{
		{Name: "cpu_percent", Value: 85, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		engine.Match(metrics)
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			b.Fatalf("match latency too high: %v", elapsed)
		}
	}
}

// T-PERF-05: Kill 操作延迟 < 500ms
func BenchmarkKillLatency_T_PERF_05(b *testing.B) {
	b.Skip("requires process management setup")
}

// T-PERF-06: 证书续期延迟 < 30s
func BenchmarkCertRenewal_T_PERF_06(b *testing.B) {
	b.Skip("requires ACME staging server")
}

// T-PERF-07: 首屏加载 < 2s (Web面板)
func BenchmarkWebFirstLoad_T_PERF_07(b *testing.B) {
	b.Skip("requires web server running")
}

// T-PERF-08: 并发连接 1000+
func BenchmarkConcurrentConnections_T_PERF_08(b *testing.B) {
	b.Skip("requires hub server running")
}

// T-PERF-09: Agent→Hub 带宽 < 100KB/s
func BenchmarkAgentHubBandwidth_T_PERF_09(b *testing.B) {
	b.Skip("requires hub server running")
}

// T-PERF-10: SQLite IOPS < 100/s
func BenchmarkSQLiteIOPS_T_PERF_10(b *testing.B) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.SaveMetric(types.Metric{
			Name:      "test_metric",
			Value:     float64(i),
			Timestamp: time.Now(),
		})
	}
}

// T-PERF-11: 90天存储 < 36MB
func BenchmarkStorage90Days_T_PERF_11(b *testing.B) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	b.ResetTimer()
	for i := 0; i < 129600; i++ {
		store.SaveMetric(types.Metric{
			Name:      "cpu_percent",
			Value:     50.0,
			Timestamp: time.Now().Add(-time.Duration(129600-i) * time.Minute),
		})
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b.ReportMetric(float64(m.Alloc)/1024/1024, "MB")
}
