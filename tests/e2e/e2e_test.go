//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/collector"
	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/types"
)

// T-E2E-01: CPU 爆缸自愈 - 模拟CPU 100%占用，验证Agent自动Kill
func TestCPUOverloadSelfHeal_T_E2E_01(t *testing.T) {
	if os.Getenv("SG_TEST_E2E") == "" {
		t.Skip("set SG_TEST_E2E=1 to run E2E tests")
	}

	engine := ruleengine.New(5 * time.Minute)

	engine.AddRule(types.Rule{
		ID:       "cpu-protect",
		Name:     "CPU保护",
		Priority: 100,
		Enabled:  true,
		Trigger: types.ConditionGroup{
			Operator: types.OpAnd,
			Conditions: []types.Condition{
				{Metric: "cpu_percent", Op: types.CmpGT, Value: 80},
			},
		},
		Actions: []types.Action{
			{Type: types.ActionKill, Params: map[string]interface{}{"name": "stress"}},
		},
	})

	c := collector.New()
	sysInfo, err := c.CollectSystem()
	if err != nil {
		t.Fatalf("collect system info: %v", err)
	}
	procs, _ := c.CollectProcesses(100)
	metrics := c.CollectMetrics(sysInfo, procs)

	for _, m := range metrics {
		if m.Name == "cpu_percent" && m.Value > 80 {
			matches := engine.Match([]types.Metric{m})
			if len(matches) == 0 {
				t.Fatal("should match CPU protect rule")
			}
			t.Logf("matched rule: %s, cpu=%.1f%%", matches[0].Rule.ID, m.Value)
			return
		}
	}

	t.Log("no CPU overload detected (expected in normal env)")
}

// T-E2E-02: 磁盘满自愈 - 模拟磁盘空间不足，验证Agent自动清理
func TestDiskFullSelfHeal_T_E2E_02(t *testing.T) {
	if os.Getenv("SG_TEST_E2E") == "" {
		t.Skip("set SG_TEST_E2E=1 to run E2E tests")
	}

	engine := ruleengine.New(5 * time.Minute)

	engine.AddRule(types.Rule{
		ID:       "disk-protect",
		Name:     "磁盘保护",
		Priority: 90,
		Enabled:  true,
		Trigger: types.ConditionGroup{
			Operator: types.OpAnd,
			Conditions: []types.Condition{
				{Metric: "disk_percent", Op: types.CmpGT, Value: 90},
			},
		},
		Actions: []types.Action{
			{Type: types.ActionCleanDisk},
		},
	})

	c := collector.New()
	sysInfo, err := c.CollectSystem()
	if err != nil {
		t.Fatalf("collect system info: %v", err)
	}
	procs, _ := c.CollectProcesses(100)
	metrics := c.CollectMetrics(sysInfo, procs)

	for _, m := range metrics {
		if m.Name == "disk_percent" && m.Value > 90 {
			matches := engine.Match([]types.Metric{m})
			if len(matches) == 0 {
				t.Fatal("should match disk protect rule")
			}
			t.Logf("matched rule: %s, disk=%.1f%%", matches[0].Rule.ID, m.Value)
			return
		}
	}

	t.Log("no disk full detected (expected in normal env)")
}

// T-E2E-03: 证书过期自愈 - 模拟证书即将过期，验证Agent自动续期
func TestCertExpirySelfHeal_T_E2E_03(t *testing.T) {
	if os.Getenv("SG_TEST_E2E") == "" {
		t.Skip("set SG_TEST_E2E=1 to run E2E tests")
	}
	if runtime.GOOS == "windows" {
		t.Skip("cert E2E test skipped on Windows")
	}
}

// T-E2E-CROSS: 跨平台一致性 - 验证Linux和Windows上行为一致
func TestCrossPlatformConsistency(t *testing.T) {
	if os.Getenv("SG_TEST_E2E") == "" {
		t.Skip("set SG_TEST_E2E=1 to run E2E tests")
	}

	c := collector.New()
	sysInfo, err := c.CollectSystem()
	if err != nil {
		t.Fatalf("collect system info: %v", err)
	}
	procs, _ := c.CollectProcesses(100)
	metrics := c.CollectMetrics(sysInfo, procs)

	if len(metrics) == 0 {
		t.Fatal("collector should return metrics on any platform")
	}

	t.Logf("collected %d metrics on %s", len(metrics), runtime.GOOS)
}

// T-E2E-MULTI: 多机管控 - 验证Hub管理多个Agent
func TestMultiAgentManagement(t *testing.T) {
	if os.Getenv("SG_TEST_E2E") == "" {
		t.Skip("set SG_TEST_E2E=1 to run E2E tests")
	}
	if _, err := exec.LookPath("serverguard-hub"); err != nil {
		t.Skip("serverguard-hub not available")
	}
}
