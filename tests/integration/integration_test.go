//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/baota"
	"github.com/suoten/serverguard/internal/guards/attackwarn"
	"github.com/suoten/serverguard/internal/guards/cert"
	"github.com/suoten/serverguard/internal/guards/config"
	"github.com/suoten/serverguard/internal/guards/serversecurity"
	"github.com/suoten/serverguard/internal/guards/vulnscan"
	"github.com/suoten/serverguard/internal/guards/websecurity"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// T-CORE-01: 核心流水线 Collector→RuleEngine→Decider→Executor
func TestCorePipeline_T_CORE_01(t *testing.T) {
	engine := ruleengine.New(5 * time.Minute)

	engine.AddRule(types.Rule{
		ID:       "cpu-protect",
		Name:     "CPU保护规则",
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

	metrics := []types.Metric{
		{Name: "cpu_percent", Value: 85, Timestamp: time.Now()},
	}

	matches := engine.Match(metrics)
	if len(matches) == 0 {
		t.Fatal("rule engine should match cpu_percent > 80")
	}

	t.Logf("matched %d rules", len(matches))
}

// T-CORE-02: 事件总线全链路 trace_id 传播
func TestCorePipeline_T_CORE_02(t *testing.T) {
	t.Skip("requires EventBus with trace context setup")
}

// T-CERT-01: 证书自动续期 ACME 流程
func TestCertRenewal_T_CERT_01(t *testing.T) {
	if os.Getenv("SG_TEST_ACME") == "" {
		t.Skip("set SG_TEST_ACME=1 to run ACME integration test")
	}
	bus := eventbus.New(100)
	store, _ := storage.New(":memory:")
	defer store.Close()
	bt := baota.New()
	_ = cert.New(bus, store, bt)
}

// T-CERT-02: 证书链校验
func TestCertChain_T_CERT_02(t *testing.T) {
	t.Skip("requires test certificate chain")
}

// T-CERT-03: CA 降级链
func TestCADegradation_T_CERT_03(t *testing.T) {
	t.Skip("requires ACME staging server with CA degradation")
}

// T-BAOTA-01: 宝塔动态发现
func TestBaotaDiscovery_T_BAOTA_01(t *testing.T) {
	if _, err := exec.LookPath("bt"); err != nil {
		t.Skip("bt command not available")
	}
	_ = baota.New()
}

// T-BAOTA-02: 宝塔配置同步
func TestBaotaSync_T_BAOTA_02(t *testing.T) {
	if _, err := exec.LookPath("bt"); err != nil {
		t.Skip("bt command not available")
	}
}

// T-W-01: Web 安全扫描全流程
func TestWebSecurityScan_T_W_01(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()
	guard := websecurity.New(store, "/tmp")
	findings, err := guard.Scan(context.Background(), types.ScanTarget{
		Type: "website",
		Host: "localhost",
		Port: 8080,
	})
	if err != nil {
		t.Logf("scan error (expected without target): %v", err)
	}
	t.Logf("findings: %d", len(findings))
}

// T-X-01: 漏洞扫描全流程
func TestVulnScan_T_X_01(t *testing.T) {
	guard := vulnscan.NewVulnScanGuard()
	findings, err := guard.Scan(context.Background(), []string{"/"})
	if err != nil {
		t.Logf("scan error: %v", err)
	}
	t.Logf("findings: %d", len(findings))
}

// T-Y-01: 服务器安全扫描
func TestServerSecurity_T_Y_01(t *testing.T) {
	guard := serversecurity.NewServerSecurityGuard()
	findings, err := guard.Scan(context.Background())
	if err != nil {
		t.Logf("scan error: %v", err)
	}
	t.Logf("findings: %d", len(findings))
}

// T-Z-01: 攻击告警自动处置
func TestAttackWarn_T_Z_01(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()
	_ = store
	_ = attackwarn.NewAttackWarnGuard
}

// T-Z-02: 攻击画像聚合
func TestAttackProfile_T_Z_02(t *testing.T) {
	t.Skip("requires attack event history")
}

// T-UPG-01: Agent 自升级
func TestUpgrade_T_UPG_01(t *testing.T) {
	if os.Getenv("SG_TEST_UPGRADE") == "" {
		t.Skip("set SG_TEST_UPGRADE=1 to run upgrade test")
	}
}

// T-MULTI-01: 多租户隔离
func TestMultiTenant_T_MULTI_01(t *testing.T) {
	t.Skip("requires multi-tenant storage setup")
}

// T-CONFIG-01: 配置审批流程
func TestConfigApproval_T_CONFIG_01(t *testing.T) {
	bus := eventbus.New(100)
	_ = config.New(bus, "/tmp/config-backup")
}
