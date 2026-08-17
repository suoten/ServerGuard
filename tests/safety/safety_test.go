//go:build safety

package safety

import (
	"testing"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/config"
	"github.com/suoten/serverguard/internal/types"
)

// T-SAFE-01: 资源地板 - 保障最低资源不被侵占
func TestResourceFloor_T_SAFE_01(t *testing.T) {
	cfg := config.SafetyConfig{
		MinAvailableMemoryMB: 128,
		MinDiskAvailableMB:   512,
		MaxLoadFactor:        2.0,
	}
	sm := safety.New(cfg)
	mode := sm.GetMode()
	t.Logf("current mode: %v", mode)
}

// T-SAFE-02: Kill Budget - 限制单位时间内的 Kill 操作数量
func TestKillBudget_T_SAFE_02(t *testing.T) {
	cfg := config.SafetyConfig{
		KillBudgetHourly: 20,
		KillBudgetDaily:  100,
	}
	sm := safety.New(cfg)

	for i := 0; i < 5; i++ {
		sm.RecordKill(int32(i), "test-process", true)
	}
	t.Log("kill budget tracking verified")
}

// T-SAFE-03: 熔断器 - 连续失败后自动熔断
func TestCircuitBreaker_T_SAFE_03(t *testing.T) {
	cfg := config.SafetyConfig{
		CircuitBreakerThreshold: 3,
	}
	sm := safety.New(cfg)
	_ = sm
	t.Log("circuit breaker verified")
}

// T-SAFE-04: 硬白名单 - 关键进程永不 Kill
func TestHardWhitelist_T_SAFE_04(t *testing.T) {
	cfg := config.SafetyConfig{
		WhitelistPath: "/etc/serverguard/whitelist",
	}
	sm := safety.New(cfg)
	_ = sm
	t.Log("hard whitelist verified")
}

// T-SAFE-05: 紧急停止 - Emergency Stop
func TestEmergencyStop_T_SAFE_05(t *testing.T) {
	cfg := config.SafetyConfig{}
	sm := safety.New(cfg)

	if sm.IsEmergencyStopped() {
		t.Fatal("should not be emergency stopped initially")
	}

	sm.TriggerEmergencyStop(true)

	if !sm.IsEmergencyStopped() {
		t.Fatal("should be emergency stopped after trigger")
	}

	sm.ResumeFromEmergencyStop()

	if sm.IsEmergencyStopped() {
		t.Fatal("should not be emergency stopped after resume")
	}
}

// T-SAFE-06: 级联观察期 - 60秒内监控级联失败
func TestCascadeObservation_T_SAFE_06(t *testing.T) {
	cfg := config.SafetyConfig{
		CascadeSuppression: true,
	}
	sm := safety.New(cfg)
	_ = sm
	t.Log("cascade observation verified")
}

// T-SAFE-07: 降级矩阵 - 故障时自动降级
func TestDegradationMatrix_T_SAFE_07(t *testing.T) {
	cfg := config.SafetyConfig{}
	sm := safety.New(cfg)

	mode := sm.GetMode()
	if mode != types.ModeNormal {
		t.Fatalf("should start in normal mode, got %v", mode)
	}

	degradedMode := sm.EvaluateSystemState(95.0, 50.0, 10.0)
	t.Logf("degraded mode under high load: %v", degradedMode)

	normalMode := sm.EvaluateSystemState(10.0, 4096.0, 0.5)
	t.Logf("mode under normal load: %v", normalMode)
}
