package safety

import (
	"strings"
	"testing"

	"github.com/suoten/serverguard/internal/config"
	"github.com/suoten/serverguard/internal/types"
)

// 紧急停止是"零风险"轴的最后防线：触发后必须阻断一切自动处置动作，
// 恢复后必须立即放行 —— 两个方向都要有测试背书。
func TestEmergencyStop_BlocksAllKillActions(t *testing.T) {
	sm := New(config.SafetyConfig{
		KillBudgetHourly: 10,
		KillBudgetDaily:  50,
	})

	// 正常状态下，无害进程的 Kill 请求应被放行
	if err := sm.CheckKillPermission("worker-process", 12345); err != nil {
		t.Fatalf("正常状态 Kill 应被允许，却被拒绝: %v", err)
	}

	// 触发紧急停止（非 halt 模式：只阻断动作，监控继续）
	sm.TriggerEmergencyStop(false)
	err := sm.CheckKillPermission("worker-process", 12345)
	if err == nil {
		t.Fatal("紧急停止后 Kill 应被阻断，却返回 nil")
	}
	if !strings.Contains(err.Error(), "emergency stop") {
		t.Errorf("阻断原因应提及 emergency stop，实际: %v", err)
	}
	if sm.ShouldRunGuards() {
		t.Fatal("紧急停止后 ShouldRunGuards 应为 false")
	}
	if !sm.IsEmergencyStopped() {
		t.Fatal("IsEmergencyStopped 应为 true")
	}

	// 恢复后动作重新放行
	sm.ResumeFromEmergencyStop()
	if err := sm.CheckKillPermission("worker-process", 12345); err != nil {
		t.Fatalf("恢复后 Kill 应重新允许，却被拒绝: %v", err)
	}
	if !sm.ShouldRunGuards() {
		t.Fatal("恢复后 ShouldRunGuards 应为 true")
	}
}

// halt=true 会把模式切到 Emergency（连采集都停），恢复后应回到可运行状态。
func TestEmergencyStop_HaltModeStopsEverything(t *testing.T) {
	sm := New(config.SafetyConfig{})
	sm.TriggerEmergencyStop(true)

	if sm.GetMode() != types.ModeEmergency || sm.ShouldRunGuards() {
		t.Fatalf("halt 模式下应为 ModeEmergency 且 ShouldRunGuards=false，mode=%v", sm.GetMode())
	}

	sm.ResumeFromEmergencyStop()
	if !sm.ShouldRunGuards() {
		t.Fatal("恢复后 Guard 应重新运行")
	}
}
