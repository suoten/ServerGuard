package decider

import (
	"testing"
)

// ============================================================
// 测试 1: ActionLevel 枚举与 String() 方法
// 验收标准: 定义 auto / confirm / forbidden 三级，提供 String() 方法
// ============================================================

func TestActionLevel_String(t *testing.T) {
	tests := []struct {
		level ActionLevel
		want  string
	}{
		{LevelAuto, "auto"},
		{LevelConfirm, "confirm"},
		{LevelForbidden, "forbidden"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("ActionLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestParseActionLevel(t *testing.T) {
	tests := []struct {
		input string
		want  ActionLevel
	}{
		{"auto", LevelAuto},
		{"confirm", LevelConfirm},
		{"forbidden", LevelForbidden},
		{"AUTO", LevelAuto},
		{"Confirm", LevelConfirm},
		{"unknown_value", LevelConfirm}, // 保守处理
		{"", LevelConfirm},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseActionLevel(tt.input); got != tt.want {
				t.Errorf("ParseActionLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ============================================================
// 测试 2: ActionType 常量
// 验收标准: 定义全部 16 个动作类型（🟢5 + 🟡5 + 🔴6）
// ============================================================

func TestActionType_Count(t *testing.T) {
	allActions := []ActionType{
		// 🟢 自动执行类 (5)
		ActionSSHBruteForceBan,
		ActionCertRenewal,
		ActionMalwareKill,
		ActionZombieCleanup,
		ActionCustomServiceRestart,
		// 🟡 用户确认类 (5)
		ActionWhitelistCPUThrottle,
		ActionWhitelistMemRestart,
		ActionDiskCleanup,
		ActionLogRotation,
		ActionBaotaServiceRestart,
		// 🔴 禁止自动类 (6)
		ActionKillBTPanel,
		ActionKillBTTask,
		ActionRestartBTPanel,
		ActionCleanBaotaDir,
		ActionSystemctlBaotaSvc,
		ActionChmodBaotaFile,
	}

	if len(allActions) != 16 {
		t.Errorf("动作类型总数 = %d, want 16（🟢5 + 🟡5 + 🔴6）", len(allActions))
	}

	// 检查无重复
	seen := make(map[ActionType]bool)
	for _, a := range allActions {
		if seen[a] {
			t.Errorf("动作类型重复: %s", a)
		}
		seen[a] = true
	}
}

// ============================================================
// 测试 3: DefaultBaotaPolicy 策略表
// 验收标准: 策略表硬编码，每个动作有 Level + Reason + Suggestion
// ============================================================

func TestDefaultBaotaPolicy_Completeness(t *testing.T) {
	allActions := []ActionType{
		ActionSSHBruteForceBan, ActionCertRenewal, ActionMalwareKill,
		ActionZombieCleanup, ActionCustomServiceRestart,
		ActionWhitelistCPUThrottle, ActionWhitelistMemRestart,
		ActionDiskCleanup, ActionLogRotation, ActionBaotaServiceRestart,
		ActionKillBTPanel, ActionKillBTTask, ActionRestartBTPanel,
		ActionCleanBaotaDir, ActionSystemctlBaotaSvc, ActionChmodBaotaFile,
	}

	for _, action := range allActions {
		t.Run(string(action), func(t *testing.T) {
			policy, exists := DefaultBaotaPolicy[action]
			if !exists {
				t.Errorf("DefaultBaotaPolicy 缺少动作: %s", action)
				return
			}
			if policy.Reason == "" {
				t.Errorf("动作 %s 的 Reason 为空", action)
			}
			if policy.Suggestion == "" {
				t.Errorf("动作 %s 的 Suggestion 为空", action)
			}
		})
	}
}

func TestDefaultBaotaPolicy_LevelDistribution(t *testing.T) {
	autoCount := 0
	confirmCount := 0
	forbiddenCount := 0

	for _, policy := range DefaultBaotaPolicy {
		switch policy.Level {
		case LevelAuto:
			autoCount++
		case LevelConfirm:
			confirmCount++
		case LevelForbidden:
			forbiddenCount++
		}
	}

	if autoCount != 5 {
		t.Errorf("🟢 自动项数量 = %d, want 5", autoCount)
	}
	if confirmCount != 5 {
		t.Errorf("🟡 确认项数量 = %d, want 5", confirmCount)
	}
	if forbiddenCount != 6 {
		t.Errorf("🔴 禁止项数量 = %d, want 6", forbiddenCount)
	}
}

func TestForbiddenActions(t *testing.T) {
	forbidden := forbiddenActions()
	expectedForbidden := []ActionType{
		ActionKillBTPanel, ActionKillBTTask, ActionRestartBTPanel,
		ActionCleanBaotaDir, ActionSystemctlBaotaSvc, ActionChmodBaotaFile,
	}

	for _, action := range expectedForbidden {
		if !forbidden[action] {
			t.Errorf("forbiddenActions() 缺少禁止项: %s", action)
		}
	}

	if len(forbidden) != len(expectedForbidden) {
		t.Errorf("forbiddenActions() 数量 = %d, want %d", len(forbidden), len(expectedForbidden))
	}
}
