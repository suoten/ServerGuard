package config

import (
	"strings"
	"testing"
)

// ============================================================
// 测试 17: 配置校验 — 🟡 项值只能是 confirm/auto/alert
// ============================================================

func TestValidateBaotaConfig_ConfirmActions_ValidValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Baota.ConfirmActions = map[string]string{
		"disk_cleanup":          "confirm",
		"log_rotation":          "auto",
		"baota_service_restart": "alert",
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("合法的 confirm_actions 配置不应报错: %v", err)
	}
}

func TestValidateBaotaConfig_ConfirmActions_InvalidValue(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Baota.ConfirmActions = map[string]string{
		"disk_cleanup": "force", // 非法值
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("非法的 confirm_actions 值应报错")
	}
	if !strings.Contains(err.Error(), "无效") {
		t.Errorf("错误消息应包含'无效', got: %v", err)
	}
}

func TestValidateBaotaConfig_ConfirmActions_CaseInsensitive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Baota.ConfirmActions = map[string]string{
		"disk_cleanup": "AUTO", // 大写应被接受并规范化
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("大写的 confirm_actions 值应被接受: %v", err)
	}

	// 验证规范化为小写
	if cfg.Baota.ConfirmActions["disk_cleanup"] != "auto" {
		t.Errorf("confirm_actions 值应被规范化为小写, got %s", cfg.Baota.ConfirmActions["disk_cleanup"])
	}
}

// ============================================================
// 测试 17b: 配置校验 — 🔴 禁止项出现在配置中即报错
// ============================================================

func TestValidateBaotaConfig_ForbiddenInAutoActions(t *testing.T) {
	forbiddenActions := []string{
		"kill_bt_panel",
		"kill_bt_task",
		"restart_bt_panel",
		"clean_baota_dir",
		"systemctl_baota_svc",
		"chmod_baota_file",
	}

	for _, action := range forbiddenActions {
		t.Run(action, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Baota.AutoActions = map[string]bool{
				action: true,
			}

			err := cfg.Validate()
			if err == nil {
				t.Errorf("禁止项 %s 出现在 auto_actions 中应报错", action)
			}
			if !strings.Contains(err.Error(), "安全红线") {
				t.Errorf("错误消息应包含'安全红线', got: %v", err)
			}
		})
	}
}

func TestValidateBaotaConfig_ForbiddenInConfirmActions(t *testing.T) {
	forbiddenActions := []string{
		"kill_bt_panel",
		"kill_bt_task",
		"restart_bt_panel",
		"clean_baota_dir",
		"systemctl_baota_svc",
		"chmod_baota_file",
	}

	for _, action := range forbiddenActions {
		t.Run(action, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Baota.ConfirmActions = map[string]string{
				action: "auto",
			}

			err := cfg.Validate()
			if err == nil {
				t.Errorf("禁止项 %s 出现在 confirm_actions 中应报错", action)
			}
			if !strings.Contains(err.Error(), "安全红线") {
				t.Errorf("错误消息应包含'安全红线', got: %v", err)
			}
		})
	}
}

// ============================================================
// 测试 17c: 配置校验 — 超时时间范围校验
// ============================================================

func TestValidateBaotaConfig_TimeoutOutOfRange(t *testing.T) {
	tests := []struct {
		timeout int
		want    int
	}{
		{0, 5},   // 太小 → 重置为 5
		{-1, 5},  // 负数 → 重置为 5
		{61, 5},  // 太大 → 重置为 5
		{100, 5}, // 远超范围 → 重置为 5
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Baota.ConfirmTimeoutMinutes = tt.timeout

			_ = cfg.Validate() // 不应报错，只是重置

			if cfg.Baota.ConfirmTimeoutMinutes != tt.want {
				t.Errorf("超时 %d 应被重置为 %d, got %d", tt.timeout, tt.want, cfg.Baota.ConfirmTimeoutMinutes)
			}
		})
	}
}

func TestValidateBaotaConfig_TimeoutValid(t *testing.T) {
	validTimeouts := []int{1, 5, 10, 30, 60}

	for _, timeout := range validTimeouts {
		t.Run("", func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Baota.ConfirmTimeoutMinutes = timeout

			if err := cfg.Validate(); err != nil {
				t.Errorf("合法超时 %d 不应报错: %v", timeout, err)
			}

			if cfg.Baota.ConfirmTimeoutMinutes != timeout {
				t.Errorf("合法超时 %d 不应被修改, got %d", timeout, cfg.Baota.ConfirmTimeoutMinutes)
			}
		})
	}
}

// ============================================================
// 测试: 默认配置正确性
// ============================================================

func TestDefaultConfig_BaotaConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Baota.SafeMode != "auto" {
		t.Errorf("默认 SafeMode = %s, want auto", cfg.Baota.SafeMode)
	}
	if cfg.Baota.PanelPath != "/www/server/panel" {
		t.Errorf("默认 PanelPath = %s, want /www/server/panel", cfg.Baota.PanelPath)
	}
	if cfg.Baota.ConfirmTimeoutMinutes != 5 {
		t.Errorf("默认 ConfirmTimeoutMinutes = %d, want 5", cfg.Baota.ConfirmTimeoutMinutes)
	}
	if cfg.Baota.AutoActions == nil {
		t.Error("默认 AutoActions 不应为 nil")
	}
	if cfg.Baota.ConfirmActions == nil {
		t.Error("默认 ConfirmActions 不应为 nil")
	}
}
