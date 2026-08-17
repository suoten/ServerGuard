package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBaotaEndToEnd_ConfigLoad 验证 install.sh 生成的真实宝塔配置能被正确加载。
// 这是端到端测试：如果这个测试过不了，说明部署到服务器上 baota.safe_mode 不会生效。
func TestBaotaEndToEnd_ConfigLoad(t *testing.T) {
	// 模拟 install.sh 在宝塔环境下生成的配置文件
	yamlContent := `agent:
  collect_interval: 5
  max_memory_mb: 60
  max_cpu_percent: 3
web:
  enabled: true
  listen: "0.0.0.0:9090"
  auth_enabled: true
  username: "admin"
  password: "admin123"
  jwt_secret: "testsecret"
safety:
  kill_budget_hourly: 15
  kill_budget_daily: 50
  kill_min_interval: 30s
  circuit_breaker_threshold: 3
  circuit_breaker_reset_duration: 30m
  observation_window: 60s
  min_available_memory_mb: 50
  max_load_factor: 3.0
  min_disk_free_mb: 500
  max_disk_io_wait_percent: 80
  trash_dir: "/var/lib/serverguard/.trash"
storage:
  path: "/var/lib/serverguard/serverguard.db"
baota:
  safe_mode: "true"
  panel_path: "/www/server/panel"
  use_baota_service_manager: true
  cleanup_scope: "disabled"
  log_rotation_scope: "disabled"
  confirm_timeout_minutes: 5
  webshell_exclusions:
    - "/www/server/panel"
    - "/www/server/panel/plugin"
  auto_actions:
    ssh_bruteforce_ban: true
    cert_renewal: true
    malware_kill: true
    zombie_cleanup: true
    custom_service_restart: true
  confirm_actions:
    whitelist_cpu_throttle: "confirm"
    whitelist_mem_restart: "confirm"
    disk_cleanup: "alert"
    log_rotation: "alert"
    baota_service_restart: "confirm"
`

	// 写入临时文件
	tmpFile := filepath.Join(os.TempDir(), "test_baota_e2e_config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("无法写入测试配置文件: %v", err)
	}
	defer os.Remove(tmpFile)

	// 用 config.Load 加载 — 这是 main.go 中使用的真实加载路径
	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load 失败: %v\n这是致命错误：部署到服务器上配置文件无法加载，宝塔安全模式不会生效！", err)
	}

	// 验证 baota.safe_mode 被正确读取为 "true"
	if cfg.Baota.SafeMode != "true" {
		t.Errorf("baota.safe_mode 应为 \"true\", 实际为 %q\n这意味着宝塔安全模式不会启用！", cfg.Baota.SafeMode)
	}

	// 验证 collect_interval 被正确解析为 5 秒
	expectedInterval := Duration(5 * time.Second)
	if cfg.Agent.CollectInterval != expectedInterval {
		t.Errorf("collect_interval 应为 5s, 实际为 %v", cfg.Agent.CollectInterval.Duration())
	}

	// 验证 kill_min_interval 被正确解析为 30 秒
	if cfg.Safety.KillMinInterval.Duration() != 30*time.Second {
		t.Errorf("kill_min_interval 应为 30s, 实际为 %v", cfg.Safety.KillMinInterval.Duration())
	}

	// 验证 circuit_breaker_reset_duration 被正确解析为 30 分钟
	if cfg.Safety.CircuitBreakerResetDuration.Duration() != 30*time.Minute {
		t.Errorf("circuit_breaker_reset_duration 应为 30m, 实际为 %v", cfg.Safety.CircuitBreakerResetDuration.Duration())
	}

	// 验证 observation_window 被正确解析为 60 秒
	if cfg.Safety.ObservationWindow.Duration() != 60*time.Second {
		t.Errorf("observation_window 应为 60s, 实际为 %v", cfg.Safety.ObservationWindow.Duration())
	}

	// 验证 max_memory_mb
	if cfg.Agent.MaxMemoryMB != 60 {
		t.Errorf("max_memory_mb 应为 60, 实际为 %d", cfg.Agent.MaxMemoryMB)
	}

	// 验证 max_cpu_percent
	if cfg.Agent.MaxCPUPercent != 3 {
		t.Errorf("max_cpu_percent 应为 3, 实际为 %d", cfg.Agent.MaxCPUPercent)
	}

	// 验证 cleanup_scope
	if cfg.Baota.CleanupScope != "disabled" {
		t.Errorf("cleanup_scope 应为 disabled, 实际为 %q", cfg.Baota.CleanupScope)
	}

	// 验证 log_rotation_scope
	if cfg.Baota.LogRotationScope != "disabled" {
		t.Errorf("log_rotation_scope 应为 disabled, 实际为 %q", cfg.Baota.LogRotationScope)
	}

	t.Log("✅ 端到端测试通过：宝塔配置文件能被正确加载，所有 Duration 字段解析正确")
}

// TestBaotaEndToEnd_NonBaotaConfig 验证非宝塔配置也能正确加载
func TestBaotaEndToEnd_NonBaotaConfig(t *testing.T) {
	yamlContent := `agent:
  collect_interval: 5
  max_memory_mb: 80
  max_cpu_percent: 5
web:
  enabled: true
  listen: "0.0.0.0:9090"
  auth_enabled: true
  username: "admin"
  password: "admin123"
  jwt_secret: "testsecret"
safety:
  kill_budget_hourly: 15
  kill_budget_daily: 50
  kill_min_interval: 30s
  circuit_breaker_threshold: 3
  circuit_breaker_reset_duration: 30m
  observation_window: 60s
  min_available_memory_mb: 50
  max_load_factor: 3.0
  min_disk_free_mb: 500
  max_disk_io_wait_percent: 80
  trash_dir: "/var/lib/serverguard/.trash"
storage:
  path: "/var/lib/serverguard/serverguard.db"
baota:
  safe_mode: "auto"
  panel_path: "/www/server/panel"
  use_baota_service_manager: true
  cleanup_scope: "disabled"
  log_rotation_scope: "disabled"
  confirm_timeout_minutes: 5
`

	tmpFile := filepath.Join(os.TempDir(), "test_nonbaota_e2e_config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("无法写入测试配置文件: %v", err)
	}
	defer os.Remove(tmpFile)

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load 失败: %v", err)
	}

	if cfg.Baota.SafeMode != "auto" {
		t.Errorf("baota.safe_mode 应为 \"auto\", 实际为 %q", cfg.Baota.SafeMode)
	}

	if cfg.Agent.MaxMemoryMB != 80 {
		t.Errorf("max_memory_mb 应为 80, 实际为 %d", cfg.Agent.MaxMemoryMB)
	}

	t.Log("✅ 非宝塔配置端到端测试通过")
}
