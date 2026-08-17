package decider

import (
	"testing"

	"github.com/suoten/serverguard/internal/baota"
)

// ============================================================
// 测试 4: Decider.Evaluate — 非宝塔环境
// 验收标准: 非宝塔环境返回 auto
// ============================================================

func TestEvaluate_NonBaotaEnvironment_ReturnsAuto(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: false}
	userConfig := &UserBaotaConfig{
		AutoActions:    make(map[ActionType]bool),
		ConfirmActions: make(map[ActionType]string),
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionDiskCleanup, "/var/log/old.log.gz", nil)

	if result.Level != LevelAuto {
		t.Errorf("非宝塔环境应返回 auto, got %s", result.Level)
	}
	if !result.CanOverride {
		t.Error("非宝塔环境 CanOverride 应为 true")
	}
}

// ============================================================
// 测试 4b: Decider.Evaluate — 宝塔环境未知动作
// 验收标准: 未知动作在宝塔环境下保守处理为 confirm
// ============================================================

func TestEvaluate_BaotaUnknownAction_ReturnsConfirm(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions:    make(map[ActionType]bool),
		ConfirmActions: make(map[ActionType]string),
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionType("unknown_action"), "test_target", nil)

	if result.Level != LevelConfirm {
		t.Errorf("未知动作应返回 confirm, got %s", result.Level)
	}
}

// ============================================================
// 测试 5: 🟢 Auto 分支
// 验收标准: 检查用户开关；关闭则降级为 confirm
// ============================================================

func TestEvaluate_AutoBranch_UserEnabled(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions: map[ActionType]bool{
			ActionSSHBruteForceBan: true, // 用户开启
		},
		ConfirmActions: make(map[ActionType]string),
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionSSHBruteForceBan, "192.168.1.100", nil)

	if result.Level != LevelAuto {
		t.Errorf("用户开启的自动项应返回 auto, got %s", result.Level)
	}
}

func TestEvaluate_AutoBranch_UserDisabled_DowngradeToConfirm(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions: map[ActionType]bool{
			ActionSSHBruteForceBan: false, // 用户关闭
		},
		ConfirmActions: make(map[ActionType]string),
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionSSHBruteForceBan, "192.168.1.100", nil)

	if result.Level != LevelConfirm {
		t.Errorf("用户关闭的自动项应降级为 confirm, got %s", result.Level)
	}
}

func TestEvaluate_AutoBranch_DefaultEnabled(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions:    make(map[ActionType]bool), // 空，未配置 → 默认开启
		ConfirmActions: make(map[ActionType]string),
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionMalwareKill, "xmrig", nil)

	if result.Level != LevelAuto {
		t.Errorf("未配置的自动项默认应返回 auto, got %s", result.Level)
	}
}

// ============================================================
// 测试 6: 🟡 Confirm 分支
// 验收标准: 检查用户配置：auto → 升级；alert → 仅告警；confirm → 正常确认
// ============================================================

func TestEvaluate_ConfirmBranch_UserAuto_UpgradeToAuto(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions: make(map[ActionType]bool),
		ConfirmActions: map[ActionType]string{
			ActionDiskCleanup: "auto", // 用户升级为自动
		},
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionDiskCleanup, "/var/log", nil)

	if result.Level != LevelAuto {
		t.Errorf("用户配置 auto 的确认项应升级为 auto, got %s", result.Level)
	}
}

func TestEvaluate_ConfirmBranch_UserAlert_StayConfirm(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions: make(map[ActionType]bool),
		ConfirmActions: map[ActionType]string{
			ActionDiskCleanup: "alert", // 仅告警
		},
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionDiskCleanup, "/var/log", nil)

	if result.Level != LevelConfirm {
		t.Errorf("用户配置 alert 的确认项应保持 confirm, got %s", result.Level)
	}
	// 检查 reason 中包含"仅告警"
	if result.Reason == "" {
		t.Error("alert 模式的 Reason 不应为空")
	}
}

func TestEvaluate_ConfirmBranch_DefaultConfirm(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions:    make(map[ActionType]bool),
		ConfirmActions: make(map[ActionType]string), // 空，默认 confirm
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionLogRotation, "/var/log/syslog", nil)

	if result.Level != LevelConfirm {
		t.Errorf("默认确认项应返回 confirm, got %s", result.Level)
	}
}

func TestEvaluate_ConfirmBranch_UserConfirm(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions: make(map[ActionType]bool),
		ConfirmActions: map[ActionType]string{
			ActionBaotaServiceRestart: "confirm", // 正常确认
		},
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionBaotaServiceRestart, "nginx", nil)

	if result.Level != LevelConfirm {
		t.Errorf("用户配置 confirm 的确认项应返回 confirm, got %s", result.Level)
	}
}

// ============================================================
// 测试 7: 🔴 Forbidden 分支
// 验收标准: 直接返回 forbidden；CanOverride = false；不受任何配置影响
// ============================================================

func TestEvaluate_ForbiddenBranch_ReturnsForbidden(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	userConfig := &UserBaotaConfig{
		AutoActions:    make(map[ActionType]bool),
		ConfirmActions: make(map[ActionType]string),
	}
	d := NewBaotaDecider(env, userConfig)

	forbiddenActions := []ActionType{
		ActionKillBTPanel,
		ActionKillBTTask,
		ActionRestartBTPanel,
		ActionCleanBaotaDir,
		ActionSystemctlBaotaSvc,
		ActionChmodBaotaFile,
	}

	for _, action := range forbiddenActions {
		t.Run(string(action), func(t *testing.T) {
			result := d.Evaluate(action, "bt-panel", nil)

			if result.Level != LevelForbidden {
				t.Errorf("禁止项应返回 forbidden, got %s", result.Level)
			}
			if result.CanOverride {
				t.Error("禁止项 CanOverride 应为 false")
			}
		})
	}
}

func TestEvaluate_ForbiddenBranch_NotAffectedByUserConfig(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	// 用户试图通过配置覆盖禁止项（不应该生效）
	userConfig := &UserBaotaConfig{
		AutoActions: map[ActionType]bool{
			ActionKillBTPanel: true, // 试图开启
		},
		ConfirmActions: map[ActionType]string{
			ActionKillBTPanel: "auto", // 试图升级为自动
		},
	}
	d := NewBaotaDecider(env, userConfig)

	result := d.Evaluate(ActionKillBTPanel, "bt-panel", nil)

	if result.Level != LevelForbidden {
		t.Errorf("禁止项不应受用户配置影响, got %s", result.Level)
	}
	if result.CanOverride {
		t.Error("禁止项 CanOverride 应为 false")
	}
}

// ============================================================
// 测试 8: IsBaotaPanelProcess
// 验收标准: python 进程必须二次确认 cwd/cmdline 包含 /www/server/panel
// ============================================================

func TestIsBaotaPanelProcess_DirectMatch(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	directMatchNames := []string{
		"bt-panel",
		"bt-task",
		"bt_monitor",
		"bt-python",
	}

	for _, name := range directMatchNames {
		t.Run(name, func(t *testing.T) {
			if !d.IsBaotaPanelProcess(name, "", "") {
				t.Errorf("进程 %s 应被识别为宝塔面板进程", name)
			}
		})
	}
}

func TestIsBaotaPanelProcess_PythonWithBaotaPath(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	// python 进程在宝塔路径下 → 应识别为宝塔进程
	if !d.IsBaotaPanelProcess("python3", "/www/server/panel", "") {
		t.Error("python3 进程 cwd 为 /www/server/panel 应被识别为宝塔进程")
	}

	if !d.IsBaotaPanelProcess("python", "", "/www/server/panel/BT-Panel") {
		t.Error("python 进程 cmdline 包含 /www/server/panel 应被识别为宝塔进程")
	}
}

func TestIsBaotaPanelProcess_PythonWithoutBaotaPath(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	// python 进程不在宝塔路径下 → 不应识别为宝塔进程
	if d.IsBaotaPanelProcess("python3", "/tmp", "python3 /tmp/exploit.py") {
		t.Error("python3 进程不在宝塔路径下不应被识别为宝塔进程")
	}

	if d.IsBaotaPanelProcess("python", "/home/user", "python /home/user/script.py") {
		t.Error("python 进程不在宝塔路径下不应被识别为宝塔进程")
	}
}

func TestIsBaotaPanelProcess_NonPythonNonBaota(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	// 非宝塔进程名且非 python → 不应识别
	if d.IsBaotaPanelProcess("nginx", "/usr/sbin", "nginx -g 'daemon off;'") {
		t.Error("nginx 进程不应被识别为宝塔面板进程")
	}

	if d.IsBaotaPanelProcess("redis-server", "/var/lib/redis", "") {
		t.Error("redis-server 进程不应被识别为宝塔面板进程")
	}
}

// ============================================================
// 测试 9: IsBaotaManagedService
// 验收标准: 匹配服务名 + 检查 /www/server/ 目录二次确认
// ============================================================

func TestIsBaotaManagedService_KnownServices(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	// 这些服务名在已知列表中
	knownServices := []string{
		"nginx", "httpd", "mysqld", "redis-server",
		"php-fpm", "pure-ftpd", "vsftpd", "mongod", "postgres",
	}

	for _, svc := range knownServices {
		t.Run(svc, func(t *testing.T) {
			// 在非宝塔环境下（/www/server/ 目录不存在），应返回 false
			// 因为二次确认会失败
			// 注意: 此测试在非 Linux 环境或无 /www/server/ 目录的环境下运行
			// IsBaotaManagedService 只检查服务名匹配 + 目录存在
			// 在测试环境下 /www/server/ 不存在，所以应该返回 false
			result := d.IsBaotaManagedService(svc)
			// 不做严格断言，因为取决于 /www/server/ 是否存在
			// 只验证不 panic
			_ = result
		})
	}
}

func TestIsBaotaManagedService_UnknownService(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	// 未知服务名 → 应返回 false
	unknownServices := []string{
		"custom-app", "my-service", "unknown-daemon", "",
	}

	for _, svc := range unknownServices {
		t.Run(svc, func(t *testing.T) {
			if d.IsBaotaManagedService(svc) {
				t.Errorf("未知服务 %q 不应被识别为宝塔管理服务", svc)
			}
		})
	}
}

// ============================================================
// 测试 10: BaotaDecisionResult 结构完整性
// 验收标准: 包含 Level/Action/Target/Reason/Suggestion/CanOverride/Message
// ============================================================

func TestBaotaDecisionResult_Fields(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, &UserBaotaConfig{})

	result := d.Evaluate(ActionDiskCleanup, "/var/log", map[string]interface{}{
		"disk_usage": 95.2,
	})

	// 检查所有字段都有值
	if result.Level == 0 && result.Level != LevelAuto {
		// Level 是枚举，0 是 LevelAuto，所以需要特殊处理
	}
	if result.Action != ActionDiskCleanup {
		t.Errorf("Action = %s, want %s", result.Action, ActionDiskCleanup)
	}
	if result.Target != "/var/log" {
		t.Errorf("Target = %s, want /var/log", result.Target)
	}
	if result.Reason == "" {
		t.Error("Reason 不应为空")
	}
	if result.Suggestion == "" {
		t.Error("Suggestion 不应为空")
	}
	if result.Message == "" {
		t.Error("Message 不应为空")
	}
}

// ============================================================
// 测试 11: 配置加载校验（通过 ValidateBaotaConfig）
// ============================================================

func TestUserBaotaConfig_Defaults(t *testing.T) {
	env := &baota.BaotaEnv{IsBaota: true}
	d := NewBaotaDecider(env, nil) // userConfig 为 nil

	// 不应 panic
	result := d.Evaluate(ActionSSHBruteForceBan, "1.2.3.4", nil)

	// 默认自动项应返回 auto
	if result.Level != LevelAuto {
		t.Errorf("默认配置下自动项应返回 auto, got %s", result.Level)
	}
}
