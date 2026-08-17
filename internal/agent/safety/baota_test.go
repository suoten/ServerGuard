package safety

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/config"
)

// ============================================================
// 测试 1: 进程白名单 — 宝塔核心进程保护
// 验证 bt-panel、bt-task、php-fpm 全版本等在白名单中
// ============================================================

func TestBaotaProcessWhitelist_ContainsCoreProcesses(t *testing.T) {
	// getBaotaWhitelistSet 将所有名称转为小写存储，因此检查时也用小写
	required := []string{
		// 宝塔核心
		"bt", "bt-panel", "btpanel",
		"bt-task", "bt-task.py", "bt_monitor",
		// Web 服务
		"nginx", "httpd", "apache2", "apache", "php-fpm", "php-cgi",
		// php-fpm 全版本
		"php-fpm-52", "php-fpm-53", "php-fpm-54", "php-fpm-55",
		"php-fpm-56", "php-fpm-70", "php-fpm-71", "php-fpm-72",
		"php-fpm-73", "php-fpm-74", "php-fpm-80", "php-fpm-81",
		"php-fpm-82", "php-fpm-83",
		// 数据库
		"mysqld", "mariadbd", "postgres", "redis-server", "mongod",
		// FTP
		"pure-ftpd", "vsftpd",
	}

	wl := getBaotaWhitelistSet()
	for _, name := range required {
		if !wl[name] {
			t.Errorf("宝塔白名单缺少进程: %s", name)
		}
	}

	// 验证原始白名单包含大小写变体（BT-Panel, Bt-Panel）
	originalHasBTPanel := false
	originalHasBtPanel := false
	for _, name := range BaotaProcessWhitelist {
		if name == "BT-Panel" {
			originalHasBTPanel = true
		}
		if name == "Bt-Panel" {
			originalHasBtPanel = true
		}
	}
	if !originalHasBTPanel {
		t.Error("原始白名单应包含 BT-Panel（大写变体）")
	}
	if !originalHasBtPanel {
		t.Error("原始白名单应包含 Bt-Panel（混合大小写变体）")
	}
}

// ============================================================
// 测试 2: 进程白名单 — python 进程不直接匹配，需二次确认
// 验证 python/python3 不在直接白名单中
// ============================================================

func TestBaotaProcessWhitelist_PythonNotDirectlyMatched(t *testing.T) {
	wl := getBaotaWhitelistSet()

	pythonNames := []string{"python", "python3", "python2"}
	for _, name := range pythonNames {
		if wl[name] {
			t.Errorf("python 进程 %s 不应在直接白名单中，需二次确认", name)
		}
	}
}

// ============================================================
// 测试 3: IsBaotaProtectedProcess — 白名单进程匹配
// 模拟宝塔核心进程，验证被保护
// ============================================================

func TestIsBaotaProtectedProcess_WhitelistedProcess(t *testing.T) {
	tests := []struct {
		name string
		info *ProcInfo
		want bool
	}{
		{
			name: "bt-panel 进程",
			info: &ProcInfo{
				PID:  1001,
				Comm: "bt-panel",
				Exe:  "/www/server/panel/BT-Panel",
			},
			want: true,
		},
		{
			name: "nginx 进程",
			info: &ProcInfo{
				PID:  1002,
				Comm: "nginx",
				Exe:  "/www/server/nginx/sbin/nginx",
			},
			want: true,
		},
		{
			name: "mysqld 进程",
			info: &ProcInfo{
				PID:  1003,
				Comm: "mysqld",
				Exe:  "/www/server/mysql/bin/mysqld",
			},
			want: true,
		},
		{
			name: "php-fpm-74 进程",
			info: &ProcInfo{
				PID:  1004,
				Comm: "php-fpm-74",
				Exe:  "/www/server/php/74/sbin/php-fpm",
			},
			want: true,
		},
		{
			name: "bt-task 进程",
			info: &ProcInfo{
				PID:  1005,
				Comm: "bt-task",
				Exe:  "/www/server/panel/bt-task.py",
			},
			want: true,
		},
		{
			name: "普通恶意进程 stress-ng",
			info: &ProcInfo{
				PID:  9999,
				Comm: "stress-ng",
				Exe:  "/usr/bin/stress-ng",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBaotaProtectedProcess(tt.info)
			if got != tt.want {
				t.Errorf("IsBaotaProtectedProcess() = %v, want %v (comm=%s, exe=%s)",
					got, tt.want, tt.info.Comm, tt.info.Exe)
			}
		})
	}
}

// ============================================================
// 测试 3b: IsBaotaProtectedProcess — python 进程二次确认
// python 进程在宝塔路径下 → 应保护
// python 进程不在宝塔路径下 → 不应保护
// ============================================================

func TestIsBaotaProtectedProcess_PythonSecondConfirmation(t *testing.T) {
	tests := []struct {
		name string
		info *ProcInfo
		want bool
	}{
		{
			name: "宝塔面板 python 进程（路径包含 /www/server/panel）",
			info: &ProcInfo{
				PID:     2001,
				Comm:    "python3",
				Cmdline: "/www/server/panel/pyenv/bin/python3 /www/server/panel/BT-Panel",
				Exe:     "/www/server/panel/pyenv/bin/python3",
				Cwd:     "/www/server/panel",
			},
			want: true,
		},
		{
			name: "宝塔面板 python 进程（父进程为 bt）",
			info: &ProcInfo{
				PID:     2002,
				Comm:    "python3",
				Cmdline: "python3 /tmp/malicious.py",
				Exe:     "/usr/bin/python3",
				PPID:    1000,
				PPName:  "bt",
			},
			want: true,
		},
		{
			name: "非宝塔 python 进程（恶意脚本）",
			info: &ProcInfo{
				PID:     2003,
				Comm:    "python3",
				Cmdline: "python3 /tmp/exploit.py",
				Exe:     "/usr/bin/python3",
				Cwd:     "/tmp",
				PPID:    1,
				PPName:  "systemd",
			},
			want: false,
		},
		{
			name: "非宝塔 python 进程（用户脚本）",
			info: &ProcInfo{
				PID:     2004,
				Comm:    "python",
				Cmdline: "/home/user/my_script.py",
				Exe:     "/usr/bin/python",
				Cwd:     "/home/user",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBaotaProtectedProcess(tt.info)
			if got != tt.want {
				t.Errorf("IsBaotaProtectedProcess() = %v, want %v (cmdline=%s, cwd=%s, ppName=%s)",
					got, tt.want, tt.info.Cmdline, tt.info.Cwd, tt.info.PPName)
			}
		})
	}
}

// ============================================================
// 测试 3c: SafetyManager.CheckKillPermission — 白名单拦截
// 验证白名单进程的 Kill 请求被拒绝
// ============================================================

func TestCheckKillPermission_WhitelistedProcessRejected(t *testing.T) {
	cfg := testSafetyConfig()
	sm := New(cfg)

	// 在 Linux 上，宝塔进程在 hard whitelist 中会被拒绝
	// 在 Windows 上，hard whitelist 只包含 Windows 进程
	// 使用 serverguard-agent（在所有平台都在 hard whitelist 中）测试
	alwaysWhitelisted := []string{"serverguard-agent"}
	for _, name := range alwaysWhitelisted {
		err := sm.CheckKillPermission(name, 999999)
		if err == nil {
			t.Errorf("白名单进程 %s 的 Kill 请求应被拒绝，但未被拒绝", name)
		}
	}

	// Linux 专属测试：宝塔进程在 hard whitelist 中
	if runtime.GOOS != "windows" {
		baotaWhitelisted := []string{"nginx", "mysqld", "bt-panel", "php-fpm-74", "redis-server"}
		for _, name := range baotaWhitelisted {
			err := sm.CheckKillPermission(name, 999999)
			if err == nil {
				t.Errorf("白名单进程 %s 的 Kill 请求应被拒绝，但未被拒绝", name)
			}
		}
	}
}

// ============================================================
// 测试 3d: SafetyManager — BaotaSafeMode 状态管理
// ============================================================

func TestBaotaSafeMode_StateManagement(t *testing.T) {
	cfg := testSafetyConfig()
	sm := New(cfg)

	// 默认应为 false
	if sm.IsBaotaSafeMode() {
		t.Error("BaotaSafeMode 初始值应为 false")
	}

	// 启用
	sm.SetBaotaSafeMode(true)
	if !sm.IsBaotaSafeMode() {
		t.Error("SetBaotaSafeMode(true) 后应为 true")
	}

	// 禁用
	sm.SetBaotaSafeMode(false)
	if sm.IsBaotaSafeMode() {
		t.Error("SetBaotaSafeMode(false) 后应为 false")
	}
}

// ============================================================
// 测试 4: 磁盘清理黑名单 — 宝塔路径不被清理
// ============================================================

func TestIsPathBlacklisted_BaotaPaths(t *testing.T) {
	// 防护模型：白名单（可扫目录）是主防线，黑名单是白名单内的例外保护。
	// 宝塔核心数据/配置路径必须在黑名单（即使被遍历到也绝对跳过）。
	baotaPaths := []string{
		"/www/server/panel/data",   // default.db、session、用户数据
		"/www/server/panel/config", // 面板配置
		"/www/server/panel/vhost",  // 站点配置
		"/www/server/panel/plugin", // 插件代码
		"/www/server/panel/class",  // 面板核心代码
		"/www/server/panel/script", // 面板脚本
		"/www/server/mysql/data",   // 数据库文件
		"/www/server/nginx/conf",   // nginx 配置
		"/www/server/php",          // PHP 安装目录
		"/www/wwwroot",             // 网站源码
		"/www/backup",              // 备份数据
	}

	for _, path := range baotaPaths {
		if !IsPathBlacklisted(path) {
			t.Errorf("宝塔关键路径 %s 应在清理黑名单中", path)
		}
	}

	// 子路径也应被拦截
	subPaths := []string{
		"/www/server/panel/data/default.db",
		"/www/server/panel/vhost/nginx/site.conf",
		"/www/server/mysql/data/mysql/user.MYD",
		"/www/wwwroot/mysite/index.php",
		"/www/backup/site/20240101.zip",
	}
	for _, path := range subPaths {
		if !IsPathBlacklisted(path) {
			t.Errorf("宝塔关键子路径 %s 应在清理黑名单中", path)
		}
	}

	// 白名单中的日志目录不在黑名单（旧轮转日志允许清理，见 CleanupWhitelist）
	logPaths := []string{
		"/www/server/panel/logs",
		"/www/server/nginx/logs",
		"/www/server/apache/logs",
		"/www/wwwlogs",
	}
	for _, path := range logPaths {
		if IsPathBlacklisted(path) {
			t.Errorf("日志目录 %s 不应在黑名单中（白名单允许清理旧轮转日志）", path)
		}
	}
}

// ============================================================
// 测试 4b: 磁盘清理黑名单 — /var/log 不在黑名单中（可清理）
// ============================================================

func TestIsPathBlacklisted_VarLogNotBlacklisted(t *testing.T) {
	// /var/log 不在黑名单中（它在 CleanupWhitelist 中，不在 CleanupBlacklist 中）
	if IsPathBlacklisted("/var/log") {
		t.Error("/var/log 不应在清理黑名单中")
	}
	if IsPathBlacklisted("/var/log/nginx/access.log.gz") {
		t.Error("/var/log/nginx/access.log.gz 不应在清理黑名单中")
	}
}

// ============================================================
// 测试 4c: 磁盘清理 — 数据库文件扩展名被禁止
// ============================================================

func TestIsFileForbiddenForCleanup_DatabaseFiles(t *testing.T) {
	forbiddenFiles := []string{
		"/www/server/panel/data/default.db",
		"/var/lib/serverguard/serverguard.db",
		"/some/path/data.sqlite",
		"/some/path/data.sqlite3",
		"/some/path/mysql.sock",
		"/some/path/redis.pid",
		"/some/path/nginx.conf",
		"/some/path/api.json",
	}

	for _, path := range forbiddenFiles {
		if !IsFileForbiddenForCleanup(path) {
			t.Errorf("文件 %s 应被禁止清理（扩展名保护）", path)
		}
	}
}

// ============================================================
// 测试 4d: 磁盘清理 — 只允许清理压缩日志文件
// ============================================================

func TestIsFileAllowedForCleanup_OnlyCompressedLogs(t *testing.T) {
	allowedFiles := []string{
		"/var/log/syslog.1.gz",
		"/var/log/auth.log.1",
		"/var/log/kern.log.old",
		"/var/log/nginx/access.log.bz2",
		"/var/log/nginx/access.log.xz",
		"/var/log/nginx/access.log.zip",
	}

	for _, path := range allowedFiles {
		if !IsFileAllowedForCleanup(path) {
			t.Errorf("文件 %s 应允许清理", path)
		}
	}

	disallowedFiles := []string{
		"/var/log/syslog",
		"/var/log/auth.log",
		"/www/server/panel/data/default.db",
		"/etc/nginx/nginx.conf",
	}
	for _, path := range disallowedFiles {
		if IsFileAllowedForCleanup(path) {
			t.Errorf("文件 %s 不应允许清理", path)
		}
	}
}

// ============================================================
// 测试 5: 日志轮转豁免 — 宝塔路径全部豁免
// ============================================================

func TestIsLogRotationExempted_BaotaPaths(t *testing.T) {
	exemptedPaths := []string{
		"/www/server/panel/logs/error.log",
		"/www/wwwlogs/access.log",
		"/www/server/nginx/logs/access.log",
		"/www/server/mysql/data/mysql.err",
		"/www/server/redis/redis.log",
	}

	for _, path := range exemptedPaths {
		// 即使不在 BaotaSafeMode 下，这些路径也应豁免
		if !IsLogRotationExempted(path, false) {
			t.Errorf("路径 %s 应在日志轮转豁免列表中（非 BaotaSafeMode）", path)
		}
	}
}

// ============================================================
// 测试 5b: 日志轮转豁免 — BaotaSafeMode 下所有 /www/ 路径豁免
// ============================================================

func TestIsLogRotationExempted_BaotaSafeModeAllWWW(t *testing.T) {
	wwwPaths := []string{
		"/www/some/random/path.log",
		"/www/custom_app/logs/debug.log",
		"/www/wwwlogs/new_site.log",
	}

	for _, path := range wwwPaths {
		// BaotaSafeMode 下，所有 /www/ 路径都应豁免
		if !IsLogRotationExempted(path, true) {
			t.Errorf("BaotaSafeMode 下，路径 %s 应被豁免", path)
		}
	}

	// 非 BaotaSafeMode 下，不在豁免列表的 /www/ 路径不应被豁免
	nonExempted := "/www/some/random/path.log"
	if IsLogRotationExempted(nonExempted, false) {
		t.Errorf("非 BaotaSafeMode 下，路径 %s 不应被豁免", nonExempted)
	}
}

// ============================================================
// 测试 5c: 日志轮转豁免 — /var/log 路径豁免（系统 logrotate 管理）
// ============================================================

func TestIsLogRotationExempted_VarLog(t *testing.T) {
	if !IsLogRotationExempted("/var/log/syslog", false) {
		t.Error("/var/log/syslog 应被日志轮转豁免")
	}
	if !IsLogRotationExempted("/var/log/nginx/access.log", false) {
		t.Error("/var/log/nginx/access.log 应被日志轮转豁免")
	}
}

// ============================================================
// 测试 8: FIM 排除 — 宝塔面板路径排除
// ============================================================

func TestIsFIMExcluded_BaotaPaths(t *testing.T) {
	excludedPaths := []string{
		"/www/server/panel",
		"/www/server/panel/data",
		"/www/server/panel/logs",
		"/www/server/panel/vhost",
		"/www/server/panel/plugin",
		"/www/server/panel/config",
		"/www/server/panel/config/config.json",
		"/www/wwwroot",
		"/www/server/nginx/conf/nginx.conf",
	}

	for _, path := range excludedPaths {
		if !IsFIMExcluded(path) {
			t.Errorf("FIM 应排除路径: %s", path)
		}
	}
}

// ============================================================
// 测试 9: FIM 排除 — /etc/passwd 不被排除（正常告警）
// ============================================================

func TestIsFIMExcluded_SystemFilesNotExcluded(t *testing.T) {
	systemPaths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/ssh/sshd_config",
		"/etc/nginx/nginx.conf",
	}

	for _, path := range systemPaths {
		if IsFIMExcluded(path) {
			t.Errorf("FIM 不应排除系统文件: %s（应正常告警）", path)
		}
	}
}

// ============================================================
// 测试 6: RestartGuard — 宝塔面板自身禁止自动重启
// ============================================================

func TestRestartGuard_BaotaPanelNeverRestarted(t *testing.T) {
	rg := NewRestartGuard()

	panelNames := []string{"bt", "bt-panel", "btpanel", "BT-Panel", "Bt-Panel", "bt_panel"}
	for _, name := range panelNames {
		err, cmd := rg.BeforeAutoRestart(name, true)
		if err == nil {
			t.Errorf("宝塔面板服务 %s 应禁止自动重启", name)
		}
		if cmd != "" {
			t.Errorf("宝塔面板服务 %s 不应返回重启命令", name)
		}
	}
}

// ============================================================
// 测试 6b: RestartGuard — 宝塔环境下服务使用 /etc/init.d/ 脚本
// ============================================================

func TestRestartGuard_BaotaManagedServicesUseInitD(t *testing.T) {
	rg := NewRestartGuard()

	// 这些服务在 BaotaManagedServices 中
	managedServices := []string{"nginx", "mysqld", "redis", "php-fpm", "pure-ftpd"}
	for _, name := range managedServices {
		// 在 BaotaSafeMode 下，应返回 /etc/init.d/ 命令（如果脚本存在）
		// 由于测试环境中 /etc/init.d/nginx 可能不存在，我们只验证不返回 "禁止自动重启" 错误
		err, _ := rg.BeforeAutoRestart(name, true)
		// 不应返回"禁止自动重启"错误（面板自身才禁止）
		if err != nil && strings.Contains(err.Error(), "禁止自动重启") {
			t.Errorf("宝塔管理服务 %s 不应被禁止重启: %v", name, err)
		}
	}
}

// ============================================================
// 测试 7: RestartGuard — 重启风暴检测
// ============================================================

func TestRestartGuard_StormDetection(t *testing.T) {
	rg := NewRestartGuard()

	// 连续重启 3 次应触发风暴检测
	serviceName := "nginx"
	for i := 0; i < 3; i++ {
		rg.recordRestart(serviceName)
	}

	// 第 4 次应被风暴检测阻止
	err, _ := rg.BeforeAutoRestart(serviceName, false)
	if err == nil {
		t.Error("重启风暴应被检测到并阻止第 4 次重启")
	}
}

// ============================================================
// 测试 7b: RestartGuard — BaotaManagedServices 包含所有关键服务
// ============================================================

func TestBaotaManagedServices_ContainsAllKeyServices(t *testing.T) {
	required := []string{
		"nginx", "httpd", "apache2", "mysqld", "mariadbd",
		"redis", "redis-server", "php-fpm",
		"php-fpm-52", "php-fpm-74", "php-fpm-80", "php-fpm-83",
		"pure-ftpd", "vsftpd", "memcached", "mongodb", "tomcat",
	}

	for _, name := range required {
		if !BaotaManagedServices[name] {
			t.Errorf("BaotaManagedServices 缺少服务: %s", name)
		}
	}
}

// ============================================================
// 测试 7c: RestartGuard — BaotaPanelServiceNames 包含所有面板名称
// ============================================================

func TestBaotaPanelServiceNames_ContainsAllVariants(t *testing.T) {
	required := []string{"bt", "bt-panel", "btpanel", "BT-Panel", "Bt-Panel", "bt_panel"}

	for _, name := range required {
		if !BaotaPanelServiceNames[name] {
			t.Errorf("BaotaPanelServiceNames 缺少面板名称: %s", name)
		}
	}
}

// ============================================================
// 测试 3e: getDefaultHardWhitelist — Linux 下合并宝塔白名单
// ============================================================

func TestGetDefaultHardWhitelist_ContainsBaotaProcesses(t *testing.T) {
	wl := getDefaultHardWhitelist()

	// serverguard-agent 在所有平台都在 hard whitelist 中
	if !wl["serverguard-agent"] {
		t.Error("hard whitelist 应包含 serverguard-agent")
	}

	// Linux 专属测试：宝塔进程在 hard whitelist 中
	if runtime.GOOS != "windows" {
		baotaProcs := []string{
			"bt", "bt-panel", "btpanel",
			"nginx", "httpd", "php-fpm",
			"mysqld", "redis-server",
		}
		for _, name := range baotaProcs {
			if !wl[name] {
				t.Errorf("hard whitelist 应包含宝塔进程: %s", name)
			}
		}
	}
}

// ============================================================
// 辅助函数
// ============================================================

func testSafetyConfig() config.SafetyConfig {
	return config.SafetyConfig{
		KillBudgetHourly:            15,
		KillBudgetDaily:             50,
		KillMinInterval:             config.Duration(30 * time.Second),
		CircuitBreakerThreshold:     3,
		CircuitBreakerResetDuration: config.Duration(30 * time.Minute),
		MinAvailableMemoryMB:        50,
		MaxLoadFactor:               3.0,
		MaxDiskIOWaitPercent:        80,
		MinDiskAvailableMB:          500,
		ObservationWindow:           config.Duration(60 * time.Second),
		TrashDir:                    "/var/lib/serverguard/.trash",
	}
}
