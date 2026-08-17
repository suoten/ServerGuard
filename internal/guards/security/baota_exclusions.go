package security

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// WebShellScanExclusions WebShell 扫描排除目录（前缀匹配）。
// 宝塔自身代码目录包含大量 PHP/Python 函数调用，会触发 WebShell 特征误报。
var WebShellScanExclusions = []string{
	"/www/server/panel",
	"/www/server/panel/class",
	"/www/server/panel/plugin",
	"/www/server/panel/BTPanel",
	"/www/server/panel/pyenv", // Python 虚拟环境
	"/www/server/panel/script",
	"/www/server/panel/task",
	// 宝塔管理工具
	"/www/server/bt",
	// 常见 CMS 缓存/编译目录（通配符通过 glob 模式处理）
}

// WebShellScanGlobExclusions 通配符排除模式（使用 filepath.Match 规则）。
// 匹配 /www/wwwroot/*/runtime, /www/wwwroot/*/cache, /www/wwwroot/*/temp 等。
var WebShellScanGlobExclusions = []string{
	"/www/wwwroot/*/runtime",
	"/www/wwwroot/*/cache",
	"/www/wwwroot/*/temp",
	"/www/wwwroot/*/storage/framework",
	// PHP 框架核心目录（包含大量 eval/system 等函数调用，非 WebShell）
	"/www/wwwroot/*/thinkphp",
	"/www/wwwroot/*/vendor",
	"/www/wwwroot/*/node_modules",
	"/www/wwwroot/*/tests",
	"/www/wwwroot/*/test",
	"/www/wwwroot/*/libraries",
	"/www/wwwroot/*/core",
	"/www/wwwroot/*/system",
	// Laravel 框架
	"/www/wwwroot/*/bootstrap",
	// WordPress / CMS 核心
	"/www/wwwroot/*/wp-includes",
	"/www/wwwroot/*/wp-admin",
	// Composer 依赖
	"/www/wwwroot/*/.composer",
}

// IsWebShellScanExcluded 检查给定路径是否在 WebShell 扫描排除目录内。
// 支持前缀匹配和通配符匹配。
func IsWebShellScanExcluded(path string) bool {
	// 前缀匹配
	for _, prefix := range WebShellScanExclusions {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}

	// 通配符匹配（如 /www/wwwroot/*/runtime）
	for _, pattern := range WebShellScanGlobExclusions {
		if matchGlobPath(pattern, path) {
			return true
		}
	}

	return false
}

// matchGlobPath 检查路径是否匹配通配符模式。
// 支持 /www/wwwroot/*/runtime 这类模式。
func matchGlobPath(pattern, path string) bool {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i, pp := range patternParts {
		if pp == "*" {
			continue // 通配符匹配任意单层目录
		}
		if pp != pathParts[i] {
			return false
		}
	}
	return true
}

// IsUserWebsitePath 检查路径是否在用户网站目录下。
// 用于 WebShell 告警信息中标注"该文件位于用户网站目录，非系统文件"。
func IsUserWebsitePath(path string) bool {
	return strings.HasPrefix(path, "/www/wwwroot/")
}

// --- Cron 任务白名单 ---

// CronWhitelistPatterns Cron 任务白名单模式（命令行包含即信任）。
// 宝塔的计划任务脚本可能被误报为可疑 Cron。
var CronWhitelistPatterns = []string{
	"/www/server/panel/script/",           // 宝塔计划任务脚本目录
	"/www/server/panel/logs/",             // 宝塔日志清理任务
	"/etc/init.d/bt",                      // 宝塔面板启动脚本
	"/usr/local/bin/bt",                   // 宝塔命令
	"bt restart", "bt start", "bt stop",   // 宝塔命令
	"bt default", "bt 14", "bt 5",         // 宝塔常用命令
	"nginx -s reload",                     // Nginx 重载
	"/www/server/panel/pyenv/bin/python",  // 宝塔 Python 环境
	"/www/server/panel/install/",          // 宝塔安装脚本
	"/www/server/panel/class/",            // 宝塔面板类
	"systemctl reload nginx",              // 系统重载 Nginx
	"systemctl reload php-fpm",            // 系统重载 PHP-FPM
}

// IsCronWhitelisted 检查 cron 命令行是否匹配白名单模式。
// 匹配即标记为"可信任务"，不告警。
func IsCronWhitelisted(command string) bool {
	lowerCmd := strings.ToLower(command)
	for _, pattern := range CronWhitelistPatterns {
		if strings.Contains(lowerCmd, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// --- 异地登录 IP 白名单 ---

// SSHLoginWhitelistPaths 宝塔面板配置文件路径，用于读取绑定 IP。
var SSHLoginWhitelistPaths = []string{
	"/www/server/panel/data/limitip.conf",   // 宝塔面板授权 IP
	"/www/server/panel/data/domain.conf",    // 宝塔面板绑定域名
	"/www/server/panel/data/allowip.pl",     // 宝塔面板允许 IP（部分版本）
}

// LoadBaotaIPWhitelist 从宝塔面板配置中读取 IP 白名单。
// 读取 limitip.conf、domain.conf、allowip.pl 中的绑定 IP。
// 如果文件不存在或读取失败，返回空列表（不影响正常检测）。
func LoadBaotaIPWhitelist() []string {
	var ips []string
	seen := make(map[string]bool)

	for _, path := range SSHLoginWhitelistPaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// limitip.conf / allowip.pl 格式: 每行一个 IP 或 CIDR
			// 也可能是逗号分隔的 IP 列表
			fields := strings.FieldsFunc(line, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
			})

			for _, field := range fields {
				field = strings.TrimSpace(field)
				if field == "" {
					continue
				}
				// 验证是 IP 或 CIDR 格式
				if isValidIPOrCIDR(field) && !seen[field] {
					ips = append(ips, field)
					seen[field] = true
				}
			}
		}
		file.Close()
	}

	return ips
}

// isValidIPOrCIDR 检查字符串是否为有效的 IP 地址或 CIDR 格式。
func isValidIPOrCIDR(s string) bool {
	// 检查是否包含 CIDR 前缀长度（如 192.168.1.0/24）
	if idx := strings.Index(s, "/"); idx >= 0 {
		ipPart := s[:idx]
		// 简单验证 IP 部分
		return isValidIPv4(ipPart)
	}
	return isValidIPv4(s)
}

// isValidIPv4 简单验证 IPv4 地址格式。
func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		num := 0
		for _, c := range part {
			num = num*10 + int(c-'0')
		}
		if num > 255 {
			return false
		}
	}
	return true
}

// isIPInWhitelist 检查 IP 是否在白名单中。
// 白名单支持精确 IP 匹配和 CIDR 匹配。
func isIPInWhitelist(ip string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, entry := range whitelist {
		// 精确匹配
		if entry == ip {
			return true
		}

		// CIDR 匹配
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil {
				if cidr.Contains(parsedIP) {
					return true
				}
			}
		}
	}
	return false
}
