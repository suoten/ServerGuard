package safety

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================
// 磁盘清理策略 v2 — 分层精确防护
// ============================================================
//
// 清理流程（6 层安全检查，缺一不可）：
//
//  1. CleanupWhitelist       — 哪些目录可以扫描
//  2. CleanupBlacklist       — 扫描目录中哪些子路径绝对不能碰
//  3. CleanupProtectedPatterns — 哪些文件名模式不能碰（sess_*、bt_* 等）
//  4. CleanupForbiddenExtensions — 哪些文件类型不能删（.db、.sock、.conf 等）
//  5. CleanupAllowedExtensions  — 只有哪些文件类型可以删（.gz、.1、.old 等）
//  6. IsFileBeingWritten       — 文件是否正在被写入
//
// 设计原则：不是一刀切地屏蔽 /tmp、/www，而是精确到子目录和文件模式。
//

// ------------------------------------------------------------
// 第 1 层：CleanupWhitelist — 允许扫描的目录
// ------------------------------------------------------------

// CleanupWhitelist 磁盘清理允许扫描的目录。
// 只扫描这些目录，不在此列表中的目录根本不会被遍历。
// 扫描后仍需通过第 2~6 层安全检查才会实际删除文件。
var CleanupWhitelist = []string{
	// ── 系统日志 ──
	"/var/log",

	// ── 宝塔 Web 日志（旧轮转日志可安全清理） ──
	"/www/wwwlogs",

	// ── 宝塔面板日志（旧轮转日志可安全清理） ──
	"/www/server/panel/logs",

	// ── Nginx 日志（宝塔安装版） ──
	"/www/server/nginx/logs",

	// ── Apache 日志（宝塔安装版） ──
	"/www/server/apache/logs",

	// ── 临时目录（仅清理旧压缩文件，通过 ProtectedPatterns 保护会话文件） ──
	"/tmp",
	"/var/tmp",

	// ── Java 应用日志目录（自动发现，用于紧急清理 Java 暴日志场景） ──
	// wvp-gb28181-pro 等Java应用常见日志路径
	"/opt/wvp/logs",
	"/opt/wvp-pro/logs",
	"/opt/wvp-gb28181-pro/logs",
	"/opt/mediakit/logs",
	"/opt/zlm/logs",
	"/opt/zlmediakit/logs",
	// 通用 Java 应用日志
	"/var/log/java",
	"/var/log/wvp",
	"/var/log/zlm",
	// Spring Boot / 通用 Java 应用
	"/opt/app/logs",
	"/opt/app/log",

	// ── systemd journal 日志（紧急时通过 journalctl vacuum 清理） ──
	"/var/log/journal",
}

// ------------------------------------------------------------
// 第 2 层：CleanupBlacklist — 绝对禁止触碰的路径
// ------------------------------------------------------------

// CleanupBlacklist 磁盘清理绝对禁止触碰的路径（前缀匹配）。
// 即使路径在 CleanupWhitelist 的目录下，如果匹配黑名单也会被跳过。
//
// 注意：不再一刀切屏蔽 /tmp、/www、/opt。
// 而是精确保护关键子目录：数据库文件、配置文件、网站源码、备份等。
var CleanupBlacklist = []string{
	// ── 宝塔面板核心数据（绝对不能碰） ──
	"/www/server/panel/data",    // default.db、session、用户数据
	"/www/server/panel/config",  // 面板配置
	"/www/server/panel/vhost",   // 站点配置
	"/www/server/panel/plugin",  // 插件代码
	"/www/server/panel/class",   // 面板核心代码
	"/www/server/panel/script",  // 面板脚本

	// ── 数据库数据目录（绝对不能碰） ──
	"/www/server/mysql/data",
	"/www/server/mariadb/data",
	"/www/server/redis/data",
	"/www/server/pgsql/data",
	"/www/server/mongodb/data",
	"/var/lib/mysql",
	"/var/lib/redis",
	"/var/lib/pgsql",
	"/var/lib/mongodb",

	// ── 网站源码目录（绝对不能碰） ──
	"/www/wwwroot",

	// ── 备份数据（绝对不能碰） ──
	"/www/backup",

	// ── 宝塔软件配置目录（不能碰，但 logs 子目录已在白名单中单独处理） ──
	"/www/server/nginx/conf",
	"/www/server/apache/conf",
	"/www/server/php",
	"/www/server/pure-ftpd",

	// ── 系统关键目录 ──
	"/etc",
	"/usr/bin",
	"/usr/sbin",
	"/usr/local/bin",
	"/usr/local/sbin",
	"/dev/shm", // 内存文件系统
	"/boot",
	"/proc", "/sys", "/run", "/dev", // 虚拟文件系统

	// ── ServerGuard 自身 ──
	"/opt/serverguard",
	"/var/lib/serverguard",
}

// ------------------------------------------------------------
// 第 3 层：CleanupProtectedPatterns — 受保护的文件名模式
// ------------------------------------------------------------

// CleanupProtectedPatterns 受保护的文件名前缀/模式。
// 即使文件扩展名在允许列表中（如 .zip），如果文件名匹配这些模式也会被跳过。
// 主要用于保护 /tmp 中的会话文件和宝塔临时文件。
var CleanupProtectedPatterns = []string{
	"sess_",      // PHP session 文件（sess_xxxx）
	"bt_",        // 宝塔临时文件（bt_xxxx）
	"bt-panel",   // 宝塔面板相关
	".mozilla",   // Firefox 缓存
	"systemd-",   // systemd 临时文件
	"vim.",       // vim 交换文件（.swp 被扩展名检查拦截，但 vim.xxx 需要这里拦截）
}

// IsFileProtectedByPattern 检查文件名是否匹配受保护模式。
func IsFileProtectedByPattern(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, pattern := range CleanupProtectedPatterns {
		if strings.HasPrefix(base, pattern) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------
// 第 4 层：CleanupForbiddenExtensions — 禁止删除的文件类型
// ------------------------------------------------------------

// CleanupForbiddenExtensions 磁盘清理禁止删除的文件扩展名。
// 防止误删数据库文件、配置文件、证书等。
var CleanupForbiddenExtensions = []string{
	".db", ".sqlite", ".sqlite3",
	".sock", ".pid", ".lock",
	".conf", ".cfg", ".ini",
	".key", ".pem", ".crt", ".csr",
	".pl", ".py", ".sh", ".json",
}

// ------------------------------------------------------------
// 第 5 层：CleanupAllowedExtensions — 仅允许删除的文件类型
// ------------------------------------------------------------

// CleanupAllowedExtensions 磁盘清理仅允许删除的文件扩展名。
// 只有这些扩展名的文件才会被清理（旧轮转日志和压缩包）。
// 注意：活跃的 .log 文件不在此列表中（不直接删除），
// 但在紧急情况下会通过 copytruncate 策略安全截断（见 EmergencyLogCleaner）。
var CleanupAllowedExtensions = []string{
	".gz", ".1", ".old", ".bz2", ".xz", ".zip",
	// Java 应用轮转日志
	".log.gz", ".log.1", ".log.old",
	".out.gz", ".out.1", ".out.old",
}

// ============================================================
// 安全检查函数
// ============================================================

// IsPathBlacklisted 检查给定路径是否落在清理黑名单前缀内。
// 使用 filepath.EvalSymlinks 解析 realpath，防止符号链接绕过。
// 如果 realpath 解析失败，回退到原始路径检查。
func IsPathBlacklisted(path string) bool {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		realPath = path
	}

	for _, prefix := range CleanupBlacklist {
		if realPath == prefix || strings.HasPrefix(realPath, prefix+"/") {
			return true
		}
		// 也检查原始路径（防止 symlink 指向黑名单）
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// IsFileForbiddenForCleanup 检查文件是否因扩展名被禁止清理。
// .db / .sqlite / .sqlite3 等数据库文件绝对禁止删除。
func IsFileForbiddenForCleanup(path string) bool {
	lowerPath := strings.ToLower(path)
	for _, ext := range CleanupForbiddenExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// IsFileAllowedForCleanup 检查文件扩展名是否在允许清理的范围内。
// 只有 .gz / .1 / .old / .bz2 / .xz / .zip 才允许清理。
func IsFileAllowedForCleanup(path string) bool {
	lowerPath := strings.ToLower(path)
	for _, ext := range CleanupAllowedExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// IsFileSafeForCleanup 综合安全检查：文件是否可以安全清理。
// 依次检查：黑名单路径 → 受保护文件名模式 → 禁止扩展名 → 允许扩展名。
// 调用方还需额外检查 IsFileBeingWritten 和文件年龄。
func IsFileSafeForCleanup(path string) bool {
	// 检查 1: 路径黑名单
	if IsPathBlacklisted(path) {
		return false
	}
	// 检查 2: 受保护文件名模式
	if IsFileProtectedByPattern(path) {
		return false
	}
	// 检查 3: 禁止扩展名
	if IsFileForbiddenForCleanup(path) {
		return false
	}
	// 检查 4: 允许扩展名
	if !IsFileAllowedForCleanup(path) {
		return false
	}
	return true
}

// IsFileBeingWritten 检查文件是否正在被写入。
// 启发式：mtime 在最近 2 分钟内视为活跃文件，跳过清理。
//
// 注意：原实现（O_WRONLY|O_EXCL 打开）在 Linux 上是无效检查——内核对普通
// 文件忽略 O_EXCL、root 可打开任何文件，恒返回 false，"活跃写入保护"
// 这一层防护名存实亡。mtime 启发式虽不能 100% 捕获写入，但配合
// "只删轮转旧文件（.gz/.1/.old）"的扩展名白名单已足够安全：
// 轮转归档文件本就不该有进程在写。
func IsFileBeingWritten(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// 文件消失/不可访问：按"正在变化"处理，让调用方跳过
		return true
	}
	return time.Since(info.ModTime()) < 2*time.Minute
}

// ============================================================
// 日志轮转豁免（独立于磁盘清理，用于 LogGuard 日志轮转）
// ============================================================

// LogRotationExemptions 日志轮转豁免路径（前缀匹配）。
// 豁免路径下的日志文件禁止自动轮转，改为告警通知用户手动处理。
// 注意：轮转豁免比磁盘清理更保守 — 活跃日志的轮转可能影响服务。
var LogRotationExemptions = []string{
	"/www/server/panel/logs",     // 宝塔面板日志
	"/www/wwwlogs",               // 网站访问日志（轮转需配合 nginx -s reopen）
	"/www/server/nginx/logs",     // Nginx 日志（需 nginx -s reopen）
	"/www/server/apache/logs",    // Apache 日志（需 graceful restart）
	"/www/server/mysql/data",     // MySQL 日志（需 FLUSH LOGS）
	"/www/server/redis",          // Redis 日志
	"/www/server/pgsql/log",      // PostgreSQL 日志
	"/var/log",                   // 系统日志（由 logrotate 管理）
}

// IsLogRotationExempted 检查给定路径是否在日志轮转豁免列表中。
func IsLogRotationExempted(path string, baotaSafeMode bool) bool {
	// 宝塔安全模式下，所有 /www 路径下的日志一律不自动轮转
	// （轮转活跃日志可能导致服务异常，但磁盘清理旧轮转文件不受影响）
	if baotaSafeMode && strings.HasPrefix(path, "/www/") {
		return true
	}

	for _, prefix := range LogRotationExemptions {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// ============================================================
// 文件完整性监控排除（独立于磁盘清理）
// ============================================================

// FIMExclusions 文件完整性监控（FIM）排除路径（前缀匹配）。
// 排除宝塔动态修改的文件，避免误报。
var FIMExclusions = []string{
	"/www/server/panel",           // 宝塔面板自身会频繁更新
	"/www/server/panel/data",      // 面板数据库、session、配置
	"/www/server/panel/logs",      // 日志文件自然变化
	"/www/server/panel/vhost",     // 站点配置频繁变更
	"/www/server/panel/plugin",    // 插件安装卸载
	"/www/server/panel/class",     // 面板核心代码
	"/www/server/panel/config",    // 配置动态变更
	"/www/wwwroot",                // 网站文件由用户/宝塔管理
	"/www/server/nginx/conf",      // Nginx 配置由宝塔管理
	"/www/server/php",             // PHP 版本配置
	"/tmp", "/var/tmp", "/dev/shm", // 临时目录
	"/var/log", "/var/spool",      // 系统动态目录
	"/proc", "/sys", "/run", "/dev", // 虚拟文件系统
}

// IsFIMExcluded 检查给定路径是否在文件完整性监控排除列表中。
func IsFIMExcluded(path string) bool {
	for _, prefix := range FIMExclusions {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
