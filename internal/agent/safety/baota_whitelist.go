package safety

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// BaotaProcessWhitelist 宝塔生态进程白名单，匹配 cmdline / comm / name 任一字段。
// 白名单内的进程永不 Kill、永不降权，即使 CPU 100% 持续 1 小时也只告警不操作。
// 内存泄漏检测同样只告警不重启。
var BaotaProcessWhitelist = []string{
	// 宝塔核心
	"bt", "bt-panel", "btpanel", "BT-Panel", "Bt-Panel",
	"bt-task", "bt-task.py", "bt_monitor",
	// python / python3 需二次确认（见 IsBaotaProtectedProcess），不在此直接保护

	// 宝塔插件
	"supervisord", // 进程守护管理器

	// Web 服务
	"nginx", "httpd", "apache2", "apache", "php-fpm", "php-cgi",
	"php-fpm-52", "php-fpm-53", "php-fpm-54", "php-fpm-55",
	"php-fpm-56", "php-fpm-70", "php-fpm-71", "php-fpm-72",
	"php-fpm-73", "php-fpm-74", "php-fpm-80", "php-fpm-81",
	"php-fpm-82", "php-fpm-83",

	// 数据库
	"mysqld", "mariadbd", "postgres", "redis-server", "mongod",

	// FTP
	"pure-ftpd", "vsftpd",

	// DNS / Mail
	"named", "bind9", "postfix", "dovecot", "sendmail",

	// 系统核心
	"systemd", "systemd-journal", "systemd-journald", "systemd-network",
	"systemd-networkd", "systemd-resolve", "systemd-resolved",
	"sshd", "ssh", "cron", "crond", "atd", "auditd", "rsyslogd", "syslog-ng",
	"dockerd", "containerd", "containerd-shim",

	// ServerGuard 自身
	"serverguard", "serverguard-agent",
}

// baotaWhitelistSet 预构建的 set，用于 O(1) 查找。
var baotaWhitelistSet map[string]bool
var baotaWhitelistOnce sync.Once

// GetBaotaWhitelistSetPublic 返回宝塔白名单 set 的公共访问方法。
// 供其他包（如 guards/service）查询进程是否在宝塔白名单中。
func GetBaotaWhitelistSetPublic() map[string]bool {
	return getBaotaWhitelistSet()
}

// getBaotaWhitelistSet 返回预构建的白名单 set（惰性初始化）。
func getBaotaWhitelistSet() map[string]bool {
	baotaWhitelistOnce.Do(func() {
		baotaWhitelistSet = make(map[string]bool, len(BaotaProcessWhitelist))
		for _, name := range BaotaProcessWhitelist {
			baotaWhitelistSet[strings.ToLower(name)] = true
		}
	})
	return baotaWhitelistSet
}

// pythonConfirmNames 需要二次确认的通用进程名。
// 这些进程名本身太通用（python/python3），不能仅凭名称保护，
// 必须通过路径或父进程二次确认是宝塔相关才保护。
var pythonConfirmNames = map[string]bool{
	"python":  true,
	"python3": true,
	"python2": true,
}

// baotaPathMarkers 宝塔相关的路径标记，用于二次确认 python 进程。
var baotaPathMarkers = []string{
	"/www/server/panel",
	"/www/server/",
	"/www/backup/",
	"panelSite.py",
	"panelPlugin.py",
	"BTPanel",
}

// baotaParentNames 宝塔相关的父进程名，用于二次确认 python 进程。
var baotaParentNames = map[string]bool{
	"bt":         true,
	"bt-panel":   true,
	"btpanel":    true,
	"bt-task":    true,
	"supervisord": true,
}

// ProcInfo 包含从 /proc 读取的进程标识信息，用于白名单匹配。
type ProcInfo struct {
	PID     int32  `json:"pid"`      // 进程 ID
	Comm    string `json:"comm"`     // /proc/{pid}/comm 内容（进程名，限 15 字符）
	Cmdline string `json:"cmdline"`  // /proc/{pid}/cmdline 内容（完整命令行）
	Exe     string `json:"exe"`      // /proc/{pid}/exe 软链接指向（可执行文件路径）
	Cwd     string `json:"cwd"`      // /proc/{pid}/cwd 软链接指向（工作目录）
	PPID    int32  `json:"ppid"`     // 父进程 ID
	PPName  string `json:"pp_name"`  // 父进程名
}

// IsBaotaProtectedProcess 判断进程是否属于宝塔白名单保护范围。
// 匹配规则：
//  1. 检查 comm / cmdline / exe 任一字段是否命中白名单
//  2. 对于 python / python3 等通用进程名，必须二次确认：
//     a. cmdline 或 cwd 包含 /www/server/panel 等宝塔路径标记
//     b. 或父进程为宝塔相关进程
//  3. 禁止仅凭进程名保护 python，避免放过真正的恶意 Python 脚本
func IsBaotaProtectedProcess(info *ProcInfo) bool {
	if info == nil {
		return false
	}

	wl := getBaotaWhitelistSet()

	// 收集所有可匹配的名称字段（统一小写）
	candidates := []string{
		strings.ToLower(info.Comm),
		strings.ToLower(filepath.Base(info.Exe)),
	}
	// cmdline 中提取第一个 token 的 basename 作为进程名
	if info.Cmdline != "" {
		parts := strings.Fields(info.Cmdline)
		if len(parts) > 0 {
			candidates = append(candidates, strings.ToLower(filepath.Base(parts[0])))
		}
	}

	// 步骤 1：直接匹配白名单（非 python 类）
	for _, c := range candidates {
		if c == "" {
			continue
		}
		// 如果是 python 类通用名，跳过直接匹配，走二次确认
		if pythonConfirmNames[c] {
			continue
		}
		if wl[c] {
			return true
		}
	}

	// 步骤 2：python 类进程二次确认
	isPython := false
	for _, c := range candidates {
		if pythonConfirmNames[c] {
			isPython = true
			break
		}
	}
	if !isPython {
		return false
	}

	// 2a: 检查 cmdline / cwd 是否包含宝塔路径标记
	fieldsToCheck := info.Cmdline + " " + info.Cwd + " " + info.Exe
	for _, marker := range baotaPathMarkers {
		if strings.Contains(fieldsToCheck, marker) {
			return true
		}
	}

	// 2b: 检查父进程是否为宝塔相关进程
	if info.PPName != "" && baotaParentNames[strings.ToLower(info.PPName)] {
		return true
	}

	return false
}

// ReadProcInfo 从 /proc 文件系统读取进程标识信息（仅 Linux）。
// 在 Windows 上返回空 ProcInfo。
// 读取 comm、cmdline、exe 软链接、cwd 软链接，用于白名单精确匹配。
func ReadProcInfo(pid int32) *ProcInfo {
	info := &ProcInfo{PID: pid}

	// /proc/{pid}/comm — 进程名（内核限制 15 字符）
	if data, err := os.ReadFile("/proc/" + itoa(pid) + "/comm"); err == nil {
		info.Comm = strings.TrimSpace(string(data))
	}

	// /proc/{pid}/cmdline — 完整命令行（参数以 \0 分隔）
	if data, err := os.ReadFile("/proc/" + itoa(pid) + "/cmdline"); err == nil {
		// 将 \0 替换为空格，末尾的 \0 去掉
		cmdline := strings.TrimRight(string(data), "\x00")
		info.Cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
	}

	// /proc/{pid}/exe — 软链接指向可执行文件
	if exe, err := os.Readlink("/proc/" + itoa(pid) + "/exe"); err == nil {
		info.Exe = exe
	}

	// /proc/{pid}/cwd — 软链接指向工作目录
	if cwd, err := os.Readlink("/proc/" + itoa(pid) + "/cwd"); err == nil {
		info.Cwd = cwd
	}

	// 读取父进程信息用于二次确认
	if ppid, ppName := readParentInfo(pid); ppid > 0 {
		info.PPID = ppid
		info.PPName = ppName
	}

	return info
}

// readParentInfo 读取指定进程的父进程 PID 和名称。
func readParentInfo(pid int32) (int32, string) {
	// /proc/{pid}/status 中包含 PPid 行
	data, err := os.ReadFile("/proc/" + itoa(pid) + "/status")
	if err != nil {
		return 0, ""
	}

	var ppid int32
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// 解析 PPid 数字
				ppid = parsePid(parts[1])
				break
			}
		}
	}

	if ppid <= 0 {
		return 0, ""
	}

	// 读取父进程的 comm
	ppName := ""
	if data, err := os.ReadFile("/proc/" + itoa(ppid) + "/comm"); err == nil {
		ppName = strings.TrimSpace(string(data))
	}

	return ppid, ppName
}

// itoa 将 int32 转为字符串（避免引入 strconv 在热路径的开销，保持简单）。
func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [12]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// parsePid 将字符串解析为 int32 PID。
func parsePid(s string) int32 {
	var n int32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int32(c-'0')
	}
	return n
}
