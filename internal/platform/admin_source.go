package platform

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// adminSourceIPs 返回当前已通过认证登录的用户来源 IP（`who` 输出解析）。
// 只有认证会话才会出现在 who 里——爆破者即使保持已建立的 TCP 连接也不会出现，
// 因此用它作为"管理员来源"判定不会放过正在爆破的攻击者。
func adminSourceIPs() map[string]bool {
	out := map[string]bool{}
	if runtime.GOOS == "windows" {
		// Windows 下 netsh 封禁按规则名清理、且远程桌面来源获取复杂，
		// 暂不做管理员来源保护（BanIP 在 Windows 上本就极少自动触发）
		return out
	}
	// who 输出示例: "admin    pts/0        2026-08-17 09:30 (203.0.113.7)"
	cmd := exec.Command("sh", "-c", "who 2>/dev/null || w -h 2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, token := range strings.Fields(string(output)) {
		token = strings.Trim(token, "()")
		if ip := net.ParseIP(token); ip != nil && !ip.IsLoopback() {
			out[ip.String()] = true
		}
	}
	return out
}

// IsAdminSSHSource 判断给定 IP 是否是当前已登录用户（管理员）的来源地址。
// 封禁前调用：把正在使用 SSH 的管理员一起封掉等于把钥匙锁在门里，
// 且进程崩溃后残留规则没有任何自动解封机制能救回。
func IsAdminSSHSource(ip string) bool {
	if ip == "" {
		return false
	}
	if parsed := net.ParseIP(ip); parsed == nil || parsed.IsLoopback() {
		return false
	}
	return adminSourceIPs()[ip]
}
