package websecurity

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// ============================================================
// 反弹 Shell 检测器
// 检测服务器上运行的可疑进程：
// 1. bash -i >& /dev/tcp/ 类特征
// 2. 进程连接外部异常端口
// 3. Python/Perl 一行反弹 Shell
// 4. socat/ncat 反弹
// ============================================================

// ReverseShellDetector 反弹 Shell 检测器
type ReverseShellDetector struct {
	// 已知反弹 Shell 命令行模式
	patterns []*regexp.Regexp
	// 内网 IP 范围（不在这些范围的外部连接才可疑）
	privateCIDRs []*net.IPNet
}

// NewReverseShellDetector 创建检测器
func NewReverseShellDetector() *ReverseShellDetector {
	patterns := []*regexp.Regexp{
		// bash -i >& /dev/tcp/IP/PORT
		regexp.MustCompile(`bash\s+-i\s*(?:>&|>&|>\s*/dev/tcp/)`),
		// bash -c "bash -i >& /dev/tcp/
		regexp.MustCompile(`bash\s+-c\s*.*bash\s+-i`),
		// python -c "import socket,os,pty
		regexp.MustCompile(`python\d?\s+-c\s*["'].*import\s+(?:socket|os|pty|subprocess)`),
		// perl -e 'use Socket
		regexp.MustCompile(`perl\s+(?:-e|-le)\s*["'].*use\s+Socket`),
		// perl -MIO -e
		regexp.MustCompile(`perl\s+-MIO\s`),
		// socat exec
		regexp.MustCompile(`socat\s+.*exec`),
		// ncat --exec
		regexp.MustCompile(`ncat\s+.*--exec`),
		// nc -e /bin/bash
		regexp.MustCompile(`\bnc\s+.*-e\s+/bin/(?:bash|sh|zsh)`),
		// /bin/sh -i
		regexp.MustCompile(`/bin/(?:sh|bash)\s+-i\s`),
		// python反弹：socket.socketconnect
		regexp.MustCompile(`socket\.socket\s*\(\s*socket\.AF_INET.*socket\.SOCK_STREAM.*\.connect\s*\(`),
		// mkfifo + nc
		regexp.MustCompile(`mkfifo\s+.*\|\s*nc\s+\d+\.\d+\.\d+\.\d+`),
		// telnet IP port | /bin/bash
		regexp.MustCompile(`telnet\s+\d+\.\d+\.\d+\.\d+\s+\d+\s*\|\s*/bin/(?:bash|sh)`),
		// xterm -display
		regexp.MustCompile(`xterm\s+-display\s+\d+\.\d+\.\d+\.\d+`),
		// whois/awk 反弹
		regexp.MustCompile(`awk\s+'BEGIN.*"/bin/sh"`),
		// find -exec
		regexp.MustCompile(`find\s+.*-exec\s+/bin/(?:sh|bash)\s`),
	}

	// 内网 IP CIDR
	privateCIDRs := []*net.IPNet{}
	for _, cidr := range []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			privateCIDRs = append(privateCIDRs, n)
		}
	}

	return &ReverseShellDetector{
		patterns:     patterns,
		privateCIDRs: privateCIDRs,
	}
}

// ReverseShellFinding 反弹 Shell 检测结果
type ReverseShellFinding struct {
	Severity   types.Severity
	Title      string
	Message    string
	PID        int
	ProcName   string
	CmdLine    string
	RemoteAddr string
	Action     string
}

// Detect 检测反弹 Shell（通过 /proc 扫描进程命令行 + 网络连接）
func (d *ReverseShellDetector) Detect(ctx context.Context) []ReverseShellFinding {
	findings := []ReverseShellFinding{}

	// 扫描 /proc/*/cmdline
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return findings
	}

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !isNumeric(pid) {
			continue
		}

		// 读取 cmdline
		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil || len(cmdlineBytes) == 0 {
			continue
		}
		// cmdline 用 \0 分隔参数
		cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)

		// 匹配反弹 Shell 模式
		for _, pat := range d.patterns {
			if pat.MatchString(cmdline) {
				procName := getProcName(pid)
				findings = append(findings, ReverseShellFinding{
					Severity: types.SeverityCritical,
					Title:    "检测到反弹 Shell 进程",
					Message:  fmt.Sprintf("进程 PID=%s 命令行匹配反弹 Shell 模式: %s。已自动终止", pid, cmdline),
					PID:      atoiSafe(pid),
					ProcName: procName,
					CmdLine:  cmdline,
					Action:   "auto_kill",
				})
				break
			}
		}

		// 检查进程的网络连接
		// 读取 /proc/PID/net/tcp 检查是否有连接外部 IP 的可疑端口
		tcpBytes, err := os.ReadFile(filepath.Join("/proc", pid, "net", "tcp"))
		if err != nil {
			continue
		}
		remoteAddr := d.checkSuspiciousConnection(string(tcpBytes))
		if remoteAddr != "" {
			// 进程有外部可疑连接，检查是否是 Shell 进程
			procName := getProcName(pid)
			if isShellProcess(procName, cmdline) {
				findings = append(findings, ReverseShellFinding{
					Severity:   types.SeverityCritical,
					Title:      "检测到 Shell 进程连接外部可疑端口",
					Message:    fmt.Sprintf("进程 PID=%s (%s) 连接到外部地址 %s。可能是反弹 Shell", pid, procName, remoteAddr),
					PID:        atoiSafe(pid),
					ProcName:   procName,
					CmdLine:    cmdline,
					RemoteAddr: remoteAddr,
					Action:     "alert_kill",
				})
			}
		}
	}

	return findings
}

// isShellProcess 判断是否是 Shell 进程
func isShellProcess(procName, cmdline string) bool {
	shellNames := []string{"bash", "sh", "zsh", "dash", "python", "perl", "ruby", "php", "nc", "ncat", "socat"}
	lowerName := strings.ToLower(procName)
	lowerCmd := strings.ToLower(cmdline)
	for _, s := range shellNames {
		if strings.Contains(lowerName, s) || strings.Contains(lowerCmd, s) {
			return true
		}
	}
	return false
}

// checkSuspiciousConnection 检查 TCP 连接是否有到外部 IP 的可疑端口连接
func (d *ReverseShellDetector) checkSuspiciousConnection(tcpData string) string {
	lines := strings.Split(tcpData, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // 跳过表头
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// remote_address:port
		remoteParts := strings.Split(fields[2], ":")
		if len(remoteParts) != 2 {
			continue
		}
		remoteIP := parseHexIP(remoteParts[0])
		if remoteIP == "" {
			continue
		}
		// 检查是否是内网
		ip := net.ParseIP(remoteIP)
		if ip == nil {
			continue
		}
		isPrivate := false
		for _, cidr := range d.privateCIDRs {
			if cidr.Contains(ip) {
				isPrivate = true
				break
			}
		}
		if !isPrivate {
			// 连接到外部 IP，检查连接状态
			if len(fields) > 3 && strings.Contains(fields[3], "01") {
				// 01 = ESTABLISHED
				port := parseHexPort(remoteParts[1])
				// 常见反弹 Shell 端口
				suspiciousPorts := map[string]bool{
					"4444": true, // Metasploit default
					"1337": true, // Common
					"9001": true, // Common
					"1234": true, // Common
					"6666": true,
					"6667": true, // IRC
					"8080": true,
				}
				if suspiciousPorts[port] {
					return fmt.Sprintf("%s:%s", remoteIP, port)
				}
			}
		}
	}
	return ""
}

// parseHexIP 将十六进制 IP（小端序）转换为点分十进制
func parseHexIP(hexIP string) string {
	if len(hexIP) != 8 {
		return ""
	}
	// /proc/net/tcp 中 IP 是小端序的十六进制
	// 例如 0100007F 表示 127.0.0.1
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		var v byte
		fmt.Sscanf(hexIP[i*2:i*2+2], "%02x", &v)
		b[3-i] = v // 小端序反转
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// parseHexPort 将十六进制端口转换为十进制
func parseHexPort(hexPort string) string {
	var v int
	fmt.Sscanf(hexPort, "%04X", &v)
	return fmt.Sprintf("%d", v)
}

// getProcName 获取进程名
func getProcName(pid string) string {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// isNumeric 检查字符串是否全数字
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// atoiSafe 安全转换 PID
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

var _ = time.Second // 防止未使用 import
