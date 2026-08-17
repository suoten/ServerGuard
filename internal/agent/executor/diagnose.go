// Package executor 服务故障自动诊断。
//
// 当服务反复重启仍无法恢复（RestartGuard 判定重启无效进入放弃期）时，
// 自动收集现场证据，把"放弃重启"升级为"放弃重启 + 告诉用户为什么"：
// 服务状态、配置预检结果、端口占用者——人工介入时无需从零排查。
package executor

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DiagnoseServiceFailure 收集服务启动失败的诊断信息（仅 Linux 深度诊断）。
// serviceName 为 systemd 服务名；port 为该服务应监听的端口（0 表示跳过端口占用检查）。
// 返回人可读的诊断文本，附加在告警正文中。
func DiagnoseServiceFailure(serviceName string, port int) string {
	var sb strings.Builder
	sb.WriteString("\n\n🔬 自动诊断（反复重启无效，已暂停自动修复，请人工介入）\n")

	if runtime.GOOS == "windows" {
		// Windows：用 sc query 取服务状态
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "sc", "query", serviceName).CombinedOutput()
		cancel()
		if err == nil {
			sb.WriteString("服务状态：\n" + tailLines(string(out), 6))
		}
		return sb.String()
	}

	// 1. systemctl status 尾部（含最近日志行，通常直接写着失败原因）
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	out, err := exec.CommandContext(ctx, "systemctl", "status", serviceName,
		"--no-pager", "-l", "-n", "8").CombinedOutput()
	cancel()
	if err == nil || len(out) > 0 {
		sb.WriteString("服务状态（systemctl status 尾部）：\n" + tailLines(string(out), 12))
	}

	// 2. 端口占用检查：端口被别人占用是"重启无效"的经典原因
	if port > 0 {
		if holder := portHolder(port); holder != "" {
			fmt.Fprintf(&sb, "\n⚠️ 端口 %d 当前被占用：%s\n（服务起不来很可能因为端口冲突）", port, holder)
		}
	}

	return sb.String()
}

// portHolder 返回监听指定端口的进程描述（"pid=1234 nginx: master"），查不到返回空。
func portHolder(port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := exec.CommandContext(ctx, "ss", "-tlnp").Output()
	cancel()
	if err != nil {
		return ""
	}
	needle := fmt.Sprintf(":%d ", port)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, needle) {
			line = strings.TrimSpace(line)
			if len([]rune(line)) > 200 {
				line = string([]rune(line)[:200])
			}
			return line
		}
	}
	return ""
}

// tailLines 取文本最后 n 行并缩进展示。
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString("   " + l + "\n")
	}
	return sb.String()
}
