// Package safety 重启预检与优雅重启（reload-first）。
//
// 核心理念：重启是运维动作中"最可能把能跑的服务搞挂"的操作——
// 配置写错了还重启 nginx，等于亲手把网站打挂；开机 5 分钟内服务还在启动，
// 误判"挂了"去重启只会制造冲突。本模块在重启动作落地前做三道闸：
//  1. 开机保护：系统启动初期禁止自动重启
//  2. 配置预检：nginx -t / apachectl configtest / sshd -t 不过则拒绝重启
//  3. 优雅重启：支持平滑重载的服务优先 reload（不断开现有连接），失败才 restart
package safety

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

// bootProtectWindow 开机保护窗口：系统启动后该时长内禁止自动重启服务。
// 服务可能仍在正常启动流程中（如 MySQL 恢复 InnoDB、宝塔批量拉起站点环境），
// 此时"进程不存在/端口不通"是暂时状态，重启只会与系统启动流程打架。
const bootProtectWindow = 5 * time.Minute

// configCheckers 服务名（小写）→ 配置语法预检命令。
// 预检失败意味着重启后服务必然起不来——此时重启 = 亲手制造宕机。
// 未列出的服务（如 mysqld 无轻量校验）跳过预检。
var configCheckers = map[string][][]string{
	"nginx":   {{"nginx", "-t"}},
	"httpd":   {{"apachectl", "configtest"}, {"httpd", "-t"}},
	"apache2": {{"apache2ctl", "configtest"}, {"apachectl", "configtest"}, {"apache2", "-t"}},
	"sshd":    {{"sshd", "-t"}},
}

// reloadableServices 支持平滑重载（reload 不断开连接）的服务名（小写）。
// php-fpm-74 这类带版本号的名称通过前缀匹配归一到 php-fpm。
var reloadableServices = []string{
	"nginx", "httpd", "apache2", "php-fpm", "haproxy", "keepalived",
}

// matchService 将服务名归一匹配到已知服务 key。
// 先精确匹配，再前缀匹配（php-fpm-74 → php-fpm）。
func matchService(name string, keys []string) string {
	lower := strings.ToLower(name)
	for _, k := range keys {
		if lower == k {
			return k
		}
	}
	for _, k := range keys {
		if strings.HasPrefix(lower, k+"-") {
			return k
		}
	}
	return ""
}

// configCheckerKeys 返回 configCheckers 的 key 列表（供 matchService 使用）。
func configCheckerKeys() []string {
	keys := make([]string, 0, len(configCheckers))
	for k := range configCheckers {
		keys = append(keys, k)
	}
	return keys
}

// PreflightRestartCheck 重启落地前的安全闸。
// 返回非空 blockReason 表示禁止重启（此时重启大概率把服务搞挂）。
//
// 检查项：
//  1. 开机保护：系统启动 bootProtectWindow 内，服务可能仍在启动中
//  2. 配置预检：已知服务配置语法错误时拒绝重启（重启必挂，保持现状至少还能跑）
//
// Windows 仅做开机保护（IIS/Windows 服务无等效配置预检概念）。
func PreflightRestartCheck(serviceName string) (blockReason string) {
	// 1. 开机保护
	if up, err := host.Uptime(); err == nil {
		if time.Duration(up)*time.Second < bootProtectWindow {
			return fmt.Sprintf("系统启动仅 %d 分钟，服务可能仍在启动流程中，暂不允许自动重启（避免与启动流程冲突）",
				int(up/60)+1)
		}
	}

	// 2. 配置预检（仅 Linux，且该服务有预检命令）
	if runtime.GOOS == "windows" {
		return ""
	}
	key := matchService(serviceName, configCheckerKeys())
	if key == "" {
		return "" // 无预检手段的服务，不阻塞
	}
	for _, cmdArgs := range configCheckers[key] {
		if _, err := exec.LookPath(cmdArgs[0]); err != nil {
			continue // 该预检工具不存在，尝试下一个
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			snippet := strings.TrimSpace(string(out))
			if len([]rune(snippet)) > 300 {
				snippet = string([]rune(snippet)[:300]) + "…"
			}
			return fmt.Sprintf("配置语法检查未通过（%s），此时重启 %s 将导致服务无法启动。已拒绝重启，请人工修复配置。\n预检输出：%s",
				strings.Join(cmdArgs, " "), serviceName, snippet)
		}
		return "" // 预检通过
	}
	return "" // 所有预检工具都不存在，跳过
}

// TryGracefulReload 尝试对服务做平滑重载（reload）。
// reload 不中断现有连接：nginx 平滑换 worker、php-fpm 平滑换子进程。
// 返回 (handled=true, nil) 表示 reload 成功且服务仍健康，调用方无需再 restart；
// 返回 (false, _) 表示该服务不支持 reload 或 reload 失败，调用方应走原 restart 路径。
//
// 仅 Linux 生效；Windows 直接返回 false（无 reload 概念）。
func TryGracefulReload(ctx context.Context, serviceName string) (handled bool, err error) {
	if runtime.GOOS == "windows" {
		return false, nil
	}
	key := matchService(serviceName, reloadableServices)
	if key == "" {
		return false, nil // 不支持平滑重载的服务（mysqld/redis 等只能 restart）
	}

	// 依次尝试 systemctl reload → /etc/init.d/{name} reload
	reloadCmds := [][]string{
		{"systemctl", "reload", serviceName},
		{"/etc/init.d/" + serviceName, "reload"},
	}
	reloaded := false
	for _, cmdArgs := range reloadCmds {
		if _, err := exec.LookPath(cmdArgs[0]); err != nil {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		runErr := exec.CommandContext(c, cmdArgs[0], cmdArgs[1:]...).Run()
		cancel()
		if runErr == nil {
			reloaded = true
			break
		}
	}
	if !reloaded {
		return false, fmt.Errorf("reload 命令均失败")
	}

	// 验证：reload 后服务仍存活（systemd 服务查 is-active，否则查进程）
	time.Sleep(2 * time.Second)
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	out, err := exec.CommandContext(c, "systemctl", "is-active", serviceName).Output()
	cancel()
	if err == nil {
		state := strings.TrimSpace(string(out))
		if state == "active" {
			return true, nil
		}
		return false, fmt.Errorf("reload 后服务状态异常: %s", state)
	}
	// 非 systemd 管理（init.d 脚本拉起）：reload 成功即认为 handled
	return true, nil
}
