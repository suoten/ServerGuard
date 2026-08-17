package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// NetworkGuard implements Module E: Network Guard
// Covers: connectivity probing, network self-healing, reverse proxy guard, DNS health check
type NetworkGuard struct {
	mu       sync.RWMutex
	eventBus *eventbus.EventBus
	targets  []types.NetworkTarget
	dnsServers []string
	timeout  time.Duration
}

// New creates a new NetworkGuard.
func New(bus *eventbus.EventBus) *NetworkGuard {
	return &NetworkGuard{
		eventBus:   bus,
		dnsServers: []string{"8.8.8.8", "114.114.114.114"},
		timeout:    5 * time.Second,
	}
}

// SetTargets updates the network probe targets.
func (g *NetworkGuard) SetTargets(targets []types.NetworkTarget) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.targets = targets
}

// Check performs network connectivity checks.
func (g *NetworkGuard) Check(ctx context.Context) {
	g.mu.RLock()
	targets := g.targets
	timeout := g.timeout
	g.mu.RUnlock()

	for _, target := range targets {
		go g.checkTarget(ctx, target, timeout)
	}

	// E4: DNS health check
	go g.checkDNS(ctx)
}

// checkTarget checks a single network target.
func (g *NetworkGuard) checkTarget(ctx context.Context, target types.NetworkTarget, timeout time.Duration) {
	addr := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		// E2: Network self-healing attempt
		g.eventBus.PublishAlert(types.AlertError, "network",
			fmt.Sprintf("网络异常: %s (%s)", target.Name, addr),
			fmt.Sprintf("无法连接到 %s (%s): %v，正在诊断...", target.Name, addr, err),
			"network-down-001")

		g.diagnoseAndHeal(ctx, target)
		return
	}
	conn.Close()
}

// diagnoseAndHeal 深度诊断网络异常，给出精确修复命令但不自动执行。
// 安全策略：只诊断不自动操作，避免重启服务/修改防火墙导致连接中断或安全风险。
// 诊断维度：1.目标服务是否监听 2.防火墙是否拦截 3.网卡是否正常 4.路由是否可达
func (g *NetworkGuard) diagnoseAndHeal(ctx context.Context, target types.NetworkTarget) {
	addr := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	var diagnosis []string
	var suggestions []string

	// 诊断1：检查目标端口是否在监听（仅本机目标）
	if target.Address == "127.0.0.1" || target.Address == "localhost" || target.Address == "0.0.0.0" {
		if isProcessOnPort(target.Port) {
			diagnosis = append(diagnosis, "端口已监听但连接被拒（可能 backlog 已满或 SYN flood）")
			suggestions = append(suggestions, "检查连接数: netstat -an | grep ESTABLISHED | wc -l")
		} else {
			diagnosis = append(diagnosis, fmt.Sprintf("端口 %d 未监听，目标服务可能已停止", target.Port))
			// 给出具体的服务重启命令，但不自动执行
			restartCmd := suggestRestartCommand(target.Name)
			if restartCmd != "" {
				suggestions = append(suggestions, "重启服务: "+restartCmd)
			} else {
				suggestions = append(suggestions, fmt.Sprintf("手动启动监听端口 %d 的服务", target.Port))
			}
		}
	}

	// 诊断2：防火墙检查
	if fwBlocked := checkFirewallBlocking(target.Port); fwBlocked {
		diagnosis = append(diagnosis, fmt.Sprintf("防火墙规则阻止了端口 %d", target.Port))
		// 给出精确的放行命令，但不自动执行
		if runtime.GOOS == "windows" {
			suggestions = append(suggestions, fmt.Sprintf("放行端口: netsh advfirewall firewall add rule name=\"Port-%d\" dir=in action=allow protocol=TCP localport=%d", target.Port, target.Port))
		} else {
			suggestions = append(suggestions, fmt.Sprintf("放行端口(firewalld): firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload", target.Port))
			suggestions = append(suggestions, fmt.Sprintf("放行端口(iptables): iptables -I INPUT -p tcp --dport %d -j ACCEPT", target.Port))
		}
	} else {
		diagnosis = append(diagnosis, "防火墙未拦截该端口")
	}

	// 诊断3：网卡状态检查
	if !isNetworkInterfaceUp() {
		diagnosis = append(diagnosis, "无活跃网络接口（网卡可能已 down）")
		suggestions = append(suggestions, "启用网卡: ip link set <接口名> up 或 ifup <接口名>")
	} else {
		diagnosis = append(diagnosis, "网络接口正常")
	}

	// 诊断4：路由可达性（远程目标）
	if target.Address != "127.0.0.1" && target.Address != "localhost" && target.Address != "0.0.0.0" {
		if routeReachable := checkRouteReachable(target.Address); !routeReachable {
			diagnosis = append(diagnosis, fmt.Sprintf("路由不可达 %s（可能网关或路由配置异常）", target.Address))
			suggestions = append(suggestions, "检查路由: route -n 或 ip route show")
		} else {
			diagnosis = append(diagnosis, "路由可达，但 TCP 握手失败（对端可能拒绝或负载过高）")
		}
	}

	// 汇总发布
	detail := fmt.Sprintf("目标: %s (%s)\n诊断结果:\n  - %s\n建议操作（需手动执行）:\n  - %s",
		target.Name, addr,
		strings.Join(diagnosis, "\n  - "),
		strings.Join(suggestions, "\n  - "))

	g.eventBus.PublishAlert(types.AlertWarning, "network",
		fmt.Sprintf("网络异常诊断: %s (%s)", target.Name, addr),
		detail,
		"network-diagnose-001")
}

// checkDNS checks DNS resolution health.
func (g *NetworkGuard) checkDNS(ctx context.Context) {
	g.mu.RLock()
	servers := g.dnsServers
	g.mu.RUnlock()

	for _, server := range servers {
		// Check if DNS server is reachable
		addr := fmt.Sprintf("%s:53", server)
		conn, err := net.DialTimeout("udp", addr, 3*time.Second)
		if err != nil {
			g.eventBus.PublishAlert(types.AlertWarning, "network",
				fmt.Sprintf("DNS不可达: %s", server),
				fmt.Sprintf("DNS服务器 %s 不可达，可能影响域名解析", server),
				"dns-health-001")
		} else {
			conn.Close()
		}
	}
}

// ====== 网络诊断辅助函数 ======

// checkFirewallBlocking 检查防火墙是否阻止了指定端口
func checkFirewallBlocking(port int) bool {
	if runtime.GOOS == "windows" {
		// Windows: 使用 netsh advfirewall 检查
		cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
			fmt.Sprintf("name=ServerGuard-Port-%d", port))
		if output, err := cmd.Output(); err == nil && len(output) > 0 {
			return false // 已有放行规则
		}
		// 检查是否有阻止规则
		cmd = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
		output, err := cmd.Output()
		if err == nil {
			// 简单检查是否有阻止该端口的规则
			portStr := fmt.Sprintf("%d", port)
			return strings.Contains(string(output), portStr) && strings.Contains(string(output), "Block")
		}
		return false
	}

	// Linux: 检查 iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		cmd := exec.Command("iptables", "-L", "INPUT", "-n")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), fmt.Sprintf("dpt:%d", port)) {
			// 检查是 DROP/REJECT 还是 ACCEPT
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, fmt.Sprintf("dpt:%d", port)) {
					if strings.Contains(line, "DROP") || strings.Contains(line, "REJECT") {
						return true
					}
				}
			}
		}
	}

	// 检查 firewalld
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		cmd := exec.Command("firewall-cmd", "--list-ports")
		output, err := cmd.Output()
		if err == nil {
			portStr := fmt.Sprintf("%d/tcp", port)
			if !strings.Contains(string(output), portStr) {
				// 端口未在 firewalld 放行列表中
				return true
			}
		}
	}

	return false
}

// suggestRestartCommand 返回服务重启命令（不自动执行）
func suggestRestartCommand(serviceName string) string {
	if serviceName == "" {
		return ""
	}

	// 常见服务名映射到 systemctl 服务名
	serviceMap := map[string]string{
		"nginx":        "nginx",
		"apache":       "apache2",
		"httpd":        "httpd",
		"mysql":        "mysqld",
		"mariadb":      "mariadb",
		"redis":        "redis-server",
		"redis-server": "redis-server",
		"php-fpm":      "php-fpm",
		"sshd":         "sshd",
		"ssh":          "ssh",
	}

	svcName := serviceName
	if mapped, ok := serviceMap[serviceName]; ok {
		svcName = mapped
	}

	if runtime.GOOS != "windows" {
		return fmt.Sprintf("systemctl restart %s", svcName)
	}
	return ""
}

// checkRouteReachable 检查路由是否可达（通过 ping 或 traceroute）
func checkRouteReachable(address string) bool {
	// 先尝试 ICMP ping
	var pingCmd string
	var pingArgs []string
	if runtime.GOOS == "windows" {
		pingCmd = "ping"
		pingArgs = []string{"-n", "1", "-w", "2000", address}
	} else {
		pingCmd = "ping"
		pingArgs = []string{"-c", "1", "-W", "2", address}
	}

	cmd := exec.Command(pingCmd, pingArgs...)
	if cmd.Run() == nil {
		return true
	}

	// ping 不通可能是 ICMP 被禁，尝试 TCP ping
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, "80"), 2*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}
