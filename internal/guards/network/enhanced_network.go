package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type NetworkDiagnoser struct{}

func NewNetworkDiagnoser() *NetworkDiagnoser { return &NetworkDiagnoser{} }

type DiagnosisResult struct {
	Port       int    `json:"port"`
	Reachable  bool   `json:"reachable"`
	RootCause  string `json:"root_cause"`
	Detail     string `json:"detail"`
	Suggestion string `json:"suggestion"`
}

func (d *NetworkDiagnoser) DiagnosePort(port int) DiagnosisResult {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		ln.Close()
		return DiagnosisResult{
			Port:      port,
			Reachable: true,
			RootCause: "port_available",
			Detail:    fmt.Sprintf("端口 %d 可用", port),
		}
	}

	result := DiagnosisResult{
		Port:      port,
		Reachable: false,
	}

	if isFirewallBlocking(port) {
		result.RootCause = "firewall"
		result.Detail = "防火墙可能阻止了该端口"
		result.Suggestion = "检查 iptables/firewalld/Windows Defender 防火墙规则"
	} else if isProcessOnPort(port) {
		result.RootCause = "process_conflict"
		result.Detail = "其他进程已占用该端口"
		result.Suggestion = "使用 netstat/lsof 查看占用进程，考虑更换端口"
	} else if !isNetworkInterfaceUp() {
		result.RootCause = "network_down"
		result.Detail = "网络接口可能未启用"
		result.Suggestion = "检查网络接口状态，重启网络服务"
	} else {
		result.RootCause = "unknown"
		result.Detail = "无法确定根因"
		result.Suggestion = "检查系统日志获取更多信息"
	}

	return result
}

func isFirewallBlocking(port int) bool {
	if _, err := exec.LookPath("iptables"); err == nil {
		cmd := exec.Command("iptables", "-L", "-n")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), fmt.Sprintf("dpt:%d", port)) {
			return true
		}
	}
	return false
}

func isProcessOnPort(port int) bool {
	if _, err := exec.LookPath("lsof"); err == nil {
		cmd := exec.Command("lsof", "-i", fmt.Sprintf(":%d", port))
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			return true
		}
	}
	if _, err := exec.LookPath("netstat"); err == nil {
		cmd := exec.Command("netstat", "-tlnp")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), fmt.Sprintf(":%d", port)) {
			return true
		}
	}
	return false
}

func isNetworkInterfaceUp() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return true
		}
	}
	return false
}

type DNSHealthChecker struct {
	mu        sync.RWMutex
	upstreams []string
	current   int
}

func NewDNSHealthChecker(upstreams []string) *DNSHealthChecker {
	if len(upstreams) == 0 {
		upstreams = []string{"8.8.8.8:53", "114.114.114.114:53", "1.1.1.1:53"}
	}
	return &DNSHealthChecker{
		upstreams: upstreams,
	}
}

func (d *DNSHealthChecker) CheckUpstreams() (healthy []string, unhealthy []string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, upstream := range d.upstreams {
		conn, err := net.DialTimeout("udp", upstream, 2*time.Second)
		if err != nil {
			unhealthy = append(unhealthy, upstream)
			continue
		}
		conn.Close()
		healthy = append(healthy, upstream)
	}
	return
}

func (d *DNSHealthChecker) SwitchToNextHealthy() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := 0; i < len(d.upstreams); i++ {
		idx := (d.current + i) % len(d.upstreams)
		upstream := d.upstreams[idx]
		conn, err := net.DialTimeout("udp", upstream, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		d.current = idx
		return upstream, nil
	}
	return "", fmt.Errorf("all DNS upstreams are unavailable")
}

func (d *DNSHealthChecker) DetectCachePoisoning(domain string, expectedIPs []string) bool {
	for _, upstream := range d.upstreams {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial(network, upstream)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := r.LookupHost(ctx, domain)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			found := false
			for _, expected := range expectedIPs {
				if ip == expected {
					found = true
					break
				}
			}
			if !found {
				return true
			}
		}
	}
	return false
}
