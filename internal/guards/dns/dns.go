package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// DNSGuard implements Module P: DNS Guard
// Covers: multi-upstream probing, DNS hijacking detection, domain expiry reminder
//
// SAFETY: Never modifies DNS configuration or switches DNS servers automatically.
// Only monitors and provides remediation suggestions.
type DNSGuard struct {
	mu           sync.RWMutex
	eventBus     *eventbus.EventBus
	upstreams    []string
	probeDomains []string
	detector     *DNSCachePollutionDetector
}

func New(bus *eventbus.EventBus, upstreams []string) *DNSGuard {
	if len(upstreams) == 0 {
		upstreams = []string{"8.8.8.8", "114.114.114.114", "1.1.1.1"}
	}
	return &DNSGuard{
		eventBus:     bus,
		upstreams:    upstreams,
		probeDomains: []string{"google.com", "baidu.com", "cloudflare.com"},
		detector:     NewDNSCachePollutionDetector(),
	}
}

func (g *DNSGuard) Check(ctx context.Context) {
	// P1: Probe each upstream DNS server
	for _, server := range g.upstreams {
		go g.probeDNS(ctx, server)
	}

	// P2: Check for DNS cache pollution / hijacking
	go g.checkCachePollution(ctx)
}

// probeDNS checks if a DNS server can resolve probe domains.
func (g *DNSGuard) probeDNS(ctx context.Context, server string) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("udp", server+":53", 3*time.Second)
		},
	}

	failedDomains := 0
	var failureDetail strings.Builder

	for _, domain := range g.probeDomains {
		_, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			failedDomains++
			failureDetail.WriteString(fmt.Sprintf("  %s: %v\n", domain, err))
		}
	}

	if failedDomains > 0 {
		level := types.AlertError
		if failedDomains == len(g.probeDomains) {
			level = types.AlertCritical
		}

		detail := fmt.Sprintf("DNS服务器 %s 解析失败 (%d/%d 个域名):\n%s\n",
			server, failedDomains, len(g.probeDomains), failureDetail.String())

		detail += "排查建议:\n"
		detail += fmt.Sprintf("  1. 测试连通性: nslookup %s %s\n", g.probeDomains[0], server)
		detail += fmt.Sprintf("  2. 检查防火墙: iptables -L -n | grep 53\n")
		detail += fmt.Sprintf("  3. 检查DNS服务: dig @%s %s\n", server, g.probeDomains[0])
		if failedDomains == len(g.probeDomains) {
			detail += "\n  ⚠ 所有域名均解析失败，该DNS服务器可能不可达或已宕机！\n"
			detail += "  建议切换到备用DNS:\n"
			detail += "    sudo nano /etc/resolv.conf\n"
			detail += "    或: sudo systemctl restart systemd-resolved"
		}

		g.eventBus.PublishAlert(level, "dns",
			fmt.Sprintf("DNS解析失败: %s (%d个域名)", server, failedDomains),
			detail, "dns-fail-001")
	}
}

// checkCachePollution checks for DNS hijacking using smart heuristics.
// Unlike naive IP comparison (which produces false positives for CDN domains),
// this method checks for:
// 1. Private IPs returned for public domains (strong hijacking indicator)
// 2. Loopback/unspecified IPs (impossible results)
// 3. Only flags non-CDN domains with suspicious differences
func (g *DNSGuard) checkCachePollution(ctx context.Context) {
	results := make(map[string][]net.IP)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a non-CDN domain for pollution detection
	testDomain := "github.com"

	for _, server := range g.upstreams {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return net.DialTimeout("udp", s+":53", 3*time.Second)
				},
			}
			ips, err := resolver.LookupIP(ctx, "ipv4", testDomain)
			if err == nil {
				mu.Lock()
				results[s] = ips
				mu.Unlock()
			}
		}(server)
	}
	wg.Wait()

	if len(results) < 2 {
		return
	}

	// Use the smart pollution detector
	suspected, reason := g.detector.CheckPollution(testDomain, results)
	if suspected {
		g.eventBus.PublishAlert(types.AlertCritical, "dns",
			"DNS劫持疑似",
			fmt.Sprintf("%s\n\n"+
				"排查步骤:\n"+
				"  1. 检查 /etc/resolv.conf 是否被篡改\n"+
				"  2. 检查 /etc/hosts 是否有异常条目: cat /etc/hosts\n"+
				"  3. 清除DNS缓存: sudo systemd-resolve --flush-caches\n"+
				"  4. 检查是否有恶意软件: clamscan -r /etc/\n"+
				"  5. 检查路由器DNS设置\n\n"+
				"DNS服务器返回结果:\n%s",
				reason, formatDNSResults(results)),
			"dns-hijack-001")
	}

	// Also check system DNS configuration for leaks
	g.checkSystemDNSConfig()
}

// checkSystemDNSConfig checks /etc/resolv.conf and /etc/hosts for issues.
func (g *DNSGuard) checkSystemDNSConfig() {
	// Check /etc/hosts for suspicious entries
	if data, err := readFileSafe("/etc/hosts"); err == nil {
		lines := strings.Split(data, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Check for known malicious patterns
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := net.ParseIP(fields[0])
				if ip != nil {
					// Check if a public domain is mapped to a private/loopback IP
					for _, domain := range g.probeDomains {
						for _, f := range fields[1:] {
							if strings.EqualFold(f, domain) && (ip.IsLoopback() || isPrivateIPSimple(ip)) {
								g.eventBus.PublishAlert(types.AlertCritical, "dns",
									"hosts文件可疑条目",
									fmt.Sprintf("/etc/hosts 中将 %s 映射到 %s\n"+
										"这可能是恶意重定向！\n\n"+
										"建议检查 /etc/hosts 并移除可疑条目:\n"+
										"  sudo nano /etc/hosts\n"+
										"  或: sudo cp /etc/hosts /etc/hosts.bak && sudo nano /etc/hosts",
										domain, ip.String()),
									"dns-hosts-hijack-001")
							}
						}
					}
				}
			}
		}
	}
}

// formatDNSResults formats DNS results for alert messages.
func formatDNSResults(results map[string][]net.IP) string {
	var sb strings.Builder
	for server, ips := range results {
		var ipStrs []string
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.String())
		}
		sb.WriteString(fmt.Sprintf("  %s: %s\n", server, strings.Join(ipStrs, ", ")))
	}
	return sb.String()
}

// isPrivateIPSimple checks if an IP is in private ranges.
func isPrivateIPSimple(ip net.IP) bool {
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// readFileSafe reads a file, returning empty string on error.
func readFileSafe(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
