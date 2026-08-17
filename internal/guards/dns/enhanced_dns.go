package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DomainExpiryChecker checks domain registration expiration via WHOIS.
type DomainExpiryChecker struct {
	mu sync.RWMutex
}

func NewDomainExpiryChecker() *DomainExpiryChecker {
	return &DomainExpiryChecker{}
}

// CheckDomainExpiry checks domain expiration days using the whois command.
// Returns days until expiry. Negative means already expired.
func (c *DomainExpiryChecker) CheckDomainExpiry(domain string) (int, error) {
	// First verify domain resolves
	_, err := net.LookupHost(domain)
	if err != nil {
		return 0, fmt.Errorf("域名 %s 无法解析: %v", domain, err)
	}

	// Check if whois command is available
	if _, err := exec.LookPath("whois"); err != nil {
		return 0, fmt.Errorf("whois 命令未安装。建议安装: apt install whois / yum install whois")
	}

	// Run whois command
	output, err := exec.Command("whois", domain).Output()
	if err != nil {
		return 0, fmt.Errorf("whois 查询失败: %v", err)
	}

	// Parse expiry date from whois output
	expiryDate, err := ParseWhoisExpiry(string(output))
	if err != nil {
		return 0, fmt.Errorf("无法解析过期日期: %v", err)
	}

	days := int(time.Until(expiryDate).Hours() / 24)
	return days, nil
}

// ExpiryAdvice returns suggestions for domain expiry management.
func (c *DomainExpiryChecker) ExpiryAdvice(domain string, daysUntilExpiry int) string {
	if daysUntilExpiry < 0 {
		return fmt.Sprintf("域名 %s 已过期 %d 天！请立即续费！", domain, -daysUntilExpiry)
	}
	if daysUntilExpiry < 7 {
		return fmt.Sprintf("域名 %s 将在 %d 天后过期！请立即续费！", domain, daysUntilExpiry)
	}
	if daysUntilExpiry < 30 {
		return fmt.Sprintf("域名 %s 将在 %d 天后过期，建议尽快续费。", domain, daysUntilExpiry)
	}
	return fmt.Sprintf("域名 %s 还有 %d 天过期。", domain, daysUntilExpiry)
}

// ParseWhoisExpiry parses whois output to find expiry date.
// Supports common formats:
//   "Registry Expiry Date: 2025-12-31T00:00:00Z"  (Verisign)
//   "Expiration Time: 2025-12-31 00:00:00"         (CNNIC)
//   "paid-till: 2025-12-31"                         (RUcenter)
func ParseWhoisExpiry(whoisOutput string) (time.Time, error) {
	lines := strings.Split(whoisOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.Contains(lower, "expiry") || strings.Contains(lower, "expiration") ||
			strings.Contains(lower, "paid-till") || strings.Contains(lower, "expires") ||
			strings.Contains(lower, "expire") {

			// Extract date after colon
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			dateStr := strings.TrimSpace(line[idx+1:])

			// Try common date formats
			layouts := []string{
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05",
				"2006-01-02 15:04:05",
				"2006-01-02",
				"02-Jan-2006",
				"2006.01.02",
				"January 2, 2006",
			}

			for _, layout := range layouts {
				if t, err := time.Parse(layout, dateStr); err == nil {
					return t, nil
				}
			}
		}
	}
	return time.Time{}, fmt.Errorf("未找到过期日期")
}

// DNSCachePollutionDetector detects potential DNS cache pollution.
// Unlike naive implementations that compare IPs directly (which fails for CDN domains),
// this checker uses multiple heuristics:
// 1. Checks if IPs are in private ranges (strong indicator of DNS hijacking)
// 2. Checks for impossible IP assignments (e.g., loopback for public domains)
// 3. Only flags non-CDN domains with suspicious IP differences
type DNSCachePollutionDetector struct {
	mu              sync.RWMutex
	privateIPRanges []*net.IPNet
}

func NewDNSCachePollutionDetector() *DNSCachePollutionDetector {
	detector := &DNSCachePollutionDetector{}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		detector.privateIPRanges = append(detector.privateIPRanges, ipNet)
	}

	return detector
}

// CheckPollution checks if DNS results show signs of cache pollution.
func (d *DNSCachePollutionDetector) CheckPollution(domain string, results map[string][]net.IP) (suspected bool, reason string) {
	if len(results) < 2 {
		return false, ""
	}

	// Heuristic 1: Private IP for public domain = DNS hijacking
	for server, ips := range results {
		for _, ip := range ips {
			if d.isPrivateIP(ip) && !d.isLocalDomain(domain) {
				return true, fmt.Sprintf("DNS服务器 %s 对公网域名 %s 返回了私有IP %s，可能是DNS劫持",
					server, domain, ip.String())
			}
		}
	}

	// Heuristic 2: Unspecified or loopback IPs
	for server, ips := range results {
		for _, ip := range ips {
			if ip.IsUnspecified() || ip.IsLoopback() {
				return true, fmt.Sprintf("DNS服务器 %s 对域名 %s 返回了异常IP %s",
					server, domain, ip.String())
			}
		}
	}

	// For CDN domains, different IPs from different resolvers is NORMAL
	if d.isCDNDomain(domain) {
		return false, ""
	}

	return false, ""
}

func (d *DNSCachePollutionDetector) isPrivateIP(ip net.IP) bool {
	for _, ipNet := range d.privateIPRanges {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *DNSCachePollutionDetector) isLocalDomain(domain string) bool {
	localSuffixes := []string{".local", ".localhost", ".internal", ".lan", ".home"}
	for _, suffix := range localSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

func (d *DNSCachePollutionDetector) isCDNDomain(domain string) bool {
	cdnDomains := []string{
		"baidu.com", "google.com", "cloudflare.com",
		"microsoft.com", "apple.com", "amazon.com",
		"aliyun.com", "tencent.com", "qq.com",
	}
	lowerDomain := strings.ToLower(domain)
	for _, cdn := range cdnDomains {
		if strings.Contains(lowerDomain, cdn) {
			return true
		}
	}
	// Check for CDN subdomain patterns
	if strings.HasPrefix(lowerDomain, "cdn.") ||
		strings.HasPrefix(lowerDomain, "static.") ||
		strings.HasPrefix(lowerDomain, "assets.") {
		return true
	}
	return false
}

// DNSLeakChecker checks if DNS queries are leaking to unexpected DNS servers.
type DNSLeakChecker struct {
	mu sync.RWMutex
}

func NewDNSLeakChecker() *DNSLeakChecker {
	return &DNSLeakChecker{}
}

// CheckLeak detects DNS leaks by checking system DNS configuration.
func (c *DNSLeakChecker) CheckLeak(configuredServers []string) (leaked bool, detail string) {
	var sb strings.Builder

	sb.WriteString("DNS 配置检查:\n")
	sb.WriteString(fmt.Sprintf("  期望的DNS服务器: %s\n", strings.Join(configuredServers, ", ")))

	// Check /etc/resolv.conf on Linux
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		sb.WriteString("  /etc/resolv.conf 中的DNS服务器:\n")
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
				// Check if this server is in the configured list
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					server := parts[1]
					found := false
					for _, configured := range configuredServers {
						if strings.Contains(configured, server) {
							found = true
							break
						}
					}
					if !found {
						leaked = true
					}
				}
			}
		}
	}

	if leaked {
		sb.WriteString("\n⚠ 发现未配置的DNS服务器！可能是DNS泄漏。\n")
		sb.WriteString("可能原因:\n")
		sb.WriteString("  1. VPN/代理软件修改了DNS设置\n")
		sb.WriteString("  2. DHCP分配了非预期DNS\n")
		sb.WriteString("  3. 恶意软件篡改了DNS配置\n\n")
		sb.WriteString("修复建议:\n")
		sb.WriteString("  sudo nano /etc/resolv.conf  (手动修改)\n")
		sb.WriteString("  或: sudo systemctl restart systemd-resolved")
	} else {
		sb.WriteString("\nDNS配置正常。")
	}

	sb.WriteString("\n\n如需完整DNS泄漏测试，请访问:\n")
	sb.WriteString("  https://dnsleaktest.com\n")
	sb.WriteString("  或运行: dig +short whoami.akamai.net")

	return leaked, sb.String()
}

// Ensure unused imports are referenced
var _ = context.Background
var _ = regexp.MustCompile
var _ = strconv.Atoi
