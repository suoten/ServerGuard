package security

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// WebAttackDetector implements C2: Web Attack Defense and C6: CORS Security Hardening.
// Analyzes Nginx/Apache/IIS access logs for CC attacks, SQLi, directory traversal.
// Scans configs for CORS misconfigurations and missing security headers.

// SQLiPatterns matches common SQL injection patterns.
var sqliPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)union\s+select`),
	regexp.MustCompile(`(?i)select.*from`),
	regexp.MustCompile(`(?i)insert\s+into`),
	regexp.MustCompile(`(?i)drop\s+table`),
	regexp.MustCompile(`(?i)or\s+1\s*=\s*1`),
	regexp.MustCompile(`(?i)'.*or.*'.*=`),
	regexp.MustCompile(`(?i)exec(\s|\+)+(s|x)p_`),
	regexp.MustCompile(`(?i)sleep\s*\(\s*\d+\s*\)`),
	regexp.MustCompile(`(?i)benchmark\s*\(`),
	regexp.MustCompile(`(?i)information_schema`),
	regexp.MustCompile(`(?i)load_file\s*\(`),
	regexp.MustCompile(`(?i)into\s+outfile`),
	regexp.MustCompile(`(?i)xp_cmdshell`),
	regexp.MustCompile(`(?i)concat\s*\(`),
	regexp.MustCompile(`(?i)group_concat\s*\(`),
	regexp.MustCompile(`(?i)extractvalue\s*\(`),
	regexp.MustCompile(`(?i)updatexml\s*\(`),
	regexp.MustCompile(`(?i)char\s*\(`),
	regexp.MustCompile(`(?i)hex\s*\(`),
	regexp.MustCompile(`(?i)unhex\s*\(`),
	regexp.MustCompile(`(?i)substring\s*\(`),
	regexp.MustCompile(`(?i)0x[0-9a-fA-F]{8,}`),
	regexp.MustCompile(`(?i)procedure\s+analyse`),
	regexp.MustCompile(`(?i)outfile`),
	regexp.MustCompile(`(?i)dumpfile`),
}

// XSSPatterns matches common XSS patterns.
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)onerror\s*=`),
	regexp.MustCompile(`(?i)onload\s*=`),
	regexp.MustCompile(`(?i)<iframe`),
	regexp.MustCompile(`(?i)<img.*src.*=.*javascript:`),
	regexp.MustCompile(`(?i)</script`),
	regexp.MustCompile(`(?i)document\.cookie`),
	regexp.MustCompile(`(?i)document\.write`),
	regexp.MustCompile(`(?i)<object`),
	regexp.MustCompile(`(?i)<embed`),
	regexp.MustCompile(`(?i)<svg\s+onload`),
	regexp.MustCompile(`(?i)onmouseover\s*=`),
	regexp.MustCompile(`(?i)onclick\s*=`),
	regexp.MustCompile(`(?i)onfocus\s*=`),
	regexp.MustCompile(`(?i)<body\s+onload`),
	regexp.MustCompile(`(?i)<meta\s+http-equiv`),
	regexp.MustCompile(`(?i)eval\s*\(`),
	regexp.MustCompile(`(?i)setTimeout\s*\(`),
	regexp.MustCompile(`(?i)String\.fromCharCode`),
	regexp.MustCompile(`(?i)unescape\s*\(`),
	regexp.MustCompile(`(?i)%3Cscript`),
	regexp.MustCompile(`(?i)data:text/html`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)window\.location`),
	regexp.MustCompile(`(?i)<details\s+ontoggle`),
	regexp.MustCompile(`(?i)<marquee\s+onstart`),
}

// TraversalPatterns matches directory traversal attempts.
var traversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`\.\.%2f`),
	regexp.MustCompile(`%2e%2e/`),
	regexp.MustCompile(`etc/passwd`),
	regexp.MustCompile(`proc/self`),
	regexp.MustCompile(`\.\.%5c`),
	regexp.MustCompile(`%2e%2e%5c`),
	regexp.MustCompile(`proc/self/environ`),
	regexp.MustCompile(`proc/self/fd`),
	regexp.MustCompile(`windows/win\.ini`),
	regexp.MustCompile(`windows/system32`),
	regexp.MustCompile(`file://`),
	regexp.MustCompile(`php://filter`),
	regexp.MustCompile(`php://input`),
	regexp.MustCompile(`expect://`),
	regexp.MustCompile(`data://`),
	regexp.MustCompile(`phar://`),
	regexp.MustCompile(`\.ssh/id_rsa`),
	regexp.MustCompile(`\.ssh/authorized_keys`),
}

// CCAttackDetector detects CC attacks by tracking request frequency per IP.
type CCAttackDetector struct {
	mu          sync.RWMutex
	ipRequests  map[string][]time.Time // IP -> request timestamps
	threshold   int                    // requests per window
	window      time.Duration
	banDuration time.Duration
}

// NewCCAttackDetector creates a new CC attack detector.
func NewCCAttackDetector(threshold int, window, banDuration time.Duration) *CCAttackDetector {
	return &CCAttackDetector{
		ipRequests:  make(map[string][]time.Time),
		threshold:   threshold,
		window:      window,
		banDuration: banDuration,
	}
}

// CheckWebAttacks analyzes web server access logs for attacks.
// C2: Web Attack Defense
func (g *SecurityGuard) CheckWebAttacks(ctx context.Context, logPath string) {
	if logPath == "" {
		// Auto-detect log paths
		paths := g.detectWebLogPaths()
		for _, p := range paths {
			g.checkSingleWebLog(ctx, p)
		}
	} else {
		g.checkSingleWebLog(ctx, logPath)
	}
}

// checkSingleWebLog analyzes a single access log file.
func (g *SecurityGuard) checkSingleWebLog(ctx context.Context, logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Seek to end minus 10KB
	stat, _ := file.Stat()
	if stat.Size() > 10240 {
		file.Seek(-10240, 2)
	}

	scanner := bufio.NewScanner(file)
	attackCounts := make(map[string]int)

	for scanner.Scan() {
		line := scanner.Text()

		// Extract URL from log line
		url := extractURLFromLogLine(line)
		if url == "" {
			continue
		}

		// Check SQLi
		for _, pattern := range sqliPatterns {
			if pattern.MatchString(url) {
				attackCounts["sqli"]++
				ip := extractIP(line)
				if ip != "" {
					g.eventBus.PublishAlert(types.AlertCritical, "security",
						"SQL注入攻击",
						fmt.Sprintf("检测到SQL注入攻击，IP: %s, URL: %s", ip, url),
						"web-attack-001")
					// 自动封禁恶意 IP（对服务器本身无风险）
					g.autoBanAttacker(ctx, ip, "sql_injection", types.SeverityCritical)
				}
				break
			}
		}

		// Check XSS
		for _, pattern := range xssPatterns {
			if pattern.MatchString(url) {
				attackCounts["xss"]++
				ip := extractIP(line)
				if ip != "" {
					g.eventBus.PublishAlert(types.AlertCritical, "security",
						"XSS攻击",
						fmt.Sprintf("检测到XSS攻击，IP: %s, URL: %s", ip, url),
						"web-attack-001")
					// 自动封禁恶意 IP
					g.autoBanAttacker(ctx, ip, "xss", types.SeverityHigh)
				}
				break
			}
		}

		// Check directory traversal
		for _, pattern := range traversalPatterns {
			if pattern.MatchString(url) {
				attackCounts["traversal"]++
				ip := extractIP(line)
				if ip != "" {
					g.eventBus.PublishAlert(types.AlertCritical, "security",
						"目录遍历攻击",
						fmt.Sprintf("检测到目录遍历攻击，IP: %s, URL: %s", ip, url),
						"web-attack-001")
					// 自动封禁恶意 IP
					g.autoBanAttacker(ctx, ip, "dir_traversal", types.SeverityMedium)
				}
				break
			}
		}

		// CC attack: track request frequency
		ip := extractIP(line)
		if ip != "" {
			g.trackCCRequest(ip)
		}
	}
}

// trackCCRequest tracks request frequency per IP for CC attack detection.
func (g *SecurityGuard) trackCCRequest(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	window := 5 * time.Minute
	threshold := 100 // 100 requests in 5 minutes

	if g.loginFailures == nil {
		g.loginFailures = make(map[string][]time.Time)
	}
	// Reuse the loginFailures map for CC tracking
	times := g.loginFailures[ip]
	times = append(times, now)

	// Trim old entries
	cutoff := now.Add(-window)
	var recent []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	g.loginFailures[ip] = recent

	if len(recent) >= threshold {
		if _, banned := g.bannedIPs[ip]; !banned {
			g.eventBus.PublishAlert(types.AlertError, "security",
				fmt.Sprintf("CC攻击: %s", ip),
				fmt.Sprintf("IP %s 在5分钟内发起 %d 次请求，疑似CC攻击", ip, len(recent)),
				"cc-attack-001")
			// 自动封禁 CC 攻击 IP
			g.banIP(context.Background(), ip, len(recent))
		}
	}
}

// CheckCORSConfig scans Nginx/Apache configs for CORS misconfigurations.
// C6: CORS Security Hardening
func (g *SecurityGuard) CheckCORSConfig(ctx context.Context) {
	configDirs := []string{
		"/www/server/panel/vhost/nginx/",
		"/etc/nginx/conf.d/",
		"/etc/nginx/sites-enabled/",
		"/etc/apache2/sites-enabled/",
		"/etc/httpd/conf.d/",
	}

	for _, dir := range configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			g.analyzeCORSConfig(path)
		}
	}
}

// analyzeCORSConfig analyzes a single config file for CORS issues.
func (g *SecurityGuard) analyzeCORSConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// Check for Access-Control-Allow-Origin: *
	if strings.Contains(content, "Access-Control-Allow-Origin: *") ||
		strings.Contains(content, "add_header Access-Control-Allow-Origin *") ||
		strings.Contains(content, "Header set Access-Control-Allow-Origin *") {
		g.eventBus.PublishAlert(types.AlertWarning, "security",
			fmt.Sprintf("CORS配置不安全: %s", path),
			fmt.Sprintf("配置文件 %s 设置了 Access-Control-Allow-Origin: *，允许任意来源跨域访问，建议限制为特定域名", path),
			"cors-hardening-001")
	}

	// Check for missing security headers
	missingHeaders := []string{}
	if !strings.Contains(content, "X-Frame-Options") {
		missingHeaders = append(missingHeaders, "X-Frame-Options")
	}
	if !strings.Contains(content, "X-Content-Type-Options") {
		missingHeaders = append(missingHeaders, "X-Content-Type-Options")
	}
	if !strings.Contains(content, "X-XSS-Protection") {
		missingHeaders = append(missingHeaders, "X-XSS-Protection")
	}
	if !strings.Contains(content, "Strict-Transport-Security") {
		missingHeaders = append(missingHeaders, "Strict-Transport-Security")
	}
	if !strings.Contains(content, "Content-Security-Policy") {
		missingHeaders = append(missingHeaders, "Content-Security-Policy")
	}

	if len(missingHeaders) > 0 {
		suggestion := "建议添加以下安全头:\n"
		suggestion += "  add_header X-Frame-Options \"SAMEORIGIN\";\n"
		suggestion += "  add_header X-Content-Type-Options \"nosniff\";\n"
		suggestion += "  add_header X-XSS-Protection \"1; mode=block\";\n"
		suggestion += "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";\n"
		suggestion += "  add_header Content-Security-Policy \"default-src 'self';\";\n"

		g.eventBus.PublishAlert(types.AlertInfo, "security",
			fmt.Sprintf("安全头缺失: %s", path),
			fmt.Sprintf("配置文件 %s 缺少安全头: %s\n%s", path, strings.Join(missingHeaders, ", "), suggestion),
			"cors-hardening-001")
	}
}

// detectWebLogPaths auto-detects web server access log paths.
func (g *SecurityGuard) detectWebLogPaths() []string {
	var paths []string
	candidates := []string{
		"/www/wwwlogs/",
		"/var/log/nginx/access.log",
		"/var/log/nginx/",
		"/var/log/apache2/access.log",
		"/var/log/httpd/access_log",
		"/var/log/nginx/access.log.1",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil {
			if fi.IsDir() {
				entries, _ := os.ReadDir(p)
				for _, e := range entries {
					if !e.IsDir() && strings.Contains(e.Name(), "access") {
						paths = append(paths, filepath.Join(p, e.Name()))
					}
				}
			} else {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

// extractURLFromLogLine extracts the URL from a web server log line.
func extractURLFromLogLine(line string) string {
	// Common log format: IP - - [date] "METHOD /url HTTP/1.1" status size
	// Nginx: IP - - [date] "METHOD /url HTTP/1.1" status "referer" "UA"
	parts := strings.Split(line, "\"")
	if len(parts) >= 2 {
		// The request is in the second field
		request := parts[1]
		fields := strings.Fields(request)
		if len(fields) >= 2 {
			return fields[1] // URL part
		}
	}
	return ""
}

// autoBanAttacker 自动封禁发起 Web 攻击的恶意 IP。
// 自动封禁对服务器本身无风险，仅阻断恶意IP的网络访问。
// 安全检查：不封禁内网IP、白名单IP、服务器自身IP。
func (g *SecurityGuard) autoBanAttacker(ctx context.Context, ip, attackType string, severity types.Severity) {
	// 不封禁内网 IP
	if isPrivateIP(ip) {
		return
	}

	// 不封禁白名单 IP
	g.mu.RLock()
	if g.excludeIPs[ip] {
		g.mu.RUnlock()
		return
	}
	g.mu.RUnlock()

	// 不封禁服务器自身 IP
	if ownIPs := getServerPublicIPs(); ownIPs[ip] {
		return
	}

	// 检查是否已被封禁
	g.mu.RLock()
	_, banned := g.bannedIPs[ip]
	g.mu.RUnlock()
	if banned {
		return
	}

	// 根据攻击类型决定封禁时长
	duration := 1 * time.Hour
	switch severity {
	case types.SeverityCritical:
		duration = 2 * time.Hour
	case types.SeverityHigh:
		duration = 1 * time.Hour
	case types.SeverityMedium:
		duration = 30 * time.Minute
	case types.SeverityLow:
		duration = 10 * time.Minute
	}

	// 威胁情报增强
	intelNote := ""
	g.mu.RLock()
	iq := g.intel
	g.mu.RUnlock()
	if iq != nil {
		if info := iq.CheckIP(ctx, ip); info != nil && (info.Confidence >= 50 || info.AbuseReports > 0) {
			if duration < 24*time.Hour {
				duration = 24 * time.Hour
			}
			intelNote = fmt.Sprintf("（威胁情报: 置信度=%d%% 举报=%d次）", info.Confidence, info.AbuseReports)
		}
	}

	banReason := fmt.Sprintf("Web攻击自动封禁(%s)%s", attackType, intelNote)

	// 执行封禁
	if runtime.GOOS != "windows" {
		cmd := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
			"-m", "comment", "--comment", "serverguard-security:web-attack")
		if err := cmd.Run(); err != nil {
			cmd = exec.CommandContext(ctx, "firewall-cmd", "--add-rich-rule",
				fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip))
			cmd.Run()
		}
	} else {
		cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name", fmt.Sprintf("ServerGuard-WebAttack-Ban-%s", ip),
			"dir=in", "action=block", "remoteip="+ip)
		cmd.Run()
	}

	g.mu.Lock()
	g.bannedIPs[ip] = time.Now().Add(duration)
	g.mu.Unlock()

	g.eventBus.PublishAlert(types.AlertError, "security",
		fmt.Sprintf("已自动封禁攻击IP: %s", ip),
		fmt.Sprintf("IP %s 因发起 %s 攻击被自动封禁 %s%s", ip, attackType, duration, intelNote),
		"web-attack-001")
	g.recordAudit("ban_ip", ip, banReason, "success", "")
	g.recordAction("ban_ip", ip, fmt.Sprintf("自动封禁IP %s（%s，%v）%s", ip, attackType, duration, intelNote), true, "")
}
