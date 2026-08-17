package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ProgressiveBan struct {
	mu          sync.RWMutex
	ipStages    map[string]int
	ipFirstSeen map[string]time.Time
	rateLimit   time.Duration
	shortBan    time.Duration
	longBan     time.Duration
	bannedIPs   map[string]time.Time
}

func NewProgressiveBan() *ProgressiveBan {
	return &ProgressiveBan{
		ipStages:    make(map[string]int),
		ipFirstSeen: make(map[string]time.Time),
		rateLimit:   1 * time.Minute,
		shortBan:    1 * time.Hour,
		longBan:     24 * time.Hour,
		bannedIPs:   make(map[string]time.Time),
	}
}

func (p *ProgressiveBan) ReportViolation(ip string) (stage int, duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.ipFirstSeen[ip]; !exists {
		p.ipFirstSeen[ip] = time.Now()
	}

	p.ipStages[ip]++
	stage = p.ipStages[ip]

	switch {
	case stage <= 3:
		return 1, p.rateLimit
	case stage <= 6:
		p.bannedIPs[ip] = time.Now().Add(p.shortBan)
		return 2, p.shortBan
	default:
		p.bannedIPs[ip] = time.Now().Add(p.longBan)
		return 3, p.longBan
	}
}

func (p *ProgressiveBan) IsBanned(ip string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	expiry, exists := p.bannedIPs[ip]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		return false
	}
	return true
}

func (p *ProgressiveBan) Unban(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.bannedIPs, ip)
	delete(p.ipStages, ip)
	delete(p.ipFirstSeen, ip)
}

func (p *ProgressiveBan) GetBanInfo(ip string) (stage int, bannedUntil time.Time, isBanned bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	stage = p.ipStages[ip]
	expiry, exists := p.bannedIPs[ip]
	if exists && time.Now().Before(expiry) {
		return stage, expiry, true
	}
	return stage, time.Time{}, false
}

type CORSScanner struct{}

func NewCORSScanner() *CORSScanner {
	return &CORSScanner{}
}

type CORSIssue struct {
	URL        string `json:"url"`
	Issue      string `json:"issue"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion"`
}

func (s *CORSScanner) Scan(url string) ([]CORSIssue, error) {
	var issues []CORSIssue

	resp, err := http.Head(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	origin := resp.Header.Get("Access-Control-Allow-Origin")
	if origin == "*" {
		issues = append(issues, CORSIssue{
			URL:        url,
			Issue:      "Access-Control-Allow-Origin: *",
			Severity:   "high",
			Suggestion: "设置具体的允许来源，而非通配符 *",
		})
	}

	if resp.Header.Get("Access-Control-Allow-Credentials") == "true" && origin == "*" {
		issues = append(issues, CORSIssue{
			URL:        url,
			Issue:      "Allow-Credentials: true with Allow-Origin: *",
			Severity:   "critical",
			Suggestion: "凭证模式不能与通配符来源同时使用",
		})
	}

	if resp.Header.Get("X-Content-Type-Options") == "" {
		issues = append(issues, CORSIssue{
			URL:        url,
			Issue:      "缺少 X-Content-Type-Options 头",
			Severity:   "medium",
			Suggestion: "添加 X-Content-Type-Options: nosniff",
		})
	}

	if resp.Header.Get("X-Frame-Options") == "" {
		issues = append(issues, CORSIssue{
			URL:        url,
			Issue:      "缺少 X-Frame-Options 头",
			Severity:   "medium",
			Suggestion: "添加 X-Frame-Options: DENY 或 SAMEORIGIN",
		})
	}

	if resp.Header.Get("Strict-Transport-Security") == "" && strings.HasPrefix(url, "https") {
		issues = append(issues, CORSIssue{
			URL:        url,
			Issue:      "缺少 Strict-Transport-Security 头",
			Severity:   "medium",
			Suggestion: "添加 HSTS 头: max-age=31536000; includeSubDomains",
		})
	}

	return issues, nil
}

func (s *CORSScanner) GenerateSecurityHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'self'",
	}
}

type RemoteLoginDetector struct {
	mu             sync.RWMutex
	knownIPs       map[string]bool
	loginHistory   map[string][]time.Time
	alertThreshold int
}

func NewRemoteLoginDetector(knownIPs []string) *RemoteLoginDetector {
	m := make(map[string]bool)
	for _, ip := range knownIPs {
		m[ip] = true
	}
	return &RemoteLoginDetector{
		knownIPs:       m,
		loginHistory:   make(map[string][]time.Time),
		alertThreshold: 3,
	}
}

func (d *RemoteLoginDetector) CheckLogin(ip, user string) (isRemote bool, shouldAlert bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	isRemote = !d.knownIPs[ip]
	if !isRemote {
		return false, false
	}

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)
	var recent []time.Time
	for _, t := range d.loginHistory[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	d.loginHistory[ip] = recent

	shouldAlert = true
	return isRemote, shouldAlert
}

func (d *RemoteLoginDetector) AddKnownIP(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownIPs[ip] = true
}

func (d *RemoteLoginDetector) IsKnownIP(ip string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.knownIPs[ip]
}

func (d *RemoteLoginDetector) ParseIPFromLogLine(line string) string {
	for _, prefix := range []string{"from ", "ip=", "IP="} {
		if idx := strings.Index(line, prefix); idx >= 0 {
			rest := line[idx+len(prefix):]
			ipEnd := strings.IndexAny(rest, " \t\n:,]")
			if ipEnd > 0 {
				ip := rest[:ipEnd]
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}
	return ""
}
