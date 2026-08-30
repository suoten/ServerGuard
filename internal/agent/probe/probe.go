package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Probe monitors website liveness and API endpoint health.
type Probe struct {
	mu        sync.RWMutex
	sites     map[string]*SiteMonitor
	endpoints map[string]*EndpointMonitor
	client    *http.Client
}

// newProbeClient 创建 HTTP 客户端，跳过 TLS 证书验证（liveness 探测不需要证书校验）
// 向宝塔学习：复用连接池，不每次都新建 TCP 连接
func newProbeClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second, // 30s 总超时：慢速站点 + 网络波动留足余量
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second, // DNS 解析 + TCP 连接超时
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 探测只需检查存活，不校验证书
			},
			MaxIdleConns:        5,  // 最多缓存 5 个空闲连接
			MaxIdleConnsPerHost: 2,  // 每个 host 最多 2 个空闲连接
			IdleConnTimeout:     30 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second, // 等待响应头超时：防止连接建立但服务器不响应
			ExpectContinueTimeout: 5 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 跟随最多 5 次重定向：很多站点 HTTP→HTTPS 跳转是正常的
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

// SiteMonitor tracks liveness of a website.
type SiteMonitor struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	URL        string        `json:"url"`
	Interval   time.Duration `json:"interval"`
	Enabled    bool          `json:"enabled"`
	// Runtime state
	Up            bool          `json:"up"`
	StatusCode    int           `json:"status_code"`
	Latency       time.Duration `json:"latency"`
	LastCheck     time.Time     `json:"last_check"`
	LastError     string        `json:"last_error,omitempty"`
	UpSince       time.Time     `json:"up_since"`
	DownSince     time.Time     `json:"down_since,omitempty"`
	TotalChecks   int           `json:"total_checks"`
	FailedChecks  int           `json:"failed_checks"`
	ConsecFailures int          `json:"consec_failures"`
}

// EndpointMonitor tracks API endpoint health with percentiles.
type EndpointMonitor struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	URL      string        `json:"url"`
	Method   string        `json:"method"`
	Interval time.Duration `json:"interval"`
	Enabled  bool          `json:"enabled"`
	// Runtime state
	StatusCode   int           `json:"status_code"`
	Latency      time.Duration `json:"latency"`
	LastCheck    time.Time     `json:"last_check"`
	LastError    string        `json:"last_error,omitempty"`
	// Metrics window (last 100 checks)
	latencies    []time.Duration
	statusCodes  map[int]int // status code -> count
	totalChecks  int
	errorCount   int // 4xx + 5xx
	// Computed
	P50       float64 `json:"p50_ms"`
	P95       float64 `json:"p95_ms"`
	P99       float64 `json:"p99_ms"`
	ErrorRate float64 `json:"error_rate"`
}

// New creates a Probe instance.
func New() *Probe {
	return &Probe{
		sites:     make(map[string]*SiteMonitor),
		endpoints: make(map[string]*EndpointMonitor),
		client:    newProbeClient(),
	}
}

// --- Site Management ---

// AddSite adds a website to monitor.
func (p *Probe) AddSite(id, name, url string, interval time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if interval == 0 {
		interval = 60 * time.Second // 向宝塔学习：默认 60s 探测一次，30s 太频繁
	}
	p.sites[id] = &SiteMonitor{
		ID:       id,
		Name:     name,
		URL:      url,
		Interval: interval,
		Enabled:  true,
	}
}

// RemoveSite removes a monitored website.
func (p *Probe) RemoveSite(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sites, id)
}

// GetSites returns all monitored sites.
func (p *Probe) GetSites() []SiteMonitor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]SiteMonitor, 0, len(p.sites))
	for _, s := range p.sites {
		result = append(result, *s)
	}
	return result
}

// --- Endpoint Management ---

// AddEndpoint adds an API endpoint to monitor.
func (p *Probe) AddEndpoint(id, name, url, method string, interval time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if interval == 0 {
		interval = 120 * time.Second // 向宝塔学习：默认 120s 探测 API，60s 太频繁
	}
	if method == "" {
		method = "GET"
	}
	p.endpoints[id] = &EndpointMonitor{
		ID:         id,
		Name:       name,
		URL:        url,
		Method:     method,
		Interval:   interval,
		Enabled:    true,
		latencies:  make([]time.Duration, 0, 100),
		statusCodes: make(map[int]int),
	}
}

// RemoveEndpoint removes a monitored endpoint.
func (p *Probe) RemoveEndpoint(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.endpoints, id)
}

// GetEndpoints returns all monitored endpoints with computed metrics.
func (p *Probe) GetEndpoints() []EndpointMonitor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]EndpointMonitor, 0, len(p.endpoints))
	for _, e := range p.endpoints {
		copy := *e
		copy.computeMetrics()
		result = append(result, copy)
	}
	return result
}

// --- Probing Logic ---

// Run starts the probing loop. Call with "go probe.Run(ctx)".
// 向宝塔学习：探测间隔从 5s 改为 30s——站点 interval 默认就是 30s
// 原来 5s 的 ticker 只是检查"到时间了没有"，30s 足够
func (p *Probe) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkSites(ctx)
			p.checkEndpoints(ctx)
		}
	}
}

func (p *Probe) checkSites(ctx context.Context) {
	p.mu.RLock()
	sites := make([]*SiteMonitor, 0, len(p.sites))
	for _, s := range p.sites {
		if s.Enabled && time.Since(s.LastCheck) >= s.Interval {
			sites = append(sites, s)
		}
	}
	p.mu.RUnlock()

	for _, s := range sites {
		select {
		case <-ctx.Done():
			return
		default:
		}
		p.probeSite(s)
	}
}

func (p *Probe) probeSite(s *SiteMonitor) {
	start := time.Now()
	// 使用带超时的 context，不依赖 Client.Timeout 的全局截断
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	if err != nil {
		p.recordSiteFailure(s, err.Error(), start)
		return
	}
	// 模拟浏览器请求头：某些 WAF/防火墙会拒绝或延迟非浏览器 UA
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ServerGuard-Probe/1.0; +https://github.com/suoten/serverguard)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "close") // 探测用短连接，避免 keepalive 状态干扰

	resp, err := p.client.Do(req)
	latency := time.Since(start)
	if err != nil {
		p.recordSiteFailure(s, simplifyError(err), start)
		return
	}
	// 向宝塔学习：drain body 以便复用 TCP 连接
	io.CopyN(io.Discard, resp.Body, 1024) // 只读 1KB 就够，只为让连接可复用
	resp.Body.Close()

	p.mu.Lock()
	defer p.mu.Unlock()

	s.TotalChecks++
	s.LastCheck = time.Now()
	s.Latency = latency
	s.StatusCode = resp.StatusCode

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		if !s.Up {
			s.Up = true
			s.UpSince = s.LastCheck
			s.DownSince = time.Time{}
		}
		s.ConsecFailures = 0
		s.LastError = ""
	} else {
		s.FailedChecks++
		s.ConsecFailures++
		s.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		if s.Up && s.ConsecFailures >= 2 {
			s.Up = false
			s.DownSince = s.LastCheck
		}
	}
}

func (p *Probe) recordSiteFailure(s *SiteMonitor, errMsg string, start time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s.TotalChecks++
	s.FailedChecks++
	s.ConsecFailures++
	s.LastCheck = time.Now()
	s.Latency = time.Since(start)
	s.LastError = errMsg

	if s.Up && s.ConsecFailures >= 2 {
		s.Up = false
		s.DownSince = s.LastCheck
	}
}

func (p *Probe) checkEndpoints(ctx context.Context) {
	p.mu.RLock()
	endpoints := make([]*EndpointMonitor, 0, len(p.endpoints))
	for _, e := range p.endpoints {
		if e.Enabled && time.Since(e.LastCheck) >= e.Interval {
			endpoints = append(endpoints, e)
		}
	}
	p.mu.RUnlock()

	for _, e := range endpoints {
		select {
		case <-ctx.Done():
			return
		default:
		}
		p.probeEndpoint(e)
	}
}

func (p *Probe) probeEndpoint(e *EndpointMonitor) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, e.Method, e.URL, nil)
	if err != nil {
		p.recordEndpointFailure(e, err.Error(), start)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ServerGuard-Probe/1.0; +https://github.com/suoten/serverguard)")
	req.Header.Set("Accept", "application/json,text/plain,*/*;q=0.8")
	req.Header.Set("Connection", "close")

	resp, err := p.client.Do(req)
	latency := time.Since(start)
	if err != nil {
		p.recordEndpointFailure(e, simplifyError(err), start)
		return
	}
	// 向宝塔学习：drain body 以便复用 TCP 连接
	io.CopyN(io.Discard, resp.Body, 1024)
	resp.Body.Close()

	p.mu.Lock()
	defer p.mu.Unlock()

	e.LastCheck = time.Now()
	e.Latency = latency
	e.StatusCode = resp.StatusCode
	e.totalChecks++

	// Track status code distribution
	e.statusCodes[resp.StatusCode]++

	// Track errors (4xx + 5xx)
	if resp.StatusCode >= 400 {
		e.errorCount++
		e.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else {
		e.LastError = ""
	}

	// Append latency to window (max 100)
	e.latencies = append(e.latencies, latency)
	if len(e.latencies) > 100 {
		e.latencies = e.latencies[len(e.latencies)-100:]
	}

	// 向宝塔学习：不在每次探测时都排序算 P50/P95/P99
	// 这些指标只在用户查看面板时才需要，GetEndpoints() 会调 computeMetrics()
}

func (p *Probe) recordEndpointFailure(e *EndpointMonitor, errMsg string, start time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	e.LastCheck = time.Now()
	e.Latency = time.Since(start)
	e.LastError = errMsg
	e.totalChecks++
	e.errorCount++

	// Record a high latency for failed requests
	e.latencies = append(e.latencies, 10*time.Second)
	if len(e.latencies) > 100 {
		e.latencies = e.latencies[len(e.latencies)-100:]
	}

	// 不在每次探测时调用 computeMetrics()，延迟到 GetEndpoints()
}

// computeMetrics calculates P50/P95/P99 and error rate.
func (e *EndpointMonitor) computeMetrics() {
	if len(e.latencies) == 0 {
		return
	}

	// Sort a copy for percentile calculation
	sorted := make([]time.Duration, len(e.latencies))
	copy(sorted, e.latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	e.P50 = float64(sorted[len(sorted)*50/100].Microseconds()) / 1000.0
	e.P95 = float64(sorted[len(sorted)*95/100].Microseconds()) / 1000.0
	e.P99 = float64(sorted[len(sorted)*99/100].Microseconds()) / 1000.0

	if e.totalChecks > 0 {
		e.ErrorRate = float64(e.errorCount) / float64(e.totalChecks) * 100
	}
}

// --- Health Summary ---

// SiteDownCount returns the number of sites currently down.
func (p *Probe) SiteDownCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, s := range p.sites {
		if s.Enabled && !s.Up && s.TotalChecks > 0 {
			count++
		}
	}
	return count
}

// SiteUpCount returns the number of sites currently up.
func (p *Probe) SiteUpCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, s := range p.sites {
		if s.Enabled && s.Up {
			count++
		}
	}
	return count
}

// simplifyError 将 Go 的原始错误信息简化为用户友好的提示
func simplifyError(err error) string {
	msg := err.Error()
	// 超时类错误
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Client.Timeout exceeded") {
		return "请求超时（服务器未在 25 秒内响应）"
	}
	// DNS 解析失败
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "lookup") {
		return "DNS 解析失败（域名无法解析）"
	}
	// TCP 连接被拒绝
	if strings.Contains(msg, "connection refused") {
		return "连接被拒绝（目标端口未开放或服务未运行）"
	}
	// 网络不可达
	if strings.Contains(msg, "no route to host") || strings.Contains(msg, "network is unreachable") {
		return "网络不可达（目标主机不可访问）"
	}
	// TLS 握手失败
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "certificate") {
		return "TLS 握手失败（证书问题）"
	}
	// 连接重置
	if strings.Contains(msg, "connection reset") {
		return "连接被重置（服务器强制关闭了连接）"
	}
	// 重定向过多
	if strings.Contains(msg, "stopped after 5 redirects") {
		return "重定向次数过多（超过 5 次）"
	}
	// 默认：截断过长的错误信息
	if len(msg) > 120 {
		return msg[:120] + "..."
	}
	return msg
}
