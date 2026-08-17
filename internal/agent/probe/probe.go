package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sort"
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
func newProbeClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 探测只需检查存活，不校验证书
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
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
		interval = 30 * time.Second
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
		interval = 60 * time.Second
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
func (p *Probe) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
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
	req, err := http.NewRequestWithContext(context.Background(), "GET", s.URL, nil)
	if err != nil {
		p.recordSiteFailure(s, err.Error(), start)
		return
	}
	req.Header.Set("User-Agent", "ServerGuard-Probe/1.0")

	resp, err := p.client.Do(req)
	latency := time.Since(start)
	if err != nil {
		p.recordSiteFailure(s, err.Error(), start)
		return
	}
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
	req, err := http.NewRequestWithContext(context.Background(), e.Method, e.URL, nil)
	if err != nil {
		p.recordEndpointFailure(e, err.Error(), start)
		return
	}
	req.Header.Set("User-Agent", "ServerGuard-Probe/1.0")

	resp, err := p.client.Do(req)
	latency := time.Since(start)
	if err != nil {
		p.recordEndpointFailure(e, err.Error(), start)
		return
	}
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

	e.computeMetrics()
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

	e.computeMetrics()
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
