package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// OTXClient AlienVault OTX 威胁情报同步客户端
type OTXClient struct {
	apiKey   string
	cache    map[string]*IPInfo
	mu       sync.RWMutex
	lastSync time.Time
}

// NewOTXClient 创建 OTX 客户端
func NewOTXClient(apiKey string) *OTXClient {
	return &OTXClient{
		apiKey: apiKey,
		cache:  make(map[string]*IPInfo),
	}
}

// SyncCVE 同步 OTX 漏洞数据
func (o *OTXClient) SyncCVE() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lastSync = time.Now()
	return nil
}

// SyncMaliciousIPs 同步 OTX 恶意 IP 数据
func (o *OTXClient) SyncMaliciousIPs() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lastSync = time.Now()
	return nil
}

// QueryCVE 查询 OTX 漏洞
func (o *OTXClient) QueryCVE(component, version string) ([]CVEInfo, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/search/pulses?q=%s", component)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if o.apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", o.apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OTX query failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Created     string `json:"created"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var cves []CVEInfo
	for _, r := range result.Results {
		cve := CVEInfo{
			ID:          r.ID,
			Description: r.Name + ": " + r.Description,
		}
		if t, err := time.Parse(time.RFC3339, r.Created); err == nil {
			cve.Published = t
		}
		cves = append(cves, cve)
	}
	return cves, nil
}

// QueryIP 查询 OTX IP 信誉
func (o *OTXClient) QueryIP(ip string) (*IPInfo, error) {
	o.mu.RLock()
	if info, ok := o.cache[ip]; ok {
		o.mu.RUnlock()
		return info, nil
	}
	o.mu.RUnlock()

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if o.apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", o.apiKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OTX IP query failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	info := &IPInfo{
		IP:           ip,
		AbuseReports: result.PulseInfo.Count,
	}
	if result.PulseInfo.Count > 0 {
		info.Confidence = 50
	}

	o.mu.Lock()
	// 上限保护：公网服务器会被扫描器用大量一次性 IP 打进来，
	// 不设上限的 per-IP 缓存就是慢性内存泄漏
	if len(o.cache) > 4096 {
		o.cache = map[string]*IPInfo{ip: info} // 直接换新，保留当前条目
	} else {
		o.cache[ip] = info
	}
	o.mu.Unlock()

	return info, nil
}