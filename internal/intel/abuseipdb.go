package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AbuseIPDBClient AbuseIPDB 恶意 IP 库同步客户端
type AbuseIPDBClient struct {
	apiKey   string
	cache    map[string]*IPInfo
	mu       sync.RWMutex
	lastSync time.Time
}

// NewAbuseIPDBClient 创建 AbuseIPDB 客户端
func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		apiKey: apiKey,
		cache:  make(map[string]*IPInfo),
	}
}

// SyncCVE AbuseIPDB 不提供 CVE 数据
func (a *AbuseIPDBClient) SyncCVE() error {
	return nil
}

// SyncMaliciousIPs 同步 AbuseIPDB 黑名单 IP（拉取高置信度恶意 IP 并缓存）
func (a *AbuseIPDBClient) SyncMaliciousIPs() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastSync = time.Now()

	if a.apiKey == "" {
		return fmt.Errorf("AbuseIPDB API key not configured")
	}

	// 拉取置信度 >= 75 的恶意 IP 列表
	url := "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75&limit=1000"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("AbuseIPDB blacklist fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AbuseIPDB API returned status %d", resp.StatusCode)
	}

	var result struct {
		Data []struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// 缓存所有恶意 IP
	for _, entry := range result.Data {
		info := &IPInfo{
			IP:           entry.IPAddress,
			Confidence:   entry.AbuseConfidenceScore,
			AbuseReports: entry.TotalReports,
			Country:      entry.CountryCode,
		}
		if t, err := time.Parse(time.RFC3339, entry.LastReportedAt); err == nil {
			info.LastReported = t
		}
		a.cache[entry.IPAddress] = info
	}

	return nil
}

// QueryCVE AbuseIPDB 不提供 CVE 查询
func (a *AbuseIPDBClient) QueryCVE(component, version string) ([]CVEInfo, error) {
	return nil, nil
}

// QueryIP 查询 IP 的恶意报告
func (a *AbuseIPDBClient) QueryIP(ip string) (*IPInfo, error) {
	// 无 Key 时直接跳过——否则每个未缓存 IP 都会对 AbuseIPDB 发起一次
	// 注定 401 的外部请求（10s 超时预算），CC 攻击场景下会成倍放大延迟
	if a.apiKey == "" {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	a.mu.RLock()
	if info, ok := a.cache[ip]; ok {
		a.mu.RUnlock()
		return info, nil
	}
	a.mu.RUnlock()

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB query failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			IsPublic             bool   `json:"isPublic"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	info := &IPInfo{
		IP:           result.Data.IPAddress,
		Confidence:   result.Data.AbuseConfidenceScore,
		AbuseReports: result.Data.TotalReports,
		Country:      result.Data.CountryCode,
	}
	if t, err := time.Parse(time.RFC3339, result.Data.LastReportedAt); err == nil {
		info.LastReported = t
	}

	a.mu.Lock()
	a.cache[ip] = info
	a.mu.Unlock()

	return info, nil
}
