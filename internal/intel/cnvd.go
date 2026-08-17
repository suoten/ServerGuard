package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CNVDClient CNVD 漏洞库同步客户端
type CNVDClient struct {
	apiKey   string
	cache    map[string][]CVEInfo
	mu       sync.RWMutex
	lastSync time.Time
}

// NewCNVDClient 创建 CNVD 客户端
func NewCNVDClient(apiKey string) *CNVDClient {
	return &CNVDClient{
		apiKey: apiKey,
		cache:  make(map[string][]CVEInfo),
	}
}

// SyncCVE 同步 CNVD 漏洞数据
func (c *CNVDClient) SyncCVE() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSync = time.Now()
	return nil
}

// SyncMaliciousIPs CNVD 不提供恶意 IP 数据
func (c *CNVDClient) SyncMaliciousIPs() error {
	return nil
}

// QueryCVE 查询 CNVD 漏洞
func (c *CNVDClient) QueryCVE(component, version string) ([]CVEInfo, error) {
	c.mu.RLock()
	if cves, ok := c.cache[component+":"+version]; ok {
		c.mu.RUnlock()
		return cves, nil
	}
	c.mu.RUnlock()

	url := fmt.Sprintf("https://www.cnvd.org.cn/openapi/v1/cves?keyword=%s", component)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CNVD query failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			PublishTime string `json:"publishTime"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var cves []CVEInfo
	for _, v := range result.Data {
		cve := CVEInfo{
			ID:          v.ID,
			Description: v.Title,
		}
		if t, err := time.Parse("2006-01-02", v.PublishTime); err == nil {
			cve.Published = t
		}
		cves = append(cves, cve)
	}

	c.mu.Lock()
	c.cache[component+":"+version] = cves
	c.mu.Unlock()

	return cves, nil
}

// QueryIP CNVD 不提供 IP 查询
func (c *CNVDClient) QueryIP(ip string) (*IPInfo, error) {
	return nil, nil
}
