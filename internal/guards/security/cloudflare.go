package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CloudflareClient Cloudflare API 客户端
type CloudflareClient struct {
	apiToken string
	zoneID   string
	client   *http.Client
}

// NewCloudflareClient 创建 Cloudflare 客户端
func NewCloudflareClient(apiToken, zoneID string) *CloudflareClient {
	return &CloudflareClient{
		apiToken: apiToken,
		zoneID:   zoneID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// IsProxied 检测域名是否通过 Cloudflare 代理
func (c *CloudflareClient) IsProxied(domain string) (bool, error) {
	if c.apiToken == "" {
		return false, nil
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s", c.zoneID, domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("cloudflare API failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result []struct {
			Proxied bool `json:"proxied"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	for _, r := range result.Result {
		if r.Proxied {
			return true, nil
		}
	}
	return false, nil
}

// BanIP 通过 Cloudflare 防火墙规则封禁 IP
func (c *CloudflareClient) BanIP(ip string, duration time.Duration) error {
	if c.apiToken == "" {
		return fmt.Errorf("cloudflare API token not configured")
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules", c.zoneID)
	body := fmt.Sprintf(`{"mode":"block","configuration":{"target":"ip","value":"%s"},"notes":"ServerGuard auto-ban"}`, ip)

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare ban IP failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare ban IP returned status %d", resp.StatusCode)
	}
	return nil
}

// UnbanIP 解除 Cloudflare IP 封禁
func (c *CloudflareClient) UnbanIP(ip string) error {
	if c.apiToken == "" {
		return fmt.Errorf("cloudflare API token not configured")
	}

	// 先查询规则 ID
	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules?configuration.value=%s", c.zoneID, ip)
	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var listResult struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResult); err != nil {
		return err
	}

	for _, rule := range listResult.Result {
		delURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules/%s", c.zoneID, rule.ID)
		delReq, _ := http.NewRequest("DELETE", delURL, nil)
		delReq.Header.Set("Authorization", "Bearer "+c.apiToken)
		delResp, err := c.client.Do(delReq)
		if err != nil {
			continue
		}
		delResp.Body.Close()
	}
	return nil
}
