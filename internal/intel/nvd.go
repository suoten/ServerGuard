package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// NVDClient NVD CVE 库同步客户端
type NVDClient struct {
	apiKey   string
	cache    map[string][]CVEInfo
	mu       sync.RWMutex
	lastSync time.Time
}

// NewNVDClient 创建 NVD 客户端
func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		apiKey: apiKey,
		cache:  make(map[string][]CVEInfo),
	}
}

// SyncCVE 同步 NVD 最近 7 天的 CVE 数据并缓存
func (n *NVDClient) SyncCVE() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lastSync = time.Now()

	// 拉取最近 7 天的 CVE
	pubStart := time.Now().AddDate(0, 0, -7).Format("2006-01-02T00:00:00.000")
	pubEnd := time.Now().Format("2006-01-02T23:59:59.999")

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/v2/cves?pubStartDate=%s&pubEndDate=%s&resultsPerPage=50",
		pubStart, pubEnd)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if n.apiKey != "" {
		req.Header.Set("apiKey", n.apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("NVD sync failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV2 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Published  string `json:"published"`
				Updated    string `json:"lastModified"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// 缓存所有 CVE，按关键词索引
	for _, v := range result.Vulnerabilities {
		cve := CVEInfo{
			ID: v.CVE.ID,
		}
		// 提取英文描述
		for _, desc := range v.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}
		// 提取 CVSS 分数
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			cve.CVSSScore = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			cve.Severity = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(v.CVE.Metrics.CvssMetricV2) > 0 {
			cve.CVSSScore = v.CVE.Metrics.CvssMetricV2[0].CvssData.BaseScore
			cve.Severity = v.CVE.Metrics.CvssMetricV2[0].CvssData.BaseSeverity
		}
		if t, err := time.Parse(time.RFC3339, v.CVE.Published); err == nil {
			cve.Published = t
		}
		if t, err := time.Parse(time.RFC3339, v.CVE.Updated); err == nil {
			cve.Updated = t
		}
		for _, ref := range v.CVE.References {
			cve.References = append(cve.References, ref.URL)
		}

		// 按 CVE ID 缓存
		n.cache["_recent:"+cve.ID] = append(n.cache["_recent:"+cve.ID], cve)
	}

	return nil
}

// SyncMaliciousIPs NVD 不提供恶意 IP 数据
func (n *NVDClient) SyncMaliciousIPs() error {
	return nil
}

// QueryCVE 查询指定组件和版本的 CVE
func (n *NVDClient) QueryCVE(component, version string) ([]CVEInfo, error) {
	n.mu.RLock()
	if cves, ok := n.cache[component+":"+version]; ok {
		n.mu.RUnlock()
		return cves, nil
	}
	n.mu.RUnlock()

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/v2/cves?keywordSearch=%s&resultsPerPage=20", component)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if n.apiKey != "" {
		req.Header.Set("apiKey", n.apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD query failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description string `json:"descriptions"`
				Metrics     struct {
					CvssMetricV2 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Published string `json:"published"`
				Updated   string `json:"lastModified"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var cves []CVEInfo
	for _, v := range result.Vulnerabilities {
		cve := CVEInfo{
			ID:          v.CVE.ID,
			Description: v.CVE.Description,
		}
		if len(v.CVE.Metrics.CvssMetricV2) > 0 {
			cve.CVSSScore = v.CVE.Metrics.CvssMetricV2[0].CvssData.BaseScore
		}
		if t, err := time.Parse(time.RFC3339, v.CVE.Published); err == nil {
			cve.Published = t
		}
		if t, err := time.Parse(time.RFC3339, v.CVE.Updated); err == nil {
			cve.Updated = t
		}
		cves = append(cves, cve)
	}

	n.mu.Lock()
	n.cache[component+":"+version] = cves
	n.mu.Unlock()

	return cves, nil
}

// QueryIP NVD 不提供 IP 查询
func (n *NVDClient) QueryIP(ip string) (*IPInfo, error) {
	return nil, nil
}
