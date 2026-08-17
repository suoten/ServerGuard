package intel

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// IntelSync 威胁情报同步接口
type IntelSync interface {
	SyncCVE() error
	SyncMaliciousIPs() error
	QueryCVE(component, version string) ([]CVEInfo, error)
	QueryIP(ip string) (*IPInfo, error)
}

// CVEInfo CVE 漏洞信息
type CVEInfo struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	CVSSScore   float64   `json:"cvss_score"`
	Severity    string    `json:"severity"`
	Published   time.Time `json:"published"`
	Updated     time.Time `json:"updated"`
	References  []string  `json:"references"`
}

// IPInfo 恶意 IP 信息
type IPInfo struct {
	IP           string    `json:"ip"`
	Confidence   int       `json:"confidence"`
	AbuseReports int       `json:"abuse_reports"`
	Country      string    `json:"country"`
	Categories   []string  `json:"categories"`
	LastReported time.Time `json:"last_reported"`
}

// IntelManager 威胁情报管理器，聚合多个情报源
type IntelManager struct {
	mu          sync.RWMutex
	sources     []IntelSync
	sourceNames []string
	lastSync    time.Time
	syncErrors  map[string]string // 源名 -> 最后一次错误信息
	cveCount    int               // 已缓存的 CVE 总数
	ipCount     int               // 已缓存的恶意 IP 总数
}

// NewIntelManager 创建情报管理器
func NewIntelManager() *IntelManager {
	return &IntelManager{
		syncErrors: make(map[string]string),
	}
}

// AddSource 添加情报源
func (m *IntelManager) AddSource(name string, source IntelSync) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources = append(m.sources, source)
	m.sourceNames = append(m.sourceNames, name)
}

// SyncAll 同步所有情报源（真实执行）
func (m *IntelManager) SyncAll(ctx context.Context) error {
	m.mu.Lock()
	sources := make([]IntelSync, len(m.sources))
	names := make([]string, len(m.sourceNames))
	copy(sources, m.sources)
	copy(names, m.sourceNames)
	m.mu.Unlock()

	var wg sync.WaitGroup
	var totalCVEs, totalIPs int
	var mu sync.Mutex

	for i, source := range sources {
		name := names[i]
		wg.Add(1)
		go func(name string, source IntelSync) {
			defer wg.Done()
			cveErr := source.SyncCVE()
			ipErr := source.SyncMaliciousIPs()

			m.mu.Lock()
			if cveErr != nil {
				m.syncErrors[name] = fmt.Sprintf("CVE同步失败: %v", cveErr)
			} else if ipErr != nil {
				m.syncErrors[name] = fmt.Sprintf("IP同步失败: %v", ipErr)
			} else {
				delete(m.syncErrors, name)
			}
			m.mu.Unlock()

			// 统计缓存数
			if cves, err := source.QueryCVE("", ""); err == nil {
				mu.Lock()
				totalCVEs += len(cves)
				mu.Unlock()
			}
		}(name, source)
	}
	wg.Wait()

	m.mu.Lock()
	m.lastSync = time.Now()
	m.cveCount = totalCVEs
	m.ipCount = totalIPs
	m.mu.Unlock()

	return nil
}

// GetStatus 返回情报源真实状态
func (m *IntelManager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sourceStatus := make([]map[string]interface{}, len(m.sources))
	for i, name := range m.sourceNames {
		status := map[string]interface{}{
			"name":   name,
			"status": "ok",
		}
		if err, exists := m.syncErrors[name]; exists {
			status["status"] = "error"
			status["error"] = err
		}
		sourceStatus[i] = status
	}

	return map[string]interface{}{
		"sources":       sourceStatus,
		"last_sync":     m.lastSync,
		"cve_count":     m.cveCount,
		"ip_count":      m.ipCount,
		"source_count":  len(m.sources),
	}
}

// QueryCVE 聚合查询 CVE
func (m *IntelManager) QueryCVE(component, version string) ([]CVEInfo, error) {
	var allCVEs []CVEInfo
	for _, source := range m.sources {
		if cves, err := source.QueryCVE(component, version); err == nil {
			allCVEs = append(allCVEs, cves...)
		}
	}
	return allCVEs, nil
}

// QueryIP 聚合查询 IP
func (m *IntelManager) QueryIP(ip string) (*IPInfo, error) {
	for _, source := range m.sources {
		if info, err := source.QueryIP(ip); err == nil && info != nil {
			return info, nil
		}
	}
	return nil, nil
}
