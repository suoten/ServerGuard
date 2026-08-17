package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// ─────────────────────────────────────────────────────────────
// CVE Feed Monitor：主动拉取 NVD 近期 CVE，匹配本机已安装软件
// ─────────────────────────────────────────────────────────────

// CVEFeedItem 表示一条从 NVD 拉取的 CVE 记录
type CVEFeedItem struct {
	CVEID       string    `json:"cve_id"`
	Product     string    `json:"product"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	PublishedAt time.Time `json:"published_at"`
	ReferenceURL string   `json:"reference_url,omitempty"`
}

// SecurityUpdateItem 表示一个待安装的安全补丁
type SecurityUpdateItem struct {
	PackageName  string `json:"package_name"`
	CurrentVer   string `json:"current_version"`
	UpdateVer    string `json:"update_version"`
	Severity     string `json:"severity"` // critical / important / moderate / low
	Description  string `json:"description"`
	UpdateType   string `json:"update_type"` // security / bugfix / enhancement
	AdvisoryID   string `json:"advisory_id,omitempty"` // RHSA-xxxx:xxxx / DSA-xxxx
}

// FeedMonitor 定期拉取 NVD CVE 数据并匹配本机已安装软件版本，
// 同时检查系统待安装的安全补丁。
type FeedMonitor struct {
	mu sync.RWMutex

	// 依赖
	vulnGuard *VulnScanGuard

	// 缓存
	recentCVEs     []CVEFeedItem       // 最近拉取到的 CVE 列表
	matchedCVEs    []CVEFeedItem       // 匹配到本机软件的 CVE
	pendingUpdates []SecurityUpdateItem // 待安装的安全补丁
	lastCheckTime  time.Time
	lastError      string

	// 已通知的 CVE 集合（避免重复告警）
	notifiedCVEs map[string]bool

	// NVD API Key（可选，有 key 速率限制更宽松）
	nvdAPIKey string

	// HTTP 客户端
	httpClient *http.Client
}

// NewFeedMonitor 创建 CVE Feed 监控器
func NewFeedMonitor(vulnGuard *VulnScanGuard, nvdAPIKey string) *FeedMonitor {
	return &FeedMonitor{
		vulnGuard:   vulnGuard,
		nvdAPIKey:   nvdAPIKey,
		notifiedCVEs: make(map[string]bool),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Check 执行一次完整的检查：
//  1. 拉取 NVD 近 7 天的 CVE（针对本机已安装的关键软件）
//  2. 将 CVE 与本机版本进行匹配
//  3. 检查系统待安装的安全补丁
//
// 返回匹配到的 CVE 列表和待安装的安全补丁列表。
func (m *FeedMonitor) Check(ctx context.Context) ([]CVEFeedItem, []SecurityUpdateItem, error) {
	var errors []string

	// 1. 获取本机已安装软件版本
	installedComponents := m.getInstalledComponents(ctx)

	// 2. 拉取 NVD 近期 CVE 并匹配
	matchedCVEs, err := m.fetchAndMatchCVEs(ctx, installedComponents)
	if err != nil {
		errors = append(errors, fmt.Sprintf("NVD拉取: %v", err))
	}

	// 3. 检查系统安全补丁
	updates, err := m.checkSecurityUpdates(ctx)
	if err != nil {
		errors = append(errors, fmt.Sprintf("安全补丁检查: %v", err))
	}

	m.mu.Lock()
	m.matchedCVEs = matchedCVEs
	m.pendingUpdates = updates
	m.lastCheckTime = time.Now()
	if len(errors) > 0 {
		m.lastError = strings.Join(errors, "; ")
	} else {
		m.lastError = ""
	}
	m.mu.Unlock()

	if len(errors) > 0 {
		return matchedCVEs, updates, fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return matchedCVEs, updates, nil
}

// getInstalledComponents 获取本机已安装的关键软件及其版本
func (m *FeedMonitor) getInstalledComponents(ctx context.Context) []componentInfo {
	components := []struct {
		name string
		cmd  string
		args []string
	}{
		{"nginx", "nginx", []string{"-v"}},
		{"apache", "apachectl", []string{"-v"}},
		{"php", "php", []string{"-v"}},
		{"mysql", "mysql", []string{"--version"}},
		{"redis", "redis-server", []string{"--version"}},
		{"openssl", "openssl", []string{"version"}},
		{"openssh", "ssh", []string{"-V"}},
		{"node", "node", []string{"--version"}},
		{"python", "python3", []string{"--version"}},
		{"docker", "docker", []string{"--version"}},
	}

	var result []componentInfo
	for _, comp := range components {
		rawVersion, err := getCommandVersion(ctx, comp.cmd, comp.args)
		if err != nil || rawVersion == "" {
			continue
		}
		cleanVersion := extractProductVersion(comp.name, rawVersion)
		if cleanVersion == "" {
			continue
		}
		result = append(result, componentInfo{
			Name:    comp.name,
			Version: cleanVersion,
		})
	}
	return result
}

// componentInfo 已安装软件信息
type componentInfo struct {
	Name    string
	Version string
}

// fetchAndMatchCVEs 从 NVD API 拉取近期 CVE 并与本地软件匹配
func (m *FeedMonitor) fetchAndMatchCVEs(ctx context.Context, components []componentInfo) ([]CVEFeedItem, error) {
	if len(components) == 0 {
		return nil, nil
	}

	// 拉取近 7 天的 CVE
	since := time.Now().AddDate(0, 0, -7)
	var allCVEs []CVEFeedItem
	var fetchErrors []string

	// 为每个已安装的产品拉取 CVE
	seenProducts := make(map[string]bool)
	for _, comp := range components {
		if seenProducts[comp.Name] {
			continue
		}
		seenProducts[comp.Name] = true

		cves, err := m.fetchNVDRecentCVEs(ctx, comp.Name, since)
		if err != nil {
			fetchErrors = append(fetchErrors, fmt.Sprintf("%s: %v", comp.Name, err))
			continue
		}
		allCVEs = append(allCVEs, cves...)
	}

	m.mu.Lock()
	m.recentCVEs = allCVEs
	m.mu.Unlock()

	// 匹配：检查每个 CVE 是否影响本机安装的版本
	var matched []CVEFeedItem
	if m.vulnGuard != nil {
		m.vulnGuard.cveDatabase.mu.RLock()
		localEntries := make([]CVEEntry, len(m.vulnGuard.cveDatabase.Entries))
		copy(localEntries, m.vulnGuard.cveDatabase.Entries)
		m.vulnGuard.cveDatabase.mu.RUnlock()

		for _, cve := range allCVEs {
			for _, comp := range components {
				if !strings.EqualFold(cve.Product, comp.Name) {
					continue
				}
				// 检查本地 CVE 库中是否有该 CVE 的版本范围信息
				for _, entry := range localEntries {
					if entry.CVEID == cve.CVEID && entry.Product == comp.Name {
						if isVersionVulnerable(comp.Version, entry.VulnVersions) {
							matched = append(matched, cve)
						}
						break
					}
				}
			}
		}
	}

	if len(fetchErrors) > 0 {
		return matched, fmt.Errorf("部分产品拉取失败: %s", strings.Join(fetchErrors, "; "))
	}
	return matched, nil
}

// fetchNVDRecentCVEs 从 NVD API 拉取指定产品近期的 CVE
func (m *FeedMonitor) fetchNVDRecentCVEs(ctx context.Context, product string, since time.Time) ([]CVEFeedItem, error) {
	// NVD API v2：按关键词搜索，按发布日期过滤
	pubStart := since.Format("2006-01-02T00:00:00.000")
	pubEnd := time.Now().Format("2006-01-02T23:59:59.999")

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/v2/cves?keywordSearch=%s&pubStartDate=%s&pubEndDate=%s&resultsPerPage=20",
		product, pubStart, pubEnd)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if m.nvdAPIKey != "" {
		req.Header.Set("apiKey", m.nvdAPIKey)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API 返回状态码 %d", resp.StatusCode)
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
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
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var items []CVEFeedItem
	for _, vuln := range result.Vulnerabilities {
		severity := "medium"
		if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
			s := vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
			if s != "" {
				severity = strings.ToLower(s)
			}
		} else if len(vuln.CVE.Metrics.CvssMetricV2) > 0 {
			s := vuln.CVE.Metrics.CvssMetricV2[0].CvssData.BaseSeverity
			if s != "" {
				severity = strings.ToLower(s)
			}
		}

		description := ""
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		pubAt, _ := time.Parse(time.RFC3339, vuln.CVE.Published)

		refURL := ""
		if len(vuln.CVE.References) > 0 {
			refURL = vuln.CVE.References[0].URL
		}

		items = append(items, CVEFeedItem{
			CVEID:        vuln.CVE.ID,
			Product:      product,
			Severity:     severity,
			Description:  description,
			PublishedAt:  pubAt,
			ReferenceURL: refURL,
		})
	}

	return items, nil
}

// checkSecurityUpdates 检查系统待安装的安全补丁
func (m *FeedMonitor) checkSecurityUpdates(ctx context.Context) ([]SecurityUpdateItem, error) {
	if runtime.GOOS == "windows" {
		return nil, nil // Windows 暂不支持
	}

	// 优先尝试 yum/dnf（CentOS/RHEL/Alibaba Cloud Linux）
	updates, err := m.checkYumSecurityUpdates(ctx)
	if err == nil && len(updates) >= 0 {
		return updates, nil
	}

	// 回退到 apt（Debian/Ubuntu）
	updates, err = m.checkAptSecurityUpdates(ctx)
	if err != nil {
		return nil, err
	}
	return updates, nil
}

// checkYumSecurityUpdates 使用 yum/dnf 检查安全更新
func (m *FeedMonitor) checkYumSecurityUpdates(ctx context.Context) ([]SecurityUpdateItem, error) {
	// 优先使用 dnf，回退到 yum
	var cmd *exec.Cmd
	for _, tool := range []string{"dnf", "yum"} {
		if _, err := exec.LookPath(tool); err == nil {
			// dnf/yum updateinfo list --security --available
			cmd = exec.CommandContext(ctx, tool, "updateinfo", "list", "--security", "--available")
			break
		}
	}
	if cmd == nil {
		return nil, fmt.Errorf("yum/dnf 未安装")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var updates []SecurityUpdateItem
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") || strings.HasPrefix(line, "Updating") {
			continue
		}
		// 格式: RHSA-2024:1234  Important/Sec  pkg-name  1.2.3-4.el8
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		advisoryID := fields[0]
		severity := "moderate"
		if strings.Contains(strings.ToLower(line), "critical") {
			severity = "critical"
		} else if strings.Contains(strings.ToLower(line), "important") {
			severity = "important"
		} else if strings.Contains(strings.ToLower(line), "moderate") {
			severity = "moderate"
		} else if strings.Contains(strings.ToLower(line), "low") {
			severity = "low"
		}

		pkgName := fields[2]
		updateVer := ""
		if len(fields) >= 4 {
			updateVer = fields[3]
		}

		updates = append(updates, SecurityUpdateItem{
			PackageName: pkgName,
			UpdateVer:   updateVer,
			Severity:    severity,
			UpdateType:  "security",
			AdvisoryID:  advisoryID,
			Description: fmt.Sprintf("安全公告 %s 建议更新 %s", advisoryID, pkgName),
		})
	}

	return updates, nil
}

// checkAptSecurityUpdates 使用 apt 检查安全更新（Debian/Ubuntu）
func (m *FeedMonitor) checkAptSecurityUpdates(ctx context.Context) ([]SecurityUpdateItem, error) {
	if _, err := exec.LookPath("apt"); err != nil {
		return nil, fmt.Errorf("apt 未安装")
	}

	// 先更新包索引（静默模式）
	_ = exec.CommandContext(ctx, "apt", "update", "-qq").Run()

	// 列出可升级的包
	cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable", "-qq")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var updates []SecurityUpdateItem
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 格式: pkg-name/stable 1.2.3 all [upgradable from: 1.2.2]
		// 判断是否来自 security 源
		isSecurity := strings.Contains(line, "/security") || strings.Contains(line, "-security")
		if !isSecurity {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			continue
		}

		nameVer := strings.Split(parts[0], "/")
		pkgName := nameVer[0]
		updateVer := parts[1]

		updates = append(updates, SecurityUpdateItem{
			PackageName: pkgName,
			UpdateVer:   updateVer,
			Severity:    "important",
			UpdateType:  "security",
			Description: fmt.Sprintf("安全更新: %s -> %s", pkgName, updateVer),
		})
	}

	return updates, nil
}

// GetStatus 返回当前缓存的状态
func (m *FeedMonitor) GetStatus() FeedMonitorStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 统计各严重级别的 CVE 数量
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, cve := range m.matchedCVEs {
		switch strings.ToLower(cve.Severity) {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	// 统计安全补丁
	criticalUpdates := 0
	importantUpdates := 0
	for _, u := range m.pendingUpdates {
		switch strings.ToLower(u.Severity) {
		case "critical":
			criticalUpdates++
		case "important", "high":
			importantUpdates++
		}
	}

	return FeedMonitorStatus{
		LastCheckTime:     m.lastCheckTime,
		LastError:         m.lastError,
		RecentCVECount:    len(m.recentCVEs),
		MatchedCVEs:       m.matchedCVEs,
		PendingUpdates:    m.pendingUpdates,
		CriticalCVECount:  criticalCount,
		HighCVECount:      highCount,
		MediumCVECount:    mediumCount,
		CriticalUpdates:   criticalUpdates,
		ImportantUpdates:  importantUpdates,
		TotalUpdates:      len(m.pendingUpdates),
	}
}

// FeedMonitorStatus Feed 监控器状态
type FeedMonitorStatus struct {
	LastCheckTime    time.Time          `json:"last_check_time"`
	LastError        string             `json:"last_error,omitempty"`
	RecentCVECount   int                `json:"recent_cve_count"`
	MatchedCVEs      []CVEFeedItem      `json:"matched_cves"`
	PendingUpdates   []SecurityUpdateItem `json:"pending_updates"`
	CriticalCVECount int                `json:"critical_cve_count"`
	HighCVECount     int                `json:"high_cve_count"`
	MediumCVECount   int                `json:"medium_cve_count"`
	CriticalUpdates  int                `json:"critical_updates"`
	ImportantUpdates int                `json:"important_updates"`
	TotalUpdates     int                `json:"total_updates"`
}

// IsNewCVE 检查是否是之前未通知过的新 CVE
func (m *FeedMonitor) IsNewCVE(cveID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.notifiedCVEs[cveID] {
		return false
	}
	m.notifiedCVEs[cveID] = true
	return true
}

// BuildAlertMessage 构建告警消息
func (m *FeedMonitor) BuildAlertMessage() (title, message string, level types.AlertLevel) {
	status := m.GetStatus()

	var parts []string
	criticalTotal := status.CriticalCVECount + status.CriticalUpdates
	highTotal := status.HighCVECount + status.ImportantUpdates

	if criticalTotal > 0 {
		level = types.AlertCritical
		title = fmt.Sprintf("发现 %d 个严重安全漏洞/补丁待处理", criticalTotal)
	} else if highTotal > 0 {
		level = types.AlertWarning
		title = fmt.Sprintf("发现 %d 个高危安全漏洞/补丁待处理", highTotal)
	} else if status.TotalUpdates > 0 || len(status.MatchedCVEs) > 0 {
		level = types.AlertInfo
		title = fmt.Sprintf("发现 %d 个安全更新待处理", status.TotalUpdates+len(status.MatchedCVEs))
	} else {
		return "", "", types.AlertInfo
	}

	if status.CriticalCVECount > 0 {
		parts = append(parts, fmt.Sprintf("%d 个严重 CVE 影响已安装软件", status.CriticalCVECount))
	}
	if status.HighCVECount > 0 {
		parts = append(parts, fmt.Sprintf("%d 个高危 CVE 影响已安装软件", status.HighCVECount))
	}
	if status.CriticalUpdates > 0 {
		parts = append(parts, fmt.Sprintf("%d 个严重安全补丁待安装", status.CriticalUpdates))
	}
	if status.ImportantUpdates > 0 {
		parts = append(parts, fmt.Sprintf("%d 个重要安全补丁待安装", status.ImportantUpdates))
	}
	if status.TotalUpdates > status.CriticalUpdates+status.ImportantUpdates {
		other := status.TotalUpdates - status.CriticalUpdates - status.ImportantUpdates
		if other > 0 {
			parts = append(parts, fmt.Sprintf("%d 个一般安全补丁待安装", other))
		}
	}

	// 列出前 3 个匹配的 CVE
	for i, cve := range status.MatchedCVEs {
		if i >= 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s): %s", cve.CVEID, cve.Product, truncateDesc(cve.Description, 60)))
	}

	message = strings.Join(parts, "\n")
	return title, message, level
}

// truncateDesc 截断描述字符串
func truncateDesc(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
