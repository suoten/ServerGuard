// Package apm 提供 APM-lite 能力：Nginx 日志智能分析、慢查询自治、Redis 大Key治理。
// V3.9 — APM-lite + 知识沉淀
package apm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// Nginx 日志智能分析 (P3)
// 实时 tail access.log → 统计 UV/PV/错误率/慢请求/异常 UA/爬虫识别
// ────────────────────────────────────────────────

// NginxLogStats Nginx 日志统计结果
type NginxLogStats struct {
	Timestamp       time.Time          `json:"timestamp"`
	LogFile         string             `json:"log_file"`         // 兼容字段（最后一个文件）
	LogFiles        []LogFileInfo      `json:"log_files"`        // 所有分析的日志文件
	SiteName        string             `json:"site_name"`        // 从日志文件名提取的站点名
	PV              int64              `json:"pv"`
	UV              int64              `json:"uv"`
	ErrorCount      int64              `json:"error_count"`
	ErrorRate       float64            `json:"error_rate"`
	SlowRequests    int64              `json:"slow_requests"`
	SlowRate        float64            `json:"slow_rate"`
	TopURIs         []URIStat          `json:"top_uris"`
	TopIPs          []IPStat           `json:"top_ips"`
	TopUAs          []UAStat           `json:"top_uas"`
	CrawlerCount    int64              `json:"crawler_count"`
	StatusBreakdown map[string]int64   `json:"status_breakdown"`
	ErrorDetails    []ErrorDetail      `json:"error_details"`    // 错误 URI 分析+原因+建议
	Insights        []string           `json:"insights"`         // 智能洞察建议
	AnalyzedLines   int64              `json:"analyzed_lines"`   // 实际分析的行数
	AnalyzeMs       int64              `json:"analyze_ms"`       // 分析耗时(ms)
}

// LogFileInfo 日志文件信息
type LogFileInfo struct {
	Path     string `json:"path"`      // 完整路径
	Name     string `json:"name"`      // 文件名
	Site     string `json:"site"`     // 站点名
	Size     int64  `json:"size"`     // 文件大小(字节)
	ModTime  string `json:"mod_time"` // 最后修改时间
	Lines    int64  `json:"lines"`    // 本次分析的行数
}

// URIStat URI 统计
type URIStat struct {
	URI        string `json:"uri"`
	Count      int64  `json:"count"`
	AvgLatency int64  `json:"avg_latency_ms"`
	ErrorCount int64  `json:"error_count"`
}

// IPStat IP 统计
type IPStat struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

// UAStat User-Agent 统计
type UAStat struct {
	UA    string `json:"ua"`
	Count int64  `json:"count"`
}

// ErrorDetail 错误详情（包含原因和建议）
type ErrorDetail struct {
	URI        string `json:"uri"`
	StatusCode string `json:"status_code"`
	Count      int64  `json:"count"`
	Reason     string `json:"reason"`     // 错误原因分析
	Suggestion string `json:"suggestion"` // 修复建议
}

// NginxLogAnalyzer Nginx 日志分析器
type NginxLogAnalyzer struct {
	store      *storage.Storage
	mu         sync.Mutex
	lastStats  *NginxLogStats
	logPaths   []string // 候选日志路径
	offsets    map[string]int64 // 每个文件的已读偏移
}

// 常见 Nginx access.log 路径
var defaultNginxLogPaths = []string{
	"/var/log/nginx/access.log",
	"/www/wwwlogs/nginx_access.log",
	"/usr/local/nginx/logs/access.log",
	"/etc/nginx/logs/access.log",
	"/var/log/apache2/access.log",
	"/var/log/httpd/access_log",
}

// 爬虫 UA 正则
var crawlerUARegex = regexp.MustCompile(`(?i)(bot|crawler|spider|slurp|baidu|googlebot|bingbot|yandex|sogou|360spider|bytespider|applebot|facebookexternalhit|twitterbot|linkedinbot|semrush|ahrefs|mj12bot|dotbot|petalbot)`)

// Nginx 日志格式正则（combined log format）
var nginxLogRegex = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"`)

// NewNginxLogAnalyzer 创建 Nginx 日志分析器
func NewNginxLogAnalyzer(store *storage.Storage) *NginxLogAnalyzer {
	return &NginxLogAnalyzer{
		store:   store,
		logPaths: defaultNginxLogPaths,
		offsets: make(map[string]int64),
	}
}

// discoverLogFiles 发现存在的日志文件（最多 5 个）
func (a *NginxLogAnalyzer) discoverLogFiles() []string {
	var found []string
	for _, p := range a.logPaths {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	// 也扫描 /www/wwwlogs/ 下的 *.log（宝塔站点日志）
	matches, _ := filepath.Glob("/www/wwwlogs/*.log")
	for _, m := range matches {
		if !contains(found, m) {
			found = append(found, m)
		}
	}
	// 限制最多 5 个文件，避免太多导致分析变慢
	if len(found) > 5 {
		found = found[:5]
	}
	return found
}

// extractSiteName 从日志文件路径提取站点名
func extractSiteName(logPath string) string {
	base := filepath.Base(logPath)
	// 去掉 .log 后缀
	name := strings.TrimSuffix(base, ".log")
	// 常见模式: example.com.log → example.com
	// nginx_access → nginx（主日志）
	// xxx_access.log → xxx
	if strings.Contains(name, "_") {
		parts := strings.Split(name, "_")
		if len(parts) > 0 && parts[0] != "nginx" && parts[0] != "apache" {
			return parts[0]
		}
		return name
	}
	return name
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// Analyze 执行一次日志分析（分析最近窗口内的日志）
func (a *NginxLogAnalyzer) Analyze() (*NginxLogStats, error) {
	startTime := time.Now()

	logFiles := a.discoverLogFiles()
	if len(logFiles) == 0 {
		return nil, fmt.Errorf("未找到 Nginx/Apache access.log")
	}

	stats := &NginxLogStats{
		Timestamp:       time.Now(),
		StatusBreakdown: make(map[string]int64),
	}

	// 统计变量
	uriCount := make(map[string]*URIStat)
	ipSet := make(map[string]int64)
	uaCount := make(map[string]int64)
	errorURIs := make(map[string]*ErrorDetail) // key: URI:status
	var totalLatency int64
	var latencyCount int64

	// 读取最近的日志行（每个文件最后 2000 行，提速 2.5x）
	for _, logFile := range logFiles {
		stats.LogFile = logFile
		siteName := extractSiteName(logFile)
		if stats.SiteName == "" {
			stats.SiteName = siteName
		} else {
			stats.SiteName += ", " + siteName
		}

		lines := readLastNLines(logFile, 2000)

		// 记录文件信息
		fi, _ := os.Stat(logFile)
		fileInfo := LogFileInfo{
			Path: logFile,
			Name: filepath.Base(logFile),
			Site: siteName,
			Lines: int64(len(lines)),
		}
		if fi != nil {
			fileInfo.Size = fi.Size()
			fileInfo.ModTime = fi.ModTime().Format("2006-01-02 15:04:05")
		}
		stats.LogFiles = append(stats.LogFiles, fileInfo)

		for _, line := range lines {
			m := nginxLogRegex.FindStringSubmatch(line)
			if m == nil {
				continue
			}

			ip := m[1]
			method := m[3]
			uri := m[4]
			statusStr := m[6]
			ua := m[9]

			// 截断 URI 查询参数
			if idx := strings.Index(uri, "?"); idx > 0 {
				uri = uri[:idx]
			}

			stats.PV++
			stats.AnalyzedLines++
			ipSet[ip]++

			// 状态码统计
			statusCode := statusStr
			stats.StatusBreakdown[statusCode]++

			// 错误统计 (4xx/5xx)
			isError := len(statusCode) > 0 && (statusCode[0] == '4' || statusCode[0] == '5')
			if isError {
				stats.ErrorCount++
			}

			// 慢请求检测
			if reqTime := extractRequestTime(line); reqTime > 0 {
				totalLatency += int64(reqTime * 1000)
				latencyCount++
				if reqTime > 1.0 {
					stats.SlowRequests++
				}
			}

			// URI 统计
			if us, ok := uriCount[uri]; ok {
				us.Count++
				if isError {
					us.ErrorCount++
				}
			} else {
				uriCount[uri] = &URIStat{URI: uri, Count: 1}
				if isError {
					uriCount[uri].ErrorCount = 1
				}
			}

			// 错误 URI 详情（仅记录有错误的）
			if isError {
				key := uri + ":" + statusCode
				if ed, ok := errorURIs[key]; ok {
					ed.Count++
				} else {
					reason, suggestion := analyzeError(statusCode, uri)
					errorURIs[key] = &ErrorDetail{
						URI:        uri,
						StatusCode: statusCode,
						Count:      1,
						Reason:     reason,
						Suggestion: suggestion,
					}
				}
			}

			// UA 统计
			uaCount[ua]++

			// 爬虫检测
			if crawlerUARegex.MatchString(ua) {
				stats.CrawlerCount++
			}

			_ = method
		}
	}

	// 计算汇总
	stats.UV = int64(len(ipSet))
	if stats.PV > 0 {
		stats.ErrorRate = float64(stats.ErrorCount) * 100 / float64(stats.PV)
	}
	if latencyCount > 0 {
		stats.SlowRate = float64(stats.SlowRequests) * 100 / float64(latencyCount)
	}

	// Top URI
	stats.TopURIs = topURIs(uriCount, 10)
	if latencyCount > 0 {
		avgLat := totalLatency / latencyCount
		for i := range stats.TopURIs {
			stats.TopURIs[i].AvgLatency = avgLat
		}
	}

	// Top IP
	stats.TopIPs = topIPs(ipSet, 10)
	// Top UA
	stats.TopUAs = topUAs(uaCount, 5)

	// 错误详情（按出现次数降序）
	stats.ErrorDetails = sortErrorDetails(errorURIs)

	// 智能洞察
	stats.Insights = generateInsights(stats)

	stats.AnalyzeMs = time.Since(startTime).Milliseconds()

	a.mu.Lock()
	a.lastStats = stats
	a.mu.Unlock()

	return stats, nil
}

// analyzeError 根据状态码和 URI 分析错误原因并给出建议
func analyzeError(statusCode, uri string) (reason, suggestion string) {
	switch {
	case statusCode == "400":
		return "客户端请求语法错误", "检查前端请求参数是否正确，可能是 URL 编码问题或请求体格式错误"
	case statusCode == "401":
		return "未授权访问", "检查认证 Token 是否过期或缺失，确认 API 鉴权配置正确"
	case statusCode == "403":
		return "服务器拒绝访问", "检查文件权限、Nginx 访问控制规则，或 .htaccess 配置"
	case statusCode == "404":
		if strings.HasSuffix(uri, ".css") || strings.HasSuffix(uri, ".js") || strings.HasSuffix(uri, ".png") || strings.HasSuffix(uri, ".jpg") {
			return "静态资源不存在", "检查静态文件路径是否正确，可能是版本更新后资源路径变更，或 CDN 缓存过期"
		}
		return "页面/接口不存在", "检查路由配置是否正确，或该页面已被删除但仍有旧链接指向"
	case statusCode == "405":
		return "HTTP 方法不允许", "检查 Nginx/API 是否允许该请求方法（GET/POST/PUT/DELETE）"
	case statusCode == "408":
		return "请求超时", "客户端发送请求过慢，可适当增大 Nginx client_body_timeout"
	case statusCode == "429":
		return "请求频率超限", "触发限流策略，检查是否被 WAF 或 Nginx limit_req 限制"
	case statusCode == "500":
		return "服务器内部错误", "检查后端应用日志（PHP/Node/Python），可能是代码异常或数据库连接失败"
	case statusCode == "502":
		return "网关错误，后端服务不可达", "检查后端服务（PHP-FPM/Node/Java）是否运行，确认 Nginx upstream 配置的端口是否正确"
	case statusCode == "503":
		return "服务暂时不可用", "后端服务过载或正在重启，检查服务状态和系统负载"
	case statusCode == "504":
		return "网关超时，后端响应太慢", "检查后端接口性能，或增大 Nginx proxy_read_timeout；如果是数据库慢查询导致，需要优化 SQL"
	default:
		if len(statusCode) > 0 && statusCode[0] == '4' {
			return "客户端错误 (" + statusCode + ")", "检查请求是否符合接口规范"
		}
		if len(statusCode) > 0 && statusCode[0] == '5' {
			return "服务器错误 (" + statusCode + ")", "检查后端服务状态和错误日志"
		}
		return "未知错误 (" + statusCode + ")", "建议检查 Nginx error.log 获取详细信息"
	}
}

// generateInsights 生成智能洞察建议
func generateInsights(stats *NginxLogStats) []string {
	var insights []string

	// 错误率分析
	if stats.PV > 50 && stats.ErrorRate > 5 {
		insights = append(insights, fmt.Sprintf("错误率 %.1f%% 偏高，主要集中在 %d 个 URI", stats.ErrorRate, len(stats.ErrorDetails)))
	}

	// 502/503/504 分析
	for code, count := range stats.StatusBreakdown {
		if code == "502" || code == "503" || code == "504" {
			if count > 5 {
				insights = append(insights, fmt.Sprintf("检测到 %d 次 %s 错误，后端服务可能存在性能问题或已宕机，建议立即检查", count, code))
			}
		}
	}

	// 慢请求分析
	if stats.SlowRate > 10 {
		insights = append(insights, fmt.Sprintf("慢请求率 %.1f%%（>%d 次），建议检查后端接口性能或数据库查询", stats.SlowRate, stats.SlowRequests))
	}

	// 爬虫流量分析
	if stats.PV > 100 {
		crawlerPct := float64(stats.CrawlerCount) * 100 / float64(stats.PV)
		if crawlerPct > 40 {
			insights = append(insights, fmt.Sprintf("爬虫流量占比 %.0f%%，可考虑配置 robots.txt 或 Nginx 限流减少爬虫对服务器的影响", crawlerPct))
		}
	}

	// 404 分析
	if count, ok := stats.StatusBreakdown["404"]; ok && count > 10 {
		insights = append(insights, fmt.Sprintf("有 %d 次 404 错误，建议检查是否有失效链接或配置 301 重定向", count))
	}

	// 单一 IP 高频访问
	if len(stats.TopIPs) > 0 && stats.TopIPs[0].Count > stats.PV/10 && stats.PV > 100 {
		insights = append(insights, fmt.Sprintf("IP %s 贡献了 %d 次请求（占比 %.0f%%），可能是爬虫或恶意刷接口",
			stats.TopIPs[0].IP, stats.TopIPs[0].Count, float64(stats.TopIPs[0].Count)*100/float64(stats.PV)))
	}

	if len(insights) == 0 {
		insights = append(insights, "各项指标正常，未发现异常模式")
	}

	return insights
}

// sortErrorDetails 按出现次数降序排列错误详情
func sortErrorDetails(m map[string]*ErrorDetail) []ErrorDetail {
	result := make([]ErrorDetail, 0, len(m))
	for _, v := range m {
		result = append(result, *v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	// 最多返回 20 条
	if len(result) > 20 {
		result = result[:20]
	}
	return result
}

// GetLastStats 返回最近一次分析结果
func (a *NginxLogAnalyzer) GetLastStats() *NginxLogStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastStats
}

// TailLogFile 读取指定日志文件的最后 N 行（用于前端查看日志内容）
// 安全限制：只允许读取已发现的日志文件路径
func (a *NginxLogAnalyzer) TailLogFile(path string, lines int) ([]string, error) {
	// 安全校验：确保请求的路径在已知日志路径范围内
	knownFiles := a.discoverLogFiles()
	allowed := false
	for _, f := range knownFiles {
		if f == path {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("无权访问该文件，仅允许查看已发现的 Nginx/Apache 日志文件")
	}

	if lines <= 0 || lines > 500 {
		lines = 100
	}
	return readLastNLines(path, lines), nil
}

// extractRequestTime 从日志行末尾提取 $request_time（秒）
func extractRequestTime(line string) float64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	last := parts[len(parts)-1]
	val, err := strconv.ParseFloat(last, 64)
	if err != nil || val < 0 || val > 3600 {
		return 0
	}
	return val
}

// readLastNLinessTailMaxBytes 尾部读取的最大字节预算。
// 原实现从文件头逐行扫到末尾——GB 级 access.log 会造成巨大的磁盘 IO 毛刺，
// 在 1C1G 服务器上会明显拖慢业务。只读末尾窗口即可满足"最近 N 行"的语义。
const readLastNLinesTailMaxBytes = 8 * 1024 * 1024 // 8MB

// readLastNLines 读取文件最后 N 行（尾部有界读取，最多回看 8MB）
func readLastNLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	if stat, err := f.Stat(); err == nil && stat.Size() > readLastNLinesTailMaxBytes {
		if _, err := f.Seek(-readLastNLinesTailMaxBytes, io.SeekEnd); err != nil {
			_, _ = f.Seek(0, io.SeekStart)
		}
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n*2 {
			lines = lines[len(lines)-n:]
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func topURIs(m map[string]*URIStat, limit int) []URIStat {
	result := make([]URIStat, 0, len(m))
	for _, v := range m {
		result = append(result, *v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func topIPs(m map[string]int64, limit int) []IPStat {
	result := make([]IPStat, 0, len(m))
	for ip, count := range m {
		result = append(result, IPStat{IP: ip, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func topUAs(m map[string]int64, limit int) []UAStat {
	result := make([]UAStat, 0, len(m))
	for ua, count := range m {
		if len(ua) > 80 {
			ua = ua[:80] + "..."
		}
		result = append(result, UAStat{UA: ua, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

// PublishAlertIfAbnormal 检测异常并发布告警
func (a *NginxLogAnalyzer) PublishAlertIfAbnormal(bus *eventbus.EventBus, stats *NginxLogStats) {
	if stats == nil {
		return
	}
	// 错误率 > 10%
	if stats.PV > 100 && stats.ErrorRate > 10 {
		bus.PublishAlert(types.AlertWarning, "apm-nginx",
			fmt.Sprintf("Nginx 错误率 %.1f%%（PV=%d）", stats.ErrorRate, stats.PV),
			fmt.Sprintf("日志文件: %s\n4xx/5xx 错误: %d / 总请求: %d\n热门错误 URI: %s",
				stats.LogFile, stats.ErrorCount, stats.PV,
				formatTopErrorURIs(stats.TopURIs)),
			"apm-nginx-001")
	}
	// 慢请求率 > 20%
	if stats.PV > 100 && stats.SlowRate > 20 {
		bus.PublishAlert(types.AlertWarning, "apm-nginx",
			fmt.Sprintf("Nginx 慢请求率 %.1f%%", stats.SlowRate),
			fmt.Sprintf("近 %d 个请求中 %d 个响应超过 1 秒", stats.PV, stats.SlowRequests),
			"apm-nginx-002")
	}
	// 爬虫流量占比 > 50%
	if stats.PV > 100 && float64(stats.CrawlerCount)*100/float64(stats.PV) > 50 {
		bus.PublishAlert(types.AlertInfo, "apm-nginx",
			fmt.Sprintf("爬虫流量占比 %.0f%%", float64(stats.CrawlerCount)*100/float64(stats.PV)),
			fmt.Sprintf("近 %d 个请求中 %d 个来自爬虫\n热门爬虫 UA: %s",
				stats.PV, stats.CrawlerCount, formatTopUAs(stats.TopUAs)),
			"apm-nginx-003")
	}
}

func formatTopErrorURIs(uris []URIStat) string {
	var sb strings.Builder
	count := 0
	for _, u := range uris {
		if u.ErrorCount > 0 {
			fmt.Fprintf(&sb, "%s (错误%d次/共%d次) ", u.URI, u.ErrorCount, u.Count)
			count++
			if count >= 3 {
				break
			}
		}
	}
	if count == 0 {
		return "无"
	}
	return sb.String()
}

func formatTopUAs(uas []UAStat) string {
	var sb strings.Builder
	for i, u := range uas {
		if i >= 3 {
			break
		}
		fmt.Fprintf(&sb, "%s (%d次) ", u.UA, u.Count)
	}
	return sb.String()
}
