package apm

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// MySQL/PostgreSQL 慢查询自治 (P1)
// 采集慢查询日志 → 自动 EXPLAIN → 识别全表扫描/无索引 → 面板展示建议
// ────────────────────────────────────────────────

// SlowQueryInfo 慢查询信息
type SlowQueryInfo struct {
	Query      string  `json:"query"`        // SQL 语句（截断 500 字符）
	Database   string  `json:"database"`     // 数据库类型 mysql/postgresql
	Count      int     `json:"count"`        // 出现次数
	AvgTime    float64 `json:"avg_time_ms"`  // 平均耗时(毫秒)
	MaxTime    float64 `json:"max_time_ms"`  // 最大耗时(毫秒)
	Suggestion string  `json:"suggestion"`   // 优化建议
	Severity   string  `json:"severity"`     // high/medium/low
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// SlowQueryReport 慢查询报告
type SlowQueryReport struct {
	Timestamp  time.Time       `json:"timestamp"`
	TotalSlow  int             `json:"total_slow"`
	Queries    []SlowQueryInfo `json:"queries"`
	LogFile    string          `json:"log_file"`
	Database   string          `json:"database"`
}

// SlowQueryAnalyzer 慢查询分析器
type SlowQueryAnalyzer struct {
	store *storage.Storage
	mu    sync.Mutex
	last  *SlowQueryReport
}

// 常见慢查询日志路径
var defaultSlowLogPaths = map[string][]string{
	"mysql": {
		"/var/log/mysql/slow.log",
		"/www/server/mysql/slow.log",
		"/var/lib/mysql/slow.log",
		"/usr/local/mysql/data/slow.log",
	},
	"postgresql": {
		"/var/log/postgresql/postgresql-*.log",
		"/var/lib/pgsql/data/log/postgresql-*.log",
	},
}

// 慢查询日志行正则（MySQL slow log format）
// 示例: # Time: 2026-08-12T14:32:01.123456Z
//       # Query_time: 2.543213  Lock_time: 0.000123 Rows_sent: 1 Rows_examined: 1000000
//       SET timestamp=...;
//       SELECT * FROM users WHERE name = 'test';
var slowQueryTimeRegex = regexp.MustCompile(`# Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)`)

// NewSlowQueryAnalyzer 创建慢查询分析器
func NewSlowQueryAnalyzer(store *storage.Storage) *SlowQueryAnalyzer {
	return &SlowQueryAnalyzer{store: store}
}

// Analyze 执行慢查询分析
func (a *SlowQueryAnalyzer) Analyze() (*SlowQueryReport, error) {
	report := &SlowQueryReport{
		Timestamp: time.Now(),
	}

	// 尝试 MySQL 慢查询日志
	if mysqlLog := findFirstExisting(defaultSlowLogPaths["mysql"]); mysqlLog != "" {
		report.Database = "mysql"
		report.LogFile = mysqlLog
		queries := parseMySQLSlowLog(mysqlLog)
		report.Queries = analyzeSlowQueries(queries, "mysql")
		report.TotalSlow = len(report.Queries)
	}

	// 尝试 PostgreSQL 慢查询日志
	if pgLog := findFirstExisting(defaultSlowLogPaths["postgresql"]); pgLog != "" {
		report.Database = "postgresql"
		report.LogFile = pgLog
		queries := parsePGSlowLog(pgLog)
		pgQueries := analyzeSlowQueries(queries, "postgresql")
		report.Queries = append(report.Queries, pgQueries...)
		report.TotalSlow = len(report.Queries)
	}

	if report.TotalSlow == 0 {
		report.Queries = []SlowQueryInfo{}
	}

	a.mu.Lock()
	a.last = report
	a.mu.Unlock()

	return report, nil
}

// GetLastReport 返回最近一次报告
func (a *SlowQueryAnalyzer) GetLastReport() *SlowQueryReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}

// rawSlowQuery 原始慢查询记录
type rawSlowQuery struct {
	Query        string
	QueryTime    float64
	LockTime     float64
	RowsSent     int64
	RowsExamined int64
	Timestamp    time.Time
}

func findFirstExisting(paths []string) string {
	for _, p := range paths {
		// 支持 glob
		matches, _ := filepath.Glob(p)
		if len(matches) > 0 {
			return matches[0]
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// parseMySQLSlowLog 解析 MySQL 慢查询日志
func parseMySQLSlowLog(path string) []rawSlowQuery {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var queries []rawSlowQuery
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var current rawSlowQuery
	var queryLines []string
	inQuery := false

	for scanner.Scan() {
		line := scanner.Text()

		// 匹配 Query_time 行
		if m := slowQueryTimeRegex.FindStringSubmatch(line); m != nil {
			// 保存前一个查询
			if inQuery && len(queryLines) > 0 {
				current.Query = strings.Join(queryLines, " ")
				queries = append(queries, current)
			}
			current = rawSlowQuery{}
			queryLines = nil
			inQuery = true

			fmt.Sscanf(m[1], "%f", &current.QueryTime)
			fmt.Sscanf(m[2], "%f", &current.LockTime)
			fmt.Sscanf(m[3], "%d", &current.RowsSent)
			fmt.Sscanf(m[4], "%d", &current.RowsExamined)
			continue
		}

		if inQuery {
			// 跳过 SET timestamp 行和空行
			if strings.HasPrefix(line, "SET timestamp=") || strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
				if strings.TrimSpace(line) == "" && len(queryLines) > 0 {
					current.Query = strings.Join(queryLines, " ")
					queries = append(queries, current)
					inQuery = false
					queryLines = nil
				}
				continue
			}
			queryLines = append(queryLines, strings.TrimSpace(line))
		}
	}

	// 处理最后一个查询
	if inQuery && len(queryLines) > 0 {
		current.Query = strings.Join(queryLines, " ")
		queries = append(queries, current)
	}

	// 只返回最近的 100 条
	if len(queries) > 100 {
		queries = queries[len(queries)-100:]
	}

	return queries
}

// parsePGSlowLog 解析 PostgreSQL 慢查询日志（简化版）
func parsePGSlowLog(path string) []rawSlowQuery {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var queries []rawSlowQuery
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// PostgreSQL 日志格式: 2026-08-12 14:32:01 UTC [1234] LOG:  duration: 2500.123 ms  statement: SELECT ...
	durationRegex := regexp.MustCompile(`duration:\s*([\d.]+)\s*ms\s*statement:\s*(.+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if m := durationRegex.FindStringSubmatch(line); m != nil {
			var qt float64
			fmt.Sscanf(m[1], "%f", &qt)
			query := strings.TrimSpace(m[2])
			queries = append(queries, rawSlowQuery{
				Query:     query,
				QueryTime: qt,
				Timestamp: time.Now(),
			})
		}
	}

	if len(queries) > 100 {
		queries = queries[len(queries)-100:]
	}

	return queries
}

// analyzeSlowQueries 分析慢查询并生成建议
func analyzeSlowQueries(raw []rawSlowQuery, dbType string) []SlowQueryInfo {
	// 按查询指纹（截断参数后的 SQL 模式）分组
	fingerprints := make(map[string]*SlowQueryInfo)

	for _, r := range raw {
		fp := fingerprintQuery(r.Query)
		avgMs := r.QueryTime * 1000 // 转毫秒

		if existing, ok := fingerprints[fp]; ok {
			existing.Count++
			existing.AvgTime = (existing.AvgTime*float64(existing.Count-1) + avgMs) / float64(existing.Count)
			if avgMs > existing.MaxTime {
				existing.MaxTime = avgMs
			}
			existing.LastSeen = time.Now()
		} else {
			query := r.Query
			if len(query) > 500 {
				query = query[:500] + "..."
			}
			si := &SlowQueryInfo{
				Query:     query,
				Database:  dbType,
				Count:     1,
				AvgTime:   avgMs,
				MaxTime:   avgMs,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
			// 分析并生成建议
			si.Suggestion, si.Severity = generateSuggestion(r, fp)
			fingerprints[fp] = si
		}
	}

	// 转为切片并按平均耗时排序
	result := make([]SlowQueryInfo, 0, len(fingerprints))
	for _, si := range fingerprints {
		result = append(result, *si)
	}
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].AvgTime > result[i].AvgTime {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	// 限制返回 20 条
	if len(result) > 20 {
		result = result[:20]
	}

	return result
}

// fingerprintQuery 生成查询指纹（将具体值替换为 ?）
func fingerprintQuery(query string) string {
	// 替换字符串字面量
	q := regexp.MustCompile(`'[^']*'`).ReplaceAllString(query, "?")
	// 替换数字
	q = regexp.MustCompile(`\b\d+\b`).ReplaceAllString(q, "?")
	// 替换 IN (...)
	q = regexp.MustCompile(`IN\s*\([^)]+\)`).ReplaceAllString(q, "IN (?)")
	// 转小写并截断
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) > 100 {
		q = q[:100]
	}
	return q
}

// generateSuggestion 根据查询特征生成优化建议
func generateSuggestion(r rawSlowQuery, fingerprint string) (suggestion, severity string) {
	query := strings.ToUpper(r.Query)
	var suggestions []string

	// 全表扫描检测：Rows_examined 远大于 Rows_sent
	if r.RowsExamined > 1000 && r.RowsSent > 0 && r.RowsExamined/r.RowsSent > 100 {
		suggestions = append(suggestions, "检测到全表扫描：扫描行数远大于返回行数，建议添加合适索引")
		severity = "high"
	} else if r.RowsExamined > 10000 {
		suggestions = append(suggestions, fmt.Sprintf("扫描行数 %d 过多，建议优化查询条件或添加索引", r.RowsExamined))
		severity = "medium"
	}

	// 检测 SELECT *
	if strings.Contains(query, "SELECT *") {
		suggestions = append(suggestions, "避免 SELECT *，只查询需要的字段")
		if severity == "" {
			severity = "low"
		}
	}

	// 检测无 WHERE 条件
	if (strings.Contains(query, "SELECT") || strings.Contains(query, "DELETE") || strings.Contains(query, "UPDATE")) &&
		!strings.Contains(query, "WHERE") {
		suggestions = append(suggestions, "无 WHERE 条件，将扫描全表，建议添加过滤条件")
		if severity == "" {
			severity = "medium"
		}
	}

	// 检测 LIKE '%xxx' 前缀通配符
	if regexp.MustCompile(`LIKE\s+'%`).MatchString(strings.ToUpper(r.Query)) {
		suggestions = append(suggestions, "LIKE '%xxx' 无法使用索引，考虑全文索引或前缀匹配")
		if severity == "" {
			severity = "low"
		}
	}

	// 检测 ORDER BY 无索引（简化判断）
	if strings.Contains(query, "ORDER BY") && r.RowsExamined > 1000 {
		suggestions = append(suggestions, "ORDER BY 字段可能缺少索引，导致 filesort")
		if severity == "" {
			severity = "medium"
		}
	}

	// 查询时间判断
	if r.QueryTime > 5.0 {
		suggestions = append(suggestions, fmt.Sprintf("查询耗时 %.2f 秒，严重影响性能", r.QueryTime))
		severity = "high"
	} else if r.QueryTime > 1.0 && severity == "" {
		severity = "medium"
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "查询较慢，建议检查表结构和索引")
		severity = "low"
	}

	return strings.Join(suggestions, "；"), severity
}

// PublishAlertIfAbnormal 发布慢查询告警
func (a *SlowQueryAnalyzer) PublishAlertIfAbnormal(bus *eventbus.EventBus, report *SlowQueryReport) {
	if report == nil || len(report.Queries) == 0 {
		return
	}
	highCount := 0
	for _, q := range report.Queries {
		if q.Severity == "high" {
			highCount++
		}
	}
	if highCount > 0 {
		var sb strings.Builder
		count := 0
		for _, q := range report.Queries {
			if q.Severity == "high" {
				query := q.Query
				if len(query) > 100 {
					query = query[:100] + "..."
				}
				fmt.Fprintf(&sb, "  · [%s] %s\n    耗时: %.0fms, 建议: %s\n",
					q.Severity, query, q.AvgTime, q.Suggestion)
				count++
				if count >= 3 {
					break
				}
			}
		}
		bus.PublishAlert(types.AlertWarning, "apm-slowquery",
			fmt.Sprintf("发现 %d 条高危慢查询", highCount),
			fmt.Sprintf("数据库: %s\n%s", report.Database, sb.String()),
			"apm-slowquery-001")
	}
}
