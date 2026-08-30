package datagovern

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// dgDiscoveryCache caches auto-discovery results
var dgDiscoveryCache struct {
	sync.RWMutex
	result   *DSAutoDiscoveryResult
	lastScan time.Time
}

// dgHeavyCache caches heavy auto-check results (big tables, cache analysis, sensitive data)
// so that AutoCheck can include them without running the heavy scan every time
var dgHeavyCache struct {
	sync.RWMutex
	result   *DSAutoDiscoveryResult
	lastScan time.Time
}

// DSAutoDiscoveryResult is the data governance auto-discovery result
type DSAutoDiscoveryResult struct {
	MySQLInstances    []DiscoveredMySQL         `json:"mysql_instances"`
	RedisInstances    []DiscoveredRedis         `json:"redis_instances"`
	BackupFiles       []map[string]interface{}  `json:"backup_files"`
	BackupTasks       []BackupTask              `json:"backup_tasks"`
	SensitiveFindings []SensitiveDataFinding    `json:"sensitive_findings"`
	BigTables         []BigTableAlert           `json:"big_tables"`
	ConnPoolStatus    *ConnPoolDiagnosis        `json:"conn_pool_status"`
	DeadlockRecords   []DeadlockRecord          `json:"deadlock_records"`
	CacheAnalysis     *RedisTTLAnalysis         `json:"cache_analysis"`
	DiscoveryTime     time.Time                 `json:"discovery_time"`
}

// DiscoveredMySQL represents a discovered MySQL instance
type DiscoveredMySQL struct {
	Port     int    `json:"port"`
	Socket   string `json:"socket"`
	Version  string `json:"version"`
	DSN      string `json:"-"`
	Database string `json:"database"`
	Source   string `json:"source"`
}

// DiscoveredRedis represents a discovered Redis instance
type DiscoveredRedis struct {
	Addr    string `json:"addr"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// AutoDiscover discovers database and cache services on the server.
// Uses cache: first call scans, subsequent calls within 1 hour return cached result.
func (g *DataGovernGuard) AutoDiscover(ctx context.Context) *DSAutoDiscoveryResult {
	dgDiscoveryCache.RLock()
	if dgDiscoveryCache.result != nil && time.Since(dgDiscoveryCache.lastScan) < time.Hour {
		r := dgDiscoveryCache.result
		dgDiscoveryCache.RUnlock()
		return r
	}
	dgDiscoveryCache.RUnlock()

	result := &DSAutoDiscoveryResult{
		DiscoveryTime: time.Now(),
	}

	if isWindowsDG() {
		dgDiscoveryCache.Lock()
		dgDiscoveryCache.result = result
		dgDiscoveryCache.lastScan = time.Now()
		dgDiscoveryCache.Unlock()
		return result
	}

	// 1. Discover MySQL (multi-strategy: ps + ss ports + Docker + BaoTa + config)
	mysqls := g.discoverMySQL(ctx)
	result.MySQLInstances = mysqls

	// 2. Discover Redis (multi-strategy: ps + ss ports + Docker + BaoTa)
	redisInsts := g.discoverRedis(ctx)
	result.RedisInstances = redisInsts

	// 3. Read existing backup files
	result.BackupFiles = g.GetBackupFiles()

	// Auto-register MySQL backup tasks
	g.mu.Lock()
	for _, mysql := range mysqls {
		taskID := fmt.Sprintf("auto-mysql-%d", mysql.Port)
		if _, exists := g.backupTasks[taskID]; !exists && mysql.DSN != "" {
			g.backupTasks[taskID] = &BackupTask{
				ID:         taskID,
				Name:       fmt.Sprintf("MySQL:%d auto-backup", mysql.Port),
				DBType:     "mysql",
				DSN:        mysql.DSN,
				Database:   mysql.Database,
				Schedule:   "0 2 * * *",
				MaxBackups: 7,
			}
		}
	}
	if len(redisInsts) > 0 && g.redisAddr == "" {
		g.redisAddr = redisInsts[0].Addr
	}
	tasks := make([]BackupTask, 0, len(g.backupTasks))
	for _, t := range g.backupTasks {
		tasks = append(tasks, *t)
	}
	g.mu.Unlock()
	result.BackupTasks = tasks

	// Update cache
	dgDiscoveryCache.Lock()
	dgDiscoveryCache.result = result
	dgDiscoveryCache.lastScan = time.Now()
	dgDiscoveryCache.Unlock()

	return result
}

// AutoCheck performs lightweight auto-inspection (called every 10 min by slowTicker)
func (g *DataGovernGuard) AutoCheck(ctx context.Context) *DSAutoDiscoveryResult {
	result := &DSAutoDiscoveryResult{
		DiscoveryTime: time.Now(),
	}

	if isWindowsDG() {
		return result
	}

	cached := g.getCachedDiscovery()
	if cached != nil {
		result.MySQLInstances = cached.MySQLInstances
		result.RedisInstances = cached.RedisInstances
		result.BackupFiles = cached.BackupFiles
		result.BackupTasks = cached.BackupTasks
	} else {
		discovered := g.AutoDiscover(ctx)
		result.MySQLInstances = discovered.MySQLInstances
		result.RedisInstances = discovered.RedisInstances
		result.BackupFiles = discovered.BackupFiles
		result.BackupTasks = discovered.BackupTasks
	}

	for _, mysql := range result.MySQLInstances {
		if mysql.DSN == "" {
			continue
		}
		diag := g.DiagnoseConnPool(ctx, mysql.DSN)
		if diag != nil {
			result.ConnPoolStatus = diag
		}
		records := g.HuntDeadlocks(ctx, mysql.DSN)
		result.DeadlockRecords = append(result.DeadlockRecords, records...)
	}

	// Merge heavy check results from cache (big tables, cache analysis, sensitive data)
	dgHeavyCache.RLock()
	if dgHeavyCache.result != nil && time.Since(dgHeavyCache.lastScan) < 2*time.Hour {
		result.BigTables = dgHeavyCache.result.BigTables
		result.CacheAnalysis = dgHeavyCache.result.CacheAnalysis
		result.SensitiveFindings = dgHeavyCache.result.SensitiveFindings
	}
	dgHeavyCache.RUnlock()

	return result
}

// AutoCheckHeavy performs heavy auto-inspection (called hourly by slowTicker)
func (g *DataGovernGuard) AutoCheckHeavy(ctx context.Context) *DSAutoDiscoveryResult {
	result := &DSAutoDiscoveryResult{
		DiscoveryTime: time.Now(),
	}

	if isWindowsDG() {
		return result
	}

	cached := g.getCachedDiscovery()
	if cached == nil {
		cached = g.AutoDiscover(ctx)
	}
	result.MySQLInstances = cached.MySQLInstances
	result.RedisInstances = cached.RedisInstances

	for _, mysql := range result.MySQLInstances {
		if mysql.DSN == "" {
			continue
		}
		alerts := g.CheckBigTables(ctx, mysql.DSN)
		result.BigTables = append(result.BigTables, alerts...)
	}

	if len(result.RedisInstances) > 0 {
		g.mu.Lock()
		g.redisAddr = result.RedisInstances[0].Addr
		g.mu.Unlock()
		analysis := g.PreventCacheAvalanche(ctx)
		result.CacheAnalysis = analysis
	}

	result.SensitiveFindings = g.scanSensitiveDataLimited(ctx, 500)

	// Cache heavy results so AutoCheck can include them
	dgHeavyCache.Lock()
	dgHeavyCache.result = result
	dgHeavyCache.lastScan = time.Now()
	dgHeavyCache.Unlock()

	return result
}

// AutoBackupCheck checks and runs backup tasks daily at 2-3 AM
func (g *DataGovernGuard) AutoBackupCheck(ctx context.Context) {
	g.mu.RLock()
	tasks := make(map[string]*BackupTask, len(g.backupTasks))
	for k, v := range g.backupTasks {
		tasks[k] = v
	}
	g.mu.RUnlock()

	for _, task := range tasks {
		if task.DSN == "" {
			continue
		}
		if task.LastRun.IsZero() || time.Since(task.LastRun) > 24*time.Hour {
			go func(t *BackupTask) {
				backupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				_, _ = g.RunBackup(backupCtx, t.ID)
			}(task)
		}
	}
}

func (g *DataGovernGuard) getCachedDiscovery() *DSAutoDiscoveryResult {
	dgDiscoveryCache.RLock()
	defer dgDiscoveryCache.RUnlock()
	return dgDiscoveryCache.result
}

// GetDSNByPort returns the DSN for a discovered MySQL instance by port number.
// This allows API endpoints to accept port instead of exposing DSN to the frontend.
func (g *DataGovernGuard) GetDSNByPort(port int) string {
	cached := g.getCachedDiscovery()
	if cached == nil {
		return ""
	}
	for _, m := range cached.MySQLInstances {
		if m.Port == port {
			return m.DSN
		}
	}
	return ""
}

// scanSensitiveDataLimited scans for sensitive data with a file count limit
func (g *DataGovernGuard) scanSensitiveDataLimited(ctx context.Context, maxFiles int) []SensitiveDataFinding {
	g.mu.RLock()
	paths := make([]string, len(g.scanPaths))
	copy(paths, g.scanPaths)
	g.mu.RUnlock()

	var findings []SensitiveDataFinding
	maxFindings := 100
	filesScanned := 0

	for _, root := range paths {
		if ctx.Err() != nil || filesScanned >= maxFiles || maxFindings <= 0 {
			break
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipDir
			}
			if info.Size() > 10*1024*1024 {
				return nil
			}
			if !isTextFile(path) {
				return nil
			}
			filesScanned++
			if filesScanned > maxFiles {
				return filepath.SkipDir
			}

			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()

				if matches := phonePattern.FindStringSubmatch(line); len(matches) > 0 {
					findings = append(findings, SensitiveDataFinding{
						FilePath: path, LineNum: lineNum, Type: "phone",
						Match: maskString(matches[0]), Timestamp: time.Now(),
					})
					maxFindings--
					return nil
				}
				if matches := idcardPattern.FindStringSubmatch(line); len(matches) > 0 {
					findings = append(findings, SensitiveDataFinding{
						FilePath: path, LineNum: lineNum, Type: "idcard",
						Match: maskString(matches[0]), Timestamp: time.Now(),
					})
					maxFindings--
					return nil
				}
				if matches := apikeyPattern.FindStringSubmatch(line); len(matches) > 0 {
					findings = append(findings, SensitiveDataFinding{
						FilePath: path, LineNum: lineNum, Type: "apikey",
						Match: maskString(matches[2]), Timestamp: time.Now(),
					})
					maxFindings--
					return nil
				}
				if matches := passwordPattern.FindStringSubmatch(line); len(matches) > 0 {
					findings = append(findings, SensitiveDataFinding{
						FilePath: path, LineNum: lineNum, Type: "password",
						Match: maskString(matches[2]), Timestamp: time.Now(),
					})
					maxFindings--
					return nil
				}
			}
			return nil
		})
	}

	if len(findings) > 0 {
		var detail strings.Builder
		for i, f := range findings {
			if i >= 10 {
				detail.WriteString(fmt.Sprintf("\n... 等共 %d 处泄露", len(findings)))
				break
			}
			detail.WriteString(fmt.Sprintf("\n  %s:%d [%s] %s", f.FilePath, f.LineNum, f.Type, f.Match))
		}

		g.eventBus.PublishAlert(types.AlertCritical, "datagovern",
			"敏感数据泄露扫描",
			fmt.Sprintf("检测到 %d 处敏感数据泄露:\n%s\n\n建议:\n  1. 立即从配置/日志中清除敏感信息\n  2. 使用环境变量或密钥管理服务",
				len(findings), detail.String()),
			"sensitive-data-001")
	}

	return findings
}

// ────────────────────────────────────────────────
// MySQL auto-discovery — multi-strategy
// ────────────────────────────────────────────────

func (g *DataGovernGuard) discoverMySQL(ctx context.Context) []DiscoveredMySQL {
	if isWindowsDG() {
		return nil
	}

	found := make(map[int]DiscoveredMySQL)

	// Strategy 1: ps scan
	g.discoverMySQLByPS(ctx, found)

	// Strategy 2: ss/netstat port scan
	g.discoverMySQLByPorts(ctx, found)

	// Strategy 3: Docker containers
	g.discoverMySQLByDocker(ctx, found)

	// Strategy 4: BaoTa panel config
	g.discoverMySQLByBaoTa(ctx, found)

	// Strategy 5: MySQL config files
	g.discoverMySQLByConfig(ctx, found)

	var instances []DiscoveredMySQL
	for _, m := range found {
		instances = append(instances, m)
	}
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].Port < instances[j].Port
	})

	return instances
}

func (g *DataGovernGuard) discoverMySQLByPS(ctx context.Context, found map[int]DiscoveredMySQL) {
	output := g.runCommand(ctx, "ps", "-eo", "pid,args")
	if len(output) == 0 {
		output = g.runCommand(ctx, "bash", "-c", "for p in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < $p 2>/dev/null && echo; done | grep -i mysqld | grep -v grep")
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(strings.ToLower(line), "mysqld") {
			continue
		}

		port := 3306
		if idx := strings.Index(line, "--port="); idx >= 0 {
			portStr := line[idx+7:]
			if spaceIdx := strings.Index(portStr, " "); spaceIdx > 0 {
				portStr = portStr[:spaceIdx]
			}
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}

		socket := ""
		if idx := strings.Index(line, "--socket="); idx >= 0 {
			socketStr := line[idx+9:]
			if spaceIdx := strings.Index(socketStr, " "); spaceIdx > 0 {
				socketStr = socketStr[:spaceIdx]
			}
			socket = socketStr
		}

		if _, exists := found[port]; !exists {
			dsn := g.guessMySQLDSN(port, socket)
			version := g.getMySQLVersion(ctx, dsn)
			found[port] = DiscoveredMySQL{
				Port: port, Socket: socket, Version: version,
				DSN: dsn, Source: "ps",
			}
		}
	}
}

func (g *DataGovernGuard) discoverMySQLByPorts(ctx context.Context, found map[int]DiscoveredMySQL) {
	output := g.runCommand(ctx, "bash", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if len(output) == 0 {
		return
	}

	mysqlLineRegex := regexp.MustCompile(`:(\d+)\s+.*(?:mysql|maria)`)
	for _, line := range strings.Split(output, "\n") {
		line = strings.ToLower(line)
		if !strings.Contains(line, "mysql") && !strings.Contains(line, "maria") {
			continue
		}
		matches := mysqlLineRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		port, err := strconv.Atoi(matches[1])
		if err != nil || port <= 0 {
			continue
		}
		if _, exists := found[port]; !exists {
			dsn := g.guessMySQLDSN(port, "")
			version := g.getMySQLVersion(ctx, dsn)
			if version != "" {
				found[port] = DiscoveredMySQL{
					Port: port, Version: version,
					DSN: dsn, Source: "port",
				}
			}
		}
	}

	// Fallback: scan common MySQL port range
	if len(found) == 0 {
		commonPorts := []int{3306, 3307, 3308, 3309, 3310, 3311, 3312, 3313, 3314, 3315, 3316, 3317, 3318, 3319, 3320, 33060, 63306, 13306}
		for _, port := range commonPorts {
			if isPortListening(port) {
				if _, exists := found[port]; !exists {
					dsn := g.guessMySQLDSN(port, "")
					version := g.getMySQLVersion(ctx, dsn)
					found[port] = DiscoveredMySQL{
						Port: port, Version: version,
						DSN: dsn, Source: "port",
					}
				}
			}
		}
	}
}

func (g *DataGovernGuard) discoverMySQLByDocker(ctx context.Context, found map[int]DiscoveredMySQL) {
	output := g.runCommand(ctx, "bash", "-c", "docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Ports}}' 2>/dev/null")
	if len(output) == 0 {
		return
	}

	portRegex := regexp.MustCompile(`0\.0\.0\.0:(\d+)`)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, "mysql") && !strings.Contains(lowerLine, "maria") && !strings.Contains(lowerLine, "percona") {
			continue
		}

		matches := portRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			port, err := strconv.Atoi(m[1])
			if err != nil || port <= 0 {
				continue
			}
			if _, exists := found[port]; !exists {
				dsn := g.guessMySQLDSN(port, "")
				version := g.getMySQLVersion(ctx, dsn)
				found[port] = DiscoveredMySQL{
					Port: port, Version: version,
					DSN: dsn, Source: "docker",
				}
			}
		}
	}
}

func (g *DataGovernGuard) discoverMySQLByBaoTa(ctx context.Context, found map[int]DiscoveredMySQL) {
	configPaths := []string{
		"/www/server/mysql/etc/my.cnf",
		"/www/server/mysql/my.cnf",
		"/etc/my.cnf",
		"/etc/mysql/my.cnf",
		"/etc/mysql/mariadb.conf.d/50-server.cnf",
	}

	for _, configPath := range configPaths {
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		content := string(data)

		port := 3306
		if match := regexp.MustCompile(`(?m)^\s*port\s*=\s*(\d+)`).FindStringSubmatch(content); len(match) >= 2 {
			if p, err := strconv.Atoi(match[1]); err == nil {
				port = p
			}
		}

		socket := ""
		if match := regexp.MustCompile(`(?m)^\s*socket\s*=\s*(/\S+)`).FindStringSubmatch(content); len(match) >= 2 {
			socket = match[1]
		}

		if _, exists := found[port]; !exists {
			dsn := g.guessMySQLDSN(port, socket)
			version := g.getMySQLVersion(ctx, dsn)
			if version != "" || strings.Contains(configPath, "www/server") {
				found[port] = DiscoveredMySQL{
					Port: port, Socket: socket, Version: version,
					DSN: dsn, Source: "config",
				}
			}
		}
	}

	// Check BaoTa multi-instance MySQL
	btMySQLDir := "/www/server/mysql"
	if entries, err := os.ReadDir(btMySQLDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if match := regexp.MustCompile(`(\d+)$`).FindStringSubmatch(name); len(match) >= 2 {
				port, err := strconv.Atoi(match[1])
				if err != nil || port <= 0 {
					continue
				}
				if _, exists := found[port]; !exists {
					dsn := g.guessMySQLDSN(port, "")
					version := g.getMySQLVersion(ctx, dsn)
					found[port] = DiscoveredMySQL{
						Port: port, Version: version,
						DSN: dsn, Source: "baota",
					}
				}
			}
		}
	}
}

func (g *DataGovernGuard) discoverMySQLByConfig(ctx context.Context, found map[int]DiscoveredMySQL) {
	configDirs := []string{"/etc/mysql/", "/etc/mysql/conf.d/", "/etc/mysql/mariadb.conf.d/"}
	for _, dir := range configDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			content := string(data)
			if match := regexp.MustCompile(`(?m)^\s*port\s*=\s*(\d+)`).FindStringSubmatch(content); len(match) >= 2 {
				port, err := strconv.Atoi(match[1])
				if err != nil || port <= 0 {
					return nil
				}
				if _, exists := found[port]; !exists {
					socket := ""
					if sm := regexp.MustCompile(`(?m)^\s*socket\s*=\s*(/\S+)`).FindStringSubmatch(content); len(sm) >= 2 {
						socket = sm[1]
					}
					dsn := g.guessMySQLDSN(port, socket)
					version := g.getMySQLVersion(ctx, dsn)
					if version != "" {
						found[port] = DiscoveredMySQL{
							Port: port, Socket: socket, Version: version,
							DSN: dsn, Source: "config",
						}
					}
				}
			}
			return nil
		})
	}
}

// ────────────────────────────────────────────────
// Redis auto-discovery — multi-strategy
// ────────────────────────────────────────────────

func (g *DataGovernGuard) discoverRedis(ctx context.Context) []DiscoveredRedis {
	if isWindowsDG() {
		return nil
	}

	found := make(map[string]DiscoveredRedis)

	g.discoverRedisByPS(ctx, found)
	g.discoverRedisByPorts(ctx, found)
	g.discoverRedisByDocker(ctx, found)
	g.discoverRedisByBaoTa(ctx, found)

	var instances []DiscoveredRedis
	for _, r := range found {
		instances = append(instances, r)
	}
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].Addr < instances[j].Addr
	})

	return instances
}

func (g *DataGovernGuard) discoverRedisByPS(ctx context.Context, found map[string]DiscoveredRedis) {
	output := g.runCommand(ctx, "ps", "-eo", "pid,args")
	if len(output) == 0 {
		output = g.runCommand(ctx, "bash", "-c", "for p in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < $p 2>/dev/null && echo; done | grep -i redis-server | grep -v grep")
	}

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, "redis-server") {
			continue
		}

		port := 6379
		if idx := strings.Index(line, "--port "); idx >= 0 {
			portStr := line[idx+7:]
			if spaceIdx := strings.Index(portStr, " "); spaceIdx > 0 {
				portStr = portStr[:spaceIdx]
			}
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}

		bind := "127.0.0.1"
		if idx := strings.Index(line, "--bind "); idx >= 0 {
			bindStr := line[idx+7:]
			if spaceIdx := strings.Index(bindStr, " "); spaceIdx > 0 {
				bindStr = bindStr[:spaceIdx]
			}
			bind = bindStr
		}

		addr := fmt.Sprintf("%s:%d", bind, port)
		if _, exists := found[addr]; !exists {
			version := g.getRedisVersion(ctx, addr)
			found[addr] = DiscoveredRedis{
				Addr: addr, Version: version, Source: "ps",
			}
		}
	}
}

func (g *DataGovernGuard) discoverRedisByPorts(ctx context.Context, found map[string]DiscoveredRedis) {
	output := g.runCommand(ctx, "bash", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if len(output) == 0 {
		return
	}

	redisLineRegex := regexp.MustCompile(`:(\d+)\s+.*(?:redis)`)
	for _, line := range strings.Split(output, "\n") {
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, "redis") {
			continue
		}
		matches := redisLineRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		port, err := strconv.Atoi(matches[1])
		if err != nil || port <= 0 {
			continue
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if _, exists := found[addr]; !exists {
			version := g.getRedisVersion(ctx, addr)
			found[addr] = DiscoveredRedis{
				Addr: addr, Version: version, Source: "port",
			}
		}
	}

	if len(found) == 0 {
		commonPorts := []int{6379, 6380, 6381, 6382, 6383, 6384, 6385, 16379, 26379, 26380}
		for _, port := range commonPorts {
			if isPortListening(port) {
				addr := fmt.Sprintf("127.0.0.1:%d", port)
				if _, exists := found[addr]; !exists {
					version := g.getRedisVersion(ctx, addr)
					found[addr] = DiscoveredRedis{
						Addr: addr, Version: version, Source: "port",
					}
				}
			}
		}
	}
}

func (g *DataGovernGuard) discoverRedisByDocker(ctx context.Context, found map[string]DiscoveredRedis) {
	output := g.runCommand(ctx, "bash", "-c", "docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Ports}}' 2>/dev/null")
	if len(output) == 0 {
		return
	}

	portRegex := regexp.MustCompile(`0\.0\.0\.0:(\d+)`)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, "redis") {
			continue
		}

		matches := portRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			port, err := strconv.Atoi(m[1])
			if err != nil || port <= 0 {
				continue
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			if _, exists := found[addr]; !exists {
				version := g.getRedisVersion(ctx, addr)
				found[addr] = DiscoveredRedis{
					Addr: addr, Version: version, Source: "docker",
				}
			}
		}
	}
}

func (g *DataGovernGuard) discoverRedisByBaoTa(ctx context.Context, found map[string]DiscoveredRedis) {
	configPaths := []string{
		"/www/server/redis/redis.conf",
		"/etc/redis/redis.conf",
		"/etc/redis.conf",
	}

	for _, configPath := range configPaths {
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		content := string(data)

		port := 6379
		if match := regexp.MustCompile(`(?m)^\s*port\s+(\d+)`).FindStringSubmatch(content); len(match) >= 2 {
			if p, err := strconv.Atoi(match[1]); err == nil {
				port = p
			}
		}

		bind := "127.0.0.1"
		if match := regexp.MustCompile(`(?m)^\s*bind\s+([\d.]+)`).FindStringSubmatch(content); len(match) >= 2 {
			bind = match[1]
		}

		addr := fmt.Sprintf("%s:%d", bind, port)
		if _, exists := found[addr]; !exists {
			version := g.getRedisVersion(ctx, addr)
			found[addr] = DiscoveredRedis{
				Addr: addr, Version: version, Source: "baota",
			}
		}
	}
}

// ────────────────────────────────────────────────
// DSN guessing — multi-source credential reading
// ────────────────────────────────────────────────

func (g *DataGovernGuard) guessMySQLDSN(port int, socket string) string {
	// Source 1: /root/.my.cnf
	if dsn := g.readMyCNF("/root/.my.cnf", port, socket); dsn != "" {
		return dsn
	}

	// Source 2: BaoTa MySQL root password file
	if data, err := os.ReadFile("/www/server/mysql/root_password.txt"); err == nil {
		password := strings.TrimSpace(string(data))
		if password != "" {
			if socket != "" {
				return fmt.Sprintf("root:%s@unix(%s)/", password, socket)
			}
			return fmt.Sprintf("root:%s@tcp(127.0.0.1:%d)/", password, port)
		}
	}

	// Source 3: Common socket files
	socketPath := socket
	if socketPath == "" {
		commonSockets := []string{
			"/var/lib/mysql/mysql.sock",
			"/tmp/mysql.sock",
			"/var/run/mysqld/mysqld.sock",
			"/www/server/mysql/mysql.sock",
			"/www/server/data/mysql.sock",
		}
		for _, s := range commonSockets {
			if _, err := os.Stat(s); err == nil {
				socketPath = s
				break
			}
		}
	}

	if socketPath != "" {
		return fmt.Sprintf("root:@unix(%s)/", socketPath)
	}
	return fmt.Sprintf("root:@tcp(127.0.0.1:%d)/", port)
}

func (g *DataGovernGuard) readMyCNF(path string, port int, socket string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	content := string(data)

	user := ""
	password := ""

	lines := strings.Split(content, "\n")
	inClientSection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inClientSection = strings.HasPrefix(line, "[client]") || strings.HasPrefix(line, "[mysql]") || strings.HasPrefix(line, "[mysqldump]")
		} else if inClientSection {
			if strings.HasPrefix(line, "user=") || strings.HasPrefix(line, "user =") {
				user = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "user="), "user ="))
			}
			if strings.HasPrefix(line, "password=") || strings.HasPrefix(line, "password =") {
				password = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "password="), "password ="))
			}
		}
	}

	if user == "" {
		user = "root"
	}

	if socket != "" {
		return fmt.Sprintf("%s:%s@unix(%s)/", user, password, socket)
	}
	return fmt.Sprintf("%s:%s@tcp(127.0.0.1:%d)/", user, password, port)
}

// ────────────────────────────────────────────────
// Version detection
// ────────────────────────────────────────────────

func (g *DataGovernGuard) getMySQLVersion(ctx context.Context, dsn string) string {
	output := g.runCommand(ctx, "bash", "-c", "mysql --version 2>/dev/null || echo ''")
	return strings.TrimSpace(output)
}

func (g *DataGovernGuard) getRedisVersion(ctx context.Context, addr string) string {
	host := "127.0.0.1"
	port := "6379"
	if parts := strings.Split(addr, ":"); len(parts) == 2 {
		host = parts[0]
		port = parts[1]
	}
	cmd := exec.CommandContext(ctx, "redis-cli", "-h", host, "-p", port, "INFO", "server")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
		}
	}
	return ""
}

// ────────────────────────────────────────────────
// Helper functions
// ────────────────────────────────────────────────

func isWindowsDG() bool {
	return filepath.Separator == '\\'
}

func isPortListening(port int) bool {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("ss -tlnp 2>/dev/null | grep ':%d ' || netstat -tlnp 2>/dev/null | grep ':%d '", port, port))
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(output))) > 0
}

func (g *DataGovernGuard) runCommand(ctx context.Context, name string, args ...string) string {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(output)
}
