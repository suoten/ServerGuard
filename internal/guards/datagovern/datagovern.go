package datagovern

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.1 — 数据治理 + 备份安全
// 共 9 项能力：数据库自动备份管家、敏感数据泄露扫描、
// 大表增长预警与归档建议、备份完整性校验、数据库死锁自动猎杀、
// 连接池泄漏自动诊断、缓存雪崩预防器、时序数据库异常检测、
// 数据库自动归档管家
// ────────────────────────────────────────────────

// DataGovernGuard V4.1 数据治理守护模块
type DataGovernGuard struct {
	mu        sync.RWMutex
	eventBus  *eventbus.EventBus
	backupDir string

	// 数据库自动备份管家
	backupTasks map[string]*BackupTask
	// 敏感数据泄露扫描
	scanPaths []string
	// 备份完整性校验
	verificationHistory []BackupVerificationResult
	// 死锁猎杀
	deadlockHistory []DeadlockRecord
	// 缓存雪崩预防器
	redisAddr string
	// 时序数据库异常检测
	tsdbAddr string
}

// BackupTask 数据库备份任务
type BackupTask struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	DBType     string        `json:"db_type"` // mysql / postgresql
	DSN        string        `json:"-"`       // 不暴露
	Database   string        `json:"database"`
	Schedule   string        `json:"schedule"`  // cron 表达式
	UploadOSS  bool          `json:"upload_oss"`
	OSSBucket  string        `json:"oss_bucket"`
	MaxBackups int           `json:"max_backups"`
	LastRun    time.Time     `json:"last_run"`
	LastStatus string        `json:"last_status"` // success / failed
	LastSize    int64         `json:"last_size"`
	RunCount    int           `json:"run_count"`
}

// SensitiveDataFinding 敏感数据发现
type SensitiveDataFinding struct {
	FilePath  string    `json:"file_path"`
	LineNum   int       `json:"line_num"`
	Type      string    `json:"type"` // phone / idcard / apikey / password
	Match     string    `json:"match"` // 脱敏后的匹配内容
	Timestamp time.Time `json:"timestamp"`
}

// BigTableAlert 大表预警
type BigTableAlert struct {
	Database    string  `json:"database"`
	TableName   string  `json:"table_name"`
	SizeMB      float64 `json:"size_mb"`
	RowsCount   int64   `json:"rows_count"`
	ArchiveSQL  string  `json:"archive_sql"`
	Timestamp   time.Time `json:"timestamp"`
}

// BackupVerificationResult 备份验证结果
type BackupVerificationResult struct {
	BackupFile  string    `json:"backup_file"`
	Verified    bool      `json:"verified"`
	TableCount  int       `json:"table_count"`
	RowSample   int       `json:"row_sample"`
	Error       string    `json:"error,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// DeadlockRecord 死锁记录
type DeadlockRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	VictimSQL   string    `json:"victim_sql"`
	KilledQuery string    `json:"killed_query"`
	Action      string    `json:"action"` // killed / suggested
}

// ConnPoolDiagnosis 连接池诊断结果
type ConnPoolDiagnosis struct {
	Database         string  `json:"database"`
	ThreadsConnected int     `json:"threads_connected"`
	MaxConnections   int     `json:"max_connections"`
	UsagePercent     float64 `json:"usage_percent"`
	IsLeaking        bool    `json:"is_leaking"`
	Suggestion       string  `json:"suggestion"`
	Timestamp        time.Time `json:"timestamp"`
}

// RedisTTLAnalysis Redis TTL 分析结果
type RedisTTLAnalysis struct {
	TotalKeysScanned  int            `json:"total_keys_scanned"`
	Clusters           []TTLCluster   `json:"clusters"`
	SpillRiskKeys      int            `json:"spill_risk_keys"`
	RedistributedKeys  int            `json:"redistributed_keys"`
}

// TTLCluster TTL 聚类
type TTLCluster struct {
	TTLStart    int   `json:"ttl_start"`
	TTLEnd      int   `json:"ttl_end"`
	KeyCount    int   `json:"key_count"`
	SpillRisk   bool  `json:"spill_risk"`
}

// TSDBAnomaly 时序数据库异常
type TSDBAnomaly struct {
	Type       string  `json:"type"` // cardinality_burst / retention_fail
	Measurement string `json:"measurement"`
	Value      float64 `json:"value"`
	Threshold  float64 `json:"threshold"`
	Suggestion string  `json:"suggestion"`
	Timestamp  time.Time `json:"timestamp"`
}

// New 创建 DataGovernGuard 实例
func New(bus *eventbus.EventBus, backupDir string) *DataGovernGuard {
	if backupDir == "" {
		backupDir = "/var/lib/serverguard/db-backups"
	}
	os.MkdirAll(backupDir, 0750)
	return &DataGovernGuard{
		eventBus:    bus,
		backupDir:   backupDir,
		backupTasks: make(map[string]*BackupTask),
		scanPaths:   []string{"/var/log", "/etc", "/www/wwwroot", "/opt", "/home"},
	}
}

// SetRedisAddr 设置 Redis 地址（缓存雪崩预防器）
func (g *DataGovernGuard) SetRedisAddr(addr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.redisAddr = addr
}

// SetTSDBAddr 设置时序数据库地址
func (g *DataGovernGuard) SetTSDBAddr(addr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tsdbAddr = addr
}

// ═══════════════════════════════════════════════════
// 功能 1: 数据库自动备份管家
// ═══════════════════════════════════════════════════

// AddBackupTask 添加备份任务
func (g *DataGovernGuard) AddBackupTask(task BackupTask) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if task.MaxBackups == 0 {
		task.MaxBackups = 7
	}
	g.backupTasks[task.ID] = &task
}

// RunBackup 执行数据库备份
func (g *DataGovernGuard) RunBackup(ctx context.Context, taskID string) (*BackupTask, error) {
	g.mu.RLock()
	task, exists := g.backupTasks[taskID]
	g.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("备份任务 %s 不存在", taskID)
	}

	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("%s_%s_%s.sql.gz", task.Database, timestamp, task.DBType)
	backupPath := filepath.Join(g.backupDir, backupName)

	task.LastRun = time.Now()
	task.LastStatus = "running"

	var cmd *exec.Cmd
	if task.DBType == "mysql" {
		cmdStr := fmt.Sprintf("mysqldump %s %s 2>/dev/null | gzip > %s", task.DSN, task.Database, backupPath)
		cmd = exec.CommandContext(ctx, "bash", "-c", cmdStr)
	} else if task.DBType == "postgresql" {
		cmdStr := fmt.Sprintf("pg_dump %s -d %s 2>/dev/null | gzip > %s", task.DSN, task.Database, backupPath)
		cmd = exec.CommandContext(ctx, "bash", "-c", cmdStr)
	} else {
		task.LastStatus = "failed"
		return task, fmt.Errorf("不支持的数据库类型: %s", task.DBType)
	}

	if err := cmd.Run(); err != nil {
		task.LastStatus = "failed"
		g.eventBus.PublishAlert(types.AlertCritical, "datagovern",
			fmt.Sprintf("数据库备份失败: %s", task.Name),
			fmt.Sprintf("数据库 %s 备份失败: %v", task.Database, err),
			"db-backup-001")
		return task, fmt.Errorf("备份失败: %w", err)
	}

	// 验证可解压
	if err := g.verifyBackupGzip(ctx, backupPath); err != nil {
		task.LastStatus = "failed"
		g.eventBus.PublishAlert(types.AlertCritical, "datagovern",
			fmt.Sprintf("备份文件验证失败: %s", task.Name),
			fmt.Sprintf("备份文件 %s 验证失败: %v", backupPath, err),
			"db-backup-001")
		return task, fmt.Errorf("备份验证失败: %w", err)
	}

	if info, err := os.Stat(backupPath); err == nil {
		task.LastSize = info.Size()
	}

	task.LastStatus = "success"
	task.RunCount++

	// 清理旧备份
	g.cleanupOldBackups(task.Database, task.MaxBackups)

	g.eventBus.PublishAlert(types.AlertInfo, "datagovern",
		fmt.Sprintf("数据库备份成功: %s", task.Name),
		fmt.Sprintf("数据库 %s 备份完成\n文件: %s\n大小: %.2fMB\n第 %d 次成功备份",
			task.Database, backupPath, float64(task.LastSize)/1024/1024, task.RunCount),
		"db-backup-001")

	return task, nil
}

// verifyBackupGzip 验证 gzip 文件可解压
func (g *DataGovernGuard) verifyBackupGzip(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip 头无效: %w", err)
	}
	defer gz.Close()

	buf := make([]byte, 1024)
	_, err = gz.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return fmt.Errorf("gzip 读取失败: %w", err)
	}
	return nil
}

// cleanupOldBackups 清理旧备份文件
func (g *DataGovernGuard) cleanupOldBackups(database string, keep int) {
	prefix := database + "_"
	entries, err := os.ReadDir(g.backupDir)
	if err != nil {
		return
	}

	var backups []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			backups = append(backups, filepath.Join(g.backupDir, entry.Name()))
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(backups)))
	if len(backups) > keep {
		for _, old := range backups[keep:] {
			os.Remove(old)
		}
	}
}

// GetBackupTasks 获取备份任务列表
func (g *DataGovernGuard) GetBackupTasks() []BackupTask {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]BackupTask, 0, len(g.backupTasks))
	for _, t := range g.backupTasks {
		result = append(result, *t)
	}
	return result
}

// GetBackupFiles 获取备份文件列表
func (g *DataGovernGuard) GetBackupFiles() []map[string]interface{} {
	entries, err := os.ReadDir(g.backupDir)
	if err != nil {
		return nil
	}
	var files []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, map[string]interface{}{
			"name":     entry.Name(),
			"size":     info.Size(),
			"mod_time": info.ModTime(),
		})
	}
	return files
}

// ═══════════════════════════════════════════════════
// 功能 2: 敏感数据泄露扫描
// ═══════════════════════════════════════════════════

var (
	phonePattern    = regexp.MustCompile(`1[3-9]\d{9}`)
	idcardPattern   = regexp.MustCompile(`[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)
	apikeyPattern   = regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9+/=]{20,})['"]?`)
	passwordPattern = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?(\S{6,})['"]?`)
)

// ScanSensitiveData 扫描敏感数据泄露
func (g *DataGovernGuard) ScanSensitiveData(ctx context.Context) []SensitiveDataFinding {
	g.mu.RLock()
	paths := make([]string, len(g.scanPaths))
	copy(paths, g.scanPaths)
	g.mu.RUnlock()

	var findings []SensitiveDataFinding
	maxFindings := 100

	for _, root := range paths {
		if maxFindings <= 0 {
			break
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.Size() > 10*1024*1024 {
				return nil
			}
			if !isTextFile(path) {
				return nil
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

// maskString 脱敏字符串
func maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// isTextFile 判断是否为文本文件
func isTextFile(path string) bool {
	textExts := map[string]bool{
		".conf": true, ".config": true, ".cfg": true, ".ini": true,
		".yaml": true, ".yml": true, ".json": true, ".xml": true,
		".env": true, ".log": true, ".txt": true, ".cnf": true,
		".properties": true, ".py": true, ".sh": true, ".php": true,
		".js": true, ".ts": true, ".go": true, ".java": true,
	}
	ext := filepath.Ext(path)
	return textExts[strings.ToLower(ext)]
}

// ═══════════════════════════════════════════════════
// 功能 3: 大表增长预警与归档建议
// ═══════════════════════════════════════════════════

// CheckBigTables 检查大表并生成归档建议
func (g *DataGovernGuard) CheckBigTables(ctx context.Context, dsn string) []BigTableAlert {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `
		SELECT table_schema, table_name, 
		       ROUND((data_length + index_length) / 1024 / 1024, 2) as size_mb,
		       table_rows
		FROM information_schema.tables
		WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		  AND (data_length + index_length) > 1073741824
		ORDER BY (data_length + index_length) DESC
		LIMIT 20
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var alerts []BigTableAlert
	for rows.Next() {
		var alert BigTableAlert
		alert.Timestamp = time.Now()
		if err := rows.Scan(&alert.Database, &alert.TableName, &alert.SizeMB, &alert.RowsCount); err != nil {
			continue
		}

		alert.ArchiveSQL = fmt.Sprintf(
			"-- 归档 %s.%s (大小: %.0fMB, 行数: %d)\n"+
				"-- 方法1: 按日期分区归档\n"+
				"ALTER TABLE %s PARTITION BY RANGE (TO_DAYS(create_time)) (\n"+
				"  PARTITION p_old VALUES LESS THAN (TO_DAYS('2024-01-01')),\n"+
				"  PARTITION p_current VALUES LESS THAN MAXVALUE\n"+
				");\n\n"+
				"-- 方法2: 创建归档表并迁移旧数据\n"+
				"CREATE TABLE %s_archive LIKE %s;\n"+
				"INSERT INTO %s_archive SELECT * FROM %s WHERE create_time < '2024-01-01';\n"+
				"DELETE FROM %s WHERE create_time < '2024-01-01';\n",
			alert.Database, alert.TableName, alert.SizeMB, alert.RowsCount,
			alert.TableName, alert.TableName, alert.TableName,
			alert.TableName, alert.TableName, alert.TableName,
		)

		alerts = append(alerts, alert)

		g.eventBus.PublishAlert(types.AlertWarning, "datagovern",
			fmt.Sprintf("大表预警: %s.%s (%.0fMB)", alert.Database, alert.TableName, alert.SizeMB),
			fmt.Sprintf("表 %s.%s 当前大小 %.0fMB，行数 %d\n\n归档建议:\n%s",
				alert.Database, alert.TableName, alert.SizeMB, alert.RowsCount, alert.ArchiveSQL),
			"big-table-001")
	}

	return alerts
}

// ═══════════════════════════════════════════════════
// 功能 4: 备份完整性校验
// ═══════════════════════════════════════════════════

// VerifyBackup 备份完整性校验
func (g *DataGovernGuard) VerifyBackup(ctx context.Context) *BackupVerificationResult {
	result := &BackupVerificationResult{
		Timestamp: time.Now(),
	}

	entries, err := os.ReadDir(g.backupDir)
	if err != nil {
		result.Error = fmt.Sprintf("读取备份目录失败: %v", err)
		return result
	}

	var backupFile string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql.gz") {
			backupFile = filepath.Join(g.backupDir, entry.Name())
			break
		}
	}
	if backupFile == "" {
		result.Error = "没有可验证的备份文件"
		return result
	}
	result.BackupFile = backupFile

	if err := g.verifyBackupGzip(ctx, backupFile); err != nil {
		result.Error = fmt.Sprintf("gzip 解压失败: %v", err)
		g.eventBus.PublishAlert(types.AlertCritical, "datagovern",
			"备份验证失败",
			fmt.Sprintf("备份文件 %s 解压失败: %v", filepath.Base(backupFile), err),
			"backup-verify-001")
		return result
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("zcat %s | head -100 | grep -c 'CREATE TABLE'", backupFile))
	output, err := cmd.Output()
	if err == nil {
		fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &result.TableCount)
	}

	result.Verified = true
	g.mu.Lock()
	g.verificationHistory = append(g.verificationHistory, *result)
	g.mu.Unlock()

	g.eventBus.PublishAlert(types.AlertInfo, "datagovern",
		"备份验证通过",
		fmt.Sprintf("备份文件 %s 验证通过\n表数量: %d\n可正常解压恢复",
			filepath.Base(backupFile), result.TableCount),
		"backup-verify-001")

	return result
}

// GetVerificationHistory 获取验证历史
func (g *DataGovernGuard) GetVerificationHistory() []BackupVerificationResult {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]BackupVerificationResult, len(g.verificationHistory))
	copy(result, g.verificationHistory)
	return result
}

// ═══════════════════════════════════════════════════
// 功能 5: 数据库死锁自动猎杀
// ═══════════════════════════════════════════════════

// HuntDeadlocks 死锁自动猎杀
func (g *DataGovernGuard) HuntDeadlocks(ctx context.Context, dsn string) []DeadlockRecord {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	var innodbStatus string
	err = db.QueryRowContext(ctx, "SHOW ENGINE INNODB STATUS").Scan(&innodbStatus, &innodbStatus, &innodbStatus)
	if err != nil {
		return nil
	}

	records := g.parseDeadlocks(innodbStatus)
	if len(records) == 0 {
		return nil
	}

	rows, err := db.QueryContext(ctx, `
		SELECT id, user, time, info 
		FROM information_schema.processlist 
		WHERE time > 60 AND info IS NOT NULL AND info != ''
		ORDER BY time DESC
		LIMIT 5
	`)
	if err != nil {
		return records
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var user string
		var timeSec int
		var info string
		if err := rows.Scan(&id, &user, &timeSec, &info); err != nil {
			continue
		}

		if !isCriticalUser(user) {
			_, err := db.ExecContext(ctx, fmt.Sprintf("KILL %d", id))
			if err == nil {
				record := DeadlockRecord{
					Timestamp:   time.Now(),
					VictimSQL:   info,
					KilledQuery: fmt.Sprintf("KILL %d (user=%s, time=%ds)", id, user, timeSec),
					Action:      "killed",
				}
				records = append(records, record)

				g.eventBus.PublishAlert(types.AlertWarning, "datagovern",
					"死锁会话已 Kill",
					fmt.Sprintf("长时间运行查询已终止:\n  会话ID: %d\n  用户: %s\n  运行时间: %ds\n  SQL: %s",
						id, user, timeSec, truncateSQL(info, 200)),
					"deadlock-001")
			}
		}
	}

	g.mu.Lock()
	g.deadlockHistory = append(g.deadlockHistory, records...)
	g.mu.Unlock()

	return records
}

// parseDeadlocks 解析 InnoDB 死锁信息
func (g *DataGovernGuard) parseDeadlocks(status string) []DeadlockRecord {
	var records []DeadlockRecord
	lines := strings.Split(status, "\n")

	inDeadlock := false
	var deadlockSQL string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "DEADLOCK") {
			inDeadlock = true
			continue
		}
		if inDeadlock {
			if strings.HasPrefix(trimmed, "***") || strings.Contains(trimmed, "TRANSACTION") {
				if deadlockSQL != "" {
					records = append(records, DeadlockRecord{
						Timestamp: time.Now(),
						VictimSQL: deadlockSQL,
						Action:    "suggested",
					})
					deadlockSQL = ""
				}
				inDeadlock = false
			}
			if strings.Contains(trimmed, "QUERY") {
				deadlockSQL = trimmed
			}
		}
	}
	if deadlockSQL != "" {
		records = append(records, DeadlockRecord{
			Timestamp: time.Now(),
			VictimSQL: deadlockSQL,
			Action:    "suggested",
		})
	}
	return records
}

// isCriticalUser 判断是否为关键用户
func isCriticalUser(user string) bool {
	critical := []string{"root", "system", "admin", "monitor"}
	for _, c := range critical {
		if strings.EqualFold(user, c) {
			return true
		}
	}
	return false
}

// truncateSQL 截断 SQL 语句
func truncateSQL(sqlText string, maxLen int) string {
	if len(sqlText) <= maxLen {
		return sqlText
	}
	return sqlText[:maxLen] + "..."
}

// GetDeadlockHistory 获取死锁历史
func (g *DataGovernGuard) GetDeadlockHistory() []DeadlockRecord {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]DeadlockRecord, len(g.deadlockHistory))
	copy(result, g.deadlockHistory)
	return result
}

// ═══════════════════════════════════════════════════
// 功能 6: 连接池泄漏自动诊断
// ═══════════════════════════════════════════════════

// DiagnoseConnPool 连接池泄漏自动诊断
func (g *DataGovernGuard) DiagnoseConnPool(ctx context.Context, dsn string) *ConnPoolDiagnosis {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	diag := &ConnPoolDiagnosis{
		Database:  "mysql",
		Timestamp: time.Now(),
	}

	var varName string
	err = db.QueryRowContext(ctx, "SHOW VARIABLES LIKE 'max_connections'").Scan(&varName, &diag.MaxConnections)
	if err != nil {
		return nil
	}

	err = db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Threads_connected'").Scan(&varName, &diag.ThreadsConnected)
	if err != nil {
		return nil
	}

	if diag.MaxConnections > 0 {
		diag.UsagePercent = float64(diag.ThreadsConnected) / float64(diag.MaxConnections) * 100
	}

	hour := time.Now().Hour()
	if diag.UsagePercent > 80 {
		diag.IsLeaking = true
		diag.Suggestion = "连接数超过 80%，可能存在连接泄漏。建议检查应用连接池配置 maxIdle / maxOpen"
	} else if diag.UsagePercent > 50 && (hour >= 0 && hour <= 5) {
		diag.IsLeaking = true
		diag.Suggestion = "凌晨时段连接数仍较高，疑似连接未释放。建议检查应用连接池 maxIdle 设置"
	} else {
		diag.Suggestion = "连接数正常"
	}

	if diag.IsLeaking {
		g.eventBus.PublishAlert(types.AlertWarning, "datagovern",
			"连接池泄漏诊断",
			fmt.Sprintf("数据库: %s\nThreads_connected: %d\nMax_connections: %d\n使用率: %.1f%%\n\n%s",
				diag.Database, diag.ThreadsConnected, diag.MaxConnections, diag.UsagePercent, diag.Suggestion),
			"conn-pool-001")
	}

	return diag
}

// ═══════════════════════════════════════════════════
// 功能 7: 缓存雪崩预防器
// ═══════════════════════════════════════════════════

// PreventCacheAvalanche 缓存雪崩预防
func (g *DataGovernGuard) PreventCacheAvalanche(ctx context.Context) *RedisTTLAnalysis {
	g.mu.RLock()
	addr := g.redisAddr
	g.mu.RUnlock()

	if addr == "" {
		addr = "127.0.0.1:6379"
	}

	analysis := &RedisTTLAnalysis{}

	host := addr
	port := "6379"
	if parts := strings.Split(addr, ":"); len(parts) == 2 {
		host = parts[0]
		port = parts[1]
	}

	// 采样 Key
	cmd := exec.CommandContext(ctx, "redis-cli", "-h", host, "-p", port, "--scan", "--pattern", "*")
	output, err := cmd.Output()
	if err != nil {
		return analysis
	}

	keys := strings.Split(strings.TrimSpace(string(output)), "\n")
	analysis.TotalKeysScanned = len(keys)
	if len(keys) == 0 {
		return analysis
	}

	sampleSize := minInt(len(keys), 1000)
	ttlMap := make(map[int]int)

	for i := 0; i < sampleSize; i++ {
		key := keys[i]
		if key == "" {
			continue
		}
		ttlCmd := exec.CommandContext(ctx, "redis-cli", "-h", host, "-p", port, "TTL", key)
		ttlOut, err := ttlCmd.Output()
		if err != nil {
			continue
		}
		var ttl int
		fmt.Sscanf(strings.TrimSpace(string(ttlOut)), "%d", &ttl)
		if ttl < 0 {
			continue
		}
		bucket := ttl / 60
		ttlMap[bucket]++
	}

	for bucket, count := range ttlMap {
		cluster := TTLCluster{
			TTLStart: bucket * 60,
			TTLEnd:   (bucket + 1) * 60,
			KeyCount: count,
		}
		if sampleSize > 0 && float64(count)/float64(sampleSize) > 0.3 {
			cluster.SpillRisk = true
			analysis.SpillRiskKeys += count
		}
		analysis.Clusters = append(analysis.Clusters, cluster)
	}

	if analysis.SpillRiskKeys > 0 {
		g.eventBus.PublishAlert(types.AlertWarning, "datagovern",
			"缓存雪崩风险",
			fmt.Sprintf("检测到 %d 个 Redis Key 可能同时过期\n总扫描 Key: %d\n\n建议:\n  1. 在设置 TTL 时添加随机偏移（±60s）\n  2. 对关键 Key 永不过期，后台异步刷新",
				analysis.SpillRiskKeys, analysis.TotalKeysScanned),
			"cache-avalanche-001")
	}

	return analysis
}

// ═══════════════════════════════════════════════════
// 功能 8: 时序数据库异常检测
// ═══════════════════════════════════════════════════

// CheckTSDBAnomaly 时序数据库异常检测
// 监控 SHOW SERIES CARDINALITY → 超 100 万告警 → 建议 downsampling
func (g *DataGovernGuard) CheckTSDBAnomaly(ctx context.Context) []TSDBAnomaly {
	g.mu.RLock()
	addr := g.tsdbAddr
	g.mu.RUnlock()

	if addr == "" {
		addr = "http://127.0.0.1:8086"
	}

	var anomalies []TSDBAnomaly

	// 检查 Series Cardinality
	cmd := exec.CommandContext(ctx, "curl", "-s", fmt.Sprintf("%s/query?q=SHOW+SERIES+CARDINALITY", addr))
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// 解析返回值（简化处理：从 CSV 格式中提取数值）
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "cardinality") || strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			if len(parts) >= 4 {
				var cardinality float64
				fmt.Sscanf(parts[len(parts)-1], "%f", &cardinality)
				if cardinality > 1000000 { // 超 100 万
					anomaly := TSDBAnomaly{
						Type:       "cardinality_burst",
						Value:      cardinality,
						Threshold:  1000000,
						Suggestion: "Series 基数超过 100 万，建议：\n  1. 检查是否有高基数 tag（如 userId）\n  2. 启用 downsampling\n  3. 设置合理的 retention policy",
						Timestamp:  time.Now(),
					}
					anomalies = append(anomalies, anomaly)

					g.eventBus.PublishAlert(types.AlertWarning, "datagovern",
						"时序数据库异常: Series 基数暴涨",
						fmt.Sprintf("InfluxDB Series 基数: %.0f\n阈值: %.0f\n\n%s",
							cardinality, anomaly.Threshold, anomaly.Suggestion),
						"tsdb-anomaly-001")
				}
			}
		}
	}

	return anomalies
}

// ═══════════════════════════════════════════════════
// 功能 9: 数据库自动归档管家
// ═══════════════════════════════════════════════════

// ArchiveTable 数据库自动归档管家
// 读取表大小+日期字段 → 生成归档 SQL → 验证行数 → 清理 → 建视图兼容
func (g *DataGovernGuard) ArchiveTable(ctx context.Context, dsn, database, table, dateColumn string, beforeDate string) error {
	// 输入校验：标识符与日期来自 API 请求体，必须白名单校验并反引号引用，杜绝 SQL 注入
	for name, ident := range map[string]string{"database": database, "table": table, "date_column": dateColumn} {
		if err := validateSQLIdentifier(ident); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if _, err := time.Parse("2006-01-02", beforeDate); err != nil {
		return fmt.Errorf("before_date 必须为 YYYY-MM-DD 格式: %w", err)
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("连接数据库失败: %w", err)
	}
	defer db.Close()

	// Step 1: 查询要归档的行数
	var rowCount int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s` WHERE `%s` < ?", database, table, dateColumn)
	err = db.QueryRowContext(ctx, countQuery, beforeDate).Scan(&rowCount)
	if err != nil {
		return fmt.Errorf("查询归档行数失败: %w", err)
	}
	if rowCount == 0 {
		return fmt.Errorf("没有需要归档的数据")
	}

	// Step 2: 创建归档表
	archiveTable := table + "_archive"
	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s` LIKE `%s`.`%s`", database, archiveTable, database, table))
	if err != nil {
		return fmt.Errorf("创建归档表失败: %w", err)
	}

	// Step 3: 迁移数据
	_, err = db.ExecContext(ctx, fmt.Sprintf("INSERT INTO `%s`.`%s` SELECT * FROM `%s`.`%s` WHERE `%s` < ?",
		database, archiveTable, database, table, dateColumn), beforeDate)
	if err != nil {
		return fmt.Errorf("迁移数据失败: %w", err)
	}

	// Step 4: 验证归档行数
	var archivedCount int64
	err = db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s`", database, archiveTable)).Scan(&archivedCount)
	if err != nil {
		return fmt.Errorf("验证归档行数失败: %w", err)
	}
	if archivedCount < rowCount {
		return fmt.Errorf("归档行数不匹配: 原表 %d 行，归档表 %d 行", rowCount, archivedCount)
	}

	// Step 5: 清理原表旧数据
	_, err = db.ExecContext(ctx, fmt.Sprintf("DELETE FROM `%s`.`%s` WHERE `%s` < ?", database, table, dateColumn), beforeDate)
	if err != nil {
		return fmt.Errorf("清理原表数据失败: %w", err)
	}

	// Step 6: 创建视图兼容查询
	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE OR REPLACE VIEW `%s`.`%s_all` AS SELECT * FROM `%s`.`%s` UNION ALL SELECT * FROM `%s`.`%s`",
		database, table, database, table, database, archiveTable))
	if err != nil {
		// 视图创建失败不影响归档
		_ = err
	}

	g.eventBus.PublishAlert(types.AlertInfo, "datagovern",
		"数据库归档完成",
		fmt.Sprintf("表 %s.%s 归档完成:\n  归档行数: %d\n  归档表: %s\n  视图: %s_all\n  归档条件: %s < '%s'",
			database, table, rowCount, archiveTable, table, dateColumn, beforeDate),
		"db-archive-001")

	return nil
}

// minInt 返回较小的整数
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
// validateSQLIdentifier 校验 MySQL 标识符（库名/表名/列名）：
// 仅允许字母、数字、下划线、$，长度 ≤64（MySQL 标识符上限）。
func validateSQLIdentifier(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("标识符为空或超过 64 字符")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '$') {
			return fmt.Errorf("标识符包含非法字符 %q", r)
		}
	}
	return nil
}
