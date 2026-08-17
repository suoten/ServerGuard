package log

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// LogGuard implements Module D: Log Guard
// Covers: global log scanning, single file size limits, directory quotas,
// write rate monitoring, auto compression, emergency cleanup, config fix suggestions
type LogGuard struct {
	mu              sync.RWMutex
	eventBus        *eventbus.EventBus
	storage         *storage.Storage
	safety          *safety.SafetyManager // 安全管理器引用，用于宝塔安全模式判断
	maxFileSize     int64         // Default: 500MB
	maxDirSize     int64         // Default: 10GB
	maxWriteRate   float64       // MB/min
	compressionFmt string
	retentionDays  int
	emergencyThreshold float64 // disk usage %
	scanPaths      []string
	excludePaths   []string
	logFiles       map[string]*LogFileInfo
}

// LogFileInfo tracks a log file's state.
type LogFileInfo struct {
	Path          string
	Size          int64
	LastModified  time.Time
	WriteRate     float64
	Managed       bool
	App           string
	LastRotated   time.Time
	PrevSize      int64
	PrevCheckTime time.Time
}

// New creates a new LogGuard.
func New(bus *eventbus.EventBus, store *storage.Storage) *LogGuard {
	return &LogGuard{
		eventBus:           bus,
		storage:            store,
		maxFileSize:        500 * 1024 * 1024, // 500MB
		maxDirSize:         10 * 1024 * 1024 * 1024, // 10GB
		maxWriteRate:       10,  // 10 MB/min
		compressionFmt:     "gzip",
		retentionDays:      30,
		emergencyThreshold: 95.0,
		scanPaths:          defaultLogPaths(),
		excludePaths: []string{
			// BaoTa 全量排除
			"/www/",
			"/var/log/bt-",
			"/var/log/panel",
			// Web server logs (have open file handles)
			"/var/log/nginx/",
			"/var/log/apache2/",
			"/var/log/httpd/",
			// Database logs
			"/var/log/mysql/",
			"/var/log/mariadb/",
			"/var/log/redis/",
			"/var/log/postgresql/",
			"/var/log/mongodb/",
			// PHP
			"/var/log/php-fpm/",
			// Mail
			"/var/log/mail.log",
			"/var/log/maillog",
			// System (don't touch)
			"/var/log/audit/",
			"/var/log/secure",
			"/var/log/auth.log",
		},
		logFiles:           make(map[string]*LogFileInfo),
	}
}

// recordAudit 记录审计日志（WORM 不可篡改）
func (g *LogGuard) recordAudit(action, target, reason, result, details string) {
	if g.storage == nil {
		return
	}
	_ = g.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Actor:     "system",
		Action:    action,
		Target:    target,
		Reason:    reason,
		Result:    result,
		Details:   details,
	})
}

// recordAction 记录操作日志
func (g *LogGuard) recordAction(actionType, target, message string, success bool, errMsg string) {
	if g.storage == nil {
		return
	}
	_ = g.storage.SaveAction("log-guard", types.ActionResult{
		Action:    types.Action{Type: types.ActionType(actionType), Params: map[string]interface{}{"target": target}},
		Success:   success,
		Message:   message,
		Error:     errMsg,
		Timestamp: time.Now(),
	})
}

// SetSafetyManager 注入安全管理器，用于宝塔安全模式判断。
func (g *LogGuard) SetSafetyManager(sm *safety.SafetyManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.safety = sm
}

// SetConfig updates log guard configuration.
func (g *LogGuard) SetConfig(maxFileSize, maxDirSize int64, maxWriteRate float64, retentionDays int, scanPaths, excludePaths []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxFileSize = maxFileSize
	g.maxDirSize = maxDirSize
	g.maxWriteRate = maxWriteRate
	g.retentionDays = retentionDays
	g.scanPaths = scanPaths
	g.excludePaths = excludePaths
}

// Check performs log guard checks.
// SAFETY: Only monitors and alerts. Never auto-rotates or deletes logs.
func (g *LogGuard) Check(ctx context.Context, diskUsagePercent float64) {
	// D1: Scan and monitor log files
	g.scanLogFiles()

	// D2: Check file sizes — alert only, don't rotate
	g.checkFileSizes()

	// D3: Check write rates
	g.checkWriteRates()

	// D4: Check directory quotas
	g.checkDirQuotas()

	// D5: Log content analysis — scan for error patterns
	g.checkLogContent()

	// D6: Emergency — alert only, never auto-delete
	if diskUsagePercent >= g.emergencyThreshold {
		g.eventBus.PublishAlert(types.AlertCritical, "log",
			"磁盘空间紧急",
			fmt.Sprintf("磁盘使用率 %.1f%% 超过紧急阈值，建议手动清理旧日志文件", diskUsagePercent),
			"emergency-cleanup-001")
	}
}

// scanLogFiles discovers and tracks log files.
func (g *LogGuard) scanLogFiles() {
	g.mu.RLock()
	scanPaths := g.scanPaths
	excludePaths := g.excludePaths
	g.mu.RUnlock()

	for _, basePath := range scanPaths {
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// Check exclusion
				for _, exc := range excludePaths {
					if strings.HasPrefix(path, exc) {
						return filepath.SkipDir
					}
				}
				return nil
			}

			// Only track regular files
			if !info.Mode().IsRegular() {
				return nil
			}

			// Check if already tracking
			g.mu.Lock()
			existing, ok := g.logFiles[path]
			now := time.Now()

			if ok {
				// Update existing
				prevSize := existing.Size
				prevTime := existing.LastModified
				existing.PrevSize = prevSize
				existing.PrevCheckTime = prevTime
				existing.Size = info.Size()
				existing.LastModified = info.ModTime()

				// Calculate write rate (MB/min)
				if !prevTime.IsZero() {
					elapsed := now.Sub(prevTime).Minutes()
					if elapsed > 0 {
						sizeDiff := float64(info.Size()-prevSize) / 1024 / 1024
						existing.WriteRate = sizeDiff / elapsed
					}
				}
			} else {
				// New file
				g.logFiles[path] = &LogFileInfo{
					Path:         path,
					Size:         info.Size(),
					LastModified: info.ModTime(),
				}
				// Try to identify the application
				app := g.identifyApp(path)
				if app != "" {
					g.logFiles[path].App = app
				}
			}
			g.mu.Unlock()

			return nil
		})
	}
}

// checkFileSizes checks if any log file exceeds the size limit.
// SAFETY: Alert only. Does NOT auto-rotate — rotating a file that a service
// (nginx, IIS, Apache, MySQL) has open can break writes.
// Auto-rotation is handled by the rule engine (log-flood-001) through the
// executor with snapshot + rollback, if the user enables it.
func (g *LogGuard) checkFileSizes() {
	g.mu.RLock()
	files := make([]*LogFileInfo, 0, len(g.logFiles))
	for _, f := range g.logFiles {
		files = append(files, f)
	}
	g.mu.RUnlock()

	for _, file := range files {
		if file.Size > g.maxFileSize {
			g.eventBus.PublishAlert(types.AlertWarning, "log",
				fmt.Sprintf("日志过大: %s (%.2fMB)", file.Path, float64(file.Size)/1024/1024),
				fmt.Sprintf("日志文件 %s 大小 %.2fMB 超过限制 %.2fMB。如需自动轮转，请在规则管理中关闭 log-flood-001 的学习模式",
					file.Path, float64(file.Size)/1024/1024, float64(g.maxFileSize)/1024/1024),
				"log-flood-001")
		}
	}
}

// checkWriteRates checks for abnormal write rates.
func (g *LogGuard) checkWriteRates() {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, file := range g.logFiles {
		if file.WriteRate > g.maxWriteRate {
			g.eventBus.PublishAlert(types.AlertWarning, "log",
				fmt.Sprintf("日志暴涨: %s (%.2f MB/min)", file.Path, file.WriteRate),
				fmt.Sprintf("日志文件 %s 写入速率 %.2f MB/min 超过限制 %.2f MB/min",
					file.Path, file.WriteRate, g.maxWriteRate),
				"log-flood-001")
		}
	}
}

// checkDirQuotas checks directory-level size quotas.
func (g *LogGuard) checkDirQuotas() {
	g.mu.RLock()
	scanPaths := g.scanPaths
	g.mu.RUnlock()

	for _, dir := range scanPaths {
		var totalSize int64
		filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			totalSize += info.Size()
			return nil
		})

		if totalSize > g.maxDirSize {
			g.eventBus.PublishAlert(types.AlertError, "log",
				fmt.Sprintf("目录配额超限: %s (%.2fGB)", dir, float64(totalSize)/1024/1024/1024),
				fmt.Sprintf("目录 %s 总大小 %.2fGB 超过配额 %.2fGB",
					dir, float64(totalSize)/1024/1024/1024, float64(g.maxDirSize)/1024/1024/1024),
				"log-flood-001")
		}
	}
}

// emergencyCleanup — DISABLED.
// Never auto-delete log files. Could break services that have files open.
func (g *LogGuard) emergencyCleanup() {
	// Do nothing — safety first
}

// rotateLog rotates a log file: rename, compress, create new.
// SAFETY: Uses safety.IsLogRotationExempted to check exemption paths.
// 宝塔安全模式下，所有 /www 路径下的日志一律不自动轮转。
// 豁免路径下的日志文件禁止自动轮转，改为告警通知用户手动处理。
// 如果必须轮转，禁止直接 mv/rm 活跃日志文件。
func (g *LogGuard) rotateLog(path string) {
	// 安全检查 1: 路径黑名单校验
	if safety.IsPathBlacklisted(path) {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("轮转被阻止(黑名单): %s", path),
			fmt.Sprintf("日志文件 %s 在清理黑名单中，禁止轮转", path),
			"log-rotation-blocked-001")
		return
	}

	// 安全检查 2: 日志轮转豁免路径检查
	baotaSafeMode := false
	if g.safety != nil {
		baotaSafeMode = g.safety.IsBaotaSafeMode()
	}
	if safety.IsLogRotationExempted(path, baotaSafeMode) {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("轮转被阻止(豁免): %s", path),
			fmt.Sprintf("日志文件 %s 在轮转豁免列表中，禁止自动轮转。建议手动处理或使用系统 logrotate。\n宝塔环境下请通过宝塔面板管理日志。", path),
			"log-rotation-blocked-001")
		return
	}

	// 安全检查 3: 禁止轮转数据库文件
	if safety.IsFileForbiddenForCleanup(path) {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("轮转被阻止(数据库文件): %s", path),
			fmt.Sprintf("文件 %s 是数据库/配置文件，禁止轮转", path),
			"log-rotation-blocked-001")
		return
	}

	// 安全检查 4: 检查文件是否正在被写入
	if safety.IsFileBeingWritten(path) {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("轮转被阻止(活跃写入): %s", path),
			fmt.Sprintf("日志文件 %s 正在被写入，禁止轮转。如需轮转请先使用 copytruncate 或发送信号（nginx: SIGUSR1, MySQL: FLUSH LOGS）", path),
			"log-rotation-blocked-001")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Size() == 0 {
		return
	}

	// Generate rotated filename
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", path, timestamp)

	// Rename original to rotated
	if err := os.Rename(path, rotatedPath); err != nil {
		g.eventBus.PublishAlert(types.AlertError, "log",
			fmt.Sprintf("轮转失败: %s", path),
			fmt.Sprintf("无法重命名日志文件: %v", err),
			"log-flood-001")
		g.recordAudit("rotate_log", path, fmt.Sprintf("日志轮转失败: %v", err), "failed", "")
		g.recordAction("rotate_log", path, fmt.Sprintf("轮转失败: %s", path), false, err.Error())
		return
	}

	// Create new empty file
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		f.Close()
	}

	// Compress rotated file
	go g.compressFile(rotatedPath)

	// Update tracking
	g.mu.Lock()
	if file, ok := g.logFiles[path]; ok {
		file.Size = 0
		file.LastRotated = time.Now()
	}
	g.mu.Unlock()

	sizeMB := float64(info.Size()) / 1024 / 1024
	g.recordAudit("rotate_log", path, fmt.Sprintf("日志轮转成功（%.2f MB → %s）", sizeMB, filepath.Base(rotatedPath)), "success", "")
	g.recordAction("rotate_log", path, fmt.Sprintf("轮转 %s (%.2f MB)", path, sizeMB), true, "")
}

// isProtectedLogPath checks if a path is a protected service log that should never be rotated.
// 使用 safety.IsLogRotationExempted 统一检查豁免路径。
func (g *LogGuard) isProtectedLogPath(path string) bool {
	baotaSafeMode := false
	if g.safety != nil {
		baotaSafeMode = g.safety.IsBaotaSafeMode()
	}
	return safety.IsLogRotationExempted(path, baotaSafeMode) || safety.IsPathBlacklisted(path)
}

// compressFile compresses a file using gzip.
// SAFETY: Checks path before deleting original.
// 宝塔安全模式下，禁止压缩和删除日志文件。
func (g *LogGuard) compressFile(path string) {
	// 宝塔安全模式下，禁止压缩和删除日志文件
	if g.safety != nil && g.safety.IsBaotaSafeMode() {
		return
	}

	// Safety: don't compress/delete protected service logs
	if g.isProtectedLogPath(path) {
		return
	}

	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()

	dstPath := path + ".gz"
	dst, err := os.Create(dstPath)
	if err != nil {
		return
	}
	defer dst.Close()

	gzWriter := gzip.NewWriter(dst)
	defer gzWriter.Close()

	io.Copy(gzWriter, src)

	// Remove original uncompressed file (only if not a protected path)
	if !g.isProtectedLogPath(path) {
		os.Remove(path)
	}
}

// identifyApp tries to identify which application writes a log file.
func (g *LogGuard) identifyApp(path string) string {
	// Common log file patterns
	patterns := map[string]string{
		"wvp":         "WVP",
		"MediaServer": "ZLMediaKit",
		"nginx":       "Nginx",
		"mysql":       "MySQL",
		"redis":       "Redis",
		"wwwlogs":     "BaoTa",
		"auth":        "SSH",
		"syslog":      "Syslog",
		"messages":    "System",
		"docker":      "Docker",
	}

	lowerPath := strings.ToLower(path)
	for pattern, app := range patterns {
		if strings.Contains(lowerPath, strings.ToLower(pattern)) {
			return app
		}
	}
	return ""
}

// checkLogbackConfig checks if logback/log4j configurations have proper rolling policies.
func (g *LogGuard) checkLogbackConfig(ctx context.Context) {
	// Scan for logback.xml files
	patterns := []string{
		"/www/server/panel/vhost/rewritelog/",
		"/opt/",
		"/app/",
		"/usr/local/",
	}

	for _, basePath := range patterns {
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, "logback.xml") || strings.HasSuffix(path, "log4j2.xml") {
				g.analyzeLogbackConfig(path)
			}
			return nil
		})
	}
}

// analyzeLogbackConfig checks if a logback config has proper rolling policies.
func (g *LogGuard) analyzeLogbackConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// Check for SizeBasedTriggeringPolicy
	if !strings.Contains(content, "SizeBasedTriggeringPolicy") && !strings.Contains(content, "TimeBasedRollingPolicy") {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("日志配置缺失: %s", path),
			fmt.Sprintf("logback 配置 %s 未设置滚动策略（SizeBasedTriggeringPolicy/TimeBasedRollingPolicy），可能导致日志暴涨。建议添加: <rollingPolicy class=\"ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy\"><maxFileSize>500MB</maxFileSize><maxHistory>30</maxHistory></rollingPolicy>", path),
			"log-config-001")
	}
}

// GetLogFiles returns all tracked log files.
func (g *LogGuard) GetLogFiles() []LogFileInfo {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]LogFileInfo, 0, len(g.logFiles))
	for _, f := range g.logFiles {
		result = append(result, *f)
	}
	return result
}

// PurgeOldLogs removes logs older than retention period.
// 安全策略 v2：使用 IsFileSafeForCleanup 统一安全检查。
// 多层防护：黑名单路径 + 受保护文件名模式 + 禁止扩展名 + 允许扩展名 + 活跃写入检测。
func (g *LogGuard) PurgeOldLogs() {
	cutoff := time.Now().AddDate(0, 0, -g.retentionDays)

	g.mu.RLock()
	files := make([]*LogFileInfo, 0, len(g.logFiles))
	for _, f := range g.logFiles {
		files = append(files, f)
	}
	g.mu.RUnlock()

	for _, file := range files {
		if file.LastModified.Before(cutoff) {
			// 综合安全检查：黑名单路径 + 受保护模式 + 禁止扩展名 + 允许扩展名
			if !safety.IsFileSafeForCleanup(file.Path) {
				continue
			}
			// 安全检查：文件正在被写入
			if safety.IsFileBeingWritten(file.Path) {
				continue
			}
			os.Remove(file.Path)
			g.mu.Lock()
			delete(g.logFiles, file.Path)
			g.mu.Unlock()
		}
	}
}

// defaultLogPaths returns platform-appropriate log directories.
// IMPORTANT: Do NOT include BaoTa directories (/www/wwwlogs) — rotating those files
// will break nginx and BaoTa panel. Only scan standard system log directories.
func defaultLogPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\inetpub\logs`,
			`C:\Windows\System32\LogFiles`,
			`C:\Windows\Logs`,
		}
	}
	return []string{"/var/log"}
}

// --- Log Content Analysis ---

// errorPatterns are patterns that indicate critical errors in logs.
var errorPatterns = []string{
	"panic:", "fatal error:", "segfault", "out of memory", "OOM",
	"connection refused", "too many open files",
	"No space left on device", "disk full",
	"Permission denied", "access denied",
	"stack trace", "core dumped",
	"database is locked", "deadlock",
	"segmentation fault", "bus error",
}

// checkLogContent scans recent log file content for error patterns.
// SAFETY: Read-only. Only reads the last N lines of each log file.
func (g *LogGuard) checkLogContent() {
	g.mu.RLock()
	files := make([]*LogFileInfo, 0, len(g.logFiles))
	for _, f := range g.logFiles {
		files = append(files, f)
	}
	g.mu.RUnlock()

	for _, file := range files {
		// Skip files larger than 50MB (too slow to read)
		if file.Size > 50*1024*1024 {
			continue
		}
		// Only scan recently modified files
		if time.Since(file.LastModified) > 10*time.Minute {
			continue
		}

		// Read last 1000 lines
		f, err := os.Open(file.Path)
		if err != nil {
			continue
		}

		// Read last 64KB of the file
		var buf []byte
		if file.Size > 65536 {
			f.Seek(-65536, 2)
		}
		chunk := make([]byte, 65536)
		n, _ := f.Read(chunk)
		f.Close()
		buf = chunk[:n]

		content := string(buf)
		for _, pattern := range errorPatterns {
			if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
				g.eventBus.PublishAlert(types.AlertError, "log",
					fmt.Sprintf("日志错误: %s", file.Path),
					fmt.Sprintf("日志文件 %s 中检测到错误模式: %s", file.Path, pattern),
					"log-error-001")
				break // One alert per file per check cycle
			}
		}
	}
}
