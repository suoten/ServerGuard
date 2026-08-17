package config

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
)

// ConfigGuard implements Module H: Config Guard
// Covers: auto backup, change audit, anomaly rollback, version history
type ConfigGuard struct {
	mu       sync.RWMutex
	eventBus *eventbus.EventBus
	backupDir string
	maxVersions int
	monitored  map[string]string // path -> last known hash
	history    map[string][]ConfigVersion // path -> version history
}

// ConfigVersion represents a version of a config file.
type ConfigVersion struct {
	Path      string
	Hash      string
	Timestamp time.Time
	Size      int64
	Content   string
}

// New creates a new ConfigGuard.
func New(bus *eventbus.EventBus, backupDir string) *ConfigGuard {
	if backupDir == "" {
		backupDir = "/var/lib/serverguard/config-backups"
	}
	return &ConfigGuard{
		eventBus:   bus,
		backupDir:  backupDir,
		maxVersions: 100,
		monitored:  make(map[string]string),
		history:    make(map[string][]ConfigVersion),
	}
}

// AddMonitoredFile adds a configuration file to monitor.
// SAFETY: Uses safety.IsFIMExcluded to skip baota dynamic files.
// 宝塔动态修改的文件（面板数据库、日志、vhost 配置等）被排除，避免误报。
func (g *ConfigGuard) AddMonitoredFile(path string) error {
	// 安全检查: 文件完整性监控排除路径
	if safety.IsFIMExcluded(path) {
		return fmt.Errorf("path %s is in FIM exclusion list (baota dynamic file), skipped", path)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	hash, err := g.hashFile(path)
	if err != nil {
		return err
	}
	g.monitored[path] = hash
	return nil
}

// Check checks monitored config files for changes.
// SAFETY: Uses safety.IsFIMExcluded to skip baota dynamic files at check time too,
// in case a file was added before the exclusion was in place.
func (g *ConfigGuard) Check(ctx context.Context) {
	g.mu.RLock()
	files := make(map[string]string, len(g.monitored))
	for k, v := range g.monitored {
		files[k] = v
	}
	g.mu.RUnlock()

	for path, oldHash := range files {
		// 运行时再次检查 FIM 排除（防止配置变更后动态文件被纳入）
		if safety.IsFIMExcluded(path) {
			continue
		}

		currentHash, err := g.hashFile(path)
		if err != nil {
			// File might have been deleted
			g.eventBus.PublishAlert(types.AlertCritical, "config",
				fmt.Sprintf("配置文件丢失: %s", path),
				fmt.Sprintf("监控的配置文件 %s 无法读取，可能已被删除", path),
				"config-missing-001")
			continue
		}

		if currentHash != oldHash {
			// Config changed! Backup the old version and record the change
			g.backupAndAudit(ctx, path, oldHash, currentHash)
		}
	}
}

// backupAndAudit backs up the changed config and records the audit entry.
func (g *ConfigGuard) backupAndAudit(ctx context.Context, path, oldHash, newHash string) {
	// Read current content
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Create backup
	backupPath := filepath.Join(g.backupDir, filepath.Base(path)+time.Now().Format(".20060102-150405"))
	if err := os.MkdirAll(g.backupDir, 0750); err != nil {
		return
	}
	if err := os.WriteFile(backupPath, content, 0640); err != nil {
		return
	}

	// Record version
	version := ConfigVersion{
		Path:      path,
		Hash:      newHash,
		Timestamp: time.Now(),
		Size:      int64(len(content)),
	}

	g.mu.Lock()
	g.monitored[path] = newHash
	g.history[path] = append(g.history[path], version)

	// Trim history to maxVersions
	if len(g.history[path]) > g.maxVersions {
		g.history[path] = g.history[path][len(g.history[path])-g.maxVersions:]
	}
	g.mu.Unlock()

	g.eventBus.PublishAlert(types.AlertWarning, "config",
		fmt.Sprintf("配置变更: %s", path),
		fmt.Sprintf("配置文件 %s 已被修改。旧哈希: %s，新哈希: %s。已备份到 %s",
			path, oldHash[:16], newHash[:16], backupPath),
		"config-change-001")
}

// Rollback rolls back a config file to the previous version.
// SAFETY: Refuses to rollback critical system files (/etc/, /boot/, /usr/, etc.)
// to prevent corrupting the system with a stale backup.
func (g *ConfigGuard) Rollback(ctx context.Context, path string) error {
	// Safety: never rollback critical system files
	criticalPaths := []string{
		"/boot/", "/usr/", "/bin/", "/sbin/", "/lib/",
		"/var/lib/mysql/", "/var/lib/postgresql/",
		`C:\Windows\System32\`,
	}
	lowerPath := strings.ToLower(path)
	for _, cp := range criticalPaths {
		if strings.HasPrefix(lowerPath, strings.ToLower(cp)) {
			return fmt.Errorf("refused to rollback critical system path: %s (too dangerous, manual intervention required)", path)
		}
	}

	g.mu.RLock()
	history := g.history[path]
	g.mu.RUnlock()

	if len(history) < 2 {
		return fmt.Errorf("no previous version to rollback to")
	}

	// Get the previous version's backup
	prevVersion := history[len(history)-2]

	// Find the backup file
	backupPattern := filepath.Join(g.backupDir, filepath.Base(path)+".*")
	matches, _ := filepath.Glob(backupPattern)
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))

	if len(matches) == 0 {
		return fmt.Errorf("backup file not found")
	}

	// Read backup and restore
	backupContent, err := os.ReadFile(matches[0])
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, backupContent, 0640); err != nil {
		return err
	}

	// Update hash
	g.mu.Lock()
	g.monitored[path] = prevVersion.Hash
	g.mu.Unlock()

	g.eventBus.PublishAlert(types.AlertInfo, "config",
		fmt.Sprintf("配置回滚: %s", path),
		fmt.Sprintf("已将 %s 回滚到上一个版本", path),
		"config-rollback-001")

	return nil
}

// GetHistory returns the version history for a config file.
func (g *ConfigGuard) GetHistory(path string) []ConfigVersion {
	g.mu.RLock()
	defer g.mu.RUnlock()
	history := g.history[path]
	result := make([]ConfigVersion, len(history))
	copy(result, history)
	return result
}

// hashFile computes the SHA-256 hash of a file.
func (g *ConfigGuard) hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:]), nil
}

// GetDefaultMonitoredFiles returns common config files to monitor.
// SAFETY: Uses safety.IsFIMExcluded to filter out baota dynamic files.
// 宝塔面板自身的配置文件（port.pl, admin_path.pl, api.json）仍被监控，
// 因为它们是安全相关配置——但 /www/server/panel/data 已在 FIM 排除列表中，
// 所以这些文件会被自动过滤。如需监控这些文件，请在 FIM 排除列表中移除对应路径。
func GetDefaultMonitoredFiles() []string {
	candidates := []string{
		"/etc/nginx/nginx.conf",
		"/etc/ssh/sshd_config",
		"/etc/mysql/my.cnf",
		"/etc/redis/redis.conf",
		"/etc/sysctl.conf",
		"/www/server/panel/data/port.pl",
		"/www/server/panel/data/admin_path.pl",
		"/www/server/panel/data/api.json",
	}

	// 过滤掉 FIM 排除路径中的文件
	var result []string
	for _, path := range candidates {
		if !safety.IsFIMExcluded(path) {
			result = append(result, path)
		}
	}
	return result
}
