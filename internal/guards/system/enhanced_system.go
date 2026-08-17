package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// UpdateSafetyManager takes snapshots of config files before system updates.
// SAFETY: Snapshot is read-only (copy). Restore is only done on explicit user request.
// Never auto-restores or auto-updates.
type UpdateSafetyManager struct {
	mu           sync.RWMutex
	snapshotDir  string
	maxSnapshots int
}

func NewUpdateSafetyManager() *UpdateSafetyManager {
	return &UpdateSafetyManager{
		snapshotDir:  "/var/lib/serverguard/snapshots",
		maxSnapshots: 10,
	}
}

// SnapshotConfigs creates a backup of critical config files.
// This is read-only — it only copies files, never modifies originals.
func (m *UpdateSafetyManager) SnapshotConfigs() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	timestamp := time.Now().Format("20060102-150405")
	snapshotPath := filepath.Join(m.snapshotDir, timestamp)
	if err := os.MkdirAll(snapshotPath, 0755); err != nil {
		return "", err
	}

	configFiles := []string{
		"/etc/nginx/nginx.conf",
		"/etc/ssh/sshd_config",
		"/etc/my.cnf",
		"/etc/redis/redis.conf",
		"/etc/sysctl.conf",
		"/etc/security/limits.conf",
	}

	savedCount := 0
	for _, file := range configFiles {
		if _, err := os.Stat(file); err != nil {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		// Use a safe filename encoding: replace / with _ but prefix with _
		// to avoid collision with files starting with _
		dest := filepath.Join(snapshotPath, "root"+strings.ReplaceAll(file, "/", "_"))
		if err := os.WriteFile(dest, data, 0644); err == nil {
			savedCount++
		}
	}

	m.cleanupOldSnapshots()
	return snapshotPath, nil
}

// cleanupOldSnapshots removes old snapshots beyond maxSnapshots.
func (m *UpdateSafetyManager) cleanupOldSnapshots() {
	entries, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		return
	}
	if len(entries) <= m.maxSnapshots {
		return
	}
	for i := 0; i < len(entries)-m.maxSnapshots; i++ {
		os.RemoveAll(filepath.Join(m.snapshotDir, entries[i].Name()))
	}
}

// RestoreSnapshot restores config files from a snapshot.
// SAFETY: Only called on explicit user request. Each file is restored individually
// with error handling — a failure on one file doesn't affect others.
// The path encoding uses "root" prefix + replace / with _, so decoding is:
// "root_etc_nginx_nginx.conf" -> "/etc/nginx/nginx.conf"
func (m *UpdateSafetyManager) RestoreSnapshot(snapshotPath string) error {
	entries, err := os.ReadDir(snapshotPath)
	if err != nil {
		return fmt.Errorf("snapshot directory not found: %w", err)
	}

	var restoreErrors []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Decode: "root_etc_nginx_nginx.conf" -> "/etc/nginx/nginx.conf"
		if !strings.HasPrefix(name, "root") {
			continue
		}
		encoded := name[len("root"):]
		originalPath := strings.ReplaceAll(encoded, "_", "/")
		// Validate the path looks reasonable
		if !strings.HasPrefix(originalPath, "/etc/") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(snapshotPath, name))
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("read %s: %v", name, err))
			continue
		}

		// Create backup of current file before restoring
		currentBackup := originalPath + ".pre-restore.bak"
		if currentData, err := os.ReadFile(originalPath); err == nil {
			os.WriteFile(currentBackup, currentData, 0644)
		}

		if err := os.WriteFile(originalPath, data, 0644); err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("write %s: %v", originalPath, err))
		}
	}

	if len(restoreErrors) > 0 {
		return fmt.Errorf("部分恢复失败: %s", strings.Join(restoreErrors, "; "))
	}
	return nil
}

// ListSnapshots returns available snapshots.
func (m *UpdateSafetyManager) ListSnapshots() ([]string, error) {
	entries, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		return nil, nil
	}
	var result []string
	for _, entry := range entries {
		if entry.IsDir() {
			result = append(result, entry.Name())
		}
	}
	return result, nil
}

// TempFileAnalyzer analyzes temp directory usage without deleting anything.
// SAFETY: Never deletes files. Only reports sizes and provides suggestions.
type TempFileAnalyzer struct {
	mu         sync.RWMutex
	scanDirs   []string
	excludePatterns []string
}

func NewTempFileAnalyzer() *TempFileAnalyzer {
	dirs := []string{"/tmp", "/var/tmp"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".cache"))
	}
	return &TempFileAnalyzer{
		scanDirs: dirs,
		excludePatterns: []string{
			"mysql.sock", "mysql.pid",       // MySQL socket/PID
			"php-cgi", "php-fpm",            // PHP
			"baota", "bt",                   // BaoTa
			".X11-unix", ".ICE-unix",        // X11
			"systemd-private",               // systemd
			".lock",                         // Lock files
		},
	}
}

// Analyze scans temp directories and reports sizes without deleting.
func (a *TempFileAnalyzer) Analyze() (map[string]int64, []string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	dirSizes := make(map[string]int64)
	var largeFiles []string

	for _, dir := range a.scanDirs {
		size, files := a.scanDir(dir)
		dirSizes[dir] = size
		largeFiles = append(largeFiles, files...)
	}

	return dirSizes, largeFiles, nil
}

// scanDir walks a directory and sums file sizes, identifying large files.
func (a *TempFileAnalyzer) scanDir(dir string) (int64, []string) {
	var totalSize int64
	var largeFiles []string

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		// Check exclusion patterns
		for _, pattern := range a.excludePatterns {
			if strings.Contains(path, pattern) {
				return nil
			}
		}

		totalSize += info.Size()

		// Report files larger than 100MB
		if info.Size() > 100*1024*1024 {
			age := time.Since(info.ModTime())
			largeFiles = append(largeFiles, fmt.Sprintf("  %s (%.1fMB, %d天前)",
				path, float64(info.Size())/1024/1024, int(age.Hours()/24)))
		}
		return nil
	})

	return totalSize, largeFiles
}

// GenerateCleanupReport creates a detailed cleanup suggestion report.
func (a *TempFileAnalyzer) GenerateCleanupReport() string {
	dirSizes, largeFiles, err := a.Analyze()
	if err != nil {
		return "分析失败"
	}

	var sb strings.Builder
	sb.WriteString("临时文件分析报告:\n\n")

	for dir, size := range dirSizes {
		sb.WriteString(fmt.Sprintf("目录 %s: %.1f MB\n", dir, float64(size)/1024/1024))
	}

	if len(largeFiles) > 0 {
		sb.WriteString("\n大文件 (>100MB):\n")
		for _, f := range largeFiles {
			sb.WriteString(f + "\n")
		}
	}

	sb.WriteString("\n安全清理建议 (手动执行):\n")
	sb.WriteString("  1. 清理包管理器缓存:\n")
	sb.WriteString("     Debian/Ubuntu: sudo apt clean\n")
	sb.WriteString("     CentOS/RHEL:   sudo yum clean all\n")
	sb.WriteString("  2. 清理旧日志 (已压缩的):\n")
	sb.WriteString("     find /var/log -name '*.gz' -mtime +30 -delete\n")
	sb.WriteString("  3. 清理 systemd journal:\n")
	sb.WriteString("     sudo journalctl --vacuum-time=7d\n")
	sb.WriteString("  4. 清理 Docker: docker system prune\n")
	sb.WriteString("\n⚠ 以下文件/目录请勿删除:\n")
	sb.WriteString("  /tmp/mysql.sock, /tmp/php-cgi*, /tmp/.X11-unix/\n")
	sb.WriteString("  任何 .lock, .pid 文件\n")

	return sb.String()
}

// TimeSyncGuard checks time sync status and provides suggestions.
// SAFETY: Never force-syncs. Only reports and suggests.
type TimeSyncGuard struct {
	mu         sync.RWMutex
	maxDriftMs float64
	primaryNTP string
	backupNTPs []string
}

func NewTimeSyncGuard() *TimeSyncGuard {
	return &TimeSyncGuard{
		maxDriftMs: 500,
		primaryNTP: "pool.ntp.org",
		backupNTPs: []string{"ntp.aliyun.com", "ntp.tencent.com", "time.windows.com"},
	}
}

// CheckDrift reads the current time drift without forcing sync.
func (g *TimeSyncGuard) CheckDrift() (driftMs float64, exceeded bool, err error) {
	if runtime.GOOS == "windows" {
		return g.checkWindowsDrift()
	}
	return g.checkChronyDrift()
}

func (g *TimeSyncGuard) checkChronyDrift() (float64, bool, error) {
	cmd := exec.Command("chronyc", "tracking")
	output, err := cmd.Output()
	if err != nil {
		return 0, false, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "System time") {
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			rest := strings.TrimSpace(line[idx+1:])
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				var sec float64
				fmt.Sscanf(parts[0], "%f", &sec)
				var driftMs float64 = sec * 1000
				var exceeded bool = driftMs > g.maxDriftMs
				return driftMs, exceeded, nil
			}
		}
	}
	return 0, false, nil
}

func (g *TimeSyncGuard) checkWindowsDrift() (float64, bool, error) {
	// Windows doesn't easily expose drift value via w32tm
	// Just check if service is running
	cmd := exec.Command("w32tm", "/query", "/status")
	output, err := cmd.Output()
	if err != nil {
		return 0, true, err
	}
	if strings.Contains(strings.ToLower(string(output)), "error") {
		return 0, true, nil
	}
	return 0, false, nil
}

// ForceSyncAdvice returns the manual sync command (never executes it).
func (g *TimeSyncGuard) ForceSyncAdvice() string {
	if runtime.GOOS == "windows" {
		return "手动执行: w32tm /resync"
	}
	return "手动执行: sudo chronyc makestep\n注意: 时间跳变可能影响数据库和证书，请确认后执行。"
}

// SwitchToBackupNTPAdvice returns suggestion for switching NTP source.
func (g *TimeSyncGuard) SwitchToBackupNTPAdvice() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("切换NTP源:\n  w32tm /config /manualpeerlist:%s /syncfromflags:manual /update", g.backupNTPs[0])
	}
	return fmt.Sprintf("切换NTP源:\n  sudo chronyc sources\n  sudo chronyc add server %s\n  sudo chronyc delete <current-source>", g.backupNTPs[0])
}

// IsProtocolSensitive checks if a protocol is time-sensitive.
func (g *TimeSyncGuard) IsProtocolSensitive(protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "GB28181", "JT808":
		return true
	}
	return false
}

// PackageLockChecker checks if package manager locks are held and provides advice.
// SAFETY: Never kills processes or removes locks. Only reports and suggests.
type PackageLockChecker struct{}

func NewPackageLockChecker() *PackageLockChecker { return &PackageLockChecker{} }

// CheckLocks checks if apt/dpkg locks are held.
func (c *PackageLockChecker) CheckLocks(ctx context.Context) (locked bool, holder string, advice string) {
	if runtime.GOOS == "windows" {
		return false, "", ""
	}

	// Check apt/dpkg locks
	lockFiles := []string{
		"/var/lib/dpkg/lock",
		"/var/lib/dpkg/lock-frontend",
		"/var/cache/apt/archives/lock",
	}

	for _, lockFile := range lockFiles {
		if _, err := os.Stat(lockFile); err != nil {
			continue
		}
		// Check if lock is held using fuser (read-only check)
		output, err := exec.CommandContext(ctx, "fuser", lockFile).Output()
		if err == nil && len(output) > 0 {
			pid := strings.TrimSpace(string(output))
			// Get process name
			cmdOutput, _ := exec.CommandContext(ctx, "ps", "-p", pid, "-o", "comm=").Output()
			procName := strings.TrimSpace(string(cmdOutput))
			return true, fmt.Sprintf("PID %s (%s)", pid, procName),
				fmt.Sprintf("包管理器锁被 PID %s (%s) 占用。\n"+
					"  1. 等待该进程完成 (推荐)\n"+
					"  2. 检查是否是自动更新: systemctl status apt-daily.timer\n"+
					"  3. 如确认进程已卡死 (非自动更新):\n"+
					"     sudo kill %s  (请确认后手动执行)\n"+
					"     sudo dpkg --configure -a  (修复中断的安装)\n"+
					"⚠ 切勿直接删除锁文件，可能导致数据库损坏",
					pid, procName, pid)
		}
	}
	return false, "", ""
}
