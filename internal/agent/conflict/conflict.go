package conflict

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

	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// ConflictDetector implements §8.7: Conflict Detection with existing tools.
// Detects: fail2ban, logrotate, Supervisor, Monit, BaoTa cron, systemd watchdog.
type ConflictDetector struct {
	mu       sync.RWMutex
	eventBus *eventbus.EventBus
	safety   *safety.SafetyManager // 安全管理器引用，用于宝塔安全模式判断
	detected map[string]bool       // tool name -> detected
	managed  map[string][]string   // tool name -> managed items
}

// New creates a new ConflictDetector.
func New(bus *eventbus.EventBus) *ConflictDetector {
	return &ConflictDetector{
		eventBus: bus,
		detected: make(map[string]bool),
		managed:  make(map[string][]string),
	}
}

// SetSafetyManager 注入安全管理器，启用宝塔安全模式检查。
func (d *ConflictDetector) SetSafetyManager(sm *safety.SafetyManager) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.safety = sm
}

// Scan performs a full conflict detection scan.
func (d *ConflictDetector) Scan(ctx context.Context) *ConflictReport {
	report := &ConflictReport{
		Timestamp: time.Now(),
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. Detect fail2ban
	if d.detectFail2ban(ctx) {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:         "fail2ban",
			Conflict:     "双重封禁IP，iptables规则冲突",
			Action:       "ServerGuard的SSH爆破拦截自动让位，只做告警不做封禁",
			ManagedItems: d.managed["fail2ban"],
			Resolution:   "auto_delegated",
		})
	}

	// 2. Detect logrotate
	if managed := d.detectLogrotate(); len(managed) > 0 {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:         "logrotate",
			Conflict:     "双重轮转同一日志文件",
			Action:       "ServerGuard跳过已被logrotate管理的日志文件",
			ManagedItems: managed,
			Resolution:   "auto_skip",
		})
	}

	// 3. Detect Supervisor
	if d.detectSupervisor(ctx) {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:         "supervisor",
			Conflict:     "双重保活同一进程",
			Action:       "ServerGuard不接管Supervisor管理的进程保活，只做资源监控",
			ManagedItems: d.managed["supervisor"],
			Resolution:   "auto_delegated",
		})
	}

	// 4. Detect Monit
	if d.detectMonit(ctx) {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:       "monit",
			Conflict:   "双重监控和修复",
			Action:     "ServerGuard让位Monit管理的进程",
			Resolution: "auto_delegated",
		})
	}

	// 5. Detect BaoTa cron
	if managed := d.detectBaoTaCron(); len(managed) > 0 {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:         "baota_cron",
			Conflict:     "重复的清理/重启定时任务",
			Action:       "提示用户：宝塔已有定时任务，是否由ServerGuard接管",
			ManagedItems: managed,
			Resolution:   "user_confirm",
		})
	}

	// 6. Detect systemd watchdog
	if managed := d.detectSystemdWatchdog(); len(managed) > 0 {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:         "systemd_watchdog",
			Conflict:     "双重进程监控",
			Action:       "ServerGuard不重复保活已配置watchdog的服务，只做资源监控",
			ManagedItems: managed,
			Resolution:   "auto_skip",
		})
	}

	// 7. Detect Cloudflare/WAF
	if d.detectCloudflare() {
		report.Conflicts = append(report.Conflicts, ConflictItem{
			Tool:       "cloudflare",
			Conflict:   "IP封禁冲突",
			Action:     "优先调用Cloudflare API封禁，不操作本地iptables",
			Resolution: "auto_prefer",
		})
	}

	if len(report.Conflicts) > 0 {
		d.eventBus.PublishAlert(types.AlertInfo, "conflict",
			"检测到运维工具冲突",
			fmt.Sprintf("检测到 %d 个潜在冲突，已自动处理。详见报告", len(report.Conflicts)),
			"conflict-detect-001")
	}

	return report
}

// ConflictReport represents the result of a conflict scan.
type ConflictReport struct {
	Timestamp time.Time      `json:"timestamp"`
	Conflicts []ConflictItem `json:"conflicts"`
}

// ConflictItem represents a single detected conflict.
type ConflictItem struct {
	Tool         string   `json:"tool"`
	Conflict     string   `json:"conflict"`
	Action       string   `json:"action"`
	ManagedItems []string `json:"managed_items"`
	Resolution   string   `json:"resolution"` // auto_delegated, auto_skip, user_confirm, auto_prefer
}

// detectFail2ban detects if fail2ban is running.
func (d *ConflictDetector) detectFail2ban(ctx context.Context) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	// Check if fail2ban-client is available and running
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		cmd := exec.CommandContext(ctx, "fail2ban-client", "status")
		if err := cmd.Run(); err == nil {
			d.detected["fail2ban"] = true
			// Get managed jails
			output, _ := exec.CommandContext(ctx, "fail2ban-client", "status").Output()
			// Parse jail names
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "Jail list:") {
					jails := strings.TrimPrefix(line, "Jail list:")
					for _, jail := range strings.Split(jails, ",") {
						jail = strings.TrimSpace(jail)
						if jail != "" {
							d.managed["fail2ban"] = append(d.managed["fail2ban"], jail)
						}
					}
				}
			}
			return true
		}
	}
	return false
}

// detectLogrotate detects logrotate configs.
func (d *ConflictDetector) detectLogrotate() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var managed []string
	configDirs := []string{"/etc/logrotate.d/", "/etc/logrotate.conf"}

	for _, path := range configDirs {
		files, err := os.ReadDir(path)
		if err != nil {
			// It might be a file, not a directory
			if _, err := os.Stat(path); err == nil {
				if logs := parseLogrotateConfig(path); len(logs) > 0 {
					managed = append(managed, logs...)
				}
			}
			continue
		}
		for _, f := range files {
			filePath := filepath.Join(path, f.Name())
			if logs := parseLogrotateConfig(filePath); len(logs) > 0 {
				managed = append(managed, logs...)
			}
		}
	}

	if len(managed) > 0 {
		d.detected["logrotate"] = true
		d.managed["logrotate"] = managed
	}
	return managed
}

// parseLogrotateConfig parses a logrotate config and returns managed log paths.
func parseLogrotateConfig(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Lines that are paths (start with /)
		if strings.HasPrefix(line, "/") {
			// Take the first path before { or whitespace
			path := strings.Fields(line)[0]
			if strings.HasSuffix(path, "{") {
				path = strings.TrimSuffix(path, "{")
				path = strings.TrimSpace(path)
			}
			if strings.HasPrefix(path, "/") {
				result = append(result, path)
			}
		}
	}
	return result
}

// detectSupervisor detects if Supervisor is running.
func (d *ConflictDetector) detectSupervisor(ctx context.Context) bool {
	if _, err := exec.LookPath("supervisorctl"); err == nil {
		cmd := exec.CommandContext(ctx, "supervisorctl", "status")
		output, err := cmd.Output()
		if err == nil {
			d.detected["supervisor"] = true
			// Parse managed processes
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 1 && fields[0] != "" {
					d.managed["supervisor"] = append(d.managed["supervisor"], fields[0])
				}
			}
			return true
		}
	}
	return false
}

// detectMonit detects if Monit is running.
// 宝塔安全模式下：跳过 process.Processes() 回退检查 — I/O 开销大。
// 只通过 exec.LookPath + monit status 检测，足够覆盖大多数场景。
func (d *ConflictDetector) detectMonit(ctx context.Context) bool {
	if _, err := exec.LookPath("monit"); err == nil {
		cmd := exec.CommandContext(ctx, "monit", "status")
		if err := cmd.Run(); err == nil {
			d.detected["monit"] = true
			return true
		}
	}
	// 宝塔安全模式下：跳过 process.Processes() 回退检查
	d.mu.RLock()
	sm := d.safety
	d.mu.RUnlock()
	if sm != nil && sm.IsBaotaSafeMode() {
		return false
	}
	// Check process list
	procs, _ := process.Processes()
	for _, p := range procs {
		if name, _ := p.Name(); name == "monit" {
			d.detected["monit"] = true
			return true
		}
	}
	return false
}

// detectBaoTaCron detects BaoTa scheduled tasks.
func (d *ConflictDetector) detectBaoTaCron() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var managed []string
	// Check BaoTa cron directory
	cronDir := "/www/server/cron/"
	entries, err := os.ReadDir(cronDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Read the cron script to check what it does
		data, err := os.ReadFile(filepath.Join(cronDir, entry.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		// Check for cleanup/restart patterns
		if strings.Contains(content, "log") && (strings.Contains(content, "clean") || strings.Contains(content, "rm")) {
			managed = append(managed, fmt.Sprintf("日志清理: %s", entry.Name()))
		}
		if strings.Contains(content, "restart") || strings.Contains(content, "systemctl") {
			managed = append(managed, fmt.Sprintf("服务重启: %s", entry.Name()))
		}
	}

	// Also check system crontab
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "www/server") {
				managed = append(managed, fmt.Sprintf("宝塔定时: %s", strings.TrimSpace(line)))
			}
		}
	}

	if len(managed) > 0 {
		d.detected["baota_cron"] = true
		d.managed["baota_cron"] = managed
	}
	return managed
}

// detectSystemdWatchdog detects services with WatchdogSec configured.
func (d *ConflictDetector) detectSystemdWatchdog() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var managed []string
	// Scan systemd unit files for WatchdogSec
	unitDirs := []string{"/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/"}
	for _, dir := range unitDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "WatchdogSec=") {
				managed = append(managed, entry.Name())
			}
		}
	}
	if len(managed) > 0 {
		d.detected["systemd_watchdog"] = true
		d.managed["systemd_watchdog"] = managed
	}
	return managed
}

// detectCloudflare detects if Cloudflare is in use.
func (d *ConflictDetector) detectCloudflare() bool {
	// Check nginx config for cloudflare
	configPaths := []string{
		"/www/server/panel/vhost/nginx/",
		"/etc/nginx/conf.d/",
	}
	for _, dir := range configPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "cloudflare") || strings.Contains(string(data), "CF-") {
				d.detected["cloudflare"] = true
				return true
			}
		}
	}
	return false
}

// IsToolDetected returns whether a specific tool was detected.
func (d *ConflictDetector) IsToolDetected(tool string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected[tool]
}

// GetManagedItems returns items managed by a specific tool.
func (d *ConflictDetector) GetManagedItems(tool string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.managed[tool]
}

// ShouldSkipLogRotation checks if a log file is already managed by logrotate.
func (d *ConflictDetector) ShouldSkipLogRotation(logPath string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, managed := range d.managed["logrotate"] {
		if strings.HasPrefix(logPath, managed) || strings.HasPrefix(managed, logPath) {
			return true
		}
	}
	return false
}

// ShouldSkipProcessGuard checks if a process is already managed by Supervisor.
func (d *ConflictDetector) ShouldSkipProcessGuard(processName string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, managed := range d.managed["supervisor"] {
		if strings.EqualFold(managed, processName) {
			return true
		}
	}
	return false
}

// ShouldSkipBruteForce checks if fail2ban is handling brute force protection.
func (d *ConflictDetector) ShouldSkipBruteForce() bool {
	return d.IsToolDetected("fail2ban")
}

// ShouldUseCloudflareAPI checks if Cloudflare API should be used for IP banning.
func (d *ConflictDetector) ShouldUseCloudflareAPI() bool {
	return d.IsToolDetected("cloudflare")
}
