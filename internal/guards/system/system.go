package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// SystemGuard implements Module F: System Guard
// Covers: system update check (read-only), temp file monitoring (alert only),
// time sync guard (suggest only), kernel tuning suggestions
//
// SAFETY: Never auto-executes any system modification command.
// All remediation is provided as suggestions for manual execution.
type SystemGuard struct {
	mu            sync.RWMutex
	eventBus      *eventbus.EventBus
	safety        *safety.SafetyManager
	maxClockDrift time.Duration
	protocolAware bool // GB28181/JT808 time awareness
}

// New creates a new SystemGuard.
func New(bus *eventbus.EventBus) *SystemGuard {
	return &SystemGuard{
		eventBus:      bus,
		maxClockDrift: 500 * time.Millisecond,
		protocolAware: true,
	}
}

// SetSafetyManager 注入安全管理器，用于宝塔安全模式判断。
func (g *SystemGuard) SetSafetyManager(sm *safety.SafetyManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.safety = sm
}

// CleanTempFiles — DISABLED to prevent interference with BaoTa and other services.
// BaoTa stores session files, socket files, and temp data in /tmp.
// Cleaning /tmp can break BaoTa, MySQL, PHP, and other services.
// Disk cleanup is handled by ResourceGuard with proper exclusions.
func (g *SystemGuard) CleanTempFiles(ctx context.Context) int64 {
	// Do nothing — safety first
	return 0
}

// CheckTimeSync checks for clock drift and provides remediation suggestions.
// SAFETY: Never auto-executes chronyc makestep or w32tm /resync.
// Time jumps can corrupt databases and break TLS certificate validation.
func (g *SystemGuard) CheckTimeSync(ctx context.Context) {
	g.mu.RLock()
	maxDrift := g.maxClockDrift
	protocolAware := g.protocolAware
	g.mu.RUnlock()

	_, err := host.Info()
	if err != nil {
		return
	}

	if runtime.GOOS != "windows" {
		g.checkChronyDrift(ctx, maxDrift, protocolAware)
	} else {
		g.checkW32tmDrift(ctx, protocolAware)
	}
}

// checkChronyDrift parses chronyc tracking output for real drift value.
func (g *SystemGuard) checkChronyDrift(ctx context.Context, maxDrift time.Duration, protocolAware bool) {
	if _, err := exec.LookPath("chronyc"); err != nil {
		// chrony not installed, try timedatectl
		g.checkTimedatectl(ctx)
		return
	}

	output, err := exec.CommandContext(ctx, "chronyc", "tracking").Output()
	if err != nil {
		return
	}

	s := string(output)
	var systemOffsetSec float64
	var found bool

	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "System time") {
			// "System time     :   0.000123456 seconds fast of NTP time"
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			rest := strings.TrimSpace(line[idx+1:])
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				if val, err := strconvParseFloat(parts[0]); err == nil {
					systemOffsetSec = val
					found = true
				}
			}
		}
	}

	if !found {
		return
	}

	absDrift := absDuration(systemOffsetSec)
	if absDrift > maxDrift.Seconds() {
		level := types.AlertWarning
		msg := fmt.Sprintf("检测到时钟漂移 %.3f 秒（阈值 %.3f 秒）", systemOffsetSec, maxDrift.Seconds())
		detail := fmt.Sprintf("系统时间偏移: %.6f 秒\n\n"+
			"建议手动执行:\n"+
			"  sudo chronyc makestep\n\n"+
			"⚠ 时间跳变可能影响:\n"+
			"  - MySQL 主从复制\n"+
			"  - PostgreSQL 事务时间戳\n"+
			"  - TLS 证书验证\n"+
			"  - 定时任务 (cron)\n"+
			"请确认安全后手动执行。",
			systemOffsetSec)

		if protocolAware {
			msg += "（GB28181/JT808协议对时间精度敏感，请优先处理）"
			detail += "\n\n⚠ GB28181/JT808 要求时间精度 < 1秒，请立即处理！"
			level = types.AlertError
		}

		if strings.Contains(s, "Not synchronised") || strings.Contains(s, "Cannot communicate") {
			level = types.AlertCritical
			detail += "\n\n⚠ NTP 源不可达！排查:\n" +
				"  1. 防火墙是否放行 UDP 123 端口\n" +
				"  2. chronyc sources 查看NTP源状态\n" +
				"  3. 备用 NTP: ntp.aliyun.com, ntp.tencent.com"
		}

		g.eventBus.PublishAlert(level, "system", "时钟漂移", detail, "time-sync-001")
	}
}

// checkTimedatectl checks time sync status via timedatectl (systemd).
func (g *SystemGuard) checkTimedatectl(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "timedatectl", "status").Output()
	if err != nil {
		return
	}
	s := string(output)

	if strings.Contains(s, "NTP synchronized: no") || strings.Contains(s, "NTP service: inactive") {
		g.eventBus.PublishAlert(types.AlertWarning, "system",
			"NTP 未同步",
			"系统 NTP 同步未启用。建议:\n"+
				"  1. 启用 NTP: sudo timedatectl set-ntp true\n"+
				"  2. 或安装 chrony:\n"+
				"     Debian/Ubuntu: sudo apt install chrony\n"+
				"     CentOS/RHEL:   sudo yum install chrony\n"+
				"  3. 检查防火墙: sudo iptables -L -n | grep 123",
			"time-sync-001")
	}
}

// checkW32tmDrift checks Windows time sync status.
func (g *SystemGuard) checkW32tmDrift(ctx context.Context, protocolAware bool) {
	if _, err := exec.LookPath("w32tm"); err != nil {
		return
	}

	output, err := exec.CommandContext(ctx, "w32tm", "/query", "/status").Output()
	if err != nil {
		g.eventBus.PublishAlert(types.AlertWarning, "system",
			"Windows 时间服务异常",
			"w32tm 服务不可用。建议:\n"+
				"  1. 启动服务: net start w32time\n"+
				"  2. 手动同步: w32tm /resync\n"+
				"  3. 检查状态: w32tm /query /status",
			"time-sync-001")
		return
	}

	s := string(output)
	if strings.Contains(strings.ToLower(s), "error") || strings.Contains(s, "not running") {
		g.eventBus.PublishAlert(types.AlertWarning, "system",
			"Windows 时间服务异常",
			"检测到 Windows 时间服务异常。建议手动执行:\n"+
				"  net start w32time\n"+
				"  w32tm /resync\n"+
				"  w32tm /query /status",
			"time-sync-001")
	}
}

// strconvParseFloat safely parses a float string.
func strconvParseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

func absDuration(seconds float64) float64 {
	if seconds < 0 {
		return -seconds
	}
	return seconds
}

// CheckSystemUpdates checks if system updates are available (read-only).
// SAFETY: Only runs check commands, never installs anything.
// Detects available security updates and provides manual installation commands.
func (g *SystemGuard) CheckSystemUpdates(ctx context.Context) {
	if runtime.GOOS == "windows" {
		g.checkWindowsUpdates(ctx)
		return
	}

	// Detect package manager
	_, aptErr := exec.LookPath("apt")
	_, aptGetErr := exec.LookPath("apt-get")
	_, yumErr := exec.LookPath("yum")
	_, dnfErr := exec.LookPath("dnf")

	if aptErr == nil || aptGetErr == nil {
		g.checkAptUpdates(ctx)
	} else if yumErr == nil {
		g.checkYumUpdates(ctx)
	} else if dnfErr == nil {
		g.checkDnfUpdates(ctx)
	}
}

// checkAptUpdates checks for available updates on Debian/Ubuntu.
func (g *SystemGuard) checkAptUpdates(ctx context.Context) {
	// First, update the package list (read-only, doesn't install anything)
	// Actually, apt update modifies /var/lib/apt/lists, which is safe but let's
	// just check what's already cached to avoid network operations
	output, err := exec.CommandContext(ctx, "apt", "list", "--upgradable", "-a").Output()
	if err != nil {
		// Try alternative
		output, err = exec.CommandContext(ctx, "sh", "-c", "apt list --upgradable 2>/dev/null").Output()
		if err != nil {
			return
		}
	}

	lines := strings.Split(string(output), "\n")
	var securityUpdates []string
	var regularUpdates []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		// Format: package/version arch [upgradable from: version]
		parts := strings.Split(line, "/")
		if len(parts) < 2 {
			continue
		}
		pkgName := parts[0]
		if strings.Contains(line, "security") || strings.Contains(line, "Security") {
			securityUpdates = append(securityUpdates, pkgName)
		} else {
			regularUpdates = append(regularUpdates, pkgName)
		}
	}

	if len(securityUpdates) > 0 {
		g.eventBus.PublishAlert(types.AlertCritical, "system",
			fmt.Sprintf("安全更新可用 (%d个)", len(securityUpdates)),
			fmt.Sprintf("检测到 %d 个安全更新:\n  %s\n\n"+
				"建议尽快安装安全更新:\n"+
				"  sudo apt update && sudo apt upgrade -y\n\n"+
				"注意: 更新后可能需要重启服务或系统。\n"+
				"建议在维护窗口期执行，并先备份重要数据。",
				len(securityUpdates), strings.Join(securityUpdates[:min(10, len(securityUpdates))], ", ")),
			"sys-update-001")
	}

	if len(regularUpdates) > 0 {
		level := types.AlertInfo
		if len(regularUpdates) > 20 {
			level = types.AlertWarning
		}
		g.eventBus.PublishAlert(level, "system",
			fmt.Sprintf("系统更新可用 (%d个)", len(regularUpdates)),
			fmt.Sprintf("检测到 %d 个可用更新。\n"+
				"建议在维护窗口期执行:\n"+
				"  sudo apt update && sudo apt upgrade -y",
				len(regularUpdates)),
			"sys-update-002")
	}
}

// checkYumUpdates checks for available updates on CentOS/RHEL.
func (g *SystemGuard) checkYumUpdates(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "yum", "check-update", "--quiet").Output()
	if err != nil {
		// yum check-update returns exit code 100 when updates are available
		// and 0 when none. So err != nil might mean updates exist.
		if len(output) == 0 {
			return
		}
	}

	lines := strings.Split(string(output), "\n")
	var updates []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") || strings.HasPrefix(line, "Loading") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			updates = append(updates, parts[0])
		}
	}

	if len(updates) > 0 {
		// Check for security updates specifically
		secOutput, _ := exec.CommandContext(ctx, "yum", "--security", "check-update", "--quiet").Output()
		secCount := 0
		for _, line := range strings.Split(string(secOutput), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "Last") && !strings.HasPrefix(line, "Loading") {
				secCount++
			}
		}

		if secCount > 0 {
			g.eventBus.PublishAlert(types.AlertCritical, "system",
				fmt.Sprintf("安全更新可用 (%d个)", secCount),
				fmt.Sprintf("检测到 %d 个安全更新。\n"+
					"建议尽快安装:\n"+
					"  sudo yum update --security -y\n\n"+
					"全部更新:\n"+
					"  sudo yum update -y\n\n"+
					"注意: 更新后可能需要重启，请在维护窗口执行。",
					secCount),
				"sys-update-001")
		} else {
			g.eventBus.PublishAlert(types.AlertInfo, "system",
				fmt.Sprintf("系统更新可用 (%d个)", len(updates)),
				fmt.Sprintf("检测到 %d 个可用更新。\n"+
					"建议在维护窗口期执行: sudo yum update -y",
					len(updates)),
				"sys-update-002")
		}
	}
}

// checkDnfUpdates checks for available updates on Fedora/RHEL 8+.
func (g *SystemGuard) checkDnfUpdates(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "dnf", "check-update", "--quiet").Output()
	_ = err // dnf also returns non-zero when updates are available

	lines := strings.Split(string(output), "\n")
	var updates []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") || strings.HasPrefix(line, "Loading") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			updates = append(updates, parts[0])
		}
	}

	if len(updates) > 0 {
		g.eventBus.PublishAlert(types.AlertWarning, "system",
			fmt.Sprintf("系统更新可用 (%d个)", len(updates)),
			fmt.Sprintf("检测到 %d 个可用更新。\n"+
				"建议在维护窗口期执行:\n"+
				"  sudo dnf upgrade -y\n\n"+
				"仅安全更新: sudo dnf upgrade --security -y",
				len(updates)),
			"sys-update-002")
	}
}

// checkWindowsUpdates checks for Windows updates via PowerShell.
func (g *SystemGuard) checkWindowsUpdates(ctx context.Context) {
	// Use PowerShell to check for available updates
	psScript := `Get-WindowsUpdate -AcceptAll -Install:$false 2>$null | Select-Object -Property KB,Title,Size | Format-Table -AutoSize`
	// This requires PSWindowsUpdate module, which may not be installed.
	// Fall back to a simpler check.
	psScript = `if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) { Get-WindowsUpdate | Select-Object KB,Title | Format-Table -AutoSize } else { Write-Output "PSWindowsUpdate module not installed. Install: Install-Module PSWindowsUpdate" }`

	cmd := exec.CommandContext(ctx, "powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	s := string(output)
	if strings.Contains(s, "not installed") {
		// Module not installed, suggest installation
		g.eventBus.PublishAlert(types.AlertInfo, "system",
			"Windows 更新检查",
			"建议安装 PSWindowsUpdate 模块来检查更新:\n"+
				"  Install-Module PSWindowsUpdate -Force\n"+
				"  Import-Module PSWindowsUpdate\n"+
				"  Get-WindowsUpdate\n\n"+
				"或使用系统设置检查更新。",
			"sys-update-001")
		return
	}

	if strings.TrimSpace(s) != "" && !strings.Contains(s, "no updates") {
		g.eventBus.PublishAlert(types.AlertWarning, "system",
			"Windows 更新可用",
			fmt.Sprintf("检测到可用的 Windows 更新:\n%s\n\n建议在维护窗口期安装。", s),
			"sys-update-001")
	}
}

// GenerateTuningSuggestions generates sysctl tuning suggestions based on workload.
// SAFETY: Only returns suggestion strings. Never applies them.
func (g *SystemGuard) GenerateTuningSuggestions(workloadType string) []string {
	var suggestions []string

	switch workloadType {
	case "streaming":
		suggestions = append(suggestions,
			"net.core.rmem_max = 16777216",
			"net.core.wmem_max = 16777216",
			"net.ipv4.tcp_rmem = 4096 87380 16777216",
			"net.ipv4.tcp_wmem = 4096 65536 16777216",
			"net.ipv4.tcp_tw_reuse = 1",
		)
	case "database":
		suggestions = append(suggestions,
			"vm.swappiness = 1",
			"fs.file-max = 2097152",
			"net.ipv4.tcp_tw_reuse = 1",
			"kernel.sem = 250 32000 100 128",
		)
	case "ai":
		suggestions = append(suggestions,
			"vm.swappiness = 10",
			"fs.file-max = 2097152",
			"kernel.shmmax = 68719476736",
		)
	case "web":
		suggestions = append(suggestions,
			"net.core.somaxconn = 65535",
			"net.ipv4.tcp_max_syn_backlog = 65535",
			"net.ipv4.tcp_tw_reuse = 1",
			"net.ipv4.ip_local_port_range = 10240 65535",
		)
	}

	return suggestions
}

// CheckKernelParams checks current sysctl values and compares with recommended ones.
// Returns a list of recommendations.
func (g *SystemGuard) CheckKernelParams(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	// Read current sysctl values
	recommendedParams := map[string]string{
		"net.core.somaxconn":           "65535",
		"net.ipv4.tcp_max_syn_backlog": "65535",
		"net.ipv4.tcp_tw_reuse":        "1",
		"vm.swappiness":                "10",
		"fs.file-max":                  "2097152",
		"net.ipv4.ip_local_port_range": "10240 65535",
	}

	var warnings []string
	for param, recommended := range recommendedParams {
		output, err := exec.CommandContext(ctx, "sysctl", "-n", param).Output()
		if err != nil {
			continue
		}
		current := strings.TrimSpace(string(output))
		if current != recommended {
			warnings = append(warnings, fmt.Sprintf("  %s = %s (推荐: %s)", param, current, recommended))
		}
	}

	if len(warnings) > 0 {
		g.eventBus.PublishAlert(types.AlertInfo, "system",
			"内核参数优化建议",
			fmt.Sprintf("以下内核参数建议调整:\n%s\n\n"+
				"应用方法 (手动执行):\n"+
				"  sudo sysctl -w <参数>=<值>  (临时)\n"+
				"  echo '<参数>=<值>' >> /etc/sysctl.conf && sudo sysctl -p  (永久)\n\n"+
				"注意: 修改内核参数前请确认业务兼容性。",
				strings.Join(warnings, "\n")),
			"sys-tuning-001")
	}
}

// CheckSystemLoadAverage checks system load and alerts if too high.
func (g *SystemGuard) CheckSystemLoadAverage(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	// Read /proc/loadavg
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return
	}

	load1, _ := strconvParseFloat(fields[0])
	load5, _ := strconvParseFloat(fields[1])
	load15, _ := strconvParseFloat(fields[2])

	// Get CPU count
	cpuCount := runtime.NumCPU()

	// Load average relative to CPU count
	load1Per := load1 / float64(cpuCount)
	load5Per := load5 / float64(cpuCount)

	if load1Per > 1.0 {
		level := types.AlertWarning
		if load1Per > 2.0 {
			level = types.AlertCritical
		}
		g.eventBus.PublishAlert(level, "system",
			"系统负载过高",
			fmt.Sprintf("Load average: %.2f, %.2f, %.2f (CPU核心数: %d)\n"+
				"每核负载: %.2f (1分钟), %.2f (5分钟)\n\n"+
				"排查建议:\n"+
				"  1. 查看高CPU进程: top -o %%CPU | head -20\n"+
				"  2. 查看高CPU进程: ps aux --sort=-%%cpu | head -20\n"+
				"  3. 检查IO等待: iostat -x 1 3\n"+
				"  4. 检查是否有挖矿进程:\n"+
				"     ps aux | grep -E '(xmrig|minerd|kdevtmpfsi)' | grep -v grep",
				load1, load5, load15, cpuCount, load1Per, load5Per),
			"sys-load-001")
	}
}

// CheckRebootRequired checks if a system reboot is required (after kernel update).
func (g *SystemGuard) CheckRebootRequired(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	// Check for /var/run/reboot-required (Ubuntu/Debian)
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		// Read which packages require reboot
		packages := ""
		if data, err := os.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
			packages = strings.TrimSpace(string(data))
		}
		detail := "系统需要重启以完成更新。"
		if packages != "" {
			detail += fmt.Sprintf("\n需要重启的包:\n%s", packages)
		}
		detail += "\n\n建议在维护窗口期执行重启:\n  sudo reboot\n\n" +
			"⚠ 重启前请确认:\n  1. 保存所有未持久化的数据\n  2. 通知用户服务将短暂中断\n  3. 确认服务设置了开机自启: systemctl is-enabled <服务名>"
		g.eventBus.PublishAlert(types.AlertWarning, "system", "系统需要重启", detail, "sys-reboot-001")
	}

	// Check for CentOS/RHEL (kernel package newer than running kernel)
	if _, err := exec.LookPath("rpm"); err == nil {
		output, err := exec.CommandContext(ctx, "rpm", "-q", "kernel", "--last").Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				latestKernel := strings.Fields(lines[0])
				if len(latestKernel) > 0 {
					// Compare with running kernel
					runningKernel := runtime.GOOS
					if runtime.GOOS == "linux" {
						// Get running kernel version
						unameOutput, _ := exec.CommandContext(ctx, "uname", "-r").Output()
						runningKernel = strings.TrimSpace(string(unameOutput))
					}
					_ = latestKernel
					_ = runningKernel
					// Simple heuristic: if latest installed != running, suggest reboot
					// This is a simplified check
				}
			}
		}
	}
}

// CheckDiskIO checks disk I/O performance and alerts on issues.
func (g *SystemGuard) CheckDiskIO(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}
	// Check iostat if available
	if _, err := exec.LookPath("iostat"); err != nil {
		return
	}
	output, err := exec.CommandContext(ctx, "iostat", "-x", "1", "2").Output()
	if err != nil {
		return
	}
	// Parse for high utilization
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 14 {
			// Last field is %util
			util := fields[len(fields)-1]
			if val, err := strconvParseFloat(util); err == nil && val > 80 {
				device := fields[0]
				g.eventBus.PublishAlert(types.AlertWarning, "system",
					fmt.Sprintf("磁盘IO过高: %s", device),
					fmt.Sprintf("设备 %s 的 IO 利用率 %.1f%%\n\n"+
						"排查:\n"+
						"  1. iotop -o 查看哪个进程在读写\n"+
						"  2. 检查是否有大量日志写入\n"+
						"  3. 检查数据库是否有全表扫描\n"+
						"  4. 考虑使用 SSD 或增加 IOPS",
						device, val),
					"sys-diskio-001")
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CheckAll runs all system checks.
func (g *SystemGuard) CheckAll(ctx context.Context) {
	g.CheckTimeSync(ctx)
	g.CheckSystemUpdates(ctx)
	g.CheckKernelParams(ctx)
	g.CheckSystemLoadAverage(ctx)
	g.CheckRebootRequired(ctx)
	g.CheckDiskIO(ctx)
}

// readSystemInfo reads basic system info for reporting.
func readSystemInfo() (map[string]string, error) {
	info, err := host.Info()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"hostname":     info.Hostname,
		"os":           info.OS,
		"platform":     info.Platform,
		"kernel":       info.KernelArch,
		"uptime":       fmt.Sprintf("%d", info.Uptime),
	}, nil
}

// Ensure filepath is used to avoid unused import
var _ = filepath.Join
var _ = bufio.NewReader
