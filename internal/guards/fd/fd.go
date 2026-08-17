package fd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
)

// FDGuard implements Module O: FD (File Descriptor) Guard
// Monitors per-process FD usage, system-wide FD limits, and provides actionable
// remediation suggestions (ulimit adjustment, identifying leaking processes).
//
// SAFETY: Only monitors and suggests. Never kills processes or modifies system limits.
type FDGuard struct {
	mu          sync.RWMutex
	eventBus    *eventbus.EventBus
	safety      *safety.SafetyManager
	softLimit   int
	hardLimit   int
	systemMaxFD int // /proc/sys/fs/file-max
	alertedPIDs map[int32]bool // dedup alerts for same PID
}

func New(bus *eventbus.EventBus) *FDGuard {
	g := &FDGuard{
		eventBus:    bus,
		softLimit:   1024,
		hardLimit:   4096,
		alertedPIDs: make(map[int32]bool),
	}
	g.detectUlimit()
	g.detectSystemMaxFD()
	return g
}

// SetSafetyManager 注入安全管理器，启用宝塔安全模式检查。
func (g *FDGuard) SetSafetyManager(sm *safety.SafetyManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.safety = sm
}

func (g *FDGuard) detectUlimit() {
	if runtime.GOOS == "windows" {
		return
	}
	out, err := exec.Command("sh", "-c", "ulimit -n").Output()
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			g.softLimit = n
		}
	}
	out, err = exec.Command("sh", "-c", "ulimit -Hn").Output()
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			g.hardLimit = n
		}
	}
}

// detectSystemMaxFD reads /proc/sys/fs/file-max (Linux system-wide FD limit).
func (g *FDGuard) detectSystemMaxFD() {
	if runtime.GOOS == "windows" {
		return
	}
	data, err := os.ReadFile("/proc/sys/fs/file-max")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			g.systemMaxFD = n
		}
	}
}

// procFDInfo holds per-process FD info for sorting/reporting.
type procFDInfo struct {
	PID    int32
	Name   string
	FDs    int32
	Limit  int
	Pct    float64
}

func (g *FDGuard) Check(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	g.mu.RLock()
	sm := g.safety
	softLimit := g.softLimit
	systemMaxFD := g.systemMaxFD
	g.mu.RUnlock()

	if softLimit == 0 {
		softLimit = 1024
	}

	// Check system-wide FD usage
	g.checkSystemFDUsage(ctx)

	// Collect top FD consumers
	var topProcs []procFDInfo

	if sm != nil && sm.IsBaotaSafeMode() {
		// 宝塔模式：轻量级 /proc 扫描
		topProcs = g.scanProcFDs(softLimit)
	} else {
		// 完整进程扫描
		procs, err := process.Processes()
		if err != nil {
			return
		}
		for _, p := range procs {
			fds, err := p.NumFDs()
			if err != nil {
				continue
			}
			name, _ := p.Name()
			if name == "" {
				name = fmt.Sprintf("PID-%d", p.Pid)
			}
			pct := float64(fds) / float64(softLimit) * 100
			topProcs = append(topProcs, procFDInfo{
				PID:   p.Pid,
				Name:  name,
				FDs:   fds,
				Limit: softLimit,
				Pct:   pct,
			})
		}
	}

	// Sort by FD count descending
	sort.Slice(topProcs, func(i, j int) bool {
		return topProcs[i].FDs > topProcs[j].FDs
	})

	// Reset alert dedup map each cycle
	g.mu.Lock()
	g.alertedPIDs = make(map[int32]bool)
	g.mu.Unlock()

	// Alert on top consumers (limit to top 5 to avoid alert flood)
	maxAlerts := 5
	alertCount := 0
	for _, pi := range topProcs {
		if alertCount >= maxAlerts {
			break
		}
		if pi.Pct > 95 {
			detail := g.buildFDDetail(pi, softLimit, systemMaxFD)
			g.eventBus.PublishAlert(types.AlertCritical, "fd",
				fmt.Sprintf("FD耗尽风险: %s (PID %d)", pi.Name, pi.PID),
				detail, "fd-exhaust-001")
			alertCount++
		} else if pi.Pct > 80 {
			detail := g.buildFDDetail(pi, softLimit, systemMaxFD)
			g.eventBus.PublishAlert(types.AlertWarning, "fd",
				fmt.Sprintf("FD使用过高: %s (PID %d)", pi.Name, pi.PID),
				detail, "fd-exhaust-001")
			alertCount++
		}
	}

	// If system-wide FD usage is high, add a summary alert
	if systemMaxFD > 0 {
		g.checkSystemFDUsageAlert(ctx, systemMaxFD)
	}

	// Check if ulimit is too low and suggest adjustment
	if softLimit < 65535 {
		g.eventBus.PublishAlert(types.AlertInfo, "fd",
			"FD 限制建议调高",
			fmt.Sprintf("当前软限制 %d 低于推荐值 65535。\n"+
				"建议修改 /etc/security/limits.conf:\n"+
				"  * soft nofile 65535\n"+
				"  * hard nofile 65535\n\n"+
				"对于 systemd 管理的服务，还需修改:\n"+
				"  sudo systemctl edit <服务名>\n"+
				"  [Service]\n"+
				"  LimitNOFILE=65535\n\n"+
				"修改后需重启相关服务生效。",
				softLimit),
			"fd-limit-low-001")
	}
}

// buildFDDetail builds a detailed alert message with actionable suggestions.
func (g *FDGuard) buildFDDetail(pi procFDInfo, softLimit, systemMaxFD int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("进程 %s (PID %d) 文件描述符使用 %d/%d (%.1f%%)\n\n",
		pi.Name, pi.PID, pi.FDs, pi.Limit, pi.Pct))

	// Identify what types of FDs are open
	if runtime.GOOS != "windows" {
		sb.WriteString("打开的文件描述符类型分析:\n")
		fdTypes := g.analyzeFDTypes(pi.PID)
		for fdType, count := range fdTypes {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", fdType, count))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("诊断建议:\n")
	// Common leak patterns
	if pi.Pct > 95 {
		sb.WriteString(fmt.Sprintf("  ⚠ FD 即将耗尽！进程 %s 可能存在 FD 泄漏。\n", pi.Name))
		sb.WriteString(fmt.Sprintf("  排查命令: ls -l /proc/%d/fd | wc -l\n", pi.PID))
		sb.WriteString(fmt.Sprintf("  查看打开的文件: ls -l /proc/%d/fd\n", pi.PID))
		sb.WriteString(fmt.Sprintf("  查看网络连接: lsof -p %d -i\n", pi.PID))
		sb.WriteString(fmt.Sprintf("  查看打开的文件类型: lsof -p %d | awk '{print $5}' | sort | uniq -c | sort -rn\n", pi.PID))
	} else {
		sb.WriteString(fmt.Sprintf("  进程 %s FD 使用率较高，建议关注。\n", pi.Name))
		sb.WriteString(fmt.Sprintf("  查看详情: lsof -p %d\n", pi.PID))
	}

	// Check if it's a known service
	sb.WriteString(g.getServiceSpecificAdvice(pi.Name, pi.Pct))

	return sb.String()
}

// analyzeFDTypes categorizes FDs by type (socket, file, pipe, etc.)
func (g *FDGuard) analyzeFDTypes(pid int32) map[string]int {
	result := make(map[string]int)
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return result
	}

	socketCount := 0
	fileCount := 0
	pipeCount := 0
	otherCount := 0

	for _, entry := range entries {
		linkPath := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			otherCount++
			continue
		}
		if strings.HasPrefix(target, "socket:") {
			socketCount++
		} else if strings.HasPrefix(target, "pipe:") {
			pipeCount++
		} else if strings.HasPrefix(target, "/") {
			fileCount++
		} else {
			otherCount++
		}
	}

	if socketCount > 0 {
		result["socket (网络连接)"] = socketCount
	}
	if fileCount > 0 {
		result["file (打开的文件)"] = fileCount
	}
	if pipeCount > 0 {
		result["pipe (管道)"] = pipeCount
	}
	if otherCount > 0 {
		result["other (其他)"] = otherCount
	}
	return result
}

// getServiceSpecificAdvice provides targeted advice for known services.
func (g *FDGuard) getServiceSpecificAdvice(name string, pct float64) string {
	lowerName := strings.ToLower(name)
	var sb strings.Builder

	switch {
	case strings.Contains(lowerName, "nginx"):
		sb.WriteString("  Nginx: 检查 worker_connections 配置，可能需要调高:\n")
		sb.WriteString("    nginx -t && nginx -s reload  (修改 nginx.conf 后)\n")
	case strings.Contains(lowerName, "mysql") || strings.Contains(lowerName, "mysqld"):
		sb.WriteString("  MySQL: 检查 table_open_cache 和 max_connections:\n")
		sb.WriteString("    SHOW VARIABLES LIKE 'table_open_cache';\n")
		sb.WriteString("    SHOW VARIABLES LIKE 'max_connections';\n")
		sb.WriteString("    SHOW STATUS LIKE 'Open_files';\n")
	case strings.Contains(lowerName, "redis"):
		sb.WriteString("  Redis: 检查 maxclients 配置:\n")
		sb.WriteString("    redis-cli CONFIG GET maxclients\n")
	case strings.Contains(lowerName, "java"):
		sb.WriteString("  Java: 可能存在连接泄漏，建议检查:\n")
		sb.WriteString("    jstack <PID> 查看线程堆栈\n")
		sb.WriteString("    检查连接池配置 (HikariCP, Druid等)\n")
	case strings.Contains(lowerName, "node"):
		sb.WriteString("  Node.js: 可能存在连接泄漏，建议检查:\n")
		sb.WriteString("    使用 --inspect 调试\n")
		sb.WriteString("    检查 HTTP Agent 的 keepAlive 配置\n")
	}
	return sb.String()
}

// scanProcFDs is the lightweight /proc-based FD scanner for BaoTa mode.
func (g *FDGuard) scanProcFDs(softLimit int) []procFDInfo {
	var result []procFDInfo
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		fds := int32(len(fdEntries))

		// Read process name
		name := g.readProcName(int32(pid))
		pct := float64(fds) / float64(softLimit) * 100

		result = append(result, procFDInfo{
			PID:   int32(pid),
			Name:  name,
			FDs:   fds,
			Limit: softLimit,
			Pct:   pct,
		})
	}
	return result
}

// readProcName reads /proc/PID/comm to get the process name.
func (g *FDGuard) readProcName(pid int32) string {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return fmt.Sprintf("PID-%d", pid)
	}
	return strings.TrimSpace(string(data))
}

// checkSystemFDUsage reads /proc/sys/fs/file-nr to check system-wide FD usage.
func (g *FDGuard) checkSystemFDUsage(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}
	// /proc/sys/fs/file-nr format: "allocated  unused  max"
	data, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return
	}
	allocated, _ := strconv.Atoi(fields[0])
	maxFD, _ := strconv.Atoi(fields[2])
	if maxFD == 0 {
		return
	}
	usagePct := float64(allocated) / float64(maxFD) * 100
	if usagePct > 80 {
		g.eventBus.PublishAlert(types.AlertWarning, "fd",
			"系统级 FD 使用率过高",
			fmt.Sprintf("系统文件描述符使用 %d/%d (%.1f%%)\n"+
				"建议调高 /proc/sys/fs/file-max:\n"+
				"  sudo sysctl -w fs.file-max=2097152\n"+
				"  永久生效: echo 'fs.file-max=2097152' >> /etc/sysctl.conf && sudo sysctl -p",
				allocated, maxFD, usagePct),
			"fd-system-exhaust-001")
	}
}

// checkSystemFDUsageAlert is an alias for compatibility.
func (g *FDGuard) checkSystemFDUsageAlert(ctx context.Context, systemMaxFD int) {
	g.checkSystemFDUsage(ctx)
}

// GetStatus returns the current FD guard status.
func (g *FDGuard) GetStatus() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return map[string]interface{}{
		"soft_limit":     g.softLimit,
		"hard_limit":     g.hardLimit,
		"system_max_fd":  g.systemMaxFD,
		"alerted_pids":   len(g.alertedPIDs),
	}
}
