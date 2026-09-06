package resource

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ResourceGuard implements Module A: Resource Guard
// Covers: CPU protection, memory leak detection, disk space guard,
// OOM prevention, zombie process cleanup, GPU guard
type ResourceGuard struct {
	mu            sync.RWMutex
	eventBus      *eventbus.EventBus
	storage       *storage.Storage
	safety        *safety.SafetyManager
	cpuThreshold  float64 // CPU alert threshold
	cpuDuration   time.Duration
	memThreshold  float64 // memory leak threshold (percentage growth per hour)
	diskWarning   float64 // disk warning threshold
	diskCritical  float64 // disk critical threshold
	diskEmergency float64 // disk emergency threshold
	oomThreshold  float64 // available memory threshold
	swapThreshold float64 // swap usage threshold
	zombieLimit   int     // zombie count limit
	gpuEnabled    bool

	// Memory tracking for leak detection
	memHistory map[int32][]memSnapshot // PID -> memory samples

	// CPU 误杀防护跟踪器（连续3次触发才Kill）
	cpuTracker *CPUTriggerTracker
}

type memSnapshot struct {
	rss       uint64
	timestamp time.Time
}

// New creates a new ResourceGuard.
func New(bus *eventbus.EventBus, store *storage.Storage, sm *safety.SafetyManager) *ResourceGuard {
	return &ResourceGuard{
		eventBus:      bus,
		storage:       store,
		safety:        sm,
		cpuThreshold:  80,
		cpuDuration:   60 * time.Second,
		memThreshold:  150, // 150% growth in 1 hour
		diskWarning:   80,
		diskCritical:  90,
		diskEmergency: 95,
		oomThreshold:  3,  // 3% available — very conservative, only trigger in real emergencies
		swapThreshold: 95, // 95% swap used — only alert when swap is nearly full
		zombieLimit:   10,
		gpuEnabled:    false,
		memHistory:    make(map[int32][]memSnapshot),
		cpuTracker:    NewCPUTriggerTracker(bus, sm),
	}
}

// Check performs resource guard checks on the system.
func (g *ResourceGuard) Check(ctx context.Context, sysInfo *types.SystemInfo, procs []types.ProcessInfo) {
	var wg sync.WaitGroup

	// A1: CPU protection
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkCPU(procs)
	}()

	// A2: Memory leak detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkMemoryLeaks(procs)
	}()

	// A3: Disk space guard
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkDiskSpace(sysInfo)
	}()

	// A4: OOM prevention
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkOOM(sysInfo)
	}()

	// A5: Zombie process cleanup
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkZombies(sysInfo)
	}()

	// A6: Process explosion detection (fork bomb / runaway process multiplication)
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkProcessExplosion(procs)
	}()

	wg.Wait()
}

// checkCPU checks for processes with high CPU usage.
// 使用 CPUTriggerTracker 实现误杀防护：连续3次触发才Kill。
// 修复说明：原实现拿到 toKill 列表后只发布"执行Kill"的告警，
// 从未真正终止进程——README 承诺的"降权→SIGTERM→SIGKILL"自动处置实际不生效。
// 现在按 killLargestProcess 同款安全链执行：
// 安全总闸 → 硬白名单 → 本地关键进程表 → 宝塔深度保护 → CheckKillPermission（预算/熔断）。
func (g *ResourceGuard) checkCPU(procs []types.ProcessInfo) {
	toKill := g.cpuTracker.CheckCPUWithProtection(nil, procs, g.cpuThreshold)
	if len(toKill) == 0 {
		// 无触发时顺带清理过期状态，防止 states map 随 PID 回收无限增长
		g.cpuTracker.Cleanup()
		return
	}
	procByName := make(map[int32]types.ProcessInfo, len(procs))
	for _, p := range procs {
		procByName[p.PID] = p
	}
	for _, pid := range toKill {
		p, ok := procByName[pid]
		if !ok {
			continue
		}
		g.terminateRunawayProcess(p)
	}
}

// terminateRunawayProcess 终止 CPU 失控进程，完整走一遍安全检查链。
// 返回是否执行了终止动作。
func (g *ResourceGuard) terminateRunawayProcess(p types.ProcessInfo) bool {
	if g.safety == nil {
		return false
	}
	// 危险动作总闸：降频/最小/生存/紧急停止/维护窗口期间不动手
	if g.safety.ShouldPauseDangerousActions() {
		g.eventBus.PublishAlert(types.AlertError, "resource",
			fmt.Sprintf("CPU超限待人工处理: %s (PID %d)", p.Name, p.PID),
			fmt.Sprintf("进程 %s (PID %d) 连续 CPU 超限，但当前处于受限模式，未自动终止。请手动检查", p.Name, p.PID),
			"cpu-protect-002")
		return false
	}
	// 硬白名单 + 本地关键进程表（双保险）
	if g.safety.IsWhitelisted(p.Name) || isSystemCritical(p.Name) {
		return false
	}
	// 宝塔深度保护：python 等泛化进程名需读 /proc 精确归属
	if procInfo := safety.ReadProcInfo(p.PID); procInfo != nil && safety.IsBaotaProtectedProcess(procInfo) {
		return false
	}
	// 预算 / 熔断 / 模式终检（内部会再次校验紧急停止与 Kill 预算）
	if err := g.safety.CheckKillPermission(p.Name, p.PID); err != nil {
		g.eventBus.PublishAlert(types.AlertWarning, "resource",
			fmt.Sprintf("CPU超限Kill被安全策略拦截: %s (PID %d)", p.Name, p.PID),
			fmt.Sprintf("进程连续 CPU 超限，但被安全策略拦截：%v。请手动确认后处理", err),
			"cpu-protect-002")
		return false
	}

	proc := process.Process{Pid: p.PID}
	killErr := proc.Terminate()
	success := killErr == nil
	g.safety.RecordKill(p.PID, p.Name, success)

	if success {
		g.eventBus.PublishAlert(types.AlertError, "resource",
			fmt.Sprintf("CPU超限Kill: %s (PID %d)", p.Name, p.PID),
			fmt.Sprintf("进程 %s (PID %d) 连续 %d 次 CPU 超限（当前 %.1f%%），已自动终止以保护系统。如为误杀请将其加入白名单",
				p.Name, p.PID, cpuTriggerThreshold, p.CPUPercent),
			"cpu-protect-002")
	} else {
		g.eventBus.PublishAlert(types.AlertWarning, "resource",
			fmt.Sprintf("CPU超限Kill失败: %s (PID %d)", p.Name, p.PID),
			fmt.Sprintf("终止进程失败: %v", killErr),
			"cpu-protect-002")
	}
	g.cpuTracker.Reset(p.PID)
	return success
}

// checkMemoryLeaks detects memory leak patterns.
func (g *ResourceGuard) checkMemoryLeaks(procs []types.ProcessInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	for _, p := range procs {
		if p.IsSystem || p.RSS == 0 {
			continue
		}

		// Record current memory
		g.memHistory[p.PID] = append(g.memHistory[p.PID], memSnapshot{
			rss:       p.RSS,
			timestamp: now,
		})

		// Trim old samples (>1 hour)
		var recent []memSnapshot
		for _, s := range g.memHistory[p.PID] {
			if s.timestamp.After(oneHourAgo) {
				recent = append(recent, s)
			}
		}
		if len(recent) == 0 {
			// 该 PID 一小时内已无有效样本——删除条目本身。
			// 原实现只裁剪样本不删 key，PID 不断回收导致 memHistory 无限增长。
			delete(g.memHistory, p.PID)
			continue
		}
		g.memHistory[p.PID] = recent

		// Check for leak: if we have samples from an hour ago, compare
		if len(recent) >= 2 {
			oldest := recent[0]
			current := recent[len(recent)-1]
			if oldest.rss > 10*1024*1024 && current.rss > oldest.rss {
				// Only check if oldest > 10MB and memory actually increased
				growthPercent := float64(current.rss-oldest.rss) / float64(oldest.rss) * 100
				if growthPercent > g.memThreshold {
					g.eventBus.PublishAlert(types.AlertWarning, "resource",
						fmt.Sprintf("内存泄漏: %s (PID %d)", p.Name, p.PID),
						fmt.Sprintf("进程 %s 内存1h内增长 %.1f%%，从 %.0fMB 到 %.0fMB",
							p.Name, growthPercent,
							float64(oldest.rss)/1024/1024,
							float64(current.rss)/1024/1024),
						"mem-leak-001")
				}
			}
			// If current <= oldest, memory decreased or stayed same — not a leak
		}

		// Check if process uses > 30% of system memory
		// (sysInfo is not passed here, but we can check RSS against typical thresholds)
		if p.RSS > 25*1024*1024*1024 { // > 25GB
			g.eventBus.PublishAlert(types.AlertError, "resource",
				fmt.Sprintf("高内存使用: %s (PID %d)", p.Name, p.PID),
				fmt.Sprintf("进程 %s 内存使用 %.2fGB", p.Name, float64(p.RSS)/1024/1024/1024),
				"mem-leak-001")
		}
	}
}

// checkDiskSpace checks disk usage and cleans up when critical.
// 安全策略 v2：多层精确防护，不再一刀切屏蔽 /tmp、/www。
// 清理级别：Warning(80%) → 告警+列出 Top 大文件
//
//	Critical(90%) → 预防性清理（7天以上的旧日志）
//	Emergency(95%) → 紧急清理（30天以上的旧日志+临时文件+包管理器缓存）
func (g *ResourceGuard) checkDiskSpace(sysInfo *types.SystemInfo) {
	for _, disk := range sysInfo.Disks {
		if disk.UsedPercent >= g.diskEmergency {
			g.eventBus.PublishAlert(types.AlertCritical, "resource",
				fmt.Sprintf("磁盘紧急: %s (%.1f%%)", disk.MountPoint, disk.UsedPercent),
				fmt.Sprintf("磁盘 %s 使用率 %.1f%%，正在执行紧急清理", disk.MountPoint, disk.UsedPercent),
				"disk-space-001")
			g.emergencyDiskCleanup(disk.MountPoint)
			// 紧急清理后再检查大文件并报告
			g.reportBigFiles(disk.MountPoint)
		} else if disk.UsedPercent >= g.diskCritical {
			g.eventBus.PublishAlert(types.AlertError, "resource",
				fmt.Sprintf("磁盘告警: %s (%.1f%%)", disk.MountPoint, disk.UsedPercent),
				fmt.Sprintf("磁盘 %s 使用率 %.1f%%，正在执行预防性清理", disk.MountPoint, disk.UsedPercent),
				"disk-space-001")
			g.preventiveDiskCleanup(disk.MountPoint)
		} else if disk.UsedPercent >= g.diskWarning {
			// 提醒级别：查找并列出 Top 大文件，供用户参考
			bigFiles := g.findBigFiles(disk.MountPoint, 10)
			detail := fmt.Sprintf("磁盘 %s 使用率 %.1f%%，已超过提醒阈值 %.0f%%", disk.MountPoint, disk.UsedPercent, g.diskWarning)
			if len(bigFiles) > 0 {
				detail += "\n占用最大的文件:"
				for i, bf := range bigFiles {
					if i >= 5 { // 只显示 Top 5
						detail += fmt.Sprintf("\n  ...等共 %d 个大文件", len(bigFiles))
						break
					}
					detail += fmt.Sprintf("\n  %s (%.1fMB)", bf.Path, float64(bf.Size)/1024/1024)
				}
			}
			g.eventBus.PublishAlert(types.AlertWarning, "resource",
				fmt.Sprintf("磁盘提醒: %s (%.1f%%)", disk.MountPoint, disk.UsedPercent),
				detail,
				"disk-space-001")
		}
	}
}

// bigFileInfo 大文件信息
type bigFileInfo struct {
	Path string
	Size int64
}

// findBigFiles 查找磁盘上最大的 N 个文件（限制扫描深度为 3 层，避免全盘扫描影响性能）
func (g *ResourceGuard) findBigFiles(mountPoint string, topN int) []bigFileInfo {
	var files []bigFileInfo

	// 只扫描常见日志/临时目录，限制深度为 3 层
	searchDirs := []string{"/var/log", "/tmp", "/var/cache"}
	if runtime.GOOS == "windows" {
		searchDirs = []string{`C:\Windows\Temp`, `C:\Users\Public`}
	}

	// 跳过的子目录名（避免扫描 node_modules/.git 等大目录）
	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "vendor": true,
		".cache": true, "__pycache__": true, ".npm": true,
	}

	for _, dir := range searchDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// 限制扫描深度：最多 3 层
				depth := strings.Count(strings.TrimPrefix(path, dir), string(filepath.Separator))
				if depth > 3 {
					return filepath.SkipDir
				}
				// 跳过已知的深层目录
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Size() > 100*1024*1024 { // > 100MB
				files = append(files, bigFileInfo{Path: path, Size: info.Size()})
			}
			return nil
		})
	}

	// 按大小降序排序
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].Size > files[i].Size {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	if len(files) > topN {
		files = files[:topN]
	}
	return files
}

// preventiveDiskCleanup 预防性清理（清理 7 天以上的旧日志）
func (g *ResourceGuard) preventiveDiskCleanup(mountPoint string) {
	if runtime.GOOS == "windows" {
		filepath.Walk(`C:\Windows\Temp`, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if winFileCleanable(info, 3*24*time.Hour) {
				os.Remove(path)
			}
			return nil
		})
		return
	}

	freed := int64(0)
	cutoff := time.Now().AddDate(0, 0, -7) // 7 天以上

	for _, dir := range safety.CleanupWhitelist {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !safety.IsFileSafeForCleanup(path) {
				return nil
			}
			if safety.IsFileBeingWritten(path) {
				return nil
			}
			if info.ModTime().Before(cutoff) {
				size := info.Size()
				if os.Remove(path) == nil {
					freed += size
				}
			}
			return nil
		})
	}

	if freed > 0 {
		g.eventBus.PublishAlert(types.AlertInfo, "resource",
			fmt.Sprintf("预防性磁盘清理完成: %s", mountPoint),
			fmt.Sprintf("已释放 %.2fMB 磁盘空间（清理7天以上的旧日志/压缩文件）", float64(freed)/1024/1024),
			"disk-cleanup-001")
	}
}

// reportBigFiles 紧急清理后报告仍存在的大文件
func (g *ResourceGuard) reportBigFiles(mountPoint string) {
	bigFiles := g.findBigFiles(mountPoint, 5)
	if len(bigFiles) > 0 {
		detail := "紧急清理后仍存在的大文件（需手动处理）:"
		for _, bf := range bigFiles {
			detail += fmt.Sprintf("\n  %s (%.1fMB)", bf.Path, float64(bf.Size)/1024/1024)
		}
		g.eventBus.PublishAlert(types.AlertWarning, "resource",
			fmt.Sprintf("大文件报告: %s", mountPoint),
			detail,
			"disk-bigfile-001")
	}
}

// emergencyDiskCleanup cleans old compressed log files when disk is critical.
// 安全策略 v2：多层精确防护，不再一刀切屏蔽 /tmp、/www。
// 6 层安全检查：白名单目录 → 黑名单路径 → 受保护文件名模式 → 禁止扩展名 → 允许扩展名 → 活跃写入检测。
// 只清理 30 天以上的旧轮转/压缩日志文件（.gz/.1/.old/.bz2/.xz/.zip）。
func (g *ResourceGuard) emergencyDiskCleanup(mountPoint string) {
	if runtime.GOOS == "windows" {
		// Windows: only clean Windows Temp files older than 7 days
		filepath.Walk(`C:\Windows\Temp`, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if winFileCleanable(info, 7*24*time.Hour) {
				os.Remove(path)
			}
			return nil
		})
		return
	}

	// Linux: 分层精确清理
	freed := int64(0)
	cutoff := time.Now().AddDate(0, 0, -30)

	for _, dir := range safety.CleanupWhitelist {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// 综合安全检查：黑名单路径 + 受保护模式 + 禁止扩展名 + 允许扩展名
			if !safety.IsFileSafeForCleanup(path) {
				return nil
			}

			// 安全检查：文件正在被写入
			if safety.IsFileBeingWritten(path) {
				return nil
			}

			// 检查文件年龄（>30 天）
			if info.ModTime().Before(cutoff) {
				size := info.Size()
				if os.Remove(path) == nil {
					freed += size
				}
			}
			return nil
		})
	}

	if freed > 0 {
		g.eventBus.PublishAlert(types.AlertInfo, "resource",
			fmt.Sprintf("磁盘清理完成: %s", mountPoint),
			fmt.Sprintf("已释放 %.2fMB 磁盘空间（清理30天以上的旧日志/压缩文件，保护数据库/配置/网站源码/会话文件）", float64(freed)/1024/1024),
			"disk-cleanup-001")
	}
}

// checkOOM checks for OOM risk and takes action.
// SAFETY: When memory is critical, kills the largest non-whitelisted process.
// Web servers, databases, BaoTa, PHP, SSH etc. are in the hard whitelist
// and will NEVER be killed. Only kills user applications or suspicious processes
// (e.g. memory leaks, runaway scripts, miners) that are consuming excessive memory.
// 宝塔进程由 killLargestProcess 内的精确归属识别兜底（含 python 二次确认），
// 不依赖模式开关 —— 宝塔环境下的 OOM 保护对非宝塔进程正常生效。
func (g *ResourceGuard) checkOOM(sysInfo *types.SystemInfo) {
	memAvailPercent := 100 - sysInfo.MemPercent
	if memAvailPercent < g.oomThreshold {
		g.eventBus.PublishAlert(types.AlertCritical, "resource",
			"OOM风险",
			fmt.Sprintf("可用内存仅 %.1f%%（阈值 %.0f%%），内存总量 %.2fGB，可用 %.2fGB，正在尝试释放内存",
				memAvailPercent, g.oomThreshold,
				float64(sysInfo.MemTotal)/1024/1024/1024,
				float64(sysInfo.MemAvailable)/1024/1024/1024),
			"oom-prevent-001")
		// Kill the largest non-whitelisted process to free memory
		g.killLargestProcess()
	}

	if sysInfo.SwapPercent > g.swapThreshold {
		g.eventBus.PublishAlert(types.AlertError, "resource",
			"Swap使用过高",
			fmt.Sprintf("Swap 使用率 %.1f%%（阈值 %.0f%%）", sysInfo.SwapPercent, g.swapThreshold),
			"oom-prevent-001")
	}
}

// killLargestProcess finds and kills the largest non-whitelisted process.
// SAFETY: Uses safety.CheckKillPermission which checks the hard whitelist.
// Web servers (nginx, IIS, Apache), databases (MySQL, PostgreSQL, Redis),
// BaoTa panel, PHP-FPM, SSH, etc. are in the hard whitelist and will NEVER be killed.
// Only kills user applications or suspicious processes consuming excessive memory.
//
// 精确归属识别：即使进程名不在白名单中（如 python/python3），
// 也会通过 ReadProcInfo + IsBaotaProtectedProcess 二次确认是否为宝塔保护进程。
// 该保护无条件生效，不依赖任何模式开关 —— 宝塔进程永远不被选中，
// 非宝塔的高内存进程在任何环境下都受 OOM 保护管控。
func (g *ResourceGuard) killLargestProcess() {
	if g.safety == nil {
		return
	}

	procs, err := process.Processes()
	if err != nil {
		return
	}

	var largestPID int32 = 0
	var largestRSS uint64 = 0
	var largestName string

	// 同时追踪最大的宝塔保护进程 —— 若罪魁祸首是面板自身，
	// 不能 Kill，需升级为优雅重启释压（见 relieveBaotaPanel）。
	var baotaPID int32 = 0
	var baotaRSS uint64 = 0
	var baotaName string

	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		memInfo, err := p.MemoryInfo()
		if err != nil {
			continue
		}
		// 深度检查：读取 /proc 信息，匹配宝塔白名单（comm/cmdline/exe/cwd/父进程）
		// 这一步确保 python/python3 运行的宝塔面板进程不会被误杀
		if procInfo := safety.ReadProcInfo(p.Pid); procInfo != nil {
			if safety.IsBaotaProtectedProcess(procInfo) {
				if memInfo.RSS > baotaRSS {
					baotaRSS = memInfo.RSS
					baotaPID = p.Pid
					baotaName = name
				}
				continue
			}
		}
		// Check hard whitelist — nginx, mysql, bt-panel, etc. will NEVER be killed
		if g.safety.IsWhitelisted(name) {
			continue
		}
		// Also check our local whitelist (redundant but safe)
		if isSystemCritical(name) {
			continue
		}
		if memInfo.RSS > largestRSS {
			largestRSS = memInfo.RSS
			largestPID = p.Pid
			largestName = name
		}
	}

	// 决策：谁是大头就处置谁，避免"杀小放大"
	// 1) 可杀进程是大头 → 正常 OOM Kill
	// 2) 宝塔面板进程是大头且已失控（RSS >= 512MB）→ 优雅重启面板释压
	baotaDominant := baotaPID > 0 && baotaRSS >= baotaReliefMinRSS && baotaRSS >= largestRSS

	if largestPID > 0 && largestRSS > 100*1024*1024 && !baotaDominant { // > 100MB
		// 维护窗口/远程暂停期间不做 OOM Kill——运维正在变更时杀进程极易雪上加霜
		if g.safety.ShouldPauseDangerousActions() {
			g.eventBus.PublishAlert(types.AlertWarning, "resource",
				"OOM防护: 处于维护窗口/暂停期，跳过自动终止",
				fmt.Sprintf("内存严重不足（最大非白名单进程 %s PID %d，RSS %.0fMB），但当前处于维护窗口或远程暂停期，不自动终止。请尽快手动处理",
					largestName, largestPID, float64(largestRSS)/1024/1024),
				"oom-kill-paused-001")
			return
		}
		// Double-check with safety manager
		if err := g.safety.CheckKillPermission(largestName, largestPID); err != nil {
			g.eventBus.PublishAlert(types.AlertWarning, "resource",
				"OOM防护: 未找到可安全终止的进程",
				fmt.Sprintf("内存严重不足，但所有高内存进程都在白名单中（nginx/mysql/bt-panel等），无法自动终止。请手动检查进程列表"),
				"oom-kill-001")
			return
		}

		// 终止前再次深度检查宝塔保护进程（三重保险）
		if procInfo := safety.ReadProcInfo(largestPID); procInfo != nil {
			if safety.IsBaotaProtectedProcess(procInfo) {
				g.relieveBaotaPanel(largestName, largestPID, largestRSS)
				return
			}
		}

		p := process.Process{Pid: largestPID}
		p.Terminate()
		// 记账：不记录则 Kill 预算/最小间隔/熔断器/自动急停对 OOM kill 全部失明，
		// 被 kill 后又被拉起再膨胀的进程会形成无限 OOM kill 循环
		g.safety.RecordKill(largestPID, largestName, true)

		g.eventBus.PublishAlert(types.AlertCritical, "resource",
			fmt.Sprintf("OOM防护: 已终止进程 %s (PID %d)", largestName, largestPID),
			fmt.Sprintf("内存严重不足，已终止占用内存最多的非关键进程 %s (PID %d)，释放 %.2fGB 内存。如需恢复，请手动重启该服务",
				largestName, largestPID, float64(largestRSS)/1024/1024/1024),
			"oom-kill-001")
		return
	}

	// 无可杀对象，或宝塔面板进程才是失控大头 → 升级为面板释压重启
	if baotaPID > 0 && baotaRSS >= baotaReliefMinRSS {
		g.relieveBaotaPanel(baotaName, baotaPID, baotaRSS)
	}
}

// baotaReliefMinRSS 宝塔面板进程释压重启的内存阈值。
// 宝塔面板 Python 进程正常 RSS 约 100~400MB，超过 512MB 视为失控。
const baotaReliefMinRSS = 512 * 1024 * 1024

// relieveBaotaPanel 宝塔面板进程失控时的止损动作：
// 通过 /etc/init.d/bt restart 优雅重启面板释放资源 —— 而非 Kill
// （Kill 面板 Python 会导致面板硬崩、SQLite 写入中断）。
// 受冷却期 + 每日预算约束（PanelReliefController），超限只告警：
// 面板反复失控属于结构性问题（插件泄漏/版本 bug），重启无意义，需人工排查。
func (g *ResourceGuard) relieveBaotaPanel(name string, pid int32, rss uint64) {
	rssGB := float64(rss) / 1024 / 1024 / 1024

	// 危险动作总闸：降频/最小/生存/紧急停止/维护窗口期间不自动重启面板
	if g.safety.ShouldPauseDangerousActions() {
		g.eventBus.PublishAlert(types.AlertCritical, "resource",
			"宝塔面板进程失控（需人工处理）",
			fmt.Sprintf("宝塔保护进程 %s (PID %d) 占用 %.2fGB 内存，系统内存危急。当前处于受限模式，未自动重启面板。请手动执行: /etc/init.d/bt restart",
				name, pid, rssGB),
			"baota-relief-001")
		return
	}

	// 冷却期 + 每日预算检查
	if reason, ok := g.safety.PanelRelief().CanRelieve(); !ok {
		g.eventBus.PublishAlert(types.AlertCritical, "resource",
			"宝塔面板进程失控（释压重启已暂停）",
			fmt.Sprintf("宝塔保护进程 %s (PID %d) 占用 %.2fGB 内存，系统内存危急。%s。请人工排查: bt 16 修复面板 或 /etc/init.d/bt restart",
				name, pid, rssGB, reason),
			"baota-relief-001")
		return
	}

	g.eventBus.PublishAlert(types.AlertWarning, "resource",
		"宝塔面板进程失控，正在优雅重启释压",
		fmt.Sprintf("宝塔保护进程 %s (PID %d) 占用 %.2fGB 内存，系统内存危急。通过 /etc/init.d/bt restart 优雅重启面板（不 Kill 进程，避免面板硬崩）...",
			name, pid, rssGB),
		"baota-relief-001")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	output, err := safety.RestartBaotaPanelForRelief(ctx)
	cancel()
	g.safety.PanelRelief().RecordRelief()

	if err != nil {
		g.eventBus.PublishAlert(types.AlertFatal, "resource",
			"宝塔面板释压重启失败",
			fmt.Sprintf("宝塔保护进程 %s (PID %d) 占用 %.2fGB 内存。优雅重启失败: %v\n输出: %s\n请手动执行: /etc/init.d/bt restart",
				name, pid, rssGB, err, output),
			"baota-relief-001")
		return
	}

	g.eventBus.PublishAlert(types.AlertInfo, "resource",
		"宝塔面板已优雅重启释压",
		fmt.Sprintf("宝塔保护进程 %s (PID %d) 原占用 %.2fGB 内存，面板已通过 /etc/init.d/bt restart 完成优雅重启。若面板反复失控，建议排查最近安装的插件（bt 16 修复面板）",
			name, pid, rssGB),
		"baota-relief-001")
}

// isSystemCritical checks if a process name is a critical system process that should never be killed.
func isSystemCritical(name string) bool {
	critical := map[string]bool{
		// Linux system
		"systemd": true, "init": true, "kernel_task": true,
		"sshd": true, "systemd-journald": true, "systemd-logind": true,
		"dbus": true, "rsyslogd": true, "cron": true,
		// Windows
		"System": true, "smss.exe": true, "csrss.exe": true,
		"wininit.exe": true, "services.exe": true, "lsass.exe": true,
		"svchost.exe": true, "winlogon.exe": true,
		// Database (don't kill, restart instead)
		"mysqld": true, "postgres": true, "redis-server": true,
		"mariadbd": true, "mongod": true,
		// Web servers (never kill — would take down all websites)
		"nginx": true, "nginx.exe": true,
		"httpd": true, "apache2": true,
		"caddy": true,
		// PHP (BaoTa/Aapanel PHP workers)
		"php-fpm": true, "php-cgi": true, "php": true,
		"php-fpm-74": true, "php-fpm-80": true, "php-fpm-81": true,
		"php-fpm-82": true, "php-fpm-83": true,
		// BaoTa panel processes
		"bt-panel": true, "bt": true, "btpanel": true,
		"panelSite.py": true,
		"pure-ftpd":    true, "pure-ftpd.exe": true,
		"proftpd": true,
		// Mail/DNS
		"named": true, "bind9": true,
		"postfix": true, "dovecot": true,
		"sendmail": true,
		// ServerGuard itself
		"serverguard-agent": true, "serverguard-agent.exe": true,
	}
	return critical[name]
}

// checkZombies 检测僵尸进程并尝试自动回收。
// 僵尸进程占用 PID 和进程表条目，过多的僵尸会导致无法启动新进程。
// 回收策略：1.查找僵尸进程的父进程 2.向父进程发送 SIGCHLD 通知其回收 3.如果父进程不回收，考虑杀掉父进程（仅非关键进程）
func (g *ResourceGuard) checkZombies(sysInfo *types.SystemInfo) {
	if sysInfo.ZombieCount <= g.zombieLimit {
		return
	}

	g.eventBus.PublishAlert(types.AlertWarning, "resource",
		"僵尸进程过多",
		fmt.Sprintf("检测到 %d 个僵尸进程（阈值 %d），正在自动回收...", sysInfo.ZombieCount, g.zombieLimit),
		"zombie-cleanup-001")

	if runtime.GOOS == "windows" {
		// Windows 没有传统意义的僵尸进程，跳过
		return
	}

	// 查找僵尸进程及其父进程
	reaped := 0
	failed := 0

	// 使用 ps 查找僵尸进程
	cmd := exec.Command("ps", "-eo", "pid,ppid,stat,comm")
	output, err := cmd.Output()
	if err != nil {
		g.eventBus.PublishAlert(types.AlertError, "resource",
			"僵尸进程回收失败",
			fmt.Sprintf("无法执行 ps 命令: %v", err),
			"zombie-cleanup-002")
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { // 跳过标题行
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		stat := fields[2]
		if !strings.Contains(stat, "Z") {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		comm := fields[3]
		_ = pid // 保留 PID 信息用于日志

		// 向父进程发送 SIGCHLD，通知其回收子进程
		if ppid > 1 {
			killErr := exec.Command("kill", "-CHLD", strconv.Itoa(ppid)).Run()
			if killErr == nil {
				reaped++
			} else {
				failed++
			}
		}

		// 如果父进程是 init (PID 1)，僵尸应该已被自动回收
		// 如果仍然存在，记录日志
		_ = comm // 保留进程名用于日志
	}

	if reaped > 0 {
		g.eventBus.PublishAlert(types.AlertInfo, "resource",
			"僵尸进程回收完成",
			fmt.Sprintf("已向 %d 个僵尸进程的父进程发送回收信号，成功 %d 个，失败 %d 个", reaped+failed, reaped, failed),
			"zombie-cleanup-003")
	}
}

// checkGPU checks GPU status (if enabled).
func (g *ResourceGuard) checkGPU() {
	if !g.gpuEnabled {
		return
	}
	// GPU monitoring would use nvidia-smi
	// Placeholder for GPU guard implementation
}

// GetMemoryHistory returns memory history for a process.
func (g *ResourceGuard) GetMemoryHistory(pid int32) []memSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.memHistory[pid]
}

// SetCPUThreshold updates the CPU alert threshold.
func (g *ResourceGuard) SetCPUThreshold(threshold float64, duration time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cpuThreshold = threshold
	g.cpuDuration = duration
}

// SetDiskThresholds updates the disk alert thresholds.
func (g *ResourceGuard) SetDiskThresholds(warning, critical, emergency float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.diskWarning = warning
	g.diskCritical = critical
	g.diskEmergency = emergency
}

// ============================================================
// A6: 进程爆炸检测（Process Explosion / Fork Bomb）
// 检测同一程序产生大量进程实例的场景：
//   - Python 脚本无限循环 fork/subprocess
//   - 程序不断重启产生大量僵尸子进程
//   - 恶意 fork bomb
// 当同一进程名/命令行出现超过阈值时，自动终止多余的进程实例
// ============================================================

// procExplosionThreshold 同一程序允许的最大并发进程数
const procExplosionThreshold = 30

// procExplosionKillCount 检测到进程爆炸时，保留多少个进程不杀（保留最早启动的）
const procExplosionKeepAlive = 3

// checkProcessExplosion 检测进程爆炸：同一程序产生大量进程实例
func (g *ResourceGuard) checkProcessExplosion(procs []types.ProcessInfo) {
	// 按进程名+命令行分组统计
	type procGroup struct {
		name    string
		cmdline string
		pids    []types.ProcessInfo
	}
	groups := make(map[string]*procGroup)
	for _, p := range procs {
		if p.IsSystem {
			continue
		}
		// 跳过系统关键进程
		if isSystemCritical(p.Name) {
			continue
		}
		// 跳过宝塔保护进程
		if procInfo := safety.ReadProcInfo(p.PID); procInfo != nil && safety.IsBaotaProtectedProcess(procInfo) {
			continue
		}
		// 用命令行的前 200 字符作为分组键（区分不同脚本）
		cmdKey := p.Cmdline
		if len(cmdKey) > 200 {
			cmdKey = cmdKey[:200]
		}
		// 如果命令行为空，用进程名
		if cmdKey == "" {
			cmdKey = p.Name
		}
		key := p.Name + "|" + cmdKey
		if g, ok := groups[key]; ok {
			g.pids = append(g.pids, p)
		} else {
			groups[key] = &procGroup{name: p.Name, cmdline: cmdKey, pids: []types.ProcessInfo{p}}
		}
	}

	for _, grp := range groups {
		if len(grp.pids) <= procExplosionThreshold {
			continue
		}

		// 进程爆炸检测到：同一程序超过阈值的进程实例
		excess := len(grp.pids) - procExplosionKeepAlive
		g.eventBus.PublishAlert(types.AlertCritical, "resource",
			fmt.Sprintf("进程爆炸: %s (%d 个实例)", grp.name, len(grp.pids)),
			fmt.Sprintf("程序 %s 当前运行 %d 个进程实例，远超正常水平（阈值 %d）。\n"+
				"这可能导致系统资源耗尽、数据库连接池占满等严重问题。\n"+
				"命令行: %s\n"+
				"正在自动终止 %d 个多余进程（保留 %d 个最早启动的）...",
				grp.name, len(grp.pids), procExplosionThreshold,
				truncateStr(grp.cmdline, 100), excess, procExplosionKeepAlive),
			"proc-explosion-001")

		// 按 CreateTime 排序，保留最早启动的 procExplosionKeepAlive 个
		sortedProcs := make([]types.ProcessInfo, len(grp.pids))
		copy(sortedProcs, grp.pids)
		// 简单插入排序（按启动时间升序）
		for i := 1; i < len(sortedProcs); i++ {
			for j := i; j > 0; j-- {
				if sortedProcs[j].CreateTime.Before(sortedProcs[j-1].CreateTime) {
					sortedProcs[j], sortedProcs[j-1] = sortedProcs[j-1], sortedProcs[j]
				}
			}
		}
		// 终止多余的进程（从第 procExplosionKeepAlive 个开始）
		killed := 0
		failed := 0
		for i := procExplosionKeepAlive; i < len(sortedProcs); i++ {
			p := sortedProcs[i]
			// 再次检查安全策略（可能在检测期间状态变化）
			if g.safety != nil {
				if g.safety.ShouldPauseDangerousActions() {
					break
				}
				if g.safety.IsWhitelisted(p.Name) || isSystemCritical(p.Name) {
					continue
				}
				if procInfo := safety.ReadProcInfo(p.PID); procInfo != nil && safety.IsBaotaProtectedProcess(procInfo) {
					continue
				}
				if err := g.safety.CheckKillPermission(p.Name, p.PID); err != nil {
					continue
				}
			}
			// 先 SIGTERM，给进程优雅退出的机会
			proc := process.Process{Pid: p.PID}
			err := proc.Terminate()
			if err == nil {
				killed++
				if g.safety != nil {
					g.safety.RecordKill(p.PID, p.Name, true)
				}
			} else {
				failed++
				if g.safety != nil {
					g.safety.RecordKill(p.PID, p.Name, false)
				}
			}
		}

		if killed > 0 {
			g.eventBus.PublishAlert(types.AlertError, "resource",
				fmt.Sprintf("进程爆炸已处置: %s", grp.name),
				fmt.Sprintf("程序 %s 的 %d 个多余进程实例已终止（成功 %d，失败 %d）。\n"+
					"保留了 %d 个最早启动的进程。\n"+
					"建议检查程序是否存在循环 fork/subprocess 的 Bug，或配置进程数限制（如 supervisord numprocs）。",
					grp.name, excess, killed, failed, procExplosionKeepAlive),
				"proc-explosion-002")
		}
	}
}

// truncateStr 截断字符串到指定长度
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// winCleanupExtAllowed Windows 清理的扩展名白名单——与 Linux 的
// .gz/.1/.old/.bz2/.xz/.zip 对齐，并加入 Windows 常见临时后缀。
// 没有这份白名单时，TEMP 目录 24h 全删会把用户正在使用的安装包、
// 文档、数据库导出等一并删掉。
var winCleanupExt = map[string]bool{
	".log": true, ".gz": true, ".zip": true, ".bz2": true, ".xz": true,
	".tmp": true, ".temp": true, ".bak": true, ".old": true, ".etl": true,
}

// winFileCleanable 判断 Windows 临时文件是否可清理：扩展名白名单 +
// mtime 已超过 minAge（活跃文件跳过）。
func winFileCleanable(info os.FileInfo, minAge time.Duration) bool {
	ext := strings.ToLower(filepath.Ext(info.Name()))
	if !winCleanupExt[ext] {
		return false
	}
	return time.Since(info.ModTime()) > minAge
}
