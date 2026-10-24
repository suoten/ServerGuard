package log

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
)

// ============================================================
// 幽灵文件检测器 — "已删除但句柄未释放"的隐形空间杀手
// ============================================================
//
// 问题场景：
//   WVP (Java) 把 stdout/stderr 重定向到 /www/wwwlogs/java/springboot/wvp-2026-07-15.0.log
//   日志文件被删除或轮转后，Java 进程没有重启，文件句柄一直未释放
//   du 看不到这个文件（已从目录树中移除）
//   df 却显示空间仍被占用（内核中 inode 仍存在，因为进程持有打开句柄）
//   实际占用 18.5GB × 2 = 37GB（stdout + stderr 两个句柄）
//
// 检测原理：
//   /proc/{pid}/fd/{n} 的 readlink 结果中包含 "(deleted)" 标记
//   例如: /www/wwwlogs/java/springboot/wvp-2026-07-15.0.log (deleted)
//   通过读取 /proc/{pid}/fdinfo/{n} 获取文件大小
//   或通过 /proc/{pid}/fd/{n} 的 fstat 获取实际大小
//
// 清理策略：
//   1. 优先：对持有幽灵句柄的进程发送 SIGTERM 优雅重启（释放句柄）
//   2. 兜底：如果进程不响应 SIGTERM，发送 SIGKILL 强制终止
//   3. 安全：通过安全检查白名单，不杀关键系统进程
//   4. 重启：对 systemd 管理的服务，用 systemctl restart 优雅重启

// GhostFile 幽灵文件信息
type GhostFile struct {
	PID          int32  `json:"pid"`
	ProcessName  string `json:"process_name"`
	FD           int    `json:"fd"`           // 文件描述符编号
	OriginalPath string `json:"original_path"` // 原始文件路径
	Size         int64  `json:"size"`         // 幽灵文件大小（字节）
	SizeGB       float64 `json:"size_gb"`
	Cmdline      string `json:"cmdline"`      // 进程命令行
	IsJava       bool   `json:"is_java"`      // 是否 Java 进程
	SystemdUnit  string `json:"systemd_unit"`  // systemd 服务名（如果适用）
}

// GhostFileDetector 幽灵文件检测器
type GhostFileDetector struct {
	eventBus interface {
		PublishAlert(types.AlertLevel, string, string, string, string)
	}
	safety *safety.SafetyManager
}

// NewGhostFileDetector 创建幽灵文件检测器
func NewGhostFileDetector(eventBus interface {
	PublishAlert(types.AlertLevel, string, string, string, string)
}, sm *safety.SafetyManager) *GhostFileDetector {
	return &GhostFileDetector{
		eventBus: eventBus,
		safety:   sm,
	}
}

// Detect 执行一次幽灵文件检测
// 扫描所有 /proc/{pid}/fd/* 的 symlink，查找包含 "(deleted)" 的句柄
func (d *GhostFileDetector) Detect() []GhostFile {
	if runtime.GOOS == "windows" {
		return nil
	}

	var ghosts []GhostFile
	seen := make(map[string]bool) // 去重：同一进程同一FD只记录一次

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid <= 0 {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			fdName := fd.Name()
			fdNum, _ := strconv.Atoi(fdName)
			linkPath := filepath.Join(fdDir, fdName)
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// 检测 "(deleted)" 标记
			if !strings.HasSuffix(target, " (deleted)") {
				continue
			}

			// 排除 ServerGuard 自身的文件（db、WAL、SHM）
			// 这些文件在 WAL 模式下会被频繁创建/删除/checkpoint，
			// 产生大量幽灵文件误报，且杀掉 serverguard 进程会导致监控中断
			originalPathForCheck := strings.TrimSuffix(target, " (deleted)")
			if isServerGuardFile(originalPathForCheck) {
				continue
			}

			// 去重
			dedupKey := fmt.Sprintf("%d-%s", pid, target)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			// 提取原始路径（去掉 " (deleted)" 后缀）
			originalPath := strings.TrimSuffix(target, " (deleted)")

			// 获取幽灵文件大小
			fileSize := d.getGhostFileSize(int32(pid), fdNum, linkPath)

			// 只报告大于 1MB 的幽灵文件
			if fileSize < 1024*1024 {
				continue
			}

			// 读取进程信息
			procName := d.readProcName(int32(pid))
			cmdline := d.readProcCmdline(int32(pid))
			isJava := d.isJavaProcess(int32(pid), cmdline)
			systemdUnit := d.getSystemdUnit(int32(pid))

			ghosts = append(ghosts, GhostFile{
				PID:          int32(pid),
				ProcessName:  procName,
				FD:           fdNum,
				OriginalPath: originalPath,
				Size:         fileSize,
				SizeGB:       float64(fileSize) / 1024 / 1024 / 1024,
				Cmdline:      cmdline,
				IsJava:       isJava,
				SystemdUnit:  systemdUnit,
			})
		}
	}

	// 按大小降序排序
	sort.Slice(ghosts, func(i, j int) bool {
		return ghosts[i].Size > ghosts[j].Size
	})

	return ghosts
}

// getGhostFileSize 获取幽灵文件的实际大小
// 方法：直接 fstat 打开 /proc/{pid}/fd/{n} 获取文件大小
func (d *GhostFileDetector) getGhostFileSize(pid int32, fdNum int, fdPath string) int64 {
	// 方法1：通过 /proc/{pid}/fdinfo/{fd} 读取 size 字段
	fdinfoPath := fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fdNum)
	if data, err := os.ReadFile(fdinfoPath); err == nil {
		// fdinfo 中有 size: 字段
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "size:") || strings.HasPrefix(line, "pos:") {
				var size int64
				if _, err := fmt.Sscanf(line, "size: %d", &size); err == nil {
					return size
				}
			}
		}
	}

	// 方法2：通过 os.Stat 获取（跨平台兼容）
	if info, err := os.Stat(fdPath); err == nil {
		return info.Size()
	}
	return 0
}

// readProcName 读取进程名
func (d *GhostFileDetector) readProcName(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("PID-%d", pid)
	}
	return strings.TrimSpace(string(data))
}

// readProcCmdline 读取进程命令行
func (d *GhostFileDetector) readProcCmdline(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

// isJavaProcess 判断是否为 Java 进程
func (d *GhostFileDetector) isJavaProcess(pid int32, cmdline string) bool {
	lower := strings.ToLower(cmdline)
	return strings.Contains(lower, "java") || strings.Contains(lower, "jar")
}

// getSystemdUnit 获取进程对应的 systemd 服务名
func (d *GhostFileDetector) getSystemdUnit(pid int32) string {
	// 读取 /proc/{pid}/cgroup
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		// 格式: 0::/system.slice/system-wvp.service
		// 或   0::/wvp.service
		if strings.Contains(line, ".service") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if strings.HasSuffix(part, ".service") {
					return strings.TrimPrefix(part, "system-")
				}
			}
		}
	}
	return ""
}

// ============================================================
// 幽灵文件清理器 — 释放被占用的磁盘空间
// ============================================================

// GhostFileCleaner 幽灵文件清理器
type GhostFileCleaner struct {
	eventBus interface {
		PublishAlert(types.AlertLevel, string, string, string, string)
	}
	safety *safety.SafetyManager
}

// NewGhostFileCleaner 创建幽灵文件清理器
func NewGhostFileCleaner(eventBus interface {
	PublishAlert(types.AlertLevel, string, string, string, string)
}, sm *safety.SafetyManager) *GhostFileCleaner {
	return &GhostFileCleaner{
		eventBus: eventBus,
		safety:   sm,
	}
}

// publish 安全发布告警（eventBus 为 nil 时跳过）
func (c *GhostFileCleaner) publish(level types.AlertLevel, source, title, detail, code string) {
	if c.eventBus == nil {
		return
	}
	c.eventBus.PublishAlert(level, source, title, detail, code)
}

// CleanGhostFiles 检测并清理幽灵文件
// 返回：释放的字节数、清理前检测到的幽灵文件列表、清理后剩余的幽灵文件列表
func (c *GhostFileCleaner) CleanGhostFiles() (freed int64, before []GhostFile, after []GhostFile) {
	detector := NewGhostFileDetector(c.eventBus, c.safety)
	ghosts := detector.Detect()

	if len(ghosts) == 0 {
		return 0, nil, nil
	}

	totalSize := int64(0)
	for _, g := range ghosts {
		totalSize += g.Size
	}

	// 发出告警
	c.publish(types.AlertError, "log",
		fmt.Sprintf("幽灵文件占用 %.2fGB", float64(totalSize)/1024/1024/1024),
		fmt.Sprintf("检测到 %d 个幽灵文件（已删除但句柄未释放），总计占用 %.2fGB 磁盘空间", len(ghosts), float64(totalSize)/1024/1024/1024),
		"ghost-file-001")

	// 自动清理：对非关键进程发送 SIGTERM 释放句柄
	freed = c.autoClean(ghosts)

	if freed > 0 {
		c.publish(types.AlertInfo, "log",
			"幽灵文件清理完成",
			fmt.Sprintf("已释放 %.2fGB 幽灵空间（通过重启持有句柄的进程释放文件描述符）", float64(freed)/1024/1024/1024),
			"ghost-file-cleanup-001")
	}

	// 清理后重新检测剩余的幽灵文件
	remainingDetector := NewGhostFileDetector(c.eventBus, c.safety)
	after = remainingDetector.Detect()

	return freed, ghosts, after
}

// autoClean 自动清理幽灵文件
// 策略：
//  1. 按文件路径聚合：同一个 original_path 的多个进程批量处理，避免逐个 kill 超时
//  2. 过滤掉关键系统进程（nginx, mysql, sshd 等）
//  3. 对 systemd 管理的服务：systemctl restart 优雅重启
//  4. 对非 systemd 进程：批量 SIGTERM，统一等待 5 秒，仍存活则批量 SIGKILL
//  5. 记录审计日志
func (c *GhostFileCleaner) autoClean(ghosts []GhostFile) int64 {
	freed := int64(0)

	// 维护窗口/远程暂停/紧急停止期间不自动清理——
	// 批量 SIGTERM/systemctl restart 属高危动作，运维变更中执行极易雪上加霜
	if c.safety != nil && c.safety.ShouldPauseDangerousActions() {
		c.publish(types.AlertWarning, "log",
			"幽灵文件清理已跳过（维护窗口/暂停期）",
			fmt.Sprintf("检测到 %d 个幽灵文件待清理，但当前处于维护窗口或远程暂停期，已跳过自动清理", len(ghosts)),
			"ghost-file-paused-001")
		return 0
	}

	// 按文件路径聚合：同一个被删文件可能被几百个进程持有（如宝塔 cron 的 curl）
	// 逐个 kill 会导致 API 超时（172 进程 × 15 秒 = 43 分钟）
	type pathGroup struct {
		Path     string
		Size     int64
		SizeGB   float64
		PIDs     []int32
		ProcNames []string
		SystemdUnits []string
	}
	groups := make(map[string]*pathGroup)
	var groupOrder []string // 保持顺序

	for _, g := range ghosts {
		// 安全检查：不杀关键系统进程
		if isCriticalProcess(g.ProcessName) {
			c.publish(types.AlertWarning, "log",
				fmt.Sprintf("幽灵文件跳过(关键进程): %s (PID %d)", g.ProcessName, g.PID),
				fmt.Sprintf("进程 %s (PID %d) 持有幽灵文件 %s (%.2fGB)，但属于关键系统进程，已跳过。\n建议手动重启该服务释放空间。",
					g.ProcessName, g.PID, g.OriginalPath, g.SizeGB),
				"ghost-file-skip-001")
			continue
		}

		// 安全检查：宝塔安全模式下不杀宝塔相关进程
		if c.safety != nil && c.safety.IsBaotaSafeMode() {
			lowerName := strings.ToLower(g.ProcessName)
			if strings.HasPrefix(lowerName, "bt") || strings.Contains(lowerName, "panel") {
				continue
			}
		}

		grp, exists := groups[g.OriginalPath]
		if !exists {
			grp = &pathGroup{
				Path: g.OriginalPath,
				Size: g.Size,
				SizeGB: g.SizeGB,
			}
			groups[g.OriginalPath] = grp
			groupOrder = append(groupOrder, g.OriginalPath)
		}
		grp.PIDs = append(grp.PIDs, g.PID)
		grp.ProcNames = append(grp.ProcNames, g.ProcessName)
		if g.SystemdUnit != "" {
			grp.SystemdUnits = append(grp.SystemdUnits, g.SystemdUnit)
		}
	}

	// 按文件路径分组处理
	for _, path := range groupOrder {
		grp := groups[path]
		if len(grp.PIDs) == 0 {
			continue
		}

		// 策略1：如果是 systemd 服务，优先 systemctl restart
		if len(grp.SystemdUnits) > 0 {
			unit := grp.SystemdUnits[0]
			if c.restartSystemdService(GhostFile{SystemdUnit: unit, OriginalPath: grp.Path, SizeGB: grp.SizeGB}) {
				freed += grp.Size
				c.publish(types.AlertInfo, "log",
					fmt.Sprintf("幽灵文件已释放(systemd重启): %s", unit),
					fmt.Sprintf("已通过 systemctl restart %s 释放幽灵文件 %s (%.2fGB)，涉及 %d 个进程",
						unit, grp.Path, grp.SizeGB, len(grp.PIDs)),
					"ghost-file-restart-001")
				continue
			}
		}

		// 策略2：批量 SIGTERM 所有相关进程
		killed := c.batchKill(grp.PIDs, "TERM", 5)
		if killed > 0 {
			freed += grp.Size
			c.publish(types.AlertInfo, "log",
				fmt.Sprintf("幽灵文件已释放(SIGTERM批量): %s", grp.Path),
				fmt.Sprintf("已通过 SIGTERM 批量终止 %d/%d 个进程释放幽灵文件 %s (%.2fGB)\n进程: %s",
					killed, len(grp.PIDs), grp.Path, grp.SizeGB, strings.Join(grp.ProcNames[:min(3, len(grp.ProcNames))], ", ")),
				"ghost-file-sigterm-001")
		}

		// 策略3：对仍存活的进程批量 SIGKILL
		var survivors []int32
		for _, pid := range grp.PIDs {
			if processExists(pid) {
				survivors = append(survivors, pid)
			}
		}
		if len(survivors) > 0 {
			killed2 := c.batchKill(survivors, "KILL", 3)
			if killed2 > 0 {
				freed += grp.Size // 已经加过就不再重复加
				c.publish(types.AlertWarning, "log",
					fmt.Sprintf("幽灵文件已释放(SIGKILL批量): %s", grp.Path),
					fmt.Sprintf("SIGTERM 无响应，已通过 SIGKILL 强制终止 %d/%d 个进程释放幽灵文件 %s (%.2fGB)",
						killed2, len(survivors), grp.Path, grp.SizeGB),
					"ghost-file-sigkill-001")
			}
		}

		// 检查是否仍有残留
		stillAlive := 0
		for _, pid := range grp.PIDs {
			if processExists(pid) {
				stillAlive++
			}
		}
		if stillAlive > 0 {
			c.publish(types.AlertError, "log",
				fmt.Sprintf("幽灵文件部分清理失败: %s", grp.Path),
				fmt.Sprintf("%d 个进程无法终止释放幽灵文件 %s (%.2fGB)，可能需要手动处理", stillAlive, grp.Path, grp.SizeGB),
				"ghost-file-fail-001")
		}
	}

	return freed
}

// batchKill 批量发送信号给多个进程，然后统一等待
// 返回成功终止的进程数。
// 每个 PID 先过 CheckKillPermission（预算/熔断/紧急停止/白名单），
// 被拒的跳过——幽灵文件清理不得绕过五层安全阀；成功后 RecordKill 记账。
func (c *GhostFileCleaner) batchKill(pids []int32, signal string, waitSecs int) int {
	killed := 0
	// 先整体做一遍审批，全部被拒则不动手（避免一半杀一半留的中间态）
	approved := make([]int32, 0, len(pids))
	for _, pid := range pids {
		if !processExists(pid) {
			killed++
			continue
		}
		if c.safety != nil {
			name := ghostProcName(pid)
			if err := c.safety.CheckKillPermission(name, pid); err != nil {
				c.publish(types.AlertWarning, "log",
					fmt.Sprintf("幽灵文件清理被安全机制拦截: PID %d", pid),
					fmt.Sprintf("进程 %s (PID %d) 持有幽灵文件，但安全审批拒绝终止：%v", name, pid, err),
					"ghost-file-blocked-001")
				continue
			}
		}
		approved = append(approved, pid)
	}
	// 同时给所有获批进程发信号（并行）
	for _, pid := range approved {
		_ = exec.Command("kill", "-"+signal, fmt.Sprintf("%d", pid)).Run()
	}
	// 统一等待，不逐个等待
	for i := 0; i < waitSecs; i++ {
		time.Sleep(1 * time.Second)
		alive := 0
		for _, pid := range pids {
			if processExists(pid) {
				alive++
			}
		}
		if alive == 0 {
			break
		}
	}
	// 统计成功数
	for _, pid := range approved {
		if !processExists(pid) {
			killed++
			if c.safety != nil {
				c.safety.RecordKill(pid, ghostProcName(pid), true)
			}
		}
	}
	return killed
}

// ghostProcName 轻量读取 /proc/{pid}/comm（失败返回占位符）。
func ghostProcName(pid int32) string {
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		return strings.TrimSpace(string(data))
	}
	return fmt.Sprintf("pid-%d", pid)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// restartSystemdService 通过 systemctl restart 重启 systemd 服务
func (c *GhostFileCleaner) restartSystemdService(g GhostFile) bool {
	// 安全预检
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}

	// 执行重启
	cmd := exec.Command("systemctl", "restart", g.SystemdUnit)
	if err := cmd.Run(); err != nil {
		return false
	}

	// 等待服务恢复
	time.Sleep(3 * time.Second)

	// 验证服务已恢复
	checkCmd := exec.Command("systemctl", "is-active", g.SystemdUnit)
	output, err := checkCmd.Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(output))
	return state == "active" || state == "running"
}

// sigtermAndVerify 发送 SIGTERM 并验证进程是否终止
func (c *GhostFileCleaner) sigtermAndVerify(pid int32) bool {
	if !processExists(pid) {
		return true
	}

	// 发送 SIGTERM
	if err := exec.Command("kill", "-TERM", fmt.Sprintf("%d", pid)).Run(); err != nil {
		return false
	}

	// 等待最多 10 秒
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		if !processExists(pid) {
			return true
		}
	}

	return false
}

// sigkillAndVerify 发送 SIGKILL 并验证进程是否终止
func (c *GhostFileCleaner) sigkillAndVerify(pid int32) bool {
	if !processExists(pid) {
		return true
	}

	// 发送 SIGKILL
	if err := exec.Command("kill", "-KILL", fmt.Sprintf("%d", pid)).Run(); err != nil {
		return false
	}

	// 等待最多 5 秒
	for i := 0; i < 5; i++ {
		time.Sleep(1 * time.Second)
		if !processExists(pid) {
			return true
		}
	}

	return false
}

// processExists 检查进程是否仍然存在
func processExists(pid int32) bool {
	// /proc/{pid} 目录存在意味着进程仍存活
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// isServerGuardFile 检查路径是否为 ServerGuard 自身的数据文件。
// serverguard.db、serverguard.db-wal、serverguard.db-shm 在 WAL 模式下
// 会被频繁创建/删除/checkpoint，产生大量幽灵文件误报。
// 杀掉 serverguard 进程释放这些句柄会导致监控中断，得不偿失。
func isServerGuardFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	// 匹配 serverguard.db、serverguard.db-wal、serverguard.db-shm、serverguard.db-journal 等
	if strings.HasPrefix(base, "serverguard.db") {
		return true
	}
	// 匹配 serverguard 的备份数据库文件
	if strings.HasPrefix(base, "serverguard.db.bak.") {
		return true
	}
	return false
}

// isCriticalProcess 检查是否为关键系统进程
// 这些进程不应被自动终止，否则会导致系统不可用
func isCriticalProcess(name string) bool {
	critical := map[string]bool{
		// 系统关键进程
		"systemd": true, "init": true, "kernel_task": true,
		"sshd": true, "systemd-journald": true, "systemd-logind": true,
		"dbus": true, "rsyslogd": true, "cron": true, "crond": true,
		// 数据库（重启可能导致数据损坏）
		"mysqld": true, "postgres": true, "redis-server": true,
		"mariadbd": true, "mongod": true,
		// Web 服务器
		"nginx": true, "httpd": true, "apache2": true, "caddy": true,
		// PHP
		"php-fpm": true, "php-cgi": true, "php": true,
		// 宝塔
		"bt-panel": true, "bt": true, "btpanel": true,
		// 其他
		"pure-ftpd": true, "named": true, "bind9": true,
		"postfix": true, "dovecot": true, "sendmail": true,
		// ServerGuard 自身
		"serverguard-agent": true, "serverguard-hub": true,
	}
	return critical[name]
}

// ============================================================
// 集成到 LogGuard 的检查流程
// ============================================================

// lastGhostScan 缓存最近一次幽灵文件扫描结果，供前端读取
var lastGhostScan struct {
	sync.RWMutex
	ghosts    []GhostFile
	count     int
	totalSize int64
	scanTime  time.Time
}

// GetLastGhostScanResult 返回最近一次幽灵文件扫描结果（供 API 读取）
func GetLastGhostScanResult() (ghosts []GhostFile, count int, totalSizeGB float64, scanTime time.Time) {
	lastGhostScan.RLock()
	defer lastGhostScan.RUnlock()
	if len(lastGhostScan.ghosts) == 0 && lastGhostScan.scanTime.IsZero() {
		return nil, 0, 0, time.Time{}
	}
	// 返回副本
	ghosts = make([]GhostFile, len(lastGhostScan.ghosts))
	copy(ghosts, lastGhostScan.ghosts)
	return ghosts, lastGhostScan.count, float64(lastGhostScan.totalSize) / 1024 / 1024 / 1024, lastGhostScan.scanTime
}

// UpdateGhostScanCache 更新幽灵文件扫描缓存（供 API 调用）
func UpdateGhostScanCache(ghosts []GhostFile) {
	totalSize := int64(0)
	for _, g := range ghosts {
		totalSize += g.Size
	}
	lastGhostScan.Lock()
	lastGhostScan.ghosts = ghosts
	lastGhostScan.count = len(ghosts)
	lastGhostScan.totalSize = totalSize
	lastGhostScan.scanTime = time.Now()
	lastGhostScan.Unlock()
}

// IsGhostCriticalProcess 检查进程是否为关键系统进程（供 API 调用）
func IsGhostCriticalProcess(name string) bool {
	return isCriticalProcess(name)
}

// CheckGhostFiles LogGuard 定期检查幽灵文件
// 改进：每次调用都执行检测（无条件），结果缓存供前端读取，记录到 action_history
// 清理策略：磁盘 >80% 时自动清理，<80% 时只检测告警不清理
//
// 资源优化：限制扫描频率，避免在低配服务器上频繁遍历 /proc/*/fd/
// 每 30 分钟最多扫描一次，间隔内的调用直接返回缓存结果
var lastGhostScanTime time.Time

func (g *LogGuard) CheckGhostFiles(diskUsagePercent float64) {
	if runtime.GOOS == "windows" {
		return
	}

	// 降频：30 分钟内只扫描一次，避免低配服务器 I/O 压力
	// 如果磁盘使用率 >= 90%（紧急），则无视缓存立即扫描
	if diskUsagePercent < 90 {
		lastGhostScan.RLock()
		lastTS := lastGhostScanTime
		lastGhostScan.RUnlock()
		if !lastTS.IsZero() && time.Since(lastTS) < 30*time.Minute {
			return // 30 分钟内已扫描过，跳过
		}
	}

	lastGhostScanTime = time.Now()
	detector := NewGhostFileDetector(g.eventBus, g.safety)
	ghosts := detector.Detect()

	// 缓存结果供前端读取
	totalSize := int64(0)
	for _, ghost := range ghosts {
		totalSize += ghost.Size
	}
	lastGhostScan.Lock()
	lastGhostScan.ghosts = ghosts
	lastGhostScan.count = len(ghosts)
	lastGhostScan.totalSize = totalSize
	lastGhostScan.scanTime = time.Now()
	lastGhostScan.Unlock()

	// 记录到操作日志（留迹）—— 无幽灵文件也记录，证明我们检查过了
	if len(ghosts) > 0 {
		g.recordAction("ghost_scan", "",
			fmt.Sprintf("检测到 %d 个幽灵文件，占用 %.2fGB（磁盘 %.1f%%）", len(ghosts), float64(totalSize)/1024/1024/1024, diskUsagePercent),
			true, "")

		// 发出告警
		g.eventBus.PublishAlert(types.AlertError, "log",
			fmt.Sprintf("幽灵文件占用 %.2fGB", float64(totalSize)/1024/1024/1024),
			fmt.Sprintf("检测到 %d 个幽灵文件（已删除但句柄未释放），总计占用 %.2fGB 磁盘空间。ServerGuard 将自动清理。", len(ghosts), float64(totalSize)/1024/1024/1024),
			"ghost-file-001")
	} else {
		// 没有幽灵文件也记录一次成功扫描
		g.recordAction("ghost_scan", "", "扫描完成，未发现幽灵文件", true, "")
	}

	// 清理策略：磁盘使用率 ≥80% 时自动清理
	if diskUsagePercent >= 80 && len(ghosts) > 0 {
		cleaner := NewGhostFileCleaner(g.eventBus, g.safety)
		freed, cleanedGhosts, remaining := cleaner.CleanGhostFiles()

		// 记录清理结果
		if freed > 0 {
			g.recordAction("clean_disk", "",
				fmt.Sprintf("幽灵文件自动清理：释放 %.2fGB（%d 个文件）", float64(freed)/1024/1024/1024, len(cleanedGhosts)),
				true, "")
		}

		// 更新缓存为清理后剩余的幽灵文件
		remSize := int64(0)
		for _, ghost := range remaining {
			remSize += ghost.Size
		}
		lastGhostScan.Lock()
		lastGhostScan.ghosts = remaining
		lastGhostScan.count = len(remaining)
		lastGhostScan.totalSize = remSize
		lastGhostScan.scanTime = time.Now()
		lastGhostScan.Unlock()

		// 如果有未能清理的幽灵文件，告警提示手动处理
		if len(remaining) > 0 && freed < totalSize {
			var detail strings.Builder
			detail.WriteString("以下幽灵文件无法自动清理，建议手动重启对应服务:\n")
			for i, ghost := range remaining {
				if i >= 5 {
					detail.WriteString(fmt.Sprintf("\n...等共 %d 个", len(remaining)))
					break
				}
				detail.WriteString(fmt.Sprintf("\n  %s (PID %d): %s (%.2fGB) → 建议执行: systemctl restart %s 或 kill %d",
					ghost.ProcessName, ghost.PID, ghost.OriginalPath, ghost.SizeGB,
					ghost.SystemdUnit, ghost.PID))
			}
			g.eventBus.PublishAlert(types.AlertWarning, "log",
				"幽灵文件需手动处理",
				detail.String(),
				"ghost-file-manual-001")
		}
	}
}

// ============================================================
// 幽灵文件预防 — logrotate copytruncate 配置自动生成
// ============================================================

// GenerateGhostFilePreventionConfig 为 Java 应用生成预防幽灵文件的配置建议
func GenerateGhostFilePreventionConfig(appName, logPath string) string {
	return fmt.Sprintf(`# ===== 幽灵文件预防配置 =====
# 应用: %s
# 日志路径: %s
#
# 问题：直接删除/轮转 Java 进程的输出日志文件后，进程不释放文件句柄，
#        导致"幽灵文件"占用磁盘空间（du看不到，df显示满）。
#
# 解决方案1: 使用 copytruncate 策略（推荐）
#   /etc/logrotate.d/%s
#   %s {
#       daily
#       rotate 7
#       compress
#       delaycompress
#       missingok
#       notifempty
#       copytruncate    # 关键：复制后截断，不改变文件句柄
#       size 500M
#   }
#
# 解决方案2: 使用 postrotate 重启服务
#   /etc/logrotate.d/%s
#   %s {
#       daily
#       rotate 7
#       compress
#       missingok
#       notifempty
#       size 500M
#       postrotate
#           systemctl restart %s 2>/dev/null || true
#       endscript
#   }
#
# 解决方案3: 修改 Java 应用日志配置（最佳）
#   使用 logback RollingFileAppender 替代 stdout 重定向
#   logback.xml 配置 SizeAndTimeBasedRollingPolicy 自动滚动
#
# 解决方案4: 使用 > 重定向而非 >> 模式
#   启动脚本中使用: java -jar app.jar > /dev/null 2>&1
#   或使用进程管理器（systemd/supervisor）自动管理日志
`, appName, logPath,
		appName, logPath,
		appName, logPath, appName)
}
