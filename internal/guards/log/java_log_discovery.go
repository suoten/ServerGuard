package log

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
)

// ============================================================
// Java 应用日志自动发现 + 紧急清理增强
// ============================================================
//
// 问题场景：wvp-gb28181-pro 等 Java 应用日志暴涨占满根分区
//
// 原有机制缺陷：
//  1. LogGuard.scanPaths 只扫描 /var/log，不包含 Java 应用自定义日志目录
//  2. CleanupAllowedExtensions 只允许 .gz/.1/.old，不清理活跃的 .log 文件
//  3. ResourceGuard.emergencyDiskCleanup 只扫描 CleanupWhitelist 中的目录
//
// 增强方案：
//  1. 通过 /proc 自动发现 Java 进程的工作目录和日志输出路径
//  2. 扫描常见 Java 应用日志目录（/opt、/home、/usr/local 下的 logs 子目录）
//  3. 紧急情况下使用 copytruncate 策略安全截断活跃日志文件
//  4. 自动生成 logback/log4j 配置修复建议

// JavaAppLogDiscovery Java 应用日志自动发现器
type JavaAppLogDiscovery struct {
	discoveredPaths []string
	javaProcesses   []JavaProcessInfo
}

// JavaProcessInfo Java 进程信息
type JavaProcessInfo struct {
	PID       int32
	JavaApp   string
	Cmdline   string
	WorkingDir string
	LogPaths  []string
}

// NewJavaAppLogDiscovery 创建日志发现器
func NewJavaAppLogDiscovery() *JavaAppLogDiscovery {
	return &JavaAppLogDiscovery{}
}

// Discover 自动发现 Java 应用日志路径
// 通过扫描 /proc 文件系统查找 Java 进程，定位其工作目录和日志输出路径
func (d *JavaAppLogDiscovery) Discover() []JavaProcessInfo {
	if runtime.GOOS == "windows" {
		return nil
	}

	var javaProcs []JavaProcessInfo

	// 扫描 /proc 找出所有 Java 进程
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

		// 读取 /proc/{pid}/cmdline
		cmdlineData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		cmdline := strings.ReplaceAll(strings.TrimRight(string(cmdlineData), "\x00"), "\x00", " ")
		if cmdline == "" {
			continue
		}

		// 判断是否为 Java 进程
		lowerCmd := strings.ToLower(cmdline)
		isJava := false
		javaApp := ""
		if strings.Contains(lowerCmd, "java") || strings.Contains(lowerCmd, "jar") {
			isJava = true
			// 尝试识别具体应用
			if strings.Contains(lowerCmd, "wvp") {
				javaApp = "wvp-gb28181-pro"
			} else if strings.Contains(lowerCmd, "zlm") || strings.Contains(lowerCmd, "mediaserver") {
				javaApp = "ZLMediaKit"
			} else if strings.Contains(lowerCmd, "elasticsearch") {
				javaApp = "Elasticsearch"
			} else if strings.Contains(lowerCmd, "logstash") {
				javaApp = "Logstash"
			} else if strings.Contains(lowerCmd, "kafka") {
				javaApp = "Kafka"
			} else if strings.Contains(lowerCmd, "nacos") {
				javaApp = "Nacos"
			} else if strings.Contains(lowerCmd, "jenkins") {
				javaApp = "Jenkins"
			} else if strings.Contains(lowerCmd, "spring") {
				javaApp = "SpringBoot"
			} else {
				// 尝试从 -jar 参数提取应用名
				parts := strings.Fields(cmdline)
				for i, p := range parts {
					if p == "-jar" && i+1 < len(parts) {
						jarName := filepath.Base(parts[i+1])
						jarName = strings.TrimSuffix(jarName, ".jar")
						if jarName != "" {
							javaApp = jarName
						}
						break
					}
				}
				if javaApp == "" {
					javaApp = "java-app"
				}
			}
		}

		if !isJava {
			continue
		}

		// 读取工作目录
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			cwd = ""
		}

		procInfo := JavaProcessInfo{
			PID:       int32(pid),
			JavaApp:   javaApp,
			Cmdline:   cmdline,
			WorkingDir: cwd,
		}

		// 从命令行参数中提取日志路径
		procInfo.LogPaths = d.extractLogPaths(cmdline, cwd)

		// 自动发现工作目录下的 logs 子目录
		if cwd != "" {
			candidateDirs := []string{
				filepath.Join(cwd, "logs"),
				filepath.Join(cwd, "log"),
				filepath.Join(cwd, "logs", "info"),
				filepath.Join(cwd, "logs", "error"),
				filepath.Join(cwd, "logs", "debug"),
			}
			for _, dir := range candidateDirs {
				if info, err := os.Stat(dir); err == nil && info.IsDir() {
					procInfo.LogPaths = append(procInfo.LogPaths, dir)
				}
			}
		}

		// 扫描常见 Java 应用日志目录
		commonDirs := []string{
			fmt.Sprintf("/opt/%s/logs", strings.ToLower(javaApp)),
			fmt.Sprintf("/opt/%s/log", strings.ToLower(javaApp)),
			fmt.Sprintf("/usr/local/%s/logs", strings.ToLower(javaApp)),
			fmt.Sprintf("/home/%s/logs", strings.ToLower(javaApp)),
			"/var/log/wvp",
			"/var/log/zlm",
			"/var/log/java",
		}
		for _, dir := range commonDirs {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				procInfo.LogPaths = append(procInfo.LogPaths, dir)
			}
		}

		if len(procInfo.LogPaths) > 0 {
			javaProcs = append(javaProcs, procInfo)
			for _, lp := range procInfo.LogPaths {
				d.discoveredPaths = append(d.discoveredPaths, lp)
			}
		}
	}

	d.javaProcesses = javaProcs
	return javaProcs
}

// extractLogPaths 从 Java 命令行参数中提取日志路径
// 例如: -Dlogging.file.name=/opt/wvp/logs/wvp.log
//       -Dlog.path=/opt/wvp/logs
func (d *JavaAppLogDiscovery) extractLogPaths(cmdline, cwd string) []string {
	var paths []string
	parts := strings.Fields(cmdline)

	for _, p := range parts {
		lowerP := strings.ToLower(p)
		// -Dlogging.file.name=xxx
		if strings.HasPrefix(lowerP, "-dlogging.file.name=") || strings.HasPrefix(lowerP, "-dlogging.file=") {
			logFile := p[strings.Index(p, "=")+1:]
			if !filepath.IsAbs(logFile) && cwd != "" {
				logFile = filepath.Join(cwd, logFile)
			}
			paths = append(paths, filepath.Dir(logFile))
		}
		// -Dlog.path=xxx
		if strings.HasPrefix(lowerP, "-dlog.path=") || strings.HasPrefix(lowerP, "-dlog.dir=") {
			logDir := p[strings.Index(p, "=")+1:]
			if !filepath.IsAbs(logDir) && cwd != "" {
				logDir = filepath.Join(cwd, logDir)
			}
			paths = append(paths, logDir)
		}
		// -Dcatalina.base=xxx (Tomcat)
		if strings.HasPrefix(lowerP, "-dcatalina.base=") {
			catalinaBase := p[strings.Index(p, "=")+1:]
			paths = append(paths, filepath.Join(catalinaBase, "logs"))
		}
	}

	return paths
}

// GetDiscoveredPaths 返回发现的所有日志路径
func (d *JavaAppLogDiscovery) GetDiscoveredPaths() []string {
	return d.discoveredPaths
}

// GetJavaProcesses 返回发现的 Java 进程信息
func (d *JavaAppLogDiscovery) GetJavaProcesses() []JavaProcessInfo {
	return d.javaProcesses
}

// ============================================================
// 紧急日志清理器 — copytruncate 策略
// ============================================================

// EmergencyLogCleaner 紧急日志清理器
// 当磁盘使用率超过紧急阈值时，使用 copytruncate 策略安全截断活跃日志文件
type EmergencyLogCleaner struct {
	eventBus interface {
		PublishAlert(types.AlertLevel, string, string, string, string)
	}
	safety *safety.SafetyManager
}

// NewEmergencyLogCleaner 创建紧急日志清理器
func NewEmergencyLogCleaner(eventBus interface {
	PublishAlert(types.AlertLevel, string, string, string, string)
}, sm *safety.SafetyManager) *EmergencyLogCleaner {
	return &EmergencyLogCleaner{
		eventBus: eventBus,
		safety:   sm,
	}
}

// EmergencyLogCleanup 紧急日志清理
// 策略：
//  1. 发现所有 Java 应用日志（通过 JavaAppLogDiscovery）
//  2. 扫描 /var/log 下的活跃日志
//  3. 对大于 100MB 的活跃 .log 文件使用 copytruncate：复制+压缩+截断
//  4. 删除旧的轮转日志文件（.gz/.old/.1 等）
//  5. 对于明确的 Java 应用日志暴涨场景，直接截断活跃日志文件
func (c *EmergencyLogCleaner) EmergencyLogCleanup() int64 {
	if runtime.GOOS == "windows" {
		return c.emergencyLogCleanupWindows()
	}

	freed := int64(0)

	// 步骤 1: 发现 Java 应用日志
	discovery := NewJavaAppLogDiscovery()
	discovery.Discover()

	// 收集所有需要扫描的日志目录
	scanDirs := []string{"/var/log"}
	scanDirs = append(scanDirs, discovery.GetDiscoveredPaths()...)

	// 去重
	seen := make(map[string]bool)
	uniqueDirs := []string{}
	for _, d := range scanDirs {
		if !seen[d] {
			seen[d] = true
			uniqueDirs = append(uniqueDirs, d)
		}
	}

	// 步骤 2: 扫描所有日志目录，找出大文件
	type logFile struct {
		path    string
		size    int64
		modTime time.Time
	}
	var bigLogFiles []logFile
	var oldRotatedFiles []logFile

	for _, dir := range uniqueDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// 安全检查：路径黑名单
			if safety.IsPathBlacklisted(path) {
				return nil
			}

			lowerName := strings.ToLower(info.Name())
			isLog := strings.HasSuffix(lowerName, ".log") || strings.HasSuffix(lowerName, ".out")
			isRotated := strings.HasSuffix(lowerName, ".gz") || strings.HasSuffix(lowerName, ".1") ||
				strings.HasSuffix(lowerName, ".old") || strings.HasSuffix(lowerName, ".bz2") ||
				strings.HasSuffix(lowerName, ".xz") || strings.HasSuffix(lowerName, ".zip")

			if isRotated && info.Size() > 1024*1024 { // >1MB 的旧轮转文件
				oldRotatedFiles = append(oldRotatedFiles, logFile{path, info.Size(), info.ModTime()})
			} else if isLog && info.Size() > 100*1024*1024 { // >100MB 的活跃日志
				bigLogFiles = append(bigLogFiles, logFile{path, info.Size(), info.ModTime()})
			}

			return nil
		})
	}

	// 步骤 3: 先删除旧的轮转文件（最安全）
	sort.Slice(oldRotatedFiles, func(i, j int) bool {
		return oldRotatedFiles[i].modTime.Before(oldRotatedFiles[j].modTime)
	})
	for _, f := range oldRotatedFiles {
		if !safety.IsFileSafeForCleanup(f.path) {
			continue
		}
		if safety.IsFileBeingWritten(f.path) {
			continue
		}
		if os.Remove(f.path) == nil {
			freed += f.size
		}
	}

	// 步骤 4: 对大日志文件使用 copytruncate 策略
	// copytruncate: 先复制文件内容到 .bak，然后截断原文件为 0
	// 这样不会破坏文件描述符（Java 进程仍然在写同一个文件）
	sort.Slice(bigLogFiles, func(i, j int) bool {
		return bigLogFiles[i].size > bigLogFiles[j].size // 从大到小
	})
	for _, f := range bigLogFiles {
		// 安全检查：路径不能在黑名单
		if safety.IsPathBlacklisted(f.path) {
			continue
		}
		// 安全检查：不能是数据库文件
		if safety.IsFileForbiddenForCleanup(f.path) {
			continue
		}
		// 安全检查：受保护的文件名模式
		if safety.IsFileProtectedByPattern(f.path) {
			continue
		}

		// 使用 copytruncate 策略
		freedBytes := c.copyTruncate(f.path, f.size)
		freed += freedBytes
	}

	if freed > 0 {
		c.eventBus.PublishAlert(types.AlertInfo, "log",
			"紧急日志清理完成",
			fmt.Sprintf("已释放 %.2fGB 磁盘空间（copytruncate 截断大日志 + 删除旧轮转文件）", float64(freed)/1024/1024/1024),
			"emergency-log-cleanup-001")
	}

	return freed
}

// copyTruncate 安全截断活跃日志文件
// 策略：
//  1. 将文件内容复制到 .bak 文件
//  2. 压缩 .bak 文件
//  3. 截断原文件为 0 字节
//  4. 删除压缩后的 .bak.gz 文件（如果磁盘极度紧张）或保留（如果有空间）
//
// 注意：此操作不影响 Java 进程的文件描述符，因为文件 inode 不变
func (c *EmergencyLogCleaner) copyTruncate(path string, currentSize int64) int64 {
	// 复制到 .bak
	bakPath := path + ".emergency.bak"
	srcFile, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer srcFile.Close()

	bakFile, err := os.Create(bakPath)
	if err != nil {
		return 0
	}
	defer bakFile.Close()

	// 复制内容
	if _, err := io.Copy(bakFile, srcFile); err != nil {
		os.Remove(bakPath)
		return 0
	}
	bakFile.Close()

	// 截断原文件为 0 字节
	// 使用 O_TRUNC 标志打开原文件，这不会改变文件描述符
	truncFile, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		os.Remove(bakPath)
		return 0
	}
	truncFile.Close()

	// 尝试压缩 .bak 文件
	go c.compressAndRemoveBackup(bakPath)

	c.eventBus.PublishAlert(types.AlertInfo, "log",
		fmt.Sprintf("日志已截断: %s", path),
		fmt.Sprintf("活跃日志文件 %s 大小 %.2fMB 已通过 copytruncate 安全截断为 0，备份已压缩保存", path, float64(currentSize)/1024/1024),
		"log-copytruncate-001")

	return currentSize
}

// compressAndRemoveBackup 将截断前的日志备份压缩为 .gz。
// 修复：原实现用 defer os.Remove 把压缩备份和原始备份全部立刻删掉，
// 而告警却声称"备份已压缩保存"——日志内容被静默永久销毁。
// 现在压缩成功后保留 .gz 备份（可人工恢复），只删除未压缩临时文件；
// 压缩失败时保留原始备份，绝不"既没压成又删了原文件"。
func (c *EmergencyLogCleaner) compressAndRemoveBackup(bakPath string) {
	src, err := os.Open(bakPath)
	if err != nil {
		return
	}
	defer src.Close()

	gzPath := bakPath + ".gz"
	dst, err := os.Create(gzPath)
	if err != nil {
		return // 保留原始备份
	}

	gzWriter, zerr := gzip.NewWriterLevel(dst, gzip.BestSpeed)
	if zerr != nil {
		dst.Close()
		os.Remove(gzPath)
		return
	}
	if _, err := io.Copy(gzWriter, src); err != nil {
		gzWriter.Close()
		dst.Close()
		os.Remove(gzPath)
		return // 保留原始备份
	}
	if err := gzWriter.Close(); err != nil {
		dst.Close()
		os.Remove(gzPath)
		return
	}
	if err := dst.Close(); err != nil {
		os.Remove(gzPath)
		return
	}
	// 压缩成功且完整落盘：删除未压缩临时备份，保留 .gz
	os.Remove(bakPath)
}

// emergencyLogCleanupWindows Windows 版紧急清理
func (c *EmergencyLogCleaner) emergencyLogCleanupWindows() int64 {
	freed := int64(0)
	searchDirs := []string{
		`C:\Windows\Temp`,
		`C:\Windows\Logs`,
		`C:\inetpub\logs`,
	}
	cutoff := time.Now().AddDate(0, 0, -7)
	for _, dir := range searchDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.ModTime().Before(cutoff) {
				if os.Remove(path) == nil {
					freed += info.Size()
				}
			}
			return nil
		})
	}
	return freed
}

// ============================================================
// 日志暴涨检测增强 — Java 应用专项
// ============================================================

// CheckJavaLogFlood 检测 Java 应用日志暴涨
// 专门针对 wvp-gb28181-pro 等Java应用的日志暴涨场景
func (g *LogGuard) CheckJavaLogFlood() {
	if runtime.GOOS == "windows" {
		return
	}

	// 发现 Java 进程和日志路径
	discovery := NewJavaAppLogDiscovery()
	javaProcs := discovery.Discover()

	for _, proc := range javaProcs {
		for _, logDir := range proc.LogPaths {
			var totalSize int64
			var fileCount int
			var biggestFile string
			var biggestSize int64

			filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				totalSize += info.Size()
				fileCount++
				if info.Size() > biggestSize {
					biggestSize = info.Size()
					biggestFile = path
				}
				return nil
			})

			// 如果日志目录总大小超过 1GB，发出告警并记录
			if totalSize > 1024*1024*1024 {
				msg := fmt.Sprintf("应用 %s (PID %d) 的日志目录 %s 总大小 %.2fGB，文件数 %d，最大文件 %s (%.2fMB)",
					proc.JavaApp, proc.PID, logDir, float64(totalSize)/1024/1024/1024, fileCount, biggestFile, float64(biggestSize)/1024/1024)
				g.recordAction("clean_log", logDir,
					"Java日志暴涨检测: "+msg, true, "")
				g.eventBus.PublishAlert(types.AlertWarning, "log",
					fmt.Sprintf("Java日志暴涨: %s (%s)", proc.JavaApp, logDir),
					msg+"\n建议检查应用日志配置，添加滚动策略。\nServerGuard 会在磁盘紧急时自动截断大日志文件。",
					"java-log-flood-001")
			}

			// 检查 logback 配置
			g.checkLogbackConfigForApp(proc)
		}
	}
}

// checkLogbackConfigForApp 检查 Java 应用的日志配置
func (g *LogGuard) checkLogbackConfigForApp(proc JavaProcessInfo) {
	// 在应用工作目录和 classpath 中搜索 logback/log4j 配置文件
	searchPaths := []string{proc.WorkingDir}
	for _, lp := range proc.LogPaths {
		searchPaths = append(searchPaths, filepath.Dir(lp))
	}

	for _, searchPath := range searchPaths {
		if searchPath == "" {
			continue
		}
		configFiles := []string{
			filepath.Join(searchPath, "config", "logback.xml"),
			filepath.Join(searchPath, "logback.xml"),
			filepath.Join(searchPath, "logback-spring.xml"),
			filepath.Join(searchPath, "config", "log4j2.xml"),
			filepath.Join(searchPath, "log4j2.xml"),
			filepath.Join(searchPath, "log4j2-spring.xml"),
		}

		for _, cfgPath := range configFiles {
			if _, err := os.Stat(cfgPath); err == nil {
				g.analyzeLogbackConfigForApp(cfgPath, proc.JavaApp)
			}
		}
	}
}

// analyzeLogbackConfigForApp 分析 Java 应用的日志配置
func (g *LogGuard) analyzeLogbackConfigForApp(path, appName string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// 检查是否有滚动策略
	hasRollingPolicy := strings.Contains(content, "SizeBasedTriggeringPolicy") ||
		strings.Contains(content, "TimeBasedRollingPolicy") ||
		strings.Contains(content, "SizeAndTimeBasedRollingPolicy")
	hasMaxHistory := strings.Contains(content, "maxHistory") || strings.Contains(content, "maxFileSize")
	hasTotalCap := strings.Contains(content, "totalSizeCap")

	if !hasRollingPolicy {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("日志配置缺陷: %s (%s)", appName, path),
			fmt.Sprintf("应用 %s 的日志配置 %s 缺少滚动策略（SizeBasedTriggeringPolicy/TimeBasedRollingPolicy），\n这是导致日志暴涨的根本原因！\n建议添加:\n<rollingPolicy class=\"ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy\">\n  <fileNamePattern>%s.%%d{yyyy-MM-dd}.%%i.log.gz</fileNamePattern>\n  <maxFileSize>100MB</maxFileSize>\n  <maxHistory>30</maxHistory>\n  <totalSizeCap>2GB</totalSizeCap>\n</rollingPolicy>", appName, path, filepath.Base(path)),
			"log-config-defect-001")
	} else if !hasMaxHistory {
		g.eventBus.PublishAlert(types.AlertWarning, "log",
			fmt.Sprintf("日志配置缺陷: %s", path),
			fmt.Sprintf("应用 %s 的日志配置 %s 有滚动策略但未设置 maxHistory/maxFileSize，可能导致日志累积。", appName, path),
			"log-config-defect-002")
	} else if !hasTotalCap {
		g.eventBus.PublishAlert(types.AlertInfo, "log",
			fmt.Sprintf("日志配置建议: %s", path),
			fmt.Sprintf("应用 %s 的日志配置 %s 建议添加 <totalSizeCap> 限制总日志大小。", appName, path),
			"log-config-defect-003")
	}
}

// ============================================================
// 根分区保护器 — 综合磁盘保护
// ============================================================

// RootPartitionProtector 根分区保护器
// 当根分区使用率超过阈值时，执行多层清理策略：
//  1. 删除旧轮转日志文件
//  2. copytruncate 截断活跃 Java 日志文件
//  3. 清理包管理器缓存
//  4. 清理 journalctl 日志
//  5. 告警并建议手动处理
type RootPartitionProtector struct {
	eventBus interface {
		PublishAlert(types.AlertLevel, string, string, string, string)
	}
	safety *safety.SafetyManager
}

// NewRootPartitionProtector 创建根分区保护器
func NewRootPartitionProtector(eventBus interface {
	PublishAlert(types.AlertLevel, string, string, string, string)
}, sm *safety.SafetyManager) *RootPartitionProtector {
	return &RootPartitionProtector{
		eventBus: eventBus,
		safety:   sm,
	}
}

// Protect 执行根分区保护
// diskUsagePercent: 根分区当前使用率
// 增强策略：优先检测和清理幽灵文件（已删除但句柄未释放的隐形空间占用）
func (p *RootPartitionProtector) Protect(diskUsagePercent float64) {
	if diskUsagePercent < 85 {
		return
	}

	// 步骤0（最高优先级）：检测和清理幽灵文件
	// 幽灵文件是"隐形"的空间占用，du看不到但df显示满
	// 典型场景：Java进程stdout/stderr日志被删除后句柄未释放
	ghostCleaner := NewGhostFileCleaner(p.eventBus, p.safety)
	ghostFreed, ghosts, _ := ghostCleaner.CleanGhostFiles()
	if ghostFreed > 0 {
		// 幽灵文件清理后重新评估磁盘使用率
		// 由于无法在这里直接获取最新磁盘使用率，继续执行其他清理
		_ = ghosts
	}

	// 85%: 预防性清理
	if diskUsagePercent >= 85 && diskUsagePercent < 90 {
		p.eventBus.PublishAlert(types.AlertWarning, "log",
			"根分区空间预警",
			fmt.Sprintf("根分区使用率 %.1f%%，执行预防性清理", diskUsagePercent),
			"root-partition-protect-001")
		p.preventiveCleanup()
		return
	}

	// 90%: 紧急清理
	if diskUsagePercent >= 90 && diskUsagePercent < 95 {
		p.eventBus.PublishAlert(types.AlertError, "log",
			"根分区空间告急",
			fmt.Sprintf("根分区使用率 %.1f%%，执行紧急清理（幽灵文件+截断大日志+清理缓存）", diskUsagePercent),
			"root-partition-protect-002")
		p.emergencyCleanup()
		return
	}

	// 95%: 极度紧急 — 全力清理
	if diskUsagePercent >= 95 {
		p.eventBus.PublishAlert(types.AlertCritical, "log",
			"根分区空间极度紧急",
			fmt.Sprintf("根分区使用率 %.1f%%，执行全力清理（幽灵文件+截断所有大日志+清理缓存+清理journal）", diskUsagePercent),
			"root-partition-protect-003")
		p.emergencyCleanup()
		p.cleanJournalctl()
		p.cleanPackageManagerCache()
	}
}

// preventiveCleanup 预防性清理
func (p *RootPartitionProtector) preventiveCleanup() {
	freed := int64(0)
	cutoff := time.Now().AddDate(0, 0, -7)

	// 清理 CleanupWhitelist 中的旧日志
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
		p.eventBus.PublishAlert(types.AlertInfo, "log",
			"预防性清理完成",
			fmt.Sprintf("已释放 %.2fMB 空间（清理7天以上的旧轮转日志）", float64(freed)/1024/1024),
			"preventive-cleanup-001")
	}
}

// emergencyCleanup 紧急清理
func (p *RootPartitionProtector) emergencyCleanup() {
	// 使用 EmergencyLogCleaner 执行日志清理
	cleaner := NewEmergencyLogCleaner(p.eventBus, p.safety)
	cleaner.EmergencyLogCleanup()
}

// cleanJournalctl 清理 systemd journal 日志
func (p *RootPartitionProtector) cleanJournalctl() {
	if runtime.GOOS == "windows" {
		return
	}

	// journalctl --vacuum-size=100M 只保留最近100MB日志
	cmd := exec.Command("journalctl", "--vacuum-size=100M")
	if err := cmd.Run(); err == nil {
		p.eventBus.PublishAlert(types.AlertInfo, "log",
			"Journal日志清理完成",
			"已将 systemd journal 日志压缩到100MB以内",
			"journal-cleanup-001")
	}

	// 同时清理旧的时间 rotated journal 文件
	cmd2 := exec.Command("journalctl", "--vacuum-time=3d")
	_ = cmd2.Run()
}

// cleanPackageManagerCache 清理包管理器缓存
func (p *RootPartitionProtector) cleanPackageManagerCache() {
	if runtime.GOOS == "windows" {
		return
	}

	// yum/dnf clean
	if _, err := exec.LookPath("yum"); err == nil {
		cmd := exec.Command("yum", "clean", "all")
		_ = cmd.Run()
		p.eventBus.PublishAlert(types.AlertInfo, "log",
			"Yum缓存清理完成", "已清理 yum 缓存", "yum-cache-cleanup-001")
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		cmd := exec.Command("dnf", "clean", "all")
		_ = cmd.Run()
	}

	// apt clean
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd := exec.Command("apt-get", "clean")
		_ = cmd.Run()
		cmd2 := exec.Command("apt-get", "autoclean")
		_ = cmd2.Run()
		p.eventBus.PublishAlert(types.AlertInfo, "log",
			"Apt缓存清理完成", "已清理 apt 缓存", "apt-cache-cleanup-001")
	}

	// pip cache
	if _, err := exec.LookPath("pip"); err == nil {
		cmd := exec.Command("pip", "cache", "purge")
		_ = cmd.Run()
	}

	// npm cache
	if _, err := exec.LookPath("npm"); err == nil {
		cmd := exec.Command("npm", "cache", "clean", "--force")
		_ = cmd.Run()
	}
}

// ============================================================
// 日志目录自动扫描增强
// ============================================================

// EnrichedScanPaths 返回增强后的日志扫描路径
// 在原有 /var/log 基础上，自动添加 Java 应用日志目录
func EnrichedScanPaths(basePaths []string) []string {
	if runtime.GOOS == "windows" {
		return basePaths
	}

	// 发现 Java 应用日志路径
	discovery := NewJavaAppLogDiscovery()
	discovery.Discover()
	javaPaths := discovery.GetDiscoveredPaths()

	// 合并去重
	seen := make(map[string]bool)
	result := make([]string, 0, len(basePaths)+len(javaPaths))
	for _, p := range basePaths {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range javaPaths {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}

	return result
}

// ScanLogTail 读取日志文件的最后 N 行
// 用于快速查看 Java 应用日志内容
func ScanLogTail(path string, lines int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 读取最后 64KB
	stat, _ := f.Stat()
	fileSize := stat.Size()
	readSize := int64(64 * 1024)
	if readSize > fileSize {
		readSize = fileSize
	}
	f.Seek(fileSize-readSize, 0)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var allLines []string
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	start := 0
	if len(allLines) > lines {
		start = len(allLines) - lines
	}
	return allLines[start:], nil
}
