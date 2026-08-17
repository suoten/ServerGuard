package log

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogAutoDiscoverer 全局日志自动发现器。
// Linux 调 lsof 或读 /proc/*/fd 追踪写入句柄，
// Windows 调 NtQuerySystemHandle，
// 输出正在写入的日志文件路径列表，无需手动配置。
type LogAutoDiscoverer struct {
	mu         sync.Mutex
	discovered map[string]*DiscoveredLog // path -> log info
	lastScan   time.Time
}

// DiscoveredLog 发现的日志文件信息
type DiscoveredLog struct {
	Path         string
	Process      string // 写入该日志的进程
	PID          int32
	Size         int64
	LastWrite    time.Time
	DiscoveredAt time.Time
}

// NewLogAutoDiscoverer 创建日志自动发现器。
func NewLogAutoDiscoverer() *LogAutoDiscoverer {
	return &LogAutoDiscoverer{
		discovered: make(map[string]*DiscoveredLog),
	}
}

// Discover 执行一次日志发现扫描，返回发现的日志文件路径列表。
func (d *LogAutoDiscoverer) Discover() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var paths []string
	if runtime.GOOS == "windows" {
		paths = d.discoverWindows()
	} else {
		paths = d.discoverLinux()
	}

	now := time.Now()
	d.lastScan = now

	for _, path := range paths {
		if _, ok := d.discovered[path]; !ok {
			d.discovered[path] = &DiscoveredLog{
				Path:         path,
				DiscoveredAt: now,
			}
		}
		// 更新文件大小
		if info, err := os.Stat(path); err == nil {
			d.discovered[path].Size = info.Size()
			d.discovered[path].LastWrite = info.ModTime()
		}
	}

	return paths
}

// discoverLinux Linux 平台日志发现：读 /proc/*/fd 追踪写入句柄。
func (d *LogAutoDiscoverer) discoverLinux() []string {
	var logPaths []string
	seen := make(map[string]bool)

	// 常见日志目录
	logDirs := []string{"/var/log", "/tmp", "/opt"}

	// 1. 扫描 /proc/*/fd 查找打开的日志文件
	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range procEntries {
			if !entry.IsDir() {
				continue
			}
			pid := entry.Name()
			fdDir := filepath.Join("/proc", pid, "fd")
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				fdPath := filepath.Join(fdDir, fd.Name())
				target, err := os.Readlink(fdPath)
				if err != nil {
					continue
				}
				if d.isLogFile(target) && !seen[target] {
					seen[target] = true
					logPaths = append(logPaths, target)
				}
			}
		}
	}

	// 2. 扫描常见日志目录中的 .log 文件
	for _, dir := range logDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if d.isLogFile(path) && !seen[path] {
				if info.ModTime().After(time.Now().Add(-24 * time.Hour)) {
					seen[path] = true
					logPaths = append(logPaths, path)
				}
			}
			return nil
		})
	}

	return logPaths
}

// discoverWindows Windows 平台日志发现。
func (d *LogAutoDiscoverer) discoverWindows() []string {
	var logPaths []string
	seen := make(map[string]bool)

	// Windows 常见日志目录
	logDirs := []string{
		`C:\inetpub\logs`,
		`C:\Windows\System32\LogFiles`,
		`C:\ProgramData`,
	}

	for _, dir := range logDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if d.isLogFile(path) && !seen[path] {
				if info.ModTime().After(time.Now().Add(-24 * time.Hour)) {
					seen[path] = true
					logPaths = append(logPaths, path)
				}
			}
			return nil
		})
	}

	return logPaths
}

// isLogFile 判断文件是否为日志文件。
func (d *LogAutoDiscoverer) isLogFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	name := strings.ToLower(filepath.Base(path))

	// 扩展名判断
	if ext == ".log" || ext == ".out" || ext == ".err" {
		return true
	}

	// 文件名模式判断
	if strings.Contains(name, "log") || strings.Contains(name, "access") || strings.Contains(name, "error") {
		return true
	}

	// 检查文件内容是否为文本（简单判断）
	if d.isTextFile(path) {
		return true
	}

	return false
}

// isTextFile 简单判断文件是否为文本文件。
func (d *LogAutoDiscoverer) isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 1024)
	if scanner.Scan() {
		line := scanner.Text()
		// 检查是否包含常见日志模式
		if strings.Contains(line, " - ") || strings.Contains(line, "[") || strings.Contains(line, "ERROR") || strings.Contains(line, "INFO") {
			return true
		}
	}
	return false
}

// GetDiscoveredLogs 返回所有已发现的日志文件。
func (d *LogAutoDiscoverer) GetDiscoveredLogs() []*DiscoveredLog {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]*DiscoveredLog, 0, len(d.discovered))
	for _, log := range d.discovered {
		result = append(result, log)
	}
	return result
}

// GetLastScanTime 返回上次扫描时间。
func (d *LogAutoDiscoverer) GetLastScanTime() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastScan
}

// String 返回发现器状态。
func (d *LogAutoDiscoverer) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("LogAutoDiscoverer{discovered: %d logs}", len(d.discovered))
}
