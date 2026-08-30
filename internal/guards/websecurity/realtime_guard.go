package websecurity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/guards/scannercommon"
	"github.com/suoten/serverguard/internal/types"
)

// ============================================================
// 实时挂马拦截 + 反弹 Shell 检测
// 通过定时轮询 web 目录文件变更（兼容无 inotify 的环境）
// 检测到新增可疑文件时自动隔离 + 告警
// ============================================================

// RealtimeGuard 实时文件防护
type RealtimeGuard struct {
	mu          sync.Mutex
	monitorDirs []string
	knownFiles  map[string]int64 // path -> mtime
	quarantine  *scannercommon.QuarantineManager
	suspiciousExts map[string]bool
	checkInterval time.Duration
}

// NewRealtimeGuard 创建实时防护实例
func NewRealtimeGuard(quarantine *scannercommon.QuarantineManager) *RealtimeGuard {
	return &RealtimeGuard{
		knownFiles:    make(map[string]int64),
		quarantine:    quarantine,
		checkInterval:  30 * time.Second,
		suspiciousExts: map[string]bool{
			".php":  true,
			".phtml": true,
			".php5": true,
			".php7": true,
			".pht":  true,
			".phar": true,
			".inc":  true,
			".asp":  true,
			".aspx": true,
			".jsp":  true,
			".jspx": true,
			".sh":   true,
			".py":   true,
			".pl":   true,
			".cgi":  true,
		},
	}
}

// AddMonitorDir 添加监控目录
func (g *RealtimeGuard) AddMonitorDir(dir string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.monitorDirs = append(g.monitorDirs, dir)
	// 初始化已知文件快照
	g.snapshotDir(dir)
}

// snapshotDir 记录目录下所有文件的当前 mtime
func (g *RealtimeGuard) snapshotDir(root string) {
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		g.knownFiles[path] = info.ModTime().Unix()
		return nil
	})
}

// Check 检查文件变更（轮询模式，每 30 秒一次）
func (g *RealtimeGuard) Check(ctx context.Context) []RealtimeFinding {
	findings := []RealtimeFinding{}
	g.mu.Lock()
	dirs := make([]string, len(g.monitorDirs))
	copy(dirs, g.monitorDirs)
	g.mu.Unlock()

	for _, dir := range dirs {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !g.suspiciousExts[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mtime := info.ModTime().Unix()

			g.mu.Lock()
			oldMtime, exists := g.knownFiles[path]
			g.mu.Unlock()

			if !exists {
				// 新文件
				g.mu.Lock()
				g.knownFiles[path] = mtime
				g.mu.Unlock()
				// 检查是否是最近创建的（7 天内）
				if time.Now().Unix()-mtime < 7*24*3600 {
					finding := g.analyzeNewFile(path, info)
					if finding != nil {
						findings = append(findings, *finding)
					}
				}
			} else if mtime != oldMtime {
				// 文件被修改
				g.mu.Lock()
				g.knownFiles[path] = mtime
				g.mu.Unlock()
				finding := g.analyzeModifiedFile(path, info)
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
			return nil
		})
	}
	return findings
}

// RealtimeFinding 实时检测结果
type RealtimeFinding struct {
	Type      types.Severity
	Title     string
	Message   string
	FilePath  string
	Action    string
	IsMalicious bool
}

// analyzeNewFile 分析新发现的文件
func (g *RealtimeGuard) analyzeNewFile(path string, info os.FileInfo) *RealtimeFinding {
	// 读取文件内容做快速检测
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	// 快速 Webshell 特征检测
	shellPatterns := []string{
		"eval(base64_decode(",
		"eval(gzinflate(",
		"assert($_POST",
		"eval($_POST",
		"system($_POST",
		"shell_exec($_",
		"passthru($_",
		"create_function(",
		"base64_decode(",
		"str_rot13(",
		"gzuncompress(",
	}

	content := strings.ToLower(string(data))
	for _, pat := range shellPatterns {
		if strings.Contains(content, pat) {
			return &RealtimeFinding{
				Type:        types.SeverityCritical,
				Title:       "实时拦截: 新增可疑 Webshell 文件",
				Message:     fmt.Sprintf("检测到新增文件 %s 包含 Webshell 特征码: %s。已自动隔离", path, pat),
				FilePath:    path,
				Action:      "auto_quarantine",
				IsMalicious: true,
			}
		}
	}

	// 检查文件名是否随机/可疑（但不作为唯一依据，只是附加信息）
	baseName := filepath.Base(path)
	return &RealtimeFinding{
		Type:        types.SeverityMedium,
		Title:       "实时告警: 新增可执行脚本文件",
		Message:     fmt.Sprintf("检测到新增脚本文件 %s（%s）。请人工确认是否为正常业务文件", path, baseName),
		FilePath:    path,
		Action:      "alert_only",
		IsMalicious: false,
	}
}

// analyzeModifiedFile 分析被修改的文件
func (g *RealtimeGuard) analyzeModifiedFile(path string, info os.FileInfo) *RealtimeFinding {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	content := strings.ToLower(string(data))
	// 检查是否被注入了恶意代码
	shellPatterns := []string{
		"eval(base64_decode(",
		"assert($_post",
		"eval($_post",
		"system($_post",
		"<iframe src=\"javascript:",
	}
	for _, pat := range shellPatterns {
		if strings.Contains(content, pat) {
			return &RealtimeFinding{
				Type:        types.SeverityCritical,
				Title:       "实时拦截: 文件被注入恶意代码",
				Message:     fmt.Sprintf("文件 %s 被修改并注入恶意代码: %s。已自动隔离", path, pat),
				FilePath:    path,
				Action:      "auto_quarantine",
				IsMalicious: true,
			}
		}
	}
	return nil
}

// QuarantineFile 隔离文件
func (g *RealtimeGuard) QuarantineFile(path string) error {
	if g.quarantine != nil {
		_, err := g.quarantine.Quarantine(path)
		return err
	}
	// 降级：重命名文件
	quarantinePath := path + ".quarantined"
	return os.Rename(path, quarantinePath)
}
