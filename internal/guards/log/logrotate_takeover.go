package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LogrotateTakeoverManager logrotate 冲突让位与接管管理器。
// 检测 logrotate 已管理某日志时跳过该文件，
// 用户在面板选择接管时备份并注释 /etc/logrotate.d/xxx 的对应 block。
type LogrotateTakeoverManager struct {
	mu         sync.Mutex
	checker    *LogRotateChecker
	takenOver  map[string]bool   // 已接管的日志路径
	lastBackup map[string]string // 配置文件 -> 最近一次接管备份路径
}

// NewLogrotateTakeoverManager 创建 logrotate 接管管理器。
func NewLogrotateTakeoverManager() *LogrotateTakeoverManager {
	return &LogrotateTakeoverManager{
		checker:   NewLogRotateChecker(),
		takenOver: make(map[string]bool),
	}
}

// ShouldSkip 检查是否应跳过指定日志（被 logrotate 管理且未接管）。
func (m *LogrotateTakeoverManager) ShouldSkip(logPath string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 已接管的日志不跳过
	if m.takenOver[logPath] {
		return false
	}

	// 被 logrotate 管理的日志跳过
	return m.checker.IsManagedByLogrotate(logPath)
}

// TakeOverFromLogrotate 接管指定日志的轮转。
// 备份并注释 /etc/logrotate.d/xxx 的对应 block。
func (m *LogrotateTakeoverManager) TakeOverFromLogrotate(logPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 查找包含该日志的 logrotate 配置文件
	configFile, block, err := m.findLogrotateConfig(logPath)
	if err != nil {
		return fmt.Errorf("find logrotate config: %w", err)
	}
	if configFile == "" {
		// 未找到 logrotate 配置，无需接管
		m.takenOver[logPath] = true
		return nil
	}

	// 备份原配置（带时间戳）：固定 .sg.bak 文件名会在第二次接管时被
	// "已注释版本"覆盖，原始配置从此永久丢失，Release 恢复的也是注释版
	backupPath := configFile + ".sg.bak-" + time.Now().Format("20060102150405")
	if err := copyFile(configFile, backupPath); err != nil {
		return fmt.Errorf("备份 logrotate 配置失败: %w", err)
	}
	m.lastBackup[configFile] = backupPath

	// 注释掉对应的 block
	if err := m.commentOutBlock(configFile, block); err != nil {
		return fmt.Errorf("comment out block: %w", err)
	}

	m.takenOver[logPath] = true
	return nil
}

// ReleaseToLogrotate 将日志管理权交还给 logrotate。
// 恢复被注释的 logrotate 配置 block。
func (m *LogrotateTakeoverManager) ReleaseToLogrotate(logPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	configFile, _, err := m.findLogrotateConfig(logPath)
	if err != nil {
		return err
	}
	if configFile == "" {
		delete(m.takenOver, logPath)
		return nil
	}

	// 恢复备份：优先最近一次接管时的时间戳备份，兼容旧版固定 .sg.bak
	backupPath := ""
	if p, ok := m.lastBackup[configFile]; ok {
		if _, err := os.Stat(p); err == nil {
			backupPath = p
		}
	}
	if backupPath == "" {
		if entries, err := filepath.Glob(configFile + ".sg.bak-*"); err == nil && len(entries) > 0 {
			backupPath = entries[len(entries)-1] // Glob 按字典序=时间序
		}
	}
	if backupPath == "" {
		if _, err := os.Stat(configFile + ".sg.bak"); err == nil {
			backupPath = configFile + ".sg.bak"
		}
	}
	if backupPath == "" {
		// 无备份，无需恢复
		delete(m.takenOver, logPath)
		return nil
	}

	if err := copyFile(backupPath, configFile); err != nil {
		return fmt.Errorf("restore logrotate config: %w", err)
	}

	delete(m.takenOver, logPath)
	return nil
}

// IsTakenOver 检查指定日志是否已被 ServerGuard 接管。
func (m *LogrotateTakeoverManager) IsTakenOver(logPath string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.takenOver[logPath]
}

// GetTakenOverLogs 返回所有已接管的日志。
func (m *LogrotateTakeoverManager) GetTakenOverLogs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []string
	for path := range m.takenOver {
		result = append(result, path)
	}
	return result
}

// findLogrotateConfig 查找包含指定日志F日志路径的 logrotate 配置文件和对应 block。
func (m *LogrotateTakeoverManager) findLogrotateConfig(logPath string) (configFile string, block string, err error) {
	dirs := []string{"/etc/logrotate.d", "/etc/logrotate.conf"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if strings.Contains(string(content), logPath) {
				return path, extractBlock(string(content), logPath), nil
			}
		}
	}
	return "", "", nil
}

// extractBlock 从 logrotate 配置内容中提取包含指定路径的 block。
func extractBlock(content, path string) string {
	lines := strings.Split(content, "\n")
	var blockLines []string
	inBlock := false
	braceDepth := 0

	for _, line := range lines {
		if strings.Contains(line, path) || inBlock {
			inBlock = true
			blockLines = append(blockLines, line)
			if strings.Contains(line, "{") {
				braceDepth++
			}
			if strings.Contains(line, "}") {
				braceDepth--
				if braceDepth == 0 {
					break
				}
			}
		}
	}
	return strings.Join(blockLines, "\n")
}

// commentOutBlock 注释掉配置文件中的指定 block。
func (m *LogrotateTakeoverManager) commentOutBlock(configFile, block string) error {
	content, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	// 将 block 的每一行前面加 #
	commentedBlock := "# ServerGuard: disabled for takeover\n"
	for _, line := range strings.Split(block, "\n") {
		commentedBlock += "# " + line + "\n"
	}

	if strings.TrimSpace(block) == "" {
		return fmt.Errorf("提取到的 logrotate block 为空（路径可能只出现在注释行），拒绝改写配置文件")
	}
	newContent := strings.Replace(string(content), block, commentedBlock, 1)
	// 原子写：直接覆盖 /etc/logrotate.d/* 时写入中途崩溃会留下半个配置
	tmp := configFile + ".sg.tmp"
	if err := os.WriteFile(tmp, []byte(newContent), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, configFile)
}

// copyFile 复制文件。
func copyFile(src, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, content, 0644)
}
