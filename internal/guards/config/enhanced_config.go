package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ConfigBackupManager struct {
	mu          sync.RWMutex
	backupDir   string
	maxVersions int
}

func NewConfigBackupManager() *ConfigBackupManager {
	return &ConfigBackupManager{
		backupDir:   "/var/lib/serverguard/config-backups",
		maxVersions: 100,
	}
}

type ConfigVersionInfo struct {
	CommitID  string    `json:"commit_id"`
	FilePath  string    `json:"file_path"`
	Tag       string    `json:"tag"`
	Author    string    `json:"author"`
	Message   string    `json:"message"`
	Hash      string    `json:"hash"`
	Diff      string    `json:"diff"`
	CreatedAt time.Time `json:"created_at"`
}

func (m *ConfigBackupManager) Backup(filePath, author, message string) (*ConfigVersionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(content))
	timestamp := time.Now().Format("20060102-150405")
	commitID := timestamp + "-" + hash[:8]

	backupPath := filepath.Join(m.backupDir, filepath.Base(filePath)+"."+commitID)
	if err := os.MkdirAll(m.backupDir, 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return nil, err
	}

	diff := ""
	prevBackup := m.findPreviousBackup(filePath)
	if prevBackup != "" {
		prevContent, _ := os.ReadFile(prevBackup)
		diff = m.generateDiff(string(prevContent), string(content))
	}

	info := &ConfigVersionInfo{
		CommitID:  commitID,
		FilePath:  filePath,
		Author:    author,
		Message:   message,
		Hash:      hash,
		Diff:      diff,
		CreatedAt: time.Now(),
	}

	m.cleanupOldVersions(filePath)
	return info, nil
}

func (m *ConfigBackupManager) findPreviousBackup(filePath string) string {
	baseName := filepath.Base(filePath)
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return ""
	}

	var backups []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), baseName+".") {
			backups = append(backups, filepath.Join(m.backupDir, entry.Name()))
		}
	}
	if len(backups) == 0 {
		return ""
	}
	sort.Sort(sort.Reverse(sort.StringSlice(backups)))
	return backups[0]
}

func (m *ConfigBackupManager) generateDiff(old, new string) string {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")

	var diff strings.Builder
	maxLines := len(oldLines)
	if len(newLines) > maxLines {
		maxLines = len(newLines)
	}

	for i := 0; i < maxLines; i++ {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}
		if oldLine != newLine {
			if oldLine != "" {
				diff.WriteString(fmt.Sprintf("- %s\n", oldLine))
			}
			if newLine != "" {
				diff.WriteString(fmt.Sprintf("+ %s\n", newLine))
			}
		}
	}
	return diff.String()
}

func (m *ConfigBackupManager) Rollback(filePath, commitID string) error {
	backupPath := filepath.Join(m.backupDir, filepath.Base(filePath)+"."+commitID)
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("backup not found: %w", err)
	}
	return os.WriteFile(filePath, content, 0644)
}

func (m *ConfigBackupManager) ListVersions(filePath string) ([]ConfigVersionInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	baseName := filepath.Base(filePath)
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return nil, err
	}

	var versions []ConfigVersionInfo
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), baseName+".") {
			continue
		}
		info, _ := entry.Info()
		commitID := strings.TrimPrefix(entry.Name(), baseName+".")
		versions = append(versions, ConfigVersionInfo{
			CommitID:  commitID,
			FilePath:  filePath,
			CreatedAt: info.ModTime(),
		})
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].CreatedAt.After(versions[j].CreatedAt)
	})

	if len(versions) > m.maxVersions {
		versions = versions[:m.maxVersions]
	}
	return versions, nil
}

func (m *ConfigBackupManager) cleanupOldVersions(filePath string) {
	baseName := filepath.Base(filePath)
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return
	}

	var backups []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), baseName+".") {
			backups = append(backups, entry.Name())
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(backups)))
	if len(backups) > m.maxVersions {
		for i := m.maxVersions; i < len(backups); i++ {
			os.Remove(filepath.Join(m.backupDir, backups[i]))
		}
	}
}

func (m *ConfigBackupManager) Export(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}

func (m *ConfigBackupManager) Import(filePath string, data []byte) error {
	return os.WriteFile(filePath, data, 0644)
}

func (m *ConfigBackupManager) Tag(filePath, commitID, tag string) error {
	tagFile := filepath.Join(m.backupDir, "tags", commitID)
	os.MkdirAll(filepath.Dir(tagFile), 0755)
	return os.WriteFile(tagFile, []byte(tag), 0644)
}

func (m *ConfigBackupManager) GetTag(commitID string) (string, error) {
	tagFile := filepath.Join(m.backupDir, "tags", commitID)
	data, err := os.ReadFile(tagFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
