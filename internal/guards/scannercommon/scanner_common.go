package scannercommon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// Scanner 安全扫描器统一接口
type Scanner interface {
	Name() string
	SubScanner() string
	Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error)
}

// QuarantineManager 隔离管理器（W/X/Y 模块共用）
type QuarantineManager struct {
	quarantineDir string
	mu            sync.Mutex
}

// NewQuarantineManager 创建隔离管理器
func NewQuarantineManager(baseDir string) *QuarantineManager {
	qDir := filepath.Join(baseDir, "quarantine")
	_ = os.MkdirAll(qDir, 0750)
	return &QuarantineManager{quarantineDir: qDir}
}

// Quarantine 隔离文件（移动到隔离目录，保留原权限和时间戳）
func (q *QuarantineManager) Quarantine(filePath string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, err := os.Stat(filePath); err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}

	// 保留原始权限和时间戳
	stat, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("stat file: %w", err)
	}

	// 生成隔离路径：quarantine/original_name.timestamp.uuid
	quarantinedPath := filepath.Join(q.quarantineDir,
		fmt.Sprintf("%s.%d.%s", filepath.Base(filePath), time.Now().Unix(), uuid.New().String()[:8]))

	// 移动文件
	if err := os.Rename(filePath, quarantinedPath); err != nil {
		// 如果跨设备移动失败，尝试复制+删除
		if err := copyAndDelete(filePath, quarantinedPath); err != nil {
			return "", fmt.Errorf("quarantine file: %w", err)
		}
	}

	// 恢复原始权限
	_ = os.Chmod(quarantinedPath, stat.Mode())

	return quarantinedPath, nil
}

// Restore 从隔离恢复文件
func (q *QuarantineManager) Restore(quarantinedPath, originalPath string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, err := os.Stat(quarantinedPath); err != nil {
		return fmt.Errorf("quarantined file not found: %w", err)
	}

	return os.Rename(quarantinedPath, originalPath)
}

// ListQuarantined 列出所有隔离文件
func (q *QuarantineManager) ListQuarantined() ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	entries, err := os.ReadDir(q.quarantineDir)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, e := range entries {
		result = append(result, filepath.Join(q.quarantineDir, e.Name()))
	}
	return result, nil
}

// CleanQuarantine 清理过期的隔离文件
func (q *QuarantineManager) CleanQuarantine(maxAge time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	entries, err := os.ReadDir(q.quarantineDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(q.quarantineDir, e.Name()))
		}
	}
	return nil
}

func copyAndDelete(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return err
	}
	return os.Remove(src)
}

// BaselineManager 基线管理器（文件哈希基线）
type BaselineManager struct {
	store    *storage.Storage
	mu       sync.RWMutex
	baseline map[string]string // path -> sha256
}

// NewBaselineManager 创建基线管理器
func NewBaselineManager(store *storage.Storage) *BaselineManager {
	return &BaselineManager{
		store:    store,
		baseline: make(map[string]string),
	}
}

// ReportBuilder 报告生成器
type ReportBuilder struct {
	scanner   string
	target    string
	startTime time.Time
	findings  []types.ScanFinding
}

// NewReportBuilder 创建报告生成器
func NewReportBuilder(scanner, target string) *ReportBuilder {
	return &ReportBuilder{
		scanner:   scanner,
		target:    target,
		startTime: time.Now(),
		findings:  make([]types.ScanFinding, 0),
	}
}

// AddFinding 添加发现项
func (rb *ReportBuilder) AddFinding(severity types.Severity, title, description, target, detail, suggestion, consequence string) {
	finding := types.ScanFinding{
		ID:          uuid.New().String(),
		Scanner:     rb.scanner,
		Severity:    severity,
		Title:       title,
		Description: description,
		Target:      target,
		Detail:      detail,
		Suggestion:  suggestion,
		Consequence: consequence,
	}
	rb.findings = append(rb.findings, finding)
}

// Build 构建扫描报告
func (rb *ReportBuilder) Build() types.ScanReport {
	summary := types.ScanSummary{Total: len(rb.findings)}
	for _, f := range rb.findings {
		switch f.Severity {
		case types.SeverityCritical:
			summary.Critical++
		case types.SeverityHigh:
			summary.High++
		case types.SeverityMedium:
			summary.Medium++
		case types.SeverityLow:
			summary.Low++
		case types.SeverityInfo:
			summary.Info++
		}
	}
	return types.ScanReport{
		Scanner:   rb.scanner,
		Target:    rb.target,
		ScannedAt: rb.startTime,
		Duration:  time.Since(rb.startTime),
		Findings:  rb.findings,
		Summary:   summary,
	}
}

// GetFindings 获取发现项
func (rb *ReportBuilder) GetFindings() []types.ScanFinding {
	return rb.findings
}

// SaveFindingsToStorage 将发现项保存到存储
func SaveFindingsToStorage(store *storage.Storage, findings []types.ScanFinding) error {
	for _, f := range findings {
		finding := &storage.Finding{
			ID:          f.ID,
			Scanner:     f.Scanner,
			ScannerSub:  f.ScannerSub,
			Severity:    string(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Target:      f.Target,
			Detail:      f.Detail,
			Suggestion:  f.Suggestion,
			Consequence: f.Consequence,
			Snapshot:    f.Snapshot,
			Status:      string(types.FindingStatusOpen),
		}
		if err := store.SaveFinding(finding); err != nil {
			return fmt.Errorf("save finding: %w", err)
		}
	}
	return nil
}
