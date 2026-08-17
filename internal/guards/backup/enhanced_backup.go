package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BackupValidator provides comprehensive backup validation.
// SAFETY: All restores go to isolated directories. Never touches production data.
type BackupValidator struct {
	mu           sync.RWMutex
	validateDir  string
}

func NewBackupValidator() *BackupValidator {
	return &BackupValidator{
		validateDir: "/tmp/sg-backup-validate",
	}
}

type ValidationReport struct {
	BackupFile string        `json:"backup_file"`
	Success    bool          `json:"success"`
	Duration   time.Duration `json:"duration"`
	Errors     []string      `json:"errors"`
	Checks     []CheckResult `json:"checks"`
	FileCount  int           `json:"file_count"`
	TotalSize  int64         `json:"total_size"`
}

type CheckResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Validate performs comprehensive backup validation.
func (v *BackupValidator) Validate(ctx context.Context, backupFile string) (*ValidationReport, error) {
	start := time.Now()
	report := &ValidationReport{
		BackupFile: backupFile,
	}

	// Prepare isolated environment
	envReady, err := v.prepareIsolatedEnv(ctx)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("无法创建隔离环境: %v", err))
		report.Duration = time.Since(start)
		return report, nil
	}
	if !envReady {
		report.Errors = append(report.Errors, "隔离环境不可用，跳过验证")
		report.Duration = time.Since(start)
		return report, nil
	}

	defer v.cleanup()

	// Restore to isolated environment
	if restored, err := v.restore(ctx, backupFile); err != nil || !restored {
		report.Errors = append(report.Errors, fmt.Sprintf("恢复失败: %v", err))
		report.Duration = time.Since(start)
		return report, nil
	}
	report.Checks = append(report.Checks, CheckResult{
		Name:   "restore",
		Passed: true,
		Detail: "备份恢复成功",
	})

	// Verify file count and sizes
	if count, size, err := v.verifyFiles(); err == nil {
		report.FileCount = count
		report.TotalSize = size
		report.Checks = append(report.Checks, CheckResult{
			Name:   "file_integrity",
			Passed: count > 0 && size > 100,
			Detail: fmt.Sprintf("文件数: %d, 总大小: %d bytes", count, size),
		})
		if count == 0 {
			report.Errors = append(report.Errors, "恢复后无文件")
		}
	}

	// Verify SQL content (if it's a SQL backup)
	if strings.HasSuffix(backupFile, ".sql") || strings.HasSuffix(backupFile, ".sql.gz") {
		if passed, detail := v.verifySQLContent(); true {
			report.Checks = append(report.Checks, CheckResult{
				Name:   "sql_content",
				Passed: passed,
				Detail: detail,
			})
			if !passed {
				report.Errors = append(report.Errors, "SQL内容验证失败")
			}
		}
	}

	// Verify file permissions
	if passed, detail := v.verifyPermissions(); true {
		report.Checks = append(report.Checks, CheckResult{
			Name:   "permissions",
			Passed: passed,
			Detail: detail,
		})
	}

	report.Success = len(report.Errors) == 0
	report.Duration = time.Since(start)
	return report, nil
}

func (v *BackupValidator) prepareIsolatedEnv(ctx context.Context) (bool, error) {
	// Clean any previous validation data
	os.RemoveAll(v.validateDir)
	if err := os.MkdirAll(v.validateDir, 0750); err != nil {
		return false, err
	}
	return true, nil
}

func (v *BackupValidator) restore(ctx context.Context, backupFile string) (bool, error) {
	ext := filepath.Ext(backupFile)
	switch ext {
	case ".tar", ".gz", ".tgz":
		cmd := exec.CommandContext(ctx, "tar", "-xf", backupFile, "-C", v.validateDir)
		return cmd.Run() == nil, nil
	case ".zip":
		cmd := exec.CommandContext(ctx, "unzip", "-o", backupFile, "-d", v.validateDir)
		return cmd.Run() == nil, nil
	case ".sql":
		// Just copy the file for verification
		data, err := os.ReadFile(backupFile)
		if err != nil {
			return false, err
		}
		err = os.WriteFile(filepath.Join(v.validateDir, filepath.Base(backupFile)), data, 0640)
		return err == nil, err
	default:
		data, err := os.ReadFile(backupFile)
		if err != nil {
			return false, err
		}
		err = os.WriteFile(filepath.Join(v.validateDir, filepath.Base(backupFile)), data, 0640)
		return err == nil, err
	}
}

// verifyFiles counts restored files and checks for empty files.
func (v *BackupValidator) verifyFiles() (count int, size int64, err error) {
	err = filepath.Walk(v.validateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		count++
		size += info.Size()
		if info.Size() == 0 {
			return fmt.Errorf("文件 %s 为空", info.Name())
		}
		return nil
	})
	return
}

// verifySQLContent checks if SQL backup contains expected statements.
func (v *BackupValidator) verifySQLContent() (bool, string) {
	// Find SQL file in validation directory
	var sqlFile string
	filepath.Walk(v.validateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".sql") {
			sqlFile = path
		}
		return nil
	})

	if sqlFile == "" {
		return false, "未找到SQL文件"
	}

	data, err := os.ReadFile(sqlFile)
	if err != nil {
		return false, "无法读取SQL文件"
	}

	content := string(data)
	hasCreate := strings.Contains(content, "CREATE")
	hasInsert := strings.Contains(content, "INSERT")
	hasDrop := strings.Contains(content, "DROP")

	if !hasCreate && !hasInsert && !hasDrop {
		return false, "SQL文件缺少 CREATE/INSERT/DROP 语句"
	}

	detail := fmt.Sprintf("CREATE: %v, INSERT: %v, DROP: %v, 文件大小: %.1f KB",
		hasCreate, hasInsert, hasDrop, float64(len(data))/1024)
	return true, detail
}

// verifyPermissions checks if restored files have reasonable permissions.
func (v *BackupValidator) verifyPermissions() (bool, string) {
	issueCount := 0
	filepath.Walk(v.validateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Check for world-writable files (security risk)
		if info.Mode().Perm()&0002 != 0 {
			issueCount++
		}
		return nil
	})
	if issueCount > 0 {
		return false, fmt.Sprintf("%d 个文件具有 world-writable 权限", issueCount)
	}
	return true, "权限检查通过"
}

func (v *BackupValidator) cleanup() {
	os.RemoveAll(v.validateDir)
}

// BackupScheduler manages periodic backup validation.
type BackupScheduler struct {
	mu           sync.RWMutex
	validator    *BackupValidator
	interval     time.Duration
	lastValidate time.Time
}

func NewBackupScheduler() *BackupScheduler {
	return &BackupScheduler{
		validator: NewBackupValidator(),
		interval:  7 * 24 * time.Hour,
	}
}

func (s *BackupScheduler) ShouldValidate() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.lastValidate) >= s.interval
}

func (s *BackupScheduler) Validate(ctx context.Context, backupFile string) (*ValidationReport, error) {
	report, err := s.validator.Validate(ctx, backupFile)
	if err == nil && report.Success {
		s.mu.Lock()
		s.lastValidate = time.Now()
		s.mu.Unlock()
	}
	return report, err
}

// SetInterval allows customizing the validation interval.
func (s *BackupScheduler) SetInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = d
}
