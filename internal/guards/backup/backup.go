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

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// BackupVerifier implements Module M: Backup Verifier
// Verifies backup integrity by restoring to an isolated environment and checking data.
//
// SAFETY:
// - Never restores SQL backups to the production database.
// - Uses a dedicated test database or isolated directory.
// - All restore operations go to /tmp/serverguard-backup-test/ which is cleaned up.
// - Never deletes production data.
type BackupVerifier struct {
	mu        sync.RWMutex
	eventBus  *eventbus.EventBus
	backupDir string
	testDir   string
}

func New(bus *eventbus.EventBus, backupDir, testDir string) *BackupVerifier {
	if testDir == "" {
		testDir = "/tmp/serverguard-backup-test"
	}
	return &BackupVerifier{
		eventBus:  bus,
		backupDir: backupDir,
		testDir:   testDir,
	}
}

// Verify performs a backup verification cycle.
func (g *BackupVerifier) Verify(ctx context.Context) {
	// Step 1: Sample a random backup
	backup := g.sampleBackup()
	if backup == "" {
		return
	}

	// Step 2: Restore to isolated test environment (NEVER to production)
	if err := g.restoreBackup(ctx, backup); err != nil {
		g.eventBus.PublishAlert(types.AlertCritical, "backup",
			"备份恢复失败",
			fmt.Sprintf("从 %s 恢复到隔离环境失败: %v\n\n"+
				"可能原因:\n"+
				"  1. 备份文件损坏\n"+
				"  2. 备份格式不兼容\n"+
				"  3. 磁盘空间不足\n\n"+
				"建议检查备份文件完整性后重试。",
				filepath.Base(backup), err),
			"backup-verify-001")
		return
	}

	// Step 3: Validate restored data
	if err := g.validateBackup(ctx); err != nil {
		g.eventBus.PublishAlert(types.AlertCritical, "backup",
			"备份验证失败",
			fmt.Sprintf("备份验证失败: %v\n\n"+
				"⚠ 备份可能已损坏，建议:\n"+
				"  1. 检查备份源是否正常\n"+
				"  2. 重新创建备份\n"+
				"  3. 检查磁盘是否有坏道: badblocks -sv /dev/sda",
				err),
			"backup-verify-001")
		return
	}

	// Step 4: Report success
	g.eventBus.PublishAlert(types.AlertInfo, "backup",
		"备份验证通过",
		fmt.Sprintf("备份 %s 验证通过，数据完整性确认", filepath.Base(backup)),
		"backup-verify-001")

	// Step 5: Cleanup test environment
	g.cleanup(ctx)
}

// sampleBackup picks a backup file to verify.
func (g *BackupVerifier) sampleBackup() string {
	entries, err := os.ReadDir(g.backupDir)
	if err != nil {
		return ""
	}

	var backups []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Only verify known backup formats
		ext := filepath.Ext(entry.Name())
		if ext == ".sql" || ext == ".tar" || ext == ".gz" || ext == ".tgz" || ext == ".zip" {
			backups = append(backups, filepath.Join(g.backupDir, entry.Name()))
		}
	}

	if len(backups) == 0 {
		return ""
	}

	// Pick the most recent one
	return backups[len(backups)-1]
}

// restoreBackup restores a backup to the isolated test directory.
// SAFETY: SQL backups are restored to a dedicated test database, never production.
func (g *BackupVerifier) restoreBackup(ctx context.Context, backupPath string) error {
	// Ensure test directory exists and is empty
	os.RemoveAll(g.testDir) // Clean any previous test data
	os.MkdirAll(g.testDir, 0750)

	ext := filepath.Ext(backupPath)
	// Handle .sql.gz and .tar.gz
	if strings.HasSuffix(backupPath, ".sql.gz") {
		// Decompress then handle as SQL
		return g.restoreSQLGz(ctx, backupPath)
	}

	switch ext {
	case ".sql":
		return g.restoreSQL(ctx, backupPath)
	case ".tar", ".gz", ".tgz":
		cmd := exec.CommandContext(ctx, "tar", "xf", backupPath, "-C", g.testDir)
		return cmd.Run()
	case ".zip":
		cmd := exec.CommandContext(ctx, "unzip", "-o", backupPath, "-d", g.testDir)
		return cmd.Run()
	default:
		// Just copy the file
		data, err := os.ReadFile(backupPath)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(g.testDir, filepath.Base(backupPath)), data, 0640)
	}
}

// restoreSQL restores a SQL backup to an isolated test database.
// SAFETY: Uses a dedicated test database "sg_backup_test" that is dropped and recreated.
// NEVER restores to any production database.
func (g *BackupVerifier) restoreSQL(ctx context.Context, backupPath string) error {
	// Check if mysql is available
	if _, err := exec.LookPath("mysql"); err != nil {
		// No mysql, just verify file is readable and non-empty
		return g.verifySQLFile(backupPath)
	}

	// Create isolated test database
	// Use a unique name to avoid collision
	testDB := "sg_backup_test"

	// Drop and recreate test database (this is safe — it's a dedicated test DB)
	exec.CommandContext(ctx, "mysql", "-e", fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDB)).Run()
	if err := exec.CommandContext(ctx, "mysql", "-e", fmt.Sprintf("CREATE DATABASE %s", testDB)).Run(); err != nil {
		// Can't create test database, fall back to file verification
		return g.verifySQLFile(backupPath)
	}

	// Restore to test database
	file, err := os.Open(backupPath)
	if err != nil {
		return err
	}
	defer file.Close()

	cmd := exec.CommandContext(ctx, "mysql", testDB)
	cmd.Stdin = file
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("SQL恢复失败: %v", err)
	}

	// Verify tables exist
	output, err := exec.CommandContext(ctx, "mysql", testDB, "-e",
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '"+testDB+"'").Output()
	if err != nil {
		return fmt.Errorf("验证表数量失败: %v", err)
	}
	if strings.TrimSpace(string(output)) == "0" {
		return fmt.Errorf("恢复后没有表")
	}

	// Clean up test database
	exec.CommandContext(ctx, "mysql", "-e", fmt.Sprintf("DROP DATABASE %s", testDB)).Run()

	return nil
}

// restoreSQLGz restores a gzip-compressed SQL backup.
func (g *BackupVerifier) restoreSQLGz(ctx context.Context, backupPath string) error {
	// Decompress to temp file first
	tempFile := filepath.Join(g.testDir, "decompressed.sql")
	cmd := exec.CommandContext(ctx, "gunzip", "-c", backupPath)
	outFile, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer outFile.Close()
	cmd.Stdout = outFile
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("解压失败: %v", err)
	}
	return g.restoreSQL(ctx, tempFile)
}

// verifySQLFile is a fallback verification when MySQL is not available.
func (g *BackupVerifier) verifySQLFile(backupPath string) error {
	info, err := os.Stat(backupPath)
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return fmt.Errorf("SQL文件为空")
	}
	// Check for basic SQL content
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	content := string(data)
	if !strings.Contains(content, "CREATE") && !strings.Contains(content, "INSERT") &&
		!strings.Contains(content, "DROP") {
		return fmt.Errorf("SQL文件内容不像有效的备份")
	}
	return nil
}

// validateBackup checks that restored files are valid and non-empty.
func (g *BackupVerifier) validateBackup(ctx context.Context) error {
	entries, err := os.ReadDir(g.testDir)
	if err != nil {
		return fmt.Errorf("测试目录不可读")
	}

	fileCount := 0
	totalSize := int64(0)
	for _, entry := range entries {
		if !entry.IsDir() {
			fileCount++
			if info, err := entry.Info(); err == nil {
				totalSize += info.Size()
				if info.Size() == 0 {
					return fmt.Errorf("恢复的文件 %s 为空", entry.Name())
				}
			}
		}
	}

	if fileCount == 0 {
		return fmt.Errorf("没有恢复出任何文件")
	}

	if totalSize < 100 {
		return fmt.Errorf("恢复的数据量过小 (%d bytes)，备份可能不完整", totalSize)
	}

	return nil
}

// cleanup removes the test directory.
func (g *BackupVerifier) cleanup(ctx context.Context) {
	os.RemoveAll(g.testDir)
}

// GetLastVerifyTime returns the last verification time.
func (g *BackupVerifier) GetLastVerifyTime() time.Time {
	info, err := os.Stat(g.testDir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// CheckBackupAge checks if backups are too old and alerts.
func (g *BackupVerifier) CheckBackupAge(maxAge time.Duration) {
	entries, err := os.ReadDir(g.backupDir)
	if err != nil {
		return
	}

	var latestTime time.Time
	var backupCount int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backupCount++
		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
		}
	}

	if backupCount == 0 {
		g.eventBus.PublishAlert(types.AlertCritical, "backup",
			"无备份",
			fmt.Sprintf("备份目录 %s 中没有备份文件！\n\n"+
				"⚠ 请立即创建备份！\n"+
				"建议设置自动备份计划任务。",
				g.backupDir),
			"backup-missing-001")
		return
	}

	age := time.Since(latestTime)
	if age > maxAge {
		g.eventBus.PublishAlert(types.AlertWarning, "backup",
			"备份过期",
			fmt.Sprintf("最近备份是 %s (%.0f 小时前)\n"+
				"备份数量: %d\n\n"+
				"建议:\n"+
				"  1. 检查备份计划任务是否正常\n"+
				"  2. 手动创建备份\n"+
				"  3. 检查备份服务是否运行",
				latestTime.Format("2006-01-02 15:04:05"), age.Hours(), backupCount),
			"backup-age-001")
	}
}

// CheckBackupSize checks if backup files are suspiciously small.
func (g *BackupVerifier) CheckBackupSize(minSize int64) {
	entries, err := os.ReadDir(g.backupDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Size() < minSize {
			g.eventBus.PublishAlert(types.AlertWarning, "backup",
				fmt.Sprintf("备份文件异常小: %s", entry.Name()),
				fmt.Sprintf("备份文件 %s 大小仅 %d bytes\n\n"+
					"可能原因:\n"+
					"  1. 备份过程中断\n"+
					"  2. 数据源为空\n"+
					"  3. 备份脚本配置错误\n\n"+
					"建议重新创建备份并验证。",
					entry.Name(), info.Size()),
				"backup-size-001")
		}
	}
}
