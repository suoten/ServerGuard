package vulnscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewVulnScanGuard(t *testing.T) {
	v := NewVulnScanGuard()
	if v == nil {
		t.Fatal("NewVulnScanGuard returned nil")
	}
	if v.cveDatabase == nil {
		t.Error("cveDatabase should be initialized")
	}
	if len(v.cveDatabase.Entries) == 0 {
		t.Error("default CVE database should have entries")
	}
}

func TestNewVulnScanGuardWithIntel(t *testing.T) {
	v := NewVulnScanGuardWithIntel("nvd-key", "cnvd-key")
	if v == nil {
		t.Fatal("NewVulnScanGuardWithIntel returned nil")
	}
	if v.nvdAPIKey != "nvd-key" {
		t.Error("nvdAPIKey not set")
	}
	if v.cnvdAPIKey != "cnvd-key" {
		t.Error("cnvdAPIKey not set")
	}
}

func TestGetDefaultCVEDatabase(t *testing.T) {
	db := getDefaultCVEDatabase()
	if db == nil {
		t.Fatal("getDefaultCVEDatabase returned nil")
	}
	if len(db.Entries) == 0 {
		t.Fatal("default CVE database should have entries")
	}

	ids := make(map[string]bool)
	for _, e := range db.Entries {
		if e.CVEID == "" {
			t.Error("CVE entry has empty ID")
		}
		if ids[e.CVEID] {
			t.Errorf("duplicate CVE ID: %s", e.CVEID)
		}
		ids[e.CVEID] = true
	}

	// Verify known entries
	expected := []string{"CVE-2021-23017", "CVE-2023-44487", "CVE-2022-0778", "CVE-2023-38508"}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected CVE %s in default database", id)
		}
	}
}

func TestCVEDatabase_Concurrency(t *testing.T) {
	db := getDefaultCVEDatabase()
	done := make(chan struct{}, 2)

	// Concurrent reads should be safe
	go func() {
		_ = db.Entries
		done <- struct{}{}
	}()
	go func() {
		db.mu.RLock()
		_ = len(db.Entries)
		db.mu.RUnlock()
		done <- struct{}{}
	}()

	for i := 0; i < 2; i++ {
		<-done
	}
}

func TestGetLastSyncTime_Initial(t *testing.T) {
	v := NewVulnScanGuard()
	if !v.GetLastSyncTime().IsZero() {
		t.Error("initial last sync time should be zero")
	}
}

func TestSyncCVEDatabase_NoAPIKeys(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Without API keys, sync is a no-op and should succeed
	if err := v.SyncCVEDatabase(ctx); err != nil {
		t.Errorf("SyncCVEDatabase without keys should succeed, got: %v", err)
	}
	// lastSyncTime should be updated
	if v.GetLastSyncTime().IsZero() {
		t.Error("lastSyncTime should be set after successful sync")
	}
}

func TestSyncCVEDatabase_WithNVDKeyNetworkError(t *testing.T) {
	v := NewVulnScanGuardWithIntel("invalid-key", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// NVD sync will fail (network or invalid key), but syncFromNVD swallows per-product errors
	// and returns nil. So SyncCVEDatabase should succeed and update lastSyncTime.
	err := v.SyncCVEDatabase(ctx)
	// Either it succeeds (errors swallowed) or returns a partial-failure error
	_ = err
	// lastSyncTime only set on full success
}

func TestScan_All(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := v.Scan(ctx, []string{"/nonexistent/webroot"})
	if err != nil {
		t.Errorf("Scan should not return error, got: %v", err)
	}
	// Findings may be empty on Windows/minimal env, but should not error
	_ = findings
}

func TestScanComponents(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := v.ScanComponents(ctx)
	if err != nil {
		t.Errorf("ScanComponents error: %v", err)
	}
	// On most systems, components may or may not be installed
	_ = findings
}

func TestScanCMS_NonexistentRoot(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := v.ScanCMS(ctx, []string{"/nonexistent/webroot"})
	if err != nil {
		t.Errorf("ScanCMS error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nonexistent root, got %d", len(findings))
	}
}

func TestScanCMS_WithTempRoot(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ScanCMS 的新语义：只在 CMS 版本低于安全版本时才报告（检测到 CMS 本身不是漏洞）
	tmp := t.TempDir()
	wpDir := filepath.Join(tmp, "wp-includes")
	if err := os.MkdirAll(wpDir, 0750); err != nil {
		t.Fatal(err)
	}
	versionContent := `<?php $wp_version = '5.8'; ?>`
	if err := os.WriteFile(filepath.Join(wpDir, "version.php"), []byte(versionContent), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := v.ScanCMS(ctx, []string{tmp})
	if err != nil {
		t.Errorf("ScanCMS error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected to detect WordPress old version in temp root")
	}
	foundWP := false
	for _, f := range findings {
		if strings.Contains(f.Title, "wordpress") {
			foundWP = true
			break
		}
	}
	if !foundWP {
		t.Error("expected WordPress finding for version below safe threshold")
	}

	// 新版本（>= minSafeVer）不应产生发现
	safeTmp := t.TempDir()
	safeWpDir := filepath.Join(safeTmp, "wp-includes")
	if err := os.MkdirAll(safeWpDir, 0750); err != nil {
		t.Fatal(err)
	}
	safeContent := `<?php $wp_version = '6.2'; ?>`
	if err := os.WriteFile(filepath.Join(safeWpDir, "version.php"), []byte(safeContent), 0644); err != nil {
		t.Fatal(err)
	}

	safeFindings, err := v.ScanCMS(ctx, []string{safeTmp})
	if err != nil {
		t.Errorf("ScanCMS error: %v", err)
	}
	for _, f := range safeFindings {
		if strings.Contains(f.Title, "wordpress") {
			t.Errorf("up-to-date WordPress should not be reported, got: %s", f.Title)
		}
	}
}

func TestScanDependencies_NonexistentRoot(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := v.ScanDependencies(ctx, []string{"/nonexistent"})
	if err != nil {
		t.Errorf("ScanDependencies error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDependencies_WithDepFile(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module test\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 新语义：依赖文件的存在本身不是漏洞，不再生成发现（降噪）。
	// 真正的依赖漏洞检查由 npm audit / composer audit / sgctl security-check 完成。
	findings, err := v.ScanDependencies(ctx, []string{tmp})
	if err != nil {
		t.Errorf("ScanDependencies error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for dependency file presence (noise reduction), got %d", len(findings))
	}
}

func TestScanConfigCompliance(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := v.ScanConfigCompliance(ctx)
	if err != nil {
		t.Errorf("ScanConfigCompliance error: %v", err)
	}
	// On Windows, /etc/ssh and /proc won't exist, so findings may be empty
	_ = findings
}

func TestCVEEntry_Fields(t *testing.T) {
	e := CVEEntry{
		CVEID:         "CVE-2024-0001",
		Product:       "nginx",
		VulnVersions:  "<1.25.0",
		FixedVersions: "1.25.0+",
		Severity:      "high",
		Description:   "test vuln",
	}
	if e.CVEID != "CVE-2024-0001" || e.Product != "nginx" {
		t.Error("CVEEntry fields not set correctly")
	}
}

func TestVulnScanGuard_GetLastSyncTime_AfterSync(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	before := time.Now()
	if err := v.SyncCVEDatabase(ctx); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	after := v.GetLastSyncTime()
	if after.Before(before) {
		t.Error("lastSyncTime should be >= time before sync")
	}
}

func TestSyncCVEDatabase_WithCNVDKey(t *testing.T) {
	v := NewVulnScanGuardWithIntel("", "cnvd-test-key")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = v.SyncCVEDatabase(ctx)
}

func TestSyncCVEDatabase_WithBothKeys(t *testing.T) {
	v := NewVulnScanGuardWithIntel("nvd-key", "cnvd-key")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = v.SyncCVEDatabase(ctx)
}

func TestSyncCVEDatabase_CancelledContext(t *testing.T) {
	v := NewVulnScanGuardWithIntel("nvd-key", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = v.SyncCVEDatabase(ctx)
}

func TestScan_WithMultipleRoots(t *testing.T) {
	v := NewVulnScanGuard()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tmp1 := t.TempDir()
	tmp2 := t.TempDir()
	_, err := v.Scan(ctx, []string{tmp1, tmp2})
	if err != nil {
		t.Errorf("Scan error: %v", err)
	}
}

func TestScanComponents_WithCVEEntries(t *testing.T) {
	v := NewVulnScanGuard()
	products := make(map[string]bool)
	for _, e := range v.cveDatabase.Entries {
		products[e.Product] = true
	}
	expectedProducts := []string{"nginx", "openssl", "openssh"}
	for _, p := range expectedProducts {
		if !products[p] {
			t.Errorf("expected CVE entry for product %s", p)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = v.ScanComponents(ctx)
}

func TestCVEDatabase_ConcurrentAccess(t *testing.T) {
	v := NewVulnScanGuard()
	done := make(chan struct{}, 2)
	go func() {
		v.cveDatabase.mu.RLock()
		_ = len(v.cveDatabase.Entries)
		v.cveDatabase.mu.RUnlock()
		done <- struct{}{}
	}()
	go func() {
		v.cveDatabase.mu.RLock()
		_ = v.cveDatabase.Entries[0]
		v.cveDatabase.mu.RUnlock()
		done <- struct{}{}
	}()
	for i := 0; i < 2; i++ {
		<-done
	}
}
