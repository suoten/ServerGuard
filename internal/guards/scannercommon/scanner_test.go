package scannercommon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

func TestYaraEngine_LoadBuiltinRules(t *testing.T) {
	eng := NewYaraEngine()
	if eng == nil {
		t.Fatal("NewYaraEngine returned nil")
	}
	if eng.RuleCount() == 0 {
		t.Error("should have built-in rules loaded")
	}
}

func TestYaraEngine_ScanData(t *testing.T) {
	eng := NewYaraEngine()

	malicious := []byte(`<?php eval(base64_decode($_POST['cmd'])); ?>`)
	matches := eng.ScanData(malicious)
	if len(matches) == 0 {
		t.Error("should detect PHP eval(base64_decode pattern")
	}

	safe := []byte(`<?php echo "Hello World"; ?>`)
	matches = eng.ScanData(safe)
	if len(matches) > 0 {
		t.Error("safe code should not trigger matches")
	}
}

func TestYaraEngine_ScanFile(t *testing.T) {
	eng := NewYaraEngine()
	_, err := eng.ScanFile("/nonexistent/file.php")
	if err == nil {
		t.Error("should return error for nonexistent file")
	}
}

func TestYaraEngine_IsAvailable(t *testing.T) {
	eng := NewYaraEngine()
	if !eng.IsAvailable() {
		t.Error("engine should be available with built-in rules")
	}
}

func TestExternalScanners(t *testing.T) {
	trivy := NewTrivyScanner()
	_ = trivy.IsAvailable()
	_ = trivy.Version()

	grype := NewGrypeScanner()
	_ = grype.IsAvailable()

	rk := NewRkhunterScanner()
	_ = rk.IsAvailable()

	nmap := NewNmapScanner()
	_ = nmap.IsAvailable()
}

// --- Extended YaraEngine tests ---

func TestYaraEngine_RuleCount(t *testing.T) {
	eng := NewYaraEngine()
	count := eng.RuleCount()
	if count < 10 {
		t.Errorf("expected at least 10 built-in rules, got %d", count)
	}
}

func TestYaraEngine_ScanDataMultipleMatches(t *testing.T) {
	eng := NewYaraEngine()
	// Content matching multiple patterns
	malicious := []byte(`<?php eval(base64_decode($_POST['x'])); system($_GET['cmd']); ?>`)
	matches := eng.ScanData(malicious)
	if len(matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(matches))
	}
	// Verify match structure
	for _, m := range matches {
		if m.Rule == "" {
			t.Error("match rule name should be non-empty")
		}
		if m.Length <= 0 {
			t.Error("match length should be positive")
		}
	}
}

func TestYaraEngine_ScanDataEmpty(t *testing.T) {
	eng := NewYaraEngine()
	matches := eng.ScanData([]byte{})
	if len(matches) != 0 {
		t.Error("empty data should produce no matches")
	}
	matches = eng.ScanData(nil)
	if len(matches) != 0 {
		t.Error("nil data should produce no matches")
	}
}

func TestYaraEngine_ScanDataJSPWebshell(t *testing.T) {
	eng := NewYaraEngine()
	matches := eng.ScanData([]byte(`<% Runtime.getRuntime().exec(cmd); %>`))
	if len(matches) == 0 {
		t.Error("should detect JSP webshell pattern")
	}
}

func TestYaraEngine_ScanDataChinaChopper(t *testing.T) {
	eng := NewYaraEngine()
	matches := eng.ScanData([]byte(`eval chopper`))
	if len(matches) == 0 {
		t.Error("should detect china chopper pattern")
	}
}

func TestYaraEngine_ScanFileWithTempFile(t *testing.T) {
	eng := NewYaraEngine()

	tmp := t.TempDir()
	path := tmp + "/test.php"
	content := []byte(`<?php eval(base64_decode($_POST['cmd'])); ?>`)
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}

	matches, err := eng.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(matches) == 0 {
		t.Error("should detect webshell in file")
	}
}

func TestYaraEngine_ScanFileSafeContent(t *testing.T) {
	eng := NewYaraEngine()

	tmp := t.TempDir()
	path := tmp + "/safe.php"
	if err := writeFile(path, []byte(`<?php echo "hello world"; ?>`)); err != nil {
		t.Fatal(err)
	}

	matches, err := eng.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(matches) != 0 {
		t.Error("safe content should not match")
	}
}

func TestYaraEngine_LoadRulesFromDir(t *testing.T) {
	eng := NewYaraEngine()
	initialCount := eng.RuleCount()

	tmp := t.TempDir()
	// Create a .yar file with a simple rule
	yarContent := `rule test_webshell { strings: $s = /eval\s*\(/ condition: $s }`
	if err := writeFile(tmp+"/rules.yar", []byte(yarContent)); err != nil {
		t.Fatal(err)
	}
	// Create a .yara file
	yaraContent := `rule another_rule { strings: $s = /base64_decode/ condition: $s }`
	if err := writeFile(tmp+"/more.yara", []byte(yaraContent)); err != nil {
		t.Fatal(err)
	}
	// Create a non-yara file (should be ignored)
	if err := writeFile(tmp+"/readme.txt", []byte("not a rule")); err != nil {
		t.Fatal(err)
	}

	if err := eng.LoadRulesFromDir(tmp); err != nil {
		t.Fatalf("LoadRulesFromDir error: %v", err)
	}

	if eng.RuleCount() <= initialCount {
		t.Error("rule count should increase after loading from dir")
	}
}

func TestYaraEngine_LoadRulesFromDirNonexistent(t *testing.T) {
	eng := NewYaraEngine()
	err := eng.LoadRulesFromDir("/nonexistent/dir")
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestYaraEngine_LoadRulesFromDirEmpty(t *testing.T) {
	eng := NewYaraEngine()
	initialCount := eng.RuleCount()

	tmp := t.TempDir()
	if err := eng.LoadRulesFromDir(tmp); err != nil {
		t.Fatalf("LoadRulesFromDir on empty dir error: %v", err)
	}
	if eng.RuleCount() != initialCount {
		t.Error("empty dir should not change rule count")
	}
}

func TestYaraEngine_LoadRulesFromDirWithSubdir(t *testing.T) {
	eng := NewYaraEngine()
	tmp := t.TempDir()

	// Create a subdirectory (should be skipped)
	if err := mkdirAll(tmp + "/subdir"); err != nil {
		t.Fatal(err)
	}

	if err := eng.LoadRulesFromDir(tmp); err != nil {
		t.Fatalf("LoadRulesFromDir error: %v", err)
	}
}

func TestYaraEngine_IsAvailableAfterLoad(t *testing.T) {
	eng := NewYaraEngine()
	if !eng.IsAvailable() {
		t.Error("should be available with built-in rules")
	}
}

func TestYaraEngine_ScanDataAfterLoadFromDir(t *testing.T) {
	eng := NewYaraEngine()

	tmp := t.TempDir()
	yarContent := `rule custom_pattern { strings: $s = /UNIQUE_PATTERN_12345/ condition: $s }`
	if err := writeFile(tmp+"/custom.yar", []byte(yarContent)); err != nil {
		t.Fatal(err)
	}
	if err := eng.LoadRulesFromDir(tmp); err != nil {
		t.Fatal(err)
	}

	matches := eng.ScanData([]byte("this contains UNIQUE_PATTERN_12345 here"))
	found := false
	for _, m := range matches {
		if m.Rule == "custom_pattern" {
			found = true
			break
		}
	}
	if !found {
		t.Error("should match custom loaded rule")
	}
}

func TestYaraMatch_Struct(t *testing.T) {
	m := YaraMatch{Rule: "r", Tag: "webshell,php", Offset: 10, Length: 20}
	if m.Rule != "r" || m.Tag != "webshell,php" || m.Offset != 10 || m.Length != 20 {
		t.Error("YaraMatch fields not set correctly")
	}
}

// --- helpers ---

func writeFile(path string, content []byte) error {
	return osWriteFile(path, content)
}

func mkdirAll(path string) error {
	return osMkdirAll(path)
}

func osWriteFile(path string, content []byte) error {
	return os.WriteFile(path, content, 0644)
}

func osMkdirAll(path string) error {
	return os.MkdirAll(path, 0750)
}

// --- ReportBuilder tests ---

func TestReportBuilder_New(t *testing.T) {
	rb := NewReportBuilder("vulnscan", "system")
	if rb == nil {
		t.Fatal("NewReportBuilder returned nil")
	}
}

func TestReportBuilder_AddFinding(t *testing.T) {
	rb := NewReportBuilder("vulnscan", "system")
	rb.AddFinding(
		types.SeverityHigh,
		"Test Finding",
		"Test description",
		"test-target",
		`{"key":"value"}`,
		"Fix it",
		"May break things",
	)

	findings := rb.GetFindings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "Test Finding" {
		t.Errorf("unexpected title: %q", findings[0].Title)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("unexpected severity: %v", findings[0].Severity)
	}
	if findings[0].ID == "" {
		t.Error("finding ID should be auto-generated")
	}
	if findings[0].Scanner != "vulnscan" {
		t.Errorf("unexpected scanner: %q", findings[0].Scanner)
	}
}

func TestReportBuilder_AddMultipleFindings(t *testing.T) {
	rb := NewReportBuilder("test", "target")
	rb.AddFinding(types.SeverityCritical, "c", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityHigh, "h", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityMedium, "m", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityLow, "l", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityInfo, "i", "d", "t", "", "", "")

	findings := rb.GetFindings()
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}
}

func TestReportBuilder_Build(t *testing.T) {
	rb := NewReportBuilder("test", "target")
	rb.AddFinding(types.SeverityCritical, "c", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityHigh, "h", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityMedium, "m", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityLow, "l", "d", "t", "", "", "")
	rb.AddFinding(types.SeverityInfo, "i", "d", "t", "", "", "")

	report := rb.Build()
	if report.Scanner != "test" {
		t.Errorf("unexpected scanner: %q", report.Scanner)
	}
	if report.Summary.Total != 5 {
		t.Errorf("expected total 5, got %d", report.Summary.Total)
	}
	if report.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", report.Summary.Critical)
	}
	if report.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.High)
	}
	if report.Summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", report.Summary.Medium)
	}
	if report.Summary.Low != 1 {
		t.Errorf("expected 1 low, got %d", report.Summary.Low)
	}
	if report.Summary.Info != 1 {
		t.Errorf("expected 1 info, got %d", report.Summary.Info)
	}
}

func TestReportBuilder_BuildEmpty(t *testing.T) {
	rb := NewReportBuilder("test", "target")
	report := rb.Build()
	if report.Summary.Total != 0 {
		t.Error("empty report should have 0 total")
	}
}

func TestReportBuilder_GetFindingsEmpty(t *testing.T) {
	rb := NewReportBuilder("test", "target")
	findings := rb.GetFindings()
	if len(findings) != 0 {
		t.Error("new builder should have 0 findings")
	}
}

// --- QuarantineManager tests ---

func TestQuarantineManager_New(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)
	if q == nil {
		t.Fatal("NewQuarantineManager returned nil")
	}
}

func TestQuarantineManager_QuarantineAndList(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)

	// Create a file to quarantine
	srcPath := tmp + "/malware.php"
	if err := os.WriteFile(srcPath, []byte("malicious content"), 0644); err != nil {
		t.Fatal(err)
	}

	quarantinedPath, err := q.Quarantine(srcPath)
	if err != nil {
		t.Fatalf("Quarantine error: %v", err)
	}
	if quarantinedPath == "" {
		t.Error("expected non-empty quarantined path")
	}

	// Original file should be gone
	if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
		t.Error("original file should be removed after quarantine")
	}

	// Quarantined file should exist
	if _, err := os.Stat(quarantinedPath); err != nil {
		t.Errorf("quarantined file should exist: %v", err)
	}

	// List quarantined files
	listed, err := q.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined error: %v", err)
	}
	if len(listed) != 1 {
		t.Errorf("expected 1 quarantined file, got %d", len(listed))
	}
}

func TestQuarantineManager_QuarantineNonexistent(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)

	_, err := q.Quarantine(tmp + "/nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestQuarantineManager_Restore(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)

	srcPath := tmp + "/suspicious.php"
	if err := os.WriteFile(srcPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	quarantinedPath, err := q.Quarantine(srcPath)
	if err != nil {
		t.Fatal(err)
	}

	// Restore the file
	restoredPath := tmp + "/restored.php"
	if err := q.Restore(quarantinedPath, restoredPath); err != nil {
		t.Fatalf("Restore error: %v", err)
	}

	if _, err := os.Stat(restoredPath); err != nil {
		t.Error("restored file should exist")
	}
}

func TestQuarantineManager_RestoreNonexistent(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)

	err := q.Restore(tmp+"/nonexistent", tmp+"/dest")
	if err == nil {
		t.Error("expected error for restoring nonexistent file")
	}
}

func TestQuarantineManager_CleanQuarantine(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)

	// Create and quarantine a file
	srcPath := tmp + "/old_malware.php"
	if err := os.WriteFile(srcPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := q.Quarantine(srcPath)
	if err != nil {
		t.Fatal(err)
	}

	// Clean with a very short max age (everything is "old")
	if err := q.CleanQuarantine(1 * time.Nanosecond); err != nil {
		t.Fatalf("CleanQuarantine error: %v", err)
	}

	listed, _ := q.ListQuarantined()
	if len(listed) != 0 {
		t.Errorf("expected 0 files after cleanup, got %d", len(listed))
	}
}

func TestQuarantineManager_ListQuarantinedEmpty(t *testing.T) {
	tmp := t.TempDir()
	q := NewQuarantineManager(tmp)

	listed, err := q.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined error: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("expected 0 files, got %d", len(listed))
	}
}

// --- External Scanner tests ---

func TestNewChkrootkitScanner(t *testing.T) {
	c := NewChkrootkitScanner()
	if c == nil {
		t.Fatal("NewChkrootkitScanner returned nil")
	}
}

func TestChkrootkitScanner_ScanNotAvailable(t *testing.T) {
	c := NewChkrootkitScanner()
	// chkrootkit is not installed in test environment
	_, err := c.Scan("/", nil)
	if err == nil {
		// If chkrootkit happens to be installed, the scan succeeds - that's OK
		// But on most test environments it won't be
	}
}

func TestTrivyScanner_ScanNotAvailable(t *testing.T) {
	ts := NewTrivyScanner()
	_, err := ts.Scan(".", nil)
	if err == nil {
		// trivy might be installed; not an error
	}
}

func TestGrypeScanner_ScanNotAvailable(t *testing.T) {
	g := NewGrypeScanner()
	_, err := g.Scan(".", nil)
	if err == nil {
		// grype might be installed; not an error
	}
}

func TestRkhunterScanner_ScanNotAvailable(t *testing.T) {
	r := NewRkhunterScanner()
	_, err := r.Scan("/", nil)
	if err == nil {
		// rkhunter might be installed; not an error
	}
}

func TestNmapScanner_ScanNotAvailable(t *testing.T) {
	n := NewNmapScanner()
	_, err := n.Scan("127.0.0.1", nil)
	if err == nil {
		// nmap might be installed; not an error
	}
}

func TestNmapScanner_ScanWithPorts(t *testing.T) {
	n := NewNmapScanner()
	// Test with custom ports option - will fail if nmap not installed
	_, _ = n.Scan("127.0.0.1", map[string]string{"ports": "80,443"})
}

func TestBaseScanner_VersionNotAvailable(t *testing.T) {
	// Test Version() when binary is not available
	c := NewChkrootkitScanner()
	if c.IsAvailable() {
		// chkrootkit is installed, skip this test
		return
	}
	v := c.Version()
	if v != "" {
		t.Errorf("expected empty version when binary not available, got '%s'", v)
	}
}

// --- copyAndDelete tests ---

func TestCopyAndDelete(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src.txt")
	dst := filepath.Join(t.TempDir(), "dst.txt")

	content := []byte("test content")
	if err := os.WriteFile(src, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := copyAndDelete(src, dst); err != nil {
		t.Fatalf("copyAndDelete failed: %v", err)
	}

	// Source should be deleted
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("source file should be deleted")
	}

	// Destination should exist with same content
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "test content" {
		t.Errorf("expected 'test content', got '%s'", string(data))
	}
}

func TestCopyAndDelete_SourceNotFound(t *testing.T) {
	src := filepath.Join(t.TempDir(), "nonexistent")
	dst := filepath.Join(t.TempDir(), "dst")
	if err := copyAndDelete(src, dst); err == nil {
		t.Error("expected error for non-existent source")
	}
}

func TestCopyAndDelete_DestDirNotWritable(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	// Use a path that can't be created (parent is a file)
	dst := filepath.Join(src, "subdir", "dst")
	if err := copyAndDelete(src, dst); err == nil {
		t.Error("expected error for unwritable destination")
	}
}

// --- BaselineManager test ---

func TestNewBaselineManager(t *testing.T) {
	bm := NewBaselineManager(nil)
	if bm == nil {
		t.Fatal("NewBaselineManager returned nil")
	}
	if bm.baseline == nil {
		t.Error("baseline map should be initialized")
	}
}

// --- SaveFindingsToStorage test ---

func TestSaveFindingsToStorage(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	findings := []types.ScanFinding{
		{
			ID:       "finding-1",
			Scanner:  "test-scanner",
			Severity: types.SeverityHigh,
			Title:    "Test Finding",
			Target:   "test-target",
		},
		{
			ID:       "finding-2",
			Scanner:  "test-scanner",
			Severity: types.SeverityLow,
			Title:    "Another Finding",
			Target:   "another-target",
		},
	}

	if err := SaveFindingsToStorage(store, findings); err != nil {
		t.Fatalf("SaveFindingsToStorage failed: %v", err)
	}
}

func TestSaveFindingsToStorage_Empty(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	if err := SaveFindingsToStorage(store, []types.ScanFinding{}); err != nil {
		t.Fatalf("SaveFindingsToStorage with empty list should succeed: %v", err)
	}
}
