package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// --- New / Close / DB ---

func TestStorage_NewAndClose(t *testing.T) {
	s := newTestStorage(t)

	if s == nil {
		t.Fatal("expected non-nil Storage")
	}
	if s.DB() == nil {
		t.Fatal("DB() should return non-nil *sql.DB")
	}
	if s.path == "" {
		t.Fatal("path should be set")
	}
}

func TestStorage_NewCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nestedDir := filepath.Join(dir, "nested", "deep")
	dbPath := filepath.Join(nestedDir, "test.db")
	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() should create nested dirs: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Fatal("nested directory was not created")
	}
}

// --- Metrics ---

func TestStorage_SaveMetricAndGetMetrics(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)
	m := types.Metric{
		Type:      types.MetricType("cpu"),
		Name:      "cpu_percent",
		Value:     75.5,
		Unit:      "%",
		Timestamp: now,
		Labels:    map[string]string{"host": "test"},
	}

	if err := s.SaveMetric(m); err != nil {
		t.Fatalf("SaveMetric failed: %v", err)
	}

	metrics, err := s.GetMetrics("cpu", "cpu_percent", now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].Value != 75.5 {
		t.Errorf("expected value 75.5, got %f", metrics[0].Value)
	}
	if metrics[0].Name != "cpu_percent" {
		t.Errorf("expected name cpu_percent, got %s", metrics[0].Name)
	}
}

func TestStorage_SaveMetricsBatch(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)
	metrics := []types.Metric{
		{Type: types.MetricType("mem"), Name: "mem_used", Value: 100, Unit: "MB", Timestamp: now},
		{Type: types.MetricType("mem"), Name: "mem_used", Value: 200, Unit: "MB", Timestamp: now.Add(1 * time.Second)},
		{Type: types.MetricType("mem"), Name: "mem_used", Value: 300, Unit: "MB", Timestamp: now.Add(2 * time.Second)},
	}

	if err := s.SaveMetrics(metrics); err != nil {
		t.Fatalf("SaveMetrics failed: %v", err)
	}

	got, err := s.GetMetrics("mem", "mem_used", now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(got))
	}
	// Should be ordered DESC by timestamp
	if got[0].Value != 300 {
		t.Errorf("expected first value 300 (newest), got %f", got[0].Value)
	}
}

func TestStorage_GetMetricsEmpty(t *testing.T) {
	s := newTestStorage(t)
	metrics, err := s.GetMetrics("nonexistent", "metric", time.Now().Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

// 回归测试：空 type/name 表示通配（不过滤）。
// 面板的 /api/servers/:id/metrics 与指标导出都用 GetMetrics("", "", ...) 调用，
// 原实现把它编译成 WHERE type='' AND name=''，永远返回空列表。
func TestStorage_GetMetricsWildcard(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)
	_ = s.SaveMetric(types.Metric{Type: types.MetricType("cpu"), Name: "cpu_percent", Value: 11, Timestamp: now})
	_ = s.SaveMetric(types.Metric{Type: types.MetricType("mem"), Name: "mem_percent", Value: 22, Timestamp: now})

	metrics, err := s.GetMetrics("", "", now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("wildcard GetMetrics failed: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics with wildcard filters, got %d", len(metrics))
	}

	// 只按 name 过滤、type 留空也应命中
	metrics, err = s.GetMetrics("", "cpu_percent", now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("half-wildcard GetMetrics failed: %v", err)
	}
	if len(metrics) != 1 || metrics[0].Name != "cpu_percent" {
		t.Fatalf("expected only cpu_percent, got %d metrics", len(metrics))
	}
}

// 回归测试：降采样把 raw 聚合进 metrics_1m 并删除后，GetMetrics / 基线统计
// 必须仍能读到历史数据（面板曲线和基线异常检测依赖这一点）。
func TestStorage_GetMetricsReadsAggregatedHistory(t *testing.T) {
	s := newTestStorage(t)
	d := NewDownsampler(s)

	old := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Minute)
	if err := s.SaveMetric(types.Metric{Type: types.MetricType("cpu"), Name: "cpu_percent", Value: 66.5, Timestamp: old}); err != nil {
		t.Fatalf("SaveMetric: %v", err)
	}

	// raw→1m 聚合并删除原始行
	if err := d.RunHourlyDownsample(); err != nil {
		t.Fatalf("RunHourlyDownsample: %v", err)
	}

	// 通配查询应能从聚合表读到该点
	metrics, err := s.GetMetrics("", "", old.Add(-time.Minute), 10)
	if err != nil {
		t.Fatalf("GetMetrics after downsample: %v", err)
	}
	found := false
	for _, m := range metrics {
		if m.Name == "cpu_percent" && m.Value == 66.5 {
			found = true
		}
	}
	if !found {
		t.Fatal("aggregated (metrics_1m) history should be visible via GetMetrics")
	}

	// 基线统计也应覆盖聚合数据
	buckets, err := s.GetMetricBaselineStats("cpu_percent", old.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("GetMetricBaselineStats: %v", err)
	}
	total := 0
	for _, b := range buckets {
		total += b.Count
	}
	if total == 0 {
		t.Fatal("baseline stats should include aggregated samples")
	}
}

func TestStorage_SaveMetricsEmpty(t *testing.T) {
	s := newTestStorage(t)

	if err := s.SaveMetrics([]types.Metric{}); err != nil {
		t.Errorf("SaveMetrics with empty slice should succeed: %v", err)
	}
}

// --- Alerts ---

func TestStorage_SaveAlertAndGetUnresolved(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)
	alert := types.Alert{
		ID:        "alert-1",
		Level:     types.AlertWarning,
		Title:     "High CPU",
		Message:   "CPU usage above 90%",
		Source:    "traffic",
		RuleID:    "rule-1",
		Timestamp: now,
		Labels:    map[string]string{"host": "server1"},
	}

	if err := s.SaveAlert(alert); err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}

	alerts, err := s.GetUnresolvedAlerts()
	if err != nil {
		t.Fatalf("GetUnresolvedAlerts failed: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Title != "High CPU" {
		t.Errorf("expected title 'High CPU', got '%s'", alerts[0].Title)
	}
	if alerts[0].Level != types.AlertWarning {
		t.Errorf("expected level warning, got %s", alerts[0].Level)
	}
}

func TestStorage_ResolveAlert(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC()
	alert := types.Alert{
		ID:        "alert-resolve",
		Level:     types.AlertError,
		Title:     "Disk Full",
		Message:   "Disk usage critical",
		Source:    "resource",
		Timestamp: now,
	}
	if err := s.SaveAlert(alert); err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}

	if err := s.ResolveAlert("alert-resolve"); err != nil {
		t.Fatalf("ResolveAlert failed: %v", err)
	}

	alerts, err := s.GetUnresolvedAlerts()
	if err != nil {
		t.Fatalf("GetUnresolvedAlerts failed: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 unresolved alerts after resolve, got %d", len(alerts))
	}
}

func TestStorage_AckAlert(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC()
	alert := types.Alert{
		ID:        "alert-ack",
		Level:     types.AlertCritical,
		Title:     "Service Down",
		Message:   "nginx not responding",
		Source:    "service",
		Timestamp: now,
	}
	if err := s.SaveAlert(alert); err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}

	if err := s.AckAlert("alert-ack"); err != nil {
		t.Fatalf("AckAlert failed: %v", err)
	}

	// Alert should still be unresolved (ack != resolve)
	alerts, err := s.GetUnresolvedAlerts()
	if err != nil {
		t.Fatalf("GetUnresolvedAlerts failed: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("acknowledged alert should still be unresolved, got %d", len(alerts))
	}
}

func TestStorage_SaveAlertReplace(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC()
	alert := types.Alert{
		ID:        "alert-rep",
		Level:     types.AlertInfo,
		Title:     "Original",
		Source:    "test",
		Timestamp: now,
	}
	if err := s.SaveAlert(alert); err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}

	// Replace with updated title
	alert.Title = "Updated"
	if err := s.SaveAlert(alert); err != nil {
		t.Fatalf("SaveAlert replace failed: %v", err)
	}

	alerts, err := s.GetUnresolvedAlerts()
	if err != nil {
		t.Fatalf("GetUnresolvedAlerts failed: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after replace, got %d", len(alerts))
	}
	if alerts[0].Title != "Updated" {
		t.Errorf("expected title 'Updated', got '%s'", alerts[0].Title)
	}
}

// --- Actions ---

func TestStorage_SaveActionAndGetHistory(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)
	result := types.ActionResult{
		Action:    types.Action{Type: types.ActionRestart},
		Success:   true,
		Message:   "restarted nginx",
		Duration:  500 * time.Millisecond,
		Timestamp: now,
	}

	if err := s.SaveAction("rule-restart", result); err != nil {
		t.Fatalf("SaveAction failed: %v", err)
	}

	history, err := s.GetActionHistory(now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetActionHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 action, got %d", len(history))
	}
	if !history[0].Success {
		t.Error("expected success=true")
	}
	if history[0].Action.Type != types.ActionRestart {
		t.Errorf("expected action type restart, got %s", history[0].Action.Type)
	}
	if history[0].Duration != 500*time.Millisecond {
		t.Errorf("expected duration 500ms, got %v", history[0].Duration)
	}
}

func TestStorage_GetActionHistoryByRule(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)

	// Save actions for two different rules
	r1 := types.ActionResult{
		Action:    types.Action{Type: types.ActionKill},
		Success:   true,
		Timestamp: now,
	}
	r2 := types.ActionResult{
		Action:    types.Action{Type: types.ActionBanIP},
		Success:   false,
		Error:     "iptables not found",
		Timestamp: now.Add(1 * time.Second),
	}

	if err := s.SaveAction("rule-A", r1); err != nil {
		t.Fatalf("SaveAction failed: %v", err)
	}
	if err := s.SaveAction("rule-B", r2); err != nil {
		t.Fatalf("SaveAction failed: %v", err)
	}

	// Query by rule-A
	entries, err := s.GetActionHistoryByRule("rule-A", now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetActionHistoryByRule failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for rule-A, got %d", len(entries))
	}
	if entries[0].RuleID != "rule-A" {
		t.Errorf("expected rule ID 'rule-A', got '%s'", entries[0].RuleID)
	}
	if !entries[0].Success {
		t.Error("expected success=true for rule-A")
	}

	// Query by rule-B
	entriesB, err := s.GetActionHistoryByRule("rule-B", now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetActionHistoryByRule failed: %v", err)
	}
	if len(entriesB) != 1 {
		t.Fatalf("expected 1 entry for rule-B, got %d", len(entriesB))
	}
	if entriesB[0].Success {
		t.Error("expected success=false for rule-B")
	}
	if entriesB[0].Error != "iptables not found" {
		t.Errorf("expected error 'iptables not found', got '%s'", entriesB[0].Error)
	}
}

func TestStorage_GetActionHistoryEmpty(t *testing.T) {
	s := newTestStorage(t)

	history, err := s.GetActionHistory(time.Now().Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetActionHistory failed: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected 0 actions, got %d", len(history))
	}
}

// --- Audit ---

func TestStorage_SaveAuditAndGetAuditLog(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC().Truncate(time.Second)
	entry := types.AuditEntry{
		ID:        "audit-1",
		Timestamp: now,
		Actor:     "user:admin",
		Action:    "kill_process",
		Target:    "nginx",
		Reason:    "high memory usage",
		Result:    "success",
		Details:   "killed PID 1234",
		IPAddress: "192.168.1.100",
	}

	if err := s.SaveAudit(entry); err != nil {
		t.Fatalf("SaveAudit failed: %v", err)
	}

	entries, err := s.GetAuditLog(now.Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].Actor != "user:admin" {
		t.Errorf("expected actor 'user:admin', got '%s'", entries[0].Actor)
	}
	if entries[0].Action != "kill_process" {
		t.Errorf("expected action 'kill_process', got '%s'", entries[0].Action)
	}
	if entries[0].IPAddress != "192.168.1.100" {
		t.Errorf("expected IP '192.168.1.100', got '%s'", entries[0].IPAddress)
	}
}

func TestStorage_GetAuditLogEmpty(t *testing.T) {
	s := newTestStorage(t)

	entries, err := s.GetAuditLog(time.Now().Add(-1*time.Hour), 10)
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// --- Guard Targets ---

func TestStorage_SaveAndGetGuardTargets(t *testing.T) {
	s := newTestStorage(t)

	target := types.GuardTarget{
		ID:          "target-1",
		Name:        "nginx",
		Type:        types.TargetSystemd,
		Command:     "systemctl start nginx",
		StopCommand: "systemctl stop nginx",
		Port:        80,
		HealthCheck: "http://localhost/health",
		ProcessName: "nginx",
		Enabled:     true,
	}

	if err := s.SaveGuardTarget(target); err != nil {
		t.Fatalf("SaveGuardTarget failed: %v", err)
	}

	targets, err := s.GetGuardTargets()
	if err != nil {
		t.Fatalf("GetGuardTargets failed: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Name != "nginx" {
		t.Errorf("expected name 'nginx', got '%s'", targets[0].Name)
	}
	if targets[0].Type != types.TargetSystemd {
		t.Errorf("expected type systemd, got %s", targets[0].Type)
	}
	if !targets[0].Enabled {
		t.Error("expected enabled=true")
	}
}

func TestStorage_GetGuardTargetsOnlyEnabled(t *testing.T) {
	s := newTestStorage(t)

	disabled := types.GuardTarget{
		ID:      "target-disabled",
		Name:    "old-service",
		Type:    types.TargetBare,
		Enabled: false,
	}
	enabled := types.GuardTarget{
		ID:      "target-enabled",
		Name:    "active-service",
		Type:    types.TargetBare,
		Enabled: true,
	}

	if err := s.SaveGuardTarget(disabled); err != nil {
		t.Fatalf("SaveGuardTarget failed: %v", err)
	}
	if err := s.SaveGuardTarget(enabled); err != nil {
		t.Fatalf("SaveGuardTarget failed: %v", err)
	}

	// 契约：GetGuardTargets 返回全量目标（含 disabled），
	// enabled 过滤由消费层负责（service.Check 跳过 disabled；面板需展示全部）
	targets, err := s.GetGuardTargets()
	if err != nil {
		t.Fatalf("GetGuardTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets (including disabled), got %d", len(targets))
	}
	enabledSeen := false
	for _, gt := range targets {
		if gt.ID == "target-enabled" && gt.Enabled {
			enabledSeen = true
		}
		if gt.ID == "target-disabled" && gt.Enabled {
			t.Errorf("disabled target returned with Enabled=true")
		}
	}
	if !enabledSeen {
		t.Errorf("expected enabled target present with Enabled=true")
	}
}

func TestStorage_DeleteGuardTarget(t *testing.T) {
	s := newTestStorage(t)

	target := types.GuardTarget{
		ID:      "target-delete",
		Name:    "temp-service",
		Type:    types.TargetBare,
		Enabled: true,
	}
	if err := s.SaveGuardTarget(target); err != nil {
		t.Fatalf("SaveGuardTarget failed: %v", err)
	}

	if err := s.DeleteGuardTarget("target-delete"); err != nil {
		t.Fatalf("DeleteGuardTarget failed: %v", err)
	}

	targets, err := s.GetGuardTargets()
	if err != nil {
		t.Fatalf("GetGuardTargets failed: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets after delete, got %d", len(targets))
	}
}

// --- KV Store ---

func TestStorage_SetAndGet(t *testing.T) {
	s := newTestStorage(t)

	if err := s.Set("key1", "value1"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	val, err := s.Get("key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "value1" {
		t.Errorf("expected 'value1', got '%s'", val)
	}
}

func TestStorage_GetNonExistentKey(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.Get("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestStorage_SetOverwrite(t *testing.T) {
	s := newTestStorage(t)

	s.Set("key", "original")
	s.Set("key", "overwritten")

	val, err := s.Get("key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "overwritten" {
		t.Errorf("expected 'overwritten', got '%s'", val)
	}
}

func TestStorage_GetKeyValue(t *testing.T) {
	s := newTestStorage(t)

	s.Set("kvkey", "kvvalue")

	val, err := s.GetKeyValue("kvkey")
	if err != nil {
		t.Fatalf("GetKeyValue failed: %v", err)
	}
	if val != "kvvalue" {
		t.Errorf("expected 'kvvalue', got '%s'", val)
	}
}

func TestStorage_GetKeysByPrefix(t *testing.T) {
	s := newTestStorage(t)

	s.Set("config:nginx:port", "80")
	s.Set("config:nginx:workers", "4")
	s.Set("config:redis:port", "6379")
	s.Set("other:key", "val")

	keys, err := s.GetKeysByPrefix("config:nginx:")
	if err != nil {
		t.Fatalf("GetKeysByPrefix failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys with prefix 'config:nginx:', got %d: %v", len(keys), keys)
	}

	allConfig, err := s.GetKeysByPrefix("config:")
	if err != nil {
		t.Fatalf("GetKeysByPrefix failed: %v", err)
	}
	if len(allConfig) != 3 {
		t.Fatalf("expected 3 keys with prefix 'config:', got %d: %v", len(allConfig), allConfig)
	}
}

func TestStorage_GetKeysByPrefixSkipsEmpty(t *testing.T) {
	s := newTestStorage(t)

	s.Set("active:key", "value")
	s.Set("deleted:key", "") // empty value = deleted

	keys, err := s.GetKeysByPrefix("")
	if err != nil {
		t.Fatalf("GetKeysByPrefix failed: %v", err)
	}
	for _, k := range keys {
		if k == "deleted:key" {
			t.Error("empty-value key should be skipped")
		}
	}
}

// --- Maintenance / Integrity ---

func TestStorage_IntegrityCheck(t *testing.T) {
	s := newTestStorage(t)

	ok, err := s.IntegrityCheck()
	if err != nil {
		t.Fatalf("IntegrityCheck failed: %v", err)
	}
	if !ok {
		t.Error("expected integrity check to pass on fresh database")
	}
}

func TestStorage_Vacuum(t *testing.T) {
	s := newTestStorage(t)

	if err := s.Vacuum(); err != nil {
		t.Fatalf("Vacuum failed: %v", err)
	}
}

func TestStorage_GetDBSize(t *testing.T) {
	s := newTestStorage(t)

	// Write some data
	s.Set("key", "value")
	s.SaveMetric(types.Metric{
		Type:      types.MetricType("test"),
		Name:      "metric",
		Value:     1,
		Timestamp: time.Now(),
	})

	size := s.GetDBSize()
	if size <= 0 {
		t.Errorf("expected positive DB size, got %d", size)
	}
}

func TestStorage_Backup(t *testing.T) {
	s := newTestStorage(t)

	// Write some data
	s.Set("key", "value")

	backupDir := filepath.Join(t.TempDir(), "backups")
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	if err := s.Backup(backupDir); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Check backup file exists
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected backup file to be created")
	}
	if !strings.HasPrefix(entries[0].Name(), "serverguard.db.bak.") {
		t.Errorf("unexpected backup file name: %s", entries[0].Name())
	}
}

// --- NewStorage ---

func TestStorage_NewStorageSQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := StorageConfig{
		Driver: DriverSQLite,
		Path:   dbPath,
	}
	s, err := NewStorage(cfg)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	defer s.Close()

	if s == nil {
		t.Fatal("expected non-nil Storage")
	}
}

func TestStorage_NewStorageDefault(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	cfg := StorageConfig{
		Driver: "unknown",
		Path:   dbPath,
	}
	s, err := NewStorage(cfg)
	if err != nil {
		t.Fatalf("NewStorage with unknown driver should fall back to SQLite: %v", err)
	}
	defer s.Close()
}

// --- Helper functions ---

func TestLabelsToJSON(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"nil", nil, "{}"},
		{"empty", map[string]string{}, "{}"},
		{"single", map[string]string{"k": "v"}, `{"k":"v"}`},
		{"multi", map[string]string{"a": "1", "b": "2"}, `{"a":"1","b":"2"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsToJSON(tt.labels)
			// For multi-key maps, order is non-deterministic, so just check content
			if tt.name == "multi" {
				if !strings.Contains(got, `"a":"1"`) || !strings.Contains(got, `"b":"2"`) {
					t.Errorf("expected both keys in result, got '%s'", got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("expected '%s', got '%s'", tt.want, got)
			}
		})
	}
}

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("boolToInt(true) should be 1")
	}
	if boolToInt(false) != 0 {
		t.Error("boolToInt(false) should be 0")
	}
}

// --- Internal maintenance functions ---

func TestStorage_WalCheckpoint(t *testing.T) {
	s := newTestStorage(t)
	s.walCheckpoint()
}

func TestStorage_PurgeOldData(t *testing.T) {
	s := newTestStorage(t)
	s.SaveMetric(types.Metric{
		Type:      types.MetricType("test"),
		Name:      "metric",
		Value:     1,
		Timestamp: time.Now(),
	})
	s.Set("key", "value")
	s.purgeOldData()
}

// --- StorageDriver constants ---

func TestStorageDriverConstants(t *testing.T) {
	if DriverSQLite != "sqlite" {
		t.Errorf("expected DriverSQLite='sqlite', got '%s'", DriverSQLite)
	}
	if DriverPostgres != "postgres" {
		t.Errorf("expected DriverPostgres='postgres', got '%s'", DriverPostgres)
	}
}
