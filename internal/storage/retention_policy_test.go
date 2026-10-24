package storage

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// --- RetentionPolicy ---

func TestRetentionPolicy_Default(t *testing.T) {
	rp := DefaultRetentionPolicy()
	if rp.RawMetrics != 1*time.Hour {
		t.Errorf("RawMetrics = %v, want 1h", rp.RawMetrics)
	}
	if rp.MinMetrics != 7*24*time.Hour {
		t.Errorf("MinMetrics = %v, want 7d", rp.MinMetrics)
	}
	if rp.HourMetrics != 90*24*time.Hour {
		t.Errorf("HourMetrics = %v, want 90d", rp.HourMetrics)
	}
	if rp.Alerts != 180*24*time.Hour {
		t.Errorf("Alerts = %v, want 180d", rp.Alerts)
	}
	if rp.Actions != 365*24*time.Hour {
		t.Errorf("Actions = %v, want 365d", rp.Actions)
	}
}

func TestRetentionPolicy_SetAndGet(t *testing.T) {
	s := newTestStorage(t)

	custom := DefaultRetentionPolicy()
	custom.RawMetrics = 2 * time.Hour
	custom.Alerts = 30 * 24 * time.Hour
	custom.AttackEvents = 60 * 24 * time.Hour

	if err := s.SetRetentionPolicy(custom); err != nil {
		t.Fatalf("SetRetentionPolicy failed: %v", err)
	}

	loaded, err := s.GetRetentionPolicy()
	if err != nil {
		t.Fatalf("GetRetentionPolicy failed: %v", err)
	}

	if loaded.RawMetrics != 2*time.Hour {
		t.Errorf("loaded RawMetrics = %v, want 2h", loaded.RawMetrics)
	}
	if loaded.Alerts != 30*24*time.Hour {
		t.Errorf("loaded Alerts = %v, want 30d", loaded.Alerts)
	}
	if loaded.AttackEvents != 60*24*time.Hour {
		t.Errorf("loaded AttackEvents = %v, want 60d", loaded.AttackEvents)
	}
}

func TestRetentionPolicy_GetDefaultWhenNotSet(t *testing.T) {
	s := newTestStorage(t)

	rp, err := s.GetRetentionPolicy()
	if err != nil {
		t.Fatalf("GetRetentionPolicy failed: %v", err)
	}

	def := DefaultRetentionPolicy()
	if rp.RawMetrics != def.RawMetrics {
		t.Errorf("RawMetrics = %v, want default %v", rp.RawMetrics, def.RawMetrics)
	}
}

func TestRetentionPolicy_EnforceRetentionCleansAlerts(t *testing.T) {
	s := newTestStorage(t)

	// 插入一条过期告警
	oldAlert := types.Alert{
		ID:        "old-alert-retention",
		Level:     types.AlertWarning,
		Title:     "old",
		Message:   "old alert",
		Source:    "test",
		Timestamp: time.Now().Add(-400 * 24 * time.Hour),
	}
	if err := s.SaveAlert(oldAlert); err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}

	// 插入一条新告警
	newAlert := types.Alert{
		ID:        "new-alert-retention",
		Level:     types.AlertWarning,
		Title:     "new",
		Message:   "new alert",
		Source:    "test",
		Timestamp: time.Now(),
	}
	if err := s.SaveAlert(newAlert); err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}

	// 执行保留策略清理
	rp := DefaultRetentionPolicy()
	if err := s.EnforceRetention(rp); err != nil {
		t.Fatalf("EnforceRetention failed: %v", err)
	}

	// 旧告警应被删除 - 查询数据库确认
	var count int
	err := s.DB().QueryRow("SELECT COUNT(*) FROM alerts WHERE id = ?", "old-alert-retention").Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 0 {
		t.Error("old alert should have been deleted by retention policy")
	}

	// 新告警应仍存在
	err = s.DB().QueryRow("SELECT COUNT(*) FROM alerts WHERE id = ?", "new-alert-retention").Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 1 {
		t.Error("new alert should still exist")
	}
}

func TestRetentionPolicy_AuditLogCleaned(t *testing.T) {
	s := newTestStorage(t)

	// 插入一条很旧的审计日志（超过 365 天保留期）
	oldTime := time.Now().Add(-400 * 24 * time.Hour)
	audit := types.AuditEntry{
		ID:        "old-audit-retention",
		Timestamp: oldTime,
		Actor:     "system",
		Action:    "test",
		Target:    "test",
		Result:    "success",
	}
	if err := s.SaveAudit(audit); err != nil {
		t.Fatalf("SaveAudit failed: %v", err)
	}

	// 插入一条新的审计日志（在保留期内）
	newAudit := types.AuditEntry{
		ID:        "new-audit-retention",
		Timestamp: time.Now(),
		Actor:     "system",
		Action:    "test",
		Target:    "test",
		Result:    "success",
	}
	if err := s.SaveAudit(newAudit); err != nil {
		t.Fatalf("SaveAudit failed: %v", err)
	}

	// 执行保留策略清理
	rp := DefaultRetentionPolicy()
	if err := s.EnforceRetention(rp); err != nil {
		t.Fatalf("EnforceRetention failed: %v", err)
	}

	// 超过保留期的审计日志应被清理
	var oldCount int
	err := s.DB().QueryRow("SELECT COUNT(*) FROM audit_log WHERE id = ?", "old-audit-retention").Scan(&oldCount)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if oldCount != 0 {
		t.Error("audit log older than retention period should be deleted")
	}

	// 保留期内的审计日志应仍然存在
	var newCount int
	err = s.DB().QueryRow("SELECT COUNT(*) FROM audit_log WHERE id = ?", "new-audit-retention").Scan(&newCount)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if newCount != 1 {
		t.Error("audit log within retention period should NOT be deleted")
	}
}

// --- DBSize ---

func TestDBSize_CheckSize(t *testing.T) {
	s := newTestStorage(t)

	result := s.CheckDBSize()
	if result.SizeBytes == 0 {
		t.Error("SizeBytes should be > 0 for an initialized database")
	}
	if !result.CanWrite {
		t.Error("CanWrite should be true for a small database")
	}
}

// --- DiskWatermark ---

func TestDiskWatermark_Check(t *testing.T) {
	s := newTestStorage(t)

	result := s.CheckDiskWatermark()
	// 测试环境磁盘使用率应在合理范围内
	if result.UsedPercent < 0 || result.UsedPercent > 100 {
		t.Errorf("UsedPercent = %.2f, should be 0-100", result.UsedPercent)
	}
}

func TestWatermarkLevel_String(t *testing.T) {
	if WatermarkNormal.String() != "normal" {
		t.Error("WatermarkNormal string should be 'normal'")
	}
	if WatermarkHigh.String() != "high" {
		t.Error("WatermarkHigh string should be 'high'")
	}
	if WatermarkCritical.String() != "critical" {
		t.Error("WatermarkCritical string should be 'critical'")
	}
}

func TestClassifyWatermark(t *testing.T) {
	cases := []struct {
		percent float64
		level   WatermarkLevel
	}{
		{0, WatermarkNormal},
		{50, WatermarkNormal},
		{79.9, WatermarkNormal},
		{80, WatermarkHigh},
		{89.9, WatermarkHigh},
		{90, WatermarkCritical},
		{99, WatermarkCritical},
	}
	for _, c := range cases {
		if got := classifyWatermark(c.percent); got != c.level {
			t.Errorf("classifyWatermark(%.1f) = %v, want %v", c.percent, got, c.level)
		}
	}
}
