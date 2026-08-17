package storage

import (
	"testing"
	"time"
)

func TestStorage_SaveAttackEvent(t *testing.T) {
	s := newTestStorage(t)

	e := &AttackEvent{
		EventType:   "sql_injection",
		SourceIP:    "10.0.0.1",
		Target:      "web-app",
		Severity:    "high",
		Detail:      `{"path":"/login"}`,
		ActionTaken: "ban_ip",
		TraceID:     "trace-123",
	}

	if err := s.SaveAttackEvent(e); err != nil {
		t.Fatalf("SaveAttackEvent failed: %v", err)
	}
	if e.ID == "" {
		t.Error("expected ID to be auto-generated")
	}
	if e.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be auto-set")
	}
}

func TestStorage_SaveAttackEventWithID(t *testing.T) {
	s := newTestStorage(t)

	e := &AttackEvent{
		ID:        "custom-id",
		EventType: "xss",
		SourceIP:  "10.0.0.2",
		Target:    "form",
		Severity:  "medium",
		CreatedAt: time.Now().UTC(),
	}

	if err := s.SaveAttackEvent(e); err != nil {
		t.Fatalf("SaveAttackEvent failed: %v", err)
	}
	if e.ID != "custom-id" {
		t.Errorf("expected ID 'custom-id', got '%s'", e.ID)
	}
}

func TestStorage_QueryAttackEvents(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC()
	events := []*AttackEvent{
		{EventType: "cc", SourceIP: "10.0.0.1", Target: "site", Severity: "high", CreatedAt: now},
		{EventType: "cc", SourceIP: "10.0.0.2", Target: "site", Severity: "low", CreatedAt: now.Add(1 * time.Second)},
		{EventType: "port_scan", SourceIP: "10.0.0.1", Target: "site", Severity: "medium", CreatedAt: now.Add(2 * time.Second)},
	}
	for _, e := range events {
		if err := s.SaveAttackEvent(e); err != nil {
			t.Fatalf("SaveAttackEvent failed: %v", err)
		}
	}

	// Query all
	all, err := s.QueryAttackEvents("", "", "", now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 events, got %d", len(all))
	}

	// Query by event type
	ccOnly, err := s.QueryAttackEvents("cc", "", "", now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(ccOnly) != 2 {
		t.Errorf("expected 2 cc events, got %d", len(ccOnly))
	}

	// Query by source IP
	fromIP1, err := s.QueryAttackEvents("", "10.0.0.1", "", now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(fromIP1) != 2 {
		t.Errorf("expected 2 events from 10.0.0.1, got %d", len(fromIP1))
	}

	// Query by severity
	highOnly, err := s.QueryAttackEvents("", "", "high", now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(highOnly) != 1 {
		t.Errorf("expected 1 high severity event, got %d", len(highOnly))
	}

	// Query with limit
	limited, err := s.QueryAttackEvents("", "", "", now.Add(-1*time.Hour), 2)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 events with limit, got %d", len(limited))
	}
}

func TestStorage_QueryAttackEventsEmpty(t *testing.T) {
	s := newTestStorage(t)

	events, err := s.QueryAttackEvents("", "", "", time.Now().Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestStorage_SaveAttackProfile(t *testing.T) {
	s := newTestStorage(t)

	p := &AttackProfile{
		SourceIP:    "10.0.0.1",
		GeoLocation: "CN",
		AttackTypes: `["cc","xss"]`,
		FirstSeen:   time.Now().Add(-1 * time.Hour),
		LastSeen:    time.Now(),
		Duration:    3600,
		Trend:       "escalating",
		Confidence:  0.95,
	}

	if err := s.SaveAttackProfile(p); err != nil {
		t.Fatalf("SaveAttackProfile failed: %v", err)
	}
	if p.ID == "" {
		t.Error("expected ID to be auto-generated")
	}
	if p.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be auto-set")
	}
	if p.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be auto-set")
	}
}

func TestStorage_QueryAttackProfiles(t *testing.T) {
	s := newTestStorage(t)

	now := time.Now().UTC()
	profiles := []*AttackProfile{
		{SourceIP: "10.0.0.1", FirstSeen: now, LastSeen: now, CreatedAt: now},
		{SourceIP: "10.0.0.2", FirstSeen: now, LastSeen: now, CreatedAt: now},
	}
	for _, p := range profiles {
		if err := s.SaveAttackProfile(p); err != nil {
			t.Fatalf("SaveAttackProfile failed: %v", err)
		}
	}

	// Query all
	all, err := s.QueryAttackProfiles("", now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackProfiles failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(all))
	}

	// Query by source IP
	fromIP1, err := s.QueryAttackProfiles("10.0.0.1", now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("QueryAttackProfiles failed: %v", err)
	}
	if len(fromIP1) != 1 {
		t.Errorf("expected 1 profile from 10.0.0.1, got %d", len(fromIP1))
	}
}

func TestStorage_PurgeOldAttackEvents(t *testing.T) {
	s := newTestStorage(t)

	// Insert an old event
	old := &AttackEvent{
		EventType: "old_attack",
		SourceIP:  "10.0.0.1",
		Target:    "site",
		Severity:  "low",
		CreatedAt: time.Now().AddDate(0, 0, -100), // 100 days ago
	}
	if err := s.SaveAttackEvent(old); err != nil {
		t.Fatalf("SaveAttackEvent failed: %v", err)
	}

	if err := s.PurgeOldAttackEvents(); err != nil {
		t.Fatalf("PurgeOldAttackEvents failed: %v", err)
	}

	events, err := s.QueryAttackEvents("", "", "", time.Now().AddDate(0, 0, -200), 0)
	if err != nil {
		t.Fatalf("QueryAttackEvents failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events after purge, got %d", len(events))
	}
}

func TestStorage_PurgeOldAttackProfiles(t *testing.T) {
	s := newTestStorage(t)

	// Insert an old profile
	old := &AttackProfile{
		SourceIP:  "10.0.0.1",
		FirstSeen: time.Now().AddDate(-2, 0, 0),
		LastSeen:  time.Now().AddDate(-2, 0, 0),
	}
	if err := s.SaveAttackProfile(old); err != nil {
		t.Fatalf("SaveAttackProfile failed: %v", err)
	}
	// Manually set updated_at to 2 years ago (SaveAttackProfile sets it to now)
	s.db.Exec("UPDATE attack_profiles SET updated_at = ? WHERE id = ?", time.Now().AddDate(-2, 0, 0), old.ID)

	if err := s.PurgeOldAttackProfiles(); err != nil {
		t.Fatalf("PurgeOldAttackProfiles failed: %v", err)
	}

	profiles, err := s.QueryAttackProfiles("", time.Now().AddDate(-3, 0, 0), 0)
	if err != nil {
		t.Fatalf("QueryAttackProfiles failed: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles after purge, got %d", len(profiles))
	}
}
