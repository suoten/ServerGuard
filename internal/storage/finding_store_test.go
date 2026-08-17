package storage

import (
	"testing"
	"time"
)

func TestStorage_SaveFinding(t *testing.T) {
	s := newTestStorage(t)

	f := &Finding{
		Scanner:    "vulnscan",
		ScannerSub: "x1_component",
		Severity:   "high",
		Title:      "Outdated OpenSSL",
		Target:     "libssl.so.1.1",
	}

	if err := s.SaveFinding(f); err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}
	if f.ID == "" {
		t.Error("expected ID to be auto-generated")
	}
	if f.Status != "open" {
		t.Errorf("expected default status 'open', got '%s'", f.Status)
	}
	if f.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be auto-set")
	}
}

func TestStorage_SaveFindingWithID(t *testing.T) {
	s := newTestStorage(t)

	f := &Finding{
		ID:         "finding-custom",
		Scanner:    "websecurity",
		ScannerSub: "w1_sensitive",
		Severity:   "critical",
		Title:      "SQL Injection",
		Target:     "/api/users",
		Status:     "confirmed",
	}

	if err := s.SaveFinding(f); err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}
	if f.ID != "finding-custom" {
		t.Errorf("expected ID 'finding-custom', got '%s'", f.ID)
	}
}

func TestStorage_QueryFindings(t *testing.T) {
	s := newTestStorage(t)

	findings := []*Finding{
		{Scanner: "vulnscan", ScannerSub: "x1", Severity: "high", Title: "CVE-2024-1", Target: "lib"},
		{Scanner: "vulnscan", ScannerSub: "x1", Severity: "low", Title: "CVE-2024-2", Target: "lib"},
		{Scanner: "websecurity", ScannerSub: "w1", Severity: "high", Title: "XSS", Target: "/form"},
	}
	for _, f := range findings {
		if err := s.SaveFinding(f); err != nil {
			t.Fatalf("SaveFinding failed: %v", err)
		}
	}

	// Query all
	all, err := s.QueryFindings("", "", "", 0)
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 findings, got %d", len(all))
	}

	// Query by scanner
	vulnOnly, err := s.QueryFindings("vulnscan", "", "", 0)
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(vulnOnly) != 2 {
		t.Errorf("expected 2 vulnscan findings, got %d", len(vulnOnly))
	}

	// Query by severity
	highOnly, err := s.QueryFindings("", "high", "", 0)
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(highOnly) != 2 {
		t.Errorf("expected 2 high findings, got %d", len(highOnly))
	}

	// Query by status
	openOnly, err := s.QueryFindings("", "", "open", 0)
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(openOnly) != 3 {
		t.Errorf("expected 3 open findings, got %d", len(openOnly))
	}

	// Query with limit
	limited, err := s.QueryFindings("", "", "", 2)
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 findings with limit, got %d", len(limited))
	}
}

func TestStorage_QueryFindingsEmpty(t *testing.T) {
	s := newTestStorage(t)

	findings, err := s.QueryFindings("", "", "", 0)
	if err != nil {
		t.Fatalf("QueryFindings failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestStorage_UpdateFindingStatus(t *testing.T) {
	s := newTestStorage(t)

	f := &Finding{
		Scanner:    "vulnscan",
		ScannerSub: "x1",
		Severity:   "high",
		Title:      "Test",
		Target:     "lib",
	}
	if err := s.SaveFinding(f); err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}

	// Update to confirmed
	if err := s.UpdateFindingStatus(f.ID, "confirmed", "admin"); err != nil {
		t.Fatalf("UpdateFindingStatus failed: %v", err)
	}

	got, err := s.GetFinding(f.ID)
	if err != nil {
		t.Fatalf("GetFinding failed: %v", err)
	}
	if got.Status != "confirmed" {
		t.Errorf("expected status 'confirmed', got '%s'", got.Status)
	}
	if got.ConfirmedBy != "admin" {
		t.Errorf("expected confirmed_by 'admin', got '%s'", got.ConfirmedBy)
	}

	// Update to fixed
	if err := s.UpdateFindingStatus(f.ID, "fixed", ""); err != nil {
		t.Fatalf("UpdateFindingStatus failed: %v", err)
	}
	got, err = s.GetFinding(f.ID)
	if err != nil {
		t.Fatalf("GetFinding failed: %v", err)
	}
	if got.Status != "fixed" {
		t.Errorf("expected status 'fixed', got '%s'", got.Status)
	}
	if got.FixedAt.IsZero() {
		t.Error("expected FixedAt to be set")
	}

	// Update to ignored (default branch)
	if err := s.UpdateFindingStatus(f.ID, "ignored", ""); err != nil {
		t.Fatalf("UpdateFindingStatus failed: %v", err)
	}
	got, err = s.GetFinding(f.ID)
	if err != nil {
		t.Fatalf("GetFinding failed: %v", err)
	}
	if got.Status != "ignored" {
		t.Errorf("expected status 'ignored', got '%s'", got.Status)
	}
}

func TestStorage_GetFinding(t *testing.T) {
	s := newTestStorage(t)

	f := &Finding{
		ID:         "finding-get-test",
		Scanner:    "test",
		ScannerSub: "test",
		Severity:   "info",
		Title:      "Test Finding",
		Target:     "test",
	}
	if err := s.SaveFinding(f); err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}

	got, err := s.GetFinding("finding-get-test")
	if err != nil {
		t.Fatalf("GetFinding failed: %v", err)
	}
	if got.Title != "Test Finding" {
		t.Errorf("expected title 'Test Finding', got '%s'", got.Title)
	}
}

func TestStorage_GetFindingNotFound(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.GetFinding("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent finding")
	}
}

func TestStorage_SaveFindingReplace(t *testing.T) {
	s := newTestStorage(t)

	f := &Finding{
		ID:         "finding-replace",
		Scanner:    "test",
		ScannerSub: "test",
		Severity:   "low",
		Title:      "Original",
		Target:     "test",
	}
	if err := s.SaveFinding(f); err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}

	f.Title = "Updated"
	f.Status = "confirmed"
	if err := s.SaveFinding(f); err != nil {
		t.Fatalf("SaveFinding replace failed: %v", err)
	}

	got, err := s.GetFinding("finding-replace")
	if err != nil {
		t.Fatalf("GetFinding failed: %v", err)
	}
	if got.Title != "Updated" {
		t.Errorf("expected title 'Updated', got '%s'", got.Title)
	}
}

// Ensure time import is used
var _ = time.Now
