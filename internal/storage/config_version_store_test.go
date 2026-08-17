package storage

import (
	"testing"
	"time"
)

func TestStorage_SaveConfigVersion(t *testing.T) {
	s := newTestStorage(t)

	v := &ConfigVersion{
		FilePath: "/etc/nginx/nginx.conf",
		Content:  "worker_processes 4;",
		Author:   "admin",
		Message:  "increase workers",
	}

	if err := s.SaveConfigVersion(v); err != nil {
		t.Fatalf("SaveConfigVersion failed: %v", err)
	}
	if v.ID == "" {
		t.Error("expected ID to be auto-generated")
	}
	if v.CommitID == "" {
		t.Error("expected CommitID to be auto-generated")
	}
	if v.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be auto-set")
	}
}

func TestStorage_SaveConfigVersionWithIDs(t *testing.T) {
	s := newTestStorage(t)

	v := &ConfigVersion{
		ID:       "cv-custom",
		CommitID: "abc123",
		FilePath: "/etc/app.conf",
		Content:  "key=value",
	}
	if err := s.SaveConfigVersion(v); err != nil {
		t.Fatalf("SaveConfigVersion failed: %v", err)
	}
	if v.ID != "cv-custom" {
		t.Errorf("expected ID 'cv-custom', got '%s'", v.ID)
	}
	if v.CommitID != "abc123" {
		t.Errorf("expected CommitID 'abc123', got '%s'", v.CommitID)
	}
}

func TestStorage_QueryConfigVersions(t *testing.T) {
	s := newTestStorage(t)

	versions := []*ConfigVersion{
		{CommitID: "c1", FilePath: "/etc/a.conf", Content: "a=1", Tag: "v1.0"},
		{CommitID: "c2", FilePath: "/etc/a.conf", Content: "a=2", Tag: "v1.1"},
		{CommitID: "c3", FilePath: "/etc/b.conf", Content: "b=1", Tag: "v1.0"},
	}
	for _, v := range versions {
		if err := s.SaveConfigVersion(v); err != nil {
			t.Fatalf("SaveConfigVersion failed: %v", err)
		}
	}

	// Query all
	all, err := s.QueryConfigVersions("", "", 0)
	if err != nil {
		t.Fatalf("QueryConfigVersions failed: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 versions, got %d", len(all))
	}

	// Query by file path
	aOnly, err := s.QueryConfigVersions("/etc/a.conf", "", 0)
	if err != nil {
		t.Fatalf("QueryConfigVersions failed: %v", err)
	}
	if len(aOnly) != 2 {
		t.Errorf("expected 2 versions for /etc/a.conf, got %d", len(aOnly))
	}

	// Query by tag
	tagged, err := s.QueryConfigVersions("", "v1.0", 0)
	if err != nil {
		t.Fatalf("QueryConfigVersions failed: %v", err)
	}
	if len(tagged) != 2 {
		t.Errorf("expected 2 versions with tag v1.0, got %d", len(tagged))
	}

	// Query with limit
	limited, err := s.QueryConfigVersions("", "", 2)
	if err != nil {
		t.Fatalf("QueryConfigVersions failed: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 versions with limit, got %d", len(limited))
	}
}

func TestStorage_GetConfigVersion(t *testing.T) {
	s := newTestStorage(t)

	v := &ConfigVersion{
		CommitID: "get-test-commit",
		FilePath: "/etc/test.conf",
		Content:  "test=true",
	}
	if err := s.SaveConfigVersion(v); err != nil {
		t.Fatalf("SaveConfigVersion failed: %v", err)
	}

	got, err := s.GetConfigVersion("get-test-commit")
	if err != nil {
		t.Fatalf("GetConfigVersion failed: %v", err)
	}
	if got.FilePath != "/etc/test.conf" {
		t.Errorf("expected file path '/etc/test.conf', got '%s'", got.FilePath)
	}
	if got.Content != "test=true" {
		t.Errorf("expected content 'test=true', got '%s'", got.Content)
	}
}

func TestStorage_GetConfigVersionNotFound(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.GetConfigVersion("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent commit")
	}
}

func TestStorage_ApproveConfigVersion(t *testing.T) {
	s := newTestStorage(t)

	v := &ConfigVersion{
		CommitID: "approve-test",
		FilePath: "/etc/app.conf",
		Content:  "key=val",
	}
	if err := s.SaveConfigVersion(v); err != nil {
		t.Fatalf("SaveConfigVersion failed: %v", err)
	}

	if err := s.ApproveConfigVersion("approve-test", "admin"); err != nil {
		t.Fatalf("ApproveConfigVersion failed: %v", err)
	}

	got, err := s.GetConfigVersion("approve-test")
	if err != nil {
		t.Fatalf("GetConfigVersion failed: %v", err)
	}
	if !got.IsApproved {
		t.Error("expected IsApproved=true after approval")
	}
	if got.ApprovedBy != "admin" {
		t.Errorf("expected ApprovedBy 'admin', got '%s'", got.ApprovedBy)
	}
}

func TestStorage_RollbackConfigVersion(t *testing.T) {
	s := newTestStorage(t)

	v := &ConfigVersion{
		CommitID: "rollback-test",
		FilePath: "/etc/app.conf",
		Content:  "original=true",
	}
	if err := s.SaveConfigVersion(v); err != nil {
		t.Fatalf("SaveConfigVersion failed: %v", err)
	}

	got, err := s.RollbackConfigVersion("rollback-test")
	if err != nil {
		t.Fatalf("RollbackConfigVersion failed: %v", err)
	}
	if got.Content != "original=true" {
		t.Errorf("expected content 'original=true', got '%s'", got.Content)
	}
}

func TestStorage_SaveConfigVersionWithApproval(t *testing.T) {
	s := newTestStorage(t)

	v := &ConfigVersion{
		CommitID:    "pre-approved",
		FilePath:    "/etc/app.conf",
		Content:     "key=val",
		IsApproved:  true,
		ApprovedBy:  "admin",
		CanRollback: false,
	}
	if err := s.SaveConfigVersion(v); err != nil {
		t.Fatalf("SaveConfigVersion failed: %v", err)
	}

	got, err := s.GetConfigVersion("pre-approved")
	if err != nil {
		t.Fatalf("GetConfigVersion failed: %v", err)
	}
	if !got.IsApproved {
		t.Error("expected IsApproved=true")
	}
	if got.CanRollback {
		t.Error("expected CanRollback=false")
	}
}

// Ensure time import is used
var _ = time.Now
