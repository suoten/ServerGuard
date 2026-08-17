package storage

import (
	"strings"
	"testing"
)

func TestPostgresSchema(t *testing.T) {
	schema := PostgresSchema()
	if schema == "" {
		t.Fatal("expected non-empty schema")
	}
	if !strings.Contains(schema, "CREATE TABLE") {
		t.Error("schema should contain CREATE TABLE statements")
	}
	if !strings.Contains(schema, "metrics") {
		t.Error("schema should contain metrics table")
	}
	if !strings.Contains(schema, "tenant_id") {
		t.Error("schema should contain tenant_id for RLS")
	}
}

func TestPostgresRLSPolicies(t *testing.T) {
	policies := PostgresRLSPolicies()
	if policies == "" {
		t.Fatal("expected non-empty RLS policies")
	}
	if !strings.Contains(policies, "ROW LEVEL SECURITY") {
		t.Error("RLS policies should contain ROW LEVEL SECURITY statements")
	}
	if !strings.Contains(policies, "POLICY") {
		t.Error("RLS policies should contain POLICY statements")
	}
	if !strings.Contains(policies, "tenant_isolation") {
		t.Error("RLS policies should contain tenant_isolation policy")
	}
}

func TestPostgresWORMTriggers(t *testing.T) {
	triggers := PostgresWORMTriggers()
	if triggers == "" {
		t.Fatal("expected non-empty WORM triggers")
	}
	if !strings.Contains(triggers, "TRIGGER") {
		t.Error("WORM triggers should contain TRIGGER statements")
	}
	if !strings.Contains(triggers, "audit_log") {
		t.Error("WORM triggers should reference audit_log table")
	}
	if !strings.Contains(triggers, "prevent_audit_update") {
		t.Error("WORM triggers should contain prevent_audit_update function")
	}
	if !strings.Contains(triggers, "prevent_audit_delete") {
		t.Error("WORM triggers should contain prevent_audit_delete function")
	}
}

func TestSanitizeTenantID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"with'quote", "with''quote"},
		{"multi''quote", "multi''''quote"},
		{"", ""},
		{"no-special-chars", "no-special-chars"},
	}

	for _, tt := range tests {
		got := sanitizeTenantID(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeTenantID('%s') = '%s', want '%s'", tt.input, got, tt.want)
		}
	}
}

func TestConvertPlaceholders(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{"no_placeholders", "SELECT 1", "SELECT 1"},
		{"single", "SELECT * FROM t WHERE id = ?", "SELECT * FROM t WHERE id = $1"},
		{"multi", "SELECT * FROM t WHERE a = ? AND b = ?", "SELECT * FROM t WHERE a = $1 AND b = $2"},
		{"three", "INSERT INTO t VALUES (?, ?, ?)", "INSERT INTO t VALUES ($1, $2, $3)"},
		{"empty_string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertPlaceholders(tt.query)
			if got != tt.want {
				t.Errorf("ConvertPlaceholders('%s') = '%s', want '%s'", tt.query, got, tt.want)
			}
		})
	}
}
