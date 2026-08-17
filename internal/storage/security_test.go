package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewSecurityModel(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	if sm == nil {
		t.Fatal("expected non-nil SecurityModel")
	}
	if sm.GetEncryptionKeyHex() == "" {
		t.Error("expected non-empty encryption key")
	}
}

func TestNewSecurityModelWithValidKey(t *testing.T) {
	// Generate a valid 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyHex := hex.EncodeToString(key)

	sm := NewSecurityModel(t.TempDir(), keyHex)
	if sm == nil {
		t.Fatal("expected non-nil SecurityModel")
	}
	if sm.GetEncryptionKeyHex() != keyHex {
		t.Error("expected provided key to be used")
	}
}

func TestNewSecurityModelWithInvalidKey(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "invalid-hex")
	if sm == nil {
		t.Fatal("expected non-nil SecurityModel")
	}
	// Should generate a new key
	if sm.GetEncryptionKeyHex() == "" {
		t.Error("expected auto-generated key when invalid key provided")
	}
}

func TestSecurityModel_EncryptDecrypt(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	plaintext := []byte("sensitive data")

	ciphertext, err := sm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := sm.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("expected '%s', got '%s'", plaintext, decrypted)
	}
}

func TestSecurityModel_DecryptTooShort(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	_, err := sm.Decrypt([]byte("short"))
	if err == nil {
		t.Error("expected error for too-short ciphertext")
	}
}

func TestSecurityModel_EncryptSensitiveConfig(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	value := "api-key-secret-123"

	encrypted, err := sm.EncryptSensitiveConfig(value)
	if err != nil {
		t.Fatalf("EncryptSensitiveConfig failed: %v", err)
	}
	if encrypted == value {
		t.Error("encrypted should differ from original")
	}

	decrypted, err := sm.DecryptSensitiveConfig(encrypted)
	if err != nil {
		t.Fatalf("DecryptSensitiveConfig failed: %v", err)
	}
	if decrypted != value {
		t.Errorf("expected '%s', got '%s'", value, decrypted)
	}
}

func TestSecurityModel_DecryptSensitiveConfigInvalidHex(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	_, err := sm.DecryptSensitiveConfig("not-hex!@#")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestSecurityModel_SaveAuditLogWORM(t *testing.T) {
	dir := t.TempDir()
	sm := NewSecurityModel(dir, "")

	entry := AuditEntry{
		ID:        "audit-worm-1",
		Timestamp: time.Now().UTC(),
		Actor:     "admin",
		Action:    "config_change",
		Target:    "/etc/nginx/nginx.conf",
		Result:    "success",
	}

	if err := sm.SaveAuditLogWORM(entry); err != nil {
		t.Fatalf("SaveAuditLogWORM failed: %v", err)
	}

	// Verify file was created
	dateStr := time.Now().Format("2006-01-02")
	auditFile := filepath.Join(dir, "audit", "audit-"+dateStr+".jsonl")
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		t.Fatal("audit log file was not created")
	}

	// Verify integrity
	ok, err := sm.VerifyAuditIntegrity(auditFile)
	if err != nil {
		t.Fatalf("VerifyAuditIntegrity failed: %v", err)
	}
	if !ok {
		t.Error("integrity check should pass for untampered file")
	}
}

func TestSecurityModel_VerifyAuditIntegrityTampered(t *testing.T) {
	dir := t.TempDir()
	sm := NewSecurityModel(dir, "")

	entry := AuditEntry{
		ID:        "audit-tamper",
		Timestamp: time.Now().UTC(),
		Actor:     "admin",
		Action:    "delete",
		Target:    "important-file",
		Result:    "success",
	}
	if err := sm.SaveAuditLogWORM(entry); err != nil {
		t.Fatalf("SaveAuditLogWORM failed: %v", err)
	}

	dateStr := time.Now().Format("2006-01-02")
	auditFile := filepath.Join(dir, "audit", "audit-"+dateStr+".jsonl")

	// Tamper with the file
	data, _ := os.ReadFile(auditFile)
	tampered := strings.Replace(string(data), "important-file", "hacked-file", 1)
	os.WriteFile(auditFile, []byte(tampered), 0640)

	ok, err := sm.VerifyAuditIntegrity(auditFile)
	if err == nil && ok {
		t.Error("integrity check should fail for tampered file")
	}
}

func TestSecurityModel_VerifyAuditIntegrityFileNotFound(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	_, err := sm.VerifyAuditIntegrity("/nonexistent/file.jsonl")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestDesensitizePII(t *testing.T) {
	data := map[string]interface{}{
		"ip":       "192.168.1.100",
		"client_ip": "10.0.0.1",
		"username": "adminuser",
		"email":    "test@example.com",
		"password": "secret123",
		"api_key":  "key-abc-def",
		"normal":   "keep-me",
		"count":    42,
	}

	result := DesensitizePII(data)

	// IP should be hashed
	if result["ip"] == "192.168.1.100" {
		t.Error("IP should be hashed")
	}
	if !strings.HasPrefix(result["ip"].(string), "hash:") {
		t.Error("IP should be hashed with 'hash:' prefix")
	}

	// Username should be truncated + ***
	if result["username"] == "adminuser" {
		t.Error("username should be desensitized")
	}
	if !strings.HasSuffix(result["username"].(string), "***") {
		t.Error("username should end with ***")
	}

	// Password should be redacted
	if result["password"] != "[redacted]" {
		t.Errorf("expected '[redacted]', got '%v'", result["password"])
	}
	if result["api_key"] != "[redacted]" {
		t.Errorf("expected '[redacted]', got '%v'", result["api_key"])
	}

	// Normal fields should be preserved
	if result["normal"] != "keep-me" {
		t.Errorf("expected 'keep-me', got '%v'", result["normal"])
	}
	if result["count"] != 42 {
		t.Errorf("expected 42, got '%v'", result["count"])
	}
}

func TestDesensitizePIINilValue(t *testing.T) {
	data := map[string]interface{}{
		"ip":  12345, // non-string IP
		"user": 123,  // non-string username
	}
	result := DesensitizePII(data)
	if result["ip"] != "[redacted]" {
		t.Errorf("expected '[redacted]' for non-string IP, got '%v'", result["ip"])
	}
	if result["user"] != "[redacted]" {
		t.Errorf("expected '[redacted]' for non-string username, got '%v'", result["user"])
	}
}

func TestDesensitizePIIEmpty(t *testing.T) {
	result := DesensitizePII(map[string]interface{}{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d items", len(result))
	}
}

func TestHashIP(t *testing.T) {
	h1 := hashIP("192.168.1.1")
	h2 := hashIP("192.168.1.1")
	h3 := hashIP("192.168.1.2")

	if h1 != h2 {
		t.Error("same IP should produce same hash")
	}
	if h1 == h3 {
		t.Error("different IPs should produce different hashes")
	}
	if !strings.HasPrefix(h1, "hash:") {
		t.Error("hash should have 'hash:' prefix")
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 3, "hel"},
		{"hi", 5, "hi"},
		{"", 3, ""},
		{"abc", 3, "abc"},
	}

	for _, tt := range tests {
		got := truncateString(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("truncateString('%s', %d) = '%s', want '%s'", tt.input, tt.n, got, tt.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	data := []byte("line1\nline2\nline3")
	lines := splitLines(data)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "line1" || lines[1] != "line2" || lines[2] != "line3" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestSplitLinesEmpty(t *testing.T) {
	lines := splitLines([]byte{})
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %d", len(lines))
	}
}

func TestSplitLinesTrailingNewline(t *testing.T) {
	data := []byte("line1\nline2\n")
	lines := splitLines(data)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}

func TestSecurityModel_SetFilePermissions(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	file := filepath.Join(t.TempDir(), "testfile")
	os.WriteFile(file, []byte("test"), 0644)

	if err := sm.SetFilePermissions(file); err != nil {
		t.Fatalf("SetFilePermissions failed: %v", err)
	}
}

func TestSecurityModel_VerifyFileIntegrity(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	file := filepath.Join(t.TempDir(), "testfile")
	content := []byte("test content")
	os.WriteFile(file, content, 0644)

	hash := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(hash[:])

	ok, err := sm.VerifyFileIntegrity(file, expectedHash)
	if err != nil {
		t.Fatalf("VerifyFileIntegrity failed: %v", err)
	}
	if !ok {
		t.Error("integrity check should pass for untampered file")
	}

	// Wrong hash should fail
	ok, err = sm.VerifyFileIntegrity(file, "wrong-hash")
	if err != nil {
		t.Fatalf("VerifyFileIntegrity failed: %v", err)
	}
	if ok {
		t.Error("integrity check should fail for wrong hash")
	}
}

func TestSecurityModel_VerifyFileIntegrityNotFound(t *testing.T) {
	sm := NewSecurityModel(t.TempDir(), "")
	_, err := sm.VerifyFileIntegrity("/nonexistent/file", "hash")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}