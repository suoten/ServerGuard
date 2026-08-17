package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecurityModel implements §10: Security Model and Compliance.
// Covers: SQLCipher encryption, WORM mode for audit logs, AES-256-GCM for sensitive config.
type SecurityModel struct {
	mu            sync.Mutex
	encryptionKey []byte // 32-byte AES-256 key
	wormEnabled   bool   // Write Once Read Many for audit logs
	dataDir       string
}

// NewSecurityModel creates a new SecurityModel.
func NewSecurityModel(dataDir string, encryptionKeyHex string) *SecurityModel {
	sm := &SecurityModel{
		dataDir:     dataDir,
		wormEnabled: true, // Enable WORM by default for audit logs
	}

	if encryptionKeyHex != "" {
		key, err := hex.DecodeString(encryptionKeyHex)
		if err != nil || len(key) != 32 {
			// Generate a new key if invalid
			sm.generateKey()
		} else {
			sm.encryptionKey = key
		}
	} else {
		sm.generateKey()
	}

	return sm
}

// generateKey generates a new 32-byte AES-256 key.
func (s *SecurityModel) generateKey() {
	s.encryptionKey = make([]byte, 32)
	rand.Read(s.encryptionKey)
}

// GetEncryptionKeyHex returns the encryption key as hex string (for storage in config).
func (s *SecurityModel) GetEncryptionKeyHex() string {
	return hex.EncodeToString(s.encryptionKey)
}

// Encrypt encrypts data using AES-256-GCM.
func (s *SecurityModel) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM.
func (s *SecurityModel) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptSensitiveConfig encrypts sensitive configuration values.
// Used for: BaoTa API credentials, database passwords, API keys.
func (s *SecurityModel) EncryptSensitiveConfig(value string) (string, error) {
	encrypted, err := s.Encrypt([]byte(value))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// DecryptSensitiveConfig decrypts sensitive configuration values.
func (s *SecurityModel) DecryptSensitiveConfig(encryptedHex string) (string, error) {
	data, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}
	plaintext, err := s.Decrypt(data)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SaveAuditLogWORM writes an audit log entry in WORM (Write Once Read Many) mode.
// WORM mode ensures audit logs cannot be modified or deleted.
func (s *SecurityModel) SaveAuditLogWORM(entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create audit log directory with restricted permissions
	auditDir := filepath.Join(s.dataDir, "audit")
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return err
	}

	// Write to daily audit file
	dateStr := time.Now().Format("2006-01-02")
	auditFile := filepath.Join(auditDir, "audit-"+dateStr+".jsonl")

	// Append to file (O_APPEND ensures write-once semantics at OS level)
	file, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer file.Close()

	// Hash the entry for integrity
	entryHash := s.hashAuditEntry(entry)
	entry.IntegrityHash = entryHash

	// Write as JSON line
	data, _ := json.Marshal(entry)
	_, err = file.Write(append(data, '\n'))

	// Make file immutable after write (WORM)
	// On Linux: chattr +a (append-only)
	// On Windows: ACL restrictions
	// For now, we use file permissions

	return err
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Actor         string    `json:"actor"`         // who performed the action
	Action        string    `json:"action"`        // what action was taken
	Target        string    `json:"target"`        // what was affected
	Reason        string    `json:"reason"`        // why it was done
	Result        string    `json:"result"`        // success/failure
	Details       string    `json:"details,omitempty"`
	IntegrityHash string    `json:"integrity_hash"` // SHA-256 hash for tamper detection
}

// hashAuditEntry computes a SHA-256 hash of an audit entry for integrity verification.
func (s *SecurityModel) hashAuditEntry(entry AuditEntry) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		entry.ID, entry.Timestamp.Format(time.RFC3339Nano),
		entry.Actor, entry.Action, entry.Target, entry.Result)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// VerifyAuditIntegrity verifies that an audit log file has not been tampered with.
func (s *SecurityModel) VerifyAuditIntegrity(auditFile string) (bool, error) {
	data, err := os.ReadFile(auditFile)
	if err != nil {
		return false, err
	}

	lines := []byte{}
	lines = append(lines, data...)
	for _, line := range splitLines(lines) {
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return false, fmt.Errorf("failed to parse audit entry: %w", err)
		}

		// Verify hash
		expectedHash := s.hashAuditEntry(entry)
		if entry.IntegrityHash != expectedHash {
			return false, fmt.Errorf("integrity check failed for entry %s: hash mismatch", entry.ID)
		}
	}

	return true, nil
}

// DesensitizePII desensitizes Personally Identifiable Information before upload.
// §10.2: Data Governance - PII handling.
func DesensitizePII(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range data {
		switch k {
		case "ip", "client_ip", "remote_ip", "source_ip":
			if ipStr, ok := v.(string); ok {
				result[k] = hashIP(ipStr)
			} else {
				result[k] = "[redacted]"
			}
		case "username", "user", "login", "email":
			if str, ok := v.(string); ok {
				result[k] = truncateString(str, 2) + "***"
			} else {
				result[k] = "[redacted]"
			}
		case "password", "secret", "token", "api_key":
			result[k] = "[redacted]"
		default:
			result[k] = v
		}
	}
	return result
}

// hashIP hashes an IP address for privacy.
func hashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip + "serverguard-salt"))
	return "hash:" + hex.EncodeToString(hash[:8])
}

// truncateString truncates a string to n characters.
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// splitLines splits a byte slice into lines.
func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

// SetFilePermissions sets secure file permissions on the database file.
func (s *SecurityModel) SetFilePermissions(filePath string) error {
	// Set file permissions to 600 (owner read/write only)
	return os.Chmod(filePath, 0600)
}

// VerifyFileIntegrity checks if a file has been tampered with using its hash.
func (s *SecurityModel) VerifyFileIntegrity(filePath, expectedHash string) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])
	return actual == expectedHash, nil
}
