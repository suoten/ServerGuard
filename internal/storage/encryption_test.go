package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncryptionKey(t *testing.T) {
	key1, err := EncryptionKey("password1")
	if err != nil {
		t.Fatalf("EncryptionKey failed: %v", err)
	}
	if key1 == "" {
		t.Error("expected non-empty key")
	}

	key2, err := EncryptionKey("password2")
	if err != nil {
		t.Fatalf("EncryptionKey failed: %v", err)
	}

	if key1 == key2 {
		t.Error("different passwords should produce different keys")
	}

	// Same password should produce same key (deterministic)
	key1Again, err := EncryptionKey("password1")
	if err != nil {
		t.Fatalf("EncryptionKey failed: %v", err)
	}
	if key1 != key1Again {
		t.Error("same password should produce same key")
	}
}

func TestMachineFingerprint(t *testing.T) {
	fp, err := machineFingerprint()
	if err != nil {
		t.Fatalf("machineFingerprint failed: %v", err)
	}
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
	if len(fp) != 32 {
		t.Errorf("expected 32-char fingerprint, got %d", len(fp))
	}

	// Should be deterministic
	fp2, _ := machineFingerprint()
	if fp != fp2 {
		t.Error("fingerprint should be deterministic")
	}
}

func TestEncryptAES256(t *testing.T) {
	key := DeriveAESKey("test-password")
	plaintext := "sensitive data"

	ciphertext, err := EncryptAES256(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAES256 failed: %v", err)
	}
	if ciphertext == "" {
		t.Error("expected non-empty ciphertext")
	}
	if ciphertext == plaintext {
		t.Error("ciphertext should differ from plaintext")
	}
}

func TestDecryptAES256(t *testing.T) {
	key := DeriveAESKey("test-password")
	plaintext := "secret api key 12345"

	ciphertext, err := EncryptAES256(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAES256 failed: %v", err)
	}

	decrypted, err := DecryptAES256(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptAES256 failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected '%s', got '%s'", plaintext, decrypted)
	}
}

func TestDecryptAES256WrongKey(t *testing.T) {
	key1 := DeriveAESKey("password1")
	key2 := DeriveAESKey("password2")

	ciphertext, err := EncryptAES256("secret", key1)
	if err != nil {
		t.Fatalf("EncryptAES256 failed: %v", err)
	}

	_, err = DecryptAES256(ciphertext, key2)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptAES256InvalidHex(t *testing.T) {
	key := DeriveAESKey("test")
	_, err := DecryptAES256("not-valid-hex!@#", key)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestDecryptAES256TooShort(t *testing.T) {
	key := DeriveAESKey("test")
	// Valid hex but too short to contain nonce
	shortHex := hex.EncodeToString([]byte("short"))
	_, err := DecryptAES256(shortHex, key)
	if err == nil {
		t.Error("expected error for too-short ciphertext")
	}
}

func TestEncryptAES256InvalidKey(t *testing.T) {
	// AES-256 requires 32-byte key
	_, err := EncryptAES256("test", []byte("short"))
	if err == nil {
		t.Error("expected error for invalid key length")
	}
}

func TestDeriveAESKey(t *testing.T) {
	key := DeriveAESKey("my-password")
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}

	// Should be deterministic
	key2 := DeriveAESKey("my-password")
	if hex.EncodeToString(key) != hex.EncodeToString(key2) {
		t.Error("same password should produce same key")
	}

	// Different passwords should produce different keys
	key3 := DeriveAESKey("different")
	if hex.EncodeToString(key) == hex.EncodeToString(key3) {
		t.Error("different passwords should produce different keys")
	}
}

func TestDeriveAESKeyKnownValue(t *testing.T) {
	// Verify the derivation matches the implementation
	password := "test123"
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte("serverguard-aes256-v1"))
	expected := h.Sum(nil)

	got := DeriveAESKey(password)
	if hex.EncodeToString(got) != hex.EncodeToString(expected) {
		t.Error("DeriveAESKey does not match expected derivation")
	}
}

func TestEncryptDecryptAES256EmptyString(t *testing.T) {
	key := DeriveAESKey("test")
	ciphertext, err := EncryptAES256("", key)
	if err != nil {
		t.Fatalf("EncryptAES256 failed: %v", err)
	}

	decrypted, err := DecryptAES256(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptAES256 failed: %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string, got '%s'", decrypted)
	}
}

func TestEncryptDecryptAES256Unicode(t *testing.T) {
	key := DeriveAESKey("test")
	plaintext := "中文加密测试 🔐"

	ciphertext, err := EncryptAES256(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAES256 failed: %v", err)
	}

	decrypted, err := DecryptAES256(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptAES256 failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected '%s', got '%s'", plaintext, decrypted)
	}
}

// Ensure strings import is used
var _ = strings.Contains