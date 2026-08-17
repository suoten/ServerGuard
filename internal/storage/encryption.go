package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
)

// EncryptionKey 派生 SQLCipher 加密密钥
// 密钥由机器指纹 + 用户密码派生，不落盘明文
func EncryptionKey(userPassword string) (string, error) {
	fingerprint, err := machineFingerprint()
	if err != nil {
		return "", fmt.Errorf("get machine fingerprint: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(fingerprint))
	h.Write([]byte(userPassword))
	h.Write([]byte("serverguard-sqlcipher-v1"))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// machineFingerprint 获取机器指纹
func machineFingerprint() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	h := sha256.New()
	h.Write([]byte(hostname))
	h.Write([]byte(runtime.GOOS))
	h.Write([]byte(runtime.GOARCH))
	// 加入 CPU 核心数作为额外标识
	h.Write([]byte(fmt.Sprintf("%d", runtime.NumCPU())))
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// EncryptAES256 AES-256-GCM 加密（用于敏感配置存储，如宝塔API凭据）
func EncryptAES256(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptAES256 AES-256-GCM 解密
func DecryptAES256(ciphertext string, key []byte) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertextBody := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}

// DeriveAESKey 从密码派生 AES-256 密钥
func DeriveAESKey(password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte("serverguard-aes256-v1"))
	return h.Sum(nil)
}
