package upgrader

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

// VerifyPackageSignature 验证升级包签名（Ed25519）
// publicKey 内置在 Agent 二进制中
func VerifyPackageSignature(packagePath, sigHex string, publicKey ed25519.PublicKey) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d (expected %d)", len(sig), ed25519.SignatureSize)
	}

	data, err := os.ReadFile(packagePath)
	if err != nil {
		return fmt.Errorf("failed to read package: %w", err)
	}

	if !ed25519.Verify(publicKey, data, sig) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// EmbeddedPublicKey Agent 内置的 Ed25519 公钥
// 用于验证升级包签名，防止篡改
// 防降级攻击
var EmbeddedPublicKey ed25519.PublicKey

// SetEmbeddedPublicKey 设置内置公钥
func SetEmbeddedPublicKey(key ed25519.PublicKey) {
	EmbeddedPublicKey = key
}

// VerifyWithEmbeddedKey 使用内置公钥验证签名
func VerifyWithEmbeddedKey(packagePath, sigHex string) error {
	if EmbeddedPublicKey == nil {
		return fmt.Errorf("embedded public key not set")
	}
	return VerifyPackageSignature(packagePath, sigHex, EmbeddedPublicKey)
}
