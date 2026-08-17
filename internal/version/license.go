package version

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"
)

// Tier 授权层级
type Tier string

const (
	TierCommunity  Tier = "community"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
	TierFlagship   Tier = "flagship"
)

// License 授权信息
type License struct {
	Tier      Tier      `json:"tier"`
	Expiry    time.Time `json:"expiry"`
	Features  []string  `json:"features"`
	MaxAgents int       `json:"max_agents"`
}

// Feature 功能标识
type Feature string

const (
	FeatureProcessGuardUnlimited Feature = "process_guard_unlimited"
	FeatureCertAutoRenew         Feature = "cert_auto_renew"
	FeatureIntrusionDetection    Feature = "intrusion_detection"
	FeatureFileTamper            Feature = "file_tamper"
	FeatureDatabaseGuard         Feature = "database_guard"
	FeatureAllChannels           Feature = "all_channels"
	FeatureMultiServer           Feature = "multi_server"
	FeatureBatchPolicy           Feature = "batch_policy"
	FeatureAPI                   Feature = "api"
	FeatureRBAC                  Feature = "rbac"
	FeatureOfflineMode           Feature = "offline_mode"
	FeatureCentralStorage        Feature = "central_storage"
	FeatureConfigApproval        Feature = "config_approval"
	FeatureUnlimitedAgents       Feature = "unlimited_agents"
	FeatureManagedService        Feature = "managed_service"
	FeatureSLA                   Feature = "sla"
)

// tierFeatures 各层级功能矩阵
var tierFeatures = map[Tier][]Feature{
	TierCommunity: {
		FeatureProcessGuardUnlimited, // 限 3 个，不是 unlimited
	},
	TierPro: {
		FeatureProcessGuardUnlimited,
		FeatureCertAutoRenew,
		FeatureIntrusionDetection,
		FeatureFileTamper,
		FeatureDatabaseGuard,
		FeatureAllChannels,
	},
	TierEnterprise: {
		FeatureProcessGuardUnlimited,
		FeatureCertAutoRenew,
		FeatureIntrusionDetection,
		FeatureFileTamper,
		FeatureDatabaseGuard,
		FeatureAllChannels,
		FeatureMultiServer,
		FeatureBatchPolicy,
		FeatureAPI,
		FeatureRBAC,
		FeatureOfflineMode,
		FeatureCentralStorage,
		FeatureConfigApproval,
	},
	TierFlagship: {
		FeatureProcessGuardUnlimited,
		FeatureCertAutoRenew,
		FeatureIntrusionDetection,
		FeatureFileTamper,
		FeatureDatabaseGuard,
		FeatureAllChannels,
		FeatureMultiServer,
		FeatureBatchPolicy,
		FeatureAPI,
		FeatureRBAC,
		FeatureOfflineMode,
		FeatureCentralStorage,
		FeatureConfigApproval,
		FeatureUnlimitedAgents,
		FeatureManagedService,
		FeatureSLA,
	},
}

// tierMaxAgents 各层级最大 Agent 数
var tierMaxAgents = map[Tier]int{
	TierCommunity:  1,
	TierPro:        1,
	TierEnterprise: 10,
	TierFlagship:   0, // 0 = unlimited
}

// HasFeature 检查授权是否有指定功能
func (l *License) HasFeature(feature Feature) bool {
	if l == nil {
		return false
	}
	features, ok := tierFeatures[l.Tier]
	if !ok {
		return false
	}
	for _, f := range features {
		if f == feature {
			return true
		}
	}
	return false
}

// IsExpired 检查授权是否过期
func (l *License) IsExpired() bool {
	if l == nil {
		return true
	}
	return time.Now().After(l.Expiry)
}

// IsDowngraded 授权过期后降级为社区版
func (l *License) IsDowngraded() bool {
	return l.IsExpired()
}

// EffectiveTier 获取有效层级（过期降级为社区版）
func (l *License) EffectiveTier() Tier {
	if l == nil || l.IsExpired() {
		return TierCommunity
	}
	return l.Tier
}

// GetMaxAgents 获取最大 Agent 数
func (l *License) GetMaxAgents() int {
	if l == nil || l.IsExpired() {
		return tierMaxAgents[TierCommunity]
	}
	max := tierMaxAgents[l.Tier]
	if max == 0 {
		return -1 // unlimited
	}
	return max
}

// DefaultLicense 默认社区版授权
func DefaultLicense() *License {
	return &License{
		Tier:      TierCommunity,
		Expiry:    time.Time{}, // 永不过期的零值表示社区版
		Features:  []string{},
		MaxAgents: 1,
	}
}

// VerifyLicenseSignature 验证授权码签名（Ed25519）
func VerifyLicenseSignature(licenseData, signature []byte, publicKey ed25519.PublicKey) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, licenseData, signature)
}

// ParseLicenseFromHex 从十六进制字符串解析授权
func ParseLicenseFromHex(tierStr, expiryStr, sigHex string, pubKey ed25519.PublicKey) (*License, error) {
	tier := Tier(tierStr)
	if _, ok := tierFeatures[tier]; !ok {
		return nil, fmt.Errorf("invalid tier: %s", tierStr)
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	data := []byte(tierStr + ":" + expiryStr)
	if !VerifyLicenseSignature(data, sig, pubKey) {
		return nil, fmt.Errorf("license signature verification failed")
	}

	expiry, err := time.Parse(time.RFC3339, expiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry: %w", err)
	}

	return &License{
		Tier:   tier,
		Expiry: expiry,
	}, nil
}
