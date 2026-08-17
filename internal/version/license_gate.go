package version

import (
	"sync"
)

type LicenseGate struct {
	mu      sync.RWMutex
	license *License
}

func NewLicenseGate(lic *License) *LicenseGate {
	if lic == nil {
		lic = DefaultLicense()
	}
	return &LicenseGate{license: lic}
}

func (g *LicenseGate) SetLicense(lic *License) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.license = lic
}

func (g *LicenseGate) CanUse(feature Feature) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.license == nil {
		return false
	}
	if g.license.IsExpired() {
		return isCommunityFeature(feature)
	}
	return g.license.HasFeature(feature)
}

func (g *LicenseGate) CanUseModule(module string) bool {
	switch module {
	case "resource", "service", "security", "log", "network", "system", "config", "cert", "clock", "fd", "dns", "tuning", "traffic":
		return true
	case "docker", "ai", "database", "backup":
		return g.CanUse(FeatureIntrusionDetection)
	case "websecurity", "vulnscan", "serversecurity", "attackwarn":
		return g.CanUse(FeatureIntrusionDetection)
	case "cloudflare":
		return g.CanUse(FeatureAPI)
	case "rbac":
		return g.CanUse(FeatureRBAC)
	case "offline":
		return g.CanUse(FeatureOfflineMode)
	case "multi_server":
		return g.CanUse(FeatureMultiServer)
	case "config_approval":
		return g.CanUse(FeatureConfigApproval)
	default:
		return true
	}
}

func (g *LicenseGate) GetMaxAgents() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.license == nil {
		return 3
	}
	return g.license.GetMaxAgents()
}

func (g *LicenseGate) GetTier() Tier {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.license == nil {
		return TierCommunity
	}
	return g.license.EffectiveTier()
}

func (g *LicenseGate) CanAutoRenewCert() bool {
	return g.CanUse(FeatureCertAutoRenew)
}

func (g *LicenseGate) CanUseAllChannels() bool {
	return g.CanUse(FeatureAllChannels)
}

func (g *LicenseGate) CanBatchPolicy() bool {
	return g.CanUse(FeatureBatchPolicy)
}

func (g *LicenseGate) IsFeatureGated(feature Feature) (allowed bool, reason string) {
	allowed = g.CanUse(feature)
	if !allowed {
		reason = "此功能需要更高版本的许可证"
		tier := g.GetTier()
		switch tier {
		case TierCommunity:
			reason = "社区版不支持此功能，请升级到专业版"
		case TierPro:
			reason = "专业版不支持此功能，请升级到企业版"
		case TierEnterprise:
			reason = "企业版不支持此功能，请升级到旗舰版"
		}
	}
	return
}

func isCommunityFeature(f Feature) bool {
	switch f {
	case FeatureProcessGuardUnlimited:
		return true
	}
	return false
}

var globalGate *LicenseGate

func InitLicenseGate(lic *License) {
	globalGate = NewLicenseGate(lic)
}

func GetLicenseGate() *LicenseGate {
	if globalGate == nil {
		globalGate = NewLicenseGate(nil)
	}
	return globalGate
}
