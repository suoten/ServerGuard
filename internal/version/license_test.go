package version

import (
	"testing"
	"time"
)

func TestLicense_HasFeature(t *testing.T) {
	// 社区版
	community := &License{Tier: TierCommunity}
	if community.HasFeature(FeatureCertAutoRenew) {
		t.Error("Community should not have CertAutoRenew")
	}

	// 专业版
	pro := &License{Tier: TierPro}
	if !pro.HasFeature(FeatureCertAutoRenew) {
		t.Error("Pro should have CertAutoRenew")
	}
	if !pro.HasFeature(FeatureIntrusionDetection) {
		t.Error("Pro should have IntrusionDetection")
	}

	// 企业版
	ent := &License{Tier: TierEnterprise}
	if !ent.HasFeature(FeatureMultiServer) {
		t.Error("Enterprise should have MultiServer")
	}
	if !ent.HasFeature(FeatureRBAC) {
		t.Error("Enterprise should have RBAC")
	}

	// 旗舰版
	flag := &License{Tier: TierFlagship}
	if !flag.HasFeature(FeatureUnlimitedAgents) {
		t.Error("Flagship should have UnlimitedAgents")
	}
	if !flag.HasFeature(FeatureSLA) {
		t.Error("Flagship should have SLA")
	}
}

func TestLicense_IsExpired(t *testing.T) {
	// 未过期
	future := &License{Tier: TierPro, Expiry: time.Now().Add(365 * 24 * time.Hour)}
	if future.IsExpired() {
		t.Error("future license should not be expired")
	}

	// 已过期
	past := &License{Tier: TierPro, Expiry: time.Now().Add(-1 * time.Hour)}
	if !past.IsExpired() {
		t.Error("past license should be expired")
	}

	// nil license
	var nilLicense *License
	if !nilLicense.IsExpired() {
		t.Error("nil license should be expired")
	}
}

func TestLicense_EffectiveTier(t *testing.T) {
	// 未过期，返回原层级
	pro := &License{Tier: TierPro, Expiry: time.Now().Add(365 * 24 * time.Hour)}
	if pro.EffectiveTier() != TierPro {
		t.Error("non-expired pro should return TierPro")
	}

	// 过期，降级为社区版
	expired := &License{Tier: TierEnterprise, Expiry: time.Now().Add(-1 * time.Hour)}
	if expired.EffectiveTier() != TierCommunity {
		t.Error("expired enterprise should downgrade to community")
	}
}

func TestLicense_GetMaxAgents(t *testing.T) {
	community := &License{Tier: TierCommunity}
	if community.GetMaxAgents() != 1 {
		t.Error("Community should have max 1 agent")
	}

	ent := &License{Tier: TierEnterprise, Expiry: time.Now().Add(365 * 24 * time.Hour)}
	if ent.GetMaxAgents() != 10 {
		t.Error("Enterprise should have max 10 agents")
	}

	flag := &License{Tier: TierFlagship, Expiry: time.Now().Add(365 * 24 * time.Hour)}
	if flag.GetMaxAgents() != -1 {
		t.Error("Flagship should have unlimited agents (-1)")
	}
}

func TestDefaultLicense(t *testing.T) {
	l := DefaultLicense()
	if l.Tier != TierCommunity {
		t.Error("Default license should be community")
	}
}
