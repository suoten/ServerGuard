package version

import (
	"testing"
	"time"
)

func TestNewLicenseGate_NilDefaultsToCommunity(t *testing.T) {
	g := NewLicenseGate(nil)
	if g == nil {
		t.Fatal("NewLicenseGate returned nil")
	}
	if g.GetTier() != TierCommunity {
		t.Error("nil license should default to community tier")
	}
}

func TestNewLicenseGate_WithLicense(t *testing.T) {
	lic := &License{Tier: TierPro, Expiry: time.Now().Add(365 * 24 * time.Hour)}
	g := NewLicenseGate(lic)
	if g.GetTier() != TierPro {
		t.Error("expected pro tier")
	}
}

func TestLicenseGate_SetLicense(t *testing.T) {
	g := NewLicenseGate(nil)
	g.SetLicense(&License{Tier: TierEnterprise, Expiry: time.Now().Add(time.Hour)})
	if g.GetTier() != TierEnterprise {
		t.Error("SetLicense should update tier")
	}
}

func TestLicenseGate_CanUse(t *testing.T) {
	cases := []struct {
		name    string
		tier    Tier
		expired bool
		feature Feature
		want    bool
	}{
		{"pro_has_cert", TierPro, false, FeatureCertAutoRenew, true},
		{"pro_no_rbac", TierPro, false, FeatureRBAC, false},
		{"enterprise_has_rbac", TierEnterprise, false, FeatureRBAC, true},
		{"community_no_cert", TierCommunity, false, FeatureCertAutoRenew, false},
		{"community_process_guard", TierCommunity, false, FeatureProcessGuardUnlimited, true},
		{"expired_pro_process_guard", TierPro, true, FeatureProcessGuardUnlimited, true},
		{"expired_pro_cert", TierPro, true, FeatureCertAutoRenew, false},
		{"flagship_sla", TierFlagship, false, FeatureSLA, true},
		{"expired_flagship_sla", TierFlagship, true, FeatureSLA, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expiry := time.Now().Add(365 * 24 * time.Hour)
			if tc.expired {
				expiry = time.Now().Add(-time.Hour)
			}
			g := NewLicenseGate(&License{Tier: tc.tier, Expiry: expiry})
			if got := g.CanUse(tc.feature); got != tc.want {
				t.Errorf("CanUse(%s) = %v, want %v", tc.feature, got, tc.want)
			}
		})
	}
}

func TestLicenseGate_CanUseModule(t *testing.T) {
	community := NewLicenseGate(&License{Tier: TierCommunity})
	pro := NewLicenseGate(&License{Tier: TierPro, Expiry: time.Now().Add(time.Hour)})
	expiredPro := NewLicenseGate(&License{Tier: TierPro, Expiry: time.Now().Add(-time.Hour)})

	cases := []struct {
		name   string
		module string
		gate   *LicenseGate
		want   bool
	}{
		{"community_resource", "resource", community, true},
		{"community_security", "security", community, true},
		{"community_vulnscan", "vulnscan", community, false},
		{"community_rbac", "rbac", community, false},
		{"community_offline", "offline", community, false},
		{"community_multi_server", "multi_server", community, false},
		{"community_unknown", "unknown-module", community, true},
		{"pro_vulnscan", "vulnscan", pro, true},
		{"pro_rbac", "rbac", pro, false},
		{"pro_cloudflare", "cloudflare", pro, false},
		{"expired_pro_vulnscan", "vulnscan", expiredPro, false},
		{"expired_pro_resource", "resource", expiredPro, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.gate.CanUseModule(tc.module); got != tc.want {
				t.Errorf("CanUseModule(%q) = %v, want %v", tc.module, got, tc.want)
			}
		})
	}
}

func TestLicenseGate_GetMaxAgents(t *testing.T) {
	// NewLicenseGate(nil) uses DefaultLicense() which is a non-nil community license (max=1)
	g := NewLicenseGate(nil)
	if g.GetMaxAgents() != 1 {
		t.Errorf("nil-arg license should use community default (max=1), got %d", g.GetMaxAgents())
	}

	// Explicitly setting nil license hits the `return 3` fallback path
	g2 := NewLicenseGate(&License{Tier: TierCommunity})
	g2.SetLicense(nil)
	if g2.GetMaxAgents() != 3 {
		t.Errorf("nil license should return 3 max agents, got %d", g2.GetMaxAgents())
	}

	g.SetLicense(&License{Tier: TierEnterprise, Expiry: time.Now().Add(time.Hour)})
	if g.GetMaxAgents() != 10 {
		t.Errorf("enterprise should have 10 max agents, got %d", g.GetMaxAgents())
	}

	g.SetLicense(&License{Tier: TierFlagship, Expiry: time.Now().Add(time.Hour)})
	if g.GetMaxAgents() != -1 {
		t.Errorf("flagship should have unlimited (-1) agents, got %d", g.GetMaxAgents())
	}
}

func TestLicenseGate_GetTier(t *testing.T) {
	g := NewLicenseGate(nil)
	if g.GetTier() != TierCommunity {
		t.Error("nil license -> community tier")
	}

	g.SetLicense(&License{Tier: TierEnterprise, Expiry: time.Now().Add(-time.Hour)})
	if g.GetTier() != TierCommunity {
		t.Error("expired enterprise should downgrade to community")
	}
}

func TestLicenseGate_CanAutoRenewCert(t *testing.T) {
	community := NewLicenseGate(&License{Tier: TierCommunity})
	if community.CanAutoRenewCert() {
		t.Error("community should not auto-renew cert")
	}
	pro := NewLicenseGate(&License{Tier: TierPro, Expiry: time.Now().Add(time.Hour)})
	if !pro.CanAutoRenewCert() {
		t.Error("pro should auto-renew cert")
	}
}

func TestLicenseGate_CanUseAllChannels(t *testing.T) {
	community := NewLicenseGate(&License{Tier: TierCommunity})
	if community.CanUseAllChannels() {
		t.Error("community should not use all channels")
	}
	pro := NewLicenseGate(&License{Tier: TierPro, Expiry: time.Now().Add(time.Hour)})
	if !pro.CanUseAllChannels() {
		t.Error("pro should use all channels")
	}
}

func TestLicenseGate_CanBatchPolicy(t *testing.T) {
	community := NewLicenseGate(&License{Tier: TierCommunity})
	if community.CanBatchPolicy() {
		t.Error("community should not batch policy")
	}
	ent := NewLicenseGate(&License{Tier: TierEnterprise, Expiry: time.Now().Add(time.Hour)})
	if !ent.CanBatchPolicy() {
		t.Error("enterprise should batch policy")
	}
}

func TestLicenseGate_IsFeatureGated(t *testing.T) {
	g := NewLicenseGate(&License{Tier: TierCommunity})

	allowed, reason := g.IsFeatureGated(FeatureProcessGuardUnlimited)
	if !allowed {
		t.Error("community should allow process guard unlimited")
	}
	if reason != "" {
		t.Errorf("allowed feature should have empty reason, got %q", reason)
	}

	allowed, reason = g.IsFeatureGated(FeatureCertAutoRenew)
	if allowed {
		t.Error("community should not allow cert auto renew")
	}
	if reason == "" {
		t.Error("denied feature should have non-empty reason")
	}
}

func TestLicenseGate_IsFeatureGatedReasonByTier(t *testing.T) {
	cases := []struct {
		tier         Tier
		expectReason string
	}{
		{TierCommunity, "社区版不支持此功能，请升级到专业版"},
		{TierPro, "专业版不支持此功能，请升级到企业版"},
		{TierEnterprise, "企业版不支持此功能，请升级到旗舰版"},
	}
	for _, tc := range cases {
		g := NewLicenseGate(&License{Tier: tc.tier, Expiry: time.Now().Add(time.Hour)})
		_, reason := g.IsFeatureGated(FeatureSLA)
		if reason != tc.expectReason {
			t.Errorf("tier %s: expected reason %q, got %q", tc.tier, tc.expectReason, reason)
		}
	}
}

func TestIsCommunityFeature(t *testing.T) {
	if !isCommunityFeature(FeatureProcessGuardUnlimited) {
		t.Error("ProcessGuardUnlimited should be a community feature")
	}
	if isCommunityFeature(FeatureCertAutoRenew) {
		t.Error("CertAutoRenew should not be a community feature")
	}
	if isCommunityFeature(FeatureSLA) {
		t.Error("SLA should not be a community feature")
	}
}

func TestInitLicenseGateAndGetLicenseGate(t *testing.T) {
	InitLicenseGate(&License{Tier: TierPro, Expiry: time.Now().Add(time.Hour)})
	g := GetLicenseGate()
	if g == nil {
		t.Fatal("GetLicenseGate returned nil")
	}
	if g.GetTier() != TierPro {
		t.Error("expected pro tier after init")
	}
}

func TestGetLicenseGate_DefaultWhenUninitialized(t *testing.T) {
	globalGate = nil
	g := GetLicenseGate()
	if g == nil {
		t.Fatal("GetLicenseGate returned nil")
	}
	if g.GetTier() != TierCommunity {
		t.Error("uninitialized gate should default to community")
	}
}

// --- License methods coverage ---

func TestLicense_IsDowngraded(t *testing.T) {
	expired := &License{Tier: TierPro, Expiry: time.Now().Add(-time.Hour)}
	if !expired.IsDowngraded() {
		t.Error("expired license should be downgraded")
	}
	valid := &License{Tier: TierPro, Expiry: time.Now().Add(time.Hour)}
	if valid.IsDowngraded() {
		t.Error("valid license should not be downgraded")
	}
}

func TestLicense_HasFeatureNil(t *testing.T) {
	var nilLic *License
	if nilLic.HasFeature(FeatureCertAutoRenew) {
		t.Error("nil license should not have any feature")
	}
}

func TestLicense_HasFeatureUnknownTier(t *testing.T) {
	lic := &License{Tier: "unknown-tier"}
	if lic.HasFeature(FeatureCertAutoRenew) {
		t.Error("unknown tier should not have features")
	}
}

func TestVerifyLicenseSignature(t *testing.T) {
	// Invalid signature length should return false
	if VerifyLicenseSignature([]byte("data"), []byte("short"), nil) {
		t.Error("invalid signature length should return false")
	}
}

func TestFullVersion(t *testing.T) {
	v := FullVersion()
	if v == "" {
		t.Error("FullVersion should return non-empty string")
	}
}

func TestShortVersion(t *testing.T) {
	v := ShortVersion()
	if v == "" {
		t.Error("ShortVersion should return non-empty string")
	}
}
