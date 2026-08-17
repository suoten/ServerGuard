package config

import (
	"fmt"
	"strings"
)

// LegalModel implements §10.6: Legal and Liability Definition.
// Covers: disclaimer, high-risk operations default off, liability caps.

// LegalConfig defines the legal and liability configuration.
type LegalConfig struct {
	// Disclaimer text shown to users on first launch
	DisclaimerText string `yaml:"disclaimer_text"`

	// High-risk operations that are disabled by default and require explicit user opt-in
	HighRiskDisabledByDefault []string `yaml:"high_risk_disabled_by_default"`

	// Liability cap = annual subscription fee × this multiplier
	LiabilityCapMultiplier int `yaml:"liability_cap_multiplier"`

	// Whether auto-repair is opt-in (true) or opt-out (false)
	AutoRepairOptIn bool `yaml:"auto_repair_opt_in"`

	// User agreement version
	UserAgreementVersion string `yaml:"user_agreement_version"`

	// Data processing agreement (DPA) version
	DPAVersion string `yaml:"dpa_version"`

	// Privacy policy URL
	PrivacyPolicyURL string `yaml:"privacy_policy_url"`

	// Compliance certifications
	ComplianceCertifications []string `yaml:"compliance_certifications"`
}

// DefaultLegalConfig returns the default legal configuration.
func DefaultLegalConfig() LegalConfig {
	return LegalConfig{
		DisclaimerText: `ServerGuard 自动修复功能为尽力而为（Best Effort），不保证零故障。
自动 Kill 进程、重启服务、清理文件等操作可能导致数据丢失或服务中断。
用户在使用前应充分理解风险，并确保重要数据已备份。
ServerGuard 不承担因自动修复操作导致的任何直接或间接损失。`,

		HighRiskDisabledByDefault: []string{
			"kill_database",       // Kill database processes (MySQL, PostgreSQL, etc.)
			"kill_system_service", // Kill systemd managed services
			"delete_files",        // Delete files without trash
			"modify_config_auto",  // Auto-apply config changes without approval
			"disable_firewall",    // Disable firewall rules
			"kill_cron",           // Kill cron/scheduled tasks
		},

		LiabilityCapMultiplier: 3,    // Liability cap = annual fee × 3
		AutoRepairOptIn:        true, // Auto-repair is opt-in (not enabled by default)
		UserAgreementVersion:   "1.0",
		DPAVersion:             "1.0",
		PrivacyPolicyURL:       "https://serverguard.io/privacy",
		ComplianceCertifications: []string{
			"等保 2.0 三级", // China cybersecurity classification
			"ISO 27001", // Information security management
			"GDPR",      // EU General Data Protection Regulation
			"网络安全法",     // China Cybersecurity Law
		},
	}
}

// IsHighRiskOperation checks if an operation type is high-risk (disabled by default).
func (lc *LegalConfig) IsHighRiskOperation(operation string) bool {
	for _, op := range lc.HighRiskDisabledByDefault {
		if op == operation {
			return true
		}
	}
	return false
}

// GetLiabilityCap returns the liability cap based on annual fee.
func (lc *LegalConfig) GetLiabilityCap(annualFee float64) float64 {
	return annualFee * float64(lc.LiabilityCapMultiplier)
}

// GetUserAgreement returns the user agreement text.
func (lc *LegalConfig) GetUserAgreement() string {
	return fmt.Sprintf(`
ServerGuard 用户协议 v%s

1. 自动修复为尽力而为（Best Effort），不承担间接损失
2. 高危操作（Kill 数据库/系统服务、删除文件）默认关闭，需用户显式开启
3. 赔付上限 = 年订阅费 × %d 倍
4. 数据处理协议（DPA）v%s
5. 隐私政策: %s

合规认证: %s
`, lc.UserAgreementVersion, lc.LiabilityCapMultiplier, lc.DPAVersion,
		lc.PrivacyPolicyURL, strings.Join(lc.ComplianceCertifications, ", "))
}

// ValidActionTypes 合法 action type 枚举
var ValidActionTypes = map[string]bool{
	"restart": true, "kill": true, "alert": true, "quarantine": true,
	"cleanup": true, "rotate_log": true, "block_ip": true, "unblock_ip": true,
	"scale": true, "migrate": true, "snapshot": true, "rollback": true,
	"notify": true, "webhook": true, "exec": true, "noop": true,
	"ban_ip": true, "unban_ip": true, "rate_limit": true,
}

// ValidateRules 校验规则配置的合法性
func ValidateRules(rules []RuleItem) error {
	seenIDs := make(map[string]bool)

	for _, r := range rules {
		// 规则 ID 唯一性
		if seenIDs[r.ID] {
			return fmt.Errorf("规则 ID 重复: %s", r.ID)
		}
		seenIDs[r.ID] = true

		// priority 范围 (0-1000)
		if r.Priority < 0 || r.Priority > 1000 {
			return fmt.Errorf("规则 %s: priority %d 超出范围 [0, 1000]", r.ID, r.Priority)
		}

		// cooldown 正整数
		if r.CooldownMs < 0 {
			return fmt.Errorf("规则 %s: cooldown_ms 不能为负数", r.ID)
		}

		// action type 枚举校验
		for _, action := range r.Actions {
			if !ValidActionTypes[action.Type] {
				return fmt.Errorf("规则 %s: 未知 action type %q", r.ID, action.Type)
			}
		}
	}

	return nil
}

// ValidateWhitelistConflict 校验白名单与硬白名单不冲突
func ValidateWhitelistConflict(whitelist, hardWhitelist []string) error {
	hardSet := make(map[string]bool)
	for _, ip := range hardWhitelist {
		hardSet[ip] = true
	}
	for _, ip := range whitelist {
		if hardSet[ip] {
			return fmt.Errorf("白名单 IP %s 与硬白名单冲突（硬白名单不可覆盖）", ip)
		}
	}
	return nil
}

// RuleItem 规则配置项（用于校验）
type RuleItem struct {
	ID         string
	Priority   int
	CooldownMs int
	Actions    []ActionRef
}

// ActionRef 动作引用
type ActionRef struct {
	Type string
}
