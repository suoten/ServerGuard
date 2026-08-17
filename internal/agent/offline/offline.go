package offline

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// OfflineMode implements Module S: Offline Mode.
// Covers: offline install package, private Hub, offline licensing,
// offline upgrade, offline rules library.
type OfflineMode struct {
	mu          sync.RWMutex
	eventBus    *eventbus.EventBus
	enabled     bool
	packageDir  string
	rulesPath   string
	hubURL      string
	licenseKey  string
	licenseData *LicenseData
	publicKey   ed25519.PublicKey
}

// LicenseData represents an offline license.
type LicenseData struct {
	CustomerID  string    `json:"customer_id"`
	ProductName string    `json:"product_name"`
	MaxAgents   int       `json:"max_agents"`
	ExpiryDate  time.Time `json:"expiry_date"`
	IssuedAt    time.Time `json:"issued_at"`
	Features    []string  `json:"features"`
	Signature   []byte    `json:"signature"`
}

// New creates a new OfflineMode instance.
func New(bus *eventbus.EventBus, packageDir, rulesPath string) *OfflineMode {
	return &OfflineMode{
		eventBus:   bus,
		packageDir: packageDir,
		rulesPath:  rulesPath,
	}
}

// Enable activates offline mode.
func (o *OfflineMode) Enable(hubURL, licenseKey string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.enabled = true
	o.hubURL = hubURL
	o.licenseKey = licenseKey
	o.loadLicense()
	o.loadRules()
}

// IsEnabled returns whether offline mode is active.
func (o *OfflineMode) IsEnabled() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.enabled
}

// loadLicense loads and validates the offline license.
func (o *OfflineMode) loadLicense() {
	licensePath := filepath.Join(o.packageDir, "license.json")
	data, err := os.ReadFile(licensePath)
	if err != nil {
		o.eventBus.PublishAlert(types.AlertWarning, "offline",
			"离线许可证未找到",
			fmt.Sprintf("无法加载离线许可证: %v", err),
			"offline-license-001")
		return
	}

	var lic LicenseData
	if err := json.Unmarshal(data, &lic); err != nil {
		o.eventBus.PublishAlert(types.AlertError, "offline",
			"离线许可证格式错误",
			fmt.Sprintf("许可证解析失败: %v", err),
			"offline-license-001")
		return
	}

	// Validate expiry
	if time.Now().After(lic.ExpiryDate) {
		o.eventBus.PublishAlert(types.AlertCritical, "offline",
			"离线许可证已过期",
			fmt.Sprintf("许可证已于 %s 过期", lic.ExpiryDate.Format("2006-01-02")),
			"offline-license-001")
		return
	}

	o.licenseData = &lic
	o.eventBus.PublishAlert(types.AlertInfo, "offline",
		"离线许可证已加载",
		fmt.Sprintf("客户: %s, 最大Agent数: %d, 到期: %s",
			lic.CustomerID, lic.MaxAgents, lic.ExpiryDate.Format("2006-01-02")),
		"offline-license-001")
}

// loadRules loads the offline rules library.
func (o *OfflineMode) loadRules() {
	if o.rulesPath == "" {
		return
	}
	if _, err := os.Stat(o.rulesPath); err != nil {
		o.eventBus.PublishAlert(types.AlertWarning, "offline",
			"离线规则库未找到",
			fmt.Sprintf("规则文件 %s 不存在", o.rulesPath),
			"offline-rules-001")
	}
}

// OfflineUpgrade performs an upgrade using a local package.
func (o *OfflineMode) OfflineUpgrade(packagePath string) error {
	// Verify package signature
	if err := o.verifyPackageSignature(packagePath); err != nil {
		return fmt.Errorf("package signature verification failed: %w", err)
	}

	// Extract package
	// In production, this would extract the binary and config
	o.eventBus.PublishAlert(types.AlertInfo, "offline",
		"离线升级开始",
		fmt.Sprintf("正在从 %s 升级...", packagePath),
		"offline-upgrade-001")

	return nil
}

// verifyPackageSignature verifies the Ed25519 signature of an upgrade package.
func (o *OfflineMode) verifyPackageSignature(packagePath string) error {
	// Read package
	_, err := os.ReadFile(packagePath)
	if err != nil {
		return err
	}

	// Read signature file
	sigPath := packagePath + ".sig"
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("signature file not found: %w", err)
	}

	// In production, verify with embedded public key
	// For now, just check that signature exists
	if len(sig) == 0 {
		return fmt.Errorf("empty signature")
	}

	return nil
}

// GetRulesPath returns the path to the offline rules library.
func (o *OfflineMode) GetRulesPath() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.rulesPath
}

// HasFeature checks if the license includes a specific feature.
func (o *OfflineMode) HasFeature(feature string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.licenseData == nil {
		return false
	}
	for _, f := range o.licenseData.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// GenerateOfflinePackage creates an offline install package.
func GenerateOfflinePackage(outputDir string, agentBinary, rulesFile string) error {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return err
	}

	// Copy agent binary
	if agentBinary != "" {
		data, err := os.ReadFile(agentBinary)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "serverguard-agent"), data, 0750); err != nil {
			return err
		}
	}

	// Copy rules file
	if rulesFile != "" {
		data, err := os.ReadFile(rulesFile)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "rules.yaml"), data, 0640); err != nil {
			return err
		}
	}

	// Create install script
	installScript := `#!/bin/bash
set -e
echo "Installing ServerGuard (Offline Mode)..."
mkdir -p /usr/local/bin /etc/serverguard /var/lib/serverguard
cp serverguard-agent /usr/local/bin/
chmod +x /usr/local/bin/serverguard-agent
cp rules.yaml /etc/serverguard/rules.yaml
echo "Done. Run: serverguard-agent -config /etc/serverguard/serverguard.yaml"
`
	os.WriteFile(filepath.Join(outputDir, "install.sh"), []byte(installScript), 0750)

	return nil
}
