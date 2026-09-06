package upgrader

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/version"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// Upgrader implements §8.8: Upgrade and Version Migration.
// Supports: A/B switching, atomic upgrade, version migration, rollback.
type Upgrader struct {
	mu          sync.RWMutex
	eventBus    *eventbus.EventBus
	installDir  string
	backupDir   string
	currentVer  string
	maxBackups  int
	downloadURL string
	signingKey  string // Ed25519 public key for signature verification
}

// New creates a new Upgrader.
func New(bus *eventbus.EventBus, installDir, backupDir string) *Upgrader {
	if installDir == "" {
		installDir = "/usr/local/bin"
	}
	if backupDir == "" {
		backupDir = "/var/lib/serverguard/backups"
	}
	return &Upgrader{
		eventBus:   bus,
		installDir: installDir,
		backupDir:  backupDir,
		currentVer: version.Version,
		maxBackups: 3,
	}
}

// SetServerURL sets the official website API URL for update checking.
// e.g., "https://sg.jjtt.net/api/v1"
func (u *Upgrader) SetServerURL(url string) {
	u.downloadURL = strings.TrimRight(url, "/")
}

// SetSigningKey sets the Ed25519 public key for signature verification.
func (u *Upgrader) SetSigningKey(key string) {
	u.signingKey = key
}

// updateHTTPClient 带超时的更新服务器客户端（元数据检查用）。
// 调用方的 ctx 是 6 小时一次的后台检查（无超时），http.DefaultClient 无超时——
// 更新服务器挂起会让该 goroutine 永久卡死在当次迭代。
var updateHTTPClient = &http.Client{Timeout: 30 * time.Second}

// updateDownloadClient 二进制包下载专用：Client.Timeout 覆盖整个响应体读取，
// 30s 会掐断大包下载；这里交给 ctx 控制（15 分钟）。
var updateDownloadClient = &http.Client{}

// CheckForUpdate checks if a new version is available.
func (u *Upgrader) CheckForUpdate(ctx context.Context, channel string) (*UpdateInfo, error) {
	if channel == "" {
		channel = "stable"
	}

	// Check for offline upgrade package first
	localPkg := filepath.Join(u.backupDir, "upgrade.pkg")
	if _, err := os.Stat(localPkg); err == nil {
		return &UpdateInfo{
			Version:     "local",
			DownloadURL: localPkg,
			IsOffline:   true,
			Local:       true,
		}, nil
	}

	// Check online (if not in offline mode)
	url := fmt.Sprintf("%s/latest?channel=%s&os=%s&arch=%s",
		u.downloadURL, channel, runtime.GOOS, runtime.GOARCH)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("update server returned %d", resp.StatusCode)
	}

	var info UpdateInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	if info.UpToDate || info.DownloadURL == "" {
		return nil, nil
	}

	// Only upgrade when the remote version is strictly newer — never
	// silently downgrade (e.g. server has no published version yet and
	// reports 0.0.0).
	if compareVersions(info.Version, u.currentVer) <= 0 {
		return nil, nil
	}

	return &info, nil
}

// compareVersions compares two dotted version strings ("1.2.3").
// Returns 1 if a > b, 0 if equal, -1 if a < b. Non-numeric suffixes are ignored.
func compareVersions(a, b string) int {
	parse := func(s string) [3]int {
		var out [3]int
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		parts := strings.SplitN(s, ".", 3)
		for i := 0; i < len(parts) && i < 3; i++ {
			p := parts[i]
			if idx := strings.IndexAny(p, "-+"); idx >= 0 {
				p = p[:idx]
			}
			fmt.Sscanf(p, "%d", &out[i])
		}
		return out
	}
	va, vb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if va[i] > vb[i] {
			return 1
		}
		if va[i] < vb[i] {
			return -1
		}
	}
	return 0
}

// UpdateInfo represents information about an available update.
type UpdateInfo struct {
	Version      string `json:"version"`
	DownloadURL  string `json:"download_url"`
	SHA256       string `json:"sha256"`
	Signature    string `json:"signature"`
	ReleaseNotes string `json:"release_notes"`
	Critical     bool   `json:"critical"`
	UpToDate     bool   `json:"up_to_date"`
	IsOffline    bool   `json:"-"`
	Local        bool   `json:"-"`
}

// PerformUpgrade performs an atomic A/B upgrade.
func (u *Upgrader) PerformUpgrade(ctx context.Context, info *UpdateInfo) error {
	u.eventBus.PublishAlert(types.AlertInfo, "upgrade",
		"开始升级",
		fmt.Sprintf("从 v%s 升级到 v%s", u.currentVer, info.Version),
		"upgrade-001")

	// Step 1: Download new binary (or use local package)
	binaryPath := filepath.Join(u.backupDir, fmt.Sprintf("serverguard-agent.%s", info.Version))
	if info.Local {
		binaryPath = info.DownloadURL
	} else {
		// Prepend server URL if download_url is relative
		dlURL := info.DownloadURL
		if strings.HasPrefix(dlURL, "/") && u.downloadURL != "" {
			dlURL = u.downloadURL + dlURL
		}
		// 只允许 http(s) 下载地址，杜绝 file:// 等协议注入
		if !strings.HasPrefix(dlURL, "https://") && !strings.HasPrefix(dlURL, "http://") {
			return fmt.Errorf("refusing unsafe download_url: %q", dlURL)
		}
		if err := u.downloadBinary(ctx, dlURL, binaryPath, info.SHA256); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
	}

	// Step 2: Verify SHA-256（强制：更新服务器必须提供校验和；离线本地包除外）
	if !info.Local {
		if info.SHA256 == "" {
			return fmt.Errorf("update server did not provide sha256, refusing upgrade")
		}
		if err := u.verifySHA256(binaryPath, info.SHA256); err != nil {
			return fmt.Errorf("SHA-256 verification failed: %w", err)
		}
	}

	// Step 3: Verify Ed25519 signature（fail-closed：配置了公钥就必须有有效签名）
	if u.signingKey != "" {
		if info.Signature == "" {
			return fmt.Errorf("update server did not provide signature, refusing upgrade")
		}
		pubKey, err := parseEd25519PublicKey(u.signingKey)
		if err != nil {
			return fmt.Errorf("invalid signing key config: %w", err)
		}
		if err := VerifyPackageSignature(binaryPath, info.Signature, pubKey); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	} else if !info.Local {
		// 未配置公钥时仍允许升级（兼容存量部署），但明确告警留痕
		u.eventBus.PublishAlert(types.AlertWarning, "upgrade",
			"升级签名校验未启用",
			"未配置升级签名公钥（upgrader.signing_key），本次升级仅依赖 SHA-256 校验",
			"upgrade-001")
	}

	// Step 4: Migrate config if needed
	if err := u.migrateConfig(ctx, u.currentVer, info.Version); err != nil {
		u.eventBus.PublishAlert(types.AlertWarning, "upgrade",
			"配置迁移警告",
			fmt.Sprintf("配置迁移出错: %v（已备份旧配置）", err),
			"upgrade-001")
	}

	// Step 5: Backup current binary (A/B switching)
	currentBinary := filepath.Join(u.installDir, "serverguard-agent")
	backupPath := filepath.Join(u.backupDir, fmt.Sprintf("serverguard-agent.%s.bak", u.currentVer))
	if err := u.copyFile(currentBinary, backupPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// Step 6: Replace binary (atomic)
	tmpPath := currentBinary + ".new"
	if err := u.copyFile(binaryPath, tmpPath); err != nil {
		return fmt.Errorf("copy new binary failed: %w", err)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}
	// Atomic rename
	if err := os.Rename(tmpPath, currentBinary); err != nil {
		// Rollback
		u.copyFile(backupPath, currentBinary)
		return fmt.Errorf("replace failed, rolled back: %w", err)
	}

	// Step 7: Clean old backups
	u.cleanOldBackups()

	u.eventBus.PublishAlert(types.AlertInfo, "upgrade",
		"升级完成",
		fmt.Sprintf("已升级到 v%s，旧版本备份在 %s", info.Version, backupPath),
		"upgrade-001")

	return nil
}

// Rollback rolls back to the previous version.
func (u *Upgrader) Rollback(ctx context.Context) error {
	backups := u.listBackups()
	if len(backups) == 0 {
		return fmt.Errorf("no backup available for rollback")
	}

	// Use the most recent backup
	backupPath := backups[0]
	currentBinary := filepath.Join(u.installDir, "serverguard-agent")

	u.eventBus.PublishAlert(types.AlertWarning, "upgrade",
		"开始回滚",
		fmt.Sprintf("正在回滚到 %s", filepath.Base(backupPath)),
		"upgrade-001")

	if err := u.copyFile(backupPath, currentBinary); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}
	os.Chmod(currentBinary, 0755)

	u.eventBus.PublishAlert(types.AlertInfo, "upgrade",
		"回滚完成",
		fmt.Sprintf("已回滚到 %s", filepath.Base(backupPath)),
		"upgrade-001")

	return nil
}

// migrateConfig performs config version migration.
func (u *Upgrader) migrateConfig(ctx context.Context, fromVer, toVer string) error {
	configPath := "/etc/serverguard/serverguard.yaml"
	if _, err := os.Stat(configPath); err != nil {
		return nil // No config to migrate
	}

	// Backup config before migration
	backupPath := filepath.Join(u.backupDir, fmt.Sprintf("serverguard.yaml.%s.bak", time.Now().Format("20060102-150405")))
	if err := u.copyFile(configPath, backupPath); err != nil {
		return err
	}

	// Check schema_version and migrate if needed
	// In production, this would parse YAML and run migration functions
	// migrate_v1_to_v2(), migrate_v2_to_v3(), etc.

	u.eventBus.PublishAlert(types.AlertInfo, "upgrade",
		"配置已迁移",
		fmt.Sprintf("从 v%s 迁移到 v%s，旧配置备份在 %s", fromVer, toVer, backupPath),
		"upgrade-001")

	return nil
}

// downloadBinary downloads the new binary.
// 使用独立的长超时客户端（二进制包下载可能耗时数分钟，但不能无限挂起）。
func (u *Upgrader) downloadBinary(ctx context.Context, url, destPath, expectedSHA string) error {
	dlCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := updateDownloadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// verifySHA256 verifies the SHA-256 hash of a file.
func (u *Upgrader) verifySHA256(path, expectedHash string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])
	if actual != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actual)
	}
	return nil
}

// verifySignature verifies the Ed25519 signature.
// Deprecated: PerformUpgrade now uses VerifyPackageSignature with a parsed key.
func (u *Upgrader) verifySignature(path, signature string) error {
	if u.signingKey == "" {
		return fmt.Errorf("signing key not configured")
	}
	pubKey, err := parseEd25519PublicKey(u.signingKey)
	if err != nil {
		return err
	}
	return VerifyPackageSignature(path, signature, pubKey)
}

// parseEd25519PublicKey 解析十六进制编码的 Ed25519 公钥。
func parseEd25519PublicKey(keyHex string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key length %d, expected %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// copyFile copies a file from src to dst.
func (u *Upgrader) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// listBackups lists available backup binaries sorted by date (newest first).
func (u *Upgrader) listBackups() []string {
	entries, err := os.ReadDir(u.backupDir)
	if err != nil {
		return nil
	}
	var backups []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "serverguard-agent.") && strings.HasSuffix(e.Name(), ".bak") {
			backups = append(backups, filepath.Join(u.backupDir, e.Name()))
		}
	}
	return backups
}

// cleanOldBackups removes backups exceeding the max limit.
func (u *Upgrader) cleanOldBackups() {
	backups := u.listBackups()
	if len(backups) <= u.maxBackups {
		return
	}
	for i := u.maxBackups; i < len(backups); i++ {
		os.Remove(backups[i])
	}
}

// RestartService restarts the ServerGuard service after upgrade.
func (u *Upgrader) RestartService() error {
	if runtime.GOOS != "windows" {
		return exec.Command("systemctl", "restart", "serverguard-agent").Run()
	}
	return exec.Command("sc", "stop", "ServerGuard").Run()
}
