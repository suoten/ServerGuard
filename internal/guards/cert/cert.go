package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/acme"
	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/baota"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// CertGuard implements Module L: Cert Guard (core differentiator)
// Covers: cert scanning, expiry alert levels, auto renewal (BaoTa API -> ACME -> alert),
// cert chain validation, enterprise cert calendar
type CertGuard struct {
	mu             sync.RWMutex
	eventBus       *eventbus.EventBus
	storage        *storage.Storage
	baota          *baota.Discovery
	scanPorts      []int
	alertDays      []int
	autoRenewDays  int
	renewCooldown  time.Duration
	preferredCAs   []string
	nginxReloadCmd string
	certCacheDir   string
	certs          []types.CertInfo
	lastScan       time.Time
	renewHistory   map[string]time.Time   // domain -> last renew attempt
	baotaSafeMode  bool                   // 宝塔兼容安全模式
	rateLimitMgr   *acme.RateLimitManager // ACME 限速管理器（错峰续期）
	renewalQueue   *RenewalFailureQueue   // 失败队列
	postRenewal    *PostRenewalHandler    // 续期后验证
}

// recordAudit 记录审计日志（WORM 不可篡改）
func (g *CertGuard) recordAudit(action, target, reason, result, details string) {
	if g.storage == nil {
		return
	}
	_ = g.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Actor:     "system",
		Action:    action,
		Target:    target,
		Reason:    reason,
		Result:    result,
		Details:   details,
	})
}

// recordAction 记录操作日志（显示在仪表盘"操作日志"中）
func (g *CertGuard) recordAction(actionType, target, message string, success bool, errMsg string) {
	if g.storage == nil {
		return
	}
	_ = g.storage.SaveAction("cert-guard", types.ActionResult{
		Action:    types.Action{Type: types.ActionType(actionType), Params: map[string]interface{}{"target": target}},
		Success:   success,
		Message:   message,
		Error:     errMsg,
		Timestamp: time.Now(),
	})
}

// SetBaotaSafeMode 启用或禁用宝塔兼容安全模式。
// 启用后，证书续期将仅通过宝塔API进行，跳过ACME直接操作和nginx reload。
func (g *CertGuard) SetBaotaSafeMode(enabled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.baotaSafeMode = enabled
}

// New creates a new CertGuard.
func New(bus *eventbus.EventBus, store *storage.Storage, bt *baota.Discovery) *CertGuard {
	return &CertGuard{
		eventBus:       bus,
		storage:        store,
		baota:          bt,
		scanPorts:      []int{443, 8443, 8001, 8888},
		alertDays:      []int{30, 14, 7, 3, 1},
		autoRenewDays:  14,
		renewCooldown:  1 * time.Hour,
		preferredCAs:   []string{"lets_encrypt", "zerossl", "trustasia", "buypass"},
		nginxReloadCmd: "nginx -s reload",
		certCacheDir:   "/var/lib/serverguard/certs",
		renewHistory:   make(map[string]time.Time),
		renewalQueue:   NewRenewalFailureQueue(bus),
		postRenewal:    NewPostRenewalHandler(bus),
	}
}

// SetConfig updates cert guard configuration.
func (g *CertGuard) SetConfig(scanPorts []int, alertDays []int, autoRenewDays int, preferredCAs []string, nginxReloadCmd, certCacheDir string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.scanPorts = scanPorts
	g.alertDays = alertDays
	g.autoRenewDays = autoRenewDays
	g.preferredCAs = preferredCAs
	g.nginxReloadCmd = nginxReloadCmd
	g.certCacheDir = certCacheDir
}

// Scan performs a full certificate scan.
func (g *CertGuard) Scan(ctx context.Context) ([]types.CertInfo, error) {
	var certs []types.CertInfo

	// L1: Scan HTTPS ports for certificates
	portCerts := g.scanPortsForCerts(ctx)
	certs = append(certs, portCerts...)

	// L1: Scan BaoTa managed certificates
	if g.baota != nil && g.baota.IsDetected() {
		baotaCerts := g.scanBaoTaCerts(ctx)
		certs = append(certs, baotaCerts...)
	}

	// L1: Scan Nginx/Apache config for cert paths
	configCerts := g.scanConfigCerts()
	certs = append(certs, configCerts...)

	// L4: Validate cert chains
	for i := range certs {
		g.validateCertChain(&certs[i])
	}

	// L5: Filter out entries with no meaningful domain
	filtered := certs[:0]
	for _, c := range certs {
		if c.Domain == "" || c.Domain == "-" {
			continue
		}
		filtered = append(filtered, c)
	}
	certs = filtered

	// L6: Deduplicate by domain+port
	seen := make(map[string]bool)
	deduped := certs[:0]
	for _, c := range certs {
		key := fmt.Sprintf("%s:%d", c.Domain, c.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, c)
	}
	certs = deduped

	g.mu.Lock()
	g.certs = certs
	g.lastScan = time.Now()
	g.mu.Unlock()

	// Save to storage
	for _, c := range certs {
		g.saveCertInfo(c)
	}

	return certs, nil
}

// scanPortsForCerts scans HTTPS ports and extracts certificate information.
func (g *CertGuard) scanPortsForCerts(ctx context.Context) []types.CertInfo {
	var certs []types.CertInfo

	g.mu.RLock()
	ports := make([]int, len(g.scanPorts))
	copy(ports, g.scanPorts)
	g.mu.RUnlock()

	// Also scan ports from BaoTa sites
	if g.baota != nil && g.baota.IsDetected() {
		for _, site := range g.baota.GetSites() {
			// Parse port from domain if present
			if strings.Contains(site.Domain, ":") {
				parts := strings.Split(site.Domain, ":")
				if len(parts) == 2 {
					var port int
					fmt.Sscanf(parts[1], "%d", &port)
					if port > 0 {
						ports = append(ports, port)
					}
				}
			}
		}
	}

	scannedPorts := make(map[int]bool)
	for _, port := range ports {
		if scannedPorts[port] {
			continue
		}
		scannedPorts[port] = true

		cert, err := g.getCertFromPort("127.0.0.1", port)
		if err != nil || cert == nil {
			continue
		}
		certs = append(certs, *cert)
	}

	return certs
}

// getCertFromPort connects to a port and retrieves the TLS certificate.
func (g *CertGuard) getCertFromPort(host string, port int) (*types.CertInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	cert := state.PeerCertificates[0]
	info := &types.CertInfo{
		Domain:             cert.Subject.CommonName,
		Port:               port,
		Issuer:             cert.Issuer.CommonName,
		Subject:            cert.Subject.CommonName,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		KeyAlgorithm:       keyAlgorithmString(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: sigAlgorithmString(cert.SignatureAlgorithm),
		SerialNumber:       cert.SerialNumber.String(),
		ChainComplete:      len(state.PeerCertificates) > 1,
	}

	// SANs
	for _, san := range cert.DNSNames {
		info.SANs = append(info.SANs, san)
	}

	// Calculate days until expiry
	info.DaysUntilExpiry = int(time.Until(info.NotAfter).Hours() / 24)

	return info, nil
}

// scanBaoTaCerts scans certificates managed by BaoTa panel.
func (g *CertGuard) scanBaoTaCerts(ctx context.Context) []types.CertInfo {
	var certs []types.CertInfo

	if g.baota == nil || !g.baota.IsDetected() {
		return certs
	}

	// Read cert files from BaoTa's cert directory
	certDir := "/www/server/panel/vhost/cert/"
	entries, err := os.ReadDir(certDir)
	if err != nil {
		// Try alternative path
		certDir = filepath.Join(g.baota.GetInstallPath(), "vhost/cert/")
		entries, err = os.ReadDir(certDir)
		if err != nil {
			return certs
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domain := entry.Name()

		// 跳过宝塔面板自身的默认证书目录（不是网站证书）
		if domain == "0.default" || strings.HasPrefix(domain, "0.default") {
			continue
		}

		certPath := filepath.Join(certDir, domain, "fullchain.pem")
		if _, err := os.Stat(certPath); err != nil {
			certPath = filepath.Join(certDir, domain, "cert.pem")
			if _, err := os.Stat(certPath); err != nil {
				continue
			}
		}

		info, err := g.parseCertFile(certPath, domain)
		if err != nil {
			continue
		}
		info.ManagedBy = "baota"
		certs = append(certs, *info)
	}

	return certs
}

// scanConfigCerts scans Nginx/Apache configs for certificate paths.
func (g *CertGuard) scanConfigCerts() []types.CertInfo {
	var certs []types.CertInfo

	configDirs := []string{
		"/etc/nginx/conf.d/",
		"/etc/nginx/sites-enabled/",
		"/www/server/panel/vhost/nginx/",
		"/etc/apache2/sites-enabled/",
		"/etc/httpd/conf.d/",
	}

	for _, dir := range configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			certPaths := g.parseCertPathsFromConfig(path)
			for _, certPath := range certPaths {
				info, err := g.parseCertFile(certPath, "")
				if err != nil {
					continue
				}
				certs = append(certs, *info)
			}
		}
	}

	return certs
}

// parseCertFile reads and parses a certificate file.
func (g *CertGuard) parseCertFile(path, domain string) (*types.CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse the certificate
	cert, err := parsePEMCertificate(data)
	if err != nil {
		return nil, err
	}

	info := &types.CertInfo{
		Domain:             domain,
		Issuer:             cert.Issuer.CommonName,
		Subject:            cert.Subject.CommonName,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		KeyAlgorithm:       keyAlgorithmString(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: sigAlgorithmString(cert.SignatureAlgorithm),
		SerialNumber:       cert.SerialNumber.String(),
		CertPath:           path,
	}

	if info.Domain == "" {
		info.Domain = cert.Subject.CommonName
	}

	for _, san := range cert.DNSNames {
		info.SANs = append(info.SANs, san)
	}

	info.DaysUntilExpiry = int(time.Until(info.NotAfter).Hours() / 24)

	return info, nil
}

// validateCertChain checks cert chain completeness and security.
func (g *CertGuard) validateCertChain(info *types.CertInfo) {
	// Check for weak algorithms
	if info.SignatureAlgorithm == "SHA1" || strings.Contains(info.SignatureAlgorithm, "SHA1") {
		g.eventBus.PublishAlert(types.AlertWarning, "cert",
			fmt.Sprintf("弱签名算法: %s", info.Domain),
			fmt.Sprintf("证书 %s 使用 SHA-1 签名算法，建议更换", info.Domain),
			"cert-chain-001")
	}

	// Check key length
	if strings.Contains(info.KeyAlgorithm, "RSA") {
		// Would need to check key size from cert
	}

	// Check chain completeness
	if !info.ChainComplete {
		g.eventBus.PublishAlert(types.AlertWarning, "cert",
			fmt.Sprintf("证书链不完整: %s", info.Domain),
			fmt.Sprintf("证书 %s 缺少中间证书，可能导致部分客户端无法验证", info.Domain),
			"cert-chain-001")
	}
}

// CheckExpiry checks certificate expiration and triggers alerts/renewal.
func (g *CertGuard) CheckExpiry(ctx context.Context) {
	g.mu.RLock()
	certs := g.certs
	alertDays := g.alertDays
	autoRenewDays := g.autoRenewDays
	g.mu.RUnlock()

	for _, cert := range certs {
		days := cert.DaysUntilExpiry

		// Check alert levels
		for _, alertDay := range alertDays {
			if days <= alertDay {
				level := g.getAlertLevel(days)
				g.eventBus.PublishAlert(level, "cert",
					fmt.Sprintf("证书到期: %s (剩余 %d 天)", cert.Domain, days),
					fmt.Sprintf("域名 %s 的 SSL 证书将在 %d 天后到期（颁发者: %s，端口: %d）",
						cert.Domain, days, cert.Issuer, cert.Port),
					"cert-expiring-001")
				break
			}
		}

		// Auto-renewal (including already expired certificates)
		if days <= autoRenewDays {
			g.attemptRenewal(ctx, cert)
		}
	}
}

// SetRateLimitManager 注入 ACME 限速管理器，启用错峰续期。
func (g *CertGuard) SetRateLimitManager(mgr *acme.RateLimitManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rateLimitMgr = mgr
}

// CheckExpiryWithStagger 错峰续期检查。
// 使用 GetStaggeredRenewalTime 将续期时间分散在过期前 8-14 天窗口内，
// 避免所有域名同时续期触发 ACME 速率限制。同时利用缓存跳过近期已检查的证书。
// 同时处理失败队列中的到期重试项。
func (g *CertGuard) CheckExpiryWithStagger(ctx context.Context) {
	// 先处理失败队列重试（ProcessRetry 返回到期域名，需要真正执行续期）
	g.mu.RLock()
	rq := g.renewalQueue
	g.mu.RUnlock()
	if rq != nil {
		for _, domain := range rq.ProcessRetry(ctx) {
			if err := g.RenewCertificate(ctx, domain); err == nil {
				rq.Remove(domain)
			}
		}
	}

	g.mu.RLock()
	certs := g.certs
	alertDays := g.alertDays
	autoRenewDays := g.autoRenewDays
	rateMgr := g.rateLimitMgr
	g.mu.RUnlock()

	now := time.Now()

	for i := range certs {
		cert := &certs[i]
		days := cert.DaysUntilExpiry

		// 缓存检查：CachedUntil 未过期则跳过
		if !cert.CachedUntil.IsZero() && now.Before(cert.CachedUntil) {
			continue
		}

		// 告警检查（与 CheckExpiry 相同）
		for _, alertDay := range alertDays {
			if days <= alertDay {
				level := g.getAlertLevel(days)
				g.eventBus.PublishAlert(level, "cert",
					fmt.Sprintf("证书到期: %s (剩余 %d 天)", cert.Domain, days),
					fmt.Sprintf("域名 %s 的 SSL 证书将在 %d 天后到期（颁发者: %s，端口: %d）",
						cert.Domain, days, cert.Issuer, cert.Port),
					"cert-expiring-001")
				break
			}
		}

		// 错峰续期判断
		shouldRenew := false
		if days <= 0 {
			shouldRenew = true
		} else if days <= autoRenewDays {
			if rateMgr != nil {
				staggeredTime := rateMgr.GetStaggeredRenewalTime(cert.Domain, cert.NotAfter)
				cert.StaggeredDeadline = staggeredTime
				if now.After(staggeredTime) || now.Equal(staggeredTime) {
					shouldRenew = true
				}
			} else {
				shouldRenew = true
			}
		}

		if shouldRenew {
			g.attemptRenewal(ctx, *cert)
			cert.CachedUntil = now.Add(1 * time.Hour)
		} else {
			if cert.CachedUntil.IsZero() || now.After(cert.CachedUntil) {
				cert.CachedUntil = now.Add(10 * time.Minute)
			}
		}
	}

	g.mu.Lock()
	g.certs = certs
	g.mu.Unlock()
}

// getAlertLevel returns the alert level based on days until expiry.
func (g *CertGuard) getAlertLevel(days int) types.AlertLevel {
	switch {
	case days <= 1:
		return types.AlertFatal
	case days <= 3:
		return types.AlertCritical
	case days <= 7:
		return types.AlertError
	case days <= 14:
		return types.AlertWarning
	default:
		return types.AlertInfo
	}
}

// RenewCertificate renews a certificate for the given domain.
// This is a public method used by the certificate calendar.
func (g *CertGuard) RenewCertificate(ctx context.Context, domain string) error {
	// Find the cert info for this domain
	var cert types.CertInfo
	g.mu.RLock()
	safeMode := g.baotaSafeMode
	for _, c := range g.certs {
		if c.Domain == domain {
			cert = c
			break
		}
	}
	g.mu.RUnlock()

	if cert.Domain == "" {
		// Cert not found, create a minimal info
		cert = types.CertInfo{
			Domain: domain,
		}
	}

	g.recordAudit("renew_cert", domain, "用户手动触发证书续期", "started", "")

	// Try renewal paths
	if g.baota != nil && g.baota.IsDetected() {
		if err := g.renewViaBaoTa(ctx, domain); err == nil {
			if !safeMode {
				g.reloadNginx(ctx)
			}
			g.clearRenewalFailure(domain)
			g.recordAudit("renew_cert", domain, "手动续期成功（宝塔API）", "success", "")
			g.recordAction("renew_cert", domain, fmt.Sprintf("手动续期成功(宝塔API): %s", domain), true, "")
			return nil
		}
	}

	// 宝塔安全模式下：如果宝塔 API 续期失败，回退到 ACME（ACME 不影响宝塔面板运行）
	if safeMode {
		if err := g.renewViaACME(ctx, domain); err == nil {
			g.clearRenewalFailure(domain)
			g.recordAudit("renew_cert", domain, "手动续期成功（ACME）", "success", "")
			g.recordAction("renew_cert", domain, fmt.Sprintf("手动续期成功(ACME): %s", domain), true, "")
			return nil
		} else {
			g.recordAudit("renew_cert", domain, fmt.Sprintf("手动续期失败: %v", err), "failed", "宝塔API和ACME均失败")
			g.recordAction("renew_cert", domain, fmt.Sprintf("手动续期失败: %s", domain), false, err.Error())
			return fmt.Errorf("宝塔API和ACME续期均失败，请通过宝塔面板手动续期 %s（宝塔→网站→SSL→重新申请）", domain)
		}
	}

	if err := g.renewViaACME(ctx, domain); err == nil {
		g.clearRenewalFailure(domain)
		g.recordAudit("renew_cert", domain, "手动续期成功（ACME）", "success", "")
		g.recordAction("renew_cert", domain, fmt.Sprintf("手动续期成功(ACME): %s", domain), true, "")
		return nil
	}

	g.recordAudit("renew_cert", domain, "手动续期失败（所有路径均失败）", "failed", "")
	g.recordAction("renew_cert", domain, fmt.Sprintf("手动续期失败: %s", domain), false, "all renewal paths failed")
	return fmt.Errorf("all renewal paths failed for %s", domain)
}

// attemptRenewal attempts to renew a certificate using the multi-path approach:
// Path 1: BaoTa API (doesn't consume ACME quota)
// Path 2: ACME (LE -> ZeroSSL -> TrustAsia) - skipped in Baota safe mode
// Path 3: Full alert with manual instructions
func (g *CertGuard) attemptRenewal(ctx context.Context, cert types.CertInfo) {
	g.mu.Lock()
	lastRenew, exists := g.renewHistory[cert.Domain]
	if exists && time.Since(lastRenew) < g.renewCooldown {
		g.mu.Unlock()
		return // Still in cooldown
	}
	g.renewHistory[cert.Domain] = time.Now()
	safeMode := g.baotaSafeMode
	g.mu.Unlock()

	// 站点存活性检查：如果端口未监听，站点可能已停止，跳过续期
	if cert.Port > 0 && !g.isSiteAlive(cert.Port) {
		g.eventBus.PublishAlert(types.AlertInfo, "cert",
			fmt.Sprintf("跳过续期（站点未运行）: %s", cert.Domain),
			fmt.Sprintf("证书 %s 的端口 %d 未监听，站点可能已停止，跳过自动续期。站点启动后会自动重试。", cert.Domain, cert.Port),
			"cert-renew-001")
		g.recordAudit("renew_cert", cert.Domain, "站点未运行，跳过自动续期", "skipped", fmt.Sprintf("端口 %d 未监听", cert.Port))
		return
	}

	g.eventBus.PublishAlert(types.AlertInfo, "cert",
		fmt.Sprintf("开始续期: %s", cert.Domain),
		fmt.Sprintf("证书 %s 剩余 %d 天，启动自动续期流程", cert.Domain, cert.DaysUntilExpiry),
		"cert-renew-001")
	g.recordAudit("renew_cert", cert.Domain, fmt.Sprintf("自动续期开始（剩余 %d 天）", cert.DaysUntilExpiry), "started", "")

	// Path 1: BaoTa API renewal (doesn't consume ACME quota)
	if g.baota != nil && g.baota.IsDetected() {
		err := g.renewViaBaoTa(ctx, cert.Domain)
		if err == nil {
			g.eventBus.PublishAlert(types.AlertInfo, "cert",
				fmt.Sprintf("续期成功: %s (宝塔API)", cert.Domain),
				fmt.Sprintf("通过宝塔API成功续期 %s 的证书", cert.Domain),
				"cert-renew-001")
			g.recordAudit("renew_cert", cert.Domain, "通过宝塔API自动续期成功", "success", "")
			g.recordAction("renew_cert", cert.Domain, fmt.Sprintf("宝塔API续期成功: %s", cert.Domain), true, "")
			// 宝塔API续期成功后，宝塔会自行reload nginx，无需额外reload
			if !safeMode {
				g.reloadNginx(ctx)
			}
			g.clearRenewalFailure(cert.Domain)
			return
		}
		g.eventBus.PublishAlert(types.AlertWarning, "cert",
			fmt.Sprintf("宝塔API续期失败: %s", cert.Domain),
			fmt.Sprintf("宝塔API续期失败: %v", err),
			"cert-renew-001")
		g.recordAudit("renew_cert", cert.Domain, fmt.Sprintf("宝塔API续期失败: %v", err), "failed", "尝试回退到ACME")
	}

	// 宝塔安全模式下：允许 ACME 续期（acme.sh --issue --nginx），
	// 但不执行额外的 nginx -s reload（acme.sh 内部会自己 reload nginx，
	// 这只影响 nginx 不影响宝塔面板进程）
	if safeMode {
		acmeErr := g.renewViaACME(ctx, cert.Domain)
		if acmeErr == nil {
			g.eventBus.PublishAlert(types.AlertInfo, "cert",
				fmt.Sprintf("续期成功: %s (ACME)", cert.Domain),
				fmt.Sprintf("通过ACME协议成功续期 %s 的证书。安全保护模式下不执行额外 nginx reload，acme.sh 已自行 reload。", cert.Domain),
				"cert-renew-001")
			g.recordAudit("renew_cert", cert.Domain, "通过ACME自动续期成功（安全保护模式）", "success", "")
			g.recordAction("renew_cert", cert.Domain, fmt.Sprintf("ACME续期成功: %s", cert.Domain), true, "")
			g.clearRenewalFailure(cert.Domain)
			return
		}
		// ACME 也失败了
		g.eventBus.PublishAlert(types.AlertCritical, "cert",
			fmt.Sprintf("[安全保护模式] 证书续期需手动处理: %s", cert.Domain),
			fmt.Sprintf("证书 %s 剩余 %d 天。宝塔API续期失败（可能API未开启），ACME续期也失败: %v。\n请通过宝塔面板→站点→SSL手动续期，或开启宝塔API。", cert.Domain, cert.DaysUntilExpiry, acmeErr),
			"cert-renew-001")
		g.recordAudit("renew_cert", cert.Domain, fmt.Sprintf("续期全部失败（剩余 %d 天）: %v", cert.DaysUntilExpiry, acmeErr), "failed", "宝塔API和ACME均失败，需手动处理")
		g.recordAction("renew_cert", cert.Domain, fmt.Sprintf("续期失败: %s", cert.Domain), false, acmeErr.Error())
		return
	}

	// Path 2: ACME renewal
	err := g.renewViaACME(ctx, cert.Domain)
	if err == nil {
		g.eventBus.PublishAlert(types.AlertInfo, "cert",
			fmt.Sprintf("续期成功: %s (ACME)", cert.Domain),
			fmt.Sprintf("通过ACME协议成功续期 %s 的证书", cert.Domain),
			"cert-renew-001")
		g.recordAudit("renew_cert", cert.Domain, "通过ACME自动续期成功", "success", "")
		g.recordAction("renew_cert", cert.Domain, fmt.Sprintf("ACME续期成功: %s", cert.Domain), true, "")
		// 续期后验证：reload + HTTPS 探测
		if g.postRenewal != nil {
			g.postRenewal.ReloadAndVerify(cert.Domain, cert.CertPath, cert.CertPath)
		} else {
			g.reloadNginx(ctx)
		}
		g.clearRenewalFailure(cert.Domain)
		return
	}

	// Path 3: Full alert with manual instructions + 入失败队列
	g.eventBus.PublishAlert(types.AlertCritical, "cert",
		fmt.Sprintf("续期失败: %s", cert.Domain),
		fmt.Sprintf("证书 %s 自动续期失败！请手动续期。ACME错误: %v。手动续期: 1.登录宝塔→站点→SSL→重新申请 2.或使用: acme.sh --issue -d %s --nginx", cert.Domain, err, cert.Domain),
		"cert-renew-001")
	g.recordAudit("renew_cert", cert.Domain, fmt.Sprintf("自动续期全部失败（剩余 %d 天）: %v", cert.DaysUntilExpiry, err), "failed", "已加入失败队列，稍后自动重试")
	g.recordAction("renew_cert", cert.Domain, fmt.Sprintf("续期失败: %s", cert.Domain), false, err.Error())
	// 入失败队列，稍后自动重试
	if g.renewalQueue != nil {
		g.renewalQueue.Enqueue(cert.Domain, "acme", []string{err.Error()})
	}
}

// isSiteAlive checks if a TCP port is listening (site is running).
// 用于判断站点是否在运行，站点停止时跳过证书续期。
func (g *CertGuard) isSiteAlive(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// renewViaBaoTa triggers certificate renewal through BaoTa API.
// 如果宝塔 API 未开启，返回错误，由调用方回退到 ACME 续期。
func (g *CertGuard) renewViaBaoTa(ctx context.Context, domain string) error {
	if g.baota == nil {
		return fmt.Errorf("baota not detected")
	}
	// 宝塔安全模式下：只走 HTTP API，不执行 python3/bt 命令
	if g.baotaSafeMode {
		return g.baota.RenewSSLViaAPI(ctx, domain)
	}
	return g.baota.RenewSSL(ctx, domain)
}

// clearRenewalFailure 续期成功后清理失败队列中的域名，避免已恢复的证书再触发"最终失败"告警。
func (g *CertGuard) clearRenewalFailure(domain string) {
	g.mu.RLock()
	rq := g.renewalQueue
	g.mu.RUnlock()
	if rq != nil {
		rq.Remove(domain)
	}
}

// renewViaACME attempts certificate renewal through ACME protocol with multi-CA fallback.
func (g *CertGuard) renewViaACME(ctx context.Context, domain string) error {
	// Try each CA in order
	for _, ca := range g.preferredCAs {
		err := g.tryACMEWithCA(ctx, domain, ca)
		if err == nil {
			return nil
		}
		// 单个 CA 失败是正常的降级过程，用 Warning 级别
		g.eventBus.PublishAlert(types.AlertWarning, "cert",
			fmt.Sprintf("ACME续期失败，尝试下一个CA: %s", ca),
			fmt.Sprintf("使用 %s 续期 %s 失败: %v", ca, domain, err),
			"cert-renew-001")
	}
	// 所有 CA 都失败，说明服务器缺少 ACME 客户端，用 Error 级别
	g.eventBus.PublishAlert(types.AlertError, "cert",
		fmt.Sprintf("证书续期全部失败: %s", domain),
		fmt.Sprintf("所有 CA 均续期失败，请安装 acme.sh 或 certbot，或通过宝塔面板手动续期。域名: %s", domain),
		"cert-renew-001")
	return fmt.Errorf("all CAs failed for %s", domain)
}

// tryACMEWithCA attempts ACME renewal with a specific CA.
func (g *CertGuard) tryACMEWithCA(ctx context.Context, domain, ca string) error {
	// Find acme.sh — check PATH first, then common BaoTa install locations
	acmeSh, err := exec.LookPath("acme.sh")
	if err != nil {
		// Check common BaoTa install locations
		acmePaths := []string{
			"/www/server/acme.sh/acme.sh",
			"/root/.acme.sh/acme.sh",
			os.ExpandEnv("$HOME/.acme.sh/acme.sh"),
			"/usr/local/acme.sh/acme.sh",
		}
		for _, p := range acmePaths {
			if _, statErr := os.Stat(p); statErr == nil {
				acmeSh = p
				err = nil
				break
			}
		}
	}

	if err == nil {
		// Use acme.sh via sh -c for better compatibility
		var acmeCmd string
		switch ca {
		case "lets_encrypt":
			acmeCmd = fmt.Sprintf("%s --issue -d %s --nginx --server letsencrypt", acmeSh, domain)
		case "zerossl":
			acmeCmd = fmt.Sprintf("%s --issue -d %s --nginx --server zerossl", acmeSh, domain)
		case "trustasia":
			acmeCmd = fmt.Sprintf("%s --issue -d %s --nginx --server trustasia", acmeSh, domain)
		case "buypass":
			acmeCmd = fmt.Sprintf("%s --issue -d %s --nginx --server buypass", acmeSh, domain)
		default:
			acmeCmd = fmt.Sprintf("%s --issue -d %s --nginx", acmeSh, domain)
		}
		cmd := exec.CommandContext(ctx, "sh", "-c", acmeCmd)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("acme.sh failed: %v, output: %s", err, string(output))
		}
		// Install the certificate to BaoTa's cert directory
		installCmdStr := fmt.Sprintf("%s --install-cert -d %s --key-file /www/server/panel/vhost/cert/%s/privkey.pem --fullchain-file /www/server/panel/vhost/cert/%s/fullchain.pem",
			acmeSh, domain, domain, domain)
		installCmd := exec.CommandContext(ctx, "sh", "-c", installCmdStr)
		if output, err := installCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("install cert failed: %v, output: %s", err, string(output))
		}
		return nil
	}

	// Try certbot if available
	certbot, err := exec.LookPath("certbot")
	if err == nil {
		cmd := exec.CommandContext(ctx, certbot, "renew", "--cert-name", domain, "--quiet")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("certbot renew failed: %v", err)
		}
		return nil
	}

	return fmt.Errorf("no ACME client found (tried acme.sh in PATH and /www/server/acme.sh, ~/.acme.sh; also tried certbot)")
}

// reloadNginx reloads Nginx to pick up new certificates.
func (g *CertGuard) reloadNginx(ctx context.Context) {
	g.mu.RLock()
	safeMode := g.baotaSafeMode
	cmdStr := g.nginxReloadCmd
	g.mu.RUnlock()

	// 宝塔安全模式下跳过nginx reload，由宝塔自行管理
	if safeMode {
		g.eventBus.PublishAlert(types.AlertInfo, "cert",
			"[安全保护模式] 跳过nginx reload",
			"安全保护模式下不直接reload nginx，请通过宝塔面板操作",
			"cert-renew-001")
		return
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		g.eventBus.PublishAlert(types.AlertWarning, "cert",
			"Nginx reload失败",
			fmt.Sprintf("nginx reload 失败: %v", err),
			"cert-renew-001")
	}
}

// parseCertPathsFromConfig extracts certificate paths from Nginx/Apache config.
func (g *CertGuard) parseCertPathsFromConfig(configPath string) []string {
	var certPaths []string

	data, err := os.ReadFile(configPath)
	if err != nil {
		return certPaths
	}
	content := string(data)

	// Look for ssl_certificate directives (Nginx)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssl_certificate") || strings.HasPrefix(line, "ssl_certificate_key") {
			// Extract path
			parts := strings.Fields(line)
			for _, part := range parts {
				part = strings.Trim(part, ";")
				if strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".crt") {
					if !strings.HasSuffix(part, ".key") {
						certPaths = append(certPaths, part)
					}
				}
			}
		}
	}

	return certPaths
}

// saveCertInfo saves certificate info to storage.
func (g *CertGuard) saveCertInfo(info types.CertInfo) {
	g.storage.Set(fmt.Sprintf("cert:%s:%d", info.Domain, info.Port), info.NotAfter.Format(time.RFC3339))
}

// GetCerts returns all scanned certificates.
func (g *CertGuard) GetCerts() []types.CertInfo {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.certs
}

// parsePEMCertificate parses a PEM-encoded certificate.
func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	// Try raw DER
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Try base64 decode then parse
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		return x509.ParseCertificate(decoded)
	}

	return nil, fmt.Errorf("failed to parse certificate: %w", err)
}

// keyAlgorithmString converts a public key algorithm to string.
func keyAlgorithmString(algo x509.PublicKeyAlgorithm) string {
	switch algo {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return algo.String()
	}
}

// sigAlgorithmString converts a signature algorithm to string.
func sigAlgorithmString(algo x509.SignatureAlgorithm) string {
	return algo.String()
}
