package baota

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver, no CGO required

	"github.com/suoten/serverguard/internal/types"
)

// Discovery implements the BaoTa API Dynamic Discovery Engine (§8.5a)
// Design: Don't hardcode API paths. Instead, dynamically detect BaoTa's presence,
// read its config, probe its API capabilities, and build a runtime adapter.
//
// 宝塔安全模式下：所有与宝塔面板交互的操作（bt 命令、API 请求、SQLite 数据库直读）
// 都会被跳过，只使用纯文件读取进行检测。这避免了与面板进程争抢资源导致面板崩溃。
type Discovery struct {
	mu            sync.RWMutex
	installPath   string
	port          string
	adminPath     string
	apiKey        string
	limitAddr     []string // API IP 白名单（空 = 未配置）
	version       string
	panelType     string // "baota_cn", "aapanel"
	panelURL      string // 含安全入口的面板访问地址（仅用于展示）
	apiBase       string // API 请求基础地址（不含安全入口，签名请求可绕过入口校验）
	apiEnabled    bool
	capabilities  map[string]bool
	sites         []types.BaoTaSite
	detected      bool
	baotaSafeMode bool // 宝塔安全模式：跳过所有与面板交互的操作
	httpClient    *http.Client
	renewClient   *http.Client // 续期专用：ACME 验证耗时长，需要更大超时
}

// New creates a new BaoTa discovery engine.
func New() *Discovery {
	// 面板 API 走 127.0.0.1 回环；面板 SSL 开启时是自签证书，必须跳过校验
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &Discovery{
		capabilities: make(map[string]bool),
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		renewClient: &http.Client{
			Timeout:   180 * time.Second, // ACME 验证（含 DNS 传播）可能需要 1-2 分钟
			Transport: transport,
		},
	}
}

// SetBaotaSafeMode sets the Baota safe mode flag.
// When enabled, all panel-interacting operations (bt commands, API requests,
// SQLite database access) are skipped to avoid interfering with the panel process.
func (d *Discovery) SetBaotaSafeMode(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.baotaSafeMode = enabled
}

// Detect performs the first step: Presence Detection
// Uses multiple signals (≥2 required) to confirm BaoTa is installed.
func (d *Discovery) Detect() bool {
	if runtime.GOOS == "windows" {
		return false // BaoTa is Linux-only
	}

	signals := 0

	// Signal 1: Installation directory
	if fi, err := os.Stat("/www/server/panel/"); err == nil && fi.IsDir() {
		signals++
		d.installPath = "/www/server/panel/"
	}

	// Signal 2: Data directory
	if fi, err := os.Stat("/www/server/panel/data/"); err == nil && fi.IsDir() {
		signals++
	}

	// Signal 3: Process detection (lightweight, no panel interaction)
	if output, err := exec.Command("pgrep", "-f", "bt").Output(); err == nil && len(output) > 0 {
		signals++
	}

	// Signal 4: CLI tool exists
	if _, err := exec.LookPath("bt"); err == nil {
		signals++
	}

	// 宝塔安全模式下：跳过 `bt default` 命令 — 该命令在宝塔 Python 环境中启动新进程，
	// 会与正在运行的面板进程争抢 SQLite 数据库锁和 Python 模块，导致面板进程崩溃。
	// 只在非安全模式下执行，用于获取面板 URL 等信息。
	if !d.baotaSafeMode {
		// Use `bt default` to get panel info
		if output, err := exec.Command("bt", "default").Output(); err == nil {
			d.parseBtDefault(string(output))
		}
	}

	// Signal 5: BaoTa database
	if fi, err := os.Stat("/www/server/panel/data/default.db"); err == nil && !fi.IsDir() {
		signals++
	}

	// Signal 6: Nginx vhost directory
	if fi, err := os.Stat("/www/server/panel/vhost/"); err == nil && fi.IsDir() {
		signals++
	}

	d.mu.Lock()
	d.detected = signals >= 2
	d.mu.Unlock()

	return d.detected
}

// LoadConfig performs the second step: Config Extraction
// Reads BaoTa's configuration files directly (no API needed).
func (d *Discovery) LoadConfig() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.installPath == "" {
		d.installPath = "/www/server/panel/"
	}

	// Read port
	if data, err := os.ReadFile(d.installPath + "data/port.pl"); err == nil {
		d.port = strings.TrimSpace(string(data))
	}

	// Read admin path (security entrance)
	if data, err := os.ReadFile(d.installPath + "data/admin_path.pl"); err == nil {
		d.adminPath = strings.TrimSpace(string(data))
	}

	// Read API config — 兼容新旧面板路径（data/api.json、config/api.json），
	// 字段类型容忍差异（limit_addr 可能是数组或逗号分隔字符串）。
	for _, p := range []string{
		d.installPath + "data/api.json",
		d.installPath + "config/api.json",
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			continue
		}
		if open, ok := raw["open"].(bool); ok {
			d.apiEnabled = open
		}
		if key, ok := raw["key"].(string); ok {
			d.apiKey = key
		}
		switch v := raw["limit_addr"].(type) {
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					d.limitAddr = append(d.limitAddr, s)
				}
			}
		case string:
			if v != "" {
				d.limitAddr = strings.Split(v, ",")
			}
		}
		break
	}

	// Detect version
	d.detectVersion()

	// Detect panel type (BaoTa CN vs aaPanel)
	d.detectPanelType()

	// 面板 SSL 开启后（data/ssl.pl 存在），端口只接受 HTTPS
	scheme := "http"
	if _, err := os.Stat(d.installPath + "data/ssl.pl"); err == nil {
		scheme = "https"
	}

	// Construct panel URL（含安全入口，仅用于展示给用户）
	if d.port != "" {
		d.panelURL = fmt.Sprintf("%s://127.0.0.1:%s%s", scheme, d.port, d.adminPath)
		// API 基础地址不含安全入口：带正确签名的 API 请求由面板 check_api 前置处理，
		// 拼上入口路径反而会路由不到 /site、/acme 等模块（404）。
		d.apiBase = fmt.Sprintf("%s://127.0.0.1:%s", scheme, d.port)
	}

	// Load sites from SQLite database
	d.loadSitesFromDB()

	return nil
}

// ProbeCapabilities performs the third step: API Capability Probing
// Tests known API endpoints to determine what's available.
// 只探测只读端点 — 绝不探测 SetSSL 等写接口（参数缺失可能破坏站点配置）。
func (d *Discovery) ProbeCapabilities() {
	d.mu.RLock()
	enabled := d.apiEnabled
	key := d.apiKey
	d.mu.RUnlock()

	if !enabled || key == "" {
		// API not enabled, all capabilities are false
		// But site list and cert paths are still available from file system
		return
	}

	// 只读探测端点（action 放在 query 或表单中面板都支持）
	candidates := []struct {
		Name string
		Path string
		Form url.Values
	}{
		{"system_info", "/system?action=GetSystemTotal", nil},
		{"site_list", "/data?action=getData", url.Values{"table": {"sites"}, "limit": {"1"}}},
		{"ssl_info", "/ssl?action=GetCertList", nil},
		{"ssl_renew", "/acme?action=get_orders", nil}, // /acme 模块存在 = 可走官方续签链路
		{"crontab", "/crontab?action=GetCrontab", nil},
	}

	for _, ep := range candidates {
		_, status, err := d.apiPost(context.Background(), d.httpClient, ep.Path, ep.Form)
		if err == nil && status == 200 {
			d.mu.Lock()
			d.capabilities[ep.Name] = true
			d.mu.Unlock()
		}
	}

	// ssl_deploy 不直接探测（写接口），/acme 可用即认为可部署（SetCertToSite）
	d.mu.Lock()
	d.capabilities["ssl_deploy"] = d.capabilities["ssl_renew"]
	d.mu.Unlock()
}

// IsDetected returns whether BaoTa was detected.
func (d *Discovery) IsDetected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected
}

// GetInstallPath returns the BaoTa installation path.
func (d *Discovery) GetInstallPath() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.installPath
}

// HasCapability checks if a specific API capability is available.
func (d *Discovery) HasCapability(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.capabilities[name]
}

// GetSites returns the list of BaoTa-managed sites.
func (d *Discovery) GetSites() []types.BaoTaSite {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.siteList()
}

// GetCapabilityMap returns the full capability map as JSON-serializable data.
func (d *Discovery) GetCapabilityMap() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	caps := make(map[string]bool)
	for k, v := range d.capabilities {
		caps[k] = v
	}

	return map[string]interface{}{
		"baota_detected": d.detected,
		"version":        d.version,
		"panel_type":     d.panelType,
		"panel_url":      d.panelURL,
		"api_enabled":    d.apiEnabled,
		"capabilities":   caps,
		"sites_from_db":  d.sites,
	}
}

// RenewSSL triggers SSL certificate renewal through BaoTa API.
// API 未开启时返回错误，由调用方（cert guard）回退到 ACME 续期。
// 不再回退到 python3/bt CLI — 在运行中的面板环境里导入面板模块会与面板进程
// 争抢 SQLite 锁和 Python 模块，可能导致面板崩溃（安全模式的设计初衷）。
func (d *Discovery) RenewSSL(ctx context.Context, domain string) error {
	return d.RenewSSLViaAPI(ctx, domain)
}

// RenewSSLViaAPI 仅通过宝塔 API（HTTP 请求）续期，不回退到 CLI。
// 宝塔安全模式下使用此方法 — HTTP 请求不会与面板进程争抢资源。
// 如果 API 未开启，直接返回错误，不执行 python3 或 bt 命令。
func (d *Discovery) RenewSSLViaAPI(ctx context.Context, domain string) error {
	d.mu.RLock()
	key := d.apiKey
	enabled := d.apiEnabled
	base := d.apiBase
	d.mu.RUnlock()

	if !enabled || key == "" {
		return fmt.Errorf("宝塔 API 未开启，无法通过 API 续期。请在 宝塔面板 → 设置 → API接口 中开启，并将 127.0.0.1 加入 IP 白名单")
	}
	if base == "" {
		return fmt.Errorf("宝塔面板端口未知，无法构造 API 地址")
	}

	return d.renewSSLViaAPI(ctx, domain)
}

// renewSSLViaAPI 通过宝塔官方 API 续期免费 SSL 证书（纯 HTTP 请求，安全）。
//
// 续签链路（官方文档 docs.bt.cn/api/acme）：
//  1. /acme?action=get_orders  找到域名对应的订单 index
//  2. /acme?action=renew_cert&index=xxx  续签（面板自动完成 ACME 验证）
//  3. 校验站点证书文件确实更新；未更新则用 /acme?action=SetCertToSite 重新部署
//
// 旧版面板（无 /acme 模块）回退到 /site?action=RenewLet。
func (d *Discovery) renewSSLViaAPI(ctx context.Context, domain string) error {
	if err := d.checkAPIWhitelist(); err != nil {
		return err
	}

	siteName := d.findSiteName(domain)

	// 幂等前置检查：证书剩余 >30 天说明面板计划任务已续期，无需调用 API
	if days, err := d.certDaysLeft(siteName); err == nil && days > 30 {
		return nil
	}

	var acmeErr error

	// 路径 A：官方 ACME 订单续签（宝塔 v8+/v11）
	index, err := d.findACMEOrderIndex(ctx, domain)
	if err == nil && index != "" {
		if renewErr := d.acmeRenewCert(ctx, index); renewErr != nil {
			acmeErr = renewErr
		} else if d.certRenewed(siteName) {
			return nil
		} else {
			// 续签成功但站点证书未更新 → 重新部署到站点后再校验
			if deployErr := d.acmeDeployToSite(ctx, index, siteName); deployErr == nil && d.certRenewed(siteName) {
				return nil
			}
			acmeErr = fmt.Errorf("续签请求成功但站点证书未更新")
		}
	} else if err != nil {
		acmeErr = err
	}

	// 路径 B：旧版站点级续签（宝塔 7.x，/site?action=RenewLet）
	if legacyErr := d.legacyRenewLet(ctx, siteName); legacyErr == nil {
		if d.certRenewed(siteName) {
			return nil
		}
		return fmt.Errorf("宝塔续签接口返回成功，但站点证书文件未更新，请在宝塔面板检查 %s 的 SSL 配置", siteName)
	} else if acmeErr != nil {
		return fmt.Errorf("宝塔续期失败: ACME订单续签: %v; 旧版续签: %v", acmeErr, legacyErr)
	} else {
		return fmt.Errorf("宝塔续期失败: %v", legacyErr)
	}
}

// checkAPIWhitelist 预检 API IP 白名单：白名单非空且不含回环地址时给出可操作的错误提示。
func (d *Discovery) checkAPIWhitelist() error {
	d.mu.RLock()
	addrs := d.limitAddr
	d.mu.RUnlock()

	if len(addrs) == 0 {
		return nil
	}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "127.0.0.1" || a == "localhost" || a == "::1" || a == "*" {
			return nil
		}
	}
	return fmt.Errorf("宝塔 API IP 白名单未包含 127.0.0.1（当前白名单: %s），请在 宝塔面板 → 设置 → API接口 中添加 127.0.0.1", strings.Join(addrs, ","))
}

// findSiteName 根据域名找宝塔站点名（证书目录名 = 站点名）。
func (d *Discovery) findSiteName(domain string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, s := range d.sites {
		if s.Name == domain || s.Domain == domain {
			return s.Name
		}
	}
	for _, s := range d.sites {
		if strings.Contains(s.Domain, domain) {
			return s.Name
		}
	}
	return domain
}

// findACMEOrderIndex 在宝塔 ACME 订单中查找域名对应的订单 index。
// 面板无 /acme 模块（旧版）时返回错误。
func (d *Discovery) findACMEOrderIndex(ctx context.Context, domain string) (string, error) {
	body, status, err := d.apiPost(ctx, d.httpClient, "/acme?action=get_orders", nil)
	if err != nil {
		return "", err
	}
	if status == 404 {
		return "", fmt.Errorf("面板无 /acme 模块（旧版面板）")
	}
	if status != 200 {
		return "", fmt.Errorf("get_orders 返回状态 %d", status)
	}

	var orders []struct {
		Index   string   `json:"index"`
		Domains []string `json:"domains"`
	}
	if err := json.Unmarshal(body, &orders); err != nil {
		return "", fmt.Errorf("get_orders 响应解析失败: %w", err)
	}

	for _, o := range orders {
		for _, d := range o.Domains {
			if d == domain || strings.TrimPrefix(d, "*.") == domain {
				return o.Index, nil
			}
		}
	}
	return "", fmt.Errorf("未找到域名 %s 的 ACME 订单（证书可能不是通过宝塔申请的）", domain)
}

// acmeRenewCert 调用 /acme?action=renew_cert 续签订单。
func (d *Discovery) acmeRenewCert(ctx context.Context, index string) error {
	form := url.Values{"index": {index}}
	body, status, err := d.apiPost(ctx, d.renewClient, "/acme?action=renew_cert", form)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("renew_cert 返回状态 %d", status)
	}
	return parseBtStatus(body)
}

// acmeDeployToSite 调用 /acme?action=SetCertToSite 把订单证书部署到站点。
func (d *Discovery) acmeDeployToSite(ctx context.Context, index, siteName string) error {
	form := url.Values{"index": {index}, "siteName": {siteName}}
	body, status, err := d.apiPost(ctx, d.renewClient, "/acme?action=SetCertToSite", form)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("SetCertToSite 返回状态 %d", status)
	}
	return parseBtStatus(body)
}

// legacyRenewLet 调用旧版 /site?action=RenewLet 续签站点 Let's Encrypt 证书。
func (d *Discovery) legacyRenewLet(ctx context.Context, siteName string) error {
	form := url.Values{"siteName": {siteName}}
	body, status, err := d.apiPost(ctx, d.renewClient, "/site?action=RenewLet", form)
	if err != nil {
		return err
	}
	if status == 404 {
		return fmt.Errorf("面板不支持 RenewLet 接口")
	}
	if status != 200 {
		return fmt.Errorf("RenewLet 返回状态 %d", status)
	}
	return parseBtStatus(body)
}

// certDaysLeft 读取站点证书文件，返回剩余天数。
func (d *Discovery) certDaysLeft(siteName string) (int, error) {
	d.mu.RLock()
	installPath := d.installPath
	d.mu.RUnlock()

	certDir := filepath.Join(installPath, "vhost/cert", siteName)
	data, err := os.ReadFile(filepath.Join(certDir, "fullchain.pem"))
	if err != nil {
		data, err = os.ReadFile(filepath.Join(certDir, "cert.pem"))
		if err != nil {
			return 0, err
		}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, fmt.Errorf("证书文件无 PEM 数据")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, err
	}
	return int(time.Until(cert.NotAfter).Hours() / 24), nil
}

// certRenewed 校验站点证书已更新（剩余 >30 天视为续期成功，免费证书有效期 90 天）。
func (d *Discovery) certRenewed(siteName string) bool {
	days, err := d.certDaysLeft(siteName)
	return err == nil && days > 30
}

// btStatusResponse 宝塔 API 通用状态响应。
type btStatusResponse struct {
	Status bool   `json:"status"`
	Msg    string `json:"msg"`
}

// parseBtStatus 解析宝塔 {"status":bool,"msg":...} 响应，status=false 时返回带 msg 的错误。
func parseBtStatus(body []byte) error {
	var r btStatusResponse
	if err := json.Unmarshal(body, &r); err != nil {
		s := string(body)
		if len(s) > 200 {
			s = s[:200]
		}
		return fmt.Errorf("宝塔返回了无法解析的响应: %s", s)
	}
	if !r.Status {
		return fmt.Errorf("宝塔 API 错误: %s", r.Msg)
	}
	return nil
}

// apiPost 发送带宝塔官方签名（request_time + request_token）的 POST 表单请求。
// request_token = md5(request_time + md5(api_key))，见 docs.bt.cn/api。
func (d *Discovery) apiPost(ctx context.Context, client *http.Client, path string, form url.Values) ([]byte, int, error) {
	d.mu.RLock()
	base := d.apiBase
	key := d.apiKey
	d.mu.RUnlock()

	if base == "" || key == "" {
		return nil, 0, fmt.Errorf("宝塔 API 配置不完整（缺少地址或密钥）")
	}
	if form == nil {
		form = url.Values{}
	}
	requestTime := strconv.FormatInt(time.Now().Unix(), 10)
	form.Set("request_time", requestTime)
	form.Set("request_token", md5Hex(requestTime+md5Hex(key)))

	req, err := http.NewRequestWithContext(ctx, "POST", base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// md5Hex 返回字符串的 MD5 十六进制摘要。
func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// parseBtDefault parses the output of `bt default` command.
func (d *Discovery) parseBtDefault(output string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "port") {
			// Extract port number
			parts := strings.Fields(line)
			for _, part := range parts {
				if port := strings.TrimRight(part, ","); port != "" {
					if _, err := fmt.Sscanf(port, "%s", &d.port); err == nil && d.port != "" {
						break
					}
				}
			}
		}
		if strings.Contains(line, "面板地址") || strings.Contains(line, "panel address") {
			// Extract URL
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "http") {
					d.panelURL = part
					break
				}
			}
		}
	}
}

// detectVersion detects the BaoTa panel version.
func (d *Discovery) detectVersion() {
	// 宝塔安全模式下：优先从 version.pl 读取版本（纯文件读取，不启动任何进程）
	if d.baotaSafeMode {
		if data, err := os.ReadFile(d.installPath + "version.pl"); err == nil {
			v := strings.TrimSpace(string(data))
			if v != "" {
				d.version = v
				return
			}
		}
		// 回退到 common.py（也是纯文件读取）
		if data, err := os.ReadFile(d.installPath + "class/common.py"); err == nil {
			content := string(data)
			if idx := strings.Index(content, "version"); idx >= 0 {
				rest := content[idx:]
				if colon := strings.Index(rest, "'"); colon >= 0 {
					end := strings.Index(rest[colon+1:], "'")
					if end >= 0 {
						d.version = rest[colon+1 : colon+1+end]
					}
				}
			}
		}
		if d.version == "" {
			d.version = "unknown"
		}
		return // 宝塔安全模式：不执行 bt 14 命令
	}

	// 非安全模式：原有逻辑
	// Try reading from common.php
	if data, err := os.ReadFile(d.installPath + "class/common.php"); err == nil {
		content := string(data)
		// Look for version string
		if idx := strings.Index(content, "version"); idx >= 0 {
			// Extract version from nearby content
			rest := content[idx:]
			if colon := strings.Index(rest, "'"); colon >= 0 {
				end := strings.Index(rest[colon+1:], "'")
				if end >= 0 {
					d.version = rest[colon+1 : colon+1+end]
				}
			}
		}
	}

	// Try `bt 14` command
	if d.version == "" {
		if output, err := exec.Command("bt", "14").Output(); err == nil {
			d.version = strings.TrimSpace(string(output))
		}
	}

	// Fallback
	if d.version == "" {
		d.version = "unknown"
	}
}

// detectPanelType detects whether it's BaoTa CN or aaPanel (international).
func (d *Discovery) detectPanelType() {
	// Check for aaPanel indicator
	if _, err := os.Stat(d.installPath + "config/config.json"); err == nil {
		if data, err := os.ReadFile(d.installPath + "config/config.json"); err == nil {
			content := string(data)
			if strings.Contains(content, "aaPanel") || strings.Contains(content, "aapanel") {
				d.panelType = "aapanel"
				return
			}
		}
	}

	// Check for language files
	if _, err := os.Stat(d.installPath + "language/English/"); err == nil {
		d.panelType = "aapanel"
		return
	}

	d.panelType = "baota_cn"
}

// loadSitesFromDB loads the site list from BaoTa's SQLite database.
// 宝塔安全模式下：跳过数据库直读 — SQLite 文件级锁会与面板进程争抢，
// 可能导致面板写入失败或崩溃。站点列表通过 /www/server/panel/vhost/ 目录推断。
func (d *Discovery) loadSitesFromDB() {
	// 宝塔安全模式下：跳过数据库直读
	if d.baotaSafeMode {
		d.loadSitesFromFilesystem()
		return
	}

	dbPath := d.installPath + "data/default.db"
	db, err := sql.Open("sqlite", dbPath+"?_pragma=query_only(1)")
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT name, path FROM sites")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, path string
		if err := rows.Scan(&name, &path); err != nil {
			continue
		}
		site := types.BaoTaSite{
			Name:   name,
			Domain: name,
		}
		// Check for SSL cert directory
		certDir := filepath.Join(d.installPath, "vhost/cert", name)
		if fi, err := os.Stat(certDir); err == nil && fi.IsDir() {
			site.CertPath = certDir
		}
		d.sites = append(d.sites, site)
	}
}

// loadSitesFromFilesystem infers the site list from the Nginx vhost directory.
// This is a fallback for Baota safe mode — doesn't open the SQLite database,
// only reads directory names from /www/server/panel/vhost/cert/ and /www/server/panel/vhost/nginx/
func (d *Discovery) loadSitesFromFilesystem() {
	vhostDir := filepath.Join(d.installPath, "vhost/nginx")
	entries, err := os.ReadDir(vhostDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Nginx vhost files are named like "domain.conf"
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		domain := strings.TrimSuffix(name, ".conf")
		if domain == "" || domain == "default" {
			continue
		}
		site := types.BaoTaSite{
			Name:   domain,
			Domain: domain,
		}
		// Check for SSL cert directory
		certDir := filepath.Join(d.installPath, "vhost/cert", domain)
		if fi, err := os.Stat(certDir); err == nil && fi.IsDir() {
			site.CertPath = certDir
		}
		d.sites = append(d.sites, site)
	}
}

// siteList returns a copy of the sites list.
func (d *Discovery) siteList() []types.BaoTaSite {
	sites := make([]types.BaoTaSite, len(d.sites))
	copy(sites, d.sites)
	return sites
}

// Rescan performs a full re-discovery (step 5: Re-discovery).
func (d *Discovery) Rescan() {
	d.Detect()
	if d.detected {
		d.LoadConfig()
		d.ProbeCapabilities()
	}
}

// TestAPI tests the BaoTa API connectivity.
func (d *Discovery) TestAPI(ctx context.Context) error {
	d.mu.RLock()
	base := d.apiBase
	key := d.apiKey
	enabled := d.apiEnabled
	d.mu.RUnlock()

	if !enabled {
		return fmt.Errorf("baota API is not enabled")
	}
	if key == "" {
		return fmt.Errorf("baota API key is missing")
	}
	if base == "" {
		return fmt.Errorf("baota panel URL is unknown")
	}

	// 签名 POST 请求系统信息接口验证连通性与密钥正确性
	body, status, err := d.apiPost(ctx, d.httpClient, "/system?action=GetSystemTotal", nil)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("API returned status %d", status)
	}

	// 密钥错误/IP 不在白名单时面板返回 {"status":false,"msg":"..."}
	var r btStatusResponse
	if err := json.Unmarshal(body, &r); err == nil && !r.Status && r.Msg != "" {
		return fmt.Errorf("API rejected request: %s", r.Msg)
	}

	return nil
}

// Version returns the detected BaoTa version.
func (d *Discovery) Version() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.version
}

// PanelType returns the detected panel type.
func (d *Discovery) PanelType() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.panelType
}

// FullScan performs the complete discovery sequence.
func (d *Discovery) FullScan() {
	d.Detect()
	if d.detected {
		d.LoadConfig()
		d.ProbeCapabilities()
	}
}

// ToJSON serializes the discovery state to JSON.
func (d *Discovery) ToJSON() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	caps := make(map[string]bool)
	for k, v := range d.capabilities {
		caps[k] = v
	}

	return json.Marshal(map[string]interface{}{
		"detected":     d.detected,
		"install_path": d.installPath,
		"version":      d.version,
		"panel_type":   d.panelType,
		"panel_url":    d.panelURL,
		"port":         d.port,
		"admin_path":   d.adminPath,
		"api_enabled":  d.apiEnabled,
		"capabilities": caps,
		"sites":        d.sites,
	})
}
