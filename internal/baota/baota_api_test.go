package baota

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

const testAPIKey = "testkey123"

// writeTestCert 在指定目录生成有效期 days 天的测试证书 fullchain.pem。
func writeTestCert(t *testing.T, dir string, days int) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), pemData, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

// mockPanel 模拟宝塔面板 API：校验官方签名，按 action 分发响应。
type mockPanel struct {
	mu        sync.Mutex
	calls     []string // 记录收到的 action
	orders    string   // get_orders 响应体
	orders404 bool     // 模拟旧版面板无 /acme 模块
	onDeploy  func()   // SetCertToSite 被调用时触发（模拟面板部署证书）
}

func (m *mockPanel) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}

		// 校验宝塔官方签名：request_token = md5(request_time + md5(api_key))
		reqTime := r.Form.Get("request_time")
		reqToken := r.Form.Get("request_token")
		if reqTime == "" || reqToken != md5Hex(reqTime+md5Hex(testAPIKey)) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": false, "msg": "API密钥校验失败"})
			return
		}

		action := r.URL.Query().Get("action")
		if action == "" {
			action = r.Form.Get("action")
		}
		m.mu.Lock()
		m.calls = append(m.calls, action)
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "get_orders":
			if m.orders404 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write([]byte(m.orders))
		case "renew_cert":
			if r.Form.Get("index") == "" {
				json.NewEncoder(w).Encode(map[string]interface{}{"status": false, "msg": "缺少index参数"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": true, "msg": "续签成功!"})
		case "SetCertToSite":
			if m.onDeploy != nil {
				m.onDeploy()
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": true, "msg": "SSL开启成功!"})
		case "RenewLet":
			if m.orders404 {
				json.NewEncoder(w).Encode(map[string]interface{}{"status": true, "msg": "续签成功"})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (m *mockPanel) hasCall(action string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.calls {
		if c == action {
			return true
		}
	}
	return false
}

// newTestDiscovery 构造连接 mock 面板的 Discovery。
func newTestDiscovery(t *testing.T, panel *mockPanel) (*Discovery, func()) {
	t.Helper()
	server := httptest.NewServer(panel.handler(t))
	installPath := t.TempDir()

	d := New()
	d.apiEnabled = true
	d.apiKey = testAPIKey
	d.apiBase = server.URL
	d.installPath = installPath
	d.sites = []types.BaoTaSite{{Name: "example.com", Domain: "example.com"}}
	return d, server.Close
}

// TestAPIPostSignature 验证签名参数格式与算法。
func TestAPIPostSignature(t *testing.T) {
	var gotTime, gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotTime = r.Form.Get("request_time")
		gotToken = r.Form.Get("request_token")
		w.Write([]byte(`{"status":true}`))
	}))
	defer server.Close()

	d := New()
	d.apiKey = testAPIKey
	d.apiBase = server.URL

	_, status, err := d.apiPost(context.Background(), d.httpClient, "/system?action=GetSystemTotal", nil)
	if err != nil || status != 200 {
		t.Fatalf("apiPost failed: status=%d err=%v", status, err)
	}
	if gotTime == "" {
		t.Fatal("request_time missing")
	}
	want := md5Hex(gotTime + md5Hex(testAPIKey))
	if gotToken != want {
		t.Fatalf("request_token = %s, want %s", gotToken, want)
	}
	if ct := "application/x-www-form-urlencoded"; !strings.Contains("application/x-www-form-urlencoded", ct) {
		t.Fatalf("unexpected content type")
	}
}

// TestRenewSSL_ACMEOrderFlow 验证主链路：get_orders → renew_cert → 证书文件校验。
func TestRenewSSL_ACMEOrderFlow(t *testing.T) {
	panel := &mockPanel{
		orders: `[{"index":"abc123","domains":["example.com"],"status":"valid"}]`,
	}
	d, cleanup := newTestDiscovery(t, panel)
	defer cleanup()

	// 证书文件已是新证书（90 天），模拟面板续签后落盘
	certDir := filepath.Join(d.installPath, "vhost/cert", "example.com")
	writeTestCert(t, certDir, 10) // 先放 10 天旧证书，确保前置检查不短路
	writeTestCert(t, certDir, 10)

	// renew_cert 成功后面板会更新证书文件，这里用 SetCertToSite 钩子模拟
	panel.onDeploy = func() { writeTestCert(t, certDir, 89) }

	// 情况1: 证书 10 天 → 触发续签，renew_cert 成功但文件未更新 → SetCertToSite 部署后校验通过
	if err := d.RenewSSLViaAPI(context.Background(), "example.com"); err != nil {
		t.Fatalf("RenewSSLViaAPI failed: %v", err)
	}
	if !panel.hasCall("get_orders") || !panel.hasCall("renew_cert") {
		t.Fatalf("expected get_orders + renew_cert calls, got %v", panel.calls)
	}
	if !panel.hasCall("SetCertToSite") {
		t.Fatalf("expected SetCertToSite deploy after stale cert file, got %v", panel.calls)
	}
}

// TestRenewSSL_IdempotentWhenFresh 证书剩余 >30 天时不调用任何续签接口。
func TestRenewSSL_IdempotentWhenFresh(t *testing.T) {
	panel := &mockPanel{orders: `[]`}
	d, cleanup := newTestDiscovery(t, panel)
	defer cleanup()

	writeTestCert(t, filepath.Join(d.installPath, "vhost/cert", "example.com"), 80)

	if err := d.RenewSSLViaAPI(context.Background(), "example.com"); err != nil {
		t.Fatalf("expected nil for fresh cert, got %v", err)
	}
	if len(panel.calls) != 0 {
		t.Fatalf("expected no API calls for fresh cert, got %v", panel.calls)
	}
}

// TestRenewSSL_LegacyFallback 旧版面板无 /acme 时回退 /site?action=RenewLet。
func TestRenewSSL_LegacyFallback(t *testing.T) {
	panel := &mockPanel{orders404: true}
	d, cleanup := newTestDiscovery(t, panel)
	defer cleanup()

	// 旧证书 10 天；RenewLet 成功后证书仍 10 天 → 应报错提示未更新
	certDir := filepath.Join(d.installPath, "vhost/cert", "example.com")
	writeTestCert(t, certDir, 10)

	err := d.RenewSSLViaAPI(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error when cert file not updated after RenewLet")
	}
	if !panel.hasCall("RenewLet") {
		t.Fatalf("expected RenewLet fallback call, got %v", panel.calls)
	}
	if !strings.Contains(err.Error(), "未更新") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRenewSSL_APIDisabled API 未开启时返回明确指引。
func TestRenewSSL_APIDisabled(t *testing.T) {
	d := New()
	err := d.RenewSSLViaAPI(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "API 未开启") {
		t.Fatalf("expected API disabled error, got %v", err)
	}
}

// TestCheckAPIWhitelist 白名单不含回环地址时给出可操作错误。
func TestCheckAPIWhitelist(t *testing.T) {
	d := New()
	d.limitAddr = []string{"1.2.3.4"}
	if err := d.checkAPIWhitelist(); err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("expected whitelist error, got %v", err)
	}

	d.limitAddr = []string{"1.2.3.4", "127.0.0.1"}
	if err := d.checkAPIWhitelist(); err != nil {
		t.Fatalf("expected pass with loopback whitelisted, got %v", err)
	}

	d.limitAddr = nil
	if err := d.checkAPIWhitelist(); err != nil {
		t.Fatalf("expected pass with empty whitelist, got %v", err)
	}
}

// TestFindACMEOrderIndex 订单匹配：精确域名与泛域名。
func TestFindACMEOrderIndex(t *testing.T) {
	panel := &mockPanel{
		orders: `[{"index":"wild1","domains":["*.example.com"]},{"index":"other2","domains":["foo.bar"]}]`,
	}
	d, cleanup := newTestDiscovery(t, panel)
	defer cleanup()

	idx, err := d.findACMEOrderIndex(context.Background(), "example.com")
	if err != nil || idx != "wild1" {
		t.Fatalf("wildcard match: idx=%q err=%v", idx, err)
	}

	if _, err := d.findACMEOrderIndex(context.Background(), "missing.com"); err == nil {
		t.Fatal("expected error for unknown domain")
	}
}

// TestParseBtStatus 状态响应解析。
func TestParseBtStatus(t *testing.T) {
	if err := parseBtStatus([]byte(`{"status":true,"msg":"ok"}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := parseBtStatus([]byte(`{"status":false,"msg":"证书未到期"}`))
	if err == nil || !strings.Contains(err.Error(), "证书未到期") {
		t.Fatalf("expected msg in error, got %v", err)
	}
	if err := parseBtStatus([]byte(`<html>404</html>`)); err == nil {
		t.Fatal("expected parse error for HTML body")
	}
}
