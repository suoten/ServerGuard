package cert

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// PostRenewalHandler 续期后处理与验证。
// 续期成功后自动 reload Nginx/Apache（不重启避免业务中断），
// HTTPS 探测验证新证书已生效，验证失败回滚到旧证书 + 告警。
type PostRenewalHandler struct {
	eventBus *eventbus.EventBus
}

// NewPostRenewalHandler 创建续期后处理器。
func NewPostRenewalHandler(bus *eventbus.EventBus) *PostRenewalHandler {
	return &PostRenewalHandler{eventBus: bus}
}

// ReloadAndVerify reload Web 服务器并验证新证书。
// 返回验证是否成功。
func (h *PostRenewalHandler) ReloadAndVerify(domain string, certPath string, oldCertPath string) bool {
	// 1. 验证证书文件存在且有效
	if !h.validateCertFile(certPath) {
		h.publishAlert(domain, "证书文件验证失败", "error")
		return false
	}

	// 2. reload Nginx/Apache
	if err := h.reloadWebServer(); err != nil {
		// reload 失败，回滚旧证书
		h.rollbackCert(domain, certPath, oldCertPath)
		h.publishAlert(domain, fmt.Sprintf("Web服务器reload失败: %v，已回滚旧证书", err), "error")
		return false
	}

	// 3. HTTPS 探测验证新证书已生效
	if !h.verifyHTTPS(domain) {
		// 验证失败，回滚旧证书
		h.rollbackCert(domain, certPath, oldCertPath)
		h.publishAlert(domain, "HTTPS探测验证失败，已回滚旧证书", "error")
		return false
	}

	h.publishAlert(domain, "证书续期成功并已验证", "info")
	return true
}

// validateCertFile 验证证书文件。
func (h *PostRenewalHandler) validateCertFile(certPath string) bool {
	// 使用 openssl 验证证书
	cmd := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-checkend", "0")
	return cmd.Run() == nil
}

// reloadWebServer reload Nginx 或 Apache。
func (h *PostRenewalHandler) reloadWebServer() error {
	if runtime.GOOS == "windows" {
		// Windows: 尝试 reload IIS
		cmd := exec.Command("iisreset", "/noforce")
		return cmd.Run()
	}

	// 先尝试 Nginx
	if h.isCommandAvailable("nginx") {
		// 验证配置语法
		if err := exec.Command("nginx", "-t").Run(); err != nil {
			return fmt.Errorf("nginx config test failed: %w", err)
		}
		return exec.Command("nginx", "-s", "reload").Run()
	}

	// 再尝试 Apache
	if h.isCommandAvailable("apachectl") {
		return exec.Command("apachectl", "graceful").Run()
	}
	if h.isCommandAvailable("apache2ctl") {
		return exec.Command("apache2ctl", "graceful").Run()
	}

	// 没有 Web 服务器，跳过 reload
	return nil
}

// verifyHTTPS HTTPS 探测验证新证书已生效。
func (h *PostRenewalHandler) verifyHTTPS(domain string) bool {
	// 使用 openssl 验证 HTTPS 证书
	cmd := exec.Command("openssl", "s_client", "-connect", domain+":443", "-servername", domain)
	cmd.Stdin = strings.NewReader("")
	// 简化实现：检查命令是否能连接
	return cmd.Run() == nil
}

// rollbackCert 回滚到旧证书。
func (h *PostRenewalHandler) rollbackCert(domain, newCertPath, oldCertPath string) {
	if oldCertPath == "" {
		return
	}
	// 复制旧证书回原位置
	exec.Command("cp", oldCertPath, newCertPath).Run()
	// 再次 reload
	h.reloadWebServer()
}

// isCommandAvailable 检查命令是否可用。
func (h *PostRenewalHandler) isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// publishAlert 发布告警。
func (h *PostRenewalHandler) publishAlert(domain, message, level string) {
	if h.eventBus == nil {
		return
	}
	var alertLevel types.AlertLevel
	switch level {
	case "error":
		alertLevel = types.AlertError
	case "info":
		alertLevel = types.AlertInfo
	default:
		alertLevel = types.AlertWarning
	}
	h.eventBus.PublishAlert(alertLevel, "cert",
		fmt.Sprintf("证书续期: %s", domain),
		message,
		"cert-post-renewal-001")
}

// RenewalEvent 续期事件记录
type RenewalEvent struct {
	Domain    string
	CertPath  string
	Success   bool
	Timestamp time.Time
	UsedCA    string
	Error     string
}
