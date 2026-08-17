package acme

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CAServer ACME CA 服务器枚举
type CAServer string

const (
	CA_LetsEncrypt CAServer = "letsencrypt"
	CA_ZeroSSL     CAServer = "zerossl"
	CA_TrustAsia   CAServer = "trustasia"
)

// CAConfig CA 服务器配置
type CAConfig struct {
	Server       CAServer
	DirectoryURL string
	Contact      string
	Enabled      bool
}

// DefaultCAOrder 默认 CA 降级顺序：LE → ZeroSSL → TrustAsia
var DefaultCAOrder = []CAServer{CA_LetsEncrypt, CA_ZeroSSL, CA_TrustAsia}

// caConfigs CA 服务器配置映射
var caConfigs = map[CAServer]CAConfig{
	CA_LetsEncrypt: {
		Server:       CA_LetsEncrypt,
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Enabled:      true,
	},
	CA_ZeroSSL: {
		Server:       CA_ZeroSSL,
		DirectoryURL: "https://acme.zerossl.com/v2/D90",
		Enabled:      true,
	},
	CA_TrustAsia: {
		Server:       CA_TrustAsia,
		DirectoryURL: "https://acme.trustasia.com/directory",
		Enabled:      true,
	},
}

// RenewResult 续期结果
type RenewResult struct {
	Success      bool
	UsedCA       CAServer
	FailureChain []CAFailure // 尝试过的 CA 及失败原因
	CertPath     string
	Error        error
}

// CAFailure CA 尝试失败记录
type CAFailure struct {
	CA    CAServer
	Error string
	Time  time.Time
}

// MultiCARenewer 多 CA 降级续期器。
// 按序尝试 LE→ZeroSSL→TrustAsia，任一 CA 成功即停止。
type MultiCARenewer struct {
	mu        sync.Mutex
	caOrder   []CAServer
	renewFunc func(ctx context.Context, ca CAServer, domain string) (certPath string, err error)
}

// NewMultiCARenewer 创建多 CA 降级续期器。
func NewMultiCARenewer(renewFunc func(ctx context.Context, ca CAServer, domain string) (string, error)) *MultiCARenewer {
	return &MultiCARenewer{
		caOrder:   DefaultCAOrder,
		renewFunc: renewFunc,
	}
}

// RenewWithFallback 按序尝试多个 CA 进行续期。
// 任一 CA 成功即停止尝试，返回结果包含所有尝试过的 CA 的失败信息。
func (m *MultiCARenewer) RenewWithFallback(ctx context.Context, domain string) RenewResult {
	m.mu.Lock()
	order := make([]CAServer, len(m.caOrder))
	copy(order, m.caOrder)
	m.mu.Unlock()

	result := RenewResult{
		FailureChain: []CAFailure{},
	}

	for _, ca := range order {
		config, ok := caConfigs[ca]
		if !ok || !config.Enabled {
			continue
		}

		certPath, err := m.renewFunc(ctx, ca, domain)
		if err == nil {
			result.Success = true
			result.UsedCA = ca
			result.CertPath = certPath
			return result
		}

		// 记录失败
		result.FailureChain = append(result.FailureChain, CAFailure{
			CA:    ca,
			Error: err.Error(),
			Time:  time.Now(),
		})
	}

	result.Error = fmt.Errorf("all CAs failed: %d attempts", len(result.FailureChain))
	return result
}

// SetCAOrder 设置 CA 降级顺序。
func (m *MultiCARenewer) SetCAOrder(order []CAServer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.caOrder = order
}

// GetCAOrder 返回当前 CA 降级顺序。
func (m *MultiCARenewer) GetCAOrder() []CAServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]CAServer, len(m.caOrder))
	copy(result, m.caOrder)
	return result
}

// GetCAConfig 返回指定 CA 的配置。
func GetCAConfig(ca CAServer) (CAConfig, bool) {
	config, ok := caConfigs[ca]
	return config, ok
}

// GetAllCAConfigs 返回所有 CA 配置。
func GetAllCAConfigs() map[CAServer]CAConfig {
	result := make(map[CAServer]CAConfig)
	for k, v := range caConfigs {
		result[k] = v
	}
	return result
}
