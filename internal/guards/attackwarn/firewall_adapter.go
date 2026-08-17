package attackwarn

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/suoten/serverguard/internal/platform"
)

// platformFirewallAdapter 将 platform.FirewallManager 适配为 attackwarn.FirewallManager
type platformFirewallAdapter struct {
	platformFW platform.FirewallManager
}

// NewPlatformFirewallAdapter 创建适配器
func NewPlatformFirewallAdapter(pfw platform.FirewallManager) FirewallManager {
	return &platformFirewallAdapter{platformFW: pfw}
}

func (a *platformFirewallAdapter) BanIP(ctx context.Context, ip string, duration time.Duration, reason string) error {
	if a.platformFW == nil {
		return fmt.Errorf("firewall manager not available")
	}
	opts := platform.BanOptions{
		Duration:   duration,
		Reason:     reason,
		RulePrefix: "serverguard-attackwarn",
		Protocol:   "tcp",
	}
	return a.platformFW.BanIP(ctx, ip, opts)
}

func (a *platformFirewallAdapter) UnbanIP(ctx context.Context, ip string) error {
	if a.platformFW == nil {
		return fmt.Errorf("firewall manager not available")
	}
	if ip == "all" {
		return a.platformFW.ClearAll(ctx)
	}
	return a.platformFW.UnbanIP(ctx, ip)
}

func (a *platformFirewallAdapter) RateLimit(ctx context.Context, ip string, rate int) error {
	if a.platformFW == nil {
		return fmt.Errorf("firewall manager not available")
	}
	opts := platform.RateLimitOptions{
		Burst:    rate * 2,
		Protocol: "tcp",
	}
	return a.platformFW.RateLimit(ctx, ip, rate, opts)
}

// noopFirewallManager 空实现，用于不支持防火墙的环境
type noopFirewallManager struct{}

func (n *noopFirewallManager) BanIP(ctx context.Context, ip string, duration time.Duration, reason string) error {
	return nil
}
func (n *noopFirewallManager) UnbanIP(ctx context.Context, ip string) error             { return nil }
func (n *noopFirewallManager) RateLimit(ctx context.Context, ip string, rate int) error { return nil }

// NewNoopFirewallManager 创建空防火墙管理器
func NewNoopFirewallManager() FirewallManager {
	return &noopFirewallManager{}
}

// IsLinuxAvailable 检查当前平台是否有可用的防火墙
func IsLinuxAvailable() bool {
	return runtime.GOOS == "linux"
}
