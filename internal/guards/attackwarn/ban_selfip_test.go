package attackwarn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// recordingFW 记录所有封禁请求的假防火墙，用于断言"绝不该封的 IP 没有被封"。
type recordingFW struct {
	bans []string
}

func (f *recordingFW) BanIP(ctx context.Context, ip string, duration time.Duration, reason string) error {
	f.bans = append(f.bans, ip)
	return nil
}
func (f *recordingFW) UnbanIP(ctx context.Context, ip string) error             { return nil }
func (f *recordingFW) RateLimit(ctx context.Context, ip string, rate int) error { return nil }

// pickLocalIP 返回本机一个非回环地址（找不到则返回空串，如纯回环环境）。
func pickLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

// 核心安全回归：本机 IP（含公网出口 IP）、内网 IP、白名单 IP 绝不允许触发封禁。
// 事故背景：封禁自己的公网 IP 会导致服务器无法访问自身站点/服务，属于自残式封禁。
func TestHandleAttackNeverBansSelfOrPrivateIPs(t *testing.T) {
	fw := &recordingFW{}
	g := NewAttackWarnGuard(nil, fw)
	ctx := context.Background()

	protected := []string{"127.0.0.1", "::1"}
	if local := pickLocalIP(); local != "" {
		protected = append(protected, local)
	} else {
		t.Log("未找到非回环网卡地址，仅验证回环与内网")
	}

	for _, ip := range protected {
		action := g.handleAttack(ctx, ip, "web_scanner", types.SeverityHigh)
		switch action {
		case "skip_self_ip", "whitelisted_skip", "skip_private_ip":
			// 合法的跳过路径
		default:
			t.Errorf("本机地址 %s 不应进入处置流程，实际 action=%s", ip, action)
		}
	}

	private := []string{"10.0.0.5", "172.16.3.9", "192.168.1.50", "100.64.0.1"}
	for _, ip := range private {
		g.handleAttack(ctx, ip, "xss", types.SeverityCritical)
	}

	if len(fw.bans) != 0 {
		t.Fatalf("受保护 IP 被执行了封禁: %v", fw.bans)
	}

	// 对照组：公网攻击 IP 应正常封禁
	if action := g.handleAttack(ctx, "203.0.113.77", "sql_injection", types.SeverityHigh); len(fw.bans) != 1 || fw.bans[0] != "203.0.113.77" {
		t.Fatalf("公网攻击 IP 应被封禁，action=%s bans=%v", action, fw.bans)
	}
}

// isSelfIP 的归一化：IPv4-mapped IPv6 形式也要能识别为本机地址。
func TestIsSelfIPMappedForm(t *testing.T) {
	if !isSelfIP("127.0.0.1") {
		t.Fatal("127.0.0.1 应识别为受保护")
	}
	if !isPrivateIP("::ffff:192.168.1.5") {
		t.Fatal("IPv4-mapped 内网地址应被 isPrivateIP 识别")
	}
	if isSelfIP("203.0.113.99") && pickLocalIP() == "" {
		t.Fatal("测试网段地址不应被误判为本机")
	}
}
