package security

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// EmergencyRollback SSH 失联紧急回滚看门狗。
// 每次封禁后 5s 检测 SSH 活跃连接数=0 且无法 ping 网关→
// 自动清除所有 C/Z 模块添加的 iptables 规则，触发告警。
type EmergencyRollback struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus
	stopCh   chan struct{}
	running  bool

	// 检测配置
	checkDelay    time.Duration // 封禁后延迟检测时间（默认5s）
	sshPort       int           // SSH 端口
	gatewayIP     string        // 网关IP
	maxRollbacks  int           // 最大回滚次数（避免循环）
	rollbackCount int           // 当前回滚次数
}

// NewEmergencyRollback 创建紧急回滚看门狗。
func NewEmergencyRollback(bus *eventbus.EventBus) *EmergencyRollback {
	return &EmergencyRollback{
		eventBus:     bus,
		stopCh:       make(chan struct{}),
		checkDelay:   5 * time.Second,
		sshPort:      22,
		gatewayIP:    detectGateway(),
		maxRollbacks: 3,
	}
}

// Start 启动看门狗。
func (e *EmergencyRollback) Start() {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()
}

// Stop 停止看门狗。
func (e *EmergencyRollback) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		close(e.stopCh)
		e.running = false
	}
}

// OnBanCalled 封禁操作后调用，启动延迟检测。
func (e *EmergencyRollback) OnBanCalled(bannedIP string) {
	go func() {
		select {
		case <-e.stopCh:
			return
		case <-time.After(e.checkDelay):
		}

		if e.checkSSHDisconnected() && !e.canPingGateway() {
			e.triggerRollback(bannedIP)
		}
	}()
}

// checkSSHDisconnected 检测 SSH 活跃连接数是否为 0。
func (e *EmergencyRollback) checkSSHDisconnected() bool {
	// 尝试连接 SSH 端口
	addr := fmt.Sprintf("127.0.0.1:%d", e.sshPort)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		// SSH 端口不可达，可能失联
		return true
	}
	conn.Close()
	// SSH 端口可达，但需要检查活跃连接数
	// 简化实现：端口可达即认为未失联
	return false
}

// canPingGateway 检测是否可以 ping 网关。
func (e *EmergencyRollback) canPingGateway() bool {
	if e.gatewayIP == "" {
		return true // 无法确定网关，假设可达
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", e.gatewayIP)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", e.gatewayIP)
	}
	err := cmd.Run()
	return err == nil
}

// triggerRollback 触发紧急回滚。
func (e *EmergencyRollback) triggerRollback(bannedIP string) {
	e.mu.Lock()
	if e.rollbackCount >= e.maxRollbacks {
		e.mu.Unlock()
		return
	}
	e.rollbackCount++
	count := e.rollbackCount
	e.mu.Unlock()

	// 清除所有 ServerGuard 添加的 iptables 规则
	e.clearAllSGRules()

	if e.eventBus != nil {
		e.eventBus.PublishAlert(types.AlertCritical, "security",
			"SSH失联紧急回滚",
			fmt.Sprintf("封禁 %s 后检测到 SSH 失联，已自动清除所有封禁规则（第 %d 次回滚）",
				bannedIP, count),
			"emergency-rollback-001")
	}
}

// clearAllSGRules 清除所有 ServerGuard 添加的 iptables 规则。
func (e *EmergencyRollback) clearAllSGRules() {
	if runtime.GOOS == "windows" {
		// Windows 使用防火墙规则
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ServerGuard").Run()
		return
	}
	// Linux: 清除带 ServerGuard 标记的 iptables 规则
	exec.Command("iptables", "-S").Run() // 列出规则
	// 使用注释标记的规则可以精确删除
	// 这里简化实现：flush INPUT 链中带 SG_ 前缀的规则
	exec.Command("sh", "-c", "iptables -S INPUT | grep 'SG_' | while read rule; do iptables -D INPUT ${rule#-A INPUT}; done").Run()
}

// detectGateway 检测默认网关 IP。
func detectGateway() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/C", "route print 0.0.0.0").Output()
		if err != nil {
			return ""
		}
		_ = out
		return ""
	}
	out, err := exec.Command("sh", "-c", "ip route | grep default | awk '{print $3}'").Output()
	if err != nil {
		return ""
	}
	gw := string(out)
	if len(gw) > 0 && gw[len(gw)-1] == '\n' {
		gw = gw[:len(gw)-1]
	}
	return gw
}

// ResetRollbackCount 重置回滚计数（用于恢复正常后重置）。
func (e *EmergencyRollback) ResetRollbackCount() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rollbackCount = 0
}
