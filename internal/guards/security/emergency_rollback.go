package security

import (
	"fmt"

	"os/exec"
	"runtime"
	"strings"
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

// checkSSHDisconnected 检测是否存在来自非回环地址的活跃 SSH 会话。
// 不能用拨 127.0.0.1:22 判断——本机回环永远可达，与封禁的外部 IP 无关，
// 原实现因此永远检测不到失联。改用 ss 统计 22 端口的已建立外部连接。
func (e *EmergencyRollback) checkSSHDisconnected() bool {
	if runtime.GOOS == "windows" {
		return false // Windows 无 ss/proc，不做此检测（封禁走 netsh）
	}
	out, err := exec.Command("sh", "-c",
		fmt.Sprintf("ss -tnH state established '( sport = :%d )' 2>/dev/null | awk '{print $4}'", e.sshPort)).Output()
	if err != nil {
		// 检测手段不可用：宁可误判"未失联"也不触发误回滚
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		peer := strings.TrimSpace(line)
		if peer == "" {
			continue
		}
		// 排除回环/本地地址（sshd 自身的测试连接等）
		if strings.HasPrefix(peer, "127.") || strings.HasPrefix(peer, "[::1]") || strings.HasPrefix(peer, "::1") {
			continue
		}
		return false // 存在活跃的外部 SSH 会话 → 未失联
	}
	return true // 22 端口没有任何外部已建立连接
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
// 实际规则的注释是 "serverguard-*"（小写），原实现 grep 'SG_' 永远匹配
// 不到任何规则——紧急回滚是空操作。改为按小写标记精确删除。
func (e *EmergencyRollback) clearAllSGRules() {
	if runtime.GOOS == "windows" {
		// Windows 使用防火墙规则
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ServerGuard").Run()
		return
	}
	// Linux: 逐条删除带 serverguard 注释的 INPUT 规则（只动自己的规则，
	// 绝不 flush 整条链——服务器上可能有宝塔/用户自己的防火墙规则）
	exec.Command("sh", "-c",
		`iptables -S INPUT | grep 'serverguard' | sed 's/^-A INPUT //' | while read -r rule; do iptables -D INPUT $rule; done`).Run()
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
