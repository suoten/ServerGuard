package traffic

import (
	"context"
	"fmt"
	"sync"
	"time"

	netproc "github.com/shirou/gopsutil/v3/net"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// TrafficGuard implements Module R: Traffic Guard
// Covers: SYN Flood, CC attack, port scan, outbound surge, slow attack detection
type TrafficGuard struct {
	mu           sync.RWMutex
	eventBus     *eventbus.EventBus
	prevSent     uint64
	prevRecv     uint64
	prevTime     time.Time
	baselineSent float64
	baselineRecv float64
	sentHistory  []float64
	recvHistory  []float64
	historyMax   int
}

func New(bus *eventbus.EventBus) *TrafficGuard {
	return &TrafficGuard{
		eventBus:   bus,
		prevTime:   time.Now(),
		historyMax: 60,
	}
}

func (g *TrafficGuard) Check(ctx context.Context) {
	// R1: Check network traffic anomalies
	go g.checkTrafficAnomaly(ctx)

	// R2: Check for SYN flood
	go g.checkSYNFlood(ctx)

	// R3: Check for port scanning
	go g.checkPortScan(ctx)
}

func (g *TrafficGuard) checkTrafficAnomaly(ctx context.Context) {
	io, err := netproc.IOCounters(false)
	if err != nil || len(io) == 0 {
		return
	}

	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.prevTime.IsZero() {
		elapsed := now.Sub(g.prevTime).Seconds()
		if elapsed > 0 {
			sentRate := float64(io[0].BytesSent-g.prevSent) / elapsed
			recvRate := float64(io[0].BytesRecv-g.prevRecv) / elapsed

			// Check for outbound surge (potential data exfiltration)
			if g.baselineSent > 0 && sentRate > g.baselineSent*5 {
				g.eventBus.PublishAlert(types.AlertWarning, "traffic",
					"出站流量突增",
					fmt.Sprintf("出站流量 %.2f MB/s 是基线 %.2f MB/s 的 %.1f 倍，疑似数据外泄（需排查是否为正常业务流量）",
						sentRate/1024/1024, g.baselineSent/1024/1024, sentRate/g.baselineSent),
					"outbound-surge-001")
			}

			// Check for inbound surge (potential DDoS)
			if g.baselineRecv > 0 && recvRate > g.baselineRecv*5 {
				g.eventBus.PublishAlert(types.AlertWarning, "traffic",
					"入站流量突增",
					fmt.Sprintf("入站流量 %.2f MB/s 是基线 %.2f MB/s 的 %.1f 倍，疑似遭受DDoS攻击（需排查是否为正常流量高峰）",
						recvRate/1024/1024, g.baselineRecv/1024/1024, recvRate/g.baselineRecv),
					"inbound-surge-001")
			}

			g.recordSample(sentRate, recvRate)
		}
	}

	g.prevSent = io[0].BytesSent
	g.prevRecv = io[0].BytesRecv
	g.prevTime = now
}

func (g *TrafficGuard) checkSYNFlood(ctx context.Context) {
	// Check for SYN flood by monitoring connection states
	// This would read /proc/net/tcp or use netstat
	conns, err := netproc.Connections("tcp")
	if err != nil {
		return
	}

	synRecvCount := 0
	for _, conn := range conns {
		if conn.Status == "SYN_RECV" {
			synRecvCount++
		}
	}

	if synRecvCount > 100 {
		g.eventBus.PublishAlert(types.AlertError, "traffic",
			"SYN Flood攻击",
			fmt.Sprintf("检测到 %d 个SYN_RECV连接，疑似遭受SYN Flood攻击，服务器资源可能被耗尽", synRecvCount),
			"syn-flood-001")
	}
}

func (g *TrafficGuard) checkPortScan(ctx context.Context) {
	// Check for port scanning patterns
	// This would monitor for connections to many different ports in a short time
	conns, err := netproc.Connections("tcp")
	if err != nil {
		return
	}

	// Group by remote IP and count unique local ports
	ipPortMap := make(map[string]map[int]bool)
	for _, conn := range conns {
		if conn.Raddr.IP != "" {
			if ipPortMap[conn.Raddr.IP] == nil {
				ipPortMap[conn.Raddr.IP] = make(map[int]bool)
			}
			ipPortMap[conn.Raddr.IP][int(conn.Laddr.Port)] = true
		}
	}

	for ip, ports := range ipPortMap {
		if len(ports) > 20 {
			g.eventBus.PublishAlert(types.AlertWarning, "traffic",
				fmt.Sprintf("端口扫描: %s", ip),
				fmt.Sprintf("IP %s 在短时间内连接了 %d 个不同端口，可能是端口扫描", ip, len(ports)),
				"port-scan-001")
		}
	}
}

// SetBaseline sets the traffic baseline for anomaly detection.
func (g *TrafficGuard) SetBaseline(sentRate, recvRate float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.baselineSent = sentRate
	g.baselineRecv = recvRate
}

// UpdateBaseline updates the baseline based on observed traffic.
// 使用滑动窗口（默认60个采样点）计算指数加权移动平均作为基线
func (g *TrafficGuard) UpdateBaseline() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.sentHistory) == 0 || len(g.recvHistory) == 0 {
		return
	}

	alpha := 0.3
	sentBaseline := g.sentHistory[0]
	for i := 1; i < len(g.sentHistory); i++ {
		sentBaseline = alpha*g.sentHistory[i] + (1-alpha)*sentBaseline
	}

	recvBaseline := g.recvHistory[0]
	for i := 1; i < len(g.recvHistory); i++ {
		recvBaseline = alpha*g.recvHistory[i] + (1-alpha)*recvBaseline
	}

	g.baselineSent = sentBaseline
	g.baselineRecv = recvBaseline
}

// recordSample 记录当前流量速率采样值到历史窗口
func (g *TrafficGuard) recordSample(sentRate, recvRate float64) {
	g.sentHistory = append(g.sentHistory, sentRate)
	g.recvHistory = append(g.recvHistory, recvRate)

	if len(g.sentHistory) > g.historyMax {
		g.sentHistory = g.sentHistory[len(g.sentHistory)-g.historyMax:]
	}
	if len(g.recvHistory) > g.historyMax {
		g.recvHistory = g.recvHistory[len(g.recvHistory)-g.historyMax:]
	}
}
