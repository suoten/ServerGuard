package traffic

import (
	"context"
	"fmt"
	"sync"
	"time"

	netproc "github.com/shirou/gopsutil/v3/net"

	"github.com/suoten/serverguard/internal/types"
)

type CCAttackDetector struct {
	mu            sync.RWMutex
	requestCounts map[string]map[string]int
	threshold     int
	window        time.Duration
	lastCleanup   time.Time
}

func NewCCAttackDetector() *CCAttackDetector {
	return &CCAttackDetector{
		requestCounts: make(map[string]map[string]int),
		threshold:     100,
		window:        10 * time.Second,
		lastCleanup:   time.Now(),
	}
}

func (d *CCAttackDetector) RecordRequest(ip, url string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.requestCounts[ip] == nil {
		d.requestCounts[ip] = make(map[string]int)
	}
	d.requestCounts[ip][url]++

	now := time.Now()
	if now.Sub(d.lastCleanup) > d.window {
		d.requestCounts = make(map[string]map[string]int)
		d.lastCleanup = now
	}

	return d.requestCounts[ip][url] >= d.threshold
}

func (d *CCAttackDetector) GetTopAttackers(n int) []CCAttackerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	type ipCount struct {
		ip    string
		total int
	}
	var counts []ipCount
	for ip, urls := range d.requestCounts {
		total := 0
		for _, c := range urls {
			total += c
		}
		counts = append(counts, ipCount{ip, total})
	}

	result := make([]CCAttackerInfo, 0, n)
	for i := 0; i < n && i < len(counts); i++ {
		result = append(result, CCAttackerInfo{
			IP:        counts[i].ip,
			Requests:  counts[i].total,
			Threshold: d.threshold,
		})
	}
	return result
}

type CCAttackerInfo struct {
	IP        string `json:"ip"`
	Requests  int    `json:"requests"`
	Threshold int    `json:"threshold"`
}

type OutboundAnomalyDetector struct {
	mu          sync.RWMutex
	ipOutbound  map[string]uint64
	thresholdMB uint64
	windowStart time.Time
	window      time.Duration
}

func NewOutboundAnomalyDetector() *OutboundAnomalyDetector {
	return &OutboundAnomalyDetector{
		ipOutbound:  make(map[string]uint64),
		thresholdMB: 100,
		windowStart: time.Now(),
		window:      1 * time.Hour,
	}
}

func (d *OutboundAnomalyDetector) RecordOutbound(ip string, bytes uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if now.Sub(d.windowStart) > d.window {
		d.ipOutbound = make(map[string]uint64)
		d.windowStart = now
	}

	d.ipOutbound[ip] += bytes
	return d.ipOutbound[ip] > d.thresholdMB*1024*1024
}

func (d *OutboundAnomalyDetector) GetAnomalies() []OutboundAnomaly {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var anomalies []OutboundAnomaly
	for ip, bytes := range d.ipOutbound {
		if bytes > d.thresholdMB*1024*1024 {
			anomalies = append(anomalies, OutboundAnomaly{
				IP:        ip,
				BytesOut:  bytes,
				Threshold: d.thresholdMB * 1024 * 1024,
			})
		}
	}
	return anomalies
}

type OutboundAnomaly struct {
	IP        string `json:"ip"`
	BytesOut  uint64 `json:"bytes_out"`
	Threshold uint64 `json:"threshold"`
}

type PortScanDetector struct {
	mu          sync.RWMutex
	ipPortHits  map[string]map[int]bool
	threshold   int
	windowStart time.Time
	window      time.Duration
}

func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{
		ipPortHits:  make(map[string]map[int]bool),
		threshold:   20,
		windowStart: time.Now(),
		window:      5 * time.Minute,
	}
}

func (d *PortScanDetector) RecordPortHit(ip string, port int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if now.Sub(d.windowStart) > d.window {
		d.ipPortHits = make(map[string]map[int]bool)
		d.windowStart = now
	}

	if d.ipPortHits[ip] == nil {
		d.ipPortHits[ip] = make(map[int]bool)
	}
	d.ipPortHits[ip][port] = true
	return len(d.ipPortHits[ip]) >= d.threshold
}

type SlowAttackDetector struct {
	mu            sync.RWMutex
	connections   map[string]*slowConnInfo
	threshold     time.Duration
	checkInterval time.Duration
}

type slowConnInfo struct {
	StartTime    time.Time
	LastActivity time.Time
	BytesSent    uint64
}

func NewSlowAttackDetector() *SlowAttackDetector {
	return &SlowAttackDetector{
		connections:   make(map[string]*slowConnInfo),
		threshold:     30 * time.Second,
		checkInterval: 5 * time.Second,
	}
}

func (d *SlowAttackDetector) OnConnect(connID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connections[connID] = &slowConnInfo{
		StartTime:    time.Now(),
		LastActivity: time.Now(),
	}
}

func (d *SlowAttackDetector) OnActivity(connID string, bytes uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if info, ok := d.connections[connID]; ok {
		info.LastActivity = time.Now()
		info.BytesSent += bytes
	}
}

func (d *SlowAttackDetector) OnDisconnect(connID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.connections, connID)
}

func (d *SlowAttackDetector) CheckSlowAttacks() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var slowConns []string
	now := time.Now()
	for connID, info := range d.connections {
		idleTime := now.Sub(info.LastActivity)
		totalTime := now.Sub(info.StartTime)
		if idleTime > d.threshold && totalTime > 2*d.threshold && info.BytesSent < 1024 {
			slowConns = append(slowConns, connID)
		}
	}
	return slowConns
}

func (g *TrafficGuard) CheckEnhanced(ctx context.Context) {
	go g.checkTrafficAnomaly(ctx)
	go g.checkSYNFlood(ctx)
	go g.checkPortScan(ctx)
	go g.checkOutboundAnomaly(ctx)
}

func (g *TrafficGuard) checkOutboundAnomaly(ctx context.Context) {
	io, err := netproc.IOCounters(false)
	if err != nil || len(io) == 0 {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	if !g.prevTime.IsZero() {
		elapsed := now.Sub(g.prevTime).Seconds()
		if elapsed > 0 {
			sentRate := float64(io[0].BytesSent-g.prevSent) / elapsed
			if sentRate > 100*1024*1024/3600 {
				g.eventBus.PublishAlert(types.AlertWarning, "traffic",
					"出站流量异常",
					fmt.Sprintf("当前出站速率 %.2f MB/s，超过 100MB/小时阈值", sentRate/1024/1024),
					"outbound-anomaly-001")
			}
		}
	}
	g.prevSent = io[0].BytesSent
	g.prevRecv = io[0].BytesRecv
	g.prevTime = now
}
