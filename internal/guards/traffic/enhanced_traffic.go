package traffic

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	netproc "github.com/shirou/gopsutil/v3/net"

	"github.com/suoten/serverguard/internal/types"
)

// ============================================================
// 增强型流量安全检测
// 包含：CC攻击检测、出站异常检测、端口扫描检测、慢攻击检测
// ============================================================

// CCAttackDetector CC攻击检测器
// 基于滑动窗口检测单IP对单URL的高频请求
type CCAttackDetector struct {
	mu            sync.RWMutex
	requestCounts map[string]map[string]int // IP -> URL -> count
	threshold     int                       // 单窗口内同IP同URL请求阈值
	window        time.Duration             // 检测窗口
	lastCleanup   time.Time
	// 记录被标记为CC攻击的IP及其首次检测时间，用于升级封禁
	flaggedIPs map[string]time.Time
}

func NewCCAttackDetector() *CCAttackDetector {
	return &CCAttackDetector{
		requestCounts: make(map[string]map[string]int),
		// 阈值从 100 提高到 500：100 次/10 秒对正常浏览宝塔面板可能误触，
		// 此检测器只做告警标记，真正的 CC 封禁由 attackwarn 模块的行为分析完成
		threshold:   500,
		window:      10 * time.Second,
		lastCleanup: time.Now(),
		flaggedIPs:  make(map[string]time.Time),
	}
}

// RecordRequest 记录一次请求，返回是否超过阈值
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

// GetTopAttackers 返回请求量最高的N个IP
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

	// 简单选择排序，取前N个
	result := make([]CCAttackerInfo, 0, n)
	for i := 0; i < n && i < len(counts); i++ {
		maxIdx := i
		for j := i + 1; j < len(counts); j++ {
			if counts[j].total > counts[maxIdx].total {
				maxIdx = j
			}
		}
		counts[i], counts[maxIdx] = counts[maxIdx], counts[i]
		result = append(result, CCAttackerInfo{
			IP:        counts[i].ip,
			Requests:  counts[i].total,
			Threshold: d.threshold,
		})
	}
	return result
}

// IsFlagged 检查IP是否已被标记为CC攻击者
func (d *CCAttackDetector) IsFlagged(ip string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.flaggedIPs[ip]
	return ok
}

// FlagIP 标记IP为CC攻击者
func (d *CCAttackDetector) FlagIP(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.flaggedIPs[ip]; !ok {
		d.flaggedIPs[ip] = time.Now()
	}
}

// CleanFlaggedIPs 清理过期的标记IP
func (d *CCAttackDetector) CleanFlaggedIPs(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for ip, t := range d.flaggedIPs {
		if now.Sub(t) > maxAge {
			delete(d.flaggedIPs, ip)
		}
	}
}

type CCAttackerInfo struct {
	IP        string `json:"ip"`
	Requests  int    `json:"requests"`
	Threshold int    `json:"threshold"`
}

// ============================================================
// 出站异常检测器
// ============================================================

// OutboundAnomalyDetector 出站异常检测器
// 检测per-IP出站流量、可疑外联目标、数据外泄
type OutboundAnomalyDetector struct {
	mu          sync.RWMutex
	ipOutbound  map[string]uint64 // IP -> bytes
	thresholdMB uint64            // 单IP出站阈值
	windowStart time.Time
	window      time.Duration
	// 可疑外联目标端口（常见C2端口）
	suspiciousPorts map[int]string
	// 记录可疑外联IP
	suspiciousIPs map[string][]string // IP -> list of "port:reason"
}

func NewOutboundAnomalyDetector() *OutboundAnomalyDetector {
	return &OutboundAnomalyDetector{
		ipOutbound:      make(map[string]uint64),
		thresholdMB:     100,
		windowStart:     time.Now(),
		window:          1 * time.Hour,
		suspiciousPorts: initSuspiciousPorts(),
		suspiciousIPs:   make(map[string][]string),
	}
}

// initSuspiciousPorts 初始化可疑端口列表
func initSuspiciousPorts() map[int]string {
	return map[int]string{
		1337: "常见C2端口",
		31337: "Back Orifice",
		4444:  "Metasploit默认端口",
		6667:  "IRC（常用于C2通信）",
		6668:  "IRC（常用于C2通信）",
		6669:  "IRC（常用于C2通信）",
		9001:  "常见C2端口",
		8080:  "非常规Web代理端口",
		8443:  "非常规HTTPS端口",
		9999:  "常见C2端口",
		1234:  "常见后门端口",
		4433:  "非常规HTTPS端口",
		5555:  "常见Android调试端口",
		2375:  "Docker未认证API",
		2376:  "Docker TLS API",
		11211: "Memcached默认端口",
		6379:  "Redis默认端口（外联可疑）",
		27017: "MongoDB默认端口（外联可疑）",
		3306:  "MySQL默认端口（外联可疑）",
	}
}

// RecordOutbound 记录出站流量，返回是否超过阈值
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

// RecordSuspiciousOutbound 记录可疑外联（连接到可疑端口）
func (d *OutboundAnomalyDetector) RecordSuspiciousOutbound(ip string, port int) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	reason, suspicious := d.suspiciousPorts[port]
	if suspicious {
		entry := fmt.Sprintf("%d:%s", port, reason)
		d.suspiciousIPs[ip] = append(d.suspiciousIPs[ip], entry)
	}
	return reason, suspicious
}

// GetAnomalies 返回出站流量异常的IP列表
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

// GetSuspiciousOutboundIPs 返回有可疑外联的IP列表
func (d *OutboundAnomalyDetector) GetSuspiciousOutboundIPs() map[string][]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make(map[string][]string)
	for ip, entries := range d.suspiciousIPs {
		result[ip] = make([]string, len(entries))
		copy(result[ip], entries)
	}
	return result
}

type OutboundAnomaly struct {
	IP        string `json:"ip"`
	BytesOut  uint64 `json:"bytes_out"`
	Threshold uint64 `json:"threshold"`
}

// ============================================================
// 端口扫描检测器
// ============================================================

// PortScanDetector 端口扫描检测器
type PortScanDetector struct {
	mu          sync.RWMutex
	ipPortHits  map[string]map[int]bool // IP -> set of ports
	threshold   int                     // 端口数阈值
	windowStart time.Time
	window      time.Duration
}

func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{
		ipPortHits:  make(map[string]map[int]bool),
		// 从 20 提高到 50：正常多站点浏览（宝塔面板8888 + 多个站点443/80 + SSH22 + 数据库3306等）
		// 可能连接 10+ 个不同端口，20 太低会误报
		threshold:   50,
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

// ============================================================
// 慢攻击检测器
// ============================================================

// SlowAttackDetector 慢攻击检测器
// 检测Slowloris、Slow POST等慢速攻击
type SlowAttackDetector struct {
	mu            sync.RWMutex
	connections   map[string]*slowConnInfo // connID -> info
	threshold     time.Duration            // 空闲阈值
	checkInterval time.Duration            // 检查间隔
}

type slowConnInfo struct {
	StartTime    time.Time
	LastActivity time.Time
	BytesSent    uint64
	BytesRecv    uint64
	RemoteIP     string
	LocalPort    int
}

func NewSlowAttackDetector() *SlowAttackDetector {
	return &SlowAttackDetector{
		connections:   make(map[string]*slowConnInfo),
		threshold:     30 * time.Second,
		checkInterval: 5 * time.Second,
	}
}

func (d *SlowAttackDetector) OnConnect(connID, remoteIP string, localPort int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connections[connID] = &slowConnInfo{
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		RemoteIP:     remoteIP,
		LocalPort:    localPort,
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

// CheckSlowAttacks 检测慢攻击连接
// 返回被判定为慢攻击的连接ID列表
func (d *SlowAttackDetector) CheckSlowAttacks() []SlowAttackInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var slowConns []SlowAttackInfo
	now := time.Now()
	for connID, info := range d.connections {
		idleTime := now.Sub(info.LastActivity)
		totalTime := now.Sub(info.StartTime)
		// 慢攻击特征：长时间空闲 + 总连接时间长 + 传输数据极少
		if idleTime > d.threshold && totalTime > 2*d.threshold && info.BytesSent < 1024 {
			slowConns = append(slowConns, SlowAttackInfo{
				ConnID:    connID,
				RemoteIP:  info.RemoteIP,
				LocalPort: info.LocalPort,
				IdleTime:  idleTime,
				TotalTime: totalTime,
				BytesSent: info.BytesSent,
			})
		}
	}
	return slowConns
}

// SlowAttackInfo 慢攻击连接信息
type SlowAttackInfo struct {
	ConnID    string        `json:"conn_id"`
	RemoteIP  string        `json:"remote_ip"`
	LocalPort int           `json:"local_port"`
	IdleTime  time.Duration `json:"idle_time"`
	TotalTime time.Duration `json:"total_time"`
	BytesSent uint64        `json:"bytes_sent"`
}

// GetSlowConnCount 返回当前跟踪的慢连接数量
func (d *SlowAttackDetector) GetSlowConnCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.connections)
}

// CleanupStale 清理过期的连接记录
func (d *SlowAttackDetector) CleanupStale(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for connID, info := range d.connections {
		if now.Sub(info.LastActivity) > maxAge {
			delete(d.connections, connID)
		}
	}
}

// ============================================================
// 连接状态分布检测器
// 检测 TIME_WAIT/CLOSE_WAIT 堆积等连接状态异常
// ============================================================

// ConnectionStateStats 连接状态统计
type ConnectionStateStats struct {
	ESTABLISHED int
	SYN_SENT    int
	SYN_RECV    int
	FIN_WAIT1   int
	FIN_WAIT2   int
	TIME_WAIT   int
	CLOSE_WAIT  int
	LAST_ACK    int
	CLOSED      int
	Total       int
}

// CheckConnectionStates 检测连接状态分布异常
// 返回异常描述列表，若无异常返回空
func CheckConnectionStates() []ConnectionStateAnomaly {
	conns, err := netproc.Connections("tcp")
	if err != nil || len(conns) == 0 {
		return nil
	}

	stats := ConnectionStateStats{}
	for _, c := range conns {
		stats.Total++
		switch c.Status {
		case "ESTABLISHED":
			stats.ESTABLISHED++
		case "SYN_SENT":
			stats.SYN_SENT++
		case "SYN_RECV":
			stats.SYN_RECV++
		case "FIN_WAIT1":
			stats.FIN_WAIT1++
		case "FIN_WAIT2":
			stats.FIN_WAIT2++
		case "TIME_WAIT":
			stats.TIME_WAIT++
		case "CLOSE_WAIT":
			stats.CLOSE_WAIT++
		case "LAST_ACK":
			stats.LAST_ACK++
		case "CLOSED":
			stats.CLOSED++
		}
	}

	var anomalies []ConnectionStateAnomaly

	// TIME_WAIT 过多（超过总连接的50%且总数 > 1000）
	if stats.TIME_WAIT > 1000 && float64(stats.TIME_WAIT)/float64(stats.Total) > 0.5 {
		anomalies = append(anomalies, ConnectionStateAnomaly{
			Type:    "TIME_WAIT堆积",
			Count:   stats.TIME_WAIT,
			Total:   stats.Total,
			Ratio:   float64(stats.TIME_WAIT) / float64(stats.Total),
			Suggest: "TIME_WAIT过多可能导致端口耗尽。建议调整 net.ipv4.tcp_tw_reuse=1，或检查是否有大量短连接。注意：不建议设置 tcp_tw_recycle=1（已在内核 4.12+ 移除）",
		})
	}

	// CLOSE_WAIT 过多——从 100 提高到 200
	// 正常应用可能有少量 CLOSE_WAIT（连接关闭有延迟），100 太低
	if stats.CLOSE_WAIT > 200 {
		anomalies = append(anomalies, ConnectionStateAnomaly{
			Type:    "CLOSE_WAIT堆积",
			Count:   stats.CLOSE_WAIT,
			Total:   stats.Total,
			Ratio:   float64(stats.CLOSE_WAIT) / float64(stats.Total),
			Suggest: "CLOSE_WAIT过多说明应用层未正确关闭连接。排查应用程序是否正确调用 close()，检查是否有连接泄漏",
		})
	}

	// SYN_RECV 过多（可能 SYN Flood）——从 100 提高到 500
	// 正常高负载服务器的 SYN_RECV 可能达到几十到上百，100 太低会误报
	if stats.SYN_RECV > 500 {
		anomalies = append(anomalies, ConnectionStateAnomaly{
			Type:    "SYN_RECV异常",
			Count:   stats.SYN_RECV,
			Total:   stats.Total,
			Ratio:   float64(stats.SYN_RECV) / float64(stats.Total),
			Suggest: "SYN_RECV过多可能遭受SYN Flood攻击。建议检查 net.ipv4.tcp_max_syn_backlog 设置，考虑启用 SYN Cookie",
		})
	}

	// 总连接数过多
	if stats.Total > 10000 {
		anomalies = append(anomalies, ConnectionStateStateAnomalyTotal(stats))
	}

	return anomalies
}

// ConnectionStateStateAnomalyTotal 创建总连接数异常
func ConnectionStateStateAnomalyTotal(stats ConnectionStateStats) ConnectionStateAnomaly {
	return ConnectionStateAnomaly{
		Type:    "总连接数过多",
		Count:   stats.Total,
		Total:   stats.Total,
		Ratio:   1.0,
		Suggest: fmt.Sprintf("总连接数 %d 过多，可能影响服务器性能。建议检查 ulimit -n 设置，排查是否有异常连接", stats.Total),
	}
}

// ConnectionStateAnomaly 连接状态异常
type ConnectionStateAnomaly struct {
	Type    string  `json:"type"`
	Count   int     `json:"count"`
	Total   int     `json:"total"`
	Ratio   float64 `json:"ratio"`
	Suggest string  `json:"suggest"`
}

// ============================================================
// 增强型 TrafficGuard 方法
// ============================================================

// CheckEnhanced 执行增强型流量安全检测
func (g *TrafficGuard) CheckEnhanced(ctx context.Context) {
	go g.checkTrafficAnomaly(ctx)
	go g.checkSYNFlood(ctx)
	go g.checkPortScan(ctx)
	go g.checkOutboundAnomaly(ctx)
	go g.checkConnectionStates(ctx)
	go g.checkSuspiciousOutbound(ctx)
}

// checkOutboundAnomaly 检测出站流量异常
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
					fmt.Sprintf("当前出站速率 %.2f MB/s，超过 100MB/小时阈值。建议排查：1) 是否有大文件上传/下载 2) 是否有备份任务 3) 是否存在数据外泄", sentRate/1024/1024),
					"outbound-anomaly-001")
			}
		}
	}
	g.prevSent = io[0].BytesSent
	g.prevRecv = io[0].BytesRecv
	g.prevTime = now
}

// checkConnectionStates 检测连接状态分布异常
func (g *TrafficGuard) checkConnectionStates(ctx context.Context) {
	anomalies := CheckConnectionStates()
	for _, a := range anomalies {
		var severity types.AlertLevel
		switch a.Type {
		case "SYN_RECV异常":
			severity = types.AlertError
		case "CLOSE_WAIT堆积":
			severity = types.AlertError
		case "TIME_WAIT堆积":
			severity = types.AlertWarning
		default:
			severity = types.AlertWarning
		}
		g.eventBus.PublishAlert(severity, "traffic",
			fmt.Sprintf("连接状态异常: %s", a.Type),
			fmt.Sprintf("%s：当前 %d 个（占总连接 %.1f%%，总连接 %d）。建议：%s",
				a.Type, a.Count, a.Ratio*100, a.Total, a.Suggest),
			"conn-state-"+a.Type)
	}
}

// checkSuspiciousOutbound 检测可疑外联
// 通过分析当前出站连接，检测是否连接到可疑端口
func (g *TrafficGuard) checkSuspiciousOutbound(ctx context.Context) {
	conns, err := netproc.Connections("tcp")
	if err != nil || len(conns) == 0 {
		return
	}

	// 获取本机所有网卡 IP，用于排除服务器自身 IP（包括公网 IP）
	localIPs := getLocalIPs()

	detector := NewOutboundAnomalyDetector()
	suspiciousIPs := make(map[string][]string)

	for _, conn := range conns {
		// 只检查 ESTABLISHED 状态的出站连接
		if conn.Status != "ESTABLISHED" {
			continue
		}
		// 只检查远端端口（出站连接）
		if conn.Raddr.IP == "" || conn.Raddr.Port == 0 {
			continue
		}

		rip := conn.Raddr.IP

		// 排除本地回环地址
		if rip == "127.0.0.1" || rip == "::1" {
			continue
		}

		// 排除内网私有 IP（10.x / 172.16-31.x / 192.168.x）
		if isPrivateIP(rip) {
			continue
		}

		// 排除服务器自身的 IP（包括公网 IP）
		// 服务器可能通过自己的公网 IP 回环访问自己的服务（如 MySQL 3306、Redis 6379）
		if localIPs[rip] {
			continue
		}

		port := int(conn.Raddr.Port)
		if reason, suspicious := detector.RecordSuspiciousOutbound(rip, port); suspicious {
			entry := fmt.Sprintf("端口 %d (%s)", port, reason)
			suspiciousIPs[rip] = append(suspiciousIPs[rip], entry)
		}
	}

	// 报告可疑外联
	for ip, entries := range suspiciousIPs {
		g.eventBus.PublishAlert(types.AlertWarning, "traffic",
			fmt.Sprintf("可疑外联: %s", ip),
			fmt.Sprintf("服务器正在连接 IP %s 的可疑端口: %s。建议排查：1) 确认为合法业务 2) 检查是否有恶意程序外联 3) 必要时通过防火墙封禁",
				ip, strings.Join(entries, ", ")),
			"suspicious-outbound-001")
	}
}

// getLocalIPs 返回本机所有网卡的 IP 地址集合
// 用于排除服务器自身的 IP（包括公网 IP），避免误报
func getLocalIPs() map[string]bool {
	ips := make(map[string]bool)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
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
			if ip != nil {
				ips[ip.String()] = true
			}
		}
	}
	return ips
}

// ============================================================
// 系统级慢连接检测（通过 ss/netstat 获取真实连接数据）
// ============================================================

// CheckSystemSlowConnections 从系统获取连接信息并检测慢连接
// 在 Linux 上使用 ss 命令，在 Windows 上使用 netstat
func CheckSystemSlowConnections(idleThreshold time.Duration) []SystemSlowConn {
	if runtime.GOOS == "windows" {
		return checkSlowConnectionsWindows(idleThreshold)
	}
	return checkSlowConnectionsLinux(idleThreshold)
}

// SystemSlowConn 系统级慢连接信息
type SystemSlowConn struct {
	LocalAddr  string
	RemoteAddr string
	State      string
	Reason     string
}

// checkSlowConnectionsLinux 在 Linux 上通过 ss 检测慢连接
func checkSlowConnectionsLinux(idleThreshold time.Duration) []SystemSlowConn {
	// ss -toState established 可以显示连接状态和超时
	cmd := exec.Command("ss", "-to", "state", "established")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// ss 不可用时降级为 netstat
		return checkSlowConnectionsNetstat(idleThreshold)
	}

	var slowConns []SystemSlowConn
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "timer:") {
			// ss 输出中包含 timer 信息表示连接有超时
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				slowConns = append(slowConns, SystemSlowConn{
					LocalAddr:  parts[3],
					RemoteAddr: parts[4],
					State:      "ESTABLISHED",
					Reason:     "连接存在超时计时器，可能是慢连接",
				})
			}
		}
	}
	return slowConns
}

// checkSlowConnectionsWindows 在 Windows 上通过 netstat 检测慢连接
func checkSlowConnectionsWindows(idleThreshold time.Duration) []SystemSlowConn {
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	var slowConns []SystemSlowConn
	lines := strings.Split(string(output), "\n")
	estabCount := 0
	for _, line := range lines {
		if !strings.Contains(line, "ESTABLISHED") {
			continue
		}
		estabCount++
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			slowConns = append(slowConns, SystemSlowConn{
				LocalAddr:  parts[1],
				RemoteAddr: parts[2],
				State:      "ESTABLISHED",
				Reason:     fmt.Sprintf("当前共 %d 个ESTABLISHED连接", estabCount),
			})
		}
	}

	// 如果 ESTABLISHED 连接过多，报告异常
	if estabCount > 5000 {
		slowConns = append(slowConns, SystemSlowConn{
			LocalAddr:  "N/A",
			RemoteAddr: "N/A",
			State:      "ESTABLISHED",
			Reason:     fmt.Sprintf("ESTABLISHED连接数 %d 过多，可能存在慢攻击或连接耗尽", estabCount),
		})
	}

	return slowConns
}

// checkSlowConnectionsNetstat 使用 netstat 作为降级方案
func checkSlowConnectionsNetstat(idleThreshold time.Duration) []SystemSlowConn {
	cmd := exec.Command("netstat", "-an")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	var slowConns []SystemSlowConn
	lines := strings.Split(string(output), "\n")
	synRecvCount := 0
	closeWaitCount := 0

	for _, line := range lines {
		upperLine := strings.ToUpper(line)
		if strings.Contains(upperLine, "SYN_RECV") {
			synRecvCount++
		}
		if strings.Contains(upperLine, "CLOSE_WAIT") {
			closeWaitCount++
		}
	}

	if synRecvCount > 100 {
		slowConns = append(slowConns, SystemSlowConn{
			LocalAddr:  "N/A",
			RemoteAddr: "N/A",
			State:      "SYN_RECV",
			Reason:     fmt.Sprintf("SYN_RECV 连接 %d 个，可能遭受 SYN Flood", synRecvCount),
		})
	}

	if closeWaitCount > 100 {
		slowConns = append(slowConns, SystemSlowConn{
			LocalAddr:  "N/A",
			RemoteAddr: "N/A",
			State:      "CLOSE_WAIT",
			Reason:     fmt.Sprintf("CLOSE_WAIT 连接 %d 个，应用层可能未正确关闭连接", closeWaitCount),
		})
	}

	return slowConns
}

// ============================================================
// 连接数限制检测
// ============================================================

// CheckConnLimit 检测文件描述符/连接数使用情况
// 返回当前使用情况和是否接近限制
func CheckConnLimit() (*ConnLimitInfo, error) {
	// 获取当前系统 FD 限制
	cmd := exec.Command("bash", "-c", "ulimit -n")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo 65536")
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("无法获取 FD 限制: %w", err)
	}

	limitStr := strings.TrimSpace(string(output))
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 65536 // 默认值
	}

	// 获取当前连接数
	conns, err := netproc.Connections("tcp")
	if err != nil {
		return nil, fmt.Errorf("无法获取连接数: %w", err)
	}

	info := &ConnLimitInfo{
		FDLimit:    limit,
		ConnCount:  len(conns),
		UsageRatio: float64(len(conns)) / float64(limit),
	}

	if info.UsageRatio > 0.8 {
		info.Warning = fmt.Sprintf("连接数 %d 已达 FD 限制 %d 的 %.1f%%，接近耗尽。建议：1) 增大 ulimit -n 2) 检查是否有连接泄漏 3) 优化连接池配置", len(conns), limit, info.UsageRatio*100)
	}

	return info, nil
}

// ConnLimitInfo 连接数限制信息
type ConnLimitInfo struct {
	FDLimit    int     `json:"fd_limit"`
	ConnCount  int     `json:"conn_count"`
	UsageRatio float64 `json:"usage_ratio"`
	Warning    string  `json:"warning,omitempty"`
}

// ============================================================
// 辅助函数
// ============================================================

// isPrivateIP 检查是否为私有 IP 地址
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// IPv4 私有地址
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 127:
			return true
		}
		return false
	}
	// IPv6 回环
	if ip.IsLoopback() {
		return true
	}
	// IPv6 链路本地地址 fe80::/10
	if len(ip) == 16 && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	return false
}
