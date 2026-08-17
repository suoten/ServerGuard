package attackwarn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/agent/tuning"
	"github.com/suoten/serverguard/internal/intel"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// AttackWarnGuard 攻击预警中心
type AttackWarnGuard struct {
	store             *storage.Storage
	firewallMgr       FirewallManager
	whitelist         *Whitelist
	banCounter        int
	mu                sync.Mutex
	maxBansPerEvent   int
	correlationEngine *CorrelationEngine // 关联引擎

	// 智能增强
	intel          IPIntelQuerier                 // 威胁情报查询器（可选）
	tuner          *tuning.ThresholdTuner         // 阈值自调优器（可选）
	persistentIPs  map[string]bool                // 持久攻击者集合
	handledAt      map[string]time.Time           // IP -> 上次处置时间，用于误报识别
}

// IPIntelQuerier 最小威胁情报查询接口，便于注入与测试。
type IPIntelQuerier interface {
	CheckIP(ctx context.Context, ip string) *intel.IPInfo
}

// 持久攻击者判定阈值常量。
const (
	persistentLookback       = 7 * 24 * time.Hour // 近 7 天
	persistentMinAttacks     = 30                 // 累计攻击次数阈值
	persistentMinDays        = 3                  // 攻击跨度（天）阈值
	persistentMinTypes       = 3                  // 攻击类型数阈值
	persistentProfileIDPrefix = "persistent:"     // attack_profiles 表中持久攻击者画像的稳定 ID 前缀
)

// FirewallManager 防火墙接口（与 platform.FirewallManager 对齐）
type FirewallManager interface {
	BanIP(ctx context.Context, ip string, duration time.Duration, reason string) error
	UnbanIP(ctx context.Context, ip string) error
	RateLimit(ctx context.Context, ip string, rate int) error
}

// Whitelist 白名单
type Whitelist struct {
	IPs map[string]bool
}

// NewWhitelist 创建白名单
func NewWhitelist() *Whitelist {
	return &Whitelist{IPs: make(map[string]bool)}
}

// IsWhitelisted 检查 IP+ 是否在白名单中
func (w *Whitelist) IsWhitelisted(ip string) bool {
	return w.IPs[ip]
}

// Add 添加白名单
func (w *Whitelist) Add(ip string) {
	w.IPs[ip] = true
}

// NewAttackWarnGuard 创建攻击预警中心
func NewAttackWarnGuard(store *storage.Storage, fwMgr FirewallManager) *AttackWarnGuard {
	wl := NewWhitelist()
	// 默认白名单：本机 + 常见内网网段，永不封禁
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0"} {
		wl.Add(ip)
	}
	return &AttackWarnGuard{
		store:             store,
		firewallMgr:       fwMgr,
		whitelist:         wl,
		maxBansPerEvent:   0, // 0 = 不设上限，始终允许封禁
		correlationEngine: NewCorrelationEngine(),
		persistentIPs:     make(map[string]bool),
		handledAt:         make(map[string]time.Time),
	}
}

// SetIntelChecker 注入威胁情报查询器（可选，未注入则不进行情报增强）。
func (g *AttackWarnGuard) SetIntelChecker(intel IPIntelQuerier) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.intel = intel
}

// SetThresholdTuner 注入阈值自调优器（可选，未注入则使用内置默认阈值）。
func (g *AttackWarnGuard) SetThresholdTuner(t *tuning.ThresholdTuner) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tuner = t
}

// isPrivateIP 检查是否为私有/内网 IP（不应被封禁）
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// 回环地址
	if ip.IsLoopback() {
		return true
	}
	// 私有地址段
	if ip.IsPrivate() {
		return true
	}
	// 链路本地
	if ip.IsLinkLocalUnicast() {
		return true
	}
	// 未指定地址
	if ip.IsUnspecified() {
		return true
	}
	return false
}

// SetCorrelationEngine 注入外部关联引擎。
func (g *AttackWarnGuard) SetCorrelationEngine(engine *CorrelationEngine) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.correlationEngine = engine
}

// GetCorrelationEngine 返回关联引擎。
func (g *AttackWarnGuard) GetCorrelationEngine() *CorrelationEngine {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.correlationEngine
}

// GetAttackProfiles 返回高置信度攻击画像（从关联引擎获取）。
func (g *AttackWarnGuard) GetAttackProfiles(threshold float64) []AttackProfile {
	g.mu.Lock()
	engine := g.correlationEngine
	g.mu.Unlock()
	if engine == nil {
		return nil
	}
	return engine.GetHighConfidenceProfiles(threshold)
}

// ResetBanCounter 重置封禁计数器（每小时调用一次，允许后续攻击继续封禁）。
func (g *AttackWarnGuard) ResetBanCounter() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.banCounter = 0
}

// AddWhitelist 添加白名单 IP
func (g *AttackWarnGuard) AddWhitelist(ip string) {
	g.whitelist.Add(ip)
}

// readTail 读取文件末尾最多 maxBytes 字节，避免将整个大文件加载到内存
func readTail(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err == nil && stat.Size() > maxBytes {
		_, err = f.Seek(-maxBytes, io.SeekEnd)
		if err != nil {
			_, _ = f.Seek(0, io.SeekStart)
		}
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// ScanWebAttacks Z1: 网站攻击实时预警
// 使用流式读取（bufio.Scanner），避免将整个日志文件加载到内存
func (g *AttackWarnGuard) ScanWebAttacks(ctx context.Context, logPath string) ([]types.AttackEvent, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 只读取最后 5000 行，避免大日志文件导致内存膨胀
	// 使用 Seek 从文件末尾读取
	const maxLines = 5000
	const tailSize = 512 * 1024 // 最多读 512KB

	var lines []string
	stat, err := f.Stat()
	if err == nil && stat.Size() > tailSize {
		// 从文件末尾读取最后 tailSize 字节
		_, err = f.Seek(-tailSize, io.SeekEnd)
		if err != nil {
			_, err = f.Seek(0, io.SeekStart)
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024) // 每行最多 256KB
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxLines {
			lines = lines[1:] // 滑动窗口，只保留最后 maxLines 行
		}
	}

	content := strings.Join(lines, "\n")

	var events []types.AttackEvent

	sqlInjectionEvents := g.detectSQLInjection(ctx, content, logPath)
	events = append(events, sqlInjectionEvents...)

	xssEvents := g.detectXSS(ctx, content, logPath)
	events = append(events, xssEvents...)

	ccEvents := g.detectCC(ctx, content, logPath)
	events = append(events, ccEvents...)

	webshellEvents := g.detectWebshellUpload(ctx, content, logPath)
	events = append(events, webshellEvents...)

	dirTraversalEvents := g.detectDirTraversal(ctx, content, logPath)
	events = append(events, dirTraversalEvents...)

	for _, event := range events {
		if s := g.intelSummary(ctx, event.SourceIP); s != "" {
			event.Detail += "\n" + s
		}
		if g.IsPersistentAttacker(event.SourceIP) {
			event.Detail += "\n⚠️ 持久攻击者：该 IP 长期/多类型攻击，已升级封禁"
		}
		_ = g.store.SaveAttackEvent(&storage.AttackEvent{
			ID:          event.ID,
			EventType:   event.EventType,
			SourceIP:    event.SourceIP,
			Target:      event.Target,
			Severity:    string(event.Severity),
			Detail:      event.Detail,
			ActionTaken: event.ActionTaken,
			TraceID:     event.TraceID,
			CreatedAt:   event.CreatedAt,
		})
		// 同时保存为 Finding，使 Findings 页面能统计攻击预警
		g.saveAttackFinding(event)
		// 喂入关联引擎
		g.mu.Lock()
		engine := g.correlationEngine
		g.mu.Unlock()
		if engine != nil {
			engine.Ingest(AttackEvent{
				SourceIP:   event.SourceIP,
				Module:     "Z1",
				AttackType: event.EventType,
				Timestamp:  event.CreatedAt,
				Severity:   string(event.Severity),
			})
		}
	}

	return events, nil
}

func (g *AttackWarnGuard) detectSQLInjection(ctx context.Context, content, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	patterns := []string{
		`' OR 1=1`, `' OR '1'='1`, `union select`, `UNION SELECT`,
		`sleep(`, `benchmark(`, `' AND 1=1`, `' AND 1=2`,
		`information_schema`, `load_file(`, `into outfile`,
		`' OR '1'='1' --`, `' OR '1'='1' #`, `' OR 1=1 --`,
		`'; DROP TABLE`, `'; INSERT INTO`, `'; UPDATE`,
		`xp_cmdshell`, `sp_executesql`, `0x[0-9a-fA-F]{8,}`,
		`concat(`, `group_concat(`, `char(`, `ascii(`, `ord(`,
		`hex(`, `unhex(`, `conv(`, `substring(`, `mid(`,
		`extractvalue(`, `updatexml(`, `ST_X`, `ST_Y`,
		`%27`, `%22`, `%20OR%20`, `%20UNION%20`, `%20SELECT%20`,
		`JSON_KEYS`, `JSON_EXTRACT`, `CAST(`, `CONVERT(`,
		`PROCEDURE ANALYSE`, `OUTFILE`, `DUMPFILE`,
	}

	logRegex := regexp.MustCompile(`^(\S+).*"(\S+) (\S+) .*" (\d+)`)
	for _, line := range strings.Split(content, "\n") {
		match := logRegex.FindStringSubmatch(line)
		if len(match) < 4 {
			continue
		}
		ip := match[1]
		url := match[3]

		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(url), strings.ToLower(pattern)) {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "sql_injection",
				SourceIP:  ip,
				Target:    logPath,
				Severity:  types.SeverityHigh,
				Detail:    fmt.Sprintf("SQL 注入攻击尝试，匹配特征: %s，攻击 URL: %s", pattern, url),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				event.ActionTaken = g.handleAttack(ctx, ip, "sql_injection", types.SeverityHigh)
				events = append(events, event)
				break
			}
		}
	}
	return events
}

func (g *AttackWarnGuard) detectXSS(ctx context.Context, content, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	patterns := []string{
		`<script`, `</script`, `onerror=`, `onload=`, `javascript:`,
		`<img src=x`, `alert(`, `document.cookie`, `document.write`,
		`<iframe`, `<object`, `<embed`, `<svg onload`,
		`onmouseover=`, `onclick=`, `onfocus=`, `onblur=`,
		`<body onload`, `<meta http-equiv`, `<link href`,
		`eval(`, `setTimeout(`, `setInterval(`, `Function(`,
		`String.fromCharCode`, `unescape(`, `decodeURIComponent`,
		`%3Cscript`, `%3C%73%63%72%69%70%74`, `&#x3C;script`,
		`data:text/html`, `vbscript:`, `<form action`,
		`window.location`, `window.open`, `location.href`,
		`<input onfocus`, `<details ontoggle`, `<marquee onstart`,
	}

	logRegex := regexp.MustCompile(`^(\S+).*"(\S+) (\S+) .*" (\d+)`)
	for _, line := range strings.Split(content, "\n") {
		match := logRegex.FindStringSubmatch(line)
		if len(match) < 4 {
			continue
		}
		ip := match[1]
		url := match[3]

		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(url), strings.ToLower(pattern)) {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "xss",
				SourceIP:  ip,
				Target:    logPath,
				Severity:  types.SeverityHigh,
				Detail:    fmt.Sprintf("XSS 跨站脚本攻击尝试，匹配特征: %s，攻击 URL: %s", pattern, url),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				event.ActionTaken = g.handleAttack(ctx, ip, "xss", types.SeverityHigh)
				events = append(events, event)
				break
			}
		}
	}
	return events
}

func (g *AttackWarnGuard) detectCC(ctx context.Context, content, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	logRegex := regexp.MustCompile(`^(\S+).*"(\S+) (\S+) .*" (\d+)`)

	ipRequestCount := make(map[string]int)

	for _, line := range strings.Split(content, "\n") {
		match := logRegex.FindStringSubmatch(line)
		if len(match) < 4 {
			continue
		}
		ip := match[1]
		// 跳过白名单和私有 IP，不产生误报事件
		if g.whitelist.IsWhitelisted(ip) || isPrivateIP(ip) {
			continue
		}
		ipRequestCount[ip]++
	}

	threshold := g.ccThreshold()
	for ip, count := range ipRequestCount {
		if float64(count) > threshold {
			event := types.AttackEvent{
				ID:        uuid.New().String(),
				EventType: "cc_attack",
				SourceIP:  ip,
				Target:    logPath,
				Severity:  types.SeverityHigh,
				Detail:    fmt.Sprintf("CC 攻击，该 IP 在日志期间发送了 %d 次请求（超过 %v 次阈值）", count, threshold),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
			event.ActionTaken = g.handleAttack(ctx, ip, "cc_attack", types.SeverityHigh)
			g.noteTuning(ip, "cc_attack")
			events = append(events, event)
		}
	}

	return events
}

func (g *AttackWarnGuard) detectWebshellUpload(ctx context.Context, content, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	patterns := []string{
		`eval(`, `base64_decode(`, `system(`, `exec(`, `passthru(`, `shell_exec(`,
		`assert(`, `preg_replace`, `create_function`, `call_user_func`,
		`popen(`, `proc_open(`, `pcntl_exec(`, `dl(`,
		`file_put_contents`, `fwrite`, `fputs`, `move_uploaded_file`,
		`$_POST[`, `$_GET[`, `$_REQUEST[`, `$_COOKIE[`, `$_FILES[`,
		`@eval`, `@system`, `@exec`, `@passthru`,
		`gzinflate(`, `gzuncompress(`, `str_rot13(`, `gzdecode(`,
		`chr(`, `pack(`, `sprintf(`, `urldecode(`,
	}

	logRegex := regexp.MustCompile(`^(\S+).*"(\S+) (\S+) .*" (\d+)`)
	for _, line := range strings.Split(content, "\n") {
		match := logRegex.FindStringSubmatch(line)
		if len(match) < 4 {
			continue
		}
		ip := match[1]
		method := match[2]
		url := match[3]

		if method == "POST" && strings.HasSuffix(url, ".php") {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "webshell_upload",
				SourceIP:  ip,
				Target:    logPath,
				Severity:  types.SeverityCritical,
				Detail:    fmt.Sprintf("Webshell 上传攻击，匹配特征: %s，目标文件: %s（可能导致远程代码执行）", pattern, url),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				event.ActionTaken = g.handleAttack(ctx, ip, "webshell_upload", types.SeverityCritical)
					events = append(events, event)
					break
				}
			}
		}
	}
	return events
}

func (g *AttackWarnGuard) detectDirTraversal(ctx context.Context, content, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	patterns := []string{
		`../`, `..\\`, `/etc/passwd`, `/etc/shadow`, `%2e%2e%2f`,
		`%2e%2e/`, `..%2f`, `..%5c`, `%2e%2e%5c`,
		`/proc/self/environ`, `/proc/self/fd`, `/proc/self/cmdline`,
		`/var/log/`, `C:\windows\win.ini`, `C:\windows\system32`,
		`/usr/local/etc/`, `/usr/share/`, `/root/.ssh/`,
		`/home/`, `/.ssh/id_rsa`, `/.ssh/authorized_keys`,
		`file://`, `php://filter`, `php://input`, `expect://`,
		`data://`, `phar://`, `zip://`, `glob://`,
	}

	logRegex := regexp.MustCompile(`^(\S+).*"(\S+) (\S+) .*" (\d+)`)
	for _, line := range strings.Split(content, "\n") {
		match := logRegex.FindStringSubmatch(line)
		if len(match) < 4 {
			continue
		}
		ip := match[1]
		url := match[3]

		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(url), strings.ToLower(pattern)) {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "dir_traversal",
				SourceIP:  ip,
				Target:    logPath,
				Severity:  types.SeverityMedium,
				Detail:    fmt.Sprintf("目录遍历攻击尝试，匹配特征: %s，攻击 URL: %s", pattern, url),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				event.ActionTaken = g.handleAttack(ctx, ip, "dir_traversal", types.SeverityMedium)
				events = append(events, event)
				break
			}
		}
	}
	return events
}

// ScanServerAttacks Z2: 服务器攻击实时预警
func (g *AttackWarnGuard) ScanServerAttacks(ctx context.Context) ([]types.AttackEvent, error) {
	var events []types.AttackEvent

	if sshEvents, err := g.detectSSHBruteForce(ctx); err == nil {
		events = append(events, sshEvents...)
	}
	if portScanEvents, err := g.detectPortScan(ctx); err == nil {
		events = append(events, portScanEvents...)
	}
	if ddosEvents, err := g.detectDDoS(ctx); err == nil {
		events = append(events, ddosEvents...)
	}

	for _, event := range events {
		if s := g.intelSummary(ctx, event.SourceIP); s != "" {
			event.Detail += "\n" + s
		}
		if g.IsPersistentAttacker(event.SourceIP) {
			event.Detail += "\n⚠️ 持久攻击者：该 IP 长期/多类型攻击，已升级封禁"
		}
		_ = g.store.SaveAttackEvent(&storage.AttackEvent{
			ID:          event.ID,
			EventType:   event.EventType,
			SourceIP:    event.SourceIP,
			Target:      event.Target,
			Severity:    string(event.Severity),
			Detail:      event.Detail,
			ActionTaken: event.ActionTaken,
			TraceID:     event.TraceID,
			CreatedAt:   event.CreatedAt,
		})
		// 同时保存为 Finding，使 Findings 页面能统计攻击预警
		g.saveAttackFinding(event)
		// 喂入关联引擎
		g.mu.Lock()
		engine := g.correlationEngine
		g.mu.Unlock()
		if engine != nil {
			engine.Ingest(AttackEvent{
				SourceIP:   event.SourceIP,
				Module:     "Z2",
				AttackType: event.EventType,
				Timestamp:  event.CreatedAt,
				Severity:   string(event.Severity),
			})
		}
	}

	return events, nil
}

func (g *AttackWarnGuard) detectSSHBruteForce(ctx context.Context) ([]types.AttackEvent, error) {
	var events []types.AttackEvent
	logPaths := []string{"/var/log/secure", "/var/log/auth.log"}

	for _, logPath := range logPaths {
		content, err := readTail(logPath, 256*1024) // 最多读 256KB
		if err != nil {
			continue
		}

		failRegex := regexp.MustCompile(`Failed password for .* from (\d+\.\d+\.\d+\.\d+)`)
		matches := failRegex.FindAllStringSubmatch(content, -1)

		ipFailCount := make(map[string]int)
		for _, match := range matches {
			if len(match) > 1 {
				ipFailCount[match[1]]++
			}
		}

		threshold := g.sshBruteThreshold()
		for ip, count := range ipFailCount {
			if float64(count) >= threshold {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "ssh_brute_force",
				SourceIP:  ip,
				Target:    "ssh",
				Severity:  types.SeverityHigh,
				Detail:    fmt.Sprintf("SSH 暴力破解，该 IP 在日志期间尝试失败登录 %d 次（超过 %v 次阈值），均已失败", count, threshold),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				event.ActionTaken = g.handleAttack(ctx, ip, "ssh_brute_force", types.SeverityHigh)
				g.noteTuning(ip, "ssh_brute_force")
				events = append(events, event)
			}
		}
		break
	}

	return events, nil
}

// detectPortScan Y2b: 端口扫描检测
// 通过分析 SSH 日志中的连接模式来检测端口扫描行为
func (g *AttackWarnGuard) detectPortScan(ctx context.Context) ([]types.AttackEvent, error) {
	var events []types.AttackEvent

	// 读取 SSH 日志，查找短时间内大量不同端口的连接尝试
	logPaths := []string{"/var/log/secure", "/var/log/auth.log"}
	for _, logPath := range logPaths {
		content, err := readTail(logPath, 256*1024) // 最多读 256KB
		if err != nil {
			continue
		}

		// 匹配 "Connection closed by invalid user ... port NNNN" 或 "Connection from ... port NNNN"
		connRegex := regexp.MustCompile(`(?:Connection closed by|Connection from|Failed password for).*?(\d+\.\d+\.\d+\.\d+) port (\d+)`)
		matches := connRegex.FindAllStringSubmatch(content, -1)

		// 统计每个 IP 连接的不同端口数
		ipPorts := make(map[string]map[int]bool)
		for _, match := range matches {
			if len(match) >= 3 {
				ip := match[1]
				var port int
				fmt.Sscanf(match[2], "%d", &port)
				if ipPorts[ip] == nil {
					ipPorts[ip] = make(map[int]bool)
				}
				ipPorts[ip][port] = true
			}
		}

		for ip, ports := range ipPorts {
			if len(ports) >= 10 { // 单 IP 探测 10+ 不同端口视为端口扫描
				portList := make([]string, 0, len(ports))
				for p := range ports {
					portList = append(portList, fmt.Sprintf("%d", p))
				}
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "port_scan",
				SourceIP:  ip,
				Target:    "ssh",
				Severity:  types.SeverityMedium,
				Detail:    fmt.Sprintf("端口扫描行为，该 IP 探测了 %d 个不同端口（前 10 个: %s），属于侦察行为", len(ports), strings.Join(portList[:min(10, len(portList))], ", ")),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				event.ActionTaken = g.handleAttack(ctx, ip, "port_scan", types.SeverityMedium)
				events = append(events, event)
			}
		}
		break // 只需读一个日志文件
	}

	return events, nil
}

// detectDDoS Y2c: DDoS 检测
// 通过检查网络连接数异常增长来检测可能的 DDoS 攻击
func (g *AttackWarnGuard) detectDDoS(ctx context.Context) ([]types.AttackEvent, error) {
	var events []types.AttackEvent

	// Linux: 使用 ss/netstat 统计连接数
	if runtime.GOOS == "linux" {
		// 统计每个 IP 的连接数
		cmd := exec.CommandContext(ctx, "ss", "-tn", "-o", "state", "established")
		output, err := cmd.Output()
		if err != nil {
			// 降级到 netstat
			cmd = exec.CommandContext(ctx, "netstat", "-tn")
			output, err = cmd.Output()
			if err != nil {
				return events, nil
			}
		}

		ipConnCount := make(map[string]int)
		for _, line := range strings.Split(string(output), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// 远程地址在倒数第二列（peer address）
			peerAddr := fields[len(fields)-2]
			// 提取 IP（去掉端口部分）
			addrParts := strings.Split(peerAddr, ":")
			if len(addrParts) < 2 {
				continue
			}
			ip := addrParts[0]
			// 处理 IPv6 地址 [::1]:443 格式
			ip = strings.TrimPrefix(strings.TrimSuffix(ip, "]"), "[")
			if ip == "" || ip == "0.0.0.0" || ip == "::" {
				continue
			}
			ipConnCount[ip]++
		}

		for ip, count := range ipConnCount {
			if count >= 100 { // 单 IP 100+ 并发连接视为可疑
				// 跳过白名单和私有 IP，不产生误报事件
				if g.whitelist.IsWhitelisted(ip) || isPrivateIP(ip) {
					continue
				}
				severity := types.SeverityMedium
				if count >= 500 {
					severity = types.SeverityHigh
				}
				if count >= 1000 {
					severity = types.SeverityCritical
				}
				event := types.AttackEvent{
					ID:        uuid.New().String(),
					EventType: "ddos_suspected",
					SourceIP:  ip,
					Target:    "server",
					Severity:  severity,
					Detail:    fmt.Sprintf("疑似 DDoS 攻击，该 IP 有 %d 个并发连接到服务器（100+ 为疑似，500+ 为高危，1000+ 为严重）", count),
					TraceID:   uuid.New().String(),
					CreatedAt: time.Now(),
				}
				event.ActionTaken = g.handleAttack(ctx, ip, "ddos_suspected", severity)
				events = append(events, event)
			}
		}
	}

	return events, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleAttack 处理攻击：自动处置 + 多重安全兜底
// 智能增强：威胁情报命中恶意 IP 或命中持久攻击者时，升级封禁时长并附注情报摘要。
func (g *AttackWarnGuard) handleAttack(ctx context.Context, ip, attackType string, severity types.Severity) string {
	// 白名单 IP 永不处置
	if g.whitelist.IsWhitelisted(ip) {
		return "whitelisted_skip"
	}

	// 私有/内网 IP 不处置（本机、局域网等）
	if isPrivateIP(ip) {
		return "skip_private_ip"
	}

	// 不再设封禁上限，所有恶意 IP 都执行封禁

	if g.firewallMgr == nil {
		return "alert_only"
	}

	duration := banDurationFor(severity)
	if duration == 0 {
		return "alert_only"
	}

	// 智能增强：威胁情报 + 持久攻击者
	note := ""
	g.mu.Lock()
	iq := g.intel
	persistent := g.persistentIPs[ip]
	g.mu.Unlock()

	if iq != nil {
		if info := iq.CheckIP(ctx, ip); info != nil && (info.Confidence >= 50 || info.AbuseReports > 0) {
			if duration < 24*time.Hour {
				duration = 24 * time.Hour
			}
			note = fmt.Sprintf(" 威胁情报: 置信度=%d%% 举报=%d次", info.Confidence, info.AbuseReports)
		}
	}
	if persistent {
		if severity == types.SeverityCritical {
			duration = 7 * 24 * time.Hour
		} else if duration < 24*time.Hour {
			duration = 24 * time.Hour
		}
		note += " ⚠️ 持久攻击者：该 IP 长期/多类型攻击，已升级封禁"
	}

	label := banActionLabel(duration)
	labelCN := banDurationLabel(duration)
	if err := g.firewallMgr.BanIP(ctx, ip, duration, fmt.Sprintf("attack:%s", attackType)); err != nil {
		g.recordAction("ban_ip", ip, fmt.Sprintf("自动封禁IP %s（%s）", labelCN, attackType), false, err)
		return fmt.Sprintf("ban_failed:%v", err)
	}
	// 记录审计日志 + 操作日志
	detail := fmt.Sprintf("自动封禁IP %s（%s）%s", labelCN, attackType, note)
	g.recordAudit("ban_ip", ip, detail, "success")
	g.recordAction("ban_ip", ip, detail, true, nil)
	return label
}

// CorrelateAttacks Z3: 攻击情报关联分析
func (g *AttackWarnGuard) CorrelateAttacks(ctx context.Context, since time.Time) ([]types.AttackProfile, error) {
	events, err := g.store.QueryAttackEvents("", "", "", since, 1000)
	if err != nil {
		return nil, err
	}

	ipEvents := make(map[string][]storage.AttackEvent)
	for _, event := range events {
		ipEvents[event.SourceIP] = append(ipEvents[event.SourceIP], event)
	}

	var profiles []types.AttackProfile
	for ip, ipEvents := range ipEvents {
		if len(ipEvents) < 1 {
			continue
		}

	attackTypes := make(map[string]bool)
	var firstSeen, lastSeen time.Time
	totalAttacks := 0
	criticalCount := 0
	highCount := 0
	for _, event := range ipEvents {
		attackTypes[event.EventType] = true
		totalAttacks++
		if event.Severity == "critical" {
			criticalCount++
		} else if event.Severity == "high" {
			highCount++
		}
		if firstSeen.IsZero() || event.CreatedAt.Before(firstSeen) {
			firstSeen = event.CreatedAt
		}
		if event.CreatedAt.After(lastSeen) {
			lastSeen = event.CreatedAt
		}
	}

		typesList := make([]string, 0, len(attackTypes))
		for t := range attackTypes {
			typesList = append(typesList, t)
		}

	confidence := 0.5
	if len(attackTypes) >= 3 {
		confidence = 0.9
	} else if len(attackTypes) >= 2 {
		confidence = 0.7
	}

	// 计算威胁等级
	threatLevel := "low"
	if criticalCount > 0 || totalAttacks >= 20 {
		threatLevel = "critical"
	} else if highCount > 0 || totalAttacks >= 10 {
		threatLevel = "high"
	} else if totalAttacks >= 5 {
		threatLevel = "medium"
	}

		profile := types.AttackProfile{
			ID:          uuid.New().String(),
			SourceIP:    ip,
			AttackTypes: typesList,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			Duration:    int64(lastSeen.Sub(firstSeen).Seconds()),
			Confidence:  confidence,
			Trend:       "stable",
		}

		profiles = append(profiles, profile)

		_ = g.store.SaveAttackProfile(&storage.AttackProfile{
			ID:           profile.ID,
			SourceIP:     profile.SourceIP,
			AttackTypes:  strings.Join(typesList, ","),
			TotalAttacks: totalAttacks,
			ThreatLevel:  threatLevel,
			FirstSeen:    profile.FirstSeen,
			LastSeen:     profile.LastSeen,
			Duration:     profile.Duration,
			Confidence:   profile.Confidence,
			Trend:        profile.Trend,
		})
	}

	return profiles, nil
}

// saveAttackFinding 将攻击事件同时保存为 Finding，使 Findings 页面能统计攻击预警
// 去重：同一 IP + 同一攻击类型，只保存一条 Finding（更新而非新增）
func (g *AttackWarnGuard) saveAttackFinding(event types.AttackEvent) {
	if g.store == nil {
		return
	}

	// 攻击类型中文映射
	typeLabels := map[string]string{
		"sql_injection":   "SQL注入攻击",
		"xss":             "XSS跨站脚本攻击",
		"cc_attack":       "CC攻击",
		"webshell_upload": "Webshell上传攻击",
		"dir_traversal":   "目录遍历攻击",
		"ssh_brute_force": "SSH暴力破解",
		"port_scan":       "端口扫描",
		"ddos_suspected":  "疑似DDoS攻击",
	}

	typeLabel := typeLabels[event.EventType]
	if typeLabel == "" {
		typeLabel = event.EventType
	}

	// 处置方式中文映射
	actionLabels := map[string]string{
		"alert_only":           "仅告警",
		"skip_private_ip":      "跳过（内网IP）",
		"whitelisted_skip":     "跳过（白名单）",
		"rate_limited_5rps":    "已限速 5req/s",
		"banned_2h":            "已封禁 2小时",
		"banned_1h":            "已封禁 1小时",
		"banned_30m":           "已封禁 30分钟",
		"banned_10m":           "已封禁 10分钟",
		"banned_24h":           "已封禁 24小时",
		"banned_7d":            "已封禁 7天",
		"ban_limit_alert_only": "封禁数量已达上限（仅告警）",
	}

	actionLabel := actionLabels[event.ActionTaken]
	if actionLabel == "" {
		actionLabel = event.ActionTaken
	}

	// 如果 IP 已被封禁（action_taken 以 banned_ 开头），则将 Finding 状态设为 resolved
	findingStatus := "open"
	if strings.HasPrefix(event.ActionTaken, "banned_") {
		findingStatus = "resolved"
	}

	_ = g.store.SaveFinding(&storage.Finding{
		Scanner:     "attackwarn",
		ScannerSub:  event.EventType,
		Severity:    string(event.Severity),
		Title:       fmt.Sprintf("%s: %s", typeLabel, event.SourceIP),
		Description: event.Detail,
		Target:      event.SourceIP,
		Detail:      event.Detail,
		Suggestion:  "建议在防火墙中封禁该恶意 IP，并检查服务器日志确认是否有数据泄露",
		Consequence: "如不及时处理，攻击者可能获取服务器权限、窃取数据或导致服务不可用",
		Status:      findingStatus,
	})
}

// EmergencyRollback 紧急回滚：清除所有 Z 模块添加的封禁规则
func (g *AttackWarnGuard) EmergencyRollback(ctx context.Context) error {
	if g.firewallMgr == nil {
		return nil
	}
	err := g.firewallMgr.UnbanIP(ctx, "all")
	g.recordAudit("emergency_rollback", "all", "用户手动解除所有封禁IP", "success")
	return err
}

// GetBannedIPs 获取已封禁的 IP 列表（查询 action_taken 以 banned_ 开头的攻击事件）
func (g *AttackWarnGuard) GetBannedIPs(ctx context.Context) ([]storage.AttackEvent, error) {
	return g.store.QueryBannedAttackEvents(500)
}

// intelSummary 返回某 IP 的威胁情报摘要；若 intel 为空或该 IP 不属恶意则返回空字符串。
// 仅当情报显示为恶意（置信度较高或存在举报）时返回，供告警 Detail 附注。
func (g *AttackWarnGuard) intelSummary(ctx context.Context, ip string) string {
	g.mu.Lock()
	iq := g.intel
	g.mu.Unlock()
	if iq == nil {
		return ""
	}
	info := iq.CheckIP(ctx, ip)
	if info == nil || !(info.Confidence >= 50 || info.AbuseReports > 0) {
		return ""
	}
	return fmt.Sprintf("威胁情报: 置信度=%d%% 举报=%d次 来源=%s",
		info.Confidence, info.AbuseReports, info.Country)
}

// UpdateLongTermProfiles 汇总近 7 天攻击事件，识别持久攻击者并写入 attack_profiles 表。
// 当一个 IP 满足「累计攻击次数 >= 30 或 攻击跨度 >= 3 天 或 攻击类型数 >= 3」时，
// 标记为持久攻击者(persistent_attacker)；已存在则更新 total_attacks / threat_level 等字段。
func (g *AttackWarnGuard) UpdateLongTermProfiles(ctx context.Context) error {
	if g.store == nil {
		return nil
	}
	events, err := g.store.QueryAttackEvents("", "", "", time.Now().Add(-persistentLookback), 10000)
	if err != nil {
		return err
	}

	// 按源 IP 聚合
	type agg struct {
		totalAttacks int
		firstSeen    time.Time
		lastSeen     time.Time
		attackTypes  map[string]bool
	}
	byIP := make(map[string]*agg)
	for _, ev := range events {
		if ev.SourceIP == "" {
			continue
		}
		a := byIP[ev.SourceIP]
		if a == nil {
			a = &agg{attackTypes: make(map[string]bool)}
			byIP[ev.SourceIP] = a
		}
		a.totalAttacks++
		if ev.EventType != "" {
			a.attackTypes[ev.EventType] = true
		}
		if a.firstSeen.IsZero() || ev.CreatedAt.Before(a.firstSeen) {
			a.firstSeen = ev.CreatedAt
		}
		if ev.CreatedAt.After(a.lastSeen) {
			a.lastSeen = ev.CreatedAt
		}
	}

	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	for ip, a := range byIP {
		spanDays := int(a.lastSeen.Sub(a.firstSeen).Hours() / 24)
		persistent := a.totalAttacks >= persistentMinAttacks ||
			spanDays >= persistentMinDays ||
			len(a.attackTypes) >= persistentMinTypes
		if persistent {
			g.persistentIPs[ip] = true
		}

		typesList := make([]string, 0, len(a.attackTypes))
		for t := range a.attackTypes {
			typesList = append(typesList, t)
		}

		threatLevel := "low"
		switch {
		case persistent:
			threatLevel = "critical"
		case a.totalAttacks >= 20:
			threatLevel = "critical"
		case a.totalAttacks >= 10:
			threatLevel = "high"
		case a.totalAttacks >= 5:
			threatLevel = "medium"
		}

		detail := ""
		if persistent {
			detail = "持久攻击者：该 IP 长期/多类型攻击，已标记为持久攻击者"
		}

		_ = g.store.SaveAttackProfile(&storage.AttackProfile{
			// 使用稳定 ID 实现 INSERT OR REPLACE，覆盖更新同一 IP 的画像行
			ID:           persistentProfileIDPrefix + ip,
			SourceIP:     ip,
			AttackTypes:  strings.Join(typesList, ","),
			TotalAttacks: a.totalAttacks,
			ThreatLevel:  threatLevel,
			FirstSeen:    a.firstSeen,
			LastSeen:     a.lastSeen,
			Duration:     int64(a.lastSeen.Sub(a.firstSeen).Seconds()),
			Confidence:   0.9,
			Trend:        "persistent",
			Detail:       detail,
			CreatedAt:    now,
		})
	}

	return nil
}

// IsPersistentAttacker 判断某 IP 是否已被标记为持久攻击者。
func (g *AttackWarnGuard) IsPersistentAttacker(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.persistentIPs[ip]
}

// ccThreshold 返回 CC 攻击判定阈值；已注入 tuner 时使用自调优阈值，否则使用默认 100。
func (g *AttackWarnGuard) ccThreshold() float64 {
	g.mu.Lock()
	t := g.tuner
	g.mu.Unlock()
	if t == nil {
		return 100
	}
	return t.SuggestThreshold("cc_attack", 100, 50, 500, 10)
}

// sshBruteThreshold 返回 SSH 暴破判定阈值；已注入 tuner 时使用自调优阈值，否则使用默认 10。
func (g *AttackWarnGuard) sshBruteThreshold() float64 {
	g.mu.Lock()
	t := g.tuner
	g.mu.Unlock()
	if t == nil {
		return 10
	}
	return t.SuggestThreshold("ssh_brute_force", 10, 5, 50, 2)
}

// noteTuning 记录一次告警触发的调优样本。
// 若同一 IP 在短时间内被反复处置（封禁后仍持续出现），视为误报（阈值可能过灵敏），否则记为正常触发。
func (g *AttackWarnGuard) noteTuning(ip, alertType string) {
	g.mu.Lock()
	t := g.tuner
	g.mu.Unlock()
	if t == nil {
		return
	}
	g.mu.Lock()
	last, ok := g.handledAt[ip]
	g.handledAt[ip] = time.Now()
	g.mu.Unlock()
	if ok && time.Since(last) < 30*time.Minute {
		t.RecordFalsePositive(alertType)
	} else {
		t.RecordFire(alertType)
	}
}

// banDurationFor 根据严重度返回基础封禁时长。
// 自动封禁对服务器本身无风险，仅阻断恶意IP的网络访问。
func banDurationFor(severity types.Severity) time.Duration {
	switch severity {
	case types.SeverityCritical:
		return 2 * time.Hour // 严重攻击封禁2小时
	case types.SeverityHigh:
		return 1 * time.Hour // 高危攻击封禁1小时
	case types.SeverityMedium:
		return 30 * time.Minute // 中危攻击封禁30分钟
	case types.SeverityLow:
		return 10 * time.Minute // 低危攻击封禁10分钟
	default:
		return 0
	}
}

// banDurationLabel 返回封禁时长的中文描述。
func banDurationLabel(d time.Duration) string {
	switch d {
	case 2 * time.Hour:
		return "2小时"
	case 1 * time.Hour:
		return "1小时"
	case 30 * time.Minute:
		return "30分钟"
	case 10 * time.Minute:
		return "10分钟"
	case 24 * time.Hour:
		return "24小时"
	case 7 * 24 * time.Hour:
		return "7天"
	default:
		return d.String()
	}
}

// banActionLabel 返回封禁时长的 Action 标识，供 saveAttackFinding 映射中文标签。
func banActionLabel(d time.Duration) string {
	switch d {
	case 2 * time.Hour:
		return "banned_2h"
	case 1 * time.Hour:
		return "banned_1h"
	case 30 * time.Minute:
		return "banned_30m"
	case 10 * time.Minute:
		return "banned_10m"
	case 24 * time.Hour:
		return "banned_24h"
	case 7 * 24 * time.Hour:
		return "banned_7d"
	default:
		return "banned"
	}
}

// recordAction 记录操作日志（显示在仪表盘"操作日志"和审计日志中）
func (g *AttackWarnGuard) recordAction(actionType, target, message string, success bool, err error) {
	if g.store == nil {
		return
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	_ = g.store.SaveAction("attack-warn", types.ActionResult{
		Action:    types.Action{Type: types.ActionBanIP, Params: map[string]interface{}{"target": target}},
		Success:   success,
		Message:   message,
		Error:     errMsg,
		Timestamp: time.Now(),
	})
}

// recordAudit 记录审计日志
func (g *AttackWarnGuard) recordAudit(action, target, reason, result string) {
	if g.store == nil {
		return
	}
	_ = g.store.SaveAudit(types.AuditEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Actor:     "system",
		Action:    action,
		Target:    target,
		Reason:    reason,
		Result:    result,
	})
}

// AnalyzeLogFiles 分析多个日志文件
func (g *AttackWarnGuard) AnalyzeLogFiles(ctx context.Context, logDir string) ([]types.AttackEvent, error) {
	var allEvents []types.AttackEvent

	logFiles := []string{"access.log", "nginx_access.log"}
	entries, err := os.ReadDir(logDir)
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), "access.log") || strings.Contains(e.Name(), "access") {
				logFiles = append(logFiles, e.Name())
			}
		}
	}

	for _, file := range logFiles {
		path := filepath.Join(logDir, file)
		if events, err := g.ScanWebAttacks(ctx, path); err == nil {
			allEvents = append(allEvents, events...)
		}
	}

	return allEvents, nil
}
