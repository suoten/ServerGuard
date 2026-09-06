package attackwarn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/agent/tuning"
	"github.com/suoten/serverguard/internal/guards/security"
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
	intel          IPIntelQuerier              // 威胁情报查询器（可选）
	tuner          *tuning.ThresholdTuner      // 旧版阈值自调优器（向后兼容，可选）
	baseline       *tuning.BaselineEngine       // 智能基线引擎（动态阈值 + 置信度评分）
	escalation     *tuning.EscalationTracker    // 渐进式响应追踪（observe → block）
	persistentIPs  map[string]bool               // 持久攻击者集合
	handledAt      map[string]time.Time          // IP -> 上次处置时间，用于误报识别
	rollback       *security.EmergencyRollback   // SSH 失联看门狗（封禁自锁兜底）
	recentEvents   map[string]time.Time          // 事件去重：ip|type|url摘要 -> 上次入库时间
	banCooldown    map[string]time.Time          // IP -> 上次实际封禁时间（冷却期内同 IP 不重复执行防火墙命令）
	banBudget      []time.Time                   // 封禁预算滑动窗口：防止一次扫描产生数百次 iptables 调用拖垮系统
}

// 事件去重窗口与容量上限。
// 每轮扫描都会重新分析同一段日志尾部，若不按"IP+类型+URL"去重，
// 同一次攻击每天会被重复入库几十次——这正是历史上"几千条误报"的主要来源。
// 【修复】从 6h 缩短到 30min：6h 太长导致 10 分钟扫描间隔下后续 35 轮全部被去重为 0，
// 仪表盘攻击预警数量持续为 0。30min 仍能覆盖同一轮内的重复事件，但不会跨太多轮次。
const (
	dedupWindow     = 30 * time.Minute // 同一事件 30 分钟内只入库一次
	dedupMaxEntries = 4096             // 去重表容量上限，超限回收过期条目，防止内存缓慢泄漏
)

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

// logLineRegex Nginx/Apache 访问日志行解析（包级预编译，避免每次调用重复编译）。
// 捕获组: 1=IP 2=Method 3=URL 4=Status
var logLineRegex = regexp.MustCompile(`^(\S+).*"(\S+) (\S+) .*" (\d+)`)

// sshFailRegex SSH 登录失败行
var sshFailRegex = regexp.MustCompile(`Failed password for .* from (\d+\.\d+\.\d+\.\d+)`)

// sshConnRegex SSH 连接/失败行（端口扫描检测用）
var sshConnRegex = regexp.MustCompile(`(?:Connection closed by|Connection from|Failed password for).*?(\d+\.\d+\.\d+\.\d+) port (\d+)`)

// uaTailRegex 提取 combined 格式日志行末尾两个带引号字段：Referer 与 User-Agent
var uaTailRegex = regexp.MustCompile(`"([^"]*)" "([^"]*)"\s*$`)

// webLogEntry 单条访问日志的结构化解析结果。
// ScanWebAttacks 对日志内容只做一次逐行解析，十个检测器共用，
// 避免每个检测器都重新 strings.Split 整段内容（500KB 日志 ×5 次分割纯属浪费）。
type webLogEntry struct {
	IP      string
	Method  string
	URL     string
	Status  string
	Raw     string // 完整日志行（含 Referer/User-Agent），供高置信度特征做整行匹配
	Referer string
	UA      string // User-Agent（扫描器识别依赖此字段）
}

// parseWebLogLines 将整段日志文本解析为结构化条目（一次分割，多次复用）。
func parseWebLogLines(content string) []webLogEntry {
	lines := strings.Split(content, "\n")
	entries := make([]webLogEntry, 0, len(lines))
	for _, line := range lines {
		m := logLineRegex.FindStringSubmatch(line)
		if len(m) < 5 {
			continue
		}
		entry := webLogEntry{IP: m[1], Method: m[2], URL: m[3], Status: m[4], Raw: line}
		if t := uaTailRegex.FindStringSubmatch(line); len(t) >= 3 {
			entry.Referer = t[1]
			entry.UA = t[2]
		}
		entries = append(entries, entry)
	}
	return entries
}

// NewAttackWarnGuard 创建攻击预警中心
func NewAttackWarnGuard(store *storage.Storage, fwMgr FirewallManager) *AttackWarnGuard {
	wl := NewWhitelist()
	// 默认白名单：本机 + 常见内网网段，永不封禁
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0"} {
		wl.Add(ip)
	}
	// 本机全部网卡地址（含公网出口 IP）一并入白名单——与 handleAttack 内的动态检查互为双保险
	for ip := range currentSelfIPs() {
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
		recentEvents:      make(map[string]time.Time),
		banCooldown:       make(map[string]time.Time),
		baseline:           tuning.NewBaselineEngine(),
		escalation:         tuning.NewEscalationTracker(),
		// SSH 失联看门狗：每次封禁后检测管理员是否被自己锁在门外。
		// 此前只有 security 模块的封禁有看门狗，Z 模块（主力封禁路径）却没有
		// ——封禁自锁时没有任何自动解封手段。
		rollback: security.NewEmergencyRollback(nil),
	}
}

// 封禁节流常量。
// 教训：请求级检测器曾对每条匹配日志直接执行 iptables，扫描器一次探测
// 数百个 URL 就会产生数百次防火墙调用，叠加规则不幂等导致 INPUT 链膨胀、
// 小型 VPS 整机负载被打满（"把服务器干崩溃"事故的根因）。
const (
	banCooldownWindow = 10 * time.Minute // 同一 IP 封禁冷却期：期内重复攻击不再执行防火墙命令
	banBudgetWindow   = 5 * time.Minute  // 预算滑动窗口时长
	banBudgetMax      = 30               // 窗口内最多实际封禁次数，超出部分只告警不动防火墙
)

// shouldRecordEvent 事件去重：同一 IP+类型+指纹 在 dedupWindow 内只入库一次。
// 指纹建议传入事件 Detail 的前缀（含攻击 URL/特征，粒度到单条请求），
// 返回 false 表示该事件是近期已入库事件的重复，应跳过（不落库、不告警、不计调优样本）。
// 攻击仍在持续时，窗口过期后下一次扫描会重新入库——不会漏掉持续攻击的最新动态。
func (g *AttackWarnGuard) shouldRecordEvent(ip, eventType, fingerprint string) bool {
	key := ip + "|" + eventType + "|" + fingerprint
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if last, ok := g.recentEvents[key]; ok && now.Sub(last) < dedupWindow {
		g.recentEvents[key] = now // 持续出现的攻击刷新时间戳，保持压制
		return false
	}
	// 容量兜底：超限时回收窗口外的旧条目（长期公网服务器会被扫描器塞满）
	if len(g.recentEvents) >= dedupMaxEntries {
		cutoff := now.Add(-dedupWindow)
		for k, at := range g.recentEvents {
			if at.Before(cutoff) {
				delete(g.recentEvents, k)
			}
		}
	}
	g.recentEvents[key] = now
	return true
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

// cgnatCIDR 运营商级 NAT 共享地址段（RFC6598），云厂商内网常使用该段
var cgnatCIDR = func() *net.IPNet {
	_, n, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return nil
	}
	return n
}()

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
	// 运营商级 NAT / 云内网共享段
	if cgnatCIDR != nil && ip.To4() != nil && cgnatCIDR.Contains(ip) {
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

// 本机网卡地址缓存：带 1 分钟 TTL 的惰性刷新。
// 动态检查而非仅启动时写白名单——DHCP 换 IP / 热插网卡后依然受保护。
var (
	selfIPMu     sync.RWMutex
	selfIPs      map[string]bool
	selfIPLoaded time.Time
)

// currentSelfIPs 返回本机全部网卡地址集合（IPv4/IPv6，含 IPv4-mapped 归一化形式）。
func currentSelfIPs() map[string]bool {
	selfIPMu.RLock()
	if selfIPs != nil && time.Since(selfIPLoaded) < time.Minute {
		defer selfIPMu.RUnlock()
		return selfIPs
	}
	selfIPMu.RUnlock()

	selfIPMu.Lock()
	defer selfIPMu.Unlock()
	if selfIPs != nil && time.Since(selfIPLoaded) < time.Minute {
		return selfIPs
	}

	set := make(map[string]bool)
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				default:
					continue
				}
				set[ip.String()] = true
				if v4 := ip.To4(); v4 != nil {
					set[v4.String()] = true
				}
			}
		}
	}
	selfIPs = set
	selfIPLoaded = time.Now()
	return set
}

// isSelfIP 判断目标 IP 是否为本机地址（任意网卡，含公网出口 IP）。
// 本机 IP 一旦被加入 INPUT DROP，服务器将无法访问自身的站点与服务，
// 属于"自残式封禁"，任何情况下都必须跳过。
func isSelfIP(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	set := currentSelfIPs()
	if set[parsed.String()] {
		return true
	}
	if v4 := parsed.To4(); v4 != nil {
		return set[v4.String()]
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

	// 只读取最后 2MB 日志（从 512KB 提升：宝塔站点日志通常较大，512KB 只能覆盖最近几十分钟，
	// 10 分钟扫描间隔下可能每轮读到相同的尾部内容，去重后返回 0）
	const tailSize = 2 * 1024 * 1024

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
	var sb strings.Builder
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
		if sb.Len() > tailSize*2 {
			// 超出预算即停：只分析最近的日志内容，避免大文件拖垮低配服务器
			break
		}
	}
	content := sb.String()

	// 一次性解析为结构化条目，五个检测器共用（原来每个检测器各自 Split 一遍）
	entries := parseWebLogLines(content)

	var events []types.AttackEvent

	sqlInjectionEvents := g.detectSQLInjection(ctx, entries, logPath)
	events = append(events, sqlInjectionEvents...)

	xssEvents := g.detectXSS(ctx, entries, logPath)
	events = append(events, xssEvents...)

	ccEvents := g.detectCC(ctx, entries, logPath)
	events = append(events, ccEvents...)

	webshellEvents := g.detectWebshellUpload(ctx, entries, logPath)
	events = append(events, webshellEvents...)

	dirTraversalEvents := g.detectDirTraversal(ctx, entries, logPath)
	events = append(events, dirTraversalEvents...)

	scannerUAEvents := g.detectScannerUA(ctx, entries, logPath)
	events = append(events, scannerUAEvents...)

	sensitiveProbeEvents := g.detectSensitiveProbe(ctx, entries, logPath)
	events = append(events, sensitiveProbeEvents...)

	codeInjectEvents := g.detectCodeInjection(ctx, entries, logPath)
	events = append(events, codeInjectEvents...)

	cmsBruteEvents := g.detectCMSBruteForce(ctx, entries, logPath)
	events = append(events, cmsBruteEvents...)

	dirBruteEvents := g.detectDirBruteForce(ctx, entries, logPath)
	events = append(events, dirBruteEvents...)

	for _, event := range events {
		// 去重：同 IP+类型+攻击指纹 6 小时内只入库一次（根治每轮扫描重复入库导致的误报洪流）
		if !g.shouldRecordEvent(event.SourceIP, event.EventType, eventFingerprint(event)) {
			continue
		}
		// 处置统一在去重之后执行：检测器只负责发现，封禁经由 tryBan 节流，
		// 确保同一扫描周期内不会对同一 IP / 同一指纹反复调用防火墙
		// 但如果检测器已标记为 observe_only，则不执行封禁
		if event.ActionTaken != "observe_only" {
			event.ActionTaken = g.tryBan(ctx, event.SourceIP, event.EventType, event.Severity)
		}
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

func (g *AttackWarnGuard) detectSQLInjection(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	// URL 匹配：常规注入特征（查询串中的探测 payload）
	// 注入特征分两类：
	// A. 完整注入 payload（自身即攻击签名，出现即判）
	// B. 高危函数/语法（需要搭配 SQL 上下文才算注入，单独出现可能误报，需上下文验证）
	// 注入特征分两类：
	// A. 完整注入 payload（自身即攻击签名，出现即判）——这些 payload 正常业务
	// 和数据库管理工具的 URL 中都**不可能**出现，只有真正注入时才有
	// B. 高危函数/语法（需要搭配 SQL 上下文才算注入，单独出现可能误报，需上下文验证）
	patterns := []string{
		// A 类：完整注入 payload——正常 URL 中不会出现，包括 phpMyAdmin
		`' OR 1=1`, `' OR '1'='1`, `' AND 1=1`, `' AND 1=2`,
		`' OR '1'='1' --`, `' OR '1'='1' #`, `' OR 1=1 --`,
		`'; DROP TABLE`, `'; INSERT INTO`, `'; UPDATE`,
		`union select`, `UNION SELECT`,
		`xp_cmdshell`, `sp_executesql`,
		`PROCEDURE ANALYSE`,
	}
	// B 类：高危函数/关键字——单独出现在 URL 中可能是 phpMyAdmin/数据库管理工具的
	// 正常操作（浏览 information_schema 数据库、导出时含 OUTFILE/load_file 等），
	// 需搭配 SQL 注入上下文（引号 + SQL 关键字组合）才算注入。
	// 历史误报案例：
	// - phpMyAdmin 导出数据时 URL 含 OUTFILE/concat/hex 等正常函数名
	// - phpMyAdmin 浏览系统数据库时 URL 含 db=information_schema
	// - phpMyAdmin 执行查询时 URL 含 sleep(/benchmark( 等函数名
	highRiskFuncs := []string{
		`concat(`, `group_concat(`, `char(`, `ascii(`, `ord(`,
		`hex(`, `unhex(`, `conv(`, `substring(`, `mid(`,
		`CAST(`, `CONVERT(`, `JSON_KEYS`, `JSON_EXTRACT`,
		`OUTFILE`, `DUMPFILE`,
		`information_schema`, `load_file(`, `into outfile`,
		`sleep(`, `benchmark(`,
		`extractvalue(`, `updatexml(`,
	}
	// SQL 上下文标志：只有 B 类函数同时搭配以下标志才算注入
	sqlCtxMarkers := []string{
		`'`, `%27`, `"`, `%22`, `--`, `%20--`, `#`, `%23`,
		`union`, `select`, `or%201`, `and%201`, `or 1`, `and 1`,
		`0x`, `0x[`, `from`, `where`, `into`,
	}
	// 注：已移除裸 `%27`/`%22`（正常站内搜索对引号做 URL 编码即触发，纯误报源）
	// 与 `0x[0-9a-f]{8,}`（正常 token/hash 参数即可命中）。
	// 已移除裸 `%20OR%20`/`%20UNION%20`/`%20SELECT%20`（正常搜索词被 URL 编码即触发）
	// 已移除裸 OUTFILE/DUMPFILE/concat/hex/char 等（phpMyAdmin 正常操作即触发）

	// 整行匹配的高置信度特征：sqlmap 等工具的注入 payload 常位于
	// User-Agent / Referer 而非请求 URL，只查 URL 会漏掉这类真实攻击。
	// 工具名本身（sqlmap/havij 等）由 detectScannerUA 按 UA 统一分类，避免同一请求双重计数。
	rawPatterns := []string{
		`union select`, `UNION SELECT`,
		// information_schema/load_file/into outfile/sleep/benchmark/extractvalue/updatexml
		// 已移至 B 类：phpMyAdmin 正常操作会在 UA/Referer 中包含这些词
	}

	for _, entry := range entries {
		matched := ""
		lowerURL := strings.ToLower(entry.URL)

		// A 类特征：完整注入 payload，出现即判
		for _, pattern := range patterns {
			if strings.Contains(lowerURL, strings.ToLower(pattern)) {
				matched = pattern
				break
			}
		}

		// B 类特征：高危函数 + SQL 上下文标志同时出现才算注入
		// 避免 phpMyAdmin 导出数据时 URL 含 OUTFILE/concat 等正常函数名被误判
		if matched == "" {
			hasSQLCtx := false
			for _, marker := range sqlCtxMarkers {
				if strings.Contains(lowerURL, strings.ToLower(marker)) {
					hasSQLCtx = true
					break
				}
			}
			if hasSQLCtx {
				for _, fn := range highRiskFuncs {
					if strings.Contains(lowerURL, strings.ToLower(fn)) {
						matched = fn + "（搭配SQL上下文）"
						break
					}
				}
			}
		}

		if matched == "" {
			lowerRaw := strings.ToLower(entry.Raw)
			for _, pattern := range rawPatterns {
				if strings.Contains(lowerRaw, pattern) {
					matched = pattern + "（UA/Referer）"
					break
				}
			}
		}
		if matched == "" {
			continue
		}
		// phpMyAdmin/数据库管理后台的正常操作不判注入
		// URL 中含 phpmyadmin/adminer 等路径的请求，其 OUTFILE/concat 等
		// 来自面板自身的 SQL 功能，非外部注入
		if isDBAdminURL(lowerURL) && !isSQLInjectionPayload(matched) {
			continue
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "sql_injection",
			SourceIP:  entry.IP,
			Target:    logPath,
			Severity:  types.SeverityHigh,
			Detail:    fmt.Sprintf("SQL 注入攻击尝试，匹配特征: %s，攻击 URL: %s", matched, entry.URL),
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		events = append(events, event)
	}
	return events
}

func (g *AttackWarnGuard) detectXSS(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	patterns := []string{
		`<script`, `</script`, `onerror=`, `onload=`, `javascript:`,
		`<img src=x`, `alert(`, `document.cookie`, `document.write`,
		`<iframe`, `<object`, `<embed`, `<svg onload`,
		`<body onload`, `<link href`,
		`String.fromCharCode`, `%3Cscript`, `&#x3C;script`,
		`data:text/html`, `<form action`,
	}
	// 注：已移除 eval(/setTimeout(/Function(/window.location/location.href
	// ——这些是 JavaScript 正常函数名/属性，在 URL 搜索参数中出现不等于 XSS 攻击
	// 已移除 onmouseover/onclick/onfocus/onblur 等常见 DOM 事件属性
	//（正常前端框架的 URL 参数即可命中，误报率高），以及 decodeURIComponent、
	// vbscript: 等过泛特征；保留的均为 URL 中出现即属探测的特征。

	// 整行高置信度特征：反射型 XSS 探测常通过 Referer 注入（如
	// Referer: https://evil/<script>...），只查 URL 会漏报。
	rawPatterns := []string{
		`<script>alert`, `<svg onload`, `<img src=x onerror`, `javascript:void(document.cookie`,
	}

	for _, entry := range entries {
		matched := ""
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(entry.URL), strings.ToLower(pattern)) {
				matched = pattern
				break
			}
		}
		if matched == "" {
			lowerRaw := strings.ToLower(entry.Raw)
			for _, pattern := range rawPatterns {
				if strings.Contains(lowerRaw, pattern) {
					matched = pattern + "（UA/Referer）"
					break
				}
			}
		}
		if matched == "" {
			continue
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "xss",
			SourceIP:  entry.IP,
			Target:    logPath,
			Severity:  types.SeverityHigh,
			Detail:    fmt.Sprintf("XSS 跨站脚本攻击尝试，匹配特征: %s，攻击 URL: %s", matched, entry.URL),
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		events = append(events, event)
	}
	return events
}

// ccStat 记录单个 IP 的多维请求特征，用于区分正常浏览与真实 CC 攻击。
//
// 设计哲学：数量不判攻击，行为才判攻击。
// 管理员一天刷几万次面板是正常运维，CC 工具可能只发几百次但全是恶意压测。
// 判定 CC 攻击需要同时满足以下条件（AND 逻辑，条件越多越难误判）：
//   1. 动态请求数超过阈值（去掉静态资源 .css/.js/.png 等）
//   2. URL 集中度高：最频繁 URL 占比 ≥ 60%（正常浏览 URL 高度分散）
//   3. 无 Referer 比例高：CC 工具通常不带 Referer（浏览器自带）
//   4. 有 User-Agent 标记为工具/爬虫：已知攻击工具 UA（sqlmap/nikto 等）
//   5. POST 请求占比异常高：CC 压测常用 POST
// 只要同时命中上述 3+ 条件，才判定为 CC 攻击。
type ccStat struct {
	total       int            // 总请求数（含静态资源）
	dynamic     int            // 去除静态资源后的动态请求数
	postCount   int            // POST 请求数
	noReferer   int            // 无 Referer 的动态请求数
	urlCounter  map[string]int // 每个动态 URL 路径的命中次数
	hasToolUA   bool           // 是否命中已知攻击工具 UA
}

// staticResourceExt 常见静态资源后缀——浏览器加载页面时自动请求，
// 不应计入 CC 攻击判断（真实攻击者不会拿带宽去刷 .css/.png）。
var staticResourceExt = map[string]bool{
	".css": true, ".js": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".map": true, ".webp": true, ".avif": true,
}

// isStaticResource 判断 URL 路径是否为静态资源（CSS/JS/图片/字体）。
func isStaticResource(url string) bool {
	path := url
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	path = strings.ToLower(path)
	for ext := range staticResourceExt {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func (g *AttackWarnGuard) detectCC(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent

	ipStat := make(map[string]*ccStat)

	for _, entry := range entries {
		if g.whitelist.IsWhitelisted(entry.IP) || isPrivateIP(entry.IP) || isSelfIP(entry.IP) {
			continue
		}
		stat := ipStat[entry.IP]
		if stat == nil {
			stat = &ccStat{urlCounter: make(map[string]int)}
			ipStat[entry.IP] = stat
		}
		stat.total++
		if isStaticResource(entry.URL) {
			continue // 静态资源不参与后续所有分析
		}
		stat.dynamic++
		if entry.Method == "POST" {
			stat.postCount++
		}
		if entry.Referer == "" || entry.Referer == "-" {
			stat.noReferer++
		}
		// 检查是否命中已知攻击工具 UA
		if !stat.hasToolUA {
			ua := strings.ToLower(entry.UA)
			for _, token := range scannerUATokens {
				if strings.Contains(ua, token) {
					stat.hasToolUA = true
					break
			}
			}
		}
		// 以路径（去掉查询参数）作为 URL 指纹
		urlKey := entry.URL
		if idx := strings.IndexByte(urlKey, '?'); idx >= 0 {
			urlKey = urlKey[:idx]
		}
		stat.urlCounter[urlKey]++
	}

	// 智能阈值：优先使用基线引擎动态计算，回退到旧版 tuner 或默认值
	threshold := g.smartCCThreshold()
	for ip, stat := range ipStat {
		// 记录基线样本——每轮都把各 IP 的动态请求数喂入基线引擎
		g.recordCCBaseline(ip, stat.dynamic)

		// 条件 1：动态请求数必须超过智能阈值
		if float64(stat.dynamic) <= threshold {
			continue
		}
		// 找出被请求最多的 URL
		topURL := ""
		topCount := 0
		for u, c := range stat.urlCounter {
			if c > topCount {
				topURL = u
				topCount = c
			}
		}
		// 行为特征维度（用于置信度评分，不再用固定阈值硬判）
		topRatio := 0.0
		if stat.dynamic > 0 {
			topRatio = float64(topCount) / float64(stat.dynamic)
		}
		noRefRatio := 0.0
		if stat.dynamic > 0 {
			noRefRatio = float64(stat.noReferer) / float64(stat.dynamic)
		}
		postRatio := 0.0
		if stat.dynamic > 0 {
			postRatio = float64(stat.postCount) / float64(stat.dynamic)
		}

		// z-score：当前请求数偏离该 IP 历史基线的程度
		zScore := g.ccDeviationScore(ip, float64(stat.dynamic))

		// 置信度评分：多维度交叉验证，单一维度达标不等于攻击
		factors := []tuning.ConfidenceFactor{
			{
				Name:     "请求数超阈值",
				Score:    30,
				Weight:   0.15,
				Triggered: float64(stat.dynamic) > threshold,
				Detail:   fmt.Sprintf("动态请求%d次（阈值%.0f）", stat.dynamic, threshold),
			},
			{
				Name:     "URL集中度高",
				Score:    30,
				Weight:   0.25,
				Triggered: topRatio >= 0.6,
				Detail:   fmt.Sprintf("最频繁URL占比%.0f%%（%s被打%d次）", topRatio*100, topURL, topCount),
			},
			{
				Name:     "无Referer比例高",
				Score:    25,
				Weight:   0.20,
				Triggered: noRefRatio >= 0.7,
				Detail:   fmt.Sprintf("无Referer占比%.0f%%", noRefRatio*100),
			},
			{
				Name:     "命中攻击工具UA",
				Score:    40,
				Weight:   0.25,
				Triggered: stat.hasToolUA,
				Detail:   "已知攻击工具User-Agent",
			},
			{
				Name:     "POST占比异常",
				Score:    20,
				Weight:   0.10,
				Triggered: postRatio >= 0.8,
				Detail:   fmt.Sprintf("POST占比%.0f%%", postRatio*100),
			},
			{
				Name:     "偏离历史基线",
				Score:    35,
				Weight:   0.05,
				Triggered: zScore > 2.0,
				Detail:   fmt.Sprintf("z-score=%.1f（偏离历史均值%.1f个标准差）", zScore, zScore),
			},
		}

		confResult := tuning.ScoreConfidence(factors, tuning.DefaultConfidenceThresholds)

		// 渐进式响应：首次触发只观察，连续触发才升级封禁
		finalDecision := g.escalation.Track(ip, "cc_attack", confResult.Decision)

		if finalDecision == "ignore" {
			continue
		}

		// 根据最终决策设定严重度
		severity := types.SeverityMedium
		if finalDecision == "block" {
			severity = types.SeverityHigh
		}

		// 构建详情
		reasons := make([]string, 0, len(confResult.Factors))
		for _, f := range confResult.Factors {
			reasons = append(reasons, f.Detail)
		}

		detail := fmt.Sprintf("CC 攻击（置信度%.0f分，决策:%s）：%s；动态请求%d次（智能阈值%.0f），总请求%d次",
			confResult.Score, finalDecision, strings.Join(reasons, "；"), stat.dynamic, threshold, stat.total)

		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "cc_attack",
			SourceIP:  ip,
			Target:    logPath,
			Severity:  severity,
			Detail:    detail,
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		if finalDecision == "observe" {
			event.ActionTaken = "observe_only"
		}
		g.noteTuning(ip, "cc_attack")
		events = append(events, event)
	}

	return events
}

func (g *AttackWarnGuard) detectWebshellUpload(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	// 只保留高置信度的 webshell 特征组合，移除常见 PHP 标准函数
	patterns := []string{
		`eval(base64_decode(`, `eval(gzinflate(`, `eval(gzuncompress(`, `eval(str_rot13(`, `eval(gzdecode(`,
		`assert(`, `create_function`, `call_user_func`,
		`@eval`, `@system`, `@exec`, `@passthru`,
		`pcntl_exec(`, `proc_open(`, `popen(`,
		`$_POST[`, `$_GET[`, `$_REQUEST[`,
	}

	for _, entry := range entries {
		if entry.Method == "POST" && strings.HasSuffix(entry.URL, ".php") {
			for _, pattern := range patterns {
				// 只在 URL 部分检测，而非整个日志行（避免误报）
				if strings.Contains(strings.ToLower(entry.URL), strings.ToLower(pattern)) {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "webshell_upload",
				SourceIP:  entry.IP,
				Target:    logPath,
				Severity:  types.SeverityCritical,
				Detail:    fmt.Sprintf("Webshell 上传攻击，匹配特征: %s，目标文件: %s（可能导致远程代码执行）", pattern, entry.URL),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
					events = append(events, event)
					break
				}
			}
		}
	}
	return events
}

func (g *AttackWarnGuard) detectDirTraversal(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	// 移除常见合法路径（/home/, /var/log/ 等），只保留明确的遍历/攻击特征
	patterns := []string{
		`../`, `..\`, `/etc/passwd`, `/etc/shadow`, `%2e%2e%2f`,
		`%2e%2e/`, `..%2f`, `..%5c`, `%2e%2e%5c`,
		`/proc/self/environ`, `/proc/self/fd`, `/proc/self/cmdline`,
		`C:\windows\win.ini`, `C:\windows\system32`,
		`/root/.ssh/`, `/.ssh/id_rsa`, `/.ssh/authorized_keys`,
		`php://filter`, `php://input`, `expect://`,
		`phar://`, `data://text/plain`,
	}

	for _, entry := range entries {
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(entry.URL), strings.ToLower(pattern)) {
				event := types.AttackEvent{
					ID:        uuid.New().String(),
				EventType: "dir_traversal",
				SourceIP:  entry.IP,
				Target:    logPath,
				Severity:  types.SeverityMedium,
				Detail:    fmt.Sprintf("目录遍历攻击尝试，匹配特征: %s，攻击 URL: %s", pattern, entry.URL),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
				events = append(events, event)
				break
			}
		}
	}
	return events
}

// isDBAdminURL 判断 URL 是否指向数据库管理后台（phpMyAdmin/Adminer 等）。
// 这些后台的 URL 中天然含 SQL 函数名（OUTFILE/concat 等），属于正常操作而非注入。
func isDBAdminURL(lowerURL string) bool {
	dbAdminPaths := []string{
		`phpmyadmin`, `adminer`, `pma`, `myadmin`, `dbadmin`,
		`phpmanager`, `mysqladmin`, `admin/mysql`, `adminer.php`,
	}
	for _, p := range dbAdminPaths {
		if strings.Contains(lowerURL, p) {
			return true
		}
	}
	return false
}

// isSQLInjectionPayload 判断匹配到的特征是否为真正的注入 payload（A 类），
// 而非依赖上下文验证的 B 类高危函数。
// 用于 isDBAdminURL 排除时保留真正的注入告警——
// 即使在 phpMyAdmin 后台 URL 中，如果匹配到 `' OR 1=1` 等完整注入 payload，
// 仍然判定为攻击（有人在 phpMyAdmin 页面上被注入）。
func isSQLInjectionPayload(matched string) bool {
	// B 类特征以"（搭配SQL上下文）"结尾，不是完整 payload
	if strings.Contains(matched, "（搭配SQL上下文）") {
		return false
	}
	// UA/Referer 来源的也不在此排除范围
	if strings.Contains(matched, "（UA/Referer）") {
		return true
	}
	return true
}

// scannerUATokens 已知攻击/扫描工具的 User-Agent 特征（小写匹配）。
// 只收录"正常业务不会出现"的工具名，通用库（python-requests、Go-http-client 等）不收录以免误报。
var scannerUATokens = []string{
	`sqlmap`, `nikto`, `nessus`, `openvas`, `masscan`, `zgrab`, `nuclei`,
	`dirbuster`, `gobuster`, `wfuzz`, `ffuf`, `wpscan`, `whatweb`,
	`acunetix`, `netsparker`, `arachni`, `w3af`, `havij`,
	`metasploit`, `sqlninja`, `nmap scripting engine`,
}

// detectScannerUA W10: 扫描器探测
// 攻击前的自动化漏洞扫描（sqlmap/nikto/goby 等）都会暴露工具 UA，
// 宝塔免费防火墙的"恶意UA拦截"即覆盖此类，这里对齐补齐。
func (g *AttackWarnGuard) detectScannerUA(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	for _, entry := range entries {
		ua := strings.ToLower(entry.UA)
		if ua == "" || ua == "-" {
			continue
		}
		matched := ""
		for _, token := range scannerUATokens {
			if strings.Contains(ua, token) {
				matched = token
				break
			}
		}
		if matched == "" {
			continue
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "web_scanner",
			SourceIP:  entry.IP,
			Target:    logPath,
			Severity:  types.SeverityMedium,
			Detail: fmt.Sprintf("扫描器探测，User-Agent 命中已知攻击工具特征: %s，请求: %s %s（通常为漏洞挖掘前奏，后续往往跟随注入/爆破）", matched, entry.Method, entry.URL),
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		events = append(events, event)
	}
	return events
}

// sensitiveFileTokens 敏感文件/备份文件探测特征（对解码后的小写 URL 匹配）。
// 对齐宝塔"禁止的URL扩展名/敏感文件访问"，覆盖 .env/.git/.sql 等信息收集类攻击。
var sensitiveFileTokens = []string{
	`.env`, `.git`, `.svn`, `.hg`, `.ds_store`, `.htaccess`, `.htpasswd`,
	`web.config`, `.sql`, `.bak`, `phpinfo`, `adminer`, `wp-config`,
	`id_rsa`, `.aws/credentials`,
}

// detectSensitiveProbe W11: 敏感文件探测
func (g *AttackWarnGuard) detectSensitiveProbe(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	for _, entry := range entries {
		haystack := decodeURLLower(entry.URL)
		matched := ""
		for _, token := range sensitiveFileTokens {
			if strings.Contains(haystack, token) {
				matched = token
				break
			}
		}
		if matched == "" {
			continue
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "sensitive_probe",
			SourceIP:  entry.IP,
			Target:    logPath,
			Severity:  types.SeverityMedium,
			Detail: fmt.Sprintf("敏感文件探测，尝试访问受保护资源（特征: %s），URL: %s——常见于信息收集阶段，一旦命中可能泄露配置、源码或数据库凭据", matched, entry.URL),
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		events = append(events, event)
	}
	return events
}

// codeInjectTokens 远程代码执行类 payload 特征（对解码后的小写 URL 匹配）。
// 覆盖 ThinkPHP RCE、PHP 代码注入、Log4j JNDI、命令拼接等宝塔重点拦截类型。
var codeInjectTokens = []string{
	`call_user_func`, `invokefunction`, `\think\`, `eval(`, `base64_decode(`,
	`assert(`, `system(`, `passthru(`, `${jndi:`,
	`|whoami`, `;whoami`, `$(whoami)`, "`whoami`",
	`wget http`, `curl http`,
}

// detectCodeInjection W12: 代码执行/命令注入
func (g *AttackWarnGuard) detectCodeInjection(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	for _, entry := range entries {
		haystack := decodeURLLower(entry.URL)
		matched := ""
		for _, token := range codeInjectTokens {
			if strings.Contains(haystack, token) {
				matched = token
				break
			}
		}
		if matched == "" {
			continue
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "code_injection",
			SourceIP:  entry.IP,
			Target:    logPath,
			Severity:  types.SeverityCritical,
			Detail: fmt.Sprintf("远程代码执行攻击，URL 携带可执行 payload（特征: %s），URL: %s——一旦成功可直接控制服务器", matched, entry.URL),
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		events = append(events, event)
	}
	return events
}

const (
	cmsBruteMinPosts     = 20 // 对 wp-login.php/xmlrpc.php 的 POST 达到该次数判定为后台爆破（从10提高到20：正常调试后台可能登录几次）
	dirBruteMinDistinct  = 50 // 单 IP 404 且 URL 各不相同达到该数量判定为目录字典枚举（从30提高到50：正常网站死链+调试可能产生30+个404）
	dirBruteSampleLimit  = 5  // 事件详情中最多附带的样例路径数
)

// detectCMSBruteForce W13: CMS 后台登录爆破
// 对 wp-login.php / xmlrpc.php 的高频 POST 是 WordPress 爆破的标准形态。
// 提高 20 次：正常调试后台登录不会 POST 20 次；暴破工具一次跑几十个密码。
// 加入响应码分析：暴破通常全是 401/403（登录失败），正常登录成功后 200/302。
func (g *AttackWarnGuard) detectCMSBruteForce(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent
	type cmsStat struct {
		count  int
		status map[string]int
	}
	stats := make(map[string]*cmsStat)
	for _, entry := range entries {
		if entry.Method != "POST" {
			continue
		}
		u := decodeURLLower(entry.URL)
		if !strings.Contains(u, "wp-login.php") && !strings.Contains(u, "xmlrpc.php") {
			continue
		}
		if g.whitelist.IsWhitelisted(entry.IP) || isPrivateIP(entry.IP) || isSelfIP(entry.IP) {
			continue
		}
		s := stats[entry.IP]
		if s == nil {
			s = &cmsStat{status: make(map[string]int)}
			stats[entry.IP] = s
		}
		s.count++
		s.status[entry.Status]++
	}
	for ip, s := range stats {
		// 记录基线样本
		g.recordCMSBruteBaseline(ip, s.count)

		// 智能阈值
		threshold := g.smartCMSBruteThreshold()
		if float64(s.count) < threshold {
			continue
		}
		// 分析响应码：如果 200/302 占比高，可能是正常登录调试（成功登录返回 302）
		// 如果 401/403/500 占比高，是暴破失败
		failCount := 0
		for code, c := range s.status {
			if strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") {
				failCount += c
			}
		}
		failRatio := float64(failCount) / float64(s.count)
		detail := fmt.Sprintf("后台登录爆破，该 IP 在日志期间对 WordPress 登录/xmlrpc 接口发起 %d 次 POST（≥%.0f 判定为爆破），失败率 %.0f%%", s.count, threshold, failRatio*100)
		if failRatio < 0.5 {
			detail += "（⚠️ 成功率较高，可能是正常调试，非自动化暴破）"
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "cms_bruteforce",
			SourceIP:  ip,
			Target:    logPath,
			Severity:  types.SeverityHigh,
			Detail:    detail,
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		g.noteTuning(ip, "cms_bruteforce")
		events = append(events, event)
	}
	return events
}

// detectDirBruteForce W14: 目录字典枚举
// 批量探测不存在的路径（404 海量且各不相同）是目录爆破器/dirsearch 的典型行为。
// 智能改进：不仅看 404 数量，还要看 404 占比——
// 正常用户浏览网站时大部分请求是 200，偶尔几个 404（死链/输错地址）；
// 目录爆破工具几乎全是 404（字典里的路径大部分不存在）。
// 404 占比 >= 70% + 绝对数量 >= 50 才判定为爆破。
func (g *AttackWarnGuard) detectDirBruteForce(ctx context.Context, entries []webLogEntry, logPath string) []types.AttackEvent {
	var events []types.AttackEvent

	type scanState struct {
		notFound int     // 404 数量
		total    int     // 总请求数
		sample   []string
	}
	states := make(map[string]*scanState)
	for _, entry := range entries {
		if g.whitelist.IsWhitelisted(entry.IP) || isPrivateIP(entry.IP) || isSelfIP(entry.IP) {
			continue
		}
		s := states[entry.IP]
		if s == nil {
			s = &scanState{}
			states[entry.IP] = s
		}
		s.total++
		if entry.Status == "404" {
			s.notFound++
			if len(s.sample) < dirBruteSampleLimit {
				s.sample = append(s.sample, entry.URL)
			}
		}
	}
	for ip, s := range states {
		// 记录基线样本
		g.recordDirBruteBaseline(ip, s.notFound)

		// 智能阈值
		dirThreshold := g.smartDirBruteThreshold()
		if float64(s.notFound) < dirThreshold {
			continue
		}
		// 404 占比检查：正常浏览 404 占比 < 10%，爆破工具 404 占比 > 70%
		// 占比 < 50% 的一律不判定为爆破（说明该 IP 大部分请求是正常的）
		notFoundRatio := float64(s.notFound) / float64(s.total)
		if notFoundRatio < 0.5 {
			continue
		}
		event := types.AttackEvent{
			ID:        uuid.New().String(),
			EventType: "dir_bruteforce",
			SourceIP:  ip,
			Target:    logPath,
			Severity:  types.SeverityMedium,
			Detail: fmt.Sprintf("目录爆破探测，该 IP 在日志期间命中 %d 个不存在路径（≥%.0f 判定为字典枚举），404占比 %.0f%%（总请求 %d），样例: %s",
				s.notFound, dirThreshold, notFoundRatio*100, s.total, strings.Join(s.sample, " , ")),
			TraceID:   uuid.New().String(),
			CreatedAt: time.Now(),
		}
		g.noteTuning(ip, "dir_bruteforce")
		events = append(events, event)
	}
	return events
}

// decodeURLLower 将 URL 解码（最多两轮，处理双重编码）并转小写，
// 使 %2Eenv、${jndi} 等编码变体也能命中明文特征；解码失败回退原文。
func decodeURLLower(raw string) string {
	decoded := raw
	for i := 0; i < 2; i++ {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	return strings.ToLower(decoded)
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
		// 去重：同 IP+类型+攻击指纹 6 小时内只入库一次（与 Z1 同策略）
		if !g.shouldRecordEvent(event.SourceIP, event.EventType, eventFingerprint(event)) {
			continue
		}
		// 处置统一在去重之后执行（与 Z1 相同的 tryBan 节流闸门）
		// 但如果检测器已标记为 observe_only（置信度不足或渐进式响应观察期），
		// 则不执行封禁，只入库告警
		if event.ActionTaken != "observe_only" {
			event.ActionTaken = g.tryBan(ctx, event.SourceIP, event.EventType, event.Severity)
		}
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

// fingerprintOf 生成事件去重指纹：Detail 中已包含"匹配特征 + 攻击 URL/次数"等
// 稳定信息，取前 160 字符足以区分不同请求，同时避免超长 key 占用内存。
func fingerprintOf(detail string) string {
	if len(detail) > 160 {
		return detail[:160]
	}
	return detail
}

// eventFingerprint 返回事件的去重指纹。
// SQLi/XSS/Webshell/目录遍历等"单请求"类事件以攻击 URL 为指纹；
// CC/SSH暴破/DDoS/端口扫描等"计数聚合"类事件的次数随日志增长每轮都在变，
// 若计入指纹则去重永远不命中，因此只按 IP+类型 去重。
func eventFingerprint(event types.AttackEvent) string {
	switch event.EventType {
	case "cc_attack", "ssh_brute_force", "ddos_suspected", "port_scan", "cms_bruteforce", "dir_bruteforce":
		return ""
	default:
		return fingerprintOf(event.Detail)
	}
}

// sshBruteRegexFull 匹配 SSH 失败日志并提取用户名，用于区分暴破（多用户名）和人工输错（单用户名）
var sshBruteRegexFull = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)`)

func (g *AttackWarnGuard) detectSSHBruteForce(ctx context.Context) ([]types.AttackEvent, error) {
	var events []types.AttackEvent
	logPaths := []string{"/var/log/secure", "/var/log/auth.log", "/var/log/security", "/var/log/messages"}

	for _, logPath := range logPaths {
		content, err := readTail(logPath, 1024*1024) // 最多读 1MB
		if err != nil {
			continue
		}

		matches := sshBruteRegexFull.FindAllStringSubmatch(content, -1)

		type sshStat struct {
			failCount int
			usernames map[string]bool
		}
		ipStat := make(map[string]*sshStat)

		for _, match := range matches {
			if len(match) < 3 {
				continue
			}
			username := match[1]
			ip := match[2]
			if ipStat[ip] == nil {
				ipStat[ip] = &sshStat{usernames: make(map[string]bool)}
			}
			ipStat[ip].failCount++
			ipStat[ip].usernames[username] = true
		}

		// 智能阈值：基线引擎动态计算或回退默认 30
		threshold := g.smartSSHBruteThreshold()
		if threshold < 10 {
			threshold = 10
		}
		for ip, stat := range ipStat {
			// 记录基线样本
			g.recordSSHBruteBaseline(ip, stat.failCount)

			if float64(stat.failCount) < threshold {
				continue
			}
			// 智能判断：暴破工具会尝试多个用户名，人工输错通常只有一个用户名
			usernameCount := len(stat.usernames)

			// z-score 偏离度
			zScore := g.sshDeviationScore(ip, float64(stat.failCount))

			// 置信度评分
			factors := []tuning.ConfidenceFactor{
				{
					Name:      "失败次数超阈值",
					Score:     35,
					Weight:    0.40,
					Triggered: float64(stat.failCount) >= threshold,
					Detail:    fmt.Sprintf("失败%d次（阈值%.0f）", stat.failCount, threshold),
				},
				{
					Name:      "多用户名尝试",
					Score:     40,
					Weight:    0.35,
					Triggered: usernameCount >= 3,
					Detail:    fmt.Sprintf("涉及%d个不同用户名", usernameCount),
				},
				{
					Name:      "偏离历史基线",
					Score:     30,
					Weight:    0.15,
					Triggered: zScore > 2.0,
					Detail:    fmt.Sprintf("z-score=%.1f", zScore),
				},
				{
					Name:      "单用户名大量失败",
					Score:     20,
					Weight:    0.10,
					Triggered: usernameCount <= 1 && stat.failCount >= 50,
					Detail:    "单用户名但失败次数极高（>=50）",
				},
			}
			confResult := tuning.ScoreConfidence(factors, tuning.DefaultConfidenceThresholds)
			finalDecision := g.escalation.Track(ip, "ssh_brute_force", confResult.Decision)
			if finalDecision == "ignore" {
				continue
			}

			severity := types.SeverityMedium
			if finalDecision == "block" || usernameCount >= 3 {
				severity = types.SeverityHigh
			}
			if usernameCount <= 1 && stat.failCount < 50 {
				severity = types.SeverityMedium
				confResult.Factors = append(confResult.Factors, tuning.ConfidenceFactor{
					Name: "人工输错提示", Score: 0, Weight: 0, Triggered: true,
					Detail: "⚠️ 单用户名多次失败，可能是管理员密码记错，非自动化暴破",
				})
			}

			reasons := make([]string, 0, len(confResult.Factors))
			for _, f := range confResult.Factors {
				reasons = append(reasons, f.Detail)
			}
			detail := fmt.Sprintf("SSH 暴力破解（置信度%.0f分，决策:%s）：失败%d次（智能阈值%.0f），%s",
				confResult.Score, finalDecision, stat.failCount, threshold, strings.Join(reasons, "；"))

			event := types.AttackEvent{
				ID:        uuid.New().String(),
				EventType: "ssh_brute_force",
				SourceIP:  ip,
				Target:    "ssh",
				Severity:  severity,
				Detail:    detail,
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
			if finalDecision == "observe" {
				event.ActionTaken = "observe_only"
			}
			g.noteTuning(ip, "ssh_brute_force")
			events = append(events, event)
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
	logPaths := []string{"/var/log/secure", "/var/log/auth.log", "/var/log/security", "/var/log/messages"}
	for _, logPath := range logPaths {
		content, err := readTail(logPath, 1024*1024) // 最多读 1MB
		if err != nil {
			continue
		}

		// 匹配 "Connection closed by invalid user ... port NNNN" 或 "Connection from ... port NNNN"
		matches := sshConnRegex.FindAllStringSubmatch(content, -1)

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
			// 记录基线样本
			g.recordPortScanBaseline(ip, len(ports))

			// 智能阈值
			portScanThreshold := g.smartPortScanThreshold()
			if float64(len(ports)) >= portScanThreshold {
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
				events = append(events, event)
			}
		}
		break // 只需读一个日志文件
	}

	return events, nil
}

// detectDDoS Y2c: DDoS 检测
// 通过检查网络连接数异常增长来检测可能的 DDoS 攻击
// 提高阈值到 500+：正常浏览宝塔面板+多站点维护，浏览器会保持多个 keep-alive 连接，
// 100 个并发连接轻松达到，不能作为 DDoS 判定依据。真正的 DDoS 通常 500+ 甚至上千。
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

		// 智能阈值：基线引擎动态计算或回退默认 500
		ddosThreshold := g.smartDDoSThreshold()

		// 收集基线样本
		baselineSamples := make([]tuning.BaselineSample, 0, len(ipConnCount))
		for ip, count := range ipConnCount {
			baselineSamples = append(baselineSamples, tuning.BaselineSample{
				IP: ip, Timestamp: time.Now(), ConnCount: count,
			})
		}
		g.mu.Lock()
		b := g.baseline
		g.mu.Unlock()
		if b != nil {
			b.RecordSample("ddos_suspected", baselineSamples)
		}

		for ip, count := range ipConnCount {
			if float64(count) < ddosThreshold {
				continue
			}
			if g.whitelist.IsWhitelisted(ip) || isPrivateIP(ip) || isSelfIP(ip) {
				continue
			}

			// z-score 偏离度
			zScore := 0.0
			if b != nil {
				zScore = b.IPDeviationScore("ddos_suspected", ip, float64(count))
			}

			// 置信度评分：连接数 + z-score + 历史记录
			factors := []tuning.ConfidenceFactor{
				{
					Name:      "连接数超阈值",
					Score:     40,
					Weight:    0.50,
					Triggered: float64(count) >= ddosThreshold,
					Detail:    fmt.Sprintf("并发连接%d（阈值%.0f）", count, ddosThreshold),
				},
				{
					Name:      "偏离历史基线",
					Score:     35,
					Weight:    0.30,
					Triggered: zScore > 2.0,
					Detail:    fmt.Sprintf("z-score=%.1f", zScore),
				},
				{
					Name:      "连接数极高",
					Score:     30,
					Weight:    0.20,
					Triggered: count >= 1000,
					Detail:    fmt.Sprintf("连接数%d（>=1000为极高）", count),
				},
			}
			confResult := tuning.ScoreConfidence(factors, tuning.DefaultConfidenceThresholds)
			finalDecision := g.escalation.Track(ip, "ddos_suspected", confResult.Decision)
			if finalDecision == "ignore" {
				continue
			}

			severity := types.SeverityMedium
			if count >= 1000 || finalDecision == "block" {
				severity = types.SeverityHigh
			}
			if count >= 2000 {
				severity = types.SeverityCritical
			}
			event := types.AttackEvent{
				ID:        uuid.New().String(),
				EventType: "ddos_suspected",
				SourceIP:  ip,
				Target:    "server",
				Severity:  severity,
				Detail:    fmt.Sprintf("疑似 DDoS 攻击（置信度%.0f分，决策:%s），该 IP 有 %d 个并发连接（智能阈值%.0f），z-score=%.1f", confResult.Score, finalDecision, count, ddosThreshold, zScore),
				TraceID:   uuid.New().String(),
				CreatedAt: time.Now(),
			}
			events = append(events, event)
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

// tryBan 带节流的封禁入口：所有检测器必须经由本函数处置攻击 IP，
// 严禁在逐行循环中直接调用防火墙。
// 两道闸门：
//  1. 同 IP 冷却期——冷却期内重复攻击只告警（返回 already_banned），不重复执行 iptables；
//     同时天然合并"同一扫描器打几百个 URL"的场景为一次真实封禁
//  2. 滑动窗口预算——窗口内实际封禁次数到达上限后只告警（ban_budget_exhausted），
//     保证即使遭遇大规模分布式扫描，防火墙调用频率也有硬性天花板
func (g *AttackWarnGuard) tryBan(ctx context.Context, ip, attackType string, severity types.Severity) string {
	g.mu.Lock()
	now := time.Now()
	if last, ok := g.banCooldown[ip]; ok && now.Sub(last) < banCooldownWindow {
		g.mu.Unlock()
		return "already_banned"
	}
	kept := g.banBudget[:0]
	for _, at := range g.banBudget {
		if now.Sub(at) < banBudgetWindow {
			kept = append(kept, at)
		}
	}
	g.banBudget = kept
	if len(g.banBudget) >= banBudgetMax {
		g.mu.Unlock()
		return "ban_budget_exhausted"
	}
	g.banBudget = append(g.banBudget, now)
	g.banCooldown[ip] = now
	// 冷却表容量兜底：超限回收窗口外的旧条目
	if len(g.banCooldown) > 4096 {
		cutoff := now.Add(-banCooldownWindow)
		for k, at := range g.banCooldown {
			if at.Before(cutoff) {
				delete(g.banCooldown, k)
			}
		}
	}
	g.mu.Unlock()

	return g.handleAttack(ctx, ip, attackType, severity)
}

// handleAttack 处理攻击：自动处置 + 多重安全兜底
// 智能增强：威胁情报命中恶意 IP 或命中持久攻击者时，升级封禁时长并附注情报摘要。
func (g *AttackWarnGuard) handleAttack(ctx context.Context, ip, attackType string, severity types.Severity) string {
	// 本机任意网卡地址（含公网出口 IP）永不封禁——封自己的公网 IP = 服务器自断
	if isSelfIP(ip) {
		return "skip_self_ip"
	}

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
	// 封禁成功后启动 SSH 失联看门狗（防自锁兜底）
	if g.rollback != nil {
		g.rollback.OnBanCalled(ip)
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
		"web_scanner":     "Web扫描器探测",
		"sensitive_probe": "敏感文件探测",
		"code_injection":  "远程代码执行攻击",
		"cms_bruteforce":  "后台登录爆破",
		"dir_bruteforce":  "目录爆破探测",
	}

	typeLabel := typeLabels[event.EventType]
	if typeLabel == "" {
		typeLabel = event.EventType
	}

	// 处置方式中文映射
	actionLabels := map[string]string{
		"alert_only":           "仅告警",
		"skip_self_ip":         "跳过（本机IP）",
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
		"already_banned":       "封禁冷却中（近期已封）",
		"ban_budget_exhausted": "封禁预算已满（仅告警）",
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

	// 稳定 ID（类型+IP）：配合 INSERT OR REPLACE 实现同 IP 同攻击类型只占一行，
	// 反复扫描更新同一行而非无限插入——否则 findings 表随事件量无界增长
	_ = g.store.SaveFinding(&storage.Finding{
		ID:          fmt.Sprintf("attackwarn:%s:%s", event.EventType, event.SourceIP),
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

// smartCCThreshold 返回 CC 攻击智能阈值。
// 优先使用基线引擎动态计算（P95 × 倍率），回退到旧版 tuner，最终回退默认 100。
func (g *AttackWarnGuard) smartCCThreshold() float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b != nil {
		return b.SuggestThreshold("cc_attack", "", 100, 30, 1000, 2.5)
	}
	g.mu.Lock()
	t := g.tuner
	g.mu.Unlock()
	if t == nil {
		return 100
	}
	return t.SuggestThreshold("cc_attack", 100, 50, 500, 10)
}

// recordCCBaseline 记录一轮 CC 检测的基线样本。
func (g *AttackWarnGuard) recordCCBaseline(ip string, dynamicReq int) {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return
	}
	b.RecordSample("cc_attack", []tuning.BaselineSample{
		{IP: ip, Timestamp: time.Now(), DynamicReq: dynamicReq},
	})
}

// ccDeviationScore 返回某 IP 当前动态请求数的 z-score。
func (g *AttackWarnGuard) ccDeviationScore(ip string, current float64) float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return 0
	}
	return b.IPDeviationScore("cc_attack", ip, current)
}

// smartSSHBruteThreshold 返回 SSH 暴破智能阈值。
// 优先使用基线引擎动态计算，回退到旧版 tuner，最终回退默认 30。
func (g *AttackWarnGuard) smartSSHBruteThreshold() float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b != nil {
		return b.SuggestThreshold("ssh_brute_force", "", 30, 10, 200, 2.5)
	}
	g.mu.Lock()
	t := g.tuner
	g.mu.Unlock()
	if t == nil {
		return 30
	}
	return t.SuggestThreshold("ssh_brute_force", 10, 5, 50, 2)
}

// recordSSHBruteBaseline 记录 SSH 暴破基线样本。
func (g *AttackWarnGuard) recordSSHBruteBaseline(ip string, failCount int) {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return
	}
	b.RecordSample("ssh_brute_force", []tuning.BaselineSample{
		{IP: ip, Timestamp: time.Now(), SSHFailCount: failCount},
	})
}

// sshDeviationScore 返回某 IP SSH 失败次数的 z-score。
func (g *AttackWarnGuard) sshDeviationScore(ip string, current float64) float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return 0
	}
	return b.IPDeviationScore("ssh_brute_force", ip, current)
}

// smartDDoSThreshold 返回 DDoS 智能阈值。
// 优先使用基线引擎动态计算，回退默认 500。
func (g *AttackWarnGuard) smartDDoSThreshold() float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b != nil {
		return b.SuggestThreshold("ddos_suspected", "", 500, 100, 5000, 2.5)
	}
	return 500
}

// recordDDoSBaseline 记录 DDoS 基线样本。
func (g *AttackWarnGuard) recordDDoSBaseline(ip string, connCount int) {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return
	}
	b.RecordSample("ddos_suspected", []tuning.BaselineSample{
		{IP: ip, Timestamp: time.Now(), ConnCount: connCount},
	})
}

// ddosDeviationScore 返回某 IP 连接数的 z-score。
func (g *AttackWarnGuard) ddosDeviationScore(ip string, current float64) float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return 0
	}
	return b.IPDeviationScore("ddos_suspected", ip, current)
}

// smartCMSBruteThreshold 返回 CMS 爆破智能阈值。
func (g *AttackWarnGuard) smartCMSBruteThreshold() float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b != nil {
		return b.SuggestThreshold("cms_bruteforce", "", 20, 5, 200, 2.5)
	}
	return 20
}

// recordCMSBruteBaseline 记录 CMS 爆破基线样本。
func (g *AttackWarnGuard) recordCMSBruteBaseline(ip string, postCount int) {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return
	}
	b.RecordSample("cms_bruteforce", []tuning.BaselineSample{
		{IP: ip, Timestamp: time.Now(), PostCount: postCount},
	})
}

// smartDirBruteThreshold 返回目录爆破智能阈值。
func (g *AttackWarnGuard) smartDirBruteThreshold() float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b != nil {
		return b.SuggestThreshold("dir_bruteforce", "", 50, 10, 500, 2.5)
	}
	return 50
}

// recordDirBruteBaseline 记录目录爆破基线样本。
func (g *AttackWarnGuard) recordDirBruteBaseline(ip string, notFound404 int) {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return
	}
	b.RecordSample("dir_bruteforce", []tuning.BaselineSample{
		{IP: ip, Timestamp: time.Now(), NotFound404: notFound404},
	})
}

// smartPortScanThreshold 返回端口扫描智能阈值。
func (g *AttackWarnGuard) smartPortScanThreshold() float64 {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b != nil {
		return b.SuggestThreshold("port_scan", "", 30, 10, 200, 2.5)
	}
	return 30
}

// recordPortScanBaseline 记录端口扫描基线样本。
func (g *AttackWarnGuard) recordPortScanBaseline(ip string, portCount int) {
	g.mu.Lock()
	b := g.baseline
	g.mu.Unlock()
	if b == nil {
		return
	}
	b.RecordSample("port_scan", []tuning.BaselineSample{
		{IP: ip, Timestamp: time.Now(), PortCount: portCount},
	})
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
	// handledAt 以攻击 IP 为 key，只增不删——长期运行的公网服务器会被
	// 扫描器塞进成千上万个 IP，造成缓慢内存泄漏。超限时回收 24h 未更新的条目。
	if len(g.handledAt) > 2048 {
		cutoff := time.Now().Add(-24 * time.Hour)
		for k, at := range g.handledAt {
			if at.Before(cutoff) {
				delete(g.handledAt, k)
			}
		}
	}
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
// 注意：
//   - 只扫描未压缩的 .log 文本日志（压缩包 .log.gz 不当纯文本解析）
//   - 排除错误日志（*.error.log / error.log）——错误格式与访问日志不同且无攻击探测价值
//   - 文件名含 access 的优先扫描；随后补充其余站点日志。
//     此前只认文件名含 "access" 的文件——宝塔站点日志命名为 www.域名.com.log，
//     导致宝塔环境下 Z1 网站攻击检测整体静默失效（0 结果的直接原因）
//   - 同优先级内按修改时间倒序——多站点服务器优先扫最近活跃的站点日志，
//     冷站点的陈旧日志即使被截断也不影响近期攻击的发现
//   - 单目录默认最多分析 48 个文件（116 站点场景下旧上限 16 会让大多数站点
//     从未被扫描，是"宝塔有告警而本工具没有"的主要覆盖面缺口）；
//     可用环境变量 SG_Z1_MAX_LOG_FILES 调整
func (g *AttackWarnGuard) AnalyzeLogFiles(ctx context.Context, logDir string) ([]types.AttackEvent, error) {
	var allEvents []types.AttackEvent

	type logCandidate struct {
		name string
		mod  time.Time
	}
	var priorityFiles, otherFiles []logCandidate
	entries, err := os.ReadDir(logDir)
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".log") {
				continue
			}
			lower := strings.ToLower(name)
			// 排除错误日志与错误日志变体
			if strings.Contains(lower, ".error.") || lower == "error.log" {
				continue
			}
			mod := time.Time{}
			if info, infoErr := e.Info(); infoErr == nil {
				mod = info.ModTime()
			}
			candidate := logCandidate{name: name, mod: mod}
			if strings.Contains(lower, "access") {
				priorityFiles = append(priorityFiles, candidate)
			} else {
				otherFiles = append(otherFiles, candidate)
			}
		}
	}

	sort.Slice(priorityFiles, func(i, j int) bool { return priorityFiles[i].mod.After(priorityFiles[j].mod) })
	sort.Slice(otherFiles, func(i, j int) bool { return otherFiles[i].mod.After(otherFiles[j].mod) })

	logFiles := append(priorityFiles, otherFiles...)
	maxFiles := z1MaxLogFiles()
	if len(logFiles) > maxFiles {
		logFiles = logFiles[:maxFiles]
	}

	for _, file := range logFiles {
		select {
		case <-ctx.Done():
			return allEvents, ctx.Err()
		default:
		}
		path := filepath.Join(logDir, file.name)
		if events, err := g.ScanWebAttacks(ctx, path); err == nil {
			allEvents = append(allEvents, events...)
		}
	}

	return allEvents, nil
}

// z1MaxLogFiles 返回单目录扫描的日志文件数上限，可用 SG_Z1_MAX_LOG_FILES 覆盖默认值 48。
func z1MaxLogFiles() int {
	if v := strings.TrimSpace(os.Getenv("SG_Z1_MAX_LOG_FILES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 48
}
