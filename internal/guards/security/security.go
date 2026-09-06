package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/intel"
	"github.com/suoten/serverguard/internal/platform"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// SecurityGuard implements Module C: Security Guard
// Covers: brute force protection, web attack defense, file tamper detection,
// abnormal process detection, remote login alert, CORS hardening, traffic anomaly
type SecurityGuard struct {
	mu             sync.RWMutex
	eventBus       *eventbus.EventBus
	storage        *storage.Storage
	safety         *safety.SafetyManager // 安全管理器引用，用于宝塔安全模式判断
	bruteThreshold int
	bruteWindow    time.Duration
	banDuration    time.Duration
	banProgression bool
	excludeIPs     map[string]bool
	monitorPaths   map[string]string // path -> expected hash
	sshLogPath     string
	authLogPath    string

	// Login failure tracking: IP -> timestamps
	loginFailures map[string][]time.Time
	// Banned IPs: IP -> ban expiry
	bannedIPs map[string]time.Time
	// Known good file hashes for tamper detection
	fileHashes map[string]string
	// Baota IP whitelist for remote login detection
	baotaIPWhitelist []string

	// 渐进式封禁管理器
	progressiveBan *ProgressiveBanManager
	// 封禁振荡熔断器
	banBreaker *safety.BanUnbanBreaker
	// SSH失联紧急回滚看门狗
	emergencyRollback *EmergencyRollback

	// 威胁情报查询器（可选），用于封禁时长情报增强
	intel IPIntelQuerier
}

// IPIntelQuerier 最小威胁情报查询接口，便于注入与测试。
type IPIntelQuerier interface {
	CheckIP(ctx context.Context, ip string) *intel.IPInfo
}

// New creates a new SecurityGuard.
func New(bus *eventbus.EventBus, store *storage.Storage) *SecurityGuard {
	return &SecurityGuard{
		eventBus:          bus,
		storage:           store,
		bruteThreshold:    30, // 从 5 提高到 30：5 次失败就封太低，管理员密码记错输几次就被封
		bruteWindow:       5 * time.Minute,
		banDuration:       1 * time.Hour,
		banProgression:    true,
		excludeIPs:        make(map[string]bool),
		monitorPaths:      make(map[string]string),
		sshLogPath:        "/var/log/secure", // CentOS/RHEL/Kylin
		authLogPath:       "/var/log/secure", // CentOS/RHEL/Kylin (Ubuntu uses /var/log/auth.log)
		loginFailures:     make(map[string][]time.Time),
		bannedIPs:         make(map[string]time.Time),
		fileHashes:        make(map[string]string),
		progressiveBan:    NewProgressiveBanManager(bus),
		banBreaker:        safety.NewBanUnbanBreaker(),
		emergencyRollback: NewEmergencyRollback(bus),
	}
}

// recordAudit 记录审计日志（WORM 不可篡改）
func (g *SecurityGuard) recordAudit(action, target, reason, result, details string) {
	if g.storage == nil {
		return
	}
	_ = g.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Actor:     "system",
		Action:    action,
		Target:    target,
		Reason:    reason,
		Result:    result,
		Details:   details,
	})
}

// recordAction 记录操作日志
func (g *SecurityGuard) recordAction(actionType, target, message string, success bool, errMsg string) {
	if g.storage == nil {
		return
	}
	_ = g.storage.SaveAction("security-guard", types.ActionResult{
		Action:    types.Action{Type: types.ActionType(actionType), Params: map[string]interface{}{"target": target}},
		Success:   success,
		Message:   message,
		Error:     errMsg,
		Timestamp: time.Now(),
	})
}

// SetIntelChecker 注入威胁情报查询器（可选，未注入则不进行情报增强）。
func (g *SecurityGuard) SetIntelChecker(intel IPIntelQuerier) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.intel = intel
}

// SetSafetyManager 注入安全管理器，用于宝塔安全模式判断。
// 同时加载宝塔 IP 白名单用于异地登录检测。
func (g *SecurityGuard) SetSafetyManager(sm *safety.SafetyManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.safety = sm
	// 加载宝塔面板 IP 白名单
	g.baotaIPWhitelist = LoadBaotaIPWhitelist()
	if len(g.baotaIPWhitelist) > 0 {
		fmt.Printf("已加载宝塔面板 IP 白名单: %d 条\n", len(g.baotaIPWhitelist))
	}
}

// SetBruteForceConfig updates brute force protection settings.
func (g *SecurityGuard) SetBruteForceConfig(threshold int, window time.Duration, banDuration time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bruteThreshold = threshold
	g.bruteWindow = window
	g.banDuration = banDuration
}

// AddExcludeIP adds an IP to the exclusion list.
func (g *SecurityGuard) AddExcludeIP(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.excludeIPs[ip] = true
}

// AddMonitorPath adds a file path for tamper detection.
func (g *SecurityGuard) AddMonitorPath(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	hash, err := g.hashFile(path)
	if err != nil {
		return fmt.Errorf("failed to hash %s: %w", path, err)
	}
	g.fileHashes[path] = hash
	g.monitorPaths[path] = hash
	return nil
}

// Check performs security checks.
func (g *SecurityGuard) Check(ctx context.Context) {
	var wg sync.WaitGroup

	// C1: Check login failures (brute force)
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkBruteForce(ctx)
	}()

	// C3: File tamper detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkFileTamper(ctx)
	}()

	// C4: Abnormal process detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkAbnormalProcesses(ctx)
	}()

	// C5: Remote login alert
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkRemoteLogins(ctx)
	}()

	// Expire old bans
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.expireBans()
	}()

	// C6: WebShell detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkWebShells(ctx)
	}()

	// C7: Cron tamper detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkCronTamper(ctx)
	}()

	// C8: File integrity monitoring
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.checkFileIntegrity(ctx)
	}()

	wg.Wait()
}

// checkBruteForce monitors login failures and bans IPs.
func (g *SecurityGuard) checkBruteForce(ctx context.Context) {
	if runtime.GOOS == "windows" {
		g.checkWindowsBruteForce(ctx)
		return
	}

	// Read auth log for failed logins
	g.mu.Lock()
	logPath := g.authLogPath
	g.mu.Unlock()

	// Try to open the log file, fallback to alternative paths
	file, err := os.Open(logPath)
	if err != nil {
		// Try alternative paths
		alternatives := []string{"/var/log/auth.log", "/var/log/secure"}
		for _, alt := range alternatives {
			if f, err := os.Open(alt); err == nil {
				file = f
				break
			}
		}
		if file == nil {
			return
		}
	}
	defer file.Close()

	// Read the last part of the file
	if _, err := file.Seek(-4096, 2); err != nil {
		return
	}

	scanner := bufio.NewScanner(file)
	now := time.Now()
	window := g.bruteWindow

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Failed password") || strings.Contains(line, "authentication failure") {
			// Extract IP
			ip := extractIP(line)
			if ip == "" {
				continue
			}
			// Check exclusion
			g.mu.RLock()
			excluded := g.excludeIPs[ip]
			g.mu.RUnlock()
			if excluded {
				continue
			}

			g.mu.Lock()
			g.loginFailures[ip] = append(g.loginFailures[ip], now)
			// Trim old failures
			cutoff := now.Add(-window)
			var recent []time.Time
			for _, t := range g.loginFailures[ip] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(g.loginFailures, ip) // 空条目即删，防止按攻击 IP 无限增长
			} else {
				g.loginFailures[ip] = recent
			}

			// Check threshold
			if len(recent) >= g.bruteThreshold {
				if _, banned := g.bannedIPs[ip]; !banned {
					g.banIP(ctx, ip, len(recent))
				}
			}
			g.mu.Unlock()
		}
	}

	// 周期性回收（每轮检查一次，而非每行一次）：已过期未显式解封的封禁记录、
	// 长期无更新的失败历史。放在扫描循环外，避免暴破风暴时 O(行数×封禁数) 的锁内开销。
	g.mu.Lock()
	nowClean := time.Now()
	for bip, until := range g.bannedIPs {
		if nowClean.After(until) {
			delete(g.bannedIPs, bip)
		}
	}
	if len(g.loginFailures) > 4096 {
		for fip, fails := range g.loginFailures {
			if len(fails) == 0 || nowClean.Sub(fails[len(fails)-1]) > time.Hour {
				delete(g.loginFailures, fip)
			}
		}
	}
	g.mu.Unlock()
}

// checkWindowsBruteForce checks Windows Event Log for failed logins.
func (g *SecurityGuard) checkWindowsBruteForce(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "powershell", "-Command",
		"Get-EventLog -LogName Security -EntryType FailureAudit -Newest 20 | Select-Object Message")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	// Parse Windows event log for failed logins
	// Extract IP addresses and track failures
	_ = output
}

// banIP bans an IP address using iptables or Windows Firewall.
// SAFETY: Auto-bans after threshold, but NEVER bans:
// - Private/local IPs (10.x, 172.16.x, 192.168.x, 127.x)
// - The server's own public IP
// - Excluded IPs (configured by user)
// 宝塔安全模式下，IP 封禁保持生效，但增加额外安全检查。
func (g *SecurityGuard) banIP(ctx context.Context, ip string, failures int) {
	// Never ban private IPs or localhost
	if isPrivateIP(ip) {
		return
	}

	// Never ban excluded IPs
	g.mu.RLock()
	if g.excludeIPs[ip] {
		g.mu.RUnlock()
		return
	}
	g.mu.RUnlock()

	// Never ban the server's own public IP
	if ownIPs := getServerPublicIPs(); ownIPs[ip] {
		g.eventBus.PublishAlert(types.AlertWarning, "security",
			"跳过封禁服务器自身IP",
			fmt.Sprintf("检测到失败登录来自服务器自身IP %s，跳过封禁以避免锁定", ip),
			"ssh-brute-001")
		return
	}

	// 封禁振荡熔断器检查
	if !g.banBreaker.CanBan(ip) {
		reason := g.banBreaker.PauseReason(ip)
		g.eventBus.PublishAlert(types.AlertWarning, "security",
			fmt.Sprintf("跳过封禁（振荡熔断）: %s", ip),
			reason,
			"ssh-brute-001")
		return
	}

	// 渐进式封禁：使用 ProgressiveBanManager 决定封禁等级
	duration := g.banDuration
	banLevel := g.progressiveBan.RecordAttack(ip, "ssh-brute")
	switch banLevel {
	case BanLevelShort:
		duration = 1 * time.Hour
	case BanLevelLong:
		duration = 24 * time.Hour
	case BanLevelLimit:
		duration = 10 * time.Minute
	}

	// Progressive ban duration
	// 注意：bruteThreshold=30，所以 failures 最小为 30
	// failures>=50 说明暴力破解持续超过阈值将近两倍，封 24 小时
	// failures>=30 是刚达到阈值，封 6 小时
	if g.banProgression {
		switch {
		case failures >= 50:
			duration = 24 * time.Hour
		case failures >= 30:
			duration = 6 * time.Hour
		default:
			duration = g.banDuration
		}
	}

	// 威胁情报增强：命中恶意 IP 时延长封禁时长（仅增强，不破坏现有逻辑）
	intelNote := ""
	g.mu.RLock()
	iq := g.intel
	g.mu.RUnlock()
	if iq != nil {
		if info := iq.CheckIP(ctx, ip); info != nil && (info.Confidence >= 50 || info.AbuseReports > 0) {
			if duration < 24*time.Hour {
				duration = 24 * time.Hour
			}
			intelNote = fmt.Sprintf("（威胁情报: 置信度=%d%% 举报=%d次）", info.Confidence, info.AbuseReports)
		}
	}

	banReason := fmt.Sprintf("SSH暴力破解: %s 内失败 %d 次%s", g.bruteWindow, failures, intelNote)

	if runtime.GOOS != "windows" {
		// 管理员来源保护：该 IP 正有已认证登录会话时拒绝封禁（防自锁）
		if platform.IsAdminSSHSource(ip) {
			g.eventBus.PublishAlert(types.AlertWarning, "security",
				fmt.Sprintf("封禁被防自锁保护拦截: %s", ip),
				fmt.Sprintf("IP %s 触发封禁条件（%s 内失败 %d 次），但它是当前已登录管理员的活动来源，已拒绝封禁。请确认后手动处理",
					ip, g.bruteWindow, failures),
				"ssh-brute-admin-001")
			g.recordAudit("ban_ip_blocked", ip, "封禁目标为管理员活动来源，防自锁保护拒绝", "blocked", "")
			return
		}

		// 安全保护模式下 IP 封禁保持生效（不会导致服务器崩溃）
		// 注释带 exp=<unix>：Agent 崩溃/重启后 platform 清扫器仍能按期清理，
		// 否则内存到期记录丢失后封禁将永久化
		expireUnix := time.Now().Add(duration).Unix()
		cmd := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
			"-m", "comment", "--comment", fmt.Sprintf("serverguard-security:ssh-brute:exp=%d", expireUnix))
		if err := cmd.Run(); err != nil {
			// Try firewalld as fallback
			cmd = exec.CommandContext(ctx, "firewall-cmd", "--add-rich-rule",
				fmt.Sprintf("rule family='ipv4' source address='%s' reject", ip))
			cmd.Run()
		}

		g.bannedIPs[ip] = time.Now().Add(duration)

		// 封禁后启动 SSH 失联检测
		g.emergencyRollback.OnBanCalled(ip)

		g.eventBus.PublishAlert(types.AlertError, "security",
			fmt.Sprintf("已封禁IP: %s", ip),
			fmt.Sprintf("IP %s 在 %s 内失败登录 %d 次，已封禁 %s%s",
				ip, g.bruteWindow, failures, duration, intelNote),
			"ssh-brute-001")
		g.recordAudit("ban_ip", ip, banReason, "success", "")
		g.recordAction("ban_ip", ip, fmt.Sprintf("自动封禁IP %s（%v）%s", ip, duration, intelNote), true, "")
	} else {
		cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name", fmt.Sprintf("ServerGuard-Ban-%s", ip),
			"dir=in", "action=block", "remoteip="+ip)
		if err := cmd.Run(); err == nil {
			g.bannedIPs[ip] = time.Now().Add(duration)
			// 封禁后启动 SSH 失联检测（Windows 同样需要）
			g.emergencyRollback.OnBanCalled(ip)
			g.eventBus.PublishAlert(types.AlertError, "security",
				fmt.Sprintf("已封禁IP: %s", ip),
				fmt.Sprintf("IP %s 在 %s 内失败登录 %d 次，已通过防火墙封禁 %s%s",
					ip, g.bruteWindow, failures, duration, intelNote),
				"ssh-brute-001")
			g.recordAudit("ban_ip", ip, banReason, "success", "")
			g.recordAction("ban_ip", ip, fmt.Sprintf("自动封禁IP %s（%v）%s", ip, duration, intelNote), true, "")
		} else {
			g.recordAudit("ban_ip", ip, banReason, "failed", fmt.Sprintf("封禁命令失败: %v", err))
			g.recordAction("ban_ip", ip, fmt.Sprintf("封禁IP失败: %s", ip), false, err.Error())
		}
	}
}

// expireBans removes expired IP bans.
// 宝塔安全模式下，不操作 iptables/firewalld（与宝塔防火墙插件冲突），只清理内存记录。
func (g *SecurityGuard) expireBans() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// 宝塔安全模式下，不执行 iptables/firewalld 命令
	baotaSafeMode := false
	if g.safety != nil {
		baotaSafeMode = g.safety.IsBaotaSafeMode()
	}

	now := time.Now()
	for ip, expiry := range g.bannedIPs {
		if now.After(expiry) {
			// 非宝塔模式下才执行防火墙命令
			if !baotaSafeMode {
				if runtime.GOOS != "windows" {
					exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
						"-m", "comment", "--comment", "serverguard-security:ssh-brute").Run()
				} else {
					exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
						"name", fmt.Sprintf("ServerGuard-Ban-%s", ip)).Run()
				}
			}
			delete(g.bannedIPs, ip)
			g.eventBus.PublishAlert(types.AlertInfo, "security",
				fmt.Sprintf("已解封IP: %s", ip),
				fmt.Sprintf("IP %s 的封禁已到期", ip),
				"ssh-brute-001")
			g.recordAudit("unban_ip", ip, "封禁到期自动解禁", "success", "")
			g.recordAction("unban_ip", ip, fmt.Sprintf("自动解封IP: %s", ip), true, "")
		}
	}
}

// checkFileTamper checks monitored files for changes.
func (g *SecurityGuard) checkFileTamper(ctx context.Context) {
	g.mu.RLock()
	paths := make(map[string]string, len(g.fileHashes))
	for k, v := range g.fileHashes {
		paths[k] = v
	}
	g.mu.RUnlock()

	for path, expectedHash := range paths {
		currentHash, err := g.hashFile(path)
		if err != nil {
			// File might have been deleted
			g.eventBus.PublishAlert(types.AlertCritical, "security",
				fmt.Sprintf("文件异常: %s", path),
				fmt.Sprintf("监控文件 %s 无法读取或已删除", path),
				"file-tamper-001")
			continue
		}

		if currentHash != expectedHash {
			g.eventBus.PublishAlert(types.AlertCritical, "security",
				fmt.Sprintf("文件篡改: %s", path),
				fmt.Sprintf("文件 %s 已被修改！原始哈希: %s，当前哈希: %s",
					path, expectedHash[:16], currentHash[:16]),
				"file-tamper-001")

			// Auto-restore from backup if available
			g.restoreFromBackup(path, expectedHash)
		}
	}
}

// checkAbnormalProcesses detects and kills suspicious processes.
// SAFETY: Only kills processes that match known malware/mining signatures.
// Normal services (nginx, mysql, etc.) are protected by the whitelist.
//
// 精确归属识别：通过 ReadProcInfo + IsBaotaProtectedProcess 二次确认，
// 确保 python/python3 运行的宝塔面板进程不会被误杀。该保护无条件生效，
// 不依赖模式开关 —— 宝塔环境下的真实恶意进程仍然会被正常查杀。
func (g *SecurityGuard) checkAbnormalProcesses(ctx context.Context) {
	procs, err := process.Processes()
	if err != nil {
		return
	}

	// Known mining/malware process names — auto-kill on sight
	malwareProcesses := map[string]bool{
		// Cryptocurrency miners
		"xmrig": true, "xmrig.exe": true,
		"cpuminer": true, "cpuminer.exe": true,
		"ethminer": true, "ethminer.exe": true,
		"minerd": true, "minerd.exe": true,
		"ccminer": true, "ccminer.exe": true,
		"cryptonight":     true,
		"stratum":         true,
		"kdevtmpfsi":      true, // Common Docker/Kubernetes miner
		"kinsing":         true, // Kinsing malware
		"pnscan":          true,
		"masscan":         true,
		"tsm":             true,
		"dbused":          true, // Disguised miner
		"systemd-private": true, // Disguised miner (not real systemd)
		"kthrotlds":       true,
		"sysguard":        true,
		"networkservice":  true,
		"sysupdate":       true,
		"update.sh":       true,
		"nonce":           true,
		// 注意：不收录 "bot"/"ddos"/"busybox"/" circum" 等泛化名称 ——
		// 合法爬虫/脚本/嵌入式 busybox 会被误杀；busybox 从 /tmp 运行的
		// 场景已由下方"可疑目录运行"规则（含 exe 路径双重确认）覆盖。
	}

	// Suspicious working directories (malware often runs from these)
	suspiciousPaths := []string{
		"/tmp/",
		"/dev/shm/",
		"/var/tmp/",
	}

	for _, p := range procs {
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()
		cwd, _ := p.Cwd()
		pid := p.Pid

		lowerName := strings.ToLower(name)

		// 深度安全检查：读取 /proc 信息，匹配宝塔白名单（comm/cmdline/exe/cwd/父进程）
		// 即使进程名不在白名单中（如 python/python3），也通过路径和父进程二次确认
		isBaotaProtected := false
		if procInfo := safety.ReadProcInfo(pid); procInfo != nil {
			if safety.IsBaotaProtectedProcess(procInfo) {
				isBaotaProtected = true
			}
		}

		// 1. Auto-kill known malware/mining processes
		if malwareProcesses[lowerName] {
			// Verify it's not a false positive (check if in whitelist)
			if g.isWhitelisted(name) {
				continue
			}
			// 宝塔保护进程不杀
			if isBaotaProtected {
				continue
			}

			// 走安全审批（预算/熔断/紧急停止/白名单），不绕过五层安全阀
			if !g.killWithApproval(name, pid, "已知恶意/挖矿进程") {
				continue
			}
			g.eventBus.PublishAlert(types.AlertCritical, "security",
				fmt.Sprintf("已清除恶意进程: %s (PID %d)", name, pid),
				fmt.Sprintf("检测到已知恶意/挖矿进程 %s (PID %d)，已自动终止。命令行: %s，工作目录: %s", name, pid, cmdline, cwd),
				"abnormal-process-001")
			continue
		}

		// 2. Check for processes masquerading as system processes
		// e.g. a process named "[kworker]" running from /tmp
		if cwd != "" {
			for _, sp := range suspiciousPaths {
				if strings.HasPrefix(cwd, sp) && name != "" {
					// Skip if it's a known safe process or ServerGuard itself
					if g.isWhitelisted(name) || strings.Contains(name, "serverguard") {
						continue
					}
					// 宝塔保护进程不杀
					if isBaotaProtected {
						continue
					}
					// Check if executable is also in the suspicious directory
					if exePath, err := p.Exe(); err == nil && strings.HasPrefix(exePath, sp) {
						// Auto-kill processes running executables from /tmp or /dev/shm
						// (legitimate services don't run from these directories)
						// 走安全审批：临时目录跑构建/临时工具属合法场景，必须可被
						// 白名单/预算/紧急停止拦住
						if !g.killWithApproval(name, pid, "从可疑目录运行可执行文件") {
							break
						}
						g.eventBus.PublishAlert(types.AlertCritical, "security",
							fmt.Sprintf("已清除可疑进程: %s (PID %d)", name, pid),
							fmt.Sprintf("进程 %s (PID %d) 从可疑目录 %s 运行，已自动终止。命令行: %s，可执行文件: %s",
								name, pid, cwd, cmdline, exePath),
							"abnormal-process-001")
						break
					}
				}
			}
		}

		// 3. Check for processes using excessive CPU and hiding (name starts with [ or is empty)
		// Some malware hides by setting process name to [kworker] or empty
		if (strings.HasPrefix(name, "[") || name == "") && pid > 2 {
			cpuPercent, _ := p.CPUPercent()
			if cpuPercent > 50 {
				g.eventBus.PublishAlert(types.AlertWarning, "security",
					fmt.Sprintf("隐藏进程高CPU: PID %d", pid),
					fmt.Sprintf("进程 PID %d 名称异常('%s')且CPU占用 %.1f%%，可能是隐藏的恶意进程。命令行: %s",
						pid, name, cpuPercent, cmdline),
					"abnormal-process-001")
			}
		}
	}
}

// killWithApproval 在杀灭威胁进程前走一遍完整安全审批：
// CheckKillPermission（Kill 预算/熔断器/紧急停止/硬白名单/PID 保护）
// + RecordKill（记账，让自动急停条件"1 小时 >10 次 kill"可见）。
// 返回是否实际执行了杀灭。审批被拒时发一条 Warning 告警说明原因，
// 避免管理员看到"检测到威胁"却不知道为什么没处理。
func (g *SecurityGuard) killWithApproval(name string, pid int32, reason string) bool {
	if g.safety != nil {
		if err := g.safety.CheckKillPermission(name, pid); err != nil {
			g.eventBus.PublishAlert(types.AlertWarning, "security",
				fmt.Sprintf("威胁进程处理被安全机制拦截: %s (PID %d)", name, pid),
				fmt.Sprintf("检测到%s %s (PID %d)，但安全审批拒绝了终止动作：%v。请人工确认后处理",
					reason, name, pid, err),
				"abnormal-process-blocked-001")
			return false
		}
	}
	if err := g.killProcess(pid); err != nil {
		g.eventBus.PublishAlert(types.AlertWarning, "security",
			fmt.Sprintf("终止进程失败: %s (PID %d)", name, pid),
			fmt.Sprintf("%s：SIGKILL 发送失败：%v", reason, err),
			"abnormal-process-001")
		return false
	}
	if g.safety != nil {
		g.safety.RecordKill(pid, name, true)
	}
	return true
}

// killProcess 发送 SIGKILL（Windows 上由 gopsutil Terminate 处理）。
func (g *SecurityGuard) killProcess(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// isWhitelisted checks if a process is in the safety whitelist.
func (g *SecurityGuard) isWhitelisted(name string) bool {
	whitelist := map[string]bool{
		"systemd": true, "init": true, "kthreadd": true,
		"sshd": true, "systemd-journald": true, "systemd-logind": true,
		"dbus": true, "dbus-daemon": true, "rsyslogd": true, "cron": true,
		"nginx": true, "httpd": true, "apache2": true, "caddy": true,
		"mysqld": true, "mariadbd": true, "postgres": true,
		"redis-server": true, "mongod": true,
		"php-fpm": true, "php-cgi": true, "php": true,
		"php-fpm-74": true, "php-fpm-80": true, "php-fpm-81": true,
		"php-fpm-82": true, "php-fpm-83": true,
		"bt-panel": true, "bt": true, "btpanel": true,
		"panelSite.py": true,
		"pure-ftpd":    true, "proftpd": true, "vsftpd": true,
		"named": true, "bind9": true,
		"postfix": true, "dovecot": true, "sendmail": true,
		"serverguard-agent": true, "serverguard-agent.exe": true,
		// Windows
		"System": true, "smss.exe": true, "csrss.exe": true,
		"wininit.exe": true, "services.exe": true, "lsass.exe": true,
		"svchost.exe": true, "winlogon.exe": true,
		"w3svc": true, "nginx.exe": true, "httpd.exe": true,
		"sqlservr.exe": true, "mysqld.exe": true, "postgres.exe": true,
		"redis-server.exe": true, "php-cgi.exe": true, "php.exe": true,
	}
	return whitelist[name]
}

// checkRemoteLogins checks for logins from unusual locations.
// 排除宝塔面板 IP 白名单中的 IP，避免宝塔面板操作触发误报。
func (g *SecurityGuard) checkRemoteLogins(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	// 获取宝塔 IP 白名单
	g.mu.RLock()
	baotaWhitelist := g.baotaIPWhitelist
	g.mu.RUnlock()

	// Check who/w command output for active sessions
	cmd := exec.CommandContext(ctx, "who")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			user := fields[0]
			ip := extractIP(line)
			if ip != "" {
				// Check if IP is in a typical remote range (not localhost, not private)
				if !isPrivateIP(ip) {
					// 检查宝塔面板 IP 白名单
					if isIPInWhitelist(ip, baotaWhitelist) {
						continue
					}

					g.eventBus.PublishAlert(types.AlertWarning, "security",
						fmt.Sprintf("异地登录: %s from %s", user, ip),
						fmt.Sprintf("用户 %s 从 %s 登录，可能是异地访问", user, ip),
						"remote-login-001")
				}
			}
		}
	}
}

// hashFile computes the SHA-256 hash of a file.
func (g *SecurityGuard) hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:]), nil
}

// restoreFromBackup attempts to restore a file from backup.
// SAFETY: Only restores files that were explicitly monitored by the user.
// Never auto-restores system files, web configs, or database files —
// could corrupt the system if backup is stale or compromised.
// 宝塔安全模式下，禁止自动恢复文件，改为只告警。
func (g *SecurityGuard) restoreFromBackup(path, expectedHash string) {
	// 宝塔安全模式下，禁止自动恢复文件
	if g.safety != nil && g.safety.IsBaotaSafeMode() {
		g.eventBus.PublishAlert(types.AlertCritical, "security",
			fmt.Sprintf("文件篡改(宝塔模式不自动恢复): %s", path),
			fmt.Sprintf("文件 %s 已被修改，但安全保护模式下禁止自动恢复，请人工确认后手动处理", path),
			"file-tamper-001")
		return
	}

	// Safety: never auto-restore critical system/config files
	criticalPaths := []string{
		"/etc/", "/boot/", "/usr/", "/bin/", "/sbin/", "/lib/",
		"/www/server/",                            // BaoTa panel files
		"/var/lib/mysql/", "/var/lib/postgresql/", // Database data
		`C:\Windows\System32\`, `C:\Windows\System32\drivers\`,
	}
	lowerPath := strings.ToLower(path)
	for _, cp := range criticalPaths {
		if strings.HasPrefix(lowerPath, strings.ToLower(cp)) {
			g.eventBus.PublishAlert(types.AlertCritical, "security",
				fmt.Sprintf("文件篡改(未自动恢复): %s", path),
				fmt.Sprintf("文件 %s 已被修改，但由于是系统/关键路径文件，未自动恢复。请人工确认后手动处理", path),
				"file-tamper-001")
			return
		}
	}

	backupPath := filepath.Join(filepath.Dir(path), ".serverguard-backup", filepath.Base(path))
	if _, err := os.Stat(backupPath); err == nil {
		backupHash, err := g.hashFile(backupPath)
		if err == nil && backupHash == expectedHash {
			// Restore from backup
			os.Rename(backupPath, path)
			g.eventBus.PublishAlert(types.AlertInfo, "security",
				fmt.Sprintf("已恢复: %s", path),
				fmt.Sprintf("文件 %s 已从备份恢复", path),
				"file-tamper-001")
		}
	}
}

// GetBannedIPs returns currently banned IPs.
func (g *SecurityGuard) GetBannedIPs() map[string]time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make(map[string]time.Time, len(g.bannedIPs))
	for k, v := range g.bannedIPs {
		result[k] = v
	}
	return result
}

// GetMonitoredFiles returns the list of monitored files.
func (g *SecurityGuard) GetMonitoredFiles() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var result []string
	for path := range g.fileHashes {
		result = append(result, path)
	}
	return result
}

// extractIP extracts an IP address from a log line.
func extractIP(line string) string {
	// Look for IP address pattern
	parts := strings.Fields(line)
	for _, part := range parts {
		ip := net.ParseIP(part)
		if ip != nil {
			return part
		}
		// Check for "from 1.2.3.4" pattern
		if strings.HasPrefix(part, "from") {
			ipStr := strings.TrimPrefix(part, "from")
			ipStr = strings.TrimSpace(ipStr)
			if ip := net.ParseIP(ipStr); ip != nil {
				return ipStr
			}
		}
	}
	// Try regex-like extraction
	for i := 0; i < len(line); i++ {
		if line[i] >= '0' && line[i] <= '9' {
			end := i
			dotCount := 0
			for end < len(line) {
				if line[end] == '.' {
					dotCount++
				} else if line[end] < '0' || line[end] > '9' {
					break
				}
				end++
			}
			if dotCount == 3 {
				ipStr := line[i:end]
				if ip := net.ParseIP(ipStr); ip != nil {
					return ipStr
				}
			}
		}
	}
	return ""
}

// isPrivateIP checks if an IP is a private/local address.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}

// serverIPCache 缓存服务器自身 IP，避免每次 banIP 都重新探测。
var serverIPCache map[string]bool

// getServerPublicIPs 获取服务器自身的所有公网 IP 地址。
// 用于防止误封服务器自身 IP 导致服务不可访问。
func getServerPublicIPs() map[string]bool {
	if serverIPCache != nil {
		return serverIPCache
	}

	serverIPCache = make(map[string]bool)

	// 获取所有网卡绑定的 IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				serverIPCache[ipNet.IP.String()] = true
			}
		}
	}

	// 获取公网出口 IP（通过外网请求）
	// 使用 ifconfig.me 快速获取
	if resp, err := netHttpGet("http://ifconfig.me"); err == nil && resp != "" {
		if ip := net.ParseIP(strings.TrimSpace(resp)); ip != nil {
			serverIPCache[ip.String()] = true
		}
	}

	return serverIPCache
}

// netHttpGet 执行简单的 HTTP GET 请求并返回响应体。
func netHttpGet(url string) (string, error) {
	client := &netHttpClient{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// netHttpClient 是 http.Client 的类型别名，方便测试。
type netHttpClient = http.Client

// --- WebShell Detection ---

// webShellPatterns are PHP function patterns commonly used in web shells.
var webShellPatterns = []string{
	"eval(", "assert(", "base64_decode(", "gzinflate(", "gzuncompress(",
	"str_rot13(", "strrev(", "system(", "exec(", "passthru(", "shell_exec(",
	"popen(", "proc_open(", "pcntl_exec(", "${@eval", "${$_",
	"preg_replace('/.", "create_function(", "call_user_func(",
	"file_put_contents($_", "file_get_contents('http", "fputs(fopen(",
	"$_POST[", "$_GET[", "$_REQUEST[", "$_COOKIE[",
	"move_uploaded_file(", "copy($_", "rename($_",
	"chmod($_", "unlink($_", "mkdir($_", "rmdir($_",
	"phpinfo()", "ini_restore(", "ini_set('disable_functions'",
	"error_reporting(0)", "@set_time_limit(0)",
}

// checkWebShells scans web root for PHP files containing web shell signatures.
// SAFETY: Read-only scan. Only alerts, does NOT delete files.
// 排除宝塔自身代码目录（/www/server/panel 等），避免误报。
// 对于 /www/wwwroot/ 下的用户网站，正常扫描，但告警中标注"用户网站目录，非系统文件"。
func (g *SecurityGuard) checkWebShells(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	// 宝塔安全模式下，跳过 WebShell 扫描
	// 扫描 /www/wwwroot 会产生大量磁盘 I/O，可能影响宝塔网站性能
	baotaSafeMode := false
	if g.safety != nil {
		baotaSafeMode = g.safety.IsBaotaSafeMode()
	}
	if baotaSafeMode {
		return
	}

	webRoots := []string{
		"/www/wwwroot", "/var/www/html", "/var/www",
		"/usr/share/nginx/html", "/home/wwwroot",
	}

	maxScanFiles := 5000
	scanned := 0
	found := 0

	for _, root := range webRoots {
		if scanned >= maxScanFiles {
			break
		}

		// 排除宝塔自身代码目录
		if IsWebShellScanExcluded(root) {
			continue
		}

		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				// 目录级别排除检查
				if info != nil && info.IsDir() && IsWebShellScanExcluded(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if scanned >= maxScanFiles {
				return filepath.SkipDir
			}

			// 安全检查: 排除宝塔自身代码文件
			if IsWebShellScanExcluded(path) {
				return nil
			}

			if !strings.HasSuffix(strings.ToLower(path), ".php") {
				return nil
			}
			if info.Size() > 1024*1024 {
				return nil
			}
			scanned++
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			contentStr := strings.ToLower(string(content))
			matchCount := 0
			for _, pattern := range webShellPatterns {
				if strings.Contains(contentStr, strings.ToLower(pattern)) {
					matchCount++
				}
			}
			// 阈值提高到 5，减少框架文件误报
			// 正常 PHP 框架文件可能包含 3-4 个特征函数（如 $_POST, eval, system）
			// 真正的 WebShell 通常包含 5+ 个特征
			if matchCount >= 5 {
				found++
				shortPath := path
				if len(shortPath) > 80 {
					shortPath = "..." + shortPath[len(shortPath)-77:]
				}

				// 标注文件来源信息
				sourceTag := ""
				if IsUserWebsitePath(path) {
					sourceTag = "（该文件位于用户网站目录，非系统文件）"
				}

				g.eventBus.PublishAlert(types.AlertCritical, "security",
					fmt.Sprintf("疑似WebShell: %s", shortPath),
					fmt.Sprintf("文件 %s 包含 %d 个可疑函数特征，疑似WebShell后门。请立即检查！%s\n注意: 本告警仅为检测提醒，不会自动删除或隔离文件。", shortPath, matchCount, sourceTag),
					"webshell-001")
			}
			return nil
		})
	}
}

// --- Cron Task Monitoring ---

func (g *SecurityGuard) checkCronTamper(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	suspiciousPatterns := []string{
		"/dev/tcp", "bash -i", "nc -e", "/dev/shm/",
		"curl http", "wget http", "python -c import",
		"base64 -d", "perl -e", "ruby -e",
		"xmrig", "minerd", "stratum+tcp",
		"/tmp/.", "/var/tmp/.", "/dev/shm/.",
	}

	// 宝塔环境下，Cron 篡改检测只告警、不尝试自动恢复
	baotaSafeMode := false
	if g.safety != nil {
		baotaSafeMode = g.safety.IsBaotaSafeMode()
	}

	// Check crontab -l
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// 白名单检查: 宝塔计划任务脚本不告警
			if IsCronWhitelisted(line) {
				continue
			}

			lowerLine := strings.ToLower(line)
			for _, pattern := range suspiciousPatterns {
				if strings.Contains(lowerLine, pattern) {
					alertMsg := fmt.Sprintf("crontab中发现可疑条目: %s（匹配: %s）", line, pattern)
					if baotaSafeMode {
						alertMsg += "\n[安全保护模式] 仅告警，不会自动恢复"
					}
					g.eventBus.PublishAlert(types.AlertCritical, "security",
						"可疑定时任务", alertMsg, "cron-tamper-001")
					break
				}
			}
		}
	}

	// Check system cron files
	cronFiles := []string{"/etc/crontab", "/var/spool/cron/root", "/var/spool/cron/crontabs/root"}
	for _, cf := range cronFiles {
		g.scanCronFile(cf, suspiciousPatterns, baotaSafeMode)
	}
	// Check /etc/cron.d/
	filepath.Walk("/etc/cron.d", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		g.scanCronFile(path, suspiciousPatterns, baotaSafeMode)
		return nil
	})
}

func (g *SecurityGuard) scanCronFile(path string, patterns []string, baotaSafeMode bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 白名单检查: 宝塔计划任务脚本不告警
		if IsCronWhitelisted(line) {
			continue
		}

		lowerLine := strings.ToLower(line)
		for _, pattern := range patterns {
			if strings.Contains(lowerLine, pattern) {
				alertMsg := fmt.Sprintf("文件%s中发现可疑条目: %s（匹配: %s）", path, line, pattern)
				if baotaSafeMode {
					alertMsg += "\n[安全保护模式] 仅告警，不会自动恢复"
				}
				g.eventBus.PublishAlert(types.AlertCritical, "security",
					"可疑定时任务", alertMsg, "cron-tamper-001")
				break
			}
		}
	}
}

// --- File Integrity Monitoring ---

func (g *SecurityGuard) checkFileIntegrity(ctx context.Context) {
	if runtime.GOOS == "windows" {
		return
	}

	criticalFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
		"/etc/ssh/sshd_config", "/etc/crontab",
		"/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/wget", "/usr/bin/curl",
		"/usr/bin/python3", "/usr/bin/bash", "/bin/bash", "/bin/sh",
	}

	g.mu.Lock()
	if g.fileHashes == nil {
		g.fileHashes = make(map[string]string)
	}
	if len(g.fileHashes) == 0 {
		// Initialize: record hashes on first run
		for _, f := range criticalFiles {
			if hash, err := g.hashFile(f); err == nil {
				g.fileHashes[f] = hash
			}
		}
		g.mu.Unlock()
		return
	}
	savedHashes := make(map[string]string, len(g.fileHashes))
	for k, v := range g.fileHashes {
		savedHashes[k] = v
	}
	g.mu.Unlock()

	for path, oldHash := range savedHashes {
		currentHash, err := g.hashFile(path)
		if err != nil {
			g.eventBus.PublishAlert(types.AlertCritical, "security",
				fmt.Sprintf("系统文件丢失: %s", path),
				fmt.Sprintf("关键文件%s无法读取，可能已被删除", path),
				"file-integrity-001")
			continue
		}
		if currentHash != oldHash {
			g.eventBus.PublishAlert(types.AlertCritical, "security",
				fmt.Sprintf("系统文件被修改: %s", path),
				fmt.Sprintf("关键文件%s哈希已改变，可能是系统更新或入侵篡改", path),
				"file-integrity-001")
			g.mu.Lock()
			g.fileHashes[path] = currentHash
			g.mu.Unlock()
		}
	}
}
