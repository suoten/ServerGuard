package serversecurity

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/guards/scannercommon"
)

// ServerSecurityGuard 服务器安全扫描
type ServerSecurityGuard struct{}

// NewServerSecurityGuard 创建服务器安全扫描
func NewServerSecurityGuard() *ServerSecurityGuard {
	return &ServerSecurityGuard{}
}

// Scan 执行全量服务器安全扫描
func (s *ServerSecurityGuard) Scan(ctx context.Context) ([]types.ScanFinding, error) {
	var allFindings []types.ScanFinding

	if findings, err := s.ScanPortExposure(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanUserAudit(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanAbnormalProcesses(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanCronTasks(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanRootkit(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanPHPConfig(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanFileIntegrity(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanSSHBehavior(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanRedisSecurity(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanMySQLSecurity(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanSSHKeySecurity(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := s.ScanNetworkMisconfig(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// ScanPortExposure Y1: 端口暴露风险评估
func (s *ServerSecurityGuard) ScanPortExposure(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "port_exposure")

	cmd := exec.CommandContext(ctx, "ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	highRiskPorts := map[int]string{
		22:    "SSH",
		23:    "Telnet",
		21:    "FTP",
		3389:  "RDP",
		445:   "SMB",
		1433:  "MSSQL",
		1521:  "Oracle",
		3306:  "MySQL",
		6379:  "Redis",
		27017: "MongoDB",
		5432:  "PostgreSQL",
		9200:  "Elasticsearch",
	}

	for _, line := range strings.Split(string(output), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addrParts := strings.Split(fields[3], ":")
		if len(addrParts) < 2 {
			continue
		}
		var port int
		fmt.Sscanf(addrParts[len(addrParts)-1], "%d", &port)

		if port == 0 {
			continue
		}

		isLocal := strings.HasPrefix(fields[3], "127.0.0.1:") || strings.HasPrefix(fields[3], "[::1]:")
		if !isLocal {
			if service, high := highRiskPorts[port]; high {
				rb.AddFinding(
					types.SeverityHigh,
					fmt.Sprintf("高危端口暴露: %d (%s)", port, service),
					fmt.Sprintf("端口 %d (%s) 对外开放，可能被攻击者利用", port, service),
					fmt.Sprintf("port:%d", port),
					fmt.Sprintf(`{"port":%d,"service":"%s","addr":"%s"}`, port, service, fields[3]),
					fmt.Sprintf("如非必要，封禁端口: iptables -A INPUT -p tcp --dport=%d -j DROP", port),
					fmt.Sprintf("封禁端口后，通过该端口访问的服务将无法连接（如封了 3306 则远程数据库连接断开）"),
				)
			}
		}
	}

	return rb.GetFindings(), nil
}

// ScanUserAudit Y2: 系统用户与权限审计
func (s *ServerSecurityGuard) ScanUserAudit(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "user_audit")

	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	uidRegex := regexp.MustCompile(`^[^:]+:x:(\d+):`)

	for _, line := range strings.Split(string(passwdData), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		username := fields[0]
		uid := fields[2]

		if uid == "0" && username != "root" {
			rb.AddFinding(
				types.SeverityCritical,
				fmt.Sprintf("UID 0 非 root 用户: %s", username),
				fmt.Sprintf("用户 %s 的 UID 为 0，拥有 root 权限", username),
				username,
				fmt.Sprintf(`{"user":"%s","uid":0}`, username),
				fmt.Sprintf("锁定用户: passwd -l %s", username),
				"锁定后该用户将无法登录，如有业务依赖该用户的定时任务/服务会报错",
			)
		}

		if strings.HasPrefix(username, "$") {
			rb.AddFinding(
				types.SeverityMedium,
				fmt.Sprintf("隐藏用户: %s", username),
				fmt.Sprintf("检测到隐藏用户 %s（带 $ 符号），可能是后门账户", username),
				username,
				fmt.Sprintf(`{"user":"%s"}`, username),
				"检查该用户用途，如非必要则删除",
				"删除用户前需确认无业务依赖",
			)
		}
	}

	shadowData, err := os.ReadFile("/etc/shadow")
	if err == nil {
		for _, line := range strings.Split(string(shadowData), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 2 {
				continue
			}
			if fields[1] == "" || fields[1] == "!" || fields[1] == "*" {
				continue
			}
			if match := uidRegex.FindStringSubmatch(line); match != nil {
				_ = match
			}
		}
	}

	sudoersData, err := os.ReadFile("/etc/sudoers")
	if err == nil {
		for _, line := range strings.Split(string(sudoersData), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "ALL=(ALL)") && !strings.Contains(line, "root") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					rb.AddFinding(
						types.SeverityMedium,
						fmt.Sprintf("sudo 权限用户: %s", fields[0]),
						fmt.Sprintf("用户 %s 拥有完整 sudo 权限", fields[0]),
						fields[0],
						fmt.Sprintf(`{"user":"%s","sudo":"ALL=(ALL)"}`, fields[0]),
						"审查是否需要完整 sudo 权限，建议使用最小权限方案",
						"修改 sudo 权限可能影响该用户的运维操作",
					)
				}
			}
		}
	}

	return rb.GetFindings(), nil
}

// ScanAbnormalProcesses Y3: 异常进程检测（挖矿木马重点防御）
func (s *ServerSecurityGuard) ScanAbnormalProcesses(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "abnormal_process")

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	miningPatterns := []string{
		"xmrig", "xmr-stak", "ccminer", "ethminer", "cgminer", "bfgminer",
		"cryptonight", "stratum+tcp", "monero", "nicehash",
	}
	miningDomains := []string{
		"pool.minexmr.com", "xmr.pool.minergate.com", "monero.crypto-pool.fr",
		"pool.supportxmr.com", "xmrpool.com",
	}

	for _, line := range strings.Split(string(output), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		cmdline := strings.Join(fields[10:], " ")
		lowerCmd := strings.ToLower(cmdline)

		for _, pattern := range miningPatterns {
			if strings.Contains(lowerCmd, pattern) {
				rb.AddFinding(
					types.SeverityCritical,
					fmt.Sprintf("检测到挖矿进程: %s", pattern),
					fmt.Sprintf("进程包含挖矿特征 %s: %s", pattern, cmdline),
					fmt.Sprintf("pid:%s", fields[1]),
					fmt.Sprintf(`{"pattern":"%s","cmd":"%s"}`, pattern, cmdline),
					fmt.Sprintf("Kill 进程并清理定时任务/启动项: kill -9 %s", fields[1]),
					"Kill 进程后该进程关联的业务可能中断（误报情况下）",
				)
				break
			}
		}

		for _, domain := range miningDomains {
			if strings.Contains(lowerCmd, domain) {
				rb.AddFinding(
					types.SeverityCritical,
					fmt.Sprintf("连接到矿池: %s", domain),
					fmt.Sprintf("进程连接到已知矿池 %s: %s", domain, cmdline),
					fmt.Sprintf("pid:%s", fields[1]),
					fmt.Sprintf(`{"domain":"%s","cmd":"%s"}`, domain, cmdline),
					fmt.Sprintf("Kill 进程: kill -9 %s", fields[1]),
					"Kill 进程后该进程关联的业务可能中断",
				)
				break
			}
		}

		suspiciousNames := []string{"kworker", "kthreadd", "systemd-network", "ksoftirqd"}
		procName := fields[10]
		for _, suspicious := range suspiciousNames {
			if strings.HasPrefix(procName, suspicious) && !strings.HasPrefix(procName, suspicious) {
				continue
			}
			if strings.Contains(procName, suspicious) && strings.Contains(cmdline, "/tmp/") {
				rb.AddFinding(
					types.SeverityHigh,
					fmt.Sprintf("仿冒内核进程: %s", procName),
					fmt.Sprintf("进程名仿冒内核线程 %s 但从 /tmp 启动: %s", suspicious, cmdline),
					fmt.Sprintf("pid:%s", fields[1]),
					fmt.Sprintf(`{"name":"%s","cmd":"%s"}`, procName, cmdline),
					fmt.Sprintf("Kill 进程: kill -9 %s", fields[1]),
					"Kill 进程前请确认非系统进程",
				)
			}
		}
	}

	return rb.GetFindings(), nil
}

// ScanCronTasks Y4: 计划任务风险扫描
func (s *ServerSecurityGuard) ScanCronTasks(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "cron_tasks")

	cronPaths := []string{"/etc/crontab"}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			cronPaths = append(cronPaths, filepath.Join("/etc/cron.d", e.Name()))
		}
	}

	if output, err := exec.CommandContext(ctx, "crontab", "-l").Output(); err == nil {
		s.analyzeCronContent(rb, string(output), "root crontab")
	}

	for _, path := range cronPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s.analyzeCronContent(rb, string(data), path)
	}

	return rb.GetFindings(), nil
}

func (s *ServerSecurityGuard) analyzeCronContent(rb *scannercommon.ReportBuilder, content, source string) {
	suspiciousPatterns := []string{
		"nc -e", "bash -i", "/dev/tcp/", "python -c", "perl -e",
		"wget -q", "curl -s", "chmod +x", "/tmp/", "base64 -d",
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lowerLine := strings.ToLower(line)

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(lowerLine, pattern) {
				rb.AddFinding(
					types.SeverityHigh,
					fmt.Sprintf("可疑定时任务: %s", pattern),
					fmt.Sprintf("在 %s 中检测到可疑命令模式 %s: %s", source, pattern, line),
					source,
					fmt.Sprintf(`{"source":"%s","line":"%s"}`, source, line),
					"注释或删除该定时任务",
					"删除定时任务后，依赖该任务的业务流程将停止运行",
				)
				break
			}
		}
	}
}

// ScanRootkit Y5: 可疑文件/rootkit 检测
// 检测内核模块、隐藏目录、异常 udev 规则、ld.so.preload 劫持、/var/adm rootkit 文件
func (s *ServerSecurityGuard) ScanRootkit(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "rootkit")

	// 1. 检查可疑内核模块
	if output, err := exec.CommandContext(ctx, "lsmod").Output(); err == nil {
		suspiciousModules := []string{"adore", "rootkit", "knark", "suckit", "modhide"}
		for _, line := range strings.Split(string(output), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			moduleName := strings.ToLower(fields[0])
			for _, suspicious := range suspiciousModules {
				if strings.Contains(moduleName, suspicious) {
					rb.AddFinding(
						types.SeverityCritical,
						fmt.Sprintf("可疑内核模块: %s", fields[0]),
						fmt.Sprintf("检测到可疑内核模块 %s，可能是 rootkit", fields[0]),
						fields[0],
						fmt.Sprintf(`{"module":"%s"}`, fields[0]),
						fmt.Sprintf("卸载模块: rmmod %s", fields[0]),
						"卸载内核模块后，依赖该模块的硬件/功能将失效",
					)
				}
			}
		}
	}

	// 2. 检查异常 udev 规则（RingH23 等 rootkit 常用持久化手段）
	// 已知合法 udev 规则白名单（云厂商标准组件）
	knownLegitUdevRules := map[string]bool{
		"99-gen-net-conf.rules": true, // 天翼云（CTYun）弹性网卡热插拔 DHCP 配置脚本
	}
	udevDir := "/etc/udev/rules.d"
	if entries, err := os.ReadDir(udevDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			// 跳过已知合法规则
			if knownLegitUdevRules[name] {
				continue
			}
			// 正常 udev 规则以数字开头（如 99-systemd.rules），恶意规则可能用随机 UUID
			if strings.Contains(name, "-") && !regexp.MustCompile(`^\d+-`).MatchString(name) {
				// 读取规则内容，检查是否有可疑行为（如加载 /var/adm、/tmp 下的脚本）
				rulePath := filepath.Join(udevDir, name)
				ruleData, readErr := os.ReadFile(rulePath)
				if readErr == nil {
					ruleContent := string(ruleData)
					// 只有规则内容包含可疑路径时才告警
					if strings.Contains(ruleContent, "/var/adm/") ||
						strings.Contains(ruleContent, "/dev/shm/") ||
						strings.Contains(ruleContent, "/tmp/.") ||
						(strings.Contains(ruleContent, "RUN==") && strings.Contains(ruleContent, "/tmp/")) {
						rb.AddFinding(
							types.SeverityCritical,
							fmt.Sprintf("异常 udev 规则: %s", rulePath),
							fmt.Sprintf("检测到异常 udev 规则文件 %s，规则内容包含可疑路径引用，可能是 rootkit 的持久化手段", name),
							rulePath,
							fmt.Sprintf(`{"file":"%s"}`, name),
							fmt.Sprintf("检查规则内容，确认后删除: rm -f %s", rulePath),
							"删除 udev 规则后需确认不会影响正常硬件识别",
						)
					}
				}
			}
		}
	}

	// 3. 检查 ld.so.preload（rootkit 常用的库劫持手段）
	preloadFile := "/etc/ld.so.preload"
	if data, err := os.ReadFile(preloadFile); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// 检查是否指向可疑路径
				if strings.Contains(line, "/var/adm/") || strings.Contains(line, "/tmp/") ||
					strings.Contains(line, "/dev/shm/") || !strings.HasPrefix(line, "/usr/") {
					rb.AddFinding(
						types.SeverityCritical,
						fmt.Sprintf("ld.so.preload 劫持: %s", line),
						fmt.Sprintf("/etc/ld.so.preload 中包含可疑模块路径 %s，可能是 rootkit 注入的恶意库", line),
						preloadFile,
						fmt.Sprintf(`{"file":"%s","module":"%s"}`, preloadFile, line),
						fmt.Sprintf("从 %s 中删除恶意路径: %s，然后执行 ldconfig", preloadFile, line),
						"删除 preload 模块后需确认无正常程序依赖该库",
					)
				}
			}
		}
	}

	// 4. 检查 /var/adm/ 目录（RingH23 rootkit 常用藏匿路径）
	// /var/adm 在某些 Linux 发行版是标准目录（存放系统管理日志等），
	// 只有包含可疑文件（隐藏文件、非文本文件、可执行文件）时才告警
	varAdmDir := "/var/adm"
	if info, err := os.Stat(varAdmDir); err == nil && info.IsDir() {
		if entries, err := os.ReadDir(varAdmDir); err == nil && len(entries) > 0 {
			suspiciousFiles := 0
			for _, entry := range entries {
				entryName := entry.Name()
				// 检查是否有隐藏文件（以 . 开头）或可疑可执行文件
				if strings.HasPrefix(entryName, ".") ||
					strings.HasSuffix(entryName, ".so") ||
					strings.HasSuffix(entryName, ".sh") {
					suspiciousFiles++
				}
			}
			// 只有存在可疑文件时才告警
			if suspiciousFiles > 0 {
				rb.AddFinding(
					types.SeverityCritical,
					fmt.Sprintf("可疑 rootkit 目录: %s", varAdmDir),
					fmt.Sprintf("/var/adm/ 目录中存在 %d 个可疑文件（隐藏文件或可执行文件），可能是 rootkit 的藏匿目录", suspiciousFiles),
					varAdmDir,
					fmt.Sprintf(`{"dir":"%s","suspicious_count":%d}`, varAdmDir, suspiciousFiles),
					fmt.Sprintf("检查目录内容，确认后删除: rm -rf %s", varAdmDir),
					"删除前请确认非系统正常使用",
				)
			}
		}
	}

	// 5. 只扫描常见隐藏目录所在路径，避免全盘 find / 导致超时
	hiddenDirScanPaths := []string{"/tmp", "/var/tmp", "/dev/shm", "/root", "/home"}
	suspiciousHiddenDirs := map[string]bool{
		".ICE-unix": true, ".X11-unix": true, ".font-unix": true,
	}
	for _, searchDir := range hiddenDirScanPaths {
		if _, err := os.Stat(searchDir); err != nil {
			continue
		}
		filepath.WalkDir(searchDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				base := filepath.Base(path)
				if suspiciousHiddenDirs[base] {
					rb.AddFinding(
						types.SeverityMedium,
						fmt.Sprintf("可疑隐藏目录: %s", path),
						fmt.Sprintf("发现可疑隐藏目录 %s，可能被用于存放恶意文件", base),
						path,
						fmt.Sprintf(`{"dir":"%s"}`, path),
						fmt.Sprintf("检查目录内容，确认无恶意文件后删除: rm -rf %s", path),
						"删除前请确认目录非系统正常使用",
					)
				}
			}
			return nil
		})
	}

	return rb.GetFindings(), nil
}

// ScanFileIntegrity Y6: 系统关键文件完整性
func (s *ServerSecurityGuard) ScanFileIntegrity(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "file_integrity")

	criticalFiles := []string{
		"/sbin/init",
		"/etc/ssh/sshd_config",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/bin/login",
		"/usr/bin/passwd",
	}

	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err != nil {
			rb.AddFinding(
				types.SeverityHigh,
				fmt.Sprintf("关键文件缺失: %s", file),
				fmt.Sprintf("系统关键文件 %s 不存在，可能被删除或篡改", file),
				file,
				fmt.Sprintf(`{"file":"%s"}`, file),
				"从备份或包管理器恢复该文件",
				"恢复系统文件会覆盖当前版本，如果系统已做过安全升级，恢复旧版本会重新引入漏洞",
			)
		}
	}

	return rb.GetFindings(), nil
}

// ScanSSHBehavior Y7: 登录与 SSH 行为审计
func (s *ServerSecurityGuard) ScanSSHBehavior(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "ssh_behavior")

	logPaths := []string{"/var/log/secure", "/var/log/auth.log"}
	for _, logPath := range logPaths {
		data, err := os.ReadFile(logPath)
		if err != nil {
			continue
		}
		content := string(data)

		failRegex := regexp.MustCompile(`Failed password for .* from (\d+\.\d+\.\d+\.\d+)`)
		matches := failRegex.FindAllStringSubmatch(content, -1)

		ipFailCount := make(map[string]int)
		for _, match := range matches {
			if len(match) > 1 {
				ipFailCount[match[1]]++
			}
		}

		for ip, count := range ipFailCount {
			if count >= 10 {
				rb.AddFinding(
					types.SeverityHigh,
					fmt.Sprintf("SSH 暴力破解: %s", ip),
					fmt.Sprintf("IP %s 在日志中有 %d 次登录失败记录，可能正在暴力破解", ip, count),
					ip,
					fmt.Sprintf(`{"ip":"%s","fail_count":%d}`, ip, count),
					fmt.Sprintf("封禁 IP: iptables -A INPUT -s %s -j DROP", ip),
					"封禁 IP 后，该 IP 的所有服务访问全部断开，如果误封正常用户 IP 需手动解封",
				)
			}
		}

		break
	}

	return rb.GetFindings(), nil
}

// ScanPHPConfig 检测 PHP 危险函数是否已禁用
// 检查所有 php.ini 配置文件中的 disable_functions 指令
func (s *ServerSecurityGuard) ScanPHPConfig(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "php_config")

	// 常见 php.ini 路径
	phpIniPaths := []string{
		"/etc/php.ini",
		"/usr/local/php/etc/php.ini",
		"/www/server/php/*/etc/php.ini",
		"/etc/php/*/php.ini",
		"/usr/local/etc/php/php.ini",
	}

	// 危险函数列表
	dangerousFunctions := []string{
		"system", "exec", "passthru", "shell_exec", "popen",
		"proc_open", "putenv", "dl", "pcntl_exec",
	}

	// 收集所有实际存在的 php.ini 文件
	var iniFiles []string
	for _, pattern := range phpIniPaths {
		// 处理通配符路径
		if strings.Contains(pattern, "*") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			iniFiles = append(iniFiles, matches...)
		} else {
			if _, err := os.Stat(pattern); err == nil {
				iniFiles = append(iniFiles, pattern)
			}
		}
	}

	for _, iniPath := range iniFiles {
		data, err := os.ReadFile(iniPath)
		if err != nil {
			continue
		}
		content := string(data)

		// 提取 PHP 版本（用于报告）
		phpVersion := "unknown"
		versionRegex := regexp.MustCompile(`PHP_Version\s*=\s*"([^"]+)"`)
		if match := versionRegex.FindStringSubmatch(content); len(match) > 1 {
			phpVersion = match[1]
		}

		// 查找 disable_functions 指令
		disableRegex := regexp.MustCompile(`(?m)^\s*disable_functions\s*=\s*(.*)$`)
		match := disableRegex.FindStringSubmatch(content)

		var disabledSet map[string]bool
		if match != nil && len(match) > 1 {
			disabledList := strings.Split(match[1], ",")
			disabledSet = make(map[string]bool, len(disabledList))
			for _, fn := range disabledList {
				disabledSet[strings.TrimSpace(fn)] = true
			}
		} else {
			disabledSet = make(map[string]bool)
		}

		// 检查哪些危险函数未禁用
		var notDisabled []string
		for _, fn := range dangerousFunctions {
			if !disabledSet[fn] {
				notDisabled = append(notDisabled, fn)
			}
		}

		if len(notDisabled) > 0 {
			severity := types.SeverityMedium
			// 如果 system/exec/passthru/shell_exec 未禁用，升级为高危
			for _, fn := range notDisabled {
				if fn == "system" || fn == "exec" || fn == "passthru" || fn == "shell_exec" {
					severity = types.SeverityHigh
					break
				}
			}

			rb.AddFinding(
				severity,
				fmt.Sprintf("PHP 危险函数未禁用: %s", strings.Join(notDisabled, ", ")),
				fmt.Sprintf("PHP 配置文件 %s (版本 %s) 中以下危险函数未加入 disable_functions: %s", iniPath, phpVersion, strings.Join(notDisabled, ", ")),
				iniPath,
				fmt.Sprintf(`{"php_version":"%s","not_disabled":["%s"],"ini_path":"%s"}`, phpVersion, strings.Join(notDisabled, `","`), iniPath),
				fmt.Sprintf("在 %s 的 disable_functions 中添加: %s", iniPath, strings.Join(notDisabled, ",")),
				"禁用危险函数后，依赖这些函数的 PHP 程序将无法执行系统命令，请确认业务无影响",
			)
		}
	}

	return rb.GetFindings(), nil
}

// GetLastScanTime 获取上次扫描时间
func (s *ServerSecurityGuard) GetLastScanTime() time.Time {
	return time.Time{}
}

// ScanRedisSecurity Y8: Redis 安全检测
// 检测 Redis 未授权访问、空口令、危险配置
func (s *ServerSecurityGuard) ScanRedisSecurity(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "redis_security")

	// 检查 Redis 配置文件
	redisConfigPaths := []string{
		"/etc/redis/redis.conf",
		"/etc/redis.conf",
		"/usr/local/redis/etc/redis.conf",
		"/www/server/redis/redis.conf",
	}

	for _, configPath := range redisConfigPaths {
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		content := string(data)

		// 检查是否设置了密码
		hasPassword := false
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(line, "requirepass") && len(strings.Fields(line)) > 1 {
				hasPassword = true
				break
			}
		}

		if !hasPassword {
			rb.AddFinding(
				types.SeverityCritical,
				"Redis 未设置密码",
				fmt.Sprintf("Redis 配置文件 %s 未设置 requirepass，任何人可连接 Redis 执行任意操作（读写数据、写入 SSH 公钥、写入 crontab 后门）", configPath),
				configPath,
				fmt.Sprintf(`{"config":"%s","issue":"no_password"}`, configPath),
				fmt.Sprintf("在 %s 中设置: requirepass YourStrongPassword123", configPath),
				"设置密码后，现有应用程序需要更新 Redis 连接配置，否则无法连接",
			)
		}

		// 检查是否绑定了所有接口
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(line, "bind") {
				bindValue := strings.TrimSpace(strings.TrimPrefix(line, "bind"))
				if bindValue == "0.0.0.0" || bindValue == "" {
					rb.AddFinding(
						types.SeverityHigh,
						"Redis 绑定所有接口",
						fmt.Sprintf("Redis 配置文件 %s 绑定到 0.0.0.0，Redis 服务对外暴露，结合无密码可被远程利用", configPath),
						configPath,
						fmt.Sprintf(`{"config":"%s","bind":"%s"}`, configPath, bindValue),
						fmt.Sprintf("将 bind 改为 127.0.0.1 或具体内网 IP: bind 127.0.0.1"),
						"修改 bind 后，远程 Redis 客户端将无法连接，需更新连接配置",
					)
				}
			}
		}

		// 检查是否禁用了危险命令
		hasRenameCommand := false
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(line, "rename-command") {
				hasRenameCommand = true
				break
			}
		}

		if !hasRenameCommand {
			rb.AddFinding(
				types.SeverityMedium,
				"Redis 未禁用危险命令",
				fmt.Sprintf("Redis 配置文件 %s 未禁用 FLUSHALL/CONFIG/KEYS 等危险命令，攻击者可清空数据或读取配置", configPath),
				configPath,
				fmt.Sprintf(`{"config":"%s","issue":"no_rename_command"}`, configPath),
				fmt.Sprintf("在 %s 中添加:\n  rename-command FLUSHALL \"\"\n  rename-command CONFIG \"\"\n  rename-command KEYS \"\"", configPath),
				"禁用命令后，管理工具依赖这些命令的功能将不可用",
			)
		}
	}

	return rb.GetFindings(), nil
}

// ScanMySQLSecurity Y9: MySQL 安全检测
// 检测 MySQL root 空口令、匿名用户、远程 root 登录
func (s *ServerSecurityGuard) ScanMySQLSecurity(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "mysql_security")

	// 尝试检测 MySQL 配置文件
	mysqlConfigPaths := []string{
		"/etc/my.cnf",
		"/etc/mysql/my.cnf",
		"/www/server/mysql/my.cnf",
		"/usr/local/mysql/etc/my.cnf",
	}

	for _, configPath := range mysqlConfigPaths {
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		content := string(data)

		// 检查是否允许远程 root 登录
		if strings.Contains(content, "bind-address") {
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "bind-address") {
					value := strings.TrimSpace(strings.Split(line, "=")[1])
					if value == "0.0.0.0" || value == "*" {
						rb.AddFinding(
							types.SeverityHigh,
							"MySQL 绑定所有接口",
							fmt.Sprintf("MySQL 配置 %s 绑定到 %s，数据库对外暴露", configPath, value),
							configPath,
							fmt.Sprintf(`{"config":"%s","bind":"%s"}`, configPath, value),
							"将 bind-address 改为 127.0.0.1",
							"修改后远程 MySQL 客户端无法连接，需通过 SSH 隧道或更新配置",
						)
					}
				}
			}
		}
	}

	// 尝试用无密码连接 MySQL 检测 root 空口令
	cmd := exec.CommandContext(ctx, "mysql", "-u", "root", "-e", "SELECT 1")
	if err := cmd.Run(); err == nil {
		// 无密码连接成功 = root 空口令
		rb.AddFinding(
			types.SeverityCritical,
			"MySQL root 空口令",
			"MySQL root 用户无密码即可连接，任何人可通过 mysql -u root 登录",
			"mysql",
			`{"issue":"root_empty_password"}`,
			"设置 root 密码: mysqladmin -u root password \"YourStrongPassword\"",
			"设置密码后，所有 MySQL 客户端和应用程序需更新连接配置",
		)
	}

	// 检查 MySQL 是否有匿名用户
	cmd = exec.CommandContext(ctx, "mysql", "-u", "root", "-e",
		"SELECT user,host FROM mysql.user WHERE user=''")
	if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) != "" {
		// 检查是否有匿名用户
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) > 1 {
			rb.AddFinding(
				types.SeverityHigh,
				"MySQL 存在匿名用户",
				"MySQL 有匿名用户账户，任何人可无凭据连接数据库",
				"mysql",
				`{"issue":"anonymous_user","detail":"检查 mysql.user 表中 user='' 的行"}`,
				"删除匿名用户: DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;",
				"删除匿名用户后，依赖匿名连接的应用将无法工作",
			)
		}
	}

	return rb.GetFindings(), nil
}

// ScanSSHKeySecurity Y10: SSH 密钥安全检测
// 检测 authorized_keys 中的弱密钥、过多密钥、异常密钥
func (s *ServerSecurityGuard) ScanSSHKeySecurity(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "ssh_key_security")

	// 检查 root 和普通用户的 authorized_keys
	homeDirs := []string{"/root", "/home"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homeDirs = append(homeDirs, filepath.Join("/home", e.Name()))
			}
		}
	}

	for _, homeDir := range homeDirs {
		sshDir := filepath.Join(homeDir, ".ssh")
		authKeysPath := filepath.Join(sshDir, "authorized_keys")

		data, err := os.ReadFile(authKeysPath)
		if err != nil {
			continue
		}
		content := string(data)
		lines := strings.Split(content, "\n")

		keyCount := 0
		weakKeys := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			keyCount++

			// 检查弱密钥类型和短密钥
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				keyType := parts[0]
				keyData := parts[1]

				// DSA 密钥已不安全
				if keyType == "ssh-dss" {
					weakKeys++
					rb.AddFinding(
						types.SeverityMedium,
						fmt.Sprintf("弱 SSH 密钥类型(DSA): %s", authKeysPath),
						fmt.Sprintf("authorized_keys 包含 DSA 密钥（已不安全，OpenSSH 7.0+ 默认禁用）"),
						authKeysPath,
						fmt.Sprintf(`{"path":"%s","key_type":"ssh-dss"}`, authKeysPath),
						"删除 DSA 密钥，使用 ed25519 或 RSA 4096 位密钥替代",
						"删除密钥后，使用该密钥的客户端将无法登录",
					)
				}

				// RSA 密钥过短（base64 编码后长度小于 372 字符 ≈ 2048 位）
				if keyType == "ssh-rsa" && len(keyData) < 372 {
					weakKeys++
					rb.AddFinding(
						types.SeverityMedium,
						fmt.Sprintf("短 RSA SSH 密钥: %s", authKeysPath),
						fmt.Sprintf("authorized_keys 包含短 RSA 密钥（可能低于 2048 位），存在被暴力破解风险"),
						authKeysPath,
						fmt.Sprintf(`{"path":"%s","key_type":"ssh-rsa","key_length":"<2048"}`, authKeysPath),
						"替换为 4096 位 RSA 密钥或 ed25519 密钥",
						"替换密钥后，使用旧密钥的客户端需更新",
					)
				}
			}
		}

		// 密钥过多
		if keyCount > 10 {
			rb.AddFinding(
				types.SeverityLow,
				fmt.Sprintf("SSH 授权密钥过多: %s (%d 个)", authKeysPath, keyCount),
				fmt.Sprintf("authorized_keys 中有 %d 个密钥，过多的密钥增加攻击面，建议清理不再使用的密钥", keyCount),
				authKeysPath,
				fmt.Sprintf(`{"path":"%s","key_count":%d}`, authKeysPath, keyCount),
				"审查并删除不再使用的 SSH 密钥",
				"删除密钥后，使用该密钥的客户端将无法登录",
			)
		}
	}

	return rb.GetFindings(), nil
}

// ScanNetworkMisconfig Y11: 网络配置安全检测
// 检测异常路由、iptables 规则、hosts 文件篡改
func (s *ServerSecurityGuard) ScanNetworkMisconfig(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("serversecurity", "network_misconfig")

	// 检查 hosts 文件是否被篡改
	hostsPath := "/etc/hosts"
	if data, err := os.ReadFile(hostsPath); err == nil {
		content := string(data)
		knownBadDomains := []string{
			"paypal.com", "alipay.com", "weixin.qq.com", "qq.com",
			"taobao.com", "tmall.com", "jd.com", "baidu.com",
			"github.com", "google.com", "apple.com", "microsoft.com",
			"amazonaws.com", "cloudflare.com",
		}

		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lowerLine := strings.ToLower(line)
			for _, domain := range knownBadDomains {
				if strings.Contains(lowerLine, domain) {
					// 检查是否被指向到异常 IP
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						ip := fields[0]
						// 如果域名被指向到非官方 IP
						parsedIP := net.ParseIP(ip)
						if parsedIP != nil && !parsedIP.IsLoopback() {
							rb.AddFinding(
								types.SeverityCritical,
								fmt.Sprintf("hosts 文件可疑条目: %s -> %s", domain, ip),
								fmt.Sprintf("hosts 文件将 %s 指向到 %s，可能是 DNS 劫持/钓鱼攻击", domain, ip),
								hostsPath,
								fmt.Sprintf(`{"path":"%s","line":"%s"}`, hostsPath, line),
								fmt.Sprintf("删除 hosts 文件中的可疑行: %s", line),
								"删除后该域名将使用正常 DNS 解析",
							)
						}
					}
				}
			}
		}
	}

	// 检查 iptables 是否有可疑的 NAT/转发规则
	if output, err := exec.CommandContext(ctx, "iptables", "-t", "nat", "-L", "-n").Output(); err == nil {
		suspiciousPatterns := []string{
			"REDIRECT", "DNAT", "SNAT",
		}
		for _, line := range strings.Split(string(output), "\n") {
			for _, pattern := range suspiciousPatterns {
				if strings.Contains(line, pattern) {
					fields := strings.Fields(line)
					if len(fields) >= 0 {
						// 检查是否重定向到外部 IP
						for _, field := range fields {
							if net.ParseIP(field) != nil && !net.ParseIP(field).IsLoopback() && !net.ParseIP(field).IsPrivate() {
								rb.AddFinding(
									types.SeverityHigh,
									fmt.Sprintf("可疑 iptables NAT 规则: %s", pattern),
									fmt.Sprintf("iptables NAT 表包含重定向到外部 IP %s 的规则，可能是流量劫持: %s", field, line),
									"iptables",
									fmt.Sprintf(`{"table":"nat","rule":"%s"}`, line),
									fmt.Sprintf("审查并删除可疑规则: iptables -t nat -D <规则>"),
									"删除 NAT 规则后，依赖该规则的端口映射/转发将失效",
								)
								break
							}
						}
					}
					break
				}
			}
		}
	}

	// 检查是否禁用了 IP 转发（作为网关时才需要开启）
	ipForwardPath := "/proc/sys/net/ipv4/ip_forward"
	if data, err := os.ReadFile(ipForwardPath); err == nil {
		value := strings.TrimSpace(string(data))
		if value == "1" {
			// 检查是否是网关/路由器场景
			// 如果不是网关但开启了 IP 转发，可能是攻击者用于流量中转
			rb.AddFinding(
				types.SeverityLow,
				"IP 转发已开启",
				"服务器开启了 IP 转发 (net.ipv4.ip_forward=1)，如果非网关/路由器场景，可能被攻击者用于流量中转",
				ipForwardPath,
				fmt.Sprintf(`{"param":"ip_forward","value":"%s"}`, value),
				"如非网关场景，建议关闭: sysctl -w net.ipv4.ip_forward=0",
				"关闭 IP 转发后，作为路由/网关的功能将失效",
			)
		}
	}

	return rb.GetFindings(), nil
}
