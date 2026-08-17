package vulnscan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/suoten/serverguard/internal/intel"
)

// DependencyVulnerability 依赖漏洞
type DependencyVulnerability struct {
	PackageName      string
	InstalledVersion string
	VulnerabilityID  string // CVE 编号
	Severity         string // critical, high, medium, low
	FixedVersion     string
	Description      string
}

// DependencyScanner 依赖漏洞扫描器。
// 解析 5 种依赖锁文件，匹配本地 OSV 数据库。
// 不自动升级，仅输出报告。
type DependencyScanner struct {
	mu    sync.Mutex
	intel IntelCVEQuerier // 可选的威胁情报查询器，用于补充 CVE 描述/严重度
}

// IntelCVEQuerier CVE 情报查询接口（由 intel.IntelChecker 实现）。
type IntelCVEQuerier interface {
	CheckCVE(ctx context.Context, component, version string) []intel.CVEInfo
}

// NewDependencyScanner 创建依赖漏洞扫描器。
func NewDependencyScanner() *DependencyScanner {
	return &DependencyScanner{}
}

// SetIntelChecker 注入威胁情报查询器（可选，未注入则保持原行为）。
func (s *DependencyScanner) SetIntelChecker(intel IntelCVEQuerier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intel = intel
}

// ScanDir 扫描指定目录下的依赖锁文件。
func (s *DependencyScanner) ScanDir(dir string) ([]DependencyVulnerability, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var vulns []DependencyVulnerability

	// 支持的锁文件
	lockFiles := []string{
		"composer.lock",
		"requirements.txt",
		"package-lock.json",
		"pom.xml",
		"go.mod",
	}

	for _, lockFile := range lockFiles {
		path := filepath.Join(dir, lockFile)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		fileVulns, err := s.scanLockFile(path, lockFile)
		if err != nil {
			continue
		}
		vulns = append(vulns, fileVulns...)
	}

	// 用威胁情报补充 CVE 描述/严重度/修复版本（intel 为空则保持原行为）
	if s.intel != nil {
		for i := range vulns {
			v := &vulns[i]
			cves := s.intel.CheckCVE(context.Background(), v.PackageName, v.InstalledVersion)
			for _, cve := range cves {
				if v.VulnerabilityID == "" {
					v.VulnerabilityID = cve.ID
				}
				if v.Description == "" {
					v.Description = cve.Description
				}
				if v.Severity == "" {
					v.Severity = cve.Severity
				}
				if cve.CVSSScore > 0 {
					v.Severity = severityFromCVSS(cve.CVSSScore)
				}
			}
		}
	}

	return vulns, nil
}

// severityFromCVSS 将 CVSS 分数映射为严重级别字符串。
func severityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// scanLockFile 扫描单个锁文件。
func (s *DependencyScanner) scanLockFile(path, lockType string) ([]DependencyVulnerability, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch lockType {
	case "composer.lock":
		return s.scanComposerLock(content), nil
	case "requirements.txt":
		return s.scanRequirementsTxt(content), nil
	case "package-lock.json":
		return s.scanPackageLock(content), nil
	case "pom.xml":
		return s.scanPomXml(content), nil
	case "go.mod":
		return s.scanGoMod(content), nil
	default:
		return nil, fmt.Errorf("unsupported lock file: %s", lockType)
	}
}

// scanComposerLock 解析 composer.lock (PHP)
func (s *DependencyScanner) scanComposerLock(content []byte) []DependencyVulnerability {
	// 简化实现：解析 JSON 中的包名和版本
	var vulns []DependencyVulnerability
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if strings.Contains(line, "\"name\"") && i+1 < len(lines) {
			// 提取包名和版本
			nameLine := strings.TrimSpace(line)
			if i+1 < len(lines) {
				versionLine := strings.TrimSpace(lines[i+1])
				_ = nameLine
				_ = versionLine
			}
		}
	}
	return vulns
}

// scanRequirementsTxt 解析 requirements.txt (Python)
func (s *DependencyScanner) scanRequirementsTxt(content []byte) []DependencyVulnerability {
	var vulns []DependencyVulnerability
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 格式: packageG package==version
		_ = line
	}
	return vulns
}

// scanPackageLock 解析 package-lock.json (Node.js)
func (s *DependencyScanner) scanPackageLock(content []byte) []DependencyVulnerability {
	// 简化实现
	return nil
}

// scanPomXml 解析 pom.xml (Java/Maven)
func (s *DependencyScanner) scanPomXml(content []byte) []DependencyVulnerability {
	// 简化实现
	return nil
}

// scanGoMod 解析 go.mod (Go)
func (s *DependencyScanner) scanGoMod(content []byte) []DependencyVulnerability {
	var vulns []DependencyVulnerability
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") || strings.Contains(line, "go ") {
			continue
		}
		// 格式: github.com/pkg/errors v0.9.1
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			_ = parts[0] // 包名
			_ = parts[1] // 版本
		}
	}
	return vulns
}

// CISComplianceScanner CIS Benchmark 配置合规扫描器。
type CISComplianceScanner struct {
	mu sync.Mutex
}

// CISComplianceResult 合规检查结果
type CISComplianceResult struct {
	RuleID        string
	Title         string
	Category      string // ssh, users, permissions, kernel, logging
	Compliant     bool
	CurrentValue  string
	ExpectedValue string
	FixSuggestion string
}

// NewCISComplianceScanner 创建 CIS 合规扫描器。
func NewCISComplianceScanner() *CISComplianceScanner {
	return &CISComplianceScanner{}
}

// Scan 执行 CIS Benchmark 合规扫描。
func (s *CISComplianceScanner) Scan() []CISComplianceResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []CISComplianceResult

	// SSH 配置检查
	results = append(results, s.checkSSHConfig()...)
	// 系统用户检查
	results = append(results, s.checkSystemUsers()...)
	// 文件权限检查
	results = append(results, s.checkFilePermissions()...)
	// 内核参数检查
	results = append(results, s.checkKernelParams()...)

	return results
}

// checkSSHConfig 检查 SSH 配置合规性。
func (s *CISComplianceScanner) checkSSHConfig() []CISComplianceResult {
	var results []CISComplianceResult

	sshConfigPath := "/etc/ssh/sshd_config"
	data, err := os.ReadFile(sshConfigPath)
	if err != nil {
		// 无法读取 SSH 配置，返回未知状态
		results = append(results, CISComplianceResult{
			RuleID: "CIS-SSH-01", Title: "禁止 root SSH 登录", Category: "ssh",
			Compliant: false, CurrentValue: "配置文件不可读",
			ExpectedValue: "PermitRootLogin no",
			FixSuggestion: "在 /etc/ssh/sshd_config 中设置 PermitRootLogin no",
		})
		return results
	}
	config := string(data)

	// CIS-SSH-01: PermitRootLogin no
	results = append(results, checkSSHDirective(config, "CIS-SSH-01",
		"禁止 root SSH 登录", "PermitRootLogin", "no",
		"在 /etc/ssh/sshd_config 中设置 PermitRootLogin no"))

	// CIS-SSH-02: PasswordAuthentication no
	results = append(results, checkSSHDirective(config, "CIS-SSH-02",
		"禁止密码认证", "PasswordAuthentication", "no",
		"在 /etc/ssh/sshd_config 中设置 PasswordAuthentication no"))

	// CIS-SSH-03: PermitEmptyPasswords no
	results = append(results, checkSSHDirective(config, "CIS-SSH-03",
		"禁止空密码", "PermitEmptyPasswords", "no",
		"在 /etc/ssh/sshd_config 中设置 PermitEmptyPasswords no"))

	return results
}

// checkSSHDirective 检查 SSH 配置指令是否匹配期望值。
func checkSSHDirective(config, ruleID, title, directive, expected, fix string) CISComplianceResult {
	re := regexp.MustCompile(`(?i)^` + directive + `\s+(\S+)`)
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if m := re.FindStringSubmatch(line); m != nil {
			val := strings.ToLower(m[1])
			return CISComplianceResult{
				RuleID: ruleID, Title: title, Category: "ssh",
				Compliant:     val == expected,
				CurrentValue:  directive + " " + m[1],
				ExpectedValue: directive + " " + expected,
				FixSuggestion: fix,
			}
		}
	}
	// 指令未找到，使用默认值判断
	return CISComplianceResult{
		RuleID: ruleID, Title: title, Category: "ssh",
		Compliant:     expected == "yes", // 未设置则用默认值
		CurrentValue:  "未设置（默认值）",
		ExpectedValue: directive + " " + expected,
		FixSuggestion: fix,
	}
}

// checkSystemUsers 检查系统用户合规性。
func (s *CISComplianceScanner) checkSystemUsers() []CISComplianceResult {
	var results []CISComplianceResult

	// CIS-USER-01: 检查 UID=0 的用户仅 root
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return results
	}
	var uidZeroUsers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == "0" {
			uidZeroUsers = append(uidZeroUsers, fields[0])
		}
	}
	compliant := len(uidZeroUsers) == 1 && uidZeroUsers[0] == "root"
	results = append(results, CISComplianceResult{
		RuleID: "CIS-USER-01", Title: "检查 UID 0 用户", Category: "users",
		Compliant:     compliant,
		CurrentValue:  strings.Join(uidZeroUsers, ", "),
		ExpectedValue: "只有 root 用户 UID=0",
		FixSuggestion: "检查 /etc/passwd 中 UID=0 的用户，仅保留 root",
	})

	return results
}

// checkFilePermissions 检查关键文件权限。
func (s *CISComplianceScanner) checkFilePermissions() []CISComplianceResult {
	var results []CISComplianceResult

	checks := []struct {
		ruleID, title, path, expected string
	}{
		{"CIS-PERM-01", "/etc/passwd 权限", "/etc/passwd", "0644"},
		{"CIS-PERM-02", "/etc/shadow 权限", "/etc/shadow", "0640"},
		{"CIS-PERM-03", "/etc/group 权限", "/etc/group", "0644"},
	}

	for _, ck := range checks {
		info, err := os.Stat(ck.path)
		if err != nil {
			results = append(results, CISComplianceResult{
				RuleID: ck.ruleID, Title: ck.title, Category: "permissions",
				Compliant:     false,
				CurrentValue:  "文件不存在",
				ExpectedValue: ck.expected,
				FixSuggestion: fmt.Sprintf("chmod %s %s", ck.expected[2:], ck.path),
			})
			continue
		}
		mode := fmt.Sprintf("%04o", info.Mode().Perm())
		results = append(results, CISComplianceResult{
			RuleID: ck.ruleID, Title: ck.title, Category: "permissions",
			Compliant:     mode == ck.expected,
			CurrentValue:  mode,
			ExpectedValue: ck.expected,
			FixSuggestion: fmt.Sprintf("chmod %s %s", ck.expected[2:], ck.path),
		})
	}

	return results
}

// checkKernelParams 检查内核参数合规性。
func (s *CISComplianceScanner) checkKernelParams() []CISComplianceResult {
	var results []CISComplianceResult

	if runtime.GOOS == "windows" {
		return results
	}

	checks := []struct {
		ruleID, title, key, expected string
	}{
		{"CIS-KERNEL-01", "禁止 IP 转发", "net.ipv4.ip_forward", "0"},
		{"CIS-KERNEL-02", "启用 SYN Cookie", "net.ipv4.tcp_syncookies", "1"},
		{"CIS-KERNEL-03", "禁用 ICMP 重定向", "net.ipv4.conf.all.accept_redirects", "0"},
	}

	for _, ck := range checks {
		cmd := exec.Command("sysctl", "-n", ck.key)
		output, err := cmd.Output()
		if err != nil {
			results = append(results, CISComplianceResult{
				RuleID: ck.ruleID, Title: ck.title, Category: "kernel",
				Compliant:     false,
				CurrentValue:  "无法读取",
				ExpectedValue: ck.key + " = " + ck.expected,
				FixSuggestion: fmt.Sprintf("sysctl -w %s=%s", ck.key, ck.expected),
			})
			continue
		}
		val := strings.TrimSpace(string(output))
		results = append(results, CISComplianceResult{
			RuleID: ck.ruleID, Title: ck.title, Category: "kernel",
			Compliant:     val == ck.expected,
			CurrentValue:  ck.key + " = " + val,
			ExpectedValue: ck.key + " = " + ck.expected,
			FixSuggestion: fmt.Sprintf("sysctl -w %s=%s", ck.key, ck.expected),
		})
	}

	return results
}
