package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/guards/scannercommon"
)

// VulnScanGuard 漏洞扫描守护
type VulnScanGuard struct {
	store        *scannercommon.ReportBuilder
	cveDatabase  *CVEDatabase
	nvdAPIKey    string
	cnvdAPIKey   string
	lastSyncTime time.Time
	mu           sync.RWMutex
	intel        IntelCVEQuerier // 可选威胁情报查询器，用于补充外部 CVE（缺口A）
}

// SetIntelChecker 注入威胁情报查询器（可选，未注入则保持原行为）。
func (v *VulnScanGuard) SetIntelChecker(intel IntelCVEQuerier) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.intel = intel
}

// CVEDatabase CVE 漏洞库
type CVEDatabase struct {
	Entries []CVEEntry
	mu      sync.RWMutex
}

// CVEEntry CVE 条目
type CVEEntry struct {
	CVEID         string `json:"cve_id"`
	Product       string `json:"product"`
	VulnVersions  string `json:"vuln_versions"`
	FixedVersions string `json:"fixed_versions"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	ReferenceURL  string `json:"reference_url,omitempty"`
}

// NewVulnScanGuard 创建漏洞扫描守护
func NewVulnScanGuard() *VulnScanGuard {
	return &VulnScanGuard{
		cveDatabase: getDefaultCVEDatabase(),
	}
}

// NewVulnScanGuardWithIntel 创建带情报源同步能力的漏洞扫描守护
func NewVulnScanGuardWithIntel(nvdAPIKey, cnvdAPIKey string) *VulnScanGuard {
	return &VulnScanGuard{
		cveDatabase: getDefaultCVEDatabase(),
		nvdAPIKey:   nvdAPIKey,
		cnvdAPIKey:  cnvdAPIKey,
	}
}

// Scan 执行全量漏洞扫描
func (v *VulnScanGuard) Scan(ctx context.Context, webRoots []string) ([]types.ScanFinding, error) {
	var allFindings []types.ScanFinding

	if findings, err := v.ScanComponents(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := v.ScanSystemPackages(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := v.ScanCMS(ctx, webRoots); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := v.ScanDependencies(ctx, webRoots); err == nil {
		allFindings = append(allFindings, findings...)
	}
	if findings, err := v.ScanConfigCompliance(ctx); err == nil {
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// ScanComponents X1: 软件组件漏洞扫描
func (v *VulnScanGuard) ScanComponents(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("vulnscan", "system-components")

	components := []struct {
		name string
		cmd  string
		args []string
	}{
		{"nginx", "nginx", []string{"-v"}},
		{"apache", "apachectl", []string{"-v"}},
		{"php", "php", []string{"-v"}},
		{"mysql", "mysql", []string{"--version"}},
		{"redis", "redis-server", []string{"--version"}},
		{"openssl", "openssl", []string{"version"}},
		{"openssh", "ssh", []string{"-V"}},
		{"node", "node", []string{"--version"}},
		{"python", "python3", []string{"--version"}},
		{"docker", "docker", []string{"--version"}},
	}

	for _, comp := range components {
		rawVersion, err := getCommandVersion(ctx, comp.cmd, comp.args)
		if err != nil || rawVersion == "" {
			continue
		}

		// 从原始输出中提取干净的版本号
		cleanVersion := extractProductVersion(comp.name, rawVersion)
		if cleanVersion == "" {
			continue
		}

		for _, cve := range v.cveDatabase.Entries {
			if !strings.EqualFold(cve.Product, comp.name) {
				continue
			}

			// 核心改进：只有当前版本确实在受影响范围内才报告漏洞
			if !isVersionVulnerable(cleanVersion, cve.VulnVersions) {
				continue
			}

			severity := parseSeverity(cve.Severity)
			// 智能修复建议：根据产品类型提供具体的升级命令
			fixGuide := getSmartFixGuide(comp.name, cve.FixedVersions, cleanVersion)
			rb.AddFinding(
				severity,
				fmt.Sprintf("%s 漏洞: %s", comp.name, cve.CVEID),
				fmt.Sprintf("检测到 %s %s 存在已知漏洞 %s: %s\n详情参考: %s", comp.name, cleanVersion, cve.CVEID, cve.Description, cve.ReferenceURL),
				comp.name,
				fmt.Sprintf(`{"product":"%s","current_version":"%s","cve":"%s","severity":"%s","fixed_version":"%s","reference":"%s"}`, comp.name, cleanVersion, cve.CVEID, cve.Severity, cve.FixedVersions, cve.ReferenceURL),
				fixGuide,
				fmt.Sprintf("升级 %s 可能导致配置不兼容或服务中断，建议在测试环境验证后再升级", comp.name),
			)
		}

		// 威胁情报补充：查询外部情报源，补充本地 CVE 库之外的新漏洞（缺口A）
		if v.intel != nil && cleanVersion != "" {
			for _, cve := range v.intel.CheckCVE(ctx, comp.name, cleanVersion) {
				ref := ""
				if len(cve.References) > 0 {
					ref = " 详情参考: " + cve.References[0]
				}
				fixGuide := getSmartFixGuide(comp.name, "最新安全版本", cleanVersion)
				rb.AddFinding(
					parseSeverity(cve.Severity),
					fmt.Sprintf("%s 情报漏洞: %s", comp.name, cve.ID),
					fmt.Sprintf("外部威胁情报检测到 %s %s 存在漏洞 %s: %s%s", comp.name, cleanVersion, cve.ID, cve.Description, ref),
					comp.name,
					fmt.Sprintf(`{"product":"%s","current_version":"%s","cve":"%s","severity":"%s","source":"intel"}`, comp.name, cleanVersion, cve.ID, cve.Severity),
					fixGuide,
					fmt.Sprintf("升级 %s 可能导致配置不兼容或服务中断，建议在测试环境验证后再升级", comp.name),
				)
			}
		}
	}

	return rb.GetFindings(), nil
}

// ScanSystemPackages 扫描系统安装的软件包是否存在已知 CVE 漏洞
// 支持 rpm (CentOS/RHEL) 和 dpkg (Debian/Ubuntu) 包管理器
func (v *VulnScanGuard) ScanSystemPackages(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("vulnscan", "system-packages")

	// 已知漏洞软件包数据库（包名 -> 漏洞信息列表）
	// 这些是常见的、影响服务器安全的关键 CVE
	knownVulnPackages := getKnownVulnPackages()

	// 尝试 rpm（CentOS/RHEL/Alibaba Cloud Linux 等）
	packages, err := getRpmPackages(ctx)
	if err != nil || len(packages) == 0 {
		// 回退到 dpkg（Debian/Ubuntu）
		packages, err = getDpkgPackages(ctx)
		if err != nil || len(packages) == 0 {
			return rb.GetFindings(), nil
		}
	}

	for _, pkg := range packages {
		vulns, exists := knownVulnPackages[pkg.Name]
		if !exists {
			continue
		}

		for _, vuln := range vulns {
			// 版本比较：如果当前版本低于修复版本，报告漏洞
			if isVersionLower(pkg.Version, vuln.FixedVersion) {
				rb.AddFinding(
					vuln.Severity,
					fmt.Sprintf("系统软件漏洞: %s-%s (%s)", pkg.Name, pkg.Version, vuln.CVEID),
					fmt.Sprintf("发现以下系统软件存在安全漏洞:\n%s-%s 版本低于 %s\n涉及漏洞: %s\n漏洞描述: %s\n详情参考官方公告: %s",
						pkg.Name, pkg.Version, vuln.FixedVersion, vuln.CVEID, vuln.Description, vuln.ReferenceURL),
					pkg.Name,
					fmt.Sprintf(`{"package":"%s","current_version":"%s","fixed_version":"%s","cve":"%s","severity":"%s","reference":"%s"}`,
						pkg.Name, pkg.Version, vuln.FixedVersion, vuln.CVEID, string(vuln.Severity), vuln.ReferenceURL),
					fmt.Sprintf("更新软件至安全版本: yum update %s 或 dnf update %s", pkg.Name, pkg.Name),
					"修复漏洞具有一定风险，建议做好系统快照，防止影响系统运行",
				)
			}
		}
	}

	return rb.GetFindings(), nil
}

// systemPackage 表示一个已安装的系统软件包
type systemPackage struct {
	Name    string
	Version string
}

// vulnPackageInfo 表示一个软件包的已知漏洞信息
type vulnPackageInfo struct {
	CVEID        string
	FixedVersion string
	Severity     types.Severity
	Description  string
	ReferenceURL string
}

// getRpmPackages 使用 rpm -qa 获取已安装的 RPM 包列表
func getRpmPackages(ctx context.Context) ([]systemPackage, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []systemPackage
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		packages = append(packages, systemPackage{
			Name:    strings.TrimSpace(parts[0]),
			Version: strings.TrimSpace(parts[1]),
		})
	}

	return packages, nil
}

// getDpkgPackages 使用 dpkg -l 获取已安装的 DEB 包列表
func getDpkgPackages(ctx context.Context) ([]systemPackage, error) {
	cmd := exec.CommandContext(ctx, "dpkg", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []systemPackage
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "ii" {
			continue
		}
		packages = append(packages, systemPackage{
			Name:    fields[1],
			Version: fields[2],
		})
	}

	return packages, nil
}

// extractProductVersion 从命令原始输出中提取干净的版本号
// 例如: "nginx version: nginx/1.24.0" -> "1.24.0"
//
//	"OpenSSL 3.0.7 1 Nov 2022" -> "3.0.7"
//	"Redis server v=7.0.11" -> "7.0.11"
func extractProductVersion(product, raw string) string {
	// 通用正则：匹配 x.y.z 或 x.y.z.p 格式的版本号
	versionRe := regexp.MustCompile(`(\d+\.\d+\.\d+(?:\.\d+)?)`)

	switch strings.ToLower(product) {
	case "nginx":
		// nginx version: nginx/1.24.0
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "apache":
		// Server version: Apache/2.4.57 (Unix)
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "php":
		// PHP 8.1.2 (cli)
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "mysql":
		// mysql  Ver 8.0.36 for Linux
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "redis":
		// Redis server v=7.0.11 sha=...
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "openssl":
		// OpenSSL 3.0.7 1 Nov 2022
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "openssh":
		// OpenSSH_8.7p1, OpenSSL 1.1.1k
		re := regexp.MustCompile(`OpenSSH_([\d.]+p\d+)`)
		if m := re.FindStringSubmatch(raw); len(m) > 1 {
			return m[1]
		}
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "node":
		// v18.19.0
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "python":
		// Python 3.11.5
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	case "docker":
		// Docker version 24.0.7, build afdd53b
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	}

	// 通用回退
	if m := versionRe.FindString(raw); m != "" {
		return m
	}
	return ""
}

// isVersionVulnerable 判断当前版本是否在受影响范围内
// vulnRange 格式: "<1.21.0", "<=1.20.2", ">=1.0,<2.0", "*"(所有版本)
func isVersionVulnerable(currentVersion, vulnRange string) bool {
	if vulnRange == "*" || vulnRange == "" {
		return true
	}

	current := parseSemanticVersion(currentVersion)
	if current == nil {
		return false
	}

	// 支持逗号分隔的多个条件（AND 关系）
	conditions := strings.Split(vulnRange, ",")
	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if !checkVersionCondition(current, cond) {
			return false
		}
	}
	return true
}

// checkVersionCondition 检查单个版本条件
func checkVersionCondition(current []int, cond string) bool {
	cond = strings.TrimSpace(cond)

	// 解析操作符和版本号
	var op string
	var verStr string

	for _, prefix := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(cond, prefix) {
			op = prefix
			verStr = strings.TrimSpace(cond[len(prefix):])
			break
		}
	}

	if op == "" || verStr == "" {
		return false
	}

	target := parseSemanticVersion(verStr)
	if target == nil {
		return false
	}

	cmp := compareVersions(current, target)

	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=":
		return cmp == 0
	}
	return false
}

// parseSemanticVersion 将版本字符串解析为数字数组
// 例如: "1.24.0" -> [1, 24, 0], "8.7p1" -> [8, 7, 1]
func parseSemanticVersion(version string) []int {
	// 先处理 openssh 特殊格式 8.7p1
	sshRe := regexp.MustCompile(`(\d+)\.(\d+)p(\d+)`)
	if m := sshRe.FindStringSubmatch(version); len(m) == 4 {
		var nums [3]int
		fmt.Sscanf(m[1], "%d", &nums[0])
		fmt.Sscanf(m[2], "%d", &nums[1])
		fmt.Sscanf(m[3], "%d", &nums[2])
		return nums[:]
	}

	// 通用: 提取 x.y.z 格式
	re := regexp.MustCompile(`(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?`)
	m := re.FindStringSubmatch(version)
	if m == nil {
		return nil
	}

	var parts []int
	for _, s := range m[1:] {
		if s == "" {
			break
		}
		var n int
		fmt.Sscanf(s, "%d", &n)
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return nil
	}
	// 补齐到至少 3 位
	for len(parts) < 3 {
		parts = append(parts, 0)
	}
	return parts
}

// compareVersions 比较两个版本数组
// 返回 -1, 0, 1
func compareVersions(a, b []int) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// parseSeverity 将字符串转为 types.Severity
func parseSeverity(s string) types.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityMedium
	}
}

// getSmartFixGuide 根据产品类型生成智能修复建议
func getSmartFixGuide(product, fixedVersions, currentVersion string) string {
	switch strings.ToLower(product) {
	case "nginx":
		return fmt.Sprintf("1. 使用包管理器升级: yum update nginx 或 dnf update nginx\n2. 如需指定版本: yum install nginx-%s\n3. 如从源码编译: 下载 %s 版本源码重新编译\n4. 升级后重启: systemctl restart nginx\n当前版本: %s", fixedVersions, fixedVersions, currentVersion)
	case "openssl":
		return fmt.Sprintf("1. 使用包管理器升级: yum update openssl 或 dnf update openssl\n2. 如需指定版本: yum install openssl-%s\n3. 升级后需重启依赖 OpenSSL 的服务（nginx, apache, sshd 等）\n当前版本: %s", fixedVersions, currentVersion)
	case "openssh":
		return fmt.Sprintf("1. 使用包管理器升级: yum update openssh 或 dnf update openssh\n2. 升级后重启 SSH 服务: systemctl restart sshd\n3. 注意: 升级 SSH 前请保持现有会话不断开，以防升级失败导致无法连接\n当前版本: %s", currentVersion)
	case "redis":
		return fmt.Sprintf("1. 使用包管理器升级: yum update redis 或 dnf update redis\n2. 如从源码编译: 下载 %s 版本重新编译安装\n3. 升级前建议执行 BGSAVE 保存数据\n4. 升级后重启: systemctl restart redis\n当前版本: %s", fixedVersions, currentVersion)
	case "mysql":
		return fmt.Sprintf("1. 使用包管理器升级: yum update mysql-server 或 dnf update mysql-server\n2. 升级前务必备份数据: mysqldump --all-databases > backup.sql\n3. 升级后执行: mysql_upgrade\n当前版本: %s", currentVersion)
	case "apache":
		return fmt.Sprintf("1. 使用包管理器升级: yum update httpd 或 dnf update httpd\n2. 升级后重启: systemctl restart httpd\n当前版本: %s", currentVersion)
	case "php":
		return fmt.Sprintf("1. 使用包管理器升级: yum update php 或 dnf update php\n2. 如使用宝塔面板: 在软件商店中升级 PHP 版本\n3. 升级后重启 PHP-FPM: systemctl restart php-fpm\n当前版本: %s", currentVersion)
	default:
		return fmt.Sprintf("1. 使用包管理器升级: yum update %s 或 dnf update %s\n2. 或使用 apt update && apt upgrade %s\n3. 升级后重启相关服务\n当前版本: %s", product, product, product, currentVersion)
	}
}

// isVersionLower 简单版本比较：判断 current 是否低于 fixed
// 不是精确的语义版本比较，而是基于字符串的近似匹配
func isVersionLower(current, fixed string) bool {
	currentParts := parseSemanticVersion(current)
	fixedParts := parseSemanticVersion(fixed)

	if currentParts == nil || fixedParts == nil {
		return false
	}

	return compareVersions(currentParts, fixedParts) < 0
}

// getKnownVulnPackages 返回已知漏洞软件包数据库
// 包含常见的、影响服务器安全的关键 CVE
func getKnownVulnPackages() map[string][]vulnPackageInfo {
	return map[string][]vulnPackageInfo{
		"libzip": {
			{CVEID: "CVE-2019-11043", FixedVersion: "1.5.2", Severity: types.SeverityHigh,
				Description:  "PHP is an HTML-embedded scripting language. php-fpm underflow in env_path_info in fpm_main.c",
				ReferenceURL: "https://access.redhat.com/errata/RHSA-2019:3736"},
		},
		"libzip-devel": {
			{CVEID: "CVE-2019-11043", FixedVersion: "1.5.2", Severity: types.SeverityHigh,
				Description:  "PHP is an HTML-embedded scripting language. php-fpm underflow in env_path_info in fpm_main.c",
				ReferenceURL: "https://access.redhat.com/errata/RHSA-2019:3736"},
		},
		"python3-setuptools": {
			{CVEID: "CVE-2024-6345", FixedVersion: "39.2.0-8", Severity: types.SeverityHigh,
				Description:  "Remote code execution via download functions in the package_index module",
				ReferenceURL: "https://access.redhat.com/errata/RHSA-2024:5530"},
		},
		"python3-setuptools-wheel": {
			{CVEID: "CVE-2024-6345", FixedVersion: "39.2.0-8", Severity: types.SeverityHigh,
				Description:  "Remote code execution via download functions in the package_index module",
				ReferenceURL: "https://access.redhat.com/errata/RHSA-2024:5530"},
		},
		"platform-python-setuptools": {
			{CVEID: "CVE-2024-6345", FixedVersion: "39.2.0-8", Severity: types.SeverityHigh,
				Description:  "Remote code execution via download functions in the package_index module",
				ReferenceURL: "https://access.redhat.com/errata/RHSA-2024:5530"},
		},
		"microcode_ctl": {
			{CVEID: "CVE-2024-39279", FixedVersion: "20250211", Severity: types.SeverityMedium,
				Description:  "Intel and AMD processor microcode updates for multiple CVEs including CVE-2023-34440, CVE-2024-28047, CVE-2024-29214, etc.",
				ReferenceURL: "https://access.redhat.com/errata/RHEA-2025:3114"},
		},
		"kernel": {
			{CVEID: "CVE-2024-1086", FixedVersion: "6.6.15", Severity: types.SeverityCritical,
				Description:  "Linux kernel netfilter use-after-free vulnerability, local privilege escalation",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-1086"},
			{CVEID: "CVE-2023-6546", FixedVersion: "6.6.15", Severity: types.SeverityHigh,
				Description:  "Linux kernel io_uring local privilege escalation",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2023-6546"},
			{CVEID: "CVE-2024-26581", FixedVersion: "6.6.17", Severity: types.SeverityHigh,
				Description:  "Linux kernel TLS 提权漏洞",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-26581"},
			{CVEID: "CVE-2024-26582", FixedVersion: "6.6.17", Severity: types.SeverityHigh,
				Description:  "Linux kernel TLS 回绕漏洞",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-26582"},
		},
		"openssh": {
			{CVEID: "CVE-2024-6387", FixedVersion: "9.8p1", Severity: types.SeverityCritical,
				Description:  "OpenSSH regreSSHion - race condition in sshd allowing remote code execution",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-6387"},
		},
		"openssh-server": {
			{CVEID: "CVE-2024-6387", FixedVersion: "9.8p1", Severity: types.SeverityCritical,
				Description:  "OpenSSH regreSSHion - race condition in sshd allowing remote code execution",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-6387"},
		},
		"openssl": {
			{CVEID: "CVE-2024-5535", FixedVersion: "1.1.1w", Severity: types.SeverityHigh,
				Description:  "OpenSSL SSL_select_next_proto buffer overread",
				ReferenceURL: "https://www.openssl.org/news/secadv/20240627.txt"},
			{CVEID: "CVE-2024-6119", FixedVersion: "3.2.3", Severity: types.SeverityMedium,
				Description:  "OpenSSL 拒绝服务漏洞（X.509 名称处理）",
				ReferenceURL: "https://www.openssl.org/news/secadv/20240903.txt"},
		},
		"openssl-libs": {
			{CVEID: "CVE-2024-5535", FixedVersion: "1.1.1w", Severity: types.SeverityHigh,
				Description:  "OpenSSL SSL_select_next_proto buffer overread",
				ReferenceURL: "https://www.openssl.org/news/secadv/20240627.txt"},
		},
		"nginx": {
			{CVEID: "CVE-2024-7347", FixedVersion: "1.27.2", Severity: types.SeverityMedium,
				Description:  "nginx MP4 module memory disclosure",
				ReferenceURL: "https://nginx.org/en/security_advisories.html"},
		},
		"polkit": {
			{CVEID: "CVE-2021-4034", FixedVersion: "0.120", Severity: types.SeverityCritical,
				Description:  "PwnKit - Local privilege escalation in polkit's pkexec",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2021-4034"},
		},
		"sudo": {
			{CVEID: "CVE-2023-42465", FixedVersion: "1.9.15p5", Severity: types.SeverityHigh,
				Description:  "sudo - arbitrary file write via -R option (BARON SAMEDIT)",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2023-42465"},
		},
		"gnutls": {
			{CVEID: "CVE-2024-28834", FixedVersion: "3.6.16", Severity: types.SeverityHigh,
				Description:  "GnuTLS timing side-channel in RSA decryption",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-28834"},
		},
		"curl": {
			{CVEID: "CVE-2024-2398", FixedVersion: "8.7.1", Severity: types.SeverityMedium,
				Description:  "curl HTTP/2 PUSH_PROMISE leak",
				ReferenceURL: "https://curl.se/docs/CVE-2024-2398.html"},
			{CVEID: "CVE-2024-7264", FixedVersion: "8.9.0", Severity: types.SeverityHigh,
				Description:  "curl ASN.1 date parser 漏洞",
				ReferenceURL: "https://curl.se/docs/CVE-2024-7264.html"},
		},
		"libcurl": {
			{CVEID: "CVE-2024-2398", FixedVersion: "8.7.1", Severity: types.SeverityMedium,
				Description:  "curl HTTP/2 PUSH_PROMISE leak",
				ReferenceURL: "https://curl.se/docs/CVE-2024-2398.html"},
			{CVEID: "CVE-2024-7264", FixedVersion: "8.9.0", Severity: types.SeverityHigh,
				Description:  "curl ASN.1 date parser 漏洞",
				ReferenceURL: "https://curl.se/docs/CVE-2024-7264.html"},
		},
		"httpd": {
			{CVEID: "CVE-2024-38475", FixedVersion: "2.4.60", Severity: types.SeverityHigh,
				Description:  "Apache HTTP Server 后端文件名混淆漏洞",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-38475"},
			{CVEID: "CVE-2024-38476", FixedVersion: "2.4.60", Severity: types.SeverityHigh,
				Description:  "Apache HTTP Server SSRF 漏洞",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-38476"},
		},
		"redis": {
			{CVEID: "CVE-2024-31449", FixedVersion: "7.2.4", Severity: types.SeverityHigh,
				Description:  "Redis Lua 脚本溢出漏洞",
				ReferenceURL: "https://github.com/redis/redis/security/advisories/GHSA-w..."},
		},
		"php": {
			{CVEID: "CVE-2024-4577", FixedVersion: "8.3.8", Severity: types.SeverityCritical,
				Description:  "PHP CGI 参数注入漏洞，可导致远程代码执行",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-4577"},
			{CVEID: "CVE-2024-2961", FixedVersion: "8.3.6", Severity: types.SeverityHigh,
				Description:  "PHP gconv 漏洞，可导致缓冲区溢出",
				ReferenceURL: "https://access.redhat.com/security/cve/CVE-2024-2961"},
		},
	}
}

// ScanCMS X2: CMS/框架漏洞扫描
func (v *VulnScanGuard) ScanCMS(ctx context.Context, webRoots []string) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("vulnscan", "cms-frameworks")

	cmsDetectors := []struct {
		name         string
		signature    string
		versionFile  string
		versionRegex string
	}{
		{"wordpress", "wp-includes/version.php", "wp-includes/version.php", `\$wp_version\s*=\s*'([^']+)'`},
		{"thinkphp", "thinkphp/base.php", "thinkphp/base.php", `THINK_VERSION\s*=\s*'([^']+)'`},
		{"laravel", "vendor/laravel/framework/src/Illuminate/Foundation/Application.php", "vendor/laravel/framework/src/Illuminate/Foundation/Application.php", `const VERSION\s*=\s*'([^']+)'`},
		{"dedecms", "data/common.inc.php", "data/common.inc.php", ""},
		{"discuz", "source/class/discuz/discuz_application.php", "source/class/discuz/discuz_application.php", ""},
		{"typecho", "var/Typecho/Common.php", "var/Typecho/Common.php", `VERSION\s*=\s*'([^']+)'`},
		{"drupal", "includes/bootstrap.inc", "includes/bootstrap.inc", `define\('DRUPAL_VERSION',\s*'([^']+)'\)`},
		{"joomla", "libraries/cms/version/version.php", "libraries/cms/version/version.php", `RELEASE\s*=\s*'([^']+)'`},
	}

	for _, root := range webRoots {
		for _, cms := range cmsDetectors {
			sigPath := filepath.Join(root, cms.signature)
			if _, err := os.Stat(sigPath); err != nil {
				continue
			}

			version := "unknown"
			if cms.versionFile != "" && cms.versionRegex != "" {
				versionPath := filepath.Join(root, cms.versionFile)
				if data, err := os.ReadFile(versionPath); err == nil {
					re := regexp.MustCompile(cms.versionRegex)
					if match := re.FindStringSubmatch(string(data)); len(match) > 1 {
						version = match[1]
					}
				}
			}

			rb.AddFinding(
				types.SeverityMedium,
				fmt.Sprintf("检测到 CMS: %s %s", cms.name, version),
				fmt.Sprintf("在 %s 检测到 %s CMS，版本 %s", root, cms.name, version),
				root,
				fmt.Sprintf(`{"cms":"%s","version":"%s","path":"%s"}`, cms.name, version, root),
				"检查是否有已知漏洞，及时升级到最新版本",
				"升级 CMS 可能导致主题/插件不兼容，建议先备份",
			)
		}
	}

	return rb.GetFindings(), nil
}

// ScanDependencies X3: 依赖漏洞扫描
func (v *VulnScanGuard) ScanDependencies(ctx context.Context, webRoots []string) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("vulnscan", "dependencies")

	depFiles := []struct {
		name string
		file string
	}{
		{"composer.lock", "composer.lock"},
		{"package-lock.json", "package-lock.json"},
		{"requirements.txt", "requirements.txt"},
		{"Pipfile.lock", "Pipfile.lock"},
		{"go.mod", "go.mod"},
		{"pom.xml", "pom.xml"},
	}

	for _, root := range webRoots {
		for _, dep := range depFiles {
			depPath := filepath.Join(root, dep.file)
			if _, err := os.Stat(depPath); err != nil {
				continue
			}

			data, err := os.ReadFile(depPath)
			if err != nil {
				continue
			}

			rb.AddFinding(
				types.SeverityLow,
				fmt.Sprintf("检测到依赖文件: %s", dep.name),
				fmt.Sprintf("在 %s 检测到 %s，建议使用 npm audit / composer audit / safety check 检查依赖漏洞", root, dep.name),
				depPath,
				fmt.Sprintf(`{"file":"%s","size":%d}`, dep.name, len(data)),
				fmt.Sprintf("运行依赖审计工具检查已知漏洞: %s", dep.name),
				"升级依赖可能破坏业务功能，建议先在测试环境验证",
			)
		}
	}

	return rb.GetFindings(), nil
}

// ScanConfigCompliance X4: 配置合规扫描（CIS Benchmark）
func (v *VulnScanGuard) ScanConfigCompliance(ctx context.Context) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("vulnscan", "config-compliance")

	v.checkSSHConfig(rb)
	v.checkFilePermissions(rb)
	v.checkSUIDFiles(rb)
	v.checkKernelParams(rb)

	return rb.GetFindings(), nil
}

func (v *VulnScanGuard) checkSSHConfig(rb *scannercommon.ReportBuilder) {
	sshConfig := "/etc/ssh/sshd_config"
	data, err := os.ReadFile(sshConfig)
	if err != nil {
		return
	}
	content := string(data)

	if strings.Contains(content, "PermitRootLogin yes") {
		rb.AddFinding(
			types.SeverityHigh,
			"SSH 允许 root 密码登录",
			"sshd_config 中 PermitRootLogin 设置为 yes，允许 root 直接密码登录",
			sshConfig,
			`{"config":"PermitRootLogin","value":"yes"}`,
			"将 PermitRootLogin 改为 prohibit-password 或 no",
			"修改后需重启 sshd，如配置有误可能导致 SSH 无法连接，服务器失联",
		)
	}

	if strings.Contains(content, "PasswordAuthentication yes") || !strings.Contains(content, "PasswordAuthentication") {
		rb.AddFinding(
			types.SeverityMedium,
			"SSH 允许密码认证",
			"sshd_config 允许密码认证，可能遭受暴力破解",
			sshConfig,
			`{"config":"PasswordAuthentication","value":"yes"}`,
			"将 PasswordAuthentication 改为 no，使用密钥认证",
			"修改后需重启 sshd，仅使用密钥认证的客户端才能连接",
		)
	}

	if strings.Contains(content, "Port 22") || !strings.Contains(content, "Port ") {
		rb.AddFinding(
			types.SeverityLow,
			"SSH 使用默认端口 22",
			"SSH 使用默认端口 22，容易被自动化扫描",
			sshConfig,
			`{"config":"Port","value":"22"}`,
			"将 Port 改为非标准端口（如 22222）",
			"修改后需重启 sshd，所有 SSH 客户端需更新连接端口",
		)
	}
}

func (v *VulnScanGuard) checkFilePermissions(rb *scannercommon.ReportBuilder) {
	criticalFiles := []struct {
		path        string
		maxPerm     os.FileMode
		description string
	}{
		{"/etc/shadow", 0640, "密码哈希文件"},
		{"/etc/passwd", 0644, "用户信息文件"},
		{"/etc/sudoers", 0440, "sudo 配置文件"},
	}

	for _, f := range criticalFiles {
		stat, err := os.Stat(f.path)
		if err != nil {
			continue
		}
		perm := stat.Mode().Perm()
		if perm > f.maxPerm {
			rb.AddFinding(
				types.SeverityMedium,
				fmt.Sprintf("文件权限过宽: %s", f.path),
				fmt.Sprintf("%s 权限为 %o，建议为 %o", f.description, perm, f.maxPerm),
				f.path,
				fmt.Sprintf(`{"path":"%s","current_perm":"%o","recommended_perm":"%o"}`, f.path, perm, f.maxPerm),
				fmt.Sprintf("执行 chmod %o %s", f.maxPerm, f.path),
				"修改权限后可能影响依赖该文件的程序运行",
			)
		}
	}
}

func (v *VulnScanGuard) checkSUIDFiles(rb *scannercommon.ReportBuilder) {
	// 限制 find 命令搜索范围，避免全盘扫描耗时过长
	// 只扫描常见 SUID 文件所在目录，排除 docker overlay 路径
	searchDirs := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin"}
	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		cmd := exec.Command("find", dir, "-perm", "-4000", "-type", "f")
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// 扩充已知标准 SUID 文件白名单，避免常见系统工具误报
		knownSUID := map[string]bool{
			"/usr/bin/sudo":                                 true,
			"/usr/bin/passwd":                               true,
			"/usr/bin/su":                                   true,
			"/usr/bin/chsh":                                 true,
			"/usr/bin/chfn":                                 true,
			"/usr/bin/newgrp":                               true,
			"/usr/bin/gpasswd":                              true,
			"/usr/bin/mount":                                true,
			"/usr/bin/umount":                               true,
			"/usr/bin/pkexec":                               true,
			"/usr/bin/at":                                   true,
			"/usr/bin/crontab":                              true,
			"/usr/bin/fusermount":                           true,
			"/usr/bin/fusermount3":                          true,
			"/usr/sbin/pkexec":                              true,
			"/usr/sbin/mount.nfs":                           true,
			"/usr/sbin/pam_timestamp_check":                 true,
			"/usr/sbin/unix_chkpwd":                         true,
			"/usr/sbin/grub2-set-bootflag":                  true,
			"/usr/sbin/userhelper":                          true,
			"/usr/sbin/usernetctl":                          true,
			"/usr/libexec/sssd/proxy_child":                 true,
			"/usr/libexec/sssd/selinux_child":               true,
			"/usr/libexec/sssd/ldap_child":                  true,
			"/usr/libexec/sssd/krb5_child":                  true,
			"/usr/libexec/cockpit-session":                  true,
			"/usr/libexec/dbus-1/dbus-daemon-launch-helper": true,
			"/usr/lib/polkit-1/polkit-agent-helper-1":       true,
			"/usr/libexec/polkit-agent-helper-1":            true,
			"/usr/lib/dbus-1/dbus-daemon-launch-helper":     true,
			"/opt/google/chrome/chrome-sandbox":             true,
		}

		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || knownSUID[line] {
				continue
			}
			// 排除 docker overlay 路径下的文件（容器内 SUID 不影响宿主机安全）
			if strings.Contains(line, "/var/lib/docker/overlay") ||
				strings.Contains(line, "/var/lib/docker/overlay2") {
				continue
			}
			rb.AddFinding(
				types.SeverityMedium,
				fmt.Sprintf("非标准 SUID 文件: %s", line),
				fmt.Sprintf("检测到非标准 SUID 文件 %s，可能被用于提权", line),
				line,
				fmt.Sprintf(`{"path":"%s"}`, line),
				fmt.Sprintf("去除 SUID 权限: chmod u-s %s", line),
				"去除 SUID 后，依赖该权限的程序将无法提权运行",
			)
		}
	}
}

func (v *VulnScanGuard) checkKernelParams(rb *scannercommon.ReportBuilder) {
	params := []struct {
		name        string
		path        string
		expected    string
		description string
	}{
		{"net.ipv4.tcp_syncookies", "/proc/sys/net/ipv4/tcp_syncookies", "1", "SYN Flood 保护"},
		{"net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", "0", "IP 转发"},
		{"net.ipv4.conf.all.accept_redirects", "/proc/sys/net/ipv4/conf/all/accept_redirects", "0", "ICMP 重定向"},
	}

	for _, p := range params {
		data, err := os.ReadFile(p.path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if value != p.expected {
			rb.AddFinding(
				types.SeverityLow,
				fmt.Sprintf("内核参数不合规: %s", p.name),
				fmt.Sprintf("%s 当前值为 %s，建议为 %s", p.description, value, p.expected),
				p.name,
				fmt.Sprintf(`{"param":"%s","current":"%s","expected":"%s"}`, p.name, value, p.expected),
				fmt.Sprintf("执行 sysctl -w %s=%s", p.name, p.expected),
				"修改内核参数可能影响网络行为，建议在测试环境验证",
			)
		}
	}
}

func getCommandVersion(ctx context.Context, cmd string, args []string) (string, error) {
	// systemd 服务环境下 PATH 可能不包含 /usr/sbin、/usr/local/bin 等
	// 尝试在常见路径中查找二进制文件
	command := exec.CommandContext(ctx, cmd, args...)
	// 补充常见路径到 PATH
	envPath := os.Getenv("PATH")
	if !strings.Contains(envPath, "/usr/sbin") {
		envPath = envPath + ":/usr/sbin:/usr/local/bin:/usr/local/sbin:/opt/bin"
	}
	command.Env = append(os.Environ(), "PATH="+envPath)

	output, err := command.CombinedOutput()
	if err != nil {
		// 尝试绝对路径
		absPaths := []string{
			"/usr/bin/" + cmd,
			"/usr/sbin/" + cmd,
			"/usr/local/bin/" + cmd,
			"/usr/local/sbin/" + cmd,
			"/bin/" + cmd,
			"/sbin/" + cmd,
		}
		for _, p := range absPaths {
			if _, err := os.Stat(p); err == nil {
				command = exec.CommandContext(ctx, p, args...)
				output, err = command.CombinedOutput()
				if err == nil {
					return strings.TrimSpace(string(output)), nil
				}
			}
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getDefaultCVEDatabase() *CVEDatabase {
	return &CVEDatabase{
		Entries: []CVEEntry{
			// nginx
			{CVEID: "CVE-2021-23017", Product: "nginx", VulnVersions: "<1.21.0", FixedVersions: "1.21.0+", Severity: "medium",
				Description: "nginx DNS 解析器漏洞，可能导致 1-byte 内存覆盖", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
			{CVEID: "CVE-2022-41741", Product: "nginx", VulnVersions: "<1.23.4", FixedVersions: "1.23.4+", Severity: "medium",
				Description: "nginx mp4 模块内存损坏漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2022-41741"},
			{CVEID: "CVE-2023-44487", Product: "nginx", VulnVersions: "<1.25.3", FixedVersions: "1.25.3+", Severity: "high",
				Description: "HTTP/2 快速重置攻击（Rapid Reset），可导致 DoS", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"},
			{CVEID: "CVE-2024-7347", Product: "nginx", VulnVersions: "<1.27.2", FixedVersions: "1.27.2+", Severity: "medium",
				Description: "nginx MP4 模块内存泄露", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-7347"},

			// openssl
			{CVEID: "CVE-2022-0778", Product: "openssl", VulnVersions: "<3.0.2", FixedVersions: "3.0.2+", Severity: "high",
				Description: "OpenSSL BN_mod_sqrt 无限循环漏洞，可导致 DoS", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2022-0778"},
			{CVEID: "CVE-2021-3711", Product: "openssl", VulnVersions: "<1.1.1l", FixedVersions: "1.1.1l+", Severity: "high",
				Description: "OpenSSL SM2 解密缓冲区溢出", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2021-3711"},
			{CVEID: "CVE-2023-0286", Product: "openssl", VulnVersions: "<3.0.8", FixedVersions: "3.0.8+", Severity: "medium",
				Description: "OpenSSL X.400 地址类型混淆漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-0286"},
			{CVEID: "CVE-2023-2650", Product: "openssl", VulnVersions: "<3.1.1", FixedVersions: "3.1.1+", Severity: "medium",
				Description: "OpenSSL OBJ_obj2txt() 递归可能导致 DoS", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-2650"},
			{CVEID: "CVE-2024-5535", Product: "openssl", VulnVersions: "<3.0.15", FixedVersions: "3.0.15+", Severity: "high",
				Description: "OpenSSL SSL_select_next_proto 缓冲区过读", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-5535"},
			{CVEID: "CVE-2024-6119", Product: "openssl", VulnVersions: "<3.2.3", FixedVersions: "3.2.3+", Severity: "medium",
				Description: "OpenSSL 拒绝服务漏洞（X.509 名称处理）", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-6119"},

			// openssh
			{CVEID: "CVE-2023-38508", Product: "openssh", VulnVersions: "<9.6p1", FixedVersions: "9.6p1+", Severity: "high",
				Description: "OpenSSH SOCKS5 代理堆缓冲区溢出", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-38508"},
			{CVEID: "CVE-2023-28486", Product: "openssh", VulnVersions: "<9.3p1", FixedVersions: "9.3p1+", Severity: "medium",
				Description: "OpenSSH 绕过限制漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-28486"},
			{CVEID: "CVE-2024-6387", Product: "openssh", VulnVersions: "<9.8p1", FixedVersions: "9.8p1+", Severity: "critical",
				Description: "OpenSSH regreSSHion 远程代码执行漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},

			// redis
			{CVEID: "CVE-2023-37554", Product: "redis", VulnVersions: "<7.0.12", FixedVersions: "7.0.12+", Severity: "medium",
				Description: "Redis SANDALBOCS 漏洞，可导致 DoS", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-37554"},
			{CVEID: "CVE-2023-41053", Product: "redis", VulnVersions: "<7.0.14", FixedVersions: "7.0.14+", Severity: "medium",
				Description: "Redis LUA 堆栈溢出漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-41053"},
			{CVEID: "CVE-2024-31449", Product: "redis", VulnVersions: "<7.2.4", FixedVersions: "7.2.4+", Severity: "high",
				Description: "Redis Lua 脚本溢出漏洞，可导致 DoS", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-31449"},

			// php
			{CVEID: "CVE-2024-4577", Product: "php", VulnVersions: "<8.3.8", FixedVersions: "8.3.8+", Severity: "critical",
				Description: "PHP CGI 参数注入漏洞，可导致远程代码执行", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"},
			{CVEID: "CVE-2024-2961", Product: "php", VulnVersions: "<8.3.6", FixedVersions: "8.3.6+", Severity: "high",
				Description: "PHP gconv 漏洞，可导致缓冲区溢出", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-2961"},
			{CVEID: "CVE-2023-3824", Product: "php", VulnVersions: "<8.2.9", FixedVersions: "8.2.9+", Severity: "high",
				Description: "PHP SOAP SSPI 漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-3824"},

			// apache
			{CVEID: "CVE-2023-31122", Product: "apache", VulnVersions: "<2.4.57", FixedVersions: "2.4.57+", Severity: "medium",
				Description: "Apache HTTP Server mod_macro 漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-31122"},
			{CVEID: "CVE-2024-38475", Product: "apache", VulnVersions: "<2.4.60", FixedVersions: "2.4.60+", Severity: "high",
				Description: "Apache HTTP Server 后端文件名混淆漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-38475"},
			{CVEID: "CVE-2024-38476", Product: "apache", VulnVersions: "<2.4.60", FixedVersions: "2.4.60+", Severity: "high",
				Description: "Apache HTTP Server SSRF 漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-38476"},

			// mysql
			{CVEID: "CVE-2024-20996", Product: "mysql", VulnVersions: "<8.0.36", FixedVersions: "8.0.36+", Severity: "high",
				Description: "MySQL Server Optimizer 漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-20996"},
			{CVEID: "CVE-2024-21009", Product: "mysql", VulnVersions: "<8.0.36", FixedVersions: "8.0.36+", Severity: "high",
				Description: "MySQL Server InnoDB 漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-21009"},

			// docker
			{CVEID: "CVE-2024-21626", Product: "docker", VulnVersions: "<25.0.2", FixedVersions: "25.0.2+", Severity: "critical",
				Description: "runc 容器逃逸漏洞", ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626"},
		},
	}
}

// SyncCVEDatabase X5: 同步 CVE 漏洞库
// 从 NVD 和 CNVD API 拉取最新 CVE 数据，合并到本地数据库
func (v *VulnScanGuard) SyncCVEDatabase(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var syncErrors []string

	if v.nvdAPIKey != "" {
		if err := v.syncFromNVD(ctx); err != nil {
			syncErrors = append(syncErrors, fmt.Sprintf("NVD: %v", err))
		}
	}

	if v.cnvdAPIKey != "" {
		if err := v.syncFromCNVD(ctx); err != nil {
			syncErrors = append(syncErrors, fmt.Sprintf("CNVD: %v", err))
		}
	}

	if len(syncErrors) > 0 {
		return fmt.Errorf("CVE同步部分失败: %s", strings.Join(syncErrors, "; "))
	}

	v.lastSyncTime = time.Now()
	return nil
}

// syncFromNVD 从 NVD API 同步 CVE 数据
func (v *VulnScanGuard) syncFromNVD(ctx context.Context) error {
	client := &http.Client{Timeout: 30 * time.Second}

	products := []string{"nginx", "openssl", "openssh", "mysql", "redis", "postgresql"}
	for _, product := range products {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		url := fmt.Sprintf("https://services.nvd.nist.gov/rest/v2/cves?keywordSearch=%s&resultsPerPage=50", product)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("apiKey", v.nvdAPIKey)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var result struct {
			Vulnerabilities []struct {
				CVE struct {
					ID           string `json:"id"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					Metrics struct {
						CvssMetricV31 []struct {
							CvssData struct {
								BaseScore    float64 `json:"baseScore"`
								BaseSeverity string  `json:"baseSeverity"`
							} `json:"cvssData"`
						} `json:"cvssMetricV31"`
						CvssMetricV2 []struct {
							CvssData struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssData"`
						} `json:"cvssMetricV2"`
					} `json:"metrics"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, vuln := range result.Vulnerabilities {
			severity := "medium"
			if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
				severity = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
			}

			description := ""
			if len(vuln.CVE.Descriptions) > 0 {
				description = vuln.CVE.Descriptions[0].Value
			}

			entry := CVEEntry{
				CVEID:       vuln.CVE.ID,
				Product:     product,
				Severity:    severity,
				Description: description,
			}

			v.cveDatabase.mu.Lock()
			updated := false
			for i, e := range v.cveDatabase.Entries {
				if e.CVEID == entry.CVEID {
					v.cveDatabase.Entries[i] = entry
					updated = true
					break
				}
			}
			if !updated {
				v.cveDatabase.Entries = append(v.cveDatabase.Entries, entry)
			}
			v.cveDatabase.mu.Unlock()
		}
	}

	return nil
}

// syncFromCNVD 从 CNVD API 同步 CVE 数据
func (v *VulnScanGuard) syncFromCNVD(ctx context.Context) error {
	client := &http.Client{Timeout: 30 * time.Second}

	url := "https://www.cnvd.org.cn/openapi/v1/cves?resultsPerPage=100"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+v.cnvdAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CNVD API返回状态码: %d", resp.StatusCode)
	}

	var result struct {
		Data []struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Product     string `json:"product"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	for _, item := range result.Data {
		entry := CVEEntry{
			CVEID:       item.ID,
			Product:     item.Product,
			Severity:    item.Severity,
			Description: item.Title + ": " + item.Description,
		}

		v.cveDatabase.mu.Lock()
		updated := false
		for i, e := range v.cveDatabase.Entries {
			if e.CVEID == entry.CVEID {
				v.cveDatabase.Entries[i] = entry
				updated = true
				break
			}
		}
		if !updated {
			v.cveDatabase.Entries = append(v.cveDatabase.Entries, entry)
		}
		v.cveDatabase.mu.Unlock()
	}

	return nil
}

// GetLastSyncTime 获取上次同步时间
func (v *VulnScanGuard) GetLastSyncTime() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastSyncTime
}
