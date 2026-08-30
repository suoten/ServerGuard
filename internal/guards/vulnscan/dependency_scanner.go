package vulnscan

import (
	"context"
	"encoding/json"
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
// 解析 5 种依赖锁文件，匹配本地已知漏洞数据库 + 外部威胁情报（可选）。
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
		return nil, fmt.Errorf("不支持的锁文件类型: %s", lockType)
	}
}

// ============================================================
// 本地已知漏洞数据库（按语言生态分类）
// 当版本低于 FixedVersion 时报告漏洞。
// 威胁情报（intel）注入后可补充更多 CVE。
// ============================================================

// knownVulnDB 本地已知漏洞数据库：packageName -> []vulnEntry
type vulnEntry struct {
	CVEID        string
	FixedVersion string
	Severity     string
	Description  string
}

// composerKnownVulns PHP Composer 包已知漏洞
var composerKnownVulns = map[string][]vulnEntry{
	"symfony/http-kernel": {
		{CVEID: "CVE-2022-24895", FixedVersion: "5.4.1", Severity: "medium",
			Description: "Symfony CSRF token 信息泄露"},
		{CVEID: "CVE-2024-50423", FixedVersion: "5.4.44", Severity: "critical",
			Description: "Symfony 远程代码执行漏洞"},
	},
	"laravel/framework": {
		{CVEID: "CVE-2024-45406", FixedVersion: "10.15.0", Severity: "high",
			Description: "Laravel 修复 Illuminate/Routing 序列化漏洞"},
		{CVEID: "CVE-2018-15133", FixedVersion: "5.5.40", Severity: "critical",
			Description: "Laravel 反序列化 RCE 漏洞"},
	},
	"monolog/monolog": {
		{CVEID: "CVE-2022-24898", FixedVersion: "1.27.1", Severity: "medium",
			Description: "Monolog 日志注入漏洞"},
	},
	"guzzlehttp/guzzle": {
		{CVEID: "CVE-2022-31042", FixedVersion: "6.5.6", Severity: "medium",
			Description: "GuzzleHTTP 头注入漏洞"},
		{CVEID: "CVE-2022-31043", FixedVersion: "6.5.6", Severity: "medium",
			Description: "GuzzleHTTP SSRF 漏洞"},
	},
	"phpunit/phpunit": {
		{CVEID: "CVE-2017-9841", FixedVersion: "4.8.28", Severity: "critical",
			Description: "PHPUnit 远程代码执行漏洞"},
	},
	"nesbot/carbon": {
		{CVEID: "CVE-2022-31090", FixedVersion: "2.61.0", Severity: "medium",
			Description: "Carbon 时区处理信息泄露"},
	},
}

// npmKnownVulns Node.js npm 包已知漏洞
var npmKnownVulns = map[string][]vulnEntry{
	"lodash": {
		{CVEID: "CVE-2021-23337", FixedVersion: "4.17.21", Severity: "high",
			Description: "Lodash 命令注入漏洞"},
		{CVEID: "CVE-2020-8203", FixedVersion: "4.17.19", Severity: "high",
			Description: "Lodash 原型链污染漏洞"},
	},
	"axios": {
		{CVEID: "CVE-2024-39338", FixedVersion: "0.30.0", Severity: "high",
			Description: "Axios SSRF 漏洞"},
		{CVEID: "CVE-2023-45857", FixedVersion: "0.28.0", Severity: "medium",
			Description: "Axios CSRF 漏洞"},
	},
	"express": {
		{CVEID: "CVE-2024-29041", FixedVersion: "4.19.2", Severity: "medium",
			Description: "Express 开放重定向漏洞"},
	},
	"minimatch": {
		{CVEID: "CVE-2022-3517", FixedVersion: "3.0.5", Severity: "high",
			Description: "minimatch ReDoS 漏洞"},
	},
	"minimist": {
		{CVEID: "CVE-2021-44906", FixedVersion: "1.2.6", Severity: "critical",
			Description: "minimist 原型链污染漏洞"},
	},
	"qs": {
		{CVEID: "CVE-2022-24999", FixedVersion: "6.5.3", Severity: "high",
			Description: "qs 原型链污染漏洞"},
	},
	"node-fetch": {
		{CVEID: "CVE-2022-0235", FixedVersion: "2.6.7", Severity: "high",
			Description: "node-fetch 头部信息泄露漏洞"},
	},
	"jsonwebtoken": {
		{CVEID: "CVE-2022-23529", FixedVersion: "9.0.0", Severity: "critical",
			Description: "jsonwebtoken 密钥混淆 RCE 漏洞"},
	},
	"pug": {
		{CVEID: "CVE-2018-20190", FixedVersion: "2.0.4", Severity: "high",
			Description: "Pug 模板注入漏洞"},
	},
	"ejs": {
		{CVEID: "CVE-2022-29078", FixedVersion: "3.1.7", Severity: "high",
			Description: "EJS 模板注入 RCE 漏洞"},
	},
}

// pythonKnownVulns Python pip 包已知漏洞
var pythonKnownVulns = map[string][]vulnEntry{
	"django": {
		{CVEID: "CVE-2024-43189", FixedVersion: "4.2.15", Severity: "high",
			Description: "Django SQL 注入漏洞"},
		{CVEID: "CVE-2024-38912", FixedVersion: "5.0.7", Severity: "high",
			Description: "Django 路径遍历漏洞"},
	},
	"flask": {
		{CVEID: "CVE-2023-30861", FixedVersion: "2.3.2", Severity: "medium",
			Description: "Flask Cookie 安全漏洞"},
	},
	"requests": {
		{CVEID: "CVE-2024-35195", FixedVersion: "2.32.0", Severity: "medium",
			Description: "Requests SSL 证书验证绕过漏洞"},
	},
	"cryptography": {
		{CVEID: "CVE-2024-26130", FixedVersion: "42.0.4", Severity: "high",
			Description: "cryptography PKCS#12 缓冲区溢出漏洞"},
		{CVEID: "CVE-2023-49083", FixedVersion: "41.0.6", Severity: "high",
			Description: "cryptography NULL 指针解引用漏洞"},
	},
	"pyyaml": {
		{CVEID: "CVE-2020-1747", FixedVersion: "5.4", Severity: "high",
			Description: "PyYAML 任意代码执行漏洞"},
	},
	"pillow": {
		{CVEID: "CVE-2023-50447", FixedVersion: "10.3.0", Severity: "high",
			Description: "Pillow 任意代码执行漏洞"},
	},
}

// goKnownVulns Go 模块已知漏洞
var goKnownVulns = map[string][]vulnEntry{
	"github.com/golang-jwt/jwt": {
		{CVEID: "CVE-2025-30204", FixedVersion: "5.2.2", Severity: "high",
			Description: "golang-jwt JWT 解析器 panic 漏洞"},
	},
	"github.com/gin-gonic/gin": {
		{CVEID: "CVE-2023-29401", FixedVersion: "1.9.0", Severity: "medium",
			Description: "Gin 文件上传路径遍历漏洞"},
	},
	"github.com/gorilla/websocket": {
		{CVEID: "CVE-2020-27813", FixedVersion: "1.4.1", Severity: "medium",
			Description: "gorilla/websocket DoS 漏洞"},
	},
	"github.com/go-playground/validator": {
		{CVEID: "CVE-2023-29435", FixedVersion: "10.12.0", Severity: "medium",
			Description: "go-playground/validator ReDoS 漏洞"},
	},
}

// mavenKnownVulns Java Maven 包已知漏洞
var mavenKnownVulns = map[string][]vulnEntry{
	"org.apache.logging.log4j:log4j-core": {
		{CVEID: "CVE-2021-44228", FixedVersion: "2.17.1", Severity: "critical",
			Description: "Log4Shell - Log4j JNDI 注入 RCE 漏洞"},
		{CVEID: "CVE-2021-45046", FixedVersion: "2.16.0", Severity: "critical",
			Description: "Log4j JNDI 注入漏洞变体"},
	},
	"org.springframework:spring-core": {
		{CVEID: "CVE-2022-22965", FixedVersion: "5.3.18", Severity: "critical",
			Description: "Spring4Shell - Spring Framework RCE 漏洞"},
	},
	"com.fasterxml.jackson.core:jackson-databind": {
		{CVEID: "CVE-2022-42003", FixedVersion: "2.13.4", Severity: "high",
			Description: "Jackson 反序列化漏洞"},
		{CVEID: "CVE-2020-36518", FixedVersion: "2.12.6", Severity: "high",
			Description: "Jackson 深度嵌套 DoS 漏洞"},
	},
	"org.apache.commons:commons-text": {
		{CVEID: "CVE-2022-42889", FixedVersion: "1.10.0", Severity: "critical",
			Description: "Text4Shell - Commons Text RCE 漏洞"},
	},
	"org.apache.tomcat:tomcat-coyote": {
		{CVEID: "CVE-2025-24813", FixedVersion: "9.0.99", Severity: "critical",
			Description: "Tomcat 远程代码执行漏洞"},
	},
}

// ============================================================
// 锁文件解析器
// ============================================================

// composerLockEntry composer.lock JSON 结构
type composerLockEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// scanComposerLock 解析 composer.lock (PHP)
func (s *DependencyScanner) scanComposerLock(content []byte) []DependencyVulnerability {
	var lockFile struct {
		Packages    []composerLockEntry `json:"packages"`
		PackagesDev []composerLockEntry `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &lockFile); err != nil {
		return nil
	}

	allPackages := append(lockFile.Packages, lockFile.PackagesDev...)
	var vulns []DependencyVulnerability
	for _, pkg := range allPackages {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		// 去掉版本前缀 v（如 v1.2.3 -> 1.2.3）
		version := strings.TrimPrefix(pkg.Version, "v")
		// 去掉版本约束前缀（如 ^1.2.3, ~1.2.3, >=1.2.3）
		version = strings.TrimLeft(version, "^~>=< ")
		version = strings.Split(version, " ")[0]

		for _, vuln := range composerKnownVulns[pkg.Name] {
			if isVersionLower(version, vuln.FixedVersion) {
				vulns = append(vulns, DependencyVulnerability{
					PackageName:      pkg.Name,
					InstalledVersion: version,
					VulnerabilityID:  vuln.CVEID,
					Severity:         vuln.Severity,
					FixedVersion:     vuln.FixedVersion,
					Description:      vuln.Description,
				})
			}
		}
	}
	return vulns
}

// scanRequirementsTxt 解析 requirements.txt (Python)
func (s *DependencyScanner) scanRequirementsTxt(content []byte) []DependencyVulnerability {
	var vulns []DependencyVulnerability

	// pip 包名正则：字母、数字、下划线、连字符、点号
	pkgRe := regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*([=<>!~]=?\s*)?([0-9][0-9a-zA-Z._-]*)?`)

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// 去掉行内注释
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// 去掉环境标记（如 package; python_version >= "3.6"）
		if idx := strings.Index(line, ";"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// 去掉 extras（如 package[extra1,extra2]==1.2.3）
		if idx := strings.Index(line, "["); idx > 0 {
			line = line[:idx] + line[strings.Index(line, "]")+1:]
		}

		m := pkgRe.FindStringSubmatch(line)
		if m == nil || m[1] == "" {
			continue
		}
		pkgName := strings.ToLower(m[1])
		version := m[3]
		if version == "" {
			continue // 无版本号，跳过
		}

		for _, vuln := range pythonKnownVulns[pkgName] {
			if isVersionLower(version, vuln.FixedVersion) {
				vulns = append(vulns, DependencyVulnerability{
					PackageName:      pkgName,
					InstalledVersion: version,
					VulnerabilityID:  vuln.CVEID,
					Severity:         vuln.Severity,
					FixedVersion:     vuln.FixedVersion,
					Description:      vuln.Description,
				})
			}
		}
	}
	return vulns
}

// scanPackageLock 解析 package-lock.json (Node.js)
func (s *DependencyScanner) scanPackageLock(content []byte) []DependencyVulnerability {
	var lockFile struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(content, &lockFile); err != nil {
		return nil
	}

	// 合并 dependencies 和 packages 两种格式
	type pkgVer struct{ name, version string }
	seen := make(map[string]string) // name -> version，去重

	for name, dep := range lockFile.Dependencies {
		if dep.Version != "" {
			seen[name] = dep.Version
		}
	}
	for path, pkg := range lockFile.Packages {
		// packages 的 key 是路径如 node_modules/lodash 或 node_modules/foo/node_modules/lodash
		// 取最后一段作为包名
		parts := strings.Split(path, "node_modules/")
		name := parts[len(parts)-1]
		if name == "" || name == path {
			continue
		}
		// 跳过根包（空路径或包名 == ""）
		if pkg.Version == "" {
			continue
		}
		// 只保留第一次出现的版本（嵌套的取最外层）
		if _, exists := seen[name]; !exists {
			seen[name] = pkg.Version
		}
	}

	var vulns []DependencyVulnerability
	for name, version := range seen {
		// 去掉版本前缀（如 file:、npm: 等非语义版本前缀）
		cleanVer := version
		if strings.HasPrefix(cleanVer, "npm:") {
			cleanVer = strings.TrimPrefix(cleanVer, "npm:")
		}
		// 只处理纯语义版本（以数字开头）
		if cleanVer == "" || cleanVer[0] < '0' || cleanVer[0] > '9' {
			continue
		}

		for _, vuln := range npmKnownVulns[name] {
			if isVersionLower(cleanVer, vuln.FixedVersion) {
				vulns = append(vulns, DependencyVulnerability{
					PackageName:      name,
					InstalledVersion: cleanVer,
					VulnerabilityID:  vuln.CVEID,
					Severity:         vuln.Severity,
					FixedVersion:     vuln.FixedVersion,
					Description:      vuln.Description,
				})
			}
		}
	}
	return vulns
}

// scanPomXml 解析 pom.xml (Java/Maven)
func (s *DependencyScanner) scanPomXml(content []byte) []DependencyVulnerability {
	var vulns []DependencyVulnerability

	// 简单 XML 解析：提取 <dependency> 块中的 groupId:artifactId:version
	depRe := regexp.MustCompile(`(?s)<dependency>\s*(.*?)\s*</dependency>`)
	gavRe := regexp.MustCompile(`(?s)<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>`)

	for _, depMatch := range depRe.FindAllStringSubmatch(string(content), -1) {
		if len(depMatch) < 2 {
			continue
		}
		depBlock := depMatch[1]
		gav := gavRe.FindStringSubmatch(depBlock)
		if len(gav) < 4 {
			continue
		}
		groupID := strings.TrimSpace(gav[1])
		artifactID := strings.TrimSpace(gav[2])
		version := strings.TrimSpace(gav[3])

		// 跳过 Maven 属性引用（如 ${spring.version}）
		if strings.Contains(version, "${") {
			continue
		}

		// 去掉版本前缀（如 ${project.version} 等）
		version = strings.TrimPrefix(version, "[")

		// 构建 Maven 坐标 key
		mavenKey := groupID + ":" + artifactID
		for _, vuln := range mavenKnownVulns[mavenKey] {
			if isVersionLower(version, vuln.FixedVersion) {
				vulns = append(vulns, DependencyVulnerability{
					PackageName:      mavenKey,
					InstalledVersion: version,
					VulnerabilityID:  vuln.CVEID,
					Severity:         vuln.Severity,
					FixedVersion:     vuln.FixedVersion,
					Description:      vuln.Description,
				})
			}
		}
	}
	return vulns
}

// scanGoMod 解析 go.mod (Go)
func (s *DependencyScanner) scanGoMod(content []byte) []DependencyVulnerability {
	var vulns []DependencyVulnerability

	lines := strings.Split(string(content), "\n")
	inRequireBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 处理 require 块（单行和多行两种形式）
		if strings.HasPrefix(line, "require ") {
			// 单行 require: require github.com/pkg/errors v0.9.1
			rest := strings.TrimPrefix(line, "require ")
			if v := checkGoModule(rest); v != nil {
				vulns = append(vulns, v...)
			}
			continue
		}
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if line == ")" && inRequireBlock {
			inRequireBlock = false
			continue
		}
		if inRequireBlock {
			if v := checkGoModule(line); v != nil {
				vulns = append(vulns, v...)
			}
		}
	}
	return vulns
}

// checkGoModule 检查单个 Go 模块行是否有已知漏洞。
// 行格式: github.com/pkg/errors v0.9.1
// 或带注释: github.com/pkg/errors v0.9.1 // indirect
func checkGoModule(line string) []DependencyVulnerability {
	// 去掉注释
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	modulePath := parts[0]
	version := strings.TrimPrefix(parts[1], "v") // go.mod 版本格式为 v1.2.3

	// 只处理语义版本（以数字开头）
	if version == "" || version[0] < '0' || version[0] > '9' {
		return nil
	}

	// 精确匹配模块路径
	if vulns, ok := goKnownVulns[modulePath]; ok {
		var result []DependencyVulnerability
		for _, vuln := range vulns {
			if isVersionLower(version, vuln.FixedVersion) {
				result = append(result, DependencyVulnerability{
					PackageName:      modulePath,
					InstalledVersion: version,
					VulnerabilityID:  vuln.CVEID,
					Severity:         vuln.Severity,
					FixedVersion:     vuln.FixedVersion,
					Description:      vuln.Description,
				})
			}
		}
		return result
	}

	// 前缀匹配（处理子包：github.com/golang-jwt/jwt/v4 等）
	for modPath, vulns := range goKnownVulns {
		if strings.HasPrefix(modulePath, modPath) {
			var result []DependencyVulnerability
			for _, vuln := range vulns {
				if isVersionLower(version, vuln.FixedVersion) {
					result = append(result, DependencyVulnerability{
						PackageName:      modulePath,
						InstalledVersion: version,
						VulnerabilityID:  vuln.CVEID,
						Severity:         vuln.Severity,
						FixedVersion:     vuln.FixedVersion,
						Description:      vuln.Description,
					})
				}
			}
			return result
		}
	}
	return nil
}

// ============================================================
// CIS Benchmark 合规扫描器（保持不变）
// ============================================================

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
