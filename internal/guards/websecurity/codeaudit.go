package websecurity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/suoten/serverguard/internal/guards/scannercommon"
	"github.com/suoten/serverguard/internal/types"
)

// ============================================================
// W12-W18: 源码漏洞审计扫描器
// 静态分析 PHP/JSP/Python/Node 源码中的安全漏洞
// 安全原则：只检测不修复，所有修复需用户在面板点击"确认修复"后执行
// ============================================================

type codeAuditPattern struct {
	pattern  *regexp.Regexp
	name     string
	severity types.Severity
}

// W12 SQL注入漏洞扫描器
type W12SQLiScanner struct{ base *WebSecurityGuard }

func (s *W12SQLiScanner) Name() string       { return "websecurity" }
func (s *W12SQLiScanner) SubScanner() string { return "W12" }

var w12Patterns = []codeAuditPattern{
	{regexp.MustCompile(`(?i)(?:mysql_query|mysqli_query|->query|->execute|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\s*\[`), "SQL注入: 用户输入直接拼接SQL查询", types.SeverityCritical},
	// 收紧：只匹配 SQL 语句直接拼接用户输入，不匹配拼接任意变量
	// 旧正则 "SELECT" . $variable 会匹配几乎所有 PHP 框架的查询构造器
	{regexp.MustCompile(`(?i)\$\w+\s*=\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*["']\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)`), "SQL注入: SQL语句拼接用户输入", types.SeverityCritical},
	// 删除旧的第36行正则："SELECT" . $variable 匹配太宽泛，框架查询构造器中极其常见
	{regexp.MustCompile(`(?i)(?:cursor\.execute|db\.execute)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"']*["']\s*%\s*(?:request|input|form|args)`), "Python SQL注入: 字符串格式化SQL", types.SeverityCritical},
	{regexp.MustCompile(`(?i)(?:query|execute)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"']*["']\s*\+\s*(?:req\.(body|query|params))`), "Node.js SQL注入: 拼接用户输入", types.SeverityCritical},
}

func (s *W12SQLiScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	scanCodeFiles(s.base, target.Path, w12Patterns, "SQL注入漏洞", rb, "W12")
	return rb.GetFindings(), nil
}

// W13 文件上传漏洞扫描器
type W13UploadScanner struct{ base *WebSecurityGuard }

func (s *W13UploadScanner) Name() string       { return "websecurity" }
func (s *W13UploadScanner) SubScanner() string { return "W13" }

var w13Patterns = []codeAuditPattern{
	// 收紧：只匹配后端代码中的上传逻辑，不匹配前端 JS 中的上传配置
	// 旧正则 upload.*\.php 会匹配 UEditor 等前端配置中的 allowFiles: [".php"]
	{regexp.MustCompile(`move_uploaded_file\s*\([^,]*,\s*["'][^"']*?\$_(FILES|GET|POST)`), "文件上传: 使用用户提供的文件名", types.SeverityHigh},
	// 收紧：匹配 move_uploaded_file 上传到以 .php 结尾的目标路径
	// 旧正则会匹配 FastAdmin 的 Ajax.php 中的 move_uploaded_file($file, $dir . $filename)
	// 其中 $filename 可能包含 .php 扩展名，但这是框架的正常上传逻辑
	{regexp.MustCompile(`move_uploaded_file\s*\([^,]*,\s*["'][^"']*\/[^"']*\.php["']`), "文件上传: 上传到PHP目录", types.SeverityCritical},
	{regexp.MustCompile(`(?i)(?:fs\.writeFile|fs\.createWriteStream)\s*\([^)]*req\.(files|body)`), "Node.js文件上传: 无类型校验", types.SeverityHigh},
	// 删除旧的泛化正则：upload.*\.(?:php|phtml|jsp|asp|aspx|sh|py)
	// 该正则会匹配所有前端 JS 中的上传配置（UEditor、Vue 组件等），误报率极高
}

func (s *W13UploadScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	scanCodeFiles(s.base, target.Path, w13Patterns, "文件上传漏洞", rb, "W13")
	return rb.GetFindings(), nil
}

// W14 XSS漏洞扫描器
type W14XSSScanner struct{ base *WebSecurityGuard }

func (s *W14XSSScanner) Name() string       { return "websecurity" }
func (s *W14XSSScanner) SubScanner() string { return "W14" }

var w14Patterns = []codeAuditPattern{
	{regexp.MustCompile(`echo\s+\$_(GET|POST|REQUEST|COOKIE)\s*\[`), "XSS: echo直接输出用户输入", types.SeverityCritical},
	{regexp.MustCompile(`printf\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)\s*\[`), "XSS: printf输出用户输入", types.SeverityHigh},
	{regexp.MustCompile(`<\w+[^>]*>\s*<\?php\s+echo\s+\$_(GET|POST|REQUEST)`), "XSS: HTML中输出用户输入", types.SeverityCritical},
	{regexp.MustCompile(`(?i)res\.(send|write|end)\s*\(\s*[^)]*req\.(query|body|params|cookies)`), "Node.js XSS: 响应输出用户输入", types.SeverityHigh},
}

func (s *W14XSSScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	scanCodeFiles(s.base, target.Path, w14Patterns, "XSS漏洞", rb, "W14")
	return rb.GetFindings(), nil
}

// W15 命令注入漏洞扫描器
type W15CmdInjectionScanner struct{ base *WebSecurityGuard }

func (s *W15CmdInjectionScanner) Name() string       { return "websecurity" }
func (s *W15CmdInjectionScanner) SubScanner() string { return "W15" }

var w15Patterns = []codeAuditPattern{
	{regexp.MustCompile(`(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\s*\[`), "命令注入: 系统命令拼接用户输入", types.SeverityCritical},
	{regexp.MustCompile("(?i)os\\.system\\s*\\([^)]*(?:request|input|argv|form|args)"), "Python命令注入: os.system拼接用户输入", types.SeverityCritical},
	{regexp.MustCompile(`(?i)child_process\.(?:exec|execSync|spawn)\s*\([^)]*req\.(query|body|params)`), "Node.js命令注入: child_process拼接用户输入", types.SeverityCritical},
	{regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\s*\([^)]*request\.get`), "Java命令注入: Runtime.exec拼接用户输入", types.SeverityCritical},
}

func (s *W15CmdInjectionScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	scanCodeFiles(s.base, target.Path, w15Patterns, "命令注入漏洞", rb, "W15")
	return rb.GetFindings(), nil
}

// W16 SSRF漏洞扫描器
type W16SSRFScanner struct{ base *WebSecurityGuard }

func (s *W16SSRFScanner) Name() string       { return "websecurity" }
func (s *W16SSRFScanner) SubScanner() string { return "W16" }

var w16Patterns = []codeAuditPattern{
	{regexp.MustCompile(`curl_(?:exec|setopt)\s*\([^)]*CURLOPT_URL[^)]*\$_(GET|POST|REQUEST|COOKIE)`), "SSRF: curl拼接用户输入URL", types.SeverityCritical},
	{regexp.MustCompile(`file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`), "SSRF: file_get_contents拼接用户输入", types.SeverityCritical},
	// Python SSRF: 收紧为 requests.get(f"...{request/input/form/args}...") 形式
	// 避免匹配 requests.get(request) 这种正常调用（参数名恰好叫 request）
	{regexp.MustCompile(`(?i)requests\.(?:get|post|put|delete|head)\s*\(\s*f["'].*\{[^}]*\}(?:request|input|form|args)`), "Python SSRF: requests拼接用户输入", types.SeverityCritical},
	{regexp.MustCompile(`(?i)axios\.(?:get|post)\s*\(\s*req\.(query|body|params)`), "Node.js SSRF: axios拼接用户输入", types.SeverityCritical},
}

func (s *W16SSRFScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	scanCodeFiles(s.base, target.Path, w16Patterns, "SSRF漏洞", rb, "W16")
	return rb.GetFindings(), nil
}

// W17 反序列化漏洞扫描器
type W17DeserializeScanner struct{ base *WebSecurityGuard }

func (s *W17DeserializeScanner) Name() string       { return "websecurity" }
func (s *W17DeserializeScanner) SubScanner() string { return "W17" }

var w17Patterns = []codeAuditPattern{
	{regexp.MustCompile(`unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`), "反序列化: unserialize用户输入", types.SeverityCritical},
	// 删除旧的第152行正则：unserialize($variable) 在第三方库中极其常见
	// 只保留匹配用户输入的 unserialize($_GET/$_POST) 规则（第151行已有）
	{regexp.MustCompile(`pickle\.loads\s*\(\s*(?:request|input|form|args)`), "Python反序列化: pickle.loads用户输入", types.SeverityCritical},
	{regexp.MustCompile(`ObjectInputStream\s*\(`), "Java反序列化: ObjectInputStream", types.SeverityCritical},
}

func (s *W17DeserializeScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	scanCodeFiles(s.base, target.Path, w17Patterns, "反序列化漏洞", rb, "W17")
	return rb.GetFindings(), nil
}

// W18 敏感信息泄露扫描器
type W18SensitiveDataScanner struct{ base *WebSecurityGuard }

func (s *W18SensitiveDataScanner) Name() string       { return "websecurity" }
func (s *W18SensitiveDataScanner) SubScanner() string { return "W18" }

var w18Patterns = []codeAuditPattern{
	{regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}["']`), "硬编码密码", types.SeverityHigh},
	{regexp.MustCompile(`(?i)(?:mysql|pgsql|mongodb|redis)://\w+:\w+@`), "数据库连接串硬编码", types.SeverityCritical},
	{regexp.MustCompile(`(?i)(?:api_key|apikey|secret_key|access_key)\s*[:=]\s*["'][^"']{16,}["']`), "API Key 硬编码", types.SeverityHigh},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS AccessKey 硬编码", types.SeverityCritical},
	{regexp.MustCompile(`LTAI[0-9A-Za-z]{12,}`), "阿里云 AccessKey 硬编码", types.SeverityCritical},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`), "私钥泄露", types.SeverityCritical},
	{regexp.MustCompile(`(?i)jwt[_-]?secret\s*[:=]\s*["'][^"']{8,}["']`), "JWT Secret 硬编码", types.SeverityHigh},
}

func (s *W18SensitiveDataScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)
	if target.Path == "" {
		return rb.GetFindings(), nil
	}
	root := target.Path
	s.base.walkFiles(root, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		isConfig := ext == ".env" || ext == ".conf" || ext == ".ini" || ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".xml" || strings.HasSuffix(strings.ToLower(path), ".env")
		isSource := ext == ".php" || ext == ".py" || ext == ".go" || ext == ".java" || ext == ".sh"
		// JS 文件不进行敏感信息审计：前端打包文件中常含 API Key 字符串（前端公钥），不是真正的泄露
		if !isConfig && !isSource {
			return nil
		}
		// .env 文件本身就是用来存放密钥的，报告"硬编码"是矛盾的
		// .env 文件的安全由 W1 敏感文件检测覆盖（检测 .env 是否暴露到 Web 可访问目录）
		if strings.HasSuffix(strings.ToLower(path), ".env") {
			return nil
		}
		// docker-compose 文件中的密码通常引用环境变量（${PASSWORD}），是正常配置
		lowerBase := strings.ToLower(filepath.Base(path))
		if strings.HasPrefix(lowerBase, "docker-compose") || strings.HasPrefix(lowerBase, "compose") {
			return nil
		}
		// CI/CD 配置文件中的密钥通常引用 CI 变量（$CI_xxx），是正常配置
		if lowerBase == ".gitlab-ci.yml" || lowerBase == ".github-workflows.yml" ||
			strings.HasPrefix(lowerBase, ".github/") || lowerBase == "jenkinsfile" ||
			strings.HasPrefix(lowerBase, ".gitlab-ci") {
			return nil
		}
		// 测试文件中的数据库连接串/密钥通常是测试用的本地凭据，不是真实泄露
		lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
		if strings.Contains(lowerPath, "/tests/") || strings.Contains(lowerPath, "/test/") ||
			strings.Contains(lowerPath, "/testing/") || strings.Contains(lowerPath, "/__tests__/") ||
			strings.HasPrefix(filepath.Base(lowerPath), "test_") ||
			strings.HasPrefix(filepath.Base(lowerPath), "conftest.") {
			return nil
		}
		// 示例文件（example/sample/demo）中的密码是教学/模板，不是真实泄露
		if strings.Contains(lowerBase, "example") || strings.Contains(lowerBase, "sample") ||
			strings.Contains(lowerBase, "demo") || strings.Contains(lowerBase, "template") {
			return nil
		}
		if isKnownVendorFramework(path) || isKnownFrontendLibrary(path) {
			return nil
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}
		data, err := s.base.readFileLimited(path)
		if err != nil || len(data) == 0 {
			return nil
		}
		for _, p := range w18Patterns {
			if p.pattern.Match(data) {
				rb.AddFinding(
					p.severity,
					fmt.Sprintf("敏感信息泄露: %s", p.name),
					fmt.Sprintf("文件 %s 中发现 %s", path, p.name),
					path,
					fmt.Sprintf("文件: %s, 泄露类型: %s", path, p.name),
					"将密码/Key 移到环境变量或 .env 文件",
					"修改后需确认程序能正常读取到配置",
				)
				break
			}
		}
		return nil
	})
	findings := rb.GetFindings()
	setSubScanner(findings, "W18")
	return findings, nil
}

// scanCodeFiles 通用源码扫描函数
func scanCodeFiles(g *WebSecurityGuard, root string, patterns []codeAuditPattern, vulnType string, rb *scannercommon.ReportBuilder, subScanner string) {
	g.walkFilesForMalware(root, func(path string, info os.FileInfo) error {
		ext := strings.ToLower(filepath.Ext(path))
		// JS 文件不进行代码漏洞审计
		// 漏洞审计只针对后端代码（PHP/Python/Java/Go），前端 JS 中只有配置和 UI 逻辑，不是真正的漏洞
		// 之前扫描 JS 导致大量误报：UEditor 配置中的 allowFiles、Vue 打包文件中的 upload 关键词等
		if ext != ".php" && ext != ".phtml" && ext != ".py" && ext != ".jsp" && ext != ".go" {
			return nil
		}
		if isKnownVendorFramework(path) {
			return nil
		}
		// 跳过测试文件：测试代码中的数据库连接/命令执行等是测试用的本地凭据，不是真实漏洞
		lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
		if strings.Contains(lowerPath, "/tests/") || strings.Contains(lowerPath, "/test/") ||
			strings.Contains(lowerPath, "/testing/") || strings.Contains(lowerPath, "/__tests__/") ||
			strings.HasPrefix(filepath.Base(lowerPath), "test_") ||
			strings.HasPrefix(filepath.Base(lowerPath), "conftest.") {
			return nil
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}
		data, err := g.readFileLimited(path)
		if err != nil || len(data) == 0 {
			return nil
		}
		for _, p := range patterns {
			if p.pattern.Match(data) {
				rb.AddFinding(
					p.severity,
					fmt.Sprintf("%s: %s", vulnType, p.name),
					fmt.Sprintf("文件 %s 存在%s风险: %s", path, vulnType, p.name),
					path,
					fmt.Sprintf("文件: %s, 漏洞: %s", path, p.name),
					"根据修复指南修改代码",
					"修改后需重新测试相关功能",
				)
				break
			}
		}
		return nil
	})
	f := rb.GetFindings()
	setSubScanner(f, subScanner)
}
