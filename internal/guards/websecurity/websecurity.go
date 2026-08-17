package websecurity

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/guards/scannercommon"
)

// ============================================================
// W 模块：网站安全扫描（WebSecurityGuard）
// 包含 9 个子扫描器 W1-W9
// 安全原则：只检测不修复，所有修复需用户在面板点击"确认修复"后执行
// 每个修复项均明确提示修复后果
// ============================================================

// WebSecurityGuard W模块主结构体，管理9个子扫描器
type WebSecurityGuard struct {
	store       *storage.Storage
	quarantine  *scannercommon.QuarantineManager
	baseline    *scannercommon.BaselineManager
	httpTimeout time.Duration
	maxFileSize int64
	maxFiles    int
	scanners    []scannercommon.Scanner
	yaraEngine  *scannercommon.YaraEngine

	// 文件哈希基线：path -> sha256（W3 篡改检测使用）
	baselineMu    sync.RWMutex
	fileBaselines map[string]string
	// 已扫描 URL 缓存（避免重复探测）
	urlCacheMu sync.Mutex
	urlCache   map[string]int

	// W5 数据库扫描去重：避免对同一 host 的端口重复报告（116个站点指向同一个 localhost）
	w5DedupMu sync.Mutex
	w5Scanned map[string]bool // key: "host:port"
	// W6 配置文件扫描去重：同一配置文件只扫描一次
	w6DedupMu      sync.Mutex
	w6ScannedFiles map[string]bool
}

// New 创建 WebSecurityGuard 实例
func New(store *storage.Storage, baseDir string) *WebSecurityGuard {
	yaraEngine := scannercommon.NewYaraEngine()
	// 加载 configs/yara_rules/ 下的 .yar 规则文件
	if err := yaraEngine.LoadRulesFromDir("configs/yara_rules"); err != nil {
		// 规则加载失败不阻断启动，仅降级为内置规则
		_ = err
	}

	g := &WebSecurityGuard{
		store:          store,
		quarantine:     scannercommon.NewQuarantineManager(baseDir),
		baseline:       scannercommon.NewBaselineManager(store),
		httpTimeout:    10 * time.Second,
		maxFileSize:    50 * 1024 * 1024, // 50MB
		maxFiles:       10000,
		fileBaselines:  make(map[string]string),
		urlCache:       make(map[string]int),
		yaraEngine:     yaraEngine,
		w5Scanned:      make(map[string]bool),
		w6ScannedFiles: make(map[string]bool),
	}
	// 注册 9 个子扫描器
	g.scanners = []scannercommon.Scanner{
		&W1SensitiveFileScanner{base: g},
		&W2BackupFileScanner{base: g},
		&W3TamperScanner{base: g},
		&W4AdminScanner{base: g},
		&W5DatabaseScanner{base: g},
		&W6ConfigScanner{base: g},
		&W7BrokenLinkScanner{base: g},
		&W8FTPScanner{base: g},
		&W9HomepageScanner{base: g},
	}
	return g
}

// Scanners 返回所有子扫描器
func (g *WebSecurityGuard) Scanners() []scannercommon.Scanner {
	return g.scanners
}

// Quarantine 返回隔离管理器
func (g *WebSecurityGuard) Quarantine() *scannercommon.QuarantineManager {
	return g.quarantine
}

// ResetDedupCaches 重置去重缓存。
// 必须在每次完整扫描周期开始前调用，否则跨扫描周期的去重会导致后续扫描返回 0 个发现项，
// 进而 ResolveStaleFindings 会把之前的 open 发现项全部标记为 auto_resolved。
func (g *WebSecurityGuard) ResetDedupCaches() {
	g.w5DedupMu.Lock()
	g.w5Scanned = make(map[string]bool)
	g.w5DedupMu.Unlock()

	g.w6DedupMu.Lock()
	g.w6ScannedFiles = make(map[string]bool)
	g.w6DedupMu.Unlock()

	g.urlCacheMu.Lock()
	g.urlCache = make(map[string]int)
	g.urlCacheMu.Unlock()
}

// Scan 执行所有子扫描器，汇总发现项
// 单个子扫描器失败不中断整体扫描
func (g *WebSecurityGuard) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	// 每次扫描前重置去重缓存，确保跨扫描周期的发现项不会因为去重而丢失
	g.ResetDedupCaches()

	var allFindings []types.ScanFinding
	for _, s := range g.scanners {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}
		findings, err := s.Scan(ctx, target)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

// ScanWithSub 执行指定子扫描器
func (g *WebSecurityGuard) ScanWithSub(ctx context.Context, target types.ScanTarget, sub string) ([]types.ScanFinding, error) {
	for _, s := range g.scanners {
		if s.SubScanner() == sub {
			return s.Scan(ctx, target)
		}
	}
	return nil, fmt.Errorf("sub scanner %s not found", sub)
}

// SetBaseline 设置文件哈希基线
func (g *WebSecurityGuard) SetBaseline(path, hash string) {
	g.baselineMu.Lock()
	defer g.baselineMu.Unlock()
	g.fileBaselines[path] = hash
}

// GetBaseline 获取文件哈希基线
func (g *WebSecurityGuard) GetBaseline(path string) (string, bool) {
	g.baselineMu.RLock()
	defer g.baselineMu.RUnlock()
	hash, ok := g.fileBaselines[path]
	return hash, ok
}

// SaveFindings 将发现项保存到存储
func (g *WebSecurityGuard) SaveFindings(findings []types.ScanFinding) error {
	if g.store == nil {
		return nil
	}
	return scannercommon.SaveFindingsToStorage(g.store, findings)
}

// ---------- 内部工具方法 ----------

// httpGet 发送 HTTP GET 请求（跳过 TLS 验证以支持自签名证书检测）
func (g *WebSecurityGuard) httpGet(ctx context.Context, url string) (*http.Response, error) {
	client := &http.Client{
		Timeout: g.httpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ServerGuard-WebSecurity-Scanner/1.0")
	return client.Do(req)
}

// targetURL 构建目标 URL
func (g *WebSecurityGuard) targetURL(target types.ScanTarget) string {
	if target.Host == "" {
		return ""
	}
	scheme := "http"
	if target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}
	if target.Port == 0 || target.Port == 80 || target.Port == 443 {
		return fmt.Sprintf("%s://%s", scheme, target.Host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, target.Host, target.Port)
}

// walkFiles 遍历目录下的文件，限制数量
// 使用 WalkDir 比 Walk 更快（不调用 os.Lstat）

// webSkipDirsGeneral 通用扫描时跳过的目录（W2 备份文件扫描等）
// 这些目录中的备份文件不是常见攻击向量
var webSkipDirsGeneral = map[string]bool{
	"node_modules": true, // Node.js 依赖（数千文件，PHP webshell 不执行）
	"__pycache__":  true, // Python 字节码缓存
	".git":         true,
	".svn":         true,
	".cache":       true,
	"dist":         true, // 编译前端
	"build":        true,
	"vendor":       true, // Composer 依赖
	"wp-includes":  true, // WordPress 核心
	"wp-admin":     true, // WordPress 管理
	"runtime":      true, // ThinkPHP/Yii 运行时
	"storage":      true, // Laravel 存储
	"bootstrap":    true, // Laravel bootstrap
	"bundles":      true, // Symfony
	"components":   true,
}

// webSkipDirsMalware 恶意代码扫描时只跳过这些目录
// 注意：vendor/wp-includes/wp-admin/plugins/themes 不跳过！
// 因为攻击者经常在这些目录植入 Webshell
var webSkipDirsMalware = map[string]bool{
	"node_modules": true, // JS 依赖（PHP/ASP webshell 不执行）
	"__pycache__":  true, // Python 字节码
	".git":         true,
	".svn":         true,
	".cache":       true,
}

func (g *WebSecurityGuard) walkFiles(root string, fn func(path string, info os.FileInfo) error) error {
	return g.walkFilesWithSkip(root, webSkipDirsGeneral, fn)
}

// walkFilesForMalware 遍历文件用于恶意代码检测
// 不跳过 vendor/wp-includes/wp-admin/plugins/themes 等目录
// 因为攻击者经常在这些目录植入 Webshell
func (g *WebSecurityGuard) walkFilesForMalware(root string, fn func(path string, info os.FileInfo) error) error {
	return g.walkFilesWithSkip(root, webSkipDirsMalware, fn)
}

func (g *WebSecurityGuard) walkFilesWithSkip(root string, skipDirs map[string]bool, fn func(path string, info os.FileInfo) error) error {
	count := 0
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无法访问的路径
		}
		if count >= g.maxFiles {
			return filepath.SkipDir
		}
		if d.IsDir() {
			dirName := d.Name()
			if skipDirs[dirName] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		count++
		return fn(path, info)
	})
}

// readFileLimited 读取文件内容（限制大小）
func (g *WebSecurityGuard) readFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, g.maxFileSize))
}

// sha256Hash 计算 SHA256 哈希
func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// shannonEntropy 计算香农熵（用于检测加密/混淆内容）
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// setSubScanner 为 findings 设置子扫描器标识
func setSubScanner(findings []types.ScanFinding, sub string) {
	for i := range findings {
		findings[i].ScannerSub = sub
	}
}

// ============================================================
// W1: 敏感文件泄露检测
// 检测 .git/、.env、.svn/、config.php、database.yml、backup.sql、
// .htpasswd、id_rsa、docker-compose.yml、.DS_Store、web.config、
// .idea/、.vscode/ 等敏感文件和目录的泄露
// ============================================================

// W1SensitiveFileScanner 敏感文件泄露检测扫描器
type W1SensitiveFileScanner struct {
	base *WebSecurityGuard
}

func (s *W1SensitiveFileScanner) Name() string       { return "websecurity" }
func (s *W1SensitiveFileScanner) SubScanner() string { return "W1" }

// w1SensitiveFiles 敏感文件/目录列表
var w1SensitiveFiles = []struct {
	name     string
	severity types.Severity
	desc     string
}{
	{".git/", types.SeverityHigh, "Git仓库目录泄露，可能暴露源代码和提交历史"},
	{".git/config", types.SeverityHigh, "Git配置文件泄露，包含仓库路径和远程地址"},
	{".git/HEAD", types.SeverityMedium, "Git HEAD文件泄露"},
	{".env", types.SeverityHigh, "环境变量文件，可能包含数据库密码、API密钥等敏感信息（需确认是否可被Web访问）"},
	{".env.local", types.SeverityHigh, "本地环境变量文件，可能包含敏感配置"},
	{".env.production", types.SeverityHigh, "生产环境变量文件，可能包含敏感配置"},
	{".svn/", types.SeverityHigh, "SVN仓库目录泄露"},
	{".svn/entries", types.SeverityHigh, "SVN条目文件泄露"},
	{".htpasswd", types.SeverityHigh, "Apache密码文件泄露"},
	{".htaccess", types.SeverityLow, "Apache配置文件泄露（通常无法通过Web直接访问）"},
	{"id_rsa", types.SeverityCritical, "SSH私钥泄露"},
	{"id_dsa", types.SeverityCritical, "SSH DSA私钥泄露"},
	{"id_ecdsa", types.SeverityCritical, "SSH ECDSA私钥泄露"},
	{"id_ed25519", types.SeverityCritical, "SSH Ed25519私钥泄露"},
	{".DS_Store", types.SeverityLow, "macOS目录信息文件泄露，可能暴露目录结构"},
	{".idea/", types.SeverityMedium, "JetBrains IDE配置目录泄露"},
	{".vscode/", types.SeverityLow, "VS Code配置目录泄露"},
	{".hg/", types.SeverityHigh, "Mercurial仓库目录泄露"},
	{".bzr/", types.SeverityMedium, "Bazaar仓库目录泄露"},
	{"credentials.json", types.SeverityHigh, "凭证文件，可能包含API密钥或服务凭证"},
	{"service-account.json", types.SeverityCritical, "服务账号密钥文件泄露"},
	{".aws/credentials", types.SeverityCritical, "AWS凭证文件泄露"},
	{".ssh/config", types.SeverityMedium, "SSH配置文件泄露"},
}

// Scan 执行 W1 敏感文件泄露检测
func (s *W1SensitiveFileScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	// 方式1：文件系统扫描
	if target.Path != "" {
		s.scanFileSystem(rb, target.Path)
	}

	// 方式2：HTTP 探测
	baseURL := s.base.targetURL(target)
	if baseURL != "" {
		s.scanHTTP(ctx, rb, baseURL)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W1")
	return findings, nil
}

// scanFileSystem 文件系统扫描敏感文件
func (s *W1SensitiveFileScanner) scanFileSystem(rb *scannercommon.ReportBuilder, root string) {
	for _, sf := range w1SensitiveFiles {
		fullPath := filepath.Join(root, sf.name)
		if _, err := os.Stat(fullPath); err == nil {
			rb.AddFinding(
				sf.severity,
				fmt.Sprintf("敏感文件泄露: %s", sf.name),
				sf.desc,
				fullPath,
				fmt.Sprintf("在路径 %s 发现敏感文件/目录: %s", root, sf.name),
				"删除该敏感文件或目录，或配置 Web 服务器拒绝访问",
				"删除文件后相关功能可能受影响；请确认文件用途后再删除",
			)
		}
	}
}

// scanHTTP 通过 HTTP 探测敏感文件是否可访问
func (s *W1SensitiveFileScanner) scanHTTP(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	for _, sf := range w1SensitiveFiles {
		url := strings.TrimRight(baseURL, "/") + "/" + sf.name
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		// 200 响应表示文件可访问
		if resp.StatusCode == 200 {
			detail := fmt.Sprintf("URL %s 返回 200，敏感文件可被公开访问", url)
			if len(body) > 0 {
				detail += fmt.Sprintf("，响应大小: %d 字节", len(body))
			}
			rb.AddFinding(
				sf.severity,
				fmt.Sprintf("敏感文件可通过HTTP访问: %s", sf.name),
				sf.desc,
				url,
				detail,
				"配置 Web 服务器拒绝访问该路径，或删除该文件",
				"限制访问后依赖该文件的合法功能可能受影响",
			)
		}
	}
}

// ============================================================
// W2: 备份文件暴露检测
// 检测 *.sql、*_backup.zip、*.bak、*.old、*.swp、www.zip、
// backup.zip、data.zip 等备份文件的暴露
// ============================================================

// W2BackupFileScanner 备份文件暴露检测扫描器
type W2BackupFileScanner struct {
	base *WebSecurityGuard
}

func (s *W2BackupFileScanner) Name() string       { return "websecurity" }
func (s *W2BackupFileScanner) SubScanner() string { return "W2" }

// w2BackupExtensions 备份文件扩展名（仅明确的备份类型，不含 .sql/.tmp）
var w2BackupExtensions = []string{
	".bak", ".old", ".swp", ".swo",
	".backup", ".orig", ".save", ".dump",
}

// w2BackupFileNames 常见备份文件名（仅匹配这些精确文件名，不再用模糊正则）
var w2BackupFileNames = []string{
	"www.zip", "backup.zip", "data.zip", "site.zip", "web.zip",
	"www.tar.gz", "backup.tar.gz", "site.tar.gz",
	"www.rar", "backup.rar", "www.7z", "backup.7z",
	"database.sql", "db.sql", "dump.sql",
	"backup_1.zip", "backup_2.zip",
}

// w2BackupNameRegex 备份文件名正则模式（收紧：必须有明确的备份后缀模式）
var w2BackupNameRegex = regexp.MustCompile(`(?i)^(.*[_-])?(backup|dump|export)([_-]\d{4}[_-]\d{2}[_-]\d{2})?\.(zip|tar\.gz|rar|7z|sql|bak)$`)

// w2SqlBackupNames 明确的 SQL 备份文件名（只有这些 .sql 文件会被标记）
var w2SqlBackupNames = map[string]bool{
	"database.sql": true, "db.sql": true, "dump.sql": true,
	"backup.sql": true, "data.sql": true, "export.sql": true,
	"mysql.sql": true, "all.sql": true,
}

// Scan 执行 W2 备份文件暴露检测
func (s *W2BackupFileScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	// 方式1：文件系统扫描
	if target.Path != "" {
		s.scanFileSystem(rb, target.Path)
	}

	// 方式2：HTTP 探测
	baseURL := s.base.targetURL(target)
	if baseURL != "" {
		s.scanHTTP(ctx, rb, baseURL)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W2")
	return findings, nil
}

// scanFileSystem 文件系统扫描备份文件
func (s *W2BackupFileScanner) scanFileSystem(rb *scannercommon.ReportBuilder, root string) {
	s.base.walkFiles(root, func(path string, info os.FileInfo) error {
		name := info.Name()
		lowerName := strings.ToLower(name)

		// 跳过小文件（< 1KB），只关注有实际内容的备份文件
		if info.Size() < 1024 {
			return nil
		}

		matched := false
		severity := types.SeverityHigh

		// 检查 1: 精确匹配已知备份文件名
		for _, bn := range w2BackupFileNames {
			if lowerName == strings.ToLower(bn) {
				matched = true
				if strings.HasSuffix(lowerName, ".sql") {
					severity = types.SeverityCritical // SQL 备份文件可能包含完整数据库
				}
				break
			}
		}

		// 检查 2: 匹配收紧后的正则（仅匹配 *_backup_20240101.zip 这类明确备份）
		if !matched && w2BackupNameRegex.MatchString(name) {
			matched = true
		}

		// 检查 3: 明确的 SQL 备份文件名
		if !matched && strings.HasSuffix(lowerName, ".sql") {
			if w2SqlBackupNames[lowerName] {
				matched = true
				severity = types.SeverityCritical
			}
		}

		// 检查 4: *_backup.zip / *-backup.zip 模式
		if !matched {
			if strings.HasSuffix(lowerName, "_backup.zip") ||
				strings.HasSuffix(lowerName, "-backup.zip") ||
				strings.HasSuffix(lowerName, "_backup.tar.gz") ||
				strings.HasSuffix(lowerName, "-backup.tar.gz") {
				matched = true
			}
		}

		// 检查 5: 扩展名匹配（.bak/.old/.swp 等，但不包含 .sql/.tmp）
		if !matched {
			for _, ext := range w2BackupExtensions {
				if strings.HasSuffix(lowerName, ext) {
					matched = true
					severity = types.SeverityMedium // .bak/.old 文件风险较低
					break
				}
			}
		}

		if matched {
			rb.AddFinding(
				severity,
				fmt.Sprintf("备份文件暴露: %s", name),
				fmt.Sprintf("备份文件 %s 可能包含敏感数据，不应存放在 Web 可访问目录", name),
				path,
				fmt.Sprintf("文件路径: %s，大小: %d 字节", path, info.Size()),
				"将备份文件移到 Web 根目录之外，或删除不再需要的备份",
				"移动或删除备份文件后，相关恢复操作需使用新路径",
			)
		}
		return nil
	})
}

// scanHTTP 通过 HTTP 探测备份文件
func (s *W2BackupFileScanner) scanHTTP(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	for _, bn := range w2BackupFileNames {
		url := strings.TrimRight(baseURL, "/") + "/" + bn
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			rb.AddFinding(
				types.SeverityCritical,
				fmt.Sprintf("备份文件可通过HTTP下载: %s", bn),
				fmt.Sprintf("备份文件 %s 可被公开下载，可能包含完整数据库或源代码", bn),
				url,
				fmt.Sprintf("URL %s 返回 200，备份文件可被任意下载", url),
				"立即删除该备份文件，并将后续备份存放到 Web 根目录之外",
				"删除后无法通过该 URL 恢复数据；请确认已安全保存备份",
			)
		}
	}
}

// ============================================================
// W3: 网站挂马/篡改检测
// 使用正则匹配检测恶意代码模式（eval(base64_decode(、assert($_POST[、
// file_put_contents等）+文件哈希基线+熵值检测
// ============================================================

// W3TamperScanner 网站挂马/篡改检测扫描器
type W3TamperScanner struct {
	base *WebSecurityGuard
}

func (s *W3TamperScanner) Name() string       { return "websecurity" }
func (s *W3TamperScanner) SubScanner() string { return "W3" }

// w3MalwarePatterns 恶意代码正则模式（模拟 YARA 规则）
var w3MalwarePatterns = []struct {
	pattern  *regexp.Regexp
	name     string
	severity types.Severity
}{
	{regexp.MustCompile(`eval\s*\(\s*base64_decode\s*\(`), "eval(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*gzinflate\s*\(`), "eval(gzinflate())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*gzuncompress\s*\(`), "eval(gzuncompress())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*str_rot13\s*\(`), "eval(str_rot13())", types.SeverityCritical},
	{regexp.MustCompile(`assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[`), "assert($_POST/GET)", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[`), "eval($_POST/GET)", types.SeverityCritical},
	{regexp.MustCompile(`system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "system($_POST/GET)", types.SeverityCritical},
	{regexp.MustCompile(`exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "exec($_POST/GET)", types.SeverityCritical},
	{regexp.MustCompile(`passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "passthru($_POST/GET)", types.SeverityCritical},
	{regexp.MustCompile(`shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "shell_exec($_POST/GET)", types.SeverityCritical},
	{regexp.MustCompile(`preg_replace\s*\(\s*["'].*\/e["']`), "preg_replace /e 修饰符", types.SeverityCritical},
	{regexp.MustCompile(`create_function\s*\(`), "create_function()", types.SeverityHigh},
	{regexp.MustCompile(`file_put_contents\s*\(\s*["'].*\.(php|phtml|jsp|asp|aspx)`), "file_put_contents写Webshell", types.SeverityCritical},
	{regexp.MustCompile(`\bbase64_decode\s*\(\s*["'][A-Za-z0-9+/=]{100,}`), "长base64解码", types.SeverityHigh},
	{regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "十六进制混淆", types.SeverityMedium},
	{regexp.MustCompile(`<script[^>]*src\s*=\s*["']https?://[^"']+["']`), "外部JS引用", types.SeverityLow},
	{regexp.MustCompile(`<iframe[^>]*style\s*=\s*["'].*display\s*:\s*none`), "隐藏iframe", types.SeverityHigh},
	{regexp.MustCompile(`document\.write\s*\(\s*unescape\s*\(`), "document.write(unescape())", types.SeverityHigh},
	{regexp.MustCompile(`String\.fromCharCode\s*\(\s*\d+\s*,`), "String.fromCharCode混淆", types.SeverityMedium},
	{regexp.MustCompile(`\bchmod\s*\(\s*["'].*\.(php|phtml|sh)`), "chmod修改脚本权限", types.SeverityMedium},
	{regexp.MustCompile(`move_uploaded_file\s*\(\s*\$.*\.\s*["'].*\.(php|phtml)`), "move_uploaded_file上传PHP", types.SeverityCritical},
	// 新增更高级的 Webshell 检测模式
	{regexp.MustCompile(`@?eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)`), "eval直接执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`@?assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)`), "assert直接执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`call_user_func\s*\(\s*\$_(POST|GET|REQUEST)`), "call_user_func执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`call_user_func_array\s*\(\s*\$_(POST|GET|REQUEST)`), "call_user_func_array执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`popen\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "popen执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`proc_open\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "proc_open执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`pcntl_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`), "pcntl_exec执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "长十六进制混淆", types.SeverityHigh},
	{regexp.MustCompile(`eval\s*\(\s*gzdecode\s*\(`), "eval(gzdecode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*strrev\s*\(`), "eval(strrev())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*convert_uudecode\s*\(`), "eval(convert_uudecode())", types.SeverityCritical},
	{regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "短十六进制混淆", types.SeverityMedium},
	{regexp.MustCompile(`eval\s*\(\s*pack\s*\(`), "eval(pack())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*chr\s*\(`), "eval(chr())", types.SeverityCritical},
	{regexp.MustCompile(`\\x\\x[0-9a-fA-F]{2}`), "双转义十六进制混淆", types.SeverityMedium},
	{regexp.MustCompile(`eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET|REQUEST)`), "eval(base64_decode($_POST))", types.SeverityCritical},
	{regexp.MustCompile(`file_put_contents\s*\(\s*\$_(POST|GET|REQUEST)`), "file_put_contents写用户输入", types.SeverityCritical},
	{regexp.MustCompile(`fwrite\s*\(\s*\$.*\$_(POST|GET|REQUEST)`), "fwrite写用户输入", types.SeverityCritical},
	{regexp.MustCompile(`@?system\s*\(\s*base64_decode\s*\(`), "system(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`@?exec\s*\(\s*base64_decode\s*\(`), "exec(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`@?passthru\s*\(\s*base64_decode\s*\(`), "passthru(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`@?shell_exec\s*\(\s*base64_decode\s*\(`), "shell_exec(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}`), "Unicode转义混淆", types.SeverityMedium},
	{regexp.MustCompile(`eval\s*\(\s*urldecode\s*\(`), "eval(urldecode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*rawurldecode\s*\(`), "eval(rawurldecode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*substr\s*\(`), "eval(substr())", types.SeverityCritical},
	// ===== 新增：更高级 Webshell 检测模式 =====
	// 变量函数调用型 Webshell：$a($b) 其中 $a 来自用户输入
	{regexp.MustCompile(`\$\w+\s*\(\s*\$\w+\s*\)`), "变量函数调用型Webshell", types.SeverityHigh},
	// PHP $_FILES 上传后直接执行
	{regexp.MustCompile(`move_uploaded_file\s*\(.*\$_FILES`), "上传文件执行", types.SeverityCritical},
	// preg_replace /e 修饰符的更多变体
	{regexp.MustCompile(`preg_replace\s*\(\s*["'][^"']*["']\s*,\s*\\e`), "preg_replace /e变体", types.SeverityCritical},
	// PHP assert 变体
	{regexp.MustCompile(`\bassert\s*\(\s*base64_decode\s*\(`), "assert(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`\bassert\s*\(\s*gzinflate\s*\(`), "assert(gzinflate())", types.SeverityCritical},
	{regexp.MustCompile(`\bassert\s*\(\s*gzuncompress\s*\(`), "assert(gzuncompress())", types.SeverityCritical},
	// call_user_func 混淆执行
	{regexp.MustCompile(`call_user_func\s*\(\s*base64_decode\s*\(`), "call_user_func(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`call_user_func_array\s*\(\s*base64_decode\s*\(`), "call_user_func_array(base64_decode())", types.SeverityCritical},
	// array_map/filter/walk 执行用户输入
	{regexp.MustCompile(`array_map\s*\(\s*\$_(POST|GET|REQUEST)`), "array_map执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`array_filter\s*\(\s*\$_(POST|GET|REQUEST)`), "array_filter执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`array_walk\s*\(\s*\$_(POST|GET|REQUEST)`), "array_walk执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`usort\s*\(.*\$_(POST|GET|REQUEST)`), "usort执行用户输入", types.SeverityCritical},
	{regexp.MustCompile(`array_map\s*\(\s*base64_decode\s*\(`), "array_map(base64_decode())", types.SeverityCritical},
	// 反射型 Webshell
	{regexp.MustCompile(`ReflectionFunction\s*\(\s*\$_(POST|GET|REQUEST)`), "反射执行用户输入", types.SeverityCritical},
	// PHP 7+ dynamic function call
	{regexp.MustCompile(`\(\$_(POST|GET|REQUEST|COOKIE)\[\w+\]\)\s*\(`), "动态函数调用Webshell", types.SeverityCritical},
	// 可疑的 PHP 短标签执行
	{regexp.MustCompile(`<\?\=\s*\$_(POST|GET|REQUEST)`), "PHP短标签执行用户输入", types.SeverityCritical},
	// Google/Baidu SEO 挂马特征：隐藏链接
	{regexp.MustCompile(`<div[^>]*style\s*=\s*["'][^"']*position\s*:\s*absolute[^"']*left\s*:\s*-9999`), "SEO挂马隐藏层", types.SeverityHigh},
	{regexp.MustCompile(`<span[^>]*style\s*=\s*["'][^"']*display\s*:\s*none[^"']*>\s*<a\s+href`), "隐藏链接挂马", types.SeverityHigh},
	// 挖矿脚本检测
	{regexp.MustCompile(`coinhive|coin-hive|cryptonight|crypto-loot|webminerpool|jsecoin|coinerra`), "挖矿脚本注入", types.SeverityCritical},
	{regexp.MustCompile(`var\s+\w+\s*=\s*new\s+CoinHive`), "CoinHive挖矿对象", types.SeverityCritical},
	{regexp.MustCompile(`navigator\.hardwareConcurrency.*\bwhile\s*\(\s*true\s*\)`), "CPU挖矿循环", types.SeverityHigh},
	// JS 混淆+eval 组合
	{regexp.MustCompile(`eval\s*\(\s*function\s*\(`), "eval(function())混淆", types.SeverityHigh},
	{regexp.MustCompile(`eval\s*\(\s*atob\s*\(`), "eval(atob())Base64执行", types.SeverityHigh},
	// PHP 特征函数组合（Webshell 常用）
	{regexp.MustCompile(`\barray_map\s*\(.*\bassert\b`), "array_map+assert组合", types.SeverityCritical},
	{regexp.MustCompile(`\barray_filter\s*\(.*\bassert\b`), "array_filter+assert组合", types.SeverityCritical},
	{regexp.MustCompile(`\barray_walk\s*\(.*\bassert\b`), "array_walk+assert组合", types.SeverityCritical},
	// Webshell 常见特征字符串
	{regexp.MustCompile(`(?i)GodMode|b374k|c99|r57|wso|shellphp|IndoXploit|b374k\s*m1n1`), "已知Webshell特征", types.SeverityCritical},
	{regexp.MustCompile(`(?i)phpspy|phplist|phpjackal|NCC-Group|RootShell|NST`), "已知Webshell名称", types.SeverityCritical},
	// 可疑的 PHP 变量拼接执行
	{regexp.MustCompile(`\$\w+\s*\=\s*\$_(POST|GET|REQUEST)\[`), "用户输入赋值变量", types.SeverityMedium},
	// Content-Disposition 注入检测
	{regexp.MustCompile(`Content-Disposition\s*:.*\r?\n\s*\r?\n`), "Header注入检测", types.SeverityHigh},
	// PHP 混淆变量名（常见于 Webshell）
	{regexp.MustCompile(`\$[a-z0-9_]{40,}`), "超长变量名混淆", types.SeverityMedium},
	// 可疑的 null byte 注入
	{regexp.MustCompile(`%00|\\x00|\\0`), "Null Byte注入", types.SeverityHigh},
	// 恶意 iframe 注入（更多变体）
	{regexp.MustCompile(`<iframe[^>]*width\s*=\s*["']?0["']?[^>]*height\s*=\s*["']?0["']?`), "零尺寸iframe挂马", types.SeverityHigh},
	{regexp.MustCompile(`<iframe[^>]*src\s*=\s*["']javascript:`), "JavaScript协议iframe", types.SeverityCritical},
	// document.write 写入外部脚本
	{regexp.MustCompile(`document\.write\s*\(\s*['"]<script[^>]*src\s*=`), "document.write注入外部脚本", types.SeverityHigh},
	//可疑的 setTimeout/setInterval 执行外部代码
	{regexp.MustCompile(`setTimeout\s*\(\s*['"]?\w+\(\)\s*\{.*eval\s*\(`), "setTimeout+eval混淆", types.SeverityHigh},
	// Base64 编码的 PHP 标签
	{regexp.MustCompile(`(?i)PD9waA|PD8g|PD9waHAg|<?php.*eval`), "Base64编码PHP标签", types.SeverityHigh},
	// 可疑的 str_replace 混淆
	{regexp.MustCompile(`str_replace\s*\(\s*["'][^"']{50,}`), "str_replace长字符串混淆", types.SeverityMedium},
	// PHP goto 混淆（PHP Webshell 新型混淆）
	{regexp.MustCompile(`goto\s+\w+\s*;.*goto\s+\w+\s*;`), "goto混淆控制流", types.SeverityHigh},
}

// w3CDNWhitelist 常见 CDN 域名，外部 JS 引用指向这些域名时不报告
var w3CDNWhitelist = []string{
	"cdn.", "googleapis.com", "jsdelivr.net", "unpkg.com",
	"cdnjs.cloudflare.com", "ajax.googleapis.com", "stackpath.",
	"bootcdn.net", "cdn.bootcss.com", "cdn.staticfile.org",
	"lib.sinaapp.com", "upcdn.b0.upaiyun.com", "cdn.bytedance.com",
	"lf3-cdn-tos.bytecdntp.com", "lf6-cdn-tos.bytecdntp.com",
}

// isCDNURL 检查 URL 是否指向已知 CDN
func isCDNURL(url string) bool {
	lower := strings.ToLower(url)
	for _, cdn := range w3CDNWhitelist {
		if strings.Contains(lower, cdn) {
			return true
		}
	}
	return false
}

// w3WebShellExtensions 需要检测的 Web 脚本文件扩展名
var w3WebShellExtensions = []string{".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".html", ".htm", ".js", ".ts"}

// w3HighEntropyThreshold 高熵值阈值（大于此值可能为加密/混淆内容）
// 提高到 7.0 以减少 minified JS 的误报（正常 minified JS 熵值约 5.5-6.5）
const w3HighEntropyThreshold = 7.0

// w3MinFileSizeEntropy 熵值检测的最小文件大小（太小文件熵值不准确）
const w3MinFileSizeEntropy = 2048

// Scan 执行 W3 网站挂马/篡改检测
func (s *W3TamperScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	if target.Path == "" {
		findings := rb.GetFindings()
		setSubScanner(findings, "W3")
		return findings, nil
	}

	// 1. 恶意代码模式检测 + 熵值检测
	s.detectMalwarePatterns(rb, target.Path)

	// 2. 文件哈希基线检测（篡改检测）
	s.detectTampering(rb, target.Path)

	findings := rb.GetFindings()
	setSubScanner(findings, "W3")
	return findings, nil
}

// detectMalwarePatterns 检测恶意代码模式和高熵值内容
func (s *W3TamperScanner) detectMalwarePatterns(rb *scannercommon.ReportBuilder, root string) {
	// 使用 walkFilesForMalware：不跳过 vendor/wp-includes/wp-admin 等目录
	// 因为攻击者经常在这些目录植入 Webshell
	s.base.walkFilesForMalware(root, func(path string, info os.FileInfo) error {
		ext := strings.ToLower(filepath.Ext(path))
		isWebScript := false
		for _, e := range w3WebShellExtensions {
			if ext == e {
				isWebScript = true
				break
			}
		}
		if !isWebScript {
			return nil
		}

		// 跳过 minified JS/CSS 文件（文件名包含 .min.）
		baseName := strings.ToLower(filepath.Base(path))
		if strings.Contains(baseName, ".min.") || strings.Contains(baseName, ".pack.") {
			return nil
		}

		// 跳过大于 1MB 的文件（Webshell 通常很小，大文件通常是正常业务代码）
		if info.Size() > 1024*1024 {
			return nil
		}

		data, err := s.base.readFileLimited(path)
		if err != nil {
			return nil
		}
		if len(data) == 0 {
			return nil
		}

		// 检测恶意代码模式
		for _, mp := range w3MalwarePatterns {
			if mp.pattern.Match(data) {
				// 外部JS引用模式需要排除 CDN
				if mp.name == "外部JS引用" {
					// 提取匹配到的 URL，检查是否为 CDN
					matches := mp.pattern.FindStringSubmatch(string(data))
					if len(matches) > 0 {
						// 从整个匹配中提取 URL
						urlMatch := regexp.MustCompile(`https?://[^"'\s]+`).FindString(matches[0])
						if urlMatch != "" && isCDNURL(urlMatch) {
							continue // 跳过 CDN 引用
						}
					}
				}
				rb.AddFinding(
					mp.severity,
					fmt.Sprintf("检测到恶意代码模式: %s", mp.name),
					fmt.Sprintf("文件 %s 包含可疑代码模式: %s，疑似 Webshell 或挂马", path, mp.name),
					path,
					fmt.Sprintf("文件: %s，匹配模式: %s", path, mp.name),
					"隔离或删除该文件，检查最近修改记录，排查入侵途径",
					"删除文件后相关功能将不可用；隔离后可在面板查看并恢复",
				)
				break // 每个文件只报告一次恶意模式
			}
		}

		// YARA 引擎扫描（与正则 + 熵值检测并存）
		if s.base.yaraEngine != nil && s.base.yaraEngine.IsAvailable() {
			matches := s.base.yaraEngine.ScanData(data)
			for _, m := range matches {
				rb.AddFinding(
					types.SeverityHigh,
					fmt.Sprintf("YARA 规则匹配: %s", m.Rule),
					fmt.Sprintf("文件 %s 匹配 YARA 规则 %s（偏移 %d，长度 %d），疑似 Webshell", path, m.Rule, m.Offset, m.Length),
					path,
					fmt.Sprintf("文件: %s，规则: %s，偏移: %d，长度: %d", path, m.Rule, m.Offset, m.Length),
					"隔离或删除该文件，检查最近修改记录，排查入侵途径",
					"删除文件后相关功能将不可用；隔离后可在面板查看并恢复",
				)
			}
		}

		// 熵值检测：高熵值可能表示加密/混淆内容
		// 只检测 PHP/JSP/ASP 等服务端脚本，不检测 JS/HTML（minified JS 误报太多）
		isServerScript := ext == ".php" || ext == ".phtml" || ext == ".php3" ||
			ext == ".php4" || ext == ".php5" || ext == ".phps" ||
			ext == ".jsp" || ext == ".jspx" || ext == ".asp" || ext == ".aspx" || ext == ".ashx"

		if isServerScript && len(data) > w3MinFileSizeEntropy {
			entropy := shannonEntropy(data)
			if entropy > w3HighEntropyThreshold {
				rb.AddFinding(
					types.SeverityMedium,
					fmt.Sprintf("文件内容熵值异常: %s", filepath.Base(path)),
					fmt.Sprintf("文件 %s 的香农熵值为 %.2f（阈值 %.1f），可能包含加密或混淆内容", path, entropy, w3HighEntropyThreshold),
					path,
					fmt.Sprintf("文件: %s，熵值: %.2f，文件大小: %d 字节", path, entropy, len(data)),
					"人工审查该文件内容，确认是否为合法的加密/压缩内容",
					"审查期间可先隔离该文件；确认无害后可恢复",
				)
			}
		}

		return nil
	})
}

// detectTampering 通过文件哈希基线检测篡改
func (s *W3TamperScanner) detectTampering(rb *scannercommon.ReportBuilder, root string) {
	// 使用 walkFilesForMalware：检测 vendor/wp-includes 等目录中的文件篡改
	s.base.walkFilesForMalware(root, func(path string, info os.FileInfo) error {
		ext := strings.ToLower(filepath.Ext(path))
		isWebScript := false
		for _, e := range w3WebShellExtensions {
			if ext == e {
				isWebScript = true
				break
			}
		}
		if !isWebScript {
			return nil
		}

		data, err := s.base.readFileLimited(path)
		if err != nil {
			return nil
		}
		currentHash := sha256Hash(data)

		// 如果有基线，检测是否被篡改
		if expectedHash, ok := s.base.GetBaseline(path); ok {
			if currentHash != expectedHash {
				rb.AddFinding(
					types.SeverityHigh,
					fmt.Sprintf("文件被篡改: %s", filepath.Base(path)),
					fmt.Sprintf("文件 %s 的哈希值与基线不一致，可能被篡改", path),
					path,
					fmt.Sprintf("文件: %s，基线哈希: %s，当前哈希: %s", path, expectedHash[:16], currentHash[:16]),
					"对比文件修改记录，确认是否为合法更新；如非合法修改，从备份恢复",
					"恢复到基线版本会丢失最近的合法修改；请先确认修改来源",
				)
			}
		}
		return nil
	})
}

// ============================================================
// W4: 后台安全检测
// 检测 /admin/、/manage/、/wp-admin/ 等后台路径暴露、
// 无验证码、弱口令
// ============================================================

// W4AdminScanner 后台安全检测扫描器
type W4AdminScanner struct {
	base *WebSecurityGuard
}

func (s *W4AdminScanner) Name() string       { return "websecurity" }
func (s *W4AdminScanner) SubScanner() string { return "W4" }

// w4AdminPaths 常见后台路径
var w4AdminPaths = []string{
	"/admin/", "/admin/login", "/admin/login.php", "/admin/index.php",
	"/manage/", "/management/", "/manager/", "/manager/html",
	"/wp-admin/", "/wp-admin/login.php", "/wp-login.php",
	"/administrator/", "/administrator/index.php",
	"/admin.php", "/login.php", "/login.html", "/login/",
	"/backend/", "/backend/login", "/dashboard/", "/console/",
	"/panel/", "/cp/", "/controlpanel/", "/cpanel/",
	"/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/mysql/",
	"/admin/login.aspx", "/Account/Login", "/umbraco/",
	"/user/login", "/member/login", "/system/login",
}

// w4WeakPasswords 常见弱口令
var w4WeakPasswords = []string{
	"admin", "password", "123456", "admin123", "root", "test",
	"12345678", "abc123", "111111", "admin@123", "qwerty",
	"password123", "1234567890", "admin888", "admin666",
}

// w4CommonAdminUsers 常见管理员用户名
var w4CommonAdminUsers = []string{
	"admin", "administrator", "root", "test", "user", "guest",
}

// Scan 执行 W4 后台安全检测
func (s *W4AdminScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	baseURL := s.base.targetURL(target)
	if baseURL == "" {
		findings := rb.GetFindings()
		setSubScanner(findings, "W4")
		return findings, nil
	}

	// 1. 检测后台路径暴露
	s.detectAdminPaths(ctx, rb, baseURL)

	// 2. 检测登录页面是否有验证码
	s.detectMissingCaptcha(ctx, rb, baseURL)

	// 3. 检测弱口令（仅检测常见后台路径）
	s.detectWeakPassword(ctx, rb, baseURL)

	findings := rb.GetFindings()
	setSubScanner(findings, "W4")
	return findings, nil
}

// detectAdminPaths 检测后台路径暴露
func (s *W4AdminScanner) detectAdminPaths(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	for _, path := range w4AdminPaths {
		url := strings.TrimRight(baseURL, "/") + path
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		// 200 或 301/302 表示后台路径存在
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			bodyStr := string(body)
			// 检查是否为登录页面
			isLoginPage := strings.Contains(strings.ToLower(bodyStr), "login") ||
				strings.Contains(strings.ToLower(bodyStr), "密码") ||
				strings.Contains(strings.ToLower(bodyStr), "password") ||
				strings.Contains(strings.ToLower(bodyStr), "登录")

			severity := types.SeverityMedium
			desc := fmt.Sprintf("后台路径 %s 可访问", path)
			if isLoginPage {
				severity = types.SeverityHigh
				desc = fmt.Sprintf("后台登录页面 %s 暴露，可被攻击者尝试暴力破解", path)
			}

			rb.AddFinding(
				severity,
				fmt.Sprintf("后台路径暴露: %s", path),
				desc,
				url,
				fmt.Sprintf("URL: %s，HTTP状态: %d", url, resp.StatusCode),
				"限制后台访问IP白名单，修改默认后台路径，增加验证码和登录失败锁定",
				"修改后台路径后需更新书签和运维流程；IP白名单可能影响远程管理",
			)
		}
	}
}

// detectMissingCaptcha 检测登录页面是否缺少验证码
func (s *W4AdminScanner) detectMissingCaptcha(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	loginPaths := []string{"/admin/login", "/admin/login.php", "/wp-login.php", "/login.php", "/login.html", "/login/"}
	for _, path := range loginPaths {
		url := strings.TrimRight(baseURL, "/") + path
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}
		bodyStr := strings.ToLower(string(body))
		// 检查是否为登录页面
		if !strings.Contains(bodyStr, "login") && !strings.Contains(bodyStr, "登录") && !strings.Contains(bodyStr, "password") {
			continue
		}
		// 检查是否有验证码
		hasCaptcha := strings.Contains(bodyStr, "captcha") ||
			strings.Contains(bodyStr, "verifycode") ||
			strings.Contains(bodyStr, "vcode") ||
			strings.Contains(bodyStr, "验证码") ||
			strings.Contains(bodyStr, "geetest") ||
			strings.Contains(bodyStr, "recaptcha")

		if !hasCaptcha {
			rb.AddFinding(
				types.SeverityMedium,
				fmt.Sprintf("登录页面缺少验证码: %s", path),
				fmt.Sprintf("登录页面 %s 未检测到验证码，容易遭受暴力破解", path),
				url,
				fmt.Sprintf("URL: %s，页面内容未包含验证码相关字段", url),
				"为登录页面增加验证码（图形验证码或滑动验证码）",
				"增加验证码可能影响用户体验；建议使用无感验证码",
			)
		}
	}
}

// detectWeakPassword 检测弱口令（仅尝试少量常见组合，避免被当作攻击）
func (s *W4AdminScanner) detectWeakPassword(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	// 仅检测 phpMyAdmin 等高危后台的弱口令
	testPaths := []string{"/phpmyadmin/", "/phpMyAdmin/", "/pma/"}
	for _, path := range testPaths {
		url := strings.TrimRight(baseURL, "/") + path
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		// 检测到后台存在，报告弱口令风险（不实际尝试登录）
		rb.AddFinding(
			types.SeverityHigh,
			fmt.Sprintf("数据库管理后台暴露: %s", path),
			fmt.Sprintf("数据库管理后台 %s 暴露，如使用弱口令（如 admin/123456）将导致数据库被入侵", path),
			url,
			fmt.Sprintf("URL: %s 可访问，常见弱口令: admin/123456, root/root, admin/password", url),
			"设置强密码（至少12位，包含大小写字母、数字、特殊字符），限制访问IP",
			"修改密码后需更新所有使用该后台的客户端配置",
		)
	}
}

// ============================================================
// W5: 数据库安全检测
// 检测 phpMyAdmin未授权、MySQL root空密码、Redis无密码、
// MongoDB无认证、数据库端口暴露
// ============================================================

// W5DatabaseScanner 数据库安全检测扫描器
type W5DatabaseScanner struct {
	base *WebSecurityGuard
}

func (s *W5DatabaseScanner) Name() string       { return "websecurity" }
func (s *W5DatabaseScanner) SubScanner() string { return "W5" }

// w5DBPorts 数据库默认端口
var w5DBPorts = []struct {
	port    int
	name    string
	service string
}{
	{3306, "MySQL", "mysql"},
	{5432, "PostgreSQL", "postgresql"},
	{27017, "MongoDB", "mongodb"},
	{6379, "Redis", "redis"},
	{1433, "SQL Server", "mssql"},
	{1521, "Oracle", "oracle"},
	{9200, "Elasticsearch", "elasticsearch"},
	{11211, "Memcached", "memcached"},
	{9042, "Cassandra", "cassandra"},
	{8529, "TiDB", "tidb"},
}

// Scan 执行 W5 数据库安全检测
func (s *W5DatabaseScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	host := target.Host
	if host == "" {
		host = "127.0.0.1"
	}

	// 1. 检测数据库端口暴露
	s.detectDBPortExposure(ctx, rb, host)

	// 2. 检测 Redis 无密码
	s.detectRedisNoPassword(ctx, rb, host)

	// 3. 检测 MongoDB 无认证
	s.detectMongoNoAuth(ctx, rb, host)

	// 4. 检测 MySQL root 空密码
	s.detectMySQLEmptyPassword(ctx, rb, host)

	// 5. 检测 phpMyAdmin 未授权访问
	baseURL := s.base.targetURL(target)
	if baseURL != "" {
		s.detectPhpMyAdminUnauth(ctx, rb, baseURL)
	}

	// 6. 检测 Elasticsearch 未授权
	s.detectESUnauth(ctx, rb, host)

	findings := rb.GetFindings()
	setSubScanner(findings, "W5")
	return findings, nil
}

// detectDBPortExposure 检测数据库端口是否暴露
func (s *W5DatabaseScanner) detectDBPortExposure(ctx context.Context, rb *scannercommon.ReportBuilder, host string) {
	for _, db := range w5DBPorts {
		// 去重：同一 host:port 只报告一次（116个站点指向同一个 localhost）
		dedupKey := fmt.Sprintf("%s:%d", host, db.port)
		s.base.w5DedupMu.Lock()
		if s.base.w5Scanned[dedupKey] {
			s.base.w5DedupMu.Unlock()
			continue
		}
		s.base.w5Scanned[dedupKey] = true
		s.base.w5DedupMu.Unlock()

		addr := fmt.Sprintf("%s:%d", host, db.port)
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		conn.Close()
		// 只报告外部可访问的端口（非 127.0.0.1 的才值得告警）
		severity := types.SeverityMedium
		if host != "127.0.0.1" && host != "localhost" {
			severity = types.SeverityHigh
		} else {
			// localhost 的数据库端口只是信息记录，不重复报告
			continue
		}
		rb.AddFinding(
			severity,
			fmt.Sprintf("数据库端口暴露: %s (%d)", db.name, db.port),
			fmt.Sprintf("%s 服务端口 %d 对外暴露，可被外部访问", db.name, db.port),
			addr,
			fmt.Sprintf("地址: %s，端口: %d，服务: %s", addr, db.port, db.name),
			"配置防火墙规则仅允许内网访问该端口，绑定到 127.0.0.1 而非 0.0.0.0",
			"修改绑定地址后外部应用将无法连接；需同步更新应用配置",
		)
	}
}

// detectRedisNoPassword 检测 Redis 无密码
func (s *W5DatabaseScanner) detectRedisNoPassword(ctx context.Context, rb *scannercommon.ReportBuilder, host string) {
	// 去重：同一 host 只检测一次
	dedupKey := fmt.Sprintf("%s:redis:nopass", host)
	s.base.w5DedupMu.Lock()
	if s.base.w5Scanned[dedupKey] {
		s.base.w5DedupMu.Unlock()
		return
	}
	s.base.w5Scanned[dedupKey] = true
	s.base.w5DedupMu.Unlock()

	addr := fmt.Sprintf("%s:6379", host)
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	// 发送 INFO 命令
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("INFO\r\n"))
	if err != nil {
		return
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	response := string(buf[:n])
	// 如果直接返回信息（没有要求认证），说明无密码
	if strings.HasPrefix(response, "$") || strings.Contains(response, "redis_version") {
		rb.AddFinding(
			types.SeverityCritical,
			"Redis 无密码保护",
			"Redis 服务未配置密码，攻击者可直接连接并读写数据，甚至利用 Redis 写 SSH 公钥实现入侵",
			addr,
			fmt.Sprintf("地址: %s，发送 INFO 命令后直接返回数据，未要求认证", addr),
			"在 redis.conf 中设置 requirepass，并重启 Redis 服务",
			"设置密码后所有 Redis 客户端需更新连接配置",
		)
	}
}

// detectMongoNoAuth 检测 MongoDB 无认证
func (s *W5DatabaseScanner) detectMongoNoAuth(ctx context.Context, rb *scannercommon.ReportBuilder, host string) {
	// 去重：同一 host 只检测一次
	dedupKey := fmt.Sprintf("%s:mongo:noauth", host)
	s.base.w5DedupMu.Lock()
	if s.base.w5Scanned[dedupKey] {
		s.base.w5DedupMu.Unlock()
		return
	}
	s.base.w5Scanned[dedupKey] = true
	s.base.w5DedupMu.Unlock()

	addr := fmt.Sprintf("%s:27017", host)
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	// MongoDB 无认证时可直接连接
	rb.AddFinding(
		types.SeverityCritical,
		"MongoDB 可能无认证",
		"MongoDB 端口可连接，如未启用 --auth 参数，攻击者可直接读写数据库",
		addr,
		fmt.Sprintf("地址: %s 端口可连接", addr),
		"在 MongoDB 配置中启用 authorization: enabled，创建管理员账户",
		"启用认证后所有 MongoDB 客户端需配置认证信息",
	)
}

// detectMySQLEmptyPassword 检测 MySQL root 空密码
func (s *W5DatabaseScanner) detectMySQLEmptyPassword(ctx context.Context, rb *scannercommon.ReportBuilder, host string) {
	// 去重：同一 host 只检测一次
	dedupKey := fmt.Sprintf("%s:mysql:emptypass", host)
	s.base.w5DedupMu.Lock()
	if s.base.w5Scanned[dedupKey] {
		s.base.w5DedupMu.Unlock()
		return
	}
	s.base.w5Scanned[dedupKey] = true
	s.base.w5DedupMu.Unlock()

	addr := fmt.Sprintf("%s:3306", host)
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	// 读取 MySQL 握手包
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	// MySQL 服务会先发送握手包
	if n > 4 && buf[4] == 0x0a { // 0x0a 是 MySQL 协议版本
		rb.AddFinding(
			types.SeverityHigh,
			"MySQL 服务可达",
			"MySQL 端口可连接，如 root 账户使用空密码或弱口令，将导致数据库被入侵",
			addr,
			fmt.Sprintf("地址: %s，MySQL 服务响应握手包", addr),
			"为 root 账户设置强密码，删除空密码账户，禁止 root 远程登录",
			"修改 root 密码后所有使用 root 的应用需更新连接配置",
		)
	}
}

// detectPhpMyAdminUnauth 检测 phpMyAdmin 未授权访问
func (s *W5DatabaseScanner) detectPhpMyAdminUnauth(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	pmaPaths := []string{"/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/mysql/", "/db/"}
	for _, path := range pmaPaths {
		url := strings.TrimRight(baseURL, "/") + path
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "phpmyadmin") || strings.Contains(bodyStr, "mysql") {
				// 检查是否可以直接访问（无需登录）
				if strings.Contains(bodyStr, "server_status") || strings.Contains(bodyStr, "navigation") {
					rb.AddFinding(
						types.SeverityCritical,
						"phpMyAdmin 未授权访问",
						fmt.Sprintf("phpMyAdmin 在 %s 可无需登录直接访问，攻击者可操作数据库", path),
						url,
						fmt.Sprintf("URL: %s 返回 200 且包含 phpMyAdmin 管理界面", url),
						"配置 phpMyAdmin 要求登录认证，限制访问 IP，或移除 phpMyAdmin",
						"移除 phpMyAdmin 后需使用命令行或其他工具管理数据库",
					)
				} else {
					rb.AddFinding(
						types.SeverityHigh,
						"phpMyAdmin 暴露",
						fmt.Sprintf("phpMyAdmin 在 %s 可访问，应限制访问", path),
						url,
						fmt.Sprintf("URL: %s 返回 200", url),
						"限制 phpMyAdmin 访问 IP 白名单，使用强密码",
						"限制 IP 后非白名单地址将无法访问",
					)
				}
			}
		}
	}
}

// detectESUnauth 检测 Elasticsearch 未授权访问
func (s *W5DatabaseScanner) detectESUnauth(ctx context.Context, rb *scannercommon.ReportBuilder, host string) {
	// 去重：同一 host 只检测一次
	dedupKey := fmt.Sprintf("%s:es:unauth", host)
	s.base.w5DedupMu.Lock()
	if s.base.w5Scanned[dedupKey] {
		s.base.w5DedupMu.Unlock()
		return
	}
	s.base.w5Scanned[dedupKey] = true
	s.base.w5DedupMu.Unlock()

	urls := []string{
		fmt.Sprintf("http://%s:9200/", host),
		fmt.Sprintf("http://%s:9200/_cat/indices", host),
	}
	for _, url := range urls {
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "cluster_name") || strings.Contains(bodyStr, "elasticsearch") {
				rb.AddFinding(
					types.SeverityCritical,
					"Elasticsearch 未授权访问",
					"Elasticsearch 可无需认证直接访问，攻击者可读取、修改或删除索引数据",
					url,
					fmt.Sprintf("URL: %s 返回 200，包含集群信息", url),
					"在 elasticsearch.yml 中配置 xpack.security.enabled: true，设置认证",
					"启用安全后所有 ES 客户端需配置认证信息",
				)
				break
			}
		}
	}
}

// ============================================================
// W6: 网站配置安全性检测
// 检测 server_tokens on、X-Frame-Options缺失、HSTS缺失、
// Access-Control-Allow-Origin: *、目录遍历、SSL弱协议
// ============================================================

// W6ConfigScanner 网站配置安全性检测扫描器
type W6ConfigScanner struct {
	base *WebSecurityGuard
}

func (s *W6ConfigScanner) Name() string       { return "websecurity" }
func (s *W6ConfigScanner) SubScanner() string { return "W6" }

// w6ConfigDirs Web 服务器配置文件目录
var w6ConfigDirs = []string{
	"/www/server/panel/vhost/nginx/",
	"/etc/nginx/conf.d/",
	"/etc/nginx/sites-enabled/",
	"/etc/nginx/",
	"/etc/apache2/sites-enabled/",
	"/etc/apache2/",
	"/etc/httpd/conf.d/",
	"/etc/httpd/conf/",
}

// Scan 执行 W6 网站配置安全性检测
func (s *W6ConfigScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	// 1. 检测配置文件安全性
	if target.Path != "" {
		s.scanConfigFile(rb, target.Path)
	}
	// 扫描常见配置目录
	for _, dir := range w6ConfigDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			s.scanConfigFile(rb, path)
		}
	}

	// 2. HTTP 响应头检测
	baseURL := s.base.targetURL(target)
	if baseURL != "" {
		s.checkHTTPHeaders(ctx, rb, baseURL)
		// 3. SSL 弱协议检测
		s.checkSSLProtocol(ctx, rb, baseURL)
		// 4. 目录遍历检测
		s.checkDirectoryListing(ctx, rb, baseURL)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W6")
	return findings, nil
}

// scanConfigFile 扫描单个配置文件
func (s *W6ConfigScanner) scanConfigFile(rb *scannercommon.ReportBuilder, path string) {
	// 去重：同一配置文件只扫描一次（多个站点会触发多次 W6 扫描）
	s.base.w6DedupMu.Lock()
	if s.base.w6ScannedFiles[path] {
		s.base.w6DedupMu.Unlock()
		return
	}
	s.base.w6ScannedFiles[path] = true
	s.base.w6DedupMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// 检测 server_tokens on
	if strings.Contains(content, "server_tokens") && strings.Contains(content, "on") &&
		!strings.Contains(content, "server_tokens off") {
		rb.AddFinding(
			types.SeverityLow,
			"server_tokens 未关闭",
			fmt.Sprintf("配置文件 %s 中 server_tokens 开启，会暴露 Nginx 版本号", path),
			path,
			fmt.Sprintf("文件: %s，包含 server_tokens on", path),
			"设置 server_tokens off; 隐藏服务器版本号",
			"隐藏版本号不影响功能；有助于减少信息泄露",
		)
	}

	// 检测 Access-Control-Allow-Origin: *
	if strings.Contains(content, "Access-Control-Allow-Origin *") ||
		strings.Contains(content, "Access-Control-Allow-Origin: *") {
		rb.AddFinding(
			types.SeverityMedium,
			"CORS 配置过于宽松",
			fmt.Sprintf("配置文件 %s 设置了 Access-Control-Allow-Origin: *，允许任意来源跨域访问", path),
			path,
			fmt.Sprintf("文件: %s，包含 Access-Control-Allow-Origin: *", path),
			"将 Access-Control-Allow-Origin 限制为特定可信域名",
			"修改 CORS 配置后部分跨域请求可能被拒绝；需确认合法来源",
		)
	}

	// 检测缺失的安全头
	missingHeaders := []string{}
	if !strings.Contains(content, "X-Frame-Options") {
		missingHeaders = append(missingHeaders, "X-Frame-Options")
	}
	if !strings.Contains(content, "X-Content-Type-Options") {
		missingHeaders = append(missingHeaders, "X-Content-Type-Options")
	}
	if !strings.Contains(content, "Strict-Transport-Security") {
		missingHeaders = append(missingHeaders, "Strict-Transport-Security (HSTS)")
	}
	if !strings.Contains(content, "X-XSS-Protection") {
		missingHeaders = append(missingHeaders, "X-XSS-Protection")
	}
	if !strings.Contains(content, "Content-Security-Policy") {
		missingHeaders = append(missingHeaders, "Content-Security-Policy")
	}

	if len(missingHeaders) > 0 {
		suggestion := "建议添加以下安全头:\n"
		suggestion += "  add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
		suggestion += "  add_header X-Content-Type-Options \"nosniff\" always;\n"
		suggestion += "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
		suggestion += "  add_header X-XSS-Protection \"1; mode=block\" always;\n"
		suggestion += "  add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';\" always;"

		rb.AddFinding(
			types.SeverityMedium,
			fmt.Sprintf("安全头缺失: %s", path),
			fmt.Sprintf("配置文件 %s 缺少安全头: %s", path, strings.Join(missingHeaders, ", ")),
			path,
			fmt.Sprintf("文件: %s，缺失: %s", path, strings.Join(missingHeaders, ", ")),
			suggestion,
			"添加安全头可能影响部分页面的嵌入和资源加载；需测试后生效",
		)
	}

	// 检测 SSL 弱协议
	if strings.Contains(content, "ssl_protocols") {
		if strings.Contains(content, "SSLv3") || strings.Contains(content, "TLSv1") {
			rb.AddFinding(
				types.SeverityHigh,
				"SSL 弱协议启用",
				fmt.Sprintf("配置文件 %s 启用了 SSLv3 或 TLSv1 等弱协议，存在安全漏洞", path),
				path,
				fmt.Sprintf("文件: %s，包含弱协议配置", path),
				"仅启用 TLSv1.2 和 TLSv1.3: ssl_protocols TLSv1.2 TLSv1.3;",
				"禁用弱协议后旧浏览器将无法访问；需确认用户群体支持",
			)
		}
	}

	// 检测弱加密套件
	if strings.Contains(content, "ssl_ciphers") {
		if strings.Contains(content, "RC4") || strings.Contains(content, "MD5") ||
			strings.Contains(content, "DES") || strings.Contains(content, "EXPORT") {
			rb.AddFinding(
				types.SeverityHigh,
				"弱加密套件启用",
				fmt.Sprintf("配置文件 %s 包含弱加密套件（RC4/DES/MD5/EXPORT）", path),
				path,
				fmt.Sprintf("文件: %s，包含弱加密套件", path),
				"使用强加密套件: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...';",
				"移除弱套件后部分旧客户端将无法连接",
			)
		}
	}

	// 检测 autoindex on（目录遍历）
	if strings.Contains(content, "autoindex on") {
		rb.AddFinding(
			types.SeverityMedium,
			"目录遍历开启",
			fmt.Sprintf("配置文件 %s 启用了 autoindex on，允许列出目录内容", path),
			path,
			fmt.Sprintf("文件: %s，包含 autoindex on", path),
			"移除 autoindex on 或设置为 autoindex off",
			"关闭目录遍历后用户需知道确切文件名才能访问",
		)
	}
}

// checkHTTPHeaders 检测 HTTP 响应头安全性
func (s *W6ConfigScanner) checkHTTPHeaders(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	resp, err := s.base.httpGet(ctx, baseURL)
	if err != nil {
		return
	}
	resp.Body.Close()

	headers := resp.Header

	// 检测 X-Frame-Options
	if headers.Get("X-Frame-Options") == "" {
		rb.AddFinding(
			types.SeverityLow,
			"X-Frame-Options 头缺失",
			"响应缺少 X-Frame-Options 头，页面可被 iframe 嵌套，存在点击劫持风险",
			baseURL,
			fmt.Sprintf("URL: %s 响应未包含 X-Frame-Options 头", baseURL),
			"添加响应头: X-Frame-Options: SAMEORIGIN",
			"添加后页面将无法被外部站点 iframe 嵌套",
		)
	}

	// 检测 HSTS
	if headers.Get("Strict-Transport-Security") == "" && strings.HasPrefix(baseURL, "https://") {
		rb.AddFinding(
			types.SeverityMedium,
			"HSTS 头缺失",
			"HTTPS 站点缺少 Strict-Transport-Security 头，浏览器可能降级为 HTTP",
			baseURL,
			fmt.Sprintf("URL: %s 响应未包含 HSTS 头", baseURL),
			"添加响应头: Strict-Transport-Security: max-age=31536000; includeSubDomains",
			"启用 HSTS 后浏览器将强制使用 HTTPS；需确保所有子域名支持 HTTPS",
		)
	}

	// 检测 CORS
	acao := headers.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		rb.AddFinding(
			types.SeverityMedium,
			"Access-Control-Allow-Origin: *",
			"响应设置了 Access-Control-Allow-Origin: *，允许任意来源跨域访问",
			baseURL,
			fmt.Sprintf("URL: %s 响应包含 Access-Control-Allow-Origin: *", baseURL),
			"将 CORS 限制为特定可信域名",
			"修改 CORS 后部分跨域请求可能被拒绝",
		)
	}

	// 检测 X-Content-Type-Options
	if headers.Get("X-Content-Type-Options") == "" {
		rb.AddFinding(
			types.SeverityLow,
			"X-Content-Type-Options 头缺失",
			"响应缺少 X-Content-Type-Options: nosniff 头，浏览器可能进行 MIME 类型嗅探",
			baseURL,
			fmt.Sprintf("URL: %s 响应未包含 X-Content-Type-Options 头", baseURL),
			"添加响应头: X-Content-Type-Options: nosniff",
			"添加后浏览器将严格按声明的 Content-Type 处理内容",
		)
	}

	// 检测 Server 头暴露版本
	server := headers.Get("Server")
	if server != "" {
		if strings.Contains(server, "/") || regexp.MustCompile(`\d+\.\d+`).MatchString(server) {
			rb.AddFinding(
				types.SeverityLow,
				"服务器版本信息暴露",
				fmt.Sprintf("Server 头暴露了服务器版本: %s", server),
				baseURL,
				fmt.Sprintf("URL: %s，Server: %s", baseURL, server),
				"配置 server_tokens off 隐藏版本号",
				"隐藏版本号不影响功能",
			)
		}
	}
}

// checkSSLProtocol 检测 SSL 弱协议
func (s *W6ConfigScanner) checkSSLProtocol(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	if !strings.HasPrefix(baseURL, "https://") {
		return
	}

	// 尝试用弱协议连接
	weakVersions := []uint16{
		tls.VersionSSL30,
		tls.VersionTLS10,
		tls.VersionTLS11,
	}
	versionNames := map[uint16]string{
		tls.VersionSSL30: "SSLv3",
		tls.VersionTLS10: "TLSv1.0",
		tls.VersionTLS11: "TLSv1.1",
	}

	for _, ver := range weakVersions {
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:         ver,
					MaxVersion:         ver,
					InsecureSkipVerify: true,
				},
			},
		}
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue // 弱协议连接失败是好事
		}
		resp.Body.Close()
		rb.AddFinding(
			types.SeverityHigh,
			fmt.Sprintf("SSL 弱协议可用: %s", versionNames[ver]),
			fmt.Sprintf("服务器支持 %s 弱协议，存在已知安全漏洞（如 POODLE、BEAST）", versionNames[ver]),
			baseURL,
			fmt.Sprintf("URL: %s 支持 %s 协议", baseURL, versionNames[ver]),
			"在服务器配置中禁用弱协议，仅保留 TLSv1.2 和 TLSv1.3",
			"禁用弱协议后旧浏览器/客户端将无法连接",
		)
	}
}

// checkDirectoryListing 检测目录遍历
func (s *W6ConfigScanner) checkDirectoryListing(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	testPaths := []string{"/", "/static/", "/uploads/", "/images/", "/files/", "/data/"}
	for _, path := range testPaths {
		url := strings.TrimRight(baseURL, "/") + path
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyStr := string(body)
			// 检测目录列表特征
			if strings.Contains(bodyStr, "Index of /") ||
				strings.Contains(bodyStr, "Directory listing") ||
				(strings.Contains(bodyStr, "<title>Index of") && strings.Contains(bodyStr, "Last modified")) {
				rb.AddFinding(
					types.SeverityMedium,
					fmt.Sprintf("目录遍历开启: %s", path),
					fmt.Sprintf("路径 %s 开启了目录遍历，攻击者可查看目录下所有文件", path),
					url,
					fmt.Sprintf("URL: %s 返回目录列表", url),
					"关闭目录遍历: autoindex off 或在 Web 配置中禁用",
					"关闭目录遍历后用户需知道确切文件名才能访问",
				)
			}
		}
	}
}

// ============================================================
// W7: 坏链扫描
// 检测 404链接、失效外链、混合内容
// ============================================================

// W7BrokenLinkScanner 坏链扫描器
type W7BrokenLinkScanner struct {
	base *WebSecurityGuard
}

func (s *W7BrokenLinkScanner) Name() string       { return "websecurity" }
func (s *W7BrokenLinkScanner) SubScanner() string { return "W7" }

// w7LinkRegex 链接提取正则
var w7LinkRegex = regexp.MustCompile(`(?:href|src)\s*=\s*["']([^"']+)["']`)

// w7MaxLinks 单页最多检测的链接数
const w7MaxLinks = 100

// Scan 执行 W7 坏链扫描
func (s *W7BrokenLinkScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	baseURL := s.base.targetURL(target)
	if baseURL == "" && target.Path == "" {
		findings := rb.GetFindings()
		setSubScanner(findings, "W7")
		return findings, nil
	}

	// 从文件系统扫描 HTML 文件提取链接
	if target.Path != "" {
		s.scanFilesForBrokenLinks(ctx, rb, target.Path, baseURL)
	}

	// 从 HTTP 首页扫描链接
	if baseURL != "" {
		s.scanPageForBrokenLinks(ctx, rb, baseURL, baseURL)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W7")
	return findings, nil
}

// scanPageForBrokenLinks 扫描页面中的链接
func (s *W7BrokenLinkScanner) scanPageForBrokenLinks(ctx context.Context, rb *scannercommon.ReportBuilder, pageURL, baseURL string) {
	resp, err := s.base.httpGet(ctx, pageURL)
	if err != nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	if err != nil {
		return
	}

	links := w7LinkRegex.FindAllStringSubmatch(string(body), w7MaxLinks)
	isHTTPS := strings.HasPrefix(baseURL, "https://")

	for _, link := range links {
		href := link[1]
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") ||
			strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "data:") {
			continue
		}

		// 构建完整 URL
		fullURL := href
		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
			if strings.HasPrefix(href, "/") {
				fullURL = strings.TrimRight(baseURL, "/") + href
			} else {
				fullURL = strings.TrimRight(baseURL, "/") + "/" + href
			}
		}

		// 检测混合内容（HTTPS 页面引用 HTTP 资源）
		if isHTTPS && strings.HasPrefix(fullURL, "http://") {
			rb.AddFinding(
				types.SeverityMedium,
				"混合内容",
				fmt.Sprintf("HTTPS 页面引用了 HTTP 资源: %s", fullURL),
				pageURL,
				fmt.Sprintf("页面: %s，混合内容: %s", pageURL, fullURL),
				"将 HTTP 资源改为 HTTPS 引用",
				"修改后需确保目标资源支持 HTTPS 访问",
			)
			continue
		}

		// 检测外链是否失效
		if strings.HasPrefix(fullURL, "http://") || strings.HasPrefix(fullURL, "https://") {
			s.checkLink(ctx, rb, fullURL, pageURL)
		}
	}
}

// checkLink 检测单个链接是否有效
func (s *W7BrokenLinkScanner) checkLink(ctx context.Context, rb *scannercommon.ReportBuilder, linkURL, pageURL string) {
	resp, err := s.base.httpGet(ctx, linkURL)
	if err != nil {
		rb.AddFinding(
			types.SeverityMedium,
			"失效链接",
			fmt.Sprintf("链接无法访问: %s", linkURL),
			pageURL,
			fmt.Sprintf("页面: %s，链接: %s，错误: %v", pageURL, linkURL, err),
			"更新或移除该链接",
			"移除链接后页面内容会变化；需确认链接用途",
		)
		return
	}
	resp.Body.Close()

	if resp.StatusCode == 404 {
		rb.AddFinding(
			types.SeverityMedium,
			"404 链接",
			fmt.Sprintf("链接返回 404: %s", linkURL),
			pageURL,
			fmt.Sprintf("页面: %s，链接: %s，HTTP 404", pageURL, linkURL),
			"更新或移除该链接",
			"移除链接后页面内容会变化；需确认链接用途",
		)
	} else if resp.StatusCode >= 500 {
		rb.AddFinding(
			types.SeverityLow,
			"链接服务端错误",
			fmt.Sprintf("链接返回 %d: %s", resp.StatusCode, linkURL),
			pageURL,
			fmt.Sprintf("页面: %s，链接: %s，HTTP %d", pageURL, linkURL, resp.StatusCode),
			"检查目标服务是否正常，或更新链接",
			"更新链接后需确认新链接可用",
		)
	}
}

// scanFilesForBrokenLinks 从文件系统扫描 HTML 文件提取链接
func (s *W7BrokenLinkScanner) scanFilesForBrokenLinks(ctx context.Context, rb *scannercommon.ReportBuilder, root, baseURL string) {
	count := 0
	s.base.walkFiles(root, func(path string, info os.FileInfo) error {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".html" && ext != ".htm" && ext != ".php" {
			return nil
		}
		if count >= 20 { // 限制扫描的 HTML 文件数量
			return filepath.SkipDir
		}
		count++

		data, err := s.base.readFileLimited(path)
		if err != nil {
			return nil
		}

		links := w7LinkRegex.FindAllStringSubmatch(string(data), w7MaxLinks)
		isHTTPS := strings.HasPrefix(baseURL, "https://")

		for _, link := range links {
			href := link[1]
			if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") ||
				strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "data:") {
				continue
			}

			// 检测混合内容
			if isHTTPS && strings.HasPrefix(href, "http://") {
				rb.AddFinding(
					types.SeverityMedium,
					"混合内容",
					fmt.Sprintf("HTTPS 站点 HTML 文件引用 HTTP 资源: %s", href),
					path,
					fmt.Sprintf("文件: %s，混合内容: %s", path, href),
					"将 HTTP 资源改为 HTTPS 引用",
					"修改后需确保目标资源支持 HTTPS",
				)
			}

			// 检测外链
			if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
				s.checkLink(ctx, rb, href, path)
			}
		}
		return nil
	})
}

// ============================================================
// W8: FTP 风险检测
// 检测匿名登录、明文传输、弱口令、目录遍历
// ============================================================

// W8FTPScanner FTP 风险检测扫描器
type W8FTPScanner struct {
	base *WebSecurityGuard
}

func (s *W8FTPScanner) Name() string       { return "websecurity" }
func (s *W8FTPScanner) SubScanner() string { return "W8" }

// Scan 执行 W8 FTP 风险检测
func (s *W8FTPScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	host := target.Host
	if host == "" {
		host = "127.0.0.1"
	}

	// 检测 FTP 端口（21）和 SFTP 端口（22）
	ftpAddr := fmt.Sprintf("%s:21", host)

	// 1. 检测 FTP 服务是否运行
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ftpAddr)
	if err != nil {
		findings := rb.GetFindings()
		setSubScanner(findings, "W8")
		return findings, nil // FTP 未运行，无需检测
	}

	// 2. 检测明文传输（FTP 协议本身是明文）
	rb.AddFinding(
		types.SeverityHigh,
		"FTP 明文传输",
		fmt.Sprintf("FTP 服务在 %s 运行，FTP 协议传输数据为明文，用户名和密码可被嗅探", ftpAddr),
		ftpAddr,
		fmt.Sprintf("地址: %s，FTP 使用明文协议", ftpAddr),
		"使用 SFTP（基于 SSH）或 FTPS（FTP over TLS）替代传统 FTP",
		"迁移到 SFTP/FTPS 后 FTP 客户端需更新连接配置",
	)

	// 3. 检测匿名登录
	s.checkAnonymousLogin(ctx, rb, host)

	// 4. 检测弱口令风险
	rb.AddFinding(
		types.SeverityMedium,
		"FTP 弱口令风险",
		fmt.Sprintf("FTP 服务在 %s 运行，如使用弱口令（如 admin/123456）将导致文件被入侵", ftpAddr),
		ftpAddr,
		fmt.Sprintf("地址: %s，常见弱口令: ftp/ftp, admin/123456, test/test", ftpAddr),
		"为所有 FTP 账户设置强密码，禁用或限制匿名访问",
		"修改密码后 FTP 客户端需更新连接配置",
	)

	conn.Close()

	findings := rb.GetFindings()
	setSubScanner(findings, "W8")
	return findings, nil
}

// checkAnonymousLogin 检测 FTP 匿名登录
func (s *W8FTPScanner) checkAnonymousLogin(ctx context.Context, rb *scannercommon.ReportBuilder, host string) {
	addr := fmt.Sprintf("%s:21", host)
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	// 读取欢迎信息
	_, err = reader.ReadString('\n')
	if err != nil {
		return
	}

	// 发送 USER anonymous
	fmt.Fprintf(conn, "USER anonymous\r\n")
	_, err = reader.ReadString('\n')
	if err != nil {
		return
	}

	// 发送 PASS anonymous@
	fmt.Fprintf(conn, "PASS anonymous@\r\n")
	response, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// 230 开头表示登录成功
	if strings.HasPrefix(response, "230") {
		rb.AddFinding(
			types.SeverityCritical,
			"FTP 匿名登录",
			fmt.Sprintf("FTP 服务 %s 允许匿名登录，攻击者可无需密码访问文件", addr),
			addr,
			fmt.Sprintf("地址: %s，使用 anonymous/anonymous@ 成功登录", addr),
			"在 FTP 配置中禁用匿名登录",
			"禁用匿名登录后依赖匿名访问的用户将无法连接",
		)

		// 尝试检测目录遍历
		fmt.Fprintf(conn, "PWD\r\n")
		pwdResp, err := reader.ReadString('\n')
		if err == nil && strings.HasPrefix(pwdResp, "257") {
			fmt.Fprintf(conn, "CWD /\r\n")
			cwdResp, err := reader.ReadString('\n')
			if err == nil && strings.HasPrefix(cwdResp, "250") {
				fmt.Fprintf(conn, "CWD ../../../..\r\n")
				traversalResp, err := reader.ReadString('\n')
				if err == nil && strings.HasPrefix(traversalResp, "250") {
					rb.AddFinding(
						types.SeverityCritical,
						"FTP 目录遍历",
						fmt.Sprintf("FTP 服务 %s 允许通过 ../ 遍历到上级目录", addr),
						addr,
						fmt.Sprintf("地址: %s，CWD ../../../.. 返回 250", addr),
						"限制 FTP 用户在其家目录内（chroot），禁止访问上级目录",
						"限制目录后 FTP 用户只能访问其家目录下的文件",
					)
				}
			}
		}
	}
}

// ============================================================
// W9: 首页内容风险检测
// 检测篡改、恶意跳转、暗链、可疑外部JS
// ============================================================

// W9HomepageScanner 首页内容风险检测扫描器
type W9HomepageScanner struct {
	base *WebSecurityGuard
}

func (s *W9HomepageScanner) Name() string       { return "websecurity" }
func (s *W9HomepageScanner) SubScanner() string { return "W9" }

// w9SuspiciousJSPatterns 可疑 JS 引用模式（匹配所有外部 JS，已知 CDN 在代码中过滤）
var w9SuspiciousJSPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*src\s*=\s*["'](https?://[^"']+)["']`),
}

// w9KnownCDNs 已知可信 CDN 域名列表
var w9KnownCDNs = []string{
	"www.googleapis.com",
	"cdn.jsdelivr.net",
	"ajax.googleapis.com",
	"code.jquery.com",
	"cdn.bootcdn.net",
	"cdn.bootcss.com",
	"unpkg.com",
}

// w9DarkLinkPatterns 暗链特征模式
var w9DarkLinkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<a[^>]*href\s*=\s*["'](https?://[^"']+)["'][^>]*style\s*=\s*["'].*display\s*:\s*none`),
	regexp.MustCompile(`(?i)<a[^>]*style\s*=\s*["'].*display\s*:\s*none[^>]*href\s*=\s*["'](https?://[^"']+)["']`),
	regexp.MustCompile(`(?i)<a[^>]*href\s*=\s*["'](https?://[^"']+)["'][^>]*style\s*=\s*["'].*visibility\s*:\s*hidden`),
	regexp.MustCompile(`(?i)<div[^>]*style\s*=\s*["'].*display\s*:\s*none[^>]*>.*<a[^>]*href\s*=\s*["'](https?://[^"']+)["']`),
}

// w9MaliciousRedirectPatterns 恶意跳转模式
var w9MaliciousRedirectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)window\.location\s*\.href\s*=\s*["'](https?://[^"']+)["']`),
	regexp.MustCompile(`(?i)window\.location\s*\.replace\s*\(\s*["'](https?://[^"']+)["']`),
	regexp.MustCompile(`(?i)document\.location\s*=\s*["'](https?://[^"']+)["']`),
	regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*url\s*=\s*(https?://[^"'>\s]+)`),
	regexp.MustCompile(`(?i)location\.assign\s*\(\s*["'](https?://[^"']+)["']`),
}

// w9KnownBadDomains 已知恶意域名特征
var w9KnownBadDomains = []string{
	".cn.gg/", ".ru/", ".tk/", ".ml/", ".ga/", ".cf/",
	"porn", "gambling", "casino", "viagra", "pharmacy",
}

// Scan 执行 W9 首页内容风险检测
func (s *W9HomepageScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	baseURL := s.base.targetURL(target)
	if baseURL == "" && target.Path == "" {
		findings := rb.GetFindings()
		setSubScanner(findings, "W9")
		return findings, nil
	}

	// HTTP 方式检测首页
	if baseURL != "" {
		s.scanHomepageHTTP(ctx, rb, baseURL)
	}

	// 文件系统方式检测首页文件
	if target.Path != "" {
		s.scanHomepageFile(rb, target.Path)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W9")
	return findings, nil
}

// scanHomepageHTTP 通过 HTTP 检测首页内容风险
func (s *W9HomepageScanner) scanHomepageHTTP(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	resp, err := s.base.httpGet(ctx, baseURL)
	if err != nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	resp.Body.Close()
	if err != nil {
		return
	}
	bodyStr := string(body)

	// 1. 检测恶意跳转
	s.detectMaliciousRedirect(rb, baseURL, bodyStr)

	// 2. 检测暗链
	s.detectDarkLinks(rb, baseURL, bodyStr)

	// 3. 检测可疑外部 JS
	s.detectSuspiciousJS(rb, baseURL, bodyStr)

	// 4. 检测已知恶意域名
	s.detectKnownBadDomains(rb, baseURL, bodyStr)

	// 5. 检测首页篡改特征
	s.detectTamperSigns(rb, baseURL, bodyStr)

	// 6. 基于哈希基线的篡改检测
	if expectedHash, ok := s.base.GetBaseline(baseURL); ok {
		currentHash := sha256Hash(body)
		if currentHash != expectedHash {
			rb.AddFinding(
				types.SeverityHigh,
				"首页内容被篡改",
				fmt.Sprintf("首页 %s 内容哈希与基线不一致，可能被篡改", baseURL),
				baseURL,
				fmt.Sprintf("URL: %s，基线哈希: %s，当前哈希: %s", baseURL, expectedHash[:16], currentHash[:16]),
				"对比首页修改记录，确认是否为合法更新；如非合法修改，从备份恢复",
				"恢复到基线版本会丢失最近的合法修改；请先确认修改来源",
			)
		}
	}
}

// detectMaliciousRedirect 检测恶意跳转
func (s *W9HomepageScanner) detectMaliciousRedirect(rb *scannercommon.ReportBuilder, pageURL, body string) {
	for _, pattern := range w9MaliciousRedirectPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			redirectURL := m[1]
			// 排除同域名跳转
			if strings.Contains(redirectURL, pageURL) || strings.HasPrefix(redirectURL, "/") {
				continue
			}
			rb.AddFinding(
				types.SeverityHigh,
				"恶意跳转",
				fmt.Sprintf("首页包含外部跳转: %s", redirectURL),
				pageURL,
				fmt.Sprintf("页面: %s，跳转目标: %s", pageURL, redirectURL),
				"检查跳转代码是否为合法需求；如非合法，移除跳转代码",
				"移除跳转后页面行为会变化；需确认跳转用途",
			)
		}
	}
}

// detectDarkLinks 检测暗链
func (s *W9HomepageScanner) detectDarkLinks(rb *scannercommon.ReportBuilder, pageURL, body string) {
	for _, pattern := range w9DarkLinkPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			linkURL := m[1]
			rb.AddFinding(
				types.SeverityHigh,
				"暗链检测",
				fmt.Sprintf("首页包含隐藏链接（暗链）: %s", linkURL),
				pageURL,
				fmt.Sprintf("页面: %s，暗链: %s（使用 display:none 或 visibility:hidden 隐藏）", pageURL, linkURL),
				"移除暗链代码，排查网站是否被入侵",
				"移除暗链后不影响正常显示；需排查入侵途径",
			)
		}
	}
}

// detectSuspiciousJS 检测可疑外部 JS
func (s *W9HomepageScanner) detectSuspiciousJS(rb *scannercommon.ReportBuilder, pageURL, body string) {
	for _, pattern := range w9SuspiciousJSPatterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			jsURL := m[1]
			// 过滤已知可信 CDN
			if isKnownCDN(jsURL) {
				continue
			}
			rb.AddFinding(
				types.SeverityMedium,
				"可疑外部JS引用",
				fmt.Sprintf("首页引用了外部 JS: %s", jsURL),
				pageURL,
				fmt.Sprintf("页面: %s，JS URL: %s（非常见可信 CDN）", pageURL, jsURL),
				"确认该 JS 来源可信；如不可信，移除引用或替换为可信 CDN",
				"移除 JS 后依赖该脚本的功能将失效；需确认 JS 用途",
			)
		}
	}
}

// isKnownCDN 检查 URL 是否来自已知可信 CDN
func isKnownCDN(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	for _, cdn := range w9KnownCDNs {
		if host == cdn {
			return true
		}
	}
	return false
}

// detectKnownBadDomains 检测已知恶意域名
func (s *W9HomepageScanner) detectKnownBadDomains(rb *scannercommon.ReportBuilder, pageURL, body string) {
	lowerBody := strings.ToLower(body)
	for _, bad := range w9KnownBadDomains {
		if strings.Contains(lowerBody, bad) {
			rb.AddFinding(
				types.SeverityHigh,
				"可疑恶意域名引用",
				fmt.Sprintf("首页包含可疑内容: %s", bad),
				pageURL,
				fmt.Sprintf("页面: %s，匹配特征: %s", pageURL, bad),
				"检查相关内容是否为合法需求；如非合法，移除相关代码",
				"移除后页面内容会变化；需确认内容用途",
			)
		}
	}
}

// detectTamperSigns 检测首页篡改特征
func (s *W9HomepageScanner) detectTamperSigns(rb *scannercommon.ReportBuilder, pageURL, body string) {
	lowerBody := strings.ToLower(body)

	// 检测典型篡改特征
	tamperSigns := []struct {
		sign     string
		severity types.Severity
		desc     string
	}{
		{"hacked by", types.SeverityCritical, "页面包含 'hacked by' 字样，疑似被篡改"},
		{"被黑", types.SeverityCritical, "页面包含 '被黑' 字样，疑似被篡改"},
		{"赌场", types.SeverityHigh, "页面包含 '赌场' 字样，可能被植入赌博暗链"},
		{"博彩", types.SeverityHigh, "页面包含 '博彩' 字样，可能被植入赌博暗链"},
		{"色情", types.SeverityHigh, "页面包含 '色情' 字样，可能被植入色情暗链"},
		{"代开发", types.SeverityMedium, "页面包含 '代开发' 字样，可能被植入广告"},
		{"代孕", types.SeverityMedium, "页面包含 '代孕' 字样，可能被植入广告"},
		{"六合彩", types.SeverityHigh, "页面包含 '六合彩' 字样，可能被植入赌博暗链"},
		{"外围", types.SeverityMedium, "页面包含 '外围' 字样，可能被植入广告"},
		{"北京赛车", types.SeverityHigh, "页面包含 '北京赛车' 字样，可能被植入赌博暗链"},
	}

	for _, sign := range tamperSigns {
		if strings.Contains(lowerBody, sign.sign) {
			rb.AddFinding(
				sign.severity,
				"首页篡改特征",
				sign.desc,
				pageURL,
				fmt.Sprintf("页面: %s，匹配特征: %s", pageURL, sign.sign),
				"检查相关内容是否为合法需求；如非合法，从备份恢复首页",
				"恢复首页会丢失最近修改；请先确认修改来源",
			)
		}
	}

	// 检测大量隐藏元素（可能是挂马）
	hiddenCount := strings.Count(lowerBody, "display:none") + strings.Count(lowerBody, "display: none")
	if hiddenCount > 10 {
		rb.AddFinding(
			types.SeverityMedium,
			"大量隐藏元素",
			fmt.Sprintf("首页包含 %d 个隐藏元素，可能被植入暗链或挂马", hiddenCount),
			pageURL,
			fmt.Sprintf("页面: %s，隐藏元素数量: %d", pageURL, hiddenCount),
			"审查隐藏元素是否为合法需求；如非合法，移除相关代码",
			"移除隐藏元素后不影响正常显示；需确认元素用途",
		)
	}
}

// scanHomepageFile 从文件系统检测首页文件
func (s *W9HomepageScanner) scanHomepageFile(rb *scannercommon.ReportBuilder, root string) {
	// 查找首页文件
	indexFiles := []string{"index.html", "index.htm", "index.php", "default.html", "default.htm", "index.aspx", "index.jsp"}
	for _, name := range indexFiles {
		path := filepath.Join(root, name)
		data, err := s.base.readFileLimited(path)
		if err != nil {
			continue
		}
		bodyStr := string(data)

		// 复用 HTTP 检测逻辑
		s.detectMaliciousRedirect(rb, path, bodyStr)
		s.detectDarkLinks(rb, path, bodyStr)
		s.detectSuspiciousJS(rb, path, bodyStr)
		s.detectKnownBadDomains(rb, path, bodyStr)
		s.detectTamperSigns(rb, path, bodyStr)

		// 基线检测
		if expectedHash, ok := s.base.GetBaseline(path); ok {
			currentHash := sha256Hash(data)
			if currentHash != expectedHash {
				rb.AddFinding(
					types.SeverityHigh,
					"首页文件被篡改",
					fmt.Sprintf("首页文件 %s 内容哈希与基线不一致，可能被篡改", path),
					path,
					fmt.Sprintf("文件: %s，基线哈希: %s，当前哈希: %s", path, expectedHash[:16], currentHash[:16]),
					"对比文件修改记录，确认是否为合法更新；如非合法修改，从备份恢复",
					"恢复到基线版本会丢失最近的合法修改；请先确认修改来源",
				)
			}
		}
	}
}
