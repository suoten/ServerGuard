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
	"strconv"
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

	// 全局共享 HTTP Client（避免每次请求创建新 Transport 导致 goroutine 泄漏）
	httpClient *http.Client

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
		httpTimeout:    3 * time.Second, // 从 10s 降到 3s：164 站点 × 多个 HTTP 请求时避免总超时
		maxFileSize:    10 * 1024 * 1024, // 10MB（降低从 50MB，减少内存峰值）
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
				TLSHandshakeTimeout:   3 * time.Second,
				ResponseHeaderTimeout: 3 * time.Second,
				MaxIdleConns:          20,
				MaxIdleConnsPerHost:   5,
				IdleConnTimeout:       30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		maxFiles:       200000,            // 限制遍历文件数（宝塔多站点场景 100+ 站点，每个站点可能数千文件）
		fileBaselines:  make(map[string]string),
		urlCache:       make(map[string]int),
		yaraEngine:     yaraEngine,
		w5Scanned:      make(map[string]bool),
		w6ScannedFiles: make(map[string]bool),
	}
	// 注册 18 个子扫描器（W1-W11 原有 + W12-W18 源码漏洞审计）
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
		&W10FilePermissionScanner{base: g},
		&W11PHPConfigScanner{base: g},
		// W12-W18: 源码漏洞审计
		&W12SQLiScanner{base: g},
		&W13UploadScanner{base: g},
		&W14XSSScanner{base: g},
		&W15CmdInjectionScanner{base: g},
		&W16SSRFScanner{base: g},
		&W17DeserializeScanner{base: g},
		&W18SensitiveDataScanner{base: g},
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

	// 全局配置文件去重也要清空：每轮扫描应重新检测配置文件
	// 否则第二轮扫描会跳过所有已扫描过的配置文件，导致 W6 几乎返回 0 个发现
	w6GlobalMu.Lock()
	w6GlobalScannedFiles = make(map[string]bool)
	w6GlobalMu.Unlock()

	// W11 PHP 配置文件全局去重也需清空：每轮扫描应重新检测 php.ini
	w11GlobalMu.Lock()
	w11GlobalScannedFiles = make(map[string]bool)
	w11GlobalMu.Unlock()

	g.urlCacheMu.Lock()
	g.urlCache = make(map[string]int)
	g.urlCacheMu.Unlock()
}

// PerSiteTimeout 根据站点总数动态计算每站点超时
// 站点少时给充足时间（60s），站点多时适当缩短（最低 15s）
// 大部分站点在 5-10s 内完成，超时只是防止个别慢站点卡死
func PerSiteTimeout(siteCount int) time.Duration {
	switch {
	case siteCount <= 10:
		return 60 * time.Second
	case siteCount <= 50:
		return 45 * time.Second
	case siteCount <= 200:
		return 30 * time.Second
	case siteCount <= 500:
		return 20 * time.Second
	default:
		return 15 * time.Second
	}
}

// GlobalWTimeout 根据站点数动态计算 W 模块全局超时
// 每个站点有 11 个子扫描器，每个子扫描器独立超时（W1-W3: 60s, W4-W7: 30s, 其余: 15s）
// 实际执行中大部分子扫描器在 2-5s 内完成，平均每站点约 30-90s
// 并发模式下除以并发数
func GlobalWTimeout(siteCount int, isIdle bool) time.Duration {
	// 并发数：与 main.go 中的逻辑保持一致
	concurrency := 1
	switch {
	case siteCount <= 20:
		concurrency = 1
	case siteCount <= 100:
		concurrency = 4
	case siteCount <= 300:
		concurrency = 6
	default:
		concurrency = 8
	}
	// 保守预估：平均每站点 90s（11 个子扫描器，大部分 2-5s，少数可能超时）
	avgPerSite := 90 * time.Second
	totalEstimate := time.Duration(siteCount) * avgPerSite / time.Duration(concurrency)
	// 至少 10 分钟，最多 3 小时
	if totalEstimate < 10*time.Minute {
		totalEstimate = 10 * time.Minute
	}
	if totalEstimate > 3*time.Hour {
		totalEstimate = 3 * time.Hour
	}
	// 空闲时多给 50%
	if isIdle {
		totalEstimate = totalEstimate * 3 / 2
	}
	return totalEstimate
}

// Scan 执行所有子扫描器，汇总发现项
// 单个子扫描器失败或超时不中断后续扫描器
// 每个子扫描器有独立超时，避免某个慢扫描器（如 W3 YARA 扫描）耗尽整个站点的时间
// 注意：调用方应在并发扫描前调用 ResetDedupCaches() 一次
func (g *WebSecurityGuard) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	// 计算每个子扫描器的超时时间
	// 文件系统扫描器（W1/W2/W3）较慢，给 60s；HTTP 扫描器给 30s；其余 15s
	perSubTimeout := func(sub string) time.Duration {
		switch sub {
		case "W1", "W2", "W3":
			return 60 * time.Second
		case "W4", "W5", "W6", "W7":
			return 30 * time.Second
		default:
			return 15 * time.Second
		}
	}

	// 同时受全局 ctx 约束：如果全局剩余时间不足，用剩余时间
	globalRemaining := time.Duration(0)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			globalRemaining = remaining
		}
	}

	var allFindings []types.ScanFinding
	for _, s := range g.scanners {
		subTimeout := perSubTimeout(s.SubScanner())
		// 如果全局剩余时间小于子扫描器超时，用全局剩余时间（至少 5s）
		if globalRemaining > 0 && globalRemaining < subTimeout {
			if globalRemaining < 5*time.Second {
				// 全局时间已不足，跳过后续扫描器
				fmt.Printf("[WebSecurity] global time exhausted, skipping sub=%s for %s\n", s.SubScanner(), target.Path)
				continue
			}
			subTimeout = globalRemaining
		}

		// 每个子扫描器独立超时：一个超时不影响后续
		subCtx, subCancel := context.WithTimeout(ctx, subTimeout)
		findings, err := s.Scan(subCtx, target)
		subCancel()
		if err != nil {
			// 超时或出错只跳过当前子扫描器，继续执行后续
			fmt.Fprintf(os.Stderr, "[WebSecurity] sub=%s error/timeout for %s: %v\n", s.SubScanner(), target.Path, err)
			continue
		}
		if len(findings) > 0 {
			fmt.Printf("[WebSecurity] sub=%s found %d findings for %s\n", s.SubScanner(), len(findings), target.Path)
		}
		allFindings = append(allFindings, findings...)

		// 更新全局剩余时间
		if globalRemaining > 0 {
			globalRemaining -= subTimeout
		}
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

// hashBody 计算响应体的短哈希指纹，用于去重
func hashBody(body []byte) string {
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:8])
}

// isGenericHTMLResponse 检查响应是否为通用 HTML 页面（SPA fallback / 反向代理默认页）
// 敏感文件应返回纯文本/二进制内容，不是 HTML 页面
// 不依赖 Content-Type，因为很多反代/SPA 不设正确的 Content-Type
func isGenericHTMLResponse(body []byte, contentType string) bool {
	if len(body) == 0 {
		return false
	}
	// 快速检测：检查前 512 字节是否有 HTML 标记
	checkSize := len(body)
	if checkSize > 512 {
		checkSize = 512
	}
	lowerBody := strings.ToLower(string(body[:checkSize]))
	// HTML 文档特征（敏感文件不应该是 HTML 页面）
	htmlMarkers := []string{
		"<!doctype html",
		"<!doctype",
		"<html",
		"<head",
		"<body",
		"<title",
		"<!--",
		"<meta ",
		"<link ",
		"<script",
		"<div",
		"<span",
		"<style",
		"<iframe",
		"<noscript",
		"<!doctype html",
	}
	for _, marker := range htmlMarkers {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	// 服务器默认页特征
	serverMarkers := []string{
		"welcome to nginx",
		"welcome to apache",
		"宝塔面板",
		"bt-panel",
		"test page",
		"default page",
		"index of /",   // 目录列表
		"<h1>404</h1>", // 404 页面但返回 200
	}
	for _, marker := range serverMarkers {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}

// httpGet 发送 HTTP GET 请求（跳过 TLS 验证以支持自签名证书检测）
// 使用全局共享的 httpClient，避免每次请求创建新 Transport 导致 goroutine 泄漏
func (g *WebSecurityGuard) httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ServerGuard-WebSecurity-Scanner/1.0")
	return g.httpClient.Do(req)
}

// isBogusResponse 检查 HTTP 响应是否为虚假页面（404/403/宝塔停站/空白页等）
// 很多站点对不存在的路径返回 200 + 自定义错误页，必须检查内容才能避免误报
func isBogusResponse(bodyStr string) bool {
	lower := strings.ToLower(bodyStr)
	// 404 页面
	if strings.Contains(lower, "404") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "页面不存在") ||
		strings.Contains(lower, "页面未找到") {
		return true
	}
	// 403 页面
	if strings.Contains(lower, "403") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "访问被拒") {
		return true
	}
	// 宝塔停站页面
	if strings.Contains(lower, "停止运行") ||
		strings.Contains(lower, "停止访问") ||
		strings.Contains(lower, "站点已停") {
		return true
	}
	// 宝塔默认页面
	if strings.Contains(lower, "恭喜") &&
		strings.Contains(lower, "站点创建成功") {
		return true
	}
	// 空白页面
	if len(strings.TrimSpace(bodyStr)) == 0 {
		return true
	}
	return false
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
	// Python 虚拟环境目录（包含大量第三方 SDK 文件，不是用户代码）
	// .venv/venv/env/site-packages 里的文件权限和内容不应被扫描
	".venv":         true,
	"venv":          true,
	"env":           true,
	"site-packages": true,
	// 其他第三方依赖目录
	"libs":          true, // 前端库目录（FastAdmin 等框架的 assets/libs/）
	"addons":        true, // 插件目录（UEditor 等前端编辑器）
}

// webSkipDirsMalware 恶意代码扫描时跳过这些目录
// 原则：跳过纯依赖目录和缓存目录，但不跳过可能包含恶意代码的目录
// 多语言检测已经足够智能，可以区分前端 JS 和后端脚本
var webSkipDirsMalware = map[string]bool{
	"node_modules": true, // JS 依赖（数万文件，扫描太慢）
	"__pycache__":  true, // Python 字节码
	".git":         true,
	".svn":         true,
	".cache":       true,
	// Python 虚拟环境目录（包含大量第三方 SDK 文件，如 tencentcloud/boto3/requests 等）
	// 这些 SDK 的源码会触发通用恶意代码模式（如 os.system+request 关键词组合）
	".venv":        true,
	"venv":         true,
	"env":          true, // virtualenv 的另一种命名
	"site-packages": true, // Python 安装包目录（系统级）
	"tests":        true, // 框架自带测试目录
	"test":         true,
	"Test":         true, // PHPUnit
	"fixtures":     true,
	"mock":         true,
	// 前端库目录（JS/CSS 资源，不会执行 PHP webshell）
	"libs":         true, // 前端库目录（assets/libs/）
	"locale":       true, // 国际化语言包目录（moment/locale 等，大量 \uHHHH）
	"locales":      true,
	"i18n":         true,
	"lang":         true,
	"languages":    true,
	// 框架运行时/缓存目录（ThinkPHP/Yii/Laravel 等生成的哈希命名缓存文件，不是 webshell）
	"runtime":      true, // ThinkPHP/Yii 运行时目录
	"temp":         true, // ThinkPHP runtime/temp 缓存目录
	"tmp":          true, // 通用临时目录
	"cache":        true, // Laravel/ Symfony 缓存目录
	"smarty":       true, // Smarty 模板编译缓存
	"compiled":     true, // 模板编译输出目录
	"sessions":     true, // 会话文件目录
	"logs":         true, // 日志目录
	// 其他非可执行文件目录
	"fonts":        true,
	"img":          true,
	"images":       true,
	"icons":        true,
	"svg":          true,
}

// isKnownVendorFramework 检查路径是否属于已知 PHP 框架的 vendor 目录
// 这些框架的核心代码中正常的 PHP 函数调用（system/exec/base64_eval 等）会被误报为 Webshell
// 统一排除列表，供 W3 正则检测、YARA 扫描、phpinfo 检测共用
// isKnownVendorFramework 检测路径是否属于已知 PHP 框架的 vendor 目录或第三方库目录
// vendor 目录下的文件是 Composer 安装的第三方库，正常配置下不会被 Web 服务器解析执行
// 策略：vendor 目录下的文件全部跳过正则检测和 YARA 扫描
// 改用"文件修改时间"来检测 vendor 中的异常文件（新植入的 Webshell 通常是最近创建的）
func isKnownVendorFramework(path string) bool {
	lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	// vendor 目录：Composer 安装的第三方库，直接全部排除
	if strings.Contains(lowerPath, "/vendor/") {
		return true
	}
	// ThinkPHP 框架核心目录
	if strings.Contains(lowerPath, "/thinkphp/library/") ||
		strings.Contains(lowerPath, "/thinkphp/think-") {
		return true
	}
	// TCPDF 独立目录（非 vendor 安装）
	if strings.Contains(lowerPath, "/tcpdf-main/") ||
		strings.Contains(lowerPath, "/library/tcpdf") {
		return true
	}
	// FastAdmin addons 下的库
	if strings.Contains(lowerPath, "/addons/") && strings.Contains(lowerPath, "/library/") {
		return true
	}
	// FastAdmin 框架核心目录
	if strings.Contains(lowerPath, "/extend/fast/") ||
		strings.Contains(lowerPath, "/application/common.php") {
		return true
	}
	return false
}

// isKnownFrontendLibrary 检测文件是否为知名前端库文件
// 这些库文件（jquery-ui、bootstrap 等）中的 iframe/javascript: 组合是正常功能代码
func isKnownFrontendLibrary(path string) bool {
	lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	baseName := filepath.Base(lowerPath)
	// 知名前端库文件名模式
	knownLibPatterns := []string{
		"jquery-ui", "jquery-ui-", "jquery.min", "jquery-",
		"bootstrap.min", "bootstrap.js", "bootstrap-",
		"angular.min", "angular.js", "vue.min", "vue.js", "react.min", "react.js",
		"prototype.js", "mootools", "dojo", "yui-min",
		"echarts.min", "echarts.js", "chart.min", "chart.js",
		"layui.js", "element-ui", "element-plus",
		"lodash.min", "underscore.min", "moment.min", "moment.js",
		"axios.min", "axios.js", "swiper.min", "swiper.js",
		"fontawesome", "font-awesome",
		"ueditor", "ueditor.all", "ueditor.min", "ueditorplus",
		"kindeditor", "ckeditor", "tinymce", "tinymce.min",
		"layer.js", "layer.min",
		"element_main", "googletrans", "google-trans",
		// 前端打包文件模式：index-XXXX.js / index.XXXX.js / vendor-XXXX.js 等
		"index-", "vendor-", "chunk-", "runtime-",
		"index.", "vendor.", "chunk.", "runtime.",
		// 新增：编辑器/文件管理器/前端框架
		"elfinder", "ace.", "ace.min", "codemirror", "monaco",
		"tinymce", "froala", "simditor", "summernote",
		"wangeditor", "wang-editor",
		"plupload", "dropzone", "fineuploader", "webuploader",
		"spectrum", "colorpicker", "datepicker", "datetimepicker",
		"select2", "select2.min", "chosen", "parsley",
		"slick.", "swiper", "owl.carousel", "magnific-popup",
		"isotope", "imagesloaded", "masonry",
		"backbone", "ember", "handlebars", "mustache",
		"d3.min", "d3.js", "three.min", "three.js",
		"socket.io", "socket.io.min",
		"pdf.js", "pdf.min", "pdf.worker",
		"video.js", "video.min", "plyr", "hls.js", "flv.js",
		"hls.min", "flv.min",
		"crypto-js", "aes.js", "sha256.js", "md5.js",
		"ztree", "ztree.min", "jstree", "jstree.min",
		"datatables", "datatables.min",
		"fullcalendar", "fullcalendar.min",
		"intro.js", "intro.min", "popper.js", "popper.min",
		"sweetalert", "sweetalert.min", "toastr", "toastr.min",
		"raphael", "raphael.min", "snap.svg", "snap.svg-min",
		"modernizr", "modernizr.min",
		"polyfill", "polyfill.min",
		"bluebird", "bluebird.min",
		"core.js", "core.min", "app.js", "app.min",
		"main.js", "main.min", "bundle.js", "bundle.min",
		"runtime.js", "runtime.min", "vendors.js", "vendors.min",
	}
	for _, p := range knownLibPatterns {
		if strings.Contains(baseName, p) {
			return true
		}
	}
	// 知名前端库路径
	knownLibPaths := []string{
		"/static/jquery/", "/static/js/jquery/",
		"/static/bootstrap/", "/static/layui/",
		"/public/static/", "/assets/jquery/",
		"/node_modules/",
	}
	for _, p := range knownLibPaths {
		if strings.Contains(lowerPath, p) && (strings.Contains(baseName, "jquery") ||
			strings.Contains(baseName, "bootstrap") ||
			strings.Contains(baseName, "angular") ||
			strings.Contains(baseName, "vue") ||
			strings.Contains(baseName, "echarts")) {
			return true
		}
	}
	return false
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
	rootAbs, _ := filepath.Abs(root)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无法访问的路径
		}
		if count >= g.maxFiles {
			return filepath.SkipDir
		}
		if d.IsDir() {
			dirName := d.Name()
			// 不要跳过 root 本身——站点根目录可能叫 "dist"、"build" 等
			absPath, _ := filepath.Abs(path)
			if absPath != rootAbs && skipDirs[dirName] {
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
	// 版本控制：降低严重级别，大部分站点已通过 Nginx 配置阻止 .git/ 访问
	{".git/", types.SeverityLow, "Git仓库目录存在（如已配置 Nginx 拒绝访问则可忽略）"},
	// .git/config 和 .git/HEAD 不再单独报告，.git/ 目录报告已覆盖
	// {".git/config", types.SeverityHigh, "Git配置文件泄露，包含仓库路径和远程地址"},
	// {".git/HEAD", types.SeverityMedium, "Git HEAD文件泄露"},
	{".svn/", types.SeverityHigh, "SVN仓库目录泄露"},
	{".svn/entries", types.SeverityHigh, "SVN条目文件泄露"},
	{".hg/", types.SeverityHigh, "Mercurial仓库目录泄露"},
	{".bzr/", types.SeverityMedium, "Bazaar仓库目录泄露"},
	// 环境配置
	// .env 文件：FastAdmin/Laravel 等框架的运行目录是 public/，.env 在项目根目录外部不可达
	// 只有当 .env 直接在网站根目录（Nginx root 指向的目录）时才是真实泄露
	// 递归扫描时会判断同级是否有 public/ 目录来区分
	{".env", types.SeverityMedium, "环境变量文件，可能包含数据库密码、密钥等敏感配置"},
	{".env.local", types.SeverityMedium, "本地环境变量文件，可能包含敏感配置"},
	{".env.production", types.SeverityHigh, "生产环境变量文件，可能包含敏感配置"},
	{".env.development", types.SeverityLow, "开发环境变量文件"},
	{".env.staging", types.SeverityLow, "测试环境变量文件"},
	// SSH 密钥
	{"id_rsa", types.SeverityCritical, "SSH私钥泄露"},
	{"id_dsa", types.SeverityCritical, "SSH DSA私钥泄露"},
	{"id_ecdsa", types.SeverityCritical, "SSH ECDSA私钥泄露"},
	{"id_ed25519", types.SeverityCritical, "SSH Ed25519私钥泄露"},
	{".ssh/config", types.SeverityMedium, "SSH配置文件泄露"},
	{".aws/credentials", types.SeverityCritical, "AWS凭证文件泄露"},
	{".aws/config", types.SeverityHigh, "AWS配置文件泄露"},
	// IDE 配置：移除，IDE 配置文件是正常项目文件，不含敏感信息
	// .idea/ {".idea/", types.SeverityMedium, "JetBrains IDE配置目录泄露"},
	// .vscode/ {".vscode/", types.SeverityLow, "VS Code配置目录泄露"},
	// Apache
	{".htpasswd", types.SeverityHigh, "Apache密码文件泄露"},
	// .htaccess 是 Apache 正常配置文件，不是泄露
	// macOS 目录信息：移除，.DS_Store 不含敏感信息，只是目录列表缓存
	// {".DS_Store", types.SeverityLow, "macOS目录信息文件泄露，可能暴露目录结构"},
	// 凭证文件
	{"credentials.json", types.SeverityHigh, "凭证文件，可能包含API密钥或服务凭证"},
	{"service-account.json", types.SeverityCritical, "服务账号密钥文件泄露"},
	// 以下为新增——与宝塔等竞品对齐
	// PHP 信息泄露
	{"phpinfo.php", types.SeverityHigh, "phpinfo 信息泄露，暴露服务器完整配置"},
	{"info.php", types.SeverityHigh, "phpinfo 信息泄露，暴露服务器完整配置"},
	{"test.php", types.SeverityMedium, "测试文件残留，可能泄露服务器信息"},
	{"phpinfo.php.bak", types.SeverityHigh, "phpinfo 备份文件残留"},
	// 包管理文件
	// composer.lock / package-lock.json / yarn.lock / pnpm-lock.yaml 移除：每个项目的标准锁文件，不是泄露
	// composer.json / package.json 移除：项目标配文件，不是泄露
	// Docker Compose 包含环境变量（可能含密码），算泄露
// docker-compose 文件是标准项目配置，不是敏感泄露
	// {"docker-compose.yml", types.SeverityMedium, "Docker Compose 配置泄露，可能包含数据库密码等环境变量"},
	// {"docker-compose.yaml", types.SeverityMedium, "Docker Compose 配置泄露"},
	// 以下构建配置文件不算敏感泄露（每个前端项目都有）：
	// Dockerfile / webpack.config / vite.config / .babelrc / tsconfig.json
	// 数据库备份
	{"database.sql", types.SeverityCritical, "数据库备份文件泄露"},
	{"db.sql", types.SeverityCritical, "数据库备份文件泄露"},
	{"dump.sql", types.SeverityCritical, "数据库备份文件泄露"},
	{"backup.sql", types.SeverityCritical, "数据库备份文件泄露"},
	{"data.sql", types.SeverityCritical, "数据库备份文件泄露"},
	// 配置文件
	{"config.php.bak", types.SeverityHigh, "PHP 配置文件备份泄露"},
	{"config.php.old", types.SeverityHigh, "PHP 配置文件旧版本泄露"},
	{"config.php.swp", types.SeverityHigh, "Vim 交换文件泄露配置"},
	{"config.php~", types.SeverityHigh, "编辑器备份文件泄露配置"},
	{"wp-config.php.bak", types.SeverityHigh, "WordPress 配置备份文件泄露"},
	{"wp-config.php~", types.SeverityHigh, "WordPress 配置编辑器备份泄露"},
	{"configuration.php", types.SeverityMedium, "Joomla 配置文件泄露"},
	// 管理面板
	{"phpmyadmin/", types.SeverityMedium, "phpMyAdmin 目录暴露"},
	{"adminer.php", types.SeverityMedium, "Adminer 数据库管理工具暴露"},
	{"pma/", types.SeverityMedium, "phpMyAdmin 目录暴露"},
	// 日志文件
	{"error_log", types.SeverityMedium, "PHP 错误日志泄露，可能包含路径等敏感信息"},
	{"error.log", types.SeverityMedium, "错误日志泄露"},
	{"access.log", types.SeverityLow, "访问日志泄露"},
	{"debug.log", types.SeverityMedium, "调试日志泄露"},
// app.log 日志文件：已移除，日志文件在 /logs/ 目录下是正常的项目结构
	// {"app.log", types.SeverityMedium, "应用日志泄露"},
	// 其他
	{"web.config", types.SeverityMedium, "IIS 配置文件泄露"},
	// GitLab CI 配置：移除，CI/CD 配置是正常项目文件，密钥通常引用 CI 变量
	// {".gitlab-ci.yml", types.SeverityMedium, "GitLab CI 配置泄露，暴露构建流程"},
	// .npmrc 移除：Node.js 项目标配配置文件，不一定包含 token
	// .pypirc / .netrc 仍保留：确实包含上传凭证
	// {.".npmrc", types.SeverityHigh, "NPM 配置文件泄露，可能包含认证 token"},
	{".pypirc", types.SeverityHigh, "Python PyPI 配置文件泄露，可能包含上传凭证"},
	{".netrc", types.SeverityCritical, ".netrc 文件泄露，包含 FTP/HTTP 凭证"},
	// 以下文件是正常的公开/配置文件，不是安全风险，不再报告：
	// - robots.txt: 每个网站都应公开的爬虫协议
	// - sitemap.xml: SEO 站点地图，本就是公开的
	// - crossdomain.xml / clientaccesspolicy.xml: Flash/Silverlight 跨域策略（过时但不敏感）
	// - .gitignore / .dockerignore: 只列忽略规则，不含敏感数据
	// - .editorconfig: 编辑器格式配置
	// - .well-known/security.txt: 本来就是公开的安全联系信息
	// - go.mod / go.sum / requirements.txt / Pipfile / Gemfile: 依赖列表（不算敏感）
	// - .procfile: 进程配置
	// - .github/: GitHub CI 目录
	// - Thumbs.db / desktop.ini / __MACOSX/: 操作系统元数据（不是安全风险）
	// - .htaccess: Apache 正常配置文件（每个 Apache 站点都有）
	// 如果这些文件的备份/变体（如 .htaccess.bak / .HTACCESS）才是泄露
	// 网站打包备份
	// 降级：这些文件可能是在部署过程中创建的，不一定可被外部访问
	{"www.zip", types.SeverityHigh, "网站打包备份文件，可能暴露源代码"},
	{"backup.zip", types.SeverityHigh, "备份压缩包，可能包含敏感数据"},
	{"site.zip", types.SeverityHigh, "站点压缩包，可能暴露源代码"},
	{"web.zip", types.SeverityHigh, "Web 目录压缩包，可能暴露源代码"},
	{"www.tar.gz", types.SeverityCritical, "网站打包备份泄露"},
	{"backup.tar.gz", types.SeverityCritical, "备份 tar 包泄露"},
	{"www.rar", types.SeverityCritical, "网站打包备份泄露"},
	{"backup.rar", types.SeverityCritical, "备份 RAR 包泄露"},
	{"1.zip", types.SeverityHigh, "可疑数字命名压缩包"},
	{"1.tar.gz", types.SeverityHigh, "可疑数字命名 tar 包"},
	{"a.zip", types.SeverityHigh, "可疑单字母命名压缩包"},
	{"a.tar.gz", types.SeverityHigh, "可疑单字母命名 tar 包"},
	{"data.zip", types.SeverityHigh, "数据压缩包泄露"},
	{"data.tar.gz", types.SeverityHigh, "数据 tar 包泄露"},
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
// 递归遍历 root 及其子目录（覆盖宝塔多站点场景：/www/wwwroot/siteA/、/www/wwwroot/siteB/ 都扫到）
func (s *W1SensitiveFileScanner) scanFileSystem(rb *scannercommon.ReportBuilder, root string) {
	// 方式1：直接在根目录检查（保持原有行为）
	for _, sf := range w1SensitiveFiles {
		fullPath := filepath.Join(root, sf.name)
		if _, err := os.Stat(fullPath); err == nil {
			// .env 智能判断：如果同级目录有 public/，说明是 FastAdmin/Laravel 框架项目
			// 运行目录是 public/，.env 在项目根目录外部不可达，跳过报告
			if strings.Contains(sf.name, ".env") {
				publicDir := filepath.Join(root, "public")
				if _, err := os.Stat(publicDir); err == nil {
					continue // 同级有 public/ 目录，.env 外部不可达，跳过
				}
				// 也检查上级目录（如 /www/wwwroot/site/backend → 检查 /www/wwwroot/site/public）
				parentDir := filepath.Dir(root)
				publicDir2 := filepath.Join(parentDir, "public")
				if _, err := os.Stat(publicDir2); err == nil {
					continue // 上级有 public/ 目录，.env 外部不可达，跳过
				}
			}
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
	// 方式2：递归遍历子目录，检查每个子站点目录中的敏感文件
	// 宝塔场景：/www/wwwroot/example.com/.env、/www/wwwroot/siteB/.git/config 等
	seen := make(map[string]bool) // 去重：同一文件只报告一次
	for _, sf := range w1SensitiveFiles {
		seen[sf.name] = true
	}
	// 包管理文件只在网站根目录报告，不在深层子目录中报告
	// 原因：assets/libs/jstree/composer.json 是第三方库自带的依赖描述文件，不是泄露
	// package.json / composer.json 不再算敏感文件
	// packageManifestFiles := map[string]bool{
	// phpinfo 相关文件也只在网站根目录级别报告
	// 原因：FastAdmin 的 application/admin/lang/zh-cn/.../info.php 是语言包文件，不是 phpinfo 页面
	// test.php 同理：FastAdmin 语言包目录下的 test.php 不是测试文件
	// 只有网站根目录的 info.php/phpinfo.php/test.php 才可能是泄露
	phpInfoFiles := map[string]bool{
		"info.php":          true,
		"phpinfo.php":       true,
		"phpinfo.php.bak":   true,
		"test.php":          true,
	}
	s.base.walkFiles(root, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			return nil
		}
		baseName := filepath.Base(path)
		// phpinfo 相关文件只在网站根目录级别报告
		if phpInfoFiles[baseName] {
			dir := filepath.Dir(path)
			absDir, _ := filepath.Abs(dir)
			absRoot, _ := filepath.Abs(root)
			if absDir != absRoot {
				return nil
			}
		}
		// package.json / composer.json 已从敏感列表移除，不再报告
		if !seen[baseName] {
			// 也检查目录名匹配（如 .git/ 目录下的 config 文件）
			dirName := filepath.Base(filepath.Dir(path))
			if seen[dirName] {
				// 找到了敏感目录下的文件，报告目录泄露
				dirPath := filepath.Dir(path)
				for _, sf := range w1SensitiveFiles {
					if sf.name == dirName+"/" {
						rb.AddFinding(
							sf.severity,
							fmt.Sprintf("敏感目录泄露: %s", dirName),
							sf.desc,
							dirPath,
							fmt.Sprintf("在路径 %s 发现敏感目录: %s", dirPath, dirName),
							"删除该敏感目录，或配置 Web 服务器拒绝访问",
							"删除目录后相关功能可能受影响；请确认用途后再删除",
						)
						break
					}
				}
				seen[dirName+"_reported"] = true // 避免同一目录重复报告
			}
			return nil
		}
		// 找到了敏感文件（在子目录中）
		for _, sf := range w1SensitiveFiles {
			if sf.name == baseName {
				fullPath := path
				// 避免与根目录检查重复
				if fullPath == filepath.Join(root, sf.name) {
					break
				}
		// .env 智能判断：如果同级或上级目录有 public/，说明是 FastAdmin/Laravel 框架项目
		// 运行目录是 public/，.env 在项目根目录外部不可达，跳过报告
		// 同时覆盖 .env.production.bak 等变体：只要文件名包含 .env 就检查
		if strings.Contains(baseName, ".env") {
			parentDir := filepath.Dir(fullPath)
			// 检查同级目录
			publicDir := filepath.Join(parentDir, "public")
			if _, err := os.Stat(publicDir); err == nil {
				break // 同级有 public/ 目录，.env 外部不可达，跳过
			}
			// 检查上级目录（如 /www/wwwroot/site/backend/.env → 检查 /www/wwwroot/site/public）
			parentOfParent := filepath.Dir(parentDir)
			publicDir2 := filepath.Join(parentOfParent, "public")
			if _, err := os.Stat(publicDir2); err == nil {
				break // 上级有 public/ 目录，.env 外部不可达，跳过
			}
			// 如果 .env 在 public/ 子目录中（如 uniapp/Vue 前端项目），
			// 前端 .env 只含 API 地址等非敏感配置，降为低危
			if strings.Contains(strings.ToLower(fullPath), "/public/") {
				rb.AddFinding(
					types.SeverityLow,
					fmt.Sprintf("敏感文件泄露: %s", sf.name),
					"前端项目的环境变量文件，通常只包含 API 地址等非敏感配置",
					fullPath,
					fmt.Sprintf("在路径 %s 发现前端 .env 文件", filepath.Dir(fullPath)),
					"如确认不含敏感信息可忽略；建议配置 Web 服务器拒绝访问 .env 文件",
					"前端 .env 通常无安全风险",
				)
				break
			}
		}
				rb.AddFinding(
					sf.severity,
					fmt.Sprintf("敏感文件泄露: %s", sf.name),
					sf.desc,
					fullPath,
					fmt.Sprintf("在路径 %s 发现敏感文件: %s", filepath.Dir(fullPath), sf.name),
					"删除该敏感文件，或配置 Web 服务器拒绝访问",
					"删除文件后相关功能可能受影响；请确认文件用途后再删除",
				)
				break
			}
		}
		return nil
	})
}

// scanHTTP 通过 HTTP 探测敏感文件是否可访问
// 遍历 w1SensitiveFiles 全列表，但通过通用页面过滤和指纹去重排除误报
func (s *W1SensitiveFileScanner) scanHTTP(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	// 响应指纹去重：很多站点（SPA/反向代理）对所有路径返回同一个 200 页面
	// 记录第一个 200 响应的内容指纹，后续相同指纹的响应跳过
	var firstBodyHash string
	var firstBodySize int
	// 已报告的文件名去重
	reported := make(map[string]bool)
	// 反代短路：如果连续多个路径返回相同的通用页面，判定为反代/SPA 站点，跳过后续探测
	genericHitCount := 0
	skipRemaining := false
	for _, sf := range w1SensitiveFiles {
		if reported[sf.name] {
			continue
		}
		// 反代短路：已经判定为反代站点，不再发请求
		if skipRemaining {
			break
		}
		url := strings.TrimRight(baseURL, "/") + "/" + sf.name
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		// 非 200 响应，不是敏感文件暴露
		if resp.StatusCode != 200 {
			continue
		}

		// 排除虚假页面（404/403/宝塔停站等）
		if isBogusResponse(string(body)) {
			continue
		}

		// 检查是否为通用 HTML 页面（SPA fallback / 反向代理默认页）
		if isGenericHTMLResponse(body, resp.Header.Get("Content-Type")) {
			bodyHash := hashBody(body)
			if firstBodyHash == "" {
				firstBodyHash = bodyHash
				firstBodySize = len(body)
			}
			// 通用页面跳过
			genericHitCount++
			// 连续 3 个路径都返回相同通用页面 → 判定为反代站点，跳过剩余探测
			if genericHitCount >= 3 {
				skipRemaining = true
			}
			continue
		}

		// 响应指纹去重：与第一个通用页面指纹相同的也跳过
		if firstBodyHash != "" && len(body) == firstBodySize {
			bodyHash := hashBody(body)
			if bodyHash == firstBodyHash {
				genericHitCount++
				if genericHitCount >= 3 {
					skipRemaining = true
				}
				continue
			}
		}

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
		reported[sf.name] = true
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
	"www.rar", "backup.rar",
	"database.sql", "db.sql", "dump.sql", "backup.sql",
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
	// 响应指纹去重：很多站点（SPA/反向代理）对所有路径返回同一个 200 页面
	var firstBodyHash string
	for _, bn := range w2BackupFileNames {
		url := strings.TrimRight(baseURL, "/") + "/" + bn
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			// 排除虚假页面（404/403/宝塔停站等）
			if isBogusResponse(string(body)) {
				continue
			}
			// 检查是否为通用 HTML 页面（SPA fallback / 反向代理默认页）
			if isGenericHTMLResponse(body, resp.Header.Get("Content-Type")) {
				bodyHash := hashBody(body)
				if firstBodyHash == "" {
					firstBodyHash = bodyHash
				}
				// 通用页面跳过
				continue
			}
			// 响应指纹去重
			if firstBodyHash != "" {
				bodyHash := hashBody(body)
				if bodyHash == firstBodyHash {
					continue
				}
			}
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
	// create_function：收紧为要求与用户输入同出现，避免 vendor 库正常使用误报
	{regexp.MustCompile(`create_function\s*\([^\n]{0,80}\$_(GET|POST|REQUEST|COOKIE)`), "create_function()+用户输入", types.SeverityHigh},
	{regexp.MustCompile(`file_put_contents\s*\(\s*["'].*\.(php|phtml|jsp|asp|aspx)`), "file_put_contents写Webshell", types.SeverityCritical},
	{regexp.MustCompile(`\bbase64_decode\s*\(\s*["'][A-Za-z0-9+/=]{100,}`), "长base64解码", types.SeverityHigh},
	// 纯十六进制混淆模式已禁用：误报率极高（PhpSpreadsheet XmlScanner、jQuery 等正常代码都会触发）
	// 真正的 webshell 检测靠危险函数+混淆组合（如 eval(base64_decode()) 等已在上面定义）
	// {regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "十六进制混淆", types.SeverityLow},
	// 外部JS引用：已禁用（每个 HTML 文件都有 <script src="https://...">，误报率极高）
	// 真正的恶意 JS 注入靠 "document.write注入外部脚本" 模式检测
	// {regexp.MustCompile(`<script[^>]*src\s*=\s*["']https?://[^"']+["']`), "外部JS引用", types.SeverityLow},
	// 隐藏 iframe：要求 src 指向外部 URL 且 display:none（排除正常 UI iframe）
	{regexp.MustCompile(`<iframe[^>]*src\s*=\s*["']https?://[^"']+["'][^>]*style\s*=\s*["'].*display\s*:\s*none`), "隐藏iframe", types.SeverityHigh},
// 零尺寸 iframe 挂马：要求同时有 src 指向外部 URL（排除前端框架的正常 UI iframe 和后台模板）
{regexp.MustCompile(`<iframe[^>]*src\s*=\s*["']https?://[^"']+["'][^>]*width\s*=\s*["']?0["']?[^>]*height\s*=\s*["']?0["']?`), "零尺寸iframe挂马", types.SeverityHigh},
	{regexp.MustCompile(`document\.write\s*\(\s*unescape\s*\(`), "document.write(unescape())", types.SeverityHigh},
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
	// 长十六进制混淆：已禁用（PhpSpreadsheet XmlScanner 会触发 10+ 连续 \xHH）
	// {regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "长十六进制混淆", types.SeverityMedium},
	{regexp.MustCompile(`eval\s*\(\s*gzdecode\s*\(`), "eval(gzdecode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*strrev\s*\(`), "eval(strrev())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*convert_uudecode\s*\(`), "eval(convert_uudecode())", types.SeverityCritical},
	// 短十六进制混淆：已禁用（正常 JS/PHP 代码中 6 个连续 \xHH 太常见）
	// {regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "短十六进制混淆", types.SeverityLow},
	{regexp.MustCompile(`eval\s*\(\s*pack\s*\(`), "eval(pack())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*chr\s*\(`), "eval(chr())", types.SeverityCritical},
	// 双转义十六进制混淆：去掉此模式（正常 JS 中 \x\xHH 也很常见）
	// {regexp.MustCompile(`\\x\\x[0-9a-fA-F]{2}`), "双转义十六进制混淆", types.SeverityMedium},
	{regexp.MustCompile(`eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET|REQUEST)`), "eval(base64_decode($_POST))", types.SeverityCritical},
	{regexp.MustCompile(`file_put_contents\s*\(\s*\$_(POST|GET|REQUEST)`), "file_put_contents写用户输入", types.SeverityCritical},
	{regexp.MustCompile(`fwrite\s*\(\s*\$.*\$_(POST|GET|REQUEST)`), "fwrite写用户输入", types.SeverityCritical},
	{regexp.MustCompile(`@?system\s*\(\s*base64_decode\s*\(`), "system(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`@?exec\s*\(\s*base64_decode\s*\(`), "exec(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`@?passthru\s*\(\s*base64_decode\s*\(`), "passthru(base64_decode())", types.SeverityCritical},
	{regexp.MustCompile(`@?shell_exec\s*\(\s*base64_decode\s*\(`), "shell_exec(base64_decode())", types.SeverityCritical},
	// Unicode转义混淆：已禁用（moment.js locale、PHP XML处理等正常代码会触发）
	// {regexp.MustCompile(`\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}`), "Unicode转义混淆", types.SeverityLow},
	{regexp.MustCompile(`eval\s*\(\s*urldecode\s*\(`), "eval(urldecode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*rawurldecode\s*\(`), "eval(rawurldecode())", types.SeverityCritical},
	{regexp.MustCompile(`eval\s*\(\s*substr\s*\(`), "eval(substr())", types.SeverityCritical},
	// ===== 新增：更高级 Webshell 检测模式 =====
	// 变量函数调用型 Webshell：已禁用（误报率极高，$var($other) 在正常 PHP 框架中极其常见）
	// {regexp.MustCompile(`\$\w+\s*\(\s*\$\w+\s*\)`), "变量函数调用型Webshell", types.SeverityHigh},
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
	// Webshell 常见特征字符串（收紧：去掉过短的 c99/r57/wso 等避免误报正常 JS）
	{regexp.MustCompile(`(?i)GodMode|b374k|m1n1|shellphp|IndoXploit`), "已知Webshell特征", types.SeverityCritical},
	{regexp.MustCompile(`(?i)phpspy|phpjackal|NCC-Group|RootShell`), "已知Webshell名称", types.SeverityCritical},
	// 已知 Webshell 家族名（c99/r57/wso/NST/phplist）：此前因误报 JS/CSS 被整体移除，
	// 但 detectMalwarePatterns 现已按 phpOnlyPatterns 门控——这些模式只在 .php 文件中
	// 匹配，正常 JS/CSS 不再进入判定，可安全恢复对经典木马家族的识别。
	{regexp.MustCompile(`(?i)\bc99\.shell|r57\.shell|wso\.php|NST\.View|phpList\b`), "已知Webshell家族", types.SeverityCritical},
	// 可疑的 PHP 变量拼接执行：收紧为 eval($var=...) 形式，避免误报 $name=$_POST['name'] 这种正常表单处理
	{regexp.MustCompile(`(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$\w+\s*=\s*\$_(POST|GET|REQUEST)`), "eval执行用户输入赋值", types.SeverityCritical},
	// Content-Disposition 注入检测
// Content-Disposition 注入：已禁用（FastAdmin/ThinkPHP 导出功能中 header('Content-Disposition:...') 是正常操作）
	// {regexp.MustCompile(`Content-Disposition\s*:.*\r?\n\s*\r?\n`), "Header注入检测", types.SeverityHigh},
	// 超长变量名混淆：已禁用（正常代码中 hash 变量名常超 40 字符）
	// {regexp.MustCompile(`\$[a-z0-9_]{40,}`), "超长变量名混淆", types.SeverityMedium},
	// 可疑的 null byte 注入
	// Null Byte 注入：已禁用（正则中的 \0 和字符串中的 %00 在正常代码中太常见）
	// {regexp.MustCompile(`%00|\\x00|\\0`), "Null Byte注入", types.SeverityHigh},
// 恶意 iframe 注入（更多变体）——要求同时有外部 src，避免 FastAdmin/ThinkPHP 后台模板误报
{regexp.MustCompile(`<iframe[^>]*src\s*=\s*["']https?://[^"']+["'][^>]*width\s*=\s*["']?0["']?[^>]*height\s*=\s*["']?0["']?`), "零尺寸iframe挂马", types.SeverityHigh},
	{regexp.MustCompile(`<iframe[^>]*src\s*=\s*["']javascript:`), "JavaScript协议iframe", types.SeverityCritical},
	// document.write 写入外部脚本
	{regexp.MustCompile(`document\.write\s*\(\s*['"]<script[^>]*src\s*=`), "document.write注入外部脚本", types.SeverityHigh},
	//可疑的 setTimeout/setInterval 执行外部代码
	{regexp.MustCompile(`setTimeout\s*\(\s*['"]?\w+\(\)\s*\{.*eval\s*\(`), "setTimeout+eval混淆", types.SeverityHigh},
	// Base64 编码的 PHP 标签
	// Base64 编码的 PHP 标签：收紧为只匹配完整 PD9waHAg（<?php）和 PD8gZXZhbCg（<? eval(）
	{regexp.MustCompile(`(?i)PD9waHAg|PD8gZXZhbA`), "Base64编码PHP标签", types.SeverityHigh},
	// str_replace 长字符串混淆：已禁用（正常代码中 str_replace 常用于长字符串替换）
	// {regexp.MustCompile(`str_replace\s*\(\s*["'][^"']{50,}`), "str_replace长字符串混淆", types.SeverityMedium},
	// goto 混淆控制流：已禁用（PHP 正常代码也使用 goto 进行流程控制）
	// {regexp.MustCompile(`goto\s+\w+\s*;.*goto\s+\w+\s*;`), "goto混淆控制流", types.SeverityHigh},

	// ===== 多语言 Webshell 检测模式 =====
	// --- Python Webshell 检测 ---
	// Python os.system 执行用户输入
	{regexp.MustCompile(`os\.system\s*\(\s*(request|input|argv|os\.environ)`), "Python os.system执行用户输入", types.SeverityCritical},
	// Python subprocess 执行用户输入
	{regexp.MustCompile(`subprocess\.(Popen|call|run|check_output)\s*\(.*(?:request|input|argv)`), "Python subprocess执行用户输入", types.SeverityCritical},
	// Python eval/exec 执行用户输入
	{regexp.MustCompile(`\b(eval|exec)\s*\(\s*(request|input|os\.environ|sys\.argv)`), "Python eval/exec执行用户输入", types.SeverityCritical},
	// Python base64 解码后执行
	{regexp.MustCompile(`(?:eval|exec)\s*\(\s*base64\.b64decode`), "Python base64解码执行", types.SeverityCritical},
	// Python pickle 反序列化攻击
	{regexp.MustCompile(`pickle\.loads\s*\(\s*(request|input|__import__)`), "Python pickle反序列化", types.SeverityCritical},
	// Python importlib 动态导入用户输入
	{regexp.MustCompile(`importlib\.(import_module|__import__)\s*\(\s*(request|input|os\.environ)`), "Python动态导入用户输入", types.SeverityCritical},
	// Python Flask/Django 命令注入
	{regexp.MustCompile(`(?i)(?:os\.system|subprocess|eval|exec)\s*\(.*(?:request\.(GET|POST|args|form|cookies)|flask\.request)`), "Python Web框架命令注入", types.SeverityCritical},

	// --- Node.js Webshell 检测 ---
	// Node.js child_process 执行用户输入
	{regexp.MustCompile(`child_process\.(exec|execSync|spawn|spawnSync|fork)\s*\(\s*(?:req\.(query|body|params|cookies|headers)|process\.argv)`), "Node.js child_process执行用户输入", types.SeverityCritical},
	// Node.js eval/Function 执行用户输入
	{regexp.MustCompile(`(?:eval|new\s+Function)\s*\(\s*(?:req\.(query|body|params)|process\.argv)`), "Node.js eval执行用户输入", types.SeverityCritical},
	// Node.js Buffer base64 解码后 eval
	{regexp.MustCompile(`eval\s*\(\s*(?:Buffer\.from|atob)\s*\(.*base64`), "Node.js base64解码执行", types.SeverityCritical},
	// Node.js vm 模块执行用户输入
	{regexp.MustCompile(`vm\.(runInNewContext|runInThisContext|compileFunction)\s*\(\s*(?:req\.|process\.)`), "Node.js vm沙箱执行用户输入", types.SeverityCritical},
	// Node.js require 动态加载用户输入
	{regexp.MustCompile(`require\s*\(\s*(?:req\.(query|body|params)|process\.argv)`), "Node.js动态require用户输入", types.SeverityCritical},

	// --- Ruby Webshell 检测 ---
	// Ruby system/exec 执行用户输入
	{regexp.MustCompile(`(?:system|exec|spawn|IO\.popen|open3|` + "`" + `)\s*\(?.*(?:params|request|ARGV|ENV)`), "Ruby命令执行用户输入", types.SeverityCritical},
	// Ruby eval 执行用户输入
	{regexp.MustCompile(`\beval\s*\(\s*(?:params|request|ARGV|ENV)`), "Ruby eval执行用户输入", types.SeverityCritical},
	// Ruby send 动态方法调用
	{regexp.MustCompile(`\.send\s*\(\s*(?:params|request)`), "Ruby动态方法调用用户输入", types.SeverityHigh},
	// Ruby ERB 注入
	{regexp.MustCompile(`<%=\s*(?:system|exec|eval|IO\.popen|` + "`" + `)`), "Ruby ERB命令注入", types.SeverityCritical},

	// --- Java Webshell 检测 ---
	// Java Runtime.exec 执行用户输入
	{regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\s*\(.*(?:request\.(getParameter|getHeader)|request\.getQueryString)`), "Java Runtime.exec执行用户输入", types.SeverityCritical},
	// Java ProcessBuilder 执行用户输入
	{regexp.MustCompile(`ProcessBuilder\s*\(.*(?:request\.(getParameter|getHeader)|request\.getQueryString)`), "Java ProcessBuilder执行用户输入", types.SeverityCritical},
	// Java 反射调用执行用户输入
	{regexp.MustCompile(`Method\.invoke\s*\(.*(?:request\.(getParameter|getHeader)|request\.getQueryString)`), "Java反射执行用户输入", types.SeverityCritical},
	// Java ScriptEngine 执行用户输入
	{regexp.MustCompile(`ScriptEngine\s*\(.*(?:eval|invoke)\s*\(.*request\.(getParameter|getHeader)`), "Java ScriptEngine执行用户输入", types.SeverityCritical},
	// Java JSP Expression Language 注入
	{regexp.MustCompile(`\$\{.*(?:Runtime|exec|ProcessBuilder|cmd)`), "JSP EL表达式注入", types.SeverityCritical},
	// Java ObjectInputStream 反序列化
	{regexp.MustCompile(`ObjectInputStream\s*\(.*(?:request\.(getInputStream|getReader))`), "Java反序列化用户输入", types.SeverityCritical},
	// Java Class.forName 动态加载
	{regexp.MustCompile(`Class\.forName\s*\(\s*(?:request\.(getParameter|getHeader)|request\.getQueryString)`), "Java动态类加载用户输入", types.SeverityCritical},
	// Java URLClassLoader 加载远程代码
	{regexp.MustCompile(`URLClassLoader\s*\(.*new\s+URL\s*\(.*request\.`), "Java远程类加载用户输入", types.SeverityCritical},

	// --- Go Webshell 检测 ---
	// Go os/exec 执行用户输入（限制距离 80 字符）
	{regexp.MustCompile(`exec\.(Command|CommandContext)\s*\([^\n]{0,80}(?:r\.(URL|Form|Header)|os\.Args)`), "Go exec执行用户输入", types.SeverityCritical},
	// Go 反射执行用户输入（限制距离 80 字符）
	{regexp.MustCompile(`reflect\.(Call|Method)\s*\([^\n]{0,80}(?:r\.(URL|Form|Header)|os\.Args)`), "Go反射执行用户输入", types.SeverityHigh},

	// --- 通用 Webshell 检测（跨语言）---
// 通用：从环境变量执行命令（各种语言）
	// 收紧：要求 os.environ[...] 与命令执行函数在同一行，且排除纯读取环境变量的场景
	// 避免匹配 simulator.py 等项目源码中 os.getenv('CONFIG') + subprocess 的正常组合
	{regexp.MustCompile(`(?:os\.system|subprocess\.(?:run|call|Popen|check)|child_process\.(?:exec|spawn)|IO\.popen|Runtime\.exec)\s*\([^\n]{0,40}os\.environ(?:viron)?(?:\[|\.)`), "从环境变量执行命令", types.SeverityHigh},
	// 通用：Base64 编码的命令执行
	// 收紧：要求匹配 base64_decode/base64.b64decode/atob 等解码函数，而非泛化 base64 关键词
	// 避免框架正常使用 base64 编码存储配置/数据时误报
	{regexp.MustCompile(`(?:eval|exec|system|os\.system|subprocess|child_process)\s*\([^\n]{0,80}(?:base64_decode|base64_decode|b64decode|atob|Buffer\.from)\s*\(`), "Base64编码命令执行", types.SeverityCritical},
	// 通用：HTTP 请求参数直接传入命令执行函数
	// 收紧：要求匹配确切的 HTTP 参数语法（$_GET/$_POST/$_REQUEST 或 request.GET/request.POST 等），
	// 不再匹配泛化的 req/param 关键词（框架中 exec($param) 是正常的回调执行）
	{regexp.MustCompile(`(?:os\.system|subprocess|child_process|exec|spawn|IO\.popen|Runtime|ProcessBuilder)\s*\([^\n]{0,80}(?:\$_(?:GET|POST|REQUEST|COOKIE)\[|request\.(?:GET|POST|Form|Query|Body)|r\.(?:URL|Form|Header)|req\.(?:Query|Body|Form|Param)|input\.(?:get|post|request))`), "HTTP参数直接命令执行", types.SeverityCritical},
	// 通用：反向 Shell 模式
	{regexp.MustCompile(`(?:bash|sh|zsh|nc|ncat|netcat|python|perl|ruby|php|node)\s+.*(?:-i|interactive|/dev/tcp|/dev/udp|\bnc\b).*\d+\.\d+\.\d+\.\d+`), "反向Shell模式", types.SeverityCritical},
	// 通用：Webshell 特征字符串
	// 通用：Webshell 代码特征字符串（要求多个高危特征同时出现，避免单关键词误报）
	// 旧规则只匹配 webshell|backdoor 等单词，vendor 库的注释/字符串会误报
	// 新规则要求同时匹配 webshell/backdoor 关键词 + 命令执行函数，或匹配完整的 webshell 调用模式
	{regexp.MustCompile(`(?i)(?:webshell|backdoor|reverse_shell|cmd_shell|pwned|owned|rootkit)[^\n]{0,100}(?:system|exec|eval|shell|passthru|popen|proc_open|os\.system|subprocess|child_process)\s*\(`), "Webshell特征字符串", types.SeverityHigh},
	// 通用：文件下载并执行（wget/curl 管道到 shell 解释器）
	// 收紧：要求匹配实际的下载命令语法（curl/wget + URL + | bash/sh），
	// 跳过 urllib/requests/http 等泛化关键词（框架正常 HTTP 客户端会误报）
	// 限制距离：下载命令和管道执行需在同一行 120 字符内
// 远程下载并执行：收紧为要求管道 + 立即执行，排除注释和变量中的 URL
	{regexp.MustCompile(`(?:wget|curl|fetch)\s+(?:https?://|ftp://)[^\n|]{0,80}\|\s*(?:bash|sh|python|perl|ruby|php|node)\b`), "远程下载并执行", types.SeverityCritical},
	// 通用：Webshell 命令分发器
	{regexp.MustCompile(`(?:action|cmd|command|do|func|op|option)\s*[:=]\s*(?:system|exec|eval|shell|passthru|popen|proc_open|os\.system|subprocess|child_process)`), "Webshell命令分发器", types.SeverityCritical},
}

// w3CDNWhitelist 常见 CDN 域名，外部 JS 引用指向这些域名时不报告
var w3CDNWhitelist = []string{
	"cdn.", "googleapis.com", "jsdelivr.net", "unpkg.com",
	"cdnjs.cloudflare.com", "ajax.googleapis.com", "stackpath.",
	"bootcdn.net", "cdn.bootcss.com", "cdn.staticfile.org",
	"lib.sinaapp.com", "upcdn.b0.upaiyun.com", "cdn.bytedance.com",
	"lf3-cdn-tos.bytecdntp.com", "lf6-cdn-tos.bytecdntp.com",
	// 常见前端库 CDN
	"code.jquery.com", "cdn.jsdelivr.net", "maxcdn.bootstrapcdn.com",
	"use.fontawesome.com", "kit.fontawesome.com",
	"cdn.bootcdn.net", "unpkg.zhimg.com",
	"cdn.bootcss.com", "cdn.staticfile.org",
	"apps.bdimg.com", "cdn.bdstatic.com",
	// 百度统计/Google Analytics 等统计 SDK
	"hm.baidu.com", "www.google-analytics.com", "googletagmanager.com",
	// 常见广告 SDK
	"pagead2.googlesyndication.com", "cdn.zeuskey.com",
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

// w3WebShellExtensions 需要检测的 Web 脚本文件扩展名（所有服务端+前端脚本）
var w3WebShellExtensions = []string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
	".jsp", ".jspx", ".asp", ".aspx", ".ashx",
	".html", ".htm", ".js", ".ts",
	// Python 后端
	".py", ".pyw", ".wsgi",
	// Node.js 后端
	".js", // .js 同时属于前端和 Node.js 后端
	".mjs", ".cjs",
	".ejs", ".hbs", ".handlebars",
	// Ruby 后端
	".rb", ".erb",
	// Go 后端（Go 编译为二进制，但有时源码部署）
	".go",
	// Java 后端（除 JSP 外）
	".java", ".class", ".groovy", ".kt", ".kts",
	// C/C++ 后端（FastCGI 等）
	".c", ".cpp", ".cc", ".h",
	// Shell 脚本
	".sh", ".bash", ".zsh",
	// Perl
	".pl", ".pm",
	// Lua
	".lua",
	// ASP Classic
	".asa",
	// ColdFusion
	".cfm", ".cfc",
	// SSR (Server-Side Rendering)
	".shtml",
}

// w3ServerScriptExtensions 服务端脚本扩展名（用于熵值检测等仅服务端适用的场景）
// 不含 .js/.ts/.html/.htm 等前端文件，因为前端文件高熵值通常由 minify 引起
var w3ServerScriptExtensions = []string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
	".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asa",
	".py", ".pyw", ".wsgi",
	".mjs", ".cjs", // Node.js 后端模块
	".rb", ".erb",
	".go",
	".groovy",
	".pl", ".pm",
	".lua",
	".cfm", ".cfc",
	".shtml",
}

// isServerScriptFile 判断文件是否为服务端脚本（不含前端 JS/HTML）
func isServerScriptFile(ext string) bool {
	for _, e := range w3ServerScriptExtensions {
		if ext == e {
			return true
		}
	}
	return false
}

// isPHPFile 判断是否为 PHP 文件
func isPHPFile(ext string) bool {
	return ext == ".php" || ext == ".phtml" || ext == ".php3" || ext == ".php4" || ext == ".php5" || ext == ".phps"
}

// isPythonFile 判断是否为 Python 文件
func isPythonFile(ext string) bool {
	return ext == ".py" || ext == ".pyw" || ext == ".wsgi"
}

// isNodeFile 判断是否为 Node.js 后端文件
func isNodeFile(ext string) bool {
	return ext == ".mjs" || ext == ".cjs" || ext == ".ejs" || ext == ".hbs"
}

// isRubyFile 判断是否为 Ruby 文件
func isRubyFile(ext string) bool {
	return ext == ".rb" || ext == ".erb"
}

// isJavaBackendFile 判断是否为 Java 后端文件（不含 JSP）
func isJavaBackendFile(ext string) bool {
	return ext == ".java" || ext == ".groovy" || ext == ".kt" || ext == ".kts"
}

// isShellScriptFile 判断是否为 Shell 脚本
func isShellScriptFile(ext string) bool {
	return ext == ".sh" || ext == ".bash" || ext == ".zsh"
}

// isPerlFile 判断是否为 Perl 文件
func isPerlFile(ext string) bool {
	return ext == ".pl" || ext == ".pm"
}

// isLuaFile 判断是否为 Lua 文件
func isLuaFile(ext string) bool {
	return ext == ".lua"
}

// isCLikeFile 判断是否为 C/C++/Go 文件
func isCLikeFile(ext string) bool {
	return ext == ".go" || ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".h"
}

// isFrontendFile 判断是否为前端文件（JS/HTML/CSS/TS）
func isFrontendFile(ext string) bool {
	return ext == ".js" || ext == ".ts" || ext == ".html" || ext == ".htm" || ext == ".css" || ext == ".vue" || ext == ".jsx" || ext == ".tsx"
}

// isNodeJSFile 智能判断 .js 文件是否为 Node.js 后端文件（而非前端 JS）
// 通过内容特征检测：require/http/express/child_process 等模块导入
// 以及缺少 DOM 操作（document/window 等前端 API）
func isNodeJSFile(data []byte) bool {
	content := string(data)
	// Node.js 后端特征：CommonJS require 模块导入
	hasRequire := strings.Contains(content, "require(") || strings.Contains(content, "require (")
	// Node.js 后端特征：http/https/express/fs/path/os 等核心模块
	hasNodeModules := strings.Contains(content, "require('http'") || strings.Contains(content, "require(\"http\"") ||
		strings.Contains(content, "require('https'") || strings.Contains(content, "require(\"https\"") ||
		strings.Contains(content, "require('express'") || strings.Contains(content, "require(\"express\"") ||
		strings.Contains(content, "require('fs'") || strings.Contains(content, "require(\"fs\"") ||
		strings.Contains(content, "require('path'") || strings.Contains(content, "require(\"path\"") ||
		strings.Contains(content, "require('os'") || strings.Contains(content, "require(\"os\"") ||
		strings.Contains(content, "require('child_process'") || strings.Contains(content, "require(\"child_process\"") ||
		strings.Contains(content, "require('crypto'") || strings.Contains(content, "require(\"crypto\"") ||
		strings.Contains(content, "import http from") || strings.Contains(content, "import express from") ||
		strings.Contains(content, "from 'http'") || strings.Contains(content, "from \"http\"") ||
		strings.Contains(content, "from 'express'") || strings.Contains(content, "from \"express\"") ||
		strings.Contains(content, "from 'fs'") || strings.Contains(content, "from \"fs\"") ||
		strings.Contains(content, "process.env") || strings.Contains(content, "process.argv")
	// 前端特征：DOM 操作
	hasDOM := strings.Contains(content, "document.") || strings.Contains(content, "window.") ||
		strings.Contains(content, "document.getElementById") || strings.Contains(content, "addEventListener") ||
		strings.Contains(content, "querySelector") || strings.Contains(content, "createElement") ||
		strings.Contains(content, "innerHTML") || strings.Contains(content, "React.") ||
		strings.Contains(content, "Vue.") || strings.Contains(content, "createApp") ||
		strings.Contains(content, "export default {") // Vue SFC 组件

	// 有 Node.js 模块导入且没有 DOM 操作 → Node.js 后端
	if hasNodeModules {
		return true
	}
	// 有 require 但无 DOM，也可能是 Node.js（但 require 也用于打包工具，保守一点只认 Node 模块）
	if hasRequire && !hasDOM {
		return true
	}
	return false
}

// w3IsFrontendBuildDir 判断目录是否为纯前端编译产物目录
// 通过检查目录名和内容特征判断
var w3FrontendBuildDirNames = map[string]bool{
	"dist": true, "build": true, "assets": true, "static": true,
	"_nuxt": true, "_next": true, ".nuxt": true, ".next": true,
	"node_modules": true, "vendor": true, // 前端依赖
}

// 包级预编译正则：W3 扫描在文件遍历回调中使用，循环内 MustCompile 会在
// 万级文件的站点上产生上万次无谓的编译开销（CPU + 内存分配）
var (
	// urlExtractRegex 从外部JS引用匹配中提取完整 URL
	urlExtractRegex = regexp.MustCompile(`https?://[^"'\s]+`)
// w3SuspiciousNamePattern 短随机/哈希式命名的脚本文件（可能是 Webshell）
// 支持多语言：PHP/Python/JS/JSP/ASP 等
// 注意：只匹配纯哈希/随机命名的文件，不匹配有意义的缩写
// - 8-16 位纯十六进制哈希：如 3a8f7b2c9d1e.php
// - 1-2 字母 + 3-4 位纯数字：如 a1234.php、ab5678.js（真正的 Webshell 命名模式）
// - 纯数字：如 1234.php
// 不匹配：iec104.py（IEC 104 协议）、log10.php（数学函数）等有意义的缩写
w3SuspiciousNamePattern = regexp.MustCompile(`^[0-9a-f]{8,16}\.(php|py|js|jsp|asp|aspx)$|^[a-z]{1,2}[0-9]{3,4}\.(php|py|js|jsp|asp|aspx)$|^\d{3,4}\.(php|py|js|jsp|asp|aspx)$`)
	// w3DangerousFuncRegex 危险函数调用（eval/system/exec 等）
	w3DangerousFuncRegex = regexp.MustCompile(`\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(`)
)

// w3HighEntropyThreshold 高熵值阈值（大于此值可能为加密/混淆内容）
// 提高到 7.5 以减少 minified JS 和加密配置文件的误报
const w3HighEntropyThreshold = 7.5

// w3MinFileSizeEntropy 熵值检测的最小文件大小（太小文件熵值不准确）
// 提高到 4KB 以减少小文件误报
const w3MinFileSizeEntropy = 4096

// Scan 执行 W3 网站挂马/篡改检测
func (s *W3TamperScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	if target.Path == "" {
		findings := rb.GetFindings()
		setSubScanner(findings, "W3")
		return findings, nil
	}

	// 不再粗暴跳过 dist/build 等目录，而是智能分析文件内容
	// 攻击者可能在任意目录植入 Webshell，包括前端编译目录中夹杂的恶意 JS

	// 1. 恶意代码模式检测 + 熵值检测
	s.detectMalwarePatterns(rb, target.Path)

	// 2. 文件哈希基线检测（篡改检测）
	s.detectTampering(rb, target.Path)

	// 3. 可疑文件特征检测（最近创建、可疑权限等）
	s.detectSuspiciousFiles(rb, target.Path)

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
		// 跳过 sourcemap 文件
		if strings.HasSuffix(baseName, ".js.map") || strings.HasSuffix(baseName, ".css.map") {
			return nil
		}
		// 跳过 chunk 文件和 vendor 文件（前端编译产物中的块文件，命名如 chunk-*.js, vendor-*.js）
		if strings.HasPrefix(baseName, "chunk-") || strings.HasPrefix(baseName, "vendor-") ||
			strings.HasPrefix(baseName, "runtime-") || strings.HasPrefix(baseName, "polyfill-") {
			return nil
		}

		// 跳过大于 2MB 的文件（Webshell 通常很小，大文件通常是正常业务代码）
		// 从 1MB 提升到 2MB：部分正常 PHP 文件超过 1MB 会被跳过，
		// 但在遍历计数到达上限前跳过的大文件不消耗计数，导致后续文件无法被扫描
		if info.Size() > 2*1024*1024 {
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
		// 智能识别文件语言类型，按语言匹配对应的恶意模式
		isPHP := isPHPFile(ext)
		isPython := isPythonFile(ext)
		isNode := isNodeFile(ext) || (ext == ".js" && isNodeJSFile(data)) // .js 可能是前端也可能是 Node.js
		isRuby := isRubyFile(ext)
		isJavaBackend := isJavaBackendFile(ext) || ext == ".jsp" || ext == ".jspx"
		isGo := ext == ".go"
		// isShell/isPerl/isLua 用于后续通用模式检测的上下文判断
		isShell := isShellScriptFile(ext)
		isPerl := isPerlFile(ext)
		isLua := isLuaFile(ext)
		_ = isShell // Shell 脚本使用通用模式检测
		_ = isPerl // Perl 脚本使用通用模式检测
		// 安装脚本标记（install.sh / deploy.sh 等使用 curl|bash 是正常模式）
		lowerBase := strings.ToLower(baseName)
		isInstallScript := lowerBase == "install.sh" || lowerBase == "setup.sh" ||
			lowerBase == "deploy.sh" || lowerBase == "entrypoint.sh" ||
			lowerBase == "install.bash" || lowerBase == "setup.bash" ||
			lowerBase == "deploy.bash" || lowerBase == "entrypoint.bash" ||
			(strings.HasPrefix(lowerBase, "install") && strings.HasSuffix(lowerBase, ".sh")) ||
			(strings.HasPrefix(lowerBase, "deploy") && strings.HasSuffix(lowerBase, ".sh")) ||
			(strings.HasPrefix(lowerBase, "smoke_test") && strings.HasSuffix(lowerBase, ".sh")) ||
			(strings.HasPrefix(lowerBase, "test") && strings.HasSuffix(lowerBase, ".sh"))
		_ = isLua  // Lua 脚本使用通用模式检测
		isFrontend := isFrontendFile(ext) && !isNode // 纯前端 JS/TS/HTML/CSS

		// 各语言专用模式名称集合
		// PHP 专用模式（只在 PHP 文件中检测）
		phpOnlyPatterns := map[string]bool{
			"已知Webshell名称":            true,
			"已知Webshell特征":            true,
			"已知Webshell家族":            true,
			"eval执行用户输入赋值":           true,
			"eval(base64_decode())":     true,
			"eval(gzinflate())":        true,
			"eval(gzuncompress())":     true,
			"eval(str_rot13())":        true,
			"assert($_POST/GET)":       true,
			"eval($_POST/GET)":         true,
			"system($_POST/GET)":       true,
			"exec($_POST/GET)":         true,
			"passthru($_POST/GET)":     true,
			"shell_exec($_POST/GET)":   true,
			"preg_replace /e 修饰符":      true,
			"create_function()+用户输入":   true,
			"file_put_contents写Webshell": true,
			"长base64解码":               true,
			"chmod修改脚本权限":             true,
			"move_uploaded_file上传PHP": true,
			"eval直接执行用户输入":           true,
			"assert直接执行用户输入":         true,
			"call_user_func执行用户输入":    true,
			"call_user_func_array执行用户输入": true,
			"popen执行用户输入":             true,
			"proc_open执行用户输入":         true,
			"pcntl_exec执行用户输入":        true,
			"eval(gzdecode())":        true,
			"eval(strrev())":         true,
			"eval(convert_uudecode())": true,
			"eval(pack())":           true,
			"eval(chr())":            true,
			"eval(base64_decode($_POST))": true,
			"file_put_contents写用户输入":  true,
			"fwrite写用户输入":            true,
			"system(base64_decode())": true,
			"exec(base64_decode())":  true,
			"passthru(base64_decode())": true,
			"shell_exec(base64_decode())": true,
			"eval(urldecode())":      true,
			"eval(rawurldecode())":   true,
			"eval(substr())":         true,
			"上传文件执行":               true,
			"preg_replace /e变体":      true,
			"assert(base64_decode())": true,
			"assert(gzinflate())":    true,
			"assert(gzuncompress())": true,
			"call_user_func(base64_decode())": true,
			"call_user_func_array(base64_decode())": true,
			"array_map执行用户输入":       true,
			"array_filter执行用户输入":     true,
			"array_walk执行用户输入":      true,
			"usort执行用户输入":           true,
			"array_map(base64_decode())": true,
			"反射执行用户输入":             true,
			"动态函数调用Webshell":        true,
			"PHP短标签执行用户输入":          true,
			"array_map+assert组合":    true,
			"array_filter+assert组合":  true,
			"array_walk+assert组合":   true,
			"Base64编码PHP标签":         true,
		}

		// Python 专用模式
		pythonOnlyPatterns := map[string]bool{
			"Python os.system执行用户输入":  true,
			"Python subprocess执行用户输入":  true,
			"Python eval/exec执行用户输入":  true,
			"Python base64解码执行":       true,
			"Python pickle反序列化":      true,
			"Python动态导入用户输入":        true,
			"Python Web框架命令注入":       true,
		}

		// Node.js 专用模式
		nodeOnlyPatterns := map[string]bool{
			"Node.js child_process执行用户输入": true,
			"Node.js eval执行用户输入":         true,
			"Node.js base64解码执行":         true,
			"Node.js vm沙箱执行用户输入":       true,
			"Node.js动态require用户输入":      true,
		}

		// Ruby 专用模式
		rubyOnlyPatterns := map[string]bool{
			"Ruby命令执行用户输入":  true,
			"Ruby eval执行用户输入": true,
			"Ruby动态方法调用用户输入": true,
			"Ruby ERB命令注入":  true,
		}

		// Java 专用模式
		javaOnlyPatterns := map[string]bool{
			"Java Runtime.exec执行用户输入":     true,
			"Java ProcessBuilder执行用户输入":   true,
			"Java反射执行用户输入":         true,
			"Java ScriptEngine执行用户输入":     true,
			"JSP EL表达式注入":           true,
			"Java反序列化用户输入":          true,
			"Java动态类加载用户输入":         true,
			"Java远程类加载用户输入":         true,
		}

		// Go 专用模式
		goOnlyPatterns := map[string]bool{
			"Go exec执行用户输入":   true,
			"Go反射执行用户输入": true,
		}

		for _, mp := range w3MalwarePatterns {
			// 按语言类型门控：非对应语言的文件跳过该语言专用模式
			if !isPHP && phpOnlyPatterns[mp.name] {
				continue
			}
			if !isPython && pythonOnlyPatterns[mp.name] {
				continue
			}
			if !isNode && nodeOnlyPatterns[mp.name] {
				continue
			}
			if !isRuby && rubyOnlyPatterns[mp.name] {
				continue
			}
			if !isJavaBackend && javaOnlyPatterns[mp.name] {
				continue
			}
			if !isGo && goOnlyPatterns[mp.name] {
				continue
			}

		// 对已知框架 vendor 目录下的文件，跳过所有恶意代码模式检测
		// 框架核心代码中的 system/exec/base64/require/iframe 等是正常功能调用，不是 Webshell
		// vendor 下的真正 Webshell 由 YARA 规则单独覆盖
		if isKnownVendorFramework(path) {
			continue
		}
		// 对知名前端库文件（jquery-ui、bootstrap 等），跳过所有恶意代码模式检测
		// 这些库中的 iframe/javascript: 组合是正常功能代码
		if isKnownFrontendLibrary(path) {
			continue
		}
		// 对安装脚本文件，跳过"远程下载并执行"检测
		// install.sh / deploy.sh / setup.sh 等安装部署脚本使用 curl|bash 是正常模式
		// (isInstallScript 已在外层定义)
		// 通用模式（跨语言）对所有脚本文件都检测
		// 但对纯前端 JS/TS/HTML，只保留 HTML 注入类检测（隐藏 iframe、挖矿脚本、SEO 挂马等）
		// 跳过所有代码执行类模式（eval/document.write/fetch/exec 等在正常前端 JS 中极其常见）
		if isFrontend {
			// 前端 JS 只检测以下模式（HTML 注入类，不会误报）
			frontendAllowedPatterns := map[string]bool{
				"隐藏iframe":              true,
				"零尺寸iframe挂马":         true,
				"JavaScript协议iframe":     true, // 前端 JS 中降为低危
				"SEO挂马隐藏层":            true,
				"隐藏链接挂马":             true,
				"挖矿脚本注入":             true,
				"CoinHive挖矿对象":         true,
				"CPU挖矿循环":            true,
				"document.write(unescape())": true, // 只匹配 unescape 组合，不会误报
				// "document.write注入外部脚本" 已移除：正常前端 JS 用此模式加载组件/广告/统计，
				// 真正的恶意注入会通过"隐藏iframe"、"挖矿脚本注入"等模式捕获
				"setTimeout+eval混淆":       true, // 只匹配 setTimeout+eval 组合
			}
			if !frontendAllowedPatterns[mp.name] {
				continue
			}
		}
		// 安装脚本跳过"远程下载并执行"检测
		if isInstallScript && mp.name == "远程下载并执行" {
			continue
		}
			if mp.pattern.Match(data) {
				// 外部JS引用模式需要排除 CDN
				if mp.name == "外部JS引用" {
					// 提取匹配到的 URL，检查是否为 CDN
					matches := mp.pattern.FindStringSubmatch(string(data))
					if len(matches) > 0 {
						// 从整个匹配中提取 URL（包级预编译正则，避免扫描循环内反复编译）
						urlMatch := urlExtractRegex.FindString(matches[0])
						if urlMatch != "" && isCDNURL(urlMatch) {
							continue // 跳过 CDN 引用
						}
					}
				}
				// 动态调整严重程度：前端 JS 文件中的 javascript:iframe/隐藏iframe 等降为低危
				// 这些模式在正常前端库（如 elfinder、ace editor）中是合法用法
				effectiveSeverity := mp.severity
				if isFrontend && (mp.name == "JavaScript协议iframe" || mp.name == "隐藏iframe" || mp.name == "零尺寸iframe挂马") {
					effectiveSeverity = types.SeverityLow
				}
				// 动态描述：前端 JS 中不报"疑似 Webshell"，改为"需人工确认"
				descSuffix := "疑似 Webshell 或挂马"
				if isFrontend {
					descSuffix = "前端库文件中常见，需人工确认是否为恶意注入"
				}
				rb.AddFinding(
					effectiveSeverity,
					fmt.Sprintf("检测到恶意代码模式: %s", mp.name),
					fmt.Sprintf("文件 %s 包含可疑代码模式: %s，%s", path, mp.name, descSuffix),
					path,
					fmt.Sprintf("文件: %s，匹配模式: %s", path, mp.name),
					"隔离或删除该文件，检查最近修改记录，排查入侵途径",
					"删除文件后相关功能将不可用；隔离后可在面板查看并恢复",
			)
				break // 每个文件只报告一次恶意模式
			}
		}

		// YARA 引擎扫描（与正则 + 熵值检测并存）
		// 对纯前端 JS/TS 文件跳过 YARA 扫描（minified JS 中的 Base64 字符串会触发 YARA 规则误报）
		if s.base.yaraEngine != nil && s.base.yaraEngine.IsAvailable() && !isFrontend {
			// 跳过 vendor 目录下已知框架的核心文件
			// 这些框架文件中正常的 PHP 函数调用（如 system($_POST) 用于队列处理）会被 YARA 规则误匹配
			if !isKnownVendorFramework(path) && !isInstallScript {
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
		}

		// 熵值检测：高熵值可能表示加密/混淆内容
		// 检测所有服务端脚本文件（PHP/JSP/ASP/Python/Ruby/Go/Shell等），
		// 对 Node.js 后端文件也检测，但不检测纯前端 JS/HTML（minified JS 误报太多）
		isServerScript := isServerScriptFile(ext) || isNode

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

// detectSuspiciousFiles 检测可疑文件特征：最近创建的脚本文件、可疑文件权限、隐藏文件等
func (s *W3TamperScanner) detectSuspiciousFiles(rb *scannercommon.ReportBuilder, root string) {
	// 检测最近 7 天内新建或修改的可执行脚本文件
	recentThreshold := time.Now().Add(-7 * 24 * time.Hour)
	// 可疑的文件名模式（短随机字符串命名，常见于 Webshell）
	// 注意：32位MD5哈希命名的文件通常是框架缓存（ThinkPHP/Laravel），不算可疑
	// 只匹配 8-16 位的短哈希文件名（包级预编译，避免每个扫描目录重复编译）
	suspiciousNamePattern := w3SuspiciousNamePattern

	s.base.walkFilesForMalware(root, func(path string, info os.FileInfo) error {
		ext := strings.ToLower(filepath.Ext(path))
		// 检测所有服务端脚本文件，包括多语言后端
		isServerScript := isServerScriptFile(ext)
		if !isServerScript {
			// 对 .js 文件，检查是否为 Node.js 后端
			if ext == ".js" {
				data, err := s.base.readFileLimited(path)
				if err == nil && isNodeJSFile(data) {
					isServerScript = true
				}
			}
			if !isServerScript {
				return nil
			}
		}

		baseName := filepath.Base(path)

		// 1. 检测可疑文件名（短随机哈希命名的脚本文件，可能是 Webshell）
		// 跳过 vendor 目录：框架库文件名可能恰好匹配模式（如 log10.php）
		if suspiciousNamePattern.MatchString(baseName) && !isKnownVendorFramework(path) {
			rb.AddFinding(
				types.SeverityLow,
				fmt.Sprintf("可疑文件名: %s", baseName),
				fmt.Sprintf("文件 %s 使用随机/哈希式命名，请确认是否为框架缓存或正常文件", path),
				path,
				fmt.Sprintf("文件: %s，修改时间: %s，大小: %d 字节", path, info.ModTime().Format("2006-01-02 15:04"), info.Size()),
				"人工审查文件内容，确认为合法文件后可加入白名单；如为恶意文件则隔离删除",
				"删除文件后相关功能可能不可用；请先确认文件用途",
			)
		}

		// 2. 检测最近创建的服务端脚本文件（可能是新植入的 Webshell）
		if info.ModTime().After(recentThreshold) && info.Size() < 10*1024 {
			// 只报告小文件（Webshell 通常小于 10KB）
			data, err := s.base.readFileLimited(path)
			if err == nil && len(data) > 0 {
				content := string(data)
				// 多语言危险函数检测
				// PHP: eval/system/exec/passthru/shell_exec/popen/proc_open
				// Python: os.system/subprocess/eval/exec
				// Node.js: child_process/eval/Function/vm
				// Ruby: system/exec/eval/IO.popen
				// Java: Runtime/ProcessBuilder/ScriptEngine
				// Go: exec.Command
				matches := w3DangerousFuncRegex.FindAllString(content, -1)
				// 统计不同的危险函数调用数
				uniqueFuncs := make(map[string]bool)
				for _, m := range matches {
					uniqueFuncs[m] = true
				}
				// 多语言用户输入检测
				hasUserInput := strings.Contains(content, "$_POST") || strings.Contains(content, "$_GET") ||
					strings.Contains(content, "$_REQUEST") || strings.Contains(content, "$_COOKIE") ||
					strings.Contains(content, "$_FILES") || // PHP
					strings.Contains(content, "request.GET") || strings.Contains(content, "request.POST") ||
					strings.Contains(content, "request.args") || strings.Contains(content, "request.form") ||
					strings.Contains(content, "request.cookies") || // Python Flask/Django
					strings.Contains(content, "req.query") || strings.Contains(content, "req.body") ||
					strings.Contains(content, "req.params") || strings.Contains(content, "req.cookies") ||
					strings.Contains(content, "req.headers") || // Node.js
					strings.Contains(content, "params[") || strings.Contains(content, "params.") || // Ruby
					strings.Contains(content, "request.getParameter") || strings.Contains(content, "request.getHeader") ||
					strings.Contains(content, "request.getQueryString") || // Java
					strings.Contains(content, "r.URL.Query()") || strings.Contains(content, "r.Form.Get(") ||
					strings.Contains(content, "r.Header.Get(") || // Go
					strings.Contains(content, "ARGV") || strings.Contains(content, "argv") || // Shell/Perl
					strings.Contains(content, "os.Args") // Go
				// 多语言危险函数检测补充
				if isPythonFile(ext) {
					pythonDangerous := regexp.MustCompile(`(?:os\.system|subprocess\.(?:Popen|call|run|check_output)|\beval\b|\bexec\b|pickle\.loads|__import__|importlib\.import_module)\s*\(`)
					for _, m := range pythonDangerous.FindAllString(content, -1) {
						uniqueFuncs[m] = true
					}
				} else if ext == ".js" || isNodeFile(ext) {
					nodeDangerous := regexp.MustCompile(`(?:child_process\.(?:exec|spawn|fork)|\beval\b|new\s+Function|vm\.(?:runInNewContext|runInThisContext))\s*\(`)
					for _, m := range nodeDangerous.FindAllString(content, -1) {
						uniqueFuncs[m] = true
					}
				} else if isRubyFile(ext) {
					rubyDangerous := regexp.MustCompile(`(?:\bsystem\b|\bexec\b|spawn|IO\.popen|\beval\b|\.send\s*\()\s*`)
					for _, m := range rubyDangerous.FindAllString(content, -1) {
						uniqueFuncs[m] = true
					}
				} else if isJavaBackendFile(ext) || ext == ".jsp" || ext == ".jspx" {
					javaDangerous := regexp.MustCompile(`(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Method\.invoke|ScriptEngine.*eval|Class\.forName)\s*\(`)
					for _, m := range javaDangerous.FindAllString(content, -1) {
						uniqueFuncs[m] = true
					}
				} else if ext == ".go" {
					goDangerous := regexp.MustCompile(`(?:exec\.Command|exec\.CommandContext|reflect\.(?:Call|Method))\s*\(`)
					for _, m := range goDangerous.FindAllString(content, -1) {
						uniqueFuncs[m] = true
					}
				}
				// 判定条件（平衡漏报与误报）：
				//   - ≥2 个危险函数 → 疑似 Webshell
				//   - ≥1 个危险函数 + 用户输入 → 同样报告。
				//     此前要求"必须 ≥2 个函数"，导致真实世界最常见的一句话木马
				//     `<?php eval($_POST[1]);`（仅 1 个函数）全部漏报——修复误报不能把真告警一起归零。
				//     文件名本身已命中可疑命名 + 近 7 天新增，误报概率可控。
				suspicious := len(uniqueFuncs) >= 2 || (len(uniqueFuncs) >= 1 && hasUserInput)
				if suspicious {
					reason := "多个命令执行函数"
					if len(uniqueFuncs) < 2 {
						reason = "命令执行函数 + 用户输入"
					}
					rb.AddFinding(
						types.SeverityHigh,
						fmt.Sprintf("最近创建的可疑脚本: %s", baseName),
						fmt.Sprintf("文件 %s 在最近 7 天内创建，且包含%s和用户输入，疑似 Webshell", path, reason),
						path,
						fmt.Sprintf("文件: %s，创建时间: %s，大小: %d 字节，危险函数: %v", path, info.ModTime().Format("2006-01-02 15:04"), info.Size(), uniqueFuncs),
						"隔离文件并人工审查代码内容；确认恶意后删除，排查入侵途径",
						"隔离后相关功能不可用；确认安全后可恢复",
					)
				}
			}
		}

	// 3. 检测可疑的文件权限（shell 脚本和 Python/Ruby 等需关注执行权限）
	// PHP/JSP/ASP 等服务端脚本由 Web 服务器解析，755 权限是面板默认值，不算安全问题
	//
	// 策略调整：不再单纯因为"有执行权限"就报告（每个 Python 项目的 .py 文件几乎都有执行权限）
	// 只在以下高风险组合下报告：
	//   a) 文件在最近 7 天内创建/修改 + 有执行权限 → 可能是新植入的恶意脚本
	//   b) shell 脚本（.sh/.bash/.zsh）有执行权限 + 最近 7 天内创建 → 可能是攻击者植入的后门
	// 普通的项目文件有执行权限是正常的，不报告
	isShellScript := isShellScriptFile(ext) || isPythonFile(ext) || isPerlFile(ext) || isRubyFile(ext) || isLuaFile(ext)
		if isShellScript && info.Mode()&0111 != 0 {
			// 只报告最近 7 天内创建/修改的可执行脚本
			recentThreshold := time.Now().AddDate(0, 0, -7)
			if info.ModTime().After(recentThreshold) {
				// 跳过 vendor 目录
				if isKnownVendorFramework(path) {
					// vendor 下的文件不报告执行权限
				} else {
					rb.AddFinding(
						types.SeverityLow,
						fmt.Sprintf("最近创建的可执行脚本: %s", baseName),
						fmt.Sprintf("文件 %s 在最近 7 天内创建且设置了执行权限（%v），请确认是否为预期行为", path, info.Mode().Perm()),
						path,
						fmt.Sprintf("文件: %s，修改时间: %s，权限: %v", path, info.ModTime().Format("2006-01-02 15:04"), info.Mode().Perm()),
						"人工审查文件内容，确认为合法文件后可忽略；如为恶意文件则移除执行权限并隔离",
						"移除执行权限不影响 Web 服务器解析该文件",
					)
				}
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

// w4AdminPaths 常见后台路径（与宝塔安全检测对齐，覆盖主流 CMS 后台）
var w4AdminPaths = []string{
	"/admin/", "/admin/login", "/admin/login.php", "/admin/index.php",
	"/manage/", "/manager/",
	"/wp-admin/", "/wp-login.php",
	"/administrator/",
	"/admin.php", "/login.php", "/login/",
	"/phpmyadmin/", "/phpMyAdmin/",
	"/backend/", "/dashboard/", "/console/",
	"/panel/", "/cp/",
	"/user/login", "/member/login",
	// 新增：常见 CMS / 框架后台路径
	"/wp-admin/admin-ajax.php",
	"/admin/index", "/admin/manage",
	"/system/", "/system/login",
	"/admincp/", "/admincp.php",
	"/bbs/admin/", "/forum/admin/",
	"/dede/", "/dede/login.php", // 织梦
	"/e/admin/", "/e/admin/index.php", // 帝国
	"/api/admin/", "/rest/admin/",
	"/admin.html", "/manage.html",
	"/config.php", "/install.php", "/install/",
	"/debug/", "/test/",
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
			// 排除虚假页面（404/403/宝塔停站等）
			if isBogusResponse(bodyStr) {
				continue
			}
			lowerBody := strings.ToLower(bodyStr)
			// 检查是否为登录页面
			isLoginPage := strings.Contains(lowerBody, "login") ||
				strings.Contains(lowerBody, "密码") ||
				strings.Contains(lowerBody, "password") ||
				strings.Contains(lowerBody, "登录")

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		bodyStr := strings.ToLower(string(body))
		// 排除虚假页面（404/403/宝塔停站等）
		if isBogusResponse(bodyStr) {
			continue
		}
		// 检查页面内容是否为真正的 phpMyAdmin 页面
		// 必须包含 phpMyAdmin 特征关键词，不能只匹配 "db" 这种通用词
		if !strings.Contains(bodyStr, "phpmyadmin") &&
			!strings.Contains(bodyStr, "phpadmin") &&
			!strings.Contains(bodyStr, "php admin") &&
			!strings.Contains(bodyStr, "mysql") &&
			!strings.Contains(bodyStr, "database") {
			// 页面内容不包含 phpMyAdmin 相关关键词，不是真正的 phpMyAdmin 页面
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
		// 去重：同一端口在整个扫描周期内只报告一次
		// 多站点指向同一台服务器，用 host:port 做去重 key 会导致同一端口被报告几十次
		// 改为只用 port 做去重 key，每个端口只报告一次
		dedupKey := fmt.Sprintf("dbport:%d", db.port)
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
	// 去重：整个扫描周期只检测一次（多站点指向同一台服务器）
	dedupKey := "redis:nopass"
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
	// 去重：整个扫描周期只检测一次（多站点指向同一台服务器）
	dedupKey := "mongo:noauth"
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
	// 去重：整个扫描周期只检测一次（多站点指向同一台服务器）
	dedupKey := "mysql:emptypass"
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
			// 排除虚假页面（404/403/宝塔停站等）
			if isBogusResponse(bodyStr) {
				continue
			}
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
	// 去重：整个扫描周期只检测一次（多站点指向同一台服务器）
	dedupKey := "es:unauth"
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
			// 排除虚假页面（404/403/宝塔停站等）
			if isBogusResponse(bodyStr) {
				continue
			}
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

// w6GlobalScannedFiles 全局配置文件去重（每轮扫描开始前由 ResetDedupCaches 清空）
// 避免同一轮扫描中多个站点重复扫描同一个 Nginx/Apache 配置文件
var (
	w6GlobalMu           sync.Mutex
	w6GlobalScannedFiles = make(map[string]bool)
)

// w6ConfigDirs Web 服务器配置文件目录
var w6ConfigDirs = []string{
	"/www/server/panel/vhost/nginx/",  // 宝塔站点 vhost 配置（安全头/弱协议等按站点配置在这里）
	"/www/server/nginx/conf/",         // 宝塔 Nginx 主配置目录
	"/www/server/apache/conf/",        // 宝塔 Apache 配置目录
	"/www/server/httpd/conf/",         // 宝塔 httpd 变体
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

	// 1. 只扫描与当前站点相关的配置文件
	// 避免对每个站点都扫描所有 vhost 文件（117 个站点 → 117×98=11466 个误报）
	if target.Path != "" {
		// 扫描当前站点路径下的配置文件（如果有）
		s.scanConfigFile(rb, target.Path)
	}

	// 2. 扫描当前站点对应的 vhost 配置文件
	// 从站点路径推断 vhost 文件名（宝塔命名规则：域名.conf 或 IP_端口.conf）
	if target.Path != "" {
		s.scanSiteVhostConfigs(rb, target.Path)
	}

	// 3. 扫描主配置文件（nginx.conf/httpd.conf 等）
	// 主配置只扫一次，使用全局去重
	s.scanMainConfigs(rb)

	// 4. HTTP 响应头检测
	baseURL := s.base.targetURL(target)
	if baseURL != "" {
		s.checkHTTPHeaders(ctx, rb, baseURL)
		// 5. SSL 弱协议检测
		s.checkSSLProtocol(ctx, rb, baseURL)
		// 6. 目录遍历检测
		s.checkDirectoryListing(ctx, rb, baseURL)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W6")
	return findings, nil
}

// scanSiteVhostConfigs 扫描与当前站点相关的 vhost 配置文件
func (s *W6ConfigScanner) scanSiteVhostConfigs(rb *scannercommon.ReportBuilder, sitePath string) {
	// 从站点路径提取域名/IP，推断对应的 vhost 文件名
	baseName := filepath.Base(sitePath)
	// 宝塔 vhost 目录
	vhostDirs := []string{
		"/www/server/panel/vhost/nginx/",
		"/www/server/panel/vhost/apache/",
	}

	// 去重：同一个配置文件不重复扫描
	scanned := make(map[string]bool)

	for _, dir := range vhostDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fileName := entry.Name()
			if !strings.HasSuffix(fileName, ".conf") {
				continue
			}
			// 精确匹配：文件名 == baseName.conf（如 aa.jjtt.net.conf）
			matched := fileName == baseName+".conf"
			if !matched {
				// 模糊匹配：文件名包含站点名（但排除过短的名称导致误匹配）
				// 例如 baseName=aa.jjtt.net，匹配 aa.jjtt.net.conf 和 aa.jjtt.net_ssl.conf
				domainPart := baseName
				if idx := strings.Index(domainPart, "_"); idx > 0 {
					domainPart = domainPart[:idx] // 取 IP_端口 中的 IP 部分
				}
				// 只对长度 > 6 的域名做模糊匹配（避免 a、ab 等短名误匹配）
				if len(domainPart) > 6 && strings.Contains(fileName, domainPart) {
					matched = true
				}
			}
			if matched {
				path := filepath.Join(dir, fileName)
				if !scanned[path] {
					scanned[path] = true
					s.scanConfigFile(rb, path)
				}
			}
		}
	}
}

// scanMainConfigs 扫描主配置文件（nginx.conf/httpd.conf 等）
// 使用全局去重，主配置只扫描一次
func (s *W6ConfigScanner) scanMainConfigs(rb *scannercommon.ReportBuilder) {
	mainConfigPaths := []string{
		"/www/server/nginx/conf/nginx.conf",
		"/etc/nginx/nginx.conf",
		"/www/server/apache/conf/httpd.conf",
		"/www/server/httpd/conf/httpd.conf",
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
	}
	for _, path := range mainConfigPaths {
		s.scanConfigFile(rb, path)
	}
}

// scanConfigFile 扫描单个配置文件
func (s *W6ConfigScanner) scanConfigFile(rb *scannercommon.ReportBuilder, path string) {
	// 跳过备份文件（.bak, .sg.bak, .old, .save, .orig, ~ 等）
	lowerPath := strings.ToLower(path)
	if strings.HasSuffix(lowerPath, ".bak") ||
		strings.HasSuffix(lowerPath, ".sg.bak") ||
		strings.HasSuffix(lowerPath, ".old") ||
		strings.HasSuffix(lowerPath, ".save") ||
		strings.HasSuffix(lowerPath, ".orig") ||
		strings.HasSuffix(lowerPath, "~") ||
		strings.HasSuffix(lowerPath, ".disabled") ||
		strings.HasSuffix(lowerPath, ".default") ||
		strings.HasSuffix(lowerPath, ".swp") {
		return
	}
	// 全局去重：同一配置文件在所有站点扫描中只扫描一次
	// 使用全局锁，不被 ResetDedupCaches 清空（配置文件不随站点变化）
	w6GlobalMu.Lock()
	if w6GlobalScannedFiles[path] {
		w6GlobalMu.Unlock()
		return
	}
	w6GlobalScannedFiles[path] = true
	w6GlobalMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// 检测 server_tokens on（仅在配置中显式写了 server_tokens on 时才报）
	if strings.Contains(content, "server_tokens") && strings.Contains(content, "on") &&
		!strings.Contains(content, "server_tokens off") &&
		(strings.Contains(content, "server_tokens on") || strings.Contains(content, "server_tokens  on")) {
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
	// 覆盖两类文件：
	//   1. 主配置（nginx.conf / httpd.conf 等）
	//   2. 站点级 vhost 配置（路径含 /vhost/ 的 .conf）——宝塔把安全头按站点配置在
	//      /www/server/panel/vhost/nginx/<站点>.conf 中，只查主配置会漏掉全部站点。
	//      vhost 按文件（即按站点）报告，标题含路径，不构成重复误报。
	isMainConfig := strings.HasSuffix(lowerPath, "nginx.conf") ||
		strings.HasSuffix(lowerPath, "httpd.conf") ||
		strings.HasSuffix(lowerPath, "apache2.conf")
	isVhostConfig := strings.Contains(lowerPath, "/vhost/") && strings.HasSuffix(lowerPath, ".conf")
	if isMainConfig || isVhostConfig {
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
		if !strings.Contains(content, "Referrer-Policy") {
			missingHeaders = append(missingHeaders, "Referrer-Policy")
		}
		if !strings.Contains(content, "Permissions-Policy") {
			missingHeaders = append(missingHeaders, "Permissions-Policy")
		}

		if len(missingHeaders) > 0 {
			// 区分 Nginx 和 Apache 的安全头配置语法
			isApache := strings.Contains(lowerPath, "/apache/") || strings.HasSuffix(lowerPath, "httpd.conf")
			suggestion := "建议添加以下安全头:\n"
			if isApache {
				suggestion += "  Header always set X-Frame-Options \"SAMEORIGIN\"\n"
				suggestion += "  Header always set X-Content-Type-Options \"nosniff\"\n"
				suggestion += "  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
				suggestion += "  Header always set X-XSS-Protection \"1; mode=block\"\n"
				suggestion += "  Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';\"\n"
				suggestion += "  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
				suggestion += "  Header always set Permissions-Policy \"geolocation=(),microphone=(),camera=()\"\n"
				suggestion += "  （需确保 mod_headers 已启用: a2enmod headers）"
			} else {
				suggestion += "  add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
				suggestion += "  add_header X-Content-Type-Options \"nosniff\" always;\n"
				suggestion += "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
				suggestion += "  add_header X-XSS-Protection \"1; mode=block\" always;\n"
				suggestion += "  add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';\" always;\n"
				suggestion += "  add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
				suggestion += "  add_header Permissions-Policy \"geolocation=(),microphone=(),camera=()\" always;"
			}

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
	}

	// 检测 SSL 弱协议
	// 注意：必须精确匹配 SSLv3 和 TLSv1（不含 TLSv1.1/1.2/1.3）
	if strings.Contains(content, "ssl_protocols") {
		// Go regexp 不支持 (?!...) lookahead，改用字符串匹配
		// 检测 SSLv3 或 TLSv1（但排除 TLSv1.0/TLSv1.1/TLSv1.2/TLSv1.3）
		hasWeakProto := false
		if strings.Contains(strings.ToLower(content), "sslv3") {
			hasWeakProto = true
		}
		// 检查 TLSv1 后面是否不跟 .数字（即不是 TLSv1.0/1.1/1.2/1.3）
		if !hasWeakProto && strings.Contains(strings.ToLower(content), "tlsv1") {
			// 找到所有 TLSv1 出现的位置，检查后面是否跟着 .数字
			lowerContent := strings.ToLower(content)
			idx := 0
			for {
				pos := strings.Index(lowerContent[idx:], "tlsv1")
				if pos == -1 {
					break
				}
				pos += idx
				after := lowerContent[pos+5:] // "tlsv1" 后面的内容
				// 如果后面不是 .数字，则是弱协议
				if len(after) == 0 || after[0] != '.' {
					hasWeakProto = true
					break
				}
				// 如果后面是 .数字（如 TLSv1.2），不是弱协议
				idx = pos + 5
			}
		}
		if hasWeakProto {
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
	// 注意：只检查 ssl_ciphers 行，不检查整个文件内容（注释中可能提到这些词）
	// 且要排除 !RC4/!DES/!MD5/!EXPORT 这种禁用写法（! 前缀表示禁用）
	if strings.Contains(content, "ssl_ciphers") {
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "ssl_ciphers") {
				continue
			}
			// 跳过注释行
			if strings.HasPrefix(line, "#") {
				continue
			}
			// 检查是否包含弱算法（排除 ! 前缀的禁用写法）
			// 使用正则确保匹配的是算法名而非注释
			hasWeakCipher := false
			weakCiphers := []string{"RC4", "DES", "MD5", "EXPORT", "PSK", "aNULL", "eNULL"}
			for _, cipher := range weakCiphers {
				// 匹配 !RC4（禁用）或 !DES 等，不算弱加密
				// 只匹配 RC4/DES/MD5/EXPORT 前面没有 ! 的
				idx := strings.Index(line, cipher)
				for idx >= 0 {
					// 检查前一个字符是否是 !
					if idx > 0 && line[idx-1] == '!' {
						// 这是禁用写法，跳过
					} else {
						hasWeakCipher = true
						break
					}
					// 继续搜索后面的
					nextIdx := strings.Index(line[idx+1:], cipher)
					if nextIdx < 0 {
						break
					}
					idx = idx + 1 + nextIdx
				}
				if hasWeakCipher {
					break
				}
			}
			if hasWeakCipher {
				rb.AddFinding(
					types.SeverityHigh,
					"弱加密套件启用",
					fmt.Sprintf("配置文件 %s 包含弱加密套件（RC4/DES/MD5/EXPORT）", path),
					path,
					fmt.Sprintf("文件: %s，ssl_ciphers 行包含弱加密算法", path),
					"使用强加密套件: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...';",
					"移除弱套件后部分旧客户端将无法连接",
				)
				break // 每个文件只报告一次
			}
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

	// 检测 client_max_body_size 过大
	// 注意：client_max_body_size 是 Nginx 指令，Apache 应使用 LimitRequestBody
	// Nginx 默认 1MB，未设置时并非安全问题，只有显式设置过大才有风险
	isApacheConfig := strings.Contains(lowerPath, "/apache/") || strings.Contains(content, "DocumentRoot") || strings.Contains(content, "DirectoryIndex")
	if (isMainConfig || isVhostConfig) && !isApacheConfig {
		// 只检查是否设置过大（> 100m）
		if strings.Contains(content, "client_max_body_size") {
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && strings.Contains(line, "client_max_body_size") {
					// 尝试提取数值
					fields := strings.Fields(line)
					for _, f := range fields {
						f = strings.TrimSuffix(strings.TrimSuffix(f, "m"), "M")
						if n, err := strconv.Atoi(f); err == nil && n > 100 {
							rb.AddFinding(
								types.SeverityLow,
								"client_max_body_size 过大",
								fmt.Sprintf("配置文件 %s 设置 client_max_body_size %dM，允许上传超大文件", path, n),
								path,
								fmt.Sprintf("文件: %s，client_max_body_size: %dM", path, n),
								"根据实际业务需求调小，如 client_max_body_size 20m;",
								"调小后大文件上传可能失败；需根据实际需求设置",
							)
							break
						}
					}
					break
				}
			}
		}
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

	// 检测 X-Powered-By 头泄露
	xPoweredBy := headers.Get("X-Powered-By")
	if xPoweredBy != "" {
		rb.AddFinding(
			types.SeverityLow,
			"X-Powered-By 头泄露",
			fmt.Sprintf("响应包含 X-Powered-By: %s，暴露了后端技术信息", xPoweredBy),
			baseURL,
			fmt.Sprintf("URL: %s，X-Powered-By: %s", baseURL, xPoweredBy),
			"关闭 X-Powered-By 头：Nginx 用 proxy_hide_header，PHP 设置 expose_php = Off",
			"隐藏后不影响功能",
		)
	}

	// 检测 Content-Security-Policy 头缺失
	if headers.Get("Content-Security-Policy") == "" {
		rb.AddFinding(
			types.SeverityLow,
			"Content-Security-Policy 头缺失",
			"响应缺少 Content-Security-Policy 头，页面容易受 XSS 和数据注入攻击",
			baseURL,
			fmt.Sprintf("URL: %s 响应未包含 CSP 头", baseURL),
			"添加响应头: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';",
			"配置 CSP 后部分内联脚本/样式可能不生效；需根据实际页面调整策略",
		)
	}

	// 检测 X-XSS-Protection 头缺失
	if headers.Get("X-XSS-Protection") == "" {
		rb.AddFinding(
			types.SeverityInfo,
			"X-XSS-Protection 头缺失",
			"响应缺少 X-XSS-Protection 头，旧版浏览器（IE/旧 Safari）的 XSS 过滤器未启用",
			baseURL,
			fmt.Sprintf("URL: %s 响应未包含 X-XSS-Protection 头", baseURL),
			"添加响应头: X-XSS-Protection: 1; mode=block",
			"现代浏览器已废弃此头，但旧浏览器仍依赖它",
		)
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
		// 使用 net.Dial + tls.Dial 替代 http.Client，避免创建 Transport 导致 goroutine 泄漏
		// 只需检测是否可连接，不需要完整 HTTP 响应
		host := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
		if idx := strings.Index(host, "/"); idx > 0 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx > 0 {
			host = host[:idx]
		}
		// 直接 TCP 连接
		conn, err := net.DialTimeout("tcp", host+":443", 2*time.Second)
		if err != nil {
			continue
		}
		// TLS 握手指定弱协议版本
		tlsConn := tls.Client(conn, &tls.Config{
			MinVersion:         ver,
			MaxVersion:         ver,
			InsecureSkipVerify: true,
		})
		tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		err = tlsConn.Handshake()
		tlsConn.Close()
		if err != nil {
			continue // 弱协议连接失败是好事
		}
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
	// 精简到 4 个最常见路径
	testPaths := []string{"/uploads/", "/data/", "/files/", "/static/"}
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
			// 排除虚假页面（404/403/宝塔停站等）
			if isBogusResponse(bodyStr) {
				continue
			}
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

// w7MaxLinks 单页最多检测的链接数（从 100 降到 50，平衡精度和性能）
const w7MaxLinks = 50

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
		// 超时、连接被拒等网络错误不判为失效链接（可能是 CDN 被墙、临时网络问题）
		// 只报告明确的 404/500 等 HTTP 状态码错误
		errStr := err.Error()
		if strings.Contains(errStr, "context deadline exceeded") ||
			strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "no such host") ||
			strings.Contains(errStr, "dial") ||
			strings.Contains(errStr, "EOF") {
			return
		}
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
		// 排除 Cloudflare/CDN 特殊状态码（520-524），这些不是目标网站的真实错误
		if resp.StatusCode >= 520 && resp.StatusCode <= 524 {
			return
		}
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
				// 跳过没有 host 的空 URL（如 href="http://" 或 href="https://"）
				// UEditor 等编辑器的模板文件可能包含占位符 URL
				stripped := strings.TrimPrefix(strings.TrimPrefix(href, "https://"), "http://")
				if stripped == "" || strings.HasPrefix(stripped, "/") || strings.HasPrefix(stripped, "?") {
					continue
				}
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

// ============================================================
// W10: 文件权限风险检测
// 检测世界可写（777/666）的关键文件和目录、
// 敏感文件权限过松、上传目录可执行等
// 与宝塔安全扫描的文件权限检测项对齐
// ============================================================

// W10FilePermissionScanner 文件权限风险检测扫描器
type W10FilePermissionScanner struct {
	base *WebSecurityGuard
}

func (s *W10FilePermissionScanner) Name() string       { return "websecurity" }
func (s *W10FilePermissionScanner) SubScanner() string { return "W10" }

// w10SensitiveExtensions 需要检查权限的敏感文件扩展名
var w10SensitiveExtensions = []string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
	".sh", ".bash", ".py", ".pl", ".rb",
	".conf", ".config", ".yml", ".yaml", ".json", ".xml", ".ini", ".env",
	".sql", ".db", ".sqlite", ".sqlite3",
	".key", ".pem", ".crt", ".p12", ".pfx",
}

// Scan 执行 W10 文件权限风险检测
func (s *W10FilePermissionScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	if target.Path == "" {
		findings := rb.GetFindings()
		setSubScanner(findings, "W10")
		return findings, nil
	}

	s.scanFilePermissions(rb, target.Path)

	findings := rb.GetFindings()
	setSubScanner(findings, "W10")
	return findings, nil
}

// scanFilePermissions 扫描文件权限
func (s *W10FilePermissionScanner) scanFilePermissions(rb *scannercommon.ReportBuilder, root string) {
	// 1. 检查根目录本身的权限
	checkDirPermission(rb, root, "网站根目录")

	// 2. 递归检查关键文件和目录的权限
	s.base.walkFiles(root, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			// 检查上传目录是否可执行
			lowerName := strings.ToLower(info.Name())
			if lowerName == "upload" || lowerName == "uploads" || lowerName == "uploadfile" ||
				lowerName == "attachment" || lowerName == "attachments" ||
				lowerName == "tmp" || lowerName == "temp" || lowerName == "cache" {
				checkDirPermission(rb, path, fmt.Sprintf("上传/临时目录 (%s)", info.Name()))
			}
			return nil
		}

		// 检查敏感文件的权限
		ext := strings.ToLower(filepath.Ext(path))
		for _, se := range w10SensitiveExtensions {
			if ext == se {
				checkFilePermission(rb, path, info)
				break
			}
		}

		// 检查配置文件
		baseName := strings.ToLower(filepath.Base(path))
		if strings.Contains(baseName, "config") || strings.Contains(baseName, "wp-config") ||
			strings.Contains(baseName, ".env") || strings.Contains(baseName, "database") ||
			strings.Contains(baseName, "password") || strings.Contains(baseName, "secret") {
			checkFilePermission(rb, path, info)
		}

		return nil
	})
}

// checkDirPermission 检查目录权限是否过松
func checkDirPermission(rb *scannercommon.ReportBuilder, path, label string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode()
	// 检查世界可写 (o+w)
	if mode&os.FileMode(0o002) != 0 {
		severity := types.SeverityHigh
		if label == "网站根目录" {
			severity = types.SeverityCritical
		}
		rb.AddFinding(
			severity,
			fmt.Sprintf("目录权限过松: %s", label),
			fmt.Sprintf("目录 %s 权限为 %v，允许任何用户写入，可能导致被植入 Webshell", path, mode.Perm()),
			path,
			fmt.Sprintf("路径: %s，当前权限: %v（世界可写）", path, mode.Perm()),
			"修复权限: chmod 755 目录（仅所有者可写）",
			"修复后部分程序可能因权限不足无法写入缓存/上传文件；需根据实际需求调整",
		)
	}
	// 检查 777 权限
	if mode.Perm() == os.FileMode(0o777) {
		rb.AddFinding(
			types.SeverityCritical,
			fmt.Sprintf("目录 777 权限: %s", label),
			fmt.Sprintf("目录 %s 权限为 777，任何用户可读/写/执行", path),
			path,
			fmt.Sprintf("路径: %s，权限: 777", path),
			"修复权限: chmod 755 目录",
			"修复后部分程序可能因权限不足无法写入缓存/上传文件",
		)
	}
}

// checkFilePermission 检查文件权限是否过松
func checkFilePermission(rb *scannercommon.ReportBuilder, path string, info os.FileInfo) {
	mode := info.Mode()
	// 检查世界可写
	if mode&os.FileMode(0o002) != 0 {
		ext := strings.ToLower(filepath.Ext(path))
		severity := types.SeverityHigh
		if ext == ".key" || ext == ".pem" || ext == ".pfx" || ext == ".env" || ext == ".sql" {
			severity = types.SeverityCritical
		}
		rb.AddFinding(
			severity,
			"文件权限过松（世界可写）",
			fmt.Sprintf("文件 %s 权限为 %v，允许任何用户写入，可能被篡改植入恶意代码", path, mode.Perm()),
			path,
			fmt.Sprintf("路径: %s，当前权限: %v（世界可写）", path, mode.Perm()),
			"修复权限: chmod 644 文件（仅所有者可写）",
			"修复后部分程序可能因权限不足无法写入配置/缓存文件",
		)
	}
	// 检查 777/666
	if mode.Perm() == os.FileMode(0o777) || mode.Perm() == os.FileMode(0o666) {
		rb.AddFinding(
			types.SeverityCritical,
			"文件权限 777/666",
			fmt.Sprintf("文件 %s 权限为 %v，任何用户可写", path, mode.Perm()),
			path,
			fmt.Sprintf("路径: %s，权限: %v", path, mode.Perm()),
			fmt.Sprintf("修复权限: chmod 644 %s", filepath.Base(path)),
			"修复后部分程序可能因权限不足无法写入文件",
		)
	}
}

// ============================================================
// W11: PHP 配置风险检测
// 检测 phpinfo() 暴露、危险函数未禁用、display_errors 开启、
// allow_url_include、expose_php 等 PHP 安全配置问题
// 与宝塔 PHP 安全检测项对齐
// ============================================================

// W11PHPConfigScanner PHP 配置风险检测扫描器
type W11PHPConfigScanner struct {
	base *WebSecurityGuard
}

func (s *W11PHPConfigScanner) Name() string       { return "websecurity" }
func (s *W11PHPConfigScanner) SubScanner() string { return "W11" }

// w11PhpConfigPaths 常见 PHP 配置文件路径
var w11PhpConfigPaths = []string{
	"/etc/php.ini",
	"/etc/php/php.ini",
	"/etc/php5/php.ini",
	"/etc/php7/php.ini",
	"/etc/php/7.0/php.ini",
	"/etc/php/7.1/php.ini",
	"/etc/php/7.2/php.ini",
	"/etc/php/7.3/php.ini",
	"/etc/php/7.4/php.ini",
	"/etc/php/8.0/php.ini",
	"/etc/php/8.1/php.ini",
	"/etc/php/8.2/php.ini",
	"/www/server/php/*/etc/php.ini", // 宝塔 PHP 配置
	"/www/server/php/*/php.ini",
	"/usr/local/php/etc/php.ini",
	"/usr/local/etc/php.ini",
	"/usr/local/etc/php/php.ini",
}

// w11DangerousFunctions 应该被禁用的 PHP 危险函数
var w11DangerousFunctions = []string{
	"exec", "system", "passthru", "shell_exec",
	"proc_open", "popen", "pcntl_exec",
	"eval", "assert",
	"dl",
	"show_source", "highlight_file",
	"ini_set", "ini_restore",
	"ini_alter", "putenv",
	"chmod", "chown", "chgrp",
	"link", "symlink",
	"mail",
}

// w11GlobalScannedFiles 全局 PHP 配置文件去重（不被 ResetDedupCaches 清空）
var (
	w11GlobalMu           sync.Mutex
	w11GlobalScannedFiles = make(map[string]bool)
)

// Scan 执行 W11 PHP 配置风险检测
func (s *W11PHPConfigScanner) Scan(ctx context.Context, target types.ScanTarget) ([]types.ScanFinding, error) {
	rb := scannercommon.NewReportBuilder("websecurity", target.Path)

	// 1. 扫描 PHP 配置文件
	s.scanPHPConfigFiles(rb)

	// 2. 检测网站目录中是否有 phpinfo() 调用
	if target.Path != "" {
		s.detectPhpInfoInCode(rb, target.Path)
	}

	// 3. 通过 HTTP 检测 PHP 信息泄露
	baseURL := s.base.targetURL(target)
	if baseURL != "" {
		s.detectPHPInfoHTTP(ctx, rb, baseURL)
	}

	findings := rb.GetFindings()
	setSubScanner(findings, "W11")
	return findings, nil
}

// scanPHPConfigFiles 扫描 PHP 配置文件
func (s *W11PHPConfigScanner) scanPHPConfigFiles(rb *scannercommon.ReportBuilder) {
	for _, pattern := range w11PhpConfigPaths {
		// 处理通配符路径（如 /www/server/php/*/etc/php.ini）
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, path := range matches {
			// 全局去重：同一 php.ini 在所有站点扫描中只扫描一次
			w11GlobalMu.Lock()
			if w11GlobalScannedFiles[path] {
				w11GlobalMu.Unlock()
				continue
			}
			w11GlobalScannedFiles[path] = true
			w11GlobalMu.Unlock()
			s.parsePHPIni(rb, path)
		}
	}
}

// parsePHPIni 解析 php.ini 文件
func (s *W11PHPConfigScanner) parsePHPIni(rb *scannercommon.ReportBuilder, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	lowerContent := strings.ToLower(content)

	// 1. 检测 display_errors 是否开启
	if matchLine(lowerContent, "display_errors", "on") {
		rb.AddFinding(
			types.SeverityHigh,
			"PHP display_errors 开启",
			fmt.Sprintf("PHP 配置 %s 中 display_errors 为 On，会在页面显示错误详情，泄露服务器路径等敏感信息", path),
			path,
			fmt.Sprintf("文件: %s，配置项: display_errors = On", path),
			"设置 display_errors = Off；开发环境可用 display_errors = stderr",
			"关闭后 PHP 错误不会在页面显示；需配合 error_log 记录错误",
		)
	}

	// 2. 检测 expose_php 是否开启
	if matchLine(lowerContent, "expose_php", "on") {
		rb.AddFinding(
			types.SeverityLow,
			"PHP expose_php 开启",
			fmt.Sprintf("PHP 配置 %s 中 expose_php 为 On，会在响应头 X-Powered-By 中暴露 PHP 版本号", path),
			path,
			fmt.Sprintf("文件: %s，配置项: expose_php = On", path),
			"设置 expose_php = Off",
			"关闭后不影响功能",
		)
	}

	// 3. 检测 allow_url_include 是否开启
	if matchLine(lowerContent, "allow_url_include", "on") {
		rb.AddFinding(
			types.SeverityCritical,
			"PHP allow_url_include 开启",
			fmt.Sprintf("PHP 配置 %s 中 allow_url_include 为 On，允许远程文件包含（RFI），极其危险", path),
			path,
			fmt.Sprintf("文件: %s，配置项: allow_url_include = On", path),
			"设置 allow_url_include = Off",
			"关闭后部分依赖远程包含的旧代码将无法工作",
		)
	}

	// 4. 检测 allow_url_fopen 是否开启
	if matchLine(lowerContent, "allow_url_fopen", "on") {
		rb.AddFinding(
			types.SeverityMedium,
			"PHP allow_url_fopen 开启",
			fmt.Sprintf("PHP 配置 %s 中 allow_url_fopen 为 On，允许 PHP 通过 URL 读取远程文件", path),
			path,
			fmt.Sprintf("文件: %s，配置项: allow_url_fopen = On", path),
			"如非必要，设置 allow_url_fopen = Off",
			"关闭后部分远程 API 调用、远程图片抓取等功能将失效",
		)
	}

	// 5. 检测危险函数是否未禁用
	disabledLine := findConfigLine(lowerContent, "disable_functions")
	missingFuncs := []string{}
	if disabledLine == "" || strings.Contains(disabledLine, "disable_functions =") {
		// disable_functions 为空或未设置
		for _, fn := range w11DangerousFunctions {
			if !strings.Contains(disabledLine, fn) {
				missingFuncs = append(missingFuncs, fn)
			}
		}
	} else {
		// 有设置但可能不全
		for _, fn := range w11DangerousFunctions {
			if !strings.Contains(disabledLine, fn) {
				missingFuncs = append(missingFuncs, fn)
			}
		}
	}
	if len(missingFuncs) > 0 {
		rb.AddFinding(
			types.SeverityHigh,
			"PHP 危险函数未禁用",
			fmt.Sprintf("PHP 配置 %s 中 disable_functions 未包含以下危险函数: %s", path, strings.Join(missingFuncs, ", ")),
			path,
			fmt.Sprintf("文件: %s，disable_functions 当前值: %s", path, strings.TrimSpace(disabledLine)),
			fmt.Sprintf("在 php.ini 中设置: \ndisable_functions = %s", strings.Join(w11DangerousFunctions, ",")),
			"禁用危险函数后部分需要执行系统命令的程序（如 Composer、Git 部署脚本等）将无法运行",
		)
	}

	// 6. 检测 open_basedir 是否未设置
	openBasedirLine := findConfigLine(lowerContent, "open_basedir")
	if openBasedirLine == "" || strings.Contains(openBasedirLine, "open_basedir =") {
		trimmed := strings.TrimSpace(openBasedirLine)
		if openBasedirLine == "" || strings.HasSuffix(trimmed, "=") ||
			strings.HasSuffix(trimmed, "= ") ||
			strings.HasSuffix(trimmed, "=\"\"") {
			rb.AddFinding(
				types.SeverityMedium,
				"PHP open_basedir 未设置",
				fmt.Sprintf("PHP 配置 %s 中 open_basedir 未设置，PHP 可以访问服务器上的任意文件", path),
				path,
				fmt.Sprintf("文件: %s，open_basedir 未设置或为空", path),
				"设置 open_basedir 限制 PHP 访问范围，如: open_basedir = /www/wwwroot/yoursite/:/tmp/",
				"设置后 PHP 无法访问指定范围外的文件；部分 CMS 可能需要额外路径",
			)
		}
	}
}

// matchLine 检查 php.ini 中某配置项是否为指定值
func matchLine(content, key, value string) bool {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, key) && strings.Contains(line, value) {
			return true
		}
	}
	return false
}

// findConfigLine 查找配置文件中某配置项所在行
func findConfigLine(content, key string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, key) {
			return line
		}
	}
	return ""
}

// detectPhpInfoInCode 检测代码中的 phpinfo() 调用
// 跳过 vendor 目录下的框架核心文件（Symfony/Laravel 等框架的 Process 组件正常使用 phpinfo 测试进程功能）
func (s *W11PHPConfigScanner) detectPhpInfoInCode(rb *scannercommon.ReportBuilder, root string) {
	s.base.walkFilesForMalware(root, func(path string, info os.FileInfo) error {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".php" && ext != ".phtml" && ext != ".php5" && ext != ".phps" {
			return nil
		}

	// 跳过 vendor 目录下的框架核心文件（统一排除函数）
	if isKnownVendorFramework(path) {
		return nil
	}

		data, err := s.base.readFileLimited(path)
		if err != nil {
			return nil
		}
		content := string(data)

		// 检测 phpinfo() 调用（排除注释中的）
		if strings.Contains(strings.ToLower(content), "phpinfo(") {
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(strings.ToLower(line))
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
					strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				if strings.Contains(trimmed, "phpinfo(") {
					rb.AddFinding(
						types.SeverityHigh,
						"phpinfo() 信息泄露",
						fmt.Sprintf("文件 %s 包含 phpinfo() 调用，会暴露服务器完整配置信息", path),
						path,
						fmt.Sprintf("文件: %s，包含: %s", path, strings.TrimSpace(line)),
						"删除 phpinfo() 调用；如需调试，使用后立即删除",
						"删除后无法通过该页面查看 PHP 配置；可用 php --ini 命令行替代",
					)
					break
				}
			}
		}

		return nil
	})
}

// detectPHPInfoHTTP 通过 HTTP 检测 PHP 信息泄露
func (s *W11PHPConfigScanner) detectPHPInfoHTTP(ctx context.Context, rb *scannercommon.ReportBuilder, baseURL string) {
	phpInfoPaths := []string{
		"/phpinfo.php", "/info.php", "/test.php", "/pi.php",
		"/php.php", "/p.php", "/i.php", "/inf.php",
		"/1.php", "/a.php",
	}
	for _, p := range phpInfoPaths {
		url := strings.TrimRight(baseURL, "/") + p
		resp, err := s.base.httpGet(ctx, url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyStr := strings.ToLower(string(body))
			// 排除虚假页面（404/403/宝塔停站等）
			if isBogusResponse(bodyStr) {
				continue
			}
			if strings.Contains(bodyStr, "phpinfo") || strings.Contains(bodyStr, "php version") ||
				strings.Contains(bodyStr, "configuration file") || strings.Contains(bodyStr, "loaded configuration") {
				rb.AddFinding(
					types.SeverityHigh,
					"phpinfo 页面可通过 HTTP 访问",
					fmt.Sprintf("URL %s 返回 PHP 信息页面，泄露服务器完整配置", url),
					url,
					fmt.Sprintf("URL: %s，HTTP状态: %d，页面包含 PHP 配置信息", url, resp.StatusCode),
					"删除该 PHP 文件，或配置 Web 服务器拒绝访问",
					"删除后无法通过该页面查看 PHP 配置",
				)
			}
		}
	}
}
