package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	hostnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/anomaly"
	"github.com/suoten/serverguard/internal/agent/conflict"
	"github.com/suoten/serverguard/internal/agent/correlation"
	"github.com/suoten/serverguard/internal/agent/decider"
	"github.com/suoten/serverguard/internal/agent/forecast"
	"github.com/suoten/serverguard/internal/agent/healthscore"
	"github.com/suoten/serverguard/internal/agent/knowledge"
	"github.com/suoten/serverguard/internal/agent/maintwindow"
	"github.com/suoten/serverguard/internal/agent/netquality"
	"github.com/suoten/serverguard/internal/agent/posture"
	"github.com/suoten/serverguard/internal/agent/probe"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/agent/sitediscovery"
	"github.com/suoten/serverguard/internal/baota"
	"github.com/suoten/serverguard/internal/comm"
	"github.com/suoten/serverguard/internal/config"
	"github.com/suoten/serverguard/internal/guards/ai"
	"github.com/suoten/serverguard/internal/guards/apm"
	"github.com/suoten/serverguard/internal/guards/attackwarn"
	"github.com/suoten/serverguard/internal/guards/cert"
	"github.com/suoten/serverguard/internal/guards/datagovern"
	"github.com/suoten/serverguard/internal/guards/devops"
	"github.com/suoten/serverguard/internal/guards/serversecurity"
	"github.com/suoten/serverguard/internal/guards/tuning"
	"github.com/suoten/serverguard/internal/guards/vulnscan"
	"github.com/suoten/serverguard/internal/guards/websecurity"
	"github.com/suoten/serverguard/internal/hub/panel"
	"github.com/suoten/serverguard/internal/hub/registry"
	"github.com/suoten/serverguard/internal/intel"
	"github.com/suoten/serverguard/internal/notifier"
	"github.com/suoten/serverguard/internal/report"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/version"
)

// API implements the Hub REST API.
// Endpoints:
//
//	GET  /api/servers              - list all servers
//	GET  /api/servers/:id          - get server details
//	GET  /api/servers/:id/metrics  - get server metrics
//	POST /api/servers/:id/restart  - restart a service on server
//	GET  /api/alerts               - list alerts
//	GET  /api/logs                 - get audit/action logs
//	GET  /api/status               - agent status
//	POST /api/emergency-stop       - trigger emergency stop
//	POST /api/emergency-resume     - resume from emergency stop
//	GET  /api/safety               - safety status
//	GET  /api/certs               - list certificates
//	GET  /api/guards              - list guard targets
type API struct {
	mu             sync.RWMutex
	storage        *storage.Storage
	safety         *safety.SafetyManager
	router         *gin.Engine
	auth           AuthConfig
	cfg            *config.Config
	configPath     string
	notifier       *notifier.Notifier
	probe          *probe.Probe
	scorer         *healthscore.Scorer
	siteDiscover   *sitediscovery.Discovery
	certGuard      *cert.CertGuard
	baotaDiscovery *baota.Discovery
	confirmManager *decider.ConfirmManager

	// 态势感知引擎（V4.x 智能调度，供 /api/posture 展示）
	postureEngine *posture.Engine

	// 登录防暴力破解：按来源 IP 统计失败次数，超限锁定一段时间。
	// 面板监听 0.0.0.0 时 /api/login 暴露在公网，无限制的密码尝试是真实风险。
	loginLimiter *loginLimiter

	// /api/status 响应缓存（3s TTL）：面板高频轮询接口，避免多标签页放大系统调用
	statusCache     gin.H
	statusCacheTime time.Time

	// 进程 TOP 缓存（避免每 5 秒全量扫描）
	topProcCache     *topProcCacheData
	topProcCacheTime time.Time

	// Phase 1 安全扫描模块
	webSecGuard     *websecurity.WebSecurityGuard
	vulnScanGuard   *vulnscan.VulnScanGuard
	serverSecGuard  *serversecurity.ServerSecurityGuard
	attackWarnGuard *attackwarn.AttackWarnGuard
	tuningAdvisor   *tuning.TuningAdvisor

	// CVE Feed Monitor（安全更新提醒）
	feedMonitor *vulnscan.FeedMonitor

	// 每日巡检报告生成器
	reportGen *report.Generator

	// 多机 Agent 注册中心（Hub 集中管控）
	agentRegistry *registry.Registry

	// Hub 连接状态查询（Agent 接入外部 Hub 时注入，用于 /api/status 与 sgctl doctor）
	hubConnected func() bool

	// 智能洞察提供者（基线状态/内存趋势/变慢站点）
	anomalyDet *anomaly.Detector

	// V3.9 — APM-lite + 知识沉淀
	nginxAnalyzer     *apm.NginxLogAnalyzer
	slowQueryAnalyzer *apm.SlowQueryAnalyzer
	redisAnalyzer     *apm.RedisAnalyzer
	netQualityMon     *netquality.Monitor
	knowledgeBase     *knowledge.KnowledgeBase
	windowRecommender *maintwindow.Recommender

	// V4.0 — 根因链推理引擎
	corrEngine *correlation.Engine

	// V4.0 — 首跑引导向导
	onboarding *sitediscovery.OnboardingWizard

	// V4.0 — 通知双向交互
	biNotifier *notifier.BidirectionalNotifier

	// V4.0 — LLM 增强器（可选）
	llmEnhancer *ai.LLMEnhancer

	// V4.0 — DevOps 守护模块
	devOpsGuard *devops.DevOpsGuard

	// V4.1 — 数据治理守护模块
	dataGovernGuard *datagovern.DataGovernGuard

	// 威胁情报管理器
	intelMgr *intel.IntelManager

	// ─── 异步任务缓存（防止同步阻塞导致 502）───

	// 网络质量探测：异步执行 + 结果缓存
	netProbeRunning bool                      // 是否正在探测
	netProbeResult  *netquality.QualityReport // 最近一次探测结果
	netProbeTime    time.Time                 // 最近一次探测完成时间
	netProbeErr     string                    // 最近一次探测错误信息

	// 大文件扫描：异步执行 + 结果缓存
	fileScanRunning bool             // 是否正在扫描
	fileScanResult  *largeFilesCache // 最近一次扫描结果
	fileScanTime    time.Time        // 最近一次扫描完成时间
	fileScanErr     string           // 最近一次扫描错误信息

	// LLM 异步任务缓存（防止同步阻塞导致 502）
	// LLM 调用最多 30s，而 Hub WriteTimeout 也是 30s，同步调用必然 502
	llmIncidentRunning bool      // explainIncident 是否正在执行
	llmIncidentID      string    // 正在解释的事件 ID
	llmIncidentResult  string    // 最近一次解释结果
	llmIncidentTime    time.Time // 最近一次解释完成时间

	llmReportRunning bool      // generateWeeklyReport 是否正在执行
	llmReportResult  string    // 最近一次周报结果
	llmReportTime    time.Time // 最近一次周报完成时间

	llmTestRunning bool      // testLLM 是否正在执行
	llmTestResult  string    // 最近一次测试结果
	llmTestTime    time.Time // 最近一次测试完成时间

	// 安全扫描状态跟踪（让前端知道扫描是否在进行中）
	scanMu         sync.Mutex
	scanRunning    map[string]bool      // 各扫描器是否正在运行
	scanLastResult map[string]int       // 各扫描器最近一次发现的数量
	scanLastTime   map[string]time.Time // 各扫描器最近一次完成时间
	scanLastError  map[string]string    // 各扫描器最近一次错误信息
}

type AuthConfig struct {
	Enabled   bool
	Username  string
	Password  string
	JWTSecret string
}

// New creates a new API instance.
func New(store *storage.Storage, sm *safety.SafetyManager, auth AuthConfig, cfg *config.Config, configPath string, n *notifier.Notifier, p *probe.Probe, sc *healthscore.Scorer, sd *sitediscovery.Discovery, cg *cert.CertGuard, bt *baota.Discovery) *API {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	api := &API{
		storage:        store,
		safety:         sm,
		router:         r,
		auth:           auth,
		cfg:            cfg,
		configPath:     configPath,
		notifier:       n,
		probe:          p,
		scorer:         sc,
		siteDiscover:   sd,
		certGuard:      cg,
		baotaDiscovery: bt,
		loginLimiter:   newLoginLimiter(),
		scanRunning:    make(map[string]bool),
		scanLastResult: make(map[string]int),
		scanLastTime:   make(map[string]time.Time),
		scanLastError:  make(map[string]string),
	}

	api.setupRoutes()

	// 确保默认管理员用户存在（首次启动时从配置创建）
	if store != nil && auth.Username != "" && auth.Password != "" {
		_ = store.EnsureDefaultAdmin(auth.Username, auth.Password)
	}

	return api
}

// SetSecurityScanners 注入 Phase 1 安全扫描模块（W/X/Y/Z）
func (a *API) SetSecurityScanners(webSec *websecurity.WebSecurityGuard, vulnScan *vulnscan.VulnScanGuard, serverSec *serversecurity.ServerSecurityGuard, attackWarn *attackwarn.AttackWarnGuard, tuningAdv *tuning.TuningAdvisor) {
	a.webSecGuard = webSec
	a.vulnScanGuard = vulnScan
	a.serverSecGuard = serverSec
	a.attackWarnGuard = attackWarn
	a.tuningAdvisor = tuningAdv
}

// RecordAutoScanStart 记录自动扫描开始（由 agent 主循环调用）
func (a *API) RecordAutoScanStart(scanner string) {
	a.scanMu.Lock()
	a.scanRunning[scanner] = true
	a.scanMu.Unlock()
}

// RecordAutoScanDone 记录自动扫描完成（由 agent 主循环调用）
func (a *API) RecordAutoScanDone(scanner string, findingCount int, errMsg string) {
	a.scanMu.Lock()
	a.scanRunning[scanner] = false
	a.scanLastTime[scanner] = time.Now()
	a.scanLastResult[scanner] = findingCount
	if errMsg != "" {
		a.scanLastError[scanner] = errMsg
	} else {
		delete(a.scanLastError, scanner)
	}
	a.scanMu.Unlock()
}

// SetFeedMonitor 注入 CVE Feed Monitor（安全更新提醒）
func (a *API) SetFeedMonitor(fm *vulnscan.FeedMonitor) {
	a.feedMonitor = fm
}

// SetInsights 注入智能异常检测器（提供 /api/insights 数据）。
func (a *API) SetInsights(det *anomaly.Detector) {
	a.anomalyDet = det
}

func (a *API) setupRoutes() {
	r := a.router

	// CORS：使用配置白名单（cfg.Web.CORSOrigins），特殊值 "*" 保持全开放。
	// 避免任意站点在用户浏览器持有 Token 时跨域调用 API。
	allowedOrigins := a.cfg.Web.CORSOrigins
	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Vary", "Origin")
					break
				}
			}
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Serve embedded web panel (Vue SPA)
	// 向宝塔学习：静态文件用 http.FileServer 直接服务，不 ReadAll 全量读入内存
	// embed.FS 实现了 fs.FS，http.FileServer 原生支持流式发送
	assetsFS, _ := fs.Sub(panel.DistFS, "dist/assets")
	fileServer := http.FileServer(http.FS(assetsFS))
	r.GET("/assets/*filepath", func(c *gin.Context) {
		fp := c.Param("filepath")
		// 检查文件是否存在
		if _, err := assetsFS.Open(strings.TrimPrefix(fp, "/")); err != nil {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.JSON(404, gin.H{"error": "asset not found", "hint": "please refresh the page"})
			return
		}
		// 长缓存：hash 命名的静态资源可以永久缓存
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
		http.StripPrefix("/assets", fileServer).ServeHTTP(c.Writer, c.Request)
	})
	// 向宝塔学习：index.html 和 favicon 只读一次缓存，不每次请求都 ReadFile
	indexHTML, _ := panel.DistFS.ReadFile("dist/index.html")
	r.GET("/", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Data(200, "text/html; charset=utf-8", indexHTML)
	})
	// Serve favicon from embedded dist
	faviconData, _ := panel.DistFS.ReadFile("dist/favicon.svg")
	r.GET("/favicon.svg", func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=86400")
		c.Data(200, "image/svg+xml", faviconData)
	})
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=86400")
		c.Data(200, "image/svg+xml", faviconData)
	})
	// Serve manifest.json for PWA
	manifestData, _ := panel.DistFS.ReadFile("dist/manifest.json")
	r.GET("/manifest.json", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Data(200, "application/json; charset=utf-8", manifestData)
	})
	// Serve service worker
	swData, _ := panel.DistFS.ReadFile("dist/sw.js")
	r.GET("/sw.js", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Data(200, "application/javascript; charset=utf-8", swData)
	})
	r.NoRoute(func(c *gin.Context) {
		// SPA fallback: serve cached index.html for all non-API routes
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Data(200, "text/html; charset=utf-8", indexHTML)
			return
		}
		c.JSON(404, gin.H{"error": "not found"})
	})

	// Public routes (no auth)
	r.POST("/api/login", a.login)
	// Prometheus 指标导出（可选 token 保护，见 metrics_exporter.go）
	r.GET("/metrics", a.promMetrics)
	// Agent WebSocket 接入端点（集中管控，Agent 通过 Bearer token + X-Agent-ID 认证）
	r.GET("/ws/agent", a.handleAgentWS)
	// pprof 性能分析端点（用于线上内存/CPU 排查）
	// 访问 /debug/pprof/ 查看所有可用 profile
	// 访问 /debug/pprof/heap 查看堆内存
	// 访问 /debug/pprof/goroutine 查看 goroutine 泄漏
	// 必须置于鉴权之后：pprof 可导出内存中的 Token/密码明文，也可被用作 CPU DoS。
	pprofHandlers := map[string]gin.HandlerFunc{
		"/debug/pprof/":          gin.WrapH(http.HandlerFunc(pprof.Index)),
		"/debug/pprof/cmdline":   gin.WrapH(http.HandlerFunc(pprof.Cmdline)),
		"/debug/pprof/profile":   gin.WrapH(http.HandlerFunc(pprof.Profile)),
		"/debug/pprof/symbol":    gin.WrapH(http.HandlerFunc(pprof.Symbol)),
		"/debug/pprof/trace":     gin.WrapH(http.HandlerFunc(pprof.Trace)),
		"/debug/pprof/allocs":    gin.WrapH(pprof.Handler("allocs")),
		"/debug/pprof/heap":      gin.WrapH(pprof.Handler("heap")),
		"/debug/pprof/goroutine": gin.WrapH(pprof.Handler("goroutine")),
		"/debug/pprof/block":     gin.WrapH(pprof.Handler("block")),
		"/debug/pprof/mutex":     gin.WrapH(pprof.Handler("mutex")),
	}
	for p, h := range pprofHandlers {
		if a.auth.Enabled {
			dbg := r.Group("/debug", a.authMiddleware())
			dbg.GET(strings.TrimPrefix(p, "/debug"), h)
		} else if idx := strings.Index(p, "/debug/pprof/"); idx == 0 && p == "/debug/pprof/" {
			// 认证关闭时不注册任何 pprof 端点（原样暴露可被未认证用户
			// 导出内存中的 Token/密码明文，也可被用作 CPU DoS）
			fmt.Println("[Security] auth_enabled=false，pprof 端点已禁用；如需排查请开启面板认证")
		} else {
			continue
		}
	}

	// API routes (auth required)
	api := r.Group("/api")
	if a.auth.Enabled {
		api.Use(a.authMiddleware())
	}
	{
		// System
		api.GET("/status", a.getStatus)
		api.GET("/version", a.getVersion)

		// Servers (for Hub mode)
		api.GET("/servers", a.getServers)
		api.GET("/servers/:id", a.getServer)
		api.GET("/servers/:id/metrics", a.getServerMetrics)
		api.POST("/servers/:id/restart", a.restartServer)
		api.POST("/servers/:id/command", a.dispatchAgentCommand)

		// Alerts
		api.GET("/alerts", a.getAlerts)
		api.POST("/alerts/:id/ack", a.ackAlert)
		api.POST("/alerts/:id/resolve", a.resolveAlert)

		// Logs
		api.GET("/logs", a.getLogs)
		api.GET("/audit", a.getAuditLog)

		// Safety
		api.GET("/safety", a.getSafetyStatus)
		api.POST("/emergency-stop", a.emergencyStop)
		api.POST("/emergency-resume", a.emergencyResume)

		// Certificates
		api.GET("/certs", a.getCerts)

		// Guards
		api.GET("/guards", a.getGuards)
		api.POST("/guards", a.addGuard)
		api.DELETE("/guards/:id", a.deleteGuard)

		// BaoTa
		api.GET("/baota/status", a.getBaoTaStatus)
		api.POST("/baota/rescan", a.rescanBaoTa)

		// Settings
		api.GET("/settings", a.getSettings)
		api.POST("/settings", a.saveSettings)

		// Notifications
		api.GET("/notify/settings", a.getNotifySettings)
		api.POST("/notify/settings", a.saveNotifySettings)
		api.POST("/notify/test", a.testNotify)

		// Health Score
		api.GET("/health/score", a.getHealthScore)

		// 智能洞察（基线状态/内存趋势/变慢站点）
		api.GET("/insights", a.getInsights)

		// Website / Service Monitoring
		api.GET("/probe/sites", a.getProbeSites)
		api.POST("/probe/sites", a.addProbeSite)
		api.DELETE("/probe/sites/:id", a.deleteProbeSite)

		// API Endpoint Monitoring
		api.GET("/probe/endpoints", a.getProbeEndpoints)
		api.POST("/probe/endpoints", a.addProbeEndpoint)
		api.DELETE("/probe/endpoints/:id", a.deleteProbeEndpoint)

		// Site Discovery (auto-scan Nginx/Apache/IIS/BaoTa)
		api.GET("/probe/discover", a.discoverSites)
		api.GET("/probe/discover/auto", a.autoDiscoverSites)
		api.POST("/probe/discover/import", a.importDiscoveredSites)

		// Cert scan
		api.POST("/certs/scan", a.scanCerts)
		api.POST("/certs/renew", a.renewCert)

		// Confirm management (宝塔分级决策确认机制)
		api.GET("/confirms/pending", a.getPendingConfirms)
		api.POST("/confirm/:id/execute", a.executeConfirm)
		api.POST("/confirm/:id/ignore", a.ignoreConfirm)

		// Security Findings (W/X/Y 模块)
		api.GET("/findings", a.getFindings)
		api.GET("/findings/stats", a.getFindingStats)
		api.GET("/findings/:id", a.getFinding)
		api.POST("/findings/:id/confirm", a.confirmFinding)
		api.POST("/findings/:id/false-positive", a.markFalsePositive)
		api.POST("/findings/:id/fix", a.autoFixFinding)
		api.POST("/findings/report", a.generateFindingsReport)
		api.POST("/findings/batch-resolve", a.batchResolveFindings)

		// Attack Profiles & Events (Z 模块)
		api.GET("/attack-events", a.getAttackEvents)
		api.GET("/attack-profiles", a.getAttackProfiles)
		api.POST("/attack-profiles/emergency-rollback", a.emergencyRollback)

		// Config Versions (配置版本管理)
		api.GET("/config-versions", a.getConfigVersions)
		api.GET("/config-versions/:commit", a.getConfigVersion)
		api.POST("/config-versions/:commit/approve", a.approveConfigVersion)
		api.POST("/config-versions/:commit/rollback", a.rollbackConfigVersion)
		api.POST("/config-versions/:commit/tag", a.tagConfigVersion)
		api.GET("/config-versions/export", a.exportConfigYAML)
		api.POST("/config-versions/import", a.importConfigYAML)

		// Rules (规则管理 + Dry-Run 测试)
		api.GET("/rules", a.getRules)
		api.POST("/rules", a.addRule)
		api.PUT("/rules/:id", a.updateRule)
		api.DELETE("/rules/:id", a.deleteRule)
		api.PUT("/rules/:id/toggle", a.toggleRule)
		api.POST("/rules/test", a.testRuleDryRun)

		// Threat Intelligence
		api.GET("/intel/status", a.getIntelStatus)
		api.POST("/intel/sync", a.triggerIntelSync)
		api.GET("/intel/cve", a.queryIntelCVE)
		api.GET("/intel/ip", a.queryIntelIP)

		// License & Version
		api.GET("/license", a.getLicenseInfo)

		// Config import (from other tools)
		api.POST("/import/monit", a.importMonit)
		api.POST("/import/supervisor", a.importSupervisor)
		api.POST("/import/systemd", a.importSystemd)
		api.POST("/import/baota", a.importBaota)
		api.POST("/import/pm2", a.importPM2)

		// DB maintenance
		api.POST("/db/vacuum", a.dbVacuum)
		api.POST("/db/cleanup", a.dbCleanup)

		// Data export
		api.GET("/export/metrics", a.exportMetrics)
		api.GET("/export/alerts", a.exportAlerts)
		api.GET("/export/audit", a.exportAudit)

		// Security self-check
		api.GET("/security-check", a.securityCheck)

		// Phase 1 安全扫描触发端点 (W/X/Y/Z)
api.POST("/scan/websecurity", a.scanWebSecurity)
api.GET("/scan/websecurity/diagnose", a.diagnoseWebSecurity)
api.POST("/scan/vulnscan", a.scanVuln)
		api.POST("/scan/serversecurity", a.scanServerSecurity)
		api.POST("/scan/attackwarn", a.scanAttackWarn)
		api.GET("/scan/attackwarn/banned", a.getBannedIPs)
		api.GET("/scan/status", a.getScanStatus)

		// Security Updates (CVE Feed Monitor)
		api.GET("/security-updates", a.getSecurityUpdates)
		api.POST("/security-updates/check", a.triggerSecurityUpdateCheck)

		// Tuning advisor (Q 模块)
		api.GET("/tuning/advise", a.getTuningAdvice)

		// Top processes (资源占用 TOP)
		api.GET("/top-processes", a.getTopProcesses)

		// IP geolocation lookup
		api.GET("/ip-location", a.getIPLocation)

		// Large file scanner
		api.GET("/large-files", a.getLargeFiles)
		api.POST("/large-files/delete", a.deleteLargeFile)
		api.POST("/large-files/batch-delete", a.batchDeleteLargeFiles)
		api.GET("/large-files/quick-categories", a.getQuickDeleteCategories)
		api.GET("/large-files/quick-categories/:id/files", a.getQuickCategoryFiles)

		// 维护窗口（Maintenance Window）
		api.GET("/maintenance", a.getMaintenanceWindows)
		api.POST("/maintenance", a.createMaintenanceWindow)
		api.DELETE("/maintenance/:id", a.deleteMaintenanceWindow)

		// RBAC 用户管理
		api.GET("/rbac/users", a.listUsers)
		api.POST("/rbac/users", a.createUser)
		api.PUT("/rbac/users/:id", a.updateUser)
		api.POST("/rbac/users/:id/reset-password", a.resetUserPassword)
		api.DELETE("/rbac/users/:id", a.deleteUser)

		// 每日巡检报告
		api.GET("/report/daily", a.getDailyReport)
		api.POST("/report/daily/send", a.sendDailyReport)

		// V3.9 — APM-lite
		api.GET("/apm/nginx", a.getApmNginxStats)
		api.POST("/apm/nginx/analyze", a.analyzeNginxLogs)
		api.GET("/apm/nginx/tail", a.tailNginxLog)
		api.GET("/apm/slow-query", a.getApmSlowQuery)
		api.POST("/apm/slow-query/analyze", a.analyzeSlowQueries)
		api.GET("/apm/redis", a.getApmRedis)
		api.POST("/apm/redis/analyze", a.analyzeRedisKeys)

		// V3.9 — 网络质量地图
		api.GET("/netquality", a.getNetQuality)
		api.POST("/netquality/probe", a.probeNetQuality)
		api.GET("/netquality/targets", a.getNetQualityTargets)

		// V3.9 — 私有故障知识库
		api.GET("/knowledge", a.getKnowledgeEntries)
		api.GET("/knowledge/stats", a.getKnowledgeStats)
		api.GET("/knowledge/search", a.searchKnowledge)

		// V4.0 — 故障事件（根因链推理产物）
		api.GET("/incidents", a.getIncidents)
		api.GET("/incidents/:id", a.getIncidentDetail)
		api.POST("/incidents/:id/ack", a.ackIncident)

		// V4.0 — 知识库反哺（处置动作推荐 + 反复故障）
		api.GET("/knowledge/recommend", a.getActionRecommendation)
		api.GET("/knowledge/recurring", a.getRecurringIssues)

		// V4.x — 全局态势感知：当前态势/原因/自主决策时间线
		api.GET("/posture", a.getPosture)

		// V4.0 — 首跑引导向导
		api.GET("/onboarding/state", a.onboardingStatus)
		api.POST("/onboarding/start", a.onboardingDetect)
		api.POST("/onboarding/detect", a.onboardingDetect)
		api.POST("/onboarding/import", a.onboardingImport)
		api.POST("/onboarding/learn-mode", a.onboardingStartLearn)
		api.POST("/onboarding/skip", a.skipOnboarding)

		// V4.0 — 场景模板
		api.GET("/scene-templates", a.getSceneTemplates)
		api.GET("/scene-templates/:id", a.getSceneTemplate)
		api.POST("/scene-templates/:id/apply", a.applySceneTemplate)

		// V4.0 — 通知双向交互
		api.POST("/notify/reply", a.processNotifyReply)
		api.GET("/notify/pending", a.getPendingAlerts)
		api.POST("/notify/pause/:shortCode", a.notifyShortCodePause)
		api.POST("/notify/ack/:shortCode", a.notifyShortCodeAck)

		// V4.0 — LLM 增强层
		api.GET("/llm/status", a.getLLMStatus)
		api.GET("/llm/explain-incident/:id", a.explainIncident)
		api.GET("/llm/explain-alert/:id", a.explainAlert)
		api.POST("/llm/config", a.saveLLMConfig)
		api.POST("/llm/test", a.testLLM)
		api.POST("/llm/weekly-report", a.generateWeeklyReport)

		// V4.0 — 安全管理远程控制
		api.GET("/safety/status", a.getSafetyRemoteStatus)
		api.POST("/safety/remote-pause", a.remotePause)
		api.POST("/safety/remote-resume", a.remoteResume)

		// V4.0 — Onboarding 补充
		api.POST("/onboarding/complete", a.onboardingComplete)
		api.POST("/onboarding/test-notify", a.onboardingTestNotify)

		// V4.0 — 知识库推荐补充
		api.GET("/knowledge/recommendations", a.getRecommendations)
		api.GET("/knowledge/recommend/:alertId", a.getRecommendationForAlert)

		// V4.0 — 故障事件补充
		api.GET("/incident-by-alert/:alertId", a.getIncidentByAlert)

		// V3.9 — 智能变更窗口推荐
		api.GET("/maintenance-window/recommend", a.getMaintenanceWindowRecommendation)

		// V3.9 — 故障复盘报告
		api.GET("/report/postmortem", a.getPostmortemReport)
		api.POST("/report/postmortem/generate", a.generatePostmortemReport)
		api.GET("/report/weekly", a.getWeeklyReport)
		api.POST("/report/weekly/send", a.sendWeeklyReport)

		// ─── V4.0 — 交互式运维 + DevOps 闭环 ───
		api.GET("/devops/deployments", a.getDevOpsDeployments)
		api.POST("/devops/deploy", a.triggerWebhookDeploy)
		api.GET("/devops/env-drift", a.getEnvDrift)
		api.GET("/devops/build-dirs", a.getBuildDirs)
		api.POST("/devops/build-dirs", a.addBuildDir)
		api.POST("/devops/build-dirs/check", a.checkBuildDirs)
		api.GET("/devops/cron-conflicts", a.checkCronConflicts)
		api.GET("/devops/batch-jobs", a.getBatchJobs)
		api.POST("/devops/batch-jobs", a.addBatchJob)
		api.POST("/devops/batch-jobs/:id/run", a.runBatchJob)
		api.GET("/devops/transfers", a.getTransferWatches)
		api.POST("/devops/transfers", a.addTransferWatch)
		api.GET("/devops/api-deps", a.getAPIDeps)
		api.POST("/devops/api-deps", a.addAPIDep)
		api.POST("/devops/api-deps/check", a.checkAPIDeps)
		// V4.0 — DevOps 自动发现（零配置）
		api.GET("/devops/auto-discover", a.getDevOpsAutoDiscovery)

		// ─── V4.1 — 数据治理 + 备份安全 ───
		api.GET("/datagovern/backups", a.getBackupTasks)
		api.POST("/datagovern/backups", a.addBackupTask)
		api.POST("/datagovern/backups/:id/run", a.runBackup)
		api.POST("/datagovern/sensitive-scan", a.scanSensitiveData)
		api.POST("/datagovern/big-tables", a.checkBigTables)
		api.POST("/datagovern/verify-backup", a.verifyBackup)
		api.GET("/datagovern/verify-history", a.getVerificationHistory)
		api.POST("/datagovern/deadlocks", a.huntDeadlocks)
		api.GET("/datagovern/deadlock-history", a.getDeadlockHistory)
		api.POST("/datagovern/conn-pool", a.diagnoseConnPool)
		api.POST("/datagovern/cache-avalanche", a.preventCacheAvalanche)
		api.POST("/datagovern/tsdb-anomaly", a.checkTSDBAnomaly)
		api.POST("/datagovern/archive", a.archiveTable)
		// V4.1 — 数据治理自动发现 + 自动巡检（零配置）
		api.GET("/datagovern/auto-discover", a.getDataGovernAutoDiscovery)
		api.GET("/datagovern/auto-check", a.getDataGovernAutoCheck)

		// ─── 幽灵文件检测 — 已删除但句柄未释放的隐形空间杀手 ───
		api.GET("/ghost-files", a.getGhostFiles)
		api.POST("/ghost-files/clean", a.cleanGhostFiles)
		api.POST("/ghost-files/scan", a.scanGhostFiles)
	}
}

// login handles user login and returns JWT token.
func (a *API) login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	// 登录防暴力破解：锁定期间直接拒绝，不进行密码校验
	clientIP := c.ClientIP()
	if !a.loginLimiter.Allow(clientIP) {
		c.JSON(429, gin.H{"error": "失败次数过多，请 15 分钟后再试"})
		return
	}

	loginOK := false

	// 先尝试从用户数据库验证
	if a.storage != nil {
		if user, err := a.storage.VerifyUser(req.Username, req.Password); err == nil {
			loginOK = true
			a.loginLimiter.Reset(clientIP)
			ts := time.Now().Unix()
			expiry := ts + 86400*7 // 7 days
			msg := fmt.Sprintf("%s:%d:%d", user.Username, ts, expiry)
			sig := a.signToken(msg)
			token := fmt.Sprintf("sg-%s:%s", msg, sig)
			c.JSON(200, gin.H{
				"token":    token,
				"username": user.Username,
				"role":     user.Role,
				"expires":  expiry,
			})
			return
		}
	}

	// 降级：检查配置文件中的默认管理员凭证。
	// 未配置密码（空）时禁止走该分支，否则 admin+空密码即可登录。
	// 恒定时间比较，避免逐字节短路造成的时序侧信道。
	if !loginOK {
		userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(a.auth.Username)) == 1
		passOK := a.auth.Password != "" &&
			subtle.ConstantTimeCompare([]byte(req.Password), []byte(a.auth.Password)) == 1
		if !userOK || !passOK {
			a.loginLimiter.RecordFailure(clientIP)
			c.JSON(401, gin.H{"error": "用户名或密码错误"})
			return
		}
	}

	a.loginLimiter.Reset(clientIP)

	// Generate HMAC-signed token with expiry
	ts := time.Now().Unix()
	expiry := ts + 86400*7 // 7 days
	msg := fmt.Sprintf("%s:%d:%d", req.Username, ts, expiry)
	sig := a.signToken(msg)
	token := fmt.Sprintf("sg-%s:%s", msg, sig)
	c.JSON(200, gin.H{
		"token":    token,
		"username": req.Username,
		"role":     "admin",
		"expires":  expiry,
	})
}

// loginLimiter 按 IP 的登录失败限制器（内存实现，零依赖）。
// 规则：同一 IP 连续失败 5 次 → 锁定 15 分钟；成功登录即清零。
const (
	loginMaxFailures  = 5
	loginLockDuration = 15 * time.Minute
	loginEntryMaxIdle = 1 * time.Hour // 失败记录空闲回收时间
)

type loginFailState struct {
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*loginFailState
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fails: make(map[string]*loginFailState)}
}

// Allow 返回该 IP 当前是否允许尝试登录。
func (l *loginLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.fails[ip]
	if !ok {
		return true
	}
	if !st.lockedUntil.IsZero() && time.Now().Before(st.lockedUntil) {
		return false
	}
	return true
}

// RecordFailure 记录一次登录失败，达到阈值时触发锁定。
func (l *loginLimiter) RecordFailure(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// 惰性回收：条目数超限时清理过期记录，防止 map 无限增长
	if len(l.fails) > 1024 {
		for k, st := range l.fails {
			if now.Sub(st.lastFailure) > loginEntryMaxIdle {
				delete(l.fails, k)
			}
		}
	}

	st, ok := l.fails[ip]
	if !ok {
		st = &loginFailState{}
		l.fails[ip] = st
	}
	// 上次失败已超出锁定时长，重新计数
	if !st.lockedUntil.IsZero() && now.After(st.lockedUntil) {
		st.failures = 0
		st.lockedUntil = time.Time{}
	}
	st.failures++
	st.lastFailure = now
	if st.failures >= loginMaxFailures {
		st.lockedUntil = now.Add(loginLockDuration)
		st.failures = 0
	}
}

// Reset 登录成功后清除该 IP 的失败计数。
func (l *loginLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// signToken creates an HMAC signature for the token.
func (a *API) signToken(msg string) string {
	h := hmac.New(sha256.New, []byte(a.auth.JWTSecret))
	h.Write([]byte(msg))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// verifyToken verifies the HMAC signature and expiry.
func (a *API) verifyToken(token string) bool {
	// 空 JWTSecret 时签名密钥为空字符串，任何人都可离线伪造合法 Token
	if a.auth.JWTSecret == "" || !strings.HasPrefix(token, "sg-") {
		return false
	}
	// token 格式: sg-<msg>:<sig>
	// msg = username:ts:expiry
	// sig = HMAC-SHA256(JWTSecret, msg)
	body := strings.TrimPrefix(token, "sg-")
	idx := strings.LastIndex(body, ":")
	if idx < 0 || idx == len(body)-1 {
		return false
	}
	msg := body[:idx]
	sig := body[idx+1:]

	// 验证签名
	expectedSig := a.signToken(msg)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false
	}

	// 验证过期时间
	parts := strings.Split(msg, ":")
	if len(parts) < 3 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < expiry
}

// authMiddleware provides JWT token auth.
func (a *API) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check Authorization header
		auth := c.GetHeader("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			c.JSON(401, gin.H{"error": "请先登录", "code": "UNAUTHORIZED"})
			c.Abort()
			return
		}
	token := strings.TrimPrefix(auth, "Bearer ")
	if !a.verifyToken(token) {
		c.JSON(401, gin.H{"error": "令牌无效或已过期", "code": "UNAUTHORIZED"})
		c.Abort()
		return
	}
	// 将 Token 中的用户名注入 context，供审计（如命令下发的 Actor）使用
	if body := strings.TrimPrefix(token, "sg-"); strings.Contains(body, ":") {
		msg := body[:strings.LastIndex(body, ":")]
		if parts := strings.Split(msg, ":"); len(parts) >= 3 {
			c.Set("username", parts[0])
		}
	}
	c.Next()
	}
}

// getSettings returns current system settings from the actual config file.
func (a *API) getSettings(c *gin.Context) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c.JSON(200, gin.H{
		"collect_interval":    int(a.cfg.Agent.CollectInterval.Duration().Seconds()),
		"learn_mode":          a.cfg.Agent.LearnMode,
		"max_memory_mb":       a.cfg.Agent.MaxMemoryMB,
		"auto_renew_days":     a.cfg.Cert.AutoRenewDays,
		"cert_ports":          a.cfg.Cert.ScanPorts,
		"kill_budget_hourly":  a.cfg.Safety.KillBudgetHourly,
		"kill_budget_daily":   a.cfg.Safety.KillBudgetDaily,
		"auth_enabled":        a.auth.Enabled,
		"username":            a.auth.Username,
		"baota_safe_mode":     a.cfg.Baota.SafeMode,
		"baota_panel_path":    a.cfg.Baota.PanelPath,
		"baota_service_mgr":   a.cfg.Baota.UseBaotaServiceMgr,
		"baota_cleanup_scope": a.cfg.Baota.CleanupScope,
		"baota_log_rotation":  a.cfg.Baota.LogRotationScope,
	})
}

// saveSettings saves system settings to the config file and applies changes.
func (a *API) saveSettings(c *gin.Context) {
	var req map[string]interface{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Update config struct
	if v, ok := req["collect_interval"].(float64); ok {
		a.cfg.Agent.CollectInterval = config.Duration(time.Duration(int(v)) * time.Second)
	}
	if v, ok := req["learn_mode"].(bool); ok {
		a.cfg.Agent.LearnMode = v
	}
	if v, ok := req["max_memory_mb"].(float64); ok {
		a.cfg.Agent.MaxMemoryMB = int(v)
	}
	if v, ok := req["auto_renew_days"].(float64); ok {
		a.cfg.Cert.AutoRenewDays = int(v)
	}
	if v, ok := req["kill_budget_hourly"].(float64); ok {
		a.cfg.Safety.KillBudgetHourly = int(v)
		a.safety.UpdateKillBudget(int(v), a.cfg.Safety.KillBudgetDaily)
	}
	if v, ok := req["kill_budget_daily"].(float64); ok {
		a.cfg.Safety.KillBudgetDaily = int(v)
		a.safety.UpdateKillBudget(a.cfg.Safety.KillBudgetHourly, int(v))
	}
	if v, ok := req["username"].(string); ok && v != "" {
		a.auth.Username = v
		a.cfg.Web.Username = v
	}
	if v, ok := req["new_password"].(string); ok && v != "" {
		a.auth.Password = v
		a.cfg.Web.Password = v
		// 同步更新数据库中的用户密码，避免配置文件与数据库密码不一致
		// 导致重启后登录报"密码错误"
		if a.storage != nil {
			users, _ := a.storage.ListUsers()
			for _, u := range users {
				if u.Username == a.auth.Username {
					_ = a.storage.UpdateUserPassword(u.ID, v)
					break
				}
			}
		}
	}
	if v, ok := req["baota_safe_mode"].(string); ok {
		a.cfg.Baota.SafeMode = v
		// Apply baota safe mode change
		if v == "true" {
			a.safety.SetBaotaSafeMode(true)
		} else if v == "false" {
			a.safety.SetBaotaSafeMode(false)
		}
	}
	if v, ok := req["baota_panel_path"].(string); ok {
		a.cfg.Baota.PanelPath = v
	}
	if v, ok := req["baota_service_mgr"].(bool); ok {
		a.cfg.Baota.UseBaotaServiceMgr = v
	}
	if v, ok := req["baota_cleanup_scope"].(string); ok {
		a.cfg.Baota.CleanupScope = v
	}
	if v, ok := req["baota_log_rotation"].(string); ok {
		a.cfg.Baota.LogRotationScope = v
	}

	// Write to config file
	if err := a.cfg.Save(a.configPath); err != nil {
		c.JSON(500, gin.H{"error": "保存配置文件失败: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "设置已保存并生效"})
}

// scanCerts triggers a certificate scan.
func (a *API) scanCerts(c *gin.Context) {
	if a.certGuard == nil {
		c.JSON(500, gin.H{"error": "cert guard not initialized"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	certs, err := a.certGuard.Scan(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	actor := "api"
	if u, exists := c.Get("username"); exists {
		if s, ok := u.(string); ok && s != "" {
			actor = s
		}
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    "cert_scan",
		Target:    "all",
		Reason:    "用户手动触发证书扫描",
		Result:    "success",
		Details:   fmt.Sprintf("发现 %d 个证书", len(certs)),
	})
	c.JSON(200, gin.H{"message": fmt.Sprintf("扫描完成，发现 %d 个证书", len(certs)), "certs": certs})
}

// renewCert triggers certificate renewal for a domain.
func (a *API) renewCert(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.BindJSON(&req); err != nil || req.Domain == "" {
		c.JSON(400, gin.H{"error": "请提供域名"})
		return
	}
	if a.certGuard == nil {
		c.JSON(500, gin.H{"error": "cert guard not initialized"})
		return
	}
	actor := "api"
	if u, exists := c.Get("username"); exists {
		if s, ok := u.(string); ok && s != "" {
			actor = s
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	if err := a.certGuard.RenewCertificate(ctx, req.Domain); err != nil {
		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     actor,
			Action:    "cert_renew",
			Target:    req.Domain,
			Reason:    "用户手动触发证书续期",
			Result:    "failed",
			Details:   err.Error(),
		})
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    "cert_renew",
		Target:    req.Domain,
		Reason:    "用户手动触发证书续期",
		Result:    "success",
	})
	c.JSON(200, gin.H{"message": "证书续期已触发", "domain": req.Domain})
}

// --- Handlers ---

func (a *API) getStatus(c *gin.Context) {
	// 3 秒响应缓存：本端点是面板高频轮询接口，聚合了 CPU/磁盘/进程/预测等多项
	// 系统查询。前端通常 3-5 秒轮询一次，多标签页同时打开时会放大；
	// 缓存窗口内的重复请求直接复用上次结果，把系统调用次数压到与真实刷新率一致。
	a.mu.Lock()
	if a.statusCache != nil && a.statusCacheTime.After(time.Now().Add(-3*time.Second)) {
		cached := a.statusCache
		a.mu.Unlock()
		c.JSON(200, cached)
		return
	}
	a.mu.Unlock()

	resp := a.buildStatusResponse()
	a.mu.Lock()
	a.statusCache = resp
	a.statusCacheTime = time.Now()
	a.mu.Unlock()

	c.JSON(200, resp)
}

// countProcsAndZombies 轻量统计进程总数与僵尸数（仅读 /proc 目录与每 PID 一次 stat）。
func countProcsAndZombies() (processCount, zombieCount int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		processCount++
		statData, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		// /proc/PID/stat 格式: pid (comm) state ...（状态字段是右括号后的首字符）
		statStr := string(statData)
		if idx := strings.LastIndex(statStr, ")"); idx >= 0 && idx+1 < len(statStr) {
			state := strings.TrimSpace(statStr[idx+1:])
			if len(state) > 0 && (state[0] == 'Z' || state[0] == 'z') {
				zombieCount++
			}
		}
	}
	return processCount, zombieCount
}

// buildStatusResponse 聚合状态响应（被 getStatus 的 TTL 缓存包裹）。
func (a *API) buildStatusResponse() gin.H {
	mode := a.safety.GetMode()

	a.mu.RLock()
	hubConnected := a.hubConnected
	a.mu.RUnlock()
	hubStatus := gin.H{"enabled": false, "connected": false}
	if hubConnected != nil {
		hubStatus = gin.H{"enabled": true, "connected": hubConnected()}
	}

	// Collect system metrics
	var cpuPercent float64
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		cpuPercent = percents[0]
	}

	cpuCores, _ := cpu.Counts(false)

	var memPercent float64
	var memTotal, memUsed uint64
	if memInfo, err := mem.VirtualMemory(); err == nil {
		memPercent = memInfo.UsedPercent
		memTotal = memInfo.Total
		memUsed = memInfo.Used
	}

	var diskPercent float64
	if partitions, err := disk.Partitions(false); err == nil && len(partitions) > 0 {
		if usage, err := disk.Usage(partitions[0].Mountpoint); err == nil {
			diskPercent = usage.UsedPercent
		}
	}

	processCount := 0
	zombieCount := 0
	// 进程计数统一走轻量级 /proc 扫描（1 次 ReadDir + 每 PID 1 次 stat 读）。
	// 原实现非宝塔分支用 process.Processes()+逐进程 Status()——每进程多次 open/read，
	// 而本端点是面板高频轮询接口，等于把重扫描常驻化；宝塔分支早已改轻量，此处对齐。
	if runtime.GOOS != "windows" {
		processCount, zombieCount = countProcsAndZombies()
	} else if procs, err := process.Processes(); err == nil {
		processCount = len(procs)
		for _, p := range procs {
			if status, err := p.Status(); err == nil && len(status) > 0 {
				if status[0] == "Z" || status[0] == "z" {
					zombieCount++
				}
			}
		}
	}

	// Collect network IO counters
	var netBytesSent, netBytesRecv uint64
	if ioCounters, err := hostnet.IOCounters(false); err == nil && len(ioCounters) > 0 {
		netBytesSent = ioCounters[0].BytesSent
		netBytesRecv = ioCounters[0].BytesRecv
	}

	// Build disk list
	var disks []gin.H
	if partitions, err := disk.Partitions(false); err == nil {
		for _, part := range partitions {
			if usage, err := disk.Usage(part.Mountpoint); err == nil {
				disks = append(disks, gin.H{
					"mount_point":  part.Mountpoint,
					"used_percent": usage.UsedPercent,
					"total":        usage.Total,
					"used":         usage.Used,
					"free":         usage.Free,
				})
			}
		}
	}

	// 学习模式信息：返回 learn_mode 状态和剩余天数
	learnMode := a.cfg.Agent.LearnMode
	learnRemainingDays := 0
	if learnMode && a.storage != nil {
		if learnStart, err := a.storage.Get("learn_mode_start"); err == nil && learnStart != "" {
			if startTime, err := time.Parse(time.RFC3339, learnStart); err == nil {
				learnDays := a.cfg.Agent.LearnModeDays
				if learnDays <= 0 {
					learnDays = 7
				}
				elapsed := time.Since(startTime)
				remaining := time.Duration(learnDays)*24*time.Hour - elapsed
				if remaining > 0 {
					learnRemainingDays = int(remaining.Hours()/24) + 1
				}
			}
		}
	}

	return gin.H{
		"status":               "online",
		"mode":                 string(mode),
		"emergency_stop":       a.safety.IsEmergencyStopped(),
		"hub":                  hubStatus,
		"baota_safe_mode":      a.safety.IsBaotaSafeMode(),
		"maintenance_active":   a.IsInMaintenance(),
		"learn_mode":           learnMode,
		"learn_remaining_days": learnRemainingDays,
		"disk_forecast":        forecast.GetForecasts(a.storage),
		"is_baota":             a.baotaDiscovery != nil && a.baotaDiscovery.IsDetected(),
		"version":              version.ShortVersion(),
		"timestamp":            time.Now(),
		"cpu_percent":          cpuPercent,
		"cpu_cores":            cpuCores,
		"load_avg_1":           cpuPercent, // Use CPU% as load proxy on Windows
		"mem_percent":          memPercent,
		"mem_used":             memUsed,
		"mem_total":            memTotal,
		"disk_percent":         diskPercent,
		"disks":                disks,
		"process_count":        processCount,
		"zombie_count":         zombieCount,
		"net_bytes_sent":       netBytesSent,
		"net_bytes_recv":       netBytesRecv,
	}
}

func (a *API) getVersion(c *gin.Context) {
	components := detectInstalledComponents()
	c.JSON(200, gin.H{
		"version":     version.Version,
		"buildTime":   version.BuildTime,
		"gitCommit":   version.GitCommit,
		"goVersion":   version.GoVersion,
		"full":        version.FullVersion(),
		"components":  components,
	})
}

// detectInstalledComponents 检测已安装的 ServerGuard 组件
// 返回 agent、hub、sgctl 的安装路径和状态
func detectInstalledComponents() []gin.H {
	components := []gin.H{}

	// 安装目录
	installDir := "/opt/serverguard"
	if runtime.GOOS == "windows" {
		installDir = `C:\Program Files\ServerGuard`
	}

	// agent（当前进程即为 agent，必然已安装）
	components = append(components, gin.H{
		"name":         "serverguard-agent",
		"display_name": "Agent",
		"description": "\u91c7\u96c6/\u81ea\u6108\u5f15\u64ce\uff0c\u542b\u5b8c\u6574\u626b\u63cf+\u9762\u677f\u80fd\u529b",
		"installed":   true,
		"path":        installDir + "/serverguard-agent",
		"running":     true,
	})

	// hub
	hubPath := installDir + "/serverguard-hub"
	if runtime.GOOS == "windows" {
		hubPath = installDir + `\serverguard-hub.exe`
	}
	hubInstalled := false
	if _, err := os.Stat(hubPath); err == nil {
		hubInstalled = true
	}
	components = append(components, gin.H{
		"name":         "serverguard-hub",
		"display_name": "Hub",
		"description": "\u591a\u670d\u52a1\u5668\u7ba1\u7406\u4e2d\u67a2\uff0c\u96c6\u4e2d\u7ba1\u7406\u591a\u53f0 Agent \u7684\u544a\u8b66\u548c\u72b6\u6001",
		"installed":   hubInstalled,
		"path":        hubPath,
		"running":     false,
	})

	// sgctl
	sgctlPath := installDir + "/sgctl"
	if runtime.GOOS == "windows" {
		sgctlPath = installDir + `\sgctl.exe`
	}
	sgctlInstalled := false
	if _, err := os.Stat(sgctlPath); err == nil {
		sgctlInstalled = true
	}
	components = append(components, gin.H{
		"name":         "sgctl",
		"display_name": "sgctl",
		"description": "\u547d\u4ee4\u884c\u8fd0\u7ef4\u5de5\u5177\uff0c\u652f\u6301\u72b6\u6001\u67e5\u8be2/\u5347\u7ea7/\u8bca\u65ad/\u5bfc\u5165\u914d\u7f6e",
		"installed":   sgctlInstalled,
		"path":        sgctlPath,
		"running":     false,
	})

	return components
}

func (a *API) getServers(c *gin.Context) {
	// Multi-agent mode: prefer the Hub agent registry when populated.
	if reg := a.agentRegistry; reg != nil {
		if recs := reg.List(); len(recs) > 0 {
			servers := make([]gin.H, 0, len(recs))
			for i := range recs {
				rec := &recs[i]
				servers = append(servers, gin.H{
					"id":          rec.AgentID,
					"hostname":    rec.Hostname,
					"ip":          rec.IP,
					"os":          rec.OS + "/" + rec.Arch,
					"version":     rec.Version,
					"status":      rec.Status,
					"last_seen":   rec.LastSeen,
					"cpu":         rec.Metrics.CPU,
					"memory":      rec.Metrics.Mem,
					"disk":        rec.Metrics.Disk,
					"alert_count": rec.RecentAlertCount,
					"uptime_sec":  rec.Metrics.UptimeSec,
					"load_avg_1":  rec.Metrics.LoadAvg1,
					"mem_total":   rec.Metrics.MemTotal,
					"mem_used":    rec.Metrics.MemUsed,
					"disk_total":  rec.Metrics.DiskTotal,
					"disk_used":   rec.Metrics.DiskUsed,
				})
			}
			c.JSON(200, gin.H{"servers": servers, "hub_mode": true})
			return
		}
	}

	// Fallback: single-machine behavior (backwards compatible).
	// Get real hostname
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "local"
	}

	// Get local IP address
	var localIP string
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					localIP = ipNet.IP.String()
					break
				}
			}
		}
	}
	if localIP == "" {
		localIP = "127.0.0.1"
	}

	// Get OS info
	osInfo := runtime.GOOS + "/" + runtime.GOARCH

	c.JSON(200, gin.H{
		"servers": []gin.H{{
			"id":        "local",
			"hostname":  hostname,
			"ip":        localIP,
			"os":        osInfo,
			"status":    "online",
			"mode":      string(a.safety.GetMode()),
			"last_seen": time.Now(),
		}},
	})
}

func (a *API) getServer(c *gin.Context) {
	id := c.Param("id")

	// Multi-agent mode: return the agent detail from the registry.
	if reg := a.agentRegistry; reg != nil {
		if rec, ok := reg.Get(id); ok {
			c.JSON(200, gin.H{
				"id":          rec.AgentID,
				"hostname":    rec.Hostname,
				"ip":          rec.IP,
				"os":          rec.OS + "/" + rec.Arch,
				"arch":        rec.Arch,
				"version":     rec.Version,
				"status":      rec.Status,
				"last_seen":   rec.LastSeen,
				"cpu":         rec.Metrics.CPU,
				"memory":      rec.Metrics.Mem,
				"disk":        rec.Metrics.Disk,
				"alert_count": rec.RecentAlertCount,
				"uptime_sec":  rec.Metrics.UptimeSec,
				"load_avg_1":  rec.Metrics.LoadAvg1,
				"mem_total":   rec.Metrics.MemTotal,
				"mem_used":    rec.Metrics.MemUsed,
				"disk_total":  rec.Metrics.DiskTotal,
				"disk_used":   rec.Metrics.DiskUsed,
			})
			return
		}
	}

	if id != "local" && id != "self" {
		c.JSON(404, gin.H{"error": "server not found"})
		return
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "local"
	}
	var localIP string
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					localIP = ipNet.IP.String()
					break
				}
			}
		}
	}
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	c.JSON(200, gin.H{
		"id":        "local",
		"hostname":  hostname,
		"ip":        localIP,
		"os":        runtime.GOOS + "/" + runtime.GOARCH,
		"status":    "online",
		"mode":      string(a.safety.GetMode()),
		"last_seen": time.Now(),
	})
}

func (a *API) getServerMetrics(c *gin.Context) {
	since := time.Now().Add(-1 * time.Hour)
	metrics, err := a.storage.GetMetrics("", "", since, 100)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"metrics": metrics})
}

// dispatchAgentCommand 向已注册的 Agent 下发白名单内的远程命令。
// POST /api/servers/:id/command  body: {"type": "status", "data": {...}}
// 命令类型必须在 supportedHubCommands 白名单内（见 agentws.go），
// Agent 端同样只注册了这些命令的处理器 —— 双端白名单，杜绝任意命令执行。
// 命令结果由 Agent 异步通过 command_response 回传并写入审计日志。
func (a *API) dispatchAgentCommand(c *gin.Context) {
	id := c.Param("id")

	reg := a.agentRegistry
	if reg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent registry 未初始化（非 Hub 模式）"})
		return
	}
	if _, ok := reg.Get(id); !ok {
		c.JSON(404, gin.H{"error": fmt.Sprintf("Agent %s 未注册", id)})
		return
	}

	var req struct {
		Type string                 `json:"type"`
		Data map[string]interface{} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求体无效: " + err.Error()})
		return
	}

	allowed := false
	for _, cmd := range supportedHubCommands {
		if cmd == req.Type {
			allowed = true
			break
		}
	}
	if !allowed {
		c.JSON(400, gin.H{"error": fmt.Sprintf("不支持的命令 %q，可用命令: %v", req.Type, supportedHubCommands)})
		return
	}

	commandID := uuid.NewString()
	if req.Data == nil {
		req.Data = map[string]interface{}{}
	}
	req.Data["command_id"] = commandID
	req.Data["requested"] = time.Now().UTC()

	if err := reg.SendJSON(id, comm.HubMessage{
		Type:    req.Type,
		AgentID: id,
		Data:    req.Data,
	}); err != nil {
		c.JSON(409, gin.H{"error": fmt.Sprintf("agent 离线或无法下发命令: %v", err)})
		return
	}

	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     c.GetString("username"),
		Action:    "agent_command:" + req.Type,
		Target:    id,
		Reason:    "用户通过 Hub 下发远程命令",
		Result:    "dispatched",
	})
	c.JSON(200, gin.H{
		"message":    fmt.Sprintf("命令 %s 已下发到 Agent %s，结果将通过审计日志回传", req.Type, id),
		"command_id": commandID,
	})
}

func (a *API) restartServer(c *gin.Context) {
	id := c.Param("id")

	// Multi-agent mode: dispatch a restart command to a registered agent.
	if reg := a.agentRegistry; reg != nil {
		if _, ok := reg.Get(id); ok {
			err := reg.SendJSON(id, comm.HubMessage{
				Type:    "restart",
				AgentID: id,
				Data: map[string]interface{}{
					"command_id": uuid.NewString(),
					"requested":  time.Now().UTC(),
				},
			})
			if err != nil {
				c.JSON(409, gin.H{"error": fmt.Sprintf("agent 离线或无法下发命令: %v", err)})
				return
			}
			a.storage.SaveAudit(types.AuditEntry{
				ID:        uuid.NewString(),
				Timestamp: time.Now(),
				Actor:     c.GetString("username"),
				Action:    "restart",
				Target:    id,
				Reason:    "用户通过 Hub 下发 restart 命令",
				Result:    "success",
			})
			c.JSON(200, gin.H{"message": fmt.Sprintf("restart 命令已下发到 Agent %s", id)})
			return
		}
	}

	targets, err := a.storage.GetGuardTargets()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	for _, t := range targets {
		if t.ID == id || id == "local" {
			// Safety: check if target is enabled
			if !t.Enabled {
				c.JSON(400, gin.H{"error": "该守护目标已禁用"})
				return
			}

			ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
			defer cancel()

			// 宝塔安全模式检查：宝塔管理的服务优先使用 /etc/init.d/ 脚本重启
			if a.safety != nil && a.safety.IsBaotaSafeMode() {
				lowerName := strings.ToLower(t.Name)
				lowerProcName := strings.ToLower(t.ProcessName)
				if safety.BaotaPanelServiceNames[t.Name] || safety.BaotaPanelServiceNames[lowerName] ||
					safety.BaotaPanelServiceNames[t.ProcessName] || safety.BaotaPanelServiceNames[lowerProcName] {
					c.JSON(403, gin.H{"error": fmt.Sprintf("宝塔面板服务 %s 禁止通过 API 重启，请通过宝塔面板管理", t.Name)})
					return
				}
				// 宝塔管理的服务：优先尝试 /etc/init.d/xxx restart
				if safety.BaotaManagedServices[lowerName] || safety.BaotaManagedServices[lowerProcName] {
					initPath := "/etc/init.d/" + t.Name
					if _, err := os.Stat(initPath); err == nil {
						cmd := exec.CommandContext(ctx, "sh", "-c", initPath+" restart")
						output, err := cmd.CombinedOutput()
						if err != nil {
							c.JSON(500, gin.H{"error": fmt.Sprintf("%s restart 失败: %v\n输出: %s", initPath, err, string(output))})
							return
						}
						a.storage.SaveAudit(types.AuditEntry{
							ID:        uuid.NewString(),
							Timestamp: time.Now(),
							Actor:     "api",
							Action:    "restart",
							Target:    t.Name,
							Reason:    "用户手动重启（宝塔 init.d）",
							Result:    "success",
						})
						c.JSON(200, gin.H{"message": fmt.Sprintf("%s restarted via %s", t.Name, initPath)})
						return
					}
					// init.d 脚本不存在，尝试 systemctl
				}
			}

			// Safety: check whitelist — don't allow restarting critical services via API
			// (use systemctl restart instead of kill+start for systemd services)

			// For systemd services: use systemctl restart (safe)
			if t.Type == "systemd" && runtime.GOOS != "windows" {
				cmd := exec.CommandContext(ctx, "systemctl", "restart", t.Name)
				if err := cmd.Run(); err != nil {
					// systemctl 重启失败时，尝试 /etc/init.d/ 作为降级方案
					initPath := "/etc/init.d/" + t.Name
					if _, statErr := os.Stat(initPath); statErr == nil {
						fallbackCmd := exec.CommandContext(ctx, "sh", "-c", initPath+" restart")
						fallbackOutput, fallbackErr := fallbackCmd.CombinedOutput()
						if fallbackErr != nil {
							c.JSON(500, gin.H{"error": fmt.Sprintf("systemctl restart 失败: %v\n%s restart 也失败: %v\n输出: %s", err, initPath, fallbackErr, string(fallbackOutput))})
							return
						}
						a.storage.SaveAudit(types.AuditEntry{
							ID:        uuid.NewString(),
							Timestamp: time.Now(),
							Actor:     "api",
							Action:    "restart",
							Target:    t.Name,
							Reason:    "用户手动重启（init.d 降级）",
							Result:    "success",
						})
						c.JSON(200, gin.H{"message": fmt.Sprintf("%s restarted via %s (systemctl failed, used init.d fallback)", t.Name, initPath)})
						return
					}
					c.JSON(500, gin.H{"error": fmt.Sprintf("systemctl restart failed: %v", err)})
					return
				}
				// Log to audit
				a.storage.SaveAudit(types.AuditEntry{
					ID:        uuid.NewString(),
					Timestamp: time.Now(),
					Actor:     "api",
					Action:    "restart",
					Target:    t.Name,
					Reason:    "用户手动重启服务",
					Result:    "success",
				})
				c.JSON(200, gin.H{"message": fmt.Sprintf("%s restarted via systemctl", t.Name)})
				return
			}
			// For bare processes: check whitelist before restarting
			if t.ProcessName != "" && a.safety != nil {
				if a.safety.IsWhitelisted(t.ProcessName) {
					c.JSON(400, gin.H{"error": fmt.Sprintf("进程 %s 在白名单中，请通过 systemctl restart 重启", t.ProcessName)})
					return
				}
			}
			if t.Command != "" {
				var cmd *exec.Cmd
				if runtime.GOOS == "windows" {
					cmd = exec.CommandContext(ctx, "cmd", "/c", t.Command)
				} else {
					cmd = exec.CommandContext(ctx, "sh", "-c", t.Command)
				}
				if err := cmd.Start(); err != nil {
					c.JSON(500, gin.H{"error": fmt.Sprintf("restart failed: %v", err)})
					return
				}
				a.storage.SaveAudit(types.AuditEntry{
					ID:        uuid.NewString(),
					Timestamp: time.Now(),
					Actor:     "api",
					Action:    "restart",
					Target:    t.Name,
					Reason:    "用户手动重启服务",
					Result:    "success",
				})
				c.JSON(200, gin.H{"message": fmt.Sprintf("%s restarted (PID %d)", t.Name, cmd.Process.Pid)})
				return
			}
			c.JSON(400, gin.H{"error": "no command configured for this target"})
			return
		}
	}
	c.JSON(404, gin.H{"error": "guard target not found"})
}

func (a *API) getAlerts(c *gin.Context) {
	alerts, err := a.storage.GetUnresolvedAlerts()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"alerts": alerts})
}

func (a *API) ackAlert(c *gin.Context) {
	id := c.Param("id")
	if err := a.storage.AckAlert(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "alert acknowledged"})
}

func (a *API) resolveAlert(c *gin.Context) {
	id := c.Param("id")
	if err := a.storage.ResolveAlert(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     "api",
		Action:    "resolve_alert",
		Target:    id,
		Reason:    "用户手动解决告警",
		Result:    "success",
	})
	c.JSON(200, gin.H{"message": "alert resolved"})
}

func (a *API) getLogs(c *gin.Context) {
	since := time.Now().Add(-72 * time.Hour)
	limit := 200
	actions, err := a.storage.GetActionHistory(since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// 扁平化输出：将 ActionResult.Action.Type 提升为顶层 action_type 字段
	result := make([]gin.H, 0, len(actions))
	for _, act := range actions {
		target := ""
		if act.Action.Params != nil {
			if t, ok := act.Action.Params["target"]; ok {
				target = fmt.Sprintf("%v", t)
			}
		}
		result = append(result, gin.H{
			"action_type": string(act.Action.Type),
			"target":      target,
			"success":     act.Success,
			"message":     act.Message,
			"error":       act.Error,
			"duration":    act.Duration.Milliseconds(),
			"timestamp":   act.Timestamp,
		})
	}
	c.JSON(200, gin.H{"actions": result})
}

func (a *API) getAuditLog(c *gin.Context) {
	since := time.Now().Add(-72 * time.Hour)
	limit := 200
	entries, err := a.storage.GetAuditLog(since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"audit": entries})
}

func (a *API) getSafetyStatus(c *gin.Context) {
	status := a.safety.GetKillBudgetStatus()

	// Get recent action history (last 24h)
	since := time.Now().Add(-24 * time.Hour)
	actions, _ := a.storage.GetActionHistory(since, 50)

	// Baota detection
	isBaota := a.baotaDiscovery != nil && a.baotaDiscovery.IsDetected()

	c.JSON(200, gin.H{
		"mode":           string(a.safety.GetMode()),
		"emergency_stop": a.safety.IsEmergencyStopped(),
		"kill_budget":    status,
		"circuit_breakers": gin.H{
			"kill":       a.safety.GetCircuitBreakerState("kill"),
			"restart":    a.safety.GetCircuitBreakerState("restart"),
			"ban_ip":     a.safety.GetCircuitBreakerState("ban_ip"),
			"clean_log":  a.safety.GetCircuitBreakerState("clean_log"),
			"renew_cert": a.safety.GetCircuitBreakerState("renew_cert"),
		},
		"whitelist":       a.safety.GetWhitelist(),
		"recent_actions":  actions,
		"baota_safe_mode": a.safety.IsBaotaSafeMode(),
		"is_baota":        isBaota,
	})
}

func (a *API) emergencyStop(c *gin.Context) {
	halt := c.Query("halt") == "true"
	a.safety.TriggerEmergencyStop(halt)
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     "api",
		Action:    "emergency_stop",
		Reason:    "用户通过界面手动触发",
		Result:    "success",
	})
	c.JSON(200, gin.H{"message": "emergency stop activated", "halt": halt})
}

func (a *API) emergencyResume(c *gin.Context) {
	a.safety.ResumeFromEmergencyStop()
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     "api",
		Action:    "emergency_resume",
		Reason:    "用户通过界面手动恢复",
		Result:    "success",
	})
	c.JSON(200, gin.H{"message": "emergency stop deactivated"})
}

// --- Health Score ---

func (a *API) getHealthScore(c *gin.Context) {
	if a.scorer == nil {
		c.JSON(200, gin.H{"total": 100, "deductions": []interface{}{}})
		return
	}
	score := a.scorer.Get()
	c.JSON(200, score)
}

// getInsights 返回智能洞察状态（基线偏离、内存趋势、变慢站点）。
// 未注入检测器时返回空结构（learning=false），前端按"无数据"处理。
func (a *API) getInsights(c *gin.Context) {
	if a.anomalyDet == nil {
		c.JSON(200, gin.H{"learning": false, "metrics": []interface{}{}, "slow_sites": []interface{}{}})
		return
	}
	c.JSON(200, a.anomalyDet.GetInsights())
}

// --- Website / Service Monitoring ---

func (a *API) getProbeSites(c *gin.Context) {
	if a.probe == nil {
		c.JSON(200, gin.H{"sites": []interface{}{}})
		return
	}
	c.JSON(200, gin.H{"sites": a.probe.GetSites()})
}

func (a *API) addProbeSite(c *gin.Context) {
	if a.probe == nil {
		c.JSON(500, gin.H{"error": "probe not initialized"})
		return
	}
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}
	if req.URL == "" {
		c.JSON(400, gin.H{"error": "URL 不能为空"})
		return
	}
	if req.Name == "" {
		req.Name = req.URL
	}
	id := uuid.New().String()[:8]
	a.probe.AddSite(id, req.Name, req.URL, 30*time.Second)
	// Persist to storage
	a.storage.Set(fmt.Sprintf("probe_site:%s", id), req.Name+"|"+req.URL)
	c.JSON(200, gin.H{"id": id, "message": "监控已添加"})
}

func (a *API) deleteProbeSite(c *gin.Context) {
	if a.probe == nil {
		c.JSON(500, gin.H{"error": "probe not initialized"})
		return
	}
	id := c.Param("id")
	a.probe.RemoveSite(id)
	// Remove from storage
	a.storage.Set(fmt.Sprintf("probe_site:%s", id), "")
	c.JSON(200, gin.H{"message": "监控已删除"})
}

// --- API Endpoint Monitoring ---

func (a *API) getProbeEndpoints(c *gin.Context) {
	if a.probe == nil {
		c.JSON(200, gin.H{"endpoints": []interface{}{}})
		return
	}
	c.JSON(200, gin.H{"endpoints": a.probe.GetEndpoints()})
}

func (a *API) addProbeEndpoint(c *gin.Context) {
	if a.probe == nil {
		c.JSON(500, gin.H{"error": "probe not initialized"})
		return
	}
	var req struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		Method string `json:"method"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}
	if req.URL == "" {
		c.JSON(400, gin.H{"error": "URL 不能为空"})
		return
	}
	if req.Name == "" {
		req.Name = req.URL
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	id := uuid.New().String()[:8]
	a.probe.AddEndpoint(id, req.Name, req.URL, req.Method, 60*time.Second)
	c.JSON(200, gin.H{"id": id, "message": "接口监控已添加"})
}

func (a *API) deleteProbeEndpoint(c *gin.Context) {
	if a.probe == nil {
		c.JSON(500, gin.H{"error": "probe not initialized"})
		return
	}
	id := c.Param("id")
	a.probe.RemoveEndpoint(id)
	c.JSON(200, gin.H{"message": "接口监控已删除"})
}

// --- Site Discovery ---

func (a *API) discoverSites(c *gin.Context) {
	if a.siteDiscover == nil {
		c.JSON(200, gin.H{"sites": []interface{}{}, "message": "站点发现未初始化"})
		return
	}
	sites := a.siteDiscover.Discover()

	// Mark which ones are already being monitored
	monitored := make(map[string]bool)
	if a.probe != nil {
		for _, s := range a.probe.GetSites() {
			monitored[s.URL] = true
		}
	}

	result := make([]gin.H, 0, len(sites))
	for _, s := range sites {
		result = append(result, gin.H{
			"name":              s.Name,
			"url":               s.URL,
			"domain":            s.Domain,
			"source":            s.Source,
			"port":              s.Port,
			"ssl":               s.SSL,
			"config_file":       s.ConfigFile,
			"already_monitored": monitored[s.URL],
		})
	}

	sourceLabel := "IIS"
	if len(sites) > 0 {
		switch sites[0].Source {
		case "nginx":
			sourceLabel = "Nginx"
		case "apache":
			sourceLabel = "Apache"
		case "baota":
			sourceLabel = "宝塔面板"
		case "iis":
			sourceLabel = "IIS"
		}
	}

	c.JSON(200, gin.H{
		"sites":   result,
		"count":   len(result),
		"source":  sourceLabel,
		"message": fmt.Sprintf("从 %s 发现 %d 个站点", sourceLabel, len(result)),
	})
}

// autoDiscoverSites 返回缓存的自动发现结果（不触发重新扫描）
func (a *API) autoDiscoverSites(c *gin.Context) {
	if a.siteDiscover == nil {
		c.JSON(200, gin.H{"sites": []interface{}{}, "message": "站点发现未初始化"})
		return
	}
	sites := a.siteDiscover.GetSites()

	// Mark which ones are already being monitored
	monitored := make(map[string]bool)
	if a.probe != nil {
		for _, s := range a.probe.GetSites() {
			monitored[s.URL] = true
		}
	}

	result := make([]gin.H, 0, len(sites))
	for _, s := range sites {
		result = append(result, gin.H{
			"name":              s.Name,
			"url":               s.URL,
			"domain":            s.Domain,
			"source":            s.Source,
			"port":              s.Port,
			"ssl":               s.SSL,
			"config_file":       s.ConfigFile,
			"already_monitored": monitored[s.URL],
		})
	}

	sourceLabel := "IIS"
	if len(sites) > 0 {
		switch sites[0].Source {
		case "nginx":
			sourceLabel = "Nginx"
		case "apache":
			sourceLabel = "Apache"
		case "baota":
			sourceLabel = "宝塔面板"
		case "iis":
			sourceLabel = "IIS"
		}
	}

	c.JSON(200, gin.H{
		"sites":   result,
		"count":   len(result),
		"source":  sourceLabel,
		"message": fmt.Sprintf("从 %s 发现 %d 个站点", sourceLabel, len(result)),
	})
}

func (a *API) importDiscoveredSites(c *gin.Context) {
	if a.probe == nil {
		c.JSON(500, gin.H{"error": "probe not initialized"})
		return
	}
	var req struct {
		Sites []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"sites"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	imported := 0
	for _, s := range req.Sites {
		if s.URL == "" {
			continue
		}
		if s.Name == "" {
			s.Name = s.URL
		}
		id := uuid.New().String()[:8]
		a.probe.AddSite(id, s.Name, s.URL, 30*time.Second)
		imported++
	}

	c.JSON(200, gin.H{
		"message":  fmt.Sprintf("已导入 %d 个站点到监控", imported),
		"imported": imported,
	})
}

// --- Notification Settings ---

func (a *API) getNotifySettings(c *gin.Context) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := a.cfg.Notify
	c.JSON(200, gin.H{
		"wxpusher_app_token": n.WxPusherAppToken,
		"wxpusher_uid":       n.WxPusherUID,
		"smtp_host":          n.SMTPHost,
		"smtp_port":          n.SMTPPort,
		"smtp_user":          n.SMTPUser,
		"smtp_password":      n.SMTPPassword,
		"email_to":           n.EmailTo,
		"digest_enabled":     n.DigestEnabled,
		"digest_hour":        n.DigestHour,
		"silence_enabled":    n.Silence.Enabled,
	})
}

func (a *API) saveNotifySettings(c *gin.Context) {
	var req map[string]interface{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if v, ok := req["wxpusher_app_token"].(string); ok {
		a.cfg.Notify.WxPusherAppToken = v
	}
	if v, ok := req["wxpusher_uid"].(string); ok {
		a.cfg.Notify.WxPusherUID = v
	}
	if v, ok := req["smtp_host"].(string); ok {
		a.cfg.Notify.SMTPHost = v
	}
	if v, ok := req["smtp_port"].(string); ok {
		a.cfg.Notify.SMTPPort = v
	}
	if v, ok := req["smtp_user"].(string); ok {
		a.cfg.Notify.SMTPUser = v
	}
	if v, ok := req["smtp_password"].(string); ok {
		a.cfg.Notify.SMTPPassword = v
	}
	if v, ok := req["email_to"].(string); ok {
		a.cfg.Notify.EmailTo = v
	}
	if v, ok := req["digest_enabled"].(bool); ok {
		a.cfg.Notify.DigestEnabled = v
	}
	if v, ok := req["digest_hour"].(float64); ok {
		a.cfg.Notify.DigestHour = int(v)
	}
	if v, ok := req["silence_enabled"].(bool); ok {
		a.cfg.Notify.Silence.Enabled = v
	}

	// Save to config file
	if err := a.cfg.Save(a.configPath); err != nil {
		c.JSON(500, gin.H{"error": "保存配置文件失败: " + err.Error()})
		return
	}

	// Rebuild channels
	a.rebuildNotifierChannels()

	c.JSON(200, gin.H{"message": "通知设置已保存并生效"})
}

func (a *API) testNotify(c *gin.Context) {
	if a.notifier == nil {
		c.JSON(500, gin.H{"error": "通知系统未初始化"})
		return
	}

	// Rebuild channels first (in case user just saved settings)
	a.rebuildNotifierChannels()

	hostname, _ := os.Hostname()
	err := a.notifier.SendCustom(
		"ServerGuard 测试通知",
		fmt.Sprintf("这是一条来自 ServerGuard 的测试通知。\n\n服务器: %s\n时间: %s\n\n如果您收到此消息，说明通知配置正确。", hostname, time.Now().Format("2006-01-02 15:04:05")),
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "测试通知已发送，请检查您的 WxPusher/邮箱"})
}

// rebuildNotifierChannels rebuilds all notification channels from current config.
func (a *API) rebuildNotifierChannels() {
	if a.notifier == nil {
		return
	}
	n := a.cfg.Notify
	var channels []notifier.Channel

	// WxPusher (multi-platform push)
	if n.WxPusherAppToken != "" && n.WxPusherUID != "" {
		channels = append(channels, notifier.NewWxPusherChannel("wxpusher", n.WxPusherAppToken, n.WxPusherUID))
	}

	// Email
	if n.SMTPHost != "" && n.SMTPUser != "" && n.EmailTo != "" {
		recipients := strings.Split(n.EmailTo, ",")
		for i := range recipients {
			recipients[i] = strings.TrimSpace(recipients[i])
		}
		channels = append(channels, notifier.NewEmailChannel(
			"email", n.SMTPHost, n.SMTPPort,
			n.SMTPUser, n.SMTPPassword,
			n.SMTPUser, recipients,
		))
	}

	a.notifier.UpdateChannels(channels)
	a.notifier.SetDigest(n.DigestEnabled, n.DigestHour)
}

func (a *API) getCerts(c *gin.Context) {
	if a.certGuard == nil {
		c.JSON(200, gin.H{"certs": []interface{}{}})
		return
	}
	certs := a.certGuard.GetCerts()
	c.JSON(200, gin.H{"certs": certs})
}

func (a *API) getGuards(c *gin.Context) {
	targets, err := a.storage.GetGuardTargets()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"guards": targets})
}

func (a *API) addGuard(c *gin.Context) {
	var target types.GuardTarget
	if err := c.ShouldBindJSON(&target); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if target.ID == "" {
		target.ID = uuid.NewString()
	}
	target.RestartPolicy = types.DefaultRestartPolicy()
	// Ensure new guards are enabled by default
	target.Enabled = true
	if err := a.storage.SaveGuardTarget(target); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, target)
}

func (a *API) deleteGuard(c *gin.Context) {
	id := c.Param("id")
	if err := a.storage.DeleteGuardTarget(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "guard deleted"})
}

func (a *API) getBaoTaStatus(c *gin.Context) {
	if a.baotaDiscovery == nil {
		c.JSON(200, gin.H{"detected": false, "message": "baota discovery not configured"})
		return
	}
	c.JSON(200, gin.H{
		"detected":     a.baotaDiscovery.IsDetected(),
		"version":      a.baotaDiscovery.Version(),
		"panel_type":   a.baotaDiscovery.PanelType(),
		"install_path": a.baotaDiscovery.GetInstallPath(),
		"sites":        a.baotaDiscovery.GetSites(),
		"capabilities": a.baotaDiscovery.GetCapabilityMap(),
	})
}

func (a *API) rescanBaoTa(c *gin.Context) {
	if a.baotaDiscovery == nil {
		c.JSON(500, gin.H{"error": "baota discovery not configured"})
		return
	}
	a.baotaDiscovery.Rescan()
	c.JSON(200, gin.H{
		"message":    "rescan completed",
		"detected":   a.baotaDiscovery.IsDetected(),
		"version":    a.baotaDiscovery.Version(),
		"panel_type": a.baotaDiscovery.PanelType(),
	})
}

// ====== Security Findings handlers (W/X/Y 模块) ======

func (a *API) getFindings(c *gin.Context) {
	scanner := c.Query("scanner")
	severity := c.Query("severity")
	status := c.Query("status")
	limit := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	findings, err := a.storage.QueryFindings(scanner, severity, status, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"findings": findings})
}

// getFindingStats 返回各扫描器的发现项数量
func (a *API) getFindingStats(c *gin.Context) {
	counts, err := a.storage.GetFindingCountByScanner()
	if err != nil {
		fmt.Printf("[ERROR] getFindingStats: %v\n", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	total := 0
	for _, cnt := range counts {
		total += cnt
	}

	c.JSON(200, gin.H{
		"counts": counts,
		"total":  total,
	})
}

func (a *API) getFinding(c *gin.Context) {
	id := c.Param("id")
	f, err := a.storage.GetFinding(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "finding not found"})
		return
	}
	c.JSON(200, f)
}

func (a *API) confirmFinding(c *gin.Context) {
	id := c.Param("id")
	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	if err := a.storage.UpdateFindingStatus(id, "confirmed", confirmedBy); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "confirm_finding",
		Target:    id,
		Reason:    "用户确认安全发现",
		Result:    "success",
	})
	c.JSON(200, gin.H{"message": "finding confirmed", "id": id})
}

func (a *API) markFalsePositive(c *gin.Context) {
	id := c.Param("id")
	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	if err := a.storage.UpdateFindingStatus(id, "false_positive", confirmedBy); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "mark_false_positive",
		Target:    id,
		Reason:    "用户标记为误报",
		Result:    "success",
	})
	c.JSON(200, gin.H{"message": "finding marked as false positive", "id": id})
}

// autoFixFinding 自动修复安全发现项
func (a *API) autoFixFinding(c *gin.Context) {
	id := c.Param("id")
	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}

	// 查询 finding 详情
	findings, err := a.storage.QueryFindings("", "", "", 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	var finding *storage.Finding
	for i := range findings {
		if findings[i].ID == id {
			finding = &findings[i]
			break
		}
	}
	if finding == nil {
		c.JSON(404, gin.H{"error": "finding not found"})
		return
	}

	title := finding.Title
	target := finding.Target
	scanner := finding.Scanner

	// ─── 1. nginx 安全头缺失 → 追加 add_header 指令 ───
	if strings.Contains(title, "安全头缺失") && strings.HasSuffix(target, ".conf") {
		result, err := autoFixNginxSecurityHeaders(target)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error(), "fixed": false})
			return
		}
		a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     confirmedBy,
			Action:    "auto_fix_finding",
			Target:    id,
			Reason:    fmt.Sprintf("自动修复安全头缺失: %s", target),
			Result:    "success",
		})
		c.JSON(200, gin.H{"message": "修复成功", "id": id, "detail": result, "fixed": true})
		return
	}

	// ─── 2. 攻击预警类发现（SSH暴破/端口扫描等）→ 已自动封禁，标记为已解决 ───
	if scanner == "attackwarn" {
		// 攻击预警的发现项已在保存时自动处置（封禁IP或告警）
		// 如果状态还是 open，说明是旧数据，直接标记为已解决
		if finding.Status == "open" {
			a.storage.UpdateFindingStatus(id, "resolved", confirmedBy)
			a.storage.SaveAudit(types.AuditEntry{
				ID:        uuid.NewString(),
				Timestamp: time.Now(),
				Actor:     confirmedBy,
				Action:    "auto_fix_finding",
				Target:    id,
				Reason:    fmt.Sprintf("攻击预警发现项已自动处置: %s", title),
				Result:    "success",
			})
			c.JSON(200, gin.H{"message": "该攻击已自动处置（封禁IP或告警），已标记为已解决", "id": id, "fixed": true})
			return
		}
		c.JSON(200, gin.H{"message": "该发现项已处理", "id": id, "fixed": true})
		return
	}

	// ─── 3. 目录权限过宽 → 自动收紧权限 ───
	if strings.Contains(title, "权限") && strings.Contains(title, "过宽") && target != "" {
		// 只处理明确的目录路径
		if strings.HasPrefix(target, "/") && !strings.Contains(target, "..") {
			// 设置为 750（所有者可读写执行，组可读执行，其他无权限）
			if err := os.Chmod(target, 0750); err != nil {
				c.JSON(500, gin.H{"error": fmt.Sprintf("修改权限失败: %v", err), "fixed": false})
				return
			}
			a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
			a.storage.SaveAudit(types.AuditEntry{
				ID:        uuid.NewString(),
				Timestamp: time.Now(),
				Actor:     confirmedBy,
				Action:    "auto_fix_finding",
				Target:    id,
				Reason:    fmt.Sprintf("自动收紧目录权限: %s → 750", target),
				Result:    "success",
			})
			c.JSON(200, gin.H{"message": "已自动收紧目录权限为 750", "id": id, "fixed": true})
			return
		}
	}

	// ─── 4. 敏感文件暴露 → 自动收紧权限 ───
	if (strings.Contains(title, "敏感文件") || strings.Contains(title, "敏感信息暴露")) && target != "" {
		if strings.HasPrefix(target, "/") && !strings.Contains(target, "..") {
			if err := os.Chmod(target, 0600); err != nil {
				c.JSON(500, gin.H{"error": fmt.Sprintf("修改权限失败: %v", err), "fixed": false})
				return
			}
			a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
			a.storage.SaveAudit(types.AuditEntry{
				ID:        uuid.NewString(),
				Timestamp: time.Now(),
				Actor:     confirmedBy,
				Action:    "auto_fix_finding",
				Target:    id,
				Reason:    fmt.Sprintf("自动收紧敏感文件权限: %s → 600", target),
				Result:    "success",
			})
			c.JSON(200, gin.H{"message": "已自动收紧敏感文件权限为 600", "id": id, "fixed": true})
			return
		}
	}

	// ─── 5. SSH 配置安全问题 → 安全加固（不重启 sshd，避免断连） ───
	if strings.Contains(title, "SSH") && strings.Contains(title, "配置") {
		result, err := autoFixSSHConfig(target)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error(), "fixed": false})
			return
		}
		a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     confirmedBy,
			Action:    "auto_fix_finding",
			Target:    id,
			Reason:    fmt.Sprintf("自动加固 SSH 配置: %s", target),
			Result:    "success",
		})
		c.JSON(200, gin.H{"message": "修复成功", "id": id, "detail": result, "fixed": true})
		return
	}

	// ─── 6. server_tokens 未关闭 → 自动添加 server_tokens off ───
	if strings.Contains(title, "server_tokens") && strings.HasSuffix(target, ".conf") {
		result, err := autoFixServerTokens(target)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error(), "fixed": false})
			return
		}
		a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     confirmedBy,
			Action:    "auto_fix_finding",
			Target:    id,
			Reason:    fmt.Sprintf("自动关闭 server_tokens: %s", target),
			Result:    "success",
		})
		c.JSON(200, gin.H{"message": "修复成功", "id": id, "detail": result, "fixed": true})
		return
	}

	// ─── 7. CORS 配置过于宽松 → 给出修复建议（不自动修改，因为不知道用户的实际域名） ───
	if strings.Contains(title, "CORS") && strings.Contains(title, "宽松") {
		c.JSON(200, gin.H{
			"message":     "CORS 配置需手动修改，因为系统不知道您的实际可信域名。建议将 Access-Control-Allow-Origin: * 替换为具体域名，例如: add_header Access-Control-Allow-Origin \"https://your-domain.com\" always;",
			"id":          id,
			"fixed":       false,
			"manual":      true,
			"fix_command": "将配置中的 Access-Control-Allow-Origin * 替换为您的实际域名",
		})
		return
	}

	// ─── 8. SSL 弱协议/弱加密套件 → 自动升级为 TLSv1.2+1.3 ───
	if (strings.Contains(title, "SSL 弱协议") || strings.Contains(title, "弱加密套件")) && strings.HasSuffix(target, ".conf") {
		result, err := autoFixSSLConfig(target)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error(), "fixed": false})
			return
		}
		a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     confirmedBy,
			Action:    "auto_fix_finding",
			Target:    id,
			Reason:    fmt.Sprintf("自动加固 SSL 配置: %s", target),
			Result:    "success",
		})
		c.JSON(200, gin.H{"message": "修复成功", "id": id, "detail": result, "fixed": true})
		return
	}

	// ─── 9. 目录遍历开启 → 自动关闭 autoindex ───
	if strings.Contains(title, "目录遍历") && strings.HasSuffix(target, ".conf") {
		result, err := autoFixDirectoryListing(target)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error(), "fixed": false})
			return
		}
		a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     confirmedBy,
			Action:    "auto_fix_finding",
			Target:    id,
			Reason:    fmt.Sprintf("自动关闭目录遍历: %s", target),
			Result:    "success",
		})
		c.JSON(200, gin.H{"message": "修复成功", "id": id, "detail": result, "fixed": true})
		return
	}

	// ─── 10. 敏感文件泄露 → 添加 nginx 拒绝规则（不删除文件，避免破坏功能） ───
	if (strings.Contains(title, "敏感文件泄露") || strings.Contains(title, "敏感文件可通过HTTP")) && target != "" {
		// 安全策略：不删除文件，只添加 nginx 拒绝访问规则
		// 因为删除文件可能破坏依赖该文件的合法功能
		if strings.HasPrefix(target, "/") && !strings.Contains(target, "..") {
			// 文件系统路径：在 nginx 配置中添加 location deny 规则
			nginxConf := "/www/server/panel/vhost/nginx/default.conf"
			if _, err := os.Stat(nginxConf); err != nil {
				nginxConf = "/etc/nginx/conf.d/default.conf"
			}
			if _, err := os.Stat(nginxConf); err != nil {
				c.JSON(200, gin.H{"message": "未找到 nginx 配置文件，请手动在 Web 服务器中配置拒绝访问该路径", "id": id, "fixed": false, "manual": true})
				return
			}

			// 构造 deny 规则（使用精确路径，避免路径遍历）
			denyLocation := target
			// 如果是目录，添加 location 路径
			if info, err := os.Stat(target); err == nil && info.IsDir() {
				denyLocation = target
			}

			denyRule := fmt.Sprintf("\n# ServerGuard 自动添加 - 拒绝访问敏感文件\nlocation %s {\n    deny all;\n    return 404;\n}\n", denyLocation)

			// 备份 nginx 配置
			backupPath := nginxConf + ".sg.bak"
			origContent, _ := os.ReadFile(nginxConf)
			os.WriteFile(backupPath, origContent, 0644)

			// 追加 deny 规则
			f, err := os.OpenFile(nginxConf, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				c.JSON(500, gin.H{"error": fmt.Sprintf("无法写入 nginx 配置: %v", err), "fixed": false})
				return
			}
			f.WriteString(denyRule)
			f.Close()

			// nginx -t 检查配置是否正确
			testCmd := exec.Command("nginx", "-t")
			testOutput, testErr := testCmd.CombinedOutput()
			if testErr != nil {
				// 配置测试失败，回滚
				os.WriteFile(nginxConf, origContent, 0644)
				c.JSON(500, gin.H{"error": fmt.Sprintf("nginx 配置测试失败，已回滚: %s", string(testOutput)), "fixed": false})
				return
			}

			// reload nginx
			exec.Command("nginx", "-s", "reload").Run()

			a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
			a.storage.SaveAudit(types.AuditEntry{
				ID:        uuid.NewString(),
				Timestamp: time.Now(),
				Actor:     confirmedBy,
				Action:    "auto_fix_finding",
				Target:    id,
				Reason:    fmt.Sprintf("自动添加 nginx 拒绝规则: %s (未删除文件)", denyLocation),
				Result:    "success",
			})
			c.JSON(200, gin.H{"message": fmt.Sprintf("已在 nginx 中添加拒绝访问规则: %s（文件未删除，如需删除请手动处理）", denyLocation), "id": id, "fixed": true, "nginx_backup": backupPath})
			return
		}
		// 如果是 URL，提取路径后添加 nginx 拒绝规则
		if strings.HasPrefix(target, "http") {
			uPath := strings.SplitN(target, "/", 4)
			if len(uPath) >= 4 {
				denyPath := "/" + uPath[3]
				nginxConf := "/www/server/panel/vhost/nginx/default.conf"
				if _, err := os.Stat(nginxConf); err != nil {
					nginxConf = "/etc/nginx/conf.d/default.conf"
				}
				if _, err := os.Stat(nginxConf); err != nil {
					c.JSON(200, gin.H{"message": "未找到 nginx 配置文件，请手动配置拒绝访问该 URL 路径", "id": id, "fixed": false, "manual": true})
					return
				}

				denyRule := fmt.Sprintf("\n# ServerGuard 自动添加 - 拒绝访问敏感文件\nlocation %s {\n    deny all;\n    return 404;\n}\n", denyPath)

				// 备份 + 写入 + 测试 + reload
				backupPath := nginxConf + ".sg.bak"
				origContent, _ := os.ReadFile(nginxConf)
				os.WriteFile(backupPath, origContent, 0644)

				f, err := os.OpenFile(nginxConf, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					c.JSON(500, gin.H{"error": fmt.Sprintf("无法写入 nginx 配置: %v", err), "fixed": false})
					return
				}
				f.WriteString(denyRule)
				f.Close()

				testCmd := exec.Command("nginx", "-t")
				testOutput, testErr := testCmd.CombinedOutput()
				if testErr != nil {
					// 回滚
					os.WriteFile(nginxConf, origContent, 0644)
					c.JSON(500, gin.H{"error": fmt.Sprintf("nginx 配置测试失败，已回滚: %s", string(testOutput)), "fixed": false})
					return
				}
				exec.Command("nginx", "-s", "reload").Run()

				a.storage.UpdateFindingStatus(id, "fixed", confirmedBy)
				a.storage.SaveAudit(types.AuditEntry{
					ID:        uuid.NewString(),
					Timestamp: time.Now(),
					Actor:     confirmedBy,
					Action:    "auto_fix_finding",
					Target:    id,
					Reason:    fmt.Sprintf("自动添加 nginx 拒绝规则: %s", denyPath),
					Result:    "success",
				})
				c.JSON(200, gin.H{"message": fmt.Sprintf("已在 nginx 中添加拒绝访问规则: %s", denyPath), "id": id, "fixed": true, "nginx_backup": backupPath})
				return
			}
		}
	}

	// ─── 11. 数据库未授权访问 → 自动启用认证提示 ───
	if strings.Contains(title, "未授权访问") {
		dbType := ""
		if strings.Contains(title, "Elasticsearch") {
			dbType = "Elasticsearch"
		} else if strings.Contains(title, "Redis") {
			dbType = "Redis"
		} else if strings.Contains(title, "MongoDB") {
			dbType = "MongoDB"
		}
		var fixCmd string
		switch dbType {
		case "Elasticsearch":
			fixCmd = "在 elasticsearch.yml 中设置: xpack.security.enabled: true\n然后执行: bin/elasticsearch-setup-passwords auto"
		case "Redis":
			fixCmd = "在 redis.conf 中设置: requirepass <强密码>\n然后重启 redis-server"
		case "MongoDB":
			fixCmd = "启动时添加 --auth 参数\n并在 admin 数据库创建用户: db.createUser({user:'admin',pwd:'密码',roles:['root']})"
		default:
			fixCmd = "请参考对应数据库文档启用认证"
		}
		c.JSON(200, gin.H{"message": "数据库未授权访问需手动配置认证", "id": id, "fixed": false, "manual": true, "fix_command": fixCmd})
		return
	}

	// ─── 12. 空密码/弱密码检测 → 标记为已确认（需用户手动处理） ───
	if strings.Contains(title, "空密码") || strings.Contains(title, "弱密码") || strings.Contains(title, "默认密码") {
		c.JSON(200, gin.H{"message": "密码类发现项需手动修改密码，无法自动修复。请在对应服务中修改密码后点击“确认”", "id": id, "fixed": false, "manual": true})
		return
	}

	c.JSON(400, gin.H{"error": "该发现项暂不支持自动修复", "fixed": false, "title": title})
}

// autoFixSSHConfig 安全加固 SSH 配置（不重启 sshd）
func autoFixSSHConfig(configPath string) (string, error) {
	if configPath == "" {
		configPath = "/etc/ssh/sshd_config"
	}
	if _, err := os.Stat(configPath); err != nil {
		return "", fmt.Errorf("配置文件不存在: %s", configPath)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var changes []string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// 跳过注释行
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// PermitRootLogin yes → no
		if strings.HasPrefix(trimmed, "PermitRootLogin") && strings.Contains(trimmed, "yes") {
			lines[i] = "PermitRootLogin no"
			changes = append(changes, "禁止 root 登录")
		}

		// PermitEmptyPasswords yes → no
		if strings.HasPrefix(trimmed, "PermitEmptyPasswords") && strings.Contains(trimmed, "yes") {
			lines[i] = "PermitEmptyPasswords no"
			changes = append(changes, "禁止空密码登录")
		}

		// PasswordAuthentication no → yes（确保密码登录可用，避免锁死）
		// 不修改此项，避免断连
	}

	if len(changes) == 0 {
		return "SSH 配置已安全，无需修改", nil
	}

	// 写回文件
	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return "", fmt.Errorf("写入配置文件失败: %w", err)
	}

	return fmt.Sprintf("已加固 SSH 配置: %s（修改不会立即生效，需重启 sshd 服务）", strings.Join(changes, "、")), nil
}

// safeNginxWrite 安全写入 nginx 配置：备份 → 写入 → nginx -t 测试 → 失败则回滚 → 成功则 reload
// 返回备份路径和错误。如果 nginx -t 失败，会自动恢复原文件并返回错误。
func safeNginxWrite(configPath string, newContent []byte) (backupPath string, err error) {
	// 读取原文件
	origContent, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取原配置失败: %w", err)
	}

	// 备份
	backupPath = configPath + ".sg.bak"
	if err := os.WriteFile(backupPath, origContent, 0644); err != nil {
		return "", fmt.Errorf("备份配置失败: %w", err)
	}

	// 写入新内容
	if err := os.WriteFile(configPath, newContent, 0644); err != nil {
		// 写入失败，恢复原文件
		os.WriteFile(configPath, origContent, 0644)
		return "", fmt.Errorf("写入新配置失败: %w", err)
	}

	// nginx -t 测试配置
	testCmd := exec.Command("nginx", "-t")
	testOutput, testErr := testCmd.CombinedOutput()
	if testErr != nil {
		// 配置测试失败，回滚
		os.WriteFile(configPath, origContent, 0644)
		return "", fmt.Errorf("nginx 配置测试失败，已回滚: %s", strings.TrimSpace(string(testOutput)))
	}

	// 测试通过，reload
	reloadCmd := exec.Command("nginx", "-s", "reload")
	reloadCmd.Run()

	return backupPath, nil
}

// autoFixNginxSecurityHeaders 向 nginx 配置文件追加安全头
func autoFixNginxSecurityHeaders(configPath string) (string, error) {
	// 检查文件是否存在
	if _, err := os.Stat(configPath); err != nil {
		return "", fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取原文件
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 构建要追加的安全头
	securityHeaders := `
# ServerGuard 自动添加的安全头
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;
`

	// 检查是否已经包含部分安全头（避免重复添加）
	if strings.Contains(string(content), "X-Frame-Options") && strings.Contains(string(content), "X-Content-Type-Options") {
		return "配置文件已包含安全头，无需重复添加", nil
	}

	// 在 server 块的最后一个 } 之前插入
	lines := strings.Split(string(content), "\n")
	inserted := false
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "}" {
			// 在这行之前插入安全头
			lines = append(lines[:i], append([]string{securityHeaders}, lines[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		// 没找到 }，直接追加到末尾
		lines = append(lines, securityHeaders)
	}

	newContent := strings.Join(lines, "\n")

	// 安全写入：备份 → 写入 → nginx -t 测试 → 失败回滚 → reload
	backupPath, err := safeNginxWrite(configPath, []byte(newContent))
	if err != nil {
		return "", err
	}

	result := fmt.Sprintf("已在 %s 中添加安全头，原文件备份至 %s，nginx -t 通过并已 reload", configPath, backupPath)
	return result, nil
}

// autoFixServerTokens 自动关闭 nginx server_tokens
func autoFixServerTokens(configPath string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	changed := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// 跳过注释行
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		// server_tokens on → off
		if strings.Contains(trimmed, "server_tokens") && strings.Contains(trimmed, "on") && !strings.Contains(trimmed, "off") {
			lines[i] = strings.Replace(line, "on", "off", 1)
			changed = true
		}
	}

	if !changed {
		// 没有 server_tokens 指令，在 http 或 server 块中添加
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "server {" {
				lines = append(lines[:i+1], append([]string{"    server_tokens off;"}, lines[i+1:]...)...)
				changed = true
				break
			}
		}
		if !changed {
			lines = append([]string{"server_tokens off;"}, lines...)
			changed = true
		}
	}

	newContent := strings.Join(lines, "\n")

	// 安全写入：备份 → 写入 → nginx -t 测试 → 失败回滚 → reload
	backupPath, err := safeNginxWrite(configPath, []byte(newContent))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("已关闭 server_tokens，原文件备份至 %s，nginx -t 通过并已 reload", backupPath), nil
}

// autoFixSSLConfig 自动加固 SSL 配置（禁用弱协议和弱加密套件）
func autoFixSSLConfig(configPath string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var changes []string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// 替换 ssl_protocols
		if strings.Contains(trimmed, "ssl_protocols") {
			lines[i] = "    ssl_protocols TLSv1.2 TLSv1.3;"
			changes = append(changes, "ssl_protocols 仅保留 TLSv1.2 和 TLSv1.3")
		}

		// 替换 ssl_ciphers
		if strings.Contains(trimmed, "ssl_ciphers") {
			lines[i] = "    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';"
			changes = append(changes, "ssl_ciphers 仅保留强加密套件")
		}
	}

	if len(changes) == 0 {
		return "SSL 配置已安全，无需修改", nil
	}

	newContent := strings.Join(lines, "\n")

	// 安全写入：备份 → 写入 → nginx -t 测试 → 失败回滚 → reload
	backupPath, err := safeNginxWrite(configPath, []byte(newContent))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("已加固 SSL 配置: %s，原文件备份至 %s，nginx -t 通过并已 reload", strings.Join(changes, "、"), backupPath), nil
}

// autoFixDirectoryListing 自动关闭目录遍历
func autoFixDirectoryListing(configPath string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %w", err)
	}

	newContent := string(content)
	changed := false

	// autoindex on → off
	if strings.Contains(newContent, "autoindex on") {
		newContent = strings.ReplaceAll(newContent, "autoindex on", "autoindex off")
		changed = true
	}

	// 如果没有 autoindex 指令，在 server 块中添加
	if !changed {
		lines := strings.Split(newContent, "\n")
		for i, line := range lines {
			if strings.TrimSpace(line) == "server {" {
				lines = append(lines[:i+1], append([]string{"    autoindex off;"}, lines[i+1:]...)...)
				changed = true
				break
			}
		}
		newContent = strings.Join(lines, "\n")
	}

	if !changed {
		return "配置文件中未检测到 autoindex on，可能通过其他方式开启目录遍历", nil
	}

	// 安全写入：备份 → 写入 → nginx -t 测试 → 失败回滚 → reload
	backupPath, err := safeNginxWrite(configPath, []byte(newContent))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("已关闭目录遍历（autoindex off），原文件备份至 %s，nginx -t 通过并已 reload", backupPath), nil
}

func (a *API) generateFindingsReport(c *gin.Context) {
	scanner := c.Query("scanner")
	severity := c.Query("severity")
	findings, err := a.storage.QueryFindings(scanner, severity, "open", 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	bySeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	byScanner := map[string]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
		byScanner[f.Scanner]++
	}
	c.JSON(200, gin.H{
		"total":       len(findings),
		"by_severity": bySeverity,
		"by_scanner":  byScanner,
		"findings":    findings,
	})
}

// batchResolveFindings 批量清理误报告警
// POST /api/findings/batch-resolve
// Body: { "scanner": "websecurity", "title_patterns": ["十六进制混淆", "短十六进制混淆", ...] }
// 会将这些标题模式的 open 状态告警批量标记为 auto_resolved
func (a *API) batchResolveFindings(c *gin.Context) {
	var req struct {
		Scanner       string   `json:"scanner"`
		TitlePatterns []string `json:"title_patterns"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request body"})
		return
	}
	if len(req.TitlePatterns) == 0 {
		c.JSON(400, gin.H{"error": "title_patterns are required"})
		return
	}

	resolved, err := a.storage.BatchResolveFindings(req.Scanner, req.TitlePatterns)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 记录审计日志
	actor := "system"
	if u, exists := c.Get("username"); exists {
		if s, ok := u.(string); ok && s != "" {
			actor = s
		}
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    "batch_resolve_findings",
		Target:    req.Scanner,
		Reason:    "批量清理误报告警",
		Result:    "success",
		Details:   fmt.Sprintf("批量清理 %s 误报告警 %d 条", req.Scanner, resolved),
	})

	c.JSON(200, gin.H{
		"message":        fmt.Sprintf("成功清理 %d 条误报告警", resolved),
		"resolved_count": resolved,
		"scanner":        req.Scanner,
		"patterns":       req.TitlePatterns,
	})
}

// ====== Attack Profiles & Events handlers (Z 模块) ======

func (a *API) getAttackEvents(c *gin.Context) {
	eventType := c.Query("type")
	sourceIP := c.Query("source_ip")
	severity := c.Query("severity")
	since := time.Now().AddDate(0, 0, -7)
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	limit := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	events, err := a.storage.QueryAttackEvents(eventType, sourceIP, severity, since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"events": events})
}

func (a *API) getAttackProfiles(c *gin.Context) {
	sourceIP := c.Query("source_ip")
	since := time.Now().AddDate(0, 0, -30)
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	limit := 50
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	profiles, err := a.storage.QueryAttackProfiles(sourceIP, since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"profiles": profiles})
}

func (a *API) emergencyRollback(c *gin.Context) {
	var req struct {
		TraceID string `json:"trace_id"`
		Reason  string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)
	// 注意：这里不再触发全局紧急停止（TriggerEmergencyStop）。
	// 紧急回滚的语义是"解除 Z 模块封禁"，属于降低防护强度；
	// 而全局急停会永久挂起所有自动扫描/修复且无自动恢复——
	// 此前的隐藏联动导致用户点一次"紧急回滚"后所有扫描静默停摆。
	// 需要停止全部自动动作时，应显式调用 POST /api/emergency-stop。
	// 实际执行 Z 模块的紧急回滚：清除所有封禁规则
	rollbackErr := "not_initialized"
	if a.attackWarnGuard != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		if err := a.attackWarnGuard.EmergencyRollback(ctx); err != nil {
			rollbackErr = err.Error()
		} else {
			rollbackErr = ""
		}
	}
	c.JSON(200, gin.H{
		"message":        "emergency rollback triggered",
		"trace_id":       req.TraceID,
		"reason":         req.Reason,
		"action":         "all recent actions rolled back",
		"rollback_error": rollbackErr,
	})
}

// ====== Config Versions handlers ======

func (a *API) getConfigVersions(c *gin.Context) {
	filePath := c.Query("file")
	tag := c.Query("tag")
	limit := 50
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	versions, err := a.storage.QueryConfigVersions(filePath, tag, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"versions": versions})
}

func (a *API) getConfigVersion(c *gin.Context) {
	commitID := c.Param("commit")
	v, err := a.storage.GetConfigVersion(commitID)
	if err != nil {
		c.JSON(404, gin.H{"error": "version not found"})
		return
	}
	c.JSON(200, v)
}

func (a *API) approveConfigVersion(c *gin.Context) {
	commitID := c.Param("commit")
	approvedBy := c.GetString("username")
	if approvedBy == "" {
		approvedBy = "system"
	}
	if err := a.storage.ApproveConfigVersion(commitID, approvedBy); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "version approved", "commit_id": commitID})
}

func (a *API) rollbackConfigVersion(c *gin.Context) {
	commitID := c.Param("commit")
	v, err := a.storage.RollbackConfigVersion(commitID)
	if err != nil {
		c.JSON(404, gin.H{"error": "version not found"})
		return
	}
	if !v.CanRollback {
		c.JSON(400, gin.H{"error": "this version cannot be rolled back"})
		return
	}
	if a.configPath != "" && v.Content != "" {
		_ = os.WriteFile(a.configPath, []byte(v.Content), 0644)
	}
	c.JSON(200, gin.H{"message": "rolled back", "commit_id": commitID, "file": v.FilePath})
}

func (a *API) tagConfigVersion(c *gin.Context) {
	commitID := c.Param("commit")
	var req struct {
		Tag string `json:"tag"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}
	if req.Tag == "" {
		c.JSON(400, gin.H{"error": "tag 不能为空"})
		return
	}
	if err := a.storage.TagVersion(commitID, req.Tag); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "tag created", "commit_id": commitID, "tag": req.Tag})
}

func (a *API) exportConfigYAML(c *gin.Context) {
	filePath := c.Query("file")
	data, err := a.storage.ExportYAML(filePath)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("导出失败: %v", err)})
		return
	}
	c.Data(200, "application/x-yaml", data)
}

func (a *API) importConfigYAML(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "读取请求数据失败"})
		return
	}
	if err := a.storage.ImportYAML(data); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("导入失败: %v", err)})
		return
	}
	c.JSON(200, gin.H{"message": "配置导入成功"})
}

// ====== Rules handlers ======

// defaultRuleDefs 默认规则定义，首次访问 getRules 时自动创建
var defaultRuleDefs = []struct {
	Name              string
	Module            string
	Priority          int
	AlertLevel        string
	NeedsConfirmation bool
	Description       string
}{
	{"CPU 使用率过高", "resource", 80, "warning", false, "CPU > 80% 持续 60s → 告警"},
	{"内存使用率过高", "resource", 80, "warning", false, "内存 > 80% → 告警"},
	{"磁盘空间不足", "resource", 90, "critical", false, "磁盘 > 90% → 清理日志/缓存"},
	{"进程异常退出", "service", 70, "error", false, "关键进程退出 → 重启"},
	{"服务端口不可达", "service", 85, "critical", true, "端口不可达 → 重启服务"},
	{"SSH 暴力破解检测", "security", 95, "critical", false, "5min内5次失败 → 封禁IP"},
	{"异常登录检测", "security", 90, "critical", true, "异地登录 → 告警"},
	{"可疑文件检测", "security", 75, "warning", true, "发现可疑文件 → 告警"},
	{"日志文件增长异常", "log", 50, "warning", false, "单文件 > 500MB → 轮转压缩"},
	{"网络连接数过多", "network", 60, "warning", false, "连接数 > 1000 → 告警"},
	{"SSL证书到期续期", "cert", 75, "warning", false, "证书 < 14天到期 → 自动续期"},
	{"僵尸进程清理", "system", 70, "warning", false, "僵尸进程 > 10 → 清理"},
}

// rulesAutoLoaded 确保默认规则只自动加载一次
var rulesAutoLoaded bool = false

func (a *API) getRules(c *gin.Context) {
	// 首次访问时自动加载默认规则
	if !rulesAutoLoaded {
		rulesAutoLoaded = true
		existing, _ := a.storage.GetRules()
		if len(existing) == 0 {
			for _, r := range defaultRuleDefs {
				_ = a.storage.SaveRule(&storage.RuleRecord{
					Name:              r.Name,
					Module:            r.Module,
					Priority:          r.Priority,
					AlertLevel:        r.AlertLevel,
					NeedsConfirmation: r.NeedsConfirmation,
					Description:       r.Description,
					Enabled:           true,
				})
			}
			fmt.Printf("自动加载 %d 条默认规则\n", len(defaultRuleDefs))
		}
	}

	rules, err := a.storage.GetRules()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []storage.RuleRecord{}
	}
	c.JSON(200, gin.H{"rules": rules})
}

func (a *API) addRule(c *gin.Context) {
	var req struct {
		Name              string `json:"name"`
		Module            string `json:"module"`
		Priority          int    `json:"priority"`
		AlertLevel        string `json:"alert_level"`
		NeedsConfirmation bool   `json:"needs_confirmation"`
		Description       string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(400, gin.H{"error": "规则名称不能为空"})
		return
	}
	if req.Module == "" {
		req.Module = "system"
	}
	if req.AlertLevel == "" {
		req.AlertLevel = "warning"
	}
	if req.Priority == 0 {
		req.Priority = 50
	}
	rule := &storage.RuleRecord{
		Name:              req.Name,
		Module:            req.Module,
		Priority:          req.Priority,
		AlertLevel:        req.AlertLevel,
		NeedsConfirmation: req.NeedsConfirmation,
		Description:       req.Description,
		Enabled:           true,
	}
	if err := a.storage.SaveRule(rule); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"rule": rule, "message": "规则添加成功"})
}

func (a *API) updateRule(c *gin.Context) {
	id := c.Param("id")
	var rule types.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	rule.ID = id
	c.JSON(200, gin.H{"rule": rule, "message": "rule updated, restart agent to apply"})
}

func (a *API) deleteRule(c *gin.Context) {
	id := c.Param("id")
	if err := a.storage.DeleteRule(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "规则已删除", "id": id})
}

func (a *API) toggleRule(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := a.storage.UpdateRuleEnabled(id, req.Enabled); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "规则状态已更新", "id": id, "enabled": req.Enabled})
}

func (a *API) testRuleDryRun(c *gin.Context) {
	var req struct {
		Rule   types.Rule        `json:"rule"`
		Sample map[string]string `json:"sample"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	rule := req.Rule

	// 构建用户可读的测试结果
	result := gin.H{
		"matched":       true,
		"rule_id":       rule.ID,
		"rule_name":     rule.Name,
		"summary":       fmt.Sprintf("规则「%s」匹配成功，以下是将要执行的操作（仅模拟，不会真正执行）", rule.Name),
		"priority":      rule.Priority,
		"alert_level":   alertLevelLabel(rule.AlertLevel),
		"trigger":       formatTriggerCondition(rule.Trigger),
		"actions":       formatActionsSummary(rule.Actions),
		"cooldown":      formatDuration(rule.Cooldown),
		"max_triggers":  fmt.Sprintf("每小时最多 %d 次", rule.MaxTriggers),
		"learn_mode":    rule.LearnMode,
		"would_execute": !rule.LearnMode,
		"execution_mode": func() string {
			if rule.LearnMode {
				return "学习模式（仅告警，不自动执行）"
			}
			return "自动执行模式"
		}(),
	}

	c.JSON(200, result)
}

// alertLevelLabel 将告警级别转为中文
func alertLevelLabel(level types.AlertLevel) string {
	switch level {
	case types.AlertInfo:
		return "信息"
	case types.AlertWarning:
		return "警告"
	case types.AlertError:
		return "错误"
	case types.AlertCritical:
		return "严重"
	case types.AlertFatal:
		return "致命"
	default:
		return string(level)
	}
}

// formatDuration 将 time.Duration 转为中文可读格式
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "无冷却"
	}
	if d >= time.Hour {
		hours := int(d / time.Hour)
		rem := d % time.Hour
		if rem > 0 {
			return fmt.Sprintf("%d小时%d分钟", hours, int(rem/time.Minute))
		}
		return fmt.Sprintf("%d小时", hours)
	}
	if d >= time.Minute {
		mins := int(d / time.Minute)
		rem := d % time.Minute
		if rem > 0 {
			return fmt.Sprintf("%d分钟%d秒", mins, int(rem/time.Second))
		}
		return fmt.Sprintf("%d分钟", mins)
	}
	return fmt.Sprintf("%d秒", int(d/time.Second))
}

// formatTriggerCondition 将触发条件组转为中文可读描述
func formatTriggerCondition(group types.ConditionGroup) string {
	opLabel := map[types.ConditionOperator]string{
		types.OpAnd: "且",
		types.OpOr:  "或",
		types.OpNot: "非",
	}
	op := opLabel[group.Operator]
	if op == "" {
		op = "且"
	}

	var parts []string
	for _, cond := range group.Conditions {
		parts = append(parts, formatSingleCondition(cond))
	}

	if len(parts) == 0 {
		return "无条件"
	}
	if len(parts) == 1 {
		return parts[0]
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += fmt.Sprintf(" %s %s", op, parts[i])
	}
	return result
}

// formatSingleCondition 将单个条件转为中文可读描述
func formatSingleCondition(cond types.Condition) string {
	metricLabel := metricDisplayName(cond.Metric)
	opStr := string(cond.Op)

	var valueStr string
	switch v := cond.Value.(type) {
	case float64:
		if v == float64(int64(v)) {
			valueStr = fmt.Sprintf("%d", int64(v))
		} else {
			valueStr = fmt.Sprintf("%.1f", v)
		}
	case int:
		valueStr = fmt.Sprintf("%d", v)
	case int64:
		valueStr = fmt.Sprintf("%d", v)
	case string:
		valueStr = v
	default:
		valueStr = fmt.Sprintf("%v", v)
	}

	desc := fmt.Sprintf("%s %s %s", metricLabel, opStr, valueStr)
	if cond.Duration > 0 {
		desc += fmt.Sprintf("（持续%s）", formatDuration(cond.Duration))
	}
	return desc
}

// metricDisplayName 将技术指标名转为中文可读名称
func metricDisplayName(metric string) string {
	names := map[string]string{
		"process.cpu_percent":     "进程CPU使用率",
		"process.mem_percent":     "进程内存占用率",
		"disk.used_percent":       "磁盘使用率",
		"disk.available_mb":       "磁盘可用空间",
		"log.file_size":           "日志文件大小",
		"security.login_failures": "登录失败次数",
		"cert.days_until_expiry":  "证书剩余天数",
		"system.zombie_count":     "僵尸进程数",
		"system.load_avg":         "系统负载",
		"system.mem_percent":      "内存使用率",
		"system.cpu_percent":      "CPU使用率",
		"network.conn_count":      "网络连接数",
		"network.bandwidth":       "网络带宽",
		"service.status":          "服务状态",
		"port.reachable":          "端口可达性",
		"docker.container_status": "容器状态",
		"io.wait_percent":         "磁盘IO等待率",
	}
	if name, ok := names[metric]; ok {
		return name
	}
	return metric
}

// formatActionsSummary 将动作列表转为用户可读的摘要
func formatActionsSummary(actions []types.Action) []gin.H {
	if len(actions) == 0 {
		return []gin.H{{"step": 1, "action": "仅告警", "detail": "只发送告警通知，不执行修复操作", "on_fail": "—"}}
	}

	var result []gin.H
	for i, action := range actions {
		name, detail := actionDisplayName(action.Type)
		onFail := actionOnFailLabel(action.OnFail)
		result = append(result, gin.H{
			"step":    i + 1,
			"action":  name,
			"detail":  detail,
			"on_fail": onFail,
		})
	}
	return result
}

// actionDisplayName 将动作类型转为中文名称和描述
func actionDisplayName(actionType types.ActionType) (name string, detail string) {
	switch actionType {
	case types.ActionKill:
		return "终止进程", "强制终止目标进程（SIGKILL）"
	case types.ActionSigTerm:
		return "优雅终止进程", "发送SIGTERM信号，让进程自行清理后退出"
	case types.ActionSigKill:
		return "强制终止进程", "发送SIGKILL信号，立即终止进程"
	case types.ActionNice:
		return "降低进程优先级", "通过nice调整进程优先级，降低其对CPU的占用"
	case types.ActionRestart:
		return "重启服务", "通过systemd或init脚本重启服务"
	case types.ActionCleanLog:
		return "清理日志", "清空过大的日志文件内容"
	case types.ActionRotateLog:
		return "轮转日志", "将当前日志重命名并压缩，创建新日志文件"
	case types.ActionBanIP:
		return "封禁IP", "通过防火墙规则封禁恶意IP地址"
	case types.ActionUnbanIP:
		return "解封IP", "移除IP封禁规则"
	case types.ActionRenewCert:
		return "续期证书", "通过宝塔API/certbot/acme.sh自动续期SSL证书"
	case types.ActionReloadNginx:
		return "重载Nginx", "执行nginx -s reload使新配置生效"
	case types.ActionCleanDisk:
		return "清理磁盘", "清理旧的日志压缩文件释放磁盘空间"
	case types.ActionRunScript:
		return "运行脚本", "执行预定义的修复脚本"
	case types.ActionAlert:
		return "发送告警", "通过配置的告警通道发送通知"
	case types.ActionSnapshot:
		return "记录快照", "记录进程当前状态快照（PID/内存/CPU等）供分析"
	default:
		return string(actionType), ""
	}
}

// actionOnFailLabel 将失败策略转为中文
func actionOnFailLabel(onFail string) string {
	switch onFail {
	case "continue":
		return "失败后继续下一步"
	case "abort":
		return "失败后中止"
	case "alert":
		return "失败后告警"
	default:
		if onFail == "" {
			return "—"
		}
		return onFail
	}
}

// ====== Threat Intelligence handlers ======

// getIntelStatus 返回威胁情报源的真实状态
func (a *API) getIntelStatus(c *gin.Context) {
	if a.intelMgr == nil {
		c.JSON(200, gin.H{
			"sources":      []interface{}{},
			"status":       "not_configured",
			"message":      "威胁情报未配置，请在配置文件中设置 API Key",
			"source_count": 0,
		})
		return
	}
	status := a.intelMgr.GetStatus()
	c.JSON(200, status)
}

// triggerIntelSync 真正触发威胁情报同步
func (a *API) triggerIntelSync(c *gin.Context) {
	if a.intelMgr == nil {
		c.JSON(503, gin.H{"error": "威胁情报管理器未初始化"})
		return
	}

	// 异步执行同步，避免超时
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := a.intelMgr.SyncAll(ctx); err != nil {
			fmt.Printf("[ERROR] 威胁情报同步失败: %v\n", err)
		}
	}()

	c.JSON(200, gin.H{
		"message": "威胁情报同步已启动（异步执行）",
		"status":  "syncing",
	})
}

// queryIntelCVE 查询指定组件的 CVE
func (a *API) queryIntelCVE(c *gin.Context) {
	if a.intelMgr == nil {
		c.JSON(503, gin.H{"error": "威胁情报管理器未初始化"})
		return
	}
	component := c.Query("component")
	version := c.Query("version")
	if component == "" {
		c.JSON(400, gin.H{"error": "缺少 component 参数"})
		return
	}
	cves, err := a.intelMgr.QueryCVE(component, version)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"component": component, "version": version, "cves": cves, "count": len(cves)})
}

// queryIntelIP 查询指定 IP 的恶意报告
func (a *API) queryIntelIP(c *gin.Context) {
	if a.intelMgr == nil {
		c.JSON(503, gin.H{"error": "威胁情报管理器未初始化"})
		return
	}
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(400, gin.H{"error": "缺少 ip 参数"})
		return
	}
	info, err := a.intelMgr.QueryIP(ip)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if info == nil {
		c.JSON(200, gin.H{"ip": ip, "found": false, "message": "未在威胁情报库中找到该 IP"})
		return
	}
	c.JSON(200, gin.H{"ip": ip, "found": true, "info": info})
}

// ====== License handlers ======

func (a *API) getLicenseInfo(c *gin.Context) {
	lic := version.DefaultLicense()
	c.JSON(200, gin.H{
		"tier":       lic.Tier,
		"features":   lic.Features,
		"expires_at": lic.Expiry,
		"max_agents": lic.MaxAgents,
		"expired":    lic.IsExpired(),
	})
}

// ====== Phase 1 安全扫描触发 handlers (W/X/Y/Z) ======

// scanWebSecurity 触发 W 模块：网站安全扫描
// 异步执行：扫描涉及大量文件遍历，同步执行会触发 Hub WriteTimeout 30s 导致 502
func (a *API) scanWebSecurity(c *gin.Context) {
	if a.webSecGuard == nil {
		c.JSON(503, gin.H{"error": "web security scanner not initialized"})
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	_ = c.ShouldBindJSON(&req)

	// ── 自动发现网站根目录 ──
	// 不猜路径，而是从 Nginx/Apache/IIS 配置中提取 root / DocumentRoot。
	// 用户可能把网站放在任意目录，硬编码路径列表永远覆盖不全。
	type scanTarget struct {
		Path string
		Host string
		Port int
	}
	var targets []scanTarget

	if req.Path != "" {
		// 用户手动指定了路径，直接用
		if _, err := os.Stat(req.Path); err == nil {
			targets = append(targets, scanTarget{Path: req.Path})
		}
	}

	// 如果没有手动指定路径，用站点发现
	if len(targets) == 0 && a.siteDiscover != nil {
		sites := a.siteDiscover.Discover()
		seen := make(map[string]bool)
		for _, site := range sites {
			webRoot := site.WebRoot

			// WebRoot 为空时，用宝塔标准路径 /www/wwwroot/<domain> 回退
			// 宝塔的 Nginx 配置可能用 include 引入 root 指令，
			// 或用变量 root $root_path; 导致站点发现拿不到 WebRoot
			if webRoot == "" && site.Domain != "" {
				fallbackPaths := []string{
					fmt.Sprintf("/www/wwwroot/%s", site.Domain),
					fmt.Sprintf("/www/wwwroot/%s/public", site.Domain),
					fmt.Sprintf("/var/www/%s", site.Domain),
					fmt.Sprintf("/var/www/html/%s", site.Domain),
					fmt.Sprintf("/home/wwwroot/%s", site.Domain),
				}
				for _, p := range fallbackPaths {
					if _, err := os.Stat(p); err == nil {
						webRoot = p
						break
					}
				}
			}

if webRoot == "" {
continue
}
// 排除 /www/server/ 下的非站点目录（nginx/apache/php/mysql 等服务安装目录）
if strings.HasPrefix(webRoot, "/www/server/") {
continue
}
if seen[webRoot] {
continue
}
seen[webRoot] = true
port := site.Port
if port == 0 {
port = 80
}
targets = append(targets, scanTarget{
Path: webRoot,
Host: site.Domain,
Port: port,
})
}
fmt.Printf("[WebSecurity] 站点发现: %d 个站点, 成功提取 %d 个 WebRoot\n", len(sites), len(targets))
	}

	// 宝塔环境补充：直接扫描宝塔站点目录下所有子目录
	// 站点发现可能漏掉某些站点（配置文件格式不规范、include 引入等），
	// 直接遍历宝塔站点目录可以确保不遗漏。
	// 注意：站点根目录可能不在 /www/wwwroot（用户可能选了数据盘），
	// 从宝塔配置中读取实际路径，同时扫描常见数据盘路径。
	if runtime.GOOS != "windows" {
		// 收集所有可能的站点根目录候选路径
		wwwRootCandidates := []string{
			"/www/wwwroot", // 宝塔默认
		}

		// 从宝塔环境检测中获取实际路径
		// 注意：宝塔的 default_path.pl 可能返回 /www/server/nginx（Nginx 安装目录）而非站点根目录
		// 只接受以 wwwroot 结尾的路径，排除 /www/server/ 下的服务安装目录
		if baotaEnv := baota.DetectBaotaEnvironment(); baotaEnv != nil && baotaEnv.WebRoot != "" {
			webRoot := baotaEnv.WebRoot
			// 排除 /www/server/ 下的非站点目录（nginx/apache/php/mysql 等）
			if !strings.HasPrefix(webRoot, "/www/server/") {
				wwwRootCandidates = append(wwwRootCandidates, webRoot)
			}
		}

		// 常见数据盘路径（用户可能把站点放在数据盘上）
		dataDiskPaths := []string{
			"/data/wwwroot",
			"/data/www",
			"/data/sites",
			"/home/wwwroot",
			"/mnt/wwwroot",
			"/mnt/data/wwwroot",
			"/srv/wwwroot",
			"/opt/wwwroot",
			"/web/wwwroot",
		}
		wwwRootCandidates = append(wwwRootCandidates, dataDiskPaths...)

		seen := make(map[string]bool)
		for _, t := range targets {
			seen[t.Path] = true
		}

		for _, wwwRoot := range wwwRootCandidates {
			entries, err := os.ReadDir(wwwRoot)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				name := entry.Name()
				// 跳过非站点目录
				if name == "default" || strings.HasPrefix(name, ".") {
					continue
				}
				fullPath := filepath.Join(wwwRoot, name)
				if seen[fullPath] {
					continue
				}
				seen[fullPath] = true
				targets = append(targets, scanTarget{
					Path: fullPath,
					Host: name,
					Port: 80,
				})
			}
			fmt.Printf("[WebSecurity] 扫描 %s: 新增站点目录\n", wwwRoot)
		}
		fmt.Printf("[WebSecurity] 宝塔/数据盘补充扫描: 总计 %d 个站点\n", len(targets))
	}

	// 如果自动发现也没找到，回退到系统常见路径（最后手段）
	if len(targets) == 0 {
		fallbackPaths := []string{}
		if runtime.GOOS == "windows" {
			fallbackPaths = []string{"C:\\inetpub\\wwwroot", "C:\\www"}
		} else {
			fallbackPaths = []string{"/var/www", "/usr/share/nginx/html", "/srv/http", "/opt/app"}
		}
		for _, p := range fallbackPaths {
			if _, err := os.Stat(p); err == nil {
				targets = append(targets, scanTarget{Path: p})
				break
			}
		}
	}

	if len(targets) == 0 {
		c.JSON(400, gin.H{"error": "未找到网站根目录。请手动指定扫描路径，或确保 Nginx/Apache 配置中包含 root/DocumentRoot 指令。"})
		return
	}

	fmt.Printf("[WebSecurity] 扫描启动: %d 个站点目标\n", len(targets))

	// 异步执行扫描，避免 502
	a.scanMu.Lock()
	a.scanRunning["websecurity"] = true
	a.scanMu.Unlock()
	go func(scanTargets []scanTarget) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[WebSecurity] scan panicked: %v\n", r)
				a.scanMu.Lock()
				a.scanRunning["websecurity"] = false
				a.scanLastError["websecurity"] = fmt.Sprintf("panic: %v", r)
				a.scanLastTime["websecurity"] = time.Now()
				a.scanMu.Unlock()
			}
		}()

		// 动态超时：根据站点数自适应
		wTimeout := websecurity.GlobalWTimeout(len(scanTargets), false)
		ctx, cancel := context.WithTimeout(context.Background(), wTimeout)
		defer cancel()

		// 并发数：根据站点数自适应
		concurrency := 1
		switch n := len(scanTargets); {
		case n <= 20:
			concurrency = 1
		case n <= 100:
			concurrency = 4
		case n <= 300:
			concurrency = 6
		default:
			concurrency = 8
		}

		// 扫描前重置去重缓存（并发模式下只调一次）
		a.webSecGuard.ResetDedupCaches()

		fmt.Printf("[WebSecurity] 扫描启动: %d 个站点，超时 %v，并发 %d\n", len(scanTargets), wTimeout, concurrency)

		type siteResult struct {
			target   scanTarget
			findings []types.ScanFinding
			err      error
		}

		siteCh := make(chan scanTarget, len(scanTargets))
		resultCh := make(chan siteResult, len(scanTargets))

		var wg sync.WaitGroup
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range siteCh {
					target := types.ScanTarget{Type: "website", Path: t.Path, Host: t.Host, Port: t.Port}
					findings, err := a.webSecGuard.Scan(ctx, target)
					resultCh <- siteResult{target: t, findings: findings, err: err}
				}
			}()
		}

		for _, t := range scanTargets {
			siteCh <- t
		}
		close(siteCh)

		go func() {
			wg.Wait()
			close(resultCh)
		}()

		var allFindings []types.ScanFinding
		processedCount := 0
		for res := range resultCh {
			processedCount++
			if res.err != nil {
				fmt.Fprintf(os.Stderr, "[WebSecurity] scan error for %s (%d/%d): %v\n", res.target.Path, processedCount, len(scanTargets), res.err)
				continue
			}
			if len(res.findings) > 0 {
				fmt.Printf("[WebSecurity] %s (%d/%d): 发现 %d 个问题\n", res.target.Path, processedCount, len(scanTargets), len(res.findings))
			} else if processedCount <= 3 {
				fmt.Printf("[WebSecurity] %s (%d/%d): 0 个问题（路径: %s, Host: %s）\n", res.target.Path, processedCount, len(scanTargets), res.target.Path, res.target.Host)
			}
			allFindings = append(allFindings, res.findings...)
		}

		a.scanMu.Lock()
		a.scanRunning["websecurity"] = false
		a.scanLastTime["websecurity"] = time.Now()
		a.scanLastResult["websecurity"] = len(allFindings)
		a.scanLastError["websecurity"] = ""
		a.scanMu.Unlock()

		for _, f := range allFindings {
			_ = a.storage.SaveFinding(&storage.Finding{
				Scanner:     f.Scanner,
				ScannerSub:  f.ScannerSub,
				Severity:    string(f.Severity),
				Title:       f.Title,
				Description: f.Description,
				Target:      f.Target,
				Detail:      f.Detail,
				Suggestion:  f.Suggestion,
				Consequence: f.Consequence,
				Snapshot:    f.Snapshot,
			})
		}
		fmt.Printf("网站安全扫描完成（异步），扫描 %d 个站点目录，发现 %d 个安全问题\n", len(scanTargets), len(allFindings))
	}(targets)
	c.JSON(202, gin.H{
		"status":  "started",
		"message": fmt.Sprintf("网站安全扫描已启动（发现 %d 个站点），请在安全发现页面查看结果", len(targets)),
	})
}

// diagnoseWebSecurity 诊断网站安全扫描的站点发现和子扫描器状态
// GET /api/scan/websecurity/diagnose          → 只返回站点发现结果（快速，<1s）
// GET /api/scan/websecurity/diagnose?scan=1   → 额外对第一个站点执行各子扫描器（慢，可能 60s+）
func (a *API) diagnoseWebSecurity(c *gin.Context) {
	type targetInfo struct {
		Path string `json:"path"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	var targets []targetInfo

	// 1. 站点发现
	siteCount := 0
	if a.siteDiscover != nil {
		sites := a.siteDiscover.Discover()
		siteCount = len(sites)
		seen := make(map[string]bool)
		for _, site := range sites {
			webRoot := site.WebRoot
			if webRoot == "" && site.Domain != "" {
				fallbackPaths := []string{
					fmt.Sprintf("/www/wwwroot/%s", site.Domain),
					fmt.Sprintf("/var/www/%s", site.Domain),
					fmt.Sprintf("/home/wwwroot/%s", site.Domain),
				}
				for _, p := range fallbackPaths {
					if _, err := os.Stat(p); err == nil {
						webRoot = p
						break
					}
				}
			}
if webRoot == "" || seen[webRoot] {
continue
}
// 排除 /www/server/ 下的非站点目录
if strings.HasPrefix(webRoot, "/www/server/") {
continue
}
seen[webRoot] = true
			port := site.Port
			if port == 0 {
				port = 80
			}
			targets = append(targets, targetInfo{Path: webRoot, Host: site.Domain, Port: port})
		}
	}

	// 2. 宝塔环境 + 数据盘路径补充
	if runtime.GOOS != "windows" {
		wwwRootCandidates := []string{"/www/wwwroot"}
		if baotaEnv := baota.DetectBaotaEnvironment(); baotaEnv != nil && baotaEnv.WebRoot != "" {
			if !strings.HasPrefix(baotaEnv.WebRoot, "/www/server/") {
				wwwRootCandidates = append(wwwRootCandidates, baotaEnv.WebRoot)
			}
		}
		dataDiskPaths := []string{
			"/data/wwwroot", "/data/www", "/data/sites",
			"/home/wwwroot", "/mnt/wwwroot", "/mnt/data/wwwroot",
			"/srv/wwwroot", "/opt/wwwroot", "/web/wwwroot",
		}
		wwwRootCandidates = append(wwwRootCandidates, dataDiskPaths...)

		seen := make(map[string]bool)
		for _, t := range targets {
			seen[t.Path] = true
		}
		for _, wwwRoot := range wwwRootCandidates {
			entries, err := os.ReadDir(wwwRoot)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				name := entry.Name()
				if name == "default" || strings.HasPrefix(name, ".") {
					continue
				}
				fullPath := filepath.Join(wwwRoot, name)
				if seen[fullPath] {
					continue
				}
				seen[fullPath] = true
				targets = append(targets, targetInfo{Path: fullPath, Host: name, Port: 80})
			}
		}
	}

	// 3. 宝塔环境信息
	baotaInfo := gin.H{"detected": false}
	if baotaEnv := baota.DetectBaotaEnvironment(); baotaEnv != nil {
		baotaInfo = gin.H{
			"detected":  baotaEnv.IsBaota,
			"web_root":  baotaEnv.WebRoot,
			"signals":   baotaEnv.Signals,
			"version":   baotaEnv.Version,
			"panelType": baotaEnv.PanelType,
		}
	}

	// 4. 子扫描器列表（静态信息，不执行扫描）
	subScannerList := []gin.H{}
	if a.webSecGuard != nil {
		for _, s := range a.webSecGuard.Scanners() {
			subScannerList = append(subScannerList, gin.H{
				"sub":  s.SubScanner(),
				"name": s.Name(),
			})
		}
	}

	result := gin.H{
		"site_discovery_count": siteCount,
		"targets":              targets,
		"target_count":         len(targets),
		"baota":                baotaInfo,
		"sub_scanners":         subScannerList,
		"os":                   runtime.GOOS + "/" + runtime.GOARCH,
	}

	// 5. 仅当 ?scan=1 时对第一个站点执行扫描（慢操作）
	//    每个子扫描器独立 10s 超时，避免整体超时
	doScan := c.Query("scan") == "1"
	if doScan && len(targets) > 0 && a.webSecGuard != nil {
		t := targets[0]
		target := types.ScanTarget{Type: "website", Path: t.Path, Host: t.Host, Port: t.Port}
		subScannerResults := []gin.H{}
		for _, s := range a.webSecGuard.Scanners() {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
			findings, err := s.Scan(ctx, target)
			cancel()
			subScannerResults = append(subScannerResults, gin.H{
				"sub":      s.SubScanner(),
				"name":     s.Name(),
				"findings": len(findings),
				"error":    errStr(err),
				"sample":   sampleFindings(findings, 3),
			})
		}
		result["sub_scanner_results"] = subScannerResults
	}

	c.JSON(200, result)
}

// errStr returns the string representation of an error, or empty string if nil.
func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// sampleFindings returns up to n sample findings for diagnostic output.
func sampleFindings(findings []types.ScanFinding, n int) []gin.H {
	var samples []gin.H
	for i, f := range findings {
		if i >= n {
			break
		}
		samples = append(samples, gin.H{
			"severity": string(f.Severity),
			"title":   f.Title,
			"target":  f.Target,
		})
	}
	return samples
}

// scanVuln 触发 X 模块：漏洞扫描
// 异步执行：扫描涉及大量文件遍历，同步执行会触发 Hub WriteTimeout 30s 导致 502
func (a *API) scanVuln(c *gin.Context) {
	if a.vulnScanGuard == nil {
		c.JSON(503, gin.H{"error": "vuln scanner not initialized"})
		return
	}
	var req struct {
		WebRoots []string `json:"web_roots"`
	}
	_ = c.ShouldBindJSON(&req)
	if len(req.WebRoots) == 0 && a.siteDiscover != nil {
		// 自动发现网站根目录
		sites := a.siteDiscover.Discover()
		seen := make(map[string]bool)
		for _, site := range sites {
			if site.WebRoot != "" && !seen[site.WebRoot] {
				seen[site.WebRoot] = true
				req.WebRoots = append(req.WebRoots, site.WebRoot)
			}
		}
	}
	if len(req.WebRoots) == 0 {
		if runtime.GOOS == "windows" {
			req.WebRoots = []string{"C:\\inetpub\\wwwroot", "C:\\www", "."}
		} else {
			req.WebRoots = []string{"/var/www", "/opt/app"}
		}
	}
	// Filter to only existing paths
	var validRoots []string
	for _, root := range req.WebRoots {
		if _, err := os.Stat(root); err == nil {
			validRoots = append(validRoots, root)
		}
	}
	if len(validRoots) == 0 {
		validRoots = []string{"."}
	}
	// 异步执行扫描，避免 502
	a.scanMu.Lock()
	a.scanRunning["vulnscan"] = true
	a.scanMu.Unlock()
	go func(roots []string) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[VulnScan] scan panicked: %v\n", r)
				a.scanMu.Lock()
				a.scanRunning["vulnscan"] = false
				a.scanLastError["vulnscan"] = fmt.Sprintf("panic: %v", r)
				a.scanLastTime["vulnscan"] = time.Now()
				a.scanMu.Unlock()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		findings, err := a.vulnScanGuard.Scan(ctx, roots)
		a.scanMu.Lock()
		a.scanRunning["vulnscan"] = false
		a.scanLastTime["vulnscan"] = time.Now()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[VulnScan] scan error: %v\n", err)
			a.scanLastError["vulnscan"] = err.Error()
		} else {
			a.scanLastResult["vulnscan"] = len(findings)
			a.scanLastError["vulnscan"] = ""
		}
		a.scanMu.Unlock()
		if err != nil {
			return
		}
		for _, f := range findings {
			_ = a.storage.SaveFinding(&storage.Finding{
				Scanner:     f.Scanner,
				ScannerSub:  f.ScannerSub,
				Severity:    string(f.Severity),
				Title:       f.Title,
				Description: f.Description,
				Target:      f.Target,
				Detail:      f.Detail,
				Suggestion:  f.Suggestion,
				Consequence: f.Consequence,
				Snapshot:    f.Snapshot,
			})
		}
		fmt.Printf("漏洞扫描完成（异步），发现 %d 个漏洞\n", len(findings))
	}(validRoots)
	c.JSON(202, gin.H{
		"status":  "started",
		"message": "漏洞扫描已启动，请在安全发现页面查看结果",
	})
}

// scanServerSecurity 触发 Y 模块：服务器安全扫描
// 异步执行：扫描涉及系统配置检查，同步执行会触发 Hub WriteTimeout 30s 导致 502
func (a *API) scanServerSecurity(c *gin.Context) {
	if a.serverSecGuard == nil {
		c.JSON(503, gin.H{"error": "server security scanner not initialized"})
		return
	}
	// 异步执行扫描，避免 502
	a.scanMu.Lock()
	a.scanRunning["serversecurity"] = true
	a.scanMu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[ServerSecurity] scan panicked: %v\n", r)
				a.scanMu.Lock()
				a.scanRunning["serversecurity"] = false
				a.scanLastError["serversecurity"] = fmt.Sprintf("panic: %v", r)
				a.scanLastTime["serversecurity"] = time.Now()
				a.scanMu.Unlock()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		findings, err := a.serverSecGuard.Scan(ctx)
		a.scanMu.Lock()
		a.scanRunning["serversecurity"] = false
		a.scanLastTime["serversecurity"] = time.Now()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ServerSecurity] scan error: %v\n", err)
			a.scanLastError["serversecurity"] = err.Error()
		} else {
			a.scanLastResult["serversecurity"] = len(findings)
			a.scanLastError["serversecurity"] = ""
		}
		a.scanMu.Unlock()
		if err != nil {
			return
		}
		for _, f := range findings {
			_ = a.storage.SaveFinding(&storage.Finding{
				Scanner:     f.Scanner,
				ScannerSub:  f.ScannerSub,
				Severity:    string(f.Severity),
				Title:       f.Title,
				Description: f.Description,
				Target:      f.Target,
				Detail:      f.Detail,
				Suggestion:  f.Suggestion,
				Consequence: f.Consequence,
				Snapshot:    f.Snapshot,
			})
		}
		fmt.Printf("服务器安全扫描完成（异步），发现 %d 个安全问题\n", len(findings))
	}()
	c.JSON(202, gin.H{
		"status":  "started",
		"message": "服务器安全扫描已启动，请在安全发现页面查看结果",
	})
}

// scanAttackWarn 触发 Z 模块：攻击预警扫描
// 异步执行，立即返回，避免 504 超时
func (a *API) scanAttackWarn(c *gin.Context) {
	if a.attackWarnGuard == nil {
		c.JSON(503, gin.H{"error": "attack warn guard not initialized"})
		return
	}

	// 异步执行扫描，避免前端 504 超时
	a.scanMu.Lock()
	a.scanRunning["attackwarn"] = true
	a.scanMu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[AttackWarn] scan panicked: %v\n", r)
				a.scanMu.Lock()
				a.scanRunning["attackwarn"] = false
				a.scanLastError["attackwarn"] = fmt.Sprintf("panic: %v", r)
				a.scanLastTime["attackwarn"] = time.Now()
				a.scanMu.Unlock()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		var allEvents []types.AttackEvent

		// Z1: 网站攻击扫描 - platform-aware log dirs
		var logDirs []string
		if runtime.GOOS == "windows" {
			logDirs = []string{"C:\\inetpub\\logs", "C:\\www\\logs"}
		} else {
			logDirs = []string{"/var/log/nginx", "/www/wwwlogs", "/www/server/nginx/logs", "/www/server/apache/logs", "/var/log/apache2"}
		}
		for _, dir := range logDirs {
			if _, err := os.Stat(dir); err == nil {
				if events, err := a.attackWarnGuard.AnalyzeLogFiles(ctx, dir); err == nil {
					allEvents = append(allEvents, events...)
				}
			}
		}

		// Z2: 服务器攻击扫描
		if events, err := a.attackWarnGuard.ScanServerAttacks(ctx); err == nil {
			allEvents = append(allEvents, events...)
		}

		// Z3: 关联分析
		_, _ = a.attackWarnGuard.CorrelateAttacks(ctx, time.Now().AddDate(0, 0, -7))

		a.scanMu.Lock()
		a.scanRunning["attackwarn"] = false
		a.scanLastTime["attackwarn"] = time.Now()
		a.scanLastResult["attackwarn"] = len(allEvents)
		a.scanLastError["attackwarn"] = ""
		a.scanMu.Unlock()

		fmt.Printf("攻击预警扫描完成（异步），发现 %d 个攻击事件\n", len(allEvents))
	}()

	c.JSON(200, gin.H{
		"message": "攻击预警扫描已启动，请在攻击事件页面查看结果",
		"events":  []interface{}{},
	})
}

// getBannedIPs 获取已封禁的 IP 列表
func (a *API) getBannedIPs(c *gin.Context) {
	if a.attackWarnGuard == nil {
		c.JSON(503, gin.H{"error": "attack warn guard not initialized"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	banned, err := a.attackWarnGuard.GetBannedIPs(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"banned": banned})
}

// getScanStatus 返回各扫描器的当前状态（是否正在运行、上次扫描结果等）
func (a *API) getScanStatus(c *gin.Context) {
	// 先从数据库获取各扫描器 open 状态的发现项数量（在锁外执行避免锁交叉）
	var dbCounts map[string]int
	if a.storage != nil {
		dbCounts, _ = a.storage.GetFindingCountByScanner()
	}

	a.scanMu.Lock()
	defer a.scanMu.Unlock()

	scanners := []string{"websecurity", "vulnscan", "serversecurity", "attackwarn"}
	result := make(map[string]interface{})

	for _, s := range scanners {
		status := map[string]interface{}{
			"running": a.scanRunning[s],
		}
		if t, ok := a.scanLastTime[s]; ok && !t.IsZero() {
			status["last_time"] = t.Format("2006-01-02 15:04:05")
		}
		// 使用数据库中的 open 状态发现项数量，与统计卡片保持一致
		if cnt, ok := dbCounts[s]; ok {
			status["last_count"] = cnt
		} else if cnt, ok := a.scanLastResult[s]; ok {
			status["last_count"] = cnt
		}
		if errMsg, ok := a.scanLastError[s]; ok && errMsg != "" {
			status["error"] = errMsg
		}
		result[s] = status
	}
	c.JSON(200, result)
}

// getSecurityUpdates 获取安全更新状态（CVE Feed Monitor）
func (a *API) getSecurityUpdates(c *gin.Context) {
	if a.feedMonitor == nil {
		c.JSON(503, gin.H{"error": "feed monitor not initialized"})
		return
	}
	status := a.feedMonitor.GetStatus()
	c.JSON(200, status)
}

// triggerSecurityUpdateCheck 手动触发安全更新检查
func (a *API) triggerSecurityUpdateCheck(c *gin.Context) {
	if a.feedMonitor == nil {
		c.JSON(503, gin.H{"error": "feed monitor not initialized"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		matchedCVEs, updates, err := a.feedMonitor.Check(ctx)
		if err != nil {
			fmt.Printf("[FeedMonitor] 手动检查失败: %v\n", err)
		}
		fmt.Printf("[FeedMonitor] 手动检查完成: %d CVE, %d 补丁\n", len(matchedCVEs), len(updates))
	}()
	c.JSON(200, gin.H{"message": "安全更新检查已启动，请稍后刷新查看结果"})
}

// getTuningAdvice 获取内核调优建议（Q 模块）
func (a *API) getTuningAdvice(c *gin.Context) {
	if a.tuningAdvisor == nil {
		c.JSON(503, gin.H{"error": "tuning advisor not initialized"})
		return
	}
	workloadType := c.DefaultQuery("workload", "general")
	cpuCores := runtime.NumCPU()
	var memTotalGB float64
	if m, err := mem.VirtualMemory(); err == nil {
		memTotalGB = float64(m.Total) / 1024 / 1024 / 1024
	}
	suggestions := a.tuningAdvisor.Analyze(workloadType, cpuCores, memTotalGB)
	c.JSON(200, gin.H{
		"workload":     workloadType,
		"cpu_cores":    cpuCores,
		"mem_total_gb": memTotalGB,
		"suggestions":  suggestions,
	})
}

// Serve starts the HTTP server.
// Serve starts the Hub HTTP server.
// 向宝塔学习：必须设置 HTTP 超时，防止慢客户端连接堆积导致 502
// Gin 的 Run() 不设置任何超时，在低配服务器上慢请求会耗尽 goroutine
func (a *API) Serve(addr string) error {
	srv := &http.Server{
		Addr:           addr,
		Handler:        a.router,
		ReadTimeout:    10 * time.Second,  // 读请求体超时
		WriteTimeout:   120 * time.Second, // 写响应超时（含 DB 查询时间）
		IdleTimeout:    60 * time.Second,  // 空闲连接超时（keepalive）
		MaxHeaderBytes: 1 << 20,           // 1MB 请求头上限
	}
	return srv.ListenAndServe()
}

// GetRouter returns the gin router for embedding in a custom server.
func (a *API) GetRouter() *gin.Engine {
	return a.router
}

// Helper for JSON responses
func (a *API) respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

// RBAC implementation

type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
	RoleAuditor  Role = "auditor"
)

type Permission string

const (
	PermView      Permission = "view"
	PermOperate   Permission = "operate"
	PermConfigure Permission = "configure"
	PermAudit     Permission = "audit"
	PermManage    Permission = "manage"
)

// rolePermissions defines what each role can do.
var rolePermissions = map[Role][]Permission{
	RoleOwner:    {PermView, PermOperate, PermConfigure, PermAudit, PermManage},
	RoleAdmin:    {PermView, PermOperate, PermConfigure, PermAudit},
	RoleOperator: {PermView, PermOperate},
	RoleViewer:   {PermView},
	RoleAuditor:  {PermView, PermAudit},
}

// HasPermission checks if a role has a specific permission.
func HasPermission(role Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// User represents an authenticated user.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
	TenantID string `json:"tenant_id"`
}

// FormatError returns a formatted error message.
func FormatError(err error) string {
	return fmt.Sprintf("error: %v", err)
}

// importConfig handles config import from external tools via migrators.
// 按名称去重：重复导入不会产生重复的守护目标。
func (a *API) importConfig(c *gin.Context, migratorName string) {
	m := conflict.GetMigrator(migratorName)
	if m == nil {
		c.JSON(400, gin.H{"error": "未知的迁移器: " + migratorName})
		return
	}

	configPath := c.Query("path")
	targets, err := m.Parse(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("解析失败: %v", err)})
		return
	}

	existing, _ := a.storage.GetGuardTargets()
	existingNames := make(map[string]bool, len(existing))
	for _, t := range existing {
		existingNames[t.Name] = true
	}

	imported, skipped := 0, 0
	var importedNames []string
	for i := range targets {
		if existingNames[targets[i].Name] {
			skipped++
			continue
		}
		if targets[i].ID == "" {
			targets[i].ID = uuid.NewString()
		}
		if err := a.storage.SaveGuardTarget(targets[i]); err != nil {
			skipped++
			continue
		}
		existingNames[targets[i].Name] = true
		imported++
		importedNames = append(importedNames, targets[i].Name)
	}

	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     c.GetString("username"),
		Action:    "import:" + migratorName,
		Target:    configPath,
		Reason:    "从其他工具迁移守护配置",
		Result:    fmt.Sprintf("imported=%d skipped=%d", imported, skipped),
	})

	c.JSON(200, gin.H{
		"migrator": migratorName,
		"total":    len(targets),
		"imported": imported,
		"skipped":  skipped,
		"targets":  importedNames,
	})
}

func (a *API) importMonit(c *gin.Context)      { a.importConfig(c, "monit") }
func (a *API) importSupervisor(c *gin.Context) { a.importConfig(c, "supervisor") }
func (a *API) importSystemd(c *gin.Context)    { a.importConfig(c, "systemd") }
func (a *API) importBaota(c *gin.Context)      { a.importConfig(c, "baota") }
func (a *API) importPM2(c *gin.Context)        { a.importConfig(c, "pm2") }

func (a *API) dbVacuum(c *gin.Context) {
	before := a.storage.GetDBSize()
	if err := a.storage.Vacuum(); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("VACUUM 失败: %v", err)})
		return
	}
	after := a.storage.GetDBSize()
	c.JSON(200, gin.H{"status": "ok", "message": fmt.Sprintf("数据库 VACUUM 完成，%.2f MB → %.2f MB", float64(before)/1024/1024, float64(after)/1024/1024)})
}

func (a *API) dbCleanup(c *gin.Context) {
	var errs []string
	// 先按差异化保留策略清理（审计 WORM 不动），再清攻击数据
	rp, err := a.storage.GetRetentionPolicy()
	if err != nil {
		rp = storage.DefaultRetentionPolicy()
	}
	if err := a.storage.EnforceRetention(rp); err != nil {
		errs = append(errs, fmt.Sprintf("保留策略清理: %v", err))
	}
	if err := a.storage.PurgeOldAttackEvents(); err != nil {
		errs = append(errs, fmt.Sprintf("清理攻击事件: %v", err))
	}
	if err := a.storage.PurgeOldAttackProfiles(); err != nil {
		errs = append(errs, fmt.Sprintf("清理攻击画像: %v", err))
	}
	if len(errs) > 0 {
		c.JSON(500, gin.H{"error": strings.Join(errs, "; ")})
		return
	}
	c.JSON(200, gin.H{"status": "ok", "message": "数据清理完成"})
}

// parseExportParams 解析导出接口的公共查询参数。
func parseExportParams(c *gin.Context, defaultHours int) (since time.Time, limit int, csv bool) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", strconv.Itoa(defaultHours)))
	if hours <= 0 {
		hours = defaultHours
	}
	limit, _ = strconv.Atoi(c.DefaultQuery("limit", "10000"))
	if limit <= 0 || limit > 50000 {
		limit = 10000
	}
	return time.Now().Add(-time.Duration(hours) * time.Hour), limit, strings.ToLower(c.Query("format")) == "csv"
}

// writeCSVResponse 将行数据以 CSV 流式写回响应。
func writeCSVResponse(c *gin.Context, filename string, header []string, n int, rowAt func(i int) []string) {
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	w := csv.NewWriter(c.Writer)
	_ = w.Write(header)
	for i := 0; i < n; i++ {
		_ = w.Write(rowAt(i))
	}
	w.Flush()
}

func (a *API) exportMetrics(c *gin.Context) {
	since, limit, asCSV := parseExportParams(c, 30*24)
	metrics, err := a.storage.GetMetrics("", "", since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("导出指标失败: %v", err)})
		return
	}
	if asCSV {
		writeCSVResponse(c, "metrics_export.csv", []string{"timestamp", "type", "name", "value", "unit"}, len(metrics), func(i int) []string {
			m := metrics[i]
			return []string{m.Timestamp.Format(time.RFC3339), string(m.Type), m.Name, fmt.Sprintf("%g", m.Value), m.Unit}
		})
		return
	}
	c.JSON(200, gin.H{"metrics": metrics, "count": len(metrics)})
}

func (a *API) exportAlerts(c *gin.Context) {
	since, limit, asCSV := parseExportParams(c, 30*24)
	alerts, err := a.storage.GetAlertsByTimeRange(since, time.Now(), limit)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("导出告警失败: %v", err)})
		return
	}
	if asCSV {
		writeCSVResponse(c, "alerts_export.csv", []string{"id", "timestamp", "level", "title", "source", "resolved", "acknowledged"}, len(alerts), func(i int) []string {
			al := alerts[i]
			return []string{al.ID, al.Timestamp.Format(time.RFC3339), string(al.Level), al.Title, al.Source,
				strconv.FormatBool(al.Resolved), strconv.FormatBool(al.Acknowledged)}
		})
		return
	}
	c.JSON(200, gin.H{"alerts": alerts, "count": len(alerts)})
}

func (a *API) exportAudit(c *gin.Context) {
	since, limit, asCSV := parseExportParams(c, 30*24)
	logs, err := a.storage.GetAuditLog(since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("导出审计日志失败: %v", err)})
		return
	}
	if asCSV {
		writeCSVResponse(c, "audit_export.csv", []string{"id", "timestamp", "actor", "action", "target", "result", "reason"}, len(logs), func(i int) []string {
			e := logs[i]
			return []string{e.ID, e.Timestamp.Format(time.RFC3339), e.Actor, e.Action, e.Target, e.Result, e.Reason}
		})
		return
	}
	c.JSON(200, gin.H{"audit": logs, "count": len(logs)})
}

func (a *API) securityCheck(c *gin.Context) {
	var result struct {
		Dependencies  []vulnscan.DependencyVulnerability `json:"dependencies"`
		CISCompliance []vulnscan.CISComplianceResult     `json:"cis_compliance"`
	}

	depScanner := vulnscan.NewDependencyScanner()
	webRoots := []string{"/var/www", "/opt/app", "."}
	for _, root := range webRoots {
		vulns, err := depScanner.ScanDir(root)
		if err == nil {
			result.Dependencies = append(result.Dependencies, vulns...)
		}
	}

	cisScanner := vulnscan.NewCISComplianceScanner()
	result.CISCompliance = cisScanner.Scan()

	c.JSON(200, result)
}

// getTopProcesses returns top processes by CPU and memory usage
// 使用 ps 命令替代 gopsutil process.Processes()，大幅降低内存和 CPU 开销
func (a *API) getTopProcesses(c *gin.Context) {
	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 50 {
			limit = v
		}
	}

	// 30 秒缓存，避免 Dashboard 每 5 秒调用一次导致频繁扫描全量进程
	a.mu.Lock()
	if a.topProcCache != nil && time.Since(a.topProcCacheTime) < 30*time.Second {
		cached := a.topProcCache
		a.mu.Unlock()
		cpuResult := cached.topCPU
		memResult := cached.topMem
		if len(cpuResult) > limit {
			cpuResult = cpuResult[:limit]
		}
		if len(memResult) > limit {
			memResult = memResult[:limit]
		}
		c.JSON(200, gin.H{"top_cpu": cpuResult, "top_mem": memResult})
		return
	}
	a.mu.Unlock()

	var topCPU []procInfo
	var topMem []procInfo

	if runtime.GOOS == "linux" {
		// Linux: 使用 ps 命令一次获取所有进程，在 Go 中排序
		// 比 gopsutil process.Processes() 高效：不创建 Go 对象、只启动一次子进程
		allProcs := getTopProcessesViaPS("comm", 0) // 0 = 不限制数量，获取全部
		topCPU = make([]procInfo, 0, limit)
		topMem = make([]procInfo, 0, limit)
		// 复制并按 CPU 排序
		sortedCPU := make([]procInfo, len(allProcs))
		copy(sortedCPU, allProcs)
		sort.Slice(sortedCPU, func(i, j int) bool { return sortedCPU[i].CPUPercent > sortedCPU[j].CPUPercent })
		if len(sortedCPU) > limit {
			sortedCPU = sortedCPU[:limit]
		}
		topCPU = sortedCPU
		// 复制并按内存排序
		sortedMem := make([]procInfo, len(allProcs))
		copy(sortedMem, allProcs)
		sort.Slice(sortedMem, func(i, j int) bool { return sortedMem[i].MemMB > sortedMem[j].MemMB })
		if len(sortedMem) > limit {
			sortedMem = sortedMem[:limit]
		}
		topMem = sortedMem
	} else {
		// Windows/其他：回退到 gopsutil
		procs, err := process.Processes()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		for _, p := range procs {
			name, _ := p.Name()
			cpuPercent, _ := p.CPUPercent()
			memPercent, _ := p.MemoryPercent()
			memInfo, _ := p.MemoryInfo()
			info := procInfo{PID: p.Pid, Name: name, CPUPercent: cpuPercent, MemPercent: memPercent}
			if memInfo != nil {
				info.MemMB = math.Round(float64(memInfo.RSS)/1024/1024*100) / 100
			}
			topCPU = append(topCPU, info)
			topMem = append(topMem, info)
		}
		sort.Slice(topCPU, func(i, j int) bool { return topCPU[i].CPUPercent > topCPU[j].CPUPercent })
		sort.Slice(topMem, func(i, j int) bool { return topMem[i].MemMB > topMem[j].MemMB })
		if len(topCPU) > limit {
			topCPU = topCPU[:limit]
		}
		if len(topMem) > limit {
			topMem = topMem[:limit]
		}
	}

	// 更新缓存
	a.mu.Lock()
	a.topProcCache = &topProcCacheData{topCPU: topCPU, topMem: topMem}
	a.topProcCacheTime = time.Now()
	a.mu.Unlock()

	c.JSON(200, gin.H{
		"top_cpu": topCPU,
		"top_mem": topMem,
	})
}

// procInfo 进程信息（用于 TOP 进程展示）
type procInfo struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	Cmdline    string  `json:"cmdline"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float32 `json:"mem_percent"`
	MemMB      float64 `json:"mem_mb"`
	Status     string  `json:"status"`
}

// topProcCacheData 进程 TOP 缓存
type topProcCacheData struct {
	topCPU []procInfo
	topMem []procInfo
}

// getTopProcessesViaPS 使用 ps 命令获取进程列表
// limit=0 表示不限制返回数量
func getTopProcessesViaPS(sortKey string, limit int) []procInfo {
	// ps 输出: PID COMM %CPU %MEM RSS(KB)
	cmd := exec.Command("ps", "-eo", "pid,comm,%cpu,%mem,rss", "--sort="+sortKey, "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result []procInfo
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i, line := range lines {
		if limit > 0 && i >= limit {
			break
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 {
			continue
		}
		pid, _ := strconv.ParseInt(fields[0], 10, 32)
		name := fields[1]
		cpuPct, _ := strconv.ParseFloat(fields[2], 64)
		memPct, _ := strconv.ParseFloat(fields[3], 32)
		rssKB, _ := strconv.ParseFloat(fields[4], 64)

		// 读取 /proc/{pid}/cmdline 获取完整命令行
		cmdline := ""
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			// cmdline 用 \0 分隔参数
			cmdline = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
		}
		// 如果 cmdline 为空或等于 name，尝试读取 /proc/{pid}/exe 获取可执行文件路径
		if cmdline == "" || cmdline == name {
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
				cmdline = exe
			}
		}

		result = append(result, procInfo{
			PID:        int32(pid),
			Name:       name,
			Cmdline:    cmdline,
			CPUPercent: cpuPct,
			MemPercent: float32(memPct),
			MemMB:      rssKB / 1024,
		})
	}
	return result
}

// getIPLocation looks up the geographic location of an IP address
func (a *API) getIPLocation(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(400, gin.H{"error": "ip parameter required"})
		return
	}

	// Check if it's a private IP
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil && (parsedIP.IsPrivate() || parsedIP.IsLoopback()) {
		c.JSON(200, gin.H{
			"ip":       ip,
			"location": "内网地址",
			"country":  "",
			"region":   "",
			"city":     "",
			"isp":      "",
		})
		return
	}

	// Use ip-api.com free API (no key required, 45 req/min limit)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=country,regionName,city,isp,query", ip))
	if err != nil {
		c.JSON(200, gin.H{
			"ip":       ip,
			"location": "查询失败",
			"country":  "",
			"region":   "",
			"city":     "",
			"isp":      "",
		})
		return
	}
	defer resp.Body.Close()

	var result struct {
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Query      string `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(200, gin.H{
			"ip":       ip,
			"location": "解析失败",
			"country":  "",
			"region":   "",
			"city":     "",
			"isp":      "",
		})
		return
	}

	location := result.Country
	if result.RegionName != "" {
		location += " " + result.RegionName
	}
	if result.City != "" {
		location += " " + result.City
	}

	c.JSON(200, gin.H{
		"ip":       ip,
		"location": strings.TrimSpace(location),
		"country":  result.Country,
		"region":   result.RegionName,
		"city":     result.City,
		"isp":      result.ISP,
	})
}

// LargeFileInfo 大文件信息
type LargeFileInfo struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	SizeMB     float64   `json:"size_mb"`
	ModTime    time.Time `json:"mod_time"`
	Owner      string    `json:"owner"`
	IsDir      bool      `json:"is_dir"`
	CanDelete  bool      `json:"can_delete"`
	DeleteHint string    `json:"delete_hint"`
	FileType   string    `json:"file_type"`
}

// largeFilesCache 大文件扫描结果缓存
type largeFilesCache struct {
	Files           []LargeFileInfo `json:"files"`
	Total           int             `json:"total"`
	MinSizeMB       int             `json:"min_size_mb"`
	DeletableCount  int             `json:"deletable_count"`
	DeletableSizeMB float64         `json:"deletable_size_mb"`
}

// classifyFileType 分类文件类型
func classifyFileType(path string) string {
	lower := strings.ToLower(path)

	// 日志文件
	if strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".log.") ||
		strings.Contains(lower, "/var/log/") || strings.Contains(lower, "/www/wwwlogs/") {
		return "log"
	}
	// 压缩/归档
	if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".xz") ||
		strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") ||
		strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") ||
		strings.HasSuffix(lower, ".bz2") || strings.HasSuffix(lower, ".7z") {
		return "archive"
	}
	// 共享库
	if strings.HasSuffix(lower, ".so") || strings.Contains(lower, ".so.") ||
		strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".dylib") {
		return "library"
	}
	// 可执行文件
	if strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".bin") ||
		strings.HasSuffix(lower, ".run") {
		return "binary"
	}
	// 数据库文件
	if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") ||
		strings.HasSuffix(lower, ".sqlite3") || strings.HasSuffix(lower, ".ibd") ||
		strings.HasSuffix(lower, ".frm") || strings.HasSuffix(lower, ".rdb") ||
		strings.HasSuffix(lower, ".bson") {
		return "database"
	}
	// 临时/缓存
	if strings.HasSuffix(lower, ".tmp") || strings.HasSuffix(lower, ".temp") ||
		strings.HasSuffix(lower, ".cache") || strings.HasSuffix(lower, ".bak") ||
		strings.HasSuffix(lower, ".old") || strings.Contains(lower, "/tmp/") ||
		strings.Contains(lower, "/var/tmp/") || strings.Contains(lower, "/cache/") {
		return "cache"
	}
	// Python 包
	if strings.Contains(lower, "site-packages/") || strings.Contains(lower, "dist-packages/") ||
		strings.Contains(lower, "pyporject_evn/") {
		return "python_package"
	}
	// Node.js 包
	if strings.Contains(lower, "node_modules/") {
		return "node_package"
	}
	// 模型文件
	if strings.HasSuffix(lower, ".pt") || strings.HasSuffix(lower, ".pth") ||
		strings.HasSuffix(lower, ".bin") || strings.HasSuffix(lower, ".safetensors") ||
		strings.HasSuffix(lower, ".ckpt") || strings.HasSuffix(lower, ".onnx") ||
		strings.HasSuffix(lower, ".h5") || strings.HasSuffix(lower, ".pb") {
		return "model"
	}
	// 镜像文件
	if strings.HasSuffix(lower, ".iso") || strings.HasSuffix(lower, ".img") ||
		strings.HasSuffix(lower, ".qcow2") || strings.HasSuffix(lower, ".vmdk") {
		return "image"
	}
	// 视频
	if strings.HasSuffix(lower, ".mp4") || strings.HasSuffix(lower, ".mkv") ||
		strings.HasSuffix(lower, ".avi") || strings.HasSuffix(lower, ".mov") {
		return "video"
	}
	return "other"
}

// getLargeFiles 扫描系统中的大文件（异步 + 缓存）
// 磁盘扫描是 I/O 密集型操作，在低配服务器上可能超过 30s，
// 同步执行会导致 Hub WriteTimeout 30s → 502
// 改为：首次 GET 触发后台扫描立即返回 "scanning"，后续 GET 返回缓存结果
func (a *API) getLargeFiles(c *gin.Context) {
	minSizeMB := 100 // 默认 100MB
	if s := c.Query("min_size_mb"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			minSizeMB = v
		}
	}

	// 检查是否有正在进行的扫描
	a.mu.RLock()
	running := a.fileScanRunning
	cached := a.fileScanResult
	cachedTime := a.fileScanTime
	cachedErr := a.fileScanErr
	a.mu.RUnlock()

	// 如果正在扫描，返回 "scanning" 状态（附带上次缓存结果如果有）
	if running {
		resp := gin.H{
			"status":  "scanning",
			"message": "正在扫描磁盘，请稍后刷新获取结果",
		}
		if cached != nil {
			resp["files"] = cached.Files
			resp["total"] = cached.Total
			resp["min_size_mb"] = cached.MinSizeMB
			resp["deletable_count"] = cached.DeletableCount
			resp["deletable_size_mb"] = cached.DeletableSizeMB
			resp["cached_at"] = cachedTime
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	// 如果有缓存且 minSizeMB 相同且缓存不超过 5 分钟，直接返回
	if cached != nil && cached.MinSizeMB == minSizeMB && time.Since(cachedTime) < 5*time.Minute {
		c.JSON(http.StatusOK, gin.H{
			"status":            "cached",
			"files":             cached.Files,
			"total":             cached.Total,
			"min_size_mb":       cached.MinSizeMB,
			"deletable_count":   cached.DeletableCount,
			"deletable_size_mb": cached.DeletableSizeMB,
			"cached_at":         cachedTime,
			"error":             cachedErr,
		})
		return
	}

	// 没有缓存或缓存过期，启动后台扫描
	a.mu.Lock()
	if a.fileScanRunning {
		// 另一个请求刚启动了扫描
		a.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"status":  "scanning",
			"message": "正在扫描磁盘，请稍后刷新获取结果",
		})
		return
	}
	a.fileScanRunning = true
	a.fileScanErr = ""
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			a.fileScanRunning = false
			a.fileScanTime = time.Now()
			a.mu.Unlock()
		}()

		result := a.doLargeFileScan(minSizeMB)

		a.mu.Lock()
		a.fileScanResult = result
		a.mu.Unlock()
	}()

	// 立即返回 "started" 状态（附带上次缓存结果如果有）
	resp := gin.H{
		"status":  "scanning",
		"message": "扫描已启动，请稍后刷新获取结果",
	}
	if cached != nil {
		resp["files"] = cached.Files
		resp["total"] = cached.Total
		resp["min_size_mb"] = cached.MinSizeMB
		resp["deletable_count"] = cached.DeletableCount
		resp["deletable_size_mb"] = cached.DeletableSizeMB
		resp["cached_at"] = cachedTime
	}
	c.JSON(http.StatusAccepted, resp)
}

// doLargeFileScan 执行实际的大文件扫描（在后台 goroutine 中调用）
func (a *API) doLargeFileScan(minSizeMB int) *largeFilesCache {
	minSizeBytes := int64(minSizeMB) * 1024 * 1024

	scanDirs := []string{"/var/log", "/tmp", "/var/tmp", "/www/wwwlogs", "/www/server", "/root", "/home", "/opt", "/var/lib/serverguard"}
	if runtime.GOOS == "windows" {
		scanDirs = []string{"C:\\Users", "C:\\Program Files", "C:\\Windows\\Temp", "C:\\Temp"}
	}

	var files []LargeFileInfo
	maxFiles := 200

	// 使用独立 context（不依赖请求 context，因为是异步的）
	// 超时从 120s 延长到 300s，低配服务器磁盘 I/O 慢
	scanCtx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	for _, dir := range scanDirs {
		if len(files) >= maxFiles {
			break
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		scanDirForLargeFiles(scanCtx, dir, minSizeBytes, &files, maxFiles)
	}

	// 按大小降序排序
	sort.Slice(files, func(i, j int) bool {
		return files[i].Size > files[j].Size
	})

	// 统计可删除文件总大小
	var deletableSize int64
	deletableCount := 0
	for _, f := range files {
		if f.CanDelete {
			deletableSize += f.Size
			deletableCount++
		}
	}

	return &largeFilesCache{
		Files:           files,
		Total:           len(files),
		MinSizeMB:       minSizeMB,
		DeletableCount:  deletableCount,
		DeletableSizeMB: math.Round(float64(deletableSize)/1024/1024*100) / 100,
	}
}

// scanDirForLargeFiles 递归扫描目录中的大文件
// 使用 filepath.WalkDir（比 Walk 更快，不调用 os.Lstat）
// 使用 syscall.Stat_t 获取文件所有者（不启动子进程）
func scanDirForLargeFiles(ctx context.Context, dir string, minSize int64, files *[]LargeFileInfo, maxFiles int) {
	if len(*files) >= maxFiles {
		return
	}

	// UID → username 缓存，避免重复查找
	uidCache := make(map[uint32]string)

	// 计算根目录的路径深度，用于限制相对扫描深度
	rootDepth := strings.Count(dir, string(filepath.Separator))
	maxRelativeDepth := 8 // 最多递归 8 层子目录，避免无限遍历

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || len(*files) >= maxFiles {
			if err != nil {
				return filepath.SkipDir
			}
			return filepath.SkipDir
		}

		// 检查 context 是否已超时
		select {
		case <-ctx.Done():
			return filepath.SkipDir
		default:
		}

		// 跳过目录本身
		if d.IsDir() {
			base := filepath.Base(path)
			// 限制扫描深度，避免进入 proc/sys 等虚拟文件系统
			if base == "proc" || base == "sys" || base == "dev" || base == "run" || base == "snap" {
				return filepath.SkipDir
			}
			// 跳过大量小文件目录和虚拟文件系统
			skipDirs := map[string]bool{
				".git": true, "__pycache__": true, "node_modules": true,
				"site-packages": true, ".cache": true, "vendor": true,
				// 额外跳过占用 I/O 的目录
				".npm": true, ".cargo": true, ".rustup": true,
				".gradle": true, ".m2": true,
				// 跳过容器和虚拟机镜像存储
				"overlay2": true, "aufs": true, "containers": true,
				// 跳过包管理器缓存
				"apt": true, "yum": true, "dnf": true, "pacman": true,
			}
			if skipDirs[base] {
				return filepath.SkipDir
			}
			// 限制扫描深度：超过最大相对深度时跳过子目录
			currentDepth := strings.Count(path, string(filepath.Separator)) - rootDepth
			if currentDepth > maxRelativeDepth {
				return filepath.SkipDir
			}
			return nil
		}

		// 获取文件信息（WalkDir 不提供 os.FileInfo，需要单独获取）
		info, err := d.Info()
		if err != nil {
			return nil
		}

		// 只关心大文件
		if info.Size() < minSize {
			return nil
		}

		// 获取文件所有者（使用 syscall，不启动子进程）
		owner := ""
		if runtime.GOOS != "windows" {
			owner = getFileOwner(info, uidCache)
		}

		// 判断是否可安全删除
		canDelete, hint := canDeleteFile(path, info)
		fileType := classifyFileType(path)

		*files = append(*files, LargeFileInfo{
			Path:       path,
			Size:       info.Size(),
			SizeMB:     float64(info.Size()) / 1024 / 1024,
			ModTime:    info.ModTime(),
			Owner:      owner,
			IsDir:      false,
			CanDelete:  canDelete,
			DeleteHint: hint,
			FileType:   fileType,
		})

		return nil
	})
}

// canDeleteFile 判断文件是否可安全删除
// 保守策略：只有明确无害的文件才标记为可删除
func canDeleteFile(path string, info os.FileInfo) (bool, string) {
	lowerPath := strings.ToLower(path)

	// ─── 1. 绝对不可删除的系统路径 ───
	protectedPrefixes := []string{
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/",
		"/lib64/", "/etc/", "/boot/", "/proc/", "/sys/", "/dev/",
		"/var/lib/", // 包含数据库、包管理器状态等
	}
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false, "系统关键目录，不可删除"
		}
	}

	// ─── 1.5. ServerGuard 自身数据库文件 ───
	baseName := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(baseName, "serverguard.db") {
		return false, "ServerGuard 数据库，不可删除"
	}

	// ─── 2. 数据库数据目录 ───
	protectedDataDirs := []string{
		"/www/server/data/",
		"/www/server/pgsql/data/",
		"/www/server/mysql/",
		"/var/lib/mysql/",
		"/var/lib/postgresql/",
		"/var/lib/redis/",
		"/var/lib/mongodb/",
		"/www/server/redis/data/",
		"/www/server/mongodb/data/",
	}
	for _, dir := range protectedDataDirs {
		if strings.HasPrefix(path, dir) {
			return false, "数据库数据文件，删除将导致数据丢失"
		}
	}

	// ─── 3. 数据库文件扩展名 ───
	protectedExts := []string{
		".db", ".sqlite", ".sqlite3", ".db-journal", ".db-wal", ".db-shm",
		".ibd", ".frm", ".MYD", ".MYI", ".pgsql", ".rdb", ".bson",
	}
	for _, ext := range protectedExts {
		if strings.HasSuffix(lowerPath, strings.ToLower(ext)) {
			return false, "数据库文件，删除可能导致数据丢失"
		}
	}

	// ─── 4. MySQL/PostgreSQL 关键日志 ───
	if strings.Contains(path, "mysql-bin") {
		return false, "MySQL 二进制日志，用于数据恢复和主从复制，不可删除"
	}
	if strings.Contains(path, "pg_wal") || strings.Contains(path, "pg_xlog") {
		return false, "PostgreSQL WAL 日志，用于数据恢复，不可删除"
	}

	// ─── 5. 宝塔面板核心文件 ───
	if strings.Contains(path, "/www/server/panel/") {
		return false, "宝塔面板核心文件，不可删除"
	}

	// ─── 6. 共享库/动态链接库（.so/.dll/.dylib）───
	// 这些是程序运行依赖的库文件，删除会导致程序无法运行
	if strings.HasSuffix(lowerPath, ".so") || strings.Contains(lowerPath, ".so.") ||
		strings.HasSuffix(lowerPath, ".dll") || strings.HasSuffix(lowerPath, ".dylib") {
		// 但在日志目录中的 .so 文件可能是残留，给出警告
		if strings.Contains(path, "/var/log/") || strings.Contains(path, "/tmp/") {
			return true, "日志/临时目录中的库文件残留，可删除但建议确认"
		}
		return false, "共享库文件，删除可能导致依赖该库的程序无法运行"
	}

	// ─── 7. Python site-packages / pip 包 ───
	if strings.Contains(lowerPath, "site-packages/") || strings.Contains(lowerPath, "dist-packages/") ||
		strings.Contains(lowerPath, "pyporject_evn/") {
		return false, "Python 包文件，删除会导致 Python 应用无法运行"
	}

	// ─── 8. Node.js node_modules ───
	if strings.Contains(lowerPath, "node_modules/") {
		return false, "Node.js 依赖包，删除会导致 Node 应用无法运行"
	}

	// ─── 9. 可执行文件 ───
	if strings.HasSuffix(lowerPath, ".exe") || strings.HasSuffix(lowerPath, ".bin") ||
		strings.HasSuffix(lowerPath, ".run") {
		if !strings.Contains(path, "/tmp/") && !strings.Contains(path, "/var/tmp/") {
			return false, "可执行文件，删除可能导致服务无法启动"
		}
	}

	// ─── 10. 模型文件（.pt/.pth/.ckpt 等）───
	if strings.HasSuffix(lowerPath, ".pt") || strings.HasSuffix(lowerPath, ".pth") ||
		strings.HasSuffix(lowerPath, ".safetensors") || strings.HasSuffix(lowerPath, ".ckpt") ||
		strings.HasSuffix(lowerPath, ".onnx") || strings.HasSuffix(lowerPath, ".h5") ||
		strings.HasSuffix(lowerPath, ".pb") {
		return false, "AI 模型文件，删除会导致模型无法加载，需通过应用自身的流程清理"
	}

	// ─── 11. 配置文件 ───
	configExts := []string{".conf", ".config", ".yaml", ".yml", ".json", ".xml", ".ini", ".toml"}
	for _, ext := range configExts {
		if strings.HasSuffix(lowerPath, ext) {
			if !strings.Contains(path, "/tmp/") && !strings.Contains(path, "/var/tmp/") {
				return false, "配置文件，删除可能导致服务异常"
			}
		}
	}

	// ─── 12. 明确可删除的文件类型 ───
	// 日志文件（.log / .log.* / rotated logs）
	if strings.HasSuffix(lowerPath, ".log") ||
		strings.HasSuffix(lowerPath, ".log.1") || strings.HasSuffix(lowerPath, ".log.2") ||
		strings.HasSuffix(lowerPath, ".log.3") || strings.HasSuffix(lowerPath, ".log.4") ||
		strings.HasSuffix(lowerPath, ".log.5") || strings.HasSuffix(lowerPath, ".log.6") ||
		strings.HasSuffix(lowerPath, ".log.7") || strings.HasSuffix(lowerPath, ".log.8") ||
		strings.HasSuffix(lowerPath, ".log.9") ||
		strings.Contains(lowerPath, "/var/log/") || strings.Contains(lowerPath, "/www/wwwlogs/") {
		// 排除数据库目录下的日志
		for _, dir := range protectedDataDirs {
			if strings.HasPrefix(path, dir) {
				return false, "数据库目录下的日志文件，不可删除"
			}
		}
		return true, "日志文件，可安全删除"
	}

	// 压缩归档文件（.gz/.xz/.zip/.tar 等）
	if strings.HasSuffix(lowerPath, ".gz") || strings.HasSuffix(lowerPath, ".xz") ||
		strings.HasSuffix(lowerPath, ".zip") || strings.HasSuffix(lowerPath, ".tar") ||
		strings.HasSuffix(lowerPath, ".tgz") || strings.HasSuffix(lowerPath, ".bz2") ||
		strings.HasSuffix(lowerPath, ".7z") {
		// 排除数据库目录下的归档
		for _, dir := range protectedDataDirs {
			if strings.HasPrefix(path, dir) {
				return false, "数据库目录下的归档文件，不可删除"
			}
		}
		return true, "压缩/归档文件，可安全删除（如为备份文件请确认不再需要）"
	}

	// 临时/缓存文件
	if strings.HasSuffix(lowerPath, ".tmp") || strings.HasSuffix(lowerPath, ".temp") ||
		strings.HasSuffix(lowerPath, ".cache") || strings.HasSuffix(lowerPath, ".bak") ||
		strings.HasSuffix(lowerPath, ".old") || strings.HasSuffix(lowerPath, ".swp") ||
		strings.Contains(lowerPath, "/tmp/") || strings.Contains(lowerPath, "/var/tmp/") {
		return true, "临时/缓存文件，可安全删除"
	}

	// core dump 文件
	if strings.HasSuffix(lowerPath, ".core") || strings.HasSuffix(filepath.Base(path), "core") {
		return true, "Core dump 文件（程序崩溃转储），可安全删除"
	}

	// ─── 13. 其他大文件默认不标记为可删除 ───
	// 之前是 return true，现在改为 false，让用户手动确认
	return false, "未识别文件类型，请手动确认后再删除"
}

// QuickDeleteCategory 快捷删除分类
type QuickDeleteCategory struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	PathPattern string          `json:"path_pattern"`
	Count       int             `json:"count"`
	SizeMB      float64         `json:"size_mb"`
	Files       []LargeFileInfo `json:"files,omitempty"`
}

// getQuickDeleteCategories 获取快捷删除分类
func (a *API) getQuickDeleteCategories(c *gin.Context) {
	minSizeMB := 50
	if s := c.Query("min_size_mb"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			minSizeMB = v
		}
	}

	files := scanLargeFilesForQuickDelete(c, minSizeMB)
	categories := getQuickDeleteCategoryDefs()

	// 统计每个分类的文件
	for i := range categories {
		for _, f := range files {
			if !f.CanDelete {
				continue
			}
			if matchQuickDeleteCategory(categories[i].ID, f) {
				categories[i].Count++
				categories[i].SizeMB += f.SizeMB
			}
		}
	}

	// 过滤掉空的分类
	var result []QuickDeleteCategory
	for _, cat := range categories {
		if cat.Count > 0 {
			result = append(result, cat)
		}
	}

	c.JSON(200, gin.H{
		"categories":  result,
		"total_count": len(result),
	})
}

// getQuickCategoryFiles 获取某个分类下的具体文件列表
func (a *API) getQuickCategoryFiles(c *gin.Context) {
	categoryID := c.Param("id")
	minSizeMB := 50
	if s := c.Query("min_size_mb"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			minSizeMB = v
		}
	}

	files := scanLargeFilesForQuickDelete(c, minSizeMB)

	// 筛选属于该分类的可删除文件
	var matched []LargeFileInfo
	for _, f := range files {
		if !f.CanDelete {
			continue
		}
		if matchQuickDeleteCategory(categoryID, f) {
			matched = append(matched, f)
		}
	}

	c.JSON(200, gin.H{
		"category_id": categoryID,
		"files":       matched,
		"count":       len(matched),
	})
}

// scanLargeFilesForQuickDelete 扫描大文件的公共逻辑
func scanLargeFilesForQuickDelete(c *gin.Context, minSizeMB int) []LargeFileInfo {
	scanDirs := []string{"/var/log", "/tmp", "/var/tmp", "/www/wwwlogs", "/www/server", "/root", "/home", "/opt"}
	if runtime.GOOS == "windows" {
		scanDirs = []string{"C:\\Users", "C:\\Program Files", "C:\\Windows\\Temp", "C:\\Temp"}
	}
	minSizeBytes := int64(minSizeMB) * 1024 * 1024
	var files []LargeFileInfo
	maxFiles := 500
	for _, dir := range scanDirs {
		if len(files) >= maxFiles {
			break
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		scanDirForLargeFiles(c.Request.Context(), dir, minSizeBytes, &files, maxFiles)
	}
	return files
}

// getQuickDeleteCategoryDefs 返回所有快捷删除分类定义
func getQuickDeleteCategoryDefs() []QuickDeleteCategory {
	return []QuickDeleteCategory{
		{ID: "bt_logs", Name: "宝塔日志", Description: "宝塔面板相关日志（不含面板核心文件）"},
		{ID: "bt_cron_logs", Name: "宝塔计划任务日志", Description: "宝塔计划任务产生的日志文件"},
		{ID: "system_logs", Name: "系统日志", Description: "/var/log 下的系统日志文件"},
		{ID: "nginx_logs", Name: "Nginx 日志", Description: "Nginx 访问和错误日志"},
		{ID: "apache_logs", Name: "Apache 日志", Description: "Apache 访问和错误日志"},
		{ID: "java_logs", Name: "Java 日志", Description: "Java 应用日志（gc.log, catalina.out 等）"},
		{ID: "python_logs", Name: "Python 日志", Description: "Python 应用日志（gunicorn, uwsgi, celery 等）"},
		{ID: "go_logs", Name: "Go 日志", Description: "Go 应用日志文件"},
		{ID: "php_logs", Name: "PHP 日志", Description: "PHP-FPM 和 PHP 应用日志"},
		{ID: "thinkphp_logs", Name: "ThinkPHP 日志", Description: "ThinkPHP 框架运行日志"},
		{ID: "node_logs", Name: "Node.js 日志", Description: "Node.js 应用日志（pm2, npm 等）"},
		{ID: "mysql_logs", Name: "MySQL 日志", Description: "MySQL 慢查询和错误日志（不含 binlog）"},
		{ID: "pg_logs", Name: "PostgreSQL 日志", Description: "PostgreSQL 数据库日志"},
		{ID: "redis_logs", Name: "Redis 日志", Description: "Redis 服务日志文件"},
		{ID: "docker_logs", Name: "Docker 日志", Description: "Docker 容器和服务日志"},
		{ID: "www_logs", Name: "网站访问日志", Description: "/www/wwwlogs 下的网站访问日志"},
		{ID: "rotated_logs", Name: "轮转旧日志", Description: "已轮转的旧日志（.gz/.log.1 等）"},
		{ID: "core_dumps", Name: "Core Dump", Description: "程序崩溃转储文件"},
		{ID: "tmp_files", Name: "临时大文件", Description: "/tmp 和 /var/tmp 中的大文件"},
	}
}

// matchQuickDeleteCategory 判断文件是否属于某个分类
func matchQuickDeleteCategory(categoryID string, f LargeFileInfo) bool {
	lowerPath := strings.ToLower(f.Path)
	baseName := strings.ToLower(filepath.Base(f.Path))

	switch categoryID {
	case "bt_logs":
		return strings.Contains(f.Path, "/www/server/") && f.FileType == "log" &&
			!strings.Contains(f.Path, "/www/server/panel/data/") &&
			!strings.Contains(f.Path, "/www/server/panel/config/")
	case "bt_cron_logs":
		return (strings.Contains(f.Path, "/www/server/cron/") || strings.Contains(lowerPath, "bt_task")) &&
			f.FileType == "log"
	case "system_logs":
		return strings.Contains(f.Path, "/var/log/") && f.FileType == "log" &&
			!strings.Contains(lowerPath, "nginx") && !strings.Contains(lowerPath, "mysql") &&
			!strings.Contains(lowerPath, "redis") && !strings.Contains(lowerPath, "docker") &&
			!strings.Contains(lowerPath, "apache") && !strings.Contains(lowerPath, "pg_")
	case "nginx_logs":
		return (strings.Contains(lowerPath, "nginx") || strings.Contains(lowerPath, "access.log") ||
			strings.Contains(lowerPath, "error.log")) && f.FileType == "log" &&
			!strings.Contains(f.Path, "/var/log/")
	case "apache_logs":
		return strings.Contains(lowerPath, "apache") && f.FileType == "log"
	case "java_logs":
		return (strings.Contains(lowerPath, "java") || strings.Contains(lowerPath, "gc") ||
			strings.Contains(lowerPath, "catalina") || strings.Contains(lowerPath, "spring") ||
			strings.Contains(lowerPath, "tomcat") || strings.Contains(lowerPath, "jvm")) &&
			f.FileType == "log"
	case "python_logs":
		return (strings.Contains(lowerPath, "python") || strings.Contains(lowerPath, "gunicorn") ||
			strings.Contains(lowerPath, "uwsgi") || strings.Contains(lowerPath, "celery") ||
			strings.Contains(lowerPath, "django") || strings.Contains(lowerPath, "flask")) &&
			f.FileType == "log"
	case "go_logs":
		return (strings.Contains(lowerPath, "/go/") || strings.Contains(lowerPath, "golang") ||
			strings.Contains(lowerPath, "gin.log") || strings.Contains(lowerPath, "echo.log") ||
			strings.Contains(lowerPath, "fiber.log")) &&
			f.FileType == "log"
	case "php_logs":
		return (strings.Contains(lowerPath, "php") || strings.Contains(lowerPath, "fpm")) &&
			f.FileType == "log"
	case "thinkphp_logs":
		return (strings.Contains(lowerPath, "thinkphp") || strings.Contains(lowerPath, "runtime/log")) &&
			f.FileType == "log"
	case "node_logs":
		return (strings.Contains(lowerPath, "node") || strings.Contains(lowerPath, "pm2") ||
			strings.Contains(lowerPath, "npm") || strings.Contains(lowerPath, "forever")) &&
			f.FileType == "log"
	case "mysql_logs":
		return strings.Contains(lowerPath, "mysql") && f.FileType == "log" &&
			!strings.Contains(lowerPath, "mysql-bin")
	case "pg_logs":
		return strings.Contains(lowerPath, "pg_") && f.FileType == "log"
	case "redis_logs":
		return strings.Contains(lowerPath, "redis") && f.FileType == "log"
	case "docker_logs":
		return (strings.Contains(lowerPath, "docker") || strings.Contains(f.Path, "/var/lib/docker/")) &&
			f.FileType == "log"
	case "www_logs":
		return strings.Contains(f.Path, "/www/wwwlogs/") && f.FileType == "log"
	case "rotated_logs":
		return f.FileType == "archive" || strings.HasSuffix(lowerPath, ".log.1") ||
			strings.HasSuffix(lowerPath, ".log.2") || strings.HasSuffix(lowerPath, ".log.3") ||
			strings.HasSuffix(lowerPath, ".log.gz") || strings.HasSuffix(lowerPath, ".gz")
	case "core_dumps":
		return strings.HasSuffix(lowerPath, ".core") || baseName == "core" ||
			strings.HasPrefix(baseName, "core.")
	case "tmp_files":
		return strings.Contains(f.Path, "/tmp/") || strings.Contains(f.Path, "/var/tmp/")
	}
	return false
}

// batchDeleteLargeFiles 批量删除大文件
func (a *API) batchDeleteLargeFiles(c *gin.Context) {
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}
	if len(req.Paths) == 0 {
		c.JSON(400, gin.H{"error": "文件路径列表不能为空"})
		return
	}
	if len(req.Paths) > 50 {
		c.JSON(400, gin.H{"error": "单次最多删除 50 个文件"})
		return
	}

	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}

	var deleted []gin.H
	var failed []gin.H
	var totalSavedBytes int64

	for _, path := range req.Paths {
		info, err := os.Stat(path)
		if err != nil {
			failed = append(failed, gin.H{"path": path, "error": "文件不存在"})
			continue
		}
		if info.IsDir() {
			failed = append(failed, gin.H{"path": path, "error": "不支持删除目录"})
			continue
		}

		canDelete, hint := canDeleteFile(path, info)
		if !canDelete {
			failed = append(failed, gin.H{"path": path, "error": hint})
			continue
		}

		if err := os.Remove(path); err != nil {
			failed = append(failed, gin.H{"path": path, "error": fmt.Sprintf("删除失败: %v", err)})
			continue
		}

		totalSavedBytes += info.Size()
		deleted = append(deleted, gin.H{
			"path":    path,
			"size_mb": math.Round(float64(info.Size())/1024/1024*100) / 100,
		})

		a.storage.SaveAudit(types.AuditEntry{
			ID:        uuid.NewString(),
			Timestamp: time.Now(),
			Actor:     confirmedBy,
			Action:    "batch_delete_large_file",
			Target:    path,
			Reason:    fmt.Sprintf("批量删除大文件 %.1fMB", float64(info.Size())/1024/1024),
			Result:    "success",
		})
	}

	c.JSON(200, gin.H{
		"message":        fmt.Sprintf("已删除 %d 个文件，释放 %.1f MB", len(deleted), float64(totalSavedBytes)/1024/1024),
		"deleted":        deleted,
		"failed":         failed,
		"deleted_count":  len(deleted),
		"failed_count":   len(failed),
		"total_saved_mb": math.Round(float64(totalSavedBytes)/1024/1024*100) / 100,
	})
}

// deleteLargeFile 删除指定的大文件
func (a *API) deleteLargeFile(c *gin.Context) {
	var req struct {
		Path string `json:"path"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}
	if req.Path == "" {
		c.JSON(400, gin.H{"error": "文件路径不能为空"})
		return
	}

	// 安全检查：不允许删除系统关键路径
	protectedPrefixes := []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/", "/lib64/", "/etc/", "/boot/", "/proc/", "/sys/", "/dev/", "/var/lib/"}
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(req.Path, prefix) {
			c.JSON(403, gin.H{"error": "系统关键文件，禁止删除"})
			return
		}
	}

	// 检查文件是否存在
	info, err := os.Stat(req.Path)
	if err != nil {
		c.JSON(404, gin.H{"error": "文件不存在"})
		return
	}
	if info.IsDir() {
		c.JSON(400, gin.H{"error": "不支持删除目录"})
		return
	}

	// 安全检查：数据库文件/系统路径/共享库等不可删除
	canDelete, hint := canDeleteFile(req.Path, info)
	if !canDelete {
		c.JSON(403, gin.H{"error": hint})
		return
	}

	// 删除文件
	if err := os.Remove(req.Path); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("删除失败: %v", err)})
		return
	}

	// 记录审计
	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "delete_large_file",
		Target:    req.Path,
		Reason:    fmt.Sprintf("删除大文件 %.1fMB: %s", float64(info.Size())/1024/1024, req.Path),
		Result:    "success",
	})

	c.JSON(200, gin.H{"message": "文件已删除", "path": req.Path, "size_mb": math.Round(float64(info.Size())/1024/1024*100) / 100})
}

// ─── RBAC 用户管理 ───

// listUsers 获取用户列表
func (a *API) listUsers(c *gin.Context) {
	users, err := a.storage.ListUsers()
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("获取用户列表失败: %v", err)})
		return
	}

	// 为每个用户添加权限信息
	result := make([]gin.H, 0, len(users))
	for _, u := range users {
		result = append(result, gin.H{
			"id":          u.ID,
			"username":    u.Username,
			"role":        u.Role,
			"tenant_id":   u.TenantID,
			"permissions": getPermsForRole(u.Role),
			"created_at":  u.CreatedAt,
			"updated_at":  u.UpdatedAt,
		})
	}

	c.JSON(200, gin.H{"users": result, "total": len(result)})
}

// createUser 创建用户
func (a *API) createUser(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	user, err := a.storage.CreateUser(req.Username, req.Password, req.Role, req.TenantID)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "create_user",
		Target:    req.Username,
		Reason:    fmt.Sprintf("创建用户 %s，角色: %s", req.Username, req.Role),
		Result:    "success",
	})

	c.JSON(200, gin.H{
		"message":  "用户创建成功",
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

// updateUser 更新用户信息（角色和租户）
func (a *API) updateUser(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		c.JSON(400, gin.H{"error": "无效的用户 ID"})
		return
	}

	var req struct {
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	if err := a.storage.UpdateUser(id, req.Role, req.TenantID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "update_user",
		Target:    idStr,
		Reason:    fmt.Sprintf("更新用户角色为 %s", req.Role),
		Result:    "success",
	})

	c.JSON(200, gin.H{"message": "用户信息更新成功"})
}

// resetUserPassword 重置用户密码
func (a *API) resetUserPassword(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		c.JSON(400, gin.H{"error": "无效的用户 ID"})
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效请求"})
		return
	}

	if err := a.storage.UpdateUserPassword(id, req.NewPassword); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 如果重置的是配置文件中的管理员密码，同步到配置文件
	users, _ := a.storage.ListUsers()
	for _, u := range users {
		if u.ID == id && u.Username == a.auth.Username {
			a.auth.Password = req.NewPassword
			a.cfg.Web.Password = req.NewPassword
			_ = a.cfg.Save(a.configPath)
			break
		}
	}

	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "reset_password",
		Target:    idStr,
		Reason:    "管理员重置用户密码",
		Result:    "success",
	})

	c.JSON(200, gin.H{"message": "密码重置成功"})
}

// deleteUser 删除用户
func (a *API) deleteUser(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		c.JSON(400, gin.H{"error": "无效的用户 ID"})
		return
	}

	if err := a.storage.DeleteUser(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	confirmedBy := c.GetString("username")
	if confirmedBy == "" {
		confirmedBy = "system"
	}
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     confirmedBy,
		Action:    "delete_user",
		Target:    idStr,
		Reason:    "管理员删除用户",
		Result:    "success",
	})

	c.JSON(200, gin.H{"message": "用户删除成功"})
}

// getPermsForRole 根据角色获取权限列表
func getPermsForRole(role string) []string {
	permMap := map[string][]string{
		"owner":    {"view", "operate", "configure", "audit", "manage"},
		"admin":    {"view", "operate", "configure", "audit"},
		"operator": {"view", "operate"},
		"viewer":   {"view"},
		"auditor":  {"view", "audit"},
	}
	if perms, ok := permMap[role]; ok {
		return perms
	}
	return []string{"view"}
}
