package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/suoten/serverguard/internal/agent/knowledge"
	"github.com/suoten/serverguard/internal/agent/maintwindow"
	"github.com/suoten/serverguard/internal/agent/netquality"
	"github.com/suoten/serverguard/internal/guards/apm"
	"github.com/suoten/serverguard/internal/report"
)

// ────────────────────────────────────────────────
// V3.9 — APM-lite + 知识沉淀 API 端点
// ────────────────────────────────────────────────

// SetV39Modules 注入 V3.9 模块
func (a *API) SetV39Modules(
	nginx *apm.NginxLogAnalyzer,
	slowQuery *apm.SlowQueryAnalyzer,
	redis *apm.RedisAnalyzer,
	netMon *netquality.Monitor,
	kb *knowledge.KnowledgeBase,
	recommender *maintwindow.Recommender,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nginxAnalyzer = nginx
	a.slowQueryAnalyzer = slowQuery
	a.redisAnalyzer = redis
	a.netQualityMon = netMon
	a.knowledgeBase = kb
	a.windowRecommender = recommender
}

// ═════ APM-lite: Nginx 日志分析 ═════

// getApmNginxStats GET /api/apm/nginx — 获取最近的 Nginx 日志分析结果
func (a *API) getApmNginxStats(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.nginxAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Nginx 日志分析器未初始化"})
		return
	}
	stats := analyzer.GetLastStats()
	if stats == nil {
		c.JSON(http.StatusOK, gin.H{"message": "尚未执行分析，点击分析按钮开始", "stats": nil})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// analyzeNginxLogs POST /api/apm/nginx/analyze — 手动触发 Nginx 日志分析
func (a *API) analyzeNginxLogs(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.nginxAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Nginx 日志分析器未初始化"})
		return
	}
	stats, err := analyzer.Analyze()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// tailNginxLog GET /api/apm/nginx/tail?path=xxx&lines=100 — 查看日志文件内容
func (a *API) tailNginxLog(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.nginxAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Nginx 日志分析器未初始化"})
		return
	}
	path := c.Query("path")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供 path 参数"})
		return
	}
	lines := 100
	if l, err := strconv.Atoi(c.Query("lines")); err == nil {
		lines = l
	}
	result, err := analyzer.TailLogFile(path, lines)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"path":  path,
		"lines": result,
		"total": len(result),
	})
}

// ═════ APM-lite: 慢查询分析 ═════

// getApmSlowQuery GET /api/apm/slow-query — 获取最近的慢查询分析结果
func (a *API) getApmSlowQuery(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.slowQueryAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "慢查询分析器未初始化"})
		return
	}
	report := analyzer.GetLastReport()
	if report == nil {
		c.JSON(http.StatusOK, gin.H{"message": "尚未执行分析", "report": nil})
		return
	}
	c.JSON(http.StatusOK, report)
}

// analyzeSlowQueries POST /api/apm/slow-query/analyze — 手动触发慢查询分析
func (a *API) analyzeSlowQueries(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.slowQueryAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "慢查询分析器未初始化"})
		return
	}
	report, err := analyzer.Analyze()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}

// ═════ APM-lite: Redis 大Key分析 ═════

// getApmRedis GET /api/apm/redis — 获取最近的 Redis 大Key分析结果
func (a *API) getApmRedis(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.redisAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Redis 分析器未初始化"})
		return
	}
	report := analyzer.GetLastReport()
	if report == nil {
		c.JSON(http.StatusOK, gin.H{"message": "尚未执行分析", "report": nil})
		return
	}
	c.JSON(http.StatusOK, report)
}

// analyzeRedisKeys POST /api/apm/redis/analyze — 手动触发 Redis 大Key分析
func (a *API) analyzeRedisKeys(c *gin.Context) {
	a.mu.RLock()
	analyzer := a.redisAnalyzer
	a.mu.RUnlock()
	if analyzer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Redis 分析器未初始化"})
		return
	}
	report, err := analyzer.Analyze()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}

// ═════ 网络质量地图 ═════

// getNetQuality GET /api/netquality — 获取最近的网络质量报告
func (a *API) getNetQuality(c *gin.Context) {
	a.mu.RLock()
	mon := a.netQualityMon
	a.mu.RUnlock()
	if mon == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "网络质量监控器未初始化"})
		return
	}
	report := mon.GetLastReport()
	if report == nil {
		c.JSON(http.StatusOK, gin.H{"message": "尚未执行探测", "report": nil})
		return
	}
	c.JSON(http.StatusOK, report)
}

// probeNetQuality POST /api/netquality/probe — 手动触发网络质量探测
func (a *API) probeNetQuality(c *gin.Context) {
	a.mu.RLock()
	mon := a.netQualityMon
	a.mu.RUnlock()
	if mon == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "网络质量监控器未初始化"})
		return
	}
	report := mon.Probe()
	c.JSON(http.StatusOK, report)
}

// getNetQualityTargets GET /api/netquality/targets — 获取探测目标列表
func (a *API) getNetQualityTargets(c *gin.Context) {
	a.mu.RLock()
	mon := a.netQualityMon
	a.mu.RUnlock()
	if mon == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "网络质量监控器未初始化"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"targets": mon.GetTargets()})
}

// ═════ 私有故障知识库 ═════

// getKnowledgeEntries GET /api/knowledge — 获取知识库条目列表
func (a *API) getKnowledgeEntries(c *gin.Context) {
	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()
	if kb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "知识库未初始化"})
		return
	}
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		limit = l
	}
	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}
	entries, err := kb.GetAll(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// getKnowledgeStats GET /api/knowledge/stats — 获取知识库统计
func (a *API) getKnowledgeStats(c *gin.Context) {
	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()
	if kb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "知识库未初始化"})
		return
	}
	c.JSON(http.StatusOK, kb.GetStats())
}

// searchKnowledge GET /api/knowledge/search?symptom=xxx&source=yyy — 搜索相似故障
func (a *API) searchKnowledge(c *gin.Context) {
	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()
	if kb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "知识库未初始化"})
		return
	}
	symptom := c.Query("symptom")
	source := c.Query("source")
	if symptom == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供 symptom 参数"})
		return
	}
	entries, err := kb.FindSimilar(symptom, source, 5)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// ═════ 智能变更窗口推荐 ═════

// getMaintenanceWindowRecommendation GET /api/maintenance-window/recommend — 获取变更窗口推荐
func (a *API) getMaintenanceWindowRecommendation(c *gin.Context) {
	a.mu.RLock()
	rec := a.windowRecommender
	a.mu.RUnlock()
	if rec == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "变更窗口推荐器未初始化"})
		return
	}
	recommendation, err := rec.Recommend()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, recommendation)
}

// ═════ 故障复盘报告 ═════

// getPostmortemReport GET /api/report/postmortem?start=2026-08-12T00:00:00&end=2026-08-12T06:00:00 — 获取复盘报告
func (a *API) getPostmortemReport(c *gin.Context) {
	a.mu.RLock()
	g := a.reportGen
	a.mu.RUnlock()
	if g == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "报告生成器未初始化"})
		return
	}

	startStr := c.Query("start")
	endStr := c.Query("end")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.ParseInLocation("2006-01-02T15:04:05", startStr, time.Local)
		if err != nil {
			start, err = time.Parse(time.RFC3339, startStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "start 格式无效"})
				return
			}
		}
	} else {
		// 默认最近 1 小时
		start = time.Now().Add(-1 * time.Hour)
	}

	if endStr != "" {
		end, err = time.ParseInLocation("2006-01-02T15:04:05", endStr, time.Local)
		if err != nil {
			end, err = time.Parse(time.RFC3339, endStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "end 格式无效"})
				return
			}
		}
	}

	pmReport, err := g.GeneratePostmortem(start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pmReport)
}

// generatePostmortemReport POST /api/report/postmortem/generate — 生成并推送复盘报告
func (a *API) generatePostmortemReport(c *gin.Context) {
	a.mu.RLock()
	g := a.reportGen
	a.mu.RUnlock()
	if g == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "报告生成器未初始化"})
		return
	}

	var req struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	start, err := time.ParseInLocation("2006-01-02T15:04:05", req.Start, time.Local)
	if err != nil {
		start, err = time.Parse(time.RFC3339, req.Start)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "start 格式无效"})
			return
		}
	}

	var end time.Time
	if req.End != "" {
		end, err = time.ParseInLocation("2006-01-02T15:04:05", req.End, time.Local)
		if err != nil {
			end, err = time.Parse(time.RFC3339, req.End)
		}
	}

	pmReport, err := g.GeneratePostmortem(start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果有通知器，推送复盘报告
	if a.notifier != nil {
		formatted := report.FormatPostmortem(pmReport)
		_ = a.notifier.SendCustom("ServerGuard 故障复盘报告", formatted)
	}

	c.JSON(http.StatusOK, pmReport)
}

// ═════ 周报 ═════

// getWeeklyReport GET /api/report/weekly — 获取周报预览
func (a *API) getWeeklyReport(c *gin.Context) {
	a.mu.RLock()
	g := a.reportGen
	a.mu.RUnlock()
	if g == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "报告生成器未初始化"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": g.GenerateWeekly()})
}

// sendWeeklyReport POST /api/report/weekly/send — 立即推送周报
func (a *API) sendWeeklyReport(c *gin.Context) {
	a.mu.RLock()
	g := a.reportGen
	a.mu.RUnlock()
	if g == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "报告生成器未初始化"})
		return
	}
	if a.notifier == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "通知器未初始化"})
		return
	}
	if err := a.notifier.SendCustom("ServerGuard 运维周报", g.GenerateWeekly()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "周报已推送到所有已启用渠道"})
}
