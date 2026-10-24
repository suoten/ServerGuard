package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/suoten/serverguard/internal/report"
)

// ────────────────────────────────────────────────
// 每日巡检报告 API：预览与立即发送
// ────────────────────────────────────────────────

// reportCache 报告缓存，避免每次预览都重新生成（涉及多次 DB 查询）
type reportCache struct {
	mu        sync.RWMutex
	content   string
	genTime   time.Time
	generating bool
}

var dailyReportCache reportCache

// SetReportGenerator 注入巡检报告生成器。
func (a *API) SetReportGenerator(g *report.Generator) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reportGen = g
}

// getDailyReport GET /api/report/daily —— 在线预览巡检报告。
// 使用 5 分钟缓存：报告生成涉及多次 DB 聚合查询，大数据库上可能超过 30s。
// 如果缓存过期且正在生成中，返回上次缓存内容。
func (a *API) getDailyReport(c *gin.Context) {
	a.mu.RLock()
	g := a.reportGen
	a.mu.RUnlock()
	if g == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "报告生成器未初始化"})
		return
	}

	// 检查缓存（5 分钟有效）
	dailyReportCache.mu.RLock()
	content := dailyReportCache.content
	genTime := dailyReportCache.genTime
	generating := dailyReportCache.generating
	dailyReportCache.mu.RUnlock()

	if content != "" && time.Since(genTime) < 5*time.Minute {
		c.JSON(http.StatusOK, gin.H{"report": content, "cached": true, "generated_at": genTime})
		return
	}

	// 如果正在生成中，返回旧缓存
	if generating {
		if content != "" {
			c.JSON(http.StatusOK, gin.H{"report": content, "cached": true, "generating": true, "generated_at": genTime})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"status": "generating", "message": "报告正在生成中，请稍后刷新"})
		return
	}

	// 异步生成报告
	dailyReportCache.mu.Lock()
	dailyReportCache.generating = true
	dailyReportCache.mu.Unlock()

	go func() {
		report := g.Generate()
		dailyReportCache.mu.Lock()
		dailyReportCache.content = report
		dailyReportCache.genTime = time.Now()
		dailyReportCache.generating = false
		dailyReportCache.mu.Unlock()
	}()

	// 如果有旧缓存，先返回旧的
	if content != "" {
		c.JSON(http.StatusOK, gin.H{"report": content, "cached": true, "regenerating": true, "generated_at": genTime})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "报告生成已启动，请稍后刷新获取结果"})
}

// sendDailyReport POST /api/report/daily/send —— 立即推送到所有通知渠道。
func (a *API) sendDailyReport(c *gin.Context) {
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

	// 优先使用缓存
	dailyReportCache.mu.RLock()
	content := dailyReportCache.content
	genTime := dailyReportCache.genTime
	dailyReportCache.mu.RUnlock()

	if content == "" || time.Since(genTime) > 5*time.Minute {
		content = g.Generate()
		dailyReportCache.mu.Lock()
		dailyReportCache.content = content
		dailyReportCache.genTime = time.Now()
		dailyReportCache.mu.Unlock()
	}

	if err := a.notifier.SendCustom("ServerGuard 每日巡检报告", content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "巡检报告已推送到所有已启用渠道"})
}
