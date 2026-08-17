package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/suoten/serverguard/internal/report"
)

// ────────────────────────────────────────────────
// 每日巡检报告 API：预览与立即发送
// ────────────────────────────────────────────────

// SetReportGenerator 注入巡检报告生成器。
func (a *API) SetReportGenerator(g *report.Generator) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reportGen = g
}

// getDailyReport GET /api/report/daily —— 在线预览巡检报告。
func (a *API) getDailyReport(c *gin.Context) {
	a.mu.RLock()
	g := a.reportGen
	a.mu.RUnlock()
	if g == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "报告生成器未初始化"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": g.Generate()})
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
	if err := a.notifier.SendCustom("ServerGuard 每日巡检报告", g.Generate()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "巡检报告已推送到所有已启用渠道"})
}
