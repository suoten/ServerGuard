package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/suoten/serverguard/internal/agent/correlation"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.0 — 故障事件 API（根因链推理产物）
// ────────────────────────────────────────────────

// SetCorrelationEngine 注入根因链推理引擎实例。
func (a *API) SetCorrelationEngine(ce *correlation.Engine) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.corrEngine = ce
}

// getIncidents GET /api/incidents — 获取故障事件列表
// 查询参数:
//   - status: open / resolved / 空（全部）
//   - limit: 返回条数上限（默认 50，最大 200）
func (a *API) getIncidents(c *gin.Context) {
	status := c.DefaultQuery("status", "")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	// 优先从引擎内存取（包含最新的 open 事件）
	if a.corrEngine != nil {
		incidents, err := a.corrEngine.GetIncidents(status, limit)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"incidents": incidents,
				"count":     len(incidents),
			})
			return
		}
	}

	// 降级：从数据库取
	if a.storage != nil {
		incidents, err := a.storage.GetIncidents(status, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "查询故障事件失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"incidents": incidents,
			"count":     len(incidents),
		})
		return
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "故障事件引擎未初始化"})
}

// getIncidentDetail GET /api/incidents/:id — 获取单个故障事件详情
func (a *API) getIncidentDetail(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少事件 ID"})
		return
	}

	if a.storage != nil {
		inc, err := a.storage.GetIncident(id)
		if err != nil || inc == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
			return
		}
		c.JSON(http.StatusOK, inc)
		return
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "存储未初始化"})
}

// ackIncident POST /api/incidents/:id/ack — 确认故障事件
func (a *API) ackIncident(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少事件 ID"})
		return
	}

	if a.storage != nil {
		inc, err := a.storage.GetIncident(id)
		if err != nil || inc == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
			return
		}

		acker := "admin"
		if user := c.GetString("username"); user != "" {
			acker = user
		}
		_ = a.storage.SaveAudit(types.AuditEntry{
			ID:        id,
			Timestamp: time.Now(),
			Actor:     acker,
			Action:    "incident_ack",
			Target:    id,
			Reason:    "人工确认故障事件",
			Result:    "acknowledged",
		})

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "故障事件已确认",
			"id":      id,
		})
		return
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "存储未初始化"})
}

// ────────────────────────────────────────────────
// 知识库反哺 API
// ────────────────────────────────────────────────

// getActionRecommendation GET /api/knowledge/recommend?symptom=xxx&source=yyy
// 知识库反哺：根据故障症状返回推荐的处置动作
func (a *API) getActionRecommendation(c *gin.Context) {
	symptom := c.Query("symptom")
	source := c.Query("source")
	if symptom == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 symptom 参数"})
		return
	}

	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()

	if kb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "知识库未初始化"})
		return
	}

	rec := kb.GetRecommendation(symptom, source)
	if rec == nil {
		c.JSON(http.StatusOK, gin.H{
			"has_recommendation": false,
			"message":            "无历史经验，建议人工排查",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"has_recommendation": true,
		"recommendation":     rec,
	})
}

// getRecurringIssues GET /api/knowledge/recurring
// 获取反复出现的故障（出现次数≥3）
func (a *API) getRecurringIssues(c *gin.Context) {
	threshold, _ := strconv.Atoi(c.DefaultQuery("threshold", "3"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()

	if kb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "知识库未初始化"})
		return
	}

	entries, err := kb.GetRecurring(threshold, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询反复故障失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"recurring": entries,
		"count":     len(entries),
	})
}
