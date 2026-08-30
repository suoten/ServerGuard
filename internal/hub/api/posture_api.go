package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/suoten/serverguard/internal/agent/posture"
)

// SetPostureSource 注入态势感知引擎（Agent 启动时调用）。
func (a *API) SetPostureSource(e *posture.Engine) {
	a.postureEngine = e
}

// getPosture GET /api/posture — 当前系统态势快照 + 自主行为时间线。
// 让用户随时看到"程序现在处于什么状态、为什么、最近自己做了哪些决策"。
func (a *API) getPosture(c *gin.Context) {
	if a.postureEngine == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "态势感知引擎未启用",
		})
		return
	}
	snap := a.postureEngine.Describe()
	c.JSON(http.StatusOK, gin.H{
		"enabled":  true,
		"posture":  snap,
		"timeline": a.postureEngine.Timeline(),
	})
}
