package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/suoten/serverguard/internal/agent/decider"
)

// SetConfirmManager 注入确认管理器实例。
// 在 API 创建后、路由注册前调用。
func (a *API) SetConfirmManager(cm *decider.ConfirmManager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.confirmManager = cm
}

// getPendingConfirms 获取待确认列表。
// 方法: GET
// 路径: /api/confirms/pending
// 返回: ConfirmRequest 数组（未执行、未忽略、未过期的请求）
func (a *API) getPendingConfirms(c *gin.Context) {
	a.mu.RLock()
	cm := a.confirmManager
	a.mu.RUnlock()

	if cm == nil {
		c.JSON(503, gin.H{"error": "确认管理器未初始化"})
		return
	}

	requests, err := cm.GetPending()
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("查询待确认列表失败: %v", err)})
		return
	}

	c.JSON(200, gin.H{
		"pending": requests,
		"count":   len(requests),
	})
}

// executeConfirm 用户确认执行。
// 方法: POST
// 路径: /api/confirm/:id/execute
// 逻辑:
//  1. 调用 ConfirmManager.Execute(id) 校验并标记已执行
//  2. 如果成功 → 返回执行结果（实际动作由调用方执行）
func (a *API) executeConfirm(c *gin.Context) {
	a.mu.RLock()
	cm := a.confirmManager
	a.mu.RUnlock()

	if cm == nil {
		c.JSON(503, gin.H{"error": "确认管理器未初始化"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(400, gin.H{"error": "缺少确认请求 ID"})
		return
	}

	req, err := cm.Execute(id)
	if err != nil {
		// 根据错误类型返回不同的状态码
		statusCode := 400
		errMsg := err.Error()
		switch errMsg {
		case "该请求已执行":
			statusCode = 409 // Conflict
		case "该请求已被忽略":
			statusCode = 409
		case "确认请求已过期":
			statusCode = 410 // Gone
		}
		c.JSON(statusCode, gin.H{
			"error":  errMsg,
			"action": "",
			"target": "",
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "确认请求已执行",
		"id":      req.ID,
		"action":  string(req.Action),
		"target":  req.Target,
		"detail":  req.Detail,
		"context": req.Context,
	})
}

// ignoreConfirm 用户忽略确认请求。
// 方法: POST
// 路径: /api/confirm/:id/ignore
// 逻辑: 调用 ConfirmManager.Ignore(id)
func (a *API) ignoreConfirm(c *gin.Context) {
	a.mu.RLock()
	cm := a.confirmManager
	a.mu.RUnlock()

	if cm == nil {
		c.JSON(503, gin.H{"error": "确认管理器未初始化"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(400, gin.H{"error": "缺少确认请求 ID"})
		return
	}

	err := cm.Ignore(id)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "确认请求已忽略",
		"id":      id,
	})
}
