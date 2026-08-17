package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// 维护窗口（Maintenance Window）
// 窗口期内暂停一切自动修复动作（Kill/重启/清理/封禁），
// 监控采集、告警记录与通知推送不受影响。
// 窗口持久化到 KV 存储（key: maintenance_windows），Agent 重启不丢失。
// ────────────────────────────────────────────────

const maintenanceStoreKey = "maintenance_windows"

// MaintenanceWindow 维护窗口定义。
type MaintenanceWindow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`       // 窗口名称，如 "MySQL 迁移"
	Reason    string    `json:"reason"`     // 维护原因说明
	Start     time.Time `json:"start"`      // 窗口开始时间
	End       time.Time `json:"end"`        // 窗口结束时间（到期自动恢复）
	CreatedBy string    `json:"created_by"` // 创建人
	CreatedAt time.Time `json:"created_at"`
}

// loadMaintenanceWindows 从存储加载窗口列表（惰性清理已过期 24h 以上的历史窗口）。
func (a *API) loadMaintenanceWindows() []MaintenanceWindow {
	val, err := a.storage.Get(maintenanceStoreKey)
	if err != nil || val == "" {
		return nil
	}
	var windows []MaintenanceWindow
	if err := json.Unmarshal([]byte(val), &windows); err != nil {
		return nil
	}
	return windows
}

func (a *API) saveMaintenanceWindows(windows []MaintenanceWindow) {
	data, err := json.Marshal(windows)
	if err != nil {
		return
	}
	_ = a.storage.Set(maintenanceStoreKey, string(data))
}

// IsInMaintenance 返回当前是否处于任一维护窗口期内（供 SafetyManager 回调与状态展示）。
func (a *API) IsInMaintenance() bool {
	now := time.Now()
	for _, w := range a.loadMaintenanceWindows() {
		if now.After(w.Start) && now.Before(w.End) {
			return true
		}
	}
	return false
}

// getMaintenanceWindows GET /api/maintenance
func (a *API) getMaintenanceWindows(c *gin.Context) {
	windows := a.loadMaintenanceWindows()
	// 惰性清理：删除已结束超过 24 小时的历史窗口
	cutoff := time.Now().Add(-24 * time.Hour)
	kept := windows[:0]
	changed := false
	for _, w := range windows {
		if w.End.Before(cutoff) {
			changed = true
			continue
		}
		kept = append(kept, w)
	}
	if changed {
		a.saveMaintenanceWindows(kept)
	}
	if kept == nil {
		kept = []MaintenanceWindow{}
	}
	c.JSON(http.StatusOK, gin.H{
		"windows": kept,
		"active":  a.IsInMaintenance(),
	})
}

// createMaintenanceWindow POST /api/maintenance
func (a *API) createMaintenanceWindow(c *gin.Context) {
	var req struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
		Start  string `json:"start"` // RFC3339 或 "2006-01-02T15:04"
		End    string `json:"end"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请填写窗口名称"})
		return
	}
	start, err := parseWindowTime(req.Start)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "开始时间格式无效"})
		return
	}
	end, err := parseWindowTime(req.End)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "结束时间格式无效"})
		return
	}
	if !end.After(start) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "结束时间必须晚于开始时间"})
		return
	}
	if end.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "结束时间不能早于当前时间"})
		return
	}

	actor := "api"
	if u, exists := c.Get("username"); exists {
		if s, ok := u.(string); ok && s != "" {
			actor = s
		}
	}

	w := MaintenanceWindow{
		ID:        uuid.NewString(),
		Name:      req.Name,
		Reason:    req.Reason,
		Start:     start,
		End:       end,
		CreatedBy: actor,
		CreatedAt: time.Now(),
	}
	windows := append(a.loadMaintenanceWindows(), w)
	a.saveMaintenanceWindows(windows)

	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    "create_maintenance_window",
		Target:    w.Name,
		Reason:    req.Reason,
		Result:    "success",
	})
	c.JSON(http.StatusCreated, w)
}

// deleteMaintenanceWindow DELETE /api/maintenance/:id
func (a *API) deleteMaintenanceWindow(c *gin.Context) {
	id := c.Param("id")
	windows := a.loadMaintenanceWindows()
	kept := windows[:0]
	found := false
	var removed MaintenanceWindow
	for _, w := range windows {
		if w.ID == id {
			found = true
			removed = w
			continue
		}
		kept = append(kept, w)
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "窗口不存在"})
		return
	}
	a.saveMaintenanceWindows(kept)
	a.storage.SaveAudit(types.AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
		Actor:     "api",
		Action:    "delete_maintenance_window",
		Target:    removed.Name,
		Reason:    "用户手动删除维护窗口",
		Result:    "success",
	})
	c.JSON(http.StatusOK, gin.H{"message": "维护窗口已删除"})
}

// parseWindowTime 支持 RFC3339 与 datetime-local 格式（"2006-01-02T15:04"）。
func parseWindowTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.ParseInLocation("2006-01-02T15:04", s, time.Local)
}
