package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/suoten/serverguard/internal/hub/registry"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/comm"
)

// agentUpgrader upgrades HTTP connections to WebSocket for Agents.
var agentUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// Agents connect with a token header; allow all origins.
		return true
	},
}

// supportedHubCommands is the whitelist of commands the Hub may dispatch to
// agents. The list is sent to an agent on registration and enforced by
// dispatchAgentCommand before anything is sent over the wire.
var supportedHubCommands = []string{
	"restart",      // 优雅重启 Agent 自身（由服务管理器拉起）
	"status",       // 返回健康评分/安全模式/资源水位快照
	"guard.pause",  // 远程紧急停止：暂停自动修复，监控继续
	"guard.resume", // 恢复自动修复
}

// SetAgentRegistry injects the multi-agent registry into the API and wires the
// /ws/agent WebSocket endpoint. Safe to call before Serve.
func (a *API) SetAgentRegistry(reg *registry.Registry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agentRegistry = reg
}

// SetHubStatusProvider 注入 Hub 连接状态查询函数（Agent 侧 hubClient.IsConnected）。
// 未注入时 /api/status 报告 hub.enabled=false。
func (a *API) SetHubStatusProvider(connected func() bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hubConnected = connected
}

// handleAgentWS is the WebSocket endpoint accepting Agent connections.
// It authenticates via Authorization: Bearer <token> and X-Agent-ID headers,
// then processes register / heartbeat / alert / command_response messages.
func (a *API) handleAgentWS(c *gin.Context) {
	reg := a.agentRegistry
	if reg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent registry not initialized"})
		return
	}

	// Validate the shared registration token.
	auth := c.GetHeader("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if !strings.HasPrefix(auth, "Bearer ") || token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return
	}
	if a.auth.JWTSecret != "" && token != a.auth.JWTSecret {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid agent token"})
		return
	}

	// Validate the Agent ID header.
	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing X-Agent-ID header"})
		return
	}

	conn, err := agentUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	remoteIP := c.ClientIP()
	reg.AttachConn(agentID, conn)
	defer func() {
		reg.DetachConn(agentID, conn)
		reg.MarkOffline(agentID)
	}()

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg comm.HubMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		a.handleAgentMessage(reg, agentID, remoteIP, msg)
	}
}

// handleAgentMessage routes a single agent message by type.
func (a *API) handleAgentMessage(reg *registry.Registry, agentID, remoteIP string, msg comm.HubMessage) {
	switch msg.Type {
	case "register":
		var info registry.AgentInfo
		b, _ := json.Marshal(msg.Data)
		_ = json.Unmarshal(b, &info)
		if info.IP == "" {
			info.IP = remoteIP
		}
		reg.Register(agentID, info)
		// The connection is already attached at upgrade time; reply with a
		// hello message listing the commands the Hub currently supports.
		_ = reg.SendJSON(agentID, comm.HubMessage{
			Type:    "hello",
			AgentID: agentID,
			Data: map[string]interface{}{
				"commands": supportedHubCommands,
				"time":     time.Now().UTC(),
			},
		})

	case "heartbeat":
		var m registry.MetricsSummary
		b, _ := json.Marshal(msg.Data)
		_ = json.Unmarshal(b, &m)
		reg.Heartbeat(agentID, m)

	case "alert":
		a.saveAgentAlert(reg, agentID, msg)

	case "command_response":
		// Result of a previously dispatched command; log via audit with the
		// outcome and any result payload the agent returned.
		if a.storage != nil {
			result := "received"
			action := "command_response"
			if data, ok := msg.Data.(map[string]interface{}); ok {
				if cmd, ok := data["command"].(string); ok && cmd != "" {
					action = "command_response:" + cmd
				}
				if ok, _ := data["success"].(bool); ok {
					result = "success"
				} else if errMsg, _ := data["error"].(string); errMsg != "" {
					result = "failed: " + errMsg
				}
			}
			b, _ := json.Marshal(msg.Data)
			a.storage.SaveAudit(types.AuditEntry{
				ID:        uuid.NewString(),
				Timestamp: time.Now(),
				Actor:     "agent:" + agentID,
				Action:    action,
				Target:    agentID,
				Reason:    string(b),
				Result:    result,
			})
		}
	}
}

// saveAgentAlert stores an alert uploaded by an agent.
func (a *API) saveAgentAlert(reg *registry.Registry, agentID string, msg comm.HubMessage) {
	reg.RecordAlert(agentID)

	if a.storage == nil {
		return
	}
	// The agent sends a types.Alert object as Data.
	var alert types.Alert
	b, _ := json.Marshal(msg.Data)
	if err := json.Unmarshal(b, &alert); err != nil {
		return
	}
	if alert.ID == "" {
		alert.ID = uuid.NewString()
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}
	if alert.Source == "" {
		alert.Source = agentID
	}
	_ = a.storage.SaveAlert(alert)
}
