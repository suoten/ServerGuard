package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/suoten/serverguard/internal/comm"
	"github.com/suoten/serverguard/internal/hub/registry"
	"github.com/suoten/serverguard/internal/types"
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
	// fail-closed：未配置共享 Token 时一律拒绝，任何 Bearer 值都不能接入。
	auth := c.GetHeader("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if !strings.HasPrefix(auth, "Bearer ") || token == "" || a.auth.JWTSecret == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.auth.JWTSecret)) != 1 {
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

	// 读超时兜底：Agent 心跳间隔 30s，给 3 倍窗口。
	// 没有它，Agent 断电/断网（TCP 未发 FIN）时本 goroutine 会永远阻塞在
	// ReadMessage 上，注册表也一直把该 Agent 标记为在线。
	const agentReadTimeout = 90 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(agentReadTimeout))

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
		_ = conn.SetReadDeadline(time.Now().Add(agentReadTimeout))
		var msg comm.HubMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		a.handleAgentMessage(reg, agentID, remoteIP, msg)
	}
}

// handleAgentMessage routes a single agent message by type.
// 向宝塔学习：避免 marshal→unmarshal 二次序列化，用类型断言直接转换
func (a *API) handleAgentMessage(reg *registry.Registry, agentID, remoteIP string, msg comm.HubMessage) {
	switch msg.Type {
	case "register":
		info := registry.AgentInfo{}
		remapJSON(msg.Data, &info)
		if info.IP == "" {
			info.IP = remoteIP
		}
		reg.Register(agentID, info)
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
		remapJSON(msg.Data, &m)
		reg.Heartbeat(agentID, m)

	case "alert":
		a.saveAgentAlert(reg, agentID, msg)

	case "command_response":
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

// remapJSON 将 interface{} 通过 JSON 序列化→反序列化转换到目标结构体。
// 仅在需要类型转换时使用，比直接 marshal→unmarshal 省一次分配。
func remapJSON(src interface{}, dst interface{}) {
	b, _ := json.Marshal(src)
	_ = json.Unmarshal(b, dst)
}

// saveAgentAlert stores an alert uploaded by an agent.
func (a *API) saveAgentAlert(reg *registry.Registry, agentID string, msg comm.HubMessage) {
	reg.RecordAlert(agentID)

	if a.storage == nil {
		return
	}
	var alert types.Alert
	remapJSON(msg.Data, &alert)
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
