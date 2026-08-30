package comm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/version"
)

// HubClient implements the Agent <-> Hub WebSocket communication.
// Handles: registration, heartbeat, alert upload, command reception.
type HubClient struct {
	mu                sync.RWMutex
	eventBus          *eventbus.EventBus
	hubURL            string
	agentID           string
	token             string
	conn              *websocket.Conn
	connected         bool
	startTime         time.Time
	reconnectBackoff  time.Duration
	maxBackoff        time.Duration
	heartbeatInterval time.Duration
	commandHandlers   map[string]CommandHandler
}

// CommandHandler handles a command from Hub and may return a result payload
// that is reported back to the Hub in the command_response message.
type CommandHandler func(ctx context.Context, params interface{}) (interface{}, error)

// NewHubClient creates a new HubClient.
func NewHubClient(bus *eventbus.EventBus, hubURL, agentID, token string) *HubClient {
	return &HubClient{
		eventBus:          bus,
		hubURL:            hubURL,
		agentID:           agentID,
		token:             token,
		startTime:         time.Now(),
		reconnectBackoff:  1 * time.Second,
		maxBackoff:        300 * time.Second,
		heartbeatInterval: 30 * time.Second,
		commandHandlers:   make(map[string]CommandHandler),
	}
}

// RegisterCommandHandler registers a handler for a specific command type.
func (c *HubClient) RegisterCommandHandler(cmdType string, handler CommandHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commandHandlers[cmdType] = handler
}

// Connect establishes the WebSocket connection to Hub.
func (c *HubClient) Connect(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.token)
	header.Set("X-Agent-ID", c.agentID)
	header.Set("X-Agent-Version", version.Version)

	wsURL := c.hubURL + "/ws/agent"
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return fmt.Errorf("failed to connect to Hub: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.reconnectBackoff = 1 * time.Second
	c.mu.Unlock()

	// Send registration message
	c.sendRegister(ctx)

	return nil
}

// sendRegister sends the initial registration message to Hub.
func (c *HubClient) sendRegister(ctx context.Context) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	msg := HubMessage{
		Type:    "register",
		AgentID: c.agentID,
		Data: map[string]interface{}{
			"version":   version.Version,
			"os":        version.OS,
			"arch":      version.Arch,
			"hostname":  hostname,
			"timestamp": time.Now().UTC(),
		},
	}
	c.send(ctx, msg)
}

// StartHeartbeat sends periodic heartbeat messages.
func (c *HubClient) StartHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			start := c.startTime
			c.mu.RUnlock()
			c.send(ctx, HubMessage{
				Type:    "heartbeat",
				AgentID: c.agentID,
				Data: map[string]interface{}{
					"timestamp": time.Now().UTC(),
					"uptime":    time.Since(start).Seconds(),
				},
			})
		}
	}
}

// Run drives the full Hub client lifecycle: it establishes the initial
// connection, runs the command-listener (with reconnection) in a background
// goroutine, and keeps sending heartbeats until ctx is cancelled. On
// cancellation it closes the connection and returns.
func (c *HubClient) Run(ctx context.Context) {
	if !c.IsConnected() {
		_ = c.Connect(ctx)
	}
	go c.ListenForCommands(ctx)
	c.StartHeartbeat(ctx)
	c.Close()
}

// UploadMetrics sends a metrics heartbeat to the Hub (reuses the heartbeat
// message type so the Hub updates the agent record's metrics summary).
func (c *HubClient) UploadMetrics(ctx context.Context, metrics map[string]interface{}) {
	if metrics == nil {
		return
	}
	c.send(ctx, HubMessage{
		Type:    "heartbeat",
		AgentID: c.agentID,
		Data:    metrics,
	})
}

// SendCommandResult reports the outcome of a previously received command.
func (c *HubClient) SendCommandResult(ctx context.Context, commandID interface{}, success bool, errMsg string) {
	c.send(ctx, HubMessage{
		Type:    "command_response",
		AgentID: c.agentID,
		Data: map[string]interface{}{
			"command_id": commandID,
			"success":    success,
			"error":      errMsg,
		},
	})
}

// ListenForCommands listens for commands from Hub.
// 断线重连必须带退避休眠——原实现 ReadMessage 出错后立即进入下一轮循环，
// 连接对象非空导致跳过 Connect 分支，直接再次 ReadMessage 又立刻出错，
// 形成 100% CPU 的热循环（在 Hub 宕机/网络抖动时必然触发）。
func (c *HubClient) ListenForCommands(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.mu.Lock()
		conn := c.conn
		connected := c.connected
		c.mu.Unlock()

		if !connected || conn == nil {
			// Try to reconnect
			if err := c.Connect(ctx); err != nil {
				c.sleepBackoff(ctx)
				continue
			}
			continue // 连接刚建立，回到循环顶部读取消息
		}

		// Read message from Hub
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			// 连接已损坏：关闭并置空，退避后重连。
			// 置空 conn 是关键——否则下一轮会直接对坏连接再次 ReadMessage，
			// 错误立即返回形成无休眠的 CPU 忙循环。
			c.Close()
			c.sleepBackoff(ctx)
			continue
		}

		var msg HubMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}

		// Handle command
		go c.handleCommand(ctx, msg)
	}
}

// sleepBackoff 按当前退避时长休眠（可被 ctx 取消），并在返回前递增退避。
func (c *HubClient) sleepBackoff(ctx context.Context) {
	c.mu.RLock()
	backoff := c.reconnectBackoff
	c.mu.RUnlock()

	select {
	case <-ctx.Done():
	case <-time.After(backoff):
	}
	c.increaseBackoff()
}

// handleCommand processes a command received from Hub.
func (c *HubClient) handleCommand(ctx context.Context, msg HubMessage) {
	c.mu.RLock()
	handler, exists := c.commandHandlers[msg.Type]
	c.mu.RUnlock()

	if !exists {
		// Send error response
		c.send(ctx, HubMessage{
			Type:    "command_response",
			AgentID: c.agentID,
			Data: map[string]interface{}{
				"command_id": commandIDFromData(msg.Data),
				"command":    msg.Type,
				"success":    false,
				"error":      "unknown command type: " + msg.Type,
			},
		})
		return
	}

	result, err := handler(ctx, msg.Data)
	c.send(ctx, HubMessage{
		Type:    "command_response",
		AgentID: c.agentID,
		Data:    buildCommandResponse(msg, result, err),
	})
}

// buildCommandResponse 构造命令响应数据：command_id 回传 Hub 下发时的
// 关联 ID，成功时携带 result 载荷，失败时携带 error 说明。
func buildCommandResponse(msg HubMessage, result interface{}, err error) map[string]interface{} {
	resp := map[string]interface{}{
		"command_id": commandIDFromData(msg.Data),
		"command":    msg.Type,
		"success":    err == nil,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	if result != nil {
		resp["result"] = result
	}
	return resp
}

// commandIDFromData extracts the command_id the Hub attached to the command
// payload, so responses can be correlated with their dispatch.
func commandIDFromData(data interface{}) interface{} {
	if m, ok := data.(map[string]interface{}); ok {
		return m["command_id"]
	}
	return nil
}

// UploadAlert sends an alert to Hub.
func (c *HubClient) UploadAlert(ctx context.Context, alert types.Alert) {
	c.send(ctx, HubMessage{
		Type:    "alert",
		AgentID: c.agentID,
		Data:    alert,
	})
}

// send sends a message to Hub via WebSocket.
// 写操作带 10s 超时：Hub 假死/半开连接时无超时的 WriteMessage 会永久阻塞，
// 该锁是全局的——一次卡死就会冻结心跳、告警上报和所有命令响应。
func (c *HubClient) send(ctx context.Context, msg HubMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || !c.connected {
		return
	}

	data, _ := json.Marshal(msg)
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	c.conn.WriteMessage(websocket.TextMessage, data)
}

// increaseBackoff increases the reconnection backoff exponentially.
func (c *HubClient) increaseBackoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconnectBackoff *= 2
	if c.reconnectBackoff > c.maxBackoff {
		c.reconnectBackoff = c.maxBackoff
	}
}

// Close closes the WebSocket connection.
func (c *HubClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
}

// IsConnected returns whether the client is connected to Hub.
func (c *HubClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// HubMessage represents a message exchanged between Agent and Hub.
type HubMessage struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agent_id"`
	Data    interface{} `json:"data"`
}
