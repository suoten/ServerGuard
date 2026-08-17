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
				time.Sleep(c.reconnectBackoff)
				c.increaseBackoff()
				continue
			}
		}

		// Read message from Hub
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			c.increaseBackoff()
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
	c.send(ctx, HubMessage{
		Type:    "command_response",
		AgentID: c.agentID,
		Data:    resp,
	})
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
func (c *HubClient) send(ctx context.Context, msg HubMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || !c.connected {
		return
	}

	data, _ := json.Marshal(msg)
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
