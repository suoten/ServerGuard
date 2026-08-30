// Package registry implements the Hub-side in-memory agent registry that
// aggregates multiple Agent connections (single-machine management -> Hub).
package registry

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Status values for AgentRecord.Status.
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
)

// MetricsSummary is a lightweight aggregate of the latest heartbeat metrics.
type MetricsSummary struct {
	CPU       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
	Disk      float64 `json:"disk"`
	LoadAvg1  float64 `json:"load_avg_1"`
	UptimeSec float64 `json:"uptime_sec"`
	MemTotal  uint64  `json:"mem_total"`
	MemUsed   uint64  `json:"mem_used"`
	DiskTotal uint64  `json:"disk_total"`
	DiskUsed  uint64  `json:"disk_used"`
}

// AgentRecord describes a single connected (or known) agent.
type AgentRecord struct {
	AgentID          string         `json:"agent_id"`
	Hostname         string         `json:"hostname"`
	Version          string         `json:"version"`
	OS               string         `json:"os"`
	Arch             string         `json:"arch"`
	IP               string         `json:"ip"`
	LastSeen         time.Time      `json:"last_seen"`
	Status           string         `json:"status"` // online / offline
	Metrics          MetricsSummary `json:"metrics"`
	RecentAlertCount int            `json:"recent_alert_count"`

	mu      sync.Mutex // guards conn (and conn fields only)
	conn    *websocket.Conn
	writeMu sync.Mutex // serializes writes on conn
}

// AgentInfo carries the payload of an agent's register message.
type AgentInfo struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	IP       string `json:"ip"`
}

// Registry is a thread-safe in-memory store of agent records.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*AgentRecord
}

// NewRegistry creates an empty agent registry.
func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]*AgentRecord)}
}

// Register creates or updates an agent's identity record, marking it online.
func (r *Registry) Register(agentID string, info AgentInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.getOrCreateLocked(agentID)
	if info.Hostname != "" {
		rec.Hostname = info.Hostname
	}
	if info.Version != "" {
		rec.Version = info.Version
	}
	if info.OS != "" {
		rec.OS = info.OS
	}
	if info.Arch != "" {
		rec.Arch = info.Arch
	}
	if info.IP != "" {
		rec.IP = info.IP
	}
	rec.Status = StatusOnline
	rec.LastSeen = time.Now()
}

// Heartbeat updates an agent's last-seen time and metrics summary, marking it online.
// 同时把"近期告警计数"归零——否则 RecentAlertCount 只增不减，
// 名为 recent 实为历史累计，面板上永远显示总告警数。
func (r *Registry) Heartbeat(agentID string, m MetricsSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.getOrCreateLocked(agentID)
	rec.Metrics = m
	rec.Status = StatusOnline
	rec.LastSeen = time.Now()
	rec.RecentAlertCount = 0
}

// MarkOffline marks an agent as offline.
func (r *Registry) MarkOffline(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.agents[agentID]; ok {
		rec.Status = StatusOffline
	}
}

// RecordAlert increments the recent-alert counter for an agent.
func (r *Registry) RecordAlert(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.agents[agentID]; ok {
		rec.RecentAlertCount++
	}
}

// Get returns a snapshot of a single agent record.
func (r *Registry) Get(agentID string) (AgentRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.agents[agentID]
	if !ok {
		return AgentRecord{}, false
	}
	return rec.snapshot(), true
}

// List returns snapshots of all agent records, sorted by AgentID.
func (r *Registry) List() []AgentRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AgentRecord, 0, len(r.agents))
	for _, rec := range r.agents {
		out = append(out, rec.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// Prune marks agents that have not heartbeated within expireAfter as offline.
// It returns the number of agents transitioned to offline.
func (r *Registry) Prune(expireAfter time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	pruned := 0
	for _, rec := range r.agents {
		if rec.Status == StatusOnline && now.Sub(rec.LastSeen) > expireAfter {
			rec.Status = StatusOffline
			pruned++
		}
	}
	return pruned
}

// AttachConn binds a live WebSocket connection to an agent for command delivery.
func (r *Registry) AttachConn(agentID string, conn *websocket.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.getOrCreateLocked(agentID)
	rec.mu.Lock()
	rec.conn = conn
	rec.mu.Unlock()
	rec.Status = StatusOnline
	rec.LastSeen = time.Now()
}

// DetachConn removes a bound connection if it still matches the given conn.
func (r *Registry) DetachConn(agentID string, conn *websocket.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.agents[agentID]; ok {
		rec.mu.Lock()
		if rec.conn == conn {
			rec.conn = nil
		}
		rec.mu.Unlock()
	}
}

// SendJSON delivers a message to an agent's live connection (thread-safe).
// It returns an error if the agent is unknown or currently offline.
func (r *Registry) SendJSON(agentID string, v interface{}) error {
	r.mu.RLock()
	rec, ok := r.agents[agentID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("agent %q not registered", agentID)
	}
	rec.mu.Lock()
	conn := rec.conn
	rec.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("agent %q is offline", agentID)
	}
	rec.writeMu.Lock()
	defer rec.writeMu.Unlock()
	return conn.WriteJSON(v)
}

// getOrCreateLocked returns an existing or new record; caller must hold r.mu.
func (r *Registry) getOrCreateLocked(agentID string) *AgentRecord {
	rec, ok := r.agents[agentID]
	if !ok {
		rec = &AgentRecord{AgentID: agentID}
		r.agents[agentID] = rec
	}
	return rec
}

// snapshot returns a copy of the record without the live connection.
// Caller must hold r.mu (read or write).
func (rec *AgentRecord) snapshot() AgentRecord {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return AgentRecord{
		AgentID:          rec.AgentID,
		Hostname:         rec.Hostname,
		Version:          rec.Version,
		OS:               rec.OS,
		Arch:             rec.Arch,
		IP:               rec.IP,
		LastSeen:         rec.LastSeen,
		Status:           rec.Status,
		Metrics:          rec.Metrics,
		RecentAlertCount: rec.RecentAlertCount,
	}
}
