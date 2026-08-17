package safety

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// CascadeProtector implements §8.11.4: Cascade Failure Protection.
// Prevents a single Kill/restart from triggering a cascading failure.
type CascadeProtector struct {
	mu                sync.Mutex
	eventBus          *eventbus.EventBus
	observationActive bool
	observationEnd    time.Time
	observationWindow time.Duration
	affectedServices  map[string]bool      // services affected by the current cascade
	rootCause         string               // the root cause process being handled
	alertSuppressions map[string]time.Time // alert key -> suppress until
}

// NewCascadeProtector creates a new CascadeProtector.
func NewCascadeProtector(bus *eventbus.EventBus) *CascadeProtector {
	return &CascadeProtector{
		eventBus:          bus,
		observationWindow: 60 * time.Second,
		affectedServices:  make(map[string]bool),
		alertSuppressions: make(map[string]time.Time),
	}
}

// StartObservation starts the observation period after a Kill/restart action.
// During this period, no further Kill actions are allowed on other processes.
func (c *CascadeProtector) StartObservation(rootCause string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.observationActive = true
	c.observationEnd = time.Now().Add(c.observationWindow)
	c.rootCause = rootCause
	c.affectedServices = make(map[string]bool)

	c.eventBus.PublishAlert(types.AlertInfo, "cascade",
		"开始级联观察",
		fmt.Sprintf("对 %s 执行了操作，进入 %v 观察期，暂停其他 Kill 操作", rootCause, c.observationWindow),
		"cascade-protect-001")
}

// IsObserving returns whether we're currently in an observation period.
func (c *CascadeProtector) IsObserving() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.observationActive {
		return false
	}
	if time.Now().After(c.observationEnd) {
		c.observationActive = false
		c.affectedServices = make(map[string]bool)
		c.rootCause = ""
		return false
	}
	return true
}

// CanKill checks if a Kill action is allowed (not during observation).
func (c *CascadeProtector) CanKill(processName string) (bool, string) {
	if !c.IsObserving() {
		return true, ""
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if processName == c.rootCause {
		return true, "" // Allow re-killing the same root cause
	}

	// Mark as affected
	c.affectedServices[processName] = true

	return false, fmt.Sprintf("级联防护: 正在观察 %s 的影响，暂不 Kill %s（可能是受害者而非根因）", c.rootCause, processName)
}

// MarkAffected marks a service as affected by the current cascade.
func (c *CascadeProtector) MarkAffected(serviceName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.affectedServices[serviceName] = true
}

// IsAffected checks if a service is marked as affected by the current cascade.
func (c *CascadeProtector) IsAffected(serviceName string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.affectedServices[serviceName]
}

// ShouldSuppressAlert checks if an alert should be suppressed (cascade root cause).
// Rule: Same root cause -> N alerts merged into 1.
func (c *CascadeProtector) ShouldSuppressAlert(alertKey string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	suppressUntil, exists := c.alertSuppressions[alertKey]
	if exists && time.Now().Before(suppressUntil) {
		return true
	}
	return false
}

// SuppressAlert suppresses an alert for a given duration.
func (c *CascadeProtector) SuppressAlert(alertKey string, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alertSuppressions[alertKey] = time.Now().Add(duration)
}

// GetAffectedServices returns the list of services affected by the current cascade.
func (c *CascadeProtector) GetAffectedServices() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []string
	for svc := range c.affectedServices {
		result = append(result, svc)
	}
	return result
}

// GetRootCause returns the current root cause process name.
func (c *CascadeProtector) GetRootCause() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rootCause
}

// EndObservation manually ends the observation period (e.g., when system stabilizes).
func (c *CascadeProtector) EndObservation() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.observationActive {
		c.eventBus.PublishAlert(types.AlertInfo, "cascade",
			"级联观察结束",
			fmt.Sprintf("观察期结束，根因: %s，受影响服务: %d", c.rootCause, len(c.affectedServices)),
			"cascade-protect-001")
	}

	c.observationActive = false
	c.affectedServices = make(map[string]bool)
	c.rootCause = ""
}

// RestartOrderManager manages the restart order of dependent services.
type RestartOrderManager struct {
	mu           sync.Mutex
	dependencies map[string][]string // service -> depends on (upstream)
}

// NewRestartOrderManager creates a new RestartOrderManager.
func NewRestartOrderManager() *RestartOrderManager {
	return &RestartOrderManager{
		dependencies: make(map[string][]string),
	}
}

// AddDependency adds a dependency: downstream depends on upstream.
func (m *RestartOrderManager) AddDependency(downstream, upstream string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dependencies[downstream] = append(m.dependencies[downstream], upstream)
}

// GetRestartOrder returns the order in which services should be restarted.
// Upstream services are restarted first, then downstream.
func (m *RestartOrderManager) GetRestartOrder(services []string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Simple topological sort
	visited := make(map[string]bool)
	var order []string

	var visit func(svc string)
	visit = func(svc string) {
		if visited[svc] {
			return
		}
		visited[svc] = true

		// Visit dependencies first
		for _, dep := range m.dependencies[svc] {
			visit(dep)
		}

		// Check if this service is in our list
		for _, s := range services {
			if s == svc {
				order = append(order, svc)
				return
			}
		}
	}

	for _, svc := range services {
		visit(svc)
	}

	return order
}
