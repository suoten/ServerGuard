package baota

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// RediscoveryManager manages periodic re-discovery of BaoTa.
// Triggers: version change, API failure count, 24h periodic, manual.
type RediscoveryManager struct {
	mu              sync.Mutex
	eventBus        *eventbus.EventBus
	instance        *Discovery
	lastVersion     string
	lastConfigHash  string
	apiFailureCount int
	maxAPIFailures  int
	rescanInterval  time.Duration
	lastRescan      time.Time
}

// NewRediscoveryManager creates a new RediscoveryManager.
func NewRediscoveryManager(bus *eventbus.EventBus, bt *Discovery) *RediscoveryManager {
	return &RediscoveryManager{
		eventBus:       bus,
		instance:       bt,
		maxAPIFailures: 3,
		rescanInterval: 24 * time.Hour,
		lastRescan:     time.Now(),
	}
}

// Start starts the re-discovery manager.
func (r *RediscoveryManager) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour) // Check every hour
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.checkRediscoveryNeeded(ctx)
		}
	}
}

// checkRediscoveryNeeded checks if a re-discovery is needed.
func (r *RediscoveryManager) checkRediscoveryNeeded(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Trigger 1: 24h periodic
	if time.Since(r.lastRescan) >= r.rescanInterval {
		r.performRediscovery(ctx, "24h periodic check")
		return
	}

	// Trigger 2: BaoTa version change
	currentVersion := r.instance.Version()
	if r.lastVersion != "" && currentVersion != "" && r.lastVersion != currentVersion {
		r.performRediscovery(ctx, fmt.Sprintf("version changed from %s to %s", r.lastVersion, currentVersion))
		return
	}

	// Trigger 3: API failure count
	if r.apiFailureCount >= r.maxAPIFailures {
		r.performRediscovery(ctx, fmt.Sprintf("API failures %d >= %d", r.apiFailureCount, r.maxAPIFailures))
		r.apiFailureCount = 0 // Reset after re-discovery
		return
	}

	// Trigger 4: Config file changes (port.pl, api.json modified)
	if r.checkConfigChanged() {
		r.performRediscovery(ctx, "config files modified")
		return
	}
}

// performRediscovery performs a full re-discovery cycle.
func (r *RediscoveryManager) performRediscovery(ctx context.Context, reason string) {
	r.eventBus.PublishAlert(types.AlertInfo, "baota",
		"宝塔重新探测",
		fmt.Sprintf("触发原因: %s。正在重新执行探测→配置读取→能力探测...", reason),
		"baota-rediscovery-001")

	// Step 1: Re-detect
	r.instance.Detect()

	if !r.instance.IsDetected() {
		r.eventBus.PublishAlert(types.AlertWarning, "baota",
			"宝塔未检测到",
			"重新探测后未发现宝塔面板，可能已被卸载或路径变更",
			"baota-rediscovery-001")
		r.lastVersion = ""
		r.lastRescan = time.Now()
		return
	}

	// Step 2: Re-load config
	r.instance.LoadConfig()

	// Step 3: Re-probe capabilities
	r.instance.ProbeCapabilities()

	// Step 4: Update state
	newVersion := r.instance.Version()
	if r.lastVersion != newVersion {
		r.eventBus.PublishAlert(types.AlertInfo, "baota",
			"宝塔版本变更",
			fmt.Sprintf("宝塔从 %s 变更为 %s", r.lastVersion, newVersion),
			"baota-rediscovery-001")
	}
	r.lastVersion = newVersion
	r.lastRescan = time.Now()

	// Update config hash
	r.lastConfigHash = r.computeConfigHash()

	r.eventBus.PublishAlert(types.AlertInfo, "baota",
		"宝塔重新探测完成",
		fmt.Sprintf("重新探测完成。版本: %s, 能力图已更新", newVersion),
		"baota-rediscovery-001")
}

// RecordAPIFailure records an API call failure.
func (r *RediscoveryManager) RecordAPIFailure(endpoint string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.apiFailureCount++

	r.eventBus.PublishAlert(types.AlertWarning, "baota",
		"宝塔API调用失败",
		fmt.Sprintf("端点 %s 调用失败 (第 %d 次): %v", endpoint, r.apiFailureCount, err),
		"baota-api-fail-001")
}

// RecordAPISuccess records an API call success and resets failure count.
func (r *RediscoveryManager) RecordAPISuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apiFailureCount = 0
}

// ForceRescan forces a manual re-discovery (sgctl baota rescan).
func (r *RediscoveryManager) ForceRescan(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.performRediscovery(ctx, "manual trigger (sgctl baota rescan)")
}

// checkConfigChanged checks if BaoTa config files have been modified.
func (r *RediscoveryManager) checkConfigChanged() bool {
	currentHash := r.computeConfigHash()
	if r.lastConfigHash != "" && r.lastConfigHash != currentHash {
		return true
	}
	return false
}

// computeConfigHash computes a hash of BaoTa config files' modification times.
func (r *RediscoveryManager) computeConfigHash() string {
	files := []string{
		"/www/server/panel/data/port.pl",
		"/www/server/panel/data/admin_path.pl",
		"/www/server/panel/data/api.json",
	}

	var hashInput string
	for _, file := range files {
		if info, err := os.Stat(file); err == nil {
			hashInput += fmt.Sprintf("%s:%d:%d;", file, info.ModTime().Unix(), info.Size())
		}
	}

	return hashInput
}

// GetStatus returns the current re-discovery status.
func (r *RediscoveryManager) GetStatus() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()

	return map[string]interface{}{
		"last_version":      r.lastVersion,
		"current_version":   r.instance.Version(),
		"api_failure_count": r.apiFailureCount,
		"last_rescan":       r.lastRescan.Format(time.RFC3339),
		"next_rescan":       r.lastRescan.Add(r.rescanInterval).Format(time.RFC3339),
		"config_changed":    r.checkConfigChanged(),
	}
}
