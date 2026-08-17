package safety

import (
	"fmt"
	"sync"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// DegradationManager implements §9.4: Graceful Degradation Matrix.
// Each feature has a Plan B fallback when it fails.
type DegradationManager struct {
	mu              sync.RWMutex
	eventBus        *eventbus.EventBus
	fallbacks       map[string]Fallback // feature name -> fallback
	activeFallbacks map[string]bool     // features currently in fallback mode
}

// Fallback defines a fallback for a feature.
type Fallback struct {
	Feature        string // e.g., "hub", "alerts", "auto_repair", "web_panel", "sqlite", "rules", "upgrade", "cert_renew", "kill_budget", "circuit_breaker", "resource_floor", "cascade", "emergency_stop", "agent_mem", "baota_discovery"
	FallbackAction string // what to do when the feature fails
	UserImpact     string // what the user sees
}

// NewDegradationManager creates a new DegradationManager.
func NewDegradationManager(bus *eventbus.EventBus) *DegradationManager {
	dm := &DegradationManager{
		eventBus:        bus,
		fallbacks:       make(map[string]Fallback),
		activeFallbacks: make(map[string]bool),
	}
	dm.initFallbacks()
	return dm
}

// initFallbacks initializes the degradation matrix from §9.4.
func (d *DegradationManager) initFallbacks() {
	d.fallbacks = map[string]Fallback{
		"hub": {
			Feature:        "hub",
			FallbackAction: "switch_to_standalone",
			UserImpact:     "Agent切换到单机模式，本地决策。告警通道降级为本地日志",
		},
		"alerts": {
			Feature:        "alerts",
			FallbackAction: "write_to_local_file",
			UserImpact:     "告警通道全部不可用，告警写入本地文件 + 面板红点显示",
		},
		"auto_repair": {
			Feature:        "auto_repair",
			FallbackAction: "alert_only_mode",
			UserImpact:     "自动修复决策失败，降级为只告警不修复模式",
		},
		"web_panel": {
			Feature:        "web_panel",
			FallbackAction: "cli_only",
			UserImpact:     "Web面板崩溃，使用sgctl CLI进行操作",
		},
		"sqlite": {
			Feature:        "sqlite",
			FallbackAction: "restore_from_backup_or_monitor_only",
			UserImpact:     "SQLite损坏，从备份恢复。恢复失败则只做实时监控不存储",
		},
		"rules": {
			Feature:        "rules",
			FallbackAction: "basic_rules_only",
			UserImpact:     "规则引擎异常，退化为基础规则（CPU/内存/磁盘）",
		},
		"upgrade": {
			Feature:        "upgrade",
			FallbackAction: "auto_rollback",
			UserImpact:     "升级失败，自动回滚到上一版本",
		},
		"cert_renew": {
			Feature:        "cert_renew",
			FallbackAction: "path_degradation_1_2_3",
			UserImpact:     "证书续期：路径1(宝塔API)→路径2(ACME)→路径3(全渠道告警)",
		},
		"kill_budget": {
			Feature:        "kill_budget",
			FallbackAction: "pause_kill_1h",
			UserImpact:     "Kill预算耗尽，Agent暂停所有Kill操作1小时，只告警",
		},
		"circuit_breaker": {
			Feature:        "circuit_breaker",
			FallbackAction: "pause_operation_30min",
			UserImpact:     "熔断器触发，对应操作暂停30分钟，只告警",
		},
		"resource_floor": {
			Feature:        "resource_floor",
			FallbackAction: "minimal_mode_pause_repair",
			UserImpact:     "系统资源不足，Agent进入最小模式，暂停所有自动修复",
		},
		"cascade": {
			Feature:        "cascade",
			FallbackAction: "observe_60s",
			UserImpact:     "检测到级联影响，暂停后续Kill，进入60s观察期",
		},
		"emergency_stop": {
			Feature:        "emergency_stop",
			FallbackAction: "monitor_only_mode",
			UserImpact:     "紧急停止激活，Agent进入纯监控模式，所有自动操作停止",
		},
		"agent_mem": {
			Feature:        "agent_mem",
			FallbackAction: "systemd_restart",
			UserImpact:     "Agent内存超限，systemd强制重启，看门狗拉起",
		},
		"baota_discovery": {
			Feature:        "baota_discovery",
			FallbackAction: "filesystem_scan_and_acme",
			UserImpact:     "宝塔API发现失败，证书监控降级为文件系统扫描，续期走ACME",
		},
	}
}

// TriggerFallback activates the fallback for a feature.
func (d *DegradationManager) TriggerFallback(feature string, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	fallback, exists := d.fallbacks[feature]
	if !exists {
		return
	}

	if d.activeFallbacks[feature] {
		return // Already in fallback mode
	}

	d.activeFallbacks[feature] = true

	d.eventBus.PublishAlert(types.AlertWarning, "degradation",
		fmt.Sprintf("功能降级: %s", feature),
		fmt.Sprintf("功能 %s 已降级。原因: %s\n降级动作: %s\n用户影响: %s",
			feature, reason, fallback.FallbackAction, fallback.UserImpact),
		"degradation-001")
}

// RecoverFallback deactivates the fallback for a feature (recovery).
func (d *DegradationManager) RecoverFallback(feature string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.activeFallbacks[feature] {
		return
	}

	delete(d.activeFallbacks, feature)

	fallback, exists := d.fallbacks[feature]
	if !exists {
		return
	}

	d.eventBus.PublishAlert(types.AlertInfo, "degradation",
		fmt.Sprintf("功能恢复: %s", feature),
		fmt.Sprintf("功能 %s 已从降级模式恢复: %s", feature, fallback.FallbackAction),
		"degradation-001")
}

// IsInFallback checks if a feature is currently in fallback mode.
func (d *DegradationManager) IsInFallback(feature string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.activeFallbacks[feature]
}

// GetActiveFallbacks returns all features currently in fallback mode.
func (d *DegradationManager) GetActiveFallbacks() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []string
	for feature := range d.activeFallbacks {
		result = append(result, feature)
	}
	return result
}

// GetFallbackInfo returns the fallback configuration for a feature.
func (d *DegradationManager) GetFallbackInfo(feature string) *Fallback {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if f, exists := d.fallbacks[feature]; exists {
		result := f
		return &result
	}
	return nil
}

// GetAllFallbacks returns all configured fallbacks.
func (d *DegradationManager) GetAllFallbacks() map[string]Fallback {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]Fallback)
	for k, v := range d.fallbacks {
		result[k] = v
	}
	return result
}
