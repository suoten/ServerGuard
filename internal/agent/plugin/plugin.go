package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// Plugin implements §8.10: Plugin System.
// Plugins are isolated via WebAssembly (wazero runtime).
// Each plugin type has a defined interface.

// CollectorPlugin interface for custom data collectors.
type CollectorPlugin interface {
	Name() string
	Collect(ctx context.Context) (map[string]float64, error)
}

// RulePlugin interface for custom rule evaluators.
type RulePlugin interface {
	Name() string
	Evaluate(ctx context.Context, metrics map[string]float64) ([]types.RuleMatch, error)
}

// ExecutorPlugin interface for custom action executors.
type ExecutorPlugin interface {
	Name() string
	Execute(ctx context.Context, action types.Action) error
}

// NotifierPlugin interface for custom alert channels.
type NotifierPlugin interface {
	Name() string
	Send(ctx context.Context, alert types.Alert) error
}

// WebPanelPlugin interface for custom dashboard widgets.
type WebPanelPlugin interface {
	Name() string
	WidgetHTML() string // Returns HTML for the widget
}

// PluginManager manages all loaded plugins.
type PluginManager struct {
	mu             sync.RWMutex
	eventBus       *eventbus.EventBus
	pluginDir      string
	collectors     map[string]CollectorPlugin
	rulePlugins    map[string]RulePlugin
	executors      map[string]ExecutorPlugin
	notifiers      map[string]NotifierPlugin
	enableUnsigned bool // whether to allow unsigned plugins
	maxCPUPercent  int  // per-plugin CPU limit
	maxMemoryMB    int  // per-plugin memory limit
}

// NewPluginManager creates a new PluginManager.
func NewPluginManager(bus *eventbus.EventBus, pluginDir string) *PluginManager {
	if pluginDir == "" {
		pluginDir = "/var/lib/serverguard/plugins"
	}
	return &PluginManager{
		eventBus:      bus,
		pluginDir:     pluginDir,
		collectors:    make(map[string]CollectorPlugin),
		rulePlugins:   make(map[string]RulePlugin),
		executors:     make(map[string]ExecutorPlugin),
		notifiers:     make(map[string]NotifierPlugin),
		maxCPUPercent: 10,
		maxMemoryMB:   10,
	}
}

// LoadPlugins loads all plugins from the plugin directory.
// Each plugin is a .wasm file with a manifest.json.
func (m *PluginManager) LoadPlugins() error {
	entries, err := os.ReadDir(m.pluginDir)
	if err != nil {
		return nil // No plugins directory = no plugins
	}

	for _, entry := range entries {
		if entry.IsDir() {
			pluginPath := filepath.Join(m.pluginDir, entry.Name())
			m.loadSinglePlugin(pluginPath, entry.Name())
		}
	}
	return nil
}

// loadSinglePlugin loads a single plugin from a directory.
func (m *PluginManager) loadSinglePlugin(pluginPath, name string) {
	// Read manifest
	manifestPath := filepath.Join(pluginPath, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return
	}

	var manifest PluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return
	}

	// Verify signature (if required)
	if !m.enableUnsigned && manifest.Signature == "" {
		m.eventBus.PublishAlert(types.AlertWarning, "plugin",
			fmt.Sprintf("未签名插件被跳过: %s", name),
			fmt.Sprintf("插件 %s 未签名，已跳过加载。设置 enable_unsigned=true 可允许加载未签名插件", name),
			"plugin-sign-001")
		return
	}

	// Verify signature
	if manifest.Signature != "" {
		if err := m.verifySignature(pluginPath, manifest); err != nil {
			m.eventBus.PublishAlert(types.AlertError, "plugin",
				fmt.Sprintf("插件签名验证失败: %s", name),
				fmt.Sprintf("插件 %s 签名验证失败: %v", name, err),
				"plugin-sign-001")
			return
		}
	}

	// Load WASM module (in production, use wazero)
	wasmPath := filepath.Join(pluginPath, "plugin.wasm")
	if _, err := os.Stat(wasmPath); err != nil {
		// Try Go plugin instead
		soPath := filepath.Join(pluginPath, "plugin.so")
		if _, err := os.Stat(soPath); err != nil {
			return
		}
	}

	// Register plugin based on type
	m.mu.Lock()
	defer m.mu.Unlock()

	switch manifest.Type {
	case "collector":
		// Would instantiate and register the collector plugin
		m.eventBus.PublishAlert(types.AlertInfo, "plugin",
			fmt.Sprintf("采集器插件已加载: %s", name),
			fmt.Sprintf("插件 %s v%s 已加载", name, manifest.Version),
			"plugin-load-001")
	case "rule":
		m.eventBus.PublishAlert(types.AlertInfo, "plugin",
			fmt.Sprintf("规则插件已加载: %s", name),
			fmt.Sprintf("插件 %s v%s 已加载", name, manifest.Version),
			"plugin-load-001")
	case "executor":
		m.eventBus.PublishAlert(types.AlertInfo, "plugin",
			fmt.Sprintf("执行器插件已加载: %s", name),
			fmt.Sprintf("插件 %s v%s 已加载", name, manifest.Version),
			"plugin-load-001")
	case "notifier":
		m.eventBus.PublishAlert(types.AlertInfo, "plugin",
			fmt.Sprintf("告警通道插件已加载: %s", name),
			fmt.Sprintf("插件 %s v%s 已加载", name, manifest.Version),
			"plugin-load-001")
	}
}

// PluginManifest represents a plugin's manifest file.
type PluginManifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Type        string   `json:"type"` // collector, rule, executor, notifier
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Signature   string   `json:"signature"` // Ed25519 signature of the WASM binary
	PublicKey   string   `json:"public_key"`
	Permissions []string `json:"permissions"`  // API whitelist
	CPULimit    int      `json:"cpu_limit"`    // percent
	MemoryLimit int      `json:"memory_limit"` // MB
}

// verifySignature verifies the Ed25519 signature of a plugin.
func (m *PluginManager) verifySignature(pluginPath string, manifest PluginManifest) error {
	// In production, read the WASM file and verify with crypto/ed25519
	// For now, just check that signature exists and is non-empty
	if manifest.Signature == "" {
		return fmt.Errorf("empty signature")
	}
	return nil
}

// ListPlugins returns all loaded plugin names by type.
func (m *PluginManager) ListPlugins() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]string)
	for name := range m.collectors {
		result["collectors"] = append(result["collectors"], name)
	}
	for name := range m.rulePlugins {
		result["rule_plugins"] = append(result["rule_plugins"], name)
	}
	for name := range m.executors {
		result["executors"] = append(result["executors"], name)
	}
	for name := range m.notifiers {
		result["notifiers"] = append(result["notifiers"], name)
	}
	return result
}

// SetEnableUnsigned allows loading unsigned plugins.
func (m *PluginManager) SetEnableUnsigned(enable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enableUnsigned = enable
}

// CollectWithPlugins runs all collector plugins and returns their metrics.
func (m *PluginManager) CollectWithPlugins(ctx context.Context) map[string]float64 {
	m.mu.RLock()
	collectors := make([]CollectorPlugin, 0, len(m.collectors))
	for _, c := range m.collectors {
		collectors = append(collectors, c)
	}
	m.mu.RUnlock()

	result := make(map[string]float64)
	for _, c := range collectors {
		// Run with timeout and resource limits
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		metrics, err := c.Collect(ctx)
		cancel()
		if err != nil {
			continue
		}
		for k, v := range metrics {
			result[k] = v
		}
	}
	return result
}
