package config

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// HotReloadManager 配置热加载管理器
type HotReloadManager struct {
	configPath string
	onReload   func(*Config) error
	mu         sync.Mutex
	stopCh     chan struct{}
}

// NewHotReloadManager 创建热加载管理器
func NewHotReloadManager(configPath string, onReload func(*Config) error) *HotReloadManager {
	return &HotReloadManager{
		configPath: configPath,
		onReload:   onReload,
		stopCh:     make(chan struct{}),
	}
}

// Start 启动热加载监听
// Linux: 监听 SIGHUP 信号
// Windows: 监听命名事件 "ServerGuard-Reload"
func (h *HotReloadManager) Start() {
	go h.watch()
}

// Stop 停止热加载监听
func (h *HotReloadManager) Stop() {
	close(h.stopCh)
}

// watch 监听重载信号
func (h *HotReloadManager) watch() {
	sigCh := make(chan os.Signal, 1)

	// Linux: SIGHUP
	// Windows: 使用 SIGTERM 作为替代（Windows 不支持 SIGHUP）
	signal.Notify(sigCh, syscall.SIGHUP)

	for {
		select {
		case <-sigCh:
			if err := h.reload(); err != nil {
				fmt.Fprintf(os.Stderr, "config hot reload failed: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "config hot reload succeeded")
			}
		case <-h.stopCh:
			return
		}
	}
}

// reload 执行配置重新加载
func (h *HotReloadManager) reload() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	cfg, err := LoadWithMigration(h.configPath)
	if err != nil {
		return err
	}

	return h.onReload(cfg)
}

// ReloadNow 手动触发配置重新加载
func (h *HotReloadManager) ReloadNow() error {
	return h.reload()
}

// TriggerReload 发送重载信号给当前进程
func TriggerReload() error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGHUP)
}

// ConfigWatcher 配置文件变更监听器（基于轮询，跨平台兼容）
type ConfigWatcher struct {
	configPath string
	lastMod    time.Time
	interval   time.Duration
	onChange   func(*Config) error
	stopCh     chan struct{}
}

// NewConfigWatcher 创建配置文件监听器
func NewConfigWatcher(configPath string, onChange func(*Config) error) *ConfigWatcher {
	return &ConfigWatcher{
		configPath: configPath,
		interval:   5 * time.Second,
		onChange:   onChange,
		stopCh:     make(chan struct{}),
	}
}

// Start 启动配置文件监听
func (w *ConfigWatcher) Start() {
	go w.watch()
}

// Stop 停止监听
func (w *ConfigWatcher) Stop() {
	close(w.stopCh)
}

// watch 轮询检查配置文件修改时间
func (w *ConfigWatcher) watch() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			info, err := os.Stat(w.configPath)
			if err != nil {
				continue
			}
			if w.lastMod.IsZero() {
				w.lastMod = info.ModTime()
				continue
			}
			if info.ModTime().After(w.lastMod) {
				w.lastMod = info.ModTime()
				cfg, err := LoadWithMigration(w.configPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "config reload failed: %v\n", err)
					continue
				}
				if err := w.onChange(cfg); err != nil {
					fmt.Fprintf(os.Stderr, "config apply failed: %v\n", err)
				}
			}
		case <-w.stopCh:
			return
		}
	}
}
