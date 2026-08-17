package winmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// WindowsServiceManager implements Windows-specific service management.
// Uses WMI, PowerShell, and sc.exe for service operations.
type WindowsServiceManager struct {
	mu       sync.RWMutex
	eventBus *eventbus.EventBus
	safety   *safety.SafetyManager // 安全管理器引用，用于宝塔安全模式判断
}

// NewWindowsServiceManager creates a new WindowsServiceManager.
func NewWindowsServiceManager(bus *eventbus.EventBus) *WindowsServiceManager {
	return &WindowsServiceManager{eventBus: bus}
}

// SetSafetyManager 注入安全管理器，启用宝塔安全模式检查。
func (w *WindowsServiceManager) SetSafetyManager(sm *safety.SafetyManager) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.safety = sm
}

// IsWindows returns true if running on Windows.
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// ListServices lists all Windows services.
func (w *WindowsServiceManager) ListServices(ctx context.Context) ([]WindowsService, error) {
	if !IsWindows() {
		return nil, fmt.Errorf("not running on Windows")
	}

	// Use PowerShell to get services
	cmd := exec.CommandContext(ctx, "powershell", "-Command",
		"Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse output (simplified)
	_ = output
	return nil, nil
}

// WindowsService represents a Windows service.
type WindowsService struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Status      string `json:"Status"`
	StartType   string `json:"StartType"`
}

// RestartService restarts a Windows service.
func (w *WindowsServiceManager) RestartService(ctx context.Context, serviceName string) error {
	if !IsWindows() {
		return fmt.Errorf("not running on Windows")
	}

	// Stop service
	stopCmd := exec.CommandContext(ctx, "sc", "stop", serviceName)
	if output, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stop service failed: %v, output: %s", err, string(output))
	}

	// Wait for service to stop
	time.Sleep(2 * time.Second)

	// Start service
	startCmd := exec.CommandContext(ctx, "sc", "start", serviceName)
	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start service failed: %v, output: %s", err, string(output))
	}

	w.eventBus.PublishAlert(types.AlertInfo, "service",
		fmt.Sprintf("Windows服务已重启: %s", serviceName),
		fmt.Sprintf("Windows服务 %s 已通过 sc.exe 重启", serviceName),
		"win-service-001")

	return nil
}

// RegisterAsService registers an executable as a Windows Service.
func (w *WindowsServiceManager) RegisterAsService(serviceName, exePath, description string) error {
	if !IsWindows() {
		return fmt.Errorf("not running on Windows")
	}

	// Use sc create
	cmd := exec.Command("sc", "create", serviceName,
		"binPath=", exePath,
		"start=", "auto",
		"DisplayName=", serviceName,
		"description=", description)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create service failed: %v, output: %s", err, string(output))
	}

	w.eventBus.PublishAlert(types.AlertInfo, "service",
		fmt.Sprintf("已注册Windows服务: %s", serviceName),
		fmt.Sprintf("已将 %s 注册为Windows服务，路径: %s", serviceName, exePath),
		"win-service-001")

	return nil
}

// UnregisterService removes a Windows Service registration.
func (w *WindowsServiceManager) UnregisterService(serviceName string) error {
	if !IsWindows() {
		return fmt.Errorf("not running on Windows")
	}

	cmd := exec.Command("sc", "delete", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("delete service failed: %v, output: %s", err, string(output))
	}

	return nil
}

// GetServiceStatus returns the status of a Windows service.
func (w *WindowsServiceManager) GetServiceStatus(ctx context.Context, serviceName string) (string, error) {
	if !IsWindows() {
		return "", fmt.Errorf("not running on Windows")
	}

	cmd := exec.CommandContext(ctx, "sc", "query", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output for STATE
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "STATE") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				return parts[3], nil // e.g., "RUNNING"
			}
		}
	}

	return "UNKNOWN", nil
}

// CheckProcessViaWMI checks process info via WMI.
func (w *WindowsServiceManager) CheckProcessViaWMI(ctx context.Context, pid int32) (map[string]interface{}, error) {
	if !IsWindows() {
		return nil, fmt.Errorf("not running on Windows")
	}

	// Use PowerShell WMI query
	cmd := exec.CommandContext(ctx, "powershell", "-Command",
		fmt.Sprintf("Get-WmiObject Win32_Process -Filter 'ProcessId=%d' | Select-Object Name,CommandLine,ExecutablePath | ConvertTo-Json", pid))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	_ = output
	result := make(map[string]interface{})
	return result, nil
}

// CheckWindowsFirewall checks if Windows Firewall is enabled.
func (w *WindowsServiceManager) CheckWindowsFirewall(ctx context.Context) error {
	if !IsWindows() {
		return fmt.Errorf("not running on Windows")
	}

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	if !strings.Contains(string(output), "ON") {
		w.eventBus.PublishAlert(types.AlertWarning, "security",
			"Windows防火墙未启用",
			"Windows防火墙处于关闭状态，建议启用以保护服务器",
			"win-firewall-001")
	}

	return nil
}

// BanIPWindows bans an IP using Windows Firewall.
func (w *WindowsServiceManager) BanIPWindows(ctx context.Context, ip string, duration time.Duration) error {
	if !IsWindows() {
		return fmt.Errorf("not running on Windows")
	}

	// Add firewall rule to block IP
	ruleName := fmt.Sprintf("ServerGuard_Ban_%s", ip)
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=", ruleName,
		"dir=in", "action=block",
		"remoteip=", ip)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Schedule unban
	go func() {
		time.Sleep(duration)
		unbanCmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name=", ruleName)
		unbanCmd.Run()
	}()

	return nil
}

// ScanBareProcesses scans for processes not managed by systemd/Windows Service.
// B8: Service Start Dependency Auto Repair.
func (w *WindowsServiceManager) ScanBareProcesses(ctx context.Context) {
	if IsWindows() {
		w.scanWindowsBareProcesses(ctx)
	} else {
		w.scanLinuxBareProcesses(ctx)
	}
}

func (w *WindowsServiceManager) scanLinuxBareProcesses(ctx context.Context) {
	// 宝塔安全模式下：跳过 process.Processes() — I/O 开销大
	w.mu.RLock()
	sm := w.safety
	w.mu.RUnlock()
	if sm != nil && sm.IsBaotaSafeMode() {
		return
	}

	procs, _ := process.Processes()
	for _, p := range procs {
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		// Skip system processes
		if name == "" || name == "systemd" || name == "kthreadd" {
			continue
		}

		// Check if process is managed by systemd
		ppid, _ := p.Ppid()
		if ppid == 1 {
			// Parent is init/systemd, likely managed
			continue
		}

		// Check if it's a daemon started with nohup & or ./binary &
		if strings.Contains(cmdline, "nohup") || strings.Contains(cmdline, "-d") {
			w.eventBus.PublishAlert(types.AlertInfo, "service",
				fmt.Sprintf("检测到裸奔进程: %s (PID %d)", name, p.Pid),
				fmt.Sprintf("进程 %s (PID %d) 不是 systemd 管理的服务，异常退出后无法自动恢复。建议: 一键注册为 systemd 服务\n命令: %s",
					name, p.Pid, cmdline),
				"bare-process-001")
		}
	}
}

func (w *WindowsServiceManager) scanWindowsBareProcesses(ctx context.Context) {
	// On Windows, check for processes not registered as services
	procs, _ := process.Processes()
	for _, p := range procs {
		name, _ := p.Name()
		if name == "" {
			continue
		}
		// Check if process is a Windows Service
		// Would use WMI to check Win32_Service.ProcessId
	}
}

// RegisterBareProcessAsService registers a bare process as a system service.
// 宝塔安全模式下：禁止 systemctl daemon-reload 和 systemctl enable —
// 这些操作会触发 systemd 重新加载，可能影响宝塔管理的服务。
func (w *WindowsServiceManager) RegisterBareProcessAsService(ctx context.Context, name, command, workDir string) error {
	// 宝塔安全模式检查
	w.mu.RLock()
	sm := w.safety
	w.mu.RUnlock()
	if sm != nil && sm.IsBaotaSafeMode() {
		w.eventBus.PublishAlert(types.AlertWarning, "service",
			"[安全保护模式] 服务注册已禁用",
			fmt.Sprintf("注册 %s 为 systemd 服务的操作在安全保护模式下已禁用，请通过宝塔面板管理", name),
			"service-register-baota-001")
		return fmt.Errorf("安全保护模式：服务注册操作已禁用")
	}

	if IsWindows() {
		return w.RegisterAsService(name, command, "Registered by ServerGuard")
	}

	// Linux: create systemd unit file
	unitContent := fmt.Sprintf(`[Unit]
Description=%s (Registered by ServerGuard)
After=network.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, name, workDir, command)

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return err
	}

	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", name).Run()

	w.eventBus.PublishAlert(types.AlertInfo, "service",
		fmt.Sprintf("已注册为系统服务: %s", name),
		fmt.Sprintf("进程 %s 已注册为 systemd 服务，路径: %s", name, unitPath),
		"service-register-001")

	return nil
}
