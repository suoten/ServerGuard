//go:build windows

package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/suoten/serverguard/internal/types"
)

// windowsServiceManager Windows Service 管理
type windowsServiceManager struct{}

func newServiceManager() ServiceManager { return &windowsServiceManager{} }

func (m *windowsServiceManager) Start(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "sc", "start", name).Run()
}

func (m *windowsServiceManager) Stop(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "sc", "stop", name).Run()
}

func (m *windowsServiceManager) Restart(ctx context.Context, name string) error {
	if err := m.Stop(ctx, name); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	return m.Start(ctx, name)
}

func (m *windowsServiceManager) Status(ctx context.Context, name string) (ServiceStatus, error) {
	out, err := exec.CommandContext(ctx, "sc", "query", name).Output()
	if err != nil {
		return ServiceStatusUnknown, nil
	}
	s := string(out)
	switch {
	case strings.Contains(s, "RUNNING"):
		return ServiceStatusRunning, nil
	case strings.Contains(s, "STOPPED"):
		return ServiceStatusStopped, nil
	case strings.Contains(s, "FAILED"):
		return ServiceStatusFailed, nil
	default:
		return ServiceStatusUnknown, nil
	}
}

func (m *windowsServiceManager) Enable(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "sc", "config", name, "start=", "auto").Run()
}

func (m *windowsServiceManager) Disable(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "sc", "config", name, "start=", "demand").Run()
}

func (m *windowsServiceManager) List(ctx context.Context) ([]ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "sc", "query", "type=", "service", "state=", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	var services []ServiceInfo
	lines := strings.Split(string(out), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "SERVICE_NAME:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
			status := ServiceStatusUnknown
			if i+1 < len(lines) {
				stateLine := strings.TrimSpace(lines[i+1])
				if strings.Contains(stateLine, "RUNNING") {
					status = ServiceStatusRunning
				} else if strings.Contains(stateLine, "STOPPED") {
					status = ServiceStatusStopped
				}
			}
			services = append(services, ServiceInfo{
				Name:    name,
				Status:  status,
				Manager: "windows-service",
			})
		}
	}
	return services, nil
}

func (m *windowsServiceManager) Register(ctx context.Context, name string, config ServiceConfig) error {
	binaryPath := config.Command
	if len(config.Args) > 0 {
		binaryPath = fmt.Sprintf("\"%s\" %s", config.Command, strings.Join(config.Args, " "))
	}
	cmd := exec.CommandContext(ctx, "sc", "create", name,
		"binPath=", binaryPath,
		"DisplayName=", config.DisplayName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	if config.AutoStart {
		return m.Enable(ctx, name)
	}
	return nil
}

func (m *windowsServiceManager) Unregister(ctx context.Context, name string) error {
	_ = m.Stop(ctx, name)
	return exec.CommandContext(ctx, "sc", "delete", name).Run()
}

func (m *windowsServiceManager) IsManaged(ctx context.Context, name string) (bool, error) {
	err := exec.CommandContext(ctx, "sc", "query", name).Run()
	return err == nil, nil
}

// windowsProcessCollector 进程采集
type windowsProcessCollector struct{}

func newProcessCollector() ProcessCollector { return &windowsProcessCollector{} }

func (c *windowsProcessCollector) List(ctx context.Context, maxCount int) ([]types.ProcessInfo, error) {
	pids, err := process.PidsWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("get pids: %w", err)
	}
	if maxCount > 0 && len(pids) > maxCount {
		pids = pids[:maxCount]
	}
	result := make([]types.ProcessInfo, 0, len(pids))
	for _, pid := range pids {
		info, err := c.Get(ctx, pid)
		if err != nil {
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

func (c *windowsProcessCollector) Get(ctx context.Context, pid int32) (types.ProcessInfo, error) {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return types.ProcessInfo{}, err
	}
	name, _ := p.NameWithContext(ctx)
	cmdline, _ := p.CmdlineWithContext(ctx)
	cpu, _ := p.CPUPercentWithContext(ctx)
	mem, _ := p.MemoryPercentWithContext(ctx)
	memInfo, _ := p.MemoryInfoWithContext(ctx)
	ppid, _ := p.PpidWithContext(ctx)
	status, _ := p.StatusWithContext(ctx)
	createTime, _ := p.CreateTimeWithContext(ctx)
	numThreads, _ := p.NumThreadsWithContext(ctx)
	info := types.ProcessInfo{
		PID:        pid,
		PPID:       ppid,
		Name:       name,
		Cmdline:    cmdline,
		CPUPercent: cpu,
		MemPercent: float64(mem),
		Status:     strings.Join(status, " "),
		NumThreads: numThreads,
	}
	if memInfo != nil {
		info.RSS = memInfo.RSS
		info.VMS = memInfo.VMS
	}
	if createTime > 0 {
		info.CreateTime = time.Unix(0, createTime*int64(time.Millisecond))
	}
	return info, nil
}

func (c *windowsProcessCollector) Kill(ctx context.Context, pid int32, signal ProcessSignal) error {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return err
	}
	if signal == SignalSIGKILL {
		return p.KillWithContext(ctx)
	}
	return p.TerminateWithContext(ctx)
}

func (c *windowsProcessCollector) Nice(ctx context.Context, pid int32, priority int) error {
	return nil
}

func (c *windowsProcessCollector) Children(ctx context.Context, pid int32) ([]int32, error) {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return nil, err
	}
	children, err := p.ChildrenWithContext(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]int32, len(children))
	for i, child := range children {
		result[i] = child.Pid
	}
	return result, nil
}

func (c *windowsProcessCollector) IsZombie(ctx context.Context, pid int32) (bool, error) {
	return false, nil
}

func (c *windowsProcessCollector) IsKernelThread(ctx context.Context, pid int32) (bool, error) {
	return pid <= 4, nil
}

func (c *windowsProcessCollector) OpenFiles(ctx context.Context, pid int32) (int32, error) {
	return 0, nil
}

func (c *windowsProcessCollector) Connections(ctx context.Context, pid int32) ([]ConnectionInfo, error) {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return nil, err
	}
	conns, err := p.ConnectionsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]ConnectionInfo, 0, len(conns))
	for _, c := range conns {
		result = append(result, ConnectionInfo{
			LocalAddr:  c.Laddr.IP,
			LocalPort:  uint16(c.Laddr.Port),
			RemoteAddr: c.Raddr.IP,
			RemotePort: uint16(c.Raddr.Port),
			Status:     c.Status,
			PID:        pid,
		})
	}
	return result, nil
}

// windowsLogRotator 日志轮转（重命名+通知模式）
type windowsLogRotator struct {
	mu      sync.Mutex
	watched map[string]chan FileEvent
}

func newLogRotator() LogRotator {
	return &windowsLogRotator{watched: make(map[string]chan FileEvent)}
}

func (r *windowsLogRotator) Rotate(ctx context.Context, path string, opts RotateOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat log file: %w", err)
	}
	if opts.MaxSize > 0 && stat.Size() < opts.MaxSize {
		return nil
	}

	now := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", path, now)

	if err := os.Rename(path, rotatedPath); err != nil {
		return fmt.Errorf("rename log file: %w", err)
	}
	if opts.Compress {
		_ = exec.Command("gzip", "-f", rotatedPath).Run()
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("recreate log file: %w", err)
	}
	f.Close()
	return nil
}

func (r *windowsLogRotator) Compress(ctx context.Context, path string) error {
	return exec.CommandContext(ctx, "gzip", "-f", path).Run()
}

func (r *windowsLogRotator) Watch(ctx context.Context, path string, opts WatchOptions) (<-chan FileEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ch, exists := r.watched[path]; exists {
		return ch, nil
	}

	ch := make(chan FileEvent, 64)
	r.watched[path] = ch

	go func() {
		defer close(ch)
		var lastSize int64
		if stat, err := os.Stat(path); err == nil {
			lastSize = stat.Size()
		}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stat, err := os.Stat(path)
				if err != nil {
					continue
				}
				if stat.Size() != lastSize {
					ch <- FileEvent{
						Path:      path,
						Operation: "modify",
						Timestamp: time.Now(),
						Size:      stat.Size(),
					}
					lastSize = stat.Size()
				}
			}
		}
	}()

	return ch, nil
}

func (r *windowsLogRotator) Unwatch(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, exists := r.watched[path]; exists {
		close(ch)
		delete(r.watched, path)
	}
	return nil
}

func (r *windowsLogRotator) ListWatched() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, 0, len(r.watched))
	for k := range r.watched {
		result = append(result, k)
	}
	return result
}

// windowsFirewallManager netsh 防火墙
type windowsFirewallManager struct {
	mu sync.Mutex
}

func newFirewallManager() FirewallManager { return &windowsFirewallManager{} }

func (m *windowsFirewallManager) BanIP(ctx context.Context, ip string, opts BanOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=ServerGuard-Ban-"+ip,
		"dir=in", "action=block", "remoteip="+ip).Run()
}

func (m *windowsFirewallManager) UnbanIP(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name=ServerGuard-Ban-"+ip).Run()
}

func (m *windowsFirewallManager) IsBanned(ctx context.Context, ip string) (bool, error) {
	out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule",
		"name=ServerGuard-Ban-"+ip).Output()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(out), ip), nil
}

func (m *windowsFirewallManager) ListBanned(ctx context.Context) ([]BanEntry, error) {
	return []BanEntry{}, nil
}

func (m *windowsFirewallManager) RateLimit(ctx context.Context, ip string, rate int, opts RateLimitOptions) error {
	return nil
}

func (m *windowsFirewallManager) RemoveRateLimit(ctx context.Context, ip string) error {
	return nil
}

func (m *windowsFirewallManager) ClearAll(ctx context.Context) error {
	return nil
}

// windowsNetworkManager 网络管理
type windowsNetworkManager struct{}

func newNetworkManager() NetworkManager { return &windowsNetworkManager{} }

func (m *windowsNetworkManager) ListInterfaces(ctx context.Context) ([]NetInterface, error) {
	return []NetInterface{}, nil
}

func (m *windowsNetworkManager) RestartNetworking(ctx context.Context) error {
	return exec.CommandContext(ctx, "netsh", "interface", "set", "interface", "Ethernet", "disable").Run()
}

func (m *windowsNetworkManager) SetDNS(ctx context.Context, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	return exec.CommandContext(ctx, "netsh", "interface", "ip", "set", "dns",
		"name=Ethernet", "static", servers[0]).Run()
}

func (m *windowsNetworkManager) GetDNS(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func (m *windowsNetworkManager) Ping(ctx context.Context, host string, timeout time.Duration) (bool, time.Duration, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", timeout.Milliseconds()), host)
	err := cmd.Run()
	elapsed := time.Since(start)
	return err == nil, elapsed, nil
}

func (m *windowsNetworkManager) TraceRoute(ctx context.Context, host string, maxHops int) ([]string, error) {
	out, err := exec.CommandContext(ctx, "tracert", "-h", fmt.Sprintf("%d", maxHops), host).Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func (m *windowsNetworkManager) ListeningPorts(ctx context.Context) ([]PortInfo, error) {
	out, err := exec.CommandContext(ctx, "netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		return nil, err
	}
	var ports []PortInfo
	for _, line := range strings.Split(string(out), "\n")[2:] {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "TCP" {
			continue
		}
		addrParts := strings.Split(fields[1], ":")
		if len(addrParts) < 2 {
			continue
		}
		var port int32
		fmt.Sscanf(addrParts[len(addrParts)-1], "%d", &port)
		ports = append(ports, PortInfo{
			Port:      port,
			Protocol:  "tcp",
			LocalAddr: fields[1],
			State:     fields[3],
		})
	}
	return ports, nil
}

// windowsFileWatcher 文件监控
type windowsFileWatcher struct {
	mu      sync.Mutex
	watched map[string]chan FileEvent
}

func newFileWatcher() FileWatcher {
	return &windowsFileWatcher{watched: make(map[string]chan FileEvent)}
}

func (w *windowsFileWatcher) Watch(ctx context.Context, path string, recursive bool) (<-chan FileEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if ch, exists := w.watched[path]; exists {
		return ch, nil
	}

	ch := make(chan FileEvent, 64)
	w.watched[path] = ch

	go func() {
		defer close(ch)
		var lastMod time.Time
		if stat, err := os.Stat(path); err == nil {
			lastMod = stat.ModTime()
		}
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stat, err := os.Stat(path)
				if err != nil {
					continue
				}
				if stat.ModTime().After(lastMod) {
					ch <- FileEvent{
						Path:      path,
						Operation: "modify",
						Timestamp: stat.ModTime(),
						Size:      stat.Size(),
					}
					lastMod = stat.ModTime()
				}
			}
		}
	}()

	return ch, nil
}

func (w *windowsFileWatcher) Unwatch(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ch, exists := w.watched[path]; exists {
		close(ch)
		delete(w.watched, path)
	}
	return nil
}

func (w *windowsFileWatcher) ListWatched() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]string, 0, len(w.watched))
	for k := range w.watched {
		result = append(result, k)
	}
	return result
}

func (w *windowsFileWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for path, ch := range w.watched {
		close(ch)
		delete(w.watched, path)
	}
	return nil
}

// newPlatformDepsImpl 创建 Windows 平台依赖
func newPlatformDepsImpl() *PlatformDeps {
	return &PlatformDeps{
		ServiceMgr:  newServiceManager(),
		ProcessColl: newProcessCollector(),
		LogRotator:  newLogRotator(),
		FileWatcher: newFileWatcher(),
		FirewallMgr: newFirewallManager(),
		NetworkMgr:  newNetworkManager(),
	}
}
