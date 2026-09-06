//go:build linux

package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/suoten/serverguard/internal/types"
)

// linuxServiceManager systemd 服务管理
type linuxServiceManager struct{}

func newServiceManager() ServiceManager { return &linuxServiceManager{} }

func (m *linuxServiceManager) Start(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "systemctl", "start", name).Run()
}

func (m *linuxServiceManager) Stop(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "systemctl", "stop", name).Run()
}

func (m *linuxServiceManager) Restart(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "systemctl", "restart", name).Run()
}

func (m *linuxServiceManager) Status(ctx context.Context, name string) (ServiceStatus, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", name).Output()
	if err != nil {
		return ServiceStatusUnknown, nil
	}
	switch strings.TrimSpace(string(out)) {
	case "active":
		return ServiceStatusRunning, nil
	case "inactive", "deactivating":
		return ServiceStatusStopped, nil
	case "failed":
		return ServiceStatusFailed, nil
	default:
		return ServiceStatusUnknown, nil
	}
}

func (m *linuxServiceManager) Enable(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "systemctl", "enable", name).Run()
}

func (m *linuxServiceManager) Disable(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "systemctl", "disable", name).Run()
}

func (m *linuxServiceManager) List(ctx context.Context) ([]ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service",
		"--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	var services []ServiceInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		status := ServiceStatusStopped
		if fields[3] == "running" {
			status = ServiceStatusRunning
		}
		services = append(services, ServiceInfo{
			Name:    name,
			Status:  status,
			Enabled: true,
			Manager: "systemd",
		})
	}
	return services, nil
}

func (m *linuxServiceManager) Register(ctx context.Context, name string, config ServiceConfig) error {
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	restart := config.Restart
	if restart == "" {
		restart = "always"
	}
	unitContent := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s %s
WorkingDirectory=%s
Restart=%s

[Install]
WantedBy=multi-user.target
`, config.DisplayName, config.Command, strings.Join(config.Args, " "), config.WorkDir, restart)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if config.AutoStart {
		return m.Enable(ctx, name)
	}
	return nil
}

func (m *linuxServiceManager) Unregister(ctx context.Context, name string) error {
	_ = m.Stop(ctx, name)
	_ = m.Disable(ctx, name)
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	_ = os.Remove(unitPath)
	return exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
}

func (m *linuxServiceManager) IsManaged(ctx context.Context, name string) (bool, error) {
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	if _, err := os.Stat(unitPath); err == nil {
		return true, nil
	}
	unitPath = fmt.Sprintf("/usr/lib/systemd/system/%s.service", name)
	_, err := os.Stat(unitPath)
	return err == nil, nil
}

// linuxProcessCollector 进程采集
type linuxProcessCollector struct{}

func newProcessCollector() ProcessCollector { return &linuxProcessCollector{} }

func (c *linuxProcessCollector) List(ctx context.Context, maxCount int) ([]types.ProcessInfo, error) {
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

func (c *linuxProcessCollector) Get(ctx context.Context, pid int32) (types.ProcessInfo, error) {
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
	numFDs, _ := p.NumFDsWithContext(ctx)
	info := types.ProcessInfo{
		PID:        pid,
		PPID:       ppid,
		Name:       name,
		Cmdline:    cmdline,
		CPUPercent: cpu,
		MemPercent: float64(mem),
		Status:     strings.Join(status, " "),
		NumThreads: numThreads,
		NumFDs:     numFDs,
	}
	if memInfo != nil {
		info.RSS = memInfo.RSS
		info.VMS = memInfo.VMS
	}
	if createTime > 0 {
		info.CreateTime = time.Unix(0, createTime*int64(time.Millisecond))
	}
	info.Manager = c.detectManager(pid)
	return info, nil
}

func (c *linuxProcessCollector) detectManager(pid int32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	if data, err := os.ReadFile(cgroupPath); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") {
			return "docker"
		}
		if strings.Contains(s, ".scope") {
			return "systemd"
		}
	}
	return "bare"
}

func (c *linuxProcessCollector) Kill(ctx context.Context, pid int32, signal ProcessSignal) error {
	var sig syscall.Signal
	switch signal {
	case SignalSIGTERM:
		sig = syscall.SIGTERM
	case SignalSIGKILL:
		sig = syscall.SIGKILL
	case SignalSIGHUP:
		sig = syscall.SIGHUP
	case SignalSIGINT:
		sig = syscall.SIGINT
	default:
		sig = syscall.SIGTERM
	}
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return err
	}
	return p.SendSignal(sig)
}

func (c *linuxProcessCollector) Nice(ctx context.Context, pid int32, priority int) error {
	// gopsutil v3 doesn't expose SetNice; use syscall.Setpriority via /proc
	// Note: this requires CAP_SYS_NICE capability
	return fmt.Errorf("nice adjustment not supported on linux via gopsutil")
}

func (c *linuxProcessCollector) Children(ctx context.Context, pid int32) ([]int32, error) {
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

func (c *linuxProcessCollector) IsZombie(ctx context.Context, pid int32) (bool, error) {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return false, err
	}
	status, err := p.StatusWithContext(ctx)
	if err != nil {
		return false, err
	}
	for _, s := range status {
		if s == "z" || s == "Z" {
			return true, nil
		}
	}
	return false, nil
}

func (c *linuxProcessCollector) IsKernelThread(ctx context.Context, pid int32) (bool, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return false, nil
	}
	return len(data) == 0, nil
}

func (c *linuxProcessCollector) OpenFiles(ctx context.Context, pid int32) (int32, error) {
	p, err := process.NewProcessWithContext(ctx, pid)
	if err != nil {
		return 0, err
	}
	files, err := p.OpenFilesWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return int32(len(files)), nil
}

func (c *linuxProcessCollector) Connections(ctx context.Context, pid int32) ([]ConnectionInfo, error) {
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

// linuxLogRotator 日志轮转
type linuxLogRotator struct {
	mu      sync.Mutex
	watched map[string]chan FileEvent
}

func newLogRotator() LogRotator {
	return &linuxLogRotator{watched: make(map[string]chan FileEvent)}
}

func (r *linuxLogRotator) Rotate(ctx context.Context, path string, opts RotateOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat log file: %w", err)
	}

	if opts.MaxSize > 0 && stat.Size() < opts.MaxSize {
		return nil
	}

	mode := opts.Mode
	if mode == "" {
		mode = "copytruncate"
	}

	now := time.Now().Format("20060102-150405")

	switch mode {
	case "copytruncate":
		rotatedPath := fmt.Sprintf("%s.%s", path, now)
		if err := copyFile(path, rotatedPath); err != nil {
			return fmt.Errorf("copy log file: %w", err)
		}
		if opts.Compress {
			if err := compressFile(rotatedPath); err != nil {
				return fmt.Errorf("compress: %w", err)
			}
		}
		if err := truncateFile(path); err != nil {
			return fmt.Errorf("truncate: %w", err)
		}
	case "rename":
		rotatedPath := fmt.Sprintf("%s.%s", path, now)
		if err := os.Rename(path, rotatedPath); err != nil {
			return fmt.Errorf("rename log file: %w", err)
		}
		if opts.Compress {
			if err := compressFile(rotatedPath); err != nil {
				return fmt.Errorf("compress: %w", err)
			}
		}
		_ = recreateFile(path)
	}

	r.cleanupOldFiles(path, opts.MaxFiles)
	return nil
}

func (r *linuxLogRotator) Compress(ctx context.Context, path string) error {
	return compressFile(path)
}

func (r *linuxLogRotator) Watch(ctx context.Context, path string, opts WatchOptions) (<-chan FileEvent, error) {
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

func (r *linuxLogRotator) Unwatch(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, exists := r.watched[path]; exists {
		close(ch)
		delete(r.watched, path)
	}
	return nil
}

func (r *linuxLogRotator) ListWatched() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, 0, len(r.watched))
	for k := range r.watched {
		result = append(result, k)
	}
	return result
}

func (r *linuxLogRotator) cleanupOldFiles(basePath string, maxFiles int) {
	if maxFiles <= 0 {
		return
	}
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var oldFiles []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".") {
			oldFiles = append(oldFiles, filepath.Join(dir, e.Name()))
		}
	}
	if len(oldFiles) > maxFiles {
		for i := 0; i < len(oldFiles)-maxFiles; i++ {
			_ = os.Remove(oldFiles[i])
		}
	}
}

// linuxFirewallManager iptables 防火墙
type linuxFirewallManager struct {
	mu sync.Mutex
}

func newFirewallManager() FirewallManager { return &linuxFirewallManager{} }

func (m *linuxFirewallManager) BanIP(ctx context.Context, ip string, opts BanOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 管理员来源保护：该 IP 正有已认证的登录会话（SSH 等）时拒绝封禁。
	// 进程崩溃后残留规则没有任何自动解封机制，封掉管理员等于把钥匙锁在门里。
	if IsAdminSSHSource(ip) {
		return fmt.Errorf("refusing to ban %s: 当前是该 IP 上已登录管理员的活动来源（防自锁保护），请确认后在面板手动封禁", ip)
	}

	prefix := opts.RulePrefix
	if prefix == "" {
		prefix = "serverguard"
	}
	proto := opts.Protocol
	if proto == "" {
		proto = "tcp"
	}

	// 到期时间戳编码进规则注释：exp=<unix>。
	// Duration=0 表示永久（旧格式无 exp 字段同样视为永久，绝不会被误删）。
	var expireUnix int64
	if opts.Duration > 0 {
		expireUnix = time.Now().Add(opts.Duration).Unix()
	}
	comment := fmt.Sprintf("%s:exp=%d:%s", prefix, expireUnix, opts.Reason)

	args := []string{"-A", "INPUT", "-s", ip, "-p", proto}
	if opts.Port > 0 {
		args = append(args, "--dport", strconv.Itoa(opts.Port))
	}
	args = append(args, "-j", "DROP", "-m", "comment", "--comment", comment)

	// 单次列链完成三件事：幂等检查 / 自身过期续期 / 惰性清扫他人过期规则。
	// 封禁调用频率受 attackwarn 预算（≤30次/5分钟）约束，因此清扫收敛速度有保证，
	// 且每次调用最多删除 5 条，绝不产生删除风暴。
	out, lerr := exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n", "--line-numbers").Output()
	if lerr == nil {
		now := time.Now().Unix()
		expiredSelf := ""
		sweepBudget := 5
		for _, line := range strings.Split(string(out), "\n") {
			lineNum, src, exp, ok := parseBanRuleLine(line)
			if !ok {
				continue
			}
			stale := exp > 0 && now >= exp

			switch {
			case src == ip && !stale:
				// 已存在生效封禁：幂等返回，杜绝重复追加导致规则堆积
				return nil
			case src == ip && stale:
				// 记录待续期的自身过期规则，循环结束后删除重加
				expiredSelf = lineNum
			case stale && sweepBudget > 0:
				// 顺手清理其他已过期的本工具规则（预算内）
				sweepBudget--
				if err := exec.CommandContext(ctx, "iptables", "-D", "INPUT", lineNum).Run(); err != nil && expiredSelf == lineNum {
					expiredSelf = ""
				}
			}
		}
		if expiredSelf != "" {
			_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", expiredSelf).Run()
		}
	}

	return exec.CommandContext(ctx, "iptables", args...).Run()
}

func (m *linuxFirewallManager) UnbanIP(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 安全删除：只删除 ServerGuard 添加的规则（通过 comment 标记识别），
	// 不删除其他程序（如宝塔面板）为同一 IP 添加的防火墙规则。
	// 注意：源 IP 在 --line-numbers 输出中是 fields[4]（fields[3] 是 "--" 分隔符），
	// 历史实现取 fields[3] 导致解封永远匹配不到——此处已修正。
	for {
		out, err := exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n", "--line-numbers").Output()
		if err != nil {
			break
		}
		found := false
		for _, line := range strings.Split(string(out), "\n") {
			lineNum, src, _, ok := parseBanRuleLine(line)
			if !ok || src != ip {
				continue
			}
			if err := exec.CommandContext(ctx, "iptables", "-D", "INPUT", lineNum).Run(); err == nil {
				found = true
				break // 重新列表，行号会变化
			}
		}
		if !found {
			break
		}
	}
	return nil
}

func (m *linuxFirewallManager) IsBanned(ctx context.Context, ip string) (bool, error) {
	out, err := exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n").Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), ip), nil
}

func (m *linuxFirewallManager) ListBanned(ctx context.Context) ([]BanEntry, error) {
	out, err := exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n", "--line-numbers").Output()
	if err != nil {
		return nil, err
	}
	var entries []BanEntry
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "DROP") {
			continue
		}
		fields := strings.Fields(line)
		// [num, target, prot, "--", source, ...] —— 历史实现取 fields[3]（"--"）导致列表全是无效项
		if len(fields) < 5 || fields[3] != "--" {
			continue
		}
		ip := fields[4]
		if ip == "0.0.0.0/0" || ip == "anywhere" {
			continue
		}
		entries = append(entries, BanEntry{
			IP:       ip,
			BannedAt: time.Now(),
			Source:   "iptables",
		})
	}
	return entries, nil
}

func (m *linuxFirewallManager) RateLimit(ctx context.Context, ip string, rate int, opts RateLimitOptions) error {
	proto := opts.Protocol
	if proto == "" {
		proto = "tcp"
	}
	return exec.CommandContext(ctx, "iptables", "-A", "INPUT",
		"-s", ip, "-p", proto, "-m", "limit", "--limit", fmt.Sprintf("%d/s", rate),
		"-j", "ACCEPT", "-m", "comment", "--comment", "serverguard-ratelimit").Run()
}

func (m *linuxFirewallManager) RemoveRateLimit(ctx context.Context, ip string) error {
	return exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", ip, "-m", "limit",
		"-j", "ACCEPT", "-m", "comment", "--comment", "serverguard-ratelimit").Run()
}

func (m *linuxFirewallManager) ClearAll(ctx context.Context) error {
	// 安全清除：只删除 ServerGuard 添加的规则（通过 comment 模块标记），
	// 不删除其他程序（如宝塔面板）添加的 iptables 规则。
	// 逐条查找并删除包含 "serverguard" 注释的规则。
	for {
		// 列出所有 INPUT 链规则及其行号
		out, err := exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n", "--line-numbers").Output()
		if err != nil {
			break
		}
		// 找到第一条包含 serverguard 注释的规则
		found := false
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, "serverguard") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			lineNum := fields[0]
			// 删除该行规则
			if err := exec.CommandContext(ctx, "iptables", "-D", "INPUT", lineNum).Run(); err == nil {
				found = true
				break // 重新列表，行号会变化
			}
		}
		if !found {
			break // 没有更多 serverguard 规则了
		}
	}
	return nil
}

// linuxNetworkManager 网络管理
type linuxNetworkManager struct{}

func newNetworkManager() NetworkManager { return &linuxNetworkManager{} }

func (m *linuxNetworkManager) ListInterfaces(ctx context.Context) ([]NetInterface, error) {
	return []NetInterface{}, nil
}

func (m *linuxNetworkManager) RestartNetworking(ctx context.Context) error {
	return exec.CommandContext(ctx, "systemctl", "restart", "NetworkManager").Run()
}

func (m *linuxNetworkManager) SetDNS(ctx context.Context, servers []string) error {
	content := ""
	for _, s := range servers {
		content += fmt.Sprintf("nameserver %s\n", s)
	}
	return os.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

func (m *linuxNetworkManager) GetDNS(ctx context.Context) ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return servers, nil
}

func (m *linuxNetworkManager) Ping(ctx context.Context, host string, timeout time.Duration) (bool, time.Duration, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(int(timeout.Seconds())), host)
	err := cmd.Run()
	elapsed := time.Since(start)
	return err == nil, elapsed, nil
}

func (m *linuxNetworkManager) TraceRoute(ctx context.Context, host string, maxHops int) ([]string, error) {
	out, err := exec.CommandContext(ctx, "traceroute", "-m", strconv.Itoa(maxHops), host).Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func (m *linuxNetworkManager) ListeningPorts(ctx context.Context) ([]PortInfo, error) {
	out, err := exec.CommandContext(ctx, "ss", "-tlnp").Output()
	if err != nil {
		return nil, err
	}
	var ports []PortInfo
	for _, line := range strings.Split(string(out), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addrParts := strings.Split(fields[3], ":")
		if len(addrParts) < 2 {
			continue
		}
		port, _ := strconv.Atoi(addrParts[len(addrParts)-1])
		ports = append(ports, PortInfo{
			Port:      int32(port),
			Protocol:  "tcp",
			LocalAddr: fields[3],
			State:     "LISTEN",
		})
	}
	return ports, nil
}

// linuxFileWatcher inotify 文件监控
type linuxFileWatcher struct {
	mu      sync.Mutex
	watched map[string]chan FileEvent
}

func newFileWatcher() FileWatcher {
	return &linuxFileWatcher{watched: make(map[string]chan FileEvent)}
}

func (w *linuxFileWatcher) Watch(ctx context.Context, path string, recursive bool) (<-chan FileEvent, error) {
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
					if os.IsNotExist(err) {
						ch <- FileEvent{Path: path, Operation: "delete", Timestamp: time.Now()}
					}
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

func (w *linuxFileWatcher) Unwatch(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ch, exists := w.watched[path]; exists {
		close(ch)
		delete(w.watched, path)
	}
	return nil
}

func (w *linuxFileWatcher) ListWatched() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]string, 0, len(w.watched))
	for k := range w.watched {
		result = append(result, k)
	}
	return result
}

func (w *linuxFileWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for path, ch := range w.watched {
		close(ch)
		delete(w.watched, path)
	}
	return nil
}

// 辅助函数
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func truncateFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	return f.Close()
}

func recreateFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	return f.Close()
}

func compressFile(path string) error {
	// 超时兜底：大日志 gzip 可能耗时数分钟，但绝不能无限挂起占用 IO 与 goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gzip", "-f", path)
	return cmd.Run()
}

// newPlatformDepsImpl 创建 Linux 平台依赖
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
