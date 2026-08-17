package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/executor"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ServiceGuard implements Module B: Service Guard
// Covers: process keepalive, port keepalive, dependency chain,
// health check, port conflict resolution, service start dependency repair
type ServiceGuard struct {
	mu             sync.RWMutex
	eventBus       *eventbus.EventBus
	storage        *storage.Storage
	targets        []types.GuardTarget
	restartTracker map[string]*RestartTracker // target ID -> tracker
	dependencies   map[string][]string        // target ID -> depends on IDs

	// 安全管理器引用，用于宝塔安全模式判断
	safetyMgr    *safety.SafetyManager
	restartGuard *safety.RestartGuard

	// 依赖链管理器：上游宕机时隔离下游，上游恢复后按拓扑序逐个拉起
	depGraph    *DependencyGraph
	depChainMgr *DependencyChainManager
}

// RestartTracker tracks restart attempts and backoff.
type RestartTracker struct {
	mu             sync.Mutex
	attempts       int
	lastRestart    time.Time
	backoffCurrent time.Duration
	cooldown       time.Duration
}

// New creates a new ServiceGuard.
func New(bus *eventbus.EventBus, store *storage.Storage) *ServiceGuard {
	depGraph := NewDependencyGraph()
	return &ServiceGuard{
		eventBus:       bus,
		storage:        store,
		restartTracker: make(map[string]*RestartTracker),
		dependencies:   make(map[string][]string),
		restartGuard:   safety.NewRestartGuard(),
		depGraph:       depGraph,
		depChainMgr:    NewDependencyChainManager(depGraph),
	}
}

// SetSafetyManager 注入安全管理器，用于宝塔安全模式判断。
// 必须在 Check 调用前设置。
func (g *ServiceGuard) SetSafetyManager(sm *safety.SafetyManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.safetyMgr = sm
}

// AddTarget adds a process/service to be guarded.
// 同时保存到数据库，使 API 和前端能看到自动检测到的守护目标。
func (g *ServiceGuard) AddTarget(target types.GuardTarget) {
	g.mu.Lock()
	g.targets = append(g.targets, target)
	g.restartTracker[target.ID] = &RestartTracker{
		backoffCurrent: target.RestartPolicy.BackoffInitial,
		cooldown:       target.RestartPolicy.Cooldown,
	}
	if len(target.DependsOn) > 0 {
		g.dependencies[target.ID] = target.DependsOn
		for _, dep := range target.DependsOn {
			g.depGraph.AddDependency(target.ID, dep)
		}
	}
	store := g.storage
	g.mu.Unlock()
	// 保存到数据库，使前端 API 能返回
	if store != nil {
		store.SaveGuardTarget(target)
	}
}

// LoadTargets loads guard targets from storage.
func (g *ServiceGuard) LoadTargets() error {
	targets, err := g.storage.GetGuardTargets()
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.targets = targets
	for _, t := range targets {
		g.restartTracker[t.ID] = &RestartTracker{
			backoffCurrent: t.RestartPolicy.BackoffInitial,
			cooldown:       t.RestartPolicy.Cooldown,
		}
	}
	return nil
}

// Check checks all guarded services and restarts if needed.
// 被依赖链管理器隔离的服务跳过检查（上游宕机时下游误判）。
func (g *ServiceGuard) Check(ctx context.Context) {
	g.mu.RLock()
	targets := g.targets
	depMgr := g.depChainMgr
	g.mu.RUnlock()

	var wg sync.WaitGroup

	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		// 跳过被隔离的服务
		if depMgr != nil && depMgr.IsIsolated(target.ID) {
			continue
		}
		wg.Add(1)
		go func(t types.GuardTarget) {
			defer wg.Done()
			g.checkTarget(ctx, t)
		}(target)
	}

	wg.Wait()
}

// checkTarget checks a single guard target and restarts if down.
// 服务宕机时隔离下游依赖；服务恢复后按拓扑序逐个拉起下游。
func (g *ServiceGuard) checkTarget(ctx context.Context, target types.GuardTarget) {
	alive := g.isAlive(ctx, target)

	if !alive {
		// 隔离下游服务，避免误判
		g.mu.RLock()
		depMgr := g.depChainMgr
		g.mu.RUnlock()
		if depMgr != nil {
			isolated := depMgr.IsolateDownstream(target.ID)
			if len(isolated) > 0 {
				g.eventBus.PublishAlert(types.AlertWarning, "service",
					fmt.Sprintf("依赖链隔离: %s", target.Name),
					fmt.Sprintf("上游服务 %s 宕机，已隔离 %d 个下游服务", target.Name, len(isolated)),
					"dep-chain-isolate-001")
			}
		}

		tracker := g.getTracker(target.ID)
		if tracker == nil {
			return
		}

		tracker.mu.Lock()
		defer tracker.mu.Unlock()

		// Check cooldown
		if !tracker.lastRestart.IsZero() && time.Since(tracker.lastRestart) < tracker.cooldown {
			return
		}

		// Check max retries
		if tracker.attempts >= target.RestartPolicy.MaxRetries {
			g.eventBus.PublishAlert(types.AlertCritical, "service",
				fmt.Sprintf("守护失败: %s", target.Name),
				fmt.Sprintf("服务 %s 在指数退避后仍无法恢复（最大重试 %d 次）",
					target.Name, target.RestartPolicy.MaxRetries),
				"process-down-001")
			return
		}

		// Calculate backoff
		backoff := tracker.backoffCurrent
		if tracker.attempts > 0 {
			backoff = time.Duration(float64(tracker.backoffCurrent) * target.RestartPolicy.BackoffMultiplier)
			if backoff > target.RestartPolicy.BackoffMax {
				backoff = target.RestartPolicy.BackoffMax
			}
		}

		// Check dependencies before restarting
		if !g.checkDependencies(ctx, target.ID) {
			g.eventBus.PublishAlert(types.AlertWarning, "service",
				fmt.Sprintf("依赖未满足: %s", target.Name),
				fmt.Sprintf("服务 %s 的上游依赖未就绪，等待依赖恢复后重启", target.Name),
				"dependency-001")
			return
		}

		// B7: Port conflict check before restart
		if target.Port > 0 {
			if g.isPortOccupied(target.Port, target.ProcessName) {
				g.eventBus.PublishAlert(types.AlertWarning, "service",
					fmt.Sprintf("端口冲突: %s:%d", target.Name, target.Port),
					fmt.Sprintf("端口 %d 已被占用，尝试清理残留进程", target.Port),
					"port-conflict-001")
				g.resolvePortConflict(ctx, target.Port, target.ProcessName)
			}
		}

		// Restart with backoff
		time.Sleep(backoff)
		g.restartTarget(ctx, target)

		tracker.attempts++
		tracker.lastRestart = time.Now()
		tracker.backoffCurrent = backoff
	} else {
		// Service is alive, reset attempt counter
		tracker := g.getTracker(target.ID)
		if tracker != nil {
			tracker.mu.Lock()
			tracker.attempts = 0
			tracker.backoffCurrent = target.RestartPolicy.BackoffInitial
			tracker.mu.Unlock()
		}

		// 上游恢复后按拓扑序逐个拉起被隔离的下游服务
		g.mu.RLock()
		depMgr := g.depChainMgr
		g.mu.RUnlock()
		if depMgr != nil && len(depMgr.GetIsolatedServices()) > 0 {
			// 只在有该服务的被隔离下游时才尝试恢复
			affected := g.depGraph.GetAffectedServices(target.ID)
			if len(affected) > 0 {
				succeeded, failed := depMgr.RestoreInOrder(ctx, target.ID,
					func(svc string) error {
						return g.startService(svc)
					},
					func(ctx context.Context, svc string) bool {
						return g.checkServiceHealth(ctx, svc)
					},
				)
				if len(succeeded) > 0 || len(failed) > 0 {
					g.eventBus.PublishAlert(types.AlertInfo, "service",
						fmt.Sprintf("依赖链恢复: %s", target.Name),
						fmt.Sprintf("上游 %s 恢复，拉起下游：成功 %d 个，失败 %d 个",
							target.Name, len(succeeded), len(failed)),
						"dep-chain-restore-001")
				}
			}
		}
	}
}

// isAlive checks if a target is alive.
func (g *ServiceGuard) isAlive(ctx context.Context, target types.GuardTarget) bool {
	switch target.Type {
	case types.TargetSystemd:
		return g.checkSystemdService(target.Name)
	case types.TargetBare:
		return g.checkProcessAlive(target.ProcessName)
	case types.TargetPort, types.TargetHTTP:
		return g.checkPortAlive(ctx, target.Port, target.HealthCheck)
	case types.TargetDocker:
		return g.checkDockerContainer(target.Name)
	default:
		return g.checkProcessAlive(target.ProcessName)
	}
}

// startService 根据服务 ID 查找目标并启动。
func (g *ServiceGuard) startService(serviceID string) error {
	g.mu.RLock()
	var target *types.GuardTarget
	for i := range g.targets {
		if g.targets[i].ID == serviceID {
			target = &g.targets[i]
			break
		}
	}
	g.mu.RUnlock()
	if target == nil {
		return fmt.Errorf("service %s not found", serviceID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	g.restartTarget(ctx, *target)
	return nil
}

// checkServiceHealth 根据服务 ID 查找目标并检查健康状态。
func (g *ServiceGuard) checkServiceHealth(ctx context.Context, serviceID string) bool {
	g.mu.RLock()
	var target *types.GuardTarget
	for i := range g.targets {
		if g.targets[i].ID == serviceID {
			target = &g.targets[i]
			break
		}
	}
	g.mu.RUnlock()
	if target == nil {
		return false
	}
	return g.isAlive(ctx, *target)
}

// GetDependencyChainManager 返回依赖链管理器（供 API 层查询隔离状态）。
func (g *ServiceGuard) GetDependencyChainManager() *DependencyChainManager {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.depChainMgr
}

// checkSystemdService checks if a systemd service is running.
func (g *ServiceGuard) checkSystemdService(name string) bool {
	if runtime.GOOS == "windows" {
		// Windows: use sc query
		cmd := exec.Command("sc", "query", name)
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(output), "RUNNING")
	}
	cmd := exec.Command("systemctl", "is-active", name)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "active"
}

// checkProcessAlive checks if a process is running by name.
// 宝塔安全模式下：跳过 process.Processes() 调用（I/O 开销大），
// 使用 pgrep 轻量级命令替代，或直接返回 true（避免误判触发重启）。
func (g *ServiceGuard) checkProcessAlive(name string) bool {
	if name == "" {
		return true
	}

	// 宝塔安全模式下：使用 pgrep 轻量级命令替代 process.Processes()
	baotaSafeMode := false
	if g.safetyMgr != nil {
		baotaSafeMode = g.safetyMgr.IsBaotaSafeMode()
	}
	if baotaSafeMode {
		// pgrep 只做一次 /proc 扫描，比 process.Processes() 轻量得多
		if runtime.GOOS != "windows" {
			cmd := exec.Command("pgrep", "-x", name)
			if err := cmd.Run(); err == nil {
				return true // 进程存在
			}
		}
		// Windows 或 pgrep 不可用时，假设进程存在（避免误判触发重启）
		return true
	}

	procs, err := process.Processes()
	if err != nil {
		return false
	}
	for _, p := range procs {
		if pname, err := p.Name(); err == nil && pname == name {
			return true
		}
	}
	return false
}

// checkPortAlive checks if a port is listening or HTTP endpoint is reachable.
func (g *ServiceGuard) checkPortAlive(ctx context.Context, port int, healthCheck string) bool {
	if port == 0 {
		return true
	}

	if healthCheck != "" {
		// HTTP health check
		return g.checkHTTPHealth(ctx, healthCheck)
	}

	// TCP port check
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkHTTPHealth performs an HTTP health check.
func (g *ServiceGuard) checkHTTPHealth(ctx context.Context, url string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// checkDockerContainer checks if a Docker container is running.
func (g *ServiceGuard) checkDockerContainer(name string) bool {
	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", name)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return string(output) == "true\n" || string(output) == "true"
}

// checkDependencies checks if all dependencies of a target are healthy.
func (g *ServiceGuard) checkDependencies(ctx context.Context, targetID string) bool {
	deps, ok := g.dependencies[targetID]
	if !ok || len(deps) == 0 {
		return true
	}

	g.mu.RLock()
	targets := g.targets
	g.mu.RUnlock()

	for _, depID := range deps {
		for _, t := range targets {
			if t.ID == depID && t.Enabled {
				if !g.isAlive(ctx, t) {
					return false
				}
			}
		}
	}
	return true
}

// isPortOccupied checks if a port is in use.
func (g *ServiceGuard) isPortOccupied(port int, processName string) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return false // port not in use
	}
	conn.Close()
	return true
}

// resolvePortConflict attempts to free a port occupied by a zombie/stale process.
// SAFETY: Only kills zombie/stale processes. Never kills whitelisted processes
// (nginx, mysql, etc.) even if they occupy the port — alerts instead.
// 精确归属识别：对 python/python3 等通用进程名，通过 /proc 信息二次确认
// 是否为宝塔保护进程。该保护无条件生效，不依赖模式开关。
func (g *ServiceGuard) resolvePortConflict(ctx context.Context, port int, expectedProcess string) {
	procs, err := process.Processes()
	if err != nil {
		return
	}

	for _, p := range procs {
		name, _ := p.Name()
		if name != expectedProcess && name != "" {
			// Check connections
			conns, err := p.Connections()
			if err != nil {
				continue
			}
			for _, conn := range conns {
				if conn.Laddr.Port == uint32(port) && conn.Status == "LISTEN" {
					// Never kill whitelisted processes
					if isServiceWhitelisted(name) {
						g.eventBus.PublishAlert(types.AlertWarning, "service",
							fmt.Sprintf("端口被占用: %d", port),
							fmt.Sprintf("端口 %d 被关键进程 %s (PID %d) 占用，不自动终止，需人工处理",
								port, name, p.Pid),
							"port-conflict-001")
						return
					}
					// 深度检查：读取 /proc 信息，匹配宝塔白名单
					// 确保 python/python3 运行的宝塔面板进程不会被误杀
					if procInfo := safety.ReadProcInfo(p.Pid); procInfo != nil {
						if safety.IsBaotaProtectedProcess(procInfo) {
							g.eventBus.PublishAlert(types.AlertWarning, "service",
								fmt.Sprintf("端口被占用: %d (宝塔保护进程)", port),
								fmt.Sprintf("端口 %d 被宝塔保护进程 %s (PID %d, comm=%s, cmdline=%s) 占用，不自动终止",
									port, name, p.Pid, procInfo.Comm, procInfo.Cmdline),
								"port-conflict-001")
							return
						}
					}
					// Only kill zombie/stale processes
					if !g.isZombieOrStale(p) {
						g.eventBus.PublishAlert(types.AlertWarning, "service",
							fmt.Sprintf("端口被占用: %d", port),
							fmt.Sprintf("端口 %d 被进程 %s (PID %d) 占用，非僵尸进程，需人工处理",
								port, name, p.Pid),
							"port-conflict-001")
						return
					}
					// Kill zombie process（已通过上方的白名单与宝塔归属双重检查）
					p.Kill()
					g.eventBus.PublishAlert(types.AlertInfo, "service",
						fmt.Sprintf("端口已释放: %d", port),
						fmt.Sprintf("已清理占用端口 %d 的残留进程 %s (PID %d)",
							port, name, p.Pid),
						"port-conflict-001")
				}
			}
		}
	}
}

// isServiceWhitelisted checks if a process is a critical service that should never be killed.
// 合并宝塔生态全量白名单，确保宝塔管理的服务永不被 Kill。
func isServiceWhitelisted(name string) bool {
	// 先检查宝塔全量白名单
	wl := safety.GetBaotaWhitelistSetPublic()
	if wl[strings.ToLower(name)] {
		return true
	}

	// 保留原有补充项
	whitelist := map[string]bool{
		"nginx": true, "nginx.exe": true, "httpd": true, "apache2": true, "caddy": true,
		"mysqld": true, "mariadbd": true, "postgres": true, "redis-server": true, "mongod": true,
		"php-fpm": true, "php-cgi": true, "php": true,
		"php-fpm-74": true, "php-fpm-80": true, "php-fpm-81": true, "php-fpm-82": true, "php-fpm-83": true,
		"bt-panel": true, "bt": true, "btpanel": true, "panelSite.py": true,
		"sshd": true, "systemd": true, "init": true,
		"pure-ftpd": true, "proftpd": true, "vsftpd": true,
		"named": true, "bind9": true, "postfix": true, "dovecot": true, "sendmail": true,
		"serverguard-agent": true, "serverguard-agent.exe": true,
		// Windows
		"System": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
		"services.exe": true, "lsass.exe": true, "svchost.exe": true, "winlogon.exe": true,
		"w3svc": true, "iisexpress.exe": true, "sqlservr.exe": true,
		"mysqld.exe": true, "postgres.exe": true, "redis-server.exe": true,
		"php-cgi.exe": true, "php.exe": true, "httpd.exe": true,
	}
	return whitelist[name]
}

// isZombieOrStale checks if a process is a zombie or stale.
func (g *ServiceGuard) isZombieOrStale(p *process.Process) bool {
	status, err := p.Status()
	if err != nil || len(status) == 0 {
		return false
	}
	return status[0] == "Z" || status[0] == "z"
}

// restartTarget restarts a target service/process.
// 安全加固：
//   - 宝塔安全模式下，宝塔管理的服务使用 /etc/init.d/ 脚本重启，禁止 systemctl
//   - 宝塔面板自身（bt-panel）绝对禁止自动重启，只告警
//   - 重启前调用 BeforeAutoRestart 检查重启风暴和启动状态
func (g *ServiceGuard) restartTarget(ctx context.Context, target types.GuardTarget) {
	attemptNum := 0
	tracker := g.getTracker(target.ID)
	if tracker != nil {
		attemptNum = tracker.attempts + 1
	}

	// 宝塔安全模式下的前置检查
	baotaSafeMode := false
	if g.safetyMgr != nil {
		baotaSafeMode = g.safetyMgr.IsBaotaSafeMode()
	}

	if g.restartGuard != nil {
		err, suggestedCmd := g.restartGuard.BeforeAutoRestart(target.Name, baotaSafeMode)
		if err != nil {
			// 放弃期/风暴拒绝：说明反复重启无效，升级为 Critical 并附自动诊断
			if _, giveUp := g.restartGuard.IsGiveUp(target.Name); giveUp {
				g.eventBus.PublishAlert(types.AlertCritical, "service",
					fmt.Sprintf("服务反复重启未恢复，已暂停自动修复: %s", target.Name),
					fmt.Sprintf("服务 %s 多次重启仍未恢复，判定重启无效（可能原因：端口冲突/配置错误/依赖缺失）。%v",
						target.Name, err)+executor.DiagnoseServiceFailure(target.Name, target.Port),
					"restart-giveup-"+target.Name)
			} else {
				g.eventBus.PublishAlert(types.AlertWarning, "service",
					fmt.Sprintf("重启被安全检查阻止: %s", target.Name),
					fmt.Sprintf("服务 %s 自动重启被安全检查阻止: %v", target.Name, err),
					"restart-guard-001")
			}
			return
		}

		// 如果安全检查建议使用特定命令（宝塔环境 /etc/init.d/ 脚本）
		if suggestedCmd != "" {
			cmd := exec.CommandContext(ctx, "sh", "-c", suggestedCmd)
			if err := cmd.Run(); err != nil {
				g.eventBus.PublishAlert(types.AlertError, "service",
					fmt.Sprintf("重启失败: %s", target.Name),
					fmt.Sprintf("%s 失败: %v", suggestedCmd, err),
					"process-down-001")
				return
			}
			g.eventBus.PublishAlert(types.AlertInfo, "service",
				fmt.Sprintf("已重启: %s", target.Name),
				fmt.Sprintf("服务 %s 已通过宝塔脚本重启（第 %d 次）: %s", target.Name, attemptNum, suggestedCmd),
				"process-down-001")
			return
		}
	}

	// 宝塔安全模式下，宝塔管理的服务禁止使用 systemctl，降级为告警
	if baotaSafeMode && safety.BaotaManagedServices[strings.ToLower(target.Name)] {
		g.eventBus.PublishAlert(types.AlertWarning, "service",
			fmt.Sprintf("[安全保护模式] 重启降级为告警: %s", target.Name),
			fmt.Sprintf("服务 %s 在安全保护模式下不自动重启，请通过宝塔面板手动管理。\n建议命令: /etc/init.d/%s restart",
				target.Name, target.Name),
			"restart-guard-001")
		return
	}

	switch target.Type {
	case types.TargetSystemd:
		// 智能预检：开机保护 + 配置语法检查（配置错误时重启 = 亲手制造宕机）
		if blockReason := safety.PreflightRestartCheck(target.Name); blockReason != "" {
			g.eventBus.PublishAlert(types.AlertCritical, "guardian",
				fmt.Sprintf("已阻止一次高风险重启：%s", target.Name),
				fmt.Sprintf("服务 %s 触发自动重启，但重启前安全检查未通过：\n%s\n\n服务当前保持原状（未重启）。", target.Name, blockReason),
				"preflight-"+target.Name)
			return
		}

		// 优雅重启：支持平滑重载的服务优先 reload（不断开现有连接）
		if handled, _ := safety.TryGracefulReload(ctx, target.Name); handled {
			g.eventBus.PublishAlert(types.AlertInfo, "service",
				fmt.Sprintf("已平滑重载: %s", target.Name),
				fmt.Sprintf("服务 %s 检测到异常，已通过 reload 平滑恢复（第 %d 次），未中断现有连接", target.Name, attemptNum),
				"process-down-001")
			return
		}

		if runtime.GOOS == "windows" {
			// Windows: use net start
			cmd := exec.CommandContext(ctx, "net", "start", target.Name)
			if err := cmd.Run(); err != nil {
				g.eventBus.PublishAlert(types.AlertError, "service",
					fmt.Sprintf("重启失败: %s", target.Name),
					fmt.Sprintf("net start %s 失败: %v", target.Name, err),
					"process-down-001")
				return
			}
		} else {
			cmd := exec.CommandContext(ctx, "systemctl", "restart", target.Name)
			if err := cmd.Run(); err != nil {
				g.eventBus.PublishAlert(types.AlertError, "service",
					fmt.Sprintf("重启失败: %s", target.Name),
					fmt.Sprintf("systemctl restart %s 失败: %v", target.Name, err),
					"process-down-001")
				return
			}
		}
	case types.TargetBare:
		if target.Command != "" {
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.CommandContext(ctx, "cmd", "/c", target.Command)
			} else {
				cmd = exec.CommandContext(ctx, "sh", "-c", target.Command)
			}
			if err := cmd.Start(); err != nil {
				g.eventBus.PublishAlert(types.AlertError, "service",
					fmt.Sprintf("重启失败: %s", target.Name),
					fmt.Sprintf("启动命令 %s 失败: %v", target.Command, err),
					"process-down-001")
				return
			}
		}
	case types.TargetDocker:
		cmd := exec.CommandContext(ctx, "docker", "restart", target.Name)
		if err := cmd.Run(); err != nil {
			g.eventBus.PublishAlert(types.AlertError, "service",
				fmt.Sprintf("重启失败: %s", target.Name),
				fmt.Sprintf("docker restart %s 失败: %v", target.Name, err),
				"process-down-001")
			return
		}
	}

	g.eventBus.PublishAlert(types.AlertInfo, "service",
		fmt.Sprintf("已重启: %s", target.Name),
		fmt.Sprintf("服务 %s 已自动重启（第 %d 次）", target.Name, attemptNum),
		"process-down-001")
}

// GetTargets returns all guard targets.
func (g *ServiceGuard) GetTargets() []types.GuardTarget {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.targets
}

// AutoDetectTargets detects common services running on the system and adds them
// as guard targets. This makes ServerGuard smart enough to guard nginx, MySQL,
// Redis, etc. without the user manually adding each one.
// Only adds targets that don't already exist.
// 宝塔安全模式下，跳过 process.Processes() 调用（I/O 开销大），
// 改用轻量级的 TCP 端口探测来检测服务是否在运行。
func (g *ServiceGuard) AutoDetectTargets() int {
	added := 0

	// 宝塔安全模式下，使用轻量级端口探测替代 process.Processes()
	baotaSafeMode := false
	if g.safetyMgr != nil {
		baotaSafeMode = g.safetyMgr.IsBaotaSafeMode()
	}

	// Common services to auto-detect: name -> {processName, command, port, type}
	var commonServices []types.GuardTarget

	if runtime.GOOS == "windows" {
		commonServices = []types.GuardTarget{
			{Name: "IIS Web", Type: types.TargetWinSvc, ProcessName: "w3svc", Command: "iisreset /start", Port: 80, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "MySQL", Type: types.TargetWinSvc, ProcessName: "mysql", Command: "net start mysql", Port: 3306, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "Redis", Type: types.TargetBare, ProcessName: "redis-server.exe", Command: "redis-server.exe", Port: 6379, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "Nginx", Type: types.TargetBare, ProcessName: "nginx.exe", Command: "nginx.exe", Port: 80, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "PostgreSQL", Type: types.TargetWinSvc, ProcessName: "postgresql-x64-14", Command: "net start postgresql-x64-14", Port: 5432, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
		}
	} else {
		commonServices = []types.GuardTarget{
			{Name: "Nginx", Type: types.TargetBare, ProcessName: "nginx", Command: "nginx", Port: 80, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "Apache", Type: types.TargetBare, ProcessName: "httpd", Command: "httpd", Port: 80, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "Apache2", Type: types.TargetBare, ProcessName: "apache2", Command: "apache2", Port: 80, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "MySQL", Type: types.TargetBare, ProcessName: "mysqld", Command: "mysqld", Port: 3306, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "MariaDB", Type: types.TargetBare, ProcessName: "mariadbd", Command: "mariadbd", Port: 3306, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "Redis", Type: types.TargetBare, ProcessName: "redis-server", Command: "redis-server", Port: 6379, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "PostgreSQL", Type: types.TargetBare, ProcessName: "postgres", Command: "postgres", Port: 5432, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "MongoDB", Type: types.TargetBare, ProcessName: "mongod", Command: "mongod", Port: 27017, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "PHP-FPM", Type: types.TargetBare, ProcessName: "php-fpm", Command: "php-fpm", Port: 9000, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "SSH", Type: types.TargetBare, ProcessName: "sshd", Command: "/usr/sbin/sshd", Port: 22, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "BaoTa Panel", Type: types.TargetBare, ProcessName: "bt-panel", Command: "/etc/init.d/bt start", Port: 8888, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "Pure-FTPd", Type: types.TargetBare, ProcessName: "pure-ftpd", Command: "pure-ftpd", Port: 21, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
			{Name: "vsftpd", Type: types.TargetBare, ProcessName: "vsftpd", Command: "vsftpd", Port: 21, Enabled: true, RestartPolicy: types.DefaultRestartPolicy()},
		}
	}

	// Get existing target names to avoid duplicates
	g.mu.RLock()
	existing := make(map[string]bool)
	for _, t := range g.targets {
		existing[t.Name] = true
	}
	g.mu.RUnlock()

	if baotaSafeMode {
		// 宝塔模式：使用轻量级 TCP 端口探测替代 process.Processes()
		for _, svc := range commonServices {
			if existing[svc.Name] {
				continue
			}
			// 通过 TCP 连接检测端口是否在监听
			if svc.Port > 0 {
				addr := fmt.Sprintf("127.0.0.1:%d", svc.Port)
				conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
				if err != nil {
					continue // 端口未监听，服务未运行
				}
				conn.Close()
			}

			svc.ID = fmt.Sprintf("auto-%s", strings.ToLower(svc.Name))
			svc.Tags = []string{"auto-detected", "baota-safe"}
			g.AddTarget(svc)
			added++

			g.eventBus.PublishAlert(types.AlertInfo, "service",
				fmt.Sprintf("自动守护(宝塔模式): %s", svc.Name),
				fmt.Sprintf("检测到 %s 端口 %d 在监听，已自动添加到守护列表",
					svc.Name, svc.Port),
				"auto-detect-001")
		}
		return added
	}

	// 非宝塔模式：使用 process.Processes() 检测
	procs, err := process.Processes()
	if err != nil {
		return 0
	}
	runningProcs := make(map[string]bool)
	for _, p := range procs {
		if name, err := p.Name(); err == nil && name != "" {
			runningProcs[name] = true
		}
	}

	// Add detected services
	for _, svc := range commonServices {
		if existing[svc.Name] {
			continue // Already guarded
		}
		// Check if the process is running
		if !runningProcs[svc.ProcessName] {
			continue // Not running, don't guard
		}

		// Generate ID
		svc.ID = fmt.Sprintf("auto-%s", strings.ToLower(svc.Name))
		svc.Tags = []string{"auto-detected"}

		g.AddTarget(svc)
		added++

		g.eventBus.PublishAlert(types.AlertInfo, "service",
			fmt.Sprintf("自动守护: %s", svc.Name),
			fmt.Sprintf("检测到 %s 正在运行，已自动添加到守护列表（进程: %s, 端口: %d）",
				svc.Name, svc.ProcessName, svc.Port),
			"auto-detect-001")
	}

	return added
}

// getTracker returns the restart tracker for a target.
func (g *ServiceGuard) getTracker(id string) *RestartTracker {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.restartTracker[id]
}
