package safety

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// BaotaManagedServices 宝塔管理的服务列表。
// 这些服务在宝塔环境下禁止使用 systemctl restart，
// 必须优先使用 /etc/init.d/{service} restart 或 bt restart。
var BaotaManagedServices = map[string]bool{
	"nginx":      true,
	"httpd":      true,
	"apache2":    true,
	"mysqld":     true,
	"mariadbd":   true,
	"mariadb":    true,
	"redis":      true,
	"redis-server": true,
	"php-fpm":    true,
	"php-fpm-52": true,
	"php-fpm-53": true,
	"php-fpm-54": true,
	"php-fpm-55": true,
	"php-fpm-56": true,
	"php-fpm-70": true,
	"php-fpm-71": true,
	"php-fpm-72": true,
	"php-fpm-73": true,
	"php-fpm-74": true,
	"php-fpm-80": true,
	"php-fpm-81": true,
	"php-fpm-82": true,
	"php-fpm-83": true,
	"pure-ftpd":  true,
	"vsftpd":     true,
	"memcached":  true,
	"mongodb":    true,
	"mongod":     true,
	"tomcat":     true,
}

// BaotaPanelServiceNames 宝塔面板自身的服务名。
// 服务守护路径（systemctl/init.d 通用重启）禁止自动重启面板自身；
// 面板进程失控时的止损由 PanelReliefController 专用通道负责（内存危急才触发）。
var BaotaPanelServiceNames = map[string]bool{
	"bt":         true,
	"bt-panel":   true,
	"btpanel":    true,
	"BT-Panel":   true,
	"Bt-Panel":   true,
	"bt_panel":   true,
}

// RestartGuard 自动服务守护的安全检查器。
// 防止重启风暴（Restart Storm）、避免与宝塔进程管理冲突、保护面板自身。
type RestartGuard struct {
	mu             sync.Mutex
	restartHistory map[string][]time.Time // serviceName -> 最近重启时间列表
	stormWindow    time.Duration          // 重启风暴检测窗口（60 秒）
	stormMaxInWin  int                    // 窗口内最大重启次数
	giveUpUntil    map[string]time.Time   // serviceName -> 放弃自动重启的截止时间
	giveUpFor      time.Duration          // 风暴触发后的放弃时长
}

// NewRestartGuard 创建一个新的 RestartGuard。
func NewRestartGuard() *RestartGuard {
	return &RestartGuard{
		restartHistory: make(map[string][]time.Time),
		stormWindow:    60 * time.Second,
		stormMaxInWin:  3,
		giveUpUntil:    make(map[string]time.Time),
		giveUpFor:      30 * time.Minute,
	}
}

// BeforeAutoRestart 自动重启前的安全检查。
// 检查项：
//  1. 如果是宝塔面板自身（bt-panel），绝对禁止自动重启，只告警
//  2. 检查该服务 60 秒内是否已经被重启过，防止重启风暴（Restart Storm）
//  3. 检查服务进程是否正在启动中（StartPending），避免重复启动
//  4. 宝塔环境下，服务重启前必须通过 /etc/init.d/xxx 脚本检查状态
//  5. 如果是宝塔管理的服务，返回建议使用 /etc/init.d/{service} restart
//
// 参数：
//   - serviceName: 服务名（如 "nginx", "mysqld", "bt-panel"）
//   - baotaSafeMode: 是否处于宝塔安全模式
//
// 返回：
//   - error: 非 nil 表示禁止重启，error 信息为原因
//   - string: 建议的重启命令（如 "/etc/init.d/nginx restart"），空表示可用默认方式
func (rg *RestartGuard) BeforeAutoRestart(serviceName string, baotaSafeMode bool) (error, string) {
	// 1. 宝塔面板自身绝对禁止自动重启
	lowerName := strings.ToLower(serviceName)
	if BaotaPanelServiceNames[serviceName] || BaotaPanelServiceNames[lowerName] {
		return fmt.Errorf("宝塔面板服务 %s 绝对禁止自动重启，只告警不操作", serviceName), ""
	}

	// 2. 放弃期检查：此前已因重启风暴放弃，期间不再尝试
	if until, giveUp := rg.isGiveUp(serviceName); giveUp {
		return fmt.Errorf("服务 %s 此前反复重启未恢复，已暂停自动重启至 %s（请人工介入排查）",
			serviceName, until.Format("15:04:05")), ""
	}

	// 3. 检查重启风暴：触发即进入放弃期——反复重启解决不了问题，
	//    只会拖垮系统并掩盖真实故障（端口冲突/配置错误/依赖缺失）
	if rg.isRestartStorm(serviceName) {
		rg.enterGiveUp(serviceName)
		return fmt.Errorf("服务 %s 在 %v 内已重启 %d 次仍未恢复，判定重启无效，暂停自动重启 %v",
			serviceName, rg.stormWindow, rg.stormMaxInWin, rg.giveUpFor), ""
	}

	// 4. 检查服务是否正在启动中（StartPending）
	if rg.isStartPending(serviceName) {
		return fmt.Errorf("服务 %s 正在启动中（StartPending），避免重复启动", serviceName), ""
	}

	// 4 & 5. 宝塔环境下的服务管理
	suggestedCmd := ""
	if baotaSafeMode {
		// 宝塔环境下，宝塔管理的服务必须用 /etc/init.d/ 脚本
		if BaotaManagedServices[lowerName] || BaotaManagedServices[serviceName] {
			initScript := "/etc/init.d/" + serviceName
			if rg.initScriptExists(serviceName) {
				suggestedCmd = initScript + " restart"
			}
			// 即使脚本不存在也返回，调用方应检查
			// 禁止直接使用 systemctl restart
		}
	}

	// 记录本次重启
	rg.recordRestart(serviceName)

	return nil, suggestedCmd
}

// isGiveUp 检查服务是否处于放弃期。
func (rg *RestartGuard) isGiveUp(serviceName string) (time.Time, bool) {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	until, ok := rg.giveUpUntil[serviceName]
	if !ok {
		return time.Time{}, false
	}
	if time.Now().After(until) {
		delete(rg.giveUpUntil, serviceName)
		return time.Time{}, false
	}
	return until, true
}

// enterGiveUp 将服务标记进入放弃期（风暴触发时调用）。
func (rg *RestartGuard) enterGiveUp(serviceName string) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.giveUpUntil[serviceName] = time.Now().Add(rg.giveUpFor)
}

// IsGiveUp 导出放弃期查询（供调用方决定告警级别与诊断）。
func (rg *RestartGuard) IsGiveUp(serviceName string) (time.Time, bool) {
	return rg.isGiveUp(serviceName)
}

// isRestartStorm 检查指定服务在 stormWindow 内的重启次数是否超过阈值。
func (rg *RestartGuard) isRestartStorm(serviceName string) bool {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rg.stormWindow)
	history := rg.restartHistory[serviceName]

	// 过滤窗口内的记录
	var recent []time.Time
	for _, t := range history {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rg.restartHistory[serviceName] = recent

	return len(recent) >= rg.stormMaxInWin
}

// recordRestart 记录一次重启时间。
func (rg *RestartGuard) recordRestart(serviceName string) {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	rg.restartHistory[serviceName] = append(rg.restartHistory[serviceName], time.Now())

	// 清理过旧记录（保留最近 5 分钟）
	cutoff := time.Now().Add(-5 * time.Minute)
	var recent []time.Time
	for _, t := range rg.restartHistory[serviceName] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rg.restartHistory[serviceName] = recent
}

// isStartPending 检查服务是否正在启动中。
// 通过 systemctl is-active 检查 "activating" 状态。
func (rg *RestartGuard) isStartPending(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(output))
	// "activating" 表示服务正在启动中
	return state == "activating" || state == "activating (auto-restart)"
}

// initScriptExists 检查 /etc/init.d/{serviceName} 脚本是否存在且可执行。
func (rg *RestartGuard) initScriptExists(serviceName string) bool {
	path := "/etc/init.d/" + serviceName
	cmd := exec.Command("test", "-x", path)
	return cmd.Run() == nil
}

// GetRestartHistory 返回指定服务的重启历史（用于调试/展示）。
func (rg *RestartGuard) GetRestartHistory(serviceName string) []time.Time {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	history := rg.restartHistory[serviceName]
	result := make([]time.Time, len(history))
	copy(result, history)
	return result
}

// ClearRestartHistory 清除指定服务的重启历史记录。
func (rg *RestartGuard) ClearRestartHistory(serviceName string) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	delete(rg.restartHistory, serviceName)
}

// --- PanelReliefController 宝塔面板释压重启控制器 ---

// PanelReliefController 管理"面板失控 → 优雅重启释压"这一止损通道。
//
// 设计背景：宝塔面板进程（python 运行的 BT-Panel / bt-task 等）永不 Kill ——
// 直接 Kill 会导致面板硬崩、SQLite 写入中断。但若面板进程自身失控
// （如插件内存泄漏），坐视不管同样会把服务器拖垮。
// 唯一的正确止损手段是走宝塔原生通道 /etc/init.d/bt restart 优雅重启：
// 面板自行完成清理后退出并重新拉起，等价于运维人员的标准处置动作。
//
// 防滥用：
//   - 冷却期：两次释压重启之间的最小间隔（默认 30 分钟）
//   - 每日预算：每天最多自动释压重启次数（默认 2 次）
//   - 超限后只告警不操作 —— 反复失控说明存在结构性问题
//    （插件泄漏 / 版本 bug），重启已无意义，必须人工排查。
type PanelReliefController struct {
	mu          sync.Mutex
	lastAt      time.Time // 最近一次释压重启时间
	today       int       // 当日已执行次数
	dayStart    time.Time // 当日计数起点
	cooldown    time.Duration
	dailyBudget int
}

// NewPanelReliefController 创建面板释压重启控制器。
func NewPanelReliefController() *PanelReliefController {
	return &PanelReliefController{
		cooldown:    30 * time.Minute,
		dailyBudget: 2,
		dayStart:    time.Now(),
	}
}

// CanRelieve 检查当前是否允许执行一次面板释压重启。
// 返回 (原因, 是否允许)；不允许时原因可直接用于告警。
func (c *PanelReliefController) CanRelieve() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	// 跨天重置计数
	if now.Sub(c.dayStart) >= 24*time.Hour {
		c.today = 0
		c.dayStart = now
	}

	if !c.lastAt.IsZero() && now.Sub(c.lastAt) < c.cooldown {
		return fmt.Sprintf("距上次面板释压重启仅 %v（冷却期 %v）",
			now.Sub(c.lastAt).Round(time.Minute), c.cooldown), false
	}
	if c.today >= c.dailyBudget {
		return fmt.Sprintf("今日面板释压重启已达 %d 次上限，面板反复失控需人工排查（插件泄漏/版本 bug）",
			c.dailyBudget), false
	}
	return "", true
}

// RecordRelief 记录一次已执行的释压重启。
func (c *PanelReliefController) RecordRelief() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.Sub(c.dayStart) >= 24*time.Hour {
		c.today = 0
		c.dayStart = now
	}
	c.lastAt = now
	c.today++
}

// InReliefCooldown 返回最近 d 内是否执行过释压重启。
// 供面板宕机检测器使用：释压重启期间 pgrep 会短暂失败，属正常现象，不应误判为宕机。
func (c *PanelReliefController) InReliefCooldown(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.lastAt.IsZero() && time.Since(c.lastAt) < d
}

// RestartBaotaPanelForRelief 通过 /etc/init.d/bt restart 优雅重启宝塔面板。
// 仅用于面板进程失控的释压止损；返回完整命令输出。
func RestartBaotaPanelForRelief(ctx context.Context) (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("Windows 平台无 /etc/init.d/bt，不支持面板释压重启")
	}
	// 确认宝塔原生管理脚本存在且可执行
	if err := exec.CommandContext(ctx, "test", "-x", "/etc/init.d/bt").Run(); err != nil {
		return "", fmt.Errorf("/etc/init.d/bt 不存在或不可执行，无法优雅重启面板: %w", err)
	}
	cmd := exec.CommandContext(ctx, "/etc/init.d/bt", "restart")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("/etc/init.d/bt restart 执行失败: %w", err)
	}
	return string(output), nil
}
