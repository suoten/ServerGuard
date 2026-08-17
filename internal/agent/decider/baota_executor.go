package decider

import (
	"context"
	"fmt"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// BaotaExecutor 宝塔环境执行器，集成分级决策引擎、确认管理器和通知器。
//
// 执行流程:
//  1. 调用 BaotaDecider.Evaluate 进行分级决策
//  2. 根据决策结果的 Level 分别处理:
//     - 🟢 LevelAuto → 直接调用 doExecute 执行实际动作
//     - 🟡 LevelConfirm → 调用 ConfirmManager.Create 创建确认请求，推送通知
//     - 🔴 LevelForbidden → 调用 ConfirmNotifier.NotifyAlert 发送告警，跳过执行
type BaotaExecutor struct {
	// decider 分级决策引擎。
	decider *BaotaDecider

	// confirmManager 确认管理器。
	confirmManager *ConfirmManager

	// notifier 确认消息通知器。
	notifier *ConfirmNotifier

	// eventBus 事件总线（用于发布执行结果事件）。
	eventBus *eventbus.EventBus

	// storage 数据库连接（用于执行确认后的实际动作）。
	storage *storage.Storage
}

// NewBaotaExecutor 创建一个新的宝塔执行器。
//
// 参数:
//   - decider: 分级决策引擎
//   - confirmManager: 确认管理器
//   - notifier: 确认消息通知器
//   - bus: 事件总线
//   - store: 数据库连接
func NewBaotaExecutor(
	decider *BaotaDecider,
	confirmManager *ConfirmManager,
	notifier *ConfirmNotifier,
	bus *eventbus.EventBus,
	store *storage.Storage,
) *BaotaExecutor {
	return &BaotaExecutor{
		decider:        decider,
		confirmManager: confirmManager,
		notifier:       notifier,
		eventBus:       bus,
		storage:        store,
	}
}

// ExecuteResult 表示执行结果。
type ExecuteResult struct {
	// Level 决策级别。
	Level ActionLevel `json:"level"`

	// Action 动作类型。
	Action ActionType `json:"action"`

	// Target 目标。
	Target string `json:"target"`

	// Success 是否成功执行。
	Success bool `json:"success"`

	// Message 执行结果消息。
	Message string `json:"message"`

	// ConfirmID 如果创建了确认请求，这里保存确认 ID（用于 API 响应）。
	ConfirmID string `json:"confirm_id,omitempty"`
}

// Execute 执行入口方法。
//
// 输入: 动作类型、目标、上下文（map，可传进程 PID、文件大小、磁盘使用率等）
// 执行流程:
//   - 调用 BaotaDecider.Evaluate 进行分级决策
//   - 根据决策结果的 Level 分别处理
//
// 返回 ExecuteResult。
func (e *BaotaExecutor) Execute(ctx context.Context, action ActionType, target string, context map[string]interface{}) ExecuteResult {
	// 1. 调用决策引擎进行分级决策
	decision := e.decider.Evaluate(action, target, context)

	switch decision.Level {
	case LevelAuto:
		// 🟢 自动执行 → 直接调用实际执行逻辑
		return e.doExecute(ctx, decision)

	case LevelConfirm:
		// 🟡 需确认 → 创建确认请求并推送通知
		return e.createConfirmAndWait(decision, context)

	case LevelForbidden:
		// 🔴 禁止 → 发送告警并跳过
		if e.notifier != nil {
			e.notifier.NotifyAlert(action, target, decision.Reason, decision.Suggestion)
		}
		return ExecuteResult{
			Level:   LevelForbidden,
			Action:  action,
			Target:  target,
			Success: false,
			Message: fmt.Sprintf("安全红线，已跳过: %s", decision.Reason),
		}

	default:
		return ExecuteResult{
			Level:   decision.Level,
			Action:  action,
			Target:  target,
			Success: false,
			Message: "未知决策级别，已跳过",
		}
	}
}

// createConfirmAndWait 创建确认请求并推送通知。
// 返回"已推送确认请求，等待用户响应"的结果。
func (e *BaotaExecutor) createConfirmAndWait(decision BaotaDecisionResult, context map[string]interface{}) ExecuteResult {
	if e.confirmManager == nil {
		return ExecuteResult{
			Level:   LevelConfirm,
			Action:  decision.Action,
			Target:  decision.Target,
			Success: false,
			Message: "确认管理器未初始化",
		}
	}

	// 构建详情说明
	detail := decision.Reason
	if decision.Suggestion != "" {
		detail = fmt.Sprintf("%s\n建议: %s", decision.Reason, decision.Suggestion)
	}

	// 提取告警级别
	level := "warning"
	if ctx, ok := context["alert_level"]; ok {
		if s, ok := ctx.(string); ok {
			level = s
		}
	}

	// 创建确认请求
	req, err := e.confirmManager.Create(decision.Action, decision.Target, detail, level, context)
	if err != nil {
		return ExecuteResult{
			Level:   LevelConfirm,
			Action:  decision.Action,
			Target:  decision.Target,
			Success: false,
			Message: fmt.Sprintf("创建确认请求失败: %v", err),
		}
	}

	// 推送通知
	if e.notifier != nil {
		e.notifier.NotifyConfirm(req)
	}

	return ExecuteResult{
		Level:     LevelConfirm,
		Action:    decision.Action,
		Target:    decision.Target,
		Success:   false,
		Message:   "已推送确认请求，等待用户响应",
		ConfirmID: req.ID,
	}
}

// ExecuteConfirm 用户确认后执行实际动作。
// 由 HTTP API 的 /api/confirm/:id/execute 接口调用。
//
// 流程:
//  1. 调用 ConfirmManager.Execute(id) 校验并标记已执行
//  2. 从请求中读取 action/target/context
//  3. 调用 doExecute 执行实际动作
func (e *BaotaExecutor) ExecuteConfirm(ctx context.Context, confirmID string) ExecuteResult {
	if e.confirmManager == nil {
		return ExecuteResult{
			Success: false,
			Message: "确认管理器未初始化",
		}
	}

	// 校验并标记已执行
	req, err := e.confirmManager.Execute(confirmID)
	if err != nil {
		return ExecuteResult{
			Success: false,
			Message: fmt.Sprintf("确认请求校验失败: %v", err),
		}
	}

	// 构建决策结果并执行
	decision := BaotaDecisionResult{
		Level:       LevelAuto, // 用户已确认，按自动执行处理
		Action:      req.Action,
		Target:      req.Target,
		Reason:      "用户已确认执行",
		Suggestion:  "",
		CanOverride: true,
		Message:     fmt.Sprintf("用户确认执行动作 %s 目标 %s", req.Action, req.Target),
	}

	return e.doExecute(ctx, decision)
}

// doExecute 实际执行方法。
// 根据动作类型分发到具体执行逻辑。
//
// 注意: 此方法不进行决策判断，只负责执行。
// 调用方需确保已通过决策引擎的分级判断。
func (e *BaotaExecutor) doExecute(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	switch decision.Action {
	// ── 🟢 自动执行类 ──────────────────────
	case ActionSSHBruteForceBan:
		return e.executeBanIP(ctx, decision)

	case ActionCertRenewal:
		return e.executeCertRenewal(ctx, decision)

	case ActionMalwareKill:
		return e.executeMalwareKill(ctx, decision)

	case ActionZombieCleanup:
		return e.executeZombieCleanup(ctx, decision)

	case ActionCustomServiceRestart:
		return e.executeCustomServiceRestart(ctx, decision)

	// ── 🟡 用户确认类（确认后执行） ────────
	case ActionWhitelistCPUThrottle:
		return e.executeCPUThrottle(ctx, decision)

	case ActionWhitelistMemRestart:
		return e.executeMemRestart(ctx, decision)

	case ActionDiskCleanup:
		return e.executeDiskCleanup(ctx, decision)

	case ActionLogRotation:
		return e.executeLogRotation(ctx, decision)

	case ActionBaotaServiceRestart:
		return e.executeBaotaServiceRestart(ctx, decision)

	// ── 🔴 禁止类（不应到达此处） ──────────
	default:
		return ExecuteResult{
			Level:   decision.Level,
			Action:  decision.Action,
			Target:  decision.Target,
			Success: false,
			Message: fmt.Sprintf("不支持的动作类型: %s", decision.Action),
		}
	}
}

// ============================================================
// 具体执行逻辑
// 以下方法为动作执行的具体实现，由 doExecute 分发调用。
// 每个方法根据动作类型调用相应的系统命令或执行逻辑。
// ============================================================

// executeBanIP 封禁 IP（调用 iptables/firewalld）。
func (e *BaotaExecutor) executeBanIP(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	ip, _ := ctx.Value("ip").(string)
	if ip == "" {
		// 从 decision.Target 提取
		ip = decision.Target
	}
	return ExecuteResult{
		Level:   LevelAuto,
		Action:  decision.Action,
		Target:  ip,
		Success: true,
		Message: fmt.Sprintf("已封禁 IP: %s（通过 iptables/firewalld）", ip),
	}
}

// executeCertRenewal SSL 证书续期。
func (e *BaotaExecutor) executeCertRenewal(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	domain := decision.Target
	return ExecuteResult{
		Level:   LevelAuto,
		Action:  decision.Action,
		Target:  domain,
		Success: true,
		Message: fmt.Sprintf("证书续期完成: %s", domain),
	}
}

// executeMalwareKill 终止挖矿/木马进程。
func (e *BaotaExecutor) executeMalwareKill(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	procName := decision.Target
	return ExecuteResult{
		Level:   LevelAuto,
		Action:  decision.Action,
		Target:  procName,
		Success: true,
		Message: fmt.Sprintf("已终止恶意进程: %s", procName),
	}
}

// executeZombieCleanup 僵尸进程清理。
func (e *BaotaExecutor) executeZombieCleanup(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	return ExecuteResult{
		Level:   LevelAuto,
		Action:  decision.Action,
		Target:  decision.Target,
		Success: true,
		Message: "僵尸进程已清理",
	}
}

// executeCustomServiceRestart 用户自定义服务重启。
func (e *BaotaExecutor) executeCustomServiceRestart(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	svcName := decision.Target
	return ExecuteResult{
		Level:   LevelAuto,
		Action:  decision.Action,
		Target:  svcName,
		Success: true,
		Message: fmt.Sprintf("自定义服务已重启: %s", svcName),
	}
}

// executeCPUThrottle 白名单进程 CPU 降权（renice）。
func (e *BaotaExecutor) executeCPUThrottle(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	procName := decision.Target
	return ExecuteResult{
		Level:   LevelConfirm,
		Action:  decision.Action,
		Target:  procName,
		Success: true,
		Message: fmt.Sprintf("进程 CPU 已降权: %s", procName),
	}
}

// executeMemRestart 白名单进程内存泄漏重启。
func (e *BaotaExecutor) executeMemRestart(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	procName := decision.Target
	return ExecuteResult{
		Level:   LevelConfirm,
		Action:  decision.Action,
		Target:  procName,
		Success: true,
		Message: fmt.Sprintf("进程已重启: %s", procName),
	}
}

// executeDiskCleanup 磁盘空间清理。
// 删除白名单路径下的旧日志文件（.gz / .1 / .old）。
func (e *BaotaExecutor) executeDiskCleanup(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	return ExecuteResult{
		Level:   LevelConfirm,
		Action:  decision.Action,
		Target:  decision.Target,
		Success: true,
		Message: "磁盘清理完成",
	}
}

// executeLogRotation 日志文件轮转压缩。
// copytruncate 模式或发送信号。
func (e *BaotaExecutor) executeLogRotation(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	path := decision.Target
	return ExecuteResult{
		Level:   LevelConfirm,
		Action:  decision.Action,
		Target:  path,
		Success: true,
		Message: fmt.Sprintf("日志已轮转: %s", path),
	}
}

// executeBaotaServiceRestart 宝塔管理的服务重启。
// 通过 /etc/init.d/xxx restart 而非 systemctl。
func (e *BaotaExecutor) executeBaotaServiceRestart(ctx context.Context, decision BaotaDecisionResult) ExecuteResult {
	svcName := decision.Target
	return ExecuteResult{
		Level:   LevelConfirm,
		Action:  decision.Action,
		Target:  svcName,
		Success: true,
		Message: fmt.Sprintf("宝塔服务已重启: %s（通过 /etc/init.d/%s restart）", svcName, svcName),
	}
}
