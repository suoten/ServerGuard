package decider

import (
	"fmt"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ConfirmNotifier 确认消息专用通知推送模块。
// 当 ConfirmManager.Create 成功后，调用此模块推送通知到用户配置的所有渠道。
//
// 关键设计：
//   - 确认链接带一次性 Token（即 ConfirmRequest.ID）
//   - 用户点击链接即可执行，无需登录面板
//   - 链接 5 分钟后过期失效
//   - 推送到所有已启用的通知渠道（微信/钉钉/飞书/邮件等）
type ConfirmNotifier struct {
	// eventBus 事件总线引用，通过 PublishAlert 发布告警事件，
	// Notifier 会自动订阅并分发到所有已配置的通知渠道。
	eventBus *eventbus.EventBus

	// panelURL 面板基础 URL（如 https://server.example.com:8443）。
	// 用于构建确认链接和忽略链接。
	panelURL string

	// serverName 服务器名称/地址，用于通知正文中标识来源。
	serverName string
}

// NewConfirmNotifier 创建一个新的确认消息通知器。
//
// 参数:
//   - bus: 事件总线实例（Notifier 已订阅其 Alert 事件）
//   - panelURL: 面板基础 URL（如 https://server.example.com:8443）
//   - serverName: 服务器名称/地址，用于通知正文
func NewConfirmNotifier(bus *eventbus.EventBus, panelURL, serverName string) *ConfirmNotifier {
	return &ConfirmNotifier{
		eventBus:   bus,
		panelURL:   panelURL,
		serverName: serverName,
	}
}

// NotifyConfirm 推送确认请求通知到所有已启用的通知渠道。
//
// 通知内容格式：
//   - 标题: 【ServerGuard】{动作名} 待确认
//   - 正文包含: 服务器地址/名称、动作类型、目标、详情说明、过期时间、确认链接、忽略链接
//
// 参数 req 为待推送的确认请求。
func (cn *ConfirmNotifier) NotifyConfirm(req *ConfirmRequest) {
	if cn.eventBus == nil {
		return
	}

	// 构建通知标题
	title := fmt.Sprintf("【ServerGuard】%s 待确认", cn.actionDisplayName(req.Action))

	// 构建通知正文
	body := cn.buildNotifyBody(req)

	// 构建告警级别
	alertLevel := types.AlertWarning
	if req.Level == "error" {
		alertLevel = types.AlertError
	}

	// 通过事件总线发布告警事件
	// Notifier 已在构造时订阅了 EventAlert 事件，会自动将告警分发到所有已启用渠道
	cn.eventBus.PublishAlert(
		alertLevel,
		"baota_decider",
		title,
		body,
		req.ID, // ruleID 字段复用为确认请求 ID
	)
}

// NotifyAlert 推送安全红线告警通知。
// 当决策引擎返回 LevelForbidden 时，调用此方法发送告警。
//
// 参数:
//   - action: 被阻止的动作类型
//   - target: 被阻止的目标
//   - reason: 阻止原因
//   - suggestion: 建议操作
func (cn *ConfirmNotifier) NotifyAlert(action ActionType, target, reason, suggestion string) {
	if cn.eventBus == nil {
		return
	}

	title := fmt.Sprintf("【ServerGuard 安全红线】%s 已阻止", cn.actionDisplayName(action))
	body := fmt.Sprintf(
		"服务器: %s\n"+
			"被阻止动作: %s\n"+
			"目标: %s\n"+
			"阻止原因: %s\n"+
			"建议操作: %s",
		cn.serverName,
		cn.actionDisplayName(action),
		target,
		reason,
		suggestion,
	)

	cn.eventBus.PublishAlert(
		types.AlertCritical,
		"baota_decider",
		title,
		body,
		string(action),
	)
}

// actionDisplayName 返回动作类型的中文名称，用于通知标题和正文。
func (cn *ConfirmNotifier) actionDisplayName(action ActionType) string {
	displayNames := map[ActionType]string{
		ActionWhitelistCPUThrottle: "白名单进程CPU降权",
		ActionWhitelistMemRestart:  "白名单进程内存重启",
		ActionDiskCleanup:          "磁盘空间清理",
		ActionLogRotation:          "日志轮转压缩",
		ActionBaotaServiceRestart:  "宝塔服务重启",
		ActionSSHBruteForceBan:     "SSH暴力破解封禁",
		ActionCertRenewal:          "SSL证书续期",
		ActionMalwareKill:          "恶意进程终止",
		ActionZombieCleanup:        "僵尸进程清理",
		ActionCustomServiceRestart: "自定义服务重启",
		ActionKillBTPanel:          "终止宝塔面板",
		ActionKillBTTask:           "终止宝塔任务",
		ActionRestartBTPanel:       "重启宝塔面板",
		ActionCleanBaotaDir:        "清理宝塔目录",
		ActionSystemctlBaotaSvc:    "systemctl管理宝塔服务",
		ActionChmodBaotaFile:       "修改宝塔文件权限",
	}
	if name, ok := displayNames[action]; ok {
		return name
	}
	return string(action)
}

// buildNotifyBody 构建通知正文。
// 包含：服务器地址/名称、动作类型、目标、详情说明、过期时间、确认链接、忽略链接。
func (cn *ConfirmNotifier) buildNotifyBody(req *ConfirmRequest) string {
	confirmURL := fmt.Sprintf("%s/api/confirm/%s/execute", cn.panelURL, req.ID)
	ignoreURL := fmt.Sprintf("%s/api/confirm/%s/ignore", cn.panelURL, req.ID)

	body := fmt.Sprintf(
		"服务器: %s\n"+
			"动作类型: %s\n"+
			"目标: %s\n"+
			"详情: %s\n"+
			"过期时间: %s\n\n"+
			"确认执行: %s\n"+
			"忽略: %s\n\n"+
			"提示: 确认链接将在 %s 后失效",
		cn.serverName,
		cn.actionDisplayName(req.Action),
		req.Target,
		req.Detail,
		req.ExpiresAt.Format("2006-01-02 15:04:05"),
		confirmURL,
		ignoreURL,
		req.ExpiresAt.Format("15:04:05"),
	)

	return body
}
