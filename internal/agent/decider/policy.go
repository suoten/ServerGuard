package decider

// ActionLevel 表示动作的执行级别，分三级：
//   - LevelAuto:     🟢 自动执行，无需用户介入
//   - LevelConfirm:  🟡 需用户确认后才执行
//   - LevelForbidden: 🔴 禁止自动执行，只告警
type ActionLevel int

const (
	// LevelAuto 🟢 自动执行级别，Agent 可直接执行该动作。
	LevelAuto ActionLevel = iota

	// LevelConfirm 🟡 用户确认级别，需等待用户通过确认链接/面板操作后才执行。
	LevelConfirm

	// LevelForbidden 🔴 禁止级别，任何情况下都不允许自动执行，仅发送告警通知。
	LevelForbidden
)

// String 返回 ActionLevel 的字符串表示，用于日志、配置和 API 响应。
// 返回值: "auto" / "confirm" / "forbidden"
func (l ActionLevel) String() string {
	switch l {
	case LevelAuto:
		return "auto"
	case LevelConfirm:
		return "confirm"
	case LevelForbidden:
		return "forbidden"
	default:
		return "unknown"
	}
}

// ParseActionLevel 将字符串解析为 ActionLevel，不区分大小写。
// 支持的值: "auto", "confirm", "forbidden"。
// 无法识别的值返回 LevelConfirm（保守处理）。
func ParseActionLevel(s string) ActionLevel {
	switch normalizeLower(s) {
	case "auto":
		return LevelAuto
	case "confirm":
		return LevelConfirm
	case "forbidden":
		return LevelForbidden
	default:
		return LevelConfirm
	}
}

// ActionType 表示具体的动作类型，用于策略表查找和执行分发。
// 每个 ActionType 对应 DefaultBaotaPolicy 中的一条策略。
type ActionType string

const (
	// ── 🟢 自动执行类 ──────────────────────────────────

	// ActionSSHBruteForceBan SSH 暴力破解封禁 IP。
	ActionSSHBruteForceBan ActionType = "ssh_bruteforce_ban"

	// ActionCertRenewal SSL 证书自动续期。
	ActionCertRenewal ActionType = "cert_renewal"

	// ActionMalwareKill 挖矿/木马进程终止（非白名单进程）。
	ActionMalwareKill ActionType = "malware_kill"

	// ActionZombieCleanup 僵尸进程清理（回收已死但未 reap 的子进程）。
	ActionZombieCleanup ActionType = "zombie_cleanup"

	// ActionCustomServiceRestart 用户自定义非宝塔服务重启。
	ActionCustomServiceRestart ActionType = "custom_service_restart"

	// ── 🟡 用户确认类 ──────────────────────────────────

	// ActionWhitelistCPUThrottle 白名单进程 CPU 超限降权（renice）。
	ActionWhitelistCPUThrottle ActionType = "whitelist_cpu_throttle"

	// ActionWhitelistMemRestart 白名单进程内存泄漏重启。
	ActionWhitelistMemRestart ActionType = "whitelist_mem_restart"

	// ActionDiskCleanup 磁盘空间清理（删除旧日志压缩文件）。
	ActionDiskCleanup ActionType = "disk_cleanup"

	// ActionLogRotation 日志文件轮转压缩。
	ActionLogRotation ActionType = "log_rotation"

	// ActionBaotaServiceRestart 宝塔管理的服务（nginx/mysql 等）重启。
	ActionBaotaServiceRestart ActionType = "baota_service_restart"

	// ── 🔴 禁止自动类 ──────────────────────────────────

	// ActionKillBTPanel Kill 宝塔面板进程（绝对禁止）。
	ActionKillBTPanel ActionType = "kill_bt_panel"

	// ActionKillBTTask Kill 宝塔任务进程（绝对禁止）。
	ActionKillBTTask ActionType = "kill_bt_task"

	// ActionRestartBTPanel 自动重启宝塔面板（绝对禁止）。
	ActionRestartBTPanel ActionType = "restart_bt_panel"

	// ActionCleanBaotaDir 清理宝塔目录文件（绝对禁止）。
	ActionCleanBaotaDir ActionType = "clean_baota_dir"

	// ActionSystemctlBaotaSvc 用 systemctl 管理宝塔服务（绝对禁止）。
	ActionSystemctlBaotaSvc ActionType = "systemctl_baota_svc"

	// ActionChmodBaotaFile 修改宝塔文件权限（绝对禁止）。
	ActionChmodBaotaFile ActionType = "chmod_baota_file"
)

// ActionPolicy 定义单个动作的执行策略。
// 每个 ActionType 在 DefaultBaotaPolicy 中对应一条 ActionPolicy。
type ActionPolicy struct {
	// Level 基础执行级别（auto / confirm / forbidden）。
	// 🔴 forbidden 级别在代码中硬编码，任何用户配置都无法覆盖。
	Level ActionLevel `json:"level"`

	// Reason 为什么是这个级别，用于日志记录和告警文案。
	// 例如: "宝塔面板进程为核心服务，Kill 操作会导致面板不可用"
	Reason string `json:"reason"`

	// Suggestion 建议操作文案，用于通知消息中告知用户应如何手动处理。
	// 例如: "请通过宝塔面板手动管理面板服务"
	Suggestion string `json:"suggestion"`
}

// DefaultBaotaPolicy 是宝塔环境下的默认策略表。
// 键为 ActionType，值为对应的 ActionPolicy。
//
// 关键规则：
//   - 🔴 禁止项（forbidden）在代码中硬编码，任何用户配置都无法覆盖
//   - 🟢 自动项（auto）用户可关闭，关闭后降级为 confirm
//   - 🟡 确认项（confirm）用户可改为 "auto" 或 "alert"
//   - 未在此表中的未知动作，在宝塔环境下保守处理为 confirm
var DefaultBaotaPolicy = map[ActionType]ActionPolicy{
	// ── 🟢 自动执行类 ──────────────────────────────────
	ActionSSHBruteForceBan: {
		Level:      LevelAuto,
		Reason:     "SSH 暴力破解封禁不涉及宝塔核心进程，可自动执行",
		Suggestion: "已自动封禁恶意 IP",
	},
	ActionCertRenewal: {
		Level:      LevelAuto,
		Reason:     "SSL 证书续期是只读+写文件操作，不影响宝塔运行",
		Suggestion: "证书已自动续期",
	},
	ActionMalwareKill: {
		Level:      LevelAuto,
		Reason:     "挖矿/木马进程不在白名单中，可安全终止",
		Suggestion: "已终止恶意进程，建议排查入侵途径",
	},
	ActionZombieCleanup: {
		Level:      LevelAuto,
		Reason:     "僵尸进程清理是安全的内核级回收操作",
		Suggestion: "已清理僵尸进程",
	},
	ActionCustomServiceRestart: {
		Level:      LevelAuto,
		Reason:     "用户自定义服务不受宝塔管理，可自动重启",
		Suggestion: "已重启自定义服务",
	},

	// ── 🟡 用户确认类 ──────────────────────────────────
	ActionWhitelistCPUThrottle: {
		Level:      LevelConfirm,
		Reason:     "白名单进程降权可能影响服务性能，需用户确认",
		Suggestion: "建议通过宝塔面板查看进程资源使用情况后决定",
	},
	ActionWhitelistMemRestart: {
		Level:      LevelConfirm,
		Reason:     "白名单进程重启会导致服务短暂中断，需用户确认",
		Suggestion: "建议在低峰期手动重启该服务",
	},
	ActionDiskCleanup: {
		Level:      LevelConfirm,
		Reason:     "磁盘清理可能影响宝塔日志查看，需用户确认清理范围",
		Suggestion: "建议通过宝塔面板的日志管理功能进行清理",
	},
	ActionLogRotation: {
		Level:      LevelConfirm,
		Reason:     "日志轮转可能影响宝塔日志分析，需用户确认",
		Suggestion: "建议使用系统 logrotate 或宝塔日志管理",
	},
	ActionBaotaServiceRestart: {
		Level:      LevelConfirm,
		Reason:     "宝塔管理的服务重启会影响网站访问，需用户确认",
		Suggestion: "建议通过宝塔面板的服务管理功能重启",
	},

	// ── 🔴 禁止自动类 ──────────────────────────────────
	ActionKillBTPanel: {
		Level:      LevelForbidden,
		Reason:     "宝塔面板进程为核心服务，Kill 操作会导致面板不可用",
		Suggestion: "如需重启面板，请通过宝塔面板或 /etc/init.d/bt 命令操作",
	},
	ActionKillBTTask: {
		Level:      LevelForbidden,
		Reason:     "宝塔任务进程负责计划任务执行，Kill 会导致定时任务中断",
		Suggestion: "如需管理宝塔任务，请通过宝塔面板的计划任务页面",
	},
	ActionRestartBTPanel: {
		Level:      LevelForbidden,
		Reason:     "自动重启宝塔面板可能导致面板异常，必须由用户手动操作",
		Suggestion: "请通过 /etc/init.d/bt restart 手动重启面板",
	},
	ActionCleanBaotaDir: {
		Level:      LevelForbidden,
		Reason:     "清理宝塔目录文件可能导致面板数据丢失或功能异常",
		Suggestion: "请通过宝塔面板的文件管理功能手动清理",
	},
	ActionSystemctlBaotaSvc: {
		Level:      LevelForbidden,
		Reason:     "使用 systemctl 管理宝塔服务可能与宝塔的 init.d 脚本冲突",
		Suggestion: "请使用 /etc/init.d/xxx restart 管理宝塔服务",
	},
	ActionChmodBaotaFile: {
		Level:      LevelForbidden,
		Reason:     "修改宝塔文件权限可能导致面板权限异常或安全风险",
		Suggestion: "请通过宝塔面板的文件管理功能修改权限",
	},
}

// forbiddenActions 返回所有 🔴 禁止级别的动作类型集合。
// 用于配置校验：如果用户配置中出现了这些动作，应报错拒绝。
func forbiddenActions() map[ActionType]bool {
	result := make(map[ActionType]bool)
	for action, policy := range DefaultBaotaPolicy {
		if policy.Level == LevelForbidden {
			result[action] = true
		}
	}
	return result
}

// normalizeLower 将字符串转为小写并去除首尾空白。
// 避免引入 strings 包的依赖（虽然已有，但保持工具函数内聚）。
func normalizeLower(s string) string {
	if len(s) == 0 {
		return ""
	}
	// 去除首尾空白
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	s = s[start:end]

	// 转小写
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 32
		} else {
			buf[i] = c
		}
	}
	return string(buf)
}
