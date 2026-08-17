package decider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/suoten/serverguard/internal/baota"
)

// UserBaotaConfig 用户在 config.yaml 中的宝塔配置节。
// 用于控制 Agent 在宝塔环境下各动作的执行策略。
type UserBaotaConfig struct {
	// AutoActions 🟢 自动项开关映射（ActionType → bool）。
	// true 表示保持自动执行，false 表示关闭自动执行（降级为 confirm）。
	// 未在映射中的动作默认为 true（开启自动）。
	AutoActions map[ActionType]bool `yaml:"auto_actions" json:"auto_actions"`

	// ConfirmActions 🟡 确认项策略映射（ActionType → string）。
	// 值为 "confirm"（需用户确认）、"auto"（升级为自动执行）、"alert"（仅告警不执行）。
	// 未在映射中的动作默认为 "confirm"。
	ConfirmActions map[ActionType]string `yaml:"confirm_actions" json:"confirm_actions"`
}

// BaotaDecisionResult 表示宝塔分级决策引擎的决策结果。
type BaotaDecisionResult struct {
	// Level 最终执行级别（auto / confirm / forbidden）。
	Level ActionLevel `json:"level"`

	// Action 动作类型。
	Action ActionType `json:"action"`

	// Target 目标（进程名、路径、IP 等）。
	Target string `json:"target"`

	// Reason 决策原因，用于日志记录。
	Reason string `json:"reason"`

	// Suggestion 建议文案，用于通知消息。
	Suggestion string `json:"suggestion"`

	// CanOverride 是否可被用户配置覆盖。
	// 🔴 forbidden 项固定为 false，🟢 auto 和 🟡 confirm 项为 true。
	CanOverride bool `json:"can_override"`

	// Message 用于通知的完整文案，组合了动作、目标和原因。
	Message string `json:"message"`
}

// BaotaDecider 宝塔环境分级决策引擎。
// 在已有的宝塔环境感知（BaotaEnv）和进程白名单基础上，
// 根据策略表和用户配置对每个动作进行分级决策。
type BaotaDecider struct {
	// env 宝塔环境信息（通过 baota.DetectBaotaEnvironment 获取）。
	env *baota.BaotaEnv

	// userConfig 用户配置（从 config.yaml 加载）。
	userConfig *UserBaotaConfig
}

// NewBaotaDecider 创建一个新的宝塔分级决策引擎。
// env 为宝塔环境检测结果，userConfig 为用户配置（可为 nil，表示使用默认策略）。
func NewBaotaDecider(env *baota.BaotaEnv, userConfig *UserBaotaConfig) *BaotaDecider {
	if userConfig == nil {
		userConfig = &UserBaotaConfig{
			AutoActions:    make(map[ActionType]bool),
			ConfirmActions: make(map[ActionType]string),
		}
	}
	if env == nil {
		env = &baota.BaotaEnv{IsBaota: false}
	}
	return &BaotaDecider{
		env:        env,
		userConfig: userConfig,
	}
}

// Evaluate 分级决策入口方法。
// 输入参数：
//   - action: 动作类型
//   - target: 目标（进程名、路径、IP 等）
//   - context: 上下文信息（map，可传进程 PID、文件大小、磁盘使用率等额外信息）
//
// 决策逻辑：
//   - 非宝塔环境 → 返回 auto（普通模式处理）
//   - 宝塔环境 → 查 DefaultBaotaPolicy 策略表，按级别分别处理
//
// 返回 BaotaDecisionResult，包含最终执行级别和相关文案。
func (d *BaotaDecider) Evaluate(action ActionType, target string, context map[string]interface{}) BaotaDecisionResult {
	// 非宝塔环境 → 直接返回 auto
	if d.env == nil || !d.env.IsBaota {
		return BaotaDecisionResult{
			Level:       LevelAuto,
			Action:      action,
			Target:      target,
			Reason:      "非宝塔环境，按普通模式处理",
			Suggestion:  "",
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：非宝塔环境，自动执行", action, target),
		}
	}

	// 宝塔环境 → 查策略表
	policy, exists := DefaultBaotaPolicy[action]
	if !exists {
		// 未知动作在宝塔环境下保守处理为 confirm
		return BaotaDecisionResult{
			Level:       LevelConfirm,
			Action:      action,
			Target:      target,
			Reason:      "未知动作在宝塔环境下保守处理为需确认",
			Suggestion:  "请确认此操作是否安全后再执行",
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：未知动作，需用户确认", action, target),
		}
	}

	switch policy.Level {
	case LevelAuto:
		return d.evaluateAuto(action, target, policy, context)

	case LevelConfirm:
		return d.evaluateConfirm(action, target, policy, context)

	case LevelForbidden:
		return d.evaluateForbidden(action, target, policy)

	default:
		// 不应该到达此处，保守处理
		return BaotaDecisionResult{
			Level:       LevelConfirm,
			Action:      action,
			Target:      target,
			Reason:      "未知策略级别，保守处理为需确认",
			Suggestion:  policy.Suggestion,
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：策略级别异常，需用户确认", action, target),
		}
	}
}

// evaluateAuto 处理 🟢 自动执行类动作。
// 检查用户是否关闭了此自动项（AutoActions 中对应值为 false）。
// 如果关闭 → 降级为 confirm；如果开启 → 返回 auto。
func (d *BaotaDecider) evaluateAuto(action ActionType, target string, policy ActionPolicy, context map[string]interface{}) BaotaDecisionResult {
	// 检查用户是否关闭了此自动项
	// 默认为 true（开启自动），只有明确设置为 false 才算关闭
	enabled := true
	if v, exists := d.userConfig.AutoActions[action]; exists {
		enabled = v
	}

	if !enabled {
		// 用户关闭了此自动项 → 降级为 confirm
		return BaotaDecisionResult{
			Level:       LevelConfirm,
			Action:      action,
			Target:      target,
			Reason:      fmt.Sprintf("用户已关闭自动执行，降级为需确认。原始原因: %s", policy.Reason),
			Suggestion:  policy.Suggestion,
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：用户已关闭自动执行，需确认后执行", action, target),
		}
	}

	// 保持自动执行
	return BaotaDecisionResult{
		Level:       LevelAuto,
		Action:      action,
		Target:      target,
		Reason:      policy.Reason,
		Suggestion:  policy.Suggestion,
		CanOverride: true,
		Message:     fmt.Sprintf("动作 %s 目标 %s：自动执行。%s", action, target, policy.Reason),
	}
}

// evaluateConfirm 处理 🟡 用户确认类动作。
// 检查用户配置（ConfirmActions）：
//   - "auto" → 升级为 auto
//   - "alert" 或 "alert_only" → 保持 confirm 级别但标记为仅告警
//   - "confirm" 或空 → 正常 confirm
func (d *BaotaDecider) evaluateConfirm(action ActionType, target string, policy ActionPolicy, context map[string]interface{}) BaotaDecisionResult {
	// 获取用户配置
	userSetting := ""
	if v, exists := d.userConfig.ConfirmActions[action]; exists {
		userSetting = normalizeLower(v)
	}

	switch userSetting {
	case "auto":
		// 用户升级为自动执行
		return BaotaDecisionResult{
			Level:       LevelAuto,
			Action:      action,
			Target:      target,
			Reason:      fmt.Sprintf("用户配置升级为自动执行。原始原因: %s", policy.Reason),
			Suggestion:  policy.Suggestion,
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：用户配置自动执行", action, target),
		}

	case "alert", "alert_only":
		// 用户配置为仅告警 → 保持 confirm 级别但标记为仅告警（不执行）
		return BaotaDecisionResult{
			Level:       LevelConfirm,
			Action:      action,
			Target:      target,
			Reason:      fmt.Sprintf("用户配置为仅告警不执行。原始原因: %s", policy.Reason),
			Suggestion:  policy.Suggestion,
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：仅告警，需用户手动处理。%s", action, target, policy.Suggestion),
		}

	default:
		// "confirm" 或空 → 正常 confirm
		return BaotaDecisionResult{
			Level:       LevelConfirm,
			Action:      action,
			Target:      target,
			Reason:      policy.Reason,
			Suggestion:  policy.Suggestion,
			CanOverride: true,
			Message:     fmt.Sprintf("动作 %s 目标 %s：需用户确认后执行。%s", action, target, policy.Reason),
		}
	}
}

// evaluateForbidden 处理 🔴 禁止自动类动作。
// 直接返回 forbidden，CanOverride 固定为 false，任何用户配置都无法改变此结果。
func (d *BaotaDecider) evaluateForbidden(action ActionType, target string, policy ActionPolicy) BaotaDecisionResult {
	return BaotaDecisionResult{
		Level:       LevelForbidden,
		Action:      action,
		Target:      target,
		Reason:      policy.Reason,
		Suggestion:  policy.Suggestion,
		CanOverride: false, // 🔴 禁止项不可被任何配置覆盖
		Message:     fmt.Sprintf("动作 %s 目标 %s：安全红线禁止执行。%s", action, target, policy.Suggestion),
	}
}

// ============================================================
// 辅助检测方法
// ============================================================

// baotaPanelProcessNames 是宝塔面板核心进程名列表（直接匹配，不需二次确认）。
var baotaPanelProcessNames = map[string]bool{
	"bt-panel":   true,
	"bt-task":    true,
	"bt_monitor": true,
	"bt-python":  true,
}

// baotaPanelPathMarkers 是用于二次确认 python 进程的宝塔路径标识。
var baotaPanelPathMarkers = []string{
	"/www/server/panel",
}

// IsBaotaPanelProcess 判断进程是否为宝塔面板核心进程。
//
// 判断逻辑：
//  1. 进程名直接匹配 bt-panel、bt-task、bt_monitor、bt-python → 是
//  2. 进程名为 python 或 python3 → 必须二次确认：
//     - 检查进程 cwd（当前工作目录）是否包含 /www/server/panel
//     - 或检查进程 cmdline 是否包含 /www/server/panel
//     - 满足任一条件才视为宝塔进程
//  3. 不满足二次确认的 python 进程 → 视为普通进程，不受白名单保护
//
// 参数 procName 为进程名（如 python3），
// cwd 为进程当前工作目录，
// cmdline 为进程完整命令行。
func (d *BaotaDecider) IsBaotaPanelProcess(procName, cwd, cmdline string) bool {
	procNameLower := normalizeLower(procName)

	// 直接匹配宝塔面板核心进程名
	if baotaPanelProcessNames[procNameLower] {
		return true
	}

	// python / python3 进程需二次确认
	if procNameLower == "python" || procNameLower == "python3" {
		return isBaotaPath(cwd) || isBaotaPath(cmdline)
	}

	return false
}

// isBaotaPath 检查给定路径是否包含宝塔面板路径标识。
func isBaotaPath(s string) bool {
	if s == "" {
		return false
	}
	sLower := normalizeLower(s)
	for _, marker := range baotaPanelPathMarkers {
		if strings.Contains(sLower, marker) {
			return true
		}
	}
	return false
}

// baotaManagedServiceNames 是宝塔管理的常见服务名列表。
var baotaManagedServiceNames = map[string]bool{
	"nginx":           true,
	"httpd":           true,
	"apache":          true,
	"apache2":         true,
	"mysqld":          true,
	"mariadbd":        true,
	"mariadb":         true,
	"redis-server":    true,
	"redis":           true,
	"mongod":          true,
	"mongo":           true,
	"postgres":        true,
	"postgresql":      true,
	"php-fpm":         true,
	"php-fpm-74":      true,
	"php-fpm-80":      true,
	"php-fpm-81":      true,
	"php-fpm-82":      true,
	"php-fpm-83":      true,
	"php-fpm-84":      true,
	"pure-ftpd":       true,
	"pure-ftpd-mysql": true,
	"vsftpd":          true,
	"proftpd":         true,
	"memcached":       true,
}

// IsBaotaManagedService 判断服务是否为宝塔管理。
//
// 判断逻辑：
//  1. 服务名匹配已知宝塔管理服务列表（nginx、mysqld 等）
//  2. 同时检查 /www/server/ 下是否存在对应软件目录（二次确认）
//  3. 两个条件都满足才视为宝塔管理服务
//
// 参数 serviceName 为服务名（如 nginx、mysqld）。
// 返回 true 表示该服务由宝塔管理。
func (d *BaotaDecider) IsBaotaManagedService(serviceName string) bool {
	serviceNameLower := normalizeLower(serviceName)

	// 检查服务名是否匹配
	if !baotaManagedServiceNames[serviceNameLower] {
		return false
	}

	// 二次确认：检查 /www/server/ 下是否存在对应软件目录
	// 常见路径: /www/server/nginx, /www/server/mysql, /www/server/redis 等
	possibleDirs := []string{
		filepath.Join("/www/server", serviceNameLower),
		filepath.Join("/www/server", strings.TrimSuffix(serviceNameLower, "-server")),
		filepath.Join("/www/server", strings.TrimSuffix(serviceNameLower, "d")), // mysqld -> mysql, mariadbd -> mariadb
		filepath.Join("/www/server", strings.TrimSuffix(serviceNameLower, "-fpm")),
	}

	// php-fpm 特殊处理：检查 /www/server/php
	if strings.HasPrefix(serviceNameLower, "php-fpm") {
		possibleDirs = append(possibleDirs, "/www/server/php")
	}

	// pure-ftpd 特殊处理
	if strings.HasPrefix(serviceNameLower, "pure-ftpd") {
		possibleDirs = append(possibleDirs, "/www/server/pure-ftpd")
	}

	for _, dir := range possibleDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return true
		}
	}

	return false
}

// GetEnv 返回当前宝塔环境信息。
func (d *BaotaDecider) GetEnv() *baota.BaotaEnv {
	return d.env
}

// GetUserConfig 返回当前用户配置。
func (d *BaotaDecider) GetUserConfig() *UserBaotaConfig {
	return d.userConfig
}
