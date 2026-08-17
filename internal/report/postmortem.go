package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// 故障复盘自动纪要生成 (P71)
// 读取审计日志+告警记录+操作时间戳+系统指标+攻击事件+安全发现
// → 多维度交叉分析 → 生成有明确根因和建议的复盘报告
// ────────────────────────────────────────────────

// PostmortemReport 故障复盘报告
type PostmortemReport struct {
	IncidentID    string        `json:"incident_id"`
	Title         string        `json:"title"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	Duration      string        `json:"duration"`
	Severity      string        `json:"severity"`
	Summary       string        `json:"summary"`
	Timeline      []TimelineItem `json:"timeline"`
	RootCause     string        `json:"root_cause"`
	Actions       []ActionItem   `json:"actions"`
	LessonsLearned string       `json:"lessons_learned"`
	GeneratedAt   time.Time     `json:"generated_at"`
}

// TimelineItem 时间线条目
type TimelineItem struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // alert/action/recovery/audit/attack/finding
	Message   string    `json:"message"`
}

// ActionItem 修复动作
type ActionItem struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Success bool      `json:"success"`
	Message string    `json:"message"`
}

// GeneratePostmortem 生成故障复盘报告
// incidentStart: 故障开始时间
// incidentEnd: 故障结束时间（可为零值，表示到当前时间）
func (g *Generator) GeneratePostmortem(incidentStart time.Time, incidentEnd time.Time) (*PostmortemReport, error) {
	if g.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}

	if incidentEnd.IsZero() {
		incidentEnd = time.Now()
	}

	// 扩大时间范围前后 30 分钟，捕获完整上下文
	queryStart := incidentStart.Add(-30 * time.Minute)
	queryEnd := incidentEnd.Add(30 * time.Minute)

	report := &PostmortemReport{
		IncidentID:  fmt.Sprintf("INC-%s", incidentStart.Format("20060102-150405")),
		StartTime:   incidentStart,
		EndTime:     incidentEnd,
		GeneratedAt: time.Now(),
	}

	// 计算持续时间
	duration := incidentEnd.Sub(incidentStart)
	if duration < time.Minute {
		report.Duration = fmt.Sprintf("%.0f 秒", duration.Seconds())
	} else if duration < time.Hour {
		report.Duration = fmt.Sprintf("%.0f 分钟", duration.Minutes())
	} else {
		report.Duration = fmt.Sprintf("%.1f 小时", duration.Hours())
	}

	// 收集时间线和修复动作
	report.Timeline = g.collectTimeline(queryStart, queryEnd)
	report.Actions = g.collectActions(queryStart, queryEnd)

	// 收集告警（使用新的时间范围查询，包含已解决的告警）
	alerts, _ := g.store.GetAlertsByTimeRange(queryStart, queryEnd, 500)

	// 收集攻击事件
	attackEvents, _ := g.store.QueryAttackEvents("", "", "", queryStart, 200)

	// 收集安全发现
	findings, _ := g.store.QueryFindings("", "", "", 200)

	// 收集系统指标
	cpuMetrics, _ := g.store.GetMetrics("", "system.cpu_percent", queryStart, 1000)
	memMetrics, _ := g.store.GetMetrics("", "system.mem_percent", queryStart, 1000)
	diskMetrics, _ := g.store.GetMetrics("", "disk.used_percent", queryStart, 1000)
	loadMetrics, _ := g.store.GetMetrics("", "system.load_avg_1", queryStart, 1000)
	swapMetrics, _ := g.store.GetMetrics("", "system.swap_percent", queryStart, 1000)
	netSentMetrics, _ := g.store.GetMetrics("", "net.sent_rate", queryStart, 500)
	netRecvMetrics, _ := g.store.GetMetrics("", "net.recv_rate", queryStart, 500)

	// 审计日志
	auditLogs, _ := g.store.GetAuditLog(queryStart, 500)

	// 操作记录
	actions, _ := g.store.GetActionHistory(queryStart, 500)

	// 确定标题和严重级别
	report.Title, report.Severity, report.Summary = g.determineTitle(alerts, attackEvents, incidentStart)

	// 推测根因 — 多维度交叉分析
	report.RootCause = g.inferRootCause(
		alerts, attackEvents, findings, actions, auditLogs,
		cpuMetrics, memMetrics, diskMetrics, loadMetrics, swapMetrics,
		netSentMetrics, netRecvMetrics,
		queryStart, queryEnd,
	)

	// 生成经验教训
	report.LessonsLearned = g.generateLessons(report, alerts, attackEvents, actions)

	return report, nil
}

// determineTitle 从告警和攻击事件中确定最相关的标题
func (g *Generator) determineTitle(alerts []types.Alert, attacks []storage.AttackEvent, incidentStart time.Time) (title, severity, summary string) {
	// 优先级：fatal > critical > warning > info
	// 先从告警中找最高级别的
	var bestAlert *types.Alert
	for i := range alerts {
		a := &alerts[i]
		if bestAlert == nil {
			bestAlert = a
			continue
		}
		if alertSeverityWeight(a.Level) > alertSeverityWeight(bestAlert.Level) {
			bestAlert = a
		}
	}
	if bestAlert != nil {
		return bestAlert.Title, string(bestAlert.Level), bestAlert.Message
	}

	// 如果没有告警，看攻击事件
	if len(attacks) > 0 {
		// 找最严重的攻击
		var worstAttack *storage.AttackEvent
		for i := range attacks {
			a := &attacks[i]
			if worstAttack == nil {
				worstAttack = a
				continue
			}
			if attackSeverityWeight(a.Severity) > attackSeverityWeight(worstAttack.Severity) {
				worstAttack = a
			}
		}
		if worstAttack != nil {
			attackLabel := attackTypeLabel(worstAttack.EventType)
			return fmt.Sprintf("检测到%s攻击 (来源: %s)", attackLabel, worstAttack.SourceIP),
				worstAttack.Severity,
				fmt.Sprintf("攻击类型: %s，源IP: %s，目标: %s，详情: %s",
					attackLabel, worstAttack.SourceIP, worstAttack.Target, worstAttack.Detail)
		}
	}

	return fmt.Sprintf("故障复盘 %s", incidentStart.Format("01-02 15:04")),
		"warning",
		"基于审计日志、告警记录、系统指标和攻击事件自动生成的复盘报告"
}

// collectTimeline 收集事件时间线
func (g *Generator) collectTimeline(start, end time.Time) []TimelineItem {
	var timeline []TimelineItem

	// 告警记录（使用新的时间范围查询，包含已解决的）
	if alerts, err := g.store.GetAlertsByTimeRange(start, end, 500); err == nil {
		for _, a := range alerts {
			timeline = append(timeline, TimelineItem{
				Timestamp: a.Timestamp,
				Type:      "alert",
				Message:   fmt.Sprintf("[%s] %s: %s", a.Level, a.Title, truncate(a.Message, 80)),
			})
		}
	}

	// 操作记录
	if actions, err := g.store.GetActionHistory(start, 500); err == nil {
		for _, act := range actions {
			itemType := "action"
			if act.Success {
				itemType = "recovery"
			}
			timeline = append(timeline, TimelineItem{
				Timestamp: act.Timestamp,
				Type:      itemType,
				Message:   truncate(act.Message, 100),
			})
		}
	}

	// 审计日志
	if auditLogs, err := g.store.GetAuditLog(start, 500); err == nil {
		for _, entry := range auditLogs {
			timeline = append(timeline, TimelineItem{
				Timestamp: entry.Timestamp,
				Type:      "audit",
				Message:   fmt.Sprintf("%s by %s: %s", entry.Action, entry.Actor, entry.Target),
			})
		}
	}

	// 攻击事件
	if attacks, err := g.store.QueryAttackEvents("", "", "", start, 200); err == nil {
		for _, atk := range attacks {
			label := attackTypeLabel(atk.EventType)
			timeline = append(timeline, TimelineItem{
				Timestamp: atk.CreatedAt,
				Type:      "attack",
				Message:   fmt.Sprintf("%s from %s → %s: %s", label, atk.SourceIP, atk.Target, truncate(atk.Detail, 60)),
			})
		}
	}

	// 按时间排序
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})

	return timeline
}

// collectActions 收集修复动作
func (g *Generator) collectActions(start, end time.Time) []ActionItem {
	var actions []ActionItem
	if actionHistory, err := g.store.GetActionHistory(start, 500); err == nil {
		for _, act := range actionHistory {
			actions = append(actions, ActionItem{
				Time:    act.Timestamp,
				Action:  string(act.Action.Type),
				Success: act.Success,
				Message: truncate(act.Message, 100),
			})
		}
	}
	return actions
}

// inferRootCause 多维度根因分析
func (g *Generator) inferRootCause(
	alerts []types.Alert,
	attacks []storage.AttackEvent,
	findings []storage.Finding,
	actions []types.ActionResult,
	audit []types.AuditEntry,
	cpuMetrics, memMetrics, diskMetrics, loadMetrics, swapMetrics, netSentMetrics, netRecvMetrics []types.Metric,
	start, end time.Time,
) string {
	var causes []string
	var evidence []string

	// ── 1. 告警聚类分析 ──
	alertGroups := groupAlerts(alerts)
	for source, groupAlerts := range alertGroups {
		if len(groupAlerts) >= 3 {
			// 同源告警 ≥3 次，说明该模块持续异常
			titles := uniqueAlertTitles(groupAlerts)
			causes = append(causes, fmt.Sprintf(
				"「%s」模块持续告警（%d 次），涉及: %s。这表明该模块存在持续性问题而非偶发抖动",
				source, len(groupAlerts), strings.Join(titles, "、")))
		} else if len(groupAlerts) > 0 {
			// 少量告警，记录但不一定是根因
			for _, a := range groupAlerts {
				if a.Level == types.AlertFatal || a.Level == types.AlertCritical {
					causes = append(causes, fmt.Sprintf(
						"「%s」模块触发 %s 级告警: %s — %s",
						source, a.Level, a.Title, truncate(a.Message, 60)))
				}
			}
		}
	}

	// ── 2. 攻击事件分析 ──
	if len(attacks) > 0 {
		// 按类型分组
		attackByType := map[string][]storage.AttackEvent{}
		for _, a := range attacks {
			attackByType[a.EventType] = append(attackByType[a.EventType], a)
		}
		// 找出攻击次数最多的类型
		var topType string
		var topCount int
		for t, list := range attackByType {
			if len(list) > topCount {
				topType = t
				topCount = len(list)
			}
		}
		if topCount > 0 {
			label := attackTypeLabel(topType)
			// 统计独立 IP 数
			ipSet := map[string]bool{}
			for _, a := range attacks {
				ipSet[a.SourceIP] = true
			}
			// 检查是否有 IP 被封禁
			bannedCount := 0
			for _, a := range attacks {
				if a.ActionTaken != "" && a.ActionTaken != "monitor" {
					bannedCount++
				}
			}
			cause := fmt.Sprintf(
				"检测到 %d 次%s攻击（来自 %d 个独立 IP），目标: %s",
				topCount, label, len(ipSet), attacks[0].Target)
			if bannedCount > 0 {
				cause += fmt.Sprintf("，已自动封禁 %d 个 IP", bannedCount)
			}
			causes = append(causes, cause)
			evidence = append(evidence, fmt.Sprintf(
				"攻击事件明细: 类型=%s，次数=%d，独立IP=%d，封禁=%d",
				topType, len(attacks), len(ipSet), bannedCount))
		}
	}

	// ── 3. 系统资源分析 ──
	// CPU
	if len(cpuMetrics) > 0 {
		var maxCPU, sumCPU float64
		for _, m := range cpuMetrics {
			if m.Value > maxCPU {
				maxCPU = m.Value
			}
			sumCPU += m.Value
		}
		avgCPU := sumCPU / float64(len(cpuMetrics))
		if maxCPU > 90 {
			causes = append(causes, fmt.Sprintf(
				"CPU 使用率峰值 %.0f%%（均值 %.0f%%），超过 90%% 危险阈值。可能原因: 高并发请求、死循环代码、挖矿进程、或大量编译任务",
				maxCPU, avgCPU))
			evidence = append(evidence, fmt.Sprintf("CPU: max=%.1f%% avg=%.1f%% samples=%d", maxCPU, avgCPU, len(cpuMetrics)))
		} else if avgCPU > 70 {
			evidence = append(evidence, fmt.Sprintf("CPU: max=%.1f%% avg=%.1f%% (偏高但未超阈值)", maxCPU, avgCPU))
		}
	}

	// 内存
	if len(memMetrics) > 0 {
		var maxMem, sumMem float64
		for _, m := range memMetrics {
			if m.Value > maxMem {
				maxMem = m.Value
			}
			sumMem += m.Value
		}
		avgMem := sumMem / float64(len(memMetrics))
		if maxMem > 90 {
			causes = append(causes, fmt.Sprintf(
				"内存使用率峰值 %.0f%%（均值 %.0f%%），可能触发 OOM Killer 导致进程被杀。建议检查内存泄漏或增加 Swap",
				maxMem, avgMem))
			evidence = append(evidence, fmt.Sprintf("内存: max=%.1f%% avg=%.1f%%", maxMem, avgMem))
		}
	}

	// Swap
	if len(swapMetrics) > 0 {
		var maxSwap float64
		for _, m := range swapMetrics {
			if m.Value > maxSwap {
				maxSwap = m.Value
			}
		}
		if maxSwap > 80 {
			causes = append(causes, fmt.Sprintf(
				"Swap 使用率峰值 %.0f%%，系统内存严重不足，频繁换页会导致 I/O 瓶颈和响应延迟",
				maxSwap))
			evidence = append(evidence, fmt.Sprintf("Swap: max=%.1f%%", maxSwap))
		}
	}

	// 磁盘
	if len(diskMetrics) > 0 {
		var maxDisk float64
		for _, m := range diskMetrics {
			if m.Value > maxDisk {
				maxDisk = m.Value
			}
		}
		if maxDisk > 90 {
			causes = append(causes, fmt.Sprintf(
				"磁盘使用率 %.0f%%，可能因磁盘满导致写入失败、日志截断或数据库异常。建议立即清理大文件或扩容",
				maxDisk))
			evidence = append(evidence, fmt.Sprintf("磁盘: max=%.1f%%", maxDisk))
		}
	}

	// 负载
	if len(loadMetrics) > 0 {
		var maxLoad float64
		for _, m := range loadMetrics {
			if m.Value > maxLoad {
				maxLoad = m.Value
			}
		}
		if maxLoad > 10 {
			causes = append(causes, fmt.Sprintf(
				"系统负载峰值 %.1f，远超 CPU 核心数，存在严重的资源争抢。可能原因: 过多进程竞争 CPU、大量 I/O 等待、或磁盘性能瓶颈",
				maxLoad))
			evidence = append(evidence, fmt.Sprintf("Load: max=%.1f", maxLoad))
		}
	}

	// ── 4. 网络流量突变分析 ──
	if len(netSentMetrics) > 0 && len(netRecvMetrics) > 0 {
		var maxRecv float64
		for _, m := range netRecvMetrics {
			if m.Value > maxRecv {
				maxRecv = m.Value
			}
		}
		// 流量异常大（>100MB/s = 104857600 bytes/s）
		if maxRecv > 100*1024*1024 {
			causes = append(causes, fmt.Sprintf(
				"网络入站流量峰值 %.0f MB/s，可能是 DDoS 攻击或大文件传输导致带宽打满",
				maxRecv/1024/1024))
			evidence = append(evidence, fmt.Sprintf("网络: recv_max=%.0f B/s", maxRecv))
		}
	}

	// ── 5. 修复动作失败分析 ──
	failCount := 0
	for _, a := range actions {
		if !a.Success {
			failCount++
		}
	}
	if failCount > 2 {
		causes = append(causes, fmt.Sprintf(
			"ServerGuard 自动修复动作失败 %d 次，可能原因: 目标进程拒绝终止、权限不足、或级联故障导致恢复无效",
			failCount))
	}

	// ── 6. 安全发现关联 ──
	if len(findings) > 0 {
		criticalCount := 0
		highCount := 0
		for _, f := range findings {
			if f.Status == "open" || f.Status == "" {
				switch f.Severity {
				case "critical":
					criticalCount++
				case "high":
					highCount++
				}
			}
		}
		if criticalCount > 0 {
			causes = append(causes, fmt.Sprintf(
				"存在 %d 个严重级别安全发现项（高危 %d 个），可能被攻击者利用导致故障。建议优先处理严重级别的安全问题",
				criticalCount, highCount))
		}
	}

	// ── 7. 审计日志关键操作 ──
	for _, entry := range audit {
		if entry.Result == "failed" || entry.Result == "error" {
			if containsAny(entry.Action, "kill", "restart", "stop", "delete", "emergency") {
				causes = append(causes, fmt.Sprintf(
					"审计日志记录关键操作失败: %s (操作者: %s, 目标: %s, 原因: %s)",
					entry.Action, entry.Actor, entry.Target, entry.Reason))
				break
			}
		}
		if entry.Action == "emergency_stop" {
			causes = append(causes, fmt.Sprintf(
				"触发了紧急停止: %s (操作者: %s)。系统进入紧急模式后所有自动修复动作暂停",
				entry.Reason, entry.Actor))
			break
		}
	}

	// ── 汇总 ──
	if len(causes) == 0 {
		// 没有发现明确根因时，提供可操作的建议而不是笼统的话
		// 分析是否有任何数据
		dataSources := 0
		if len(alerts) > 0 {
			dataSources++
		}
		if len(attacks) > 0 {
			dataSources++
		}
		if len(cpuMetrics) > 0 {
			dataSources++
		}
		if len(actions) > 0 {
			dataSources++
		}
		if len(audit) > 0 {
			dataSources++
		}

		if dataSources == 0 {
			return "该时间段内无任何监控数据（告警、指标、操作、审计日志均为空）。可能原因: ① Agent 未启动或处于 Survival 模式只发心跳；② 数据库被重置；③ 选择的时间范围超出数据保留期。建议: 确认 Agent 运行状态，检查数据库路径，或缩小时间范围到最近 1 小时内重试。"
		}

		return fmt.Sprintf(
			"该时间段内有 %d 条告警、%d 个攻击事件、%d 条指标数据、%d 条操作记录，但各项指标均未超过危险阈值，未检测到明确的根因。"+
				"建议排查方向: ① 查看应用自身日志（nginx error.log / php-fpm / mysql slow-query）；"+
				"② 检查该时段是否有外部依赖服务（如 CDN、DNS、第三方 API）不可用；"+
				"③ 确认是否有配置变更或部署操作（查看审计日志中的 config_change / deploy 记录）。",
			len(alerts), len(attacks), len(cpuMetrics), len(actions))
	}

	// 组合根因描述
	result := strings.Join(causes, "\n")
	if len(evidence) > 0 {
		result += "\n\n[分析依据]\n" + strings.Join(evidence, "\n")
	}
	return result
}

// generateLessons 生成有针对性的经验教训
func (g *Generator) generateLessons(report *PostmortemReport, alerts []types.Alert, attacks []storage.AttackEvent, actions []types.ActionResult) string {
	var lessons []string

	// 持续时间
	if report.Duration != "" {
		lessons = append(lessons, fmt.Sprintf("本次故障持续 %s。", report.Duration))
	}

	// 修复动作统计
	successCount := 0
	failCount := 0
	for _, a := range actions {
		if a.Success {
			successCount++
		} else {
			failCount++
		}
	}
	if len(actions) > 0 {
		lessons = append(lessons, fmt.Sprintf("ServerGuard 自动执行了 %d 次修复动作（成功 %d，失败 %d）。", len(actions), successCount, failCount))
		if failCount > successCount && failCount > 0 {
			lessons = append(lessons, "修复失败率较高，建议检查: 目标进程是否有子进程自动重启、是否存在依赖链导致 kill 后级联故障、执行权限是否充足。")
		}
	}

	// 根因相关的建议
	rootCause := report.RootCause

	if strings.Contains(rootCause, "CPU") {
		lessons = append(lessons, "针对 CPU 过载: ① 使用 top/htop 定位高 CPU 进程；② 检查是否有异常定时任务或挖矿进程；③ 考虑配置 systemd CPUQuota 限制；④ 必要时横向扩容或升级实例规格。")
	}
	if strings.Contains(rootCause, "内存") || strings.Contains(rootCause, "OOM") {
		lessons = append(lessons, "针对内存不足: ① 检查进程内存趋势，定位内存泄漏；② 增大 Swap 作为应急缓冲；③ 配置 systemd MemoryMax 限制单进程内存；④ 考虑升级内存或迁移到更大实例。")
	}
	if strings.Contains(rootCause, "Swap") {
		lessons = append(lessons, "针对 Swap 频繁换页: ① 增加物理内存；② 调整 swappiness 参数（建议 10-20）；③ 检查是否有不活跃的大内存进程可以优化。")
	}
	if strings.Contains(rootCause, "磁盘") {
		lessons = append(lessons, "针对磁盘满: ① 执行 du -sh /* 定位大目录；② 清理日志、临时文件和 Docker 镜像；③ 配置日志轮转策略（logrotate）；④ 设置磁盘容量预警阈值。")
	}
	if strings.Contains(rootCause, "负载") || strings.Contains(rootCause, "Load") {
		lessons = append(lessons, "针对系统负载过高: ① 区分 CPU 密集（%us 高）还是 I/O 密集（%wa 高）；② I/O 瓶颈考虑升级 SSD 或检查磁盘队列；③ CPU 瓶颈考虑限流或扩容。")
	}
	if strings.Contains(rootCause, "DDoS") || strings.Contains(rootCause, "网络入站") || strings.Contains(rootCause, "流量") {
		lessons = append(lessons, "针对网络流量异常: ① 检查是否有 DDoS 攻击，必要时启用 CDN 或 WAF；② 使用 iftop/nethogs 定位流量来源；③ 配置防火墙 rate limiting。")
	}
	if strings.Contains(rootCause, "攻击") || strings.Contains(rootCause, "attack") {
		// 统计攻击类型
		attackTypes := map[string]int{}
		for _, a := range attacks {
			attackTypes[attackTypeLabel(a.EventType)]++
		}
		var typeSummary []string
		for t, c := range attackTypes {
			typeSummary = append(typeSummary, fmt.Sprintf("%s(%d次)", t, c))
		}
		sort.Strings(typeSummary)
		lessons = append(lessons, fmt.Sprintf("针对攻击事件（%s）: ① 检查防火墙规则是否已封禁恶意 IP；② 审查 Web 应用是否存在对应漏洞（如 SQL 注入、XSS）；③ 考虑接入 WAF 或 CDN 防护；④ 对高频攻击类型加强监控告警阈值。", strings.Join(typeSummary, "、")))
	}
	if strings.Contains(rootCause, "安全发现") || strings.Contains(rootCause, "security") {
		lessons = append(lessons, "针对安全问题: ① 优先修复 critical/high 级别发现项；② 在 ServerGuard 面板「安全发现」页面使用自动修复功能；③ 定期执行全量安全扫描。")
	}
	if strings.Contains(rootCause, "修复动作失败") || strings.Contains(rootCause, "failed") {
		lessons = append(lessons, "针对自动修复失败: ① 检查目标进程是否有 systemd 自动重启（会导致 kill 后立即恢复）；② 考虑使用 restart 替代 kill；③ 排查级联故障可能性。")
	}
	if strings.Contains(rootCause, "紧急停止") {
		lessons = append(lessons, "针对紧急停止触发: ① 审查触发原因（kill 超限、回滚失败、级联恶化）；② 在确认系统稳定后手动恢复；③ 调整 kill 预算阈值或白名单配置。")
	}
	if strings.Contains(rootCause, "审计日志") {
		lessons = append(lessons, "针对操作失败: ① 审查相关配置变更是否符合预期；② 加强操作前预检查；③ 考虑回滚到上一个已知良好配置。")
	}
	if strings.Contains(rootCause, "无任何监控数据") {
		lessons = append(lessons, "针对数据缺失: ① 确认 Agent 进程正常运行（systemctl status serverguard-agent）；② 检查数据库文件是否存在且未损坏；③ 查看 Agent 日志排查启动失败原因。")
	}
	if strings.Contains(rootCause, "未超过危险阈值") {
		lessons = append(lessons, "针对未明确根因: ① 查看 Nginx/Apache error.log 确认是否有 5xx 错误；② 检查 PHP-FPM / MySQL / Redis 等后端服务状态；③ 确认 DNS 解析是否正常；④ 检查 SSL 证书是否过期。")
	}

	// 告警聚类建议
	if len(alerts) > 0 {
		alertSources := map[string]int{}
		for _, a := range alerts {
			alertSources[a.Source]++
		}
		for source, count := range alertSources {
			if count >= 5 {
				lessons = append(lessons, fmt.Sprintf("「%s」模块告警 %d 次，建议针对该模块做专项排查。", source, count))
			}
		}
	}

	if len(lessons) <= 1 {
		lessons = append(lessons, "建议定期巡检，及时发现潜在风险。")
	}

	lessons = append(lessons, "建议将本次经验记录到知识库，避免同类故障再次发生。")

	return strings.Join(lessons, "\n")
}

// ── 辅助函数 ──

func alertSeverityWeight(level types.AlertLevel) int {
	switch level {
	case types.AlertFatal:
		return 5
	case types.AlertCritical:
		return 4
	case types.AlertWarning:
		return 3
	case types.AlertInfo:
		return 1
	default:
		return 0
	}
}

func attackSeverityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func attackTypeLabel(eventType string) string {
	labels := map[string]string{
		"sql_injection":        "SQL注入",
		"xss":                  "XSS跨站脚本",
		"cc_attack":            "CC攻击",
		"webshell_upload":      "Webshell上传",
		"dir_traversal":        "目录遍历",
		"directory_traversal":  "目录遍历",
		"directory_brute":      "目录爆破",
		"ssh_brute_force":      "SSH暴力破解",
		"port_scan":            "端口扫描",
		"ddos_suspected":       "疑似DDoS",
		"ddos":                 "DDoS攻击",
		"data_exfiltration":    "数据外泄",
		"malicious_crawler":    "恶意爬虫",
		"rate_limit_violation": "频率超限",
		"ban_limit_reached":    "封禁上限",
	}
	if label, ok := labels[eventType]; ok {
		return label
	}
	return eventType
}

func groupAlerts(alerts []types.Alert) map[string][]types.Alert {
	groups := map[string][]types.Alert{}
	for _, a := range alerts {
		groups[a.Source] = append(groups[a.Source], a)
	}
	return groups
}

func uniqueAlertTitles(alerts []types.Alert) []string {
	seen := map[string]bool{}
	var titles []string
	for _, a := range alerts {
		if !seen[a.Title] {
			seen[a.Title] = true
			titles = append(titles, a.Title)
		}
	}
	return titles
}

func containsAny(s string, substrs ...string) bool {
	sLower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(sLower, sub) {
			return true
		}
	}
	return false
}

// FormatPostmortem 格式化复盘报告为文本
func FormatPostmortem(report *PostmortemReport) string {
	if report == nil {
		return "故障复盘报告：无数据"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "【故障复盘报告】%s\n", report.IncidentID)
	fmt.Fprintf(&sb, "标题: %s\n", report.Title)
	fmt.Fprintf(&sb, "级别: %s\n", report.Severity)
	fmt.Fprintf(&sb, "时间: %s ~ %s（持续 %s）\n",
		report.StartTime.Format("01-02 15:04"), report.EndTime.Format("01-02 15:04"), report.Duration)
	fmt.Fprintf(&sb, "\n📋 摘要: %s\n", report.Summary)

	if len(report.Timeline) > 0 {
		sb.WriteString("\n📊 事件时间线:\n")
		for _, item := range report.Timeline {
			icon := "📌"
			switch item.Type {
			case "alert":
				icon = "🚨"
			case "action":
				icon = "🔧"
			case "recovery":
				icon = "✅"
			case "audit":
				icon = "📝"
			case "attack":
				icon = "⚔️"
			}
			fmt.Fprintf(&sb, "  %s %s %s\n", icon, item.Timestamp.Format("15:04:05"), item.Message)
		}
	}

	if report.RootCause != "" {
		fmt.Fprintf(&sb, "\n🔍 根因分析:\n%s\n", report.RootCause)
	}

	if len(report.Actions) > 0 {
		sb.WriteString("\n🛠 修复动作:\n")
		for _, a := range report.Actions {
			icon := "✅"
			if !a.Success {
				icon = "❌"
			}
			fmt.Fprintf(&sb, "  %s %s %s\n", icon, a.Time.Format("15:04"), a.Message)
		}
	}

	if report.LessonsLearned != "" {
		fmt.Fprintf(&sb, "\n💡 经验教训:\n%s\n", report.LessonsLearned)
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len([]rune(s)) <= maxLen {
		return s
	}
	return string([]rune(s)[:maxLen]) + "..."
}
