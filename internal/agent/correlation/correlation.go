// Package correlation 实现根因链推理：把时间窗口内的多条告警按因果规则
// 关联成一条故障链（Incident），用一条带因果关系的汇总告警替代 N 条孤立告警。
//
// 设计原则（零风险）：
//   - 只观察不拦截：原始告警照常流动（P0 延迟不变），本引擎是旁路后处理器；
//   - 因果判定全部是确定性规则（时间序 + 领域规则 + 同源连锁），可解释可调优；
//   - 链长 ≥2 才生成事件，单条告警不产生噪音；
//   - 事件解决后自动沉淀到故障知识库，形成"越用越聪明"的闭环。
package correlation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/knowledge"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// 领域因果规则：root 关键词匹配的告警会导致 effect 关键词匹配的告警。
// 全部小写匹配。规则的解释会附在事件里（"依据：数据库类故障通常引发超时类症状"）。
var causalRules = []struct {
	name    string
	root    []string
	effect  []string
	explain string
}{
	{
		name:    "数据库故障→服务超时",
		root:    []string{"mysql", "mariadb", "postgres", "redis", "mongo", "数据库", "慢查询", "connection refused"},
		effect:  []string{"超时", "timeout", "502", "504", "upstream", "api", "响应", "latency", "探活失败", "健康检查失败"},
		explain: "数据库层故障通常引发依赖它的 Web/API 服务超时或错误",
	},
	{
		name:    "CPU/负载过高→响应劣化",
		root:    []string{"cpu", "负载", "load"},
		effect:  []string{"超时", "timeout", "慢", "slow", "502", "延迟", "latency", "卡顿"},
		explain: "CPU 饱和会导致所有计算密集型服务响应劣化",
	},
	{
		name:    "磁盘空间/IO→写入失败",
		root:    []string{"磁盘", "disk", "空间不足", "inode"},
		effect:  []string{"写入失败", "write", "数据库", "日志", "无法保存", "no space"},
		explain: "磁盘满/IO 瓶颈会引发依赖写入的服务报错",
	},
	{
		name:    "内存不足→进程被杀",
		root:    []string{"内存", "memory", "oom", "swap"},
		effect:  []string{"被杀", "killed", "重启", "restart", "挂", "宕", "退出", "exit"},
		explain: "内存耗尽会触发 OOM Killer 杀掉进程，表现为进程退出/重启",
	},
	{
		name:    "网络/DNS 故障→外部不可达",
		root:    []string{"网络", "network", "dns", "丢包", "packet loss"},
		effect:  []string{"超时", "timeout", "502", "504", "unreachable", "无法连接", "探活失败"},
		explain: "网络/DNS 层故障导致所有外部访问超时或不可达",
	},
	{
		name:    "证书问题→访问异常",
		root:    []string{"证书", "cert", "ssl", "tls", "https"},
		effect:  []string{"过期", "访问失败", "浏览器", "握手", "handshake"},
		explain: "证书过期或配置错误导致 HTTPS 访问异常",
	},
	{
		name:    "进程崩溃→服务不可用",
		root:    []string{"崩溃", "crash", "segfault", "panic", "coredump", "信号", "signal"},
		effect:  []string{"不可用", "unavailable", "503", "502", "连接拒绝", "connection refused", "探活失败", "健康检查失败"},
		explain: "进程崩溃后依赖它的服务会返回 503/502 或探活失败",
	},
	{
		name:    "磁盘IO高→服务慢",
		root:    []string{"磁盘IO", "iowait", "io wait", "读写延迟", "disk latency"},
		effect:  []string{"慢", "slow", "超时", "timeout", "延迟", "latency", "卡顿"},
		explain: "磁盘 IO 瓶颈会导致依赖磁盘读写的服务响应变慢",
	},
	{
		name:    "连接数耗尽→新连接拒绝",
		root:    []string{"连接数", "fd", "文件描述符", "ulimit", "conn limit", "max connection"},
		effect:  []string{"拒绝", "refused", "502", "503", "无法连接", "connection refused"},
		explain: "连接数/FD 耗尽后新连接被拒绝，表现为 502/503",
	},
	{
		name:    "防火墙/封禁→访问不可达",
		root:    []string{"防火墙", "firewall", "iptables", "封禁", "ban", "block"},
		effect:  []string{"不可达", "unreachable", "无法连接", "timeout", "超时", "访问失败"},
		explain: "防火墙规则或 IP 封禁导致目标不可达",
	},
	{
		name:    "配置变更→服务异常",
		root:    []string{"配置", "config", "reload", "nginx.*reload", "重启服务"},
		effect:  []string{"502", "503", "504", "超时", "timeout", "报错", "error", "不可用", "unavailable"},
		explain: "配置变更后服务可能出现短暂异常或持续故障",
	},
}

const (
	alertWindow  = 5 * time.Minute  // 告警关联窗口
	actionWindow = 10 * time.Minute // 处置动作关联窗口
	resolveAge   = 10 * time.Minute // 无新成员后判定事件解决
	engineSource = "correlation"
	// 同源告警连续出现视为连锁反应（如服务守护反复拉起失败）
	sameSourceChainGap = 3 * time.Minute

	// 风暴防护硬上限：缓冲条数封顶（超限丢最旧的，防止告警风暴下无界增长）
	maxAlertsBuffered = 300
	maxActionsBuffered = 300
	// 单次关联参与两两配对的告警上限（O(n²) 热路径，持锁执行）
	maxCorrelateInput = 80
	// 事件落库节流：风暴期间同一事件的成员变化不必每次告警都落库
	incidentSaveThrottle = 30 * time.Second
)

// Engine 根因链推理引擎。
type Engine struct {
	bus  *eventbus.EventBus
	db   *storage.Storage
	kb   *knowledge.KnowledgeBase
	mu   sync.Mutex
	open map[string]*types.Incident // 进行中的事件（按根因指纹）
	buf  []types.Event              // 最近告警
	act  []types.Event              // 最近动作

	// 因果规则自我验证：统计每条领域规则"参与的事件是否真的触发了自动处置"，
	// 长期零确认的规则自动停用一段时间——让关联引擎越用越准而不是永远拍脑袋。
	ruleFeedback       map[string]*ruleStat
	suspendedRules     map[string]time.Time // 规则名 -> 停用到期时间
	confirmedIncidents map[string]bool      // 已计入确认的事件 ID（防重复计数）

	// 事件落库节流时间戳（风暴防护）
	lastIncidentSave time.Time
}

// ruleStat 单条因果规则的验证统计。
type ruleStat struct {
	Applied   int `json:"applied"`   // 参与过的事件数
	Confirmed int `json:"confirmed"` // 其中后续真的触发自动处置的事件数
}

// 自我验证参数。
const (
	// ruleVerifyMinSamples 触发停用评估的最少样本数——宁可慢一点下结论，不误杀好规则
	ruleVerifyMinSamples = 20
	// ruleSuspendDuration 零确认规则停用时长，到期自动恢复重新观察
	ruleSuspendDuration = 7 * 24 * time.Hour
)

// New 创建引擎并订阅事件总线上的告警与动作事件。
func New(bus *eventbus.EventBus, db *storage.Storage, kb *knowledge.KnowledgeBase) *Engine {
	e := &Engine{
		bus:                bus,
		db:                 db,
		kb:                 kb,
		open:               make(map[string]*types.Incident),
		ruleFeedback:       make(map[string]*ruleStat),
		suspendedRules:     make(map[string]time.Time),
		confirmedIncidents: make(map[string]bool),
	}
	if bus != nil {
		bus.Subscribe(types.EventAlert, e.onAlert)
		bus.Subscribe(types.EventAction, e.onAction)
	}
	return e
}

// ruleSuspended 判断某条因果规则当前是否被停用（调用方持有 e.mu）。
func (e *Engine) ruleSuspendedLocked(name string) bool {
	until, ok := e.suspendedRules[name]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(e.suspendedRules, name) // 停用期满，恢复观察
		return false
	}
	return true
}

// Run 周期性收尾：关闭沉寂事件并沉淀知识。
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "[correlation] closeStaleIncidents panicked: %v\n", r)
					}
				}()
				e.closeStaleIncidents()
			}()
		}
	}
}

func (e *Engine) onAlert(ev types.Event) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[correlation] onAlert panicked: %v (event: %s/%s)\n", r, ev.Source, ev.Title)
		}
	}()
	// 自己发布的汇总告警不参与关联，避免自循环
	if ev.Source == engineSource {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.buf = append(e.buf, ev)
	e.trimLocked()
	e.correlateLocked()
}

func (e *Engine) onAction(ev types.Event) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[correlation] onAction panicked: %v (event: %s/%s)\n", r, ev.Source, ev.Title)
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.act = append(e.act, ev)
	e.trimLocked()
	e.attachActionsLocked()
}

func (e *Engine) trimLocked() {
	cut := time.Now().Add(-actionWindow)
	var alerts, actions []types.Event
	for _, ev := range e.buf {
		if ev.Timestamp.After(cut) {
			alerts = append(alerts, ev)
		}
	}
	for _, ev := range e.act {
		if ev.Timestamp.After(cut) {
			actions = append(actions, ev)
		}
	}
	e.buf, e.act = alerts, actions

	// 风暴硬上限：时间窗裁剪不够——告警风暴可在 10 分钟内积压数万条，
	// 每条新告警都触发 O(n²) 关联会把事件总线卡死。超限丢最旧的。
	if len(e.buf) > maxAlertsBuffered {
		e.buf = e.buf[len(e.buf)-maxAlertsBuffered:]
	}
	if len(e.act) > maxActionsBuffered {
		e.act = e.act[len(e.act)-maxActionsBuffered:]
	}
}

// alertKey 提取告警的可匹配文本。
func alertKey(ev types.Event) string {
	return strings.ToLower(ev.Title + " " + ev.Message)
}

// ruleBetween 判断 earlier 告警是否可能导致了 later 告警，命中返回规则名。
// suspended 为当前被自我验证机制停用的规则集合（nil 表示全部可用）。
func ruleBetween(earlier, later types.Event, suspended map[string]time.Time) (string, bool) {
	a, b := alertKey(earlier), alertKey(later)
	if a == "" || b == "" {
		return "", false
	}
	now := time.Now()
	for _, r := range causalRules {
		// 被停用的规则不参与关联（停用期满自动恢复）
		if until, ok := suspended[r.name]; ok {
			if now.Before(until) {
				continue
			}
		}
		rootHit, effectHit := false, false
		for _, kw := range r.root {
			if strings.Contains(a, kw) {
				rootHit = true
				break
			}
		}
		if !rootHit {
			continue
		}
		for _, kw := range r.effect {
			if strings.Contains(b, kw) {
				effectHit = true
				break
			}
		}
		if rootHit && effectHit {
			return r.name, true
		}
	}
	return "", false
}

// buildChains 在告警缓冲上推导因果边（并查集聚类）。
// suspended：被自我验证机制停用的规则集合。
func buildChains(alerts []types.Event, suspended map[string]time.Time) ([][]int, []types.ChainLink) {
	n := len(alerts)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	var chain []types.ChainLink
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			// 时间序：i 必须早于 j（允许 1s 抖动）
			if alerts[j].Timestamp.Before(alerts[i].Timestamp.Add(-time.Second)) {
				continue
			}
			linked, via := false, ""
			if rule, ok := ruleBetween(alerts[i], alerts[j], suspended); ok {
				linked, via = true, "domain-rule:"+rule
			} else if alerts[i].Source == alerts[j].Source &&
				alerts[j].Timestamp.Sub(alerts[i].Timestamp) < sameSourceChainGap {
				linked, via = true, "same-source"
			}
			if linked {
				union(i, j)
				chain = append(chain, types.ChainLink{
					From: alerts[i].Title,
					To:   alerts[j].Title,
					Via:  via,
				})
			}
		}
	}

	groups := make(map[int][]int)
	for i := 0; i < n; i++ {
		root := find(i)
		groups[root] = append(groups[root], i)
	}
	var out [][]int
	for _, g := range groups {
		if len(g) >= 2 {
			out = append(out, g)
		}
	}
	return out, chain
}

// fingerprint 事件的分组指纹：按根因标题+来源归并（避免同一故障开多个事件）。
func fingerprint(root types.Event) string {
	return root.Source + "|" + normalizeTitle(root.Title)
}

// normalizeTitle 去掉标题中的数字/百分比等易变部分，让同类告警命中同一指纹。
func normalizeTitle(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= '0' && r <= '9' || r == '.' || r == '%' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// correlateLocked 在每个新告警后尝试关联（调用方持锁）。
func (e *Engine) correlateLocked() {
	window := time.Now().Add(-alertWindow)
	var recent []types.Event
	for _, ev := range e.buf {
		if ev.Timestamp.After(window) {
			recent = append(recent, ev)
		}
	}
	// O(n²) 截断：只对最新的 maxCorrelateInput 条做两两配对（时间序保证
	// 最新的在尾部），风暴下宁可少关联也不能卡死事件总线
	if len(recent) > maxCorrelateInput {
		recent = recent[len(recent)-maxCorrelateInput:]
	}
	groups, chain := buildChains(recent, e.suspendedRules)
	now := time.Now()

	for _, g := range groups {
		// 组内最早且级别最高的告警作为根因
		root := g[0]
		for _, idx := range g {
			if recent[idx].Timestamp.Before(recent[root].Timestamp) {
				root = idx
			}
		}

		fp := fingerprint(recent[root])
		inc, exists := e.open[fp]
		if !exists {
			inc = &types.Incident{
				ID:        storage.NewIncidentID(),
				StartedAt: now,
				Status:    "open",
				RootTitle: recent[root].Title,
				RootSource: recent[root].Source,
				RootTime:  recent[root].Timestamp,
				Summary:   "",
			}
			e.open[fp] = inc
		}

		// 合并组成员（去重），更新链与动作
		for _, idx := range g {
			ref := types.AlertRef{
				AlertID: recent[idx].ID,
				Title:   recent[idx].Title,
				Source:  recent[idx].Source,
				Level:   recent[idx].Level,
				Time:    recent[idx].Timestamp,
			}
			if !containsRef(inc.MemberAlerts, ref) {
				inc.MemberAlerts = append(inc.MemberAlerts, ref)
			}
		}
		inc.Chain = chainFor(chain, inc.MemberAlerts)
		e.attachActionsToIncidentLocked(inc)

		if !exists {
			// 新事件：记录参与的因果规则（自我验证的 applied 样本）
			e.recordRuleAppliedLocked(inc)
			// 新事件：发布汇总告警（带因果链 + 知识库建议）
			inc.Summary = e.buildSummary(inc)
			e.publishIncidentAlert(inc)
			if e.db != nil {
				_ = e.db.SaveIncident(*inc)
			}
			continue
		}
		// 已有事件的成员/链更新：落库节流——风暴期间同一事件每条告警都
		// 全量落库会放大 SQLite 写压力（持锁执行），30 秒落一次足够
		if e.db != nil && now.Sub(e.lastIncidentSave) >= incidentSaveThrottle {
			_ = e.db.SaveIncident(*inc)
			e.lastIncidentSave = now
		}
	}
}

// recordRuleAppliedLocked 记录事件链中出现的领域规则（applied 样本，调用方持锁）。
func (e *Engine) recordRuleAppliedLocked(inc *types.Incident) {
	for _, l := range inc.Chain {
		if !strings.HasPrefix(l.Via, "domain-rule:") {
			continue
		}
		name := strings.TrimPrefix(l.Via, "domain-rule:")
		st := e.ruleFeedback[name]
		if st == nil {
			st = &ruleStat{}
			e.ruleFeedback[name] = st
		}
		st.Applied++
	}
}

// recordRuleConfirmedLocked 事件首次挂上自动处置动作时，
// 给链上的每条领域规则记一次"确认"——预测引发了真实处置（调用方持锁）。
func (e *Engine) recordRuleConfirmedLocked(inc *types.Incident) {
	if len(inc.Actions) == 0 || inc.ID == "" || e.confirmedIncidents[inc.ID] {
		return
	}
	e.confirmedIncidents[inc.ID] = true
	for _, l := range inc.Chain {
		if !strings.HasPrefix(l.Via, "domain-rule:") {
			continue
		}
		name := strings.TrimPrefix(l.Via, "domain-rule:")
		st := e.ruleFeedback[name]
		if st == nil {
			st = &ruleStat{}
			e.ruleFeedback[name] = st
		}
		st.Confirmed++
		// 自我验证：样本足够且从未得到过一次确认 → 停用观察期
		if st.Applied >= ruleVerifyMinSamples && st.Confirmed == 0 {
			e.suspendedRules[name] = time.Now().Add(ruleSuspendDuration)
			fmt.Fprintf(os.Stderr, "[correlation] 因果规则 %q 已参与 %d 次事件但零确认，停用 %s 后重新评估\n",
				name, st.Applied, ruleSuspendDuration)
		}
	}
}

// GetRuleStats 返回因果规则的自我验证统计（供面板/诊断）。
func (e *Engine) GetRuleStats() []map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]map[string]interface{}, 0, len(causalRules))
	now := time.Now()
	for _, r := range causalRules {
		st := e.ruleFeedback[r.name]
		m := map[string]interface{}{
			"rule":      r.name,
			"explain":   r.explain,
			"suspended": false,
		}
		if until, ok := e.suspendedRules[r.name]; ok && now.Before(until) {
			m["suspended"] = true
			m["suspend_until"] = until
		}
		if st != nil {
			m["applied"] = st.Applied
			m["confirmed"] = st.Confirmed
			if st.Applied > 0 {
				m["confirm_rate"] = float64(st.Confirmed) / float64(st.Applied)
			}
		}
		out = append(out, m)
	}
	return out
}

func containsRef(refs []types.AlertRef, r types.AlertRef) bool {
	for _, x := range refs {
		if x.AlertID == r.AlertID && x.AlertID != "" {
			return true
		}
		if x.Title == r.Title && x.Source == r.Source && x.Time.Sub(r.Time) < alertWindow {
			return true
		}
	}
	return false
}

// chainFor 过滤出事件成员之间的因果边。
func chainFor(all []types.ChainLink, members []types.AlertRef) []types.ChainLink {
	titleSet := make(map[string]bool, len(members))
	for _, m := range members {
		titleSet[m.Title] = true
	}
	var out []types.ChainLink
	seen := make(map[string]bool)
	for _, l := range all {
		if titleSet[l.From] && titleSet[l.To] {
			k := l.From + "→" + l.To
			if !seen[k] {
				seen[k] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// attachActionsLocked 把窗口内的自动处置动作挂到匹配的开放事件上。
func (e *Engine) attachActionsLocked() {
	for fp, inc := range e.open {
		before := len(inc.Actions)
		e.attachActionsToIncidentLocked(inc)
		// 挂载了新动作的事件要落库，否则 DB 里的事件永远缺动作记录
		if len(inc.Actions) > before && e.db != nil {
			_ = e.db.SaveIncident(*inc)
			_ = fp
		}
	}
}

func (e *Engine) attachActionsToIncidentLocked(inc *types.Incident) {
	roots := map[string]bool{strings.ToLower(inc.RootTitle): true}
	for _, m := range inc.MemberAlerts {
		roots[strings.ToLower(m.Title)] = true
	}
	for _, a := range e.act {
		if a.Timestamp.Before(inc.RootTime.Add(-time.Minute)) {
			continue
		}
		text := strings.ToLower(a.Title + " " + a.Message)
		matched := false
		for kw := range roots {
			// 动作文本与任一成员告警有词面关联即挂载（动作通常描述"重启了 X"）
			for _, word := range strings.Fields(kw) {
				if len(word) >= 3 && strings.Contains(text, word) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		// 没有词面关联时，时间上紧跟根因的动作也计入（自愈动作往往紧跟告警）
		if !matched && a.Timestamp.Sub(inc.RootTime) < 2*time.Minute {
			matched = true
		}
		if matched {
			desc := fmt.Sprintf("[%s] %s %s", a.Timestamp.Format("15:04:05"), a.Title, a.Message)
			exists := false
			for _, x := range inc.Actions {
				if x == desc {
					exists = true
					break
				}
			}
			if !exists {
				inc.Actions = append(inc.Actions, desc)
			}
		}
	}
	// 事件首次有真实处置动作 → 给链上的因果规则记一次确认（自我验证闭环）
	if len(inc.Actions) > 0 {
		e.recordRuleConfirmedLocked(inc)
	}
}

// Recommend 查询知识库中相似故障的处置经验（知识库反哺）。
func (e *Engine) Recommend(symptom, source string) string {
	if e.kb == nil {
		return ""
	}
	entries, err := e.kb.FindSimilar(symptom, source, 3)
	if err != nil || len(entries) == 0 {
		return ""
	}
	var sb strings.Builder
	total := 0
	for _, en := range entries {
		total += en.OccurrenceCount
	}
	sb.WriteString(fmt.Sprintf("📚 历史经验：该症状已出现过 %d 次。", total))
	best := entries[0]
	if best.Action != "" {
		result := best.ActionResult
		if result == "" {
			result = "结果未知"
		}
		sb.WriteString(fmt.Sprintf("上次处置：%s（%s，%s）。", best.Action, result, best.LastSeen.Format("2006-01-02 15:04")))
	}
	if len(entries) >= 3 {
		sb.WriteString("该故障反复出现，建议彻底排查根因而非反复重启。")
	}
	return sb.String()
}

// buildSummary 生成"说人话"的事件摘要。
func (e *Engine) buildSummary(inc *types.Incident) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("检测到 %d 条相关告警构成一条故障链。\n", len(inc.MemberAlerts)))
	sb.WriteString(fmt.Sprintf("根因（%s）：%s\n", inc.RootTime.Format("15:04:05"), inc.RootTitle))
	for _, l := range inc.Chain {
		via := l.Via
		if idx := strings.Index(via, ":"); idx > 0 {
			via = via[idx+1:]
		}
		sb.WriteString(fmt.Sprintf("  ↓ 引发：%s（依据：%s）\n", l.To, via))
	}
	if len(inc.Actions) > 0 {
		sb.WriteString(fmt.Sprintf("已自动执行 %d 项处置：%s\n", len(inc.Actions), strings.Join(inc.Actions, "；")))
	}
	if rec := e.Recommend(inc.RootTitle, inc.RootSource); rec != "" {
		sb.WriteString(rec)
	}
	return sb.String()
}

// publishIncidentAlert 发布事件汇总告警（一条替代 N 条）。
func (e *Engine) publishIncidentAlert(inc *types.Incident) {
	if e.bus == nil {
		return
	}
	maxLevel := types.AlertWarning
	for _, m := range inc.MemberAlerts {
		if m.Level == types.AlertCritical {
			maxLevel = types.AlertCritical
			break
		}
		if m.Level == types.AlertError {
			maxLevel = types.AlertError
		}
	}
	e.bus.PublishAlert(maxLevel, engineSource,
		fmt.Sprintf("故障链分析：%s", inc.RootTitle),
		inc.Summary, inc.ID)
}

// closeStaleIncidents 关闭沉寂事件并沉淀知识库。
// 沉寂判定用"最后活动时间"（根因/成员/动作中最晚者）而非根因时间，
// 避免长时间持续演进的故障被提前判定解决。
func (e *Engine) closeStaleIncidents() {
	e.mu.Lock()
	var closed []*types.Incident
	now := time.Now()
	for fp, inc := range e.open {
		if now.Sub(lastIncidentActivity(inc)) < resolveAge {
			continue
		}
		inc.Status = "resolved"
		inc.EndedAt = &now
		inc.Summary = e.buildSummary(inc)
		if e.db != nil {
			_ = e.db.SaveIncident(*inc)
		}
		closed = append(closed, inc)
		delete(e.open, fp)
	}
	e.mu.Unlock()

	// 知识沉淀：解决的事件记入故障知识库，下次同症状直接给出处置建议
	if e.kb != nil {
		for _, inc := range closed {
			result := "success"
			if len(inc.Actions) == 0 {
				result = "no-action"
			}
			e.kb.RecordIncident(knowledge.KnowledgeEntry{
				Symptom:     inc.RootTitle,
				RootCause:   summaryChain(inc),
				Action:      firstAction(inc.Actions),
				ActionResult: result,
				Effect:      fmt.Sprintf("关联 %d 条告警", len(inc.MemberAlerts)),
				Source:      inc.RootSource,
				Severity:    "incident",
				FirstSeen:   inc.RootTime,
				LastSeen:    now,
				ResolvedAt:  now,
			})
		}
	}
}

func firstAction(actions []string) string {
	for _, a := range actions {
		return a
	}
	return ""
}

// lastIncidentActivity 返回事件最后一次有动静的时间（根因/成员取最晚）。
// 动作描述内嵌的时间戳只有时分秒无法参与日期比较，根因与成员时间已足够
// 表达"最后一次告警动静"。
func lastIncidentActivity(inc *types.Incident) time.Time {
	latest := inc.RootTime
	for _, m := range inc.MemberAlerts {
		if m.Time.After(latest) {
			latest = m.Time
		}
	}
	return latest
}

// summaryChain 把因果边序列化为一行文本（存知识库的根因字段）。
func summaryChain(inc *types.Incident) string {
	parts := make([]string, 0, len(inc.Chain)+1)
	parts = append(parts, inc.RootTitle)
	for _, l := range inc.Chain {
		parts = append(parts, "→ "+l.To)
	}
	return strings.Join(parts, " ")
}

// GetIncidents 查询事件（供 API）。
func (e *Engine) GetIncidents(status string, limit int) ([]types.Incident, error) {
	if e.db != nil {
		return e.db.GetIncidents(status, limit)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []types.Incident
	for _, inc := range e.open {
		out = append(out, *inc)
	}
	return out, nil
}
