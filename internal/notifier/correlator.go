package notifier

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// correlator.go —— 智能告警降噪。
//
// 两层机制：
//  1. 抖动抑制（Flapping）：同一告警（级别|来源|标题）10 分钟内出现 ≥3 次，
//     自动静默 30 分钟并一次性告知，避免"告警风暴"刷屏。
//  2. 关联归并（Incident）：从告警中提取来源 IP，同一 IP 在 15 分钟窗口内
//     触发 ≥2 类不同告警时，合并为一条"关联事件"推送——同一来源的端口扫描 +
//     WebShell + CPU 飙升往往是一次完整攻击链，合并后更值得关注。

const (
	flapWindow      = 10 * time.Minute
	flapThreshold   = 3
	flapMuteFor     = 30 * time.Minute
	incidentWindow  = 15 * time.Minute
	incidentResend  = 10 * time.Minute // 关联事件更新摘要的最小间隔
	maxIncidentAlrt = 50               // 单事件最多保留的告警条数（防爆内存）
)

var ipRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// TrackResult 关联跟踪结果。
type TrackResult int

const (
	TrackPass   TrackResult = iota // 无关联，走正常逐条推送
	TrackMerge                     // 达到多类告警条件，应发送合并后的关联事件
	TrackAbsorb                    // 已被关联事件吸收，不再单独推送
)

// incident 一个进行中的关联事件。
type incident struct {
	key           string
	alerts        []types.Alert
	rules         map[string]bool
	summarized    bool
	summaryCount  int // 上次摘要包含的告警条数
	lastSummaryAt time.Time
	lastAlertAt   time.Time
}

// correlator 告警关联器（仅影响通知推送，告警落库不受影响）。
type correlator struct {
	mu sync.Mutex

	// 抖动抑制
	fpHits  map[string][]time.Time // fingerprint -> 命中时间序列
	fpMuted map[string]time.Time   // fingerprint -> 静默截止时间

	// 关联事件
	incidents map[string]*incident // 来源 IP -> 事件
}

func newCorrelator() *correlator {
	return &correlator{
		fpHits:    make(map[string][]time.Time),
		fpMuted:   make(map[string]time.Time),
		incidents: make(map[string]*incident),
	}
}

// correlationKey 提取告警的关联键（来源 IP）。无 IP 返回空串（不参与归并）。
func correlationKey(a types.Alert) string {
	for _, k := range []string{"ip", "src_ip", "source_ip", "target_ip", "target", "attacker"} {
		if v := strings.TrimSpace(a.Labels[k]); v != "" && ipRegex.MatchString(v) {
			return ipRegex.FindString(v)
		}
	}
	ip := ipRegex.FindString(a.Title + " " + a.Message)
	if ip == "" || strings.HasPrefix(ip, "127.") || ip == "0.0.0.0" {
		return ""
	}
	return ip
}

// CheckFlapping 记录一次告警命中，返回 (是否静默, 是否首次触发静默需告知)。
func (c *correlator) CheckFlapping(fp string, now time.Time) (muted bool, notice bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if until, ok := c.fpMuted[fp]; ok {
		if now.Before(until) {
			return true, false
		}
		// 静默期结束，重置计数重新开始
		delete(c.fpMuted, fp)
		c.fpHits[fp] = nil
	}

	// 滑动窗口计数
	cutoff := now.Add(-flapWindow)
	hits := c.fpHits[fp]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	c.fpHits[fp] = kept

	if len(kept) >= flapThreshold {
		c.fpMuted[fp] = now.Add(flapMuteFor)
		return true, true
	}
	return false, false
}

// Track 将告警纳入关联事件跟踪，返回应采取的推送动作。
// ready 为非 nil 时，表示应立即以该合并摘要推送（TrackMerge）。
func (c *correlator) Track(a types.Alert, now time.Time) (TrackResult, *types.Alert) {
	key := correlationKey(a)
	if key == "" {
		return TrackPass, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	inc, ok := c.incidents[key]
	if !ok || now.Sub(inc.lastAlertAt) > incidentWindow {
		// 新事件（或旧事件已过期重建）
		inc = &incident{key: key, rules: make(map[string]bool)}
		c.incidents[key] = inc
	}

	inc.lastAlertAt = now
	if len(inc.alerts) < maxIncidentAlrt {
		inc.alerts = append(inc.alerts, a)
	}
	ruleKey := a.RuleID
	if ruleKey == "" {
		ruleKey = a.Title
	}
	isNewRule := !inc.rules[ruleKey]
	inc.rules[ruleKey] = true

	switch {
	case !inc.summarized && len(inc.rules) >= 2 && isNewRule:
		// 达到"同源多类告警"条件：合并推送
		inc.summarized = true
		inc.lastSummaryAt = now
		inc.summaryCount = len(inc.alerts)
		summary := buildIncidentSummary(inc, false)
		return TrackMerge, &summary
	case inc.summarized:
		// 事件已推送过，后续告警吸入等待周期摘要
		return TrackAbsorb, nil
	default:
		// 事件内首个规则，正常逐条推送
		return TrackPass, nil
	}
}

// Flush 周期调用：为有新告警的关联事件生成更新摘要，并清理过期状态。
func (c *correlator) Flush(now time.Time) []types.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []types.Alert
	for key, inc := range c.incidents {
		// 过期清理：窗口内无新告警
		if now.Sub(inc.lastAlertAt) > incidentWindow {
			delete(c.incidents, key)
			continue
		}
		// 有未摘要的新告警且距上次摘要足够久 → 发送更新
		if inc.summarized && len(inc.alerts) > inc.summaryCount && now.Sub(inc.lastSummaryAt) >= incidentResend {
			inc.lastSummaryAt = now
			inc.summaryCount = len(inc.alerts)
			out = append(out, buildIncidentSummary(inc, true))
		}
	}

	// 顺带清理陈旧的抖动计数（1 小时无命中）
	for fp, hits := range c.fpHits {
		if len(hits) == 0 || now.Sub(hits[len(hits)-1]) > time.Hour {
			delete(c.fpHits, fp)
		}
	}
	for fp, until := range c.fpMuted {
		if now.After(until.Add(time.Hour)) {
			delete(c.fpMuted, fp)
		}
	}
	return out
}

// buildIncidentSummary 把关联事件内的告警合并为一条摘要。
func buildIncidentSummary(inc *incident, isUpdate bool) types.Alert {
	// 最高级别
	maxLevel := types.AlertInfo
	rank := map[types.AlertLevel]int{
		types.AlertInfo: 0, types.AlertWarning: 1, types.AlertError: 2,
		types.AlertCritical: 3, types.AlertFatal: 4,
	}
	for _, a := range inc.alerts {
		if rank[a.Level] > rank[maxLevel] {
			maxLevel = a.Level
		}
	}

	// 按规则聚合计数
	type ruleStat struct {
		title string
		level types.AlertLevel
		count int
		first time.Time
	}
	order := []string{}
	stats := map[string]*ruleStat{}
	for _, a := range inc.alerts {
		k := a.RuleID
		if k == "" {
			k = a.Title
		}
		st, ok := stats[k]
		if !ok {
			st = &ruleStat{title: a.Title, level: a.Level, first: a.Timestamp}
			stats[k] = st
			order = append(order, k)
		}
		st.count++
	}

	var sb strings.Builder
	if isUpdate {
		fmt.Fprintf(&sb, "关联事件更新：来源 %s 又有新动态\n\n", inc.key)
	} else {
		fmt.Fprintf(&sb, "检测到针对来源 %s 的复合行为：\n\n", inc.key)
	}
	for _, k := range order {
		st := stats[k]
		line := fmt.Sprintf("• %s [%s] %s", st.first.Format("15:04:05"), st.level, st.title)
		if st.count > 1 {
			line += fmt.Sprintf("（×%d）", st.count)
		}
		sb.WriteString(line + "\n")
	}
	fmt.Fprintf(&sb, "\n同一来源在 %d 分钟内触发 %d 类告警（共 %d 条），往往指向一次完整的攻击链或连环故障，建议立即排查该来源。",
		int(incidentWindow.Minutes()), len(inc.rules), len(inc.alerts))

	title := fmt.Sprintf("关联事件：%s 触发 %d 类告警", inc.key, len(inc.rules))
	if isUpdate {
		title = fmt.Sprintf("关联事件更新：%s（累计 %d 条）", inc.key, len(inc.alerts))
	}
	return types.Alert{
		Level:     maxLevel,
		Title:     title,
		Source:    "correlator",
		Message:   sb.String(),
		Timestamp: time.Now(),
	}
}

// flappingNotice 构造"已自动静默"告知告警。
func flappingNotice(fp string) types.Alert {
	parts := strings.SplitN(fp, "|", 3)
	title := fp
	if len(parts) == 3 {
		title = parts[2]
	}
	return types.Alert{
		Level:  types.AlertWarning,
		Title:  fmt.Sprintf("智能降噪：「%s」已自动静默 30 分钟", title),
		Source: "correlator",
		Message: fmt.Sprintf("告警「%s」在 %d 分钟内重复出现 %d 次以上，判定为抖动告警。\n为防刷屏已自动静默 %d 分钟（告警仍会记录在告警中心，仅暂停推送）。\n若该问题持续存在，静默期结束后会恢复提醒。",
			title, int(flapWindow.Minutes()), flapThreshold, int(flapMuteFor.Minutes())),
		Timestamp: time.Now(),
	}
}
