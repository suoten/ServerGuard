package ruleengine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// RuleEngine matches metrics against rules and triggers actions.
// 向宝塔学习：缓存排序后的规则列表，不每次 Match 都重新排序
type RuleEngine struct {
	mu            sync.RWMutex
	rules         map[string]*types.Rule
	slidingWindow map[string]*SlidingWindow // metric key -> sliding window
	matchTimeout  time.Duration
	storage       StorageQuerier

	// 缓存排序后的规则（AddRule/RemoveRule 时置 true 失效）
	sortedRulesCache []*types.Rule
	rulesDirty       bool
}

// StorageQuerier defines the interface for querying action history from storage.
type StorageQuerier interface {
	GetActionHistoryByRule(ruleID string, since time.Time, limit int) ([]RuleHistoryEntry, error)
}

// SlidingWindow stores recent metric values for duration-based conditions.
type SlidingWindow struct {
	mu      sync.Mutex
	entries []windowEntry
}

type windowEntry struct {
	value     float64
	timestamp time.Time
}

// New creates a new RuleEngine.
func New(matchTimeout time.Duration) *RuleEngine {
	return &RuleEngine{
		rules:         make(map[string]*types.Rule),
		slidingWindow: make(map[string]*SlidingWindow),
		matchTimeout:  matchTimeout,
	}
}

// SetStorage sets the storage backend for history queries.
func (e *RuleEngine) SetStorage(s StorageQuerier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.storage = s
}

// AddRule adds or updates a rule.
func (e *RuleEngine) AddRule(rule types.Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[rule.ID] = &rule
	e.rulesDirty = true // 失效缓存
}

// RemoveRule removes a rule by ID.
func (e *RuleEngine) RemoveRule(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, id)
	e.rulesDirty = true // 失效缓存
}

// GetRules returns all enabled rules sorted by priority (descending).
func (e *RuleEngine) GetRules() []*types.Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var rules []*types.Rule
	for _, r := range e.rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
	return rules
}

// MatchResult represents the result of matching metrics against rules.
type MatchResult struct {
	Rule    *types.Rule
	Metrics []types.Metric
}

// Match checks metrics against all rules and returns matching rules.
func (e *RuleEngine) Match(metrics []types.Metric) []MatchResult {
	e.mu.RLock()
	rules := e.getSortedRules()
	e.mu.RUnlock()

	// Update sliding windows with new metrics
	e.updateSlidingWindows(metrics)

	var matches []MatchResult

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Pre-filter: quickly skip rules whose metrics aren't present
		neededMetrics := e.getNeededMetrics(rule)
		if !e.hasMetrics(neededMetrics, metrics) {
			continue
		}

		// Evaluate trigger conditions
		if e.evaluateGroup(rule.Trigger, metrics) {
			matches = append(matches, MatchResult{
				Rule:    rule,
				Metrics: metrics,
			})
		}
	}

	return matches
}

// evaluateGroup evaluates a group of conditions (AND/OR/NOT).
func (e *RuleEngine) evaluateGroup(group types.ConditionGroup, metrics []types.Metric) bool {
	switch group.Operator {
	case types.OpAnd:
		for _, cond := range group.Conditions {
			if !e.evaluateCondition(cond, metrics) {
				return false
			}
		}
		for _, subGroup := range group.Groups {
			if !e.evaluateGroup(subGroup, metrics) {
				return false
			}
		}
		return true

	case types.OpOr:
		for _, cond := range group.Conditions {
			if e.evaluateCondition(cond, metrics) {
				return true
			}
		}
		for _, subGroup := range group.Groups {
			if e.evaluateGroup(subGroup, metrics) {
				return true
			}
		}
		return false

	case types.OpNot:
		result := false
		for _, cond := range group.Conditions {
			if e.evaluateCondition(cond, metrics) {
				result = true
				break
			}
		}
		return !result

	default:
		return false
	}
}

// evaluateCondition evaluates a single condition against metrics.
func (e *RuleEngine) evaluateCondition(cond types.Condition, metrics []types.Metric) bool {
	// Find matching metrics
	var matchingMetrics []types.Metric
	for _, m := range metrics {
		if m.Name == cond.Metric || strings.HasPrefix(m.Name, cond.Metric+".") {
			matchingMetrics = append(matchingMetrics, m)
		}
	}

	if len(matchingMetrics) == 0 {
		return false
	}

	for _, m := range matchingMetrics {
		if cond.Duration > 0 {
			// Duration-based: check sliding window
			if !e.checkDuration(cond, m) {
				continue
			}
		}

		if e.compareValue(m.Value, cond.Op, cond.Value) {
			return true
		}
	}

	return false
}

// compareValue compares a metric value against a threshold using the operator.
func (e *RuleEngine) compareValue(actual float64, op types.ComparisonOperator, expected interface{}) bool {
	expFloat, ok := toFloat64(expected)
	if !ok {
		return false
	}

	switch op {
	case types.CmpGT:
		return actual > expFloat
	case types.CmpGTE:
		return actual >= expFloat
	case types.CmpLT:
		return actual < expFloat
	case types.CmpLTE:
		return actual <= expFloat
	case types.CmpEQ:
		return actual == expFloat
	case types.CmpNE:
		return actual != expFloat
	default:
		return false
	}
}

// checkDuration checks if a condition has been true for the specified duration.
func (e *RuleEngine) checkDuration(cond types.Condition, metric types.Metric) bool {
	key := fmt.Sprintf("%s_%s", cond.Metric, metric.Labels["pid"])
	window := e.getOrCreateSlidingWindow(key)

	window.mu.Lock()
	defer window.mu.Unlock()

	// Check if all entries in the duration window meet the condition
	cutoff := time.Now().Add(-cond.Duration)
	meetCondition := true

	for _, entry := range window.entries {
		if entry.timestamp.After(cutoff) {
			if !e.compareValue(entry.value, cond.Op, cond.Value) {
				meetCondition = false
				break
			}
		}
	}

	return meetCondition
}

// updateSlidingWindows updates sliding windows with new metric values.
// 向宝塔学习：原地清理旧条目，不每次都 make 新 slice
func (e *RuleEngine) updateSlidingWindows(metrics []types.Metric) {
	cleanupTime := time.Now().Add(-1 * time.Hour) // Keep 1 hour of data

	for _, m := range metrics {
		key := fmt.Sprintf("%s_%s", m.Name, m.Labels["pid"])
		window := e.getOrCreateSlidingWindow(key)

		window.mu.Lock()
		window.entries = append(window.entries, windowEntry{
			value:     m.Value,
			timestamp: m.Timestamp,
		})
		// 原地清理旧条目：移动有效条目到前面，然后截断
		// 不分配新 slice，减少 GC 压力
		n := 0
		for _, entry := range window.entries {
			if entry.timestamp.After(cleanupTime) {
				window.entries[n] = entry
				n++
			}
		}
		window.entries = window.entries[:n]
		window.mu.Unlock()
	}
}

// getOrCreateSlidingWindow gets or creates a sliding window for a metric key.
func (e *RuleEngine) getOrCreateSlidingWindow(key string) *SlidingWindow {
	e.mu.Lock()
	defer e.mu.Unlock()

	if window, ok := e.slidingWindow[key]; ok {
		return window
	}

	window := &SlidingWindow{}
	e.slidingWindow[key] = window
	return window
}

// getSortedRules returns rules sorted by priority.
// 向宝塔学习：缓存排序结果，不每次都 sort
func (e *RuleEngine) getSortedRules() []*types.Rule {
	if !e.rulesDirty && e.sortedRulesCache != nil {
		return e.sortedRulesCache
	}
	var rules []*types.Rule
	for _, r := range e.rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
	e.sortedRulesCache = rules
	e.rulesDirty = false
	return rules
}

// getNeededMetrics extracts the metric names referenced by a rule's trigger.
func (e *RuleEngine) getNeededMetrics(rule *types.Rule) []string {
	var names []string
	for _, cond := range rule.Trigger.Conditions {
		names = append(names, cond.Metric)
	}
	return names
}

// hasMetrics checks if any of the needed metrics are present.
// 向宝塔学习：不每次都 make map，用线性扫描
// metrics 通常只有 10-30 个，线性扫描比 map 分配+查询更快
func (e *RuleEngine) hasMetrics(needed []string, have []types.Metric) bool {
	for _, n := range needed {
		for _, m := range have {
			if m.Name == n {
				return true
			}
		}
	}
	return false
}

// toFloat64 converts an interface{} to float64.
func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint64:
		return float64(val), true
	default:
		return 0, false
	}
}

// GetDefaultRules returns the built-in default rule set.
func GetDefaultRules() []types.Rule {
	return []types.Rule{
		{
			ID:          "cpu-protect-001",
			Name:        "CPU超限保护",
			Description: "单进程CPU > 80%持续60s → 降权→SIGTERM→SIGKILL",
			Enabled:     true,
			Priority:    100,
			Module:      "resource",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric:   "process.cpu_percent",
						Op:       types.CmpGT,
						Value:    80,
						Duration: 60 * time.Second,
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionNice, Params: map[string]interface{}{"value": 10}, Timeout: 30 * time.Second, OnFail: "continue"},
				{Type: types.ActionSigTerm, Timeout: 30 * time.Second, OnFail: "continue"},
				{Type: types.ActionSigKill, Timeout: 10 * time.Second, OnFail: "alert"},
			},
			Cooldown:      300 * time.Second,
			MaxTriggers:   3,
			AlertLevel:    types.AlertWarning,
			AlertChannels: []string{"email", "webhook"},
			LearnMode:     true, // Learn mode: alert only, don't auto-kill
		},
		{
			ID:          "mem-leak-001",
			Name:        "内存泄漏拦截",
			Description: "进程内存1h内增长>150% → 告警+快照+重启",
			Enabled:     true,
			Priority:    90,
			Module:      "resource",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric:   "process.mem_percent",
						Op:       types.CmpGT,
						Value:    30,
						Duration: 0,
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionSnapshot, Timeout: 10 * time.Second, OnFail: "continue"},
				{Type: types.ActionRestart, Timeout: 60 * time.Second, OnFail: "alert"},
			},
			Cooldown:    600 * time.Second,
			MaxTriggers: 2,
			AlertLevel:  types.AlertWarning,
			LearnMode:   true,
		},
		{
			ID:          "disk-space-001",
			Name:        "磁盘空间守护",
			Description: "磁盘 > 90% → 清理日志/缓存",
			Enabled:     true,
			Priority:    95,
			Module:      "resource",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric: "disk.used_percent",
						Op:     types.CmpGT,
						Value:  90,
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionCleanDisk, Timeout: 120 * time.Second, OnFail: "alert"},
			},
			Cooldown:    600 * time.Second,
			MaxTriggers: 5,
			AlertLevel:  types.AlertError,
			LearnMode:   false, // Auto-execute: only cleans old compressed logs, safe
		},
		{
			ID:          "log-flood-001",
			Name:        "日志暴涨防护",
			Description: "单文件 > 500MB → 轮转压缩",
			Enabled:     true,
			Priority:    85,
			Module:      "log",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric: "log.file_size",
						Op:     types.CmpGT,
						Value:  500 * 1024 * 1024, // 500MB
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionRotateLog, Timeout: 30 * time.Second, OnFail: "alert"},
			},
			Cooldown:    300 * time.Second,
			MaxTriggers: 10,
			AlertLevel:  types.AlertWarning,
			LearnMode:   false, // Auto-execute: rotates via executor with snapshot+rollback
		},
		{
			ID:          "ssh-brute-001",
			Name:        "SSH暴力破解拦截",
			Description: "5min内5次失败 → 封禁IP",
			Enabled:     true,
			Priority:    80,
			Module:      "security",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric:   "security.login_failures",
						Op:       types.CmpGTE,
						Value:    5,
						Duration: 5 * time.Minute,
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionBanIP, Timeout: 10 * time.Second, OnFail: "alert"},
			},
			Cooldown:    60 * time.Second,
			MaxTriggers: 20,
			AlertLevel:  types.AlertError,
			LearnMode:   false, // Auto-execute: ban IPs but never private/local IPs
		},
		{
			ID:          "cert-expiring-001",
			Name:        "SSL证书到期续期",
			Description: "证书 < 14天到期 → 自动续期",
			Enabled:     true,
			Priority:    75,
			Module:      "cert",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric: "cert.days_until_expiry",
						Op:     types.CmpLTE,
						Value:  14,
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionRenewCert, Timeout: 120 * time.Second, OnFail: "alert"},
			},
			Cooldown:    3600 * time.Second,
			MaxTriggers: 5,
			AlertLevel:  types.AlertWarning,
			LearnMode:   false,
		},
		{
			ID:          "zombie-cleanup-001",
			Name:        "僵尸进程清理",
			Description: "僵尸进程数 > 10 → 清理",
			Enabled:     true,
			Priority:    70,
			Module:      "resource",
			Trigger: types.ConditionGroup{
				Operator: types.OpAnd,
				Conditions: []types.Condition{
					{
						Metric: "system.zombie_count",
						Op:     types.CmpGT,
						Value:  10,
					},
				},
			},
			Actions: []types.Action{
				{Type: types.ActionRunScript, Params: map[string]interface{}{"script": "reap_zombies"}, Timeout: 30 * time.Second, OnFail: "alert"},
			},
			Cooldown:    3600 * time.Second,
			MaxTriggers: 3,
			AlertLevel:  types.AlertWarning,
			LearnMode:   true,
		},
	}
}
