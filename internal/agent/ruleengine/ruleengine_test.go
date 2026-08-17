package ruleengine

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// --- RuleEngine core tests ---

func TestRuleEngine_New(t *testing.T) {
	e := New(time.Second)
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.GetRules() != nil && len(e.GetRules()) != 0 {
		t.Error("new engine should have no rules")
	}
}

func TestRuleEngine_AddAndRemoveRule(t *testing.T) {
	e := New(time.Second)
	rule := types.Rule{
		ID:       "r1",
		Name:     "rule-1",
		Enabled:  true,
		Priority: 10,
		Trigger: types.ConditionGroup{
			Operator: types.OpAnd,
			Conditions: []types.Condition{
				{Metric: "cpu", Op: types.CmpGT, Value: 80},
			},
		},
	}
	e.AddRule(rule)

	rules := e.GetRules()
	if len(rules) != 1 || rules[0].ID != "r1" {
		t.Fatalf("expected 1 rule r1, got %v", rules)
	}

	e.RemoveRule("r1")
	if len(e.GetRules()) != 0 {
		t.Error("expected 0 rules after remove")
	}

	// Removing non-existent should be a no-op
	e.RemoveRule("nonexistent")
}

func TestRuleEngine_AddRuleOverwrite(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{ID: "r1", Name: "v1", Enabled: true, Priority: 1})
	e.AddRule(types.Rule{ID: "r1", Name: "v2", Enabled: true, Priority: 2})

	rules := e.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (overwritten), got %d", len(rules))
	}
	if rules[0].Name != "v2" {
		t.Errorf("expected overwritten name 'v2', got %q", rules[0].Name)
	}
}

func TestRuleEngine_GetRulesSortedByPriority(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{ID: "low", Enabled: true, Priority: 10})
	e.AddRule(types.Rule{ID: "high", Enabled: true, Priority: 100})
	e.AddRule(types.Rule{ID: "mid", Enabled: true, Priority: 50})

	rules := e.GetRules()
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].ID != "high" || rules[1].ID != "mid" || rules[2].ID != "low" {
		t.Errorf("rules not sorted by priority desc: %v %v %v", rules[0].ID, rules[1].ID, rules[2].ID)
	}
}

func TestRuleEngine_GetRulesFiltersDisabled(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{ID: "on", Enabled: true, Priority: 1})
	e.AddRule(types.Rule{ID: "off", Enabled: false, Priority: 2})

	rules := e.GetRules()
	if len(rules) != 1 || rules[0].ID != "on" {
		t.Errorf("expected only enabled rule 'on', got %v", rules)
	}
}

// --- Match tests ---

func TestRuleEngine_MatchAndSingleCondition(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "cpu-high", Name: "cpu high", Enabled: true, Priority: 10,
		Trigger: types.ConditionGroup{
			Operator: types.OpAnd,
			Conditions: []types.Condition{
				{Metric: "cpu_percent", Op: types.CmpGT, Value: 80},
			},
		},
	})

	matches := e.Match([]types.Metric{{Name: "cpu_percent", Value: 90}})
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Rule.ID != "cpu-high" {
		t.Errorf("wrong rule matched: %s", matches[0].Rule.ID)
	}

	matches = e.Match([]types.Metric{{Name: "cpu_percent", Value: 50}})
	if len(matches) != 0 {
		t.Error("should not match when value below threshold")
	}
}

func TestRuleEngine_MatchNoMetrics(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "r", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "cpu", Op: types.CmpGT, Value: 80}},
		},
	})
	if len(e.Match([]types.Metric{})) != 0 {
		t.Error("empty metrics should produce no matches")
	}
	if len(e.Match(nil)) != 0 {
		t.Error("nil metrics should produce no matches")
	}
}

func TestRuleEngine_MatchOrGroup(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "or-rule", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator: types.OpOr,
			Conditions: []types.Condition{
				{Metric: "a", Op: types.CmpGT, Value: 10},
				{Metric: "b", Op: types.CmpGT, Value: 10},
			},
		},
	})

	if len(e.Match([]types.Metric{{Name: "a", Value: 5}, {Name: "b", Value: 20}})) != 1 {
		t.Error("OR should match when one condition true")
	}
	if len(e.Match([]types.Metric{{Name: "a", Value: 5}, {Name: "b", Value: 5}})) != 0 {
		t.Error("OR should not match when all conditions false")
	}
	if len(e.Match([]types.Metric{{Name: "a", Value: 20}, {Name: "b", Value: 20}})) != 1 {
		t.Error("OR should match when all conditions true")
	}
}

func TestRuleEngine_MatchNotGroup(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "not-rule", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator: types.OpNot,
			Conditions: []types.Condition{
				{Metric: "a", Op: types.CmpGT, Value: 10},
			},
		},
	})

	// NOT(false) = true -> match
	if len(e.Match([]types.Metric{{Name: "a", Value: 5}})) != 1 {
		t.Error("NOT should match when condition is false")
	}
	// NOT(true) = false -> no match
	if len(e.Match([]types.Metric{{Name: "a", Value: 20}})) != 0 {
		t.Error("NOT should not match when condition is true")
	}
}

func TestRuleEngine_MatchNestedGroups(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "nested", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "a", Op: types.CmpGT, Value: 5}},
			Groups: []types.ConditionGroup{
				{Operator: types.OpOr, Conditions: []types.Condition{
					{Metric: "b", Op: types.CmpGT, Value: 10},
					{Metric: "c", Op: types.CmpGT, Value: 10},
				}},
			},
		},
	})

	// a>5 AND (b>10 OR c>10)
	if len(e.Match([]types.Metric{{Name: "a", Value: 6}, {Name: "b", Value: 20}, {Name: "c", Value: 1}})) != 1 {
		t.Error("should match: a true AND (b true OR c false)")
	}
	if len(e.Match([]types.Metric{{Name: "a", Value: 6}, {Name: "b", Value: 1}, {Name: "c", Value: 1}})) != 0 {
		t.Error("should not match: a true AND (b false OR c false)")
	}
	if len(e.Match([]types.Metric{{Name: "a", Value: 1}, {Name: "b", Value: 20}, {Name: "c", Value: 1}})) != 0 {
		t.Error("should not match: a false AND (...)")
	}
}

func TestRuleEngine_MatchUnknownOperator(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "bad-op", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   "UNKNOWN",
			Conditions: []types.Condition{{Metric: "a", Op: types.CmpGT, Value: 5}},
		},
	})
	if len(e.Match([]types.Metric{{Name: "a", Value: 100}})) != 0 {
		t.Error("unknown group operator should not match")
	}
}

// --- Comparison operator table-driven tests ---

func TestRuleEngine_ComparisonOperators(t *testing.T) {
	cases := []struct {
		name     string
		op       types.ComparisonOperator
		actual   float64
		expected interface{}
		want     bool
	}{
		{"gt_true", types.CmpGT, 10, 5, true},
		{"gt_false", types.CmpGT, 5, 10, false},
		{"gte_true_eq", types.CmpGTE, 10, 10, true},
		{"gte_true_gt", types.CmpGTE, 11, 10, true},
		{"gte_false", types.CmpGTE, 9, 10, false},
		{"lt_true", types.CmpLT, 5, 10, true},
		{"lt_false", types.CmpLT, 10, 5, false},
		{"lte_true_eq", types.CmpLTE, 10, 10, true},
		{"lte_true_lt", types.CmpLTE, 9, 10, true},
		{"lte_false", types.CmpLTE, 11, 10, false},
		{"eq_true", types.CmpEQ, 10, 10, true},
		{"eq_false", types.CmpEQ, 10, 11, false},
		{"ne_true", types.CmpNE, 10, 11, true},
		{"ne_false", types.CmpNE, 10, 10, false},
		{"unknown_op", "??", 10, 5, false},
		{"int_value", types.CmpGT, 10, 5, true},
		{"int64_value", types.CmpGT, 10, int64(5), true},
		{"uint64_value", types.CmpGT, 10, uint64(5), true},
		{"float32_value", types.CmpGT, 10, float32(5), true},
		{"invalid_value_type", types.CmpGT, 10, "not-a-number", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(time.Second)
			e.AddRule(types.Rule{
				ID: "cmp", Enabled: true, Priority: 1,
				Trigger: types.ConditionGroup{
					Operator: types.OpAnd,
					Conditions: []types.Condition{
						{Metric: "m", Op: tc.op, Value: tc.expected},
					},
				},
			})
			matches := e.Match([]types.Metric{{Name: "m", Value: tc.actual}})
			got := len(matches) == 1
			if got != tc.want {
				t.Errorf("op=%s actual=%v expected=%v: got %v want %v", tc.op, tc.actual, tc.expected, got, tc.want)
			}
		})
	}
}

func TestRuleEngine_MatchMetricPrefix(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "prefix", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "process.cpu", Op: types.CmpGT, Value: 80}},
		},
	})
	// evaluateCondition supports prefix matching (m.Name == cond.Metric || HasPrefix(m.Name, cond.Metric+".")).
	// The pre-filter hasMetrics requires the exact base metric to be present to avoid skipping the rule.
	// Include both the base metric (to pass pre-filter) and the prefixed metric (to exercise prefix path).
	matches := e.Match([]types.Metric{
		{Name: "process.cpu", Value: 90},
		{Name: "process.cpu_percent", Value: 95},
	})
	if len(matches) != 1 {
		t.Errorf("expected match with base+prefixed metric, got %d", len(matches))
	}
}

func TestRuleEngine_MatchDisabledRuleSkipped(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "disabled", Enabled: false, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "a", Op: types.CmpGT, Value: 5}},
		},
	})
	if len(e.Match([]types.Metric{{Name: "a", Value: 100}})) != 0 {
		t.Error("disabled rule should not match")
	}
}

// --- DryRun / Simulate ---

func TestRuleEngine_DryRun(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "r", Name: "test", Enabled: true, Priority: 1, LearnMode: false,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "cpu", Op: types.CmpGT, Value: 80}},
		},
		Actions: []types.Action{{Type: types.ActionAlert}},
	})

	results := e.DryRun(context.Background(), []types.Metric{{Name: "cpu", Value: 90}})
	if len(results) != 1 {
		t.Fatalf("expected 1 dry-run result, got %d", len(results))
	}
	r := results[0]
	if r.RuleID != "r" {
		t.Errorf("expected rule id 'r', got %q", r.RuleID)
	}
	if !r.WouldExecute {
		t.Error("WouldExecute should be true when LearnMode is false")
	}
	if len(r.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(r.Actions))
	}
}

func TestRuleEngine_DryRunLearnMode(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "r", Name: "learn", Enabled: true, Priority: 1, LearnMode: true,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "cpu", Op: types.CmpGT, Value: 80}},
		},
	})

	results := e.DryRun(context.Background(), []types.Metric{{Name: "cpu", Value: 90}})
	if len(results) != 1 || results[0].WouldExecute {
		t.Error("learn mode rule should not WouldExecute")
	}
}

func TestRuleEngine_DryRunNoMatch(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "r", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "cpu", Op: types.CmpGT, Value: 80}},
		},
	})
	results := e.DryRun(context.Background(), []types.Metric{{Name: "cpu", Value: 50}})
	if len(results) != 0 {
		t.Error("expected no dry-run results when no match")
	}
}

func TestRuleEngine_Simulate(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "r", Name: "sim", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "cpu_percent", Op: types.CmpGT, Value: 80}},
		},
	})

	results := e.Simulate(context.Background(), map[string]float64{"cpu_percent": 90}, 3*time.Second)
	if len(results) == 0 {
		t.Error("expected simulate to produce results for matching metric")
	}
	for _, r := range results {
		if r.RuleID != "r" {
			t.Errorf("expected rule id 'r', got %q", r.RuleID)
		}
	}
}

func TestRuleEngine_SimulateNoMatch(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "r", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator:   types.OpAnd,
			Conditions: []types.Condition{{Metric: "cpu_percent", Op: types.CmpGT, Value: 80}},
		},
	})
	results := e.Simulate(context.Background(), map[string]float64{"cpu_percent": 50}, 2*time.Second)
	if len(results) != 0 {
		t.Error("expected no results when simulated value below threshold")
	}
}

// --- GetRuleHistory with mock storage ---

type mockStorage struct {
	entries []RuleHistoryEntry
	err     error
	calls   int
	mu      sync.Mutex
}

func (m *mockStorage) GetActionHistoryByRule(ruleID string, since time.Time, limit int) ([]RuleHistoryEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.entries, m.err
}

func TestRuleEngine_GetRuleHistoryNoStorage(t *testing.T) {
	e := New(time.Second)
	// No storage set
	history := e.GetRuleHistory("r1", time.Now().Add(-time.Hour))
	if len(history) != 0 {
		t.Error("expected empty history when no storage set")
	}
}

func TestRuleEngine_GetRuleHistoryWithStorage(t *testing.T) {
	e := New(time.Second)
	ms := &mockStorage{
		entries: []RuleHistoryEntry{
			{RuleID: "r1", Action: "kill", Success: true},
			{RuleID: "r1", Action: "restart", Success: false},
		},
	}
	e.SetStorage(ms)

	history := e.GetRuleHistory("r1", time.Now().Add(-time.Hour))
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}
	if history[0].Action != "kill" {
		t.Errorf("unexpected first entry action: %q", history[0].Action)
	}
	if ms.calls != 1 {
		t.Errorf("expected 1 storage call, got %d", ms.calls)
	}
}

func TestRuleEngine_GetRuleHistoryStorageError(t *testing.T) {
	e := New(time.Second)
	ms := &mockStorage{err: errors.New("db error")}
	e.SetStorage(ms)

	history := e.GetRuleHistory("r1", time.Now().Add(-time.Hour))
	if len(history) != 0 {
		t.Error("expected empty history on storage error")
	}
}

func TestRuleEngine_SetStorage(t *testing.T) {
	e := New(time.Second)
	ms := &mockStorage{}
	e.SetStorage(ms)
	// Verify it's used
	e.GetRuleHistory("r", time.Now().Add(-time.Hour))
	if ms.calls != 1 {
		t.Errorf("expected storage to be called, got %d calls", ms.calls)
	}
}

// --- GetDefaultRules ---

func TestGetDefaultRules(t *testing.T) {
	rules := GetDefaultRules()
	if len(rules) == 0 {
		t.Fatal("expected non-empty default rules")
	}
	ids := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			t.Error("default rule has empty ID")
		}
		if ids[r.ID] {
			t.Errorf("duplicate default rule ID: %s", r.ID)
		}
		ids[r.ID] = true
	}
	// Check a few expected rule IDs
	expected := []string{"cpu-protect-001", "mem-leak-001", "disk-space-001", "ssh-brute-001"}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected default rule %s missing", id)
		}
	}
}

func TestFormatDryRunResults(t *testing.T) {
	out := FormatDryRunResults(nil)
	if out != "No rules matched in dry-run." {
		t.Errorf("unexpected empty output: %q", out)
	}

	results := []DryRunResult{
		{RuleID: "r1", RuleName: "Rule 1", MatchedMetric: "cpu", MatchedValue: 90, WouldExecute: true, Actions: []types.Action{{Type: types.ActionAlert}}},
		{RuleID: "r2", RuleName: "Rule 2", MatchedMetric: "mem", MatchedValue: 95, WouldExecute: false, Actions: []types.Action{}},
	}
	out = FormatDryRunResults(results)
	if out == "" {
		t.Error("expected non-empty formatted output")
	}
}

// --- ConflictResolver tests ---

func TestConflictResolver_New(t *testing.T) {
	cr := NewConflictResolver()
	if cr == nil {
		t.Fatal("NewConflictResolver returned nil")
	}
	if cr.GetTriggerCount("any") != 0 {
		t.Error("new resolver should have 0 trigger count")
	}
	if cr.IsSilenced("any") {
		t.Error("new resolver should not silence anything")
	}
}

func TestConflictResolver_Whitelist(t *testing.T) {
	cr := NewConflictResolver()
	cr.SetWhitelist([]string{"1.2.3.4", "safe-proc"})

	rule := &types.Rule{ID: "r1", Priority: 10}
	results := []MatchResult{{Rule: rule, Metrics: []types.Metric{{Name: "cpu", Value: 90}}}}

	resolved := cr.Resolve(results, "1.2.3.4")
	if resolved != nil {
		t.Error("whitelisted target should be vetoed (nil)")
	}

	resolved = cr.Resolve(results, "other")
	if len(resolved) != 1 {
		t.Errorf("non-whitelisted target should resolve, got %d", len(resolved))
	}
}

func TestConflictResolver_AddWhitelist(t *testing.T) {
	cr := NewConflictResolver()
	cr.AddWhitelist("target-1")

	rule := &types.Rule{ID: "r1", Priority: 10}
	results := []MatchResult{{Rule: rule}}
	if cr.Resolve(results, "target-1") != nil {
		t.Error("AddWhitelist item should veto")
	}
}

func TestConflictResolver_PrioritySorting(t *testing.T) {
	cr := NewConflictResolver()
	results := []MatchResult{
		{Rule: &types.Rule{ID: "low", Priority: 10}, Metrics: []types.Metric{{Name: "m", Value: 1}}},
		{Rule: &types.Rule{ID: "high", Priority: 100}, Metrics: []types.Metric{{Name: "m", Value: 1}}},
		{Rule: &types.Rule{ID: "mid", Priority: 50}, Metrics: []types.Metric{{Name: "m", Value: 1}}},
	}

	resolved := cr.Resolve(results, "target")
	if len(resolved) == 0 {
		t.Fatal("expected non-empty resolved result")
	}
	// Highest priority rule should be in the merged result
	if resolved[0].Rule.ID != "high" {
		t.Errorf("expected highest priority rule 'high', got %q", resolved[0].Rule.ID)
	}
}

func TestConflictResolver_NilRuleSkipped(t *testing.T) {
	cr := NewConflictResolver()
	results := []MatchResult{
		{Rule: nil},
		{Rule: &types.Rule{ID: "r1", Priority: 10}, Metrics: []types.Metric{{Name: "m", Value: 1}}},
	}
	resolved := cr.Resolve(results, "target")
	if len(resolved) != 1 {
		t.Errorf("expected 1 resolved (nil rule skipped), got %d", len(resolved))
	}
}

func TestConflictResolver_EmptyResults(t *testing.T) {
	cr := NewConflictResolver()
	if cr.Resolve(nil, "target") != nil {
		t.Error("nil results should return nil")
	}
	if cr.Resolve([]MatchResult{}, "target") != nil {
		t.Error("empty results should return nil")
	}
}

func TestConflictResolver_TriggerCountAndSilence(t *testing.T) {
	cr := NewConflictResolver()
	rule := &types.Rule{ID: "r1", Priority: 10}
	results := []MatchResult{{Rule: rule, Metrics: []types.Metric{{Name: "m", Value: 1}}}}

	// maxTriggers is 3; trigger 3 times to enter silence
	for i := 0; i < 3; i++ {
		cr.Resolve(results, "target")
	}

	if cr.GetTriggerCount("r1") != 0 {
		t.Errorf("trigger count should reset to 0 after reaching max, got %d", cr.GetTriggerCount("r1"))
	}
	if !cr.IsSilenced("r1") {
		t.Error("rule should be silenced after reaching max triggers")
	}

	// Silenced rule should be filtered out
	resolved := cr.Resolve(results, "target")
	if len(resolved) != 0 {
		t.Errorf("silenced rule should be filtered, got %d results", len(resolved))
	}
}

func TestConflictResolver_ResetTriggerCount(t *testing.T) {
	cr := NewConflictResolver()
	rule := &types.Rule{ID: "r1", Priority: 10}
	results := []MatchResult{{Rule: rule, Metrics: []types.Metric{{Name: "m", Value: 1}}}}

	cr.Resolve(results, "target")
	cr.Resolve(results, "target")
	if cr.GetTriggerCount("r1") != 2 {
		t.Fatalf("expected 2 triggers, got %d", cr.GetTriggerCount("r1"))
	}

	cr.ResetTriggerCount("r1")
	if cr.GetTriggerCount("r1") != 0 {
		t.Error("trigger count should be 0 after reset")
	}
	if cr.IsSilenced("r1") {
		t.Error("rule should not be silenced after reset")
	}
}

// --- Duration-based condition tests (checkDuration) ---

func TestRuleEngine_DurationConditionMet(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "dur", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator: types.OpAnd,
			Conditions: []types.Condition{
				{Metric: "cpu", Op: types.CmpGT, Value: 80, Duration: 100 * time.Millisecond},
			},
		},
	})

	now := time.Now()
	// Feed multiple samples within the duration window that all meet the condition
	for i := 0; i < 3; i++ {
		e.Match([]types.Metric{{Name: "cpu", Value: 90, Timestamp: now.Add(time.Duration(i) * 10 * time.Millisecond)}})
	}
	// Final match should succeed since all recent entries meet condition
	matches := e.Match([]types.Metric{{Name: "cpu", Value: 90, Timestamp: now.Add(30 * time.Millisecond)}})
	if len(matches) != 1 {
		t.Errorf("expected duration condition to match, got %d", len(matches))
	}

}

func TestRuleEngine_DurationConditionNotMet(t *testing.T) {
	e := New(time.Second)
	e.AddRule(types.Rule{
		ID: "dur", Enabled: true, Priority: 1,
		Trigger: types.ConditionGroup{
			Operator: types.OpAnd,
			Conditions: []types.Condition{
				{Metric: "cpu", Op: types.CmpGT, Value: 80, Duration: 100 * time.Millisecond},
			},
		},
	})

	now := time.Now()
	// First sample meets condition
	e.Match([]types.Metric{{Name: "cpu", Value: 90, Timestamp: now}})
	// Second sample does NOT meet condition (value below threshold)
	e.Match([]types.Metric{{Name: "cpu", Value: 50, Timestamp: now.Add(10 * time.Millisecond)}})
	// Third sample meets condition but the window has a non-matching entry
	matches := e.Match([]types.Metric{{Name: "cpu", Value: 90, Timestamp: now.Add(20 * time.Millisecond)}})
	if len(matches) != 0 {
		t.Errorf("expected no match due to non-matching entry in window, got %d", len(matches))
	}
}

func TestRuleEngine_toFloat64AllTypes(t *testing.T) {

	// Exercise all numeric type conversions via conditions
	cases := []struct {
		name  string
		value interface{}
		match bool
	}{
		{"float64", float64(5), true},
		{"float32", float32(5), true},
		{"int", 5, true},
		{"int32", int32(5), true},
		{"int64", int64(5), true},
		{"uint64", uint64(5), true},
		{"string_invalid", "not-a-number", false},
		{"nil_invalid", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e2 := New(time.Second)
			e2.AddRule(types.Rule{
				ID: "t", Enabled: true, Priority: 1,
				Trigger: types.ConditionGroup{
					Operator:   types.OpAnd,
					Conditions: []types.Condition{{Metric: "m", Op: types.CmpGT, Value: tc.value}},
				},
			})
			matches := e2.Match([]types.Metric{{Name: "m", Value: 10}})
			got := len(matches) == 1
			if got != tc.match {
				t.Errorf("toFloat64(%T %v): got match=%v want %v", tc.value, tc.value, got, tc.match)
			}
		})
	}
}

// --- YAML loader tests ---

func TestLoadRulesFromYAMLBytes(t *testing.T) {
	e := New(time.Second)
	yamlData := []byte(`
schema_version: 1
rules:
  - id: yaml-cpu
    name: CPU High
    enabled: true
    priority: 50
    module: resource
    description: CPU too high
    trigger:
      operator: AND
      conditions:
        - metric: cpu_percent
          op: ">"
          value: 80
          duration: 60s
    actions:
      - type: kill
        timeout: 30s
        on_fail: alert
    cooldown: 300s
    max_triggers: 3
    alert_level: warning
    alert_channels: [email, webhook]
    learn_mode: true
  - id: yaml-mem
    name: Mem High
    enabled: true
    priority: 40
    module: resource
    trigger:
      operator: OR
      conditions:
        - metric: mem_percent
          op: ">"
          value: 90
    actions:
      - type: restart
    alert_level: critical
`)

	if err := e.LoadRulesFromYAMLBytes(yamlData); err != nil {
		t.Fatalf("LoadRulesFromYAMLBytes error: %v", err)
	}

	rules := e.GetRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules loaded, got %d", len(rules))
	}

	// Verify first rule
	var cpuRule *types.Rule
	for _, r := range rules {
		if r.ID == "yaml-cpu" {
			cpuRule = r
		}
	}
	if cpuRule == nil {
		t.Fatal("yaml-cpu rule not found")
	}
	if cpuRule.Priority != 50 {
		t.Errorf("expected priority 50, got %d", cpuRule.Priority)
	}
	if cpuRule.Cooldown != 300*time.Second {
		t.Errorf("expected cooldown 300s, got %v", cpuRule.Cooldown)
	}
	if len(cpuRule.Actions) != 1 || cpuRule.Actions[0].Type != types.ActionKill {
		t.Errorf("unexpected actions: %v", cpuRule.Actions)
	}
	if cpuRule.Actions[0].Timeout != 30*time.Second {
		t.Errorf("expected action timeout 30s, got %v", cpuRule.Actions[0].Timeout)
	}
	if len(cpuRule.Trigger.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(cpuRule.Trigger.Conditions))
	}
	if cpuRule.Trigger.Conditions[0].Duration != 60*time.Second {
		t.Errorf("expected duration 60s, got %v", cpuRule.Trigger.Conditions[0].Duration)
	}
	if !cpuRule.LearnMode {
		t.Error("expected learn_mode true")
	}
}

func TestLoadRulesFromYAMLBytesInvalid(t *testing.T) {
	e := New(time.Second)
	invalidYAML := []byte("not: valid: yaml: [[[")
	if err := e.LoadRulesFromYAMLBytes(invalidYAML); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadRulesFromYAMLFromFile(t *testing.T) {
	tmp := t.TempDir()
	path := tmp + "/rules.yaml"
	yamlData := []byte(`
schema_version: 1
rules:
  - id: file-rule
    name: File Rule
    enabled: true
    priority: 10
    module: log
    trigger:
      operator: AND
      conditions:
        - metric: log.size
          op: ">"
          value: 1000000
    actions:
      - type: rotate_log
    alert_level: error
`)
	if err := osWriteFileTest(path, yamlData); err != nil {
		t.Fatal(err)
	}

	e := New(time.Second)
	if err := e.LoadRulesFromYAML(path); err != nil {
		t.Fatalf("LoadRulesFromYAML error: %v", err)
	}
	if len(e.GetRules()) != 1 {
		t.Errorf("expected 1 rule, got %d", len(e.GetRules()))
	}
}

func TestLoadRulesFromYAMLNonexistentFile(t *testing.T) {
	e := New(time.Second)
	if err := e.LoadRulesFromYAML("/nonexistent/rules.yaml"); err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestConvertOperator(t *testing.T) {
	cases := []struct {
		input  string
		expect types.ComparisonOperator
	}{
		{">", types.CmpGT},
		{">=", types.CmpGTE},
		{"<", types.CmpLT},
		{"<=", types.CmpLTE},
		{"==", types.CmpEQ},
		{"!=", types.CmpNE},
		{"IN", types.CmpIn},
		{"NOT_IN", types.CmpNotIn},
		{"unknown", types.CmpGT}, // default
	}
	for _, tc := range cases {
		if got := convertOperator(tc.input); got != tc.expect {
			t.Errorf("convertOperator(%q) = %v, want %v", tc.input, got, tc.expect)
		}
	}
}

func TestConvertRuleDefAlertLevels(t *testing.T) {
	cases := []string{"info", "warning", "error", "critical", "unknown"}
	expected := []types.AlertLevel{types.AlertInfo, types.AlertWarning, types.AlertError, types.AlertCritical, types.AlertWarning}
	for i, level := range cases {
		rd := RuleDef{AlertLevel: level}
		rule := convertRuleDef(rd)
		if rule.AlertLevel != expected[i] {
			t.Errorf("alert level %q: got %v, want %v", level, rule.AlertLevel, expected[i])
		}
	}
}

func TestConvertRuleDefOperators(t *testing.T) {
	cases := []string{"AND", "OR", "NOT", "unknown"}
	expected := []types.ConditionOperator{types.OpAnd, types.OpOr, types.OpNot, types.OpAnd}
	for i, op := range cases {
		rd := RuleDef{Trigger: TriggerDef{Operator: op}}
		rule := convertRuleDef(rd)
		if rule.Trigger.Operator != expected[i] {
			t.Errorf("operator %q: got %v, want %v", op, rule.Trigger.Operator, expected[i])
		}
	}
}

func TestConvertRuleDefDefaultActionTimeout(t *testing.T) {
	rd := RuleDef{
		Actions: []ActionDef{{Type: "kill"}}, // no timeout specified
	}
	rule := convertRuleDef(rd)
	if rule.Actions[0].Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", rule.Actions[0].Timeout)
	}
}

func TestConvertRuleDefInvalidDuration(t *testing.T) {
	rd := RuleDef{
		Trigger: TriggerDef{
			Conditions: []ConditionDef{
				{Metric: "cpu", Op: ">", Value: 80, Duration: "invalid"},
			},
		},
	}
	rule := convertRuleDef(rd)
	// Invalid duration string with non-empty value defaults to 60s
	if rule.Trigger.Conditions[0].Duration != 60*time.Second {
		t.Errorf("expected default 60s for invalid duration, got %v", rule.Trigger.Conditions[0].Duration)
	}
}

// --- ResolveConflicts tests ---

func TestResolveConflicts_SingleMatch(t *testing.T) {
	e := New(time.Second)
	matches := []MatchResult{
		{Rule: &types.Rule{ID: "r1", Priority: 10}, Metrics: []types.Metric{{Name: "cpu", Value: 90}}},
	}
	result := e.ResolveConflicts(matches)
	if len(result) != 1 {
		t.Errorf("expected 1 result for single match, got %d", len(result))
	}
}

func TestResolveConflicts_Empty(t *testing.T) {
	e := New(time.Second)
	result := e.ResolveConflicts(nil)
	if len(result) != 0 {
		t.Error("expected 0 results for nil input")
	}
}

func TestResolveConflicts_DifferentTargets(t *testing.T) {
	e := New(time.Second)
	matches := []MatchResult{
		{Rule: &types.Rule{ID: "r1", Priority: 10}, Metrics: []types.Metric{{Name: "cpu", Value: 90, Labels: map[string]string{"process_name": "nginx"}}}},
		{Rule: &types.Rule{ID: "r2", Priority: 20}, Metrics: []types.Metric{{Name: "cpu", Value: 95, Labels: map[string]string{"process_name": "mysql"}}}},
	}
	result := e.ResolveConflicts(matches)
	if len(result) != 2 {
		t.Errorf("expected 2 results for different targets, got %d", len(result))
	}
}

func TestResolveConflicts_SameTargetHigherPriorityWins(t *testing.T) {
	e := New(time.Second)
	matches := []MatchResult{
		{Rule: &types.Rule{ID: "low", Priority: 10, Actions: []types.Action{{Type: types.ActionAlert}}}, Metrics: []types.Metric{{Name: "cpu", Value: 90, Labels: map[string]string{"process_name": "nginx"}}}},
		{Rule: &types.Rule{ID: "high", Priority: 100, Actions: []types.Action{{Type: types.ActionKill}}}, Metrics: []types.Metric{{Name: "cpu", Value: 95, Labels: map[string]string{"process_name": "nginx"}}}},
	}
	result := e.ResolveConflicts(matches)
	if len(result) != 2 {
		t.Fatalf("expected 2 results (1 winner + 1 suppressed), got %d", len(result))
	}
	// Find the non-suppressed rule
	for _, r := range result {
		if r.Rule.ID == "high" && !r.Rule.LearnMode {
			return // high priority rule should not be in learn mode
		}
	}
	t.Error("expected high priority rule to not be in learn mode")
}

func TestResolveConflicts_SamePriorityMerged(t *testing.T) {
	e := New(time.Second)
	matches := []MatchResult{
		{Rule: &types.Rule{ID: "r1", Priority: 100, Actions: []types.Action{{Type: types.ActionKill}}}, Metrics: []types.Metric{{Name: "cpu", Value: 90, Labels: map[string]string{"process_name": "nginx"}}}},
		{Rule: &types.Rule{ID: "r2", Priority: 100, Actions: []types.Action{{Type: types.ActionSigTerm}}}, Metrics: []types.Metric{{Name: "cpu", Value: 95, Labels: map[string]string{"process_name": "nginx"}}}},
	}
	result := e.ResolveConflicts(matches)
	// Same priority rules should be merged into one with combined actions
	if len(result) != 1 {
		t.Fatalf("expected 1 merged result, got %d", len(result))
	}
	if len(result[0].Rule.Actions) != 2 {
		t.Errorf("expected 2 merged actions, got %d", len(result[0].Rule.Actions))
	}
}

func TestResolveConflicts_SystemTarget(t *testing.T) {
	e := New(time.Second)
	matches := []MatchResult{
		{Rule: &types.Rule{ID: "r1", Priority: 10}, Metrics: []types.Metric{{Name: "cpu", Value: 90}}},
		{Rule: &types.Rule{ID: "r2", Priority: 20}, Metrics: []types.Metric{{Name: "mem", Value: 95}}},
	}
	result := e.ResolveConflicts(matches)
	// Both have no process_name label, so target = "system" for both
	if len(result) != 2 {
		t.Errorf("expected 2 results, got %d", len(result))
	}
}

// --- helpers ---

func osWriteFileTest(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
