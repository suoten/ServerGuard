package ruleengine

import (
	"context"
	"fmt"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// DryRunResult represents the result of a dry-run evaluation.
type DryRunResult struct {
	RuleID        string         `json:"rule_id"`
	RuleName      string         `json:"rule_name"`
	MatchedMetric string         `json:"matched_metric"`
	MatchedValue  float64        `json:"matched_value"`
	Threshold     interface{}    `json:"threshold"`
	Actions       []types.Action `json:"actions"`
	Cooldown      time.Duration  `json:"cooldown"`
	WouldExecute  bool           `json:"would_execute"`
}

// DryRun evaluates rules without executing actions.
// §8.5.5: Rule Test and Dry-Run.
func (e *RuleEngine) DryRun(ctx context.Context, metrics []types.Metric) []DryRunResult {
	matches := e.Match(metrics)
	var results []DryRunResult

	for _, m := range matches {
		// For each matched rule, create a dry-run result
		for _, metric := range m.Metrics {
			results = append(results, DryRunResult{
				RuleID:        m.Rule.ID,
				RuleName:      m.Rule.Name,
				MatchedMetric: metric.Name,
				MatchedValue:  metric.Value,
				Actions:       m.Rule.Actions,
				Cooldown:      m.Rule.Cooldown,
				WouldExecute:  !m.Rule.LearnMode,
			})
		}
	}

	return results
}

// Simulate simulates a metric scenario and shows what rules would trigger.
// §8.5.5: sgctl rule simulate --metric cpu_percent=85 --duration 60s
func (e *RuleEngine) Simulate(ctx context.Context, simulatedMetrics map[string]float64, duration time.Duration) []DryRunResult {
	now := time.Now()
	var metrics []types.Metric

	// Create synthetic metrics from simulated values
	steps := int(duration.Seconds())
	if steps < 1 {
		steps = 1
	}
	for i := 0; i < steps; i++ {
		ts := now.Add(-duration + time.Duration(i)*time.Second)
		for name, value := range simulatedMetrics {
			metrics = append(metrics, types.Metric{
				Name:      name,
				Value:     value,
				Timestamp: ts,
			})
		}
	}

	// Evaluate rules against simulated data
	matches := e.Match(metrics)
	var results []DryRunResult

	for _, m := range matches {
		for _, metric := range m.Metrics {
			results = append(results, DryRunResult{
				RuleID:        m.Rule.ID,
				RuleName:      m.Rule.Name,
				MatchedMetric: metric.Name,
				MatchedValue:  metric.Value,
				Actions:       m.Rule.Actions,
				Cooldown:      m.Rule.Cooldown,
				WouldExecute:  !m.Rule.LearnMode,
			})
		}
	}

	return results
}

// RuleHistoryEntry represents a rule execution history entry.
type RuleHistoryEntry struct {
	RuleID      string        `json:"rule_id"`
	Timestamp   time.Time     `json:"timestamp"`
	ProcessName string        `json:"process_name"`
	Action      string        `json:"action"`
	Success     bool          `json:"success"`
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
}

// GetRuleHistory returns the execution history of rules.
// §8.5.5: sgctl rule history --rule cpu-protect --last 7d
func (e *RuleEngine) GetRuleHistory(ruleID string, since time.Time) []RuleHistoryEntry {
	e.mu.RLock()
	storage := e.storage
	e.mu.RUnlock()

	if storage == nil {
		return []RuleHistoryEntry{}
	}

	entries, err := storage.GetActionHistoryByRule(ruleID, since, 1000)
	if err != nil {
		return []RuleHistoryEntry{}
	}
	return entries
}

// FormatDryRunResults formats dry-run results for CLI output.
func FormatDryRunResults(results []DryRunResult) string {
	if len(results) == 0 {
		return "No rules matched in dry-run."
	}

	var output string
	output = fmt.Sprintf("Dry-run matched %d rule(s):\n\n", len(results))
	for i, r := range results {
		execStatus := "WOULD EXECUTE"
		if !r.WouldExecute {
			execStatus = "ALERT ONLY (learn mode)"
		}
		output += fmt.Sprintf("%d. Rule: %s (%s)\n", i+1, r.RuleName, r.RuleID)
		output += fmt.Sprintf("   Metric: %s = %.2f\n", r.MatchedMetric, r.MatchedValue)
		output += fmt.Sprintf("   Actions: %d | Status: %s\n\n", len(r.Actions), execStatus)
	}
	return output
}
