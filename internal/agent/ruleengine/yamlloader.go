package ruleengine

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/suoten/serverguard/internal/types"
)

// RuleFile represents the YAML structure for rule definitions.
// §8.5.1: Rule data model (YAML DSL)
type RuleFile struct {
	SchemaVersion int       `yaml:"schema_version"`
	Rules         []RuleDef `yaml:"rules"`
}

// RuleDef represents a rule definition in YAML.
type RuleDef struct {
	ID            string      `yaml:"id"`
	Name          string      `yaml:"name"`
	Enabled       bool        `yaml:"enabled"`
	Priority      int         `yaml:"priority"`
	Module        string      `yaml:"module"`
	Description   string      `yaml:"description"`
	Trigger       TriggerDef  `yaml:"trigger"`
	Actions       []ActionDef `yaml:"actions"`
	Cooldown      string      `yaml:"cooldown"`
	MaxTriggers   int         `yaml:"max_triggers"`
	AlertLevel    string      `yaml:"alert_level"`
	AlertChannels []string    `yaml:"alert_channels"`
	LearnMode     bool        `yaml:"learn_mode"`
}

// TriggerDef represents a trigger condition group in YAML.
type TriggerDef struct {
	Operator   string         `yaml:"operator"` // AND, OR, NOT
	Conditions []ConditionDef `yaml:"conditions"`
}

// ConditionDef represents a single condition in YAML.
type ConditionDef struct {
	Metric   string      `yaml:"metric"`
	Op       string      `yaml:"op"` // >, >=, <, <=, ==, !=
	Value    interface{} `yaml:"value"`
	Duration string      `yaml:"duration"` // e.g., "60s", "5m"
}

// ActionDef represents an action in YAML.
type ActionDef struct {
	Type    string                 `yaml:"type"`
	Params  map[string]interface{} `yaml:"params"`
	Timeout string                 `yaml:"timeout"`
	OnFail  string                 `yaml:"on_fail"` // continue, alert
}

// LoadRulesFromYAML loads rules from a YAML file.
func (e *RuleEngine) LoadRulesFromYAML(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %s: %w", path, err)
	}

	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	for _, rd := range ruleFile.Rules {
		rule := convertRuleDef(rd)
		e.AddRule(rule)
	}

	return nil
}

// LoadRulesFromYAMLBytes loads rules from YAML bytes.
func (e *RuleEngine) LoadRulesFromYAMLBytes(data []byte) error {
	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	for _, rd := range ruleFile.Rules {
		rule := convertRuleDef(rd)
		e.AddRule(rule)
	}

	return nil
}

// convertRuleDef converts a YAML RuleDef to a types.Rule.
func convertRuleDef(rd RuleDef) types.Rule {
	cooldown, _ := time.ParseDuration(rd.Cooldown)

	// Convert trigger conditions
	operator := types.OpAnd
	switch strings.ToUpper(rd.Trigger.Operator) {
	case "OR":
		operator = types.OpOr
	case "NOT":
		operator = types.OpNot
	}

	var conditions []types.Condition
	for _, cd := range rd.Trigger.Conditions {
		duration, _ := time.ParseDuration(cd.Duration)
		if duration == 0 && cd.Duration != "" {
			duration = 60 * time.Second // default
		}

		op := convertOperator(cd.Op)
		conditions = append(conditions, types.Condition{
			Metric:   cd.Metric,
			Op:       op,
			Value:    cd.Value,
			Duration: duration,
		})
	}

	// Convert actions
	var actions []types.Action
	for _, ad := range rd.Actions {
		timeout, _ := time.ParseDuration(ad.Timeout)
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		actions = append(actions, types.Action{
			Type:    types.ActionType(ad.Type),
			Params:  ad.Params,
			Timeout: timeout,
			OnFail:  ad.OnFail,
		})
	}

	// Convert alert level
	alertLevel := types.AlertWarning
	switch strings.ToLower(rd.AlertLevel) {
	case "info":
		alertLevel = types.AlertInfo
	case "warning":
		alertLevel = types.AlertWarning
	case "error":
		alertLevel = types.AlertError
	case "critical":
		alertLevel = types.AlertCritical
	}

	return types.Rule{
		ID:          rd.ID,
		Name:        rd.Name,
		Description: rd.Description,
		Enabled:     rd.Enabled,
		Priority:    rd.Priority,
		Module:      rd.Module,
		Trigger: types.ConditionGroup{
			Operator:   operator,
			Conditions: conditions,
		},
		Actions:       actions,
		Cooldown:      cooldown,
		MaxTriggers:   rd.MaxTriggers,
		AlertLevel:    alertLevel,
		AlertChannels: rd.AlertChannels,
		LearnMode:     rd.LearnMode,
	}
}

// convertOperator converts a string operator to ComparisonOperator.
func convertOperator(op string) types.ComparisonOperator {
	switch op {
	case ">":
		return types.CmpGT
	case ">=":
		return types.CmpGTE
	case "<":
		return types.CmpLT
	case "<=":
		return types.CmpLTE
	case "==":
		return types.CmpEQ
	case "!=":
		return types.CmpNE
	case "IN":
		return types.CmpIn
	case "NOT_IN":
		return types.CmpNotIn
	default:
		return types.CmpGT
	}
}

// --- §8.5.3: Rule Priority and Conflict Resolution ---

// ResolveConflicts handles conflicting rule matches.
// §8.5.3: Same process hitting both "CPU high" and "memory leak" rules.
func (e *RuleEngine) ResolveConflicts(matches []MatchResult) []MatchResult {
	if len(matches) <= 1 {
		return matches
	}

	// Group matches by target process
	byTarget := make(map[string][]MatchResult)
	for _, m := range matches {
		// Extract process name from metrics
		target := ""
		for _, metric := range m.Metrics {
			if name, ok := metric.Labels["process_name"]; ok {
				target = name
				break
			}
		}
		if target == "" {
			target = "system"
		}
		byTarget[target] = append(byTarget[target], m)
	}

	var result []MatchResult
	for target, targetMatches := range byTarget {
		if len(targetMatches) == 1 {
			result = append(result, targetMatches[0])
			continue
		}

		// Sort by priority (highest first)
		sortedMatches := targetMatches
		for i := 0; i < len(sortedMatches)-1; i++ {
			for j := i + 1; j < len(sortedMatches); j++ {
				if sortedMatches[j].Rule.Priority > sortedMatches[i].Rule.Priority {
					sortedMatches[i], sortedMatches[j] = sortedMatches[j], sortedMatches[i]
				}
			}
		}

		// Check if top priority rules have the same priority
		topPriority := sortedMatches[0].Rule.Priority
		var samePriority []MatchResult
		var differentPriority []MatchResult
		for _, m := range sortedMatches {
			if m.Rule.Priority == topPriority {
				samePriority = append(samePriority, m)
			} else {
				differentPriority = append(differentPriority, m)
			}
		}

		if len(samePriority) > 1 {
			// §8.5.3: "同 priority 时合并为一次 Kill"
			// Merge actions from all same-priority rules
			merged := samePriority[0]
			mergedRule := *merged.Rule
			for _, m := range samePriority[1:] {
				// Merge actions (deduplicate by type)
				for _, action := range m.Rule.Actions {
					found := false
					for _, existing := range mergedRule.Actions {
						if existing.Type == action.Type {
							found = true
							break
						}
					}
					if !found {
						mergedRule.Actions = append(mergedRule.Actions, action)
					}
				}
			}
			merged.Rule = &mergedRule
			result = append(result, merged)
		} else {
			result = append(result, samePriority[0])
		}

		// Lower priority rules are suppressed (only alert, don't execute)
		for _, m := range differentPriority {
			suppressedRule := *m.Rule
			suppressedRule.LearnMode = true // Force alert-only mode
			m.Rule = &suppressedRule
			result = append(result, m)
		}

		_ = target
	}

	return result
}
