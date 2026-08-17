package ruleengine

import (
	"sort"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// ConflictResolver 多规则同命中时的冲突解决器
type ConflictResolver struct {
	mu              sync.Mutex
	whitelist       map[string]bool      // 白名单 IP/进程（一票否决）
	triggerCount    map[string]int       // ruleID -> 连续触发次数
	maxTriggers     int                  // 最大触发次数
	silenceDuration time.Duration        // 静默期时长
	silencedUntil   map[string]time.Time // ruleID -> 静默截止时间
}

// NewConflictResolver 创建冲突解决器
func NewConflictResolver() *ConflictResolver {
	return &ConflictResolver{
		whitelist:       make(map[string]bool),
		triggerCount:    make(map[string]int),
		maxTriggers:     3,
		silenceDuration: 1 * time.Hour,
		silencedUntil:   make(map[string]time.Time),
	}
}

// SetWhitelist 设置白名单
func (cr *ConflictResolver) SetWhitelist(items []string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.whitelist = make(map[string]bool)
	for _, item := range items {
		cr.whitelist[item] = true
	}
}

// AddWhitelist 添加白名单项
func (cr *ConflictResolver) AddWhitelist(item string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.whitelist[item] = true
}

// Resolve 解决多规则冲突，返回最终应该执行的规则列表
func (cr *ConflictResolver) Resolve(results []MatchResult, target string) []MatchResult {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// 白名单一票否决
	if cr.whitelist[target] {
		return nil
	}

	// 过滤掉静默期中的规则
	now := time.Now()
	var activeResults []MatchResult
	for _, r := range results {
		if r.Rule == nil {
			continue
		}
		if silencedUntil, exists := cr.silencedUntil[r.Rule.ID]; exists && now.Before(silencedUntil) {
			continue
		}
		activeResults = append(activeResults, r)
	}

	if len(activeResults) == 0 {
		return nil
	}

	// 按 priority 降序排序
	sort.Slice(activeResults, func(i, j int) bool {
		return activeResults[i].Rule.Priority > activeResults[j].Rule.Priority
	})

	// 合并同 priority 的规则为一次操作
	var resolved []MatchResult
	currentPriority := activeResults[0].Rule.Priority
	var mergedMetrics []types.Metric

	for _, r := range activeResults {
		if r.Rule.Priority == currentPriority {
			mergedMetrics = append(mergedMetrics, r.Metrics...)
		} else {
			// 输出合并结果
			if len(resolved) == 0 {
				resolved = append(resolved, MatchResult{
					Rule:    activeResults[0].Rule,
					Metrics: mergedMetrics,
				})
			}
			currentPriority = r.Rule.Priority
			mergedMetrics = r.Metrics
		}

		// 更新触发计数
		cr.triggerCount[r.Rule.ID]++
		if cr.triggerCount[r.Rule.ID] >= cr.maxTriggers {
			cr.silencedUntil[r.Rule.ID] = now.Add(cr.silenceDuration)
			cr.triggerCount[r.Rule.ID] = 0
		}
	}

	// 确保最后一个合并结果被输出
	if len(resolved) == 0 && len(mergedMetrics) > 0 {
		resolved = append(resolved, MatchResult{
			Rule:    activeResults[0].Rule,
			Metrics: mergedMetrics,
		})
	}

	return resolved
}

// ResetTriggerCount 重置规则的触发计数
func (cr *ConflictResolver) ResetTriggerCount(ruleID string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	delete(cr.triggerCount, ruleID)
	delete(cr.silencedUntil, ruleID)
}

// IsSilenced 检查规则是否在静默期
func (cr *ConflictResolver) IsSilenced(ruleID string) bool {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if silencedUntil, exists := cr.silencedUntil[ruleID]; exists {
		return time.Now().Before(silencedUntil)
	}
	return false
}

// GetTriggerCount 获取规则连续触发次数
func (cr *ConflictResolver) GetTriggerCount(ruleID string) int {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.triggerCount[ruleID]
}
