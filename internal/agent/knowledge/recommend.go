package knowledge

import (
	"fmt"
	"strings"
	"time"
)

// ────────────────────────────────────────────────
// V4.0 — 知识库反哺决策
// 让服务器"吃一堀长一智"：同一症状再次出现时自动推荐上次有效的处置动作
// ────────────────────────────────────────────────

// ActionRecommendation 处置动作推荐
type ActionRecommendation struct {
	Symptom        string    `json:"symptom"`
	RecommendedAction string  `json:"recommended_action"`
	Reason         string    `json:"reason"`
	Confidence     float64   `json:"confidence"`   // 推荐置信度（基于历史成功率）
	OccurrenceCount int      `json:"occurrence_count"` // 该症状历史出现次数
	LastAction     string    `json:"last_action"`
	LastResult     string    `json:"last_result"`
	LastSeen       time.Time `json:"last_seen"`
	ShouldAutoExecute bool   `json:"should_auto_execute"` // 是否建议自动执行（第3次+且成功率>80%）
}

// GetRecommendation 根据症状获取处置动作推荐
// 核心逻辑：
//   - 第1次出现：仅记录，不推荐
//   - 第2次出现：推荐上次处置动作，但不自动执行
//   - 第3次+且上次成功：推荐自动执行（仍需走五层安全审批）
//   - 反复出现(>5次)且无有效修复：建议彻底排查根因
func (kb *KnowledgeBase) GetRecommendation(symptom, source string) *ActionRecommendation {
	entries, err := kb.FindSimilar(symptom, source, 5)
	if err != nil || len(entries) == 0 {
		return nil
	}

	totalOccurrences := 0
	successCount := 0
	var bestEntry *KnowledgeEntry
	for i := range entries {
		totalOccurrences += entries[i].OccurrenceCount
		if entries[i].ActionResult == "success" {
			successCount += entries[i].OccurrenceCount
		}
		if bestEntry == nil || entries[i].OccurrenceCount > bestEntry.OccurrenceCount {
			bestEntry = &entries[i]
		}
	}

	if bestEntry == nil || bestEntry.Action == "" {
		// 有历史记录但没有有效动作
		if totalOccurrences >= 5 {
			return &ActionRecommendation{
				Symptom:     symptom,
				Reason:      fmt.Sprintf("该症状已出现过 %d 次，但历史无有效修复动作，建议彻底排查根因", totalOccurrences),
				Confidence:  0.3,
				OccurrenceCount: totalOccurrences,
				LastSeen:    bestEntry.LastSeen,
			}
		}
		return nil
	}

	successRate := float64(successCount) / float64(totalOccurrences)
	rec := &ActionRecommendation{
		Symptom:          symptom,
		RecommendedAction: bestEntry.Action,
		LastAction:       bestEntry.Action,
		LastResult:       bestEntry.ActionResult,
		LastSeen:         bestEntry.LastSeen,
		OccurrenceCount:  totalOccurrences,
		Confidence:       successRate,
	}

	// 构建推荐理由
	var reasons []string
	reasons = append(reasons, fmt.Sprintf("该症状历史出现 %d 次", totalOccurrences))
	if bestEntry.ActionResult == "success" {
		reasons = append(reasons, fmt.Sprintf("上次执行「%s」成功（%s）", bestEntry.Action, bestEntry.LastSeen.Format("2006-01-02 15:04")))
	} else {
		reasons = append(reasons, fmt.Sprintf("上次执行「%s」结果：%s", bestEntry.Action, bestEntry.ActionResult))
	}

	// 判断是否建议自动执行
	if totalOccurrences >= 3 && successRate >= 0.8 && bestEntry.ActionResult == "success" {
		rec.ShouldAutoExecute = true
		reasons = append(reasons, "已出现3次以上且历史成功率≥80%，建议自动执行（需安全审批确认）")
	} else if totalOccurrences >= 3 {
		reasons = append(reasons, "已反复出现，建议人工确认后执行")
	}

	// 反复出现且修复无效
	if totalOccurrences >= 5 && successRate < 0.5 {
		reasons = append(reasons, "⚠️ 该故障反复出现且历史修复效果不佳，建议彻底排查根因而非反复重启")
		rec.ShouldAutoExecute = false
		rec.Confidence = 0.2
	}

	rec.Reason = strings.Join(reasons, "；")
	return rec
}

// GetRecurring 获取反复出现的问题（出现次数 ≥ threshold）
// 用于"反复故障"面板展示和运维复盘
func (kb *KnowledgeBase) GetRecurring(threshold int, limit int) ([]KnowledgeEntry, error) {
	if threshold <= 0 {
		threshold = 3
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	db := kb.store.DB()
	rows, err := db.Query(
		`SELECT id, symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at
		 FROM knowledge_entries WHERE occurrence_count >= ?
		 ORDER BY occurrence_count DESC, last_seen DESC LIMIT ?`,
		threshold, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []KnowledgeEntry
	for rows.Next() {
		var e KnowledgeEntry
		var resolvedAt interface{}
		if err := rows.Scan(&e.ID, &e.Symptom, &e.RootCause, &e.Action, &e.ActionResult, &e.Effect, &e.Source, &e.Severity, &e.OccurrenceCount, &e.FirstSeen, &e.LastSeen, &resolvedAt); err == nil {
			if t, ok := resolvedAt.(time.Time); ok {
				e.ResolvedAt = t
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// RecordActionOutcome 记录处置动作的执行结果
// 在动作执行后调用，更新知识库中对应条目的效果记录
func (kb *KnowledgeBase) RecordActionOutcome(symptom, source, action, result, effect string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	hash := symptomHash(symptom, source)
	db := kb.store.DB()

	// 查找最近的匹配记录
	var existingID int64
	var existingCount int
	err := db.QueryRow(
		`SELECT id, occurrence_count FROM knowledge_entries WHERE symptom_hash = ? ORDER BY last_seen DESC LIMIT 1`,
		hash,
	).Scan(&existingID, &existingCount)

	if err == nil {
		// 更新已有记录
		_, err = db.Exec(
			`UPDATE knowledge_entries SET occurrence_count = ?, last_seen = ?, action = ?, action_result = ?, effect = ?, resolved_at = ? WHERE id = ?`,
			existingCount+1, time.Now(), action, result, effect, time.Now(), existingID,
		)
		if err != nil {
			fmt.Printf("[KnowledgeBase] 更新动作结果失败: %v\n", err)
		}
		return
	}

	// 插入新记录
	_, err = db.Exec(
		`INSERT INTO knowledge_entries (symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at, symptom_hash) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
		symptom, "", action, result, effect, source, "action_record", time.Now(), time.Now(), time.Now(), hash,
	)
	if err != nil {
		fmt.Printf("[KnowledgeBase] 插入动作结果失败: %v\n", err)
	}
}

// GetSuccessRate 讔回某类症状的修复成功率
func (kb *KnowledgeBase) GetSuccessRate(symptom, source string) float64 {
	entries, err := kb.FindSimilar(symptom, source, 10)
	if err != nil || len(entries) == 0 {
		return 0
	}

	total := 0
	success := 0
	for _, e := range entries {
		total += e.OccurrenceCount
		if e.ActionResult == "success" {
			success += e.OccurrenceCount
		}
	}
	if total == 0 {
		return 0
	}
	return float64(success) / float64(total)
}
