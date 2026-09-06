// Package knowledge 提供私有故障知识库能力。
// V3.9 — 每次自动修复记录"症状→根因→修复动作→效果"→ 存入 SQLite → 相似症状再次出现时提示历史方案
package knowledge

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// 私有故障知识库 (P16)
// ────────────────────────────────────────────────

// KnowledgeEntry 知识库条目
type KnowledgeEntry struct {
	ID            int64     `json:"id"`
	Symptom       string    `json:"symptom"`        // 故障症状（告警标题）
	RootCause     string    `json:"root_cause"`     // 根因分析
	Action        string    `json:"action"`         // 修复动作
	ActionResult  string    `json:"action_result"`  // 修复结果（成功/失败）
	Effect        string    `json:"effect"`         // 效果描述
	Source        string    `json:"source"`         // 来源模块（resource/log/security...）
	Severity      string    `json:"severity"`       // 严重级别
	OccurrenceCount int     `json:"occurrence_count"` // 出现次数
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	ResolvedAt    time.Time `json:"resolved_at"`
}

// KnowledgeBase 故障知识库
type KnowledgeBase struct {
	store *storage.Storage
	mu    sync.Mutex
}

// New 创建知识库
func New(store *storage.Storage) *KnowledgeBase {
	kb := &KnowledgeBase{store: store}
	kb.ensureTable()
	return kb
}

// ensureTable 确保知识库表存在
func (kb *KnowledgeBase) ensureTable() {
	db := kb.store.DB()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS knowledge_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			symptom TEXT NOT NULL,
			root_cause TEXT DEFAULT '',
			action TEXT DEFAULT '',
			action_result TEXT DEFAULT '',
			effect TEXT DEFAULT '',
			source TEXT DEFAULT '',
			severity TEXT DEFAULT '',
			occurrence_count INTEGER DEFAULT 1,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			resolved_at DATETIME,
			symptom_hash TEXT DEFAULT ''
		)`)
	if err != nil {
		fmt.Printf("[KnowledgeBase] 创建表失败: %v\n", err)
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_knowledge_symptom_hash ON knowledge_entries(symptom_hash)`)
	if err != nil {
		fmt.Printf("[KnowledgeBase] 创建索引失败: %v\n", err)
	}
}

// RecordFromEvent 从事件中记录知识
func (kb *KnowledgeBase) RecordFromEvent(event types.Event, rootCause, effect string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	symptom := event.Title
	source := event.Source
	severity := string(event.Level)
	action := ""
	actionResult := "unknown"
	effectDesc := effect

	if data, ok := event.Data.(map[string]string); ok {
		if a, exists := data["action"]; exists {
			action = a
		}
		if r, exists := data["result"]; exists {
			actionResult = r
		}
	}

	// 生成症状指纹（去重用）
	hash := symptomHash(symptom, source)

	db := kb.store.DB()

	// 检查是否已有相同指纹的记录
	var existingID int64
	var existingCount int
	err := db.QueryRow(
		`SELECT id, occurrence_count FROM knowledge_entries WHERE symptom_hash = ? ORDER BY last_seen DESC LIMIT 1`,
		hash,
	).Scan(&existingID, &existingCount)

	if err == nil {
		// 更新已有记录
		_, err = db.Exec(
			`UPDATE knowledge_entries SET occurrence_count = ?, last_seen = ?, root_cause = ?, action = ?, action_result = ?, effect = ?, resolved_at = ? WHERE id = ?`,
			existingCount+1, time.Now(), rootCause, action, actionResult, effectDesc, time.Now(), existingID,
		)
		if err != nil {
			fmt.Printf("[KnowledgeBase] 更新记录失败: %v\n", err)
		}
		return
	}

	// 插入新记录
	_, err = db.Exec(
		`INSERT INTO knowledge_entries (symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at, symptom_hash) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
		symptom, rootCause, action, actionResult, effectDesc, source, severity, time.Now(), time.Now(), time.Now(), hash,
	)
	if err != nil {
		fmt.Printf("[KnowledgeBase] 插入记录失败: %v\n", err)
	}
}

// Record 手动记录知识
func (kb *KnowledgeBase) Record(entry KnowledgeEntry) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	hash := symptomHash(entry.Symptom, entry.Source)
	db := kb.store.DB()
	_, err := db.Exec(
		`INSERT INTO knowledge_entries (symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at, symptom_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Symptom, entry.RootCause, entry.Action, entry.ActionResult, entry.Effect, entry.Source, entry.Severity,
		1, time.Now(), time.Now(), time.Now(), hash,
	)
	if err != nil {
		fmt.Printf("[KnowledgeBase] 插入记录失败: %v\n", err)
	}
}

// RecordIncident 记录一次已解决的故障事件（聚合式）：
// 相同症状指纹已存在时累加次数并刷新处置经验，否则新建。
func (kb *KnowledgeBase) RecordIncident(entry KnowledgeEntry) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	hash := symptomHash(entry.Symptom, entry.Source)
	db := kb.store.DB()

	var existingID int64
	var existingCount int
	err := db.QueryRow(
		`SELECT id, occurrence_count FROM knowledge_entries WHERE symptom_hash = ? ORDER BY last_seen DESC LIMIT 1`,
		hash,
	).Scan(&existingID, &existingCount)

	if err == nil {
		action := entry.Action
		if action == "" {
			// 保留历史有效处置，不用空值覆盖
			_ = db.QueryRow(`SELECT action FROM knowledge_entries WHERE id = ?`, existingID).Scan(&action)
		}
		_, err = db.Exec(
			`UPDATE knowledge_entries SET occurrence_count = ?, last_seen = ?, root_cause = ?, action = ?, action_result = ?, effect = ?, resolved_at = ? WHERE id = ?`,
			existingCount+1, time.Now(), entry.RootCause, action, entry.ActionResult, entry.Effect, time.Now(), existingID,
		)
		if err != nil {
			fmt.Printf("[KnowledgeBase] 更新记录失败: %v\n", err)
		}
		return
	}

	firstSeen := entry.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = time.Now()
	}
	_, err = db.Exec(
		`INSERT INTO knowledge_entries (symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at, symptom_hash) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
		entry.Symptom, entry.RootCause, entry.Action, entry.ActionResult, entry.Effect, entry.Source, entry.Severity,
		firstSeen, time.Now(), time.Now(), hash,
	)
	if err != nil {
		fmt.Printf("[KnowledgeBase] 插入记录失败: %v\n", err)
	}
}

// FindSimilar 查找相似故障的历史解决方案
func (kb *KnowledgeBase) FindSimilar(symptom string, source string, limit int) ([]KnowledgeEntry, error) {
	if limit <= 0 {
		limit = 5
	}

	db := kb.store.DB()
	hash := symptomHash(symptom, source)

	// 先精确匹配指纹
	rows, err := db.Query(
		`SELECT id, symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at FROM knowledge_entries WHERE symptom_hash = ? ORDER BY last_seen DESC LIMIT ?`,
		hash, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []KnowledgeEntry
	for rows.Next() {
		var e KnowledgeEntry
		var resolvedAt sql.NullTime
		if err := rows.Scan(&e.ID, &e.Symptom, &e.RootCause, &e.Action, &e.ActionResult, &e.Effect, &e.Source, &e.Severity, &e.OccurrenceCount, &e.FirstSeen, &e.LastSeen, &resolvedAt); err == nil {
			if resolvedAt.Valid {
				e.ResolvedAt = resolvedAt.Time
			}
			entries = append(entries, e)
		}
	}

	// 如果精确匹配没找到，尝试模糊匹配（关键词）
	if len(entries) == 0 {
		keywords := extractKeywords(symptom)
		if len(keywords) > 0 {
			// 构建模糊查询条件
			conditions := make([]string, len(keywords))
			args := make([]interface{}, len(keywords))
			for i, kw := range keywords {
				conditions[i] = "symptom LIKE ?"
				args[i] = "%" + kw + "%"
			}
			query := fmt.Sprintf(
				`SELECT id, symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at FROM knowledge_entries WHERE %s ORDER BY occurrence_count DESC, last_seen DESC LIMIT ?`,
				strings.Join(conditions, " OR "),
			)
			args = append(args, limit)
			rows, err = db.Query(query, args...)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var e KnowledgeEntry
					var resolvedAt sql.NullTime
					if err := rows.Scan(&e.ID, &e.Symptom, &e.RootCause, &e.Action, &e.ActionResult, &e.Effect, &e.Source, &e.Severity, &e.OccurrenceCount, &e.FirstSeen, &e.LastSeen, &resolvedAt); err == nil {
						if resolvedAt.Valid {
							e.ResolvedAt = resolvedAt.Time
						}
						entries = append(entries, e)
					}
				}
			}
		}
	}

	return entries, nil
}

// GetAll 获取所有知识库条目（分页）
func (kb *KnowledgeBase) GetAll(limit, offset int) ([]KnowledgeEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	db := kb.store.DB()
	rows, err := db.Query(
		`SELECT id, symptom, root_cause, action, action_result, effect, source, severity, occurrence_count, first_seen, last_seen, resolved_at FROM knowledge_entries ORDER BY last_seen DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []KnowledgeEntry
	for rows.Next() {
		var e KnowledgeEntry
		var resolvedAt sql.NullTime
		if err := rows.Scan(&e.ID, &e.Symptom, &e.RootCause, &e.Action, &e.ActionResult, &e.Effect, &e.Source, &e.Severity, &e.OccurrenceCount, &e.FirstSeen, &e.LastSeen, &resolvedAt); err == nil {
			if resolvedAt.Valid {
				e.ResolvedAt = resolvedAt.Time
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// GetStats 获取知识库统计
func (kb *KnowledgeBase) GetStats() map[string]interface{} {
	db := kb.store.DB()
	stats := map[string]interface{}{}

	var total int64
	db.QueryRow(`SELECT COUNT(*) FROM knowledge_entries`).Scan(&total)
	stats["total_entries"] = total

	var recurring int64
	db.QueryRow(`SELECT COUNT(*) FROM knowledge_entries WHERE occurrence_count > 1`).Scan(&recurring)
	stats["recurring_issues"] = recurring

	// 按来源统计
	rows, err := db.Query(`SELECT source, COUNT(*) as cnt FROM knowledge_entries GROUP BY source ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		bySource := make(map[string]int64)
		for rows.Next() {
			var src string
			var cnt int64
			rows.Scan(&src, &cnt)
			bySource[src] = cnt
		}
		stats["by_source"] = bySource
	}

	return stats
}

// symptomHash 生成症状指纹
func symptomHash(symptom, source string) string {
	// 将症状和来源合并，去重后生成简单 hash
	combined := strings.ToLower(strings.TrimSpace(symptom + "|" + source))
	// 去除数字和特殊字符
	combined = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '|' {
			return r
		}
		return -1
	}, combined)
	return combined
}

// extractKeywords 提取关键词（简单分词）
func extractKeywords(text string) []string {
	// 去除常见停用词
	stopWords := map[string]bool{
		"的": true, "了": true, "是": true, "在": true, "和": true,
		"the": true, "a": true, "an": true, "is": true, "in": true,
	}

	// 按非字母数字分割
	var keywords []string
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r < 128
	})

	for _, w := range words {
		if len(w) >= 2 && !stopWords[w] {
			keywords = append(keywords, w)
		}
	}

	// 中文字符按 2 字组合
	runes := []rune(text)
	for i := 0; i+1 < len(runes); i++ {
		if runes[i] >= 0x4e00 && runes[i] <= 0x9fff &&
			runes[i+1] >= 0x4e00 && runes[i+1] <= 0x9fff {
			kw := string(runes[i]) + string(runes[i+1])
			if !stopWords[kw] {
				keywords = append(keywords, kw)
			}
		}
	}

	// 限制关键词数量
	if len(keywords) > 5 {
		keywords = keywords[:5]
	}

	return keywords
}
