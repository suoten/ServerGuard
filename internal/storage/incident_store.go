package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/suoten/serverguard/internal/types"
)

// incident_store 提供故障事件（Incident）的持久化。
// 根因链推理引擎把多条相关告警关联成一条因果链，落库后供面板与复盘使用。

func (s *Storage) ensureIncidentSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS incidents (
	id TEXT PRIMARY KEY,
	started_at DATETIME NOT NULL,
	ended_at DATETIME,
	status TEXT NOT NULL DEFAULT 'open',
	root_title TEXT NOT NULL,
	root_source TEXT NOT NULL,
	root_time DATETIME NOT NULL,
	member_alerts TEXT NOT NULL DEFAULT '[]',
	chain TEXT NOT NULL DEFAULT '[]',
	actions TEXT NOT NULL DEFAULT '[]',
	summary TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_started ON incidents(started_at DESC);
`)
	return err
}

// SaveIncident 插入或更新一个故障事件（按 ID upsert）。
func (s *Storage) SaveIncident(inc types.Incident) error {
	if err := s.ensureIncidentSchema(); err != nil {
		return err
	}
	members, _ := json.Marshal(inc.MemberAlerts)
	chain, _ := json.Marshal(inc.Chain)
	actions, _ := json.Marshal(inc.Actions)

	s.mu.Lock()
	defer s.mu.Unlock()
	var endedAt interface{}
	if inc.EndedAt != nil {
		endedAt = inc.EndedAt
	}
	_, err := s.db.Exec(`
INSERT INTO incidents (id, started_at, ended_at, status, root_title, root_source, root_time,
                       member_alerts, chain, actions, summary, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
ON CONFLICT(id) DO UPDATE SET
	ended_at = excluded.ended_at,
	status = excluded.status,
	member_alerts = excluded.member_alerts,
	chain = excluded.chain,
	actions = excluded.actions,
	summary = excluded.summary,
	updated_at = datetime('now')`,
		inc.ID, inc.StartedAt, endedAt, inc.Status, inc.RootTitle, inc.RootSource, inc.RootTime,
		string(members), string(chain), string(actions), inc.Summary)
	return err
}

// GetIncidents 查询故障事件（open 优先，其次按开始时间倒序）。
func (s *Storage) GetIncidents(status string, limit int) ([]types.Incident, error) {
	if err := s.ensureIncidentSchema(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.Query(
			`SELECT id, started_at, ended_at, status, root_title, root_source, root_time,
			        member_alerts, chain, actions, summary
			 FROM incidents WHERE status = ? ORDER BY started_at DESC LIMIT ?`, status, limit)
	} else {
		rows, err = s.db.Query(
			`SELECT id, started_at, ended_at, status, root_title, root_source, root_time,
			        member_alerts, chain, actions, summary
			 FROM incidents ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, started_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIncidents(rows)
}

// GetIncident 按 ID 取单个故障事件。
func (s *Storage) GetIncident(id string) (*types.Incident, error) {
	if err := s.ensureIncidentSchema(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(
		`SELECT id, started_at, ended_at, status, root_title, root_source, root_time,
		        member_alerts, chain, actions, summary
		 FROM incidents WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	incs, err := scanIncidents(rows)
	if err != nil || len(incs) == 0 {
		return nil, err
	}
	return &incs[0], nil
}

// NewIncidentID 生成故障事件 ID。
func NewIncidentID() string {
	return "INC-" + uuid.NewString()[:8]
}

func scanIncidents(rows *sql.Rows) ([]types.Incident, error) {
	var out []types.Incident
	for rows.Next() {
		var inc types.Incident
		var endedAt sql.NullTime
		var members, chain, actions string
		if err := rows.Scan(&inc.ID, &inc.StartedAt, &endedAt, &inc.Status,
			&inc.RootTitle, &inc.RootSource, &inc.RootTime,
			&members, &chain, &actions, &inc.Summary); err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		if endedAt.Valid {
			t := endedAt.Time
			inc.EndedAt = &t
		}
		_ = json.Unmarshal([]byte(members), &inc.MemberAlerts)
		_ = json.Unmarshal([]byte(chain), &inc.Chain)
		_ = json.Unmarshal([]byte(actions), &inc.Actions)
		out = append(out, inc)
	}
	return out, nil
}

// ResolveStaleIncidents 把超过 maxAge 无新成员的 open 事件标记为 resolved。
// 返回本次关闭的事件（供引擎做知识沉淀与通知）。
func (s *Storage) ResolveStaleIncidents(maxAge time.Duration) ([]types.Incident, error) {
	if err := s.ensureIncidentSchema(); err != nil {
		return nil, err
	}
	// 查询与更新放在锁外：SQLite 写锁期间持 s.mu 会把其他 goroutine
	// 的所有存储操作（告警落库/自愈记录）全部串行阻塞，DB 慢时放大为全局卡顿。
	// s.mu 仅用于保护内存状态，而本函数纯 DB 操作，无需持锁。
	rows, err := s.db.Query(
		`SELECT id, started_at, ended_at, status, root_title, root_source, root_time,
		        member_alerts, chain, actions, summary
		 FROM incidents WHERE status = 'open' AND updated_at < ?`,
		time.Now().Add(-maxAge).UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, err
	}
	stale, err := scanIncidents(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, inc := range stale {
		if _, err := s.db.Exec(
			`UPDATE incidents SET status='resolved', ended_at=?, updated_at=datetime('now') WHERE id=?`,
			now, inc.ID); err != nil {
			continue
		}
	}
	return stale, nil
}
