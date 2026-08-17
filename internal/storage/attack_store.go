package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AttackEvent 攻击事件
type AttackEvent struct {
	ID          string    `json:"id"`
	EventType   string    `json:"event_type"`
	SourceIP    string    `json:"source_ip"`
	Target      string    `json:"target"`
	Severity    string    `json:"severity"`
	Detail      string    `json:"detail"`
	ActionTaken string    `json:"action_taken"`
	TraceID     string    `json:"trace_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// AttackProfile 攻击画像
type AttackProfile struct {
ID              string    `json:"id"`
SourceIP        string    `json:"source_ip"`
GeoLocation     string    `json:"geo_location"`
AttackTypes     string    `json:"attack_types"`
TotalAttacks    int       `json:"total_attacks"`
ThreatLevel     string    `json:"threat_level"`
FirstSeen       time.Time `json:"first_seen"`
LastSeen        time.Time `json:"last_seen"`
Duration        int64     `json:"duration"`
AffectedModules string    `json:"affected_modules"`
Trend           string    `json:"trend"`
Confidence      float64   `json:"confidence"`
Detail          string    `json:"detail"`
CreatedAt       time.Time `json:"created_at"`
UpdatedAt       time.Time `json:"updated_at"`
}

// SaveAttackEvent 保存攻击事件
func (s *Storage) SaveAttackEvent(e *AttackEvent) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`INSERT INTO attack_events
		(id, event_type, source_ip, target, severity, detail, action_taken, trace_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.EventType, e.SourceIP, e.Target, e.Severity, e.Detail, e.ActionTaken, e.TraceID, e.CreatedAt)
	return err
}

// QueryAttackEvents 查询攻击事件
func (s *Storage) QueryAttackEvents(eventType, sourceIP, severity string, since time.Time, limit int) ([]AttackEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, event_type, source_ip, target, severity, detail, action_taken, trace_id, created_at FROM attack_events WHERE created_at >= ?"
	args := []interface{}{since}
	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if sourceIP != "" {
		query += " AND source_ip = ?"
		args = append(args, sourceIP)
	}
	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query attack events: %w", err)
	}
	defer rows.Close()

	var events []AttackEvent
	for rows.Next() {
		var e AttackEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.SourceIP, &e.Target, &e.Severity, &e.Detail, &e.ActionTaken, &e.TraceID, &e.CreatedAt); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, nil
}

// QueryBannedAttackEvents 查询已封禁的攻击事件（action_taken 以 banned_ 开头）
func (s *Storage) QueryBannedAttackEvents(limit int) ([]AttackEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, event_type, source_ip, target, severity, detail, action_taken, trace_id, created_at FROM attack_events WHERE action_taken LIKE 'banned_%' ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query banned attack events: %w", err)
	}
	defer rows.Close()

	var events []AttackEvent
	for rows.Next() {
		var e AttackEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.SourceIP, &e.Target, &e.Severity, &e.Detail, &e.ActionTaken, &e.TraceID, &e.CreatedAt); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, nil
}

// SaveAttackProfile 保存攻击画像
func (s *Storage) SaveAttackProfile(p *AttackProfile) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	s.mu.Lock()
	defer s.mu.Unlock()

_, err := s.db.Exec(`INSERT OR REPLACE INTO attack_profiles
(id, source_ip, geo_location, attack_types, total_attacks, threat_level, first_seen, last_seen, duration, affected_modules, trend, confidence, detail, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
p.ID, p.SourceIP, p.GeoLocation, p.AttackTypes, p.TotalAttacks, p.ThreatLevel, p.FirstSeen, p.LastSeen, p.Duration,
p.AffectedModules, p.Trend, p.Confidence, p.Detail, p.CreatedAt, p.UpdatedAt)
	return err
}

// QueryAttackProfiles 查询攻击画像
func (s *Storage) QueryAttackProfiles(sourceIP string, since time.Time, limit int) ([]AttackProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, source_ip, geo_location, attack_types, total_attacks, threat_level, first_seen, last_seen, duration, affected_modules, trend, confidence, detail, created_at, updated_at FROM attack_profiles WHERE updated_at >= ?"
	args := []interface{}{since}
	if sourceIP != "" {
		query += " AND source_ip = ?"
		args = append(args, sourceIP)
	}
	query += " ORDER BY updated_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query attack profiles: %w", err)
	}
	defer rows.Close()

	var profiles []AttackProfile
	for rows.Next() {
		var p AttackProfile
if err := rows.Scan(&p.ID, &p.SourceIP, &p.GeoLocation, &p.AttackTypes, &p.TotalAttacks, &p.ThreatLevel, &p.FirstSeen, &p.LastSeen, &p.Duration,
&p.AffectedModules, &p.Trend, &p.Confidence, &p.Detail, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// PurgeOldAttackEvents 清理过期攻击事件（默认保留 90 天，可通过参数自定义）
func (s *Storage) PurgeOldAttackEvents(retention ...time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	retentionDays := 90 * 24 * time.Hour
	if len(retention) > 0 && retention[0] > 0 {
		retentionDays = retention[0]
	}
	cutoff := time.Now().Add(-retentionDays)
	_, err := s.db.Exec("DELETE FROM attack_events WHERE created_at < ?", cutoff)
	return err
}

// PurgeOldAttackProfiles 清理过期攻击画像（默认保留 1 年，可通过参数自定义）
func (s *Storage) PurgeOldAttackProfiles(retention ...time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	retentionYears := 365 * 24 * time.Hour
	if len(retention) > 0 && retention[0] > 0 {
		retentionYears = retention[0]
	}
	cutoff := time.Now().Add(-retentionYears)
	_, err := s.db.Exec("DELETE FROM attack_profiles WHERE updated_at < ?", cutoff)
	return err
}

// PurgeAttackEventsBySeverity 按严重级别差异化清理攻击事件。
// severityRetention 映射：severity -> 保留时长。未在映射中的 severity 不清理。
func (s *Storage) PurgeAttackEventsBySeverity(severityRetention map[string]time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for severity, retention := range severityRetention {
		if retention <= 0 {
			continue
		}
		cutoff := now.Add(-retention)
		if _, err := s.db.Exec("DELETE FROM attack_events WHERE severity = ? AND created_at < ?", severity, cutoff); err != nil {
			_ = err
		}
	}
	return nil
}
