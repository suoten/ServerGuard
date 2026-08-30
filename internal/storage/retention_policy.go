package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// RetentionPolicy 定义各数据类型的差异化保留期。
// 审计日志(WORM)跳过清理，证书数据永久保留。
type RetentionPolicy struct {
	RawMetrics     time.Duration // 原始指标：1h
	MinMetrics     time.Duration // 1min 聚合：7d
	HourMetrics    time.Duration // 1h 聚合：90d
	ProcessState   time.Duration // 进程状态：180d
	Alerts         time.Duration // 告警：180d
	Actions        time.Duration // 自动修复：365d
	AuditLog       time.Duration // 审计(WORM)：365d（仅元数据清理，审计内容永久）
	AttackEvents   time.Duration // 攻击事件：90d
	AttackProfiles time.Duration // 攻击画像：365d
	Findings       time.Duration // 安全发现：365d
	Snapshots      time.Duration // 快照：按 expires_at
}

// DefaultRetentionPolicy 返回默认保留策略。
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		RawMetrics:     1 * time.Hour,
		MinMetrics:     7 * 24 * time.Hour,
		HourMetrics:    90 * 24 * time.Hour,
		ProcessState:   180 * 24 * time.Hour,
		Alerts:         180 * 24 * time.Hour,
		Actions:        365 * 24 * time.Hour,
		AuditLog:       365 * 24 * time.Hour,
		AttackEvents:   90 * 24 * time.Hour,
		AttackProfiles: 365 * 24 * time.Hour,
		Findings:       365 * 24 * time.Hour,
		Snapshots:      0, // 按 expires_at 字段判断
	}
}

// retentionPolicyRow 用于数据库序列化
type retentionPolicyRow struct {
	Key      string `json:"key"`
	Duration int64  `json:"duration_hours"`
}

// SetRetentionPolicy 设置保留策略并持久化到数据库。
func (s *Storage) SetRetentionPolicy(rp RetentionPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows := []retentionPolicyRow{
		{"raw_metrics", int64(rp.RawMetrics / time.Hour)},
		{"min_metrics", int64(rp.MinMetrics / time.Hour)},
		{"hour_metrics", int64(rp.HourMetrics / time.Hour)},
		{"process_state", int64(rp.ProcessState / time.Hour)},
		{"alerts", int64(rp.Alerts / time.Hour)},
		{"actions", int64(rp.Actions / time.Hour)},
		{"audit_log", int64(rp.AuditLog / time.Hour)},
		{"attack_events", int64(rp.AttackEvents / time.Hour)},
		{"attack_profiles", int64(rp.AttackProfiles / time.Hour)},
		{"findings", int64(rp.Findings / time.Hour)},
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	for _, r := range rows {
		data, _ := json.Marshal(r)
		if _, err := tx.Exec(
			"INSERT OR REPLACE INTO retention_policy (key, value, updated_at) VALUES (?, ?, ?)",
			r.Key, string(data), time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			return fmt.Errorf("save retention policy %s: %w", r.Key, err)
		}
	}

	return tx.Commit()
}

// GetRetentionPolicy 从数据库加载保留策略，若未配置则返回默认值。
// 同时更新缓存，避免下次 purgeOldData 再查 DB。
func (s *Storage) GetRetentionPolicy() (RetentionPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rp := DefaultRetentionPolicy()

	rows, err := s.db.Query("SELECT key, value FROM retention_policy")
	if err != nil {
		if err == sql.ErrNoRows {
			return rp, nil
		}
		return rp, fmt.Errorf("query retention policy: %w", err)
	}
	defer rows.Close()

	hoursToDuration := func(h int64) time.Duration {
		return time.Duration(h) * time.Hour
	}

	for rows.Next() {
		var key, val string
		if err := rows.Scan(&key, &val); err != nil {
			continue
		}
		var row retentionPolicyRow
		if err := json.Unmarshal([]byte(val), &row); err != nil {
			continue
		}
		switch key {
		case "raw_metrics":
			rp.RawMetrics = hoursToDuration(row.Duration)
		case "min_metrics":
			rp.MinMetrics = hoursToDuration(row.Duration)
		case "hour_metrics":
			rp.HourMetrics = hoursToDuration(row.Duration)
		case "process_state":
			rp.ProcessState = hoursToDuration(row.Duration)
		case "alerts":
			rp.Alerts = hoursToDuration(row.Duration)
		case "actions":
			rp.Actions = hoursToDuration(row.Duration)
		case "audit_log":
			rp.AuditLog = hoursToDuration(row.Duration)
		case "attack_events":
			rp.AttackEvents = hoursToDuration(row.Duration)
		case "attack_profiles":
			rp.AttackProfiles = hoursToDuration(row.Duration)
		case "findings":
			rp.Findings = hoursToDuration(row.Duration)
		}
	}

	return rp, nil
}

// EnforceRetention 按保留策略清理过期数据。
// 审计表(audit_log)跳过清理以符合 WORM 要求。
func (s *Storage) EnforceRetention(rp RetentionPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	cutoff := func(d time.Duration) string {
		return now.Add(-d).UTC().Format(time.RFC3339)
	}

	// 原始指标
	if rp.RawMetrics > 0 {
		if _, err := tx.Exec("DELETE FROM metrics WHERE granularity='raw' AND timestamp < ?", cutoff(rp.RawMetrics)); err != nil {
			return fmt.Errorf("cleanup raw metrics: %w", err)
		}
	}
	// 1min 聚合（表内时间戳为 SQLite datetime() 格式"YYYY-MM-DD HH:MM:SS"，
	// 与 RFC3339 字符串直接比较会因分隔符差异失序，必须用 datetime(?) 归一后比较）
	if rp.MinMetrics > 0 {
		if _, err := tx.Exec("DELETE FROM metrics_1m WHERE timestamp < datetime(?)", cutoff(rp.MinMetrics)); err != nil {
			return fmt.Errorf("cleanup 1m metrics: %w", err)
		}
	}
	// 1h 聚合
	if rp.HourMetrics > 0 {
		if _, err := tx.Exec("DELETE FROM metrics_1h WHERE timestamp < datetime(?)", cutoff(rp.HourMetrics)); err != nil {
			return fmt.Errorf("cleanup 1h metrics: %w", err)
		}
	}
	// 告警
	if rp.Alerts > 0 {
		if _, err := tx.Exec("DELETE FROM alerts WHERE timestamp < ?", cutoff(rp.Alerts)); err != nil {
			return fmt.Errorf("cleanup alerts: %w", err)
		}
	}
	// 自动修复
	if rp.Actions > 0 {
		if _, err := tx.Exec("DELETE FROM actions WHERE timestamp < ?", cutoff(rp.Actions)); err != nil {
			return fmt.Errorf("cleanup actions: %w", err)
		}
	}
	// 审计日志：WORM，跳过清理
	// 注意：audit_log 表不执行 DELETE，确保 Write Once Read Many 语义

	// 攻击事件
	if rp.AttackEvents > 0 {
		if _, err := tx.Exec("DELETE FROM attack_events WHERE created_at < ?", cutoff(rp.AttackEvents)); err != nil {
			// 表可能不存在，忽略错误
			_ = err
		}
	}
	// 攻击画像
	if rp.AttackProfiles > 0 {
		if _, err := tx.Exec("DELETE FROM attack_profiles WHERE updated_at < ?", cutoff(rp.AttackProfiles)); err != nil {
			_ = err
		}
	}
	// 安全发现
	if rp.Findings > 0 {
		if _, err := tx.Exec("DELETE FROM findings WHERE status IN ('fixed', 'ignored', 'false_positive') AND updated_at < ?", cutoff(rp.Findings)); err != nil {
			_ = err
		}
	}
	// 快照：按 expires_at
	if _, err := tx.Exec("DELETE FROM snapshots WHERE expires_at < ?", now.UTC().Format(time.RFC3339)); err != nil {
		_ = err
	}

	return tx.Commit()
}

// initRetentionPolicySchema 初始化保留策略表（在 initSchema 中调用）。
func (s *Storage) initRetentionPolicySchema() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS retention_policy (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME NOT NULL
		);
	`)
	return err
}
