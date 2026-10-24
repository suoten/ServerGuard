package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"

	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/types"
)

// Storage provides encrypted SQLite storage for the agent.
type Storage struct {
	db   *sql.DB
	mu   sync.RWMutex
	path string
	// 向宝塔学习：缓存 retention policy，不每次维护都查 DB
	cachedRP RetentionPolicy
	rpLoaded bool

	// incidents 表 schema 是否已初始化（每实例一次，避免每次操作跑 DDL）
	incidentSchemaReady bool

	// stopCh 关闭后 maintenanceLoop 退出，Close 后不再触碰已关闭的 db
	stopCh   chan struct{}
	stopOnce sync.Once

	// 【磁盘满保护】写入降级标志：磁盘满时设为 true，所有写操作快速失败不阻塞
	// 磁盘满时 SQLite 的 _busy_timeout=5000 会导致每次写入阻塞 5 秒
	// 设为降级后，SaveMetrics/SaveAlert/SaveAction 等直接返回 error 不碰 DB
	writeDegraded atomic.Bool
	// 降级后定期检测磁盘恢复，恢复后自动退出降级
	degradeCheckAt atomic.Int64 // unix timestamp of next disk check
}

// New creates a new Storage instance and initializes the database.
func New(path string) (*Storage, error) {
	// Ensure directory exists
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create storage directory: %w", err)
		}
	}

	// Open database with WAL mode and foreign keys
	// 启用 auto_vacuum=incremental：DELETE 后的空间不自动回收，需要 incremental_vacuum 回收
	// 这对 metrics 等高频写入/删除的表至关重要，否则 db 文件只会增长不会缩小
	dsn := path + "?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_cache_size=-2000&_auto_vacuum=incremental"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Connection pool settings
	// 向宝塔学习：WAL 模式下 SQLite 支持并发读 + 单写
	// 原来只开 1 个连接，读查询和写操作互斥等待 → 慢查询阻塞采集写入 → 502
	// WAL 模式下开多个连接：写串行（SQLite 保证），读并行
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)

	s := &Storage{db: db, path: path, stopCh: make(chan struct{})}

	// Initialize schema
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// 【启动加速】如果之前磁盘满导致 WAL 文件巨大（可能几 GB），
	// 启动时立即做一次 TRUNCATE checkpoint 合并 WAL 到主库并截断 WAL 文件，
	// 否则后续每个查询都要先回放 WAL，导致面板登录等所有操作变慢。
	walPath := path + "-wal"
	if walSize, e := os.Stat(walPath); e == nil && walSize.Size() > 10*1024*1024 {
		fmt.Fprintf(os.Stderr, "[storage] WAL file is %dMB, running startup checkpoint to merge...\n", walSize.Size()/(1024*1024))
		// TRUNCATE 模式：合并 WAL 到主库后截断 WAL 文件
		s.mu.Lock()
		_, ckptErr := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		s.mu.Unlock()
		if ckptErr != nil {
			fmt.Fprintf(os.Stderr, "[storage] startup WAL checkpoint failed: %v (will retry in maintenance loop)\n", ckptErr)
		} else {
			fmt.Fprintf(os.Stderr, "[storage] startup WAL checkpoint completed\n")
		}
	}

	// 确保 auto_vacuum 已启用
	// auto_vacuum 只能在数据库创建时或 VACUUM 时设置
	// 对已有数据库（auto_vacuum=0），需要在后台执行一次 VACUUM 切换模式
	// 【OOM 修复】VACUUM 需要创建临时副本，大数据库（>100MB）会导致内存超限被 OOM Kill
	// 对于大数据库，跳过 VACUUM，改为使用 incremental_vacuum 逐步回收空间
	var autoVacuum int
	err = db.QueryRow("PRAGMA auto_vacuum").Scan(&autoVacuum)
	if err == nil && autoVacuum == 0 {
		// 检查数据库文件大小，大数据库不做 VACUUM（会 OOM）
		var dbSize int64 = 0
		if fi, e := os.Stat(path); e == nil {
			dbSize = fi.Size()
		}
		dbSizeMB := dbSize / (1024 * 1024)
		if dbSizeMB > 100 {
			// 大数据库：跳过 VACUUM，只设置 auto_vacuum 模式
			// 下次 VACUUM INTO 或手动维护时才会切换模式
			fmt.Fprintf(os.Stderr, "[storage] auto_vacuum not enabled but DB is %dMB, skipping VACUUM to avoid OOM. auto_vacuum will activate on next VACUUM.\n", dbSizeMB)
			db.Exec("PRAGMA auto_vacuum=incremental")
		} else {
			// 小数据库：在后台执行一次 VACUUM 切换模式
			// 【启动加速】延迟 60 秒执行，让面板和采集先启动起来
			db.Exec("PRAGMA auto_vacuum=incremental")
			go func() {
				time.Sleep(60 * time.Second)
				fmt.Fprintf(os.Stderr, "[storage] auto_vacuum not enabled, running background VACUUM to switch mode (DB size: %dMB)...\n", dbSizeMB)
				// VACUUM 是 SQLite 独占操作，不需要持 Go mutex
				// 持锁会阻塞所有其他 DB 操作 60+ 秒导致面板登录超时
				_, err := s.db.Exec("VACUUM")
				if err != nil {
					fmt.Fprintf(os.Stderr, "[storage] background VACUUM failed: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "[storage] background VACUUM completed, auto_vacuum=incremental now active\n")
				}
			}()
		}
	}

	// Start maintenance routines
	go s.maintenanceLoop()

	return s, nil
}

// Close stops the maintenance loop and closes the database.
func (s *Storage) Close() error {
	s.stopOnce.Do(func() { close(s.stopCh) })
	return s.db.Close()
}

// IsWriteDegraded 检查存储是否处于写入降级模式（磁盘满）。
// 降级时所有写操作快速失败，避免 SQLite _busy_timeout=5000 导致 5 秒阻塞。
func (s *Storage) IsWriteDegraded() bool {
	// 降级时每 30 秒检测一次磁盘是否恢复
	if s.writeDegraded.Load() {
		now := time.Now().Unix()
		nextCheck := s.degradeCheckAt.Load()
		if now >= nextCheck {
			s.degradeCheckAt.Store(now + 30) // 30 秒后再检测
			// 尝试一次轻量写入检测磁盘是否恢复
			// 注意：表名是 kv_store（不是 kv），原代码写错表名导致降级模式永远无法退出
			s.mu.Lock()
			_, err := s.db.Exec("INSERT OR IGNORE INTO kv_store (key, value, updated_at) VALUES ('_degrade_check', '1', ?)", time.Now().UTC().Format(time.RFC3339))
			s.mu.Unlock()
			if err == nil {
				// 写入成功，磁盘已恢复
				s.writeDegraded.Store(false)
				fmt.Fprintf(os.Stderr, "[storage] 磁盘已恢复，退出写入降级模式\n")
				return false
			}
		}
		return true
	}
	return false
}

// SetWriteDegraded 设置写入降级模式（由外部检测到磁盘满时调用）。
func (s *Storage) SetWriteDegraded(degraded bool) {
	if degraded && !s.writeDegraded.Load() {
		fmt.Fprintf(os.Stderr, "[storage] 磁盘满，进入写入降级模式（写操作快速失败不阻塞）\n")
		s.writeDegraded.Store(true)
		s.degradeCheckAt.Store(time.Now().Unix() + 30)
	}
}

// DB returns the underlying *sql.DB instance.
// Used by modules that need direct database access (e.g., ConfirmManager).
// Callers should use s.mu.RLock()/RUnlock() for read operations and
// s.mu.Lock()/Unlock() for write operations to ensure thread safety.
func (s *Storage) DB() *sql.DB {
	return s.db
}

// initSchema creates all database tables.
func (s *Storage) initSchema() error {
	schema := `
	-- Metrics: real-time and historical metrics
	CREATE TABLE IF NOT EXISTS metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		name TEXT NOT NULL,
		value REAL NOT NULL,
		unit TEXT,
		timestamp DATETIME NOT NULL,
		labels TEXT, -- JSON
		granularity TEXT DEFAULT 'raw' -- raw, 1min, 1h
	);
	CREATE INDEX IF NOT EXISTS idx_metrics_type_name_ts ON metrics(type, name, timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_granularity ON metrics(granularity, timestamp);

	-- Alerts
	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		level TEXT NOT NULL,
		title TEXT NOT NULL,
		message TEXT,
		source TEXT NOT NULL,
		rule_id TEXT,
		labels TEXT,
		timestamp DATETIME NOT NULL,
		resolved INTEGER DEFAULT 0,
		resolved_at DATETIME,
		acknowledged INTEGER DEFAULT 0,
		acked_by TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved_ts ON alerts(resolved, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_alerts_level_resolved ON alerts(level, resolved);

	-- Actions: executed actions log
	CREATE TABLE IF NOT EXISTS actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id TEXT,
		action_type TEXT NOT NULL,
		target TEXT,
		params TEXT, -- JSON
		success INTEGER NOT NULL,
		message TEXT,
		error TEXT,
		duration_ms INTEGER,
		timestamp DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_actions_type_ts ON actions(action_type, timestamp);

	-- Audit log (WORM - Write Once Read Many)
	CREATE TABLE IF NOT EXISTS audit_log (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		reason TEXT,
		result TEXT NOT NULL,
		details TEXT,
		ip_address TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);

	-- Guard targets (guarded processes/services)
	CREATE TABLE IF NOT EXISTS guard_targets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		command TEXT,
		stop_command TEXT,
		port INTEGER,
		health_check TEXT,
		process_name TEXT,
		depends_on TEXT, -- JSON array
		restart_policy TEXT, -- JSON
		enabled INTEGER DEFAULT 1,
		tags TEXT, -- JSON array
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	-- Rules
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		enabled INTEGER DEFAULT 1,
		priority INTEGER DEFAULT 100,
		module TEXT NOT NULL,
		trigger TEXT NOT NULL, -- JSON
		actions TEXT NOT NULL, -- JSON
		cooldown_ms INTEGER,
		max_triggers INTEGER DEFAULT 3,
		alert_level TEXT DEFAULT 'warning',
		alert_channels TEXT, -- JSON array
		learn_mode INTEGER DEFAULT 1,
		tags TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	-- Certificates
	CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		port INTEGER,
		issuer TEXT,
		subject TEXT,
		sans TEXT, -- JSON array
		not_before DATETIME,
		not_after DATETIME NOT NULL,
		key_algorithm TEXT,
		signature_algorithm TEXT,
		serial_number TEXT,
		cert_path TEXT,
		chain_complete INTEGER DEFAULT 1,
		managed_by TEXT,
		days_until_expiry INTEGER,
		scanned_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_certs_domain ON certificates(domain);
	CREATE INDEX IF NOT EXISTS idx_certs_expiry ON certificates(not_after);

	-- Log files being monitored
	CREATE TABLE IF NOT EXISTS log_files (
		path TEXT PRIMARY KEY,
		size INTEGER NOT NULL,
		last_modified DATETIME NOT NULL,
		write_rate REAL DEFAULT 0,
		managed INTEGER DEFAULT 0,
		app TEXT,
		last_rotated DATETIME,
		updated_at DATETIME NOT NULL
	);

	-- BaoTa discovery state
	CREATE TABLE IF NOT EXISTS baota_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		detected INTEGER NOT NULL,
		install_path TEXT,
		version TEXT,
		panel_type TEXT,
		panel_url TEXT,
		port TEXT,
		admin_path TEXT,
		api_enabled INTEGER,
		capabilities TEXT, -- JSON
		sites TEXT, -- JSON
		updated_at DATETIME NOT NULL
	);

	-- Snapshots (for rollback)
	CREATE TABLE IF NOT EXISTS snapshots (
		id TEXT PRIMARY KEY,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		data TEXT NOT NULL, -- JSON
		expires_at DATETIME
	);

	-- Server registration (for Hub)
	CREATE TABLE IF NOT EXISTS server_info (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		agent_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		ip TEXT,
		os TEXT,
		version TEXT,
		registered_at DATETIME NOT NULL
	);

	-- KV store for misc state
	CREATE TABLE IF NOT EXISTS kv_store (
		key TEXT PRIMARY KEY,
		value TEXT,
		updated_at DATETIME NOT NULL
	);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// 初始化新增表结构
	extendedSchemas := []string{
		FindingSchema(),
		AttackSchema(),
		ConfigVersionSchema(),
		MetricsDownsampleSchema(),
		UserSchema(),
	}
	for _, sch := range extendedSchemas {
		if _, err := s.db.Exec(sch); err != nil {
			return fmt.Errorf("failed to create extended schema: %w", err)
		}
	}

	// 初始化 WORM 审计触发器
	if _, err := s.db.Exec(WORMAuditTriggers()); err != nil {
		// WORM 触发器创建失败不阻塞启动，仅记录
		fmt.Fprintf(os.Stderr, "warning: failed to create WORM triggers: %v\n", err)
	}

	// 初始化保留策略表
	if err := s.initRetentionPolicySchema(); err != nil {
		return fmt.Errorf("failed to create retention_policy table: %w", err)
	}

	// 迁移：为 attack_profiles 表添加 total_attacks 和 threat_level 列（兼容旧数据库）
	s.migrateAttackProfiles()

	return nil
}

// migrateAttackProfiles 迁移 attack_profiles 表，添加 total_attacks 和 threat_level 列
func (s *Storage) migrateAttackProfiles() {
	// 检查 total_attacks 列是否存在
	rows, err := s.db.Query("SELECT total_attacks FROM attack_profiles LIMIT 0")
	if err != nil {
		// 列不存在，添加它
		s.db.Exec("ALTER TABLE attack_profiles ADD COLUMN total_attacks INTEGER DEFAULT 0")
	} else {
		rows.Close()
	}
	// 检查 threat_level 列是否存在
	rows, err = s.db.Query("SELECT threat_level FROM attack_profiles LIMIT 0")
	if err != nil {
		s.db.Exec("ALTER TABLE attack_profiles ADD COLUMN threat_level TEXT DEFAULT 'low'")
	} else {
		rows.Close()
	}
}

// maintenanceLoop runs periodic maintenance tasks.
func (s *Storage) maintenanceLoop() {
	// 向宝塔学习：维护周期从 5min 延长到 15min，减少 DB 写入锁竞争
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	// 首次启动时延迟执行一次清理，让旧数据尽快被回收
	startupTimer := time.NewTimer(30 * time.Second)
	defer startupTimer.Stop()

	vacuumCounter := 0
	started := false

	for {
		select {
		case <-s.stopCh:
			return
		case <-startupTimer.C:
			// 启动后 30 秒执行一次初始清理
			s.walCheckpoint()
			s.purgeOldData()
			s.incrementalVacuum()
			started = true
			continue // 跳过本次后续的重复清理
		case <-ticker.C:
			started = true
		}

		if !started {
			continue
		}

		select {
		case <-s.stopCh:
			return
		default:
		}

		// 【磁盘满保护】降级时跳过所有维护操作（VACUUM/checkpoint 都是写操作）
		if s.IsWriteDegraded() {
			continue
		}

		s.walCheckpoint()
		s.purgeOldData()

		// 每 4 个维护周期（约 1 小时）执行一次 incremental_vacuum 回收空间
		// DELETE 只是标记空闲页，不会缩小 db 文件
		// incremental_vacuum 逐步回收空闲页，避免一次性 VACUUM 的长时间锁
		vacuumCounter++
		if vacuumCounter >= 4 {
			s.incrementalVacuum()
			vacuumCounter = 0
		}
	}
}

// incrementalVacuum 回收被 DELETE 释放的空闲页，缩小 db 文件体积。
// 比 VACUUM 更轻量：不需要重写整个数据库，只回收空闲页。
// 配合 PRAGMA auto_vacuum=incremental 使用。
func (s *Storage) incrementalVacuum() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 设置每次回收的页数上限（每页 4KB，200 页 ≈ 800KB）
	// 避免一次性回收太多页导致长时间锁库
	s.db.Exec("PRAGMA incremental_vacuum(200)")
}

// walCheckpoint checkpoints the WAL log.
func (s *Storage) walCheckpoint() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
}

// purgeOldData removes expired data based on retention policies.
// 使用差异化保留策略，审计表(WORM)跳过清理。
// 向宝塔学习：缓存 retention policy，不每次维护都查 DB
func (s *Storage) purgeOldData() {
	s.mu.RLock()
	rp := s.cachedRP
	loaded := s.rpLoaded
	s.mu.RUnlock()
	if !loaded {
		rp, _ = s.GetRetentionPolicy()
		s.mu.Lock()
		s.cachedRP = rp
		s.rpLoaded = true
		s.mu.Unlock()
	}
	_ = s.EnforceRetention(rp)
}

// --- Metrics ---

// SaveMetric stores a single metric.
// 超过 DBSizeLimit 时拒绝写入，防止 db 文件无限增长
// 【磁盘满保护】降级模式下快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) SaveMetric(m types.Metric) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), metric write skipped")
	}
	if !s.checkCanWriteMetrics() {
		return fmt.Errorf("db size exceeds limit, metric write skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		"INSERT INTO metrics (type, name, value, unit, timestamp, labels, granularity) VALUES (?, ?, ?, ?, ?, ?, 'raw')",
		string(m.Type), m.Name, m.Value, m.Unit, m.Timestamp.UTC().Format(time.RFC3339), labelsToJSON(m.Labels),
	)
	return err
}

// SaveMetrics stores multiple metrics in a batch.
// 如果数据库体积超过 DBSizeLimit（200MB），拒绝写入新指标以防止膨胀。
// 【磁盘满保护】降级模式下快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) SaveMetrics(metrics []types.Metric) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), metrics write skipped")
	}
	// DB 体积检查：超过上限时拒绝写入，防止 db 文件无限增长
	if !s.checkCanWriteMetrics() {
		return fmt.Errorf("db size exceeds limit, metrics write skipped")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO metrics (type, name, value, unit, timestamp, labels, granularity) VALUES (?, ?, ?, ?, ?, ?, 'raw')")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, m := range metrics {
		_, err := stmt.Exec(string(m.Type), m.Name, m.Value, m.Unit, m.Timestamp.UTC().Format(time.RFC3339), labelsToJSON(m.Labels))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// checkCanWriteMetrics 检查数据库体积是否允许继续写入 metrics。
// 超过 DBSizeLimit 时返回 false，调用方应跳过写入。
// 使用缓存的文件大小（每 5 分钟更新一次），避免每次写入都 os.Stat。
var (
	dbSizeCache      int64
	dbSizeCacheTime  time.Time
	dbSizeCacheMu    sync.RWMutex
)

func (s *Storage) checkCanWriteMetrics() bool {
	dbSizeCacheMu.RLock()
	cached := dbSizeCache
	cacheTime := dbSizeCacheTime
	dbSizeCacheMu.RUnlock()

	// 5 分钟内使用缓存值
	if !cacheTime.IsZero() && time.Since(cacheTime) < 5*time.Minute {
		return cached < DBSizeLimit
	}

	// 刷新缓存
	size := s.GetDBSize()
	dbSizeCacheMu.Lock()
	dbSizeCache = size
	dbSizeCacheTime = time.Now()
	dbSizeCacheMu.Unlock()

	return size < DBSizeLimit
}

// GetMetrics retrieves metrics by type and time range.
// mType / name 为空时表示不过滤（通配）。
// 查询范围同时覆盖 raw 表和聚合表（metrics_1m / metrics_1h），
// 因为降采样会把 >1h 的原始数据聚合并删除，只查 raw 会丢失历史。
// 优化：根据时间范围只查必要的表，避免 UNION ALL 三表全扫导致超时。
func (s *Storage) GetMetrics(mType string, name string, since time.Time, limit int) ([]types.Metric, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sinceStr := since.UTC().Format(time.RFC3339)
	sinceUTC := since.UTC()
	now := time.Now().UTC()
	duration := now.Sub(sinceUTC)

	// 根据时间范围选择查询的表，避免不必要的 UNION ALL
	// raw 保留 1h，1m 保留 7d，1h 保留 90d
	// 查最近 1h：只查 raw
	// 查最近 7d：查 raw + 1m
	// 查更久：查 raw + 1m + 1h
	typeAndName := metricsWildcardAnd("type", mType) + metricsWildcardAnd("name", name)

	var query string
	var args []interface{}

	if duration <= time.Hour {
		// 只查 raw 表
		query = fmt.Sprintf(`
SELECT type, name, value, unit, timestamp, labels FROM metrics
WHERE granularity = 'raw' AND timestamp >= ?%s
ORDER BY timestamp DESC LIMIT ?`,
			typeAndName)
		args = []interface{}{sinceStr}
		args = append(args, metricsWildcardArgs(mType, name)...)
		args = append(args, limit)
	} else if duration <= 7*24*time.Hour {
		// 查 raw + 1m
		query = fmt.Sprintf(`
SELECT type, name, value, unit, timestamp, labels FROM (
	SELECT type, name, value, unit, timestamp, labels FROM metrics
	WHERE granularity = 'raw' AND timestamp >= ?%s
	UNION ALL
	SELECT type, name, avg, unit, strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', timestamp), labels FROM metrics_1m
	WHERE timestamp >= datetime(?)%s
) ORDER BY timestamp DESC LIMIT ?`,
			typeAndName, typeAndName)
		args = []interface{}{sinceStr}
		args = append(args, metricsWildcardArgs(mType, name)...)
		args = append(args, sinceStr)
		args = append(args, metricsWildcardArgs(mType, name)...)
		args = append(args, limit)
	} else {
		// 查全部三张表
		query = fmt.Sprintf(`
SELECT type, name, value, unit, timestamp, labels FROM (
	SELECT type, name, value, unit, timestamp, labels FROM metrics
	WHERE granularity = 'raw' AND timestamp >= ?%s
	UNION ALL
	SELECT type, name, avg, unit, strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', timestamp), labels FROM metrics_1m
	WHERE timestamp >= datetime(?)%s
	UNION ALL
	SELECT type, name, avg, unit, strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', timestamp), labels FROM metrics_1h
	WHERE timestamp >= datetime(?)%s
) ORDER BY timestamp DESC LIMIT ?`,
			typeAndName, typeAndName, typeAndName)
		args = []interface{}{sinceStr}
		args = append(args, metricsWildcardArgs(mType, name)...)
		args = append(args, sinceStr)
		args = append(args, metricsWildcardArgs(mType, name)...)
		args = append(args, sinceStr)
		args = append(args, metricsWildcardArgs(mType, name)...)
		args = append(args, limit)
	}

	// 使用 5 秒查询超时，避免大数据库上单次查询拖垮整个服务
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []types.Metric
	for rows.Next() {
		var m types.Metric
		var labelsJSON string
		var tsStr string
		if err := rows.Scan(&m.Type, &m.Name, &m.Value, &m.Unit, &tsStr, &labelsJSON); err != nil {
			continue
		}
		m.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		metrics = append(metrics, m)
	}
	return metrics, nil
}

// metricsWildcardAnd 返回按列过滤的 AND 子句（空值表示不过滤）。
func metricsWildcardAnd(column, value string) string {
	if value == "" {
		return ""
	}
	return " AND " + column + " = ?"
}

// metricsWildcardArgs 返回与 metricsWildcardAnd 对应的参数（单表份）。
func metricsWildcardArgs(values ...string) []interface{} {
	var args []interface{}
	for _, v := range values {
		if v != "" {
			args = append(args, v)
		}
	}
	return args
}

// BaselineBucket 一个"周几×小时"时段的基线统计（UTC）。
type BaselineBucket struct {
	Bucket int     // 0..167 = weekday(0=Sun)*24 + hour
	Mean   float64 // 均值
	Stddev float64 // 标准差
	Count  int     // 样本数
}

// GetMetricBaselineStats 按"周几×小时"聚合指标历史，用于分时段基线异常检测。
// 单查询完成，避免拉取原始明细。
// 数据源同时包含 raw 表和 1 分钟聚合表（metrics_1m）：
// 降采样会把 >1h 的 raw 聚合进 metrics_1m 后删除，只查 raw 将无法积累多天基线。
// 聚合行按 avg*count 折算为 Σx/Σx²（把一分钟内的样本近似为同值），对跨天基线的均值/方差影响可忽略。
func (s *Storage) GetMetricBaselineStats(name string, since time.Time) ([]BaselineBucket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sinceStr := since.UTC().Format(time.RFC3339)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx,
		`SELECT bucket, SUM(sum_x), SUM(sum_x2), SUM(cnt) FROM (
			SELECT (CAST(strftime('%w', timestamp) AS INTEGER) * 24 + CAST(strftime('%H', timestamp) AS INTEGER)) AS bucket,
			       SUM(value) AS sum_x, SUM(value * value) AS sum_x2, COUNT(*) AS cnt
			 FROM metrics
			 WHERE granularity='raw' AND name = ? AND timestamp >= ?
			 GROUP BY bucket
			UNION ALL
			SELECT (CAST(strftime('%w', timestamp) AS INTEGER) * 24 + CAST(strftime('%H', timestamp) AS INTEGER)) AS bucket,
			       AVG(avg) * COUNT(*) AS sum_x, AVG(avg) * AVG(avg) * COUNT(*) AS sum_x2, COUNT(*) AS cnt
			 FROM metrics_1m
			 WHERE name = ? AND timestamp >= datetime(?)
			 GROUP BY bucket
		) GROUP BY bucket`,
		name, sinceStr, name, sinceStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BaselineBucket
	for rows.Next() {
		var b BaselineBucket
		var sumX, sumX2 float64
		if err := rows.Scan(&b.Bucket, &sumX, &sumX2, &b.Count); err != nil {
			continue
		}
		if b.Count <= 0 {
			continue
		}
		b.Mean = sumX / float64(b.Count)
		variance := sumX2/float64(b.Count) - b.Mean*b.Mean
		if variance < 0 {
			variance = 0 // 浮点误差兜底
		}
		b.Stddev = math.Sqrt(variance)
		out = append(out, b)
	}
	return out, rows.Err()
}

// DiskDailyPoint 某挂载点某天的平均使用率。
type DiskDailyPoint struct {
	Mount   string
	Date    string // YYYY-MM-DD (UTC)
	UsedAvg float64
}

// GetDiskDailyAverages 返回磁盘使用率按"挂载点×天"的日均值，用于容量增长预测。
// 同时读取 raw 与 1 分钟聚合表——降采样后 raw 只保留 1 小时，仅查 raw 无法得到多天趋势。
func (s *Storage) GetDiskDailyAverages(since time.Time) ([]DiskDailyPoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sinceStr := since.UTC().Format(time.RFC3339)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx,
		`SELECT mount, date(timestamp), AVG(value) FROM (
			SELECT json_extract(labels, '$.mount') AS mount, timestamp, value
			  FROM metrics
			 WHERE granularity='raw' AND name = 'disk.used_percent' AND timestamp >= ?
			UNION ALL
			SELECT json_extract(labels, '$.mount') AS mount, timestamp, avg AS value
			  FROM metrics_1m
			 WHERE name = 'disk.used_percent' AND timestamp >= datetime(?)
		) GROUP BY mount, 2`,
		sinceStr, sinceStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DiskDailyPoint
	for rows.Next() {
		var p DiskDailyPoint
		var mount *string
		if err := rows.Scan(&mount, &p.Date, &p.UsedAvg); err != nil {
			continue
		}
		if mount != nil {
			p.Mount = *mount
		}
		if p.Mount == "" {
			p.Mount = "/"
		}
		out = append(out, p)
	}
	return out, nil
}

// MetricStats 指标在时间范围内的峰值与均值（SQL 聚合，不加载明细到内存）。
type MetricStats struct {
	Count int
	Max   float64
	Avg   float64
}

// GetMetricStats 用一条聚合查询计算指标峰值/均值。
// 报表生成原先把最多 20000 行明细拉进 Go 内存只为算 max/avg，
// 在 1G 内存的机器上是无谓的分配毛刺；聚合下推给 SQLite 完成。
// 添加 10s 查询超时，防止大数据库上慢查询阻塞。
func (s *Storage) GetMetricStats(name string, since time.Time) (MetricStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out MetricStats
	sinceStr := since.UTC().Format(time.RFC3339)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(MAX(value),0), COALESCE(AVG(value),0) FROM (
	SELECT value FROM metrics WHERE granularity='raw' AND name = ? AND timestamp >= ?
	UNION ALL
	SELECT avg AS value FROM metrics_1m WHERE name = ? AND timestamp >= datetime(?)
)`, name, sinceStr, name, sinceStr).Scan(&out.Count, &out.Max, &out.Avg)
	return out, err
}

// --- Alerts ---

// SaveAlert stores an alert.
func (s *Storage) SaveAlert(a types.Alert) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), alert write skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO alerts (id, level, title, message, source, rule_id, labels, timestamp, resolved, resolved_at, acknowledged, acked_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, string(a.Level), a.Title, a.Message, a.Source, a.RuleID, labelsToJSON(a.Labels),
		a.Timestamp.UTC().Format(time.RFC3339), boolToInt(a.Resolved), a.ResolvedAt, boolToInt(a.Acknowledged), a.AckedBy,
	)
	return err
}

// RepeatedAlert 重复告警统计项（按 source+title 聚合）。
type RepeatedAlert struct {
	Source string
	Title  string
	Count  int
	Last   time.Time
}

// GetTopRepeatedAlerts 统计时间范围内重复出现次数最多的告警。
// 用于巡检报告的"重复问题根治建议"——同一告警反复出现说明根因未除。
func (s *Storage) GetTopRepeatedAlerts(since time.Time, minCount, limit int) ([]RepeatedAlert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT source, title, COUNT(*) AS cnt, MAX(timestamp) AS last
		 FROM alerts
		 WHERE timestamp >= ?
		 GROUP BY source, title
		 HAVING cnt >= ?
		 ORDER BY cnt DESC
		 LIMIT ?`,
		since.UTC().Format(time.RFC3339), minCount, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RepeatedAlert
	for rows.Next() {
		var r RepeatedAlert
		var lastStr string
		if err := rows.Scan(&r.Source, &r.Title, &r.Count, &lastStr); err != nil {
			continue
		}
		r.Last, _ = time.Parse(time.RFC3339, lastStr)
		out = append(out, r)
	}
	return out, rows.Err()
}

// maxUnresolvedAlerts 单次返回的未解决告警上限。
// 告警风暴时 resolved=0 可能堆积数十万行，无上限全量加载会拖垮整个进程
// （面板 /api/alerts、健康分、报表、指标导出都会走到这里），曾导致 hub 反复假死/OOM。
const maxUnresolvedAlerts = 500

// GetUnresolvedAlerts returns the most recent unresolved alerts (capped).
func (s *Storage) GetUnresolvedAlerts() ([]types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, level, title, message, source, rule_id, labels, timestamp FROM alerts WHERE resolved=0 ORDER BY timestamp DESC LIMIT ?", maxUnresolvedAlerts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []types.Alert
	for rows.Next() {
		var a types.Alert
		var labelsJSON string
		var tsStr string
		if err := rows.Scan(&a.ID, &a.Level, &a.Title, &a.Message, &a.Source, &a.RuleID, &labelsJSON, &tsStr); err != nil {
			continue
		}
		a.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// GetAlertByID 按 ID 获取单条告警；不存在时返回错误。
// 供 AI 解释（explainAlert）读取原始告警内容使用。
func (s *Storage) GetAlertByID(id string) (*types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var a types.Alert
	var labelsJSON string
	var tsStr string
	err := s.db.QueryRow(
		"SELECT id, level, title, message, source, rule_id, labels, timestamp FROM alerts WHERE id=?", id,
	).Scan(&a.ID, &a.Level, &a.Title, &a.Message, &a.Source, &a.RuleID, &labelsJSON, &tsStr)
	if err != nil {
		return nil, fmt.Errorf("get alert: %w", err)
	}
	a.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
	return &a, nil
}

// ResolveAlert marks an alert as resolved.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) ResolveAlert(id string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), alert resolve skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE alerts SET resolved=1, resolved_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// ResolveAlertsBySource 批量解决指定来源的未解决告警。
// 用于攻击扫描前自动清理上一轮的旧告警，避免告警无限堆积。
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) ResolveAlertsBySource(source string) (int64, error) {
	if s.IsWriteDegraded() {
		return 0, fmt.Errorf("storage degraded (disk full), alerts resolve skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("UPDATE alerts SET resolved=1, resolved_at=? WHERE source=? AND resolved=0", time.Now().UTC().Format(time.RFC3339), source)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetAlertsByTimeRange 返回指定时间范围内的所有告警（包括已解决的）。
func (s *Storage) GetAlertsByTimeRange(start, end time.Time, limit int) ([]types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, level, title, message, source, rule_id, labels, timestamp FROM alerts WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC"
	args := []interface{}{start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)}
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []types.Alert
	for rows.Next() {
		var a types.Alert
		var labelsJSON string
		var tsStr string
		if err := rows.Scan(&a.ID, &a.Level, &a.Title, &a.Message, &a.Source, &a.RuleID, &labelsJSON, &tsStr); err != nil {
			continue
		}
		a.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// AckAlert marks an alert as acknowledged.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) AckAlert(id string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), alert ack skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE alerts SET acknowledged=1, acked_by='api' WHERE id=?", id)
	return err
}

// DeleteGuardTarget removes a guard target.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) DeleteGuardTarget(id string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), guard target delete skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM guard_targets WHERE id=?", id)
	return err
}

// --- Actions ---

// SaveAction stores an action execution record.
func (s *Storage) SaveAction(ruleID string, result types.ActionResult) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), action write skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 从 Params 中提取 target
	target := ""
	if result.Action.Params != nil {
		if t, ok := result.Action.Params["target"]; ok {
			target = fmt.Sprintf("%v", t)
		}
	}
	// 序列化 params
	paramsJSON := ""
	if result.Action.Params != nil {
		if data, err := json.Marshal(result.Action.Params); err == nil {
			paramsJSON = string(data)
		}
	}
	_, err := s.db.Exec(
		"INSERT INTO actions (rule_id, action_type, target, params, success, message, error, duration_ms, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		ruleID, string(result.Action.Type), target, paramsJSON, boolToInt(result.Success), result.Message, result.Error, result.Duration.Milliseconds(), result.Timestamp.UTC().Format(time.RFC3339),
	)
	return err
}

// GetActionHistory returns recent actions.
func (s *Storage) GetActionHistory(since time.Time, limit int) ([]types.ActionResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT action_type, target, success, message, error, duration_ms, timestamp FROM actions WHERE timestamp>=? ORDER BY timestamp DESC LIMIT ?",
		since.UTC().Format(time.RFC3339), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []types.ActionResult
	for rows.Next() {
		var a types.ActionResult
		var tsStr string
		var successInt int
		var durationMs int64
		var target string
		if err := rows.Scan(&a.Action.Type, &target, &successInt, &a.Message, &a.Error, &durationMs, &tsStr); err != nil {
			continue
		}
		a.Success = successInt == 1
		a.Duration = time.Duration(durationMs) * time.Millisecond
		a.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		if target != "" {
			if a.Action.Params == nil {
				a.Action.Params = make(map[string]interface{})
			}
			a.Action.Params["target"] = target
		}
		actions = append(actions, a)
	}
	return actions, nil
}

// GetActionHistoryByRule returns action history filtered by rule ID.
// Implements ruleengine.StorageQuerier interface.
func (s *Storage) GetActionHistoryByRule(ruleID string, since time.Time, limit int) ([]ruleengine.RuleHistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT action_type, success, error, duration_ms, timestamp FROM actions WHERE rule_id=? AND timestamp>=? ORDER BY timestamp DESC LIMIT ?",
		ruleID, since.UTC().Format(time.RFC3339), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []ruleengine.RuleHistoryEntry
	for rows.Next() {
		var e ruleengine.RuleHistoryEntry
		var tsStr string
		var successInt int
		var durationMs int64
		var errMsg string
		if err := rows.Scan(&e.Action, &successInt, &errMsg, &durationMs, &tsStr); err != nil {
			continue
		}
		e.RuleID = ruleID
		e.Success = successInt == 1
		e.Error = errMsg
		e.Duration = time.Duration(durationMs) * time.Millisecond
		e.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		entries = append(entries, e)
	}
	return entries, nil
}

// --- Audit ---

// SaveAudit stores an audit entry.
func (s *Storage) SaveAudit(entry types.AuditEntry) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), audit write skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		"INSERT INTO audit_log (id, timestamp, actor, action, target, reason, result, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		entry.ID, entry.Timestamp.UTC().Format(time.RFC3339), entry.Actor, entry.Action, entry.Target, entry.Reason, entry.Result, entry.Details, entry.IPAddress,
	)
	return err
}

// GetAuditLog returns audit entries.
func (s *Storage) GetAuditLog(since time.Time, limit int) ([]types.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT id, timestamp, actor, action, target, reason, result, details, ip_address FROM audit_log WHERE timestamp>=? ORDER BY timestamp DESC LIMIT ?",
		since.UTC().Format(time.RFC3339), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []types.AuditEntry
	for rows.Next() {
		var e types.AuditEntry
		var tsStr string
		if err := rows.Scan(&e.ID, &tsStr, &e.Actor, &e.Action, &e.Target, &e.Reason, &e.Result, &e.Details, &e.IPAddress); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		entries = append(entries, e)
	}
	return entries, nil
}

// --- Guard Targets ---

// SaveGuardTarget stores or updates a guard target.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) SaveGuardTarget(t types.GuardTarget) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), guard target write skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	// 序列化 DependsOn / RestartPolicy / Tags —— 这些字段参与依赖链隔离与重启策略，
	// 丢失会导致"上游宕机暂停下游监控"和退避重启失效
	dependsOnJSON := labelsToJSON(nil)
	if len(t.DependsOn) > 0 {
		if data, err := json.Marshal(t.DependsOn); err == nil {
			dependsOnJSON = string(data)
		}
	}
	restartPolicyJSON := labelsToJSON(nil)
	if data, err := json.Marshal(t.RestartPolicy); err == nil {
		restartPolicyJSON = string(data)
	}
	tagsJSON := labelsToJSON(nil)
	if len(t.Tags) > 0 {
		if data, err := json.Marshal(t.Tags); err == nil {
			tagsJSON = string(data)
		}
	}

	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO guard_targets (id, name, type, command, stop_command, port, health_check, process_name, depends_on, restart_policy, enabled, tags, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, string(t.Type), t.Command, t.StopCommand, t.Port, t.HealthCheck, t.ProcessName,
		dependsOnJSON, restartPolicyJSON, boolToInt(t.Enabled), tagsJSON,
		now, now,
	)
	return err
}

// GetGuardTargets returns all guard targets (including disabled ones for UI display).
func (s *Storage) GetGuardTargets() ([]types.GuardTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id, name, type, command, stop_command, port, health_check, process_name, enabled FROM guard_targets ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []types.GuardTarget
	for rows.Next() {
		var t types.GuardTarget
		var typeStr string
		var enabledInt int
		if err := rows.Scan(&t.ID, &t.Name, &typeStr, &t.Command, &t.StopCommand, &t.Port, &t.HealthCheck, &t.ProcessName, &enabledInt); err != nil {
			continue
		}
		t.Type = types.GuardTargetType(typeStr)
		t.Enabled = enabledInt == 1
		targets = append(targets, t)
	}
	return targets, nil
}

// --- Rules ---

// RuleRecord is a simplified rule record for storage/UI use.
type RuleRecord struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	Enabled           bool      `json:"enabled"`
	Priority          int       `json:"priority"`
	Module            string    `json:"module"`
	AlertLevel        string    `json:"alert_level"`
	NeedsConfirmation bool      `json:"needs_confirmation"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// SaveRule stores or updates a rule.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) SaveRule(r *RuleRecord) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), rule write skipped")
	}
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR REPLACE INTO rules
		(id, name, description, enabled, priority, module, trigger, actions, cooldown_ms, max_triggers, alert_level, alert_channels, learn_mode, tags, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Description, boolToInt(r.Enabled), r.Priority, r.Module,
		"[]", "[]", 0, 3, r.AlertLevel, "[]", boolToInt(r.NeedsConfirmation), "[]",
		r.CreatedAt, r.UpdatedAt)
	return err
}

// GetRules returns all rules.
func (s *Storage) GetRules() ([]RuleRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT id, name, description, enabled, priority, module, alert_level, learn_mode, created_at, updated_at FROM rules ORDER BY priority DESC, created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []RuleRecord
	for rows.Next() {
		var r RuleRecord
		var enabledInt, learnInt int
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &enabledInt, &r.Priority, &r.Module, &r.AlertLevel, &learnInt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		r.Enabled = enabledInt == 1
		r.NeedsConfirmation = learnInt == 1
		rules = append(rules, r)
	}
	return rules, nil
}

// DeleteRule removes a rule.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) DeleteRule(id string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), rule delete skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM rules WHERE id=?", id)
	return err
}

// UpdateRuleEnabled toggles a rule's enabled state.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) UpdateRuleEnabled(id string, enabled bool) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), rule update skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE rules SET enabled=?, updated_at=? WHERE id=?", boolToInt(enabled), time.Now(), id)
	return err
}

// --- KV Store ---

// Get retrieves a value from the KV store.
func (s *Storage) Get(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var val string
	err := s.db.QueryRow("SELECT value FROM kv_store WHERE key=?", key).Scan(&val)
	return val, err
}

// Set stores a value in the KV store.
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) Set(key, value string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), kv write skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)", key, value, time.Now())
	return err
}

// GetKeysByPrefix returns all keys that start with the given prefix.
func (s *Storage) GetKeysByPrefix(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT key, value FROM kv_store WHERE key LIKE ?", prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key, val string
		if err := rows.Scan(&key, &val); err != nil {
			continue
		}
		if val != "" { // Skip deleted entries (empty value)
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// GetKeyValue retrieves a key-value pair.
func (s *Storage) GetKeyValue(key string) (string, error) {
	return s.Get(key)
}

// --- Helper ---

func labelsToJSON(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}
	// 向宝塔学习：用 strings.Builder 代替 fmt.Sprintf 拼接，减少分配
	var b strings.Builder
	b.WriteByte('{')
	first := true
	for k, v := range labels {
		if !first {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`":"`)
		b.WriteString(v)
		b.WriteByte('"')
		first = false
	}
	b.WriteByte('}')
	return b.String()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// VACUUM reclaims space.
// 对已有数据库（auto_vacuum=0），执行完整 VACUUM 重建数据库文件，
// 同时切换到 auto_vacuum=incremental 模式。
// 注意：VACUUM 会临时锁定整个数据库，大数据库上耗时较长。
func (s *Storage) Vacuum() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 先确保 auto_vacuum 模式设置（VACUUM 时会应用此设置）
	s.db.Exec("PRAGMA auto_vacuum=incremental")
	// 执行完整 VACUUM 重建数据库
	_, err := s.db.Exec("VACUUM")
	return err
}

// IntegrityCheck runs a database integrity check.
func (s *Storage) IntegrityCheck() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result string
	err := s.db.QueryRow("PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return false, err
	}
	return result == "ok", nil
}

// GetDBSize returns the database file size in bytes.
func (s *Storage) GetDBSize() int64 {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// Backup creates a consistent backup of the database.
// 优先使用 VACUUM INTO：WAL 模式下直接拷贝主文件会丢失/错配 WAL 中未 checkpoint 的数据，
// 得到的备份可能损坏；VACUUM INTO 输出完整一致的独立快照。
func (s *Storage) Backup(destDir string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := os.MkdirAll(destDir, 0750); err != nil {
		return err
	}
	dest := filepath.Join(destDir, fmt.Sprintf("serverguard.db.bak.%s", time.Now().Format("20060102")))
	_ = os.Remove(dest) // VACUUM INTO 要求目标文件不存在

	if _, err := s.db.Exec("VACUUM INTO ?", dest); err != nil {
		// 老版本 SQLite 不支持 VACUUM INTO 时回退为文件拷贝
		src, err := os.Open(s.path)
		if err != nil {
			return err
		}
		defer src.Close()

		dst, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer dst.Close()

		_, err = dst.ReadFrom(src)
		return err
	}
	return nil
}

// StorageDriver 存储后端类型
type StorageDriver string

const (
	DriverSQLite   StorageDriver = "sqlite"
	DriverPostgres StorageDriver = "postgres"
)

// StorageConfig 存储配置，支持 SQLite 和 PostgreSQL
type StorageConfig struct {
	Driver   StorageDriver
	Path     string // SQLite 文件路径
	Postgres PostgresConfig
}

// NewStorage 根据配置创建存储实例，上层无感知后端类型
// SQLite 返回 *Storage，PostgreSQL 返回 *PostgresStorage（通过 DB() 接口访问）
func NewStorage(cfg StorageConfig) (*Storage, error) {
	switch cfg.Driver {
	case DriverPostgres:
		ps, err := NewPostgres(cfg.Postgres)
		if err != nil {
			return nil, err
		}
		return &Storage{db: ps.db, path: cfg.Postgres.Database}, nil
	default:
		return New(cfg.Path)
	}
}
