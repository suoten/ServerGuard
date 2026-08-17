package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStorage PostgreSQL 存储后端，支持 RLS 多租户隔离
type PostgresStorage struct {
	db       *sql.DB
	mu       sync.RWMutex
	tenantID string
	dsn      string
}

// PostgresConfig PostgreSQL 连接配置
type PostgresConfig struct {
	Host            string
	Port            int
	Database        string
	Username        string
	Password        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// NewPostgres 创建 PostgreSQL 存储实例并初始化 schema
func NewPostgres(cfg PostgresConfig) (*PostgresStorage, error) {
	if cfg.SSLMode == "" {
		cfg.SSLMode = "disable"
	}
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 50
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 10
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = 30 * time.Minute
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s application_name=serverguard",
		cfg.Host, cfg.Port, cfg.Database, cfg.Username, cfg.Password, cfg.SSLMode,
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	ps := &PostgresStorage{db: db, dsn: dsn}

	if err := ps.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init postgres schema: %w", err)
	}

	go ps.maintenanceLoop()

	return ps, nil
}

// initSchema 初始化 PostgreSQL schema 和 RLS 策略
func (ps *PostgresStorage) initSchema() error {
	if _, err := ps.db.Exec(PostgresSchema()); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	if _, err := ps.db.Exec(PostgresRLSPolicies()); err != nil {
		return fmt.Errorf("failed to create RLS policies: %w", err)
	}
	if _, err := ps.db.Exec(PostgresWORMTriggers()); err != nil {
		return fmt.Errorf("failed to create WORM triggers: %w", err)
	}
	return nil
}

// Close 关闭数据库连接
func (ps *PostgresStorage) Close() error {
	return ps.db.Close()
}

// DB 返回底层 *sql.DB 实例
func (ps *PostgresStorage) DB() *sql.DB {
	return ps.db
}

// SetTenantID 设置当前租户 ID，在当前连接上执行 SET app.tenant_id
// 所有后续查询自动受 RLS 策略隔离
func (ps *PostgresStorage) SetTenantID(tenantID string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.tenantID = tenantID
	_, err := ps.db.Exec(fmt.Sprintf("SET app.tenant_id = '%s'", sanitizeTenantID(tenantID)))
	if err != nil {
		return fmt.Errorf("failed to set tenant id: %w", err)
	}
	return nil
}

// GetTenantID 返回当前租户 ID
func (ps *PostgresStorage) GetTenantID() string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.tenantID
}

// sanitizeTenantID 防止 SQL 注入
func sanitizeTenantID(tenantID string) string {
	return strings.ReplaceAll(tenantID, "'", "''")
}

// maintenanceLoop 定期维护任务
func (ps *PostgresStorage) maintenanceLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ps.purgeOldData()
	}
}

// purgeOldData 清理过期数据
func (ps *PostgresStorage) purgeOldData() {
	now := time.Now()
	ps.db.Exec("DELETE FROM metrics WHERE granularity='raw' AND timestamp < $1", now.Add(-1*time.Hour))
	ps.db.Exec("DELETE FROM metrics WHERE granularity='1min' AND timestamp < $1", now.Add(-7*24*time.Hour))
	ps.db.Exec("DELETE FROM metrics WHERE granularity='1h' AND timestamp < $1", now.Add(-90*24*time.Hour))
	ps.db.Exec("DELETE FROM alerts WHERE timestamp < $1", now.Add(-180*24*time.Hour))
	ps.db.Exec("DELETE FROM actions WHERE timestamp < $1", now.Add(-365*24*time.Hour))
	ps.db.Exec("DELETE FROM snapshots WHERE expires_at < $1", now)
}

// ConvertPlaceholders 将 SQLite 风格的 ? 占位符转换为 PostgreSQL 的 $1, $2, ...
// 用于复用现有 SQL 语句
func ConvertPlaceholders(query string) string {
	parts := strings.Split(query, "?")
	if len(parts) == 1 {
		return query
	}
	var sb strings.Builder
	for i, part := range parts {
		sb.WriteString(part)
		if i < len(parts)-1 {
			sb.WriteString(fmt.Sprintf("$%d", i+1))
		}
	}
	return sb.String()
}

// --- 通用查询适配 ---

// Exec 执行 SQL（自动转换占位符）
func (ps *PostgresStorage) Exec(query string, args ...interface{}) (sql.Result, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.db.Exec(ConvertPlaceholders(query), args...)
}

// Query 查询（自动转换占位符）
func (ps *PostgresStorage) Query(query string, args ...interface{}) (*sql.Rows, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.db.Query(ConvertPlaceholders(query), args...)
}

// QueryRow 查询单行（自动转换占位符）
func (ps *PostgresStorage) QueryRow(query string, args ...interface{}) *sql.Row {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.db.QueryRow(ConvertPlaceholders(query), args...)
}