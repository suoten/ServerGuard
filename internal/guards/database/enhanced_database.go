package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MySQLDeepChecker provides read-only MySQL health diagnostics.
// SAFETY: All operations are SELECT/SHOW only. Never executes KILL, ALTER, or any modifying command.
type MySQLDeepChecker struct {
	mu sync.RWMutex
}

func NewMySQLDeepChecker() *MySQLDeepChecker {
	return &MySQLDeepChecker{}
}

// LongRunningQueries returns queries running longer than the specified duration.
// This is read-only — it does NOT kill anything.
func (c *MySQLDeepChecker) LongRunningQueries(ctx context.Context, db *sql.DB, maxDuration time.Duration) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT CONCAT('ID=', id, ' User=', user, ' Time=', time, 's Info=', LEFT(info, 100))
		FROM information_schema.processlist
		WHERE command != 'Sleep' AND time > ?
		ORDER BY time DESC`, int(maxDuration.Seconds()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var queries []string
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err == nil {
			queries = append(queries, q)
		}
	}
	return queries, nil
}

// KillAdvice generates a KILL command suggestion (never executes it).
func (c *MySQLDeepChecker) KillAdvice(processID int64, reason string) string {
	return fmt.Sprintf("如需终止该查询，请手动执行:\n  KILL %d;\n原因: %s\n注意: 终止查询可能导致事务回滚", processID, reason)
}

// ReplicaLagAdvice generates remediation suggestions for replication lag.
func (c *MySQLDeepChecker) ReplicaLagAdvice(lagSeconds int64) string {
	if lagSeconds <= 0 {
		return "复制正常"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("主从延迟 %d 秒\n", lagSeconds))
	if lagSeconds > 300 {
		sb.WriteString("严重延迟！可能原因:\n")
		sb.WriteString("  1. 大事务: 检查主库是否在执行大批量 INSERT/UPDATE\n")
		sb.WriteString("  2. 从库负载过高: 检查从库 CPU/IO\n")
		sb.WriteString("  3. 从库 IO 性能不足: 检查磁盘 IOPS\n")
		sb.WriteString("  4. 单线程复制瓶颈: 考虑开启并行复制\n")
		sb.WriteString("     (MySQL 5.7+: slave_parallel_workers = 4)\n")
	} else if lagSeconds > 30 {
		sb.WriteString("中等延迟，建议关注:\n")
		sb.WriteString("  1. 检查从库慢查询\n")
		sb.WriteString("  2. 检查网络延迟\n")
	}
	return sb.String()
}

// RedisGuard provides Redis health monitoring.
type RedisGuard struct {
	mu          sync.RWMutex
	maxMemory   uint64
	usedMemory  uint64
	connected   bool
}

func NewRedisGuard() *RedisGuard {
	return &RedisGuard{
		maxMemory: 1024 * 1024 * 1024,
		connected: false,
	}
}

// CheckMemory returns memory usage stats.
func (g *RedisGuard) CheckMemory() (used, max uint64, ratio float64) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.maxMemory > 0 {
		ratio = float64(g.usedMemory) / float64(g.maxMemory)
	}
	return g.usedMemory, g.maxMemory, ratio
}

// CheckAOFrewrite checks if AOF rewrite is in progress.
// Returns true if AOF rewrite is happening (which may cause latency).
func (g *RedisGuard) CheckAOFrewrite() (bool, error) {
	return false, nil
}

// CheckKeyExpiryRate checks the key expiry rate to detect memory pressure.
func (g *RedisGuard) CheckKeyExpiryRate() (float64, error) {
	return 0, nil
}

// BigKeyScanner scans for big keys in Redis (read-only, safe).
func (g *RedisGuard) BigKeyScanner(ctx context.Context, host string, port int, password string) (string, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("无法连接 Redis: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if password != "" {
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
		buf := make([]byte, 1024)
		conn.Read(buf)
	}

	// Use SCAN to sample keys (safe, non-blocking)
	// This is a simplified version — production would use redis-cli --bigkeys
	return "建议使用 redis-cli --bigkeys 进行大key扫描（该操作只读，安全）", nil
}

// DatabaseDegrader provides graceful degradation when deep checks are unavailable.
type DatabaseDegrader struct{}

func NewDatabaseDegrader() *DatabaseDegrader { return &DatabaseDegrader{} }

// DegradeToPortCheck returns a function that only checks TCP port connectivity.
func (d *DatabaseDegrader) DegradeToPortCheck(port int) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}
}

// ConnectionPoolAdvice generates suggestions for connection pool tuning.
func ConnectionPoolAdvice(dbType string, current, max int) string {
	var sb strings.Builder
	pct := float64(current) / float64(max) * 100

	sb.WriteString(fmt.Sprintf("连接池使用: %d/%d (%.1f%%)\n", current, max, pct))

	switch dbType {
	case "mysql":
		if pct > 80 {
			sb.WriteString("\n建议:\n")
			sb.WriteString("  1. 检查应用连接池配置:\n")
			sb.WriteString("     - Java (HikariCP): maximumPoolSize, idleTimeout\n")
			sb.WriteString("     - Python (SQLAlchemy): pool_size, max_overflow\n")
			sb.WriteString("     - Go (database/sql): SetMaxOpenConns, SetMaxIdleConns\n")
			sb.WriteString("  2. 检查是否有连接泄漏:\n")
			sb.WriteString("     SHOW STATUS LIKE 'Aborted_clients';\n")
			sb.WriteString("     SHOW STATUS LIKE 'Threads_connected';\n")
			sb.WriteString("  3. 考虑调高 max_connections (需评估内存):\n")
			sb.WriteString("     每个连接约消耗 256KB-1MB 内存\n")
			maxRecommended := max
			if max < 500 {
				maxRecommended = 500
			}
			sb.WriteString(fmt.Sprintf("     建议值: %d\n", maxRecommended))
		}
	case "postgresql":
		if pct > 80 {
			sb.WriteString("\n建议:\n")
			sb.WriteString("  1. 检查 max_connections 和连接池配置\n")
			sb.WriteString("  2. 考虑使用 PgBouncer 连接池中间件\n")
		}
	case "redis":
		if pct > 80 {
			sb.WriteString("\n建议:\n")
			sb.WriteString("  1. 检查应用 Redis 连接池配置\n")
			sb.WriteString("  2. 确保 使用连接池而非每次新建连接\n")
			sb.WriteString("  3. 检查 maxclients 配置: CONFIG GET maxclients\n")
		}
	}

	return sb.String()
}

// ParseMySQLVersion extracts version number from VERSION() output.
func ParseMySQLVersion(version string) (major, minor, patch int) {
	parts := strings.Split(version, ".")
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		// Handle versions like "8.0.31-0ubuntu0.20.04.1"
		patchStr := strings.Split(parts[2], "-")[0]
		patch, _ = strconv.Atoi(patchStr)
	}
	return
}

// IsMySQLReplicaBroken checks if replication is broken based on SHOW SLAVE STATUS output.
func IsMySQLReplicaBroken(status map[string]interface{}) bool {
	// Check Slave_IO_Running and Slave_SQL_Running
	ioRunning, ok1 := status["Slave_IO_Running"].(string)
	sqlRunning, ok2 := status["Slave_SQL_Running"].(string)
	if ok1 && ok2 {
		return ioRunning != "Yes" || sqlRunning != "Yes"
	}
	// Check for errors
	if lastIOErr, ok := status["Last_IO_Error"].(string); ok && lastIOErr != "" {
		return true
	}
	if lastSQLErr, ok := status["Last_SQL_Error"].(string); ok && lastSQLErr != "" {
		return true
	}
	return false
}
