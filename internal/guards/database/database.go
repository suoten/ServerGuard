package database

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// DatabaseGuard implements Module K: Database Guard
// Covers: MySQL, PostgreSQL, Redis, MongoDB connectivity, slow query detection,
// connection pool monitoring, replication lag checks, and actionable remediation.
//
// SAFETY: Only monitors and suggests. Never kills queries, restarts services,
// or modifies configurations directly. All remediation commands are suggestions.
type DatabaseGuard struct {
	mu        sync.RWMutex
	eventBus  *eventbus.EventBus
	instances []DBInstance
}

// DBInstance represents a database instance to monitor.
type DBInstance struct {
	Name     string
	Type     string // mysql, postgresql, redis, mongodb
	Host     string
	Port     int
	Password string // optional, for deep checks
	// MySQL deep check fields
	DSN         string // full DSN for MySQL deep checks
	MaxConnWarn int    // connection warning threshold (default 80%)
}

// New creates a new DatabaseGuard.
func New(bus *eventbus.EventBus) *DatabaseGuard {
	return &DatabaseGuard{
		eventBus: bus,
	}
}

// AddInstance adds a database instance to monitor.
func (g *DatabaseGuard) AddInstance(inst DBInstance) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if inst.MaxConnWarn == 0 {
		inst.MaxConnWarn = 80 // 80% threshold
	}
	g.instances = append(g.instances, inst)
}

// AutoDetect detects locally running database instances by checking common ports.
func (g *DatabaseGuard) AutoDetect() int {
	commonDBs := []DBInstance{
		{Name: "MySQL", Type: "mysql", Host: "127.0.0.1", Port: 3306},
		{Name: "PostgreSQL", Type: "postgresql", Host: "127.0.0.1", Port: 5432},
		{Name: "Redis", Type: "redis", Host: "127.0.0.1", Port: 6379},
		{Name: "MongoDB", Type: "mongodb", Host: "127.0.0.1", Port: 27017},
	}

	added := 0
	g.mu.RLock()
	existing := make(map[string]bool)
	for _, inst := range g.instances {
		existing[inst.Name] = true
	}
	g.mu.RUnlock()

	for _, db := range commonDBs {
		if existing[db.Name] {
			continue
		}
		addr := net.JoinHostPort(db.Host, fmt.Sprintf("%d", db.Port))
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// For MySQL, try to auto-detect DSN from common configs
		if db.Type == "mysql" {
			db.DSN = g.detectMySQLDSN()
		}

		g.AddInstance(db)
		added++
	}
	return added
}

// detectMySQLDSN attempts to find MySQL credentials from common config files.
func (g *DatabaseGuard) detectMySQLDSN() string {
	// Try common paths where MySQL credentials might be stored
	// BaoTa panel config
	baotaPaths := []string{
		"/www/server/panel/data/default.db", // BaoTa SQLite (not directly usable)
		"/etc/mysql/debian.cnf",              // Debian/Ubuntu default
		"/root/.my.cnf",                      // Root user config
	}

	for _, path := range baotaPaths {
		if _, err := os.Stat(path); err == nil {
			if path == "/etc/mysql/debian.cnf" {
				return g.parseDebianCnf(path)
			}
			if path == "/root/.my.cnf" {
				return g.parseMyCnf(path)
			}
		}
	}
	return ""
}

// parseDebianCnf parses /etc/mysql/debian.cnf for credentials.
func (g *DatabaseGuard) parseDebianCnf(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	var user, password string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "user") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				user = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "password") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				password = strings.TrimSpace(parts[1])
			}
		}
	}
	if user == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/", user, password)
}

// parseMyCnf parses ~/.my.cnf for credentials.
func (g *DatabaseGuard) parseMyCnf(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	var user, password string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "user") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				user = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "password") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				password = strings.TrimSpace(parts[1])
			}
		}
	}
	if user == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/", user, password)
}

// Check checks all database instances.
func (g *DatabaseGuard) Check(ctx context.Context) {
	g.mu.RLock()
	instances := make([]DBInstance, len(g.instances))
	copy(instances, g.instances)
	g.mu.RUnlock()

	for _, inst := range instances {
		g.checkInstance(ctx, inst)
	}
}

// checkInstance checks a single database instance.
func (g *DatabaseGuard) checkInstance(ctx context.Context, inst DBInstance) {
	addr := net.JoinHostPort(inst.Host, fmt.Sprintf("%d", inst.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		g.eventBus.PublishAlert(types.AlertError, "database",
			fmt.Sprintf("数据库不可达: %s", inst.Name),
			fmt.Sprintf("%s (%s) 无法连接 %s:%d — %v\n\n排查建议:\n"+
				"  1. 检查服务是否运行: systemctl status %s\n"+
				"  2. 检查端口是否监听: ss -tlnp | grep %d\n"+
				"  3. 检查防火墙规则: iptables -L -n | grep %d\n"+
				"  4. 检查配置文件: bind-address 是否为 127.0.0.1",
				inst.Name, inst.Type, inst.Host, inst.Port, err,
				g.guessServiceName(inst.Type), inst.Port, inst.Port),
			"db-down-001")
		return
	}
	conn.Close()

	// Type-specific deep checks
	switch inst.Type {
	case "redis":
		g.checkRedis(ctx, inst)
	case "mysql":
		g.checkMySQLDeep(ctx, inst)
	}
}

// checkRedis sends a PING command to Redis and checks memory/connections.
func (g *DatabaseGuard) checkRedis(ctx context.Context, inst DBInstance) {
	addr := net.JoinHostPort(inst.Host, fmt.Sprintf("%d", inst.Port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// AUTH if password is set
	if inst.Password != "" {
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(inst.Password), inst.Password)
		buf := make([]byte, 1024)
		conn.Read(buf)
	}

	// PING
	fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		g.eventBus.PublishAlert(types.AlertWarning, "database",
			fmt.Sprintf("Redis无响应: %s", inst.Name),
			fmt.Sprintf("Redis %s PING 无响应\n排查: redis-cli -h %s -p %d ping", inst.Name, inst.Host, inst.Port),
			"db-redis-001")
		return
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "+PONG") {
		g.eventBus.PublishAlert(types.AlertWarning, "database",
			fmt.Sprintf("Redis异常: %s", inst.Name),
			fmt.Sprintf("Redis %s PING 返回异常: %s", inst.Name, resp),
			"db-redis-001")
		return
	}

	// INFO for deep checks
	fmt.Fprintf(conn, "*1\r\n$4\r\nINFO\r\n")
	infoBuf := make([]byte, 8192)
	n, err = conn.Read(infoBuf)
	if err != nil || n == 0 {
		return
	}
	info := string(infoBuf[:n])
	g.analyzeRedisInfo(inst, info)
}

// analyzeRedisInfo parses Redis INFO output and alerts on issues.
func (g *DatabaseGuard) analyzeRedisInfo(inst DBInstance, info string) {
	lines := strings.Split(info, "\n")
	stats := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			stats[parts[0]] = parts[1]
		}
	}

	// Check memory usage
	if usedMem, ok := stats["used_memory"]; ok {
		if maxMem, ok := stats["maxmemory"]; ok {
			used, _ := strconv.ParseInt(usedMem, 10, 64)
			max, _ := strconv.ParseInt(maxMem, 10, 64)
			if max > 0 {
				pct := float64(used) / float64(max) * 100
				if pct > 90 {
					g.eventBus.PublishAlert(types.AlertCritical, "database",
						fmt.Sprintf("Redis内存即将耗尽: %s", inst.Name),
						fmt.Sprintf("Redis %s 内存使用 %.1f%% (%s / %s)\n\n"+
							"建议:\n"+
							"  1. 检查大key: redis-cli --bigkeys\n"+
							"  2. 检查过期策略: CONFIG GET maxmemory-policy\n"+
							"  3. 考虑扩容或设置淘汰策略: CONFIG SET maxmemory-policy allkeys-lru\n"+
							"  4. 分析内存: redis-cli MEMORY STATS",
							inst.Name, pct, formatBytes(used), formatBytes(max)),
						"db-redis-mem-001")
				} else if pct > 80 {
					g.eventBus.PublishAlert(types.AlertWarning, "database",
						fmt.Sprintf("Redis内存使用较高: %s", inst.Name),
						fmt.Sprintf("Redis %s 内存使用 %.1f%%", inst.Name, pct),
						"db-redis-mem-001")
				}
			}
		}
	}

	// Check connected clients
	if clients, ok := stats["connected_clients"]; ok {
		n, _ := strconv.Atoi(clients)
		if maxClients, ok := stats["maxclients"]; ok {
			max, _ := strconv.Atoi(maxClients)
			if max > 0 && float64(n)/float64(max) > 0.8 {
				g.eventBus.PublishAlert(types.AlertWarning, "database",
					fmt.Sprintf("Redis连接数过高: %s", inst.Name),
					fmt.Sprintf("Redis %s 连接数 %d/%d (%.1f%%)\n"+
						"建议: 检查应用连接池配置，可能存在连接泄漏",
						inst.Name, n, max, float64(n)/float64(max)*100),
					"db-redis-conn-001")
			}
		} else if n > 1000 {
			g.eventBus.PublishAlert(types.AlertWarning, "database",
				fmt.Sprintf("Redis连接数过高: %s", inst.Name),
				fmt.Sprintf("Redis %s 连接数 %d\n建议: 检查应用连接池配置", inst.Name, n),
				"db-redis-conn-001")
		}
	}
}

// checkMySQLDeep performs deep MySQL health checks using SQL queries.
// SAFETY: All operations are read-only (SHOW commands). Never modifies data.
func (g *DatabaseGuard) checkMySQLDeep(ctx context.Context, inst DBInstance) {
	if inst.DSN == "" {
		// No credentials, just TCP check passed
		return
	}

	db, err := sql.Open("mysql", inst.DSN)
	if err != nil {
		return
	}
	defer db.Close()

	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(10 * time.Second)

	// 1. Check connection count
	g.checkMySQLConnections(ctx, db, inst)

	// 2. Check slow queries
	g.checkMySQLSlowQueries(ctx, db, inst)

	// 3. Check replication lag (if replica)
	g.checkMySQLReplicaLag(ctx, db, inst)

	// 4. Check Aborted_clients (connection leaks)
	g.checkMySQLAbortedConnections(ctx, db, inst)

	// 5. Check InnoDB buffer pool usage
	g.checkMySQLBufferPool(ctx, db, inst)
}

// checkMySQLConnections checks current vs max connections.
// 当连接数超过阈值时，按 Host 分组统计，找出占用连接最多的来源，
// 便于定位是哪个程序/进程在耗尽连接池。
func (g *DatabaseGuard) checkMySQLConnections(ctx context.Context, db *sql.DB, inst DBInstance) {
	var maxConn int
	err := db.QueryRowContext(ctx, "SHOW VARIABLES LIKE 'max_connections'").Scan(&maxConn)
	if err != nil {
		// Try alternative query format
		row := db.QueryRowContext(ctx, "SELECT @@max_connections")
		err = row.Scan(&maxConn)
		if err != nil {
			return
		}
	}

	// SHOW STATUS returns two columns for older MySQL versions
	var varName, value string
	err = db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Threads_connected'").Scan(&varName, &value)
	if err != nil {
		return
	}
	current, _ := strconv.Atoi(value)
	if maxConn == 0 {
		return
	}

	pct := float64(current) / float64(maxConn) * 100
	if pct > float64(inst.MaxConnWarn) {
		level := types.AlertWarning
		if pct > 90 {
			level = types.AlertCritical
		}

		// 按来源 Host 分组统计连接数，找出连接消耗大户
		hostStats := g.getMySQLConnectionByHost(ctx, db)

		detail := fmt.Sprintf("MySQL %s 连接数 %d/%d (%.1f%%)\n", inst.Name, current, maxConn, pct)

		if len(hostStats) > 0 {
			detail += "\n连接来源统计（按连接数降序）:\n"
			shown := 0
			for _, hs := range hostStats {
				if shown >= 5 {
					detail += fmt.Sprintf("  ...等共 %d 个来源\n", len(hostStats))
					break
				}
				detail += fmt.Sprintf("  %s: %d 个连接\n", hs.host, hs.count)
				shown++
			}
			// 如果单个来源占用超过 50% 的连接，给出强提示
			topHost := hostStats[0]
			if topHost.count > current/2 {
				detail += fmt.Sprintf("\n⚠️ 来源 %s 占用了 %d/%d 连接（%.0f%%），疑似进程失控\n",
					topHost.host, topHost.count, current, float64(topHost.count)/float64(current)*100)
				detail += "建议执行: ps aux | grep <对应程序> 查看进程数，考虑 kill 或重启\n"
			}
		}

		detail += "\n排查建议:\n" +
			"  1. 查看活跃连接: SHOW PROCESSLIST;\n" +
			"  2. 查看Sleep连接: SELECT * FROM information_schema.processlist WHERE Command='Sleep' AND Time > 60;\n" +
			"  3. 检查应用连接池配置 (maxPoolSize, idleTimeout)\n" +
			"  4. 如需调高: SET GLOBAL max_connections = 500;  (临时)\n" +
			"     永久: 修改 my.cnf 的 max_connections"

		g.eventBus.PublishAlert(level, "database",
			fmt.Sprintf("MySQL连接数过高: %s", inst.Name),
			detail,
			"db-mysql-conn-001")
	}
}

// hostConnStat 按 Host 分组的连接统计
type hostConnStat struct {
	host  string
	count int
}

// getMySQLConnectionByHost 查询 SHOW PROCESSLIST 按 Host 分组统计连接数
func (g *DatabaseGuard) getMySQLConnectionByHost(ctx context.Context, db *sql.DB) []hostConnStat {
	rows, err := db.QueryContext(ctx, `
		SELECT SUBSTRING_INDEX(HOST, ':', 1) AS source_host, COUNT(*) AS cnt
		FROM information_schema.processlist
		GROUP BY source_host
		ORDER BY cnt DESC
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var stats []hostConnStat
	for rows.Next() {
		var host string
		var count int
		if err := rows.Scan(&host, &count); err != nil {
			continue
		}
		stats = append(stats, hostConnStat{host: host, count: count})
	}
	return stats
}

// checkMySQLSlowQueries checks for slow queries running right now.
func (g *DatabaseGuard) checkMySQLSlowQueries(ctx context.Context, db *sql.DB, inst DBInstance) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, user, host, db, command, time, state, LEFT(info, 200) as info
		FROM information_schema.processlist
		WHERE command != 'Sleep' AND time > 10
		ORDER BY time DESC LIMIT 5`)
	if err != nil {
		return
	}
	defer rows.Close()

	type slowQuery struct {
		ID      int64
		User    string
		Host    string
		DB      string
		Command string
		Time    int64
		State   string
		Info    string
	}

	var queries []slowQuery
	for rows.Next() {
		var q slowQuery
		var db, info sql.NullString
		if err := rows.Scan(&q.ID, &q.User, &q.Host, &db, &q.Command, &q.Time, &q.State, &info); err != nil {
			continue
		}
		q.DB = db.String
		q.Info = info.String
		queries = append(queries, q)
	}

	if len(queries) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MySQL %s 发现 %d 个慢查询（>10秒）:\n\n", inst.Name, len(queries)))
	for i, q := range queries {
		sb.WriteString(fmt.Sprintf("  [%d] ID=%d 用户=%s 主机=%s 数据库=%s\n", i+1, q.ID, q.User, q.Host, q.DB))
		sb.WriteString(fmt.Sprintf("      命令=%s 状态=%s 执行时间=%d秒\n", q.Command, q.State, q.Time))
		if q.Info != "" {
			sb.WriteString(fmt.Sprintf("      SQL: %s\n", q.Info))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("处理建议:\n")
	sb.WriteString("  1. 分析慢查询日志: mysqldumpslow -s t /var/log/mysql/mysql-slow.log\n")
	sb.WriteString("  2. 使用 EXPLAIN 分析执行计划\n")
	sb.WriteString("  3. 如需终止特定查询: KILL <ID>;  (请确认后手动执行)\n")
	sb.WriteString("  4. 长期优化: 添加索引、优化SQL、设置 long_query_time")

	g.eventBus.PublishAlert(types.AlertWarning, "database",
		fmt.Sprintf("MySQL慢查询: %s (%d个)", inst.Name, len(queries)),
		sb.String(), "db-mysql-slow-001")
}

// checkMySQLReplicaLag checks Seconds_Behind_Master for replica databases.
func (g *DatabaseGuard) checkMySQLReplicaLag(ctx context.Context, db *sql.DB, inst DBInstance) {
	// Check if this is a replica
	rows, err := db.QueryContext(ctx, "SHOW REPLICA STATUS") // MySQL 8.0+
	if err != nil {
		rows, err = db.QueryContext(ctx, "SHOW SLAVE STATUS") // MySQL 5.7
		if err != nil {
			return // Not a replica or no permission
		}
	}
	defer rows.Close()

	if !rows.Next() {
		return // Not configured as replica
	}

	// Get column names
	cols, err := rows.Columns()
	if err != nil {
		return
	}
	values := make([]sql.NullString, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return
	}

	// Find Seconds_Behind_Master column
	for i, col := range cols {
		if strings.EqualFold(col, "Seconds_Behind_Master") {
			if values[i].Valid {
				lag, err := strconv.ParseInt(values[i].String, 10, 64)
				if err != nil || lag < 0 {
					// NULL or error means replication is broken
					g.eventBus.PublishAlert(types.AlertCritical, "database",
						fmt.Sprintf("MySQL主从复制异常: %s", inst.Name),
						fmt.Sprintf("MySQL %s Seconds_Behind_Master 为 NULL，主从复制可能已中断！\n\n"+
							"排查步骤:\n"+
							"  1. 查看复制状态: SHOW REPLICA STATUS\\G\n"+
							"  2. 检查 Last_IO_Error 和 Last_SQL_Error\n"+
							"  3. 常见原因:\n"+
							"     - 网络中断到主库\n"+
							"     - 主库 binlog 被清理\n"+
							"     - 从库遇到重复键错误\n"+
							"  4. 如需跳过错误(谨慎): SET GLOBAL sql_replica_skip_counter = 1; START REPLICA;",
							inst.Name),
						"db-mysql-replica-001")
					return
				}
				if lag > 30 {
					level := types.AlertWarning
					if lag > 300 {
						level = types.AlertCritical
					}
					g.eventBus.PublishAlert(level, "database",
						fmt.Sprintf("MySQL主从延迟: %s (%ds)", inst.Name, lag),
						fmt.Sprintf("MySQL %s 主从延迟 %d 秒\n\n"+
							"可能原因:\n"+
							"  1. 从库负载过高，SQL线程跟不上\n"+
							"  2. 大事务导致延迟\n"+
							"  3. 从库 IO 性能不足\n\n"+
							"排查:\n"+
							"  SHOW REPLICA STATUS\\G  查看 Replica_SQL_Running_State\n"+
							"  检查从库慢查询日志",
							inst.Name, lag),
						"db-mysql-replica-001")
				}
			}
			break
		}
	}
}

// checkMySQLAbortedConnections checks for connection aborts indicating app issues.
func (g *DatabaseGuard) checkMySQLAbortedConnections(ctx context.Context, db *sql.DB, inst DBInstance) {
	var varName, abortedVal string
	err := db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Aborted_clients'").Scan(&varName, &abortedVal)
	if err != nil {
		return
	}
	aborted, _ := strconv.ParseInt(abortedVal, 10, 64)
	if aborted > 100 {
		g.eventBus.PublishAlert(types.AlertWarning, "database",
			fmt.Sprintf("MySQL异常断连较多: %s", inst.Name),
			fmt.Sprintf("MySQL %s Aborted_clients = %d\n\n"+
				"可能原因:\n"+
				"  1. 应用未正确关闭数据库连接\n"+
				"  2. wait_timeout 设置过短\n"+
				"  3. 应用进程异常退出\n\n"+
				"建议:\n"+
				"  SHOW VARIABLES LIKE 'wait_timeout';\n"+
				"  检查应用连接池的 maxLifetime 配置",
				inst.Name, aborted),
			"db-mysql-abort-001")
	}
}

// checkMySQLBufferPool checks InnoDB buffer pool usage.
func (g *DatabaseGuard) checkMySQLBufferPool(ctx context.Context, db *sql.DB, inst DBInstance) {
	var varName, sizeVal string
	err := db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_pages_total'").Scan(&varName, &sizeVal)
	if err != nil {
		return
	}
	total, _ := strconv.ParseInt(sizeVal, 10, 64)
	if total == 0 {
		return
	}

	var varName2, dataVal string
	err = db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_pages_data'").Scan(&varName2, &dataVal)
	if err != nil {
		return
	}
	data, _ := strconv.ParseInt(dataVal, 10, 64)

	pct := float64(data) / float64(total) * 100
	if pct > 95 {
		g.eventBus.PublishAlert(types.AlertWarning, "database",
			fmt.Sprintf("MySQL Buffer Pool 接近满: %s", inst.Name),
			fmt.Sprintf("MySQL %s InnoDB Buffer Pool 使用 %.1f%%\n\n"+
				"建议:\n"+
				"  1. 调大 innodb_buffer_pool_size (通常为物理内存的 60-70%%)\n"+
				"  2. 修改 my.cnf: innodb_buffer_pool_size = 4G\n"+
				"  3. 重启 MySQL 生效",
				inst.Name, pct),
			"db-mysql-bp-001")
	}
}

// guessServiceName returns the likely systemd service name for a database type.
func (g *DatabaseGuard) guessServiceName(dbType string) string {
	switch dbType {
	case "mysql":
		return "mysqld"
	case "postgresql":
		return "postgresql"
	case "redis":
		return "redis"
	case "mongodb":
		return "mongod"
	default:
		return dbType
	}
}

// formatBytes converts bytes to human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func stringContains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// ScanSlowQueryLog scans MySQL slow query log for patterns.
func (g *DatabaseGuard) ScanSlowQueryLog(logPath string) {
	if logPath == "" {
		// Try common paths
		candidates := []string{
			"/var/log/mysql/mysql-slow.log",
			"/var/log/mysqld-slow.log",
			"/www/server/mysql/slow.log",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				logPath = p
				break
			}
		}
	}
	if logPath == "" {
		return
	}

	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Read last 1000 lines for recent slow queries
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large lines

	var slowCount int
	var longestQuery string
	var longestTime float64

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# Query_time:") {
			slowCount++
			// Parse query time
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasPrefix(p, "Query_time:") {
					val := strings.TrimSuffix(p, "Query_time:")
					if t, err := strconv.ParseFloat(val, 64); err == nil && t > longestTime {
						longestTime = t
						if scanner.Scan() {
							longestQuery = scanner.Text()
						}
					}
				}
			}
		}
	}

	if slowCount > 10 {
		g.eventBus.PublishAlert(types.AlertWarning, "database",
			"MySQL慢查询日志分析",
			fmt.Sprintf("慢查询日志 %s 分析:\n"+
				"  慢查询总数: %d\n"+
				"  最长查询时间: %.3f 秒\n"+
				"  最长查询: %s\n\n"+
				"建议:\n"+
				"  1. 使用 mysqldumpslow 分析: mysqldumpslow -s t -t 10 %s\n"+
				"  2. 使用 EXPLAIN 分析慢查询执行计划\n"+
				"  3. 考虑添加索引或优化SQL",
				logPath, slowCount, longestTime, truncate(longestQuery, 200), logPath),
			"db-mysql-slowlog-001")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// init ensures filepath is used (avoid unused import if not needed)
var _ = filepath.Join
