package config

import (
	"fmt"
	"strings"
)

// ────────────────────────────────────────────────
// V4.0 — 场景模板
// WordPress 站点、Nginx+MySQL+Redis 组合、Spring Boot 服务
// 一键套用一组守护规则+阈值
// ────────────────────────────────────────────────

// SceneTemplate 场景模板
type SceneTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	GuardTargets []GuardTargetTemplate `json:"guard_targets"`
	Rules       []RuleTemplate    `json:"rules"`
	Thresholds  map[string]float64 `json:"thresholds"`
	NotifyLevel string            `json:"notify_level"` // 建议的通知级别
}

// GuardTargetTemplate 守护目标模板
type GuardTargetTemplate struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`        // systemd, docker, bare_process, http
	Command     string   `json:"command"`     // 启动命令
	HealthCheck string   `json:"health_check"` // 健康检查 URL
	Port        int      `json:"port"`
	ProcessName string   `json:"process_name"`
	Tags        []string `json:"tags"`
}

// RuleTemplate 规则模板
type RuleTemplate struct {
	Name        string  `json:"name"`
	Metric      string  `json:"metric"`
	Operator    string  `json:"operator"`     // >, <, >=, <=, ==
	Threshold   float64 `json:"threshold"`
	Duration    int     `json:"duration_sec"`  // 持续时间（秒）
	Severity    string  `json:"severity"`      // warning, error, critical
	Action      string  `json:"action"`        // alert, restart, ban_ip
	Description string  `json:"description"`
}

// ============================================================
// 内置场景模板
// ============================================================

// BuiltinTemplates 返回所有内置场景模板
func BuiltinTemplates() []SceneTemplate {
	return []SceneTemplate{
		wordpressTemplate(),
		nginxMySQLRedisTemplate(),
		springBootTemplate(),
	}
}

// wordpressTemplate WordPress 站点模板
func wordpressTemplate() SceneTemplate {
	return SceneTemplate{
		ID:          "wordpress",
		Name:        "WordPress 站点",
		Description: "完整的 WordPress 站点守护：Nginx + PHP-FPM + MySQL + 证书续期 + 安全扫描",
		Tags:        []string{"web", "cms", "php"},
		GuardTargets: []GuardTargetTemplate{
			{
				Name:        "nginx",
				Type:        "systemd",
				Command:     "systemctl start nginx",
				HealthCheck: "http://localhost/",
				Port:        80,
				ProcessName: "nginx",
				Tags:        []string{"web", "nginx"},
			},
			{
				Name:        "php-fpm",
				Type:        "systemd",
				Command:     "systemctl start php-fpm",
				Port:        9000,
				ProcessName: "php-fpm",
				Tags:        []string{"php"},
			},
			{
				Name:        "mysql",
				Type:        "systemd",
				Command:     "systemctl start mysqld",
				Port:        3306,
				ProcessName: "mysqld",
				Tags:        []string{"database", "mysql"},
			},
		},
		Rules: []RuleTemplate{
			{
				Name:        "Nginx 进程崩溃",
				Metric:      "nginx.alive",
				Operator:    "==",
				Threshold:   0,
				Duration:    10,
				Severity:    "critical",
				Action:      "restart",
				Description: "Nginx 进程不在运行，自动重启",
			},
			{
				Name:        "PHP-FPM 进程数过高",
				Metric:      "php-fpm.process_count",
				Operator:    ">",
				Threshold:   100,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "PHP-FPM 子进程数超过 100，可能遭遇 CC 攻击",
			},
			{
				Name:        "MySQL 慢查询增多",
				Metric:      "mysql.slow_queries",
				Operator:    ">",
				Threshold:   10,
				Duration:    300,
				Severity:    "warning",
				Action:      "alert",
				Description: "5分钟内慢查询超过 10 条，可能有慢 SQL 需优化",
			},
			{
				Name:        "HTTP 5xx 错误率",
				Metric:      "nginx.5xx_rate",
				Operator:    ">",
				Threshold:   5,
				Duration:    60,
				Severity:    "error",
				Action:      "alert",
				Description: "1分钟内 5xx 错误率超过 5%，服务可能异常",
			},
			{
				Name:        "证书即将到期",
				Metric:      "cert.days_to_expiry",
				Operator:    "<",
				Threshold:   14,
				Duration:    0,
				Severity:    "warning",
				Action:      "alert",
				Description: "SSL 证书 14 天后到期，准备续期",
			},
		},
		Thresholds: map[string]float64{
			"cpu.warning":      70,
			"cpu.critical":     90,
			"memory.warning":   80,
			"memory.critical":  95,
			"disk.warning":     80,
			"disk.critical":    90,
			"nginx.worker_max": 1024,
			"php.max_children": 50,
		},
		NotifyLevel: "warning",
	}
}

// nginxMySQLRedisTemplate Nginx+MySQL+Redis 组合模板
func nginxMySQLRedisTemplate() SceneTemplate {
	return SceneTemplate{
		ID:          "nginx-mysql-redis",
		Name:        "Nginx + MySQL + Redis 组合",
		Description: "经典 LNMR 架构：Nginx 反向代理 + MySQL 持久化 + Redis 缓存",
		Tags:        []string{"web", "cache", "database"},
		GuardTargets: []GuardTargetTemplate{
			{
				Name:        "nginx",
				Type:        "systemd",
				Command:     "systemctl start nginx",
				HealthCheck: "http://localhost/",
				Port:        80,
				ProcessName: "nginx",
				Tags:        []string{"web"},
			},
			{
				Name:        "mysql",
				Type:        "systemd",
				Command:     "systemctl start mysqld",
				Port:        3306,
				ProcessName: "mysqld",
				Tags:        []string{"database"},
			},
			{
				Name:        "redis",
				Type:        "systemd",
				Command:     "systemctl start redis",
				Port:        6379,
				ProcessName: "redis-server",
				Tags:        []string{"cache"},
			},
		},
		Rules: []RuleTemplate{
			{
				Name:        "Redis 内存使用率",
				Metric:      "redis.memory_usage",
				Operator:    ">",
				Threshold:   80,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "Redis 内存使用率超过 80%，检查是否需要扩容或清理 key",
			},
			{
				Name:        "Redis 连接数",
				Metric:      "redis.connected_clients",
				Operator:    ">",
				Threshold:   1000,
				Duration:    30,
				Severity:    "warning",
				Action:      "alert",
				Description: "Redis 连接数超过 1000，检查是否有连接泄漏",
			},
			{
				Name:        "MySQL 连接数",
				Metric:      "mysql.threads_connected",
				Operator:    ">",
				Threshold:   100,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "MySQL 连接数超过 100，检查连接池配置",
			},
			{
				Name:        "MySQL 主从延迟",
				Metric:      "mysql.seconds_behind_master",
				Operator:    ">",
				Threshold:   30,
				Duration:    60,
				Severity:    "error",
				Action:      "alert",
				Description: "MySQL 主从延迟超过 30 秒，从库可能数据不一致",
			},
			{
				Name:        "Nginx 并发连接",
				Metric:      "nginx.active_connections",
				Operator:    ">",
				Threshold:   500,
				Duration:    30,
				Severity:    "warning",
				Action:      "alert",
				Description: "Nginx 并发连接超过 500，关注流量是否正常",
			},
		},
		Thresholds: map[string]float64{
			"cpu.warning":       75,
			"cpu.critical":      90,
			"memory.warning":    80,
			"memory.critical":   95,
			"disk.warning":      80,
			"disk.critical":     90,
			"redis.maxmemory":   2147483648, // 2GB
			"mysql.max_connections": 200,
		},
		NotifyLevel: "warning",
	}
}

// springBootTemplate Spring Boot 服务模板
func springBootTemplate() SceneTemplate {
	return SceneTemplate{
		ID:          "spring-boot",
		Name:        "Spring Boot 服务",
		Description: "Java Spring Boot 微服务守护：JVM 监控 + 健康检查 + 日志告警 + 自动重启",
		Tags:        []string{"java", "microservice", "spring"},
		GuardTargets: []GuardTargetTemplate{
			{
				Name:        "spring-boot-app",
				Type:        "bare_process",
				Command:     "java -jar /opt/app/application.jar",
				HealthCheck: "http://localhost:8080/actuator/health",
				Port:        8080,
				ProcessName: "java",
				Tags:        []string{"java", "spring-boot"},
			},
		},
		Rules: []RuleTemplate{
			{
				Name:        "JVM 堆内存使用率",
				Metric:      "jvm.heap_usage",
				Operator:    ">",
				Threshold:   85,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "JVM 堆内存使用率超过 85%，可能发生 OOM",
			},
			{
				Name:        "JVM GC 时间过长",
				Metric:      "jvm.gc_time",
				Operator:    ">",
				Threshold:   500,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "1分钟内 GC 时间超过 500ms，可能需要调优 JVM 参数",
			},
			{
				Name:        "健康检查失败",
				Metric:      "http.health_status",
				Operator:    "==",
				Threshold:   0,
				Duration:    30,
				Severity:    "critical",
				Action:      "restart",
				Description: "Spring Boot Actuator 健康检查连续 30 秒失败，自动重启",
			},
			{
				Name:        "HTTP 响应时间",
				Metric:      "http.response_time",
				Operator:    ">",
				Threshold:   2000,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "HTTP 平均响应时间超过 2 秒，服务可能变慢",
			},
			{
				Name:        "线程数过高",
				Metric:      "jvm.thread_count",
				Operator:    ">",
				Threshold:   500,
				Duration:    60,
				Severity:    "warning",
				Action:      "alert",
				Description: "JVM 线程数超过 500，检查是否有线程泄漏",
			},
		},
		Thresholds: map[string]float64{
			"cpu.warning":       70,
			"cpu.critical":      85,
			"memory.warning":    75,
			"memory.critical":   90,
			"jvm.heap.max":      1073741824, // 1GB
			"jvm.gc.threshold":  500,
			"http.timeout":      3000,
		},
		NotifyLevel: "error",
	}
}

// FindTemplate 按 ID 查找模板
func FindTemplate(id string) *SceneTemplate {
	for _, t := range BuiltinTemplates() {
		if t.ID == id {
			return &t
		}
	}
	return nil
}

// FormatTemplateSummary 格式化模板摘要（用于 API 返回列表）
func FormatTemplateSummary(t SceneTemplate) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s（%s）\n", t.Name, t.ID))
	sb.WriteString(fmt.Sprintf("  描述：%s\n", t.Description))
	sb.WriteString(fmt.Sprintf("  守护目标：%d 个\n", len(t.GuardTargets)))
	sb.WriteString(fmt.Sprintf("  规则：%d 条\n", len(t.Rules)))
	sb.WriteString(fmt.Sprintf("  标签：%s\n", strings.Join(t.Tags, ", ")))
	return sb.String()
}
