package apm

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// Redis 大 Key / 热 Key 治理 (P2)
// 定时 redis-cli --bigkeys + MEMORY USAGE 采样 → 告警并给出拆分建议
// ────────────────────────────────────────────────

// RedisBigKey 大 Key 信息
type RedisBigKey struct {
	Key       string `json:"key"`
	Type      string `json:"type"`       // string/list/hash/set/zset
	Size      int64  `json:"size"`       // 元素个数或字节长度
	Memory    int64  `json:"memory_bytes"` // 占用内存(字节)
	Suggestion string `json:"suggestion"` // 拆分建议
	Severity  string `json:"severity"`   // high/medium/low
}

// RedisKeyReport Redis 大 Key 报告
type RedisKeyReport struct {
	Timestamp time.Time      `json:"timestamp"`
	Connected bool           `json:"connected"`
	BigKeys   []RedisBigKey  `json:"big_keys"`
	TotalKeys int64          `json:"total_keys"`
	UsedMemory int64         `json:"used_memory"`
}

// RedisAnalyzer Redis 分析器
type RedisAnalyzer struct {
	store *storage.Storage
	mu    sync.Mutex
	last  *RedisKeyReport
	redisCLI string // redis-cli 路径
}

// NewRedisAnalyzer 创建 Redis 分析器
func NewRedisAnalyzer(store *storage.Storage) *RedisAnalyzer {
	return &RedisAnalyzer{
		store:    store,
		redisCLI: findRedisCLI(),
	}
}

func findRedisCLI() string {
	for _, p := range []string{
		"redis-cli",
		"/usr/local/bin/redis-cli",
		"/usr/bin/redis-cli",
		"/www/server/redis/src/redis-cli",
	} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return "redis-cli"
}

// Analyze 执行 Redis 大 Key 分析
func (a *RedisAnalyzer) Analyze() (*RedisKeyReport, error) {
	report := &RedisKeyReport{
		Timestamp: time.Now(),
		BigKeys:   []RedisBigKey{},
	}

	if a.redisCLI == "" {
		return report, fmt.Errorf("redis-cli 未安装")
	}

	// 测试连接
	if !a.pingRedis() {
		report.Connected = false
		a.mu.Lock()
		a.last = report
		a.mu.Unlock()
		return report, nil
	}
	report.Connected = true

	// 获取基本信息
	report.TotalKeys = a.getTotalKeys()
	report.UsedMemory = a.getUsedMemory()

	// 使用 --bigkeys 采样
	bigKeys := a.scanBigKeys()
	report.BigKeys = bigKeys

	a.mu.Lock()
	a.last = report
	a.mu.Unlock()

	return report, nil
}

// GetLastReport 返回最近一次报告
func (a *RedisAnalyzer) GetLastReport() *RedisKeyReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}

func (a *RedisAnalyzer) pingRedis() bool {
	cmd := exec.Command(a.redisCLI, "ping")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "PONG"
}

func (a *RedisAnalyzer) getTotalKeys() int64 {
	cmd := exec.Command(a.redisCLI, "DBSIZE")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	// 输出格式: (integer) 12345
	re := regexp.MustCompile(`(\d+)`)
	m := re.FindStringSubmatch(string(output))
	if m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	return 0
}

func (a *RedisAnalyzer) getUsedMemory() int64 {
	cmd := exec.Command(a.redisCLI, "INFO", "memory")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "used_memory:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				n, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				return n
			}
		}
	}
	return 0
}

// scanBigKeys 使用 redis-cli --bigkeys 采样大 Key
func (a *RedisAnalyzer) scanBigKeys() []RedisBigKey {
	cmd := exec.Command(a.redisCLI, "--bigkeys", "--sample", "1000")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	var keys []RedisBigKey
	lines := strings.Split(string(output), "\n")

	// 解析 --bigkeys 输出格式:
	// Biggest string found 'key_name' has 10000 bytes
	// Biggest list   found 'key_name' has 5000 items
	bigKeyRegex := regexp.MustCompile(`Biggest\s+(\w+)\s+found\s+'([^']+)'\s+has\s+(\d+)\s+(bytes|items)`)

	for _, line := range lines {
		if m := bigKeyRegex.FindStringSubmatch(line); m != nil {
			keyType := m[1]
			keyName := m[2]
			size, _ := strconv.ParseInt(m[3], 10, 64)
			unit := m[4]

			// 尝试获取内存使用量
			mem := a.getMemoryUsage(keyName)

			// 生成建议
			suggestion, severity := generateRedisSuggestion(keyType, size, unit, mem)

			keys = append(keys, RedisBigKey{
				Key:        keyName,
				Type:       keyType,
				Size:       size,
				Memory:     mem,
				Suggestion: suggestion,
				Severity:   severity,
			})
		}
	}

	// 限制返回 20 条
	if len(keys) > 20 {
		keys = keys[:20]
	}

	return keys
}

func (a *RedisAnalyzer) getMemoryUsage(key string) int64 {
	cmd := exec.Command(a.redisCLI, "MEMORY", "USAGE", key)
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	re := regexp.MustCompile(`(\d+)`)
	m := re.FindStringSubmatch(string(output))
	if m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	return 0
}

func generateRedisSuggestion(keyType string, size int64, unit string, memory int64) (string, string) {
	var suggestions []string
	severity := "low"

	// 按类型判断阈值
	switch strings.ToLower(keyType) {
	case "string":
		if unit == "bytes" && size > 1024*1024 { // > 1MB
			suggestions = append(suggestions, fmt.Sprintf("String Key 占用 %.1fKB，建议拆分为小 Key 或使用 Hash", float64(size)/1024))
			severity = "high"
		} else if unit == "bytes" && size > 10*1024 { // > 10KB
			suggestions = append(suggestions, fmt.Sprintf("String Key 占用 %.1fKB，偏大", float64(size)/1024))
			severity = "medium"
		}
	case "list":
		if size > 10000 {
			suggestions = append(suggestions, fmt.Sprintf("List 有 %d 个元素，建议分页或使用 Hash 分桶", size))
			severity = "high"
		} else if size > 1000 {
			suggestions = append(suggestions, fmt.Sprintf("List 有 %d 个元素，偏多", size))
			severity = "medium"
		}
	case "hash":
		if size > 10000 {
			suggestions = append(suggestions, fmt.Sprintf("Hash 有 %d 个 field，建议拆分为多个 Hash", size))
			severity = "high"
		} else if size > 1000 {
			suggestions = append(suggestions, fmt.Sprintf("Hash 有 %d 个 field，偏多", size))
			severity = "medium"
		}
	case "set":
		if size > 10000 {
			suggestions = append(suggestions, fmt.Sprintf("Set 有 %d 个成员，考虑使用分片 Set", size))
			severity = "high"
		}
	case "zset":
		if size > 10000 {
			suggestions = append(suggestions, fmt.Sprintf("ZSet 有 %d 个成员，考虑分片或使用时间窗口", size))
			severity = "high"
		}
	}

	// 内存占用判断
	if memory > 10*1024*1024 { // > 10MB
		suggestions = append(suggestions, fmt.Sprintf("内存占用 %.1fMB，可能导致 del 阻塞", float64(memory)/1024/1024))
		severity = "high"
	} else if memory > 1*1024*1024 && severity != "high" { // > 1MB
		suggestions = append(suggestions, fmt.Sprintf("内存占用 %.1fKB", float64(memory)/1024))
		if severity == "" {
			severity = "medium"
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Key 大小正常")
		severity = "low"
	}

	return strings.Join(suggestions, "；"), severity
}

// PublishAlertIfAbnormal 发布大 Key 告警
func (a *RedisAnalyzer) PublishAlertIfAbnormal(bus *eventbus.EventBus, report *RedisKeyReport) {
	if report == nil || !report.Connected || len(report.BigKeys) == 0 {
		return
	}
	highCount := 0
	for _, k := range report.BigKeys {
		if k.Severity == "high" {
			highCount++
		}
	}
	if highCount > 0 {
		var sb strings.Builder
		count := 0
		for _, k := range report.BigKeys {
			if k.Severity == "high" {
				fmt.Fprintf(&sb, "  · [%s] %s (%s, size=%d, mem=%.1fKB)\n    建议: %s\n",
					k.Severity, k.Key, k.Type, k.Size, float64(k.Memory)/1024, k.Suggestion)
				count++
				if count >= 5 {
					break
				}
			}
		}
		bus.PublishAlert(types.AlertWarning, "apm-redis",
			fmt.Sprintf("Redis 发现 %d 个大 Key", highCount),
			fmt.Sprintf("总 Key 数: %d, 已用内存: %.1fMB\n%s",
				report.TotalKeys, float64(report.UsedMemory)/1024/1024, sb.String()),
			"apm-redis-001")
	}
}
