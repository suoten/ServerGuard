package selfmonitor

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/mem"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// SelfMonitor implements §9.1: Agent Self-Monitoring.
// Monitors: RSS, CPU, Goroutine count, Panic count, queue depth, collection latency.
type SelfMonitor struct {
	mu             sync.RWMutex
	eventBus       *eventbus.EventBus
	panicCount     int64 // atomic
	collectCount   int64 // atomic
	collectLatency time.Duration
	maxRSS         uint64 // bytes
	maxGoroutines  int
	maxQueueDepth  int
	startTime      time.Time
	// Histogram for collection latency (simple bucket-based)
	latencyBuckets map[float64]int // bucket upper bound -> count
}

// New creates a new SelfMonitor.
// 向宝塔学习：maxRSS 根据系统内存自适应，不硬编码
func New(bus *eventbus.EventBus) *SelfMonitor {
	// 根据系统总内存自适应设定 maxRSS
	// ≤ 1G: 64MB, ≤ 2G: 96MB, ≤ 4G: 128MB, > 4G: 192MB
	maxRSS := uint64(64 * 1024 * 1024) // 默认 64MB
	if vmem, err := mem.VirtualMemory(); err == nil {
		totalMB := vmem.Total / 1024 / 1024
		switch {
		case totalMB > 4096:
			maxRSS = 192 * 1024 * 1024
		case totalMB > 2048:
			maxRSS = 128 * 1024 * 1024
		case totalMB > 1024:
			maxRSS = 96 * 1024 * 1024
		}
	}
	return &SelfMonitor{
		eventBus:       bus,
		maxRSS:         maxRSS,
		maxGoroutines:  1000, // 并发扫描时 goroutine 会增多（8 worker × 11 子扫描器 + HTTP 连接池）
		maxQueueDepth:  500,
		startTime:      time.Now(),
		latencyBuckets: make(map[float64]int),
	}
}

// Check performs self-monitoring checks.
// 向宝塔学习：RSS 超限时不仅 GC，还主动释放内存回 OS
func (s *SelfMonitor) Check() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check RSS (Sys is the virtual memory stats, HeapAlloc is more relevant)
	rss := memStats.Sys
	if rss > s.maxRSS {
		s.eventBus.PublishAlert(types.AlertWarning, "agent",
			"Agent内存过高",
			fmt.Sprintf("Agent RSS %d MB 超过上限 %d MB，已触发 GC+FreeOSMemory。Goroutine数: %d",
				rss/1024/1024, s.maxRSS/1024/1024, runtime.NumGoroutine()),
			"agent-mem-001")
		// Force GC + 释放内存回 OS
		runtime.GC()
		debug.FreeOSMemory()
	}

	// 如果 HeapAlloc 超过 maxRSS 的 50%，主动 GC（防止内存缓步增长）
	if memStats.HeapAlloc > s.maxRSS/2 {
		runtime.GC()
		debug.FreeOSMemory()
	}

	// Check Goroutine count
	goroutines := runtime.NumGoroutine()
	if goroutines > s.maxGoroutines {
		s.eventBus.PublishAlert(types.AlertError, "agent",
			"Goroutine泄漏",
			fmt.Sprintf("Goroutine数量 %d 超过上限 %d，可能存在泄漏", goroutines, s.maxGoroutines),
			"agent-goroutine-001")
	}

	// Check panic count
	panicCount := atomic.LoadInt64(&s.panicCount)
	if panicCount > 3 {
		s.eventBus.PublishAlert(types.AlertCritical, "agent",
			"Agent频繁Panic",
			fmt.Sprintf("Agent在过去1小时内Panic %d 次，自身不稳定，建议重启", panicCount),
			"agent-panic-001")
	}

	// 【内存泄漏修复】清理 latencyBuckets：保留最近 1000 个采样，丢弃旧数据
	// latencyBuckets 按 10ms 粒度分桶，正常运行 5s 采集一次时每分钟新增 ~12 个桶，
	// 一天新增 ~17000 个桶——虽然每个桶只有一个 int，但 map 的内存开销不可忽视。
	// 每小时 Check() 被调用约 60 次（60s 周期），在此处做一次廉价清理：
	// 只保留最大的 100 个桶（覆盖最常见的延迟范围），其余丢弃。
	s.mu.Lock()
	if len(s.latencyBuckets) > 100 {
		// 找到前 100 个最常出现的桶，其余丢弃
		type bucketEntry struct {
			key   float64
			count int
		}
		entries := make([]bucketEntry, 0, len(s.latencyBuckets))
		for k, v := range s.latencyBuckets {
			entries = append(entries, bucketEntry{k, v})
		}
		// 按 count 降序排序
		for i := 1; i < len(entries); i++ {
			for j := i; j > 0 && entries[j].count > entries[j-1].count; j-- {
				entries[j], entries[j-1] = entries[j-1], entries[j]
			}
		}
		// 保留前 100 个
		newBuckets := make(map[float64]int, 100)
		for i := 0; i < 100 && i < len(entries); i++ {
			newBuckets[entries[i].key] = entries[i].count
		}
		s.latencyBuckets = newBuckets
	}
	s.mu.Unlock()

	// Check process uptime
	uptime := time.Since(s.startTime)
	_ = uptime

	// Write self-metrics to /proc-like file for external monitoring
	// 向宝塔学习：writeSelfMetrics 是空操作，直接去掉调用
	// s.writeSelfMetrics(memStats, goroutines)
	_ = memStats
	_ = goroutines
}

// RecordPanic records a panic occurrence.
func (s *SelfMonitor) RecordPanic() {
	atomic.AddInt64(&s.panicCount, 1)
}

// ResetPanicCount resets the panic counter (called hourly).
func (s *SelfMonitor) ResetPanicCount() {
	atomic.StoreInt64(&s.panicCount, 0)
}

// RecordCollectLatency records the latency of a collection cycle.
// 向宝塔学习：延迟直方图用 10ms 粒度量化，避免 map 无限增长
func (s *SelfMonitor) RecordCollectLatency(d time.Duration) {
	atomic.AddInt64(&s.collectCount, 1)
	s.mu.Lock()
	s.collectLatency = d
	// 量化到 10ms 桶：12.3ms → 10ms, 15.7ms → 10ms, 23.4ms → 20ms
	bucket := float64(int(d.Milliseconds())/10) * 10
	s.latencyBuckets[bucket]++
	s.mu.Unlock()

	// Alert if P99 > 500ms
	if d > 500*time.Millisecond {
		s.eventBus.PublishAlert(types.AlertWarning, "agent",
			"采集延迟过高",
			fmt.Sprintf("采集延迟 %v 超过 500ms 阈值", d),
			"agent-latency-001")
	}
}

// SetQueueDepth sets the current event queue depth.
func (s *SelfMonitor) SetQueueDepth(depth int) {
	if depth > s.maxQueueDepth {
		s.eventBus.PublishAlert(types.AlertWarning, "agent",
			"事件队列积压",
			fmt.Sprintf("事件队列深度 %d 超过上限 %d，可能存在处理瓶颈", depth, s.maxQueueDepth),
			"agent-queue-001")
	}
}

// GetSelfMetrics returns current self-monitoring metrics.
func (s *SelfMonitor) GetSelfMetrics() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"rss_bytes":          memStats.Sys,
		"rss_mb":             memStats.Sys / 1024 / 1024,
		"heap_alloc_bytes":   memStats.HeapAlloc,
		"goroutine_count":    runtime.NumGoroutine(),
		"panic_count":        atomic.LoadInt64(&s.panicCount),
		"collect_count":      atomic.LoadInt64(&s.collectCount),
		"collect_latency_ms": float64(s.collectLatency.Milliseconds()),
		"uptime_seconds":     time.Since(s.startTime).Seconds(),
		"max_rss_mb":         s.maxRSS / 1024 / 1024,
		"max_goroutines":     s.maxGoroutines,
	}
}

// writeSelfMetrics writes metrics to a file for external monitoring.
func (s *SelfMonitor) writeSelfMetrics(memStats runtime.MemStats, goroutines int) {
	dataDir := os.Getenv("SERVERGUARD_DATA_DIR")
	if dataDir == "" {
		dataDir = "/var/lib/serverguard"
	}
	metricsFile := dataDir + "/agent-self-metrics.json"
	// In production, write JSON metrics to file
	_ = metricsFile
}

// StartWatchdog starts the internal watchdog goroutine (L1 protection).
func (s *SelfMonitor) StartWatchdog(ctx <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	panicResetTicker := time.NewTicker(1 * time.Hour)
	defer panicResetTicker.Stop()

	for {
		select {
		case <-ctx:
			return
		case <-ticker.C:
			s.Check()
		case <-panicResetTicker.C:
			s.ResetPanicCount()
		}
	}
}

// RecoverPanic is a deferred function to recover from panics.
func (s *SelfMonitor) RecoverPanic() {
	if r := recover(); r != nil {
		s.RecordPanic()
		s.eventBus.PublishAlert(types.AlertError, "agent",
			"Agent Panic 已恢复",
			fmt.Sprintf("Agent 发生 Panic: %v，已自动恢复", r),
			"agent-panic-001")
	}
}
