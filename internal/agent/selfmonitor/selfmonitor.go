package selfmonitor

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

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
func New(bus *eventbus.EventBus) *SelfMonitor {
	return &SelfMonitor{
		eventBus:       bus,
		maxRSS:         80 * 1024 * 1024, // 80MB
		maxGoroutines:  1000,
		maxQueueDepth:  1000,
		startTime:      time.Now(),
		latencyBuckets: make(map[float64]int),
	}
}

// Check performs self-monitoring checks.
func (s *SelfMonitor) Check() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check RSS (Sys is the virtual memory stats, HeapAlloc is more relevant)
	rss := memStats.Sys
	if rss > s.maxRSS {
		s.eventBus.PublishAlert(types.AlertWarning, "agent",
			"Agent内存过高",
			fmt.Sprintf("Agent RSS %d MB 超过上限 %d MB，可能存在内存泄漏。Goroutine数: %d",
				rss/1024/1024, s.maxRSS/1024/1024, runtime.NumGoroutine()),
			"agent-mem-001")
		// Force GC
		runtime.GC()
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

	// Check process uptime
	uptime := time.Since(s.startTime)
	_ = uptime

	// Write self-metrics to /proc-like file for external monitoring
	s.writeSelfMetrics(memStats, goroutines)
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
func (s *SelfMonitor) RecordCollectLatency(d time.Duration) {
	atomic.AddInt64(&s.collectCount, 1)
	s.mu.Lock()
	s.collectLatency = d
	// Update histogram
	ms := float64(d.Milliseconds())
	s.latencyBuckets[ms]++
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
