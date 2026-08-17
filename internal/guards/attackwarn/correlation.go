package attackwarn

import (
	"fmt"
	"sync"
	"time"
)

// AttackEvent 攻击事件
type AttackEvent struct {
	SourceIP   string
	Module     string // Z1, Z2, C1, R 等
	AttackType string // sql_injection, xss, ssh_brute, port_scan 等
	Timestamp  time.Time
	Severity   string // low, medium, high
}

// AttackProfile 攻击画像
type AttackProfile struct {
	SourceIP        string
	GeoLocation     string
	AttackTypes     []string
	FirstSeen       time.Time
	LastSeen        time.Time
	Duration        time.Duration
	AffectedModules []string
	Trend           string // periodic, burst, sustained
	Confidence      float64
}

// CorrelationEngine 攻击事件关联引擎。
// 时间窗口内同源 IP 事件聚合，跨模块关联打分。
type CorrelationEngine struct {
	mu         sync.Mutex
	events     map[string][]AttackEvent // IP -> events
	windowSize time.Duration
	profiles   map[string]*AttackProfile // IP -> profile
}

// NewCorrelationEngine 创建关联引擎。
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		events:     make(map[string][]AttackEvent),
		windowSize: 5 * time.Minute,
		profiles:   make(map[string]*AttackProfile),
	}
}

// Ingest 接收一个攻击事件。
func (e *CorrelationEngine) Ingest(event AttackEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	e.events[event.SourceIP] = append(e.events[event.SourceIP], event)

	// 清理窗口外的事件
	cutoff := event.Timestamp.Add(-e.windowSize)
	var recent []AttackEvent
	for _, ev := range e.events[event.SourceIP] {
		if ev.Timestamp.After(cutoff) {
			recent = append(recent, ev)
		}
	}
	e.events[event.SourceIP] = recent
}

// Aggregate 聚合窗口内事件，生成攻击画像。
func (e *CorrelationEngine) Aggregate() []AttackProfile {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-e.windowSize)

	var profiles []AttackProfile
	for ip, events := range e.events {
		if len(events) == 0 {
			continue
		}

		// 过滤窗口内事件
		var recent []AttackEvent
		for _, ev := range events {
			if ev.Timestamp.After(cutoff) {
				recent = append(recent, ev)
			}
		}
		if len(recent) == 0 {
			continue
		}

		profile := e.buildProfile(ip, recent)
		profiles = append(profiles, profile)
		e.profiles[ip] = &profile
	}

	return profiles
}

// buildProfile 构建攻击画像。
func (e *CorrelationEngine) buildProfile(ip string, events []AttackEvent) AttackProfile {
	attackTypes := make(map[string]bool)
	modules := make(map[string]bool)
	var firstSeen, lastSeen time.Time
	firstSeen = events[0].Timestamp
	lastSeen = events[0].Timestamp

	for _, ev := range events {
		attackTypes[ev.AttackType] = true
		modules[ev.Module] = true
		if ev.Timestamp.Before(firstSeen) {
			firstSeen = ev.Timestamp
		}
		if ev.Timestamp.After(lastSeen) {
			lastSeen = ev.Timestamp
		}
	}

	var typesList, modulesList []string
	for t := range attackTypes {
		typesList = append(typesList, t)
	}
	for m := range modules {
		modulesList = append(modulesList, m)
	}

	// 计算置信度：事件数 × 类型多样性 × 跨模块数
	confidence := float64(len(events)) * float64(len(attackTypes)) * float64(len(modules)) / 100.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	// 检测趋势
	trend := e.detectTrend(events)

	return AttackProfile{
		SourceIP:        ip,
		AttackTypes:     typesList,
		FirstSeen:       firstSeen,
		LastSeen:        lastSeen,
		Duration:        lastSeen.Sub(firstSeen),
		AffectedModules: modulesList,
		Trend:           trend,
		Confidence:      confidence,
	}
}

// detectTrend 检测攻击趋势。
func (e *CorrelationEngine) detectTrend(events []AttackEvent) string {
	if len(events) < 3 {
		return "burst"
	}

	// 检查是否周期性（间隔均匀）
	intervals := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		intervals = append(intervals, events[i].Timestamp.Sub(events[i-1].Timestamp).Seconds())
	}

	avg := 0.0
	for _, v := range intervals {
		avg += v
	}
	avg /= float64(len(intervals))

	stdDev := 0.0
	for _, v := range intervals {
		stdDev += (v - avg) * (v - avg)
	}
	stdDev = sqrt(stdDev / float64(len(intervals)))

	if stdDev < avg*0.2 {
		return "periodic"
	}
	if len(events) > 10 {
		return "sustained"
	}
	return "burst"
}

// GetProfile 获取指定 IP 的攻击画像。
func (e *CorrelationEngine) GetProfile(ip string) (*AttackProfile, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.profiles[ip]
	return p, ok
}

// DetectPeriodic 检测周期性攻击模式。
func (e *CorrelationEngine) DetectPeriodic(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	p, ok := e.profiles[ip]
	if !ok {
		return false
	}
	return p.Trend == "periodic"
}

// GetHighConfidenceProfiles 返回置信度 > threshold 的画像。
func (e *CorrelationEngine) GetHighConfidenceProfiles(threshold float64) []AttackProfile {
	e.mu.Lock()
	defer e.mu.Unlock()

	var result []AttackProfile
	for _, p := range e.profiles {
		if p.Confidence > threshold {
			result = append(result, *p)
		}
	}
	return result
}

// String 返回引擎状态。
func (e *CorrelationEngine) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("CorrelationEngine{events: %d IPs, profiles: %d}", len(e.events), len(e.profiles))
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}
