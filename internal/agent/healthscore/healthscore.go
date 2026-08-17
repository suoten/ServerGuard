package healthscore

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/agent/probe"
)

// Score represents the overall health score of the server.
type Score struct {
	Total        int         `json:"total"`        // 0-100
	Performance  int         `json:"performance"`  // 0-100
	Availability int         `json:"availability"` // 0-100
	Security     int         `json:"security"`     // 0-100
	Deductions   []Deduction `json:"deductions"`
	Trend        string      `json:"trend"` // "up", "down", "stable"
	UpdatedAt    time.Time   `json:"updated_at"`
}

// Deduction represents a single score deduction.
type Deduction struct {
	Category string `json:"category"` // performance, availability, security
	Reason   string `json:"reason"`
	Points   int    `json:"points"`
}

// Scorer calculates health scores based on system metrics.
type Scorer struct {
	mu      sync.RWMutex
	current Score
	history []int // last 7 scores for trend
	store   *storage.Storage
	probe   *probe.Probe
}

// New creates a new Scorer.
func New(store *storage.Storage, p *probe.Probe) *Scorer {
	return &Scorer{
		store: store,
		probe: p,
		current: Score{
			Total:        100,
			Performance:  100,
			Availability: 100,
			Security:     100,
			Deductions:   []Deduction{},
			Trend:        "stable",
		},
	}
}

// Calculate computes the health score from current metrics.
func (s *Scorer) Calculate(metrics map[string]interface{}) Score {
	s.mu.Lock()
	defer s.mu.Unlock()

	perfScore := 100
	availScore := 100
	secScore := 100
	deductions := []Deduction{}

	// --- Performance deductions ---

	// CPU usage
	if cpu, ok := metrics["cpu_percent"].(float64); ok {
		if cpu > 90 {
			perfScore -= 15
			deductions = append(deductions, Deduction{"performance", fmt.Sprintf("CPU 使用率 %.0f%%（严重过高）", cpu), 15})
		} else if cpu > 80 {
			perfScore -= 10
			deductions = append(deductions, Deduction{"performance", fmt.Sprintf("CPU 使用率 %.0f%%", cpu), 10})
		} else if cpu > 70 {
			perfScore -= 5
			deductions = append(deductions, Deduction{"performance", fmt.Sprintf("CPU 使用率 %.0f%%（偏高）", cpu), 5})
		}
	}

	// Memory usage
	if mem, ok := metrics["mem_percent"].(float64); ok {
		if mem > 90 {
			perfScore -= 15
			deductions = append(deductions, Deduction{"performance", fmt.Sprintf("内存使用率 %.0f%%（严重过高）", mem), 15})
		} else if mem > 80 {
			perfScore -= 10
			deductions = append(deductions, Deduction{"performance", fmt.Sprintf("内存使用率 %.0f%%", mem), 10})
		} else if mem > 70 {
			perfScore -= 5
			deductions = append(deductions, Deduction{"performance", fmt.Sprintf("内存使用率 %.0f%%（偏高）", mem), 5})
		}
	}

	// Disk usage (check all disks, use the worst)
	if disks, ok := metrics["disks"].([]interface{}); ok {
		for _, d := range disks {
			if disk, ok := d.(map[string]interface{}); ok {
				if pct, ok := disk["used_percent"].(float64); ok {
					if pct > 95 {
						perfScore -= 15
						deductions = append(deductions, Deduction{"performance", fmt.Sprintf("磁盘 %v 使用率 %.0f%%（即将满）", disk["mount_point"], pct), 15})
					} else if pct > 90 {
						perfScore -= 10
						deductions = append(deductions, Deduction{"performance", fmt.Sprintf("磁盘 %v 使用率 %.0f%%", disk["mount_point"], pct), 10})
					} else if pct > 80 {
						perfScore -= 5
						deductions = append(deductions, Deduction{"performance", fmt.Sprintf("磁盘 %v 使用率 %.0f%%（偏高）", disk["mount_point"], pct), 5})
					}
				}
			}
		}
	}

	// Load average
	if load, ok := metrics["load_avg_1"].(float64); ok {
		if cores, ok := metrics["cpu_cores"].(float64); ok && cores > 0 {
			ratio := load / cores
			if ratio > 2.0 {
				perfScore -= 10
				deductions = append(deductions, Deduction{"performance", fmt.Sprintf("负载 %.2f 是CPU核数的 %.1f 倍", load, ratio), 10})
			} else if ratio > 1.5 {
				perfScore -= 5
				deductions = append(deductions, Deduction{"performance", fmt.Sprintf("负载 %.2f 偏高", load), 5})
			}
		}
	}

	if perfScore < 0 {
		perfScore = 0
	}

	// --- Availability deductions ---

	// Website down
	if s.probe != nil {
		downCount := s.probe.SiteDownCount()
		if downCount > 0 {
			points := downCount * 15
			if points > 40 {
				points = 40
			}
			availScore -= points
			deductions = append(deductions, Deduction{"availability", fmt.Sprintf("%d 个网站/服务不可用", downCount), points})
		}
	}

	// Unresolved alerts
	if s.store != nil {
		if alerts, err := s.store.GetUnresolvedAlerts(); err == nil {
			alertCount := len(alerts)
			if alertCount > 0 {
				points := alertCount * 5
				if points > 30 {
					points = 30
				}
				availScore -= points
				deductions = append(deductions, Deduction{"availability", fmt.Sprintf("%d 条未解决告警", alertCount), points})
			}
		}
	}

	if availScore < 0 {
		availScore = 0
	}

	// --- Security deductions ---

	// Emergency stop
	if es, ok := metrics["emergency_stop"].(bool); ok && es {
		secScore -= 20
		deductions = append(deductions, Deduction{"security", "紧急停止已激活", 20})
	}

	// Learning mode (not auto-fixing = less safe)
	if mode, ok := metrics["mode"].(string); ok && mode == "emergency" {
		secScore -= 15
		deductions = append(deductions, Deduction{"security", "系统处于紧急模式", 15})
	}

	if secScore < 0 {
		secScore = 0
	}

	// --- Total ---
	total := (perfScore + availScore + secScore) / 3

	// Trend
	trend := "stable"
	if len(s.history) > 0 {
		prev := s.history[len(s.history)-1]
		if total > prev+3 {
			trend = "up"
		} else if total < prev-3 {
			trend = "down"
		}
	}

	// Update history
	s.history = append(s.history, total)
	if len(s.history) > 7 {
		s.history = s.history[len(s.history)-7:]
	}

	s.current = Score{
		Total:        total,
		Performance:  perfScore,
		Availability: availScore,
		Security:     secScore,
		Deductions:   deductions,
		Trend:        trend,
		UpdatedAt:    time.Now(),
	}

	return s.current
}

// Get returns the current score.
func (s *Scorer) Get() Score {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}
