package attackwarn


import (
	"testing"
	"time"
)

func TestCorrelationEngine_IngestAndAggregate(t *testing.T) {
	engine := NewCorrelationEngine()
	now := time.Now()

	engine.Ingest(AttackEvent{SourceIP: "1.2.3.4", Module: "Z1", AttackType: "sql_injection", Timestamp: now})
	engine.Ingest(AttackEvent{SourceIP: "1.2.3.4", Module: "Z2", AttackType: "ssh_brute", Timestamp: now.Add(1 * time.Second)})
	engine.Ingest(AttackEvent{SourceIP: "1.2.3.4", Module: "C1", AttackType: "ban", Timestamp: now.Add(2 * time.Second)})

	profiles := engine.Aggregate()
	if len(profiles) == 0 {
		t.Fatal("should have profiles")
	}
	if profiles[0].SourceIP != "1.2.3.4" {
		t.Error("profile IP mismatch")
	}
	if len(profiles[0].AffectedModules) < 3 {
		t.Errorf("should have 3 modules, got %d", len(profiles[0].AffectedModules))
	}
}

func TestCorrelationEngine_Confidence(t *testing.T) {
	engine := NewCorrelationEngine()
	now := time.Now()

	// 多模块多类型事件 → 高置信度
	for i := 0; i < 10; i++ {
		engine.Ingest(AttackEvent{
			SourceIP:   "1.2.3.5",
			Module:     []string{"Z1", "Z2", "C1"}[i%3],
			AttackType: []string{"sql_injection", "xss", "ssh_brute"}[i%3],
			Timestamp:  now.Add(time.Duration(i) * time.Second),
		})
	}

	profiles := engine.Aggregate()
	if len(profiles) == 0 {
		t.Fatal("should have profiles")
	}
	if profiles[0].Confidence <= 0 {
		t.Error("confidence should be > 0")
	}
}

func TestCorrelationEngine_DetectPeriodic(t *testing.T) {
	engine := NewCorrelationEngine()
	now := time.Now()

	// 周期性事件（均匀间隔）
	for i := 0; i < 15; i++ {
		engine.Ingest(AttackEvent{
			SourceIP:   "1.2.3.6",
			Module:     "Z1",
			AttackType: "port_scan",
			Timestamp:  now.Add(time.Duration(i*5) * time.Second),
		})
	}

	engine.Aggregate()
	if !engine.DetectPeriodic("1.2.3.6") {
		t.Error("should detect periodic attack")
	}
}

func TestCorrelationEngine_GetHighConfidence(t *testing.T) {
	engine := NewCorrelationEngine()
	now := time.Now()

	for i := 0; i < 20; i++ {
		engine.Ingest(AttackEvent{
			SourceIP:   "1.2.3.7",
			Module:     []string{"Z1", "Z2", "C1", "R"}[i%4],
			AttackType: []string{"sql_injection", "xss", "ssh_brute", "cc"}[i%4],
			Timestamp:  now.Add(time.Duration(i) * time.Second),
		})
	}

	engine.Aggregate()
	highConf := engine.GetHighConfidenceProfiles(0.5)
	if len(highConf) == 0 {
		t.Error("should have high confidence profiles")
	}
}

func TestCorrelationEngine_GetProfile(t *testing.T) {
	engine := NewCorrelationEngine()
	now := time.Now()

	engine.Ingest(AttackEvent{SourceIP: "1.2.3.8", Module: "Z1", AttackType: "xss", Timestamp: now})
	engine.Aggregate()

	profile, ok := engine.GetProfile("1.2.3.8")
	if !ok {
		t.Fatal("should have profile")
	}
	if profile.SourceIP != "1.2.3.8" {
		t.Error("IP mismatch")
	}
}