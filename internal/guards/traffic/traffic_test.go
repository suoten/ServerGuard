package traffic

import (
	"context"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
)

func TestTraffic_New(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)
	if g == nil {
		t.Fatal("New returned nil")
	}
	if g.historyMax != 60 {
		t.Errorf("expected historyMax 60, got %d", g.historyMax)
	}
}

func TestTraffic_SetBaseline(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	g.SetBaseline(1000.0, 2000.0)

	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.baselineSent != 1000.0 {
		t.Errorf("expected baselineSent 1000, got %f", g.baselineSent)
	}
	if g.baselineRecv != 2000.0 {
		t.Errorf("expected baselineRecv 2000, got %f", g.baselineRecv)
	}
}

func TestTraffic_SetBaselineZero(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	g.SetBaseline(0, 0)
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.baselineSent != 0 || g.baselineRecv != 0 {
		t.Error("zero baseline should be stored")
	}
}

func TestTraffic_recordSample(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	g.recordSample(100.0, 200.0)
	g.recordSample(150.0, 250.0)

	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.sentHistory) != 2 {
		t.Fatalf("expected 2 sent samples, got %d", len(g.sentHistory))
	}
	if g.sentHistory[0] != 100.0 || g.sentHistory[1] != 150.0 {
		t.Errorf("sentHistory = %v", g.sentHistory)
	}
	if g.recvHistory[0] != 200.0 || g.recvHistory[1] != 250.0 {
		t.Errorf("recvHistory = %v", g.recvHistory)
	}
}

func TestTraffic_recordSampleTrimsToMax(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	// Record more than historyMax samples
	for i := 0; i < 100; i++ {
		g.recordSample(float64(i), float64(i*2))
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.sentHistory) != g.historyMax {
		t.Errorf("expected sentHistory trimmed to %d, got %d", g.historyMax, len(g.sentHistory))
	}
	if len(g.recvHistory) != g.historyMax {
		t.Errorf("expected recvHistory trimmed to %d, got %d", g.historyMax, len(g.recvHistory))
	}
	// Should keep the most recent samples
	if g.sentHistory[0] != float64(100-g.historyMax) {
		t.Errorf("expected first element %f, got %f", float64(100-g.historyMax), g.sentHistory[0])
	}
}

func TestTraffic_UpdateBaselineEmptyHistory(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	// No samples recorded; UpdateBaseline should be a no-op
	g.UpdateBaseline()
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.baselineSent != 0 || g.baselineRecv != 0 {
		t.Error("UpdateBaseline with empty history should not change baseline")
	}
}

func TestTraffic_UpdateBaselineSingleSample(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	g.recordSample(500.0, 800.0)
	g.UpdateBaseline()

	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.baselineSent != 500.0 {
		t.Errorf("single sample baseline should equal sample, got %f", g.baselineSent)
	}
	if g.baselineRecv != 800.0 {
		t.Errorf("single sample baseline should equal sample, got %f", g.baselineRecv)
	}
}

func TestTraffic_UpdateBaselineMultipleSamples(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	// Record samples with increasing trend
	samples := []float64{100, 200, 300, 400, 500}
	for _, s := range samples {
		g.recordSample(s, s*2)
	}
	g.UpdateBaseline()

	g.mu.RLock()
	defer g.mu.RUnlock()
	// EMA should be between min and max
	if g.baselineSent < 100 || g.baselineSent > 500 {
		t.Errorf("baselineSent %f should be within [100, 500]", g.baselineSent)
	}
	if g.baselineRecv < 200 || g.baselineRecv > 1000 {
		t.Errorf("baselineRecv %f should be within [200, 1000]", g.baselineRecv)
	}
	// EMA with alpha=0.3 weights recent samples more; should be > simple average of first values
	if g.baselineSent <= 100 {
		t.Error("EMA should be above the first sample with increasing trend")
	}
}

func TestTraffic_UpdateBaselineDecreasingSamples(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	g := New(bus)

	samples := []float64{500, 400, 300, 200, 100}
	for _, s := range samples {
		g.recordSample(s, s*2)
	}
	g.UpdateBaseline()

	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.baselineSent < 100 || g.baselineSent > 500 {
		t.Errorf("baselineSent %f should be within [100, 500]", g.baselineSent)
	}
}

func TestTraffic_CheckDoesNotPanic(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	bus.Start()
	g := New(bus)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Check spawns goroutines that read gopsutil; should not panic
	g.Check(ctx)
	// Give goroutines time to finish
	time.Sleep(200 * time.Millisecond)
}

func TestTraffic_SetBaselineThenCheck(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	bus.Start()
	g := New(bus)

	g.SetBaseline(1e6, 1e6)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	g.Check(ctx)
	time.Sleep(100 * time.Millisecond)

	// Baseline should still be set (Check reads gopsutil which may fail, but baseline persists)
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.baselineSent != 1e6 {
		t.Error("baseline should persist after Check")
	}
}
