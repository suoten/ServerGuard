package eventbus

import (
	"testing"
	"time"
)

func TestNewTraceContext(t *testing.T) {
	tc := NewTraceContext()
	if tc == nil {
		t.Fatal("NewTraceContext returned nil")
	}
	if tc.TraceID == "" {
		t.Error("TraceID should be non-empty")
	}
	if tc.SpanID == "" {
		t.Error("SpanID should be non-empty")
	}
	if tc.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
	if len(tc.Steps) != 0 {
		t.Error("new context should have no steps")
	}
}

func TestTraceContext_StartEndStep(t *testing.T) {
	tc := NewTraceContext()

	spanID := tc.StartStep("evaluate-rules")
	if spanID == "" {
		t.Fatal("StartStep should return non-empty spanID")
	}

	steps := tc.GetSteps()
	if len(steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(steps))
	}
	if steps[0].Name != "evaluate-rules" {
		t.Errorf("expected step name 'evaluate-rules', got %q", steps[0].Name)
	}
	if steps[0].Status != "running" {
		t.Errorf("expected status 'running', got %q", steps[0].Status)
	}

	time.Sleep(5 * time.Millisecond)
	tc.EndStep(spanID, "success", "matched 2 rules")

	steps = tc.GetSteps()
	if steps[0].Status != "success" {
		t.Errorf("expected status 'success', got %q", steps[0].Status)
	}
	if steps[0].Detail != "matched 2 rules" {
		t.Errorf("unexpected detail: %q", steps[0].Detail)
	}
	if steps[0].EndTime.IsZero() {
		t.Error("EndTime should be set")
	}
	if steps[0].Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestTraceContext_EndStepUnknownSpan(t *testing.T) {
	tc := NewTraceContext()
	tc.StartStep("real-step")
	// Ending a non-existent span should be a no-op, not panic
	tc.EndStep("unknown-span", "success", "")
	steps := tc.GetSteps()
	if len(steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(steps))
	}
	if steps[0].Status != "running" {
		t.Errorf("real step should still be running, got %q", steps[0].Status)
	}
}

func TestTraceContext_MultipleSteps(t *testing.T) {
	tc := NewTraceContext()
	id1 := tc.StartStep("step-1")
	id2 := tc.StartStep("step-2")
	id3 := tc.StartStep("step-3")

	if id1 == id2 || id2 == id3 || id1 == id3 {
		t.Error("span IDs should be unique")
	}

	tc.EndStep(id1, "success", "")
	tc.EndStep(id2, "failed", "err")
	tc.EndStep(id3, "success", "")

	steps := tc.GetSteps()
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(steps))
	}
}

func TestTraceContext_GetStepsReturnsCopy(t *testing.T) {
	tc := NewTraceContext()
	tc.StartStep("s1")
	steps := tc.GetSteps()
	// Mutate the returned slice
	steps[0] = TraceStep{Name: "mutated"}

	steps2 := tc.GetSteps()
	if steps2[0].Name == "mutated" {
		t.Error("GetSteps should return a copy, not the internal slice")
	}
}

func TestTraceContext_TotalDuration(t *testing.T) {
	tc := NewTraceContext()
	time.Sleep(5 * time.Millisecond)
	d := tc.TotalDuration()
	if d <= 0 {
		t.Error("TotalDuration should be positive after waiting")
	}
}

func TestTraceContext_Format(t *testing.T) {
	tc := NewTraceContext()
	id := tc.StartStep("my-step")
	tc.EndStep(id, "success", "done")

	out := tc.Format()
	if out == "" {
		t.Error("Format should return non-empty string")
	}
	if !contains(out, "TraceID:") {
		t.Error("Format output should contain 'TraceID:'")
	}
	if !contains(out, "my-step") {
		t.Error("Format output should contain step name")
	}
	if !contains(out, "Total:") {
		t.Error("Format output should contain 'Total:'")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestTraceManager_StartAndGet(t *testing.T) {
	tm := NewTraceManager()
	tc := tm.Start()
	if tc == nil {
		t.Fatal("Start returned nil")
	}

	got, ok := tm.Get(tc.TraceID)
	if !ok {
		t.Fatal("Get should find the trace just started")
	}
	if got.TraceID != tc.TraceID {
		t.Error("retrieved trace ID mismatch")
	}

	_, ok = tm.Get("nonexistent")
	if ok {
		t.Error("Get should return false for unknown trace ID")
	}
}

func TestTraceManager_QueryByTimeRange(t *testing.T) {
	tm := NewTraceManager()
	tc1 := tm.Start()
	time.Sleep(2 * time.Millisecond)
	mid := time.Now()
	time.Sleep(2 * time.Millisecond)
	tc2 := tm.Start()

	// Query for traces started after mid
	results := tm.QueryByTimeRange(mid, time.Now().Add(time.Hour))
	if len(results) != 1 {
		t.Fatalf("expected 1 trace after mid, got %d", len(results))
	}
	if results[0].TraceID != tc2.TraceID {
		t.Error("wrong trace returned by time range query")
	}

	// Query all
	all := tm.QueryByTimeRange(tc1.StartTime.Add(-time.Hour), time.Now().Add(time.Hour))
	if len(all) != 2 {
		t.Errorf("expected 2 traces in wide range, got %d", len(all))
	}
}

func TestTraceManager_QueryByTimeRangeEmpty(t *testing.T) {
	tm := NewTraceManager()
	results := tm.QueryByTimeRange(time.Now(), time.Now().Add(time.Hour))
	if results != nil && len(results) != 0 {
		t.Errorf("expected empty result, got %d", len(results))
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()
	if id1 == "" || id2 == "" {
		t.Error("generated IDs should be non-empty")
	}
	if id1 == id2 {
		t.Error("generated IDs should differ (extremely high probability)")
	}
}
