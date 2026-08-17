package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// --- aggregate tests ---

func TestDownsampler_AggregateEmpty(t *testing.T) {
	d := NewDownsampler(nil)
	agg := d.aggregate(nil)
	if agg.Count != 0 || agg.Avg != 0 || agg.Min != 0 || agg.Max != 0 || agg.P95 != 0 {
		t.Errorf("empty aggregate should be zero-value, got %+v", agg)
	}
}

func TestDownsampler_AggregateSingle(t *testing.T) {
	d := NewDownsampler(nil)
	samples := []MetricSample{{Value: 42.0, Timestamp: time.Now()}}
	agg := d.aggregate(samples)
	if agg.Count != 1 {
		t.Errorf("expected count 1, got %d", agg.Count)
	}
	if agg.Min != 42.0 || agg.Max != 42.0 || agg.Avg != 42.0 || agg.P95 != 42.0 {
		t.Errorf("single sample aggregate wrong: %+v", agg)
	}
}

func TestDownsampler_AggregateMultiple(t *testing.T) {
	d := NewDownsampler(nil)
	now := time.Now()
	samples := []MetricSample{
		{Value: 10.0, Timestamp: now},
		{Value: 20.0, Timestamp: now.Add(time.Second)},
		{Value: 30.0, Timestamp: now.Add(2 * time.Second)},
		{Value: 40.0, Timestamp: now.Add(3 * time.Second)},
		{Value: 100.0, Timestamp: now.Add(4 * time.Second)},
	}
	agg := d.aggregate(samples)

	if agg.Count != 5 {
		t.Errorf("expected count 5, got %d", agg.Count)
	}
	if agg.Min != 10.0 {
		t.Errorf("expected min 10, got %f", agg.Min)
	}
	if agg.Max != 100.0 {
		t.Errorf("expected max 100, got %f", agg.Max)
	}
	expectedAvg := (10.0 + 20.0 + 30.0 + 40.0 + 100.0) / 5.0
	if agg.Avg != expectedAvg {
		t.Errorf("expected avg %f, got %f", expectedAvg, agg.Avg)
	}
	// P95 index = int(5 * 0.95) = 4, values sorted = [10,20,30,40,100], P95 = values[4] = 100
	if agg.P95 != 100.0 {
		t.Errorf("expected p95 100, got %f", agg.P95)
	}
}

func TestDownsampler_AggregateP95SmallSet(t *testing.T) {
	d := NewDownsampler(nil)
	now := time.Now()
	samples := []MetricSample{
		{Value: 5.0, Timestamp: now},
		{Value: 1.0, Timestamp: now.Add(time.Second)},
	}
	agg := d.aggregate(samples)
	// n=2, p95Idx = int(2*0.95) = 1, values sorted = [1,5], P95 = values[1] = 5
	if agg.P95 != 5.0 {
		t.Errorf("expected p95 5, got %f", agg.P95)
	}
	if agg.Min != 1.0 || agg.Max != 5.0 {
		t.Errorf("min/max wrong: min=%f max=%f", agg.Min, agg.Max)
	}
}

func TestDownsampler_AggregateNegativeValues(t *testing.T) {
	d := NewDownsampler(nil)
	now := time.Now()
	samples := []MetricSample{
		{Value: -10.0, Timestamp: now},
		{Value: -5.0, Timestamp: now.Add(time.Second)},
		{Value: -20.0, Timestamp: now.Add(2 * time.Second)},
	}
	agg := d.aggregate(samples)
	if agg.Min != -20.0 {
		t.Errorf("expected min -20, got %f", agg.Min)
	}
	if agg.Max != -5.0 {
		t.Errorf("expected max -5, got %f", agg.Max)
	}
	expectedAvg := (-10.0 + -5.0 + -20.0) / 3.0
	if agg.Avg != expectedAvg {
		t.Errorf("expected avg %f, got %f", expectedAvg, agg.Avg)
	}
}

// --- sortFloats tests ---

func TestDownsampler_SortFloats(t *testing.T) {
	d := NewDownsampler(nil)
	cases := [][]float64{
		{3, 1, 2},
		{5, 4, 3, 2, 1},
		{1},
		{},
		{-1, -5, 0, 3, -2},
		{1.5, 0.5, 2.5, 1.0},
	}
	expected := [][]float64{
		{1, 2, 3},
		{1, 2, 3, 4, 5},
		{1},
		{},
		{-5, -2, -1, 0, 3},
		{0.5, 1.0, 1.5, 2.5},
	}
	for i, input := range cases {
		d.sortFloats(input)
		for j, v := range input {
			if v != expected[i][j] {
				t.Errorf("case %d index %d: got %v, want %v", i, j, v, expected[i][j])
			}
		}
	}
}

func TestDownsampler_SortFloatsAlreadySorted(t *testing.T) {
	d := NewDownsampler(nil)
	input := []float64{1, 2, 3, 4, 5}
	d.sortFloats(input)
	for i, v := range input {
		if v != float64(i+1) {
			t.Errorf("already sorted should remain sorted: index %d = %v", i, v)
		}
	}
}

func TestDownsampler_SortFloatsReverseSorted(t *testing.T) {
	d := NewDownsampler(nil)
	input := []float64{5, 4, 3, 2, 1}
	d.sortFloats(input)
	if input[0] != 1 || input[4] != 5 {
		t.Errorf("reverse sorted should become ascending: %v", input)
	}
}

// --- NewDownsampler / AddRawMetric ---

func TestNewDownsampler(t *testing.T) {
	d := NewDownsampler(nil)
	if d == nil {
		t.Fatal("NewDownsampler returned nil")
	}
	if d.rawBuffer == nil {
		t.Error("rawBuffer should be initialized")
	}
	if d.bufferMaxAge != time.Hour {
		t.Errorf("expected bufferMaxAge 1h, got %v", d.bufferMaxAge)
	}
}

func TestDownsampler_AddRawMetric(t *testing.T) {
	d := NewDownsampler(nil)
	now := time.Now()

	d.AddRawMetric("cpu", 50.0, now)
	d.AddRawMetric("cpu", 60.0, now.Add(time.Second))
	d.AddRawMetric("mem", 70.0, now)

	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.rawBuffer["cpu"]) != 2 {
		t.Errorf("expected 2 cpu samples, got %d", len(d.rawBuffer["cpu"]))
	}
	if len(d.rawBuffer["mem"]) != 1 {
		t.Errorf("expected 1 mem sample, got %d", len(d.rawBuffer["mem"]))
	}
	if d.rawBuffer["cpu"][0].Value != 50.0 {
		t.Errorf("first cpu sample value wrong: %f", d.rawBuffer["cpu"][0].Value)
	}
}

// --- RunHourlyDownsample / RunDailyDownsample / RunCleanup with real storage ---

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := New(path)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDownsampler_RunHourlyDownsample(t *testing.T) {
	s := newTestStorage(t)
	d := NewDownsampler(s)

	// Insert a raw metric older than 1 hour
	old := time.Now().Add(-2 * time.Hour)
	if err := s.SaveMetric(makeMetric("cpu", "cpu_percent", 50.0, old)); err != nil {
		t.Fatalf("SaveMetric: %v", err)
	}

	if err := d.RunHourlyDownsample(); err != nil {
		t.Errorf("RunHourlyDownsample error: %v", err)
	}

	// The raw metric older than 1h should be deleted from metrics table
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM metrics WHERE granularity='raw'").Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 raw metrics after downsample, got %d", count)
	}
}

func TestDownsampler_RunHourlyDownsampleWithBuffer(t *testing.T) {
	s := newTestStorage(t)
	d := NewDownsampler(s)

	// Add old samples to the buffer (older than 1 hour)
	old := time.Now().Add(-2 * time.Hour)
	d.AddRawMetric("buffered-cpu", 42.0, old)
	d.AddRawMetric("buffered-cpu", 58.0, old.Add(30*time.Second))

	if err := d.RunHourlyDownsample(); err != nil {
		t.Errorf("RunHourlyDownsample error: %v", err)
	}

	// Old buffered samples should be flushed (removed from buffer)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.rawBuffer["buffered-cpu"]) != 0 {
		t.Errorf("expected old buffered samples flushed, got %d", len(d.rawBuffer["buffered-cpu"]))
	}
}

func TestDownsampler_RunDailyDownsample(t *testing.T) {
	s := newTestStorage(t)
	d := NewDownsampler(s)

	// Insert a 1m metric older than 7 days
	old := time.Now().Add(-8 * 24 * time.Hour)
	_, err := s.DB().Exec(
		"INSERT INTO metrics_1m (type, name, avg, min, max, p95, count, unit, labels, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"cpu", "cpu_percent", 50.0, 40.0, 60.0, 55.0, 60, "%", "", old.UTC().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert metrics_1m: %v", err)
	}

	if err := d.RunDailyDownsample(); err != nil {
		t.Errorf("RunDailyDownsample error: %v", err)
	}

	// The 1m metric older than 7d should be deleted
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM metrics_1m").Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 metrics_1m after daily downsample, got %d", count)
	}
}

func TestDownsampler_RunCleanup(t *testing.T) {
	s := newTestStorage(t)
	d := NewDownsampler(s)

	// Insert old data into various tables
	old := time.Now().Add(-200 * 24 * time.Hour)
	oldStr := old.UTC().Format(time.RFC3339)

	_, _ = s.DB().Exec("INSERT INTO metrics_1h (type, name, avg, min, max, p95, count, unit, labels, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"cpu", "cpu_percent", 50.0, 40.0, 60.0, 55.0, 60, "%", "", oldStr)
	_, _ = s.DB().Exec("INSERT INTO alerts (id, level, title, source, timestamp) VALUES (?, ?, ?, ?, ?)",
		"alert-1", "warning", "old alert", "test", oldStr)
	_, _ = s.DB().Exec("INSERT INTO actions (rule_id, action_type, success, timestamp) VALUES (?, ?, ?, ?)",
		"r1", "kill", 1, oldStr)

	if err := d.RunCleanup(); err != nil {
		t.Errorf("RunCleanup error: %v", err)
	}

	// Old 1h metrics should be deleted (>90 days)
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM metrics_1h").Scan(&count); err != nil {
		t.Fatalf("query metrics_1h: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 metrics_1h after cleanup, got %d", count)
	}

	// Old alerts should be deleted (>180 days)
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count); err != nil {
		t.Fatalf("query alerts: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 alerts after cleanup, got %d", count)
	}
}

func TestDownsampler_RunCleanupEmptyDB(t *testing.T) {
	s := newTestStorage(t)
	d := NewDownsampler(s)

	if err := d.RunCleanup(); err != nil {
		t.Errorf("RunCleanup on empty DB should succeed, got: %v", err)
	}
}

func TestDownsampler_AggregatedMetricStruct(t *testing.T) {
	agg := AggregatedMetric{Min: 1, Max: 10, Avg: 5, P95: 9, P99: 9.5, Count: 100}
	if agg.Min != 1 || agg.Max != 10 || agg.Avg != 5 || agg.P95 != 9 || agg.P99 != 9.5 || agg.Count != 100 {
		t.Error("AggregatedMetric fields not set correctly")
	}
}

func makeMetric(typ, name string, value float64, ts time.Time) types.Metric {
	return types.Metric{
		Type:      types.MetricType(typ),
		Name:      name,
		Value:     value,
		Timestamp: ts,
	}
}
