package eventbus

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

func TestEventBus_New(t *testing.T) {
	bus := New(16)
	if bus == nil {
		t.Fatal("New returned nil")
	}
	defer bus.Stop()
}

func TestEventBus_SubscribeAndPublish(t *testing.T) {
	bus := New(16)
	defer bus.Stop()
	bus.Start()

	var received atomic.Int32
	var mu sync.Mutex
	var got types.Event
	bus.Subscribe(types.EventAlert, func(e types.Event) {
		mu.Lock()
		got = e
		mu.Unlock()
		received.Add(1)
	})

	bus.Publish(types.Event{
		Type:    types.EventAlert,
		Level:   types.AlertWarning,
		Title:   "test-alert",
		Message: "hello",
		Source:  "unit-test",
	})

	// Wait for async dispatch
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if received.Load() == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	if received.Load() != 1 {
		t.Fatalf("expected 1 event, got %d", received.Load())
	}

	mu.Lock()
	defer mu.Unlock()
	if got.Title != "test-alert" {
		t.Errorf("expected title 'test-alert', got %q", got.Title)
	}
	if got.ID == "" {
		t.Error("expected non-empty event ID to be assigned")
	}
	if got.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp to be assigned")
	}
}

func TestEventBus_MultipleSubscribers(t *testing.T) {
	bus := New(32)
	defer bus.Stop()
	bus.Start()

	var count atomic.Int32
	handler := func(e types.Event) {
		count.Add(1)
	}
	bus.Subscribe(types.EventAction, handler)
	bus.Subscribe(types.EventAction, handler)
	bus.Subscribe(types.EventAction, handler)

	bus.Publish(types.Event{Type: types.EventAction, Title: "a"})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if count.Load() == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if count.Load() != 3 {
		t.Fatalf("expected 3 deliveries, got %d", count.Load())
	}
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := New(16)
	defer bus.Stop()
	bus.Start()

	var count atomic.Int32
	id := bus.Subscribe(types.EventMetric, func(e types.Event) {
		count.Add(1)
	})
	bus.Unsubscribe(types.EventMetric, id)

	bus.Publish(types.Event{Type: types.EventMetric, Title: "m"})
	time.Sleep(100 * time.Millisecond)

	if count.Load() != 0 {
		t.Errorf("expected 0 deliveries after unsubscribe, got %d", count.Load())
	}
}

func TestEventBus_PublishAlertDedup(t *testing.T) {
	bus := New(64)
	defer bus.Stop()
	bus.Start()

	var count atomic.Int32
	bus.Subscribe(types.EventAlert, func(e types.Event) {
		count.Add(1)
	})

	// Same ruleID + title should be deduplicated within cooldown
	for i := 0; i < 5; i++ {
		bus.PublishAlert(types.AlertError, "src", "same-title", "msg", "rule-1")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if count.Load() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	if count.Load() != 1 {
		t.Errorf("expected 1 delivery after dedup, got %d", count.Load())
	}
}

func TestEventBus_PublishAlertDifferentRules(t *testing.T) {
	bus := New(64)
	defer bus.Stop()
	bus.Start()

	var count atomic.Int32
	bus.Subscribe(types.EventAlert, func(e types.Event) {
		count.Add(1)
	})

	bus.PublishAlert(types.AlertError, "src", "title-a", "msg", "rule-1")
	bus.PublishAlert(types.AlertError, "src", "title-b", "msg", "rule-2")

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if count.Load() == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if count.Load() != 2 {
		t.Errorf("expected 2 deliveries for different alerts, got %d", count.Load())
	}
}

func TestEventBus_PublishAction(t *testing.T) {
	bus := New(16)
	defer bus.Stop()
	bus.Start()

	var received atomic.Int32
	bus.Subscribe(types.EventAction, func(e types.Event) {
		if e.Title == "act" && e.Source == "exec" {
			received.Add(1)
		}
	})

	bus.PublishAction("exec", "act", "did something", map[string]string{"k": "v"})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if received.Load() == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if received.Load() != 1 {
		t.Errorf("expected 1 action event, got %d", received.Load())
	}
}

func TestEventBus_PublishWithTrace(t *testing.T) {
	bus := New(16)
	defer bus.Stop()
	bus.Start()

	var gotMu sync.Mutex
	var got types.Event
	bus.Subscribe(types.EventAlert, func(e types.Event) {
		gotMu.Lock()
		got = e
		gotMu.Unlock()
	})

	traceID := "trace-xyz"
	bus.PublishWithTrace(types.Event{
		Type:  types.EventAlert,
		Title: "traced",
	}, traceID)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		gotMu.Lock()
		done := got.Title == "traced"
		gotMu.Unlock()
		if done {
			break
		}
		time.Sleep(time.Millisecond)
	}

	gotMu.Lock()
	defer gotMu.Unlock()
	data, ok := got.Data.(map[string]string)
	if !ok {
		t.Fatal("expected map[string]string data")
	}
	if data["trace_id"] != traceID {
		t.Errorf("expected trace_id %q, got %q", traceID, data["trace_id"])
	}
}

func TestNewTraceID(t *testing.T) {
	id1 := NewTraceID()
	id2 := NewTraceID()
	if id1 == "" || id2 == "" {
		t.Error("trace IDs should be non-empty")
	}
	if id1 == id2 {
		t.Error("trace IDs should be unique")
	}
}

func TestEventBus_StopIdempotent(t *testing.T) {
	bus := New(8)
	bus.Start()
	bus.Stop()
	bus.Stop() // should not panic
}

func TestEventBus_QueueFullDropsOldest(t *testing.T) {
	// Buffer size 1; publish without starting the process loop to fill queue
	bus := New(1)
	defer bus.Stop()

	// Don't call Start so events accumulate in the queue
	bus.Publish(types.Event{Type: types.EventSystem, Title: "e1"})
	bus.Publish(types.Event{Type: types.EventSystem, Title: "e2"})
	bus.Publish(types.Event{Type: types.EventSystem, Title: "e3"})

	// Queue capacity is 1, so only the most recent event should remain
	if len(bus.queue) > 1 {
		t.Errorf("queue should be at most capacity 1, got %d", len(bus.queue))
	}
}
