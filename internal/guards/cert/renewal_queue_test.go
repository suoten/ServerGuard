package cert

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
)

func TestRenewalFailureQueue_Enqueue(t *testing.T) {
	bus := eventbus.New(100)
	q := NewRenewalFailureQueue(bus)

	q.Enqueue("example.com", "letsencrypt", []string{"letsencrypt", "zerossl"})

	if q.Size() != 1 {
		t.Errorf("queue size = %d, want 1", q.Size())
	}
}

func TestRenewalFailureQueue_ExponentialBackoff(t *testing.T) {
	bus := eventbus.New(100)
	q := NewRenewalFailureQueue(bus)

	q.Enqueue("example.com", "letsencrypt", []string{"letsencrypt"})
	entry, ok := q.GetEntry("example.com")
	if !ok {
		t.Fatal("entry should exist")
	}
	if entry.RetryCount != 1 {
		t.Errorf("retry count = %d, want 1", entry.RetryCount)
	}
	// 第一次重试应在 48h 后 (24h * 2^1)
	expectedDelay := 48 * time.Hour
	actualDelay := entry.RetryAfter.Sub(entry.LastFailure)
	if actualDelay < expectedDelay-time.Minute || actualDelay > expectedDelay+time.Minute {
		t.Errorf("delay = %v, want ~%v", actualDelay, expectedDelay)
	}
}

func TestRenewalFailureQueue_Remove(t *testing.T) {
	bus := eventbus.New(100)
	q := NewRenewalFailureQueue(bus)

	q.Enqueue("example.com", "letsencrypt", []string{"letsencrypt"})
	q.Remove("example.com")

	if q.Size() != 0 {
		t.Error("queue should be empty after remove")
	}
}

func TestRenewalFailureQueue_ProcessRetry(t *testing.T) {
	bus := eventbus.New(100)
	q := NewRenewalFailureQueue(bus)

	q.Enqueue("example.com", "letsencrypt", []string{"letsencrypt"})

	// 立即处理重试，不应有到期项（因为退避时间很长）
	toRetry := q.ProcessRetry(nil)
	if len(toRetry) != 0 {
		t.Error("should have no items to retry immediately")
	}
}

func TestRenewalFailureQueue_MaxRetryExceeded(t *testing.T) {
	bus := eventbus.New(100)
	q := NewRenewalFailureQueue(bus)

	// 连续入队 5 次，应触发最终失败告警并出队
	for i := 0; i < 5; i++ {
		q.Enqueue("example.com", "letsencrypt", []string{"letsencrypt"})
	}

	if q.Size() != 0 {
		t.Errorf("queue should be empty after max retries, got size %d", q.Size())
	}
}

func TestRenewalFailureQueue_GetQueue(t *testing.T) {
	bus := eventbus.New(100)
	q := NewRenewalFailureQueue(bus)

	q.Enqueue("a.com", "letsencrypt", []string{"letsencrypt"})
	q.Enqueue("b.com", "zerossl", []string{"zerossl"})

	queue := q.GetQueue()
	if len(queue) != 2 {
		t.Errorf("queue length = %d, want 2", len(queue))
	}
}

func TestPostRenewalHandler_Create(t *testing.T) {
	bus := eventbus.New(100)
	h := NewPostRenewalHandler(bus)
	if h == nil {
		t.Fatal("should create PostRenewalHandler")
	}
}
