package cert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// RenewalFailureQueueEntry 失败队列条目
type RenewalFailureQueueEntry struct {
	Domain       string
	RetryAfter   time.Time
	RetryCount   int
	LastTriedCA  string
	FailureChain []string // 尝试过的 CA 列表
	FirstFailure time.Time
	LastFailure  time.Time
}

// RenewalFailureQueue 证书续期失败队列。
// 重试间隔 24h * 2^retryCount 指数退避，最多 5 次。
// 超过 5 次仍失败→出队并触发全渠道告警 + 手动续期教程。
type RenewalFailureQueue struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus
	queue    map[string]*RenewalFailureQueueEntry // domain -> entry
	maxRetry int
}

// NewRenewalFailureQueue 创建失败队列。
func NewRenewalFailureQueue(bus *eventbus.EventBus) *RenewalFailureQueue {
	return &RenewalFailureQueue{
		eventBus: bus,
		queue:    make(map[string]*RenewalFailureQueueEntry),
		maxRetry: 5,
	}
}

// Enqueue 将续期失败的域名入队。
func (q *RenewalFailureQueue) Enqueue(domain string, triedCA string, failureChain []string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	entry, ok := q.queue[domain]
	if !ok {
		entry = &RenewalFailureQueueEntry{
			Domain:       domain,
			FirstFailure: now,
		}
		q.queue[domain] = entry
	}

	entry.RetryCount++
	entry.LastTriedCA = triedCA
	entry.FailureChain = failureChain
	entry.LastFailure = now
	// 指数退避：24h * 2^retryCount
	entry.RetryAfter = now.Add(24 * time.Hour * time.Duration(1<<entry.RetryCount))

	// 超过最大重试次数，触发告警并出队
	if entry.RetryCount >= q.maxRetry {
		q.publishFinalFailureAlert(entry)
		delete(q.queue, domain)
	}
}

// ProcessRetry 处理到期重试项。
// 返回需要重试的域名列表。
func (q *RenewalFailureQueue) ProcessRetry(ctx context.Context) []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	var toRetry []string
	for domain, entry := range q.queue {
		if now.After(entry.RetryAfter) {
			toRetry = append(toRetry, domain)
		}
	}
	return toRetry
}

// Remove 从队列中移除指定域名（续期成功后调用）。
func (q *RenewalFailureQueue) Remove(domain string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.queue, domain)
}

// GetQueue 返回失败队列快照。
func (q *RenewalFailureQueue) GetQueue() []RenewalFailureQueueEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]RenewalFailureQueueEntry, 0, len(q.queue))
	for _, entry := range q.queue {
		result = append(result, *entry)
	}
	return result
}

// GetEntry 返回指定域名的队列条目。
func (q *RenewalFailureQueue) GetEntry(domain string) (*RenewalFailureQueueEntry, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry, ok := q.queue[domain]
	if !ok {
		return nil, false
	}
	return entry, true
}

// Size 返回队列大小。
func (q *RenewalFailureQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queue)
}

// publishFinalFailureAlert 发布最终失败告警。
func (q *RenewalFailureQueue) publishFinalFailureAlert(entry *RenewalFailureQueueEntry) {
	if q.eventBus == nil {
		return
	}
	q.eventBus.PublishAlert(types.AlertCritical, "cert",
		fmt.Sprintf("证书续期最终失败: %s", entry.Domain),
		fmt.Sprintf("域名 %s 续期失败 %d 次，已超过最大重试次数。\n"+
			"最后尝试的 CA: %s\n"+
			"失败链: %v\n"+
			"请手动续期：sgctl cert renew %s\n"+
			"或检查 DNS 配置和 CA 账户状态",
			entry.Domain, entry.RetryCount, entry.LastTriedCA,
			entry.FailureChain, entry.Domain),
		"cert-renew-final-001")
}
