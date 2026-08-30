package eventbus

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/types"
)

// Handler is a function that handles events.
type Handler func(event types.Event)

// SubscriptionID 订阅标识
type SubscriptionID string

// subscription 订阅记录
type subscription struct {
	id      SubscriptionID
	handler Handler
}

// EventBus is an in-memory event bus for the agent.
// 向宝塔学习：告警冷却时间分级——Critical 立即告警，Warning 合并去重，减少噪音和 DB 写入
type EventBus struct {
	mu       sync.RWMutex
	handlers map[types.EventType][]subscription
	queue    chan types.Event
	ctx      context.Context
	cancel   context.CancelFunc

	// Alert deduplication: maps alert key (ruleID:title) to last publish time
	// 向宝塔学习：按告警级别分级冷却——Critical 快速通过，Warning 合并
	alertCooldownCritical time.Duration // Critical: 1 分钟
	alertCooldownWarning  time.Duration // Warning: 10 分钟
	alertCooldownInfo     time.Duration // Info/其他: 30 分钟
	lastAlerts            map[string]time.Time

	// next subscription ID counter
	nextSubID int64
}

// New creates a new EventBus.
func New(bufferSize int) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventBus{
		handlers:              make(map[types.EventType][]subscription),
		queue:                 make(chan types.Event, bufferSize),
		ctx:                   ctx,
		cancel:                cancel,
		alertCooldownCritical: 1 * time.Minute,  // Critical: 1 分钟冷却
		alertCooldownWarning:  10 * time.Minute, // Warning: 10 分钟冷却
		alertCooldownInfo:     30 * time.Minute,  // Info: 30 分钟冷却
		lastAlerts:            make(map[string]time.Time),
	}
}

// Start begins processing events from the queue.
func (b *EventBus) Start() {
	go b.processLoop()
}

// Stop shuts down the event bus.
func (b *EventBus) Stop() {
	b.cancel()
}

// Subscribe registers a handler for a specific event type and returns a SubscriptionID.
func (b *EventBus) Subscribe(eventType types.EventType, handler Handler) SubscriptionID {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSubID++
	id := SubscriptionID(fmt.Sprintf("sub-%d", b.nextSubID))
	b.handlers[eventType] = append(b.handlers[eventType], subscription{id: id, handler: handler})
	return id
}

// Unsubscribe removes a handler by SubscriptionID.
func (b *EventBus) Unsubscribe(eventType types.EventType, id SubscriptionID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.handlers[eventType]
	for i, s := range subs {
		if s.id == id {
			b.handlers[eventType] = append(subs[:i], subs[i+1:]...)
			return
		}
	}
}

// Publish sends an event to all subscribers. Non-blocking.
// For alert events, deduplicates based on ruleID + title within a cooldown period.
// 向宝塔学习：按级别分级冷却，减少重复告警对 DB 和 notifier 的压力
func (b *EventBus) Publish(event types.Event) {
	// Deduplicate alerts: skip if same alert was published recently
	if event.Type == types.EventAlert {
		ruleID := ""
		if data, ok := event.Data.(map[string]string); ok {
			ruleID = data["rule_id"]
		}
		alertKey := fmt.Sprintf("%s:%s", ruleID, event.Title)

		// 按告警级别选择冷却时间
		var cooldown time.Duration
		switch event.Level {
		case types.AlertCritical, types.AlertFatal:
			cooldown = b.alertCooldownCritical
		case types.AlertWarning:
			cooldown = b.alertCooldownWarning
		default:
			cooldown = b.alertCooldownInfo
		}

		b.mu.Lock()
		if lastTime, exists := b.lastAlerts[alertKey]; exists {
			if time.Since(lastTime) < cooldown {
				b.mu.Unlock()
				return // Skip duplicate alert within cooldown
			}
		}
		// Clean old entries periodically
		if len(b.lastAlerts) > 200 {
			for k, t := range b.lastAlerts {
				if time.Since(t) > b.alertCooldownInfo {
					delete(b.lastAlerts, k)
			}
			}
		}
		b.lastAlerts[alertKey] = time.Now()
		b.mu.Unlock()
	}

	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case b.queue <- event:
	default:
		// Queue full, drop oldest
		select {
		case <-b.queue:
			b.queue <- event
		default:
		}
	}
}

// processLoop processes events from the queue.
func (b *EventBus) processLoop() {
	for {
		select {
		case <-b.ctx.Done():
			return
		case event := <-b.queue:
			b.dispatch(event)
		}
	}
}

// dispatch sends an event to all registered handlers.
// 向宝塔学习：同步执行 handler，不为每个订阅者开 goroutine
// handler 通常只是 DB 写入或告警发布，执行很快
// goroutine 创建/调度开销在低配服务器上远大于同步执行
func (b *EventBus) dispatch(event types.Event) {
	b.mu.RLock()
	subs := b.handlers[event.Type]
	b.mu.RUnlock()

	for _, s := range subs {
		func(sub subscription) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "[EventBus] handler %s panicked: %v\n", sub.id, r)
				}
			}()
			sub.handler(event)
		}(s)
	}
}

// PublishWithTrace 发布带 trace_id 的事件，贯穿"规则触发→决策→执行→告警"全链路
func (b *EventBus) PublishWithTrace(event types.Event, traceID string) {
	if event.Data == nil {
		event.Data = map[string]string{}
	}
	if data, ok := event.Data.(map[string]string); ok {
		data["trace_id"] = traceID
		event.Data = data
	}
	b.Publish(event)
}

// NewTraceID 生成新的 trace_id
func NewTraceID() string {
	return uuid.NewString()
}

// PublishAlert is a convenience method to publish an alert event.
func (b *EventBus) PublishAlert(level types.AlertLevel, source, title, message string, ruleID string) {
	b.Publish(types.Event{
		Type:    types.EventAlert,
		Level:   level,
		Source:  source,
		Title:   title,
		Message: message,
		Data: map[string]string{
			"rule_id": ruleID,
		},
	})
}

// PublishAction is a convenience method to publish an action event.
func (b *EventBus) PublishAction(source, title, message string, data interface{}) {
	b.Publish(types.Event{
		Type:    types.EventAction,
		Source:  source,
		Title:   title,
		Message: message,
		Data:    data,
	})
}
