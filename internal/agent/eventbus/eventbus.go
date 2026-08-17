package eventbus

import (
	"context"
	"fmt"
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
type EventBus struct {
	mu       sync.RWMutex
	handlers map[types.EventType][]subscription
	queue    chan types.Event
	ctx      context.Context
	cancel   context.CancelFunc

	// Alert deduplication: maps alert key (ruleID:title) to last publish time
	alertCooldown time.Duration
	lastAlerts    map[string]time.Time

	// next subscription ID counter
	nextSubID int64
}

// New creates a new EventBus.
func New(bufferSize int) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventBus{
		handlers:      make(map[types.EventType][]subscription),
		queue:         make(chan types.Event, bufferSize),
		ctx:           ctx,
		cancel:        cancel,
		alertCooldown: 5 * time.Minute,
		lastAlerts:    make(map[string]time.Time),
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
func (b *EventBus) Publish(event types.Event) {
	// Deduplicate alerts: skip if same alert was published recently
	if event.Type == types.EventAlert {
		ruleID := ""
		if data, ok := event.Data.(map[string]string); ok {
			ruleID = data["rule_id"]
		}
		alertKey := fmt.Sprintf("%s:%s", ruleID, event.Title)

		b.mu.Lock()
		if lastTime, exists := b.lastAlerts[alertKey]; exists {
			if time.Since(lastTime) < b.alertCooldown {
				b.mu.Unlock()
				return // Skip duplicate alert within cooldown
			}
		}
		// Clean old entries periodically
		if len(b.lastAlerts) > 200 {
			for k, t := range b.lastAlerts {
				if time.Since(t) > b.alertCooldown {
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
func (b *EventBus) dispatch(event types.Event) {
	b.mu.RLock()
	subs := b.handlers[event.Type]
	b.mu.RUnlock()

	for _, s := range subs {
		go s.handler(event)
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
