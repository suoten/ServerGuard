package eventbus

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

type TraceContext struct {
	TraceID    string        `json:"trace_id"`
	ParentID   string        `json:"parent_id"`
	SpanID     string        `json:"span_id"`
	StartTime  time.Time     `json:"start_time"`
	Steps      []TraceStep   `json:"steps"`
	mu         sync.Mutex
}

type TraceStep struct {
	Name      string        `json:"name"`
	SpanID    string        `json:"span_id"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"`
	Detail    string        `json:"detail"`
}

func NewTraceContext() *TraceContext {
	return &TraceContext{
		TraceID:   generateID(),
		SpanID:    generateID(),
		StartTime: time.Now(),
	}
}

func (tc *TraceContext) StartStep(name string) string {
	spanID := generateID()
	step := TraceStep{
		Name:      name,
		SpanID:    spanID,
		StartTime: time.Now(),
		Status:    "running",
	}
	tc.mu.Lock()
	tc.Steps = append(tc.Steps, step)
	tc.mu.Unlock()
	return spanID
}

func (tc *TraceContext) EndStep(spanID string, status, detail string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for i := range tc.Steps {
		if tc.Steps[i].SpanID == spanID {
			tc.Steps[i].EndTime = time.Now()
			tc.Steps[i].Duration = tc.Steps[i].EndTime.Sub(tc.Steps[i].StartTime)
			tc.Steps[i].Status = status
			tc.Steps[i].Detail = detail
			return
		}
	}
}

func (tc *TraceContext) TotalDuration() time.Duration {
	return time.Since(tc.StartTime)
}

func (tc *TraceContext) GetSteps() []TraceStep {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	result := make([]TraceStep, len(tc.Steps))
	copy(result, tc.Steps)
	return result
}

func (tc *TraceContext) Format() string {
	s := fmt.Sprintf("TraceID: %s\n", tc.TraceID)
	for _, step := range tc.Steps {
		s += fmt.Sprintf("  └─ %s [%s] %s (%v)\n", step.Name, step.Status, step.Detail, step.Duration)
	}
	s += fmt.Sprintf("Total: %v\n", tc.TotalDuration())
	return s
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

type TraceManager struct {
	mu     sync.RWMutex
	traces map[string]*TraceContext
	maxKeep int
}

func NewTraceManager() *TraceManager {
	return &TraceManager{
		traces:  make(map[string]*TraceContext),
		maxKeep: 10000,
	}
}

func (tm *TraceManager) Start() *TraceContext {
	tc := NewTraceContext()
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.traces[tc.TraceID] = tc
	if len(tm.traces) > tm.maxKeep {
		tm.cleanupOld()
	}
	return tc
}

func (tm *TraceManager) Get(traceID string) (*TraceContext, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tc, ok := tm.traces[traceID]
	return tc, ok
}

func (tm *TraceManager) QueryByTimeRange(start, end time.Time) []*TraceContext {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var result []*TraceContext
	for _, tc := range tm.traces {
		if tc.StartTime.After(start) && tc.StartTime.Before(end) {
			result = append(result, tc)
		}
	}
	return result
}

func (tm *TraceManager) cleanupOld() {
	cutoff := time.Now().Add(-24 * time.Hour)
	for id, tc := range tm.traces {
		if tc.StartTime.Before(cutoff) {
			delete(tm.traces, id)
		}
	}
}