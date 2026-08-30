package posture

import (
	"sync"
	"time"
)

// DeferredTracker 推迟任务账本——回答"繁忙期错过的活，什么时候补做？".
//
// 调度器在 Busy/Combat 态势下推迟任务时调用 MarkDeferred；
// 任务真正执行后调用 MarkRan。态势回到空闲时，按"最久未跑优先"补做，
// 避免某类任务被连续推迟多轮而饿死。
type DeferredTracker struct {
	mu         sync.Mutex
	lastRan    map[string]time.Time // 任务键 -> 上次执行时间
	deferCount map[string]int       // 任务键 -> 累计被推迟次数
}

// NewDeferredTracker 创建账本。
func NewDeferredTracker() *DeferredTracker {
	return &DeferredTracker{
		lastRan:    make(map[string]time.Time),
		deferCount: make(map[string]int),
	}
}

// MarkRan 记录任务已执行。
func (t *DeferredTracker) MarkRan(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastRan[key] = now
	delete(t.deferCount, key)
}

// MarkDeferred 记录任务本轮被推迟。
func (t *DeferredTracker) MarkDeferred(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deferCount[key]++
}

// SinceLastRun 距上次执行时长；从未执行过返回 true（视为最需要补做）。
func (t *DeferredTracker) SinceLastRun(key string, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.lastRan[key]
	if !ok {
		return 0, true
	}
	return now.Sub(last), false
}

// DueForCatchUp 判断任务是否到期应补做：曾被推迟过，且距上次执行超过 minAge。
// 从未执行过的任务视为立即到期（首次运行不该被饿死）。
func (t *DeferredTracker) DueForCatchUp(key string, now time.Time, minAge time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.deferCount[key] == 0 {
		return false // 没被推迟过，按正常排期走即可
	}
	last, ok := t.lastRan[key]
	if !ok {
		return true
	}
	return now.Sub(last) >= minAge
}

// MostOverdue 在给定候选中返回最久未跑且到期待补做的任务键；无则 ok=false。
// 从未运行过的任务视为"最旧"（零值时间），优先补做。
func (t *DeferredTracker) MostOverdue(keys []string, now time.Time, minAge time.Duration) (string, bool) {
	best := ""
	var bestAt time.Time
	found := false
	for _, k := range keys {
		if !t.DueForCatchUp(k, now, minAge) {
			continue
		}
		last, never := t.SinceLastRun(k, now)
		at := time.Time{} // 从未运行：视为最旧
		if !never {
			at = now.Add(-last)
		}
		if !found || at.Before(bestAt) {
			best, bestAt, found = k, at, true
		}
	}
	return best, found
}
