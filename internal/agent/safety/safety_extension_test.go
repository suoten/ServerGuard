package safety

import (
	"testing"
	"time"
)

// --- 2.1 资源地板 IO/磁盘维度 ---

func TestResourceFloor_CheckKillAllowed_AllPass(t *testing.T) {
	rf := DefaultResourceFloor()
	result := rf.CheckKillAllowed(200, 30, 1000)
	if !result.Allowed {
		t.Errorf("expected allowed, got rejected: %s", result.Reason)
	}
}

// --- 宝塔面板释压重启控制器 ---

func TestPanelRelief_AllowsFirstRelief(t *testing.T) {
	c := NewPanelReliefController()
	if reason, ok := c.CanRelieve(); !ok {
		t.Errorf("expected first relief allowed, got rejected: %s", reason)
	}
}

func TestPanelRelief_CooldownBlocksImmediateSecond(t *testing.T) {
	c := NewPanelReliefController()
	c.RecordRelief()
	if _, ok := c.CanRelieve(); ok {
		t.Error("expected cooldown to block immediate second relief")
	}
}

func TestPanelRelief_DailyBudgetExhausted(t *testing.T) {
	c := NewPanelReliefController()
	// 模拟冷却期外（直接修改 lastAt 到 1 小时前），打满每日预算
	for i := 0; i < c.dailyBudget; i++ {
		c.RecordRelief()
		c.mu.Lock()
		c.lastAt = time.Now().Add(-1 * time.Hour)
		c.mu.Unlock()
	}
	if _, ok := c.CanRelieve(); ok {
		t.Error("expected daily budget to block relief after budget exhausted")
	}
}

func TestPanelRelief_InReliefCooldown(t *testing.T) {
	c := NewPanelReliefController()
	if c.InReliefCooldown(5 * time.Minute) {
		t.Error("expected no cooldown before any relief")
	}
	c.RecordRelief()
	if !c.InReliefCooldown(5 * time.Minute) {
		t.Error("expected cooldown active after relief")
	}
	if c.InReliefCooldown(0) {
		t.Error("expected zero-duration cooldown check to be false")
	}
}

func TestResourceFloor_CheckKillAllowed_IOWaitTooHigh(t *testing.T) {
	rf := DefaultResourceFloor()
	result := rf.CheckKillAllowed(200, 60, 1000)
	if result.Allowed {
		t.Error("should be rejected due to high IO wait")
	}
}

func TestResourceFloor_CheckKillAllowed_DiskTooLow(t *testing.T) {
	rf := DefaultResourceFloor()
	result := rf.CheckKillAllowed(200, 30, 100)
	if result.Allowed {
		t.Error("should be rejected due to low disk space")
	}
}

func TestResourceFloor_CheckKillAllowed_MemTooLow(t *testing.T) {
	rf := DefaultResourceFloor()
	result := rf.CheckKillAllowed(50, 30, 1000)
	if result.Allowed {
		t.Error("should be rejected due to low memory")
	}
}

// --- 2.2 封禁振荡熔断器 ---

func TestBanUnbanBreaker_AllowsBanInitially(t *testing.T) {
	b := NewBanUnbanBreaker()
	if !b.CanBan("1.2.3.4") {
		t.Error("should allow ban initially")
	}
}

func TestBanUnbanBreaker_PausesAfterRepeatedUnban(t *testing.T) {
	b := NewBanUnbanBreaker()
	ip := "1.2.3.5"

	// 记录 3 次解封（达到阈值）
	b.RecordUnban(ip)
	if !b.CanBan(ip) {
		t.Error("should still allow ban after 1 unban")
	}
	b.RecordUnban(ip)
	if !b.CanBan(ip) {
		t.Error("should still allow ban after 2 unbans")
	}
	b.RecordUnban(ip)
	// 第 3 次解封后应触发熔断
	if b.CanBan(ip) {
		t.Error("should pause ban after 3 unbans (threshold reached)")
	}
}

func TestBanUnbanBreaker_PauseReason(t *testing.T) {
	b := NewBanUnbanBreaker()
	ip := "1.2.3.6"

	b.RecordUnban(ip)
	b.RecordUnban(ip)
	b.RecordUnban(ip)

	reason := b.PauseReason(ip)
	if reason == "" {
		t.Error("should have a pause reason")
	}
}

func TestBanUnbanBreaker_RecoversAfterPauseDuration(t *testing.T) {
	b := NewBanUnbanBreaker()
	// 设置很短的暂停时间用于测试
	b.pauseDuration = 10 * time.Millisecond
	ip := "1.2.3.7"

	b.RecordUnban(ip)
	b.RecordUnban(ip)
	b.RecordUnban(ip)

	if b.CanBan(ip) {
		t.Error("should be paused")
	}

	time.Sleep(20 * time.Millisecond)

	if !b.CanBan(ip) {
		t.Error("should recover after pause duration")
	}
}

func TestBanUnbanBreaker_Stats(t *testing.T) {
	b := NewBanUnbanBreaker()
	ip1 := "1.2.3.8"
	ip2 := "1.2.3.9"

	b.RecordUnban(ip1)
	b.RecordUnban(ip1)
	b.RecordUnban(ip1)

	b.RecordUnban(ip2)

	total, paused := b.Stats()
	if total < 2 {
		t.Errorf("expected at least 2 total IPs, got %d", total)
	}
	if paused < 1 {
		t.Errorf("expected at least 1 paused IP, got %d", paused)
	}
}

// --- 2.3 Kill 后系统对比评估器 ---

func TestPostKillEvaluator_RecordPreKillState(t *testing.T) {
	e := NewPostKillEvaluator(nil)
	evalID := e.RecordPreKillState("test-proc", 50, 500, 1.0)
	if evalID == "" {
		t.Error("should return non-empty eval ID")
	}
	if e.PendingCount() != 1 {
		t.Errorf("expected 1 pending eval, got %d", e.PendingCount())
	}
}

func TestPostKillEvaluator_IsSystemWorse_CPU(t *testing.T) {
	e := NewPostKillEvaluator(nil)
	pre := postKillSysState{CPUPercent: 50, MemAvailableMB: 500, LoadAvg: 1.0}
	post := postKillSysState{CPUPercent: 80, MemAvailableMB: 500, LoadAvg: 1.0}
	if !e.isSystemWorse(pre, post) {
		t.Error("CPU +30% should be worse")
	}
}

func TestPostKillEvaluator_IsSystemWorse_Mem(t *testing.T) {
	e := NewPostKillEvaluator(nil)
	pre := postKillSysState{CPUPercent: 50, MemAvailableMB: 500, LoadAvg: 1.0}
	post := postKillSysState{CPUPercent: 50, MemAvailableMB: 300, LoadAvg: 1.0}
	if !e.isSystemWorse(pre, post) {
		t.Error("Mem -200MB should be worse")
	}
}

func TestPostKillEvaluator_IsSystemWorse_NotWorse(t *testing.T) {
	e := NewPostKillEvaluator(nil)
	pre := postKillSysState{CPUPercent: 50, MemAvailableMB: 500, LoadAvg: 1.0}
	post := postKillSysState{CPUPercent: 55, MemAvailableMB: 480, LoadAvg: 1.2}
	if e.isSystemWorse(pre, post) {
		t.Error("small changes should not be worse")
	}
}

// --- 2.4 四档状态机 ---

func TestSafetyManager_ShouldRunGuards(t *testing.T) {
	sm := New(testSafetyConfig())

	// Normal 模式应运行 Guards
	sm.EvaluateSystemState(50, 500, 1.0)
	if !sm.ShouldRunGuards() {
		t.Error("should run guards in normal mode")
	}

	// Survival 模式应跳过 Guards
	sm.EvaluateSystemState(96, 500, 1.0)
	if sm.ShouldRunGuards() {
		t.Error("should NOT run guards in survival mode")
	}
}

func TestSafetyManager_GetCollectInterval_AllModes(t *testing.T) {
	sm := New(testSafetyConfig())

	// Normal: default interval
	sm.EvaluateSystemState(50, 500, 1.0)
	if interval := sm.GetCollectInterval(5 * time.Second); interval != 5*time.Second {
		t.Errorf("normal mode interval = %v, want 5s", interval)
	}

	// Throttled: 15s
	sm.EvaluateSystemState(75, 500, 1.0)
	if interval := sm.GetCollectInterval(5 * time.Second); interval != 15*time.Second {
		t.Errorf("throttled mode interval = %v, want 15s", interval)
	}

	// Minimal: 60s
	sm.EvaluateSystemState(87, 500, 1.0)
	if interval := sm.GetCollectInterval(5 * time.Second); interval != 60*time.Second {
		t.Errorf("minimal mode interval = %v, want 60s", interval)
	}

	// Survival: 60s
	sm.EvaluateSystemState(96, 500, 1.0)
	if interval := sm.GetCollectInterval(5 * time.Second); interval != 60*time.Second {
		t.Errorf("survival mode interval = %v, want 60s", interval)
	}
}
