package posture

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// newTestEngine 创建带可控时钟的引擎。
func newTestEngine() (*Engine, *time.Time) {
	base := time.Now()
	e := New(nil)
	e.nowFunc = func() time.Time { return base }
	return e, &base
}

func TestNormalByDefault(t *testing.T) {
	e, _ := newTestEngine()
	e.UpdateSystem(30, 1024, 0.8) // 中等负载
	if got := e.Current(); got != PostureNormal {
		t.Fatalf("期望 normal，得到 %s", got)
	}
}

func TestIdleRequiresConsecutiveSamples(t *testing.T) {
	e, _ := newTestEngine()

	// 前两次采样：观察中，不进入 Idle
	e.UpdateSystem(10, 2048, 0.1)
	if got := e.Current(); got != PostureNormal {
		t.Fatalf("第 1 次采样不应进入 Idle，得到 %s", got)
	}
	e.UpdateSystem(10, 2048, 0.1)
	if got := e.Current(); got != PostureNormal {
		t.Fatalf("第 2 次采样不应进入 Idle（防抖），得到 %s", got)
	}
	// 第三次：确认进入空闲窗口
	e.UpdateSystem(10, 2048, 0.1)
	if got := e.Current(); got != PostureIdle {
		t.Fatalf("连续 %d 次空闲采样后应进入 idle，得到 %s", idleConfirmSamples, got)
	}
}

func TestIdleExitsImmediatelyOnSpike(t *testing.T) {
	e, _ := newTestEngine()
	for i := 0; i < idleConfirmSamples; i++ {
		e.UpdateSystem(10, 2048, 0.1)
	}
	if e.Current() != PostureIdle {
		t.Fatalf("前置条件失败：应为 idle，得到 %s", e.Current())
	}
	e.UpdateSystem(90, 300, 3.0) // CPU 飙升
	if got := e.Current(); got == PostureIdle {
		t.Fatal("CPU 飙升后应立即退出空闲窗口")
	}
}

func TestBusyOnHighLoad(t *testing.T) {
	e, _ := newTestEngine()
	e.UpdateSystem(50, 800, 2.5) // 负载因子超阈值
	if got := e.Current(); got != PostureBusy {
		t.Fatalf("高负载应进入 busy，得到 %s", got)
	}

	e2, _ := newTestEngine()
	e2.SetAgentState(types.ModeThrottled, false) // SafetyManager 判定节流
	e2.UpdateSystem(75, 250, 1.0)
	if got := e2.Current(); got != PostureBusy {
		t.Fatalf("throttled 模式应映射为 busy，得到 %s", got)
	}
}

func TestCrisisPriorityOverEverything(t *testing.T) {
	e, _ := newTestEngine()

	// 危急优先于战时：连 Agent 都快死了，先保命再抵抗
	e.ObserveSecurityEvent(time.Now())
	e.SetAgentState(types.ModeSurvival, false)
	if got := e.Current(); got != PostureCrisis {
		t.Fatalf("危急应压过战时，得到 %s", got)
	}

	// 急停也是危急
	e2, _ := newTestEngine()
	e2.SetAgentState(types.ModeNormal, true)
	if got := e2.Current(); got != PostureCrisis {
		t.Fatalf("急停应进入 crisis，得到 %s", got)
	}
}

func TestCombatEntryAndAutoExit(t *testing.T) {
	e, base := newTestEngine()

	e.ObserveSecurityEvent(*base)
	if got := e.Current(); got != PostureCombat {
		t.Fatalf("攻击信号应进入 combat，得到 %s", got)
	}

	// 保持期内即使系统繁忙也维持战时（攻击造成的负载要靠对抗解决）
	e.UpdateSystem(85, 150, 4.0)
	if got := e.Current(); got != PostureCombat {
		t.Fatalf("战时应压过繁忙，得到 %s", got)
	}

	// 攻击平息超过保持期后自动退出
	*base = base.Add(combatHold + time.Minute)
	e.UpdateSystem(30, 1024, 0.9)
	if got := e.Current(); got == PostureCombat {
		t.Fatal("保持期过后应退出战时")
	}
}

func TestCombatSignalRenewalCapped(t *testing.T) {
	e, _ := newTestEngine()
	t0 := time.Now()
	e.nowFunc = func() time.Time { return t0 }

	e.ObserveSecurityEvent(t0)
	until1 := e.attackUntil
	e.ObserveSecurityEvent(t0.Add(time.Second))
	if !e.attackUntil.After(until1) {
		t.Fatal("持续攻击信号应续期战时窗口")
	}
	// 高频信号封顶：不会超过最近一次信号 + combatHold
	e.ObserveSecurityEvent(t0.Add(2 * time.Second))
	e.ObserveSecurityEvent(t0.Add(3 * time.Second))
	if max := t0.Add(3 * time.Second).Add(combatHold); e.attackUntil.After(max) {
		t.Fatalf("战时窗口应封顶在最近信号+%v，实际 %v", combatHold, e.attackUntil)
	}
}

func TestSmallMemMachineIdleFloor(t *testing.T) {
	e, _ := newTestEngine()
	// 1G 小内存机器：可用内存 300MB 也算宽裕（自适应放宽）
	e.UpdateSystem(10, 300, 0.1)
	e.UpdateSystem(10, 300, 0.1)
	e.UpdateSystem(10, 300, 0.1)
	if got := e.Current(); got != PostureIdle {
		t.Fatalf("小内存机器 300MB 可用应可进入 idle，得到 %s", got)
	}
}

func TestTaskGatingMatrix(t *testing.T) {
	cases := []struct {
		posture      Posture
		secAllow     bool // 安全扫描允许？
		maintDefer   bool // 维护推迟？
		predictDefer bool // 预测推迟？
		scanMult     float64
	}{
		{PostureIdle, true, false, false, 0.5},       // 空闲：全放行，扫描加密
		{PostureNormal, true, false, false, 1.0},     // 常规：默认节奏
		{PostureBusy, true, true, true, 2.0},         // 繁忙：收紧，安全照跑
		{PostureCombat, true, true, true, 1.0 / 3.0}, // 战时：只做安全，提频
		{PostureCrisis, false, true, true, 3.0},      // 危急：全部挂起
	}

	for _, c := range cases {
		e, _ := newTestEngine()
		e.mu.Lock()
		e.current = c.posture
		e.mu.Unlock()

		if got := e.AllowTask(TaskSecurityScan); got != c.secAllow {
			t.Errorf("%s: AllowTask(security_scan)=%v，期望 %v", c.posture, got, c.secAllow)
		}
		if got := e.AllowTask(TaskMaintenance); !c.secAllow && got {
			t.Errorf("%s: 危急态势下维护任务不应放行", c.posture)
		}
		if got := e.ShouldDefer(TaskMaintenance); got != c.maintDefer {
			t.Errorf("%s: ShouldDefer(maintenance)=%v，期望 %v", c.posture, got, c.maintDefer)
		}
		if got := e.ShouldDefer(TaskPredict); got != c.predictDefer {
			t.Errorf("%s: ShouldDefer(predict)=%v，期望 %v", c.posture, got, c.predictDefer)
		}
		if got := e.ScanMultiplier(); got != c.scanMult {
			t.Errorf("%s: ScanMultiplier=%v，期望 %v", c.posture, got, c.scanMult)
		}
	}
}

func TestAutoResolveBias(t *testing.T) {
	e, _ := newTestEngine()
	if e.AutoResolve() != BiasNormal {
		t.Fatal("常规态势应为 BiasNormal（按规则确认要求执行）")
	}
	e.ObserveSecurityEvent(time.Now())
	if e.AutoResolve() != BiasCombatAuto {
		t.Fatal("战时态势应为 BiasCombatAuto（低风险安全动作自动提级）")
	}
}

func TestTransitionCallback(t *testing.T) {
	var transitions []string
	e := New(func(from, to Posture, _ string) {
		transitions = append(transitions, string(from)+"->"+string(to))
	})
	e.nowFunc = func() time.Time { return time.Now() }

	e.SetAgentState(types.ModeMinimal, false) // Normal → Crisis
	e.SetAgentState(types.ModeNormal, false)  // Crisis → 观察中
	e.UpdateSystem(30, 1024, 0.8)             // 喂入常规指标 → 回到 Normal
	if len(transitions) != 2 {
		t.Fatalf("应记录 2 次转换，得到 %v", transitions)
	}
	if transitions[0] != "normal->crisis" || transitions[1] != "crisis->normal" {
		t.Fatalf("转换记录不符：%v", transitions)
	}
}
