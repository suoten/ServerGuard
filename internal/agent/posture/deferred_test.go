package posture

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

func TestOverrideForcesPosture(t *testing.T) {
	e, base := newTestEngine()

	e.SetOverride(PostureCombat, 10*time.Minute, "演练")
	if got := e.Current(); got != PostureCombat {
		t.Fatalf("覆盖后应为 combat，得到 %s", got)
	}

	// 覆盖期间即使指标空闲也保持锁定
	for i := 0; i < 5; i++ {
		e.UpdateSystem(5, 2048, 0.1)
	}
	if got := e.Current(); got != PostureCombat {
		t.Fatalf("覆盖期应保持 combat，得到 %s", got)
	}

	// 到期后回归自动判定
	*base = base.Add(11 * time.Minute)
	e.UpdateSystem(5, 2048, 0.1)
	e.UpdateSystem(5, 2048, 0.1)
	e.UpdateSystem(5, 2048, 0.1)
	if got := e.Current(); got != PostureIdle {
		t.Fatalf("覆盖到期后应回归自动判定（idle），得到 %s", got)
	}
}

func TestOverrideCappedAndCleared(t *testing.T) {
	e, _ := newTestEngine()

	// 超长时长被封顶到 24h
	e.SetOverride(PostureNormal, 100*24*time.Hour, "测试")
	e.mu.Lock()
	until := e.override.until
	e.mu.Unlock()
	if max := time.Now().Add(maxOverrideDuration); until.After(max.Add(time.Second)) {
		t.Fatalf("覆盖时长应封顶 24h，实际到 %v", until)
	}

	// ClearOverride 立即解除
	e.ClearOverride()
	if e.Current() != PostureNormal {
		t.Fatalf("解除覆盖后应回到 normal，得到 %s", e.Current())
	}
}

func TestCrisisBeatsOverride(t *testing.T) {
	e, _ := newTestEngine()
	e.SetOverride(PostureNormal, 30*time.Minute, "维护期锁定")

	// 即使锁定了 normal，系统资源危急仍然优先——保命永远第一
	e.SetAgentState(types.ModeSurvival, false)
	if got := e.Current(); got != PostureCrisis {
		t.Fatalf("危急应压过手动覆盖，得到 %s", got)
	}
}

func TestTimelineRecording(t *testing.T) {
	e, _ := newTestEngine()

	e.UpdateSystem(30, 1024, 0.8)          // 维持 normal，不记录
	e.SetAgentState(types.ModeMinimal, false) // normal → crisis
	e.SetAgentState(types.ModeNormal, false)  // crisis → 观察中
	e.UpdateSystem(30, 1024, 0.8)             // → normal

	tl := e.Timeline()
	if len(tl) != 2 {
		t.Fatalf("时间线应有 2 条记录，得到 %d：%v", len(tl), tl)
	}
	if tl[0].From != PostureNormal || tl[0].To != PostureCrisis {
		t.Fatalf("第一条转换不符：%v → %v", tl[0].From, tl[0].To)
	}
	if tl[1].To != PostureNormal || tl[1].Reason == "" {
		t.Fatalf("第二条转换缺少原因：%+v", tl[1])
	}

	// Snapshot 应带 override 信息
	e.SetOverride(PostureBusy, 5*time.Minute, "测试快照")
	snap := e.Describe()
	if snap.Override == nil || snap.Override.Posture != PostureBusy {
		t.Fatalf("Snapshot 应包含覆盖状态：%+v", snap.Override)
	}
}

func TestDeferredTrackerCatchUp(t *testing.T) {
	tr := NewDeferredTracker()
	now := time.Now()

	// 未推迟过的任务不触发补做
	if tr.DueForCatchUp("apm", now, 30*time.Minute) {
		t.Fatal("从未推迟过的任务不应触发补做")
	}

	// 推迟后但距上次运行不久：仍等待
	tr.MarkRan("apm", now.Add(-10*time.Minute))
	tr.MarkDeferred("apm")
	if tr.DueForCatchUp("apm", now, 30*time.Minute) {
		t.Fatal("距上次执行仅 10 分钟不应补做")
	}

	// 时间推进超过门槛：到期
	later := now.Add(31 * time.Minute)
	if !tr.DueForCatchUp("apm", later, 30*time.Minute) {
		t.Fatal("距上次执行超 30 分钟且曾被推迟，应补做")
	}

	// 补做后账本清零
	tr.MarkRan("apm", later)
	if tr.DueForCatchUp("apm", later, 30*time.Minute) {
		t.Fatal("MarkRan 后不应再触发补做")
	}
}

func TestDeferredTrackerMostOverdue(t *testing.T) {
	tr := NewDeferredTracker()
	now := time.Now()

	// apm 上次跑于 2h 前，predict 从未跑过且被推迟——从未跑过的最紧急
	tr.MarkRan("apm", now.Add(-2*time.Hour))
	tr.MarkDeferred("apm")
	tr.MarkDeferred("predict")

	key, ok := tr.MostOverdue([]string{"apm", "predict"}, now, 30*time.Minute)
	if !ok {
		t.Fatal("应有到期待补做的任务")
	}
	if key != "predict" {
		t.Fatalf("从未运行的 predict 应最先补做，得到 %s", key)
	}

	// 无任务到期时返回 false
	tr2 := NewDeferredTracker()
	tr2.MarkRan("apm", now)
	tr2.MarkDeferred("apm") // 推迟了但才刚跑过
	if _, ok := tr2.MostOverdue([]string{"apm"}, now, 30*time.Minute); ok {
		t.Fatal("刚执行过不应触发补做")
	}
}
