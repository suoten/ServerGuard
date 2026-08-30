package attackwarn

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// mkEvent 构造仅含 Detail 的最小事件，供指纹计算使用。
func mkEvent(detail string) types.AttackEvent {
	return types.AttackEvent{EventType: "cc_attack", Detail: detail}
}

// 验证事件去重：同指纹在窗口内只记录一次，窗口外重新放行。
// 这是"每轮扫描重复入库导致数千条误报"问题的回归测试。
func TestShouldRecordEventDedup(t *testing.T) {
	g := NewAttackWarnGuard(nil, nil)

	fp := "SQL 注入攻击尝试，匹配特征: union select，攻击 URL: /id=1 union select"

	// 首次：放行
	if !g.shouldRecordEvent("1.2.3.4", "sql_injection", fp) {
		t.Fatal("首次事件应放行")
	}
	// 窗口内重复：拦截（原实现每天同一攻击重复入库几十次）
	for i := 0; i < 5; i++ {
		if g.shouldRecordEvent("1.2.3.4", "sql_injection", fp) {
			t.Fatal("去重窗口内的重复事件应被拦截")
		}
	}
	// 不同攻击 URL：放行
	if !g.shouldRecordEvent("1.2.3.4", "sql_injection", "攻击 URL: /other?id=2") {
		t.Fatal("不同指纹的事件应放行")
	}
	// 窗口过期后：重新放行（持续攻击不漏报最新动态）
	key := "1.2.3.4|sql_injection|" + fp
	g.mu.Lock()
	g.recentEvents[key] = time.Now().Add(-dedupWindow - time.Minute)
	g.mu.Unlock()
	if !g.shouldRecordEvent("1.2.3.4", "sql_injection", fp) {
		t.Fatal("去重窗口过期后应重新放行")
	}
}

// 计数型检测（CC/SSH暴破等）Detail 中的次数每轮都在变化，
// 必须只按 IP+类型 去重，否则指纹永远不同、去重失效。
func TestEventFingerprintForCountBasedTypes(t *testing.T) {
	g := NewAttackWarnGuard(nil, nil)

	e1 := "CC 攻击，该 IP 在日志期间发送了 120 次请求（超过 100 次阈值）"
	e2 := "CC 攻击，该 IP 在日志期间发送了 350 次请求（超过 100 次阈值）"

	if !g.shouldRecordEvent("5.6.7.8", "cc_attack", eventFingerprint(mkEvent(e1))) {
		t.Fatal("首次 CC 事件应放行")
	}
	// 次数变了，但仍是同一 IP 的 CC 攻击 → 应拦截
	if g.shouldRecordEvent("5.6.7.8", "cc_attack", eventFingerprint(mkEvent(e2))) {
		t.Fatal("计数型事件应按 IP+类型 去重（次数变化不应绕过去重）")
	}
}

// 去重表容量兜底：超限后仍能继续写入（回收过期条目）。
func TestShouldRecordEventEviction(t *testing.T) {
	g := NewAttackWarnGuard(nil, nil)
	now := time.Now()
	// 预填充满表且全部已过期
	g.mu.Lock()
	for i := 0; i < dedupMaxEntries; i++ {
		g.recentEvents[string(rune(i%26+97))+time.Duration(i).String()] = now.Add(-2 * dedupWindow)
	}
	g.mu.Unlock()

	if !g.shouldRecordEvent("9.9.9.9", "port_scan", "") {
		t.Fatal("表满但条目均已过期时应回收并放行新事件")
	}
}
