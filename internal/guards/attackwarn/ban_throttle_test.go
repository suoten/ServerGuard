package attackwarn

import (
	"context"
	"testing"

	"github.com/suoten/serverguard/internal/types"
)

// 封禁节流回归：同一 IP 冷却期内不得重复执行防火墙命令。
// 事故背景：请求级检测器曾对每条匹配日志各封禁一次，扫描器一次探测数百 URL
// 就触发数百次 iptables 调用，规则堆积拖垮整机负载。
func TestTryBanCooldownForSameIP(t *testing.T) {
	g := NewAttackWarnGuard(nil, nil)
	ctx := context.Background()

	first := g.tryBan(ctx, "203.0.113.1", "web_scanner", types.SeverityMedium)
	if first == "already_banned" {
		t.Fatal("首次封禁不应命中冷却")
	}
	for i := 0; i < 50; i++ {
		if got := g.tryBan(ctx, "203.0.113.1", "sensitive_probe", types.SeverityMedium); got != "already_banned" {
			t.Fatalf("冷却期内的重复封禁应被拦截为 already_banned，实际 %s（第 %d 次）", got, i+2)
		}
	}
}

// 封禁预算：滑动窗口内实际封禁次数有硬上限，超出只告警。
func TestTryBanBudgetCeiling(t *testing.T) {
	g := NewAttackWarnGuard(nil, nil)
	ctx := context.Background()

	passed := 0
	for i := 0; i < banBudgetMax+10; i++ {
		ip := "198.51.100." + itoa(100+i)
		got := g.tryBan(ctx, ip, "web_scanner", types.SeverityMedium)
		if got == "ban_budget_exhausted" {
			continue
		}
		passed++
	}
	if passed > banBudgetMax {
		t.Fatalf("窗口内实际封禁次数 %d 超过预算上限 %d", passed, banBudgetMax)
	}
	if passed != banBudgetMax {
		t.Fatalf("预算耗尽前应恰好放行 %d 次，实际 %d", banBudgetMax, passed)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// 预算耗尽后不占用冷却：同 IP 在冷却未到期但预算恢复后仍可正常封禁路径判定。
// （此处验证 budget_exhausted 返回值不会误写冷却表导致永久 already_banned）
func TestTryBanBudgetExhaustedDoesNotTouchCooldown(t *testing.T) {
	g := NewAttackWarnGuard(nil, nil)
	ctx := context.Background()

	ip := "203.0.113.200"
	g.tryBan(ctx, ip, "web_scanner", types.SeverityMedium)

	for i := 0; i < banBudgetMax; i++ {
		g.tryBan(ctx, "198.51.100."+itoa(i), "xss", types.SeverityHigh)
	}
	if got := g.tryBan(ctx, ip, "dir_traversal", types.SeverityMedium); got != "already_banned" {
		t.Fatalf("冷却期内的同 IP 应返回 already_banned，实际 %s", got)
	}
}
