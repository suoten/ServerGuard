package decider

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/ruleengine"
)

func TestIsTrustworthy(t *testing.T) {
	now := time.Now()
	mkEntries := func(success, fail int) []ruleengine.RuleHistoryEntry {
		entries := make([]ruleengine.RuleHistoryEntry, 0, success+fail)
		for i := 0; i < success; i++ {
			entries = append(entries, ruleengine.RuleHistoryEntry{Success: true, Timestamp: now})
		}
		for i := 0; i < fail; i++ {
			entries = append(entries, ruleengine.RuleHistoryEntry{Success: false, Timestamp: now})
		}
		return entries
	}

	cases := []struct {
		name    string
		success int
		fail    int
		want    bool
	}{
		{"样本不足不信任", 3, 0, false},
		{"全部成功达样本量赢得信任", 8, 0, true},
		{"一次失败立即失去信任", 12, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTrustworthy(mkEntries(c.success, c.fail), trustMinSamples, trustMinRatePct); got != c.want {
				t.Fatalf("isTrustworthy(%d成功,%d失败)=%v，期望 %v", c.success, c.fail, got, c.want)
			}
		})
	}

	// 空历史不信任
	if isTrustworthy(nil, trustMinSamples, trustMinRatePct) {
		t.Fatal("空历史不应赢得信任")
	}
}
