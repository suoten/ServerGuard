package correlation

import (
	"strings"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/knowledge"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

func newTestEngine(t *testing.T) (*Engine, *storage.Storage) {
	t.Helper()
	store, err := storage.New(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	bus := eventbus.New(100)
	kb := knowledge.New(store)
	return New(bus, store, kb), store
}

func alert(id, source, title, msg string, at time.Time) types.Event {
	return types.Event{
		ID:        id,
		Type:      types.EventAlert,
		Source:    source,
		Level:     types.AlertError,
		Title:     title,
		Message:   msg,
		Timestamp: at,
	}
}

// 因果规则：数据库故障在先、API 超时在后 → 必须聚合成一条因果链事件。
func TestCorrelate_DatabaseRootCausesAPITimeout(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()

	e.onAlert(alert("a1", "database", "MySQL 连接失败", "connection refused 127.0.0.1:3306", base))
	e.onAlert(alert("a2", "apm", "API 探活失败", "site /api/health 请求超时 5s", base.Add(40*time.Second)))

	incs, err := store.GetIncidents("open", 10)
	if err != nil {
		t.Fatalf("GetIncidents: %v", err)
	}
	if len(incs) != 1 {
		t.Fatalf("应聚合为 1 个事件，实际 %d 个", len(incs))
	}
	inc := incs[0]
	if inc.RootTitle != "MySQL 连接失败" {
		t.Errorf("根因应为 MySQL 告警，实际 %q", inc.RootTitle)
	}
	if len(inc.MemberAlerts) != 2 {
		t.Errorf("成员应为 2 条告警，实际 %d", len(inc.MemberAlerts))
	}
	if len(inc.Chain) == 0 {
		t.Fatal("应存在至少一条因果边")
	}
	link := inc.Chain[0]
	if link.Via == "" || !strings.Contains(link.Via, "domain-rule") {
		t.Errorf("因果边应标注 domain-rule，实际 %q", link.Via)
	}
	if !strings.Contains(link.From, "MySQL") || !strings.Contains(link.To, "API") {
		t.Errorf("因果方向错误：%s → %s", link.From, link.To)
	}
	if !strings.Contains(inc.Summary, "根因") {
		t.Errorf("摘要应包含根因说明，实际: %q", inc.Summary)
	}
}

// 单条告警不成链：无事件产生，不制造噪音。
func TestCorrelate_SingleAlertNoIncident(t *testing.T) {
	e, store := newTestEngine(t)
	e.onAlert(alert("a1", "database", "MySQL 连接失败", "connection refused", time.Now()))

	incs, _ := store.GetIncidents("", 10)
	if len(incs) != 0 {
		t.Errorf("单条告警不应产生事件，实际 %d 个", len(incs))
	}
}

// 无因果关系的两条告警（不同域、不同源）不应被强行关联。
func TestCorrelate_UnrelatedAlertsNoIncident(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()
	e.onAlert(alert("a1", "cert", "证书即将过期", "example.com 还有 10 天到期", base))
	e.onAlert(alert("a2", "fd", "FD 数量偏高", "进程 nginx fd 4200", base.Add(30*time.Second)))

	incs, _ := store.GetIncidents("", 10)
	if len(incs) != 0 {
		t.Errorf("无因果关系的告警不应聚合，实际 %d 个事件", len(incs))
	}
}

// 时间序校验：果在因之前发生 → 不构成因果链。
func TestCorrelate_NoReverseCausality(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()
	// 超时先发生，数据库故障在后 —— 不能把数据库当根因
	e.onAlert(alert("a1", "apm", "API 探活失败", "请求超时 5s", base))
	e.onAlert(alert("a2", "database", "MySQL 连接失败", "connection refused", base.Add(2*time.Minute)))

	incs, _ := store.GetIncidents("", 10)
	for _, inc := range incs {
		for _, l := range inc.Chain {
			if strings.Contains(l.From, "MySQL") && strings.Contains(l.To, "API") {
				t.Error("果先于因发生时不应产生 因→果 边")
			}
		}
	}
}

// 同源连续告警按连锁反应聚合。
func TestCorrelate_SameSourceChain(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()
	e.onAlert(alert("a1", "service", "nginx 重启失败", "restart attempt 1 failed", base))
	e.onAlert(alert("a2", "service", "nginx 端口未监听", "port 80 not listening", base.Add(60*time.Second)))

	incs, _ := store.GetIncidents("", 10)
	if len(incs) != 1 {
		t.Fatalf("同源告警应聚合为 1 个事件，实际 %d", len(incs))
	}
	if incs[0].Chain[0].Via != "same-source" {
		t.Errorf("同源边应标注 same-source，实际 %q", incs[0].Chain[0].Via)
	}
}

// 指纹归一化：同类告警（标题数字不同）合并到同一事件，不重复开事件。
func TestCorrelate_FingerprintMergesSimilarRoots(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()
	e.onAlert(alert("a1", "database", "MySQL 慢查询 12 条", "slow query threshold exceeded", base))
	e.onAlert(alert("a2", "apm", "API 超时", "request timeout", base.Add(30*time.Second)))
	e.onAlert(alert("a3", "database", "MySQL 慢查询 45 条", "slow query threshold exceeded", base.Add(60*time.Second)))
	e.onAlert(alert("a4", "apm", "API 超时", "request timeout", base.Add(90*time.Second)))

	incs, _ := store.GetIncidents("", 10)
	open := 0
	for _, inc := range incs {
		if inc.Status == "open" {
			open++
		}
	}
	if open != 1 {
		t.Errorf("同类故障应合并为 1 个开放事件，实际 %d", open)
	}
}

// 引擎自己的汇总告警不参与关联（防自循环）。
func TestCorrelate_IgnoresOwnAlerts(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()
	e.onAlert(alert("a1", "database", "MySQL 连接失败", "connection refused", base))
	e.onAlert(alert("self", engineSource, "故障链分析：MySQL 连接失败", "检测到 2 条相关告警", base.Add(10*time.Second)))

	incs, _ := store.GetIncidents("", 10)
	for _, inc := range incs {
		if len(inc.MemberAlerts) > 2 {
			t.Errorf("引擎自身告警被误纳入成员: %d 条", len(inc.MemberAlerts))
		}
	}
}

// 自动处置动作应挂载到事件上。
func TestCorrelate_ActionsAttached(t *testing.T) {
	e, store := newTestEngine(t)
	base := time.Now()
	e.onAlert(alert("a1", "database", "MySQL 连接失败", "connection refused", base))
	e.onAlert(alert("a2", "apm", "API 探活失败", "请求超时", base.Add(30*time.Second)))
	e.onAction(types.Event{
		ID: "act1", Type: types.EventAction, Source: "executor",
		Title: "重启 MySQL", Message: "执行 systemctl restart mysql",
		Timestamp: base.Add(35 * time.Second),
	})

	incs, _ := store.GetIncidents("", 10)
	if len(incs) != 1 {
		t.Fatalf("应产生 1 个事件，实际 %d", len(incs))
	}
	if len(incs[0].Actions) == 0 {
		t.Fatal("时间上紧跟根因的处置动作应挂载到事件")
	}
}

// 事件解决后应沉淀到知识库（RecordIncident 聚合）。
// 白盒构造一个已沉寂的事件（绕过 onAlert 的 10 分钟缓冲裁剪），验证关闭+沉淀链路。
func TestCorrelate_ResolvedIncidentFeedsKnowledge(t *testing.T) {
	e, _ := newTestEngine(t)
	old := time.Now().Add(-resolveAge - time.Minute)

	inc := &types.Incident{
		ID:         storage.NewIncidentID(),
		StartedAt:  old,
		Status:     "open",
		RootTitle:  "MySQL 连接失败",
		RootSource: "database",
		RootTime:   old,
		MemberAlerts: []types.AlertRef{
			{AlertID: "a1", Title: "MySQL 连接失败", Source: "database", Level: types.AlertError, Time: old},
			{AlertID: "a2", Title: "API 探活失败", Source: "apm", Level: types.AlertError, Time: old.Add(30 * time.Second)},
		},
		Chain: []types.ChainLink{{From: "MySQL 连接失败", To: "API 探活失败", Via: "domain-rule:数据库故障→服务超时"}},
	}
	e.open[fingerprint(types.Event{Title: inc.RootTitle, Source: inc.RootSource})] = inc
	// 动作通过正常挂载路径进入（attach 后会落库并触发规则确认）
	e.act = []types.Event{{ID: "act1", Type: types.EventAction, Source: "executor",
		Title: "重启 MySQL", Message: "systemctl restart mysql", Timestamp: old.Add(35 * time.Second)}}
	e.attachActionsLocked()

	e.closeStaleIncidents()

	entries, err := e.kb.FindSimilar("MySQL 连接失败", "database", 5)
	if err != nil {
		t.Fatalf("FindSimilar: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("解决的事件应沉淀为知识库条目")
	}
	en := entries[0]
	if en.Action == "" || !strings.Contains(en.Action, "重启 MySQL") {
		t.Errorf("知识条目应记录处置动作，实际 %q", en.Action)
	}
	if en.ActionResult != "success" {
		t.Errorf("有处置动作的事件应记为 success，实际 %q", en.ActionResult)
	}

	// 事件应已关闭并落库
	resolved, _ := e.db.GetIncidents("resolved", 10)
	found := false
	for _, r := range resolved {
		if r.ID == inc.ID {
			found = true
			if len(r.Actions) == 0 {
				t.Error("落库的事件应包含挂载的处置动作")
			}
		}
	}
	if !found {
		t.Error("关闭的事件应能在 resolved 状态下查到")
	}
}

// 相同故障第二次发生：知识库计数累加，且 Recommend 能给出上次处置。
func TestKnowledgeFeedback_SecondOccurrenceRecommends(t *testing.T) {
	e, _ := newTestEngine(t)

	recordIncident := func(offset time.Duration) {
		old := time.Now().Add(-resolveAge - time.Minute - offset)
		inc := &types.Incident{
			ID:         storage.NewIncidentID(),
			StartedAt:  old,
			Status:     "open",
			RootTitle:  "MySQL 连接失败",
			RootSource: "database",
			RootTime:   old,
			MemberAlerts: []types.AlertRef{
				{AlertID: "a" + old.Format("050405.000"), Title: "MySQL 连接失败", Source: "database", Level: types.AlertError, Time: old},
			},
		}
		e.open[fingerprint(types.Event{Title: inc.RootTitle, Source: inc.RootSource})] = inc
		e.act = []types.Event{{ID: "act" + old.Format("050405.000"), Type: types.EventAction, Source: "executor",
			Title: "重启 MySQL", Message: "systemctl restart mysql", Timestamp: old.Add(35 * time.Second)}}
		e.attachActionsLocked()
		e.closeStaleIncidents()
	}

	// 第一次故障
	recordIncident(0)
	// 第二次故障（根因指纹相同，2 小时前发生）
	recordIncident(2 * time.Hour)

	entries, _ := e.kb.FindSimilar("MySQL 连接失败", "database", 5)
	if len(entries) == 0 {
		t.Fatal("知识库应有该症状条目")
	}
	if entries[0].OccurrenceCount < 2 {
		t.Errorf("同症状第二次发生应累加计数 ≥2，实际 %d", entries[0].OccurrenceCount)
	}

	rec := e.Recommend("MySQL 连接失败", "database")
	if rec == "" {
		t.Fatal("Recommend 应返回历史经验")
	}
	if !strings.Contains(rec, "重启 MySQL") {
		t.Errorf("推荐应包含上次有效处置，实际: %q", rec)
	}
	if !strings.Contains(rec, "已出现过") {
		t.Errorf("推荐应包含出现次数，实际: %q", rec)
	}
}

// normalizeTitle 去数字/百分号，保证指纹稳定。
func TestNormalizeTitle(t *testing.T) {
	a := normalizeTitle("CPU 使用率 95.5% 持续 60s")
	b := normalizeTitle("CPU 使用率 88.2% 持续 45s")
	if a != b {
		t.Errorf("同类告警标题归一化后应相同：%q vs %q", a, b)
	}
}
