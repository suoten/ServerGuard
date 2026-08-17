package decider

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/storage"
)

// newTestStorage 创建用于测试的临时 Storage 实例。
func newTestStorage(t *testing.T) *storage.Storage {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("创建测试 Storage 失败: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
		os.RemoveAll(tmpDir)
	})
	return store
}

// ============================================================
// 测试 11: ConfirmRequest 结构
// 验收标准: 包含 ID/Action/Target/Detail/Level/Context/CreatedAt/ExpiresAt/Executed/Ignored/Expired
// ============================================================

func TestConfirmRequest_Fields(t *testing.T) {
	req := &ConfirmRequest{
		ID:        "test-id-123",
		Action:    ActionDiskCleanup,
		Target:    "/var/log",
		Detail:    "发现 8 个可清理文件",
		Level:     "warning",
		Context:   map[string]interface{}{"disk_usage": 95.2},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Executed:  false,
		Ignored:   false,
		Expired:   false,
	}

	if req.ID == "" {
		t.Error("ID 不应为空")
	}
	if req.Action == "" {
		t.Error("Action 不应为空")
	}
	if req.Target == "" {
		t.Error("Target 不应为空")
	}
	if req.Detail == "" {
		t.Error("Detail 不应为空")
	}
	if req.Level == "" {
		t.Error("Level 不应为空")
	}
	if req.Context == nil {
		t.Error("Context 不应为 nil")
	}
	if req.CreatedAt.IsZero() {
		t.Error("CreatedAt 不应为零值")
	}
	if req.ExpiresAt.IsZero() {
		t.Error("ExpiresAt 不应为零值")
	}
	// Executed, Ignored, Expired 应该有默认值 false
	if req.Executed {
		t.Error("Executed 默认应为 false")
	}
	if req.Ignored {
		t.Error("Ignored 默认应为 false")
	}
	if req.Expired {
		t.Error("Expired 默认应为 false")
	}
}

// ============================================================
// 测试 12: ConfirmManager.Create
// 验收标准: 生成随机 Token；设置 5min 过期；持久化到 SQLite
// ============================================================

func TestConfirmManager_Create(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	req, err := cm.Create(
		ActionDiskCleanup,
		"/var/log",
		"发现 8 个可清理文件，预计释放 2.3GB",
		"warning",
		map[string]interface{}{"disk_usage": 95.2},
	)
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	// 验证 ID 是随机 Token（32 字符十六进制）
	if len(req.ID) != 32 {
		t.Errorf("ID 长度 = %d, want 32 (16 bytes hex)", len(req.ID))
	}

	// 验证过期时间为 5 分钟后
	expectedExpiry := req.CreatedAt.Add(5 * time.Minute)
	diff := req.ExpiresAt.Sub(expectedExpiry)
	if diff > time.Second || diff < -time.Second {
		t.Errorf("过期时间偏差过大: %v", diff)
	}

	// 验证初始状态
	if req.Executed {
		t.Error("新创建的请求 Executed 应为 false")
	}
	if req.Ignored {
		t.Error("新创建的请求 Ignored 应为 false")
	}
	if req.Expired {
		t.Error("新创建的请求 Expired 应为 false")
	}
}

func TestConfirmManager_Create_GeneratesUniqueIDs(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req, err := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)
		if err != nil {
			t.Fatalf("Create #%d 失败: %v", i, err)
		}
		if ids[req.ID] {
			t.Errorf("生成了重复的 ID: %s", req.ID)
		}
		ids[req.ID] = true
	}
}

// ============================================================
// 测试 13: ConfirmManager.Execute
// 验收标准: 校验已执行/已忽略/已过期；通过后标记 executed
// ============================================================

func TestConfirmManager_Execute_Success(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	req, err := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	executedReq, err := cm.Execute(req.ID)
	if err != nil {
		t.Fatalf("Execute 失败: %v", err)
	}

	if !executedReq.Executed {
		t.Error("执行后 Executed 应为 true")
	}
}

func TestConfirmManager_Execute_AlreadyExecuted(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	req, _ := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)

	// 第一次执行
	_, err := cm.Execute(req.ID)
	if err != nil {
		t.Fatalf("第一次 Execute 失败: %v", err)
	}

	// 第二次执行应报错
	_, err = cm.Execute(req.ID)
	if err == nil {
		t.Error("已执行的请求再次执行应返回错误")
	}
	if err.Error() != "该请求已执行" {
		t.Errorf("错误消息 = %q, want %q", err.Error(), "该请求已执行")
	}
}

func TestConfirmManager_Execute_AlreadyIgnored(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	req, _ := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)

	// 先忽略
	err := cm.Ignore(req.ID)
	if err != nil {
		t.Fatalf("Ignore 失败: %v", err)
	}

	// 再执行应报错
	_, err = cm.Execute(req.ID)
	if err == nil {
		t.Error("已忽略的请求执行应返回错误")
	}
	if err.Error() != "该请求已被忽略" {
		t.Errorf("错误消息 = %q, want %q", err.Error(), "该请求已被忽略")
	}
}

func TestConfirmManager_Execute_Expired(t *testing.T) {
	store := newTestStorage(t)
	// 设置超时为 0（立即过期效果通过直接操作数据库模拟）
	cm := NewConfirmManager(store, 0) // 0 会使用默认 5 分钟

	req, _ := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)

	// 直接更新过期时间为过去时间
	_, _ = store.DB().Exec(
		"UPDATE confirms SET expires_at=? WHERE id=?",
		time.Now().Add(-1*time.Minute).UTC().Format(time.RFC3339),
		req.ID,
	)

	// 执行应报过期
	_, err := cm.Execute(req.ID)
	if err == nil {
		t.Error("已过期的请求执行应返回错误")
	}
	if err.Error() != "确认请求已过期" {
		t.Errorf("错误消息 = %q, want %q", err.Error(), "确认请求已过期")
	}
}

func TestConfirmManager_Execute_NotFound(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	_, err := cm.Execute("nonexistent-id")
	if err == nil {
		t.Error("不存在的 ID 执行应返回错误")
	}
}

// ============================================================
// 测试 13b: ConfirmManager.Ignore
// ============================================================

func TestConfirmManager_Ignore_Success(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	req, _ := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)

	err := cm.Ignore(req.ID)
	if err != nil {
		t.Fatalf("Ignore 失败: %v", err)
	}
}

func TestConfirmManager_Ignore_AlreadyExecuted(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	req, _ := cm.Create(ActionDiskCleanup, "/var/log", "test", "warning", nil)

	// 先执行
	_, _ = cm.Execute(req.ID)

	// 再忽略应报错
	err := cm.Ignore(req.ID)
	if err == nil {
		t.Error("已执行的请求忽略应返回错误")
	}
}

// ============================================================
// 测试 14: ConfirmManager.GetPending
// 验收标准: 查询未处理且未过期的请求；按时间倒序
// ============================================================

func TestConfirmManager_GetPending(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	// 创建 3 个请求
	req1, _ := cm.Create(ActionDiskCleanup, "/var/log", "test1", "warning", nil)
	time.Sleep(10 * time.Millisecond)
	req2, _ := cm.Create(ActionLogRotation, "/var/log/syslog", "test2", "warning", nil)
	time.Sleep(10 * time.Millisecond)
	req3, _ := cm.Create(ActionBaotaServiceRestart, "nginx", "test3", "error", nil)

	// 执行第一个
	_, _ = cm.Execute(req1.ID)

	// 忽略第二个
	_ = cm.Ignore(req2.ID)

	// 获取待确认列表 → 应只有第三个
	pending, err := cm.GetPending()
	if err != nil {
		t.Fatalf("GetPending 失败: %v", err)
	}

	if len(pending) != 1 {
		t.Fatalf("待确认数量 = %d, want 1", len(pending))
	}

	if pending[0].ID != req3.ID {
		t.Errorf("待确认请求 ID = %s, want %s", pending[0].ID, req3.ID)
	}
}

func TestConfirmManager_GetPending_Empty(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	pending, err := cm.GetPending()
	if err != nil {
		t.Fatalf("GetPending 失败: %v", err)
	}

	if len(pending) != 0 {
		t.Errorf("空表待确认数量 = %d, want 0", len(pending))
	}
}

// ============================================================
// 测试 15: ConfirmManager.ExpireCleanup
// 验收标准: 定时标记过期请求
// ============================================================

func TestConfirmManager_ExpireCleanup(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 5)

	// 创建 2 个请求
	req1, _ := cm.Create(ActionDiskCleanup, "/var/log", "test1", "warning", nil)
	req2, _ := cm.Create(ActionLogRotation, "/var/log/syslog", "test2", "warning", nil)

	// 将第一个的过期时间设为过去
	_, _ = store.DB().Exec(
		"UPDATE confirms SET expires_at=? WHERE id=?",
		time.Now().Add(-1*time.Minute).UTC().Format(time.RFC3339),
		req1.ID,
	)

	// 执行过期清理
	count, err := cm.ExpireCleanup()
	if err != nil {
		t.Fatalf("ExpireCleanup 失败: %v", err)
	}

	if count != 1 {
		t.Errorf("过期清理数量 = %d, want 1", count)
	}

	// 验证 req1 已过期（不应出现在 GetPending 中）
	// 验证 req2 仍然待确认
	pending, _ := cm.GetPending()
	if len(pending) != 1 {
		t.Errorf("清理后待确认数量 = %d, want 1", len(pending))
	}
	if len(pending) > 0 && pending[0].ID != req2.ID {
		t.Errorf("剩余请求 ID = %s, want %s", pending[0].ID, req2.ID)
	}

	// 验证已过期的请求不能执行
	_, err = cm.Execute(req1.ID)
	if err == nil {
		t.Error("已过期的请求执行应返回错误")
	}
}

// ============================================================
// 测试 16: ConfirmManager 超时配置
// ============================================================

func TestConfirmManager_TimeoutDefault(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 0) // 0 应使用默认 5 分钟

	if cm.GetTimeout() != 5*time.Minute {
		t.Errorf("默认超时 = %v, want 5m", cm.GetTimeout())
	}
}

func TestConfirmManager_CustomTimeout(t *testing.T) {
	store := newTestStorage(t)
	cm := NewConfirmManager(store, 10)

	if cm.GetTimeout() != 10*time.Minute {
		t.Errorf("自定义超时 = %v, want 10m", cm.GetTimeout())
	}
}
