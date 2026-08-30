package attackwarn

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/suoten/serverguard/internal/storage"
)

// 验证宝塔环境日志发现：
// 宝塔站点日志命名为 www.域名.com.log（不含 "access"），
// 旧实现只认文件名含 "access" 的文件，导致宝塔下 Z1 检测整体失效。
func TestAnalyzeLogFilesDiscoversBTSiteLogs(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		// 应被扫描的
		"access.log":           "", // 经典命名，优先级最高
		"www.test.com.log":     "", // 宝塔站点日志命名 ← 回归重点
		"blog.example.org.log": "",
		// 应被排除的
		"www.test.com.error.log": "", // 错误日志
		"error.log":              "", // 全局错误日志
		"old.access.log.gz":      "", // 压缩包
		"notes.txt":              "", // 非日志
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	store, err := storage.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("初始化测试存储失败: %v", err)
	}
	defer store.Close()

	g := NewAttackWarnGuard(store, nil)
	events, err := g.AnalyzeLogFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("AnalyzeLogFiles 返回错误: %v", err)
	}
	_ = events // 空日志内容不会产生事件，此处只验证不报错、不 panic

	// 直接验证文件选择逻辑：通过扫描行为间接断言——
	// 给宝塔命名的站点日志写入一条真实攻击 payload，必须能被检出。
	payload := `203.0.113.66 - - [23/Aug/2026:20:00:00 +0800] "GET /?id=1 UNION SELECT * FROM information_schema.tables HTTP/1.1" 200 123 "-" "sqlmap/1.7"`
	if err := os.WriteFile(filepath.Join(dir, "www.test.com.log"), []byte(payload+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	g2 := NewAttackWarnGuard(store, nil)
	events2, err := g2.AnalyzeLogFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("AnalyzeLogFiles 返回错误: %v", err)
	}
	found := false
	for _, e := range events2 {
		if e.EventType == "sql_injection" && e.SourceIP == "203.0.113.66" {
			found = true
		}
	}
	if !found {
		t.Fatal("宝塔命名的站点日志中的 SQL 注入未被检出 —— Z1 日志发现问题回归")
	}
}
