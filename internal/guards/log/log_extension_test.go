package log

import (
	"testing"
)

func TestLogAutoDiscoverer_Create(t *testing.T) {
	d := NewLogAutoDiscoverer()
	if d == nil {
		t.Fatal("should create LogAutoDiscoverer")
	}
}

func TestLogAutoDiscoverer_Discover(t *testing.T) {
	d := NewLogAutoDiscoverer()
	// Discover 在 Windows 上可能返回空列表，不应报错
	paths := d.Discover()
	_ = paths
}

func TestLogAutoDiscoverer_GetDiscoveredLogs(t *testing.T) {
	d := NewLogAutoDiscoverer()
	logs := d.GetDiscoveredLogs()
	_ = logs
}

func TestLogrotateTakeoverManager_Create(t *testing.T) {
	m := NewLogrotateTakeoverManager()
	if m == nil {
		t.Fatal("should create LogrotateTakeoverManager")
	}
}

func TestLogrotateTakeoverManager_ShouldSkip(t *testing.T) {
	m := NewLogrotateTakeoverManager()
	// 不存在的路径不应跳过
	if m.ShouldSkip("/nonexistent/path.log") {
		t.Error("nonexistent path should not be skipped")
	}
}

func TestLogrotateTakeoverManager_IsTakenOver(t *testing.T) {
	m := NewLogrotateTakeoverManager()
	if m.IsTakenOver("/some/path.log") {
		t.Error("should not be taken over initially")
	}
}

func TestLogrotateTakeoverManager_GetTakenOverLogs(t *testing.T) {
	m := NewLogrotateTakeoverManager()
	logs := m.GetTakenOverLogs()
	if len(logs) != 0 {
		t.Error("should have no taken over logs initially")
	}
}
