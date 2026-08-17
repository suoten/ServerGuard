package collector

import (
	"testing"

	"github.com/shirou/gopsutil/v3/process"
)

func TestNewPreFilter(t *testing.T) {
	pf := NewPreFilter()
	if pf == nil {
		t.Fatal("NewPreFilter returned nil")
	}
	if pf.minCPU != 1.0 {
		t.Errorf("expected minCPU=1.0, got %f", pf.minCPU)
	}
	if pf.minMem != 10.0 {
		t.Errorf("expected minMem=10.0, got %f", pf.minMem)
	}
}

func TestPreFilter_Whitelist(t *testing.T) {
	pf := NewPreFilter()

	// 系统进程应在白名单中
	if !pf.whitelistProcessNames["systemd"] {
		t.Error("systemd should be whitelisted")
	}
	if !pf.whitelistProcessNames["svchost.exe"] {
		t.Error("svchost.exe should be whitelisted")
	}

	// 普通进程不应在白名单中
	if pf.whitelistProcessNames["nginx"] {
		t.Error("nginx should not be whitelisted")
	}
}

func TestPreFilter_FilterProcess(t *testing.T) {
	pf := NewPreFilter()

	// 白名单进程应被过滤
	if pf.FilterProcess("systemd", 50, 100) {
		t.Error("systemd should be filtered out")
	}

	// 高CPU进程应保留
	if !pf.FilterProcess("nginx", 80, 500) {
		t.Error("nginx with high CPU should be kept")
	}

	// 高内存进程应保留
	if !pf.FilterProcess("java", 0.5, 500) {
		t.Error("java with high memory should be kept")
	}

	// 空闲进程应被过滤
	if pf.FilterProcess("idle_app", 0.5, 5) {
		t.Error("idle process should be filtered out")
	}
}

func TestPreFilter_SetThresholds(t *testing.T) {
	pf := NewPreFilter()
	pf.SetThresholds(5.0, 100.0)

	if pf.minCPU != 5.0 {
		t.Errorf("expected minCPU=5.0, got %f", pf.minCPU)
	}
	if pf.minMem != 100.0 {
		t.Errorf("expected minMem=100.0, got %f", pf.minMem)
	}
}

func TestPreFilter_AddRemoveWhitelist(t *testing.T) {
	pf := NewPreFilter()

	pf.AddWhitelist("myapp")
	if !pf.whitelistProcessNames["myapp"] {
		t.Error("myapp should be whitelisted after Add")
	}

	pf.RemoveWhitelist("myapp")
	if pf.whitelistProcessNames["myapp"] {
		t.Error("myapp should not be whitelisted after Remove")
	}
}

func TestPreFilter_FilterProcessesWithStats(t *testing.T) {
	pf := NewPreFilter()
	// 空列表测试
	result, stats, err := pf.FilterProcessesWithStats([]*process.Process{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Error("empty input should return empty result")
	}
	if stats.Total != 0 || stats.Kept != 0 || stats.Filtered != 0 {
		t.Error("empty input should have zero stats")
	}
}
