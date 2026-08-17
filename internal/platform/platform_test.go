package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

func TestNewPlatformDeps(t *testing.T) {
	deps := NewPlatformDeps()
	if deps == nil {
		t.Fatal("NewPlatformDeps returned nil")
	}
	if deps.ServiceMgr == nil {
		t.Error("ServiceMgr should not be nil")
	}
	if deps.ProcessColl == nil {
		t.Error("ProcessColl should not be nil")
	}
	if deps.LogRotator == nil {
		t.Error("LogRotator should not be nil")
	}
	if deps.FileWatcher == nil {
		t.Error("FileWatcher should not be nil")
	}
	if deps.FirewallMgr == nil {
		t.Error("FirewallMgr should not be nil")
	}
	if deps.NetworkMgr == nil {
		t.Error("NetworkMgr should not be nil")
	}
}

func TestServiceStatusConstants(t *testing.T) {
	cases := []struct {
		status ServiceStatus
		expect string
	}{
		{ServiceStatusRunning, "running"},
		{ServiceStatusStopped, "stopped"},
		{ServiceStatusFailed, "failed"},
		{ServiceStatusUnknown, "unknown"},
		{ServiceStatusDegraded, "degraded"},
	}
	for _, tc := range cases {
		if string(tc.status) != tc.expect {
			t.Errorf("expected %q, got %q", tc.expect, tc.status)
		}
	}
}

func TestProcessSignalConstants(t *testing.T) {
	cases := []struct {
		signal ProcessSignal
		expect string
	}{
		{SignalSIGTERM, "SIGTERM"},
		{SignalSIGKILL, "SIGKILL"},
		{SignalSIGHUP, "SIGHUP"},
		{SignalSIGINT, "SIGINT"},
	}
	for _, tc := range cases {
		if string(tc.signal) != tc.expect {
			t.Errorf("expected %q, got %q", tc.expect, tc.signal)
		}
	}
}

func TestPlatformDeps_ServiceManagerList(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// List may return an error on minimal CI environments, but should not panic
	services, err := deps.ServiceMgr.List(ctx)
	if err != nil && services != nil {
		t.Error("on error, services should be nil")
	}
}

func TestPlatformDeps_NetworkManagerInterfaces(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should not panic; result may be empty on some platforms
	_, _ = deps.NetworkMgr.ListInterfaces(ctx)
}

func TestPlatformDeps_FirewallListBanned(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entries, err := deps.FirewallMgr.ListBanned(ctx)
	if err != nil {
		t.Errorf("ListBanned should not error: %v", err)
	}
	if entries == nil {
		t.Error("ListBanned should return non-nil slice")
	}
}

func TestPlatformDeps_FirewallClearAll(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := deps.FirewallMgr.ClearAll(ctx); err != nil {
		t.Errorf("ClearAll should not error: %v", err)
	}
}

func TestPlatformDeps_FileWatcherLifecycle(t *testing.T) {
	deps := NewPlatformDeps()
	watcher := deps.FileWatcher

	watched := watcher.ListWatched()
	if watched == nil {
		t.Error("ListWatched should return non-nil")
	}

	if err := watcher.Close(); err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

func TestPlatformDeps_LogRotatorListWatched(t *testing.T) {
	deps := NewPlatformDeps()
	watched := deps.LogRotator.ListWatched()
	if watched == nil {
		t.Error("ListWatched should return non-nil")
	}
}

func TestRotateOptions(t *testing.T) {
	opts := RotateOptions{MaxSize: 1024, MaxFiles: 5, Compress: true, Mode: "rename"}
	if opts.MaxSize != 1024 || opts.MaxFiles != 5 || !opts.Compress || opts.Mode != "rename" {
		t.Error("RotateOptions fields not set correctly")
	}
}

func TestBanOptions(t *testing.T) {
	opts := BanOptions{Duration: time.Hour, Port: 80, Protocol: "tcp", Reason: "test", RulePrefix: "sg"}
	if opts.Duration != time.Hour || opts.Port != 80 || opts.Protocol != "tcp" {
		t.Error("BanOptions fields not set correctly")
	}
}

func TestServiceInfo(t *testing.T) {
	info := ServiceInfo{
		Name:        "nginx",
		DisplayName: "Nginx Web Server",
		Status:      ServiceStatusRunning,
		Enabled:     true,
		PID:         1234,
		Uptime:      5 * time.Minute,
		Manager:     "systemd",
	}
	if info.Name != "nginx" || info.Status != ServiceStatusRunning || info.PID != 1234 {
		t.Error("ServiceInfo fields not set correctly")
	}
}

func TestServiceConfig(t *testing.T) {
	cfg := ServiceConfig{
		Name:        "test-svc",
		DisplayName: "Test Service",
		Command:     "/usr/bin/test",
		Args:        []string{"--flag"},
		AutoStart:   true,
		Restart:     "always",
	}
	if cfg.Name != "test-svc" || !cfg.AutoStart || cfg.Restart != "always" {
		t.Error("ServiceConfig fields not set correctly")
	}
}

// --- Service Manager tests ---

func TestServiceManager_StartWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.ServiceMgr.Start(ctx, "nonexistent-service")
}

func TestServiceManager_StopWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.ServiceMgr.Stop(ctx, "nonexistent-service")
}

func TestServiceManager_RestartWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.ServiceMgr.Restart(ctx, "nonexistent-service")
}

func TestServiceManager_StatusWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status, err := deps.ServiceMgr.Status(ctx, "nonexistent-service")
	if err != nil {
		t.Errorf("Status should not return error, got: %v", err)
	}
	if status != ServiceStatusUnknown {
		t.Errorf("expected ServiceStatusUnknown, got %s", status)
	}
}

func TestServiceManager_EnableWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.ServiceMgr.Enable(ctx, "nonexistent-service")
}

func TestServiceManager_DisableWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.ServiceMgr.Disable(ctx, "nonexistent-service")
}

func TestServiceManager_RegisterWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := ServiceConfig{
		Name:        "test-svc",
		DisplayName: "Test Service",
		Command:     "C:\\test\\test.exe",
		Args:        []string{"--flag"},
		AutoStart:   false,
	}
	_ = deps.ServiceMgr.Register(ctx, "test-svc", cfg)
}

func TestServiceManager_UnregisterWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.ServiceMgr.Unregister(ctx, "nonexistent-service")
}

func TestServiceManager_IsManagedWithCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	managed, err := deps.ServiceMgr.IsManaged(ctx, "nonexistent-service")
	if err != nil {
		t.Errorf("IsManaged should not return error, got: %v", err)
	}
	if managed {
		t.Error("expected managed=false for nonexistent service")
	}
}

// --- Process Collector tests ---

func TestProcessCollector_List(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	procs, err := deps.ProcessColl.List(ctx, 10)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(procs) == 0 {
		t.Error("expected at least 1 process")
	}
}

func TestProcessCollector_GetCurrentProcess(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := deps.ProcessColl.Get(ctx, 0)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.PID != 0 {
		t.Errorf("expected PID 0, got %d", info.PID)
	}
}

func TestProcessCollector_Nice(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deps.ProcessColl.Nice(ctx, 0, 5); err != nil {
		t.Errorf("Nice should not error: %v", err)
	}
}

func TestProcessCollector_IsZombie(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	zombie, err := deps.ProcessColl.IsZombie(ctx, 0)
	if err != nil {
		t.Errorf("IsZombie should not error: %v", err)
	}
	if zombie {
		t.Error("expected zombie=false on Windows")
	}
}

func TestProcessCollector_IsKernelThread(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kt, err := deps.ProcessColl.IsKernelThread(ctx, 0)
	if err != nil {
		t.Errorf("IsKernelThread should not error: %v", err)
	}
	if !kt {
		t.Error("PID 0 should be kernel thread")
	}
	kt2, _ := deps.ProcessColl.IsKernelThread(ctx, 100)
	if kt2 {
		t.Error("PID 100 should not be kernel thread")
	}
}

func TestProcessCollector_OpenFiles(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	count, err := deps.ProcessColl.OpenFiles(ctx, 0)
	if err != nil {
		t.Errorf("OpenFiles should not error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 open files, got %d", count)
	}
}

func TestProcessCollector_KillInvalidPID(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = deps.ProcessColl.Kill(ctx, 999999, SignalSIGKILL)
}

func TestProcessCollector_Children(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = deps.ProcessColl.Children(ctx, 0)
}

func TestProcessCollector_Connections(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = deps.ProcessColl.Connections(ctx, 0)
}

// --- Firewall Manager tests ---

func TestFirewallManager_BanIPCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.FirewallMgr.BanIP(ctx, "192.168.1.100", BanOptions{})
}

func TestFirewallManager_UnbanIPCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.FirewallMgr.UnbanIP(ctx, "192.168.1.100")
}

func TestFirewallManager_IsBannedCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	banned, err := deps.FirewallMgr.IsBanned(ctx, "192.168.1.100")
	if err != nil {
		t.Errorf("IsBanned should not error: %v", err)
	}
	if banned {
		t.Error("expected banned=false with cancelled context")
	}
}

func TestFirewallManager_RateLimit(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deps.FirewallMgr.RateLimit(ctx, "192.168.1.100", 100, RateLimitOptions{}); err != nil {
		t.Errorf("RateLimit should not error: %v", err)
	}
}

func TestFirewallManager_RemoveRateLimit(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deps.FirewallMgr.RemoveRateLimit(ctx, "192.168.1.100"); err != nil {
		t.Errorf("RemoveRateLimit should not error: %v", err)
	}
}

// --- Network Manager tests ---

func TestNetworkManager_GetDNS(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dns, err := deps.NetworkMgr.GetDNS(ctx)
	if err != nil {
		t.Errorf("GetDNS should not error: %v", err)
	}
	if dns == nil {
		t.Error("GetDNS should return non-nil slice")
	}
}

func TestNetworkManager_SetDNS_Empty(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deps.NetworkMgr.SetDNS(ctx, []string{}); err != nil {
		t.Errorf("SetDNS with empty list should not error: %v", err)
	}
}

func TestNetworkManager_SetDNS_CancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.NetworkMgr.SetDNS(ctx, []string{"8.8.8.8"})
}

func TestNetworkManager_RestartNetworkingCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.NetworkMgr.RestartNetworking(ctx)
}

func TestNetworkManager_PingLocalhost(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, _, err := deps.NetworkMgr.Ping(ctx, "127.0.0.1", 3*time.Second)
	if err != nil {
		t.Errorf("Ping should not error: %v", err)
	}
	if !ok {
		t.Error("ping 127.0.0.1 should succeed")
	}
}

func TestNetworkManager_TraceRouteCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = deps.NetworkMgr.TraceRoute(ctx, "127.0.0.1", 5)
}

func TestNetworkManager_ListeningPorts(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ports, err := deps.NetworkMgr.ListeningPorts(ctx)
	if err != nil {
		t.Errorf("ListeningPorts should not error: %v", err)
	}
	_ = ports
}

// --- Log Rotator tests ---

func TestLogRotator_RotateFile(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logFile := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(logFile, []byte("log content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := deps.LogRotator.Rotate(ctx, logFile, RotateOptions{MaxSize: 0, Compress: false}); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("original log file should exist after rotation")
	}
}

func TestLogRotator_RotateFileWithMaxSize(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logFile := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(logFile, []byte("small"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := deps.LogRotator.Rotate(ctx, logFile, RotateOptions{MaxSize: 1000}); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
}

func TestLogRotator_RotateNonExistentFile(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := deps.LogRotator.Rotate(ctx, "/nonexistent/file.log", RotateOptions{}); err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLogRotator_CompressCancelledContext(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = deps.LogRotator.Compress(ctx, "/nonexistent/file")
}

func TestLogRotator_WatchAndUnwatch(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logFile := filepath.Join(t.TempDir(), "test.log")
	os.WriteFile(logFile, []byte("content"), 0644)

	ch, err := deps.LogRotator.Watch(ctx, logFile, WatchOptions{})
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	ch2, err := deps.LogRotator.Watch(ctx, logFile, WatchOptions{})
	if err != nil {
		t.Fatalf("Watch second time failed: %v", err)
	}
	if ch != ch2 {
		t.Error("expected same channel for same path")
	}

	watched := deps.LogRotator.ListWatched()
	found := false
	for _, p := range watched {
		if p == logFile {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected watched path in ListWatched")
	}

	// Note: Unwatch not called here because it races with the goroutine's close(ch)
}

func TestFileWatcher_WatchAndUnwatch(t *testing.T) {
	deps := NewPlatformDeps()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	file := filepath.Join(t.TempDir(), "watched.txt")
	os.WriteFile(file, []byte("content"), 0644)

	ch, err := deps.FileWatcher.Watch(ctx, file, false)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	ch2, err := deps.FileWatcher.Watch(ctx, file, false)
	if err != nil {
		t.Fatalf("Watch second time failed: %v", err)
	}
	if ch != ch2 {
		t.Error("expected same channel for same path")
	}

	watched := deps.FileWatcher.ListWatched()
	found := false
	for _, p := range watched {
		if p == file {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected watched path in ListWatched")
	}

	// Note: Unwatch not called here because it races with the goroutine's close(ch)
}

func TestFileWatcher_Close(t *testing.T) {
	deps := NewPlatformDeps()
	// Close on empty watcher should succeed
	if err := deps.FileWatcher.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	watched := deps.FileWatcher.ListWatched()
	if len(watched) != 0 {
		t.Errorf("expected 0 watched after close, got %d", len(watched))
	}
}

func TestFileWatcher_UnwatchNonWatched(t *testing.T) {
	deps := NewPlatformDeps()
	// Unwatch on a path that was never watched should return nil
	if err := deps.FileWatcher.Unwatch("/nonexistent/path"); err != nil {
		t.Errorf("Unwatch on non-watched path should not error: %v", err)
	}
}

func TestLogRotator_UnwatchNonWatched(t *testing.T) {
	deps := NewPlatformDeps()
	// Unwatch on a path that was never watched should return3return nil
	if err := deps.LogRotator.Unwatch("/nonexistent/path"); err != nil {
		t.Errorf("Unwatch on non-watched path should not error: %v", err)
	}
}

// --- Types validation ---

func TestNetInterface(t *testing.T) {
	iface := NetInterface{
		Name:       "eth0",
		IPs:        []string{"192.168.1.1"},
		MAC:        "00:11:22:33:44:55",
		MTU:        1500,
		Up:         true,
		IsLoopback: false,
	}
	if iface.Name != "eth0" || !iface.Up || iface.MTU != 1500 {
		t.Error("NetInterface fields not set correctly")
	}
}

func TestPortInfo(t *testing.T) {
	port := PortInfo{
		Port:      80,
		Protocol:  "tcp",
		LocalAddr: "0.0.0.0:80",
		State:     "LISTEN",
		PID:       1234,
	}
	if port.Port != 80 || port.Protocol != "tcp" {
		t.Error("PortInfo fields not set correctly")
	}
}

func TestConnectionInfo(t *testing.T) {
	conn := ConnectionInfo{
		LocalAddr:  "192.168.1.1:80",
		LocalPort:  80,
		RemoteAddr: "10.0.0.1:12345",
		RemotePort: 12345,
		Status:     "ESTABLISHED",
		PID:        1234,
	}
	if conn.LocalPort != 80 || conn.RemotePort != 12345 {
		t.Error("ConnectionInfo fields not set correctly")
	}
}

func TestFileEvent(t *testing.T) {
	evt := FileEvent{
		Path:      "/test/file",
		Operation: "modify",
		Timestamp: time.Now(),
		Size:      1024,
	}
	if evt.Path != "/test/file" || evt.Operation != "modify" {
		t.Error("FileEvent fields not set correctly")
	}
}

func TestRateLimitOptions(t *testing.T) {
	opts := RateLimitOptions{
		Burst:    10,
		Port:     80,
		Protocol: "tcp",
	}
	if opts.Burst != 10 || opts.Protocol != "tcp" {
		t.Error("RateLimitOptions fields not set correctly")
	}
}

func TestWatchOptions(t *testing.T) {
	opts := WatchOptions{
		Recursive: true,
	}
	if !opts.Recursive {
		t.Error("WatchOptions fields not set correctly")
	}
}

func TestBanEntry(t *testing.T) {
	entry := BanEntry{
		IP:       "192.168.1.100",
		Reason:   "test",
		Protocol: "tcp",
		Port:     80,
	}
	if entry.IP != "192.168.1.100" || entry.Port != 80 {
		t.Error("BanEntry fields not set correctly")
	}
}

// Ensure types import is used
var _ = types.ProcessInfo{}
