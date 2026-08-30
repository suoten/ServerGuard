package traffic

import (
	"context"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// --- CCAttackDetector tests ---

func TestCCAttackDetector_New(t *testing.T) {
	d := NewCCAttackDetector()
	if d == nil {
		t.Fatal("NewCCAttackDetector returned nil")
	}
	if d.threshold != 500 {
		t.Errorf("expected threshold 500, got %d", d.threshold)
	}
}

func TestCCAttackDetector_RecordRequest(t *testing.T) {
	d := NewCCAttackDetector()

	for i := 0; i < 499; i++ {
		if d.RecordRequest("1.2.3.4", "/index") {
			t.Error("should not trigger before threshold")
		}
	}
	if !d.RecordRequest("1.2.3.4", "/index") {
		t.Error("should trigger at threshold (500)")
	}
}

func TestCCAttackDetector_RecordRequestDifferentURLs(t *testing.T) {
	d := NewCCAttackDetector()
	for i := 0; i < 50; i++ {
		d.RecordRequest("1.2.3.4", "/url-a")
	}
	for i := 0; i < 50; i++ {
		d.RecordRequest("1.2.3.4", "/url-b")
	}
	if d.RecordRequest("1.2.3.4", "/url-a") {
		t.Error("should not trigger when per-URL count below threshold")
	}
}

func TestCCAttackDetector_GetTopAttackers(t *testing.T) {
	d := NewCCAttackDetector()
	for i := 0; i < 10; i++ {
		d.RecordRequest("1.1.1.1", "/a")
	}
	for i := 0; i < 5; i++ {
		d.RecordRequest("2.2.2.2", "/b")
	}

	attackers := d.GetTopAttackers(5)
	if len(attackers) != 2 {
		t.Fatalf("expected 2 attackers, got %d", len(attackers))
	}
	if attackers[0].Threshold != 500 {
		t.Errorf("expected threshold 500, got %d", attackers[0].Threshold)
	}
}

func TestCCAttackDetector_GetTopAttackersEmpty(t *testing.T) {
	d := NewCCAttackDetector()
	attackers := d.GetTopAttackers(5)
	if len(attackers) != 0 {
		t.Error("expected 0 attackers for empty detector")
	}
}

// --- OutboundAnomalyDetector tests ---

func TestOutboundAnomalyDetector_New(t *testing.T) {
	d := NewOutboundAnomalyDetector()
	if d == nil {
		t.Fatal("NewOutboundAnomalyDetector returned nil")
	}
	if d.thresholdMB != 100 {
		t.Errorf("expected threshold 100MB, got %d", d.thresholdMB)
	}
}

func TestOutboundAnomalyDetector_RecordOutbound(t *testing.T) {
	d := NewOutboundAnomalyDetector()

	thresholdBytes := uint64(100 * 1024 * 1024)
	if d.RecordOutbound("1.2.3.4", thresholdBytes) {
		t.Error("should not trigger at exactly threshold (not >)")
	}
	if !d.RecordOutbound("1.2.3.4", 1) {
		t.Error("should trigger when exceeding threshold")
	}
}

func TestOutboundAnomalyDetector_RecordOutboundNoTrigger(t *testing.T) {
	d := NewOutboundAnomalyDetector()
	if d.RecordOutbound("1.2.3.4", 1024) {
		t.Error("should not trigger for small outbound")
	}
}

func TestOutboundAnomalyDetector_GetAnomalies(t *testing.T) {
	d := NewOutboundAnomalyDetector()
	d.RecordOutbound("1.2.3.4", 101*1024*1024)
	d.RecordOutbound("5.6.7.8", 50*1024*1024)

	anomalies := d.GetAnomalies()
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].IP != "1.2.3.4" {
		t.Errorf("expected anomaly from 1.2.3.4, got %s", anomalies[0].IP)
	}
}

func TestOutboundAnomalyDetector_GetAnomaliesEmpty(t *testing.T) {
	d := NewOutboundAnomalyDetector()
	if len(d.GetAnomalies()) != 0 {
		t.Error("expected 0 anomalies for empty detector")
	}
}

// --- PortScanDetector tests ---

func TestPortScanDetector_New(t *testing.T) {
	d := NewPortScanDetector()
	if d == nil {
		t.Fatal("NewPortScanDetector returned nil")
	}
	if d.threshold != 50 {
		t.Errorf("expected threshold 50, got %d", d.threshold)
	}
}

func TestPortScanDetector_RecordPortHit(t *testing.T) {
	d := NewPortScanDetector()

	for port := 1; port < 50; port++ {
		if d.RecordPortHit("1.2.3.4", port) {
			t.Error("should not trigger before threshold")
		}
	}
	if !d.RecordPortHit("1.2.3.4", 50) {
		t.Error("should trigger at threshold (50 unique ports)")
	}
}

func TestPortScanDetector_RecordPortHitDuplicatePort(t *testing.T) {
	d := NewPortScanDetector()
	for i := 0; i < 100; i++ {
		d.RecordPortHit("1.2.3.4", 80) // same port
	}
	if d.RecordPortHit("1.2.3.4", 80) {
		t.Error("duplicate ports should not increase count")
	}
}

// --- SlowAttackDetector tests ---

func TestSlowAttackDetector_New(t *testing.T) {
	d := NewSlowAttackDetector()
	if d == nil {
		t.Fatal("NewSlowAttackDetector returned nil")
	}
	if d.threshold != 30*time.Second {
		t.Errorf("expected threshold 30s, got %v", d.threshold)
	}
}

func TestSlowAttackDetector_OnConnect(t *testing.T) {
	d := NewSlowAttackDetector()
	d.OnConnect("conn-1", "192.0.2.1", 80)
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.connections["conn-1"] == nil {
		t.Error("connection should be tracked after OnConnect")
	}
}

func TestSlowAttackDetector_OnActivity(t *testing.T) {
	d := NewSlowAttackDetector()
	d.OnConnect("conn-1", "192.0.2.1", 80)
	d.OnActivity("conn-1", 100)
	d.OnActivity("conn-1", 200)

	d.mu.RLock()
	info := d.connections["conn-1"]
	d.mu.RUnlock()
	if info.BytesSent != 300 {
		t.Errorf("expected 300 bytes sent, got %d", info.BytesSent)
	}
}

func TestSlowAttackDetector_OnActivityUnknownConn(t *testing.T) {
	d := NewSlowAttackDetector()
	d.OnActivity("unknown", 100) // should be no-op
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.connections["unknown"] != nil {
		t.Error("unknown connection should not be created by OnActivity")
	}
}

func TestSlowAttackDetector_OnDisconnect(t *testing.T) {
	d := NewSlowAttackDetector()
	d.OnConnect("conn-1", "192.0.2.1", 80)
	d.OnDisconnect("conn-1")
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.connections["conn-1"] != nil {
		t.Error("connection should be removed after OnDisconnect")
	}
}

func TestSlowAttackDetector_CheckSlowAttacks(t *testing.T) {
	d := NewSlowAttackDetector()
	d.OnConnect("conn-1", "192.0.2.1", 80)

	// Manually set the connection info to simulate an old, idle connection
	d.mu.Lock()
	d.connections["conn-1"].StartTime = time.Now().Add(-120 * time.Second)
	d.connections["conn-1"].LastActivity = time.Now().Add(-90 * time.Second)
	d.connections["conn-1"].BytesSent = 100
	d.mu.Unlock()

	slow := d.CheckSlowAttacks()
	if len(slow) != 1 || slow[0].ConnID != "conn-1" {
		t.Errorf("expected conn-1 in slow attacks, got %v", slow)
	}
}

func TestSlowAttackDetector_CheckSlowAttacksNone(t *testing.T) {
	d := NewSlowAttackDetector()
	d.OnConnect("conn-1", "192.0.2.1", 80)
	d.OnActivity("conn-1", 2048)

	if slow := d.CheckSlowAttacks(); len(slow) != 0 {
		t.Error("active connection should not be slow")
	}
}

// --- CheckEnhanced ---

func TestTrafficGuard_CheckEnhanced(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	bus.Start()
	g := New(bus)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	g.CheckEnhanced(ctx)
	time.Sleep(200 * time.Millisecond)
}
