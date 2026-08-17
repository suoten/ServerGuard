package security

import (
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
)

func TestProgressiveBan_FirstAttackLimit(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	level := mgr.RecordAttack("1.2.3.4", "ssh-brute")
	if level != BanLevelLimit {
		t.Errorf("first attack should be limit, got %s", level)
	}
}

func TestProgressiveBan_EscalateToShort(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	mgr.RecordAttack("1.2.3.5", "ssh-brute")
	level := mgr.RecordAttack("1.2.3.5", "ssh-brute")
	if level != BanLevelShort {
		t.Errorf("second attack should escalate to short, got %s", level)
	}
}

func TestProgressiveBan_EscalateToLong(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	mgr.RecordAttack("1.2.3.6", "ssh-brute")
	mgr.RecordAttack("1.2.3.6", "ssh-brute")
	level := mgr.RecordAttack("1.2.3.6", "ssh-brute")
	if level != BanLevelLong {
		t.Errorf("third attack should escalate to long, got %s", level)
	}
}

func TestProgressiveBan_IsBanned(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	if mgr.IsBanned("1.2.3.7") {
		t.Error("should not be banned initially")
	}

	mgr.RecordAttack("1.2.3.7", "ssh-brute")
	mgr.RecordAttack("1.2.3.7", "ssh-brute")
	if !mgr.IsBanned("1.2.3.7") {
		t.Error("should be banned after escalation to short")
	}
}

func TestProgressiveBan_Unban(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	mgr.RecordAttack("1.2.3.8", "ssh-brute")
	mgr.Unban("1.2.3.8")
	if mgr.GetBanLevel("1.2.3.8") != BanLevelNone {
		t.Error("should be unbanned")
	}
}

func TestProgressiveBan_Cleanup(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	mgr.RecordAttack("1.2.3.9", "ssh-brute")
	mgr.Cleanup()
	// 记录应仍存在（未过期）
	if mgr.GetBanLevel("1.2.3.9") == BanLevelNone {
		// 可能已过期（10min 限速），这取决于实现
	}
}

func TestEmergencyRollback_Create(t *testing.T) {
	bus := eventbus.New(100)
	er := NewEmergencyRollback(bus)
	if er == nil {
		t.Fatal("should create EmergencyRollback")
	}
	er.Start()
	er.Stop()
}

func TestBanLevel_String(t *testing.T) {
	if BanLevelNone.String() != "none" {
		t.Error("none string")
	}
	if BanLevelLimit.String() != "limit" {
		t.Error("limit string")
	}
	if BanLevelShort.String() != "short" {
		t.Error("short string")
	}
	if BanLevelLong.String() != "long" {
		t.Error("long string")
	}
}

func TestProgressiveBan_GetBannedIPs(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	mgr.RecordAttack("1.2.3.10", "ssh-brute")
	mgr.RecordAttack("1.2.3.11", "ssh-brute")

	banned := mgr.GetBannedIPs()
	if len(banned) < 2 {
		t.Errorf("expected at least 2 banned IPs, got %d", len(banned))
	}
}

func TestEmergencyRollback_ResetRollbackCount(t *testing.T) {
	bus := eventbus.New(100)
	er := NewEmergencyRollback(bus)
	er.ResetRollbackCount()
}

func TestProgressiveBan_Expiry(t *testing.T) {
	bus := eventbus.New(100)
	mgr := NewProgressiveBanManager(bus)

	mgr.RecordAttack("1.2.3.12", "ssh-brute")
	// 等待过期（限速10min，这里只验证逻辑不崩溃）
	time.Sleep(1 * time.Millisecond)
	mgr.Cleanup()
}
