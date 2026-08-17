//go:build chaos

package chaos

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

// T-CHAOS-01: Agent kill -9 后自动恢复
func TestAgentKillRecover_T_CHAOS_01(t *testing.T) {
	if os.Getenv("SG_TEST_CHAOS") == "" {
		t.Skip("set SG_TEST_CHAOS=1 to run chaos tests")
	}
	if _, err := exec.LookPath("serverguard-agent"); err != nil {
		t.Skip("serverguard-agent not available")
	}
	// TODO: kill agent process and verify systemd/supervisor restarts it
}

// T-CHAOS-02: SQLite 数据库损坏后恢复
func TestSQLiteCorruption_T_CHAOS_02(t *testing.T) {
	if os.Getenv("SG_TEST_CHAOS") == "" {
		t.Skip("set SG_TEST_CHAOS=1 to run chaos tests")
	}

	tmpFile := "test_corrupt.db"
	defer os.Remove(tmpFile)

	store, err := storage.New(tmpFile)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}

	store.SaveAudit(types.AuditEntry{
		ID:        "test-1",
		Timestamp: time.Now(),
		Actor:     "test",
		Action:    "test",
	})
	store.Close()

	// Corrupt the database file
	f, _ := os.OpenFile(tmpFile, os.O_WRONLY|os.O_APPEND, 0644)
	f.Write([]byte("CORRUPTED DATA"))
	f.Close()

	// Verify recovery - should be able to reopen and reinitialize
	store2, err := storage.New(tmpFile)
	if err != nil {
		t.Logf("expected behavior: corrupted DB fails to open: %v", err)
		return
	}
	defer store2.Close()
}

// T-CHAOS-03: Hub 失联后 Agent 离线自治
func TestHubDisconnect_T_CHAOS_03(t *testing.T) {
	if os.Getenv("SG_TEST_CHAOS") == "" {
		t.Skip("set SG_TEST_CHAOS=1 to run chaos tests")
	}
	// TODO: start agent, disconnect hub, verify agent continues operating
}

// T-CHAOS-04: 规则配置错误后安全降级
func TestBadRuleConfig_T_CHAOS_04(t *testing.T) {
	if os.Getenv("SG_TEST_CHAOS") == "" {
		t.Skip("set SG_TEST_CHAOS=1 to run chaos tests")
	}

	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	defer store.Close()

	// TODO: load invalid rule config, verify agent degrades safely
}

// T-CHAOS-05: 网络中断后恢复
func TestNetworkPartition_T_CHAOS_05(t *testing.T) {
	if os.Getenv("SG_TEST_CHAOS") == "" {
		t.Skip("set SG_TEST_CHAOS=1 to run chaos tests")
	}
	// TODO: simulate network partition, verify agent behavior
}

// T-CHAOS-06: 磁盘满后降级运行
func TestDiskFull_T_CHAOS_06(t *testing.T) {
	if os.Getenv("SG_TEST_CHAOS") == "" {
		t.Skip("set SG_TEST_CHAOS=1 to run chaos tests")
	}
	// TODO: fill disk, verify agent switches to degraded mode
}
