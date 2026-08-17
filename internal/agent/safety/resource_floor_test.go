package safety

import (
	"testing"
)

func TestResourceFloor_Default(t *testing.T) {
	rf := DefaultResourceFloor()
	if rf.MinMemForKillMB != 100 {
		t.Errorf("expected MinMemForKillMB=100, got %f", rf.MinMemForKillMB)
	}
	if rf.MaxLoadFactorRestart != 2.0 {
		t.Errorf("expected MaxLoadFactorRestart=2.0, got %f", rf.MaxLoadFactorRestart)
	}
	if rf.MaxIOWaitPercent != 50 {
		t.Errorf("expected MaxIOWaitPercent=50, got %f", rf.MaxIOWaitPercent)
	}
	if rf.MinDiskAvailableMB != 500 {
		t.Errorf("expected MinDiskAvailableMB=500, got %f", rf.MinDiskAvailableMB)
	}
}

func TestResourceFloor_CheckKillFloor(t *testing.T) {
	rf := DefaultResourceFloor()

	// 内存充足
	if err := rf.CheckKillFloor(200); err != nil {
		t.Errorf("should allow kill with enough memory: %v", err)
	}

	// 内存不足
	if err := rf.CheckKillFloor(50); err == nil {
		t.Error("should block kill with low memory")
	}

	// 边界值
	if err := rf.CheckKillFloor(100); err != nil {
		t.Errorf("should allow kill at exact threshold: %v", err)
	}
}

func TestResourceFloor_CheckRestartFloor(t *testing.T) {
	rf := DefaultResourceFloor()

	// 负载正常
	if err := rf.CheckRestartFloor(1.0); err != nil {
		t.Errorf("should allow restart with normal load: %v", err)
	}

	// 负载过高
	if err := rf.CheckRestartFloor(3.0); err == nil {
		t.Error("should block restart with high load")
	}
}

func TestResourceFloor_CheckIOIntensiveFloor(t *testing.T) {
	rf := DefaultResourceFloor()

	// IO 正常
	if err := rf.CheckIOIntensiveFloor(30); err != nil {
		t.Errorf("should allow with normal IO: %v", err)
	}

	// IO 过高
	if err := rf.CheckIOIntensiveFloor(60); err == nil {
		t.Error("should block with high IO wait")
	}
}

func TestResourceFloor_CheckWriteFloor(t *testing.T) {
	rf := DefaultResourceFloor()

	// 磁盘充足
	if err := rf.CheckWriteFloor(1000); err != nil {
		t.Errorf("should allow write with enough disk: %v", err)
	}

	// 磁盘不足
	if err := rf.CheckWriteFloor(100); err == nil {
		t.Error("should block write with low disk")
	}
}

func TestResourceFloor_CheckAllForAction(t *testing.T) {
	rf := DefaultResourceFloor()

	// Kill 操作，资源充足
	err := rf.CheckAllForAction("kill", 200, 1.0, 30, 1000)
	if err != nil {
		t.Errorf("should allow kill with good resources: %v", err)
	}

	// Kill 操作，内存不足
	err = rf.CheckAllForAction("kill", 50, 1.0, 30, 1000)
	if err == nil {
		t.Error("should block kill with low memory")
	}

	// Restart 操作，负载过高
	err = rf.CheckAllForAction("restart", 200, 3.0, 30, 1000)
	if err == nil {
		t.Error("should block restart with high load")
	}

	// Clean 操作，IO 过高
	err = rf.CheckAllForAction("clean_disk", 200, 1.0, 60, 1000)
	if err == nil {
		t.Error("should block clean with high IO")
	}
}
