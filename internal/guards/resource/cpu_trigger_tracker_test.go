package resource

import (
	"testing"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

func TestCPUTriggerTracker_FirstTriggerAlertOnly(t *testing.T) {
	bus := eventbus.New(100)
	tracker := NewCPUTriggerTracker(bus, nil)

	action := tracker.CheckAndAct(1234, "test-proc", 85, 80)
	if action != CPUActionAlertOnly {
		t.Error("first trigger should be alert only")
	}
	if tracker.GetTriggerCount(1234) != 1 {
		t.Errorf("trigger count = %d, want 1", tracker.GetTriggerCount(1234))
	}
}

func TestCPUTriggerTracker_ThreeTriggersKill(t *testing.T) {
	bus := eventbus.New(100)
	tracker := NewCPUTriggerTracker(bus, nil)

	tracker.CheckAndAct(1234, "test-proc", 85, 80)
	tracker.CheckAndAct(1234, "test-proc", 85, 80)
	action := tracker.CheckAndAct(1234, "test-proc", 85, 80)

	if action != CPUActionKill {
		t.Error("third trigger should be kill")
	}
}

func TestCPUTriggerTracker_ResetOnNormal(t *testing.T) {
	bus := eventbus.New(100)
	tracker := NewCPUTriggerTracker(bus, nil)

	tracker.CheckAndAct(1234, "test-proc", 85, 80)
	tracker.CheckAndAct(1234, "test-proc", 85, 80)

	tracker.Reset(1234)
	if tracker.GetTriggerCount(1234) != 0 {
		t.Error("trigger count should be reset to 0")
	}
}

func TestCPUTriggerTracker_DifferentProcessesIndependent(t *testing.T) {
	bus := eventbus.New(100)
	tracker := NewCPUTriggerTracker(bus, nil)

	tracker.CheckAndAct(1111, "proc-a", 85, 80)
	tracker.CheckAndAct(2222, "proc-b", 85, 80)
	tracker.CheckAndAct(1111, "proc-a", 85, 80)

	if tracker.GetTriggerCount(1111) != 2 {
		t.Errorf("proc-a count = %d, want 2", tracker.GetTriggerCount(1111))
	}
	if tracker.GetTriggerCount(2222) != 1 {
		t.Errorf("proc-b count = %d, want 1", tracker.GetTriggerCount(2222))
	}
}

func TestCPUTriggerTracker_CheckCPUWithProtection(t *testing.T) {
	bus := eventbus.New(100)
	tracker := NewCPUTriggerTracker(bus, nil)

	procs := []types.ProcessInfo{
		{PID: 1234, Name: "test", CPUPercent: 85, IsSystem: false},
	}

	toKill := tracker.CheckCPUWithProtection(nil, procs, 80)
	if len(toKill) != 0 {
		t.Error("first check should not kill")
	}

	toKill = tracker.CheckCPUWithProtection(nil, procs, 80)
	if len(toKill) != 0 {
		t.Error("second check should not kill")
	}

	toKill = tracker.CheckCPUWithProtection(nil, procs, 80)
	if len(toKill) != 1 {
		t.Errorf("third check should kill 1 process, got %d", len(toKill))
	}
}
