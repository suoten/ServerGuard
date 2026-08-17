package safety

import (
	"fmt"
)

// ResourceFloor 四条细粒度资源地板规则
type ResourceFloor struct {
	MinMemForKillMB      float64 // 可用内存 < 此值禁 Kill
	MaxLoadFactorRestart float64 // 负载 > 核心数 × 此值禁重启
	MaxIOWaitPercent     float64 // IO 等待 > 此值禁压缩/VACUUM
	MinDiskAvailableMB        float64 // 磁盘可用 < 此值禁任何写操作
}

// DefaultResourceFloor 默认资源地板配置
func DefaultResourceFloor() ResourceFloor {
	return ResourceFloor{
		MinMemForKillMB:      100, // 可用内存 < 100MB 禁 Kill
		MaxLoadFactorRestart: 2.0, // 负载 > 核心数 × 2 禁重启
		MaxIOWaitPercent:     50,  // IO 等待 > 50% 禁压缩/VACUUM
		MinDiskAvailableMB:        500, // 磁盘 < 500MB 禁任何写操作
	}
}

// CheckKillFloor 检查 Kill 操作的资源地板
func (rf ResourceFloor) CheckKillFloor(memAvailableMB float64) error {
	if memAvailableMB < rf.MinMemForKillMB {
		return fmt.Errorf("可用内存 %.0fMB < %.0fMB，禁止 Kill 操作", memAvailableMB, rf.MinMemForKillMB)
	}
	return nil
}

// CheckRestartFloor 检查重启操作的资源地板
func (rf ResourceFloor) CheckRestartFloor(loadFactor float64) error {
	if loadFactor > rf.MaxLoadFactorRestart {
		return fmt.Errorf("负载因子 %.2f > %.2f，禁止重启操作", loadFactor, rf.MaxLoadFactorRestart)
	}
	return nil
}

// CheckIOIntensiveFloor 检查 IO 密集型操作（压缩/VACUUM）的资源地板
func (rf ResourceFloor) CheckIOIntensiveFloor(ioWaitPercent float64) error {
	if ioWaitPercent > rf.MaxIOWaitPercent {
		return fmt.Errorf("IO 等待 %.1f%% > %.1f%%，禁止压缩/VACUUM 操作", ioWaitPercent, rf.MaxIOWaitPercent)
	}
	return nil
}

// CheckWriteFloor 检查写操作的资源地板
func (rf ResourceFloor) CheckWriteFloor(diskFreeMB float64) error {
	if diskFreeMB < rf.MinDiskAvailableMB {
		return fmt.Errorf("磁盘可用 %.0fMB < %.0fMB，禁止写操作", diskFreeMB, rf.MinDiskAvailableMB)
	}
	return nil
}

// CheckAllForAction 根据动作类型检查对应的资源地板
func (rf ResourceFloor) CheckAllForAction(actionType string, memAvailableMB, loadFactor, ioWaitPercent, diskFreeMB float64) error {
	switch actionType {
	case "kill", "sigkill", "sigterm":
		return rf.CheckKillFloor(memAvailableMB)
	case "restart":
		if err := rf.CheckRestartFloor(loadFactor); err != nil {
			return err
		}
		return rf.CheckKillFloor(memAvailableMB)
	case "clean_disk", "rotate_log":
		if err := rf.CheckIOIntensiveFloor(ioWaitPercent); err != nil {
			return err
		}
		return rf.CheckWriteFloor(diskFreeMB)
	case "ban_ip", "rate_limit":
		return rf.CheckWriteFloor(diskFreeMB)
	default:
		return rf.CheckWriteFloor(diskFreeMB)
	}
}

// KillCheckResult Kill 操作检查结果，包含拒绝原因
type KillCheckResult struct {
	Allowed bool
	Reason  string
}

// CheckKillAllowed 检查 Kill 操作是否允许，包含 IO 等待和磁盘可用维度。
// 任一维度不满足均拒绝 Kill，返回拒绝原因。
func (rf ResourceFloor) CheckKillAllowed(memAvailableMB, ioWaitPercent, diskFreeMB float64) KillCheckResult {
	if memAvailableMB < rf.MinMemForKillMB {
		return KillCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("可用内存 %.0fMB < %.0fMB，禁止 Kill 操作", memAvailableMB, rf.MinMemForKillMB),
		}
	}
	if ioWaitPercent > rf.MaxIOWaitPercent {
		return KillCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("IO 等待 %.1f%% > %.1f%%，系统 IO 繁忙，禁止 Kill 操作", ioWaitPercent, rf.MaxIOWaitPercent),
		}
	}
	if diskFreeMB < rf.MinDiskAvailableMB {
		return KillCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("磁盘可用 %.0fMB < %.0fMB，禁止 Kill 操作", diskFreeMB, rf.MinDiskAvailableMB),
		}
	}
	return KillCheckResult{Allowed: true}
}
