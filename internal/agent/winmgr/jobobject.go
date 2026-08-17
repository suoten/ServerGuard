//go:build windows

package winmgr

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// JobObjectLimits Windows Job Object 资源限制
type JobObjectLimits struct {
	MaxMemoryMBA       uint64 // 进程组内存上限（MB）
	MaxMemoryMBPerProc uint64 // 单进程内存上限（MB）
	CPUPercent         uint32 // CPU 限制（百分比，1-100）
}

// DefaultJobObjectLimits 默认 Job Object 限制
func DefaultJobObjectLimits() JobObjectLimits {
	return JobObjectLimits{
		MaxMemoryMBA:       80,
		MaxMemoryMBPerProc: 60,
		CPUPercent:         5,
	}
}

// JobObjectHandle Job Object 句柄
type JobObjectHandle struct {
	handle syscall.Handle
}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procGetCurrentProcess        = kernel32.NewProc("GetCurrentProcess")
)

const (
	jobObjectBasicLimitInfoClass = 2
	jobObjectLimitProcessMemory  = 0x00000100
)

type jobObjectBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInfo
	IoInfo                struct {
		ReadOperationCount  uint64
		WriteOperationCount uint64
		OtherOperationCount uint64
		ReadTransferCount   uint64
		WriteTransferCount  uint64
		OtherTransferCount  uint64
	}
	ProcessMemoryLimit    uint64
	JobMemoryLimit        uint64
	PeakProcessMemoryUsed uint64
	PeakJobMemoryUsed     uint64
}

// CreateJobObject 创建 Windows Job Object
func CreateJobObject(limits JobObjectLimits) (*JobObjectHandle, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}

	handle, _, err := procCreateJobObjectW.Call(0, 0)
	if handle == 0 {
		return nil, fmt.Errorf("CreateJobObject failed: %w", err)
	}

	// 设置内存限制
	extInfo := jobObjectExtendedLimitInfo{}
	extInfo.BasicLimitInformation.LimitFlags = jobObjectLimitProcessMemory
	extInfo.ProcessMemoryLimit = limits.MaxMemoryMBPerProc * 1024 * 1024
	extInfo.JobMemoryLimit = limits.MaxMemoryMBA * 1024 * 1024

	_, _, err = procSetInformationJobObject.Call(
		handle,
		uintptr(jobObjectBasicLimitInfoClass),
		uintptr(unsafe.Pointer(&extInfo)),
		uintptr(unsafe.Sizeof(extInfo)),
	)
	if err != nil && err != syscall.Errno(0) {
		procCloseHandle.Call(handle)
		return nil, fmt.Errorf("SetInformationJobObject failed: %w", err)
	}

	return &JobObjectHandle{handle: syscall.Handle(handle)}, nil
}

// AssignProcess 将当前进程加入 Job Object
func (j *JobObjectHandle) AssignProcess() error {
	if j == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return nil
	}

	currentProc, _, _ := procGetCurrentProcess.Call()
	ret, _, err := procAssignProcessToJobObject.Call(uintptr(j.handle), currentProc)
	if ret == 0 {
		return fmt.Errorf("AssignProcessToJobObject failed: %w", err)
	}
	return nil
}

// Close 关闭 Job Object 句柄
func (j *JobObjectHandle) Close() error {
	if j == nil {
		return nil
	}
	procCloseHandle.Call(uintptr(j.handle))
	return nil
}

// ApplyResourceConstraints 应用资源约束到当前进程
func ApplyResourceConstraints() (*JobObjectHandle, error) {
	limits := DefaultJobObjectLimits()
	job, err := CreateJobObject(limits)
	if err != nil {
		return nil, err
	}
	if job != nil {
		if err := job.AssignProcess(); err != nil {
			job.Close()
			return nil, err
		}
	}
	return job, nil
}
