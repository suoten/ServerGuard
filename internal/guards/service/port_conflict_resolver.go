package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// PortConflictDetail 端口冲突详细信息（增强版）
type PortConflictDetail struct {
	Port       int
	PID        int32
	Process    string
	Status     string // running, zombie, sleep
	PPID       int32  // 父进程ID
	CreateTime time.Time
	IsZombie   bool
	IsSystem   bool
}

// EnhancedPortConflictResolver 增强版端口冲突解决器。
// 区分处理：僵尸进程→Kill 释放端口，正常服务→告警提示用户确认。
type EnhancedPortConflictResolver struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus
	history  map[int][]PortConflictDetail
}

// NewEnhancedPortConflictResolver 创建增强版端口冲突解决器。
func NewEnhancedPortConflictResolver(bus *eventbus.EventBus) *EnhancedPortConflictResolver {
	return &EnhancedPortConflictResolver{
		eventBus: bus,
		history:  make(map[int][]PortConflictDetail),
	}
}

// ProbeOccupant 探测占用指定端口的进程详细信息。
func (r *EnhancedPortConflictResolver) ProbeOccupant(port int) (*PortConflictDetail, error) {
	// 查找占用端口的进程
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}

	for _, p := range procs {
		conns, err := p.Connections()
		if err != nil {
			continue
		}
		for _, conn := range conns {
			if conn.Status == "LISTEN" && conn.Laddr.Port == uint32(port) {
				detail := &PortConflictDetail{
					Port: port,
					PID:  p.Pid,
				}
				if name, err := p.Name(); err == nil {
					detail.Process = name
				}
				if status, err := p.Status(); err == nil && len(status) > 0 {
					detail.Status = status[0]
					detail.IsZombie = status[0] == "zombie"
				}
				if ppid, err := p.Ppid(); err == nil {
					detail.PPID = int32(ppid)
				}
				if createTime, err := p.CreateTime(); err == nil {
					detail.CreateTime = time.UnixMilli(int64(createTime))
				}
				detail.IsSystem = isSystemProcess(detail.Process)
				return detail, nil
			}
		}
	}
	return nil, nil
}

// ResolveConflict 解决端口冲突。
// 僵尸进程→Kill 释放端口，正常服务→告警提示用户确认。
func (r *EnhancedPortConflictResolver) ResolveConflict(ctx context.Context, port int, expectedProcess string) error {
	detail, err := r.ProbeOccupant(port)
	if err != nil {
		return err
	}
	if detail == nil {
		return nil // 端口未被占用
	}

	r.mu.Lock()
	r.history[port] = append(r.history[port], *detail)
	r.mu.Unlock()

	if r.eventBus == nil {
		return nil
	}

	if detail.IsZombie {
		// 精确归属识别：宝塔生态进程（含 python/python3 运行的面板进程）
		// 即使是僵尸状态也不自动 Kill，避免误杀导致面板崩溃。
		if procInfo := safety.ReadProcInfo(detail.PID); procInfo != nil && safety.IsBaotaProtectedProcess(procInfo) {
			r.eventBus.PublishAlert(types.AlertWarning, "service",
				fmt.Sprintf("端口冲突（宝塔保护进程）: %d", port),
				fmt.Sprintf("端口 %d 被宝塔保护进程 %s (PID %d, comm=%s, cmdline=%s) 占用，不自动终止，请通过宝塔面板处理",
					port, detail.Process, detail.PID, procInfo.Comm, procInfo.Cmdline),
				"port-conflict-002")
			return nil
		}
		// 僵尸进程：Kill 释放端口
		r.eventBus.PublishAlert(types.AlertWarning, "service",
			fmt.Sprintf("端口冲突（僵尸进程）: %d", port),
			fmt.Sprintf("端口 %d 被僵尸进程 %s (PID %d) 占用，将 Kill 释放端口",
				port, detail.Process, detail.PID),
			"port-conflict-002")
		return killProcess(detail.PID)
	}

	if detail.IsSystem {
		// 系统进程：告警提示用户确认
		r.eventBus.PublishAlert(types.AlertWarning, "service",
			fmt.Sprintf("端口冲突（系统进程）: %d", port),
			fmt.Sprintf("端口 %d 被系统进程 %s (PID %d) 占用，需用户确认是否处理",
				port, detail.Process, detail.PID),
			"port-conflict-002")
		return nil
	}

	// 正常服务：告警提示用户确认
	r.eventBus.PublishAlert(types.AlertWarning, "service",
		fmt.Sprintf("端口冲突: %d", port),
		fmt.Sprintf("端口 %d 被进程 %s (PID %d, 状态: %s) 占用，预期进程: %s。需用户确认",
			port, detail.Process, detail.PID, detail.Status, expectedProcess),
		"port-conflict-002")
	return nil
}

// GetConflictHistory 返回指定端口的冲突历史。
func (r *EnhancedPortConflictResolver) GetConflictHistory(port int) []PortConflictDetail {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.history[port]
}

// isSystemProcess 判断是否为系统关键进程
func isSystemProcess(name string) bool {
	systemProcs := map[string]bool{
		"sshd": true, "nginx": true, "apache2": true, "httpd": true,
		"mysqld": true, "postgres": true, "redis-server": true,
		"systemd": true, "init": true, "kernel": true,
	}
	return systemProcs[name]
}

// killProcess Kill 指定进程
func killProcess(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
