package collector

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/types"
)

// Collector collects system and process metrics.
type Collector struct {
	mu            sync.Mutex
	prevNetSent   uint64
	prevNetRecv   uint64
	prevNetTime   time.Time
	prevCPUTime   time.Time
	hostInfo      *host.InfoStat
	processCount  int
	baotaSafeMode bool // 宝塔安全模式：跳过昂贵的 process.Processes() 调用
}

// New creates a new Collector instance.
func New() *Collector {
	return &Collector{
		prevNetTime: time.Now(),
	}
}

// SetBaotaSafeMode 启用或禁用宝塔兼容安全模式。
// 启用后，CollectSystem 跳过昂贵的 process.Processes() 调用，
// 改用轻量级的 /proc 目录计数。
func (c *Collector) SetBaotaSafeMode(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baotaSafeMode = enabled
}

// CollectSystem collects system-level metrics.
func (c *Collector) CollectSystem() (*types.SystemInfo, error) {
	info := &types.SystemInfo{
		Timestamp: time.Now(),
	}

	// Host info
	if c.hostInfo == nil {
		if h, err := host.Info(); err == nil {
			c.hostInfo = h
		}
	}
	if c.hostInfo != nil {
		info.Hostname = c.hostInfo.Hostname
		info.OS = c.hostInfo.OS
		info.Platform = c.hostInfo.Platform
		info.PlatformVersion = c.hostInfo.PlatformVersion
		info.KernelVersion = c.hostInfo.KernelVersion
		info.BootTime = time.Unix(int64(c.hostInfo.BootTime), 0)
		info.Uptime = time.Duration(c.hostInfo.Uptime) * time.Second
	}

	// CPU
	cores, _ := cpu.Counts(true)
	info.CPUCores = cores
	// 使用 200ms 间隔而非 1s，减少阻塞时间
	cpuPercent, err := cpu.Percent(200*time.Millisecond, false)
	if err == nil && len(cpuPercent) > 0 {
		info.CPUPercent = cpuPercent[0]
	}

	// Load average (Linux only)
	if runtime.GOOS != "windows" {
		if load, err := loadAvg(); err == nil {
			info.LoadAvg1 = load[0]
			info.LoadAvg5 = load[1]
			info.LoadAvg15 = load[2]
		}
	}

	// Memory
	if vmem, err := mem.VirtualMemory(); err == nil {
		info.MemTotal = vmem.Total
		info.MemUsed = vmem.Used
		info.MemAvailable = vmem.Available
		info.MemPercent = vmem.UsedPercent
	}
	if smem, err := mem.SwapMemory(); err == nil {
		info.SwapTotal = smem.Total
		info.SwapUsed = smem.Used
		info.SwapPercent = smem.UsedPercent
	}

	// Disk usage
	if partitions, err := disk.Partitions(false); err == nil {
		for _, p := range partitions {
			usage, err := disk.Usage(p.Mountpoint)
			if err != nil {
				continue
			}
			info.Disks = append(info.Disks, types.DiskInfo{
				Device:      p.Device,
				MountPoint:  p.Mountpoint,
				FSType:      p.Fstype,
				Total:       usage.Total,
				Used:        usage.Used,
				Free:        usage.Free,
				UsedPercent: usage.UsedPercent,
			})
		}
	}

	// Network
	if io, err := net.IOCounters(false); err == nil && len(io) > 0 {
		info.NetSent = io[0].BytesSent
		info.NetRecv = io[0].BytesRecv

		now := time.Now()
		c.mu.Lock()
		if c.prevNetTime.Before(now) {
			elapsed := now.Sub(c.prevNetTime).Seconds()
			if elapsed > 0 {
				if io[0].BytesSent >= c.prevNetSent {
					info.NetSentRate = float64(io[0].BytesSent-c.prevNetSent) / elapsed
				}
				if io[0].BytesRecv >= c.prevNetRecv {
					info.NetRecvRate = float64(io[0].BytesRecv-c.prevNetRecv) / elapsed
				}
			}
			c.prevNetSent = io[0].BytesSent
			c.prevNetRecv = io[0].BytesRecv
			c.prevNetTime = now
		}
		c.mu.Unlock()
	}

	// Process count
	c.mu.Lock()
	safeMode := c.baotaSafeMode
	c.mu.Unlock()

	if safeMode {
		// 宝塔模式：轻量级进程计数，只读 /proc 目录条目数，不逐个读取进程状态
		if entries, err := os.ReadDir("/proc"); err == nil {
			count := 0
			for _, entry := range entries {
				if entry.IsDir() {
					name := entry.Name()
					if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
						count++
					}
				}
			}
			info.ProcessCount = count
		}
		// 宝塔模式：跳过 zombie 进程检测（需要逐个读取 /proc/{pid}/status）
		info.ZombieCount = 0
	} else {
		// 正常模式：完整进程扫描
		if procs, err := process.Processes(); err == nil {
			info.ProcessCount = len(procs)
			zombieCount := 0
			for _, p := range procs {
				if status, err := p.Status(); err == nil {
					if status[0] == "Z" || status[0] == "z" {
						zombieCount++
					}
				}
			}
			info.ZombieCount = zombieCount
		}
	}

	return info, nil
}

// CollectProcesses collects per-process metrics.
func (c *Collector) CollectProcesses(maxCount int) ([]types.ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	var result []types.ProcessInfo
	for i, p := range procs {
		if i >= maxCount {
			break
		}

		info := types.ProcessInfo{
			PID: p.Pid,
		}

		if name, err := p.Name(); err == nil {
			info.Name = name
		}
		if cmdline, err := p.Cmdline(); err == nil {
			info.Cmdline = cmdline
		}
		if cpuPercent, err := p.CPUPercent(); err == nil {
			info.CPUPercent = cpuPercent
		}
		if memPercent, err := p.MemoryPercent(); err == nil {
			info.MemPercent = float64(memPercent)
		}
		if memInfo, err := p.MemoryInfo(); err == nil {
			info.RSS = memInfo.RSS
			info.VMS = memInfo.VMS
		}
		if status, err := p.Status(); err == nil && len(status) > 0 {
			info.Status = status[0]
		}
		if createTime, err := p.CreateTime(); err == nil {
			info.CreateTime = time.UnixMilli(createTime)
		}
		if numThreads, err := p.NumThreads(); err == nil {
			info.NumThreads = numThreads
		}
		if ppid, err := p.Ppid(); err == nil {
			info.PPID = ppid
		}

		info.IsSystem = isSystemProcess(info.Name, info.PID)

		result = append(result, info)
	}

	return result, nil
}

// CollectMetrics collects all metrics and returns them as a slice.
func (c *Collector) CollectMetrics(sysInfo *types.SystemInfo, procs []types.ProcessInfo) []types.Metric {
	now := time.Now()
	var metrics []types.Metric

	// CPU metrics
	metrics = append(metrics, types.Metric{
		Type: types.MetricCPU, Name: "system.cpu_percent", Value: sysInfo.CPUPercent,
		Unit: "%", Timestamp: now,
	})
	metrics = append(metrics, types.Metric{
		Type: types.MetricCPU, Name: "system.load_avg_1", Value: sysInfo.LoadAvg1,
		Timestamp: now,
	})
	metrics = append(metrics, types.Metric{
		Type: types.MetricCPU, Name: "system.load_avg_5", Value: sysInfo.LoadAvg5,
		Timestamp: now,
	})
	metrics = append(metrics, types.Metric{
		Type: types.MetricCPU, Name: "system.load_avg_15", Value: sysInfo.LoadAvg15,
		Timestamp: now,
	})

	// Memory metrics
	metrics = append(metrics, types.Metric{
		Type: types.MetricMemory, Name: "system.mem_percent", Value: sysInfo.MemPercent,
		Unit: "%", Timestamp: now,
	})
	metrics = append(metrics, types.Metric{
		Type: types.MetricMemory, Name: "system.mem_available", Value: float64(sysInfo.MemAvailable),
		Unit: "bytes", Timestamp: now,
	})
	metrics = append(metrics, types.Metric{
		Type: types.MetricMemory, Name: "system.swap_percent", Value: sysInfo.SwapPercent,
		Unit: "%", Timestamp: now,
	})

	// Disk metrics
	for _, d := range sysInfo.Disks {
		labels := map[string]string{"mount": d.MountPoint, "device": d.Device}
		metrics = append(metrics, types.Metric{
			Type: types.MetricDisk, Name: "disk.used_percent", Value: d.UsedPercent,
			Unit: "%", Timestamp: now, Labels: labels,
		})
		metrics = append(metrics, types.Metric{
			Type: types.MetricDisk, Name: "disk.free", Value: float64(d.Free),
			Unit: "bytes", Timestamp: now, Labels: labels,
		})
	}

	// Network metrics
	metrics = append(metrics, types.Metric{
		Type: types.MetricNetwork, Name: "net.sent_rate", Value: sysInfo.NetSentRate,
		Unit: "bytes/s", Timestamp: now,
	})
	metrics = append(metrics, types.Metric{
		Type: types.MetricNetwork, Name: "net.recv_rate", Value: sysInfo.NetRecvRate,
		Unit: "bytes/s", Timestamp: now,
	})

	// Process metrics
	for _, p := range procs {
		labels := map[string]string{
			"pid":  fmt.Sprintf("%d", p.PID),
			"name": p.Name,
		}
		metrics = append(metrics, types.Metric{
			Type: types.MetricProcess, Name: "process.cpu_percent", Value: p.CPUPercent,
			Unit: "%", Timestamp: now, Labels: labels,
		})
		metrics = append(metrics, types.Metric{
			Type: types.MetricProcess, Name: "process.mem_percent", Value: p.MemPercent,
			Unit: "%", Timestamp: now, Labels: labels,
		})
		metrics = append(metrics, types.Metric{
			Type: types.MetricProcess, Name: "process.rss", Value: float64(p.RSS),
			Unit: "bytes", Timestamp: now, Labels: labels,
		})
	}

	// Zombie count
	metrics = append(metrics, types.Metric{
		Type: types.MetricProcess, Name: "system.zombie_count", Value: float64(sysInfo.ZombieCount),
		Timestamp: now,
	})

	return metrics
}

// isSystemProcess checks if a process is a critical system process.
func isSystemProcess(name string, pid int32) bool {
	if pid <= 2 {
		return true
	}

	systemProcesses := map[string]bool{
		"systemd":           true,
		"systemd-journald":  true,
		"systemd-logind":    true,
		"dbus-daemon":       true,
		"sshd":              true,
		"init":              true,
		"kthreadd":          true,
		"System":            true, // Windows
		"smss.exe":          true,
		"csrss.exe":         true,
		"wininit.exe":       true,
		"winlogon.exe":      true,
		"services.exe":      true,
		"lsass.exe":         true,
		"svchost.exe":       true,
		"serverguard-agent": true,
	}

	return systemProcesses[name]
}

// loadAvg returns the system load averages (Linux only).
func loadAvg() ([3]float64, error) {
	var load [3]float64
	if runtime.GOOS == "windows" {
		// Windows doesn't have load average, approximate from CPU
		percents, err := cpu.Percent(0, false)
		if err == nil && len(percents) > 0 {
			cores := float64(runtime.NumCPU())
			if cores > 0 {
				load[0] = percents[0] / 100 * cores
				load[1] = load[0]
				load[2] = load[0]
			}
		}
		return load, nil
	}
	// Linux: read from /proc/loadavg
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return load, err
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		load[0], _ = strconv.ParseFloat(fields[0], 64)
		load[1], _ = strconv.ParseFloat(fields[1], 64)
		load[2], _ = strconv.ParseFloat(fields[2], 64)
	}
	return load, nil
}
