package collector

import (
	"fmt"
	"os"
	"runtime"
	"sort"
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
// 向宝塔学习：缓存不易变的数据（分区列表、host info），避免每轮都 syscall
type Collector struct {
	mu            sync.Mutex
	prevNetSent   uint64
	prevNetRecv   uint64
	prevNetTime   time.Time
	prevCPUTime   time.Time
	hostInfo      *host.InfoStat
	processCount  int
	baotaSafeMode bool // 宝塔安全模式：跳过昂贵的 process.Processes() 调用

	// 缓存：分区列表不会频繁变化，避免每轮都 disk.Partitions() syscall
	partitions     []disk.PartitionStat
	partitionsTime time.Time

	// 进程列表缓存：正常模式下不是每轮都需要完整进程列表
	// 宝塔的做法：只在需要时扫描进程，不是每 5 秒扫一遍
	procCache      []types.ProcessInfo
	procCacheTime  time.Time
	procCacheTTL   time.Duration // 进程缓存有效期，默认 30s

	// zombie 进程检测降频：不需要每轮都遍历全部进程查 zombie
	// 宝塔的做法：低频检查即可，zombie 不会突然大量出现
	zombieCheckTime time.Time
	zombieCache     int
}

// New creates a new Collector instance.
func New() *Collector {
	return &Collector{
		prevNetTime:   time.Now(),
		procCacheTTL: 30 * time.Second, // 进程列表缓存 30 秒，减少 syscall
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
	// 向宝塔学习：不要为了获取 CPU% 而阻塞 200ms
	// 改用 100ms 间隔——足够获取趋势数据，减少阻塞时间
	cores, _ := cpu.Counts(true)
	info.CPUCores = cores
	cpuPercent, err := cpu.Percent(100*time.Millisecond, false)
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

	// Disk usage — 分区列表缓存，避免每轮都 disk.Partitions() syscall
	// 分区列表不会频繁变化，缓存 10 分钟
	c.mu.Lock()
	partitions := c.partitions
	if len(partitions) == 0 || time.Since(c.partitionsTime) > 10*time.Minute {
		if p, err := disk.Partitions(false); err == nil {
			c.partitions = p
			c.partitionsTime = time.Now()
			partitions = p
		}
	}
	c.mu.Unlock()

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
		// 向宝塔学习：zombie 检测降频——不需要每轮都遍历全部进程
		// zombie 不会突然大量出现，30 秒检测一次足够
		if time.Since(c.zombieCheckTime) > 30*time.Second {
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
				c.zombieCache = zombieCount
				c.zombieCheckTime = time.Now()
			}
		} else {
			// 使用缓存的 zombie 数量
			info.ZombieCount = c.zombieCache
			// 进程总数用 /proc 目录计数（轻量）
			if entries, err := os.ReadDir("/proc"); err == nil {
				count := 0
				for _, entry := range entries {
					if entry.IsDir() {
						if _, err := strconv.Atoi(entry.Name()); err == nil {
							count++
						}
					}
				}
				info.ProcessCount = count
			}
		}
	}

	return info, nil
}

// CollectProcesses collects per-process metrics.
// 向宝塔学习：进程列表缓存复用——不是每轮采集都需要完整进程列表
// 在缓存有效期内（默认 30s），直接返回缓存结果，避免每 5 秒调用 process.Processes()
//
// 重要：必须先全量读取进程详情、按 CPU 占用降序排序后再截断到 maxCount。
// 原实现按 PID 升序遍历并在达到 maxCount 时提前 break——PID 与资源占用无关，
// 高 CPU 的异常进程（挖矿、失控 worker）很可能 PID 靠后而永远不被看到，
// 导致"CPU 超限保护/内存泄漏拦截"规则对真正的肇事进程失明。
func (c *Collector) CollectProcesses(maxCount int) ([]types.ProcessInfo, error) {
	c.mu.Lock()
	// 检查缓存是否有效
	if len(c.procCache) > 0 && time.Since(c.procCacheTime) < c.procCacheTTL {
		result := c.procCache
		c.mu.Unlock()
		// 如果 maxCount 小于缓存长度，截断返回
		if maxCount > 0 && len(result) > maxCount {
			result = result[:maxCount]
		}
		return result, nil
	}
	c.mu.Unlock()

	// 缓存失效，重新采集
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	result := make([]types.ProcessInfo, 0, len(procs))
	for _, p := range procs {
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

	// 按资源占用降序排序后截断，保证 maxCount 内一定是"最值得关注的进程"
	sort.Slice(result, func(i, j int) bool {
		if result[i].CPUPercent != result[j].CPUPercent {
			return result[i].CPUPercent > result[j].CPUPercent
		}
		return result[i].MemPercent > result[j].MemPercent
	})
	if maxCount > 0 && len(result) > maxCount {
		result = result[:maxCount]
	}

	// 更新缓存（缓存保存截断后的结果即可，调用方语义一致）
	c.mu.Lock()
	c.procCache = result
	c.procCacheTime = time.Now()
	c.mu.Unlock()

	return result, nil
}

// CollectMetrics collects all metrics and returns them as a slice.
// 向宝塔学习：预分配 slice 容量，避免 append 扩容时的反复拷贝
func (c *Collector) CollectMetrics(sysInfo *types.SystemInfo, procs []types.ProcessInfo) []types.Metric {
	now := time.Now()
	// 预分配容量：系统指标 ~12 个 + 每磁盘 2 个 + 每进程 3 个
	estimatedCap := 12 + len(sysInfo.Disks)*2 + len(procs)*3
	metrics := make([]types.Metric, 0, estimatedCap)

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
	// 向宝塔学习：只记录有意义的进程指标，跳过低价值进程
	// 原来每个进程都生成 3 个 Metric（CPU/内存/RSS），但大量进程 CPU=0.0% 内存=0.1%，
	// 这些数据写入库中毫无价值还浪费存储和 IO
	for _, p := range procs {
		// 跳过 CPU 和内存都极低的进程
		if p.CPUPercent < 0.1 && p.MemPercent < 0.5 {
			continue
		}
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
