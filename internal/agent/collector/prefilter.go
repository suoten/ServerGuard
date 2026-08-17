package collector

import (
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// PreFilter 预过滤层：在规则匹配前过滤掉不需要关注的进程
// 目标：减少 80% 匹配量
type PreFilter struct {
	whitelistProcessNames map[string]bool // 白名单进程名（不监控）
	minCPU                float64         // CPU 使用率下限（%）
	minMem                float64         // 内存使用量下限（MB）
}

// NewPreFilter 创建预过滤器
func NewPreFilter() *PreFilter {
	pf := &PreFilter{
		whitelistProcessNames: make(map[string]bool),
		minCPU:                1.0,  // CPU < 1% 的进程跳过
		minMem:                10.0, // 内存 < 10MB 的进程跳过
	}

	// 默认白名单进程（系统关键进程，不监控）
	defaultWhitelist := []string{
		"kthreadd", "ksoftirqd", "kworker", "kcompactd", "ksmd",
		"rcu_sched", "rcu_bh", "rcu_kthread", "migration",
		"watchdog", "kdevtmpfs", "netns", "inet_frag",
		"systemd", "systemd-journal", "systemd-udevd",
		"svchost.exe", "services.exe", "lsass.exe", "winlogon.exe",
		"csrss.exe", "smss.exe", "wininit.exe", "fontdrvhost.exe",
		"dwm.exe", "RuntimeBroker.exe", "sihost.exe", "taskhostw.exe",
	}
	for _, name := range defaultWhitelist {
		pf.whitelistProcessNames[name] = true
	}

	return pf
}

// AddWhitelist 添加白名单进程
func (pf *PreFilter) AddWhitelist(name string) {
	pf.whitelistProcessNames[name] = true
}

// RemoveWhitelist 移除白名单进程
func (pf *PreFilter) RemoveWhitelist(name string) {
	delete(pf.whitelistProcessNames, name)
}

// SetThresholds 设置过滤阈值
func (pf *PreFilter) SetThresholds(minCPU, minMemMB float64) {
	pf.minCPU = minCPU
	pf.minMem = minMemMB
}

// FilterProcess 判断进程是否应该被监控
// 返回 true 表示保留（需要监控），false 表示过滤掉
func (pf *PreFilter) FilterProcess(name string, cpuPercent float64, memMB float64) bool {
	// 1. 白名单进程跳过
	if pf.whitelistProcessNames[name] {
		return false
	}

	// 2. 内核线程跳过（Linux: 名字以 k 开头且在方括号中）
	if runtime.GOOS == "linux" && strings.HasPrefix(name, "k") {
		return false
	}

	// 3. 空闲进程跳过（CPU < minCPU 且 内存 < minMem）
	if cpuPercent < pf.minCPU && memMB < pf.minMem {
		return false
	}

	return true
}

// FilterProcesses 批量过滤进程，返回保留的进程列表
func (pf *PreFilter) FilterProcesses(procs []*process.Process) ([]*process.Process, error) {
	var result []*process.Process
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}

		cpuPercent, _ := p.CPUPercent()
		memInfo, _ := p.MemoryInfo()
		var memMB float64
		if memInfo != nil {
			memMB = float64(memInfo.RSS) / 1024 / 1024
		}

		if pf.FilterProcess(name, cpuPercent, memMB) {
			result = append(result, p)
		}
	}
	return result, nil
}

// Stats 预过滤统计
type PreFilterStats struct {
	Total    int // 总进程数
	Filtered int // 过滤掉的进程数
	Kept     int // 保留的进程数
}

// FilterProcessesWithStats 批量过滤并返回统计信息
func (pf *PreFilter) FilterProcessesWithStats(procs []*process.Process) ([]*process.Process, PreFilterStats, error) {
	stats := PreFilterStats{Total: len(procs)}
	var result []*process.Process

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			stats.Filtered++
			continue
		}

		cpuPercent, _ := p.CPUPercent()
		memInfo, _ := p.MemoryInfo()
		var memMB float64
		if memInfo != nil {
			memMB = float64(memInfo.RSS) / 1024 / 1024
		}

		if pf.FilterProcess(name, cpuPercent, memMB) {
			result = append(result, p)
			stats.Kept++
		} else {
			stats.Filtered++
		}
	}

	return result, stats, nil
}
