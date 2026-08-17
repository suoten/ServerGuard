package executor

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/suoten/serverguard/internal/types"
)

// rootcause.go —— 告警根因分析。
//
// 自动修复动作执行时抓取系统现场（内存/磁盘/Top 进程），
// 按动作类型用启发式规则推断"可能原因"，附在动作记录与告警通知中。
// 所有推断均标注为自动推测，避免误导运维判断。

type procSnapshot struct {
	name string
	cpu  float64
	rss  uint64
}

// analyzeRootCause 生成根因分析文本。采集失败时返回空串（不影响主流程）。
func (e *Executor) analyzeRootCause(action types.Action, target *types.GuardTarget, rule *types.Rule) string {
	// 只对有现场分析价值的动作类型生成
	switch action.Type {
	case types.ActionRestart, types.ActionKill, types.ActionSigTerm, types.ActionSigKill, types.ActionCleanDisk:
	default:
		return ""
	}

	vm, _ := mem.VirtualMemory()
	memPct := 0.0
	swapPct := 0.0
	if vm != nil {
		memPct = vm.UsedPercent
	}
	if sm, err := mem.SwapMemory(); err == nil && sm != nil {
		swapPct = sm.UsedPercent
	}
	diskPct := maxDiskUsage()

	topMem, topCPU := topProcesses()

	// ── 现场摘要 ──
	var ctx strings.Builder
	fmt.Fprintf(&ctx, "【现场快照】内存 %.0f%%", memPct)
	if swapPct > 0 {
		fmt.Fprintf(&ctx, "，Swap %.0f%%", swapPct)
	}
	if diskPct > 0 {
		fmt.Fprintf(&ctx, "，磁盘 %.0f%%", diskPct)
	}
	if len(topMem) > 0 {
		fmt.Fprintf(&ctx, "\n内存大户：%s", formatProcs(topMem, true))
	}
	if len(topCPU) > 0 {
		fmt.Fprintf(&ctx, "\nCPU 大户：%s", formatProcs(topCPU, false))
	}

	// ── 按动作类型推断可能原因 ──
	var causes []string
	switch action.Type {
	case types.ActionRestart:
		causes = restartCauses(memPct, swapPct, diskPct, topMem, target)
	case types.ActionKill, types.ActionSigTerm, types.ActionSigKill:
		causes = killCauses(target, memPct)
	case types.ActionCleanDisk:
		causes = cleanDiskCauses(diskPct)
	}

	var sb strings.Builder
	sb.WriteString("\n\n🧠 根因分析（自动推测，仅供参考）\n")
	if len(causes) > 0 {
		for i, c := range causes {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, c)
		}
	} else {
		sb.WriteString("未发现典型的资源型诱因，可能是进程内部错误、配置变更或依赖服务异常，建议查看服务自身日志。\n")
	}
	sb.WriteString(ctx.String())
	return sb.String()
}

// restartCauses 服务重启类动作的推断。
func restartCauses(memPct, swapPct, diskPct float64, topMem []procSnapshot, target *types.GuardTarget) []string {
	var causes []string
	switch {
	case memPct >= 95:
		causes = append(causes, fmt.Sprintf("内存压力极高（%.0f%%），目标进程很可能被系统 OOM Killer 终止", memPct))
	case memPct >= 90 && swapPct >= 50:
		causes = append(causes, fmt.Sprintf("内存 %.0f%% 且 Swap 已用 %.0f%%，系统处于换页抖动边缘，进程可能因分配失败崩溃", memPct, swapPct))
	}
	if diskPct >= 95 {
		causes = append(causes, fmt.Sprintf("磁盘使用率 %.0f%% 接近写满，服务可能因无法写入日志/数据文件而退出", diskPct))
	}
	// 目标进程本身是内存大户 → 疑似内存泄漏
	if target != nil && target.ProcessName != "" {
		for _, p := range topMem {
			if p.name == target.ProcessName && p.rss > 500*1024*1024 {
				causes = append(causes, fmt.Sprintf("目标进程 %s 自身占用内存 %.1f MB，怀疑存在内存泄漏，建议关注其增长趋势", p.name, float64(p.rss)/1024/1024))
				break
			}
		}
	}
	return causes
}

// killCauses 进程查杀类动作的推断。
func killCauses(target *types.GuardTarget, memPct float64) []string {
	var causes []string
	if target != nil {
		causes = append(causes, fmt.Sprintf("目标进程 %s 触发资源阈值规则被查杀", target.Name))
	}
	if memPct >= 90 {
		causes = append(causes, fmt.Sprintf("系统内存 %.0f%% 处于高压状态，进程资源竞争加剧", memPct))
	}
	return causes
}

// cleanDiskCauses 磁盘清理类动作的推断。
func cleanDiskCauses(diskPct float64) []string {
	if diskPct >= 90 {
		return []string{fmt.Sprintf("磁盘使用率 %.0f%% 触发清理；建议使用「大文件扫描」定位空间占用大头，并关注磁盘写满预测", diskPct)}
	}
	return nil
}

// maxDiskUsage 返回最高的磁盘使用率（跨平台，失败返回 0）。
func maxDiskUsage() float64 {
	paths := []string{"/"}
	if runtime.GOOS == "windows" {
		paths = []string{"C:\\"}
	}
	maxPct := 0.0
	for _, p := range paths {
		if u, err := disk.Usage(p); err == nil && u != nil && u.UsedPercent > maxPct {
			maxPct = u.UsedPercent
		}
	}
	return maxPct
}

// topProcesses 返回内存 Top3 与 CPU Top2 进程快照。失败返回空。
func topProcesses() (topMem, topCPU []procSnapshot) {
	procs, err := process.Processes()
	if err != nil {
		return nil, nil
	}
	snaps := make([]procSnapshot, 0, len(procs))
	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		cpuPct, _ := p.CPUPercent()
		memInfo, _ := p.MemoryInfo()
		var rss uint64
		if memInfo != nil {
			rss = memInfo.RSS
		}
		snaps = append(snaps, procSnapshot{name: name, cpu: cpuPct, rss: rss})
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].rss > snaps[j].rss })
	if len(snaps) > 3 {
		topMem = snaps[:3]
	} else {
		topMem = snaps
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].cpu > snaps[j].cpu })
	if len(snaps) > 2 {
		topCPU = snaps[:2]
	} else {
		topCPU = snaps
	}
	return topMem, topCPU
}

// formatProcs 格式化进程快照列表。
func formatProcs(procs []procSnapshot, byMem bool) string {
	parts := make([]string, 0, len(procs))
	for _, p := range procs {
		if byMem {
			parts = append(parts, fmt.Sprintf("%s(%.0fMB)", p.name, float64(p.rss)/1024/1024))
		} else {
			parts = append(parts, fmt.Sprintf("%s(%.0f%%)", p.name, p.cpu))
		}
	}
	return strings.Join(parts, "、")
}
