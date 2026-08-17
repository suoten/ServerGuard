package resource

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

type GPUStatus struct {
	Index       int     `json:"index"`
	Name        string  `json:"name"`
	Temperature float64 `json:"temperature"`
	MemoryUsed  uint64  `json:"memory_used"`
	MemoryTotal uint64  `json:"memory_total"`
	Utilization float64 `json:"utilization"`
}

type GPUGuard struct {
	enabled        bool
	tempThreshold  float64
	memLeakPercent float64
	utilThreshold  float64
	history        map[int][]uint64
}

func NewGPUGuard() *GPUGuard {
	return &GPUGuard{
		enabled:        true,
		tempThreshold:  85,
		memLeakPercent: 150,
		utilThreshold:  95,
		history:        make(map[int][]uint64),
	}
}

func (g *GPUGuard) IsAvailable() bool {
	_, err := exec.LookPath("nvidia-smi")
	return err == nil
}

func (g *GPUGuard) GetGPUStatus() ([]GPUStatus, error) {
	cmd := exec.Command("nvidia-smi",
		"--query-gpu=index,name,temperature.gpu,memory.used,memory.total,utilization.gpu",
		"--format=csv,noheader,nounits")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi failed: %w", err)
	}

	var gpus []GPUStatus
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, ", ")
		if len(fields) < 6 {
			continue
		}
		idx, _ := strconv.Atoi(strings.TrimSpace(fields[0]))
		temp, _ := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		memUsed, _ := strconv.ParseUint(strings.TrimSpace(fields[3]), 10, 64)
		memTotal, _ := strconv.ParseUint(strings.TrimSpace(fields[4]), 10, 64)
		util, _ := strconv.ParseFloat(strings.TrimSpace(fields[5]), 64)

		gpus = append(gpus, GPUStatus{
			Index:       idx,
			Name:        strings.TrimSpace(fields[1]),
			Temperature: temp,
			MemoryUsed:  memUsed * 1024 * 1024,
			MemoryTotal: memTotal * 1024 * 1024,
			Utilization: util,
		})
	}
	return gpus, nil
}

func (g *GPUGuard) Check(ctx context.Context, bus interface {
	PublishAlert(types.AlertLevel, string, string, string, string)
}) {
	if !g.enabled || !g.IsAvailable() {
		return
	}

	gpus, err := g.GetGPUStatus()
	if err != nil {
		return
	}

	for _, gpu := range gpus {
		if gpu.Temperature > g.tempThreshold {
			bus.PublishAlert(types.AlertCritical, "resource",
				fmt.Sprintf("GPU温度过高: %s (GPU%d)", gpu.Name, gpu.Index),
				fmt.Sprintf("GPU%d %s 温度 %.0f°C 超过阈值 %.0f°C，建议降频或重启关联服务", gpu.Index, gpu.Name, gpu.Temperature, g.tempThreshold),
				"gpu-temp-001")
		}

		if gpu.MemoryTotal > 0 {
			memPercent := float64(gpu.MemoryUsed) / float64(gpu.MemoryTotal) * 100
			if memPercent > 95 {
				bus.PublishAlert(types.AlertWarning, "resource",
					fmt.Sprintf("GPU显存泄漏: %s (GPU%d)", gpu.Name, gpu.Index),
					fmt.Sprintf("GPU%d 显存使用 %.1f%%，可能存在泄漏，建议重启关联服务释放显存", gpu.Index, memPercent),
					"gpu-mem-leak-001")
			}
		}

		if gpu.Utilization > g.utilThreshold {
			bus.PublishAlert(types.AlertWarning, "resource",
				fmt.Sprintf("GPU利用率过高: %s (GPU%d)", gpu.Name, gpu.Index),
				fmt.Sprintf("GPU%d 利用率 %.1f%% 持续超阈值，可能需要降频", gpu.Index, gpu.Utilization),
				"gpu-util-001")
		}
	}
}

func (g *GPUGuard) RestartGPUProcess(gpuIndex int) error {
	cmd := exec.Command("nvidia-smi", "--gpu-reset", "-i", strconv.Itoa(gpuIndex))
	return cmd.Run()
}

type CPUStrikeTracker struct {
	strikes   map[int32]int
	maxStrike int
}

func NewCPUStrikeTracker() *CPUStrikeTracker {
	return &CPUStrikeTracker{
		strikes:   make(map[int32]int),
		maxStrike: 3,
	}
}

func (t *CPUStrikeTracker) ShouldKill(pid int32, cpuPercent float64, threshold float64) bool {
	if cpuPercent <= threshold {
		t.strikes[pid] = 0
		return false
	}
	t.strikes[pid]++
	return t.strikes[pid] >= t.maxStrike
}

func (t *CPUStrikeTracker) Reset(pid int32) {
	delete(t.strikes, pid)
}

type DiskCleaner struct {
	logRetentionDays   int
	tempRetentionDays  int
	cacheRetentionDays int
}

func NewDiskCleaner() *DiskCleaner {
	return &DiskCleaner{
		logRetentionDays:   7,
		tempRetentionDays:  30,
		cacheRetentionDays: 30,
	}
}

func (dc *DiskCleaner) CleanOldLogs(dir string) (int, error) {
	return dc.cleanOldFiles(dir, dc.logRetentionDays, []string{".log", ".log.gz", ".log.1", ".log.2.gz"})
}

func (dc *DiskCleaner) CleanTempFiles(dir string) (int, error) {
	return dc.cleanOldFiles(dir, dc.tempRetentionDays, []string{".tmp", ".temp"})
}

func (dc *DiskCleaner) CleanCache(dir string) (int, error) {
	return dc.cleanOldFiles(dir, dc.cacheRetentionDays, []string{".cache", ".lock"})
}

func (dc *DiskCleaner) cleanOldFiles(dir string, retentionDays int, extensions []string) (int, error) {
	cmd := exec.Command("find", dir, "-type", "f",
		"-mtime", fmt.Sprintf("+%d", retentionDays),
		"-name", "*.*",
		"-delete")
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (dc *DiskCleaner) CleanPackageManagerCache() error {
	var cmds []*exec.Cmd
	cmds = append(cmds, exec.Command("yum", "clean", "all"))
	cmds = append(cmds, exec.Command("apt-get", "clean"))
	cmds = append(cmds, exec.Command("pip", "cache", "purge"))
	cmds = append(cmds, exec.Command("npm", "cache", "clean", "--force"))

	for _, cmd := range cmds {
		_ = cmd.Run()
	}
	return nil
}

type MemSnapshotManager struct {
	snapshots map[int32][]string
	maxKeep   int
}

func NewMemSnapshotManager() *MemSnapshotManager {
	return &MemSnapshotManager{
		snapshots: make(map[int32][]string),
		maxKeep:   3,
	}
}

func (m *MemSnapshotManager) TakeSnapshot(pid int32, name string) string {
	timestamp := time.Now().Format("20060102-150405")
	snapshot := fmt.Sprintf("pid=%d,name=%s,ts=%s", pid, name, timestamp)
	m.snapshots[pid] = append(m.snapshots[pid], snapshot)
	if len(m.snapshots[pid]) > m.maxKeep {
		m.snapshots[pid] = m.snapshots[pid][len(m.snapshots[pid])-m.maxKeep:]
	}
	return snapshot
}

func (m *MemSnapshotManager) GetSnapshots(pid int32) []string {
	return m.snapshots[pid]
}
