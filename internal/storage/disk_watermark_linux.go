//go:build linux

package storage

import (
	"path/filepath"
	"syscall"
)

// diskUsage 返回指定数据库文件所在磁盘的使用情况（Linux 实现）。
func diskUsage(dbPath string) DiskWatermarkResult {
	dir := filepath.Dir(dbPath)
	if dir == "" {
		dir = "."
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return DiskWatermarkResult{}
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	var usedPercent float64
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100
	}

	return DiskWatermarkResult{
		TotalBytes:  total,
		UsedBytes:   used,
		FreeBytes:   free,
		UsedPercent: usedPercent,
	}
}
