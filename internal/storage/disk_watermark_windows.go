//go:build windows

package storage

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// diskUsage 返回指定数据库文件所在磁盘的使用情况（Windows 实现）。
func diskUsage(dbPath string) DiskWatermarkResult {
	dir := filepath.Dir(dbPath)
	if dir == "" {
		dir = "."
	}

	dirUTF16, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return DiskWatermarkResult{}
	}

	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(
		dirUTF16,
		&freeBytesAvailable,
		&totalBytes,
		&totalFreeBytes,
	); err != nil {
		_ = unsafe.Sizeof(err)
		return DiskWatermarkResult{}
	}

	used := totalBytes - freeBytesAvailable
	var usedPercent float64
	if totalBytes > 0 {
		usedPercent = float64(used) / float64(totalBytes) * 100
	}

	return DiskWatermarkResult{
		TotalBytes:  totalBytes,
		UsedBytes:   used,
		FreeBytes:   freeBytesAvailable,
		UsedPercent: usedPercent,
	}
}
