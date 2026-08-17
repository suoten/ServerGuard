package storage

import (
	"fmt"
	"time"
)

// WatermarkLevel 磁盘水位等级
type WatermarkLevel int

const (
	WatermarkNormal   WatermarkLevel = iota // 正常（<80%）
	WatermarkHigh                           // 高水位（>=80%）
	WatermarkCritical                       // 临界（>=90%）
)

// DBSizeLimit 数据库体积硬上限（200MB）
const DBSizeLimit = 200 * 1024 * 1024

// DBSizeResult DB 体积检查结果
type DBSizeResult struct {
	SizeBytes int64
	SizeMB    float64
	CanWrite  bool
	Reason    string
}

// CheckDBSize 返回 DB 体积和是否可写入。
// 超过 200MB 拒绝写入新指标并触发告警。
func (s *Storage) CheckDBSize() DBSizeResult {
	size := s.GetDBSize()
	result := DBSizeResult{
		SizeBytes: size,
		SizeMB:    float64(size) / (1024 * 1024),
		CanWrite:  true,
	}
	if size >= DBSizeLimit {
		result.CanWrite = false
		result.Reason = fmt.Sprintf("DB体积 %.2fMB 超过上限 %dMB，拒绝写入新指标", result.SizeMB, DBSizeLimit/(1024*1024))
	}
	return result
}

// DiskWatermarkResult 磁盘水位检查结果
type DiskWatermarkResult struct {
	TotalBytes  uint64
	UsedBytes   uint64
	FreeBytes   uint64
	UsedPercent float64
	Level       WatermarkLevel
}

// CheckDiskWatermark 返回数据库所在磁盘的使用率和水位等级。
// normal: <80%, high: >=80%, critical: >=90%
// 平台特定实现由 disk_watermark_linux.go / disk_watermark_windows.go 提供。
func (s *Storage) CheckDiskWatermark() DiskWatermarkResult {
	result := diskUsage(s.path)
	result.Level = classifyWatermark(result.UsedPercent)
	return result
}

// classifyWatermark 根据使用率分类水位等级
func classifyWatermark(usedPercent float64) WatermarkLevel {
	if usedPercent >= 90 {
		return WatermarkCritical
	}
	if usedPercent >= 80 {
		return WatermarkHigh
	}
	return WatermarkNormal
}

// String 返回水位等级的字符串表示
func (w WatermarkLevel) String() string {
	switch w {
	case WatermarkHigh:
		return "high"
	case WatermarkCritical:
		return "critical"
	default:
		return "normal"
	}
}

// DBHealthStatus 数据库健康状态汇总
type DBHealthStatus struct {
	DBSize        DBSizeResult
	DiskWatermark DiskWatermarkResult
	CheckedAt     time.Time
}

// CheckDBHealth 返回数据库健康状态汇总（体积 + 磁盘水位）
func (s *Storage) CheckDBHealth() DBHealthStatus {
	return DBHealthStatus{
		DBSize:        s.CheckDBSize(),
		DiskWatermark: s.CheckDiskWatermark(),
		CheckedAt:     time.Now(),
	}
}
