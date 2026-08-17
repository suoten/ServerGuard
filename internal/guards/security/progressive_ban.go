package security

import (
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// BanLevel 封禁等级
type BanLevel int

const (
	BanLevelNone   BanLevel = iota // 未封禁
	BanLevelLimit                  // 限速
	BanLevelShort                  // 短期 1h
	BanLevelLong                   // 长期 24h
)

func (l BanLevel) String() string {
	switch l {
	case BanLevelLimit:
		return "limit"
	case BanLevelShort:
		return "short"
	case BanLevelLong:
		return "long"
	default:
		return "none"
	}
}

// ProgressiveBanRecord 渐进式封禁记录
type ProgressiveBanRecord struct {
	IP          string
	Level       BanLevel
	BannedAt    time.Time
	ExpiresAt   time.Time
	AttackCount int // 封禁期间攻击次数
}

// ProgressiveBanManager 渐进式封禁管理器。
// 三档递进：首次→限速，5min 内 5 次→短期 1h，封禁期间再攻击→升级 24h。
type ProgressiveBanManager struct {
	mu       sync.Mutex
	eventBus *eventbus.EventBus
	records  map[string]*ProgressiveBanRecord // IP -> record
}

// NewProgressiveBanManager 创建渐进式封禁管理器。
func NewProgressiveBanManager(bus *eventbus.EventBus) *ProgressiveBanManager {
	return &ProgressiveBanManager{
		eventBus: bus,
		records:  make(map[string]*ProgressiveBanRecord),
	}
}

// RecordAttack 记录一次攻击事件，返回应执行的封禁动作。
func (m *ProgressiveBanManager) RecordAttack(ip string, attackType string) BanLevel {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	record, ok := m.records[ip]

	if !ok || now.After(record.ExpiresAt) {
		// 首次攻击或上次封禁已过期 → 限速
		record = &ProgressiveBanRecord{
			IP:        ip,
			Level:     BanLevelLimit,
			BannedAt:  now,
			ExpiresAt: now.Add(10 * time.Minute), // 限速 10min
		}
		m.records[ip] = record
		m.publishBanAlert(ip, attackType, record)
		return BanLevelLimit
	}

	// 已有封禁记录，检查是否在封禁期间再次攻击
	record.AttackCount++

	switch record.Level {
	case BanLevelLimit:
		// 限速期间再攻击 → 升级到短期 1h
		record.Level = BanLevelShort
		record.BannedAt = now
		record.ExpiresAt = now.Add(1 * time.Hour)
		m.publishBanAlert(ip, attackType, record)
		return BanLevelShort

	case BanLevelShort:
		// 短期封禁期间再攻击 → 升级到长期 24h
		record.Level = BanLevelLong
		record.BannedAt = now
		record.ExpiresAt = now.Add(24 * time.Hour)
		m.publishBanAlert(ip, attackType, record)
		return BanLevelLong

	case BanLevelLong:
		// 已是最高等级，延长封禁
		record.ExpiresAt = now.Add(24 * time.Hour)
		return BanLevelLong
	}

	return record.Level
}

// GetBanLevel 获取指定 IP 的当前封禁等级。
func (m *ProgressiveBanManager) GetBanLevel(ip string) BanLevel {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, ok := m.records[ip]
	if !ok {
		return BanLevelNone
	}
	if time.Now().After(record.ExpiresAt) {
		return BanLevelNone
	}
	return record.Level
}

// IsBanned 检查 IP 是否被封禁。
func (m *ProgressiveBanManager) IsBanned(ip string) bool {
	return m.GetBanLevel(ip) != BanLevelNone && m.GetBanLevel(ip) != BanLevelLimit
}

// Unban 解封指定 IP。
func (m *ProgressiveBanManager) Unban(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, ip)
}

// GetBannedIPs 返回所有已封禁的 IP。
func (m *ProgressiveBanManager) GetBannedIPs() []ProgressiveBanRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []ProgressiveBanRecord
	now := time.Now()
	for _, record := range m.records {
		if now.Before(record.ExpiresAt) {
			result = append(result, *record)
		}
	}
	return result
}

// Cleanup 清理过期的封禁记录。
func (m *ProgressiveBanManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for ip, record := range m.records {
		if now.After(record.ExpiresAt) {
			delete(m.records, ip)
		}
	}
}

// publishBanAlert 发布封禁告警。
func (m *ProgressiveBanManager) publishBanAlert(ip, attackType string, record *ProgressiveBanRecord) {
	if m.eventBus == nil {
		return
	}
	duration := record.ExpiresAt.Sub(record.BannedAt)
	m.eventBus.PublishAlert(types.AlertWarning, "security",
		fmt.Sprintf("IP封禁 (%s): %s", record.Level, ip),
		fmt.Sprintf("IP %s 因 %s 被封禁，等级: %s，时长: %v",
			ip, attackType, record.Level, duration),
		"brute-force-002")
}