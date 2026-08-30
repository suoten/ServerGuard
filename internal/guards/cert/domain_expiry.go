// Package cert — 域名注册到期监控。
//
// 证书还有 30 天、域名下周就过期——这种"证书没过期但网站照样打不开"的
// 事故比证书过期更隐蔽。本监控器随证书扫描周期（每日）对受监控证书的
// 域名做 WHOIS 到期查询：每域名 7 天最多查一次（WHOIS 有频率限制），
// 每轮最多查 5 个域名（whois 单次可达 15s，必须限流），结果落 KV
// 供巡检报告与面板读取；剩余 ≤30 天发布告警。
package cert

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	dnsguard "github.com/suoten/serverguard/internal/guards/dns"
	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/types"
)

const (
	domainExpiryKVPrefix = "domain_expiry:"
	domainCheckInterval  = 7 * 24 * time.Hour  // 每域名检查间隔（WHOIS 频率限制）
	domainMaxPerRun      = 5                   // 单轮最多查询数（限流）
	domainWarnDays       = 30                  // 剩余天数告警阈值
	domainReportDays     = 60                  // 巡检报告列出的阈值
)

// DomainExpiryState 单域名的最近一次到期检查结果（存 KV）。
type DomainExpiryState struct {
	Domain    string    `json:"domain"`
	DaysLeft  int       `json:"days_left"`
	CheckedAt time.Time `json:"checked_at"`
}

// DomainExpiryMonitor 域名到期监控器。
type DomainExpiryMonitor struct {
	store   *storage.Storage
	bus     *eventbus.EventBus
	checker *dnsguard.DomainExpiryChecker
	mu      sync.Mutex
	cursor  int // 轮转游标：域名多于一轮配额时按序推进，保证每个域名都会被轮到
}

// NewDomainExpiryMonitor 创建监控器。
func NewDomainExpiryMonitor(store *storage.Storage, bus *eventbus.EventBus) *DomainExpiryMonitor {
	return &DomainExpiryMonitor{
		store:   store,
		bus:     bus,
		checker: dnsguard.NewDomainExpiryChecker(),
	}
}

// RunDue 对给定域名执行一轮到期检查：
// 跳过 7 天内已查过的，单轮最多 domainMaxPerRun 个，总时长由 ctx 控制。
func (m *DomainExpiryMonitor) RunDue(ctx context.Context, domains []string) {
	if len(domains) == 0 || m.store == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// 去重 + 归一化
	seen := make(map[string]bool)
	var unique []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		unique = append(unique, d)
	}

	// 轮转起点：让每次检查从上次结束处继续，公平覆盖全部域名
	start := m.cursor % len(unique)
	checked := 0
	for i := 0; i < len(unique) && checked < domainMaxPerRun; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		domain := unique[(start+i)%len(unique)]

		kvKey := domainExpiryKVPrefix + domain
		var prev DomainExpiryState
		if v, err := m.store.Get(kvKey); err == nil && v != "" {
			if err := json.Unmarshal([]byte(v), &prev); err == nil &&
				time.Since(prev.CheckedAt) < domainCheckInterval {
				continue // 近 7 天已查过
			}
		}

		days, err := m.checker.CheckDomainExpiry(domain)
		state := DomainExpiryState{Domain: domain, DaysLeft: days, CheckedAt: time.Now()}
		if data, jerr := json.Marshal(state); jerr == nil {
			_ = m.store.Set(kvKey, string(data))
		}
		if err != nil {
			continue // whois 失败静默跳过（fail-close），下轮重试
		}
		checked++

		if days <= domainWarnDays {
			level := types.AlertWarning
			if days <= 7 {
				level = types.AlertCritical
			}
			advice := m.checker.ExpiryAdvice(domain, days)
			m.bus.PublishAlert(level, "cert",
				fmt.Sprintf("域名即将到期：%s 剩余 %d 天", domain, days),
				fmt.Sprintf("%s\n\n证书可以自动续期，但域名过期续费只能人工操作——请及时到注册商处理，否则网站/邮件都会中断。", advice),
				"domain-expiry-"+domain)
		}
	}
	// 推进游标（即使本轮没实际查询也前进，避免卡在同一批"未到期"域名上）
	m.cursor = (start + checked + len(unique)) % len(unique)
}

// GetDomainExpiryStates 读取全部域名到期状态（供巡检报告使用），按剩余天数升序。
func GetDomainExpiryStates(store *storage.Storage) []DomainExpiryState {
	if store == nil {
		return nil
	}
	keys, err := store.GetKeysByPrefix(domainExpiryKVPrefix)
	if err != nil {
		return nil
	}
	var out []DomainExpiryState
	for _, k := range keys {
		v, err := store.Get(k)
		if err != nil || v == "" {
			continue
		}
		var st DomainExpiryState
		if err := json.Unmarshal([]byte(v), &st); err != nil {
			continue
		}
		out = append(out, st)
	}
	for i := 1; i < len(out); i++ { // 插入排序：条目少且近乎有序
		for j := i; j > 0 && out[j].DaysLeft < out[j-1].DaysLeft; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
