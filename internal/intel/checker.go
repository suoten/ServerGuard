package intel

import (
	"context"
	"sync"
	"time"
)

// defaultCacheTTL 本地恶意 IP 缓存的默认过期时间，避免对同一 IP 反复发起外部请求。
const defaultCacheTTL = 24 * time.Hour

// cacheEntry 本地恶意 IP 缓存条目。
type cacheEntry struct {
	info   *IPInfo
	expiry time.Time
}

// IntelChecker 威胁情报查询封装。
// 持有 *IntelManager 聚合各情报源，并为恶意 IP 提供带过期时间的本地缓存，
// 外部网络调用全部 fail-close：无 Key / 网络失败时静默跳过，绝不阻塞、绝不 panic。
type IntelChecker struct {
	manager *IntelManager
	mu      sync.RWMutex
	cache   map[string]cacheEntry
	ttl     time.Duration
}

// NewIntelChecker 创建情报查询器，内部创建 IntelManager 并注册各情报源。
// 各源无需 API Key 也可工作（源在无 Key / 失败时返回 error，由查询方法吞掉）。
func NewIntelChecker() *IntelChecker {
	m := NewIntelManager()
	m.AddSource("abuseipdb", NewAbuseIPDBClient(""))
	m.AddSource("otx", NewOTXClient(""))
	m.AddSource("nvd", NewNVDClient(""))
	m.AddSource("cnvd", NewCNVDClient(""))
	m.AddSource("exploitdb", NewExploitDBClient())

	return &IntelChecker{
		manager: m,
		cache:   make(map[string]cacheEntry),
		ttl:     defaultCacheTTL,
	}
}

// negativeCacheTTL 查询失败/无情报结果的负缓存时长。
// 短于正缓存：情报可能有变化；但必须缓存——否则同一攻击 IP 的每个事件
// 都会重新触发外部 HTTP 调用（攻击日志里同一 IP 往往出现几十上百次）。
const negativeCacheTTL = 1 * time.Hour

// maxCacheEntries 缓存条目上限，超过时惰性清理过期项。
// 公网服务器会被扫描器塞入大量一次性 IP，不设上限就是慢性内存泄漏。
const maxCacheEntries = 4096

// CheckIP 查询 IP 的恶意情报信息。
// 先查本地缓存（含负缓存），命中且未过期直接返回；否则调用 manager.QueryIP，
// 成功写入正缓存、失败写入负缓存——外部网络调用全部 fail-close。
func (c *IntelChecker) CheckIP(ctx context.Context, ip string) *IPInfo {
	if c == nil || c.manager == nil || ip == "" {
		return nil
	}

	c.mu.RLock()
	entry, ok := c.cache[ip]
	c.mu.RUnlock()
	now := time.Now()
	if ok && entry.expiry.After(now) {
		return entry.info
	}

	info, err := c.manager.QueryIP(ip)

	c.mu.Lock()
	// 惰性清理：条目数超限时删除全部过期项
	if len(c.cache) > maxCacheEntries {
		for k, e := range c.cache {
			if e.expiry.Before(now) {
				delete(c.cache, k)
			}
		}
	}
	if err != nil || info == nil {
		// 负缓存：短 TTL 内不再对同一 IP 重复发起注定失败的外部查询
		c.cache[ip] = cacheEntry{info: nil, expiry: now.Add(negativeCacheTTL)}
		c.mu.Unlock()
		return nil
	}
	c.cache[ip] = cacheEntry{info: info, expiry: now.Add(c.ttl)}
	c.mu.Unlock()

	return info
}

// CheckCVE 查询组件/版本的 CVE 漏洞信息。
// 查询失败时返回空切片（不阻塞调用方）。
func (c *IntelChecker) CheckCVE(ctx context.Context, component, version string) []CVEInfo {
	if c == nil || c.manager == nil {
		return nil
	}
	cves, err := c.manager.QueryCVE(component, version)
	if err != nil {
		return nil
	}
	if cves == nil {
		return []CVEInfo{}
	}
	return cves
}
