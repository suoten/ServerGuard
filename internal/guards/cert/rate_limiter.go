package cert

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type ACMERateLimiter struct {
	mu               sync.RWMutex
	domainLastRenew  map[string]time.Time
	domainRetryQueue map[string]int
	cache            map[string]time.Time
	cacheTTL         time.Duration
	minInterval      time.Duration
	maxRetries       int
}

func NewACMERateLimiter() *ACMERateLimiter {
	return &ACMERateLimiter{
		domainLastRenew:  make(map[string]time.Time),
		domainRetryQueue: make(map[string]int),
		cache:            make(map[string]time.Time),
		cacheTTL:         30 * 24 * time.Hour,
		minInterval:      1 * time.Hour,
		maxRetries:       3,
	}
}

func (r *ACMERateLimiter) CanRenew(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	last, exists := r.domainLastRenew[domain]
	if !exists {
		return true
	}
	return time.Since(last) >= r.minInterval
}

func (r *ACMERateLimiter) RecordRenew(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domainLastRenew[domain] = time.Now()
	r.domainRetryQueue[domain] = 0
	r.cache[domain] = time.Now()
}

func (r *ACMERateLimiter) RecordFailure(domain string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domainRetryQueue[domain]++
	return r.domainRetryQueue[domain] >= r.maxRetries
}

func (r *ACMERateLimiter) GetRetryDelay(domain string) time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	retries := r.domainRetryQueue[domain]
	return time.Duration(1<<uint(retries)) * time.Hour
}

func (r *ACMERateLimiter) ShouldRenewNow(domain string, daysUntilExpiry int) bool {
	if daysUntilExpiry > 14 {
		return false
	}
	if daysUntilExpiry <= 3 {
		return true
	}
	randomDelay := time.Duration(rand.Intn(7)) * 24 * time.Hour
	estimatedExpiry := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return time.Now().Add(randomDelay).After(estimatedExpiry.Add(-14 * 24 * time.Hour))
}

func (r *ACMERateLimiter) IsCached(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cachedAt, exists := r.cache[domain]
	if !exists {
		return false
	}
	return time.Since(cachedAt) < r.cacheTTL
}

func (r *ACMERateLimiter) ClearCache(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, domain)
}

type CADegradationChain struct {
	primary   string
	secondary []string
	current   int
}

func NewCADegradationChain() *CADegradationChain {
	return &CADegradationChain{
		primary:   "letsencrypt",
		secondary: []string{"zerossl", "trustasia"},
	}
}

func (c *CADegradationChain) GetCurrent() string {
	if c.current == 0 {
		return c.primary
	}
	if c.current-1 < len(c.secondary) {
		return c.secondary[c.current-1]
	}
	return ""
}

func (c *CADegradationChain) Degrade() string {
	c.current++
	return c.GetCurrent()
}

func (c *CADegradationChain) Reset() {
	c.current = 0
}

func (c *CADegradationChain) IsExhausted() bool {
	return c.current > len(c.secondary)
}

type CertChainValidator struct{}

func NewCertChainValidator() *CertChainValidator { return &CertChainValidator{} }

type CertChainIssue struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

func (v *CertChainValidator) ValidateKeyLength(keyBits int) []CertChainIssue {
	var issues []CertChainIssue
	if keyBits < 2048 {
		issues = append(issues, CertChainIssue{
			Type:       "weak_key",
			Severity:   "high",
			Message:    fmt.Sprintf("密钥长度 %d 位，低于推荐的 2048 位", keyBits),
			Suggestion: "使用至少 2048 位的 RSA 密钥或 256 位的 ECC 密钥",
		})
	}
	return issues
}

func (v *CertChainValidator) ValidateSignatureAlgorithm(algo string) []CertChainIssue {
	var issues []CertChainIssue
	if algo == "SHA-1" {
		issues = append(issues, CertChainIssue{
			Type:       "weak_algorithm",
			Severity:   "high",
			Message:    "使用弱签名算法 SHA-1",
			Suggestion: "更换为 SHA-256 或更高版本的签名算法",
		})
	}
	return issues
}

func (v *CertChainValidator) ValidateDomainMatch(certDomains []string, actualDomain string) []CertChainIssue {
	var issues []CertChainIssue
	found := false
	for _, d := range certDomains {
		if d == actualDomain {
			found = true
			break
		}
	}
	if !found {
		issues = append(issues, CertChainIssue{
			Type:       "domain_mismatch",
			Severity:   "high",
			Message:    fmt.Sprintf("证书不包含域名 %s", actualDomain),
			Suggestion: "重新签发包含正确域名的证书",
		})
	}
	return issues
}
