package acme

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RateLimitManager implements ACME rate limiting avoidance.
// Strategies: staggered renewal, cert caching, failure queue, global quota awareness.
type RateLimitManager struct {
	mu             sync.Mutex
	cacheDir       string
	failureQueue   map[string]*FailureEntry // domain -> failure entry
	renewCooldowns map[string]time.Time      // domain -> next allowed renewal time
	maxRetries     int
}

// FailureEntry represents a domain in the failure queue.
type FailureEntry struct {
	Domain       string
	LastFailure  time.Time
	RetryAfter   time.Time
	RetryCount   int
	LastError    string
}

// NewRateLimitManager creates a new RateLimitManager.
func NewRateLimitManager(cacheDir string) *RateLimitManager {
	if cacheDir == "" {
		cacheDir = "/var/lib/serverguard/certs/cache"
	}
	os.MkdirAll(cacheDir, 0750)
	return &RateLimitManager{
		cacheDir:       cacheDir,
		failureQueue:   make(map[string]*FailureEntry),
		renewCooldowns: make(map[string]time.Time),
		maxRetries:     3,
	}
}

// GetStaggeredRenewalTime calculates a staggered renewal time to avoid rate limits.
// Instead of renewing all domains at 14 days before expiry, we spread renewals
// randomly between 14-7 days before expiry.
func (r *RateLimitManager) GetStaggeredRenewalTime(domain string, expiryDate time.Time) time.Time {
	// Base: 14 days before expiry
	base := expiryDate.AddDate(0, 0, -14)

	// Random offset: 0-7 days
	// Use domain hash as seed for deterministic but varied scheduling
	hash := sha256.Sum256([]byte(domain))
	seed := int64(hash[0])<<8 | int64(hash[1])
	rng := rand.New(rand.NewSource(seed))
	offsetDays := rng.Intn(7)

	return base.AddDate(0, 0, offsetDays)
}

// IsCached checks if a valid cached certificate exists for a domain.
// If the cached cert is less than 30 days old, we skip renewal.
func (r *RateLimitManager) IsCached(domain string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cachePath := filepath.Join(r.cacheDir, domain+".crt")
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	// Cache is valid for 30 days
	if time.Since(info.ModTime()) > 30*24*time.Hour {
		return false
	}

	return true
}

// CacheCertificate saves a certificate to the cache.
func (r *RateLimitManager) CacheCertificate(domain string, certData []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cachePath := filepath.Join(r.cacheDir, domain+".crt")
	return os.WriteFile(cachePath, certData, 0640)
}

// GetCachedCertificate reads a cached certificate.
func (r *RateLimitManager) GetCachedCertificate(domain string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cachePath := filepath.Join(r.cacheDir, domain+".crt")
	return os.ReadFile(cachePath)
}

// CanRenew checks if a domain can be renewed (not in cooldown, not in failure queue).
func (r *RateLimitManager) CanRenew(domain string) (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check cooldown
	if cooldown, exists := r.renewCooldowns[domain]; exists {
		if time.Now().Before(cooldown) {
			return false, fmt.Sprintf("域名 %s 在续期冷却期中，%s 后可重试", domain, cooldown.Format("15:04:05"))
		}
	}

	// Check failure queue
	if entry, exists := r.failureQueue[domain]; exists {
		if time.Now().Before(entry.RetryAfter) {
			return false, fmt.Sprintf("域名 %s 在失败队列中（失败 %d 次），%s 后重试", domain, entry.RetryCount, entry.RetryAfter.Format("15:04:05"))
		}
		if entry.RetryCount >= r.maxRetries {
			return false, fmt.Sprintf("域名 %s 已达最大重试次数 %d，需人工介入", domain, r.maxRetries)
		}
	}

	return true, ""
}

// RecordFailure records a renewal failure and adds the domain to the failure queue.
// Uses exponential backoff: 1h, 4h, 24h.
func (r *RateLimitManager) RecordFailure(domain string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.failureQueue[domain]
	if !exists {
		entry = &FailureEntry{
			Domain: domain,
		}
		r.failureQueue[domain] = entry
	}

	entry.LastFailure = time.Now()
	entry.RetryCount++
	entry.LastError = fmt.Sprintf("%v", err)

	// Exponential backoff: 1h, 4h, 24h
	backoff := time.Duration(1<<uint(entry.RetryCount-1)) * time.Hour
	if backoff > 24*time.Hour {
		backoff = 24 * time.Hour
	}
	entry.RetryAfter = time.Now().Add(backoff)

	// Also set a cooldown to prevent immediate retry
	r.renewCooldowns[domain] = time.Now().Add(1 * time.Hour)
}

// RecordSuccess records a successful renewal and removes the domain from the failure queue.
func (r *RateLimitManager) RecordSuccess(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.failureQueue, domain)
	delete(r.renewCooldowns, domain)
}

// GetFailureQueue returns the list of domains in the failure queue.
func (r *RateLimitManager) GetFailureQueue() []FailureEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []FailureEntry
	for _, entry := range r.failureQueue {
		result = append(result, *entry)
	}
	return result
}

// SetCooldown sets a manual cooldown for a domain.
func (r *RateLimitManager) SetCooldown(domain string, duration time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.renewCooldowns[domain] = time.Now().Add(duration)
}

// ClearFailureQueue clears all entries from the failure queue.
func (r *RateLimitManager) ClearFailureQueue() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failureQueue = make(map[string]*FailureEntry)
	r.renewCooldowns = make(map[string]time.Time)
}

// GlobalQuotaTracker tracks ACME requests across all agents (Hub-level).
type GlobalQuotaTracker struct {
	mu              sync.Mutex
	// Per-CA per-domain per-hour request count
	requestsPerHour map[string]map[string][]time.Time // CA -> domain -> timestamps
	maxRequestsPerHour int
}

// NewGlobalQuotaTracker creates a new GlobalQuotaTracker.
func NewGlobalQuotaTracker() *GlobalQuotaTracker {
	return &GlobalQuotaTracker{
		requestsPerHour:    make(map[string]map[string][]time.Time),
		maxRequestsPerHour: 1, // 1 request per domain per hour per CA
	}
}

// CanRequest checks if a renewal request can be sent for a domain/CA pair.
func (g *GlobalQuotaTracker) CanRequest(ca, domain string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Hour)

	if g.requestsPerHour[ca] == nil {
		g.requestsPerHour[ca] = make(map[string][]time.Time)
	}

	timestamps := g.requestsPerHour[ca][domain]

	// Filter to recent timestamps
	var recent []time.Time
	for _, t := range timestamps {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	g.requestsPerHour[ca][domain] = recent

	return len(recent) < g.maxRequestsPerHour
}

// RecordRequest records that a renewal request was sent for a domain/CA pair.
func (g *GlobalQuotaTracker) RecordRequest(ca, domain string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.requestsPerHour[ca] == nil {
		g.requestsPerHour[ca] = make(map[string][]time.Time)
	}

	g.requestsPerHour[ca][domain] = append(g.requestsPerHour[ca][domain], time.Now())
}

// GetNextAvailableCA returns the next CA that can accept a renewal request.
func (g *GlobalQuotaTracker) GetNextAvailableCA(domain string, preferredCAs []string) string {
	for _, ca := range preferredCAs {
		if g.CanRequest(ca, domain) {
			return ca
		}
	}
	return "" // All CAs are rate limited
}
