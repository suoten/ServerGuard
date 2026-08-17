package cert

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// CertCalendar implements L5: Enterprise Certificate Calendar.
// Shows all server certificates' expiry dates on a calendar,
// sorted by urgency, with batch renewal support.
type CertCalendar struct {
	mu      sync.RWMutex
	dataDir string
	entries []CalendarEntry
}

// CalendarEntry represents a certificate in the calendar.
type CalendarEntry struct {
	Domain     string    `json:"domain"`
	ServerID   string    `json:"server_id"`
	ServerName string    `json:"server_name"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DaysUntil  int       `json:"days_until_expiry"`
	ManagedBy  string    `json:"managed_by"`
	CertPath   string    `json:"cert_path"`
	Status     string    `json:"status"` // valid, expiring, expired, renewing, failed
}

// NewCertCalendar creates a new CertCalendar.
func NewCertCalendar(dataDir string) *CertCalendar {
	if dataDir == "" {
		dataDir = "/var/lib/serverguard/cert-calendar"
	}
	os.MkdirAll(dataDir, 0750)
	cal := &CertCalendar{dataDir: dataDir}
	cal.loadEntries()
	return cal
}

// AddEntry adds a certificate to the calendar.
func (c *CertCalendar) AddEntry(entry CalendarEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update or add
	found := false
	for i, e := range c.entries {
		if e.Domain == entry.Domain && e.ServerID == entry.ServerID {
			c.entries[i] = entry
			found = true
			break
		}
	}
	if !found {
		c.entries = append(c.entries, entry)
	}
	c.saveEntries()
}

// RemoveEntry removes a certificate from the calendar.
func (c *CertCalendar) RemoveEntry(domain, serverID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var filtered []CalendarEntry
	for _, e := range c.entries {
		if e.Domain != domain || e.ServerID != serverID {
			filtered = append(filtered, e)
		}
	}
	c.entries = filtered
	c.saveEntries()
}

// GetEntries returns all calendar entries sorted by expiry date.
func (c *CertCalendar) GetEntries() []CalendarEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]CalendarEntry, len(c.entries))
	copy(result, c.entries)

	// Sort by NotAfter (earliest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].NotAfter.Before(result[j].NotAfter)
	})

	// Update days until expiry
	now := time.Now()
	for i := range result {
		result[i].DaysUntil = int(result[i].NotAfter.Sub(now).Hours() / 24)
		if result[i].DaysUntil < 0 {
			result[i].Status = "expired"
		} else if result[i].DaysUntil <= 7 {
			result[i].Status = "critical"
		} else if result[i].DaysUntil <= 14 {
			result[i].Status = "expiring"
		} else {
			result[i].Status = "valid"
		}
	}

	return result
}

// GetExpiringSoon returns certificates expiring within the given days.
func (c *CertCalendar) GetExpiringSoon(days int) []CalendarEntry {
	entries := c.GetEntries()
	var result []CalendarEntry
	for _, e := range entries {
		if e.DaysUntil <= days {
			result = append(result, e)
		}
	}
	return result
}

// BatchRenew renews multiple certificates in batch.
func (c *CertCalendar) BatchRenew(ctx context.Context, guard *CertGuard, domains []string) []BatchRenewResult {
	var results []BatchRenewResult
	for _, domain := range domains {
		result := BatchRenewResult{
			Domain:  domain,
			Success: false,
		}

		err := guard.RenewCertificate(ctx, domain)
		if err != nil {
			result.Error = fmt.Sprintf("%v", err)
		} else {
			result.Success = true
		}

		results = append(results, result)

		// Update entry status
		c.mu.Lock()
		for i, e := range c.entries {
			if e.Domain == domain {
				if result.Success {
					c.entries[i].Status = "renewed"
				} else {
					c.entries[i].Status = "failed"
				}
				break
			}
		}
		c.mu.Unlock()
	}

	c.saveEntries()
	return results
}

// BatchRenewResult represents the result of a batch renewal.
type BatchRenewResult struct {
	Domain  string `json:"domain"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// GetRenewalHistory returns the renewal history.
func (c *CertCalendar) GetRenewalHistory() []RenewalHistoryEntry {
	historyPath := filepath.Join(c.dataDir, "renewal-history.json")
	data, err := os.ReadFile(historyPath)
	if err != nil {
		return nil
	}
	var entries []RenewalHistoryEntry
	json.Unmarshal(data, &entries)
	return entries
}

// RenewalHistoryEntry represents a renewal event.
type RenewalHistoryEntry struct {
	Domain    string    `json:"domain"`
	ServerID  string    `json:"server_id"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Method    string    `json:"method"` // baota_api, acme, manual
	Error     string    `json:"error,omitempty"`
}

// saveEntries saves calendar entries to disk.
func (c *CertCalendar) saveEntries() {
	data, _ := json.MarshalIndent(c.entries, "", "  ")
	os.WriteFile(filepath.Join(c.dataDir, "calendar.json"), data, 0640)
}

// loadEntries loads calendar entries from disk.
func (c *CertCalendar) loadEntries() {
	data, err := os.ReadFile(filepath.Join(c.dataDir, "calendar.json"))
	if err != nil {
		return
	}
	json.Unmarshal(data, &c.entries)
}

// GetStatistics returns summary statistics about all certificates.
func (c *CertCalendar) GetStatistics() map[string]interface{} {
	entries := c.GetEntries()
	stats := map[string]interface{}{
		"total": len(entries),
	}

	statusCounts := map[string]int{}
	for _, e := range entries {
		statusCounts[e.Status]++
	}
	stats["by_status"] = statusCounts

	// Certificates expiring in next 30 days
	expiring30 := 0
	expiring7 := 0
	expiring1 := 0
	for _, e := range entries {
		if e.DaysUntil <= 30 {
			expiring30++
		}
		if e.DaysUntil <= 7 {
			expiring7++
		}
		if e.DaysUntil <= 1 {
			expiring1++
		}
	}
	stats["expiring_30_days"] = expiring30
	stats["expiring_7_days"] = expiring7
	stats["expiring_1_day"] = expiring1

	return stats
}

// _ is a type assertion to ensure types.Alert is used (avoids unused import).
var _ = types.AlertInfo
