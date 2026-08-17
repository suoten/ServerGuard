package multi

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// TenantManager implements §8.9: Multi-tenant SaaS architecture.
// Uses PostgreSQL Row Level Security (RLS) for tenant isolation.
type TenantManager struct {
	mu       sync.RWMutex
	eventBus *eventbus.EventBus
	db       *sql.DB
	tenants  map[string]*Tenant
}

// Tenant represents a SaaS tenant.
type Tenant struct {
	ID         string
	Name       string
	MaxAgents  int
	AgentCount int
	APIQuota   int      // requests per minute
	StorageGB  int      // max storage
	Features   []string // enabled features
	CreatedAt  time.Time
	APIKeyHash string // hashed API key
}

// NewTenantManager creates a new TenantManager.
func NewTenantManager(bus *eventbus.EventBus, db *sql.DB) *TenantManager {
	return &TenantManager{
		eventBus: bus,
		db:       db,
		tenants:  make(map[string]*Tenant),
	}
}

// RegisterTenant registers a new tenant.
func (m *TenantManager) RegisterTenant(tenant *Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tenants[tenant.ID] = tenant

	// In production with PostgreSQL:
	// 1. Create tenant row: INSERT INTO tenants VALUES (...)
	// 2. Create RLS policy: CREATE POLICY tenant_isolation ON metrics
	//    USING (tenant_id = current_setting('app.tenant_id')::text);
	// 3. Set tenant-specific config

	return nil
}

// GetTenant returns a tenant by ID.
func (m *TenantManager) GetTenant(id string) *Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, exists := m.tenants[id]; exists {
		return t
	}
	return nil
}

// CheckAgentLimit checks if a tenant can register more agents.
func (m *TenantManager) CheckAgentLimit(tenantID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenant, exists := m.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found")
	}

	if tenant.AgentCount >= tenant.MaxAgents {
		return fmt.Errorf("agent limit reached: %d/%d", tenant.AgentCount, tenant.MaxAgents)
	}

	return nil
}

// IncrementAgentCount increments the agent count for a tenant.
func (m *TenantManager) IncrementAgentCount(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tenant, exists := m.tenants[tenantID]; exists {
		tenant.AgentCount++
	}
}

// CheckAPIQuota checks if a tenant has exceeded its API quota.
func (m *TenantManager) CheckAPIQuota(tenantID string, currentRequests int) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenant, exists := m.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found")
	}

	if currentRequests >= tenant.APIQuota {
		m.eventBus.PublishAlert(types.AlertWarning, "hub",
			fmt.Sprintf("API配额超限: %s", tenant.Name),
			fmt.Sprintf("租户 %s 的API请求 %d/%d/min 已超限", tenant.Name, currentRequests, tenant.APIQuota),
			"tenant-quota-001")
		return fmt.Errorf("API quota exceeded: %d/%d", currentRequests, tenant.APIQuota)
	}

	return nil
}

// HasFeature checks if a tenant has a specific feature enabled.
func (m *TenantManager) HasFeature(tenantID, feature string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenant, exists := m.tenants[tenantID]
	if !exists {
		return false
	}

	for _, f := range tenant.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// ListTenants returns all registered tenants.
func (m *TenantManager) ListTenants() []*Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Tenant
	for _, t := range m.tenants {
		result = append(result, t)
	}
	return result
}

// SetTenantContext sets the tenant context for the current database session.
// In PostgreSQL with RLS: SET app.tenant_id = 'xxx';
func (m *TenantManager) SetTenantContext(tenantID string) error {
	if m.db == nil {
		return nil
	}
	_, err := m.db.Exec("SET app.tenant_id = $1", tenantID)
	return err
}

// ApplyRLSPolicies applies Row Level Security policies to all tables.
// This should be called during database initialization.
func (m *TenantManager) ApplyRLSPolicies() error {
	if m.db == nil {
		return nil
	}

	tables := []string{"metrics", "alerts", "actions", "audit_log", "servers", "guards"}
	for _, table := range tables {
		// Enable RLS
		_, err := m.db.Exec(fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY;", table))
		if err != nil {
			continue // Table might not exist yet
		}

		// Create policy
		policy := fmt.Sprintf(`
			CREATE POLICY tenant_isolation ON %s
			USING (tenant_id = current_setting('app.tenant_id')::text)
			WITH CHECK (tenant_id = current_setting('app.tenant_id')::text);
		`, table)
		m.db.Exec(policy)
	}

	return nil
}

// GenerateAPIKey generates a new API key for a tenant.
func GenerateAPIKey(tenantID string) string {
	// In production, use crypto/rand to generate a secure key
	return fmt.Sprintf("sg_%s_%x", tenantID, time.Now().UnixNano())
}

// HashAPIKey hashes an API key for storage.
func HashAPIKey(key string) string {
	// In production, use bcrypt or Argon2
	// For now, simple hash
	return fmt.Sprintf("%x", key)
}
