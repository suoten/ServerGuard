package storage

// PostgresSchema 返回 PostgreSQL 的完整建表 SQL，所有表包含 tenant_id 字段并启用 RLS
func PostgresSchema() string {
	return `
-- 启用扩展
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Metrics
CREATE TABLE IF NOT EXISTS metrics (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    unit TEXT,
    timestamp TIMESTAMPTZ NOT NULL,
    labels TEXT,
    granularity TEXT DEFAULT 'raw'
);
CREATE INDEX IF NOT EXISTS idx_metrics_type_name_ts ON metrics(type, name, timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_granularity ON metrics(granularity, timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_tenant ON metrics(tenant_id);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,
    source TEXT NOT NULL,
    rule_id TEXT,
    labels TEXT,
    timestamp TIMESTAMPTZ NOT NULL,
    resolved INTEGER DEFAULT 0,
    resolved_at TIMESTAMPTZ,
    acknowledged INTEGER DEFAULT 0,
    acked_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_level_resolved ON alerts(level, resolved);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);

-- Actions
CREATE TABLE IF NOT EXISTS actions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    rule_id TEXT,
    action_type TEXT NOT NULL,
    target TEXT,
    params TEXT,
    success INTEGER NOT NULL,
    message TEXT,
    error TEXT,
    duration_ms INTEGER,
    timestamp TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_type_ts ON actions(action_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_tenant ON actions(tenant_id);

-- Audit log (WORM)
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    timestamp TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    reason TEXT,
    result TEXT NOT NULL,
    details TEXT,
    ip_address TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);

-- Guard targets
CREATE TABLE IF NOT EXISTS guard_targets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    command TEXT,
    stop_command TEXT,
    port INTEGER,
    health_check TEXT,
    process_name TEXT,
    depends_on TEXT,
    restart_policy TEXT,
    enabled INTEGER DEFAULT 1,
    tags TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guard_targets_tenant ON guard_targets(tenant_id);

-- Rules
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 100,
    module TEXT NOT NULL,
    trigger TEXT NOT NULL,
    actions TEXT NOT NULL,
    cooldown_ms INTEGER,
    max_triggers INTEGER DEFAULT 3,
    alert_level TEXT DEFAULT 'warning',
    alert_channels TEXT,
    learn_mode INTEGER DEFAULT 1,
    tags TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id);

-- Certificates
CREATE TABLE IF NOT EXISTS certificates (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL,
    port INTEGER,
    issuer TEXT,
    subject TEXT,
    sans TEXT,
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ NOT NULL,
    key_algorithm TEXT,
    signature_algorithm TEXT,
    serial_number TEXT,
    cert_path TEXT,
    chain_complete INTEGER DEFAULT 1,
    managed_by TEXT,
    days_until_expiry INTEGER,
    scanned_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certs_expiry ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certs_tenant ON certificates(tenant_id);

-- Log files
CREATE TABLE IF NOT EXISTS log_files (
    path TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    size BIGINT NOT NULL,
    last_modified TIMESTAMPTZ NOT NULL,
    write_rate DOUBLE PRECISION DEFAULT 0,
    managed INTEGER DEFAULT 0,
    app TEXT,
    last_rotated TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL
);

-- BaoTa state
CREATE TABLE IF NOT EXISTS baota_state (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    tenant_id TEXT NOT NULL DEFAULT '',
    detected INTEGER NOT NULL,
    install_path TEXT,
    version TEXT,
    panel_type TEXT,
    panel_url TEXT,
    port TEXT,
    admin_path TEXT,
    api_enabled INTEGER,
    capabilities TEXT,
    sites TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Snapshots
CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    data TEXT NOT NULL,
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_snapshots_tenant ON snapshots(tenant_id);

-- Server info
CREATE TABLE IF NOT EXISTS server_info (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    tenant_id TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT,
    os TEXT,
    version TEXT,
    registered_at TIMESTAMPTZ NOT NULL
);

-- KV store
CREATE TABLE IF NOT EXISTS kv_store (
    key TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    value TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Findings (安全发现项)
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    scanner_id TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    evidence TEXT,
    recommendation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    cve_id TEXT,
    cvss_score REAL,
    detected_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_findings_scanner ON findings(scanner_id, detected_at);

-- Attack events
CREATE TABLE IF NOT EXISTS attack_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    evidence TEXT,
    action_taken TEXT,
    banned INTEGER DEFAULT 0,
    ban_expires_at TIMESTAMPTZ,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_attacks_tenant ON attack_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attack_events(source_ip, last_seen);
CREATE INDEX IF NOT EXISTS idx_attacks_type ON attack_events(event_type, last_seen);

-- Attack profiles
CREATE TABLE IF NOT EXISTS attack_profiles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL,
    total_attacks INTEGER DEFAULT 0,
    attack_types TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    threat_level TEXT DEFAULT 'low',
    banned INTEGER DEFAULT 0,
    notes TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_profiles_tenant ON attack_profiles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_attack_profiles_ip ON attack_profiles(ip);

-- Config versions
CREATE TABLE IF NOT EXISTS config_versions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    module TEXT NOT NULL,
    version INTEGER NOT NULL,
    config TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL,
    approved INTEGER DEFAULT 0,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    rollback_info TEXT
);
CREATE INDEX IF NOT EXISTS idx_config_versions_tenant ON config_versions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_config_versions_module ON config_versions(module, version);

-- Metrics downsample
CREATE TABLE IF NOT EXISTS metrics_downsample (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    granularity TEXT NOT NULL,
    avg_value DOUBLE PRECISION NOT NULL,
    max_value DOUBLE PRECISION NOT NULL,
    min_value DOUBLE PRECISION NOT NULL,
    sample_count INTEGER NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    bucket_end TIMESTAMPTZ NOT NULL,
    labels TEXT
);
CREATE INDEX IF NOT EXISTS idx_downsample_tenant ON metrics_downsample(tenant_id);
CREATE INDEX IF NOT EXISTS idx_downsample_query ON metrics_downsample(type, name, granularity, bucket_start);
`
}

// PostgresRLSPolicies 返回为所有含 tenant_id 的表启用 ROW LEVEL SECURITY 的 SQL
func PostgresRLSPolicies() string {
	tables := []string{
		"metrics", "alerts", "actions", "audit_log",
		"guard_targets", "rules", "certificates", "log_files",
		"baota_state", "snapshots", "server_info", "kv_store",
		"findings", "attack_events", "attack_profiles",
		"config_versions", "metrics_downsample",
	}

	sql := ""
	for _, table := range tables {
		sql += "ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY;\n"
		sql += "DROP POLICY IF EXISTS tenant_isolation ON " + table + ";\n"
		sql += "CREATE POLICY tenant_isolation ON " + table +
			" USING (tenant_id = current_setting('app.tenant_id', true)::TEXT);\n"
	}
	return sql
}
