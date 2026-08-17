package storage

// WORMAuditTriggers 返回 WORM 审计触发器 SQL
// 禁止对 audit_log 表执行 UPDATE 和 DELETE
func WORMAuditTriggers() string {
	return `
-- WORM 审计触发器：禁止 UPDATE
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is WORM: update not allowed');
END;

-- WORM 审计触发器：禁止 DELETE
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is WORM: delete not allowed');
END;
`
}

// FindingSchema 安全发现项表结构
func FindingSchema() string {
	return `
-- 安全发现项（W/X/Y 模块通用）
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scanner TEXT NOT NULL,           -- websecurity, vulnscan, serversecurity
    scanner_sub TEXT NOT NULL,       -- w1_sensitive, w2_backup, x1_component, y1_port 等
    severity TEXT NOT NULL,          -- critical, high, medium, low, info
    title TEXT NOT NULL,
    description TEXT,
    target TEXT NOT NULL,            -- 检测目标（站点/组件/端口等）
    detail TEXT,                     -- JSON 详细信息
    suggestion TEXT,                 -- 修复建议
    consequence TEXT,                -- 修复后果提示
    status TEXT DEFAULT 'open',      -- open, confirmed, fixing, fixed, ignored, false_positive
    snapshot TEXT,                   -- 快照（用于回滚）
    confirmed_by TEXT,
    confirmed_at DATETIME,
    fixed_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scanner ON findings(scanner, scanner_sub);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, created_at);
`
}

// AttackSchema 攻击事件与画像表结构
func AttackSchema() string {
	return `
-- 攻击事件（Z 模块）
CREATE TABLE IF NOT EXISTS attack_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,        -- sql_injection, xss, cc, webshell, port_scan, ssh_brute, ddos, data_exfil
    source_ip TEXT NOT NULL,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT,                     -- JSON 详细信息
    action_taken TEXT,               -- ban_ip, rate_limit, alert_only
    trace_id TEXT,
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_events_type ON attack_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_attack_events_ip ON attack_events(source_ip, created_at);
CREATE INDEX IF NOT EXISTS idx_attack_events_severity ON attack_events(severity, created_at);

-- 攻击画像（Z3 模块，聚合分析）
CREATE TABLE IF NOT EXISTS attack_profiles (
    id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    geo_location TEXT,
    attack_types TEXT,               -- JSON 数组
    total_attacks INTEGER DEFAULT 0,  -- 攻击总次数
    threat_level TEXT DEFAULT 'low',  -- 威胁等级: critical/high/medium/low
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    duration INTEGER,
    affected_modules TEXT,           -- JSON 数组
    trend TEXT,                      -- escalating, stable, declining
    confidence REAL,
    detail TEXT,                     -- JSON 详细信息
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_profiles_ip ON attack_profiles(source_ip);
CREATE INDEX IF NOT EXISTS idx_attack_profiles_updated ON attack_profiles(updated_at);
`
}

// ConfigVersionSchema 配置版本历史表结构
func ConfigVersionSchema() string {
	return `
-- 配置版本历史（V 模块）
CREATE TABLE IF NOT EXISTS config_versions (
    id TEXT PRIMARY KEY,
    commit_id TEXT NOT NULL UNIQUE,
    file_path TEXT NOT NULL,
    content TEXT NOT NULL,
    diff TEXT,
    tag TEXT,
    author TEXT,
    message TEXT,
    is_approved INTEGER DEFAULT 0,
    approved_by TEXT,
    approved_at DATETIME,
    can_rollback INTEGER DEFAULT 1,
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_config_versions_path ON config_versions(file_path, created_at);
CREATE INDEX IF NOT EXISTS idx_config_versions_commit ON config_versions(commit_id);
CREATE INDEX IF NOT EXISTS idx_config_versions_tag ON config_versions(tag);
`
}

// MetricsDownsampleSchema 降采样表结构
func MetricsDownsampleSchema() string {
	return `
-- 1 分钟粒度指标
CREATE TABLE IF NOT EXISTS metrics_1m (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    avg REAL NOT NULL,
    min REAL NOT NULL,
    max REAL NOT NULL,
    p95 REAL,
    count INTEGER NOT NULL,
    unit TEXT,
    labels TEXT,
    timestamp DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_1m_type_name_ts ON metrics_1m(type, name, timestamp);

-- 1 小时粒度指标
CREATE TABLE IF NOT EXISTS metrics_1h (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    avg REAL NOT NULL,
    min REAL NOT NULL,
    max REAL NOT NULL,
    p95 REAL,
    count INTEGER NOT NULL,
    unit TEXT,
    labels TEXT,
    timestamp DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_1h_type_name_ts ON metrics_1h(type, name, timestamp);
`
}
