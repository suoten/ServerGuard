package storage

// PostgresWORMTriggers 返回 PostgreSQL WORM 审计触发器 SQL
// 对 audit_log 表创建触发器，禁止 UPDATE 和 DELETE 操作
func PostgresWORMTriggers() string {
	return `
-- WORM: 禁止更新 audit_log
CREATE OR REPLACE FUNCTION prevent_audit_update() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'WORM: audit_log 不允许更新';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS worm_no_update ON audit_log;
CREATE TRIGGER worm_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_update();

-- WORM: 禁止删除 audit_log
CREATE OR REPLACE FUNCTION prevent_audit_delete() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'WORM: audit_log 不允许删除';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS worm_no_delete ON audit_log;
CREATE TRIGGER worm_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_delete();

-- WORM: findings 已解决项禁止删除/篡改
CREATE OR REPLACE FUNCTION prevent_finding_tamper() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status = 'resolved' AND NEW.status != 'resolved' THEN
        RAISE EXCEPTION 'WORM: 已解决的 finding 不允许回退状态';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS worm_finding_no_tamper ON findings;
CREATE TRIGGER worm_finding_no_tamper
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION prevent_finding_tamper();
`
}