package decider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/suoten/serverguard/internal/storage"
)

// ConfirmRequest 表示一个用户确认请求。
// 当决策引擎返回 LevelConfirm 时，创建此请求并推送给用户。
// 用户可通过确认链接执行，或通过忽略链接跳过。
type ConfirmRequest struct {
	// ID 唯一标识（随机 Token，16-32 字节十六进制编码）。
	// 用作一次性 Token，用户通过此 ID 执行或忽略确认请求。
	ID string `json:"id"`

	// Action 动作类型（如 disk_cleanup、baota_service_restart 等）。
	Action ActionType `json:"action"`

	// Target 目标进程名/路径/IP 等。
	Target string `json:"target"`

	// Detail 详细说明（如"发现 8 个可清理文件，预计释放 2.3GB"）。
	Detail string `json:"detail"`

	// Level 告警级别（warning / error）。
	Level string `json:"level"`

	// Context 执行所需上下文（map，保存执行时需要的额外参数）。
	// 例如: {"disk_usage": 95.2, "files_to_clean": ["/var/log/old.log.gz"]}
	Context map[string]interface{} `json:"context"`

	// CreatedAt 创建时间。
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt 过期时间（默认当前时间 + 5 分钟）。
	// 过期后用户无法再执行此请求。
	ExpiresAt time.Time `json:"expires_at"`

	// Executed 是否已执行。
	Executed bool `json:"executed"`

	// Ignored 是否被用户忽略。
	Ignored bool `json:"ignored"`

	// Expired 是否已过期（由 ExpireCleanup 标记）。
	Expired bool `json:"expired"`
}

// ConfirmManager 管理用户确认请求的生命周期。
// 负责创建、执行、忽略、查询和过期清理确认请求。
// 所有请求持久化到 SQLite confirms 表。
type ConfirmManager struct {
	// storage 数据库连接（SQLite）。
	storage *storage.Storage

	// timeout 确认请求的超时时间（默认 5 分钟）。
	timeout time.Duration
}

// NewConfirmManager 创建一个新的确认管理器。
// store 为已初始化的 Storage 实例。
// timeoutMinutes 为确认超时时间（分钟），若 <= 0 则使用默认值 5 分钟。
func NewConfirmManager(store *storage.Storage, timeoutMinutes int) *ConfirmManager {
	if timeoutMinutes <= 0 {
		timeoutMinutes = 5
	}
	cm := &ConfirmManager{
		storage: store,
		timeout: time.Duration(timeoutMinutes) * time.Minute,
	}
	// 初始化数据库表
	_ = cm.initTable()
	return cm
}

// initTable 初始化 confirms 表。
// 表结构:
//   - id (TEXT, 主键) — 确认请求 ID
//   - action (TEXT, 非空) — 动作类型
//   - target (TEXT, 非空) — 目标
//   - detail (TEXT) — 详细说明
//   - level (TEXT, 默认 warning) — 告警级别
//   - context (TEXT) — 序列化的上下文 JSON
//   - created_at (DATETIME, 非空) — 创建时间
//   - expires_at (DATETIME, 非空) — 过期时间
//   - executed (BOOLEAN, 默认 false) — 是否已执行
//   - ignored (BOOLEAN, 默认 false) — 是否已忽略
//   - expired (BOOLEAN, 默认 false) — 是否已过期
//
// 联合索引: (executed, ignored, expired, expires_at) — 用于快速查询待确认列表
func (cm *ConfirmManager) initTable() error {
	schema := `
	CREATE TABLE IF NOT EXISTS confirms (
		id TEXT PRIMARY KEY,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		detail TEXT,
		level TEXT DEFAULT 'warning',
		context TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		executed INTEGER DEFAULT 0,
		ignored INTEGER DEFAULT 0,
		expired INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_confirms_pending ON confirms(executed, ignored, expired, expires_at);
	`
	_, err := cm.storage.DB().Exec(schema)
	return err
}

// generateToken 生成随机 Token 作为确认请求 ID。
// 使用 crypto/rand 生成 16 字节随机数，十六进制编码后为 32 字符。
func generateToken() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// Create 创建一个新的确认请求。
//
// 参数:
//   - action: 动作类型
//   - target: 目标（进程名、路径、IP 等）
//   - detail: 详细说明（如"发现 8 个可清理文件，预计释放 2.3GB"）
//   - level: 告警级别（warning / error），空则默认 warning
//   - context: 执行所需上下文（map，保存执行时需要的额外参数）
//
// 返回创建的 ConfirmRequest。
// 调用方应在 Create 成功后调用通知器推送通知。
func (cm *ConfirmManager) Create(action ActionType, target, detail, level string, context map[string]interface{}) (*ConfirmRequest, error) {
	if level == "" {
		level = "warning"
	}

	now := time.Now()
	req := &ConfirmRequest{
		ID:        generateToken(),
		Action:    action,
		Target:    target,
		Detail:    detail,
		Level:     level,
		Context:   context,
		CreatedAt: now,
		ExpiresAt: now.Add(cm.timeout),
		Executed:  false,
		Ignored:   false,
		Expired:   false,
	}

	// 序列化 context
	var contextJSON string
	if context != nil {
		data, _ := json.Marshal(context)
		contextJSON = string(data)
	}

	// 持久化到 SQLite
	_, err := cm.storage.DB().Exec(
		`INSERT INTO confirms (id, action, target, detail, level, context, created_at, expires_at, executed, ignored, expired)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)`,
		req.ID, string(action), target, detail, level, contextJSON,
		now.UTC().Format(time.RFC3339), req.ExpiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("持久化确认请求失败: %w", err)
	}

	return req, nil
}

// Execute 执行一个确认请求。
//
// 根据 ID 查询确认请求，校验状态：
//   - 如果已执行 → 返回错误"该请求已执行"
//   - 如果已忽略 → 返回错误"该请求已被忽略"
//   - 如果已过期或当前时间超过 ExpiresAt → 更新 expired=true，返回错误"确认请求已过期"
//
// 校验通过后标记 executed=true，返回请求信息（含 context），由调用方执行实际动作。
func (cm *ConfirmManager) Execute(id string) (*ConfirmRequest, error) {
	req, err := cm.getByID(id)
	if err != nil {
		return nil, fmt.Errorf("查询确认请求失败: %w", err)
	}
	if req == nil {
		return nil, fmt.Errorf("确认请求不存在: %s", id)
	}

	// 校验状态
	if req.Executed {
		return nil, fmt.Errorf("该请求已执行")
	}
	if req.Ignored {
		return nil, fmt.Errorf("该请求已被忽略")
	}

	// 检查过期
	now := time.Now()
	if req.Expired || now.After(req.ExpiresAt) {
		// 更新 expired 标记
		_, _ = cm.storage.DB().Exec("UPDATE confirms SET expired=1 WHERE id=?", id)
		return nil, fmt.Errorf("确认请求已过期")
	}

	// 标记已执行
	_, err = cm.storage.DB().Exec("UPDATE confirms SET executed=1 WHERE id=?", id)
	if err != nil {
		return nil, fmt.Errorf("标记已执行失败: %w", err)
	}

	req.Executed = true
	return req, nil
}

// Ignore 忽略一个确认请求。
// 根据 ID 标记 ignored=true。
func (cm *ConfirmManager) Ignore(id string) error {
	req, err := cm.getByID(id)
	if err != nil {
		return fmt.Errorf("查询确认请求失败: %w", err)
	}
	if req == nil {
		return fmt.Errorf("确认请求不存在: %s", id)
	}

	if req.Executed {
		return fmt.Errorf("该请求已执行，无法忽略")
	}

	_, err = cm.storage.DB().Exec("UPDATE confirms SET ignored=1 WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("标记忽略失败: %w", err)
	}

	return nil
}

// GetPending 查询所有待确认的请求。
// 条件: 未执行 (executed=0) 且 未忽略 (ignored=0) 且 未过期 (expired=0) 且 未超时 (expires_at > now)。
// 按创建时间倒序返回。
func (cm *ConfirmManager) GetPending() ([]*ConfirmRequest, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := cm.storage.DB().Query(
		`SELECT id, action, target, detail, level, context, created_at, expires_at
		 FROM confirms
		 WHERE executed=0 AND ignored=0 AND expired=0 AND expires_at > ?
		 ORDER BY created_at DESC`,
		now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []*ConfirmRequest
	for rows.Next() {
		req, err := cm.scanRow(rows)
		if err != nil {
			continue
		}
		requests = append(requests, req)
	}
	return requests, nil
}

// ExpireCleanup 定时清理任务：将已过期的未处理请求标记为 expired=true。
// 可由 cron 或 ticker 定期调用。
// 返回被标记为过期的请求数量。
func (cm *ConfirmManager) ExpireCleanup() (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := cm.storage.DB().Exec(
		`UPDATE confirms SET expired=1
		 WHERE executed=0 AND ignored=0 AND expired=0 AND expires_at <= ?`,
		now,
	)
	if err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	return count, nil
}

// getByID 根据 ID 从数据库查询单个确认请求。
func (cm *ConfirmManager) getByID(id string) (*ConfirmRequest, error) {
	row := cm.storage.DB().QueryRow(
		`SELECT id, action, target, detail, level, context, created_at, expires_at, executed, ignored, expired
		 FROM confirms WHERE id=?`,
		id,
	)

	req := &ConfirmRequest{}
	var actionStr, contextJSON, createdStr, expiresStr string
	var executedInt, ignoredInt, expiredInt int

	err := row.Scan(
		&req.ID, &actionStr, &req.Target, &req.Detail, &req.Level, &contextJSON,
		&createdStr, &expiresStr, &executedInt, &ignoredInt, &expiredInt,
	)
	if err != nil {
		return nil, nil // 不存在时返回 nil, nil
	}

	req.Action = ActionType(actionStr)
	req.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	req.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr)
	req.Executed = executedInt == 1
	req.Ignored = ignoredInt == 1
	req.Expired = expiredInt == 1

	// 反序列化 context
	if contextJSON != "" {
		_ = json.Unmarshal([]byte(contextJSON), &req.Context)
	}

	return req, nil
}

// scanRow 从 sql.Rows 扫描一行数据为 ConfirmRequest（不含 executed/ignored/expired 字段）。
func (cm *ConfirmManager) scanRow(rows interface{ Scan(...interface{}) error }) (*ConfirmRequest, error) {
	req := &ConfirmRequest{}
	var actionStr, contextJSON, createdStr, expiresStr string

	err := rows.Scan(
		&req.ID, &actionStr, &req.Target, &req.Detail, &req.Level, &contextJSON,
		&createdStr, &expiresStr,
	)
	if err != nil {
		return nil, err
	}

	req.Action = ActionType(actionStr)
	req.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	req.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr)

	if contextJSON != "" {
		_ = json.Unmarshal([]byte(contextJSON), &req.Context)
	}

	return req, nil
}

// GetTimeout 返回当前确认超时时间。
func (cm *ConfirmManager) GetTimeout() time.Duration {
	return cm.timeout
}
