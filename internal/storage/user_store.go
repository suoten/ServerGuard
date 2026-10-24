package storage

import (
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserSchema 用户表 schema
func UserSchema() string {
	return `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'viewer',
	tenant_id TEXT NOT NULL DEFAULT 'default',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
}

// User 用户信息
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateUser 创建新用户
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) CreateUser(username, password, role, tenantID string) (*User, error) {
	if s.IsWriteDegraded() {
		return nil, fmt.Errorf("storage degraded (disk full), user create skipped")
	}
	if username == "" {
		return nil, fmt.Errorf("用户名不能为空")
	}
	if password == "" {
		return nil, fmt.Errorf("密码不能为空")
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("密码长度不能少于 6 位")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("密码加密失败: %w", err)
	}

	if role == "" {
		role = "viewer"
	}
	if tenantID == "" {
		tenantID = "default"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, role, tenant_id) VALUES (?, ?, ?, ?)`,
		username, string(hash), role, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("创建用户失败（用户名可能已存在）: %w", err)
	}

	id, _ := result.LastInsertId()
	return &User{
		ID:        id,
		Username:  username,
		Role:      role,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// UpdateUser 更新用户信息（不含密码）
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) UpdateUser(id int64, role, tenantID string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), user update skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`UPDATE users SET role = ?, tenant_id = ?, updated_at = ? WHERE id = ?`,
		role, tenantID, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("更新用户失败: %w", err)
	}
	return nil
}

// UpdateUserPassword 重置用户密码
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) UpdateUserPassword(id int64, newPassword string) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), password update skipped")
	}
	if newPassword == "" {
		return fmt.Errorf("新密码不能为空")
	}
	if len(newPassword) < 6 {
		return fmt.Errorf("密码长度不能少于 6 位")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.db.Exec(
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		string(hash), time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("重置密码失败: %w", err)
	}
	return nil
}

// DeleteUser 删除用户
// 【磁盘满保护】降级时快速失败，避免 _busy_timeout 阻塞 5 秒
func (s *Storage) DeleteUser(id int64) error {
	if s.IsWriteDegraded() {
		return fmt.Errorf("storage degraded (disk full), user delete skipped")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除用户失败: %w", err)
	}
	return nil
}

// ListUsers 列出所有用户
func (s *Storage) ListUsers() ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, username, role, tenant_id, created_at, updated_at FROM users ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.TenantID, &u.CreatedAt, &u.UpdatedAt); err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

// VerifyUser 验证用户名和密码
func (s *Storage) VerifyUser(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var u User
	var passwordHash string
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, role, tenant_id FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &passwordHash, &u.Role, &u.TenantID)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("用户名或密码错误")
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("用户名或密码错误")
	}

	return &u, nil
}

// GetUserCount 获取用户数量
func (s *Storage) GetUserCount() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// EnsureDefaultAdmin 确保默认管理员用户存在。
// 如果用户已存在但配置文件中的密码已变更（与数据库不匹配），
// 则同步更新数据库密码，避免重启后登录报"密码错误"。
func (s *Storage) EnsureDefaultAdmin(username, password string) error {
	count, err := s.GetUserCount()
	if err != nil {
		return err
	}
	if count == 0 {
		// 创建默认管理员
		_, err = s.CreateUser(username, password, "owner", "default")
		return err
	}

	// 用户已存在，检查密码是否需要同步
	// 尝试用配置文件中的密码验证，如果失败说明密码已变更，需要同步
	if _, err := s.VerifyUser(username, password); err != nil {
		// 密码不匹配，查找用户 ID 并更新密码
		users, err := s.ListUsers()
		if err != nil {
			return err
		}
		for _, u := range users {
			if u.Username == username {
				return s.UpdateUserPassword(u.ID, password)
			}
		}
	}
	return nil
}
