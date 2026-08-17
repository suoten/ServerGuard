package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// ConfigVersion 配置版本
type ConfigVersion struct {
	ID          string    `json:"id"`
	CommitID    string    `json:"commit_id"`
	FilePath    string    `json:"file_path"`
	Content     string    `json:"content"`
	Diff        string    `json:"diff"`
	Tag         string    `json:"tag"`
	Author      string    `json:"author"`
	Message     string    `json:"message"`
	IsApproved  bool      `json:"is_approved"`
	ApprovedBy  string    `json:"approved_by"`
	ApprovedAt  time.Time `json:"approved_at"`
	CanRollback bool      `json:"can_rollback"`
	CreatedAt   time.Time `json:"created_at"`
}

// SaveConfigVersion 保存配置版本
func (s *Storage) SaveConfigVersion(v *ConfigVersion) error {
	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	if v.CommitID == "" {
		v.CommitID = uuid.New().String()[:8]
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	isApproved := 0
	if v.IsApproved {
		isApproved = 1
	}
	canRollback := 1
	if !v.CanRollback {
		canRollback = 0
	}

	_, err := s.db.Exec(`INSERT INTO config_versions
		(id, commit_id, file_path, content, diff, tag, author, message, is_approved, approved_by, approved_at, can_rollback, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.CommitID, v.FilePath, v.Content, v.Diff, v.Tag, v.Author, v.Message,
		isApproved, v.ApprovedBy, v.ApprovedAt, canRollback, v.CreatedAt)
	return err
}

// QueryConfigVersions 查询配置版本历史
func (s *Storage) QueryConfigVersions(filePath, tag string, limit int) ([]ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, commit_id, file_path, content, diff, tag, author, message, is_approved, approved_by, approved_at, can_rollback, created_at FROM config_versions WHERE 1=1"
	args := []interface{}{}
	if filePath != "" {
		query += " AND file_path = ?"
		args = append(args, filePath)
	}
	if tag != "" {
		query += " AND tag = ?"
		args = append(args, tag)
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query config versions: %w", err)
	}
	defer rows.Close()

	var versions []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		var isApproved, canRollback int
		if err := rows.Scan(&v.ID, &v.CommitID, &v.FilePath, &v.Content, &v.Diff, &v.Tag, &v.Author, &v.Message,
			&isApproved, &v.ApprovedBy, &v.ApprovedAt, &canRollback, &v.CreatedAt); err != nil {
			continue
		}
		v.IsApproved = isApproved == 1
		v.CanRollback = canRollback == 1
		versions = append(versions, v)
	}
	return versions, nil
}

// GetConfigVersion 获取特定版本
func (s *Storage) GetConfigVersion(commitID string) (*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var v ConfigVersion
	var isApproved, canRollback int
	err := s.db.QueryRow(`SELECT id, commit_id, file_path, content, diff, tag, author, message, is_approved, approved_by, approved_at, can_rollback, created_at FROM config_versions WHERE commit_id = ?`, commitID).
		Scan(&v.ID, &v.CommitID, &v.FilePath, &v.Content, &v.Diff, &v.Tag, &v.Author, &v.Message,
			&isApproved, &v.ApprovedBy, &v.ApprovedAt, &canRollback, &v.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get config version: %w", err)
	}
	v.IsApproved = isApproved == 1
	v.CanRollback = canRollback == 1
	return &v, nil
}

// ApproveConfigVersion 审批配置版本
func (s *Storage) ApproveConfigVersion(commitID, approvedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE config_versions SET is_approved = 1, approved_by = ?, approved_at = ? WHERE commit_id = ?",
		approvedBy, time.Now(), commitID)
	return err
}

// RollbackConfigVersion 回滚到指定版本
func (s *Storage) RollbackConfigVersion(commitID string) (*ConfigVersion, error) {
	return s.GetConfigVersion(commitID)
}

// TagVersion 为指定版本打标签。
func (s *Storage) TagVersion(commitID, tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE config_versions SET tag = ? WHERE commit_id = ?", tag, commitID)
	if err != nil {
		return fmt.Errorf("tag config version: %w", err)
	}
	return nil
}

// ConfigVersionExport YAML 导出格式
type ConfigVersionExport struct {
	Versions []ConfigVersion `yaml:"versions"`
}

// ExportYAML 导出指定文件的配置版本历史为 YAML 格式。
// filePath 为空时导出所有版本。
func (s *Storage) ExportYAML(filePath string) ([]byte, error) {
	versions, err := s.QueryConfigVersions(filePath, "", 0)
	if err != nil {
		return nil, fmt.Errorf("query for export: %w", err)
	}

	export := ConfigVersionExport{Versions: versions}
	data, err := yaml.Marshal(export)
	if err != nil {
		return nil, fmt.Errorf("marshal yaml: %w", err)
	}
	return data, nil
}

// ImportYAML 从 YAML 格式导入配置版本。
// 已存在的 commit_id 会被跳过（INSERT OR REPLACE 语义由调用方决定）。
func (s *Storage) ImportYAML(data []byte) error {
	var export ConfigVersionExport
	if err := yaml.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("unmarshal yaml: %w", err)
	}

	for _, v := range export.Versions {
		if v.CommitID == "" {
			continue
		}
		// 检查是否已存在
		existing, err := s.GetConfigVersion(v.CommitID)
		if err == nil && existing != nil {
			// 已存在，跳过
			continue
		}
		// 保存新版本
		if err := s.SaveConfigVersion(&v); err != nil {
			return fmt.Errorf("import version %s: %w", v.CommitID, err)
		}
	}
	return nil
}
