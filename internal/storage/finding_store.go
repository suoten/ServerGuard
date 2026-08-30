package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Finding 安全发现项
type Finding struct {
	ID          string    `json:"id"`
	Scanner     string    `json:"scanner"`
	ScannerSub  string    `json:"scanner_sub"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Target      string    `json:"target"`
	Detail      string    `json:"detail"`
	Suggestion  string    `json:"suggestion"`
	Consequence string    `json:"consequence"`
	Status      string    `json:"status"`
	Snapshot    string    `json:"snapshot"`
	ConfirmedBy string    `json:"confirmed_by"`
	ConfirmedAt time.Time `json:"confirmed_at"`
	FixedAt     time.Time `json:"fixed_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SaveFinding 保存安全发现项
// 如果已存在相同 scanner+title+target 的 open 状态发现，则跳过（去重）
func (s *Storage) SaveFinding(f *Finding) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	now := time.Now()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.UpdatedAt = now
	if f.Status == "" {
		f.Status = "open"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 去重检查：如果已存在相同 scanner+title+target 且状态为 open/false_positive/auto_resolved 的记录，则跳过
	// 这样用户标记为误报后，重新扫描不会再产生新的 open 记录
	var existingID string
	if f.Status == "open" {
		err := s.db.QueryRow(
			`SELECT id FROM findings WHERE scanner=? AND title=? AND target=? AND status IN ('open', 'false_positive', 'auto_resolved') ORDER BY created_at DESC LIMIT 1`,
			f.Scanner, f.Title, f.Target,
		).Scan(&existingID)
		if err == nil && existingID != "" {
			// 已存在相同的发现项（无论状态如何），跳过不重复保存
			return nil
		}
	}

	_, err := s.db.Exec(`INSERT OR REPLACE INTO findings
		(id, scanner, scanner_sub, severity, title, description, target, detail, suggestion, consequence, status, snapshot, confirmed_by, confirmed_at, fixed_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Scanner, f.ScannerSub, f.Severity, f.Title, f.Description, f.Target, f.Detail,
		f.Suggestion, f.Consequence, f.Status, f.Snapshot, f.ConfirmedBy, f.ConfirmedAt, f.FixedAt, f.CreatedAt, f.UpdatedAt)
	return err
}

// QueryFindings 查询安全发现项
func (s *Storage) QueryFindings(scanner, severity, status string, limit int) ([]Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, scanner, scanner_sub, severity, title, description, target, detail, suggestion, consequence, status, snapshot, confirmed_by, confirmed_at, fixed_at, created_at, updated_at FROM findings WHERE 1=1"
	args := []interface{}{}
	if scanner != "" {
		query += " AND scanner = ?"
		args = append(args, scanner)
	}
	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	} else {
		// 默认排除已自动消失的发现项
		query += " AND COALESCE(status, 'open') != 'auto_resolved'"
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	return scanFindings(rows)
}

// GetFindingCountByScanner 返回各扫描器的发现项数量（排除误报）
func (s *Storage) GetFindingCountByScanner() (map[string]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 使用 COALESCE 处理可能的 NULL status，确保统计准确
	rows, err := s.db.Query(`SELECT scanner, COUNT(*) as cnt FROM findings WHERE COALESCE(status, 'open') NOT IN ('false_positive', 'auto_resolved') GROUP BY scanner`)
	if err != nil {
		return nil, fmt.Errorf("query finding stats: %w", err)
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var scanner string
		var cnt int
		if err := rows.Scan(&scanner, &cnt); err != nil {
			continue
		}
		result[scanner] = cnt
	}

	// 确保 4 个已知扫描器都有值（即使为 0）
	knownScanners := []string{"serversecurity", "vulnscan", "websecurity", "attackwarn"}
	for _, sc := range knownScanners {
		if _, ok := result[sc]; !ok {
			result[sc] = 0
		}
	}

	return result, nil
}

// UpdateFindingStatus 更新发现项状态
func (s *Storage) UpdateFindingStatus(id, status, confirmedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	switch status {
	case "confirmed":
		_, err := s.db.Exec("UPDATE findings SET status = ?, confirmed_by = ?, confirmed_at = ?, updated_at = ? WHERE id = ?",
			status, confirmedBy, now, now, id)
		return err
	case "fixed":
		_, err := s.db.Exec("UPDATE findings SET status = ?, fixed_at = ?, updated_at = ? WHERE id = ?",
			status, now, now, id)
		return err
	default:
		_, err := s.db.Exec("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
			status, now, id)
		return err
	}
}

// GetFinding 获取单个发现项
func (s *Storage) GetFinding(id string) (*Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var f Finding
	err := s.db.QueryRow(`SELECT id, scanner, scanner_sub, severity, title, description, target, detail, suggestion, consequence, status, snapshot, confirmed_by, confirmed_at, fixed_at, created_at, updated_at FROM findings WHERE id = ?`, id).
		Scan(&f.ID, &f.Scanner, &f.ScannerSub, &f.Severity, &f.Title, &f.Description, &f.Target, &f.Detail,
			&f.Suggestion, &f.Consequence, &f.Status, &f.Snapshot, &f.ConfirmedBy, &f.ConfirmedAt, &f.FixedAt, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	return &f, nil
}

// ResolveStaleFindings 自动标记已消失的发现项为 "auto_resolved"
// 在每次扫描完成后调用：传入扫描器名称和本次扫描检测到的所有 key（title+target 组合），
// 该扫描器下所有未在 currentKeys 中的 open 状态发现项将被标记为 auto_resolved。
func (s *Storage) ResolveStaleFindings(scanner string, currentKeys []string) error {
	// 【关键修复】当本次扫描返回 0 条发现时，不应清除历史 open 发现。
	// 此前传入空 currentKeys 会导致所有 open 记录被标记为 auto_resolved，
	// 使仪表盘上的安全发现数量瞬间归零。
	if len(currentKeys) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 查询该扫描器所有 open 状态的发现项
	rows, err := s.db.Query(
		`SELECT id, title, target FROM findings WHERE scanner=? AND status='open'`,
		scanner,
	)
	if err != nil {
		return fmt.Errorf("query stale findings: %w", err)
	}
	defer rows.Close()

	// 构建 currentKeys 查找集合
	keySet := make(map[string]bool, len(currentKeys))
	for _, k := range currentKeys {
		keySet[k] = true
	}

	now := time.Now()
	var resolvedCount int
	for rows.Next() {
		var id, title, target string
		if err := rows.Scan(&id, &title, &target); err != nil {
			continue
		}
		key := title + "|" + target
		if !keySet[key] {
			// 该发现项在本次扫描中未检测到，标记为 auto_resolved
			_, err := s.db.Exec(
				`UPDATE findings SET status='auto_resolved', fixed_at=?, updated_at=? WHERE id=?`,
				now, now, id,
			)
			if err == nil {
				resolvedCount++
			}
		}
	}

	if resolvedCount > 0 {
		fmt.Printf("[Storage] 自动标记 %d 个 %s 发现项为已消失\n", resolvedCount, scanner)
	}
	return nil
}

// ResolveStaleFindingsByTarget 按站点路径清理已消失的发现项
// 用于 W 模块（网站安全）：只清理本次实际扫描到的站点的旧发现项，
// 不影响未扫描到的站点（因为超时导致部分站点未扫完时不会误清）。
// scanner: 扫描器名称，targetPrefix: 站点路径前缀，currentKeys: 本次扫描该站点的 key 集合
func (s *Storage) ResolveStaleFindingsByTarget(scanner string, targetPrefix string, currentKeys []string) error {
	// 当本次扫描返回 0 条发现时，不清理（保护历史数据）
	if len(currentKeys) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 查询该扫描器+该站点路径下所有 open 状态的发现项
	rows, err := s.db.Query(
		`SELECT id, title, target FROM findings WHERE scanner=? AND status='open' AND target LIKE ?`,
		scanner, targetPrefix+"%",
	)
	if err != nil {
		return fmt.Errorf("query stale findings by target: %w", err)
	}
	defer rows.Close()

	keySet := make(map[string]bool, len(currentKeys))
	for _, k := range currentKeys {
		keySet[k] = true
	}

	now := time.Now()
	var resolvedCount int
	for rows.Next() {
		var id, title, target string
		if err := rows.Scan(&id, &title, &target); err != nil {
			continue
		}
		key := title + "|" + target
		if !keySet[key] {
			_, err := s.db.Exec(
				`UPDATE findings SET status='auto_resolved', fixed_at=?, updated_at=? WHERE id=?`,
				now, now, id,
			)
			if err == nil {
				resolvedCount++
			}
		}
	}

	if resolvedCount > 0 {
		fmt.Printf("[Storage] 自动标记 %d 个 %s 发现项为已消失（站点: %s）\n", resolvedCount, scanner, targetPrefix)
	}
	return nil
}

// BatchResolveFindings 批量标记指定扫描器+标题模式的发现项为已解决
// 用于清理误报：当规则更新后，批量将旧的误报告警标记为 auto_resolved
// 当 scanner 为空字符串时，不限制扫描器（清理所有扫描器的误报）
func (s *Storage) BatchResolveFindings(scanner string, titlePatterns []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	resolvedCount := 0

	for _, pattern := range titlePatterns {
		var result sql.Result
		var err error
		if scanner == "" {
			// 不限制扫描器，清理所有扫描器的误报
			result, err = s.db.Exec(
				`UPDATE findings SET status='auto_resolved', fixed_at=?, updated_at=?
				 WHERE status='open' AND title LIKE ?`,
				now, now, "%"+pattern+"%",
			)
		} else {
			result, err = s.db.Exec(
				`UPDATE findings SET status='auto_resolved', fixed_at=?, updated_at=?
				 WHERE scanner=? AND status='open' AND title LIKE ?`,
				now, now, scanner, "%"+pattern+"%",
			)
		}
		if err != nil {
			return resolvedCount, fmt.Errorf("batch resolve findings: %w", err)
		}
		affected, _ := result.RowsAffected()
		resolvedCount += int(affected)
	}

	if resolvedCount > 0 {
		if scanner == "" {
			fmt.Printf("[Storage] 批量标记 %d 个发现项为已消失（误报清理，所有扫描器）\n", resolvedCount)
		} else {
			fmt.Printf("[Storage] 批量标记 %d 个 %s 发现项为已消失（误报清理）\n", resolvedCount, scanner)
		}
	}
	return resolvedCount, nil
}

// CleanupOldFindings 清理过期的发现项
// 删除 90 天前的已处理（非 open）发现项，防止数据库无限膨胀
func (s *Storage) CleanupOldFindings() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -90)
	result, err := s.db.Exec(
		`DELETE FROM findings WHERE status != 'open' AND created_at < ?`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("cleanup old findings: %w", err)
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		fmt.Printf("[Storage] 清理了 %d 条过期发现项\n", deleted)
	}
	return nil
}

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Scanner, &f.ScannerSub, &f.Severity, &f.Title, &f.Description, &f.Target, &f.Detail,
			&f.Suggestion, &f.Consequence, &f.Status, &f.Snapshot, &f.ConfirmedBy, &f.ConfirmedAt, &f.FixedAt, &f.CreatedAt, &f.UpdatedAt); err != nil {
			continue
		}
		findings = append(findings, f)
	}
	return findings, nil
}
