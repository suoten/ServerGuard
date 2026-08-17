package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/storage"
)

// ConfigVersionManager implements Module V: Config Version (Git-like).
// Provides: commit history, tags, diff view, one-click rollback,
// change approval, export/import.
type ConfigVersionManager struct {
	mu        sync.Mutex
	repoDir   string               // directory to store version data
	tags      map[string]string    // tag name -> commit hash
	approvals map[string]*Approval // commit hash -> pending approval
	store     *storage.Storage     // SQLite 持久化层
}

// Approval represents a change approval request.
type Approval struct {
	CommitHash  string
	FilePath    string
	RequestedBy string
	RequestedAt time.Time
	Approved    bool
	ApprovedBy  string
	ApprovedAt  time.Time
	Status      string // pending, approved, rejected
}

// Commit represents a config version commit.
type Commit struct {
	Hash       string    `json:"hash"`
	ParentHash string    `json:"parent_hash"`
	FilePath   string    `json:"file_path"`
	Timestamp  time.Time `json:"timestamp"`
	Author     string    `json:"author"`
	Message    string    `json:"message"`
	Hash256    string    `json:"hash_256"`
	Size       int64     `json:"size"`
	Diff       string    `json:"diff,omitempty"`
}

// NewConfigVersionManager creates a new ConfigVersionManager.
func NewConfigVersionManager(repoDir string, store *storage.Storage) *ConfigVersionManager {
	if repoDir == "" {
		repoDir = "/var/lib/serverguard/config-repo"
	}
	os.MkdirAll(repoDir, 0750)
	os.MkdirAll(filepath.Join(repoDir, "commits"), 0750)
	cvm := &ConfigVersionManager{
		repoDir:   repoDir,
		tags:      make(map[string]string),
		approvals: make(map[string]*Approval),
		store:     store,
	}
	cvm.loadTags()
	return cvm
}

// Commit creates a new version commit of a config file.
func (c *ConfigVersionManager) Commit(filePath, author, message string) (*Commit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read current file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Compute hash
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])[:16] // short hash

	// Get parent hash (latest commit for this file)
	parentHash := c.getLatestCommitHash(filePath)

	// Create commit
	commit := &Commit{
		Hash:       hashStr,
		ParentHash: parentHash,
		FilePath:   filePath,
		Timestamp:  time.Now(),
		Author:     author,
		Message:    message,
		Hash256:    hex.EncodeToString(hash[:]),
		Size:       int64(len(content)),
	}

	// Compute diff if parent exists
	if parentHash != "" {
		parentContent, _ := c.readCommitContent(parentHash, filePath)
		commit.Diff = c.computeDiff(string(parentContent), string(content))
	}

	// Save commit metadata
	commitPath := filepath.Join(c.repoDir, "commits", hashStr+".json")
	data, _ := json.MarshalIndent(commit, "", "  ")
	os.WriteFile(commitPath, data, 0640)

	// Save content snapshot
	snapshotPath := filepath.Join(c.repoDir, "commits", hashStr+".content")
	os.WriteFile(snapshotPath, content, 0640)

	// Update latest commit pointer
	c.updateLatestCommit(filePath, hashStr)

	return commit, nil
}

// GetHistory returns the commit history for a file.
func (c *ConfigVersionManager) GetHistory(filePath string) []*Commit {
	c.mu.Lock()
	defer c.mu.Unlock()

	var history []*Commit
	hash := c.getLatestCommitHash(filePath)

	for hash != "" {
		commit := c.loadCommit(hash)
		if commit == nil {
			break
		}
		history = append(history, commit)
		hash = commit.ParentHash
	}

	return history
}

// Rollback rolls back a file to a specific commit.
func (c *ConfigVersionManager) Rollback(filePath, commitHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read the commit's content snapshot
	snapshotPath := filepath.Join(c.repoDir, "commits", commitHash+".content")
	content, err := os.ReadFile(snapshotPath)
	if err != nil {
		return fmt.Errorf("snapshot not found: %w", err)
	}

	// Backup current content
	currentContent, _ := os.ReadFile(filePath)

	// Write old content back
	if err := os.WriteFile(filePath, content, 0640); err != nil {
		return err
	}

	// Create a new commit for the rollback
	rollbackCommit := &Commit{
		Hash:       fmt.Sprintf("rb-%s-%d", commitHash[:8], time.Now().Unix()),
		ParentHash: c.getLatestCommitHash(filePath),
		FilePath:   filePath,
		Timestamp:  time.Now(),
		Author:     "serverguard",
		Message:    fmt.Sprintf("Rollback to %s", commitHash),
		Hash256:    func() string { h := sha256.Sum256(content); return hex.EncodeToString(h[:]) }(),
		Size:       int64(len(content)),
		Diff:       c.computeDiff(string(currentContent), string(content)),
	}

	commitPath := filepath.Join(c.repoDir, "commits", rollbackCommit.Hash+".json")
	data, _ := json.MarshalIndent(rollbackCommit, "", "  ")
	os.WriteFile(commitPath, data, 0640)

	snapshotPath = filepath.Join(c.repoDir, "commits", rollbackCommit.Hash+".content")
	os.WriteFile(snapshotPath, content, 0640)

	c.updateLatestCommit(filePath, rollbackCommit.Hash)

	return nil
}

// CreateTag creates a named tag pointing to a commit.
func (c *ConfigVersionManager) CreateTag(name, commitHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tags[name] = commitHash
	c.saveTags()
	// 同步到 SQLite 持久化层
	if c.store != nil {
		_ = c.store.TagVersion(commitHash, name)
	}
	return nil
}

// GetTag returns the commit hash for a tag.
func (c *ConfigVersionManager) GetTag(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tags[name]
}

// RequestApproval creates a change approval request.
func (c *ConfigVersionManager) RequestApproval(commitHash, filePath, requestedBy string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.approvals[commitHash] = &Approval{
		CommitHash:  commitHash,
		FilePath:    filePath,
		RequestedBy: requestedBy,
		RequestedAt: time.Now(),
		Status:      "pending",
	}
}

// ApproveChange approves a change.
func (c *ConfigVersionManager) ApproveChange(commitHash, approvedBy string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	approval, exists := c.approvals[commitHash]
	if !exists {
		return fmt.Errorf("approval not found")
	}

	approval.Approved = true
	approval.ApprovedBy = approvedBy
	approval.ApprovedAt = time.Now()
	approval.Status = "approved"

	return nil
}

// ExportHistory exports all commit history as JSON.
// 同时支持通过 storage 层导出 YAML 格式。
func (c *ConfigVersionManager) ExportHistory(filePath string) ([]byte, error) {
	history := c.GetHistory(filePath)
	return json.MarshalIndent(history, "", "  ")
}

// ExportYAML 通过 storage 层导出配置版本为 YAML 格式。
func (c *ConfigVersionManager) ExportYAML(filePath string) ([]byte, error) {
	if c.store != nil {
		return c.store.ExportYAML(filePath)
	}
	return nil, fmt.Errorf("storage not available")
}

// ImportHistory imports commit history from JSON.
func (c *ConfigVersionManager) ImportHistory(data []byte) error {
	var commits []*Commit
	if err := json.Unmarshal(data, &commits); err != nil {
		return err
	}

	for _, commit := range commits {
		commitPath := filepath.Join(c.repoDir, "commits", commit.Hash+".json")
		data, _ := json.MarshalIndent(commit, "", "  ")
		os.WriteFile(commitPath, data, 0640)
	}

	return nil
}

// ImportYAML 通过 storage 层从 YAML 格式导入配置版本。
func (c *ConfigVersionManager) ImportYAML(data []byte) error {
	if c.store != nil {
		return c.store.ImportYAML(data)
	}
	return fmt.Errorf("storage not available")
}

// computeDiff computes a simple line-by-line diff.
func (c *ConfigVersionManager) computeDiff(old, new string) string {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")

	var diff strings.Builder
	maxLines := len(oldLines)
	if len(newLines) > maxLines {
		maxLines = len(newLines)
	}

	for i := 0; i < maxLines; i++ {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}

		if oldLine != newLine {
			if oldLine != "" {
				diff.WriteString(fmt.Sprintf("- %s\n", oldLine))
			}
			if newLine != "" {
				diff.WriteString(fmt.Sprintf("+ %s\n", newLine))
			}
		} else {
			diff.WriteString(fmt.Sprintf("  %s\n", oldLine))
		}
	}

	return diff.String()
}

// Helper methods

func (c *ConfigVersionManager) getLatestCommitHash(filePath string) string {
	pointerPath := filepath.Join(c.repoDir, "commits", "latest_"+sanitizeFileName(filePath))
	data, err := os.ReadFile(pointerPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *ConfigVersionManager) updateLatestCommit(filePath, hash string) {
	pointerPath := filepath.Join(c.repoDir, "commits", "latest_"+sanitizeFileName(filePath))
	os.WriteFile(pointerPath, []byte(hash), 0640)
}

func (c *ConfigVersionManager) loadCommit(hash string) *Commit {
	commitPath := filepath.Join(c.repoDir, "commits", hash+".json")
	data, err := os.ReadFile(commitPath)
	if err != nil {
		return nil
	}
	var commit Commit
	if err := json.Unmarshal(data, &commit); err != nil {
		return nil
	}
	return &commit
}

func (c *ConfigVersionManager) readCommitContent(hash, filePath string) ([]byte, error) {
	snapshotPath := filepath.Join(c.repoDir, "commits", hash+".content")
	return os.ReadFile(snapshotPath)
}

func (c *ConfigVersionManager) loadTags() {
	tagsPath := filepath.Join(c.repoDir, "tags.json")
	data, err := os.ReadFile(tagsPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &c.tags)
}

func (c *ConfigVersionManager) saveTags() {
	tagsPath := filepath.Join(c.repoDir, "tags.json")
	data, _ := json.MarshalIndent(c.tags, "", "  ")
	os.WriteFile(tagsPath, data, 0640)
}

func sanitizeFileName(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "/", "_"), "\\", "_")
}

// GetTags returns all tags sorted by name.
func (c *ConfigVersionManager) GetTags() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make(map[string]string)
	for k, v := range c.tags {
		result[k] = v
	}
	return result
}

// GetPendingApprovals returns all pending approval requests.
func (c *ConfigVersionManager) GetPendingApprovals() []*Approval {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []*Approval
	for _, a := range c.approvals {
		if a.Status == "pending" {
			result = append(result, a)
		}
	}
	// Sort by requested time
	sort.Slice(result, func(i, j int) bool {
		return result[i].RequestedAt.Before(result[j].RequestedAt)
	})
	return result
}
