package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type API struct {
	store     *Store
	uploadDir string
}

func NewAPI(store *Store, uploadDir string) *API {
	// Ensure upload directory exists
	os.MkdirAll(uploadDir, 0755)
	return &API{store: store, uploadDir: uploadDir}
}

// ===== Public API =====

// GetContent returns all website content for frontend rendering.
func (a *API) GetContent(c *gin.Context) {
	content, err := a.store.GetContent()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load content"})
		return
	}
	c.JSON(200, content)
}

// GetPricing returns all enabled pricing plans.
func (a *API) GetPricing(c *gin.Context) {
	plans, err := a.store.GetPricing()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load pricing"})
		return
	}
	c.JSON(200, gin.H{"plans": plans})
}

// GetBlogList returns published blog posts with pagination.
func (a *API) GetBlogList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 10
	}

	posts, err := a.store.GetBlogPosts(page, pageSize)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load posts"})
		return
	}
	if posts == nil {
		posts = []BlogPost{}
	}
	c.JSON(200, gin.H{"posts": posts})
}

// GetBlogPost returns a single blog post by slug.
func (a *API) GetBlogPost(c *gin.Context) {
	slug := c.Param("slug")
	post, err := a.store.GetBlogPost(slug)
	if err != nil {
		c.JSON(404, gin.H{"error": "post not found"})
		return
	}
	c.JSON(200, post)
}

// GetSecurityList returns all security advisories.
func (a *API) GetSecurityList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	advisories, err := a.store.GetSecurityAdvisories(page, pageSize)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load advisories"})
		return
	}
	if advisories == nil {
		advisories = []SecurityAdvisory{}
	}
	c.JSON(200, gin.H{"advisories": advisories})
}

// GetVersions returns all enabled versions for the public download page.
// file_path is intentionally omitted to avoid leaking server paths.
func (a *API) GetVersions(c *gin.Context) {
	versions, err := a.store.GetPublicVersions()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load versions"})
		return
	}
	type publicVersion struct {
		ID           int    `json:"id"`
		Version      string `json:"version"`
		Channel      string `json:"channel"`
		OS           string `json:"os"`
		Arch         string `json:"arch"`
		ReleaseNotes string `json:"release_notes"`
		SHA256       string `json:"sha256"`
		FileSize     int64  `json:"file_size"`
		Critical     bool   `json:"critical"`
		Downloads    int    `json:"downloads"`
		CreatedAt    string `json:"created_at"`
	}
	out := make([]publicVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, publicVersion{
			ID: v.ID, Version: v.Version, Channel: v.Channel, OS: v.OS, Arch: v.Arch,
			ReleaseNotes: v.ReleaseNotes, SHA256: v.SHA256, FileSize: v.FileSize,
			Critical: v.Critical, Downloads: v.Downloads, CreatedAt: v.CreatedAt,
		})
	}
	c.JSON(200, gin.H{"versions": out})
}

// GetLatestVersion is the endpoint called by Agent's CheckForUpdate.
// GET /api/v1/latest?channel=stable&os=linux&arch=amd64
// Returns the latest version info if a newer version exists.
func (a *API) GetLatestVersion(c *gin.Context) {
	channel := c.DefaultQuery("channel", "stable")
	osName := c.DefaultQuery("os", "")
	arch := c.DefaultQuery("arch", "")

	v, err := a.store.GetLatestVersion(channel, osName, arch)
	if err != nil || v == nil {
		c.JSON(200, gin.H{
			"version":       "0.0.0",
			"up_to_date":    true,
			"download_url":  "",
			"release_notes": "",
			"critical":      false,
		})
		return
	}

	// 使用相对路径，Agent 会自动拼接 server_url + download_url
	downloadURL := fmt.Sprintf("/download/%d", v.ID)

	c.JSON(200, gin.H{
		"version":       v.Version,
		"up_to_date":    false,
		"download_url":  downloadURL,
		"sha256":        v.SHA256,
		"signature":     v.Signature,
		"release_notes": v.ReleaseNotes,
		"critical":      v.Critical,
	})
}

// DownloadVersion serves the binary file for download.
// GET /api/v1/download/:id
func (a *API) DownloadVersion(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}

	versions, err := a.store.GetAllVersions()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to find version"})
		return
	}

	var target *VersionInfo
	for _, v := range versions {
		if v.ID == id {
			target = &v
			break
		}
	}
	if target == nil {
		c.JSON(404, gin.H{"error": "version not found"})
		return
	}

	if target.FilePath == "" || !fileExists(target.FilePath) {
		c.JSON(404, gin.H{"error": "file not found"})
		return
	}

	a.store.IncrementDownloads(id)
	c.FileAttachment(target.FilePath, filepath.Base(target.FilePath))
}

// GetStats returns public statistics.
func (a *API) GetStats(c *gin.Context) {
	content, _ := a.store.GetContent()
	stats, _ := content["stats"]
	if stats == nil {
		stats = []map[string]string{
			{"value": "16MB", "label": "单二进制大小"},
			{"value": "<50MB", "label": "内存占用"},
		}
	}
	c.JSON(200, gin.H{"stats": stats})
}

// ===== Admin API =====

// AdminLogin handles admin authentication.
func (a *API) AdminLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	ok, err := a.store.VerifyAdmin(req.Username, req.Password)
	if err != nil || !ok {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	token, err := generateToken(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(200, gin.H{"token": token, "username": req.Username})
}

// AdminChangePassword handles password change.
func (a *API) AdminChangePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if len(req.NewPassword) < 6 {
		c.JSON(400, gin.H{"error": "新密码至少 6 位"})
		return
	}
	username, _ := c.Get("username")
	if username == nil {
		username = "admin"
	}
	if err := a.store.ChangeAdminPassword(username.(string), req.OldPassword, req.NewPassword); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true, "message": "密码修改成功"})
}

// AdminGetContent returns all content for editing.
func (a *API) AdminGetContent(c *gin.Context) {
	content, err := a.store.GetContent()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load content"})
		return
	}
	c.JSON(200, content)
}

// AdminUpdateContent updates website content.
func (a *API) AdminUpdateContent(c *gin.Context) {
	var data map[string]any
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := a.store.UpdateContent(data); err != nil {
		c.JSON(500, gin.H{"error": "failed to save content"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminGetPricing returns all pricing plans (including disabled).
func (a *API) AdminGetPricing(c *gin.Context) {
	plans, err := a.store.GetAllPricing()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load pricing"})
		return
	}
	if plans == nil {
		plans = []map[string]any{}
	}
	c.JSON(200, gin.H{"plans": plans})
}

// AdminUpdatePricing updates all pricing plans.
func (a *API) AdminUpdatePricing(c *gin.Context) {
	var req struct {
		Plans []map[string]any `json:"plans"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := a.store.UpdatePricing(req.Plans); err != nil {
		c.JSON(500, gin.H{"error": "failed to save pricing"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminGetVersions returns all versions.
func (a *API) AdminGetVersions(c *gin.Context) {
	versions, err := a.store.GetAllVersions()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load versions"})
		return
	}
	if versions == nil {
		versions = []VersionInfo{}
	}
	c.JSON(200, gin.H{"versions": versions})
}

// AdminCreateVersion handles multipart upload of new version binary.
func (a *API) AdminCreateVersion(c *gin.Context) {
	version := c.PostForm("version")
	channel := c.DefaultPostForm("channel", "stable")
	osName := c.DefaultPostForm("os", "linux")
	arch := c.DefaultPostForm("arch", "amd64")
	releaseNotes := c.PostForm("release_notes")
	critical := c.PostForm("critical") == "true"

	if version == "" {
		c.JSON(400, gin.H{"error": "version is required"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "file is required"})
		return
	}

	// Save file: serverguard-agent-v<ver>-<os>-<arch>[.exe]
	filename := fmt.Sprintf("serverguard-agent-v%s-%s-%s", version, osName, arch)
	if osName == "windows" {
		filename += ".exe"
	}
	destPath := filepath.Join(a.uploadDir, filename)

	if err := c.SaveUploadedFile(file, destPath); err != nil {
		c.JSON(500, gin.H{"error": "failed to save file: " + err.Error()})
		return
	}

	// Calculate SHA256
	hash, err := calcSHA256(destPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to calculate sha256"})
		return
	}

	// Get file size
	var fileSize int64
	if info, err := os.Stat(destPath); err == nil {
		fileSize = info.Size()
	}

	v := &VersionInfo{
		Version:      version,
		Channel:      channel,
		OS:           osName,
		Arch:         arch,
		ReleaseNotes: releaseNotes,
		SHA256:       hash,
		FilePath:     destPath,
		FileSize:     fileSize,
		Critical:     critical,
	}

	if err := a.store.CreateVersion(v); err != nil {
		c.JSON(500, gin.H{"error": "failed to create version record: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"id":      v.ID,
		"version": v.Version,
		"os":      v.OS,
		"arch":    v.Arch,
		"sha256":  v.SHA256,
		"message": fmt.Sprintf("版本 v%s (%s/%s) 发布成功！对应平台的 Agent 将自动检测到此更新。", version, osName, arch),
	})
}

// AdminUpdateVersion toggles version visibility.
func (a *API) AdminUpdateVersion(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)

	var data map[string]any
	c.ShouldBindJSON(&data)

	if err := a.store.UpdateVersion(id, data); err != nil {
		c.JSON(500, gin.H{"error": "failed to update version"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminDeleteVersion removes a version.
func (a *API) AdminDeleteVersion(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)

	// Get file path before deleting
	versions, _ := a.store.GetAllVersions()
	for _, v := range versions {
		if v.ID == id && v.FilePath != "" {
			os.Remove(v.FilePath)
			break
		}
	}

	if err := a.store.DeleteVersion(id); err != nil {
		c.JSON(500, gin.H{"error": "failed to delete version"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminGetBlogList returns all blog posts (including drafts).
func (a *API) AdminGetBlogList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	posts, err := a.store.GetAllBlogPosts(page, pageSize)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load posts"})
		return
	}
	if posts == nil {
		posts = []BlogPost{}
	}
	c.JSON(200, gin.H{"posts": posts})
}

// AdminCreateBlogPost creates a new blog post.
func (a *API) AdminCreateBlogPost(c *gin.Context) {
	var p BlogPost
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := a.store.CreateBlogPost(&p); err != nil {
		c.JSON(500, gin.H{"error": "failed to create post: " + err.Error()})
		return
	}
	c.JSON(200, p)
}

// AdminUpdateBlogPost updates an existing blog post.
func (a *API) AdminUpdateBlogPost(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)

	var p BlogPost
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := a.store.UpdateBlogPost(id, &p); err != nil {
		c.JSON(500, gin.H{"error": "failed to update post"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminDeleteBlogPost removes a blog post.
func (a *API) AdminDeleteBlogPost(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := a.store.DeleteBlogPost(id); err != nil {
		c.JSON(500, gin.H{"error": "failed to delete post"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminGetSecurityList returns all security advisories.
func (a *API) AdminGetSecurityList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	advisories, err := a.store.GetSecurityAdvisories(page, pageSize)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load advisories"})
		return
	}
	if advisories == nil {
		advisories = []SecurityAdvisory{}
	}
	c.JSON(200, gin.H{"advisories": advisories})
}

// AdminCreateSecurityAdvisory creates a new security advisory.
func (a *API) AdminCreateSecurityAdvisory(c *gin.Context) {
	var a2 SecurityAdvisory
	if err := c.ShouldBindJSON(&a2); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := a.store.CreateSecurityAdvisory(&a2); err != nil {
		c.JSON(500, gin.H{"error": "failed to create advisory"})
		return
	}
	c.JSON(200, a2)
}

// AdminUpdateSecurityAdvisory updates an existing security advisory.
func (a *API) AdminUpdateSecurityAdvisory(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)

	var adv SecurityAdvisory
	if err := c.ShouldBindJSON(&adv); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := a.store.UpdateSecurityAdvisory(id, &adv); err != nil {
		c.JSON(500, gin.H{"error": "failed to update advisory"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminDeleteSecurityAdvisory removes a security advisory.
func (a *API) AdminDeleteSecurityAdvisory(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := a.store.DeleteSecurityAdvisory(id); err != nil {
		c.JSON(500, gin.H{"error": "failed to delete advisory"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// AdminGetDashboardStats returns stats for the admin dashboard.
func (a *API) AdminGetDashboardStats(c *gin.Context) {
	versions, _ := a.store.GetAllVersions()
	totalDownloads := 0
	for _, v := range versions {
		totalDownloads += v.Downloads
	}

	allPosts, _ := a.store.GetAllBlogPosts(1, 1000)
	publishedPosts := 0
	for _, p := range allPosts {
		if p.Status == "published" {
			publishedPosts++
		}
	}

	advisories, _ := a.store.GetSecurityAdvisories(1, 1000)

	c.JSON(200, gin.H{
		"versions":             len(versions),
		"downloads":           totalDownloads,
		"blogPosts":           publishedPosts,
		"securityAdvisories":  len(advisories),
	})
}

// ===== Helpers =====

func calcSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// AuthMiddleware checks for a valid JWT token on admin routes.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip login endpoint
		if strings.HasSuffix(c.Request.URL.Path, "/admin/login") {
			c.Next()
			return
		}

		auth := c.GetHeader("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		claims, err := parseToken(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}
		c.Set("username", claims["username"])
		c.Next()
	}
}
