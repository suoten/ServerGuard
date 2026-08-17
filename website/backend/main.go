package main

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

//go:embed dist
var distFS embed.FS

var indexHTML []byte

func main() {
	port := os.Getenv("SG_WEB_PORT")
	if port == "" {
		port = "8422"
	}

	dataDir := os.Getenv("SG_WEB_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	uploadDir := filepath.Join(dataDir, "uploads")
	dbPath := filepath.Join(dataDir, "serverguard.db")

	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(uploadDir, 0755)

	// 预读 index.html
	indexHTML, _ = fs.ReadFile(distFS, "dist/index.html")
	if indexHTML == nil {
		log.Fatal("Failed to read embedded index.html — dist directory may be empty. Run build.sh first.")
	}

	store, err := NewStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}
	defer store.db.Close()

	fmt.Println("========================================")
	fmt.Println("  ServerGuard Website")
	fmt.Println("========================================")
	fmt.Printf("  Port:        %s\n", port)
	fmt.Printf("  Database:    %s\n", dbPath)
	fmt.Printf("  Upload Dir:  %s\n", uploadDir)
	fmt.Println("  Admin:       admin / admin123")
	fmt.Println("  ⚠️  请立即修改默认密码！")
	fmt.Println("========================================")

	api := NewAPI(store, uploadDir)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// CORS — 确保 Access-Control-Allow-Origin 出现在所有响应上
	// crossorigin 属性让浏览器即使同源也发 Origin 头，
	// 如果响应缺 CORS 头，浏览器会拒绝加载 ES Module
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		MaxAge:           12 * time.Hour,
	}))

	// 额外保险：所有响应都加 CORS 头（即使 gin-contrib/cors 没加）
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Next()
	})

	// OPTIONS 预检直接返回 204
	r.OPTIONS("/*any", func(c *gin.Context) {
		c.Status(204)
	})

	// 静态资源（JS/CSS/图片）
	r.GET("/assets/*filepath", serveEmbeddedFile)
	r.GET("/favicon.svg", serveEmbeddedFile)
	r.GET("/install.sh", serveEmbeddedFile)
	r.GET("/manifest.json", serveEmbeddedFile)

	// SPA fallback
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api") {
			c.JSON(404, gin.H{"error": "not found"})
			return
		}
		cleanPath := strings.TrimPrefix(path, "/")
		if cleanPath == "" || !strings.Contains(cleanPath, ".") {
			// 根路径或无扩展名 → Vue Router 客户端路由
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Data(200, "text/html; charset=utf-8", indexHTML)
			return
		}
		// 有扩展名 → 尝试静态文件
		if data, err := fs.ReadFile(distFS, "dist/"+cleanPath); err == nil {
			c.Data(200, contentType(cleanPath), data)
			return
		}
		// 找不到 → index.html
		c.Data(200, "text/html; charset=utf-8", indexHTML)
	})

	// Public API
	v1 := r.Group("/api/v1")
	{
		v1.GET("/content", api.GetContent)
		v1.GET("/pricing", api.GetPricing)
		v1.GET("/blog", api.GetBlogList)
		v1.GET("/blog/:slug", api.GetBlogPost)
		v1.GET("/security", api.GetSecurityList)
		v1.GET("/versions", api.GetVersions)
		v1.GET("/latest", api.GetLatestVersion)
		v1.GET("/download/:id", api.DownloadVersion)
		v1.GET("/stats", api.GetStats)
	}
	v1.POST("/admin/login", api.AdminLogin)

	admin := v1.Group("/admin")
	admin.Use(AuthMiddleware())
	{
		admin.GET("/content", api.AdminGetContent)
		admin.PUT("/content", api.AdminUpdateContent)
		admin.GET("/pricing", api.AdminGetPricing)
		admin.PUT("/pricing", api.AdminUpdatePricing)
		admin.GET("/versions", api.AdminGetVersions)
		admin.POST("/versions", api.AdminCreateVersion)
		admin.PUT("/versions/:id", api.AdminUpdateVersion)
		admin.DELETE("/versions/:id", api.AdminDeleteVersion)
		admin.GET("/blog", api.AdminGetBlogList)
		admin.POST("/blog", api.AdminCreateBlogPost)
		admin.PUT("/blog/:id", api.AdminUpdateBlogPost)
		admin.DELETE("/blog/:id", api.AdminDeleteBlogPost)
		admin.GET("/security", api.AdminGetSecurityList)
		admin.POST("/security", api.AdminCreateSecurityAdvisory)
		admin.PUT("/security/:id", api.AdminUpdateSecurityAdvisory)
		admin.DELETE("/security/:id", api.AdminDeleteSecurityAdvisory)
		admin.GET("/stats", api.AdminGetDashboardStats)
		admin.PUT("/password", api.AdminChangePassword)
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	log.Printf("Server starting on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func serveEmbeddedFile(c *gin.Context) {
	path := c.Request.URL.Path
	cleanPath := strings.TrimPrefix(path, "/")
	if cleanPath == "" {
		c.Data(200, "text/html; charset=utf-8", indexHTML)
		return
	}
	data, err := fs.ReadFile(distFS, "dist/"+cleanPath)
	if err != nil {
		c.Status(404)
		return
	}
	// 用 http.ServeContent 确保正确的 Content-Type、Content-Length、ETag
	c.Header("Content-Type", contentType(cleanPath))
	http.ServeContent(c.Writer, c.Request, cleanPath, time.Time{}, bytes.NewReader(data))
}

func contentType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".map":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}