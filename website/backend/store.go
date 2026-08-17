package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database for the website.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the SQLite database and initializes tables.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.migrateVersionsColumns(); err != nil {
		return nil, fmt.Errorf("migrate versions columns: %w", err)
	}
	if err := s.seedDefaults(); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	return s, nil
}

// migrateVersionsColumns adds os/arch columns to an existing versions table
// created before multi-platform support was introduced.
func (s *Store) migrateVersionsColumns() error {
	cols := map[string]bool{}
	rows, err := s.db.Query("PRAGMA table_info(versions)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if !cols["os"] {
		if _, err := s.db.Exec("ALTER TABLE versions ADD COLUMN os TEXT DEFAULT ''"); err != nil {
			return err
		}
	}
	if !cols["arch"] {
		if _, err := s.db.Exec("ALTER TABLE versions ADD COLUMN arch TEXT DEFAULT ''"); err != nil {
			return err
		}
	}
	return nil
}

// migrate creates all tables.
func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS site_content (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pricing_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tagline TEXT,
    price_cny TEXT,
    price_usd TEXT,
    period TEXT,
    note TEXT,
    cta TEXT,
    popular INTEGER DEFAULT 0,
    coming_soon INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    features TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    channel TEXT DEFAULT 'stable',
    os TEXT DEFAULT '',
    arch TEXT DEFAULT '',
    release_notes TEXT,
    sha256 TEXT,
    signature TEXT,
    file_path TEXT,
    file_size INTEGER,
    critical INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    downloads INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blog_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    excerpt TEXT,
    content TEXT,
    author TEXT DEFAULT 'Admin',
    category TEXT DEFAULT '技术分享',
    status TEXT DEFAULT 'draft',
    views INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_advisories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    title TEXT NOT NULL,
    summary TEXT,
    description TEXT,
    severity TEXT DEFAULT 'medium',
    affected_versions TEXT,
    patched_version TEXT,
    published_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`)
	return err
}

// seedDefaults inserts default admin user and default content if tables are empty.
func (s *Store) seedDefaults() error {
	// Default admin (username: admin, password: admin123 — should change immediately)
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	if count == 0 {
		hash, _ := hashPassword("admin123")
		s.db.Exec("INSERT INTO admin_users (username, password_hash) VALUES (?, ?)", "admin", hash)
	}

	// Default site content
	s.db.QueryRow("SELECT COUNT(*) FROM site_content").Scan(&count)
	if count == 0 {
		defaults := map[string]string{
			"hero_badge":         "v0.1.0 社区版现已发布 · 完全免费",
			"hero_title_line1":   "你的服务器",
			"hero_title_line2":   "7×24 小时自动守护",
			"hero_subtitle":      "资源监控 → 异常检测 → 自动修复 → 微信告警\n16MB 单二进制，零依赖，装上就不用管。",
			"install_command":    "curl -sSL https://sg.jjtt.net/install.sh | bash",
			"footer_desc":        "让服务器自己照顾自己。7×24 小时自动守护、自动修复、自动告警。",
			"footer_slogan":      "Install & Forget. Guard & Heal.",
			"github_url":         "https://github.com/suoten/serverguard",
			"contact_email":      "support@serverguard.cn",
			"testimonial_quote":  "装了一周帮我处理了 4 次问题，我一次都没被叫醒。",
			"testimonial_author": "某独立开发者",
			"testimonial_role":   "5 台服务器的全栈开发者",
			"features":           `[{"icon":"🔥","title":"自动自愈","desc":"不只是告警，是真的修复"},{"icon":"🧠","title":"智能运维","desc":"越用越懂你的服务器"},{"icon":"🛡️","title":"安全防护","desc":"SSH暴破封禁+WebShell检测"},{"icon":"📜","title":"日志守护","desc":"日志暴涨自动轮转压缩"}]`,
			"stats":              `[{"value":"16MB","label":"单二进制大小"},{"value":"<50MB","label":"内存占用"},{"value":"<1%","label":"CPU占用"},{"value":"26","label":"守护模块"}]`,
			"faqs":               `[{"q":"支持哪些操作系统？","a":"Windows Server 2016+ 和主流 Linux 发行版"},{"q":"会占用多少资源？","a":"Agent 常驻内存 < 50MB，CPU < 1%"},{"q":"和宝塔有什么区别？","a":"宝塔是Web管理面板，ServerGuard是服务器守护系统"}]`,
		}
		for k, v := range defaults {
			s.db.Exec("INSERT INTO site_content (key, value) VALUES (?, ?)", k, v)
		}
	}

	// Default pricing plans
	s.db.QueryRow("SELECT COUNT(*) FROM pricing_plans").Scan(&count)
	if count == 0 {
		plans := []struct {
			name, tagline, priceCNY, priceUSD, period, note, cta, features string
			popular, comingSoon, sortOrder                                 int
		}{
			{"社区版", "个人开发者首选", "¥0", "$0", "永久免费", "开源（AGPL）", "免费下载", `["资源守护","进程保活（3个）","日志防护","证书告警","邮件告警"]`, 0, 0, 1},
			{"专业版", "独立开发者/小团队", "¥349", "$49", "大版本永久", "当前大版本永久使用", "立即购买", `["社区版全部功能","证书自动续期","入侵检测","文件篡改检测","全渠道告警"]`, 1, 0, 2},
			{"企业版", "中小企业/团队", "¥699", "$99", "/年", "10 节点", "购买企业版", `["专业版全部功能","多服务器面板","批量策略下发","API接口","RBAC","优先支持"]`, 0, 0, 3},
			{"旗舰版", "大型组织", "¥2,099", "$299", "/年", "", "联系销售", `["企业版全部功能","不限节点","电话告警","专属支持","代运维可选"]`, 0, 1, 4},
		}
		for _, p := range plans {
			s.db.Exec(`INSERT INTO pricing_plans
				(name, tagline, price_cny, price_usd, period, note, cta, features, popular, coming_soon, sort_order)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				p.name, p.tagline, p.priceCNY, p.priceUSD, p.period, p.note, p.cta, p.features,
				p.popular, p.comingSoon, p.sortOrder)
		}
	}

	// Default blog posts
	s.db.QueryRow("SELECT COUNT(*) FROM blog_posts").Scan(&count)
	if count == 0 {
		seedBlogPosts(s.db)
	}

	return nil
}

// seedBlogPosts inserts the initial published blog posts.
func seedBlogPosts(db *sql.DB) {
	type post struct {
		title, slug, excerpt, content, author, category string
	}
	posts := []post{
		{
			title:    "ServerGuard v0.1.0 发布：让服务器自己照顾自己",
			slug:     "serverguard-v010-released",
			excerpt:  "历经真实故障打磨，ServerGuard 首个公开版本正式发布：16MB 单二进制、26 个守护模块、自动自愈 + 智能告警，装上就不用管。",
			author:   "ServerGuard 团队",
			category: "产品发布",
			content: `## 为什么做 ServerGuard

过去一年里，我的服务器经历了几乎所有典型故障：CPU 爆缸 273%、日志暴涨 18.62GB 撑爆磁盘、僵尸进程残留、SSH 被暴力破解、SSL 证书过期浏览器报红叉……

每一次都是凌晨被叫醒，SSH 上去手动排查。监控工具只会告诉我"服务器死了"，**而我要的是"不让它死"**。

于是有了 ServerGuard。

## v0.1.0 有什么

- **26 个守护模块**：资源、进程、端口、日志、证书、安全、网站、流量……全覆盖
- **自动自愈**：磁盘满了自动清、进程死了自动拉起、暴破 IP 自动封、证书到期自动续
- **智能运维**：告警收敛不刷屏、168 时段基线异常检测、磁盘写满预测、根因分析
- **极致轻量**：16MB 单二进制，内存 <50MB，CPU <1%，零外部依赖

## 30 秒安装

` + "```bash" + `
curl -sSL https://sg.jjtt.net/install.sh | bash
` + "```" + `

支持 CentOS 7+ / Ubuntu 18.04+ / Debian 10+ / Rocky Linux 8+ / Windows Server 2016+。

## 下一步

多机 Hub 版（跨服务器关联分析）正在路上。社区版永久免费，欢迎下载试用并反馈意见。`,
		},
		{
			title:    "凌晨 3 点的告警不再响起：用基线检测替代阈值告警",
			slug:     "baseline-anomaly-detection",
			excerpt:  "阈值告警最大的问题是：你不知道 80% 到底算不算高。ServerGuard 按「周几×小时」把历史分成 168 个时段分别学习，只在偏离自身常态时才告警。",
			author:   "ServerGuard 团队",
			 category: "技术分享",
			content: `## 阈值告警的根本问题

传统监控的经典配置：CPU > 90% 告警。结果呢？

- 每周二下午定时跑批，CPU 必然 95% —— 每周误报一次
- 凌晨业务低谷 CPU 突然到 40% —— 可能是挖矿，但阈值没触发

**固定的阈值无法理解你的业务节奏。**

## ServerGuard 的做法

Agent 持续采集指标，按「周几 × 小时」把历史数据分成 168 个时段桶，分别学习每个时段的正常范围（均值 ± 3σ）：

- 周二 14 点的 CPU 正常范围可能是 80~100%（跑批时段）
- 凌晨 4 点的正常范围可能是 1~10%

只有**偏离自身历史常态**时才告警：

` + "```" + `
> 基线异常：CPU 偏离历史正常范围
> 当前值 87.2%，该时段（周二14时）近14天历史均值 42.1%（σ=8.3）
` + "```" + `

## 效果

同样的服务器，阈值方案每周产生 10+ 条无效告警；基线方案告警量下降 80% 以上，且每一条都带着「为什么异常」的上下文。

零外部依赖、零配置——装上一周后，基线自动建立，越用越准。`,
		},
		{
			title:    "磁盘写满之前的一周：线性回归预测实战",
			slug:     "disk-full-forecast",
			excerpt:  "磁盘告警不该在 95% 时才响起。ServerGuard 对近 14 天使用率做线性回归，提前一周告诉你「按这个增速，5 天后到 90%」。",
			author:   "ServerGuard 团队",
			category: "运维实战",
			content: `## 95% 才告警，等于没告警

磁盘从 90% 到 100%，在日志暴涨的场景下可能只要 10 分钟。等你收到告警 SSH 上去，MySQL 已经崩了。

## 预测，而不是阈值

ServerGuard 每天记录各分区的使用率，对近 14 天数据做最小二乘线性回归，算出：

- **日均增速**：每天涨多少个百分点
- **预计触顶日期**：按当前增速，哪天到 90%

` + "```" + `
⚠️ /www 当前 78%，增速 2.1%/天
预计 5 天后（08-16）达到 90%
热点目录：/www/wwwlogs（+1.4GB/天）
` + "```" + `

同时附增长热点目录扫描结果——哪个目录在疯涨，一眼定位。

## 提前一周，从容处理

有了 5~7 天的缓冲期，你可以从容地：清理旧日志、扩容磁盘、迁移数据——而不是凌晨 3 点手忙脚乱。

这就是「让服务器自己照顾自己」的其中一块拼图。`,
		},
	}
	for _, p := range posts {
		db.Exec(`INSERT INTO blog_posts (title, slug, excerpt, content, author, category, status)
			VALUES (?, ?, ?, ?, ?, ?, 'published')`,
			p.title, p.slug, p.excerpt, p.content, p.author, p.category)
	}
}

func (s *Store) GetContent() (map[string]any, error) {
	rows, err := s.db.Query("SELECT key, value FROM site_content")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]any)
	for rows.Next() {
		var key, value string
		rows.Scan(&key, &value)
		// Try to parse JSON values (features, stats, faqs)
		if key == "features" || key == "stats" || key == "faqs" {
			var parsed any
			if json.Unmarshal([]byte(value), &parsed) == nil {
				result[key] = parsed
			}
		} else {
			result[key] = value
		}
	}
	return result, nil
}

func (s *Store) UpdateContent(data map[string]any) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO site_content (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for key, val := range data {
		var strVal string
		switch v := val.(type) {
		case string:
			strVal = v
		default:
			bytes, _ := json.Marshal(val)
			strVal = string(bytes)
		}
		stmt.Exec(key, strVal, time.Now().UTC())
	}
	return tx.Commit()
}

// ===== Pricing =====

func (s *Store) GetPricing() ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT id, name, tagline, price_cny, price_usd, period, note, cta,
		popular, coming_soon, enabled, features FROM pricing_plans WHERE enabled = 1 ORDER BY sort_order`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []map[string]any
	for rows.Next() {
		var id, popular, comingSoon, enabled int
		var name, tagline, priceCNY, priceUSD, period, note, cta, features string
		rows.Scan(&id, &name, &tagline, &priceCNY, &priceUSD, &period, &note, &cta,
			&popular, &comingSoon, &enabled, &features)

		var featList []string
		json.Unmarshal([]byte(features), &featList)

		plans = append(plans, map[string]any{
			"id":          id,
			"name":        name,
			"tagline":     tagline,
			"price_cny":   priceCNY,
			"price_usd":   priceUSD,
			"period":      period,
			"note":        note,
			"cta":         cta,
			"popular":     popular == 1,
			"coming_soon": comingSoon == 1,
			"features":    featList,
		})
	}
	return plans, nil
}

func (s *Store) GetAllPricing() ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT id, name, tagline, price_cny, price_usd, period, note, cta,
		popular, coming_soon, enabled, features FROM pricing_plans ORDER BY sort_order`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []map[string]any
	for rows.Next() {
		var id, popular, comingSoon, enabled int
		var name, tagline, priceCNY, priceUSD, period, note, cta, features string
		rows.Scan(&id, &name, &tagline, &priceCNY, &priceUSD, &period, &note, &cta,
			&popular, &comingSoon, &enabled, &features)

		var featList []string
		json.Unmarshal([]byte(features), &featList)

		plans = append(plans, map[string]any{
			"id":            id,
			"name":          name,
			"tagline":       tagline,
			"price_cny":     priceCNY,
			"price_usd":     priceUSD,
			"period":        period,
			"note":          note,
			"cta":           cta,
			"popular":       popular == 1,
			"coming_soon":   comingSoon == 1,
			"enabled":       enabled == 1,
			"features_text": features,
		})
	}
	return plans, nil
}

func (s *Store) UpdatePricing(plans []map[string]any) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear existing
	tx.Exec("DELETE FROM pricing_plans")

	stmt, _ := tx.Prepare(`INSERT INTO pricing_plans
		(name, tagline, price_cny, price_usd, period, note, cta, popular, coming_soon, enabled, sort_order, features)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	defer stmt.Close()

	for i, p := range plans {
		name, _ := p["name"].(string)
		tagline, _ := p["tagline"].(string)
		priceCNY, _ := p["price_cny"].(string)
		priceUSD, _ := p["price_usd"].(string)
		period, _ := p["period"].(string)
		note, _ := p["note"].(string)
		cta, _ := p["cta"].(string)
		popular := 0
		if v, ok := p["popular"].(bool); ok && v {
			popular = 1
		}
		comingSoon := 0
		if v, ok := p["coming_soon"].(bool); ok && v {
			comingSoon = 1
		}
		enabled := 1
		if v, ok := p["enabled"].(bool); ok && !v {
			enabled = 0
		}
		features, _ := p["features_text"].(string)
		if features == "" {
			// Try features array
			if fa, ok := p["features"].([]any); ok {
				bytes, _ := json.Marshal(fa)
				features = string(bytes)
			}
		}
		stmt.Exec(name, tagline, priceCNY, priceUSD, period, note, cta,
			popular, comingSoon, enabled, i+1, features)
	}
	return tx.Commit()
}

// ===== Versions =====

type VersionInfo struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	Channel      string `json:"channel"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	ReleaseNotes string `json:"release_notes"`
	SHA256       string `json:"sha256"`
	Signature    string `json:"signature"`
	FilePath     string `json:"file_path"`
	FileSize     int64  `json:"file_size"`
	Critical     bool   `json:"critical"`
	Enabled      bool   `json:"enabled"`
	Downloads    int    `json:"downloads"`
	CreatedAt    string `json:"created_at"`
}

const versionColumns = `id, version, channel, os, arch, release_notes, sha256, signature,
	file_path, file_size, critical, enabled, downloads,
	strftime('%Y-%m-%d %H:%M:%S', created_at, '+8 hours') as created_at`

func scanVersion(row interface{ Scan(...any) error }) (*VersionInfo, error) {
	var v VersionInfo
	var critical, enabled int
	err := row.Scan(&v.ID, &v.Version, &v.Channel, &v.OS, &v.Arch, &v.ReleaseNotes,
		&v.SHA256, &v.Signature, &v.FilePath, &v.FileSize, &critical, &enabled,
		&v.Downloads, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	v.Critical = critical == 1
	v.Enabled = enabled == 1
	return &v, nil
}

func (s *Store) GetLatestVersion(channel, osName, arch string) (*VersionInfo, error) {
	query := `SELECT ` + versionColumns + ` FROM versions WHERE enabled = 1`
	args := []any{}
	if channel != "" {
		query += " AND channel = ?"
		args = append(args, channel)
	}
	// 多平台过滤：os/arch 精确匹配；为空则匹配通用包（os=''）
	if osName != "" {
		query += " AND os = ?"
		args = append(args, osName)
	}
	if arch != "" {
		query += " AND arch = ?"
		args = append(args, arch)
	}
	query += " ORDER BY id DESC LIMIT 1"

	v, err := scanVersion(s.db.QueryRow(query, args...))
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Store) GetAllVersions() ([]VersionInfo, error) {
	rows, err := s.db.Query(`SELECT ` + versionColumns + ` FROM versions ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVersionRows(rows)
}

// GetPublicVersions returns only enabled versions for the public download page.
func (s *Store) GetPublicVersions() ([]VersionInfo, error) {
	rows, err := s.db.Query(`SELECT ` + versionColumns + ` FROM versions WHERE enabled = 1 ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVersionRows(rows)
}

func scanVersionRows(rows *sql.Rows) ([]VersionInfo, error) {
	var versions []VersionInfo
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, *v)
	}
	return versions, nil
}

func (s *Store) CreateVersion(v *VersionInfo) error {
	res, err := s.db.Exec(`INSERT INTO versions
		(version, channel, os, arch, release_notes, sha256, signature, file_path, file_size, critical, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		v.Version, v.Channel, v.OS, v.Arch, v.ReleaseNotes, v.SHA256, v.Signature,
		v.FilePath, v.FileSize, v.Critical)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	v.ID = int(id)
	return nil
}

func (s *Store) UpdateVersion(id int, data map[string]any) error {
	enabled := 1
	if v, ok := data["enabled"].(bool); ok && !v {
		enabled = 0
	}
	_, err := s.db.Exec("UPDATE versions SET enabled = ? WHERE id = ?", enabled, id)
	return err
}

func (s *Store) DeleteVersion(id int) error {
	var filePath string
	s.db.QueryRow("SELECT file_path FROM versions WHERE id = ?", id).Scan(&filePath)
	_, err := s.db.Exec("DELETE FROM versions WHERE id = ?", id)
	return err
}

func (s *Store) IncrementDownloads(id int) {
	s.db.Exec("UPDATE versions SET downloads = downloads + 1 WHERE id = ?", id)
}

// ===== Blog =====

type BlogPost struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Slug      string `json:"slug"`
	Excerpt   string `json:"excerpt"`
	Content   string `json:"content"`
	Author    string `json:"author"`
	Category  string `json:"category"`
	Status    string `json:"status"`
	Views     int    `json:"views"`
	CreatedAt string `json:"created_at"`
}

func (s *Store) GetBlogPosts(page, pageSize int) ([]BlogPost, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(`SELECT id, title, slug, excerpt, content, author, category, status, views,
		strftime('%Y-%m-%d %H:%M:%S', created_at, '+8 hours') as created_at
		FROM blog_posts WHERE status = 'published' ORDER BY id DESC LIMIT ? OFFSET ?`,
		pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []BlogPost
	for rows.Next() {
		var p BlogPost
		rows.Scan(&p.ID, &p.Title, &p.Slug, &p.Excerpt, &p.Content, &p.Author, &p.Category, &p.Status, &p.Views, &p.CreatedAt)
		posts = append(posts, p)
	}
	return posts, nil
}

func (s *Store) GetAllBlogPosts(page, pageSize int) ([]BlogPost, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(`SELECT id, title, slug, excerpt, content, author, category, status, views,
		strftime('%Y-%m-%d %H:%M:%S', created_at, '+8 hours') as created_at
		FROM blog_posts ORDER BY id DESC LIMIT ? OFFSET ?`,
		pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []BlogPost
	for rows.Next() {
		var p BlogPost
		rows.Scan(&p.ID, &p.Title, &p.Slug, &p.Excerpt, &p.Content, &p.Author, &p.Category, &p.Status, &p.Views, &p.CreatedAt)
		posts = append(posts, p)
	}
	return posts, nil
}

func (s *Store) GetBlogPost(slug string) (*BlogPost, error) {
	var p BlogPost
	err := s.db.QueryRow(`SELECT id, title, slug, excerpt, content, author, category, status, views,
		strftime('%Y-%m-%d %H:%M:%S', created_at, '+8 hours') as created_at
		FROM blog_posts WHERE slug = ? AND status = 'published'`, slug).
		Scan(&p.ID, &p.Title, &p.Slug, &p.Excerpt, &p.Content, &p.Author, &p.Category, &p.Status, &p.Views, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	s.db.Exec("UPDATE blog_posts SET views = views + 1 WHERE id = ?", p.ID)
	p.Views++
	return &p, nil
}

func (s *Store) CreateBlogPost(p *BlogPost) error {
	if p.Slug == "" {
		p.Slug = fmt.Sprintf("post-%d", time.Now().Unix())
	}
	if p.Status == "" {
		p.Status = "draft"
	}
	if p.Author == "" {
		p.Author = "Admin"
	}
	if p.Category == "" {
		p.Category = "技术分享"
	}
	res, err := s.db.Exec(`INSERT INTO blog_posts (title, slug, excerpt, content, author, category, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.Title, p.Slug, p.Excerpt, p.Content, p.Author, p.Category, p.Status)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	p.ID = int(id)
	return nil
}

func (s *Store) UpdateBlogPost(id int, p *BlogPost) error {
	_, err := s.db.Exec(`UPDATE blog_posts SET title = ?, slug = ?, excerpt = ?, content = ?,
		author = ?, category = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		p.Title, p.Slug, p.Excerpt, p.Content, p.Author, p.Category, p.Status, id)
	return err
}

func (s *Store) DeleteBlogPost(id int) error {
	_, err := s.db.Exec("DELETE FROM blog_posts WHERE id = ?", id)
	return err
}

// ===== Security =====

type SecurityAdvisory struct {
	ID               int    `json:"id"`
	CVEID            string `json:"cve_id"`
	Title            string `json:"title"`
	Summary          string `json:"summary"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	AffectedVersions string `json:"affected_versions"`
	PatchedVersion   string `json:"patched_version"`
	PublishedAt      string `json:"published_at"`
}

func (s *Store) GetSecurityAdvisories(page, pageSize int) ([]SecurityAdvisory, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(`SELECT id, cve_id, title, summary, description, severity,
		affected_versions, patched_version,
		strftime('%Y-%m-%d %H:%M:%S', published_at, '+8 hours') as published_at
		FROM security_advisories ORDER BY id DESC LIMIT ? OFFSET ?`,
		pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var advisories []SecurityAdvisory
	for rows.Next() {
		var a SecurityAdvisory
		rows.Scan(&a.ID, &a.CVEID, &a.Title, &a.Summary, &a.Description, &a.Severity,
			&a.AffectedVersions, &a.PatchedVersion, &a.PublishedAt)
		advisories = append(advisories, a)
	}
	return advisories, nil
}

func (s *Store) CreateSecurityAdvisory(a *SecurityAdvisory) error {
	res, err := s.db.Exec(`INSERT INTO security_advisories
		(cve_id, title, summary, description, severity, affected_versions, patched_version)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.CVEID, a.Title, a.Summary, a.Description, a.Severity, a.AffectedVersions, a.PatchedVersion)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	a.ID = int(id)
	return nil
}

func (s *Store) UpdateSecurityAdvisory(id int, a *SecurityAdvisory) error {
	_, err := s.db.Exec(`UPDATE security_advisories SET cve_id = ?, title = ?, summary = ?,
		description = ?, severity = ?, affected_versions = ?, patched_version = ? WHERE id = ?`,
		a.CVEID, a.Title, a.Summary, a.Description, a.Severity, a.AffectedVersions, a.PatchedVersion, id)
	return err
}

func (s *Store) DeleteSecurityAdvisory(id int) error {
	_, err := s.db.Exec("DELETE FROM security_advisories WHERE id = ?", id)
	return err
}

// ===== Admin Auth =====

func (s *Store) VerifyAdmin(username, password string) (bool, error) {
	var hash string
	err := s.db.QueryRow("SELECT password_hash FROM admin_users WHERE username = ?", username).Scan(&hash)
	if err != nil {
		return false, err
	}
	return verifyPassword(hash, password), nil
}

// ChangeAdminPassword updates the admin user's password.
func (s *Store) ChangeAdminPassword(username, oldPassword, newPassword string) error {
	// Verify old password first
	ok, err := s.VerifyAdmin(username, oldPassword)
	if err != nil || !ok {
		return fmt.Errorf("旧密码错误")
	}
	// Hash new password
	hash, err := hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("密码哈希失败: %w", err)
	}
	_, err = s.db.Exec("UPDATE admin_users SET password_hash = ? WHERE username = ?", hash, username)
	return err
}
