package devops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ────────────────────────────────────────────────
// DevOps 自动发现 + 自动巡检（资源友好版）
//
// 资源保护策略：
//   1. 发现扫描（全盘遍历）—— 仅启动时执行一次，之后每小时刷新
//   2. AutoCheck 轻量巡检 —— 每 10 分钟执行，只读 cron 配置 + 已注册目录大小
//   3. dirSize 遍历加 30s 超时 + 深度限制
//   4. 所有 filepath.Walk 限制深度 ≤ 3，避免 node_modules 套娃
// ────────────────────────────────────────────────

// discoveryCache 缓存自动发现结果，避免频繁全盘扫描
var discoveryCache struct {
	sync.RWMutex
	result    *DevOpsDiscoveryResult
	lastScan  time.Time
}

// AutoDiscover 自动发现服务器上的 DevOps 相关资源
// 使用缓存策略：首次调用执行全量扫描，之后 1 小时内返回缓存
func (g *DevOpsGuard) AutoDiscover(ctx context.Context) *DevOpsDiscoveryResult {
	discoveryCache.RLock()
	if discoveryCache.result != nil && time.Since(discoveryCache.lastScan) < time.Hour {
		r := discoveryCache.result
		discoveryCache.RUnlock()
		return r
	}
	discoveryCache.RUnlock()

	result := &DevOpsDiscoveryResult{
		Timestamp: time.Now(),
	}

	if isWindows() {
		discoveryCache.Lock()
		discoveryCache.result = result
		discoveryCache.lastScan = time.Now()
		discoveryCache.Unlock()
		return result
	}

	// 1. 自动扫描常见构建目录（最重的操作，加超时保护）
	discoverCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result.BuildDirs = g.discoverBuildDirs(discoverCtx)

	// 2. 自动发现 cron 冲突（读 /etc/crontab，很轻）
	result.CronConflicts = g.discoverCronConflicts(ctx)

	// 3. 自动发现 API 依赖（读 Nginx 配置文件，很轻）
	result.APIDeps = g.discoverAPIDeps(ctx)

	// 4. 自动发现 Git 仓库（遍历但限制深度）
	result.GitRepos = g.discoverGitRepos(ctx)

	// 将发现结果自动注册
	g.mu.Lock()
	for _, dir := range result.BuildDirs {
		if dir.SizeMB > 100 { // 大于 100MB 的才注册监控
			key := dir.Path
			if _, exists := g.buildDirs[key]; !exists {
				g.buildDirs[key] = &BuildDirConfig{
					Path:         dir.Path,
					MaxSizeGB:   5.0,
					KeepVersions: 10,
				}
			}
		}
	}
	g.mu.Unlock()

	// 更新缓存
	discoveryCache.Lock()
	discoveryCache.result = result
	discoveryCache.lastScan = time.Now()
	discoveryCache.Unlock()

	return result
}

// DevOpsDiscoveryResult 自动发现结果
type DevOpsDiscoveryResult struct {
	BuildDirs      []DiscoveredBuildDir `json:"build_dirs"`
	CronConflicts []string              `json:"cron_conflicts"`
	APIDeps       []DiscoveredAPIDep    `json:"api_deps"`
	GitRepos      []DiscoveredGitRepo   `json:"git_repos"`
	Timestamp     time.Time             `json:"timestamp"`
}

// DiscoveredBuildDir 发现的构建目录
type DiscoveredBuildDir struct {
	Path       string  `json:"path"`
	SizeMB     float64 `json:"size_mb"`
	BuildType  string  `json:"build_type"`
}

// DiscoveredAPIDep 发现的 API 依赖
type DiscoveredAPIDep struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// DiscoveredGitRepo 发现的 Git 仓库
type DiscoveredGitRepo struct {
	Path       string `json:"path"`
	Branch     string `json:"branch"`
	LastCommit string `json:"last_commit"`
}

// AutoCheck 自动巡检（由 slowTicker 每 10 分钟调用）
// 只执行轻量操作：
//   - cron 冲突检测（读 /etc/crontab）
//   - API 依赖健康度（HTTP ping）
//   - 已注册构建目录检查（只检查已注册的，不全盘扫描）
//   - 文件传输检查（只检查已注册的）
// 不执行：全盘发现扫描（那个每小时才做一次）
func (g *DevOpsGuard) AutoCheck(ctx context.Context) {
	// 1. cron 冲突检测（很轻：读 /etc/crontab + /etc/cron.d/）
	g.CheckCronConflicts(ctx)

	// 2. API 依赖健康度（每个依赖一次 HTTP HEAD，很轻）
	g.CheckAPIDeps(ctx)

	// 3. 已注册构建目录检查（只检查已注册的目录大小，不做全盘发现）
	g.CheckBuildDirs(ctx)

	// 4. 文件传输检查
	g.CheckTransfers(ctx)
}

// ────────────────────────────────────────────────
// 自动发现内部实现（全盘扫描，仅低频执行）
// ────────────────────────────────────────────────

// discoverBuildDirs 扫描常见构建目录
func (g *DevOpsGuard) discoverBuildDirs(ctx context.Context) []DiscoveredBuildDir {
	var dirs []DiscoveredBuildDir

	if isWindows() {
		return dirs
	}

	// 常见构建产物目录名 → 构建类型
	patterns := map[string]string{
		// Node.js / 前端
		"node_modules": "npm",
		"dist":         "frontend",
		".next":        "nextjs",
		".nuxt":        "nuxt",
		".svelte-kit":  "svelte",
		".output":      "nitro",
		// Java
		"target": "maven",
		"build":  "gradle", // 后续用 detectBuildType 精确识别
		"out":    "java-out",
		// Go
		"bin": "go", // 后续用 detectBinType 精确识别
		// Python
		"__pycache__": "python",
		".venv":       "python",
		"venv":        "python",
		// PHP
		"vendor": "composer",
		// .NET
		"obj": "dotnet",
		// C/C++
		"cmake-build-debug":   "cmake",
		"cmake-build-release": "cmake",
	}

	// 路径特征检测：根据路径中的特征文件进一步推断类型
	// 例如：目录名是 build 但里面有 .gradle 文件 → gradle；有 Makefile → make

	// 搜索根目录：覆盖常见部署位置
	searchRoots := []string{
		"/www/wwwroot", // 宝塔站点目录（最常见）
		"/opt",         // 自定义部署
		"/home",        // 用户项目
		"/srv",         // 服务部署
		"/usr/local/src",  // 源码编译
		"/data",           // 数据目录下可能有项目
	}

	seen := make(map[string]bool)
	for _, root := range searchRoots {
		if ctx.Err() != nil {
			break
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}

		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipDir
			}
			if !info.IsDir() {
				return nil
			}

			// 限制深度 ≤ 4，覆盖更深的项目结构
			rel, _ := filepath.Rel(root, path)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth > 4 {
				return filepath.SkipDir
			}

			// 跳过系统目录和隐藏目录
			name := info.Name()
			if name == ".git" || name == ".ssh" || name == ".cache" {
				return filepath.SkipDir
			}

			if buildType, ok := patterns[name]; ok {
				if seen[path] {
				return filepath.SkipDir
				}
				seen[path] = true

				// 用限时 du 代替全量 Walk，更高效
				size := quickDirSize(path, 10*time.Second)
				if size > 1024*1024 {
					// 对 build 目录进一步检测类型
					if name == "build" {
						buildType = detectBuildType(path)
					}
					// 对 bin 目录也检测
					if name == "bin" {
						buildType = detectBinType(path)
					}
					// 对 out 目录检测
					if name == "out" {
						buildType = detectOutType(path)
					}
					dirs = append(dirs, DiscoveredBuildDir{
						Path:      path,
						SizeMB:    float64(size) / 1024 / 1024,
						BuildType: buildType,
					})
				}
				return filepath.SkipDir
			}
			return nil
		})
	}

	return dirs
}

// detectBuildType 检测名为 build 的目录的具体构建类型
func detectBuildType(dir string) string {
	// 检查目录中是否存在特征文件
	if _, err := os.Stat(filepath.Join(dir, "..", "build.gradle")); err == nil {
		return "gradle"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "build.gradle.kts")); err == nil {
		return "gradle"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "pom.xml")); err == nil {
		return "maven"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "Makefile")); err == nil {
		return "make"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "CMakeLists.txt")); err == nil {
		return "cmake"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "package.json")); err == nil {
		return "frontend"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "go.mod")); err == nil {
		return "go"
	}
	return "build"
}

// detectBinType 检测名为 bin 的目录
func detectBinType(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "..", "go.mod")); err == nil {
		return "go"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "package.json")); err == nil {
		return "npm"
	}
	return "bin"
}

// detectOutType 检测名为 out 的目录
func detectOutType(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "..", "build.gradle")); err == nil {
		return "gradle"
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "package.json")); err == nil {
		return "frontend"
	}
	return "out"
}

// discoverCronConflicts 自动检测 cron 冲突
func (g *DevOpsGuard) discoverCronConflicts(ctx context.Context) []string {
	if isWindows() {
		return nil
	}

	entries := g.readSystemCron(ctx)
	var conflicts []string

	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if g.cronOverlaps(entries[i], entries[j]) {
				if g.cronSharesResource(entries[i], entries[j]) {
					conflicts = append(conflicts,
						fmt.Sprintf("%s (%s) ↔ %s (%s)",
							entries[i].Name, entries[i].Schedule,
							entries[j].Name, entries[j].Schedule))
				}
			}
		}
	}

	return conflicts
}

// discoverAPIDeps 从 Nginx 配置中自动发现 upstream API
func (g *DevOpsGuard) discoverAPIDeps(ctx context.Context) []DiscoveredAPIDep {
	var deps []DiscoveredAPIDep

	if isWindows() {
		return deps
	}

	nginxConfDirs := []string{"/etc/nginx", "/www/server/panel/vhost"}
	seen := make(map[string]bool)

	for _, confDir := range nginxConfDirs {
		if _, err := os.Stat(confDir); err != nil {
			continue
		}

		filepath.Walk(confDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(info.Name(), ".conf") {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			content := string(data)

			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "proxy_pass") && strings.Contains(line, "http") {
					url := extractURL(line)
					if url != "" && !seen[url] {
						seen[url] = true
						deps = append(deps, DiscoveredAPIDep{
							Name: filepath.Base(path),
							URL:  url,
						})
					}
				}
			}
			return nil
		})
	}

	return deps
}

// discoverGitRepos 自动发现 Git 仓库
func (g *DevOpsGuard) discoverGitRepos(ctx context.Context) []DiscoveredGitRepo {
	var repos []DiscoveredGitRepo

	if isWindows() {
		return repos
	}

	searchRoots := []string{"/opt", "/home", "/www/wwwroot"}

	for _, root := range searchRoots {
		if ctx.Err() != nil {
			break
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}

		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipDir
			}
			if !info.IsDir() {
				return nil
			}

			// 限制深度
			rel, _ := filepath.Rel(root, path)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth > 3 {
				return filepath.SkipDir
			}

			if info.Name() == ".git" {
				repoPath := filepath.Dir(path)
				branch := g.getGitBranch(repoPath)
				commit := g.getGitCommit(repoPath)
				repos = append(repos, DiscoveredGitRepo{
					Path:       repoPath,
					Branch:     branch,
					LastCommit: commit,
				})
				return filepath.SkipDir
			}
			return nil
		})
	}

	return repos
}

// ────────────────────────────────────────────────
// 辅助函数
// ────────────────────────────────────────────────

// quickDirSize 用系统命令 du 快速获取目录大小，避免 Go 遍历几万个小文件
// 超时则返回 0
func quickDirSize(path string, timeout time.Duration) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "du", "-sb", path)
	output, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		// du 不可用时降级为有限遍历
		return fallbackDirSize(path, 5000) // 最多遍历 5000 个文件
	}

	// du -sb 输出格式: "12345678\t/path"
	parts := strings.SplitN(string(output), "\t", 2)
	if len(parts) < 1 {
		return 0
	}
	var size int64
	fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &size)
	return size
}

// fallbackDirSize 降级遍历，限制最多遍历 maxFiles 个文件
func fallbackDirSize(path string, maxFiles int) int64 {
	var size int64
	count := 0
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		size += info.Size()
		count++
		if count >= maxFiles {
			return filepath.SkipDir
		}
		return nil
	})
	return size
}

func extractURL(line string) string {
	idx := strings.Index(line, "http")
	if idx < 0 {
		return ""
	}
	url := line[idx:]
	url = strings.TrimRight(url, ";")
	url = strings.TrimSpace(url)
	return url
}

func (g *DevOpsGuard) getGitBranch(repoPath string) string {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (g *DevOpsGuard) getGitCommit(repoPath string) string {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--short", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
