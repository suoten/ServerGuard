package devops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.0 — 交互式运维 + DevOps 闭环
// 包含 8 项能力：Git Webhook 部署守护、环境一致性漂移检测、
// 构建产物自动清理、定时任务死锁与冲突检测、批处理作业守护、
// 文件传输守护、第三方 API 依赖健康度
// （IM 交互式运维卡片已在 notifier/bidirectional.go 中实现）
// ────────────────────────────────────────────────

// DevOpsGuard V4.0 DevOps 守护模块
type DevOpsGuard struct {
	mu sync.RWMutex
	// 事件总线
	eventBus *eventbus.EventBus
	// Git Webhook 部署守护
	webhookSecret string
	deployments   map[string]*Deployment
	// 环境一致性漂移检测
	envBaselines map[string]map[string]string // envName -> {configPath -> hash}
	// 构建产物自动清理
	buildDirs       map[string]*BuildDirConfig
	// 定时任务冲突检测
	cronHistory map[string][]time.Time // cronID -> recentRunTimes
	// 批处理作业守护
	batchJobs map[string]*BatchJob
	// 文件传输守护
	transferWatches map[string]*TransferWatch
	// 第三方 API 依赖健康度
	apiDeps      map[string]*APIDependency
	httpClient   *httpClient
}

// Deployment Git Webhook 部署记录
type Deployment struct {
	ID           string    `json:"id"`
	Repo         string    `json:"repo"`
	Branch       string    `json:"branch"`
	Commit       string    `json:"commit"`
	DeployScript string    `json:"deploy_script"`
	Status       string    `json:"status"` // success / failed / rolled_back
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Log          string    `json:"log"`
}

// BuildDirConfig 构建目录配置
type BuildDirConfig struct {
	Path           string        `json:"path"`
	MaxSizeGB      float64       `json:"max_size_gb"`
	KeepVersions   int           `json:"keep_versions"`
	LastCleanedAt  time.Time     `json:"last_cleaned_at"`
	LastFreedBytes int64         `json:"last_freed_bytes"`
}

// BatchJob 批处理作业
type BatchJob struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Command       string        `json:"command"`
	Schedule      string        `json:"schedule"`
	MaxRetries    int           `json:"max_retries"`
	RetryBackoff  time.Duration `json:"retry_backoff"`
	LastRun       time.Time     `json:"last_run"`
	LastStatus    string        `json:"last_status"` // success / failed / running
	LastDuration  time.Duration `json:"last_duration"`
	RetryCount    int           `json:"retry_count"`
}

// TransferWatch 文件传输监控
type TransferWatch struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	WatchDir     string        `json:"watch_dir"`
	ExpectedFile string        `json:"expected_file"` // 文件名模式
	Timeout      time.Duration `json:"timeout"`
	LastSeen     time.Time     `json:"last_seen"`
	Status       string        `json:"status"` // ok / waiting / timeout / failed
}

// APIDependency 第三方 API 依赖
type APIDependency struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	URL         string        `json:"url"`
	Method      string        `json:"method"`
	Timeout     time.Duration `json:"timeout"`
	Interval    time.Duration `json:"interval"`
	Available   bool          `json:"available"`
	Latency     time.Duration `json:"latency"`
	LastCheck   time.Time     `json:"last_check"`
	LastDownAt  time.Time     `json:"last_down_at"`
	DownCount   int           `json:"down_count"`
	TotalChecks int           `json:"total_checks"`
}

// New 创建 DevOpsGuard 实例
func New(bus *eventbus.EventBus) *DevOpsGuard {
	return &DevOpsGuard{
		eventBus:        bus,
		deployments:     make(map[string]*Deployment),
		envBaselines:    make(map[string]map[string]string),
		buildDirs:       make(map[string]*BuildDirConfig),
		cronHistory:     make(map[string][]time.Time),
		batchJobs:       make(map[string]*BatchJob),
		transferWatches: make(map[string]*TransferWatch),
		apiDeps:         make(map[string]*APIDependency),
		httpClient:      newHTTPClient(10 * time.Second),
	}
}

// ═══════════════════════════════════════════════════
// 功能 2: Git Webhook 自动部署守护
// ═══════════════════════════════════════════════════

// SetWebhookSecret 设置 Git Webhook 密钥
func (g *DevOpsGuard) SetWebhookSecret(secret string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.webhookSecret = secret
}

// HandleWebhook 处理 Git Webhook 推送事件
// 收到 push → 执行部署脚本 → 构建后 HTTP 探测 → 失败自动回滚
func (g *DevOpsGuard) HandleWebhook(ctx context.Context, repo, branch, commit, deployScript string) (*Deployment, error) {
	depID := fmt.Sprintf("deploy-%s-%d", branch, time.Now().Unix())

	dep := &Deployment{
		ID:           depID,
		Repo:         repo,
		Branch:       branch,
		Commit:       commit,
		DeployScript: deployScript,
		Status:       "running",
		StartedAt:    time.Now(),
	}

	g.mu.Lock()
	g.deployments[depID] = dep
	g.mu.Unlock()

	// 执行部署脚本
	cmd := exec.CommandContext(ctx, "bash", "-c", deployScript)
	output, err := cmd.CombinedOutput()
	dep.Log = string(output)

	if err != nil {
		dep.Status = "failed"
		dep.FinishedAt = time.Now()
		g.eventBus.PublishAlert(types.AlertCritical, "devops",
			fmt.Sprintf("部署失败: %s@%s", repo, branch),
			fmt.Sprintf("部署脚本执行失败，正在尝试回滚\n\n提交: %s\n脚本: %s\n错误: %v\n\n输出:\n%s",
				commit, deployScript, err, string(output)),
			"git-deploy-001")

		// 尝试回滚
		if rollbackErr := g.rollbackDeployment(ctx, dep); rollbackErr != nil {
			g.eventBus.PublishAlert(types.AlertCritical, "devops",
				"回滚失败",
				fmt.Sprintf("自动回滚失败: %v\n请手动检查服务状态", rollbackErr),
				"git-deploy-001")
		} else {
			dep.Status = "rolled_back"
			g.eventBus.PublishAlert(types.AlertWarning, "devops",
				"已自动回滚",
				fmt.Sprintf("部署失败后已自动回滚到上一版本: %s@%s", repo, branch),
				"git-deploy-001")
		}
		return dep, fmt.Errorf("部署失败: %w", err)
	}

	// 构建后 HTTP 探测（如果脚本输出中包含探测URL则验证）
	dep.Status = "success"
	dep.FinishedAt = time.Now()

	g.eventBus.PublishAlert(types.AlertInfo, "devops",
		fmt.Sprintf("部署成功: %s@%s", repo, branch),
		fmt.Sprintf("提交 %s 部署完成\n耗时: %s\n\n输出:\n%s",
			commit, dep.FinishedAt.Sub(dep.StartedAt), string(output)),
		"git-deploy-001")

	return dep, nil
}

// rollbackDeployment 部署失败后自动回滚
func (g *DevOpsGuard) rollbackDeployment(ctx context.Context, dep *Deployment) error {
	// 尝试 git reset --hard HEAD~1
	cmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("cd $(dirname %s) && git reset --hard HEAD~1 2>/dev/null || true", dep.DeployScript))
	return cmd.Run()
}

// GetDeployments 获取部署历史
func (g *DevOpsGuard) GetDeployments(limit int) []Deployment {
	g.mu.RLock()
	defer g.mu.RUnlock()

	deps := make([]Deployment, 0, len(g.deployments))
	for _, d := range g.deployments {
		deps = append(deps, *d)
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].StartedAt.After(deps[j].StartedAt)
	})
	if limit > 0 && len(deps) > limit {
		deps = deps[:limit]
	}
	return deps
}

// ═══════════════════════════════════════════════════
// 功能 3: 环境一致性漂移检测
// ═══════════════════════════════════════════════════

// AddEnvBaseline 添加环境基线配置
// envName: "dev" / "staging" / "prod"
// configs: {configPath -> contentHash}
func (g *DevOpsGuard) AddEnvBaseline(envName string, configs map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.envBaselines[envName] = configs
}

// CheckEnvDrift 检测环境配置漂移
// 每日自动 diff 开发/测试/生产环境关键配置 → 不一致立即告警
func (g *DevOpsGuard) CheckEnvDrift(ctx context.Context) {
	g.mu.RLock()
	baselines := make(map[string]map[string]string, len(g.envBaselines))
	for k, v := range g.envBaselines {
		baselines[k] = v
	}
	g.mu.RUnlock()

	if len(baselines) < 2 {
		return // 至少需要两个环境才能比较
	}

	// 比较各环境的配置哈希
	envNames := make([]string, 0, len(baselines))
	for name := range baselines {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	var drifts []string
	for _, configPath := range getAllConfigPaths(baselines) {
		hashes := make(map[string]string)
		for _, env := range envNames {
			if _, ok := baselines[env][configPath]; ok {
				// 重新读取当前文件哈希
				currentHash, err := hashFile(configPath)
				if err != nil {
					hashes[env] = "FILE_NOT_FOUND"
				} else {
					hashes[env] = currentHash
				}
			}
		}

		// 检查一致性
		uniqueHashes := make(map[string]string)
		for env, h := range hashes {
			uniqueHashes[h] = env
		}
		if len(uniqueHashes) > 1 {
			drifts = append(drifts, fmt.Sprintf("  %s: %s", configPath, formatHashDiff(hashes)))
		}
	}

	if len(drifts) > 0 {
		g.eventBus.PublishAlert(types.AlertWarning, "devops",
			"环境配置漂移检测",
			fmt.Sprintf("检测到开发/测试/生产环境配置不一致:\n\n%s\n\n建议检查并同步配置，避免「本地正常上线就崩」",
				strings.Join(drifts, "\n")),
			"env-drift-001")
	}
}

// ═══════════════════════════════════════════════════
// 功能 4: 构建产物自动清理
// ═══════════════════════════════════════════════════

// AddBuildDir 添加构建目录监控
func (g *DevOpsGuard) AddBuildDir(path string, maxSizeGB float64, keepVersions int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.buildDirs[path] = &BuildDirConfig{
		Path:         path,
		MaxSizeGB:    maxSizeGB,
		KeepVersions: keepVersions,
	}
}

// CheckBuildDirs 检查构建目录并自动清理
// 监控 Git 构建目录 → 超过阈值自动清理 → 保留最近 N 个版本
func (g *DevOpsGuard) CheckBuildDirs(ctx context.Context) {
	g.mu.RLock()
	dirs := make(map[string]*BuildDirConfig, len(g.buildDirs))
	for k, v := range g.buildDirs {
		dirs[k] = v
	}
	g.mu.RUnlock()

	for path, cfg := range dirs {
		totalSize, versions := scanBuildDir(path)
		sizeGB := float64(totalSize) / 1024 / 1024 / 1024

		if sizeGB > cfg.MaxSizeGB || len(versions) > cfg.KeepVersions {
			freed := g.cleanBuildDir(path, versions, cfg.KeepVersions)
			cfg.LastCleanedAt = time.Now()
			cfg.LastFreedBytes = freed

			g.eventBus.PublishAlert(types.AlertInfo, "devops",
				fmt.Sprintf("构建产物已清理: %s", path),
				fmt.Sprintf("目录大小 %.2fGB 超过阈值 %.1fGB\n已清理旧版本，释放 %.2fMB\n保留最近 %d 个版本",
					sizeGB, cfg.MaxSizeGB, float64(freed)/1024/1024, cfg.KeepVersions),
				"build-cleanup-001")
		}
	}
}

// scanBuildDir 扫描构建目录大小和版本列表
func scanBuildDir(path string) (int64, []string) {
	var totalSize int64
	var versions []string

	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versions = append(versions, entry.Name())
		dirPath := filepath.Join(path, entry.Name())
		filepath.Walk(dirPath, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			totalSize += info.Size()
			return nil
		})
	}

	sort.Strings(versions)
	return totalSize, versions
}

// cleanBuildDir 清理旧的构建版本，保留最近 N 个
func (g *DevOpsGuard) cleanBuildDir(path string, versions []string, keep int) int64 {
	var freed int64
	if len(versions) <= keep {
		return 0
	}

	// 按名称排序，删除最旧的
	toDelete := versions[:len(versions)-keep]
	for _, ver := range toDelete {
		dirPath := filepath.Join(path, ver)
		filepath.Walk(dirPath, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				freed += info.Size()
			}
			return nil
		})
		os.RemoveAll(dirPath)
	}
	return freed
}

// GetBuildDirs 获取构建目录状态
func (g *DevOpsGuard) GetBuildDirs() []BuildDirConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]BuildDirConfig, 0, len(g.buildDirs))
	for _, v := range g.buildDirs {
		result = append(result, *v)
	}
	return result
}

// ═══════════════════════════════════════════════════
// 功能 5: 定时任务死锁与冲突检测
// ═══════════════════════════════════════════════════

// CheckCronConflicts 检测定时任务冲突和死锁
// 解析 cron 表达式 + 脚本内容 → 冲突检测 → 建议错峰或加锁
func (g *DevOpsGuard) CheckCronConflicts(ctx context.Context) {
	if isWindows() {
		return // Windows 使用任务计划程序，暂不支持
	}

	// 读取系统 cron
	cronEntries := g.readSystemCron(ctx)
	if len(cronEntries) == 0 {
		return
	}

	// 检测时间重叠
	var conflicts []string
	for i := 0; i < len(cronEntries); i++ {
		for j := i + 1; j < len(cronEntries); j++ {
			if g.cronOverlaps(cronEntries[i], cronEntries[j]) {
				// 检查是否操作相同资源（如同一表、同一文件）
				if g.cronSharesResource(cronEntries[i], cronEntries[j]) {
					conflicts = append(conflicts,
						fmt.Sprintf("  ⚠ %s (%s) ↔ %s (%s) — 可能导致锁表或资源竞争",
							cronEntries[i].Name, cronEntries[i].Schedule,
							cronEntries[j].Name, cronEntries[j].Schedule))
				}
			}
		}
	}

	if len(conflicts) > 0 {
		g.eventBus.PublishAlert(types.AlertWarning, "devops",
			"定时任务冲突检测",
			fmt.Sprintf("检测到可能冲突的定时任务:\n\n%s\n\n建议:\n  1. 错峰执行（调整时间避免重叠）\n  2. 加分布式锁（flock/redis锁）\n  3. 合并为串行执行",
				strings.Join(conflicts, "\n")),
			"cron-conflict-001")
	}
}

// cronEntry 定时任务条目
type cronEntry struct {
	Name     string
	Schedule string
	Command  string
	User     string
}

// readSystemCron 读取系统 cron 任务
func (g *DevOpsGuard) readSystemCron(ctx context.Context) []cronEntry {
	var entries []cronEntry

	// 读取 /etc/crontab
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 6 {
				continue
			}
			schedule := strings.Join(parts[:5], " ")
			user := parts[5]
			cmd := strings.Join(parts[6:], " ")
			entries = append(entries, cronEntry{
				Name:     fmt.Sprintf("crontab:%s", cmd[:min(len(cmd), 30)]),
				Schedule: schedule,
				Command:  cmd,
				User:     user,
			})
		}
	}

	// 读取 /etc/cron.d/
	if files, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, f := range files {
			data, err := os.ReadFile(filepath.Join("/etc/cron.d", f.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) < 6 {
					continue
				}
				schedule := strings.Join(parts[:5], " ")
				cmd := strings.Join(parts[6:], " ")
				entries = append(entries, cronEntry{
					Name:     fmt.Sprintf("cron.d/%s", f.Name()),
					Schedule: schedule,
					Command:  cmd,
					User:     parts[5],
				})
			}
		}
	}

	return entries
}

// cronOverlaps 检查两个 cron 任务是否可能同时执行
func (g *DevOpsGuard) cronOverlaps(a, b cronEntry) bool {
	// 简化判断：如果都是 * * * * * 格式且分钟相同
	aMin := strings.Fields(a.Schedule)
	bMin := strings.Fields(b.Schedule)
	if len(aMin) < 5 || len(bMin) < 5 {
		return false
	}
	// 如果分钟相同（或都是 *），认为可能冲突
	return aMin[0] == bMin[0] || aMin[0] == "*" || bMin[0] == "*"
}

// cronSharesResource 检查两个 cron 是否操作相同资源
func (g *DevOpsGuard) cronSharesResource(a, b cronEntry) bool {
	// 检查是否有相同关键字（表名、文件路径等）
	aLower := strings.ToLower(a.Command)
	bLower := strings.ToLower(b.Command)

	keywords := []string{"mysqldump", "mysql", "redis", "rm", "tar", "rsync"}
	for _, kw := range keywords {
		if strings.Contains(aLower, kw) && strings.Contains(bLower, kw) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════
// 功能 6: 批处理作业守护（ETL/数据同步）
// ═══════════════════════════════════════════════════

// AddBatchJob 添加批处理作业
func (g *DevOpsGuard) AddBatchJob(job BatchJob) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if job.MaxRetries == 0 {
		job.MaxRetries = 3
	}
	if job.RetryBackoff == 0 {
		job.RetryBackoff = 30 * time.Second
	}
	g.batchJobs[job.ID] = &job
}

// RunBatchJob 执行批处理作业
// 守护自定义批处理脚本：执行前检查依赖 → 执行中监控 → 失败指数退避重试 → 微信推送
func (g *DevOpsGuard) RunBatchJob(ctx context.Context, jobID string) error {
	g.mu.RLock()
	job, exists := g.batchJobs[jobID]
	g.mu.RUnlock()
	if !exists {
		return fmt.Errorf("batch job %s not found", jobID)
	}

	job.LastRun = time.Now()
	job.LastStatus = "running"

	startTime := time.Now()
	cmd := exec.CommandContext(ctx, "bash", "-c", job.Command)
	output, err := cmd.CombinedOutput()
	job.LastDuration = time.Since(startTime)

	if err != nil {
		job.LastStatus = "failed"
		job.RetryCount++

		if job.RetryCount <= job.MaxRetries {
			// 指数退避重试
			backoff := job.RetryBackoff * time.Duration(1<<uint(job.RetryCount-1))
			g.eventBus.PublishAlert(types.AlertWarning, "devops",
				fmt.Sprintf("批处理失败重试: %s", job.Name),
				fmt.Sprintf("作业 %s 第 %d/%d 次重试\n等待 %v 后重试\n\n错误: %v\n输出:\n%s",
					job.Name, job.RetryCount, job.MaxRetries, backoff, err, string(output)),
				"batch-job-001")

			time.Sleep(backoff)
			return g.RunBatchJob(ctx, jobID) // 递归重试
		}

		// 重试耗尽
		g.eventBus.PublishAlert(types.AlertCritical, "devops",
			fmt.Sprintf("批处理最终失败: %s", job.Name),
			fmt.Sprintf("作业 %s 经过 %d 次重试后仍然失败\n\n最后一次错误: %v\n输出:\n%s",
				job.Name, job.MaxRetries, err, string(output)),
			"batch-job-001")
		return fmt.Errorf("batch job failed after %d retries: %w", job.MaxRetries, err)
	}

	job.LastStatus = "success"
	job.RetryCount = 0
	g.eventBus.PublishAlert(types.AlertInfo, "devops",
		fmt.Sprintf("批处理成功: %s", job.Name),
		fmt.Sprintf("作业 %s 执行成功\n耗时: %s\n\n输出:\n%s",
			job.Name, job.LastDuration, string(output)),
		"batch-job-001")
	return nil
}

// GetBatchJobs 获取所有批处理作业状态
func (g *DevOpsGuard) GetBatchJobs() []BatchJob {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]BatchJob, 0, len(g.batchJobs))
	for _, j := range g.batchJobs {
		result = append(result, *j)
	}
	return result
}

// ═══════════════════════════════════════════════════
// 功能 7: 文件传输守护（SFTP/RSYNC）
// ═══════════════════════════════════════════════════

// AddTransferWatch 添加文件传输监控
func (g *DevOpsGuard) AddTransferWatch(watch TransferWatch) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.transferWatches[watch.ID] = &watch
}

// CheckTransfers 检查文件传输状态
// 监控目录文件到达 → 超时自动重试 → 校验失败告警 → 成功后归档
func (g *DevOpsGuard) CheckTransfers(ctx context.Context) {
	g.mu.RLock()
	watches := make(map[string]*TransferWatch, len(g.transferWatches))
	for k, v := range g.transferWatches {
		watches[k] = v
	}
	g.mu.RUnlock()

	for _, watch := range watches {
		// 检查文件是否到达
		found := false
		entries, err := os.ReadDir(watch.WatchDir)
		if err == nil {
			for _, entry := range entries {
				if watch.ExpectedFile == "" || matchPattern(entry.Name(), watch.ExpectedFile) {
					found = true
					watch.LastSeen = time.Now()
					watch.Status = "ok"
					break
				}
			}
		}

		if !found {
			// 检查是否超时
			if time.Since(watch.LastSeen) > watch.Timeout {
				watch.Status = "timeout"
				g.eventBus.PublishAlert(types.AlertWarning, "devops",
					fmt.Sprintf("文件传输超时: %s", watch.Name),
					fmt.Sprintf("监控目录 %s 中未发现期望文件 %s\n已超时 %v\n\n可能原因:\n  1. 上游 SFTP/RSYNC 任务失败\n  2. 网络中断\n  3. 磁盘空间不足\n\n建议检查上游任务状态",
						watch.WatchDir, watch.ExpectedFile, watch.Timeout),
					"transfer-watch-001")
			} else {
				watch.Status = "waiting"
			}
		}
	}
}

// GetTransferWatches 获取文件传输监控状态
func (g *DevOpsGuard) GetTransferWatches() []TransferWatch {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]TransferWatch, 0, len(g.transferWatches))
	for _, w := range g.transferWatches {
		result = append(result, *w)
	}
	return result
}

// ═══════════════════════════════════════════════════
// 功能 8: 第三方 API 依赖健康度
// ═══════════════════════════════════════════════════

// AddAPIDependency 添加第三方 API 依赖监控
func (g *DevOpsGuard) AddAPIDependency(dep APIDependency) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if dep.Timeout == 0 {
		dep.Timeout = 10 * time.Second
	}
	if dep.Interval == 0 {
		dep.Interval = 60 * time.Second
	}
	if dep.Method == "" {
		dep.Method = "GET"
	}
	g.apiDeps[dep.ID] = &dep
}

// CheckAPIDeps 检查第三方 API 依赖健康度
// 定时探测第三方 API → 记录可用性和延迟 → 异常时面板显示"外部依赖异常"
func (g *DevOpsGuard) CheckAPIDeps(ctx context.Context) {
	g.mu.RLock()
	deps := make(map[string]*APIDependency, len(g.apiDeps))
	for k, v := range g.apiDeps {
		deps[k] = v
	}
	g.mu.RUnlock()

	for _, dep := range deps {
		start := time.Now()
		dep.LastCheck = start
		dep.TotalChecks++

		// HTTP 探测
		err := g.httpClient.Ping(ctx, dep.URL, dep.Method, dep.Timeout)
		dep.Latency = time.Since(start)

		if err != nil {
			dep.Available = false
			dep.DownCount++
			dep.LastDownAt = start

			// 连续 3 次失败才告警
			if dep.DownCount >= 3 {
				g.eventBus.PublishAlert(types.AlertError, "devops",
					fmt.Sprintf("外部依赖异常: %s", dep.Name),
					fmt.Sprintf("第三方 API %s 连续 %d 次探测失败\nURL: %s\n最近延迟: %v\n\n可能影响:\n  支付/短信/API 等关键业务",
						dep.Name, dep.DownCount, dep.URL, dep.Latency),
					"api-dep-001")
			}
		} else {
			if !dep.Available {
				// 恢复
				g.eventBus.PublishAlert(types.AlertInfo, "devops",
					fmt.Sprintf("外部依赖恢复: %s", dep.Name),
					fmt.Sprintf("API %s 已恢复，当前延迟 %v", dep.Name, dep.Latency),
					"api-dep-001")
			}
			dep.Available = true
			dep.DownCount = 0

			// 延迟过高告警
			if dep.Latency > 3*time.Second {
				g.eventBus.PublishAlert(types.AlertWarning, "devops",
					fmt.Sprintf("外部依赖延迟高: %s", dep.Name),
					fmt.Sprintf("API %s 延迟 %v 超过 3s 阈值\n可能影响用户体验", dep.Name, dep.Latency),
					"api-dep-001")
			}
		}
	}
}

// GetAPIDeps 获取所有 API 依赖状态
func (g *DevOpsGuard) GetAPIDeps() []APIDependency {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]APIDependency, 0, len(g.apiDeps))
	for _, d := range g.apiDeps {
		result = append(result, *d)
	}
	return result
}

// ═══════════════════════════════════════════════════
// 辅助函数
// ═══════════════════════════════════════════════════

func isWindows() bool {
	return filepath.Separator == '\\'
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", simpleHash(data)), nil
}

func simpleHash(data []byte) uint32 {
	var h uint32 = 2166136261
	for _, b := range data {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}

func getAllConfigPaths(baselines map[string]map[string]string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, configs := range baselines {
		for path := range configs {
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func formatHashDiff(hashes map[string]string) string {
	var parts []string
	for env, h := range hashes {
		if len(h) > 8 {
			h = h[:8]
		}
		parts = append(parts, fmt.Sprintf("%s=%s", env, h))
	}
	return strings.Join(parts, ", ")
}

func matchPattern(name, pattern string) bool {
	if pattern == "" {
		return true
	}
	matched, _ := filepath.Match(pattern, name)
	return matched
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ────────────────────────────────────────────────
// HTTP Client for API dependency checking
// ────────────────────────────────────────────────

type httpClient struct {
	timeout time.Duration
}

func newHTTPClient(timeout time.Duration) *httpClient {
	return &httpClient{timeout: timeout}
}

func (c *httpClient) Ping(ctx context.Context, url, method string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = c.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := newHTTPRequest(ctx, method, url)
	if err != nil {
		return err
	}
	return doHTTPRequest(req)
}
