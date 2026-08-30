package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/suoten/serverguard/internal/guards/datagovern"
	"github.com/suoten/serverguard/internal/guards/devops"
)

// ────────────────────────────────────────────────
// V4.0/V4.1 — 交互式运维 + DevOps 闭环 + 数据治理 API
// ────────────────────────────────────────────────

// SetDevOpsGuard 注入 DevOps 守护模块
func (a *API) SetDevOpsGuard(dg *devops.DevOpsGuard) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.devOpsGuard = dg
}

// SetDataGovernGuard 注入数据治理守护模块
func (a *API) SetDataGovernGuard(dg *datagovern.DataGovernGuard) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dataGovernGuard = dg
}

// ═══════════════════════════════════════════════════
// V4.0 — DevOps API 端点
// ═══════════════════════════════════════════════════

// getDevOpsDeployments GET /api/devops/deployments
func (a *API) getDevOpsDeployments(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"deployments": []interface{}{}, "count": 0})
		return
	}
	limit := 20
	deps := dg.GetDeployments(limit)
	c.JSON(http.StatusOK, gin.H{"deployments": deps, "count": len(deps)})
}

// triggerWebhookDeploy POST /api/devops/deploy
// 异步执行：部署操作最多 5 分钟，同步执行会触发 Hub WriteTimeout 30s 导致 502
func (a *API) triggerWebhookDeploy(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	var req struct {
		Repo         string `json:"repo"`
		Branch       string `json:"branch"`
		Commit       string `json:"commit"`
		DeployScript string `json:"deploy_script"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		dep, err := dg.HandleWebhook(ctx, req.Repo, req.Branch, req.Commit, req.DeployScript)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[DevOps] webhook deploy failed: %v\n", err)
			return
		}
		_ = dep
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "部署已启动，请稍后查看部署列表"})
}

// getEnvDrift GET /api/devops/env-drift — 异步执行
// 环境漂移检查可能涉及多次文件读取，同步执行会导致 502
func (a *API) getEnvDrift(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"drifts": []interface{}{}})
		return
	}
	// 异步执行，立即返回
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dg.CheckEnvDrift(ctx)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "环境漂移检查已启动"})
}

// getBuildDirs GET /api/devops/build-dirs
func (a *API) getBuildDirs(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"dirs": []interface{}{}})
		return
	}
	dirs := dg.GetBuildDirs()
	c.JSON(http.StatusOK, gin.H{"dirs": dirs, "count": len(dirs)})
}

// addBuildDir POST /api/devops/build-dirs
func (a *API) addBuildDir(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	var req struct {
		Path         string  `json:"path"`
		MaxSizeGB    float64 `json:"max_size_gb"`
		KeepVersions int     `json:"keep_versions"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	dg.AddBuildDir(req.Path, req.MaxSizeGB, req.KeepVersions)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "构建目录已添加"})
}

// checkBuildDirs POST /api/devops/build-dirs/check — 异步执行
// 构建目录检查涉及大量磁盘 I/O，同步执行会导致 502
func (a *API) checkBuildDirs(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		dg.CheckBuildDirs(ctx)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "构建产物清理检查已启动"})
}

// checkCronConflicts GET /api/devops/cron-conflicts — 异步执行
func (a *API) checkCronConflicts(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"conflicts": []interface{}{}})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dg.CheckCronConflicts(ctx)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "定时任务冲突检查已启动"})
}

// getBatchJobs GET /api/devops/batch-jobs
func (a *API) getBatchJobs(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"jobs": []interface{}{}})
		return
	}
	jobs := dg.GetBatchJobs()
	c.JSON(http.StatusOK, gin.H{"jobs": jobs, "count": len(jobs)})
}

// addBatchJob POST /api/devops/batch-jobs
func (a *API) addBatchJob(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	var job devops.BatchJob
	if err := c.BindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	dg.AddBatchJob(job)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "批处理作业已添加"})
}

// runBatchJob POST /api/devops/batch-jobs/:id/run — 异步执行
// 批处理作业可能耗时数分钟，同步执行会导致 502
func (a *API) runBatchJob(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	jobID := c.Param("id")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_ = dg.RunBatchJob(ctx, jobID)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": fmt.Sprintf("批处理作业 %s 已开始执行", jobID)})
}

// getTransferWatches GET /api/devops/transfers
func (a *API) getTransferWatches(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"watches": []interface{}{}})
		return
	}
	watches := dg.GetTransferWatches()
	c.JSON(http.StatusOK, gin.H{"watches": watches, "count": len(watches)})
}

// addTransferWatch POST /api/devops/transfers
func (a *API) addTransferWatch(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	var watch devops.TransferWatch
	if err := c.BindJSON(&watch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	dg.AddTransferWatch(watch)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "文件传输监控已添加"})
}

// getAPIDeps GET /api/devops/api-deps
func (a *API) getAPIDeps(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"deps": []interface{}{}})
		return
	}
	deps := dg.GetAPIDeps()
	c.JSON(http.StatusOK, gin.H{"deps": deps, "count": len(deps)})
}

// addAPIDep POST /api/devops/api-deps
func (a *API) addAPIDep(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	var dep devops.APIDependency
	if err := c.BindJSON(&dep); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	dg.AddAPIDependency(dep)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "API 依赖监控已添加"})
}

// checkAPIDeps POST /api/devops/api-deps/check — 异步执行
// API 依赖检查涉及多次 HTTP 请求，同步执行会导致 502
func (a *API) checkAPIDeps(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DevOps 模块未初始化"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		dg.CheckAPIDeps(ctx)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "API 依赖健康度检查已启动"})
}

// ═══════════════════════════════════════════════════
// V4.1 — 数据治理 API 端点
// ═══════════════════════════════════════════════════

// getBackupTasks GET /api/datagovern/backups
func (a *API) getBackupTasks(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"tasks": []interface{}{}, "files": []interface{}{}})
		return
	}
	tasks := dg.GetBackupTasks()
	files := dg.GetBackupFiles()
	c.JSON(http.StatusOK, gin.H{"tasks": tasks, "files": files, "task_count": len(tasks)})
}

// addBackupTask POST /api/datagovern/backups
func (a *API) addBackupTask(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	var task datagovern.BackupTask
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	dg.AddBackupTask(task)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "备份任务已添加"})
}

// runBackup POST /api/datagovern/backups/:id/run — 异步执行
// 备份操作可能耗时数分钟，同步执行会导致 502
func (a *API) runBackup(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	taskID := c.Param("id")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_, _ = dg.RunBackup(ctx, taskID)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": fmt.Sprintf("备份任务 %s 已开始执行", taskID)})
}

// scanSensitiveData POST /api/datagovern/sensitive-scan — 异步执行
// 敏感数据扫描涉及全盘文件遍历，同步执行会导致 502
func (a *API) scanSensitiveData(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		dg.ScanSensitiveData(ctx)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "敏感数据扫描已启动"})
}

// checkBigTables POST /api/datagovern/big-tables
// 异步执行：MySQL 查询可能超过 30s，同步执行会触发 Hub WriteTimeout 导致 502
func (a *API) checkBigTables(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "datagovern module not initialized"})
		return
	}
	dsn := c.Query("dsn")
	if dsn == "" {
		if portStr := c.Query("port"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				dsn = dg.GetDSNByPort(port)
			}
		}
	}
	if dsn == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing dsn or port parameter"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		alerts := dg.CheckBigTables(ctx, dsn)
		_ = alerts
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "大表检查已启动，结果将通过告警推送"})
}

// verifyBackup POST /api/datagovern/verify-backup
// 异步执行：备份验证最多 5 分钟，同步执行会触发 Hub WriteTimeout 30s 导致 502
func (a *API) verifyBackup(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		result := dg.VerifyBackup(ctx)
		_ = result
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "备份验证已启动，结果将通过告警推送"})
}

// getVerificationHistory GET /api/datagovern/verify-history
func (a *API) getVerificationHistory(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"history": []interface{}{}})
		return
	}
	history := dg.GetVerificationHistory()
	c.JSON(http.StatusOK, gin.H{"history": history, "count": len(history)})
}

// huntDeadlocks POST /api/datagovern/deadlocks
// 异步执行：死锁检测可能超过 30s，同步执行会触发 Hub WriteTimeout 导致 502
func (a *API) huntDeadlocks(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "datagovern module not initialized"})
		return
	}
	dsn := c.Query("dsn")
	if dsn == "" {
		// Try to get DSN by port from auto-discovery cache
		if portStr := c.Query("port"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				dsn = dg.GetDSNByPort(port)
			}
		}
	}
	if dsn == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing dsn or port parameter"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		records := dg.HuntDeadlocks(ctx, dsn)
		_ = records
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "死锁检测已启动，结果将通过告警推送"})
}

// getDeadlockHistory GET /api/datagovern/deadlock-history
func (a *API) getDeadlockHistory(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{"history": []interface{}{}})
		return
	}
	history := dg.GetDeadlockHistory()
	c.JSON(http.StatusOK, gin.H{"history": history, "count": len(history)})
}

// diagnoseConnPool POST /api/datagovern/conn-pool
// 异步执行：连接池诊断可能超过 30s，同步执行会触发 Hub WriteTimeout 导致 502
func (a *API) diagnoseConnPool(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "datagovern module not initialized"})
		return
	}
	dsn := c.Query("dsn")
	if dsn == "" {
		if portStr := c.Query("port"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				dsn = dg.GetDSNByPort(port)
			}
		}
	}
	if dsn == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing dsn or port parameter"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		diag := dg.DiagnoseConnPool(ctx, dsn)
		_ = diag
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "连接池诊断已启动，结果将通过告警推送"})
}

// preventCacheAvalanche POST /api/datagovern/cache-avalanche
// 异步执行：缓存雪崩分析可能超过 30s，同步执行会触发 Hub WriteTimeout 导致 502
func (a *API) preventCacheAvalanche(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		analysis := dg.PreventCacheAvalanche(ctx)
		_ = analysis
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "缓存雪崩分析已启动，结果将通过告警推送"})
}

// checkTSDBAnomaly POST /api/datagovern/tsdb-anomaly
// 异步执行：TSDB 异常检测可能超过 30s，同步执行会触发 Hub WriteTimeout 导致 502
func (a *API) checkTSDBAnomaly(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		anomalies := dg.CheckTSDBAnomaly(ctx)
		_ = anomalies
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": "TSDB 异常检测已启动，结果将通过告警推送"})
}

// archiveTable POST /api/datagovern/archive — 异步执行
// 表归档可能耗时数分钟，同步执行会导致 502
func (a *API) archiveTable(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "数据治理模块未初始化"})
		return
	}
	var req struct {
		DSN        string `json:"dsn"`
		Database   string `json:"database"`
		Table      string `json:"table"`
		DateColumn string `json:"date_column"`
		BeforeDate string `json:"before_date"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_ = dg.ArchiveTable(ctx, req.DSN, req.Database, req.Table, req.DateColumn, req.BeforeDate)
	}()
	c.JSON(http.StatusAccepted, gin.H{"status": "started", "message": fmt.Sprintf("表 %s.%s 归档已开始", req.Database, req.Table)})
}

// ═══════════════════════════════════════════════════
// V4.0/V4.1 — 自动发现 + 自动巡检 API（零配置智能模式）
// ═══════════════════════════════════════════════════

// getDevOpsAutoDiscovery GET /api/devops/auto-discover
// 同步返回发现结果（有缓存时毫秒级返回）
func (a *API) getDevOpsAutoDiscovery(c *gin.Context) {
	a.mu.RLock()
	dg := a.devOpsGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{
			"build_dirs":     []interface{}{},
			"cron_conflicts": []interface{}{},
			"api_deps":       []interface{}{},
			"git_repos":      []interface{}{},
			"auto_scanned":   false,
			"message":        "DevOps 模块未初始化",
		})
		return
	}

	// 同步执行（有缓存时毫秒级）
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	result := dg.AutoDiscover(ctx)

	c.JSON(http.StatusOK, gin.H{
		"build_dirs":     result.BuildDirs,
		"cron_conflicts": result.CronConflicts,
		"api_deps":       result.APIDeps,
		"git_repos":      result.GitRepos,
		"auto_scanned":   true,
		"discovery_time": result.Timestamp,
	})
}

// getDataGovernAutoDiscovery GET /api/datagovern/auto-discover
// 同步返回发现结果（有缓存时毫秒级返回，无缓存时执行一次扫描）
func (a *API) getDataGovernAutoDiscovery(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{
			"mysql_instances": []interface{}{},
			"redis_instances": []interface{}{},
			"backup_files":    []interface{}{},
			"backup_tasks":    []interface{}{},
			"auto_scanned":    false,
			"message":         "数据治理模块未初始化",
		})
		return
	}

	// 同步执行（有缓存时毫秒级，无缓存时扫描一次）
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	result := dg.AutoDiscover(ctx)

	c.JSON(http.StatusOK, gin.H{
		"mysql_instances": result.MySQLInstances,
		"redis_instances": result.RedisInstances,
		"backup_files":    result.BackupFiles,
		"backup_tasks":    result.BackupTasks,
		"auto_scanned":    true,
		"discovery_time":  result.DiscoveryTime,
	})
}

// getDataGovernAutoCheck GET /api/datagovern/auto-check
// 同步返回最近一次自动巡检结果
func (a *API) getDataGovernAutoCheck(c *gin.Context) {
	a.mu.RLock()
	dg := a.dataGovernGuard
	a.mu.RUnlock()
	if dg == nil {
		c.JSON(http.StatusOK, gin.H{
			"big_tables":       []interface{}{},
			"conn_pool_status": nil,
			"deadlock_records": []interface{}{},
			"cache_analysis":   nil,
			"auto_scanned":     false,
			"message":          "数据治理模块未初始化",
		})
		return
	}

	// 同步执行轻量巡检（有缓存时毫秒级）
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	result := dg.AutoCheck(ctx)

	c.JSON(http.StatusOK, gin.H{
		"mysql_instances":  result.MySQLInstances,
		"redis_instances":  result.RedisInstances,
		"big_tables":       result.BigTables,
		"conn_pool_status": result.ConnPoolStatus,
		"deadlock_records": result.DeadlockRecords,
		"cache_analysis":   result.CacheAnalysis,
		"auto_scanned":     true,
		"check_time":       result.DiscoveryTime,
	})
}
