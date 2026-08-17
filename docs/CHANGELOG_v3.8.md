# ServerGuard v3.8 变更说明

> **日期**：2026-08-09
> **范围**：自用全功能版增量改造（11 个任务组 / 41 个子任务）
> **原则**：不触碰商业化部分（license/multi-tenant/rbac/hub/plugin/官网/支付等）

---

## 1. 存储与数据生命周期基础设施

### 1.1 差异化保留策略
- **新增** `internal/storage/retention_policy.go`：`RetentionPolicy` 结构体，定义各数据类型保留期（指标原始 1h / 1min 聚合 7d / 1h 聚合 90d / 进程状态 180d / 告警 180d / 自动修复 365d / 审计 WORM 365d+ / 证书永久 / 攻击事件 90d / 攻击画像 365d）
- **新增** `Storage.SetRetentionPolicy()` / `Storage.EnforceRetention()` 方法，审计表跳过清理（WORM）

### 1.2 DB 体积与磁盘水位联动
- **新增** `internal/storage/db_watermark.go`：`CheckDBSize()` 返回 DB 体积和可写入状态，超过 200MB 拒绝写入
- **新增** `internal/storage/disk_watermark_linux.go` / `disk_watermark_windows.go`：`CheckDiskWatermark()` 返回磁盘使用率和水位等级（normal/high/critical）
- **扩展** `internal/storage/downsampler.go`：`AccelerateOnHighWatermark()`（磁盘>80% 加速降采样）、`PurgeColdDataOnCritical()`（磁盘>90% 删非审计数据只保留 7 天）
- **集成** Agent 维护循环接入磁盘水位检查，high 时加速降采样，critical 时删冷数据

### 1.3 攻击数据差异化保留
- **扩展** `internal/storage/attack_store.go`：参数化 `PurgeOldAttackEvents()` / `PurgeOldAttackProfiles()` / `PurgeAttackEventsBySeverity()`，原始事件 90 天归档，画像 1 年清理

---

## 2. 五层安全机制扩展

### 2.1 资源地板检查扩展
- **扩展** `internal/agent/safety/resource_floor.go`：新增 `MaxIOWaitPercent`（默认 50）和 `MinDiskAvailableMB`（默认 500）字段
- `CheckKillAllowed()` 增加 IO 等待>50% 拒绝 Kill、磁盘可用<500MB 拒绝写操作判断

### 2.2 封禁/解封振荡熔断器
- **新增** `internal/agent/safety/ban_unban_breaker.go`：`BanUnbanBreaker`（10min 内解封 3 次暂停封禁 1h）
- 集成到 SecurityGuard 封禁决策链

### 2.3 Kill 后系统对比评估器
- **新增** `internal/agent/safety/post_kill_evaluator.go`：`PostKillEvaluator`（Kill 前记录快照，5min 后对比，系统更差则触发紧急停止）
- 集成到 `internal/agent/executor/executor.go`

### 2.4 自我节流临界模式
- **新增** `SafetyManager.ShouldRunGuards()` 方法，Agent 主循环用此方法保护 Guard.Check() 调用
- 四档状态机完整切换：Normal → Throttled → Minimal → Survival → Emergency

---

## 3. 资源与服务守护模块扩展

### 3.1 CPU 误杀防护
- **新增** `internal/guards/resource/cpu_trigger_tracker.go`：连续 3 次触发才 Kill，首次仅告警
- 集成到 `ResourceGuard.checkCPU()`

### 3.2 端口冲突自动解决
- **新增** `internal/guards/service/port_conflict_resolver.go`：探测占用进程的 Status/PPID/CreateTime，僵尸→Kill 释放，正常→告警

### 3.3 依赖链隔离与按序拉起
- **新增** `internal/guards/service/dependency_chain_manager.go`：`IsolateDownstream()` / `RestoreInOrder()` 方法
- 集成到 `ServiceGuard.Check()` / `checkTarget()`

---

## 4. 安全防护与日志防护模块扩展

### 4.1 暴破渐进式封禁
- **新增** `internal/guards/security/progressive_ban.go`：三档渐进式（首次→限速，5min 内 5 次→短期 1h，封禁期间再攻击→升级 24h）

### 4.2 SSH 失联紧急回滚
- **新增** `internal/guards/security/emergency_rollback.go`：`EmergencyRollback` 看门狗（封禁后 5s 检测 SSH 连接=0 且无法 ping 网关→自动清除所有 iptables 规则）
- 集成到 SecurityGuard 所有封禁路径（Linux/宝塔安全模式/Windows）

### 4.3 全局日志自动发现
- **新增** `internal/guards/log/log_auto_discoverer.go`：Linux 调 `lsof`/读 `/proc/*/fd`，Windows 调 `NtQuerySystemHandle`

### 4.4 logrotate 冲突让位与接管
- **新增** `internal/guards/log/logrotate_takeover.go`：`TakeOverFromLogrotate()` 检测并跳过 logrotate 管理的日志

---

## 5. 证书守护模块扩展

### 5.1 错峰续期调度
- **新增** `CertGuard.CheckExpiryWithStagger()`：`staggeredDeadline = notAfter - 14d + rand(0,7d)`
- `CertInfo` 新增 `StaggeredDeadline` / `CachedUntil` 字段
- Agent 主循环用 `CheckExpiryWithStagger` 替代 `CheckExpiry`

### 5.2 多 CA 降级续期链
- **新增** `internal/acme/multi_ca_renewer.go`：`RenewWithFallback()` 按序尝试 LE → ZeroSSL → TrustAsia

### 5.3 失败队列重试
- **新增** `internal/guards/cert/renewal_queue.go`：`RenewalFailureQueue` 指数退避重试（`24h * 2^retryCount`，最多 5 次）
- 集成到 `CheckExpiryWithStagger()` 调用 `ProcessRetry()`，`attemptRenewal()` 失败时 `Enqueue()`

### 5.4 续期后处理与验证
- **新增** `internal/guards/cert/post_renewal.go`：`ReloadAndVerify()` reload Nginx/Apache + HTTPS 探测验证 + 失败回滚
- 集成到 `attemptRenewal()` 成功路径

---

## 6. 流量守护与攻击预警模块扩展

### 6.1 低速慢攻击检测
- **新增** `internal/guards/traffic/slow_attack_detector.go`：`SlowRateDetector` per-IP 请求速率滑动窗口

### 6.2 攻击事件关联引擎
- **新增** `internal/guards/attackwarn/correlation.go`：`CorrelationEngine` 时间窗口内同源 IP 事件聚合，跨模块关联打分
- **集成** `ScanWebAttacks()` / `ScanServerAttacks()` 中调用 `correlationEngine.Ingest()` 喂入事件

### 6.3 攻击画像聚合与周期性识别
- `CorrelationEngine` 生成 `AttackProfile`，`DetectPeriodic()` 检测周期性攻击模式
- 置信度>0.8 联动封禁 1h，>0.5 联动限速，否则仅记录

---

## 7. 网站安全与漏洞扫描模块扩展

### 7.1 YARA 引擎集成
- **集成** `internal/guards/websecurity/` W3 子扫描器加载 `configs/yara_rules/` 规则，扫描 PHP/JSP/ASP 文件
- YARA 引擎位于 `internal/guards/scannercommon/yara_engine.go`（纯 Go 实现）

### 7.2 依赖漏洞扫描
- **新增** `internal/guards/vulnscan/dependency_scanner.go`：`DependencyScanner` 解析 5 种依赖锁文件（composer.lock / requirements.txt / package-lock.json / pom.xml / go.mod），匹配本地 OSV 数据库

### 7.3 CIS Benchmark 配置合规扫描
- **新增** `configs/cis_benchmark/` 目录：`ssh.yml` / `users_permissions.yml` / `kernel_network.yml` 规则文件
- `CISComplianceScanner` 实现真实检查：SSH 配置（PermitRootLogin / PasswordAuthentication / PermitEmptyPasswords）、系统用户（UID=0）、文件权限（/etc/passwd / /etc/shadow / /etc/group）、内核参数（ip_forward / tcp_syncookies / accept_redirects）

---

## 8. 告警推送与配置版本管理扩展

### 8.1 P0 告警升级机制
- **新增** `internal/notifier/escalation.go`：`EscalationManager`（P0 告警 5min 未确认→升级全渠道，30min 未确认→通知第二联系人）
- 集成到 `notifier.go`

### 8.2 时区感知延迟推送
- **新增** `TimeZoneDelay`：凌晨 0-6 点 P2/P3 告警入延迟队列，8 点统一推送
- 集成到 `notifier.go` 的 `handleAlert()`

### 8.3 配置版本 tag 与导出导入
- **扩展** `internal/storage/config_version_store.go`：`TagVersion()` / `ExportYAML()` / `ImportYAML()`
- **扩展** `internal/guards/config/version.go`：`ConfigVersionManager` 持有 `storage.Storage` 引用，`CreateTag()` 调用 `store.TagVersion()`
- **新增 API** `POST /api/config-versions/:commit/tag`、`GET /api/config-versions/export`、`POST /api/config-versions/import`
- **新增 sgctl** `config-version tag <commit> <tag>`、`config-version export`、`config-version import <file>`

---

## 9. sgctl CLI 新增命令

### 9.1 配置迁移命令
```bash
sgctl import monit --path <config>       # 从 Monit 配置导入
sgctl import supervisor --path <config>  # 从 Supervisor 配置导入
sgctl import systemd --path <config>     # 从 systemd 配置导入
sgctl import baota                       # 从宝塔导入
sgctl import pm2 --path <config>         # 从 PM2 配置导入
```

**新增 5 个 migrator**（`internal/agent/conflict/`）：
- `migrator_monit.go` / `migrator_supervisor.go` / `migrator_systemd.go` / `migrator_baota.go` / `migrator_pm2.go`
- 各实现 `ConfigMigrator` 接口（`Name()` / `Parse(configPath)` → `[]GuardTarget`）

### 9.2 数据库维护命令
```bash
sgctl db vacuum     # VACUUM 数据库
sgctl db cleanup    # 清理旧数据（攻击事件/画像）
```

### 9.3 数据导出命令
```bash
sgctl export metrics  # 导出指标数据
sgctl export alerts   # 导出告警数据
sgctl export audit    # 导出审计日志
```

### 9.4 安全自检命令
```bash
sgctl security-check  # 依赖漏洞扫描 + CIS Benchmark 合规检查
```

---

## 10. API 新增端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/import/monit | 从 Monit 配置导入 |
| POST | /api/import/supervisor | 从 Supervisor 配置导入 |
| POST | /api/import/systemd | 从 systemd 配置导入 |
| POST | /api/import/baota | 从宝塔导入 |
| POST | /api/import/pm2 | 从 PM2 配置导入 |
| POST | /api/db/vacuum | VACUUM 数据库 |
| POST | /api/db/cleanup | 清理旧数据 |
| GET | /api/export/metrics | 导出指标 |
| GET | /api/export/alerts | 导出告警 |
| GET | /api/export/audit | 导出审计日志 |
| GET | /api/security-check | 安全自检（依赖漏洞 + CIS 合规） |
| POST | /api/config-versions/:commit/tag | 打标签 |
| GET | /api/config-versions/export | 导出配置 YAML |
| POST | /api/config-versions/import | 导入配置 YAML |

---

## 11. 配置迁移

- **schema 版本** v2 → v3
- **新增迁移** `migrateV2ToV3()`：设置 `MaxDiskIOWaitPercent=50` / `MinDiskAvailableMB=500` / `TrashRetentionDays=7` / `RetentionDays=30` 默认值
- 迁移前自动备份旧配置到 `~/.serverguard/config.backup.v2.*.yaml`

---

## 12. 部署脚本更新

- **install.sh**：新增规则文件复制步骤（`configs/yara_rules/` + `configs/cis_benchmark/` → `/opt/serverguard/configs/`）
- **install.ps1**：已递归复制 `configs/` 目录，无需修改

---

## 13. 审核修复

### 第一轮审核（4 项 + 1 bonus）
1. Agent 主循环接入磁盘水位检查（maintenanceTicker）
2. 字段名 `MinDiskFreeMB` → `MinDiskAvailableMB` 全局重命名
3. Agent 主循环用 `ShouldRunGuards()` 替换 `mode != ModeSurvival`
4. 创建 `configs/cis_benchmark/` 目录 + 3 个 CIS 规则 YAML 文件
5. W9 正则修复：Go 不支持 `(?!...)` 负向前瞻 → 改为简单正则 + `isKnownCDN()` 代码过滤

### 第二轮审核（7 项）
1. 关联引擎喂数据：`ScanWebAttacks` / `ScanServerAttacks` 中添加 `correlationEngine.Ingest()` 调用
2. emergencyRollback 遗漏路径：宝塔安全模式路径和 Windows 路径添加 `OnBanCalled(ip)`
3. 证书失败队列重试：`CheckExpiryWithStagger` 中调用 `ProcessRetry`，`attemptRenewal` 失败时 `Enqueue`
4. 续期后验证：`attemptRenewal` 成功时调用 `ReloadAndVerify`
5. Agent 主循环证书错峰：`CheckExpiry` 替换为 `CheckExpiryWithStagger`
6. logScanTicker guards 保护：添加 `ShouldRunGuards()` 保护
7. config guard 对接 storage：`ConfigVersionManager` 添加 `store` 字段，`CreateTag` 调用 `store.TagVersion`

---

## 验证结果

| 验证项 | 结果 |
|--------|------|
| `go build ./...` | ✅ 通过 |
| `go test ./... -count=1` | ✅ 全部通过（38 个测试包） |
| `go test -tags integration,e2e,performance,chaos,safety` | ✅ 全部通过 |
| `go vet` | ✅ 仅 4 个预存在 IPv6 警告（非本次改动） |
| race 检测 | ⚠️ Windows 无 gcc，需在 Linux 环境补充验证 |

---

## 新增/修改文件清单

### 新增文件
- `internal/storage/retention_policy.go`
- `internal/storage/db_watermark.go`
- `internal/storage/disk_watermark_linux.go`
- `internal/storage/disk_watermark_windows.go`
- `internal/storage/config_version_store.go`
- `internal/storage/attack_store.go`（参数化清理）
- `internal/agent/safety/ban_unban_breaker.go`
- `internal/agent/safety/post_kill_evaluator.go`
- `internal/agent/safety/safety_extension_test.go`
- `internal/guards/resource/cpu_trigger_tracker.go`
- `internal/guards/service/port_conflict_resolver.go`
- `internal/guards/service/dependency_chain_manager.go`
- `internal/guards/security/progressive_ban.go`
- `internal/guards/security/emergency_rollback.go`
- `internal/guards/log/log_auto_discoverer.go`
- `internal/guards/log/logrotate_takeover.go`
- `internal/acme/multi_ca_renewer.go`
- `internal/guards/cert/renewal_queue.go`
- `internal/guards/cert/post_renewal.go`
- `internal/guards/attackwarn/correlation.go`
- `internal/guards/traffic/slow_attack_detector.go`
- `internal/guards/vulnscan/dependency_scanner.go`（含 CIS 合规扫描）
- `internal/notifier/escalation.go`
- `internal/agent/conflict/migrator.go`
- `internal/agent/conflict/migrator_monit.go`
- `internal/agent/conflict/migrator_supervisor.go`
- `internal/agent/conflict/migrator_systemd.go`
- `internal/agent/conflict/migrator_baota.go`
- `internal/agent/conflict/migrator_pm2.go`
- `configs/cis_benchmark/ssh.yml`
- `configs/cis_benchmark/users_permissions.yml`
- `configs/cis_benchmark/kernel_network.yml`
- `docs/CHANGELOG_v3.8.md`

### 修改文件
- `cmd/serverguard-agent/main.go` — 维护循环、证书错峰、guards 保护、downsampler
- `cmd/sgctl/main.go` — 新增 import/db/export/security-check/config-version tag|export|import 命令
- `internal/hub/api/api.go` — 新增 14 个 API handler
- `internal/guards/security/security.go` — emergencyRollback 集成
- `internal/guards/cert/cert.go` — renewalQueue/postRenewal 集成
- `internal/guards/config/version.go` — store 字段、ExportYAML/ImportYAML
- `internal/guards/attackwarn/attackwarn.go` — correlationEngine.Ingest() 调用
- `internal/guards/websecurity/websecurity.go` — YARA 引擎集成、W9 正则修复
- `internal/storage/downsampler.go` — 扩展方法
- `internal/agent/safety/safety.go` — ShouldRunGuards、字段重命名
- `internal/agent/safety/resource_floor.go` — 字段重命名
- `internal/agent/executor/executor.go` — PostKillEvaluator 集成
- `internal/guards/resource/resource.go` — CpuTriggerTracker 集成
- `internal/guards/service/service.go` — DependencyChainManager 集成
- `internal/notifier/notifier.go` — EscalationManager/TimeZoneDelay 集成
- `internal/config/config.go` — 新配置字段 + yaml tag
- `internal/config/migrate.go` — v2→v3 迁移
- `internal/types/types.go` — CertInfo 新字段
- `deploy/install.sh` — 规则文件复制步骤