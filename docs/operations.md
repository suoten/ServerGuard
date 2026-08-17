# 运维手册

## 日常运维

### 查看系统状态

```bash
sgctl status
sgctl doctor
```

### 查看告警

```bash
sgctl logs
```

或通过Web面板 `/alerts` 页面查看。

### 查看安全发现

```bash
sgctl finding list
sgctl finding report
```

## 安全操作

### 紧急停止

当系统出现异常时，可以紧急停止所有自动操作：

```bash
sgctl emergency-stop
```

恢复：
```bash
sgctl emergency-resume
```

### 安全模式

ServerGuard 四模式状态机：
- **Normal**：正常运行，所有守护模块活跃
- **Throttled**：资源紧张，降低检查频率
- **Minimal**：仅保留核心守护（进程保活+磁盘监控）
- **Survival**：仅保活Agent自身，停止所有外部操作

查看当前模式：
```bash
sgctl safety status
```

### Kill预算

防止Agent过度Kill进程：
```bash
sgctl safety kill-budget
```

### 熔断器

连续失败时自动熔断：
```bash
sgctl safety circuit-breaker
```

## 证书管理

### 扫描证书

```bash
sgctl cert scan
```

### 手动续期

```bash
sgctl cert renew example.com
```

### 证书日历

通过Web面板 `/certs` 页面查看所有证书到期日历。

## 配置管理

### 配置热加载

```bash
kill -HUP $(pidof serverguard-agent)
```

### 配置回滚

```bash
sgctl config-version list
sgctl config-version rollback <commit-id>
```

## 备份与恢复

### 数据备份

SQLite数据库位于 `/var/lib/serverguard/data.db`，可直接备份：

```bash
cp /var/lib/serverguard/data.db /backup/data-$(date +%Y%m%d).db
```

### 配置备份

配置文件自动备份，保留最近100个版本。

## 性能调优

### 资源限制

Agent通过多层机制限制自身资源使用：
- systemd: MemoryMax=80M, CPUQuota=5%
- Go runtime: GOMAXPROCS=1, MemoryLimit=50MB
- 安全管理器: Kill预算+熔断器

### 调优建议

```bash
# 通过Web面板查看调优建议
# /settings → 调优建议
```

## 故障排查

### Agent无法启动

1. 检查配置文件：`sgctl config validate`
2. 检查端口占用：`netstat -tlnp | grep 8080`
3. 查看日志：`journalctl -u serverguard-agent -f`

### 守护目标无法恢复

1. 检查Kill预算是否耗尽：`sgctl safety kill-budget`
2. 检查熔断器状态：`sgctl safety circuit-breaker`
3. 检查安全模式：`sgctl safety status`
4. 查看trace链路：`sgctl trace <trace_id>`

### 证书续期失败

1. 检查ACME速率限制
2. 检查DNS解析
3. 查看证书日志：`sgctl logs | grep cert`

## 升级

```bash
sgctl upgrade
```

升级包使用Ed25519签名验证，确保完整性。

## 监控

### Web面板

访问 `http://your-server:8080` 查看Web面板。

主要页面：
- `/dashboard` - 总览
- `/alerts` - 告警
- `/findings` - 安全发现
- `/attacks` - 攻击画像
- `/certs` - 证书管理
- `/guards` - 守护目标
- `/safety` - 安全状态
- `/rbac` - 用户权限
- `/rules` - 规则管理
- `/config-approval` - 配置审批
- `/audit` - 审计日志