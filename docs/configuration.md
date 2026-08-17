# 配置说明

## 配置文件

Agent配置文件位于 `configs/agent.yaml`，Hub配置文件位于 `configs/hub.yaml`。

## 主要配置项

### Agent配置

```yaml
# 服务器信息
server:
  id: "server-001"
  name: "web-server-1"

# 存储配置
storage:
  type: sqlite          # sqlite | postgres
  path: /var/lib/serverguard/data.db
  encryption_key: ""    # SQLCipher加密密钥

# 规则配置
rules:
  config_path: /etc/serverguard/rules
  max_rules: 1000
  match_timeout: 5s
  default_cooldown: 60s

# 安全配置
safety:
  kill_budget_hourly: 10
  kill_budget_daily: 50
  kill_min_interval: 30s
  circuit_breaker_threshold: 5
  circuit_breaker_reset_duration: 5m
  min_available_memory_mb: 100
  max_load_factor: 0.8
  cascade_suppression: true

# 通知配置
notify:
  email:
    enabled: true
    smtp_host: smtp.example.com
    smtp_port: 587
    username: ""
    password: ""
    from: alert@example.com
    to: admin@example.com
  webhook:
    enabled: false
    url: ""

# 宝塔配置
baota:
  enabled: true
  auto_discover: true

# Hub配置
hub:
  enabled: false
  url: http://hub.example.com:8080
  token: ""
```

### 热加载

```bash
# 发送SIGHUP信号热加载配置
kill -HUP $(pidof serverguard-agent)
```

### 配置校验

```bash
sgctl config validate
```

## 版本管理

配置变更自动生成版本历史，支持回滚：

```bash
# 查看版本历史
sgctl config-version list

# 回滚到指定版本
sgctl config-version rollback <commit-id>

# 审批配置变更
sgctl config-version approve <commit-id>
```