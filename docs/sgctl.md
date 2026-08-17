# sgctl 命令行工具

## 概述

`sgctl` 是 ServerGuard 的命令行管理工具，用于与 Agent 和 Hub 交互。

## 全局参数

```bash
sgctl --server http://localhost:8080 --token <JWT_TOKEN> <command>
```

## 命令列表

### 系统管理

```bash
sgctl status              # 查看Agent状态
sgctl version             # 查看版本
sgctl doctor              # 完整系统诊断
sgctl upgrade             # 升级Agent
sgctl logs                # 查看日志
sgctl trace <trace_id>    # 查询trace链路
```

### 守护管理

```bash
sgctl guard list          # 守护目标列表
sgctl guard add <name>    # 添加守护目标
```

### 规则管理

```bash
sgctl rule list           # 规则列表
sgctl rule test           # Dry-Run测试
```

### 证书管理

```bash
sgctl cert list           # 证书列表
sgctl cert scan           # 扫描证书
sgctl cert renew <domain> # 续期证书
```

### 安全发现

```bash
sgctl finding list                    # 发现列表
sgctl finding confirm <id>            # 确认发现
sgctl finding false-positive <id>     # 标记误报
sgctl finding report                  # 生成报告
```

### 攻击告警

```bash
sgctl attack profiles               # 攻击画像
sgctl attack emergency-rollback     # 紧急回滚
```

### 配置版本

```bash
sgctl config-version list           # 版本列表
sgctl config-version rollback <id>  # 回滚版本
sgctl config-version approve <id>   # 审批版本
sgctl config-version tag <commit> <tag>  # 打标签
sgctl config-version export         # 导出配置 YAML
sgctl config-version import <file>  # 导入配置 YAML
```

### 配置迁移

```bash
sgctl import monit --path <config>       # 从 Monit 配置导入
sgctl import supervisor --path <config>  # 从 Supervisor 配置导入
sgctl import systemd --path <config>     # 从 systemd 配置导入
sgctl import baota                       # 从宝塔导入
sgctl import pm2 --path <config>         # 从 PM2 配置导入
```

### 数据库维护

```bash
sgctl db vacuum     # VACUUM 数据库
sgctl db cleanup    # 清理旧数据（攻击事件/画像）
```

### 数据导出

```bash
sgctl export metrics  # 导出指标数据
sgctl export alerts   # 导出告警数据
sgctl export audit    # 导出审计日志
```

### 安全自检

```bash
sgctl security-check  # 依赖漏洞扫描 + CIS Benchmark 合规检查
```

### 安全控制

```bash
sgctl safety status           # 安全状态
sgctl safety kill-budget      # Kill预算
sgctl safety circuit-breaker  # 熔断器状态
sgctl emergency-stop          # 紧急停止
sgctl emergency-resume        # 恢复操作
sgctl whitelist list          # 白名单
sgctl whitelist add <item>    # 添加白名单
```

### 宝塔

```bash
sgctl baota scan       # 扫描宝塔
sgctl baota status     # 宝塔状态
sgctl baota rescan     # 重新扫描
sgctl baota test-api   # 测试API
```

### Hub通信

```bash
sgctl hub register     # 注册到Hub
sgctl hub heartbeat    # 强制心跳
```

## doctor 诊断报告

`sgctl doctor` 执行完整系统检查，包括：

1. Agent运行状态
2. 配置文件有效性
3. 磁盘空间
4. 内存状态
5. 网络连通性
6. 端口可用性
7. 守护进程健康
8. 日志文件
9. 安全状态（四模式状态机）
10. 证书到期
11. 许可证状态

输出格式：
```
═══════════════════════════════════════════════════
         ServerGuard 系统诊断报告
═══════════════════════════════════════════════════
✓ Agent运行状态: Agent正在运行
✓ 配置文件: 配置文件加载正常
⚠ 磁盘空间: 磁盘使用率 85%
...
总计: 11 | 通过: 8 | 警告: 2 | 失败: 1
═══════════════════════════════════════════════════
```