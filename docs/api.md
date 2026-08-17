# API 参考

## 认证

所有API请求需要JWT认证（除 `/api/login` 外）：

```http
POST /api/login
Content-Type: application/json

{"username": "admin", "password": "xxx"}
```

响应：
```json
{"token": "sg-xxx", "username": "admin", "expires": 1234567890}
```

后续请求携带：`Authorization: Bearer sg-xxx`

## 系统接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/status | Agent状态 |
| GET | /api/version | 版本信息 |
| GET | /api/license | 许可证信息 |

## 服务器管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/servers | 服务器列表 |
| GET | /api/servers/:id | 服务器详情 |
| GET | /api/servers/:id/metrics | 服务器指标 |
| POST | /api/servers/:id/restart | 重启服务 |

## 告警与日志

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/alerts | 告警列表 |
| POST | /api/alerts/:id/ack | 确认告警 |
| POST | /api/alerts/:id/resolve | 解决告警 |
| GET | /api/logs | 操作日志 |
| GET | /api/audit | 审计日志 |

## 安全发现

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/findings | 发现列表（支持scanner/severity/status过滤） |
| GET | /api/findings/:id | 发现详情 |
| POST | /api/findings/:id/confirm | 确认发现 |
| POST | /api/findings/:id/false-positive | 标记误报 |
| POST | /api/findings/report | 生成报告 |

## 攻击画像

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/attack-events | 攻击事件 |
| GET | /api/attack-profiles | 攻击画像 |
| POST | /api/attack-profiles/emergency-rollback | 紧急回滚 |

## 配置版本

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/config-versions | 版本列表 |
| GET | /api/config-versions/:commit | 版本详情 |
| POST | /api/config-versions/:commit/approve | 审批版本 |
| POST | /api/config-versions/:commit/rollback | 回滚版本 |
| POST | /api/config-versions/:commit/tag | 打标签 |
| GET | /api/config-versions/export | 导出配置 YAML |
| POST | /api/config-versions/import | 导入配置 YAML |

## 配置迁移

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/import/monit | 从 Monit 配置导入 |
| POST | /api/import/supervisor | 从 Supervisor 配置导入 |
| POST | /api/import/systemd | 从 systemd 配置导入 |
| POST | /api/import/baota | 从宝塔导入 |
| POST | /api/import/pm2 | 从 PM2 配置导入 |

## 数据库维护

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/db/vacuum | VACUUM 数据库 |
| POST | /api/db/cleanup | 清理旧数据 |

## 数据导出

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/export/metrics | 导出指标 |
| GET | /api/export/alerts | 导出告警 |
| GET | /api/export/audit | 导出审计日志 |

## 安全自检

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/security-check | 依赖漏洞 + CIS 合规检查 |

## 规则管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/rules | 规则列表 |
| POST | /api/rules | 添加规则 |
| PUT | /api/rules/:id | 更新规则 |
| DELETE | /api/rules/:id | 删除规则 |
| POST | /api/rules/test | Dry-Run测试 |

## 安全控制

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/safety | 安全状态 |
| POST | /api/emergency-stop | 紧急停止 |
| POST | /api/emergency-resume | 恢复自动操作 |

## 证书管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/certs | 证书列表 |
| POST | /api/certs/scan | 扫描证书 |
| POST | /api/certs/renew | 续期证书 |

## 威胁情报

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/intel/status | 情报源状态 |
| POST | /api/intel/sync | 触发同步 |