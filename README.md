<div align="center">

# ServerGuard · 让服务器自己照顾自己

**Self-Healing Server Operations & Security Agent**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/suoten/ServerGuard?display_name=tag&sort=semver)](https://github.com/suoten/ServerGuard/releases)
[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)](#支持的操作系统)
[![GitHub Stars](https://img.shields.io/github/stars/suoten/ServerGuard?style=social)](https://github.com/suoten/ServerGuard/stargazers)
[![Gitee Stars](https://gitee.com/suoten/serverguard/badge/star.svg?theme=dark)](https://gitee.com/suoten/serverguard/stargazers)

[English](#english) | [中文](README.md)

</div>

---

> 凌晨 3 点，磁盘涨到 95%。
> 你在睡觉。ServerGuard 清掉 30 天前的旧日志，给 MySQL 留了活路，
> 早上 8 点把"昨晚发生了什么、它是怎么处理的"推到你的微信。
>
> 监控工具只负责告诉你"服务器死了"。**ServerGuard 负责不让它死。**

ServerGuard 是一个部署在服务器上的轻量级 Agent（16MB 单二进制，零依赖），7×24 小时盯着 CPU、内存、磁盘、网络、进程、网站、证书、数据库、安全威胁——发现问题时**直接动手修复**：清理磁盘、重启进程、封禁恶意 IP、续期证书、清除木马，而不是只发一条告警然后眼睁睁看着服务器崩掉。

它还会越用越懂你的服务器：学习每个时段的正常负载，在偏离常态时提醒；盯着磁盘的增长速度，提前一周告诉你"预计 5 天后写满"；自动修复的同时拍下系统快照，附上一份"根因推测"，让你不用登服务器也知道大概发生了什么。

**安全理念**：该出手时不犹豫，不该碰的不碰，不确定的交给你决定。永远不会搞崩宝塔、IIS、Apache、MySQL、Nginx。

## ✨ 特性一览

- 🔥 **自动自愈**：磁盘清理 / 内存泄漏拦截 / 服务重启 / SSH 封禁 / 证书续期 / 挖矿木马查杀，发现即修复
- 🧠 **智能运维**：基线异常检测（168 时段学习）、磁盘写满预测、根因分析快照、告警收敛降噪
- 🛡️ **五层安全机制**：45+ 进程白名单、Kill 预算、熔断器、级联防护、全局紧急停止，绝不误伤服务器
- 🌐 **多机集中管控**：Hub 统一纳管多台服务器，聚合视图 + 集中下发命令
- 📊 **实时面板**：健康评分、网站/API/数据库监控、审计日志，Vue 3 面板嵌入单二进制
- 📱 **全渠道告警**：微信（Server酱）/ 钉钉 / 企微 / 飞书 / 邮件 / Slack / Telegram / 自定义 Webhook
- 📦 **零依赖部署**：单二进制 16MB，SQLite 存储，`install.sh` 一键安装，兼容宝塔面板

<!-- 📸 截图：建议放 2-3 张面板截图（仪表盘、告警中心、安全监控），
     截图放到 docs/screenshots/ 目录后取消下面注释
![仪表盘](docs/screenshots/dashboard.png)
![安全监控](docs/screenshots/security.png)
-->

## 📚 文档导航

| 文档 | 说明 |
|---|---|
| [安装指南](docs/install.md) | 一键安装 / 手动安装 / 宝塔部署 / Docker |
| [配置说明](docs/configuration.md) | 全部配置项详解 |
| [sgctl 运维工具](docs/sgctl.md) | 配置导入导出、数据库维护、安全自检 |
| [运维手册](docs/operations.md) | 日常运维、故障排查 |
| [API 文档](docs/api.md) | REST API 全量接口 |
| [变更日志](docs/CHANGELOG_v3.8.md) | 版本变更记录 |
| [产品规划](ServerGuard_产品规划文档_v4.9.md) | Roadmap 与设计思路 |

## 🚀 快速开始

### 方式一：一键安装（推荐）

从 [GitHub Releases](https://github.com/suoten/ServerGuard/releases)（或 [Gitee Releases](https://gitee.com/suoten/serverguard/releases)）下载对应架构的发布包：

```bash
# 1. 下载发布包（选择对应架构）
#    x86_64（绝大多数服务器）:
wget https://github.com/suoten/ServerGuard/releases/latest/download/serverguard-0.3.0-linux-amd64.zip
#    ARM64（鲲鹏/飞腾/Kylin V10）:
wget https://github.com/suoten/ServerGuard/releases/latest/download/serverguard-0.3.0-linux-arm64.zip

# 2. 解压
unzip serverguard-0.3.0-linux-amd64.zip

# 3. 运行安装脚本
sudo bash install.sh

# 4. 打开面板
#    浏览器访问 http://你的服务器IP:18090
#    用户名: admin  密码: admin123
#    首次登录后请立即修改密码！
```

> 国内服务器下载慢？把 `github.com/suoten/ServerGuard` 换成 `gitee.com/suoten/serverguard` 即可。

`install.sh` 自动完成：
1. 复制二进制到 `/opt/serverguard/`
2. 生成随机 JWT Secret 的配置文件
3. 安装 systemd 服务（开机自启 + 崩溃自动重启）
4. 放行防火墙 18090 端口（firewalld / ufw / iptables 自动检测）
5. 启动服务并输出面板地址

### 方式二：手动安装

```bash
# 1. 创建目录
sudo mkdir -p /opt/serverguard /var/lib/serverguard

# 2. 复制二进制（amd64 或 arm64）
sudo cp serverguard-agent /opt/serverguard/serverguard-agent
sudo chmod +x /opt/serverguard/serverguard-agent

# 3. 复制配置并修改 JWT Secret（重要！）
sudo cp configs/serverguard-agent.yaml /opt/serverguard/config.yaml
sudo sed -i "s/CHANGE_ME_TO_RANDOM_STRING/$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)/" /opt/serverguard/config.yaml

# 4. 安装 systemd 服务
sudo cp deploy/serverguard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now serverguard-agent

# 5. 放行防火墙
sudo firewall-cmd --permanent --add-port=18090/tcp && sudo firewall-cmd --reload  # CentOS/Kylin
# 或
sudo ufw allow 18090/tcp  # Ubuntu
```

### 方式三：Docker 部署

```bash
git clone https://github.com/suoten/ServerGuard.git
cd ServerGuard
docker compose up -d
# Agent 面板: http://服务器IP:9090
# Hub 管控台: http://服务器IP:8444（单机部署可删除 hub 服务）
```

### 方式四：在宝塔面板上部署

> 适合已经在用宝塔面板的用户。

1. 宝塔面板 → 文件 → `/opt` → 新建 `serverguard` 目录，上传二进制并重命名为 `serverguard-agent`，上传 `config.yaml`
2. 宝塔面板 → 安全 → 放行端口 18090
3. 终端执行：
```bash
sudo chmod +x /opt/serverguard/serverguard-agent
sudo cp /opt/serverguard/serverguard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now serverguard-agent
```
4. （可选）宝塔 → 网站 → 反向代理到 `http://127.0.0.1:18090`，用域名 + 443 访问面板

**宝塔环境下的额外优势**：
- 自动检测宝塔面板，优先用宝塔API续期证书（不消耗ACME配额）
- 自动发现宝塔管理的网站，一键导入监控
- 监控 Nginx/MySQL/PHP 进程，挂了自动重启

### 从源码构建

```bash
# 构建前端并嵌入
cd web && npm install && npm run build && cd ..

# 构建 Agent（Linux amd64）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o serverguard-agent ./cmd/serverguard-agent

# 构建 Hub 多机管控端
go build -o serverguard-hub ./cmd/serverguard-hub

# 构建 sgctl 运维工具
go build -o sgctl ./cmd/sgctl
```

---

## 为什么需要 ServerGuard？

| 没用 ServerGuard 之前 | 用了 ServerGuard 之后 |
|---|---|
| 凌晨3点磁盘满了，MySQL崩溃，网站打不开 | 磁盘95%时自动清理旧日志，你睡觉时问题已经解决 |
| 某个进程内存泄漏吃光内存，内核OOM随机杀进程 | 检测到内存不足，智能终止非关键进程（白名单进程永不杀），发微信通知你 |
| SSL证书过期忘了续，用户浏览器报红叉 | 提前14天自动续期，续完自动reload并验证生效 |
| SSH被暴力破解，被人挂马挖矿 | 检测到30次失败登录自动封禁IP，发现挖矿进程直接杀掉 |
| Python脚本循环启动上百个进程，MySQL连接池占满 | 进程爆炸检测自动终止多余进程，MySQL连接按来源统计定位元凶 |
| 日志文件涨到50GB把磁盘撑爆 | 自动轮转压缩日志，排除web服务活跃日志 |
| 服务器被植入WebShell后门 | 扫描PHP文件特征码 + 3000+ YARA规则，发现WebShell立即告警 |
| crontab被篡改植入定时挖矿任务 | 检测可疑cron条目（反弹shell/挖矿/base64），立即告警 |
| 系统关键文件被篡改（/etc/passwd等） | 文件完整性监控发现哈希变化，立即告警 |
| MySQL/Redis挂了没发现 | 自动检测数据库端口 + Redis PING深度检测，连接失败立即告警并重启 |
| 被多模块协同攻击（SSH暴破+Web扫描+CC） | 攻击关联引擎5分钟窗口聚合，置信度>0.8自动封禁1小时 |
| Let's Encrypt限流无法续期 | 多CA降级链自动切换ZeroSSL/TrustAsia，失败队列指数退避重试 |
| 官方发了新漏洞自己不知道，被黑客利用了才发现 | 每6小时自动拉取NVD最新CVE，匹配本机软件版本，发现影响你的漏洞立即告警 |
| 系统有安全补丁该装了但没人提醒 | 自动检查yum/apt待安装的安全更新，面板直观展示补丁列表 |
| 告警太多，手机被刷屏，最后干脆关掉通知 | 抖动告警自动静默，同源攻击自动合并成一条事件摘要 |

---

## 核心能力

### 🔥 自动自愈：不只是告警，是真的修复

| 场景 | 触发条件 | 自动执行 |
|---|---|---|
| 磁盘快满 | 磁盘 > 95% | 清理30天以上的旧日志/压缩文件（保护数据库、配置、网站源码、会话文件，6层安全检查） |
| 内存泄漏 | 进程内存1h内增长 > 30% | 快照 → 重启进程（白名单进程不杀） |
| CPU超限 | 单进程 CPU > 80% 持续60s | 降优先级 → SIGTERM → SIGKILL（白名单进程不杀） |
| 服务挂了 | 进程不存在 / 端口不通 | 自动重启服务（启动时自动检测Nginx/MySQL/PHP/宝塔等） |
| 日志暴涨 | 单文件 > 500MB | 安全轮转+压缩（排除web服务活跃日志） |
| SSH暴力破解 | 5分钟内30次失败 | 渐进式封禁：限速 → 1小时 → 24小时（永不封私有IP） |
| 进程爆炸 | 同一程序 > 30个实例 | 保留最早3个，终止多余进程（走安全检查链） |
| 挖矿/木马 | 匹配已知恶意进程名 | 自动终止进程 + 告警（30+种恶意进程特征库） |
| 证书到期 | 剩余 < 14天 | 宝塔API / certbot / acme.sh 自动续期 |
| 僵尸进程 | 僵尸 > 10个 | 向父进程发 SIGCHLD 清理 |

### 🧠 智能运维：越用越懂你的服务器

告警更少、更准、更有信息量。全部基于确定性统计算法，零外部依赖，不占资源。

#### 告警收敛 —— 不刷屏

- **抖动抑制**：同一条告警 10 分钟内重复触发 3 次，自动静默 10 分钟，不再重复推送
- **同源关联**：同一个 IP 15 分钟内触发多种攻击告警，合并成一条事件摘要——"IP 45.x.x.x：SSH暴破 + Web扫描，疑似协同攻击"
- **只减打扰，不丢数据**：所有原始告警完整入库，面板随时可查全量

#### 基线异常检测 —— 知道什么算"不正常"

固定阈值分不清"白天 85% 是正常的，凌晨 3 点 85% 是异常"。ServerGuard 按**周几 × 小时**把历史指标分成 168 个时段，分别学习正常范围（均值 ± 3σ），偏离自身常态才告警：

> 基线异常：CPU 偏离历史正常范围
> 当前值 87.2%，该时段（周二 14 时）近 14 天历史均值 42.1%（σ=8.3）

同一套思路也覆盖**网站响应时间**：每个站点学习自己的正常延迟（内存滑动窗口），"没挂但变慢"（超过自身均值 3 倍且 >800ms，连续 3 次）才告警——快速站点 800ms 是异常，慢站点 800ms 是日常，不用固定阈值一刀切。

#### 磁盘写满预测 —— 提前一周知道

对近 14 天的磁盘日均使用率做线性回归，算出每天涨多少、按这个速度哪天到 90%：

- ≤ 7 天写满 → 立即告警："⚠️ /www 当前 78%，增速 2.1%/天，预计 5 天后（08-16）达到 90%"，并自动浅层扫描附上**空间占用热点 TOP3**（哪个目录在涨一眼可见）
- ≤ 30 天 → 写进每日巡检报告提醒
- 使用量稳定或下降 → 不打扰

仪表盘磁盘卡片直接显示"预计 N 天后写满"。

#### 根因分析 —— 告警里带着"为什么"

每次自动修复执行时，同步拍下系统快照（内存/Swap/磁盘/TOP进程），用启发式规则推测最可能的原因，附在告警后面：

```
🧠 根因分析（自动推测，仅供参考）
1. 内存压力极高（97%），MySQL 很可能被系统 OOM Killer 终止
2. Swap 使用率 82%，系统持续换页，建议扩容内存或限制进程内存
📸 事发时快照：内存 97% / CPU 45% / 磁盘 71%
   TOP 内存进程：mysqld(3.2G) php-fpm(1.1G)
```

所有推测都标注"仅供参考"——它给你排查方向，最终判断权永远在你手里。

#### 保护性智能 —— 不把能跑的系统搞崩

自动运维最大的风险不是"不修"，而是"越修越坏"。ServerGuard 在动手前先想清楚后果：

| 机制 | 它避免的翻车现场 |
|---|---|
| **重启前配置预检** | nginx 配置写错了还重启 = 亲手把网站打挂。重启前自动 `nginx -t` / `apachectl configtest` / `sshd -t`，预检不过**拒绝重启**并告警（附配置错误），服务保持原状至少还能跑 |
| **优雅重启 reload 优先** | 重启 nginx/php-fpm 会断开所有现有连接。支持平滑重载的服务优先 reload（零中断），验证存活后才算完成；reload 不行才回退 restart |
| **开机启动保护** | 开机 5 分钟内 MySQL 还在恢复 InnoDB、宝塔还在拉环境，误判"挂了"去重启只会添乱。这段时间内禁止自动重启 |
| **重启风暴→放弃+诊断** | 端口被占用时重启 100 次也没用。60 秒内重启 3 次仍未恢复 → 判定重启无效，放弃 30 分钟，附**自动诊断报告**（systemctl 日志尾部 + 端口被谁占用），人工介入直接定位 |
| **动作冲突智能排序** | 磁盘满导致 MySQL 崩溃：先清磁盘再重启 MySQL。否则重启完还会再挂 |
| **OOM 趋势预测** | 不等内核 OOM Killer 随机杀进程（可能误杀 MySQL）。内存 >80% 且按当前增速 15 分钟内将耗尽 → 提前告警，留出干预窗口 |

#### 威胁情报 + 阈值自调优 + 攻击者长期画像

- **威胁情报落地**：`IntelChecker` 聚合 AbuseIPDB / OTX / NVD / CNVD / ExploitDB 五类情报源，24h 本地缓存恶意 IP，全部外部调用 fail-close（无 Key / 断网静默跳过，不阻塞不 panic）。接入漏洞扫描（补充本地 CVE 库之外的新漏洞）、攻击预警（封禁前用 `CheckIP` 校验，命中恶意【置信度≥50 或举报数>0】升级封禁 24h 并附情报摘要）、安全防护（`banIP` 情报增强封禁时长）——把已同步的情报真正变成检测能力。
- **规则阈值自调优**：`ThresholdTuner` 用滑动窗口（最近 20 次）统计误报率，误报率 ≥50% 时上调阈值降低敏感度、完全无误报时回调阈值，结果夹紧在 `[min,max]` 内；CC 检测（默认 100，`[50,500]`）与 SSH 暴破（默认 10，`[5,50]`）阈值均自动调优。
- **攻击者长期画像**：`UpdateLongTermProfiles` 累计近 7 天攻击，命中"累计攻击≥30 或 攻击跨度≥3 天 或 攻击类型数≥3"标记为持久攻击者并写入 `attack_profiles`；持久攻击者封禁升级为 24h/7d 并标注"⚠️ 持久攻击者：该 IP 长期/多类型攻击，已升级封禁"。

### 🌐 多机集中管控（Hub）

Hub 从单机面板升级为真正的多机集中管控：Agent 经 WebSocket（`/ws/agent`，Bearer 鉴权 + `X-Agent-ID`）注册 / 心跳 / 上报告警，Hub 维护纯内存 Agent 注册中心，并提供聚合 REST 视图（`/api/servers` 列表、`/api/servers/:id` 详情、`/api/servers/:id/restart` 远程下发命令并审计，离线返回 409）。registry 为空时回退原单机逻辑，向后兼容。可跨机聚合服务器列表、查看跨机告警、集中下发命令。

### 🛡️ 五层安全机制：绝不会误操作搞坏服务器

```
第1层: Agent自身资源限制（内存<80MB, CPU<5%）
第2层: 系统状态自适应（CPU>95%进入存活模式，只告警不操作）
第3层: 操作安全阀（Kill预算15次/小时、熔断器、资源底线、白名单、封禁振荡熔断器）
第4层: 级联防护（操作后观察60s，系统变差则停止后续操作；Kill后5min对比系统状态）
第5层: 全局紧急停止（一键暂停所有自动修复；SSH失联自动回滚所有封禁规则）
```

**永远不会被杀的进程（45+）**：
- Linux: systemd, sshd, nginx, httpd, apache2, mysqld, mariadbd, postgres, redis-server, mongod, php-fpm, php-cgi, bt-panel, pure-ftpd, vsftpd, named, postfix, dovecot, dockerd, containerd, cron, rsyslogd，ServerGuard自身
- Windows: System, smss.exe, csrss.exe, services.exe, lsass.exe, svchost.exe, w3svc, sqlservr.exe, mysqld.exe, postgres.exe, redis-server.exe, php-cgi.exe, nginx.exe，ServerGuard自身

**学习模式**：初次部署默认只观察、只告警，不动手。建议先跑 1-2 天，确认告警合理后关闭学习模式，再让它自动修复。

### 📊 实时监控面板

- **健康评分**：0-100 分动态评分（性能 + 可用性 + 安全），趋势追踪，点击看扣分明细
- **系统指标**：CPU、内存、磁盘（多盘）、网络流量、负载、进程数、僵尸数
- **网站监控**：HTTP 探针 + 连续失败2次标记宕机 + 延迟追踪
- **API 监控**：P50/P95/P99 百分位 + 错误率
- **数据库监控**：MySQL/PostgreSQL/Redis/MongoDB 连接状态 + Redis PING 深度检测
- **安全监控**：WebShell检测 + Cron篡改 + 文件完整性 + 恶意进程 + SSH暴力破解
- **日志分析**：自动扫描日志内容中的 panic/segfault/OOM/disk full 等错误模式
- **告警中心**：所有告警持久化到数据库，可确认/解决
- **审计日志**：每次自动修复操作都有完整记录
- **深色模式 + Ctrl+K 快捷命令面板**：17 个页面模糊跳转 + 快捷操作

### 🔒 安全监控（8项检查）

| 检查项 | 说明 | 自动处理 |
|---|---|---|
| SSH暴力破解 | 5min内30次失败登录 | 自动封禁IP（不封私有IP） |
| 挖矿/木马进程 | 30+种已知恶意进程特征库 | 自动终止进程 |
| 可疑目录进程 | 从/tmp、/dev/shm运行可执行文件 | 自动终止进程 |
| WebShell检测 | PHP文件30+特征 + 3000+ YARA规则 | 告警（只读不删） |
| Cron任务篡改 | 反弹shell/挖矿/base64等14种可疑模式 | 告警 |
| 文件完整性 | 14个关键系统文件哈希（/etc/passwd等） | 告警 |
| 文件篡改 | 用户监控的配置文件哈希变化 | 自动备份 + 告警 |
| 异地登录 | 异常地理位置的SSH登录 | 告警 |

### 📱 全渠道告警通知

| 渠道 | 说明 |
|---|---|
| **Server酱（微信）** | 免费，填一个Key就能推送到微信 |
| **钉钉机器人** | 支持 HMAC 签名验证 |
| **企业微信** | 群机器人 Webhook |
| **飞书** | 群机器人 Webhook |
| **邮件** | SMTP，支持 Gmail / QQ / 163 |
| **Slack** | Incoming Webhook |
| **Telegram** | Bot Token + Chat ID |
| **自定义 Webhook** | POST JSON 到你的接口 |

**告警分级路由**（减少噪音，重要的事才打扰你）：

| 级别 | 邮件 | 微信/钉钉/飞书 | 数据库存档 |
|---|---|---|---|
| Critical/Fatal | ✅ 发送 | ✅ 发送 | ✅ |
| Error | ❌ | ✅ 发送 | ✅ |
| Warning | ❌ | ✅ 发送 | ✅ |
| Info | ❌ | ❌ | ✅ |

叠加智能收敛：抖动静默 + 同源合并 + 凌晨 P2/P3 延迟到早 8 点推送。

### 📋 每日巡检报告

每天早上 8 点（可配置），把过去 24 小时的服务器状况推到你手上：健康评分与趋势、资源峰值、网站存活性、证书到期清单、**磁盘容量预测**、未解决告警 Top5、自愈动作汇总（含成功率）、**重复问题根治建议**（同一告警 7 天内出现 3 次以上 → 提醒根因未除，别只救火）。支持面板在线预览、一键立即发送。

### 📈 Prometheus 集成

`GET /metrics` 输出标准 Prometheus 格式：健康评分、CPU/内存/磁盘、网站存活性、证书剩余天数、未解决告警数、维护窗口状态。可设置 token 保护。接入 Grafana 大盘零成本。

### 🛠️ 维护窗口

系统升级/迁移前开一个维护窗口：窗口期内**只监控告警、不执行任何自动修复**，避免"你刚停服务它又拉起来"。面板顶部常驻"维护中"横幅防止遗忘，到期自动恢复。

---

## 🆕 v0.3.0 能力清单（V4.0 — 根因链推理 + DevOps + 数据治理）

<details>
<summary>展开查看：APM-lite / 网络质量 / 故障知识库 / 智能报告 / 变更窗口推荐</summary>

#### Nginx 日志智能分析（APM-lite）
- **实时访问日志分析**：自动发现并解析 Nginx/Apache access.log，统计 PV/UV、错误率（4xx/5xx）、慢请求率（>1s）
- **热门 URI/IP/UA 排行**：快速定位高频请求路径、异常 IP 和爬虫流量
- **爬虫识别**：内置 20+ 爬虫 UA 正则库（Googlebot/Baidu/Bytespider 等），自动统计爬虫流量占比
- **异常告警**：错误率 >10%、慢请求率 >20%、爬虫流量 >50% 时自动告警
- **API**：`GET /api/apm/nginx` 获取最近分析结果，`POST /api/apm/nginx/analyze` 手动触发分析

#### MySQL/PostgreSQL 慢查询自治
- **慢查询日志采集**：自动发现并解析 MySQL slow log / PostgreSQL 日志，提取查询耗时、扫描行数、锁等待
- **查询指纹去重**：将 SQL 参数化后生成指纹，相同模式的查询自动聚合统计出现次数和平均耗时
- **智能优化建议**：检测全表扫描（扫描行数/返回行数 >100）、SELECT *、无 WHERE 条件、LIKE '%xxx' 前缀通配符、ORDER BY 无索引等常见问题，自动生成优化建议
- **严重级别分级**：high（>5s 或全表扫描）/ medium / low，面板直观展示
- **API**：`GET /api/apm/slow-query`、`POST /api/apm/slow-query/analyze`

#### Redis 大 Key / 热 Key 治理
- **自动大 Key 扫描**：定时执行 `redis-cli --bigkeys` 采样，识别 String >1MB、List/Hash/Set/ZSet >10000 元素的大 Key
- **内存占用分析**：对每个大 Key 调用 `MEMORY USAGE` 获取实际内存占用
- **拆分建议**：根据 Key 类型和大小给出针对性建议（Hash 分桶、分页、分片 Set、时间窗口 ZSet 等）
- **API**：`GET /api/apm/redis`、`POST /api/apm/redis/analyze`

#### 端到端网络质量地图
- **多目标探测**：自动 ping 网关/DNS（114/8.8.8.8）/百度/阿里云/GitHub 等目标，记录延迟（min/avg/max）和丢包率
- **路由跳数**：自动 traceroute/mtr 统计到每个目标的网络跳数
- **异常告警**：目标不可达、丢包 >50%、延迟 >500ms 时自动告警
- **API**：`GET /api/netquality`、`POST /api/netquality/probe`、`GET /api/netquality/targets`

#### 私有故障知识库
- **自动记录**：每次自动修复执行时，自动记录"症状 → 根因 → 修复动作 → 效果"到 SQLite 知识库
- **指纹去重**：相同症状的故障自动累加出现次数，避免知识库膨胀
- **相似检索**：新故障出现时，自动搜索历史相似故障的解决方案，提示历史修复经验
- **统计分析**：按来源模块统计故障分布，识别反复出现的根因
- **API**：`GET /api/knowledge`、`GET /api/knowledge/stats`、`GET /api/knowledge/search?symptom=xxx`

#### 运维日报/周报自动生成
- **周报增强**：每周一早 8:00 自动生成 Markdown 周报，包含健康评分趋势、资源峰值、故障统计、网站可用性、证书状态、安全发现、磁盘预测
- **日报增强**：每日巡检报告已包含根因分析、重复问题根治建议、磁盘容量预测
- **全渠道推送**：复用已有的通知渠道（微信/钉钉/飞书/邮件等）
- **API**：`GET /api/report/weekly`、`POST /api/report/weekly/send`、`GET /api/report/daily`、`POST /api/report/daily/send`

#### 智能变更窗口推荐
- **30 天负载分析**：按"周几 × 小时"分桶统计 CPU/内存均值和峰值，找出负载最低的时段
- **推荐理由**："基于近 30 天 N 个采样点分析，负载最低的时段是周四 02:00-03:00（CPU 均值 12%，峰值 18%）"
- **备选时段**：提供 Top 5 最佳窗口，支持夜间优先筛选
- **API**：`GET /api/maintenance-window/recommend`

#### 故障复盘自动纪要生成
- **时间线还原**：自动读取故障期间的告警记录、修复动作、审计日志，按时间排序生成事件时间线
- **根因推测**：从监控数据中推测 CPU 峰值、内存 OOM、磁盘满等可能的根因
- **经验教训**：根据故障类型和修复结果自动生成经验教训和建议
- **一键推送**：面板点击即可生成复盘报告并推送到企业微信群
- **API**：`GET /api/report/postmortem?start=...&end=...`、`POST /api/report/postmortem/generate`

</details>

---

## 🆕 V4.0-V4.1 新增模块

<details>
<summary>展开查看：态势感知 / 数据治理 / DevOps 闭环 / 反弹Shell / 源码审计 / 实时挂马拦截 / 幽灵文件 / 进程爆炸</summary>

#### 全局态势感知引擎
系统级"大脑"——根据资源状态和威胁态势动态调节 Agent 自身行为：
- **5 档态势**：空闲（Idle）→ 常规（Normal）→ 繁忙（Busy）→ 危急（Crisis）→ 战时（Combat）
- **空闲窗口**：CPU/内存宽裕时安全扫描加密跑、预测类任务提前执行
- **战时模式**：检测到持续攻击信号后安全扫描提频 3 倍，非安全任务全部让路；攻击平息后自动退出
- **自动处置偏置**：战时对低风险安全动作自动提级（攻击不等人），危急时只告警不动作

#### 数据治理守护（V4.1）
9 项数据库安全与治理能力：
- **数据库自动备份管家**：定时 mysqldump/pg_dump，备份保留策略，备份文件权限校验
- **敏感数据泄露扫描**：扫描数据库中的明文密码、身份证、手机号等敏感信息
- **大表增长预警**：监控表大小增长趋势，超阈值告警并给归档建议
- **备份完整性校验**：定期验证备份文件可恢复性
- **数据库死锁自动猎杀**：检测长时间死锁并自动终止死锁进程
- **连接池泄漏诊断**：检测 Sleep 连接过多并定位来源进程（MySQL 连接按 Host 分组统计）
- **缓存雪崩预防器**：监控 Redis 大 Key 过期时间分布，防止同时批量过期

#### DevOps 守护（V4.0）
8 项 DevOps 闭环能力：
- **Git Webhook 部署守护**：接收 GitHub/Gitee Webhook，自动拉取部署
- **环境一致性漂移检测**：对比多环境配置差异，发现配置漂移
- **构建产物自动清理**：定时清理 CI/CD 构建目录中的旧产物
- **定时任务死锁检测**：检测 cron 任务冲突和长时间未执行的定时任务
- **批处理作业守护**：监控定时批处理任务执行状态，失败自动告警
- **文件传输守护**：监控重要文件传输任务的完成状态
- **第三方 API 健康度**：定时检测关键第三方 API 可用性

#### 反弹 Shell 检测
检测服务器上运行的可疑反弹 Shell 进程：
- `bash -i >& /dev/tcp/` 类特征匹配
- Python/Perl 一行反弹 Shell 模式
- socat/ncat 反弹连接
- 进程异常外部端口连接（排除内网 IP 后告警）

#### 源码漏洞审计（W12-W18）
静态分析 PHP/JSP/Python/Node 源码中的安全漏洞：
- SQL 注入漏洞（用户输入拼接 SQL）
- XSS 跨站脚本漏洞（未转义输出）
- 文件上传漏洞（未校验文件类型）
- 命令注入漏洞（用户输入拼接系统命令）
- 路径遍历漏洞（用户输入拼接文件路径）
- 不安全的反序列化
- SSRF 服务端请求伪造
- 硬编码凭证检测

#### 实时挂马拦截
定时轮询 Web 目录文件变更，检测到新增可疑文件时自动隔离 + 告警：
- 新增 PHP/JSP/ASP 文件自动扫描恶意特征
- 已知文件的 mtime 变更触发重新扫描
- 可疑文件自动移入隔离目录（可恢复）
- 兼容无 inotify 的环境（轮询模式）

#### 幽灵文件检测
"已删除但句柄未释放"的隐形空间杀手：
- 检测 `/proc/*/fd` 中指向已删除文件的句柄
- 识别 Java/Python 进程持有已删除日志文件句柄的场景
- 计算幽灵文件实际磁盘占用
- 告警并建议重启对应进程释放句柄

#### 进程爆炸检测（A6）
防止程序无限循环启动大量进程实例耗尽系统资源：
- 按进程名 + 命令行分组统计
- 同一程序超过 30 个实例 → 触发进程爆炸告警
- 保留最早启动的 3 个进程，SIGTERM 终止多余实例
- 完整安全检查链（白名单/宝塔保护/Kill 预算/熔断器）

#### MySQL 连接耗尽定位
增强 MySQL 连接数检测，按来源 Host 分组统计：
- 查询 `information_schema.processlist` 按 Host 分组
- 显示 Top 5 来源 IP 和连接数
- 单个来源占用超过 50% 连接时给出强提示
- 与进程爆炸检测联动：定位是哪个程序耗尽了连接池

</details>

---

## 🆕 v0.1.0 能力清单

<details>
<summary>展开查看：证书守护 / 安全防护 / 攻击预警 / 漏洞扫描 / 存储生命周期 / sgctl</summary>

#### 证书守护增强
- **错峰续期**：`staggeredDeadline = notAfter - 14d + rand(0,7d)`，避免集中续期触发 ACME 限流
- **多 CA 降级链**：Let's Encrypt → ZeroSSL → TrustAsia，任一 CA 失败自动切换下一个
- **失败队列重试**：续期失败入队列，指数退避重试（`24h * 2^retryCount`，最多 5 次）
- **续期后验证**：自动 reload Nginx/Apache + HTTPS 探测验证新证书生效，失败自动回滚

#### 安全防护增强
- **渐进式封禁**：首次→限速，5min 内 5 次→短期 1h，封禁期间再攻击→升级 24h
- **SSH 失联紧急回滚**：封禁后 5s 检测 SSH 连接=0 且无法 ping 网关→自动清除所有 iptables 规则
- **封禁振荡熔断器**：10min 内解封 3 次自动暂停封禁 1h，防止反复封禁/解封
- **Kill 后系统评估**：Kill 前记录系统快照，5min 后对比，系统更差则触发紧急停止

#### 攻击预警增强
- **攻击关联引擎**：5min 窗口内同源 IP 跨模块事件聚合打分，生成攻击画像
- **周期性攻击识别**：自相关函数检测周期性攻击模式（periodic/burst/sustained）
- **分级联动响应**：置信度>0.8 联动封禁 1h，>0.5 联动限速，否则仅记录
- **低速慢攻击检测**：per-IP 请求速率滑动窗口，检测"持续低速率但模式异常"

#### 漏洞扫描增强
- **CVE 实时监控**：每 6 小时自动从 NVD（美国国家漏洞数据库）拉取近 7 天的新 CVE，与本机已安装的 Nginx/OpenSSL/OpenSSH/MySQL/Redis 等软件版本交叉匹配，发现真正影响本机的漏洞立即告警（严重漏洞 P0 级告警），不自动升级，生成修复建议
- **安全补丁检测**：自动检查系统待安装的安全补丁（CentOS/RHEL 用 `dnf/yum updateinfo --security`，Debian/Ubuntu 用 `apt list --upgradable` 过滤 security 源），面板直观展示补丁列表和严重级别，支持手动触发检查
- **Dashboard 安全更新卡片**：有漏洞或补丁时自动显示提醒卡片，按严重级别颜色区分（红色=严重/高危，橙色=重要），点击可查看 CVE 详情链接
- **YARA webshell 检测**：加载 3000+ 特征规则集，扫描 PHP/JSP/ASP 文件
- **依赖漏洞扫描**：解析 composer.lock / requirements.txt / package-lock.json / pom.xml / go.mod，匹配 OSV 数据库
- **CIS Benchmark 合规**：检查 SSH 配置、系统用户、文件权限、内核参数，输出合规报告

#### 存储与数据生命周期
- **差异化保留策略**：指标原始 1h / 聚合 90d / 告警 180d / 审计 WORM 365d+ / 攻击事件 90d / 画像 365d
- **磁盘水位联动**：磁盘>80% 加速降采样，>90% 删冷数据只保留 7 天
- **DB 体积硬约束**：超过 200MB 拒绝写入新指标并触发告警

#### 告警推送增强
- **P0 告警升级**：5min 未确认→升级全渠道再推送，30min 未确认→通知第二联系人
- **时区感知延迟**：凌晨 0-6 点 P2/P3 告警入延迟队列，8 点统一推送

#### sgctl 命令
```bash
sgctl import monit|supervisor|systemd|baota|pm2  # 从其他工具配置导入
sgctl db vacuum|cleanup                           # 数据库维护
sgctl export metrics|alerts|audit                 # 数据导出
sgctl security-check                              # 依赖漏洞 + CIS 合规自检
sgctl config-version tag|export|import            # 配置版本管理
```

</details>

---

## 支持的操作系统

| 操作系统 | 架构 | 状态 |
|---|---|---|
| CentOS 7/8 | x86_64 | ✅ 完全支持 |
| Kylin V10 | x86_64 / aarch64 | ✅ 完全支持 |
| Ubuntu 20.04/22.04 | x86_64 / aarch64 | ✅ 完全支持 |
| Debian 10/11/12 | x86_64 | ✅ 完全支持 |
| Windows Server 2012/2016/2019/2022 | x86_64 | ✅ 完全支持 |
| Rocky Linux / AlmaLinux | x86_64 | ✅ 完全支持 |

**资源占用**：
- 内存：~30-50MB（限制上限80MB）
- CPU：< 1%（限制上限5%）
- 磁盘：二进制16MB + 数据库（通常<100MB，超200MB自动拒写并告警）

---

## 首次使用指南

### 1. 修改密码
登录后 → 系统设置 → 面板密码 → 修改默认密码

### 2. 配置告警通知
系统设置 → 通知设置 → 填入推送渠道。

最简单的 **Server酱**（免费推到微信）：访问 https://sct.ftqq.com/ 扫码登录 → 获取 SendKey → 填入设置页 → 保存 → 发送测试通知。

### 3. 添加守护进程
守护管理 → 添加守护 → 选择模板（Nginx/MySQL/Redis/SSH/IIS）→ 添加。挂了自动重启。

### 4. 添加网站监控
网站监控 → 扫描服务器（自动发现 Nginx/Apache/IIS/宝塔站点）→ 一键导入。或手动填 URL，每 30 秒 HTTP 探针检测。

### 5. 查看健康评分
仪表盘 → 健康评分 + 扣分明细。评分规则：

- CPU > 70% 扣5分，> 80% 扣10分，> 90% 扣15分
- 内存 > 70% 扣5分，> 80% 扣10分，> 90% 扣15分
- 磁盘 > 80% 扣5分，> 90% 扣10分，> 95% 扣15分
- 网站宕机 每个扣15分（上限40分）
- 未解决告警 每条扣5分（上限30分）

---

## 自愈规则说明

内置规则开箱即用：

| 规则 | 触发条件 | 执行动作 | 学习模式 |
|---|---|---|---|
| CPU超限保护 | 单进程CPU > 80% 持续60s（连续3次触发） | 降权 → SIGTERM → SIGKILL | ✅ 默认只告警 |
| 内存泄漏拦截 | 进程内存 > 30% | 快照 → 重启 | ✅ 默认只告警 |
| 磁盘空间守护 | 磁盘 > 95% | 清理旧日志压缩文件 | ❌ 直接执行（只清30天+的.gz/.1/.old） |
| 日志暴涨防护 | 单文件 > 500MB | 轮转压缩 | ❌ 直接执行（排除web服务日志） |
| SSH暴力破解 | 5min内30次失败 | 渐进式封禁IP（限速→1h→24h） | ❌ 直接执行（不封私有IP） |
| 进程爆炸拦截 | 同一程序 > 30个实例 | 保留3个，SIGTERM终止多余 | ✅ 默认只告警 |
| SSL证书续期 | 剩余 < 14天（错峰触发） | 多CA降级续期 → reload → 验证 | ❌ 直接执行 |
| 僵尸进程清理 | 僵尸 > 10个 | SIGCHLD清理 | ✅ 默认只告警 |
| 依赖链隔离 | 上游服务宕机 | 标记下游为 isolated，暂停监控 | ❌ 直接执行 |
| 依赖链恢复 | 上游服务恢复 | 按拓扑序逐个拉起下游 | ❌ 直接执行 |

### 🧠 智能自动检测

启动时自动检测并守护正在运行的服务，无需手动配置：

- **自动守护（Linux）**：Nginx、Apache、MySQL、MariaDB、Redis、PostgreSQL、MongoDB、PHP-FPM、SSH、宝塔面板、Pure-FTPd、vsftpd
- **自动守护（Windows）**：IIS、MySQL、Redis、Nginx、PostgreSQL
- **自动检测数据库**：MySQL(3306)、PostgreSQL(5432)、Redis(6379)、MongoDB(27017) — 端口探测 + Redis PING 深度检测
- **自动监控系统文件**：/etc/passwd、/etc/shadow、/etc/sudoers、sshd_config、crontab 等 14 个关键文件
- **自动扫描Web根目录**：/www/wwwroot、/var/www/html、/var/www、/usr/share/nginx/html、/home/wwwroot

### 安全控制

安全控制页面提供：
- **紧急停止**：一键暂停所有自动修复（只监控不操作）
- **Kill预算**：限制每小时/每天最多杀多少进程
- **熔断器**：某类操作连续失败3次自动暂停（防止越修越坏）
- **白名单**：永远不会被杀的系统进程列表
- **操作记录**：最近24小时所有自动修复操作的详细日志

---

## 常用运维命令

```bash
# 查看服务状态
systemctl status serverguard-agent

# 重启服务
systemctl restart serverguard-agent

# 查看实时日志
journalctl -u serverguard-agent -f

# 修改配置
vim /opt/serverguard/config.yaml
systemctl restart serverguard-agent

# 升级版本
sudo cp serverguard-agent /opt/serverguard/serverguard-agent
sudo chmod +x /opt/serverguard/serverguard-agent
sudo systemctl restart serverguard-agent

# 卸载
sudo bash /opt/serverguard/uninstall.sh
```

---

## 架构设计

```
┌─────────────────────────────────────────────────────────┐
│                    Web 面板 (Vue 3 + Element Plus)       │
│  仪表盘 │ 告警中心 │ 守护管理 │ 证书管理 │ 网站监控 │ 设置 │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP API (Gin)
┌──────────────────────┴──────────────────────────────────┐
│                    Agent 核心 (Go)                        │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Collector │  │  Guards  │  │ RuleEng  │  │ Decider  │ │
│  │ 指标采集  │→│ 守护模块  │→│ 规则匹配  │→│ 安全决策 │ │
│  └──────────┘  └──────────┘  └──────────┘  └────┬────┘ │
│                                                 │       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───┴─────┐ │
│  │ Executor │  │  Safety  │  │ EventBus │  │Notifier │ │
│  │ 动作执行  │←│ 安全管理  │  │ 事件总线  │←│ 告警通知 │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │  Probe   │  │ CertGuard│  │Discovery │  │ Storage │ │
│  │ 网站探针  │  │ 证书守护  │  │ 站点发现  │  │ SQLite  │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Database │  │ Security │  │   Log    │  │ Anomaly │ │
│  │ 数据库监控│  │ 安全检测  │  │ 日志分析  │  │ 基线检测│ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │Correlate │  │ Forecast │  │RootCause │  │ VulnScan│ │
│  │ 告警收敛  │  │ 容量预测  │  │ 根因分析  │  │ 漏洞/CIS│ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  ┌──────────┐                                            │
│  │FeedMon  │  每6h拉取NVD最新CVE+检查安全补丁            │
│  │ 漏洞监控  │  匹配本机软件→告警+修复建议               │
│  └──────────┘                                            │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ NginxApm │  │ SlowQuery│  │ RedisApm │  │NetQualit│ │
│  │日志分析  │  │ 慢查询   │  │ 大Key    │  │网络质量 │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │Knowledge │  │ WindowRec│  │PostMortem│  V3.9新增    │
│  │故障知识库│  │变更窗口  │  │复盘报告  │  APM+知识    │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Posture  │  │DataGovern│ │ DevOps   │  │RevShell │ │
│  │态势感知  │  │数据治理  │  │DevOps   │  │反弹Shell│ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │CodeAudit │  │RealtimeG │  │GhostFile │  │ProcExplod│ │
│  │源码审计  │  │实时挂马  │  │幽灵文件  │  │进程爆炸 │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────┘
```

**数据流**：
```
Collector采集指标 → Guards检测异常 → RuleEngine匹配规则
→ Decider执行11点安全检查 → Executor执行修复动作（同步根因快照）
→ ObservePostAction观察60秒 → EventBus分发事件
→ Notifier收敛降噪后发送微信/钉钉通知 → Storage持久化到SQLite
→ Web面板实时展示
```

---

## 技术栈

| 组件 | 技术 |
|---|---|
| Agent | Go 1.25+，gopsutil v3，Gin，SQLite，YARA（纯 Go） |
| 前端 | Vue 3 + TypeScript + Element Plus + Vite |
| 嵌入 | 前端编译后通过 Go embed 嵌入二进制，单文件部署 |
| 依赖 | 零运行时依赖，单二进制文件，不需要安装任何东西 |

> 📋 **变更日志**：v0.3.0 新增根因链推理引擎 + DevOps 闭环 + 数据治理 + 幽灵文件检测 + 反弹Shell检测 + 源码漏洞审计 + 实时挂马拦截 + 进程爆炸检测 + MySQL连接耗尽定位 + 全局态势感知引擎（V4.0-V4.1），详见上方能力清单。v0.1.0 功能变更记录见 [docs/CHANGELOG_v3.8.md](docs/CHANGELOG_v3.8.md)

---

## 🗺️ Roadmap

- [ ] Helm Chart / K8s DaemonSet 部署
- [ ] 插件体系（自定义检测与自愈规则）
- [ ] Hub 多租户 / RBAC 完善
- [ ] 英文文档

---

## 🤝 参与贡献

欢迎任何形式的贡献！

1. Fork 本仓库，创建你的分支：`git checkout -b feature/your-feature`
2. 提交变更：`git commit -m "feat: add your feature"`
3. 推送分支：`git push origin feature/your-feature`
4. 提交 [Pull Request](https://github.com/suoten/ServerGuard/compare)

提交 Issue 前请先搜索是否已有重复；报告 Bug 请附上操作系统版本、Agent 版本和相关日志。安全漏洞请勿公开 Issue，请联系 maintainer（见下方社区）。

## 💬 社区与交流

- 🐛 问题反馈：[GitHub Issues](https://github.com/suoten/ServerGuard/issues) / [Gitee Issues](https://gitee.com/suoten/serverguard/issues)
- 💡 功能建议与讨论：[GitHub Discussions](https://github.com/suoten/ServerGuard/discussions)
- ⭐ 觉得有用的话，点个 Star 就是最大的支持——更新第一时间收到通知！

## ❤️ 赞助支持

如果 ServerGuard 帮你省下了凌晨爬起来救服务器的次数，欢迎请作者喝杯咖啡 ☕

<!-- 在此放置 GitHub Sponsors / 爱发电 / 微信收款码链接 -->

---

## FAQ

**Q: ServerGuard 会影响服务器性能吗？**
A: 不会。Agent 内存限制80MB，CPU限制5%，采集间隔5秒。实测内存占用30-50MB，CPU < 1%。基线统计和磁盘预测都是一条 SQL 聚合完成，不加载全量时序到内存。

**Q: ServerGuard 会误杀进程吗？**
A: 不会。五层安全机制 + 三级安全策略：
1. 系统进程白名单（45+个进程永不杀：nginx/mysql/bt-panel/php-fpm/sshd等）
2. Kill预算限制（每小时最多15次）
3. 熔断器（连续失败3次暂停）
4. 级联防护（操作后系统变差则停止）
5. 学习模式（可先只观察不操作）

**三级安全策略**：
- ✅ 自动执行：OOM杀非白名单进程、磁盘清理旧日志、封IP(不封私有IP)、杀木马/挖矿进程、证书续期、服务重启
- ⚠️ 只告警：网络异常、Swap过高、WebShell检测、Cron篡改、文件完整性变化
- 🚫 永不触碰：杀nginx/IIS/MySQL/宝塔、删/tmp、删/www、yum/apt clean、重启NetworkManager

**Q: 自动重启会不会把能跑的服务搞挂？**
A: 有三道闸：① 重启前自动配置预检（`nginx -t`/`apachectl configtest`/`sshd -t`），配置有错拒绝重启——能跑就不动；② 支持平滑重载的服务优先 reload，不断开现有连接；③ 反复重启不恢复会自动放弃并附诊断报告（端口占用者、服务日志尾部），不会机械重试把系统拖垮。

**Q: "智能"是真 AI 吗？**
A: 不是大模型，是确定性统计算法：基线检测用"周几×小时"分桶的均值/标准差（3σ 偏离），磁盘预测用 14 天日均值的最小二乘线性回归，告警收敛用滑动窗口计数，根因分析用启发式规则。优点是可解释、零依赖、不占资源、不会幻觉——每个告警都能说清"为什么触发"。

**Q: 数据存在哪里？重启会丢失吗？**
A: SQLite 数据库（/var/lib/serverguard/serverguard.db），重启不丢失。网站监控配置也持久化，重启自动恢复。

**Q: Windows Server 支持哪些功能？**
A: 全部支持。Windows上用 `sc query` 检测服务、`net start` 重启服务、`netsh` 封禁IP、清理Temp目录，功能与Linux完全对等。

**Q: 可以监控多台服务器吗？**
A: 支持多机集中管控（Hub）。每台服务器装一个 Agent，通过 Hub 统一纳管：聚合服务器列表、查看跨机告警、集中下发命令（见"多机集中管控"章节）。单机部署模式完全兼容。

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=suoten/ServerGuard&type=Date)](https://star-history.com/#suoten/ServerGuard&Date)

---

## License

本项目基于 [Apache License 2.0](LICENSE) 开源。

Copyright © 2026 硕腾网络 (Suoten Network)
