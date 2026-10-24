#!/bin/bash
# ServerGuard 一键安装脚本
# 用法: curl -fsSL https://your-server/install.sh | bash
# 或: bash install.sh
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║        ServerGuard 一键安装脚本                  ║"
echo "║        服务器监控 · 自动运维 · 自愈防护           ║"
echo "║        Install & Forget. Guard & Heal.           ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 root 用户运行此脚本${NC}"
  echo -e "  sudo bash install.sh"
  exit 1
fi

# ── 宝塔面板环境检测 ──────────────────────────────────
BAOTA_PANEL_PATH="/www/server/panel"
IS_BAOTA=false
if [ -d "$BAOTA_PANEL_PATH" ] && [ -f "/etc/init.d/bt" ]; then
  IS_BAOTA=true
  echo -e "${YELLOW}[INFO]${NC} 检测到宝塔面板环境，将启用安全保护模式部署"
fi

# ── 检测架构 ──────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  BINARY="serverguard-agent-linux-amd64" ;;
  aarch64) BINARY="serverguard-agent-linux-arm64" ;;
  *)
    echo -e "${RED}不支持的架构: $ARCH${NC}"
    exit 1
    ;;
esac

# ── 端口冲突检测 ──────────────────────────────────────
LISTEN_PORT="18090"
if command -v ss &> /dev/null; then
  if ss -tlnp | grep -q ":${LISTEN_PORT} "; then
    echo -e "${YELLOW}[WARN]${NC} 端口 ${LISTEN_PORT} 已被占用"
    # 如果占用者是宝塔插件（python 进程），提示更换端口
    if ss -tlnp | grep ":${LISTEN_PORT} " | grep -q "python"; then
      echo -e "${RED}[ERROR]${NC} 端口 ${LISTEN_PORT} 可能被宝塔插件占用"
      echo -e "  请修改 config.yaml 中的 web.listen 端口后重试"
      exit 1
    fi
    # 非宝塔占用者也需提示，但不强制退出
    echo -e "  ${YELLOW}请确认该端口可用，或在安装后修改 /opt/serverguard/config.yaml${NC}"
  fi
elif command -v netstat &> /dev/null; then
  if netstat -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT} "; then
    echo -e "${YELLOW}[WARN]${NC} 端口 ${LISTEN_PORT} 已被占用，请确认该端口可用${NC}"
  fi
fi

INSTALL_DIR="/opt/serverguard"
echo -e "${GREEN}[1/8]${NC} 安装目录: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

# 配置保护：升级时绝不覆盖已有 config.yaml（历史事故：覆盖导致面板密码/JWT/存储路径被重置）。
# 仅首次安装生成模板；已存在则自动备份并保留原配置。
write_config_protected() {
  if [ -f "${INSTALL_DIR}/config.yaml" ]; then
    cp "${INSTALL_DIR}/config.yaml" "${INSTALL_DIR}/config.yaml.bak.$(date +%Y%m%d%H%M%S)"
    echo -e "  ${YELLOW}[升级]${NC} 检测到现有配置，已保留原 config.yaml 并备份，未做任何修改"
    return 0
  fi
  cat > "${INSTALL_DIR}/config.yaml"
}

# ── 复制二进制文件 ────────────────────────────────────
# 发布包里二进制统一叫 serverguard-agent，dist 目录下叫带架构后缀的名字
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/serverguard-agent" ]; then
  echo -e "${GREEN}[2/8]${NC} 从本地复制二进制文件"
  cp "${SCRIPT_DIR}/serverguard-agent" "${INSTALL_DIR}/serverguard-agent"
elif [ -f "serverguard-agent" ]; then
  echo -e "${GREEN}[2/8]${NC} 从当前目录复制二进制文件"
  cp "serverguard-agent" "${INSTALL_DIR}/serverguard-agent"
elif [ -f "${SCRIPT_DIR}/${BINARY}" ]; then
  echo -e "${GREEN}[2/8]${NC} 从本地复制二进制文件"
  cp "${SCRIPT_DIR}/${BINARY}" "${INSTALL_DIR}/serverguard-agent"
elif [ -f "${BINARY}" ]; then
  echo -e "${GREEN}[2/8]${NC} 从当前目录复制二进制文件"
  cp "${BINARY}" "${INSTALL_DIR}/serverguard-agent"
else
  echo -e "${RED}[错误]${NC} 未找到二进制文件: serverguard-agent"
  echo -e "请确保安装脚本和二进制文件在同一目录"
  echo -e "当前目录: ${SCRIPT_DIR}"
  echo -e "目录下文件:"
  ls -la "${SCRIPT_DIR}"
  exit 1
fi

chmod +x "${INSTALL_DIR}/serverguard-agent"

# ── 复制 hub 和 sgctl 二进制（如果发布包中包含） ──────
# hub: 多服务器管理中枢（含独立面板），sgctl: 命令行运维工具
# 这两个组件是可选的——agent 自身已内嵌完整扫描+面板能力，
# 但如果用户需要多服务器集中管理或 CLI 工具，也会一并安装。
for comp in serverguard-hub sgctl; do
  if [ -f "${SCRIPT_DIR}/${comp}" ]; then
    cp "${SCRIPT_DIR}/${comp}" "${INSTALL_DIR}/${comp}"
    chmod +x "${INSTALL_DIR}/${comp}"
    echo -e "  ${GREEN}✓${NC} 已安装 ${comp}"
  elif [ -f "${comp}" ]; then
    cp "${comp}" "${INSTALL_DIR}/${comp}"
    chmod +x "${INSTALL_DIR}/${comp}"
    echo -e "  ${GREEN}✓${NC} 已安装 ${comp}"
  fi
done

# ── 生成配置文件 ──────────────────────────────────────
echo -e "${GREEN}[3/8]${NC} 生成配置文件"

# 检测旧数据库：如果过大（>100MB），提示清理以避免启动时 VACUUM 导致 OOM
OLD_DB="/var/lib/serverguard/serverguard.db"
if [ -f "$OLD_DB" ]; then
  OLD_DB_MB=$(du -m "$OLD_DB" 2>/dev/null | cut -f1)
  if [ -n "$OLD_DB_MB" ] && [ "$OLD_DB_MB" -gt 100 ]; then
    echo -e "${YELLOW}⚠ 检测到旧数据库（${OLD_DB_MB}MB），可能导致启动时 OOM 崩溃${NC}"
    echo -e "  ${CYAN}建议：备份后清理旧数据库，重新开始（历史数据会丢失）${NC}"
    echo -e "  ${CYAN}命令: mv ${OLD_DB} ${OLD_DB}.bak && rm -f ${OLD_DB}-wal ${OLD_DB}-shm${NC}"
    echo -n -e "  ${YELLOW}是否现在清理旧数据库？(y/N) ${NC}"
    read -r CLEAN_DB < /dev/tty
    if [ "$CLEAN_DB" = "y" ] || [ "$CLEAN_DB" = "Y" ]; then
      mv "$OLD_DB" "${OLD_DB}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
      rm -f "${OLD_DB}-wal" "${OLD_DB}-shm" 2>/dev/null || true
      echo -e "  ${GREEN}✓ 旧数据库已备份并清理${NC}"
    else
      echo -e "  ${YELLOW}跳过。如果 Agent 启动崩溃，请手动清理: mv ${OLD_DB} ${OLD_DB}.bak${NC}"
    fi
  fi
fi
JWT_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
# 随机面板密码：安全产品不应有固定默认口令，安装时生成并只显示一次
ADMIN_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 16)

# ============================================================
# 核心设计理念：安装即生效 — 零配置自愈
# 用户安装后不需要打开面板，以下能力自动运行：
#   1. 磁盘 > 90% → 自动清理日志/缓存/临时文件（保留近7天）
#   2. 日志 > 500MB → 自动轮转压缩
#   3. SSH 暴力破解 → 自动封禁 IP
#   4. SSL 证书到期 → 自动续期
#   5. 僵尸进程 → 自动清理
#   6. 宝塔面板挂了 → 自动重启
# ============================================================

if [ "$IS_BAOTA" = true ]; then
# ── 宝塔环境：安全保护模式，但日志/磁盘自愈仍然启用 ──
# 宝塔环境下只清理 /var/log、/tmp 等系统目录，不触碰宝塔目录
write_config_protected << EOF
agent:
  collect_interval: 15s
  max_memory_mb: 120
  max_cpu_percent: 10
  learn_mode: true
  learn_mode_days: 1
web:
  enabled: true
  listen: "0.0.0.0:18090"
  auth_enabled: true
  username: "admin"
  password: "${ADMIN_PASSWORD}"
  jwt_secret: "${JWT_SECRET}"
safety:
  kill_budget_hourly: 15
  kill_budget_daily: 50
  kill_min_interval: 30s
  circuit_breaker_threshold: 3
  circuit_breaker_reset_duration: 30m
  observation_window: 60s
  min_available_memory_mb: 50
  max_load_factor: 3.0
  min_disk_free_mb: 500
  max_disk_io_wait_percent: 80
  trash_dir: "/var/lib/serverguard/.trash"
storage:
  path: "/var/lib/serverguard/serverguard.db"
baota:
  safe_mode: "true"
  panel_path: "${BAOTA_PANEL_PATH}"
  use_baota_service_manager: true
  cleanup_scope: "system_only"
  log_rotation_scope: "system_only"
  confirm_timeout_minutes: 5
  webshell_exclusions:
    - "/www/server/panel"
    - "/www/server/panel/plugin"
  auto_actions:
    ssh_bruteforce_ban: true
    cert_renewal: true
    malware_kill: true
    zombie_cleanup: true
    custom_service_restart: true
    disk_cleanup: true
    log_rotation: true
  confirm_actions:
    whitelist_cpu_throttle: "confirm"
    whitelist_mem_restart: "confirm"
    disk_cleanup: "auto"
    log_rotation: "auto"
    baota_service_restart: "confirm"
EOF
else
# ── 非宝塔环境：全自愈模式，安装即生效 ──
write_config_protected << EOF
agent:
  collect_interval: 15s
  max_memory_mb: 120
  max_cpu_percent: 10
  learn_mode: true
  learn_mode_days: 1
web:
  enabled: true
  listen: "0.0.0.0:18090"
  auth_enabled: true
  username: "admin"
  password: "${ADMIN_PASSWORD}"
  jwt_secret: "${JWT_SECRET}"
safety:
  kill_budget_hourly: 15
  kill_budget_daily: 50
  kill_min_interval: 30s
  circuit_breaker_threshold: 3
  circuit_breaker_reset_duration: 30m
  observation_window: 60s
  min_available_memory_mb: 50
  max_load_factor: 3.0
  min_disk_free_mb: 500
  max_disk_io_wait_percent: 80
  trash_dir: "/var/lib/serverguard/.trash"
storage:
  path: "/var/lib/serverguard/serverguard.db"
baota:
  safe_mode: "false"
  auto_actions:
    ssh_bruteforce_ban: true
    cert_renewal: true
    malware_kill: true
    zombie_cleanup: true
    custom_service_restart: true
    disk_cleanup: true
    log_rotation: true
  confirm_actions:
    disk_cleanup: "auto"
    log_rotation: "auto"
EOF
fi

# 创建数据目录
mkdir -p /var/lib/serverguard/.trash
mkdir -p /var/lib/serverguard/config-backups
mkdir -p /var/lib/serverguard/db-backups
chmod 755 /var/lib/serverguard
chmod 755 /var/lib/serverguard/.trash

# ── 复制规则文件 ────────────────────────────────────────
echo -e "${GREEN}[3.5/8]${NC} 部署安全规则文件"
mkdir -p "${INSTALL_DIR}/configs/yara_rules" "${INSTALL_DIR}/configs/cis_benchmark"
if [ -d "${SCRIPT_DIR}/configs/yara_rules" ]; then
  cp -r "${SCRIPT_DIR}/configs/yara_rules/"* "${INSTALL_DIR}/configs/yara_rules/" 2>/dev/null || true
fi
if [ -d "${SCRIPT_DIR}/configs/cis_benchmark" ]; then
  cp -r "${SCRIPT_DIR}/configs/cis_benchmark/"* "${INSTALL_DIR}/configs/cis_benchmark/" 2>/dev/null || true
fi
echo -e "  ${YELLOW}YARA webshell 检测规则和 CIS Benchmark 合规规则已部署到 ${INSTALL_DIR}/configs/${NC}"

# ── 安装 systemd 服务 ─────────────────────────────────
echo -e "${GREEN}[4/8]${NC} 安装 systemd 服务"

# ── 自适应内存策略（向宝塔学习：按服务器实际配置设定资源上限）──
# 不再使用固定 768M 一刀切，而是根据总内存自适应：
#   ≤ 512MB  → MemoryMax=128M  （极低配 VPS，只跑核心监控）
#   ≤ 1024MB → MemoryMax=192M  （1C1G 常见配置）
#   ≤ 2048MB → MemoryMax=256M  （2C2G）
#   > 2048MB → MemoryMax=384M  （4G+ 服务器）
TOTAL_MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))

if [ "$TOTAL_MEM_MB" -le 0 ]; then
  # 检测失败，用安全默认值（192M，适合 1G 服务器）
  MEM_MAX="192M"
  MEM_HIGH="128M"
  GO_MEM_LIMIT="128MiB"
elif [ "$TOTAL_MEM_MB" -le 512 ]; then
  MEM_MAX="128M"
  MEM_HIGH="96M"
  GO_MEM_LIMIT="96MiB"
elif [ "$TOTAL_MEM_MB" -le 1024 ]; then
  MEM_MAX="192M"
  MEM_HIGH="128M"
  GO_MEM_LIMIT="128MiB"
elif [ "$TOTAL_MEM_MB" -le 2048 ]; then
  MEM_MAX="256M"
  MEM_HIGH="192M"
  GO_MEM_LIMIT="192MiB"
else
  MEM_MAX="384M"
  MEM_HIGH="256M"
  GO_MEM_LIMIT="256MiB"
fi

echo -e "  ${CYAN}系统总内存: ${TOTAL_MEM_MB}MB → 资源上限: MemoryMax=${MEM_MAX}, GOMEMLIMIT=${GO_MEM_LIMIT}${NC}"

cat > /etc/systemd/system/serverguard-agent.service << EOF
[Unit]
Description=ServerGuard Agent - Server Monitoring & Auto-Healing
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/serverguard/serverguard-agent -config /opt/serverguard/config.yaml
WorkingDirectory=/opt/serverguard
Restart=always
RestartSec=3

# ====== 资源约束策略（自适应：按服务器总内存设定）======
# 检测到总内存 ${TOTAL_MEM_MB}MB → MemoryMax=${MEM_MAX}, MemoryHigh=${MEM_HIGH}, GOMEMLIMIT=${GO_MEM_LIMIT}
# 设计原则（向宝塔学习）：
#   1. MemoryMax 占总内存 8-15%，不设固定值
#   2. GOMEMLIMIT 设为 MemoryMax 的 ~75%，Go GC 在硬限制前积极回收
#   3. GOGC=50 — 比默认 100% 更频繁 GC，用 CPU 换内存
MemoryMax=${MEM_MAX}
MemoryHigh=${MEM_HIGH}
MemoryHighTime=30s
Environment=GOMEMLIMIT=${GO_MEM_LIMIT}
Environment=GOGC=50

# CPU：CPUWeight=20 低优先级（空闲时可用满，繁忙时自动让路）
# 不使用 CPUQuota 硬限制 — 会导致启动极慢、面板无响应
CPUWeight=20
Environment=GOMAXPROCS=2

# I/O：低优先级
IOWeight=10
LimitNOFILE=4096

# OOM：内存不足时 OOM Killer 可杀 Agent（会自动重启），
# 但不设太高优先级（100 而非 500），避免扫描峰值时被过早杀掉
OOMScoreAdjust=100

# 安全加固
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/serverguard /opt/serverguard

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=serverguard-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# ── 防火墙放行 ────────────────────────────────────────
echo -e "${GREEN}[5/8]${NC} 配置防火墙"
if [ "$IS_BAOTA" = true ]; then
  # 宝塔环境下不直接修改系统防火墙，提示用户在宝塔面板中放行
  echo -e "  ${YELLOW}检测到宝塔面板，请在宝塔面板 → 安全 → 放行端口 ${LISTEN_PORT}${NC}"
  echo -e "  ${YELLOW}如已安装宝塔防火墙插件，也可通过插件添加规则${NC}"
else
  # 非 宝塔 环境：使用 firewalld / ufw / iptables
  if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${LISTEN_PORT}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null
    echo -e "  ${YELLOW}已放行 ${LISTEN_PORT} 端口 (firewalld)${NC}"
  elif command -v ufw &> /dev/null; then
    ufw allow ${LISTEN_PORT}/tcp 2>/dev/null
    echo -e "  ${YELLOW}已放行 ${LISTEN_PORT} 端口 (ufw)${NC}"
  elif command -v iptables &> /dev/null; then
    iptables -I INPUT -p tcp --dport ${LISTEN_PORT} -j ACCEPT 2>/dev/null
    echo -e "  ${YELLOW}已放行 ${LISTEN_PORT} 端口 (iptables)${NC}"
  else
    echo -e "  ${YELLOW}未检测到防火墙，请手动放行 ${LISTEN_PORT} 端口${NC}"
  fi
fi

# ── 启动服务 ──────────────────────────────────────────
echo -e "${GREEN}[6/8]${NC} 启动服务"

# 先停止旧服务（如果正在运行），避免端口冲突
if systemctl is-active --quiet serverguard-agent 2>/dev/null; then
  echo -e "  ${YELLOW}停止旧服务...${NC}"
  systemctl stop serverguard-agent 2>/dev/null || true
  sleep 1
fi
# 确保端口释放
if ss -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT} "; then
  OLD_PID=$(ss -tlnp 2>/dev/null | grep ":${LISTEN_PORT} " | grep -oP 'pid=\K[0-9]+' | head -1)
  if [ -n "$OLD_PID" ]; then
    echo -e "  ${YELLOW}端口 ${LISTEN_PORT} 仍被 PID ${OLD_PID} 占用，正在清理...${NC}"
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
fi

systemctl enable serverguard-agent
systemctl restart serverguard-agent

# 等待启动（10 秒，让进程度过初始化阶段）
sleep 10
echo -e "${GREEN}[7/8]${NC} 验证安装"

# 二次检查：如果第一次失败，等待重启后再检查
if ! systemctl is-active --quiet serverguard-agent; then
  echo -e "  ${YELLOW}服务未就绪，等待自动重启...${NC}"
  sleep 10
fi

# 检查是否在崩溃-重启循环中（systemd NRestarts > 3 说明不稳定）
RESTART_COUNT=$(systemctl show serverguard-agent -p NRestarts 2>/dev/null | cut -d= -f2)
if [ -n "$RESTART_COUNT" ] && [ "$RESTART_COUNT" -gt 3 ]; then
  echo -e "${RED}⚠ Agent 在崩溃-重启循环中（已重启 ${RESTART_COUNT} 次）${NC}"
  echo -e "${YELLOW}─── 崩溃诊断 ───${NC}"
  echo -e "  ${CYAN}最近日志:${NC}"
  journalctl -u serverguard-agent -n 20 --no-pager 2>/dev/null || true
  echo ""
  # 检查旧数据库是否过大导致 OOM
  DB_PATH="/var/lib/serverguard/serverguard.db"
  if [ -f "$DB_PATH" ]; then
    DB_SIZE_MB=$(du -m "$DB_PATH" 2>/dev/null | cut -f1)
    if [ -n "$DB_SIZE_MB" ] && [ "$DB_SIZE_MB" -gt 100 ]; then
      echo -e "${RED}⚠ 数据库过大（${DB_SIZE_MB}MB），启动时 VACUUM 导致 OOM 崩溃${NC}"
      echo -e "${YELLOW}  正在清理旧数据库并重启...${NC}"
      systemctl stop serverguard-agent 2>/dev/null || true
      mv "$DB_PATH" "${DB_PATH}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
      # 同时清理 WAL 和 SHM 文件
      rm -f "${DB_PATH}-wal" "${DB_PATH}-shm" 2>/dev/null || true
      systemctl start serverguard-agent
      sleep 10
    fi
  fi
  # 检查 OOM
  if dmesg -T 2>/dev/null | grep -qiE "out of memory|oom.?kill.*serverguard"; then
    echo -e "${RED}⚠ 检测到 OOM Kill！${NC}"
    echo -e "${YELLOW}  正在增大内存限制并重启...${NC}"
    # 将 MemoryMax 翻倍
    CURRENT_MAX=$(grep "^MemoryMax=" /etc/systemd/system/serverguard-agent.service | cut -d= -f2)
    if [ -n "$CURRENT_MAX" ]; then
      CURRENT_NUM=$(echo "$CURRENT_MAX" | grep -oP '[0-9]+')
      NEW_NUM=$((CURRENT_NUM * 2))
      NEW_MAX="${NEW_NUM}M"
      sed -i "s/^MemoryMax=.*/MemoryMax=${NEW_MAX}/" /etc/systemd/system/serverguard-agent.service
      sed -i "s/^MemoryHigh=.*/MemoryHigh=$((NEW_NUM * 2 / 3))M/" /etc/systemd/system/serverguard-agent.service
      echo -e "${YELLOW}  MemoryMax 已从 ${CURRENT_MAX} 调整为 ${NEW_MAX}${NC}"
      systemctl daemon-reload
      systemctl restart serverguard-agent
      sleep 10
    fi
  fi
fi

if systemctl is-active --quiet serverguard-agent; then
  # 等待 HTTP server 完全就绪（额外等 3 秒让 gin 初始化完成）
  sleep 3
  # 用 curl 本机测试 API 是否真正响应（不只是进程存活）
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:${LISTEN_PORT}/api/status 2>/dev/null)
  if [ "$HTTP_CODE" = "000" ] || [ -z "$HTTP_CODE" ]; then
    echo -e "${YELLOW}⚠ 进程存活但 HTTP 不响应（HTTP ${HTTP_CODE}），可能在初始化中或崩溃${NC}"
    echo -e "  等待 10 秒后重试..."
    sleep 10
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:${LISTEN_PORT}/api/status 2>/dev/null)
  fi
  if [ "$HTTP_CODE" = "000" ] || [ -z "$HTTP_CODE" ]; then
    echo -e "${RED}✗ Agent HTTP server 不响应（进程存活但连接被拒绝）${NC}"
    echo -e "${YELLOW}  这通常是崩溃-重启循环的表现。正在诊断...${NC}"
    echo -e "  ${CYAN}最近日志:${NC}"
    journalctl -u serverguard-agent -n 30 --no-pager 2>/dev/null || true
    echo ""
    # 检查 OOM
    if dmesg -T 2>/dev/null | grep -qiE "out of memory|oom.?kill.*serverguard"; then
      echo -e "${RED}⚠ 检测到 OOM Kill！Agent 因内存不足被反复杀掉${NC}"
      DB_PATH="/var/lib/serverguard/serverguard.db"
      if [ -f "$DB_PATH" ]; then
        DB_SIZE_MB=$(du -m "$DB_PATH" 2>/dev/null | cut -f1)
        if [ -n "$DB_SIZE_MB" ] && [ "$DB_SIZE_MB" -gt 50 ]; then
          echo -e "${YELLOW}  数据库 ${DB_SIZE_MB}MB 过大，正在清理...${NC}"
          systemctl stop serverguard-agent 2>/dev/null || true
          mv "$DB_PATH" "${DB_PATH}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
          rm -f "${DB_PATH}-wal" "${DB_PATH}-shm" 2>/dev/null || true
          systemctl start serverguard-agent
          sleep 10
        fi
      fi
      # 同时增大内存限制
      CURRENT_MAX=$(grep "^MemoryMax=" /etc/systemd/system/serverguard-agent.service 2>/dev/null | cut -d= -f2)
      if [ -n "$CURRENT_MAX" ]; then
        CURRENT_NUM=$(echo "$CURRENT_MAX" | grep -oP '[0-9]+')
        NEW_NUM=$((CURRENT_NUM * 2))
        if [ "$NEW_NUM" -gt 1024 ]; then NEW_NUM=1024; fi
        sed -i "s/^MemoryMax=.*/MemoryMax=${NEW_NUM}M/" /etc/systemd/system/serverguard-agent.service
        sed -i "s/^MemoryHigh=.*/MemoryHigh=$((NEW_NUM * 2 / 3))M/" /etc/systemd/system/serverguard-agent.service
        echo -e "${YELLOW}  MemoryMax 已从 ${CURRENT_MAX} 调整为 ${NEW_NUM}M${NC}"
        systemctl daemon-reload
        systemctl restart serverguard-agent
        sleep 10
      fi
    fi
    # 重新检查
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:${LISTEN_PORT}/api/status 2>/dev/null)
  fi
fi

if systemctl is-active --quiet serverguard-agent; then
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP="服务器IP"
  fi

  echo ""
  echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
  echo -e "║                    ✅ 安装成功！                            ║"
  echo -e "╠════════════════════════════════════════════════════════════╣"
  echo -e "║                                                            ║"
  echo -e "║  面板地址: http://${SERVER_IP}:${LISTEN_PORT}                        "
  echo -e "║  用户名:   admin                                           ║"
  echo -e "║  密码:     ${ADMIN_PASSWORD}                              "
  echo -e "║                                                            ║"
  echo -e "╚════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # ── 自愈能力说明 ──
  echo -e "${CYAN}${BOLD}─── 安装即生效：ServerGuard 已在后台为你守护 ───${NC}"
  echo ""
  echo -e "  ${GREEN}✓${NC} 磁盘 > 90% → 自动清理日志/缓存（保留近7天）"
  echo -e "  ${GREEN}✓${NC} 日志 > 500MB → 自动轮转压缩"
  echo -e "  ${GREEN}✓${NC} SSH 暴力破解 → 自动封禁 IP"
  echo -e "  ${GREEN}✓${NC} SSL 证书到期 → 自动续期"
  echo -e "  ${GREEN}✓${NC} 僵尸进程 → 自动清理"
  echo -e "  ${GREEN}✓${NC} 服务崩溃 → 自动重启"
  if [ "$IS_BAOTA" = true ]; then
    echo -e "  ${GREEN}✓${NC} 宝塔面板挂了 → 自动重启"
  fi
  echo ""
  echo -e "  ${YELLOW}首次安装有 1 天学习期（只观察不操作），之后自动开启自愈${NC}"
  echo ""

  # ── 通知渠道引导 ──
  echo -e "${CYAN}${BOLD}─── 通知配置（重要！）───${NC}"
  echo -e "  ${YELLOW}⚠️  你还没配通知渠道！没配通知 = 告警只能看面板 = 白装${NC}"
  echo ""
  echo -e "  打开面板 → 设置 → 通知配置，3 分钟完成："
  echo -e "    1. ${CYAN}微信通知${NC}（推荐）：扫码关注 WxPusher → 输入验证码"
  echo -e "    2. ${CYAN}钉钉/飞书${NC}：复制 Webhook URL → 粘贴"
  echo -e "    3. ${CYAN}邮件${NC}：填写 SMTP 信息"
  echo -e "    4. ${CYAN}Telegram${NC}：@BotFather 创建 Bot → 填入 Token"
  echo ""
  echo -e "  ${GREEN}配好通知后，服务器出问题你第一时间收到消息，不用盯着面板${NC}"
  echo ""

  # ── 常用命令 ──
  echo -e "${CYAN}常用命令:${NC}"
  echo -e "  systemctl status serverguard-agent   # 查看状态"
  echo -e "  systemctl restart serverguard-agent  # 重启"
  echo -e "  journalctl -u serverguard-agent -f   # 查看日志"
  echo -e "  vim /opt/serverguard/config.yaml     # 修改配置"
  echo ""

  # 安全保护模式提示
  if [ "$IS_BAOTA" = true ]; then
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "${YELLOW}宝塔安全保护模式已启用${NC}"
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "  ${CYAN}已自动启用的能力：${NC}"
    echo -e "    - SSH 暴力破解封禁 ✓"
    echo -e "    - SSL 证书自动续期 ✓"
    echo -e "    - 僵尸进程自动清理 ✓"
    echo -e "    - 磁盘自动清理（仅系统目录，不触碰宝塔）✓"
    echo -e "    - 日志自动轮转（仅系统日志，不触碰宝塔）✓"
    echo -e "    - 宝塔面板挂了自动重启 ✓"
    echo ""
    echo -e "  ${YELLOW}需要手动确认的操作：${NC}"
    echo -e "    - CPU 降权（避免误杀业务进程）"
    echo -e "    - 内存重启（避免误杀业务进程）"
    echo -e "    - 宝塔服务重启"
    echo ""
    echo -e "  如需关闭安全保护模式：修改 /opt/serverguard/config.yaml"
    echo -e "    将 baota.safe_mode 改为 \"false\""
    echo -e "${YELLOW}==========================================${NC}"
    echo ""
  fi
else
  echo -e "${RED}安装完成但服务启动失败，请检查:${NC}"
  echo -e "  ${YELLOW}journalctl -u serverguard-agent -n 50${NC}"
  echo ""
  echo -e "${CYAN}─── 自动诊断 ───${NC}"
  # 显示最近的 journal 日志
  journalctl -u serverguard-agent -n 30 --no-pager 2>/dev/null || true
  echo ""
  # 检查是否 OOM
  if dmesg -T 2>/dev/null | grep -qiE "out of memory|oom.?kill.*serverguard"; then
    echo -e "${RED}⚠ 检测到 OOM Kill！Agent 因内存不足被杀。${NC}"
    echo -e "${YELLOW}  当前 MemoryMax=${MEM_MAX}，可能不够。${NC}"
    echo -e "${YELLOW}  解决方法：编辑 /etc/systemd/system/serverguard-agent.service${NC}"
    echo -e "${YELLOW}  将 MemoryMax 改大（如 256M），然后:${NC}"
    echo -e "${YELLOW}  systemctl daemon-reload && systemctl restart serverguard-agent${NC}"
    echo ""
  fi
  # 检查密码/密钥问题
  if grep -qiE "jwt_secret.*change_me|password.*admin123|jwt_secret.*CHANGE_ME|password.*CHANGE" "${INSTALL_DIR}/config.yaml" 2>/dev/null; then
    echo -e "${RED}⚠ 配置文件中的密码或密钥是占位符/弱值，Agent 会拒绝启动！${NC}"
    echo -e "${YELLOW}  解决方法：${NC}"
    echo -e "${YELLOW}  JWT=\$(openssl rand -hex 32)${NC}"
    echo -e "${YELLOW}  PASS=\$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)${NC}"
    echo -e "${YELLOW}  sed -i \"s/password:.*/password: \"\$PASS\"/\" ${INSTALL_DIR}/config.yaml${NC}"
    echo -e "${YELLOW}  sed -i \"s/jwt_secret:.*/jwt_secret: \"\$JWT\"/\" ${INSTALL_DIR}/config.yaml${NC}"
    echo -e "${YELLOW}  systemctl restart serverguard-agent${NC}"
    echo ""
  fi
  echo -e "${CYAN}─── 手动测试（直接运行看报错）───${NC}"
  echo -e "  ${YELLOW}手动运行查看详细错误:${NC}"
  echo -e "  ${INSTALL_DIR}/serverguard-agent -config ${INSTALL_DIR}/config.yaml"
  echo ""
  echo -e "${CYAN}─── 常见问题 ───${NC}"
  echo -e "  1. 端口冲突: 检查 ss -tlnp | grep ${LISTEN_PORT}"
  echo -e "  2. 目录权限: ls -la /var/lib/serverguard/"
  echo -e "  3. 配置文件: cat ${INSTALL_DIR}/config.yaml"
  echo -e "  4. 内存不足: dmesg | grep -i oom"
  echo -e "  5. 如果外网访问 502 但本机 curl 200：检查 Nginx 反代端口是否为 ${LISTEN_PORT}"
fi

# ── Nginx 反代端口一致性检查 ──────────────────────────
echo ""
echo -e "${GREEN}[检查]${NC} Nginx 反向代理配置一致性"
NGINX_PROXY_FOUND=false
for ngdir in /www/server/panel/vhost/nginx /etc/nginx/conf.d /etc/nginx/sites-enabled; do
  if [ -d "$ngdir" ]; then
    PROXY_LINE=$(grep -rn "proxy_pass.*127.0.0.1" "$ngdir" 2>/dev/null | grep -iE "serverguard|${LISTEN_PORT}|9090|8443" | head -3 || true)
    if [ -n "$PROXY_LINE" ]; then
      NGINX_PROXY_FOUND=true
      echo -e "  ${YELLOW}发现 Nginx 反代配置:${NC}"
      echo -e "  $PROXY_LINE"
      # 检查端口是否匹配
      if echo "$PROXY_LINE" | grep -q ":${LISTEN_PORT}"; then
        echo -e "  ${GREEN}✓ Nginx 反代端口与 Agent 监听端口一致 (${LISTEN_PORT})${NC}"
      else
        echo -e "  ${RED}✗ Nginx 反代端口与 Agent 监听端口不一致！${NC}"
        echo -e "  ${YELLOW}  Agent 监听: ${LISTEN_PORT}${NC}"
        echo -e "  ${YELLOW}  Nginx 反代到上面的端口${NC}"
        echo -e "  ${YELLOW}  解决方法：${NC}"
        echo -e "  ${YELLOW}  方案 A：修改 Nginx 配置中的 proxy_pass 为 127.0.0.1:${LISTEN_PORT}${NC}"
        echo -e "  ${YELLOW}  方案 B：修改 /opt/serverguard/config.yaml 中 web.listen 为 Nginx 反代的端口${NC}"
      fi
    fi
  fi
done
if [ "$NGINX_PROXY_FOUND" = false ]; then
  echo -e "  ${YELLOW}未检测到指向 ServerGuard 的 Nginx 反代配置${NC}"
  echo -e "  ${YELLOW}如需通过域名访问，请在宝塔面板 → 网站 → 反向代理中设置：${NC}"
  echo -e "  ${YELLOW}  目标 URL: http://127.0.0.1:${LISTEN_PORT}${NC}"
fi

# ── 通知渠道引导（交互式，仅终端安装时）──
echo ""
echo -e "${GREEN}[8/8]${NC} 通知渠道引导"
if [ -t 0 ] && [ -t 1 ]; then
  echo -e "  ${CYAN}推荐配置微信通知，这样服务器出问题你能第一时间收到。${NC}"
  echo -e "  ${CYAN}现在打开面板配置？(Y/n)${NC}"
  read -r -t 10 NOTIFY_CHOICE || NOTIFY_CHOICE="n"
  if [ "${NOTIFY_CHOICE:-n}" = "Y" ] || [ "${NOTIFY_CHOICE:-n}" = "y" ]; then
    # 尝试用 curl 或 wget 打开浏览器
    if command -v xdg-open &> /dev/null; then
      xdg-open "http://${SERVER_IP:-localhost}:${LISTEN_PORT}/#/settings" 2>/dev/null || true
    elif command -v sensible-browser &> /dev/null; then
      sensible-browser "http://${SERVER_IP:-localhost}:${LISTEN_PORT}/#/settings" 2>/dev/null || true
    else
      echo -e "  ${YELLOW}请手动打开: http://${SERVER_IP:-服务器IP}:${LISTEN_PORT}/#/settings${NC}"
    fi
    echo -e "  ${GREEN}浏览器已打开，点击「设置」→「通知配置」${NC}"
  else
    echo -e "  ${YELLOW}跳过。稍后可打开面板 → 设置 → 通知配置${NC}"
    echo -e "  ${YELLOW}面板地址: http://${SERVER_IP:-服务器IP}:${LISTEN_PORT}${NC}"
  fi
else
  # 管道安装模式（如 curl | bash），跳过交互
  echo -e "  ${YELLOW}检测到非交互模式，跳过通知引导${NC}"
  echo -e "  ${YELLOW}稍后请打开面板 → 设置 → 通知配置${NC}"
  echo -e "  ${YELLOW}面板地址: http://${SERVER_IP:-服务器IP}:${LISTEN_PORT}${NC}"
fi
echo ""
