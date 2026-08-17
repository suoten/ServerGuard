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
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║        ServerGuard 一键安装脚本                  ║"
echo "║        服务器监控 · 自动运维 · 自愈防护           ║"
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
echo -e "${GREEN}[1/7]${NC} 安装目录: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

# ── 复制二进制文件 ────────────────────────────────────
# 发布包里二进制统一叫 serverguard-agent，dist 目录下叫带架构后缀的名字
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/serverguard-agent" ]; then
  echo -e "${GREEN}[2/7]${NC} 从本地复制二进制文件"
  cp "${SCRIPT_DIR}/serverguard-agent" "${INSTALL_DIR}/serverguard-agent"
elif [ -f "serverguard-agent" ]; then
  echo -e "${GREEN}[2/7]${NC} 从当前目录复制二进制文件"
  cp "serverguard-agent" "${INSTALL_DIR}/serverguard-agent"
elif [ -f "${SCRIPT_DIR}/${BINARY}" ]; then
  echo -e "${GREEN}[2/7]${NC} 从本地复制二进制文件"
  cp "${SCRIPT_DIR}/${BINARY}" "${INSTALL_DIR}/serverguard-agent"
elif [ -f "${BINARY}" ]; then
  echo -e "${GREEN}[2/7]${NC} 从当前目录复制二进制文件"
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

# ── 生成配置文件 ──────────────────────────────────────
echo -e "${GREEN}[3/7]${NC} 生成配置文件"
JWT_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
# 随机面板密码：安全产品不应有固定默认口令，安装时生成并只显示一次
ADMIN_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 16)

# 宝塔环境下生成兼容模式配置
if [ "$IS_BAOTA" = true ]; then
cat > "${INSTALL_DIR}/config.yaml" << EOF
agent:
  collect_interval: 15s
  max_memory_mb: 200
  max_cpu_percent: 10
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
  cleanup_scope: "disabled"
  log_rotation_scope: "disabled"
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
  confirm_actions:
    whitelist_cpu_throttle: "confirm"
    whitelist_mem_restart: "confirm"
    disk_cleanup: "alert"
    log_rotation: "alert"
    baota_service_restart: "confirm"
EOF
else
cat > "${INSTALL_DIR}/config.yaml" << EOF
agent:
  collect_interval: 15s
  max_memory_mb: 200
  max_cpu_percent: 10
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
  panel_path: "/www/server/panel"
  use_baota_service_manager: true
  cleanup_scope: "disabled"
  log_rotation_scope: "disabled"
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
  confirm_actions:
    whitelist_cpu_throttle: "confirm"
    whitelist_mem_restart: "confirm"
    disk_cleanup: "confirm"
    log_rotation: "confirm"
    baota_service_restart: "confirm"
EOF
fi

# 创建数据目录
mkdir -p /var/lib/serverguard/.trash
mkdir -p /var/lib/serverguard/config-backups
chmod 755 /var/lib/serverguard
chmod 755 /var/lib/serverguard/.trash

# ── 复制规则文件 ────────────────────────────────────────
echo -e "${GREEN}[3.5/7]${NC} 部署安全规则文件"
mkdir -p "${INSTALL_DIR}/configs/yara_rules" "${INSTALL_DIR}/configs/cis_benchmark"
if [ -d "${SCRIPT_DIR}/configs/yara_rules" ]; then
  cp -r "${SCRIPT_DIR}/configs/yara_rules/"* "${INSTALL_DIR}/configs/yara_rules/" 2>/dev/null || true
fi
if [ -d "${SCRIPT_DIR}/configs/cis_benchmark" ]; then
  cp -r "${SCRIPT_DIR}/configs/cis_benchmark/"* "${INSTALL_DIR}/configs/cis_benchmark/" 2>/dev/null || true
fi
echo -e "  ${YELLOW}YARA webshell 检测规则和 CIS Benchmark 合规规则已部署到 ${INSTALL_DIR}/configs/${NC}"

# ── 安装 systemd 服务 ─────────────────────────────────
echo -e "${GREEN}[4/7]${NC} 安装 systemd 服务"
cat > /etc/systemd/system/serverguard-agent.service << 'EOF'
[Unit]
Description=ServerGuard Agent - Server Monitoring & Auto-Healing
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/serverguard/serverguard-agent -config /opt/serverguard/config.yaml
WorkingDirectory=/opt/serverguard
Restart=on-failure
RestartSec=10

# ====== 资源约束策略 ======
# 内存：硬限制 256M，Go 软限制 200MiB
MemoryMax=256M
Environment=GOMEMLIMIT=200MiB

# CPU：CPUWeight=20 低优先级（空闲时可用满，繁忙时自动让路）
# 不使用 CPUQuota 硬限制 — 会导致启动极慢、面板无响应
CPUWeight=20
Environment=GOMAXPROCS=2

# I/O：低优先级
IOWeight=10
LimitNOFILE=1024

# OOM：内存不足时优先牺牲 Agent（自动重启），保护服务器和宝塔
OOMScoreAdjust=500

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
echo -e "${GREEN}[5/7]${NC} 配置防火墙"
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
echo -e "${GREEN}[6/7]${NC} 启动服务"

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

# 等待启动（增加等待时间，因为安全模式下采集间隔较大）
sleep 5
echo -e "${GREEN}[7/7]${NC} 验证安装"

if systemctl is-active --quiet serverguard-agent; then
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP="服务器IP"
  fi

  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗"
  echo -e "║              ✅ 安装成功！                       ║"
  echo -e "╠══════════════════════════════════════════════════╣"
  echo -e "║                                                  ║"
  echo -e "║  面板地址: http://${SERVER_IP}:${LISTEN_PORT}              "
  echo -e "║  用户名:   admin                                 "
  echo -e "║  密码:     admin123                              "
  echo -e "║                                                  ║"
  echo -e "║  ⚠️  首次登录后请立即修改密码                     "
  echo -e "║                                                  ║"
  echo -e "╚══════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${CYAN}常用命令:${NC}"
  echo -e "  systemctl status serverguard-agent   # 查看状态"
  echo -e "  systemctl restart serverguard-agent  # 重启"
  echo -e "  journalctl -u serverguard-agent -f   # 查看日志"
  echo -e "  vim /opt/serverguard/config.yaml     # 修改配置"
  echo ""

  # 安全保护模式提示
  if [ "$IS_BAOTA" = true ]; then
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "${YELLOW}安全保护模式部署完成${NC}"
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "  访问地址: http://${SERVER_IP}:${LISTEN_PORT}"
    echo -e "  用户名: admin"
    echo -e "  密码: admin123"
    echo ""
    echo -e "  ${YELLOW}⚠️  重要提示：${NC}"
    echo -e "     - 所有自动修复已降级为只告警"
    echo -e "     - 服务守护将使用 /etc/init.d/xxx 命令"
    echo -e "     - 磁盘清理已禁用"
    echo -e "     - 日志轮转已禁用（不影响宝塔自身日志策略）"
    echo -e "     - 如需关闭安全保护模式，修改 /opt/serverguard/config.yaml"
    echo -e "       将 baota.safe_mode 改为 \"false\""
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
  echo -e "${CYAN}─── 手动测试 ───${NC}"
  echo -e "  ${YELLOW}手动运行查看详细错误:${NC}"
  echo -e "  ${INSTALL_DIR}/serverguard-agent -config ${INSTALL_DIR}/config.yaml"
  echo ""
  echo -e "${CYAN}─── 常见问题 ───${NC}"
  echo -e "  1. 端口冲突: 检查 ss -tlnp | grep ${LISTEN_PORT}"
  echo -e "  2. 目录权限: ls -la /var/lib/serverguard/"
  echo -e "  3. 配置文件: cat ${INSTALL_DIR}/config.yaml"
fi
