#!/bin/bash
# ServerGuard Installation Script
# Usage: curl -fsSL https://install.serverguard.io | sh
#   or: ./install.sh

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/serverguard"
CONFIG_DIR="/etc/serverguard"
SERVICE_DIR="/etc/systemd/system"
VERSION="3.0.0"
ARCH=$(uname -m)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ServerGuard v${VERSION} Installer${NC}"
echo -e "${GREEN}  Install & Forget. Guard & Heal.${NC}"
echo -e "${GREEN}========================================${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Warning: Running as non-root, some features may not work${NC}"
fi

# Check OS
if [ "$(uname)" != "Linux" ]; then
  echo -e "${RED}Error: This installer is for Linux only${NC}"
  exit 1
fi

# ── 宝塔面板环境检测 ──────────────────────────────────
BAOTA_PANEL_PATH="/www/server/panel"
IS_BAOTA=false
if [ -d "$BAOTA_PANEL_PATH" ] && [ -f "/etc/init.d/bt" ]; then
  IS_BAOTA=true
  echo -e "${YELLOW}[INFO] BaoTa panel detected. Compatibility mode will be enabled.${NC}"
fi

# Determine architecture
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
    exit 1
    ;;
esac

# ── 端口冲突检测 ──────────────────────────────────────
LISTEN_PORT="8443"
if command -v ss &> /dev/null; then
  if ss -tlnp | grep -q ":${LISTEN_PORT} "; then
    echo -e "${YELLOW}[WARN]${NC} Port ${LISTEN_PORT} is already in use"
    if ss -tlnp | grep ":${LISTEN_PORT} " | grep -q "python"; then
      echo -e "${RED}[ERROR]${NC} Port ${LISTEN_PORT} may be occupied by a BaoTa plugin"
      echo -e "  Please change web.listen in the config file and retry"
      exit 1
    fi
    echo -e "  ${YELLOW}Please ensure this port is available or change it in the config${NC}"
  fi
elif command -v netstat &> /dev/null; then
  if netstat -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT} "; then
    echo -e "${YELLOW}[WARN]${NC} Port ${LISTEN_PORT} is already in use${NC}"
  fi
fi

# ── Check for conflicts ───────────────────────────────
echo -e "${GREEN}[1/8]${NC} Checking for conflicts..."
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  echo -e "${YELLOW}  Warning: fail2ban detected. ServerGuard will cooperate with it.${NC}"
fi
if systemctl is-active --quiet supervisor 2>/dev/null; then
  echo -e "${YELLOW}  Warning: Supervisor detected. ServerGuard will cooperate with it.${NC}"
fi
echo -e "${GREEN}  Conflict check passed.${NC}"

# ── Create directories ────────────────────────────────
echo -e "${GREEN}[2/8]${NC} Creating directories..."
mkdir -p "$DATA_DIR" "$CONFIG_DIR" "$DATA_DIR/config-backups" "$DATA_DIR/certs" "$DATA_DIR/.trash" "$DATA_DIR/db-backups"
echo -e "${GREEN}  Directories created.${NC}"

# ── Download / copy binary ────────────────────────────
echo -e "${GREEN}[3/8]${NC} Downloading binary..."
if [ -f "./serverguard-agent" ]; then
  echo -e "${YELLOW}  Using local binary...${NC}"
  cp serverguard-agent "$INSTALL_DIR/serverguard-agent"
else
  # Download from releases
  DOWNLOAD_URL="https://github.com/suoten/serverguard/releases/download/v${VERSION}/serverguard-agent-linux-${ARCH}"
  curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/serverguard-agent"
fi
chmod +x "$INSTALL_DIR/serverguard-agent"
echo -e "${GREEN}  Binary installed to $INSTALL_DIR/serverguard-agent${NC}"

# Install sgctl
if [ -f "./sgctl" ]; then
  cp sgctl "$INSTALL_DIR/sgctl"
  chmod +x "$INSTALL_DIR/sgctl"
fi

# ── Generate default config ───────────────────────────
echo -e "${GREEN}[4/8]${NC} Generating configuration..."
if [ ! -f "$CONFIG_DIR/serverguard.yaml" ]; then
  JWT_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
  ADMIN_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 16)

  # ============================================================
  # 安装即生效：零配置自愈
  # ============================================================
  cat > "$CONFIG_DIR/serverguard.yaml" << EOF
schema_version: 1
agent:
  name: serverguard-agent
  data_dir: /var/lib/serverguard
  log_level: info
  collect_interval: 15s
  max_memory_mb: 120
  max_cpu_percent: 10
  learn_mode: true
  learn_mode_days: 1
  emergency_stop: false

storage:
  path: /var/lib/serverguard/serverguard.db
  max_size_mb: 200
  vacuum_interval: 168h
  wal_checkpoint_interval: 5m
  backup_count: 7

collectors:
  enable_processes: true
  enable_disks: true
  enable_network: true
  enable_gpu: false
  enable_temperature: false
  enable_fd: true
  process_max_count: 1000
  inotify_max_watches: 500

safety:
  kill_budget_hourly: 15
  kill_budget_daily: 50
  kill_min_interval: 30s
  circuit_breaker_threshold: 3
  circuit_breaker_reset_duration: 30m
  min_available_memory_mb: 50
  max_load_factor: 3.0
  max_disk_io_wait_percent: 80
  min_disk_free_mb: 500
  observation_window: 60s
  cascade_suppression: true
  trash_dir: /var/lib/serverguard/.trash
  trash_retention_days: 7

web:
  enabled: true
  listen: "0.0.0.0:${LISTEN_PORT}"
  auth_enabled: true
  username: admin
  password: "${ADMIN_PASSWORD}"
  jwt_secret: "${JWT_SECRET}"
  cors_origins:
    - "http://localhost:5173"

cert:
  scan_interval: 24h
  scan_ports: [443, 8443, 8001, 8888]
  alert_days: [30, 14, 7, 3, 1]
  auto_renew_days: 14
  renew_cooldown: 1h
  acme_directory: "https://acme-v02.api.letsencrypt.org/directory"
  acme_email: ""
  baota_auto_renew: true
  preferred_cas: ["lets_encrypt", "zerossl", "trustasia", "buypass"]
  nginx_reload_cmd: "nginx -s reload"
  cert_cache_dir: /var/lib/serverguard/certs

log:
  max_file_size: 524288000
  max_dir_size: 10737418240
  max_write_rate: 10
  compression_format: gzip
  retention_days: 30
  emergency_clean_threshold: 0.95
  scan_paths: ["/var/log", "/www/wwwlogs"]
  exclude_paths: []
EOF

  # 追加 baota 配置段
  if [ "$IS_BAOTA" = true ]; then
    cat >> "$CONFIG_DIR/serverguard.yaml" << 'EOF'

baota:
  safe_mode: "true"
  panel_path: "/www/server/panel"
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
    cat >> "$CONFIG_DIR/serverguard.yaml" << 'EOF'

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

  echo -e "${GREEN}  Config created at $CONFIG_DIR/serverguard.yaml${NC}"
else
  echo -e "${YELLOW}  Config already exists, skipping.${NC}"
fi

# ── Create systemd service ────────────────────────────
echo -e "${GREEN}[5/8]${NC} Installing systemd service..."

# 宝塔环境下需要额外的可写路径
if [ "$IS_BAOTA" = true ]; then
  READ_WRITE_PATHS="/var/lib/serverguard /var/log /www/wwwlogs /www/server/panel/vhost/cert /etc/serverguard"
else
  READ_WRITE_PATHS="/var/lib/serverguard /var/log /etc/serverguard"
fi

# ── 自适应内存策略 ──
TOTAL_MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))

if [ "$TOTAL_MEM_MB" -le 0 ] || [ "$TOTAL_MEM_MB" -le 512 ]; then
  MEM_MAX="128M"; MEM_HIGH="96M"; GO_MEM_LIMIT="96MiB"
elif [ "$TOTAL_MEM_MB" -le 1024 ]; then
  MEM_MAX="192M"; MEM_HIGH="128M"; GO_MEM_LIMIT="128MiB"
elif [ "$TOTAL_MEM_MB" -le 2048 ]; then
  MEM_MAX="256M"; MEM_HIGH="192M"; GO_MEM_LIMIT="192MiB"
else
  MEM_MAX="384M"; MEM_HIGH="256M"; GO_MEM_LIMIT="256MiB"
fi
echo -e "  ${CYAN}Total RAM: ${TOTAL_MEM_MB}MB → MemoryMax=${MEM_MAX}, GOMEMLIMIT=${GO_MEM_LIMIT}${NC}"

cat > "$SERVICE_DIR/serverguard.service" << EOF
[Unit]
Description=ServerGuard Agent - Server Guardian Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/serverguard-agent -config $CONFIG_DIR/serverguard.yaml
Restart=always
RestartSec=3
StartLimitInterval=60
StartLimitBurst=3

# Resource limits (adaptive: based on total RAM=${TOTAL_MEM_MB}MB)
MemoryMax=${MEM_MAX}
MemoryHigh=${MEM_HIGH}
MemoryHighTime=30s
Environment=GOMEMLIMIT=${GO_MEM_LIMIT}
Environment=GOGC=50
CPUWeight=20
Environment=GOMAXPROCS=2
IOWeight=10
LimitNOFILE=4096
OOMScoreAdjust=100

# Security hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${READ_WRITE_PATHS}
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_PTRACE CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_DAC_READ_SEARCH

# Watchdog
WatchdogSec=30
NotifyAccess=main

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable serverguard.service
echo -e "${GREEN}  Service installed and enabled.${NC}"

# ── Firewall configuration ────────────────────────────
echo -e "${GREEN}[6/8]${NC} Configuring firewall..."
if [ "$IS_BAOTA" = true ]; then
  echo -e "  ${YELLOW}BaoTa panel detected. Please open port ${LISTEN_PORT} in:${NC}"
  echo -e "  ${YELLOW}  BaoTa Panel → Security → Release port ${LISTEN_PORT}${NC}"
else
  if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${LISTEN_PORT}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null
    echo -e "  ${YELLOW}Port ${LISTEN_PORT} opened (firewalld)${NC}"
  elif command -v ufw &> /dev/null; then
    ufw allow ${LISTEN_PORT}/tcp 2>/dev/null
    echo -e "  ${YELLOW}Port ${LISTEN_PORT} opened (ufw)${NC}"
  elif command -v iptables &> /dev/null; then
    iptables -I INPUT -p tcp --dport ${LISTEN_PORT} -j ACCEPT 2>/dev/null
    echo -e "  ${YELLOW}Port ${LISTEN_PORT} opened (iptables)${NC}"
  else
    echo -e "  ${YELLOW}No firewall detected. Please manually open port ${LISTEN_PORT}${NC}"
  fi
fi

# ── Start service ─────────────────────────────────────
echo -e "${GREEN}[7/8]${NC} Starting service..."
systemctl start serverguard.service
sleep 2

if systemctl is-active --quiet serverguard.service; then
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
  echo -e "${CYAN}${BOLD}─── Install & Forget: ServerGuard is already protecting your server ───${NC}"
  echo ""
  echo -e "  ${GREEN}✓${NC} Disk > 90% → Auto-clean logs/cache (keep last 7 days)"
  echo -e "  ${GREEN}✓${NC} Log > 500MB → Auto-rotate & compress"
  echo -e "  ${GREEN}✓${NC} SSH brute force → Auto-ban IP"
  echo -e "  ${GREEN}✓${NC} SSL cert expiring → Auto-renew"
  echo -e "  ${GREEN}✓${NC} Zombie processes → Auto-clean"
  echo -e "  ${GREEN}✓${NC} Service crash → Auto-restart"
  if [ "$IS_BAOTA" = true ]; then
    echo -e "  ${GREEN}✓${NC} BaoTa panel down → Auto-restart"
  fi
  echo ""
  echo -e "  ${YELLOW}1-day learn mode active (observe only), then auto-healing starts${NC}"
  echo ""

  # ── 通知引导 ──
  echo -e "${CYAN}${BOLD}─── Notification Setup (Important!) ───${NC}"
  echo -e "  ${YELLOW}⚠️  No notification channel configured! Without notifications, alerts only show on the panel.${NC}"
  echo ""
  echo -e "  Open panel → Settings → Notification Config, 3 minutes to setup:"
  echo -e "    1. ${CYAN}WeChat${NC} (recommended): Scan WxPusher QR → Enter code"
  echo -e "    2. ${CYAN}DingTalk/Feishu${NC}: Copy Webhook URL → Paste"
  echo -e "    3. ${CYAN}Email${NC}: Fill SMTP info"
  echo -e "    4. ${CYAN}Telegram${NC}: @BotFather → Enter token"
  echo ""
  echo -e "  ${GREEN}With notifications, you'll be the first to know when something goes wrong.${NC}"
  echo ""

  echo -e "${CYAN}Commands:${NC}"
  echo "  Status:  systemctl status serverguard"
  echo "  Logs:   journalctl -u serverguard -f"
  echo "  Config: $CONFIG_DIR/serverguard.yaml"
  echo "  Data:   $DATA_DIR/"
  echo "  CLI:    sgctl status"
  echo ""

  if [ "$IS_BAOTA" = true ]; then
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "${YELLOW}BaoTa Compatibility Mode Deployed${NC}"
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "  ${CYAN}Auto-enabled capabilities:${NC}"
    echo -e "    - SSH brute force ban ✓"
    echo -e "    - SSL cert auto-renewal ✓"
    echo -e "    - Zombie process cleanup ✓"
    echo -e "    - Disk cleanup (system dirs only, BaoTa untouched) ✓"
    echo -e "    - Log rotation (system logs only, BaoTa untouched) ✓"
    echo -e "    - BaoTa panel auto-restart ✓"
    echo ""
    echo -e "  ${YELLOW}Actions requiring manual confirmation:${NC}"
    echo -e "    - CPU throttle (avoid killing business processes)"
    echo -e "    - Memory restart (avoid killing business processes)"
    echo -e "    - BaoTa service restart"
    echo ""
    echo -e "  To disable compat mode: edit $CONFIG_DIR/serverguard.yaml"
    echo -e "    set baota.safe_mode to \"false\""
    echo -e "${YELLOW}==========================================${NC}"
    echo ""
  fi
else
  echo -e "${RED}  Failed to start service. Check: journalctl -u serverguard${NC}"
  exit 1
fi

# ── 通知渠道引导（交互式）──
echo -e "${GREEN}[8/8]${NC} Notification setup"
if [ -t 0 ] && [ -t 1 ]; then
  echo -e "  ${CYAN}Configure WeChat notifications now? (Y/n)${NC}"
  read -r -t 10 NOTIFY_CHOICE || NOTIFY_CHOICE="n"
  if [ "${NOTIFY_CHOICE:-n}" = "Y" ] || [ "${NOTIFY_CHOICE:-n}" = "y" ]; then
    if command -v xdg-open &> /dev/null; then
      xdg-open "http://${SERVER_IP:-localhost}:${LISTEN_PORT}/#/settings" 2>/dev/null || true
    elif command -v sensible-browser &> /dev/null; then
      sensible-browser "http://${SERVER_IP:-localhost}:${LISTEN_PORT}/#/settings" 2>/dev/null || true
    else
      echo -e "  ${YELLOW}Open: http://${SERVER_IP:-server-ip}:${LISTEN_PORT}/#/settings${NC}"
    fi
    echo -e "  ${GREEN}Browser opened → click Settings → Notification Config${NC}"
  else
    echo -e "  ${YELLOW}Skipped. Later: Panel → Settings → Notification Config${NC}"
    echo -e "  ${YELLOW}Panel: http://${SERVER_IP:-server-ip}:${LISTEN_PORT}${NC}"
  fi
else
  echo -e "  ${YELLOW}Non-interactive mode, skipping notification guide${NC}"
  echo -e "  ${YELLOW}Later: Panel → Settings → Notification Config${NC}"
  echo -e "  ${YELLOW}Panel: http://${SERVER_IP:-server-ip}:${LISTEN_PORT}${NC}"
fi
echo ""
