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
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ServerGuard v${VERSION} Installer${NC}"
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
echo -e "${GREEN}[1/7]${NC} Checking for conflicts..."
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  echo -e "${YELLOW}  Warning: fail2ban detected. ServerGuard will cooperate with it.${NC}"
fi
if systemctl is-active --quiet supervisor 2>/dev/null; then
  echo -e "${YELLOW}  Warning: Supervisor detected. ServerGuard will cooperate with it.${NC}"
fi
echo -e "${GREEN}  Conflict check passed.${NC}"

# ── Create directories ────────────────────────────────
echo -e "${GREEN}[2/7]${NC} Creating directories..."
mkdir -p "$DATA_DIR" "$CONFIG_DIR" "$DATA_DIR/config-backups" "$DATA_DIR/certs" "$DATA_DIR/.trash"
echo -e "${GREEN}  Directories created.${NC}"

# ── Download / copy binary ────────────────────────────
echo -e "${GREEN}[3/7]${NC} Downloading binary..."
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
echo -e "${GREEN}[4/7]${NC} Generating configuration..."
if [ ! -f "$CONFIG_DIR/serverguard.yaml" ]; then
  cat > "$CONFIG_DIR/serverguard.yaml" << 'EOF'
schema_version: 1
agent:
  name: serverguard-agent
  data_dir: /var/lib/serverguard
  log_level: info
  collect_interval: 5s
  max_memory_mb: 80
  max_cpu_percent: 5
  learn_mode: true
  learn_mode_days: 7
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
  kill_budget_hourly: 5
  kill_budget_daily: 20
  kill_min_interval: 30s
  circuit_breaker_threshold: 3
  circuit_breaker_reset_duration: 30m
  min_available_memory_mb: 100
  max_load_factor: 2.0
  max_disk_io_wait_percent: 50
  min_disk_free_mb: 500
  observation_window: 60s
  cascade_suppression: true
  whitelist_path: /var/lib/serverguard/whitelist.yaml
  trash_dir: /var/lib/serverguard/.trash
  trash_retention_days: 7

web:
  enabled: true
  listen: "127.0.0.1:8443"
  auth_enabled: true
  username: admin
  password: ""
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

security:
  brute_force_threshold: 5
  brute_force_window: 5m
  ban_duration: 1h
  ban_progression: true
  monitor_ssh_log: "/var/log/auth.log"
  monitor_auth_log: "/var/log/auth.log"
EOF

  # 追加 baota 配置段（根据检测结果设置 safe_mode）
  if [ "$IS_BAOTA" = true ]; then
    cat >> "$CONFIG_DIR/serverguard.yaml" << 'EOF'

baota:
  safe_mode: "true"
  panel_path: "/www/server/panel"
  use_baota_service_manager: true
  cleanup_scope: "disabled"
  log_rotation_scope: "disabled"
  webshell_exclusions:
    - "/www/server/panel"
    - "/www/server/panel/plugin"
EOF
  else
    cat >> "$CONFIG_DIR/serverguard.yaml" << 'EOF'

baota:
  safe_mode: "auto"
  panel_path: "/www/server/panel"
  use_baota_service_manager: true
  cleanup_scope: "disabled"
  log_rotation_scope: "disabled"
  webshell_exclusions:
    - "/www/server/panel"
    - "/www/server/panel/plugin"
EOF
  fi

  echo -e "${GREEN}  Config created at $CONFIG_DIR/serverguard.yaml${NC}"
else
  echo -e "${YELLOW}  Config already exists, skipping.${NC}"
fi

# ── Create systemd service ────────────────────────────
echo -e "${GREEN}[5/7]${NC} Installing systemd service..."

# 宝塔环境下需要额外的可写路径（宝塔日志目录、证书目录）
if [ "$IS_BAOTA" = true ]; then
  READ_WRITE_PATHS="/var/lib/serverguard /var/log /www/wwwlogs /www/server/panel/vhost/cert"
else
  READ_WRITE_PATHS="/var/lib/serverguard /var/log"
fi

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

# Resource limits (OS-level enforcement)
MemoryMax=80M
CPUQuota=5%
IOWeight=10
LimitNOFILE=1024

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
echo -e "${GREEN}[6/7]${NC} Configuring firewall..."
if [ "$IS_BAOTA" = true ]; then
  # 宝塔环境下不直接修改系统防火墙，提示用户在宝塔面板中放行
  echo -e "  ${YELLOW}BaoTa panel detected. Please open port ${LISTEN_PORT} in:${NC}"
  echo -e "  ${YELLOW}  BaoTa Panel → Security → Release port ${LISTEN_PORT}${NC}"
  echo -e "  ${YELLOW}  Or configure via BaoTa firewall plugin if installed${NC}"
else
  # 非 宝塔 环境：使用 firewalld / ufw / iptables
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
echo -e "${GREEN}[7/7]${NC} Starting service..."
systemctl start serverguard.service
sleep 2

if systemctl is-active --quiet serverguard.service; then
  echo -e "${GREEN}========================================${NC}"
  echo -e "${GREEN}  ServerGuard installed successfully!${NC}"
  echo -e "${GREEN}========================================${NC}"
  echo ""
  echo "  Status:  systemctl status serverguard"
  echo "  Logs:   journalctl -u serverguard -f"
  echo "  Config: $CONFIG_DIR/serverguard.yaml"
  echo "  Data:   $DATA_DIR/"
  echo "  CLI:    sgctl status"
  echo ""
  echo -e "${YELLOW}  Note: Learn mode is active for 7 days.${NC}"
  echo -e "${YELLOW}  ServerGuard will only alert, no auto-actions.${NC}"
  echo ""

  # 安全保护模式专用提示
  if [ "$IS_BAOTA" = true ]; then
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "${YELLOW}BaoTa Compatibility Mode Deployed${NC}"
    echo -e "${YELLOW}==========================================${NC}"
    echo -e "  Access:  http://127.0.0.1:${LISTEN_PORT}"
    echo -e "  User:    admin"
    echo -e "  Pass:    (set in config)"
    echo ""
    echo -e "  ${YELLOW}⚠️  Important:${NC}"
    echo -e "     - All auto-remediation downgraded to alert-only"
    echo -e "     - Service management uses /etc/init.d/xxx commands"
    echo -e "     - Disk cleanup disabled"
    echo -e "     - Log rotation disabled (BaoTa's own policy unaffected)"
    echo -e "     - To disable compat mode, edit $CONFIG_DIR/serverguard.yaml"
    echo -e "       set baota.safe_mode to \"false\""
    echo -e "${YELLOW}==========================================${NC}"
    echo ""
  fi
else
  echo -e "${RED}  Failed to start service. Check: journalctl -u serverguard${NC}"
  exit 1
fi
