#!/bin/bash
# ServerGuard Uninstallation Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/serverguard"
CONFIG_DIR="/etc/serverguard"
SERVICE_DIR="/etc/systemd/system"

echo -e "${YELLOW}Uninstalling ServerGuard...${NC}"

# ── 宝塔环境检测 ──────────────────────────────────────
IS_BAOTA=false
if [ -d "/www/server/panel" ]; then
  IS_BAOTA=true
  echo -e "${YELLOW}[INFO]${NC} BaoTa panel detected. All BaoTa configurations will be preserved."
fi

# ── Stop and disable service ──────────────────────────
echo -e "${GREEN}[1/4]${NC} Stopping service..."
systemctl stop serverguard.service 2>/dev/null || true
systemctl disable serverguard.service 2>/dev/null || true

# ── Remove service file ───────────────────────────────
echo -e "${GREEN}[2/4]${NC} Removing systemd service..."
rm -f "$SERVICE_DIR/serverguard.service"
systemctl daemon-reload

# ── Remove binaries ───────────────────────────────────
echo -e "${GREEN}[3/4]${NC} Removing binaries..."
rm -f "$INSTALL_DIR/serverguard-agent"
rm -f "$INSTALL_DIR/sgctl"

# ── Remove config and data (绝不触碰宝塔目录) ─────────
echo -e "${GREEN}[4/4]${NC} Removing configuration and data..."
# Remove config (keep data for backup by default)
read -p "Remove configuration directory $CONFIG_DIR? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -rf "$CONFIG_DIR"
fi

# Remove data (keep for backup by default)
read -p "Remove data directory $DATA_DIR (includes database, logs, backups)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -rf "$DATA_DIR"
fi

# ── 完成 ──────────────────────────────────────────────
echo ""
if [ "$IS_BAOTA" = true ]; then
  echo -e "${GREEN}ServerGuard has been uninstalled.${NC}"
  echo -e "${YELLOW}BaoTa panel is not affected. All BaoTa configurations preserved.${NC}"
else
  echo -e "${GREEN}ServerGuard has been uninstalled.${NC}"
fi
