﻿#!/bin/bash
# ServerGuard Agent Install Script
# 用法: curl -sSL https://sg.jjtt.net/install.sh | bash

set -e

echo ""
echo "=========================================="
echo "  ServerGuard Agent Installer"
echo "=========================================="
echo ""

# 1. 检测系统
ARCH=$(uname -m)
OS=$(uname -s)

if [ "$OS" != "Linux" ]; then
    echo "  ❌ 此脚本仅支持 Linux 系统"
    exit 1
fi

if [ "$ARCH" = "x86_64" ]; then
    ARCH_NAME="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH_NAME="arm64"
else
    echo "  ❌ 不支持的系统架构: $ARCH"
    exit 1
fi

echo "  系统: Linux $ARCH_NAME"

# 2. 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "  ⚠️  建议使用 root 权限安装"
    echo "     sudo curl -sSL https://sg.jjtt.net/install.sh | bash"
    echo ""
    read -p "  继续安装到当前用户目录？(y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    INSTALL_DIR="$HOME/.local/bin"
    DATA_DIR="$HOME/.serverguard"
    SERVICE_USER=$(whoami)
    USE_SYSTEMD=false
else
    INSTALL_DIR="/usr/local/bin"
    DATA_DIR="/opt/serverguard"
    SERVICE_USER="root"
    USE_SYSTEMD=true
fi

# 3. 下载最新版本
echo ""
echo "  正在检查最新版本..."
SITE="https://sg.jjtt.net"
LATEST_INFO=$(curl -sS --connect-timeout 10 "$SITE/api/v1/latest?channel=stable&os=linux&arch=$ARCH_NAME" 2>/dev/null || echo "")

if [ -z "$LATEST_INFO" ]; then
    echo "  ❌ 无法获取版本信息，请检查网络连接"
    exit 1
fi

VERSION=$(echo "$LATEST_INFO" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
DOWNLOAD_URL=$(echo "$LATEST_INFO" | grep -o '"download_url":"[^"]*"' | head -1 | cut -d'"' -f4)
EXPECTED_SHA=$(echo "$LATEST_INFO" | grep -o '"sha256":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$VERSION" ] || [ "$VERSION" = "0.0.0" ] || [ -z "$DOWNLOAD_URL" ]; then
    echo "  ❌ 暂无可用版本，请稍后再试"
    exit 1
fi

# 兼容相对路径与绝对 URL（API 返回的相对路径基于 /api/v1）
case "$DOWNLOAD_URL" in
    http://*|https://*) ;;
    /*) DOWNLOAD_URL="$SITE/api/v1$DOWNLOAD_URL" ;;
    *)  DOWNLOAD_URL="$SITE/api/v1/$DOWNLOAD_URL" ;;
esac

echo "  最新版本: v$VERSION"
echo "  下载地址: $DOWNLOAD_URL"

# 4. 下载二进制
TMP_FILE="/tmp/serverguard-agent.$$"
echo ""
echo "  正在下载..."
curl -sSL --connect-timeout 15 "$DOWNLOAD_URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"

# 4.1 校验 SHA256（如果官网提供了哈希）
if [ -n "$EXPECTED_SHA" ] && command -v sha256sum &> /dev/null; then
    ACTUAL_SHA=$(sha256sum "$TMP_FILE" | awk '{print $1}')
    if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
        echo "  ❌ SHA256 校验失败，文件可能已损坏"
        echo "     期望: $EXPECTED_SHA"
        echo "     实际: $ACTUAL_SHA"
        rm -f "$TMP_FILE"
        exit 1
    fi
    echo "  ✅ SHA256 校验通过"
fi

# 5. 安装
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"

cp "$TMP_FILE" "$INSTALL_DIR/serverguard-agent"
chmod +x "$INSTALL_DIR/serverguard-agent"
rm -f "$TMP_FILE"

echo "  ✅ 已安装到: $INSTALL_DIR/serverguard-agent"

# 6. 创建配置文件（如果不存在）
CONFIG_FILE="$DATA_DIR/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<EOF
schema_version: 1
agent:
    name: serverguard-agent
    data_dir: $DATA_DIR
    log_level: info
    collect_interval: 10s
    max_memory_mb: 50
    max_cpu_percent: 3
    learn_mode: true
    learn_mode_days: 7
storage:
    path: $DATA_DIR/serverguard.db
    max_size_mb: 200
    backup_count: 7
web:
    enabled: true
    listen: 127.0.0.1:18090
    auth_enabled: true
    username: admin
    password: admin123
upgrade:
    server_url: https://sg.jjtt.net/api/v1
    channel: stable
    check_interval: 6h0m0s
EOF
    echo "  ✅ 配置文件: $CONFIG_FILE"
fi

# 7. 安装 systemd 服务
if [ "$USE_SYSTEMD" = true ] && command -v systemctl &> /dev/null; then
    SERVICE_FILE="/etc/systemd/system/serverguard-agent.service"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ServerGuard Agent
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/serverguard-agent -config $CONFIG_FILE
Restart=on-failure
RestartSec=5
Environment=GOMEMLIMIT=200MiB
Environment=GOMAXPROCS=2

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable serverguard-agent
    systemctl restart serverguard-agent
    sleep 2

    if systemctl is-active --quiet serverguard-agent; then
        echo "  ✅ systemd 服务已启动"
    else
        echo "  ⚠️  服务启动失败，请检查: journalctl -u serverguard-agent"
    fi
else
    echo ""
    echo "  手动启动方式:"
    echo "    $INSTALL_DIR/serverguard-agent -config $CONFIG_FILE"
fi

# 8. 完成
echo ""
echo "=========================================="
echo "  安装完成！"
echo "=========================================="
echo ""
echo "  版本:     v$VERSION"
echo "  二进制:   $INSTALL_DIR/serverguard-agent"
echo "  数据目录: $DATA_DIR"
echo "  配置文件: $CONFIG_FILE"
echo ""
if [ "$USE_SYSTEMD" = true ]; then
    echo "  管理命令:"
    echo "    systemctl status serverguard-agent"
    echo "    systemctl restart serverguard-agent"
    echo "    journalctl -u serverguard-agent -f"
else
    echo "  启动: $INSTALL_DIR/serverguard-agent -config $CONFIG_FILE"
fi
echo ""
echo "  Web 面板: http://127.0.0.1:18090"
echo "  默认账号: admin / admin123"
echo "  ⚠️  请立即修改默认密码！"
echo ""
echo "=========================================="
