#!/bin/bash
# ServerGuard Website Install Script
# 用法：把 serverguard-web-linux-amd64 和本脚本一起上传到服务器，然后运行：
#   bash install.sh
#
# 安装在当前目录，数据在 ./data/，反向代理指向 8422 端口即可。

set -e

echo ""
echo "=========================================="
echo "  ServerGuard Website Installer"
echo "=========================================="
echo ""

# 1. 找二进制
INSTALL_DIR="$(pwd)"
BINARY=""

if [ -f "serverguard-web-linux-amd64" ]; then
    BINARY="serverguard-web-linux-amd64"
elif [ -f "serverguard-web" ]; then
    BINARY="serverguard-web"
elif [ -f "serverguard-web.exe" ]; then
    echo "  ❌ 发现 Windows 二进制，请在 Linux 上使用 Linux 版本。"
    exit 1
else
    echo "  ❌ 未找到二进制文件。"
    echo "     请把 serverguard-web-linux-amd64 和 install.sh"
    echo "     放在同一个目录下再运行。"
    echo ""
    echo "  当前目录: $INSTALL_DIR"
    echo "  目录内容:"
    ls -la
    exit 1
fi

echo "  二进制:  $BINARY"
echo "  安装到:  $INSTALL_DIR"
echo ""

# 2. 检查架构是否匹配
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo "  ⚠️  当前系统架构: $ARCH"
    echo "     此二进制为 amd64 (x86_64) 编译，可能不兼容。"
    echo "     如需 arm64 版本请联系开发者。"
    echo ""
    read -p "  仍然继续安装？(y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# 3. 重命名 + 赋予执行权限
if [ "$BINARY" != "serverguard-web" ]; then
    cp "$BINARY" serverguard-web
fi
chmod +x serverguard-web

# 4. 测试二进制能否运行
echo "  测试二进制..."
if ./serverguard-web --version 2>/dev/null || true; then
    echo "  ✅ 二进制可运行"
else
    echo "  ❌ 二进制无法运行，可能缺少依赖。"
    echo "     错误信息:"
    ldd ./serverguard-web 2>&1 || echo "    (非动态链接二进制)"
fi
echo ""

# 5. 创建数据目录
mkdir -p data/uploads
echo "  ✅ 数据目录: $INSTALL_DIR/data/"
echo ""

# 6. 询问端口
DEFAULT_PORT=8422
read -p "  监听端口（默认 $DEFAULT_PORT）: " PORT
PORT="${PORT:-$DEFAULT_PORT}"
echo "  端口: $PORT"
echo ""

# 7. 先杀掉旧进程（如果有的话）
pkill -f "serverguard-web" 2>/dev/null || true
sleep 1

# 8. 询问是否安装 systemd 服务
read -p "  是否安装为 systemd 服务（开机自启）？(y/N): " -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    SERVICE_NAME="serverguard-website"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ServerGuard Website
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/serverguard-web
Restart=on-failure
RestartSec=5
Environment=SG_WEB_PORT=$PORT
Environment=SG_WEB_DATA_DIR=$INSTALL_DIR/data

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    sleep 2

    # 检查是否启动成功
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "  ✅ systemd 服务已启动"
    else
        echo "  ❌ systemd 服务启动失败，查看错误:"
        journalctl -u "$SERVICE_NAME" --no-pager -n 10
        echo ""
        echo "  尝试手动运行查看错误:"
        SG_WEB_PORT=$PORT SG_WEB_DATA_DIR=$INSTALL_DIR/data ./serverguard-web &
        sleep 2
        if pgrep -f "serverguard-web" > /dev/null; then
            echo "  ✅ 手动启动成功"
        else
            echo "  ❌ 手动启动也失败了，请检查上面的错误信息"
            exit 1
        fi
    fi
else
    # 直接后台启动
    echo "  直接启动（后台运行）..."
    SG_WEB_PORT=$PORT SG_WEB_DATA_DIR=$INSTALL_DIR/data nohup ./serverguard-web > website.log 2>&1 &
    sleep 3

    if pgrep -f "serverguard-web" > /dev/null; then
        echo "  ✅ 已启动（PID: $(pgrep -f 'serverguard-web' | head -1)）"
    else
        echo "  ❌ 启动失败，错误日志:"
        cat website.log
        exit 1
    fi
fi

# 9. 验证端口是否在监听
echo ""
if ss -tlnp 2>/dev/null | grep -q ":$PORT"; then
    echo "  ✅ 端口 $PORT 正在监听"
else
    echo "  ⚠️  端口 $PORT 未监听，可能启动有问题"
    echo "  请运行: ./serverguard-web 查看错误"
fi

# 10. 测试 HTTP 连接
echo ""
echo "  测试 HTTP 连接..."
HTTP_TEST=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT" 2>/dev/null || echo "000")
if [ "$HTTP_TEST" != "000" ]; then
    echo "  ✅ HTTP 响应正常 (HTTP $HTTP_TEST)"
else
    echo "  ⚠️  HTTP 连接失败，服务可能需要几秒钟才能就绪"
    echo "     请稍等后重试: curl http://127.0.0.1:$PORT"
fi

echo ""
echo "=========================================="
echo "  安装完成！"
echo "=========================================="
echo ""
echo "  访问地址:"
echo "    http://服务器IP:$PORT         (前端)"
echo "    http://服务器IP:$PORT/admin    (后台管理)"
echo ""
echo "  默认账号: admin / admin123"
echo "  ⚠️  请立即修改默认密码！"
echo ""
echo "  常用命令:"
echo "    查看进程: ps aux | grep serverguard"
echo "    查看端口: ss -tlnp | grep $PORT"
echo "    手动运行: SG_WEB_PORT=$PORT ./serverguard-web"
echo "    停止:     pkill -f serverguard-web"
echo ""
echo "  Nginx 反向代理:"
echo "    location / {"
echo "        proxy_pass http://127.0.0.1:$PORT;"
echo "        proxy_set_header Host \$host;"
echo "        proxy_set_header X-Real-IP \$remote_addr;"
echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
echo "    }"
echo ""
echo "=========================================="
