#!/bin/bash
# ============================================================
# ServerGuard 502 Bad Gateway 诊断+修复脚本
# 用法: bash diagnose-502.sh
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SERVICE="serverguard-agent"
INSTALL_DIR="/opt/serverguard"
CONFIG_FILE="$INSTALL_DIR/config.yaml"
DATA_DIR="/var/lib/serverguard"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     ServerGuard 502 诊断工具                      ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}== 1. 检查 Agent 服务状态 ==${NC}"
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    echo -e "  ${GREEN}✓ Agent 服务正在运行${NC}"
    systemctl status "$SERVICE" --no-pager | head -8
else
    echo -e "  ${RED}✗ Agent 服务未运行！这就是 502 的原因${NC}"
    echo ""
    echo -e "  ${YELLOW}最近的服务日志：${NC}"
    journalctl -u "$SERVICE" --since "30 min ago" --no-pager 2>/dev/null | tail -30
    echo ""
    echo -e "  ${YELLOW}系统 OOM 记录：${NC}"
    dmesg -T 2>/dev/null | grep -iE "out of memory|oom.?kill|serverguard" | tail -10
fi

echo ""
echo -e "${BOLD}== 2. 检查 Agent 端口监听 ==${NC}"
# 从配置文件读取实际监听端口
LISTEN_PORT="18090"
if [ -f "$CONFIG_FILE" ]; then
    CFG_PORT=$(grep 'listen:' "$CONFIG_FILE" | head -1 | grep -oP ':\s*"?\K[0-9]+' || true)
    if [ -n "$CFG_PORT" ]; then
        LISTEN_PORT="$CFG_PORT"
    fi
fi
echo -e "  配置文件中的监听端口: ${CYAN}$LISTEN_PORT${NC}"

if ss -tlnp 2>/dev/null | grep -q ":$LISTEN_PORT "; then
    echo -e "  ${GREEN}✓ 端口 $LISTEN_PORT 正在监听${NC}"
    ss -tlnp | grep ":$LISTEN_PORT "
else
    echo -e "  ${RED}✗ 端口 $LISTEN_PORT 没有监听！Agent 可能已崩溃${NC}"
    echo -e "  ${YELLOW}所有 serverguard 相关端口：${NC}"
    ss -tlnp 2>/dev/null | grep -i serverguard || echo "  (无)"
fi

echo ""
echo -e "${BOLD}== 3. 本机回环测试 ==${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:$LISTEN_PORT/api/version" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "  ${GREEN}✓ http://127.0.0.1:$LISTEN_PORT/api/version 返回 200${NC}"
    curl -s --max-time 5 "http://127.0.0.1:$LISTEN_PORT/api/version" 2>/dev/null
    echo ""
else
    echo -e "  ${RED}✗ http://127.0.0.1:$LISTEN_PORT/api/version 返回 $HTTP_CODE${NC}"
    echo -e "  ${YELLOW}Agent 进程可能已崩溃或无法响应${NC}"
fi

echo ""
echo -e "${BOLD}== 4. 检查 Nginx 反代配置 ==${NC}"
echo -e "  ${YELLOW}搜索 Nginx 配置中的 proxy_pass 指令：${NC}"
NGINX_CONFS=(
    "/www/server/panel/vhost/nginx"
    "/etc/nginx/conf.d"
    "/etc/nginx/sites-enabled"
    "/etc/nginx"
)
for dir in "${NGINX_CONFS[@]}"; do
    if [ -d "$dir" ]; then
        grep -rn "proxy_pass.*127.0.0.1" "$dir" 2>/dev/null | grep -iE "serverguard|18090|9090|8443" || true
    fi
done
echo ""
echo -e "  ${YELLOW}Nginx 反代目标端口应该是: $LISTEN_PORT${NC}"
echo -e "  ${YELLOW}如果 Nginx 反代到其他端口，需要修改 Nginx 配置或 Agent 配置使端口一致${NC}"

echo ""
echo -e "${BOLD}== 5. 检查配置文件中的密码/密钥 ==${NC}"
if [ -f "$CONFIG_FILE" ]; then
    JWT=$(grep 'jwt_secret:' "$CONFIG_FILE" | head -1 | awk '{print $2}' | tr -d '"' || true)
    PASS=$(grep 'password:' "$CONFIG_FILE" | head -1 | awk '{print $2}' | tr -d '"' || true)
    
    if [ -z "$JWT" ] || [ "$JWT" = '""' ]; then
        echo -e "  ${RED}✗ jwt_secret 为空！Agent 会拒绝启动${NC}"
    elif echo "$JWT" | grep -qiE "change_me|changeme|admin123|password|12345678|serverguard"; then
        echo -e "  ${RED}✗ jwt_secret 是弱值/占位符！Agent 会拒绝启动${NC}"
        echo -e "  ${YELLOW}  当前值: $JWT${NC}"
    elif [ ${#JWT} -lt 8 ]; then
        echo -e "  ${RED}✗ jwt_secret 太短（少于8字符）！Agent 会拒绝启动${NC}"
    else
        echo -e "  ${GREEN}✓ jwt_secret 已设置且不是弱值${NC}"
    fi
    
    if [ -z "$PASS" ] || [ "$PASS" = '""' ]; then
        echo -e "  ${RED}✗ password 为空！Agent 会拒绝启动${NC}"
    elif echo "$PASS" | grep -qiE "change_me|changeme|admin123|password|12345678|serverguard"; then
        echo -e "  ${RED}✗ password 是弱值/占位符！Agent 会拒绝启动${NC}"
        echo -e "  ${YELLOW}  当前值: $PASS${NC}"
    elif [ ${#PASS} -lt 8 ]; then
        echo -e "  ${RED}✗ password 太短（少于8字符）！Agent 会拒绝启动${NC}"
    else
        echo -e "  ${GREEN}✓ password 已设置且不是弱值${NC}"
    fi
else
    echo -e "  ${RED}✗ 配置文件不存在: $CONFIG_FILE${NC}"
fi

echo ""
echo -e "${BOLD}== 6. 检查数据库文件 ==${NC}"
if [ -f "$DATA_DIR/serverguard.db" ]; then
    DB_SIZE=$(du -h "$DATA_DIR/serverguard.db" | awk '{print $1}')
    echo -e "  数据库文件: $DATA_DIR/serverguard.db ($DB_SIZE)"
    if echo "$DB_SIZE" | grep -qE "^[0-9]+G"; then
        DB_GB=$(echo "$DB_SIZE" | grep -oP '[0-9]+')
        if [ "$DB_GB" -ge 1 ]; then
            echo -e "  ${RED}⚠ 数据库超过 1GB，可能需要手动 VACUUM 缩小${NC}"
        fi
    fi
else
    echo -e "  ${GREEN}数据库文件不存在（新安装）${NC}"
fi

echo ""
echo -e "${BOLD}== 7. 检查磁盘空间 ==${NC}"
df -h "$DATA_DIR" "$INSTALL_DIR" 2>/dev/null

echo ""
echo -e "${BOLD}== 8. 检查 systemd 资源限制 ==${NC}"
if [ -f "/etc/systemd/system/$SERVICE.service" ]; then
    echo -e "  ${YELLOW}MemoryMax:$(grep MemoryMax /etc/systemd/system/$SERVICE.service | head -1 | awk '{print $1}')${NC}"
    echo -e "  ${YELLOW}GOMEMLIMIT:$(grep GOMEMLIMIT /etc/systemd/system/$SERVICE.service | head -1 | awk -F= '{print $2}')${NC}"
    
    # 检查 ProtectSystem 是否过于严格
    if grep -q "ProtectSystem=full" /etc/systemd/system/$SERVICE.service; then
        echo -e "  ${YELLOW}ProtectSystem=full 已启用（/var/log 等系统目录将只读）${NC}"
    fi
    RWP=$(grep ReadWritePaths /etc/systemd/system/$SERVICE.service | head -1)
    echo -e "  ${YELLOW}$RWP${NC}"
else
    echo -e "  ${RED}✗ systemd 服务文件不存在${NC}"
fi

echo ""
echo -e "${BOLD}== 9. 检查 Agent 进程内存使用 ==${NC}"
AGENT_PID=$(pgrep -f "serverguard-agent" | head -1)
if [ -n "$AGENT_PID" ]; then
    echo -e "  Agent PID: $AGENT_PID"
    ps -p "$AGENT_PID" -o pid,rss,vsz,%mem,%cpu,etime --no-headers 2>/dev/null
    RSS_KB=$(ps -p "$AGENT_PID" -o rss --no-headers 2>/dev/null | tr -d ' ')
    if [ -n "$RSS_KB" ]; then
        RSS_MB=$((RSS_KB / 1024))
        echo -e "  实际内存使用: ${RSS_MB}MB"
    fi
else
    echo -e "  ${RED}✗ Agent 进程不存在${NC}"
fi

echo ""
echo "=========================================="
echo -e "${BOLD}诊断完成。${NC}"
echo ""
echo -e "${YELLOW}常见 502 原因：${NC}"
echo -e "  1. Agent 进程崩溃 → 检查上方日志中的 panic/error"
echo -e "  2. 密码/jwt_secret 是弱值 → Agent 拒绝启动（fail-closed安全校验）"
echo -e "  3. Nginx 反代端口与 Agent 监听端口不匹配"
echo -e "  4. 数据库过大导致启动时 VACUUM 阻塞或 OOM"
echo -e "  5. systemd MemoryMax 太小导致 OOM Kill"
echo ""
echo -e "${YELLOW}修复命令：${NC}"
echo -e "  ${CYAN}# 查看详细日志${NC}"
echo -e "  journalctl -u $SERVICE -f"
echo ""
echo -e "  ${CYAN}# 重启 Agent${NC}"
echo -e "  systemctl restart $SERVICE"
echo ""
echo -e "  ${CYAN}# 手动修改密码/jwt_secret（使用强随机值）${NC}"
echo -e "  JWT=\$(openssl rand -hex 32)"
echo -e "  PASS=\$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)"
echo -e "  sed -i \"s/password:.*/password: \\\"\$PASS\\\"/\" $CONFIG_FILE"
echo -e "  sed -i \"s/jwt_secret:.*/jwt_secret: \\\"\$JWT\\\"/\" $CONFIG_FILE"
echo -e "  systemctl restart $SERVICE"
echo ""
echo -e "  ${CYAN}# 如果数据库过大（>1GB），手动 VACUUM${NC}"
echo -e "  systemctl stop $SERVICE"
echo -e "  sqlite3 $DATA_DIR/serverguard.db 'VACUUM;'"
echo -e "  systemctl start $SERVICE"
echo ""
