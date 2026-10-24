#!/bin/bash
# ============================================================
# ServerGuard 502 深度诊断脚本
# 在服务器上运行：bash diagnose-502-deep.sh
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}=== ServerGuard 502 深度诊断 ===${NC}"
echo ""

# 1. 进程状态
echo -e "${BOLD}== 1. Agent 进程状态 ==${NC}"
systemctl status serverguard-agent --no-pager 2>/dev/null | head -10
echo ""

# 2. 端口监听
echo -e "${BOLD}== 2. 端口监听 ==${NC}"
ss -tlnp | grep -E "18090|serverguard" || echo "  (未找到监听)"
echo ""

# 3. 本机 API 测试（逐个测 Dashboard 调用的 7 个 API）
echo -e "${BOLD}== 3. 逐个测试 Dashboard 加载的 API ==${NC}"
APIS=(
    "/api/version"
    "/api/status"
    "/api/alerts"
    "/api/safety"
    "/api/guards"
    "/api/health/score"
    "/api/probe/sites"
    "/api/insights"
)

for api in "${APIS[@]}"; do
    # 先获取认证 token
    LOGIN_RESP=$(curl -s --max-time 5 -X POST http://127.0.0.1:18090/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"yGYdiH2BzNfxffDW"}' 2>/dev/null)
    TOKEN=$(echo "$LOGIN_RESP" | grep -oP '"token"\s*:\s*"\K[^"]+' || true)
    
    if [ -z "$TOKEN" ]; then
        echo -e "  ${RED}✗$api → 登录失败，无法测试${NC}"
        continue
    fi
    
    START=$(date +%s%N)
    HTTP_CODE=$(curl -s -o /tmp/sg_resp.json -w "%{http_code}" --max-time 30 \
        -H "Authorization: Bearer $TOKEN" \
        "http://127.0.0.1:18090$api" 2>/dev/null || echo "000")
    END=$(date +%s%N)
    ELAPSED=$(( (END - START) / 1000000 ))
    
    if [ "$HTTP_CODE" = "200" ]; then
        RESP_SIZE=$(wc -c < /tmp/sg_resp.json 2>/dev/null || echo "?")
        echo -e "  ${GREEN}✓$api → 200 (${ELAPSED}ms, ${RESP_SIZE} bytes)${NC}"
    else
        echo -e "  ${RED}✗$api → $HTTP_CODE (${ELAPSED}ms)${NC}"
        cat /tmp/sg_resp.json 2>/dev/null | head -5
    fi
done
echo ""

# 4. 测试静态资源（index.html）
echo -e "${BOLD}== 4. 测试静态资源 ==${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:18090/ 2>/dev/null)
echo -e "  / → $HTTP_CODE"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:18090/dashboard 2>/dev/null)
echo -e "  /dashboard → $HTTP_CODE"
echo ""

# 5. Nginx 反代配置详情
echo -e "${BOLD}== 5. Nginx 反代配置详情 ==${NC}"
NGINX_CONF_DIR="/www/server/panel/vhost/nginx/proxy/serverguard.jjtt.net"
if [ -d "$NGINX_CONF_DIR" ]; then
    echo -e "  ${YELLOW}反代配置文件内容：${NC}"
    cat "$NGINX_CONF_DIR"/*.conf 2>/dev/null
else
    echo -e "  ${YELLOW}反代配置目录不存在，搜索其他位置...${NC}"
    grep -rn "proxy_pass.*18090" /www/server/panel/vhost/nginx/ /etc/nginx/ 2>/dev/null
fi
echo ""

# 6. Nginx 主配置中的超时设置
echo -e "${BOLD}== 6. Nginx 超时相关配置 ==${NC}"
grep -rn "proxy_read_timeout\|proxy_connect_timeout\|proxy_send_timeout" \
    /www/server/panel/vhost/nginx/ /etc/nginx/ 2>/dev/null | head -20
echo ""

# 7. Agent 启动日志
echo -e "${BOLD}== 7. Agent 最近日志 ==${NC}"
journalctl -u serverguard-agent --since "10 min ago" --no-pager 2>/dev/null | tail -40
echo ""

# 8. 内存和资源
echo -e "${BOLD}== 8. 资源使用 ==${NC}"
free -h
echo ""
ps aux | grep serverguard | grep -v grep
echo ""

# 9. 检查 systemd 限制是否导致问题
echo -e "${BOLD}== 9. systemd 限制 ==${NC}"
systemctl show serverguard-agent 2>/dev/null | grep -E "MemoryMax|MemoryHigh|MemoryCurrent|CPUWeight|OOMScoreAdjust"
echo ""

# 10. 外网访问测试
echo -e "${BOLD}== 10. 外网访问测试 ==${NC}"
echo -e "  ${YELLOW}请从浏览器访问以下地址并报告结果：${NC}"
echo -e "  1. http://serverguard.jjtt.net/ (首页)"
echo -e "  2. http://serverguard.jjtt.net/api/version (API)"
echo -e "  3. http://serverguard.jjtt.net/dashboard (仪表盘)"
echo ""
echo -e "  ${YELLOW}如果 1 和 2 正常但 3 返回 502：${NC}"
echo -e "  可能是 Dashboard 的某个 API 请求太慢导致 Nginx 超时"
echo -e "  ${YELLOW}解决方法：在宝塔反代配置中增加超时设置：${NC}"
echo -e "  proxy_connect_timeout 60s;"
echo -e "  proxy_read_timeout 120s;"
echo -e "  proxy_send_timeout 60s;"
echo ""
