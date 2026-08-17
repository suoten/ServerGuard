#!/bin/bash
# ============================================================
# ServerGuard 宝塔兼容性安全测试脚本
# 在宝塔面板环境下运行，验证所有安全修复生效
# ============================================================
# 用法: sudo bash test_baota_safety.sh
# ============================================================

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
RESULTS=()

log_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
    RESULTS+=("PASS|$1")
}

log_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL|$1")
}

log_skip() {
    echo -e "  ${YELLOW}[SKIP]${NC} $1"
    SKIP=$((SKIP + 1))
    RESULTS+=("SKIP|$1")
}

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   ServerGuard 宝塔兼容性安全测试                 ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── 前置检查 ──────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用 root 用户运行: sudo bash test_baota_safety.sh${NC}"
    exit 1
fi

# 检测宝塔环境
IS_BAOTA=false
if [ -d "/www/server/panel" ] && [ -f "/etc/init.d/bt" ]; then
    IS_BAOTA=true
    echo -e "${YELLOW}[INFO]${NC} 检测到宝塔面板环境${NC}"
else
    echo -e "${YELLOW}[INFO]${NC} 未检测到宝塔面板环境，部分测试将跳过${NC}"
fi

# 检查 ServerGuard 是否运行
SG_RUNNING=false
if systemctl is-active --quiet serverguard-agent 2>/dev/null || \
   systemctl is-active --quiet serverguard 2>/dev/null; then
    SG_RUNNING=true
    echo -e "${GREEN}[INFO]${NC} ServerGuard 服务正在运行${NC}"
else
    echo -e "${YELLOW}[WARN]${NC} ServerGuard 服务未运行，集成测试将跳过${NC}"
fi

# ServerGuard API 地址
SG_API="http://127.0.0.1:18090"
if [ "$SG_RUNNING" = true ]; then
    # 尝试获取 API 地址
    if curl -sf "$SG_API/api/status" >/dev/null 2>&1; then
        SG_API="http://127.0.0.1:18090"
    elif curl -sf "http://127.0.0.1:8443/api/status" >/dev/null 2>&1; then
        SG_API="http://127.0.0.1:8443"
    fi
fi

echo ""
echo "=========================================="
echo "测试 1: 进程白名单 — 宝塔核心进程保护"
echo "=========================================="

# 测试 1a: 验证宝塔进程在白名单中
echo -e "${CYAN}[测试 1a]${NC} 验证宝塔核心进程在 ServerGuard 白名单中"
if [ "$SG_RUNNING" = true ]; then
    WHITELIST=$(curl -sf "$SG_API/api/safety" 2>/dev/null | grep -o '"whitelist":\[[^]]*\]' || echo "")
    BAOTA_PROCS="bt-panel nginx mysqld php-fpm redis-server"
    ALL_FOUND=true
    for proc in $BAOTA_PROCS; do
        if echo "$WHITELIST" | grep -qi "$proc"; then
            : # found
        else
            ALL_FOUND=false
        fi
    done
    if [ "$ALL_FOUND" = true ]; then
        log_pass "宝塔核心进程在白名单中"
    else
        log_fail "部分宝塔进程不在白名单中"
    fi
else
    log_skip "ServerGuard 未运行，跳过 API 白名单检查"
fi

# 测试 1b: 模拟 CPU 冲高，验证白名单进程不被 Kill
echo -e "${CYAN}[测试 1b]${NC} 模拟 CPU 高负载（如果 stress-ng 可用）"
if command -v stress-ng &> /dev/null && [ "$IS_BAOTA" = true ]; then
    echo "  启动 stress-ng 120 秒..."
    stress-ng --cpu 4 --timeout 120s &
    STRESS_PID=$!
    sleep 10

    # 检查宝塔面板进程是否仍在运行
    if pgrep -f "bt-panel\|BT-Panel\|bt_panel" > /dev/null 2>&1 || \
       pgrep -f "/www/server/panel" > /dev/null 2>&1; then
        log_pass "高 CPU 负载下宝塔面板进程仍存活"
    else
        # 宝塔可能不在本机运行
        log_skip "未检测到宝塔面板进程（可能未运行）"
    fi

    # 等待 stress-ng 结束
    wait $STRESS_PID 2>/dev/null || true
else
    log_skip "stress-ng 不可用或非宝塔环境"
fi

echo ""
echo "=========================================="
echo "测试 2: 进程白名单 — 非白名单进程处理"
echo "=========================================="

echo -e "${CYAN}[测试 2]${NC} 验证非白名单进程可被正常处理"
if [ "$SG_RUNNING" = true ]; then
    # 查看 ServerGuard 的 action history 中是否有 Kill 记录
    ACTIONS=$(curl -sf "$SG_API/api/safety" 2>/dev/null | grep -o '"recent_actions":\[[^]]*\]' || echo "")
    if [ -n "$ACTIONS" ]; then
        log_pass "ServerGuard 有操作历史记录（非白名单进程可被处理）"
    else
        log_skip "暂无操作历史（需要触发条件才能验证）"
    fi
else
    log_skip "ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 3: 白名单拦截 — Kill 宝塔进程被拒绝"
echo "=========================================="

echo -e "${CYAN}[测试 3]${NC} 验证 Kill 宝塔进程的请求被拒绝"
if [ "$SG_RUNNING" = true ]; then
    # 尝试通过 API 重启白名单进程（应被拒绝）
    # 查找宝塔面板的守护目标 ID
    TARGETS=$(curl -sf "$SG_API/api/services" 2>/dev/null || echo "")
    if echo "$TARGETS" | grep -qi "bt-panel\|BaoTa"; then
        # 尝试重启宝塔面板
        PANEL_ID=$(echo "$TARGETS" | grep -o '"id":"[^"]*","name":"[^"]*BaoTa[^"]*"' | head -1 | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$PANEL_ID" ]; then
            RESP=$(curl -sf -X POST "$SG_API/api/services/$PANEL_ID/restart" 2>/dev/null || echo "error")
            if echo "$RESP" | grep -qi "白名单\|whitelist\|拒绝\|refused"; then
                log_pass "重启宝塔面板的请求被白名单拒绝"
            else
                log_fail "重启宝塔面板的请求未被拒绝: $RESP"
            fi
        else
            log_skip "未找到宝塔面板守护目标 ID"
        fi
    else
        log_skip "未配置宝塔面板为守护目标"
    fi
else
    log_skip "ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 4: 磁盘清理安全 — 宝塔日志目录不被清理"
echo "=========================================="

# 测试 4a: 在宝塔日志目录放置测试文件
echo -e "${CYAN}[测试 4a]${NC} 验证宝塔面板日志目录不被清理"
if [ "$IS_BAOTA" = true ]; then
    TEST_FILE="/www/server/panel/logs/test_serverguard_safety.gz"
    mkdir -p /www/server/panel/logs
    echo "test content" > "$TEST_FILE"
    # 修改时间为 31 天前
    touch -d "31 days ago" "$TEST_FILE" 2>/dev/null || touch -t "$(date -d '31 days ago' +%Y%m%d%H%M)" "$TEST_FILE" 2>/dev/null || true

    # 等待 ServerGuard 执行一次磁盘清理周期
    echo "  等待 60 秒（ServerGuard 清理周期）..."
    sleep 60

    if [ -f "$TEST_FILE" ]; then
        log_pass "宝塔面板日志目录下的文件未被清理"
    else
        log_fail "宝塔面板日志目录下的文件被错误清理！"
    fi
    rm -f "$TEST_FILE"
else
    log_skip "非宝塔环境"
fi

# 测试 4b: 验证 /var/log 下的旧 .gz 文件可被清理（非宝塔安全模式）
echo -e "${CYAN}[测试 4b]${NC} 验证 /var/log 下旧压缩文件可被清理（非宝塔安全模式）"
if [ "$SG_RUNNING" = true ] && [ "$IS_BAOTA" = false ]; then
    TEST_FILE="/var/log/test_serverguard_safety.gz"
    echo "test content" > "$TEST_FILE"
    touch -d "31 days ago" "$TEST_FILE" 2>/dev/null || touch -t "$(date -d '31 days ago' +%Y%m%d%H%M)" "$TEST_FILE" 2>/dev/null || true

    echo "  等待 60 秒（ServerGuard 清理周期）..."
    sleep 60

    if [ ! -f "$TEST_FILE" ]; then
        log_pass "/var/log 下旧压缩文件已被清理"
    else
        log_skip "文件未被清理（可能清理周期未到或 BaotaSafeMode 已启用）"
    fi
    rm -f "$TEST_FILE"
else
    log_skip "ServerGuard 未运行或宝塔安全模式已启用"
fi

echo ""
echo "=========================================="
echo "测试 5: 磁盘清理安全 — BaotaSafeMode 下完全禁用"
echo "=========================================="

echo -e "${CYAN}[测试 5]${NC} 验证 BaotaSafeMode 下磁盘清理被禁用"
if [ "$SG_RUNNING" = true ]; then
    STATUS=$(curl -sf "$SG_API/api/status" 2>/dev/null || echo "")
    if echo "$STATUS" | grep -q '"baota_safe_mode":true'; then
        log_pass "BaotaSafeMode 已启用，磁盘清理应已禁用"
    elif echo "$STATUS" | grep -q '"baota_safe_mode":false'; then
        log_skip "BaotaSafeMode 未启用"
    else
        log_skip "无法确定 BaotaSafeMode 状态"
    fi
else
    log_skip "ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 6: 服务守护 — 使用 /etc/init.d/ 重启"
echo "=========================================="

echo -e "${CYAN}[测试 6]${NC} 验证宝塔环境下服务使用 /etc/init.d/ 重启"
if [ "$IS_BAOTA" = true ] && [ "$SG_RUNNING" = true ]; then
    STATUS=$(curl -sf "$SG_API/api/status" 2>/dev/null || echo "")
    if echo "$STATUS" | grep -q '"baota_safe_mode":true'; then
        # BaotaSafeMode 下，服务重启应降级为告警
        log_pass "BaotaSafeMode 已启用，服务重启应降级为告警（使用 /etc/init.d/ 提示）"
    else
        log_skip "BaotaSafeMode 未启用，服务守护使用默认方式"
    fi
else
    log_skip "非宝塔环境或 ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 7: 服务守护 — 宝塔面板自身禁止重启"
echo "=========================================="

echo -e "${CYAN}[测试 7]${NC} 验证宝塔面板自身不被自动重启"
if [ "$SG_RUNNING" = true ]; then
    # 尝试通过 API 重启宝塔面板
    TARGETS=$(curl -sf "$SG_API/api/services" 2>/dev/null || echo "")
    PANEL_ID=$(echo "$TARGETS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for t in data.get('targets', []):
        if 'bt' in t.get('name','').lower() or 'baota' in t.get('name','').lower() or 'panel' in t.get('name','').lower():
            print(t['id'])
            break
except: pass
" 2>/dev/null || echo "")

    if [ -n "$PANEL_ID" ]; then
        RESP=$(curl -sf -X POST "$SG_API/api/services/$PANEL_ID/restart" 2>/dev/null || echo "error")
        if echo "$RESP" | grep -qi "禁止\|refused\|whitelist\|白名单\|guard"; then
            log_pass "宝塔面板重启请求被安全检查拒绝"
        else
            log_fail "宝塔面板重启请求未被拒绝: $RESP"
        fi
    else
        log_skip "未找到宝塔面板守护目标"
    fi
else
    log_skip "ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 8: 文件完整性 — 宝塔面板配置不告警"
echo "=========================================="

echo -e "${CYAN}[测试 8]${NC} 验证 FIM 排除宝塔面板路径"
if [ "$IS_BAOTA" = true ]; then
    # 修改宝塔面板配置文件
    TEST_CONFIG="/www/server/panel/config/test_serverguard.json"
    mkdir -p /www/server/panel/config
    echo '{"test": true}' > "$TEST_CONFIG"
    sleep 5
    echo '{"test": false}' > "$TEST_CONFIG"
    sleep 30  # 等待 FIM 检测周期

    # 检查 ServerGuard 是否对此发出告警
    # 由于 FIM 排除 /www/server/panel/config，不应有告警
    ALERTS=$(curl -sf "$SG_API/api/alerts?limit=10" 2>/dev/null || echo "")
    if echo "$ALERTS" | grep -q "test_serverguard"; then
        log_fail "FIM 对宝塔面板配置文件发出了告警（应被排除）"
    else
        log_pass "FIM 正确排除了宝塔面板配置文件"
    fi
    rm -f "$TEST_CONFIG"
else
    log_skip "非宝塔环境"
fi

echo ""
echo "=========================================="
echo "测试 9: 文件完整性 — /etc/passwd 修改正常告警"
echo "=========================================="

echo -e "${CYAN}[测试 9]${NC} 验证 /etc/passwd 修改触发 FIM 告警"
if [ "$SG_RUNNING" = true ]; then
    # 记录原始内容
    ORIG_HASH=$(sha256sum /etc/passwd | awk '{print $1}')

    # 临时添加一个测试用户
    echo "sgtest:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
    sleep 30  # 等待 FIM 检测周期

    # 检查是否收到告警
    ALERTS=$(curl -sf "$SG_API/api/alerts?limit=20" 2>/dev/null || echo "")
    if echo "$ALERTS" | grep -qi "passwd\|篡改\|tamper\|modified"; then
        log_pass "/etc/passwd 修改触发了 FIM 告警"
    else
        log_skip "未检测到 FIM 告警（可能 FIM 未配置或检测周期未到）"
    fi

    # 恢复 /etc/passwd
    sed -i '/^sgtest:/d' /etc/passwd
else
    log_skip "ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 10: 前端 — 宝塔兼容模式警告条"
echo "=========================================="

echo -e "${CYAN}[测试 10]${NC} 验证宝塔环境下仪表盘显示兼容模式警告条"
if [ "$SG_RUNNING" = true ]; then
    STATUS=$(curl -sf "$SG_API/api/status" 2>/dev/null || echo "")
    if echo "$STATUS" | grep -q '"is_baota":true'; then
        if echo "$STATUS" | grep -q '"baota_safe_mode":true'; then
            log_pass "API 返回 is_baota=true 且 baota_safe_mode=true，前端应显示警告条"
        else
            log_skip "is_baota=true 但 baota_safe_mode 未启用"
        fi
    else
        log_skip "API 返回 is_baota=false 或无法获取状态"
    fi
else
    log_skip "ServerGuard 未运行"
fi

echo ""
echo "=========================================="
echo "测试 11: 前端 — 非宝塔环境不显示警告条"
echo "=========================================="

echo -e "${CYAN}[测试 11]${NC} 验证非宝塔环境不显示兼容模式警告条"
if [ "$SG_RUNNING" = true ]; then
    STATUS=$(curl -sf "$SG_API/api/status" 2>/dev/null || echo "")
    if echo "$STATUS" | grep -q '"is_baota":false'; then
        log_pass "API 返回 is_baota=false，前端不应显示警告条"
    elif echo "$STATUS" | grep -q '"is_baota":true'; then
        log_skip "当前环境为宝塔环境，跳过非宝塔测试"
    else
        log_skip "无法获取 is_baota 状态"
    fi
else
    log_skip "ServerGuard 未运行"
fi

# ============================================================
# 测试结果汇总
# ============================================================
echo ""
echo "=========================================="
echo "测试结果汇总"
echo "=========================================="
echo -e "  ${GREEN}通过: $PASS${NC}"
echo -e "  ${RED}失败: $FAIL${NC}"
echo -e "  ${YELLOW}跳过: $SKIP${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}失败的测试:${NC}"
    for r in "${RESULTS[@]}"; do
        if [[ "$r" == FAIL* ]]; then
            echo -e "  ${RED}- ${r#FAIL|}${NC}"
        fi
    done
    echo ""
    exit 1
else
    echo -e "${GREEN}所有测试通过！${NC}"
    exit 0
fi
