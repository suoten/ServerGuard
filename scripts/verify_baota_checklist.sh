#!/bin/bash
# ============================================================
# ServerGuard 宝塔兼容性修复 — 关键修复检查清单验证脚本
# 自动化验证所有修复项是否到位
# ============================================================
# 用法: bash verify_baota_checklist.sh
# ============================================================

set -uo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local desc="$1"
    local condition="$2"
    if [ "$condition" = "true" ]; then
        echo -e "  ${GREEN}[✓]${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[✗]${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  宝塔兼容性修复 — 关键检查清单验证              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# 获取项目根目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "项目根目录: $PROJECT_ROOT"
echo ""

# ============================================================
# 1. 进程白名单
# ============================================================
echo -e "${YELLOW}━━━ 进程白名单 ━━━${NC}"

# 检查 bt-task 在白名单中
check "bt-task 在进程白名单中" \
    "$(grep -c 'bt-task' "$PROJECT_ROOT/internal/agent/safety/baota_whitelist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 php-fpm 全版本
PHP_FPM_COUNT=$(grep -c 'php-fpm-' "$PROJECT_ROOT/internal/agent/safety/baota_whitelist.go" 2>/dev/null || echo 0)
check "php-fpm 全版本（52-83）在白名单中" \
    "$([ "$PHP_FPM_COUNT" -ge 16 ] && echo true || echo false)"

# 检查 python 二次确认逻辑
check "python 进程需要二次确认宝塔路径" \
    "$(grep -c 'pythonConfirmNames' "$PROJECT_ROOT/internal/agent/safety/baota_whitelist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 baotaPathMarkers
check "python 二次确认包含宝塔路径标记" \
    "$(grep -c 'baotaPathMarkers' "$PROJECT_ROOT/internal/agent/safety/baota_whitelist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 2. 环境感知
# ============================================================
echo -e "${YELLOW}━━━ 环境感知 ━━━${NC}"

# 检查宝塔环境检测
check "自动检测宝塔环境（/www/server/panel + /etc/init.d/bt）" \
    "$([ -f "$PROJECT_ROOT/internal/baota/baota.go" ] && grep -q '/www/server/panel' "$PROJECT_ROOT/internal/baota/baota.go" && echo true || echo false)"

# 检查 install.sh 中的宝塔检测
check "install.sh 检测宝塔环境" \
    "$(grep -c 'IS_BAOTA' "$PROJECT_ROOT/deploy/install.sh" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

check "scripts/install.sh 检测宝塔环境" \
    "$(grep -c 'IS_BAOTA' "$PROJECT_ROOT/scripts/install.sh" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 3. 全局策略
# ============================================================
echo -e "${YELLOW}━━━ 全局策略 ━━━${NC}"

# 检查 BaotaSafeMode
check "BaotaSafeMode 实现存在" \
    "$(grep -c 'SetBaotaSafeMode\|IsBaotaSafeMode' "$PROJECT_ROOT/internal/agent/safety/safety.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 BaotaSafeMode 下 Kill 降级
check "BaotaSafeMode 下 Kill/Restart/Clean 降级为告警" \
    "$(grep -r 'IsBaotaSafeMode' "$PROJECT_ROOT/internal/" 2>/dev/null | grep -c '降级\|disabled\|alert\|告警' | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 4. 服务守护
# ============================================================
echo -e "${YELLOW}━━━ 服务守护 ━━━${NC}"

# 检查使用 /etc/init.d/ 重启
check "宝塔服务使用 /etc/init.d/xxx 重启" \
    "$(grep -c 'initScript\|/etc/init.d/' "$PROJECT_ROOT/internal/agent/safety/restart_guard.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查禁用 systemctl
check "宝塔环境下禁用 systemctl restart" \
    "$(grep -c 'BaotaManagedServices' "$PROJECT_ROOT/internal/agent/safety/restart_guard.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查宝塔面板自身禁止重启
check "宝塔面板自身（bt-panel）禁止自动重启" \
    "$(grep -c 'BaotaPanelServiceNames' "$PROJECT_ROOT/internal/agent/safety/restart_guard.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 5. 磁盘清理
# ============================================================
echo -e "${YELLOW}━━━ 磁盘清理 ━━━${NC}"

# 检查 CleanupBlacklist
check "CleanupBlacklist 包含 /www/server/panel 等" \
    "$(grep -c 'CleanupBlacklist' "$PROJECT_ROOT/internal/agent/safety/path_blacklist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查黑名单包含宝塔路径
BLACKLIST_HAS_BAOTA=$(grep -A 20 'CleanupBlacklist' "$PROJECT_ROOT/internal/agent/safety/path_blacklist.go" 2>/dev/null | grep -c '/www/server/panel\|/www/wwwroot\|/www/backup' || echo 0)
check "黑名单包含宝塔核心目录" \
    "$([ "$BLACKLIST_HAS_BAOTA" -ge 3 ] && echo true || echo false)"

# 检查宝塔环境下完全禁用清理
check "宝塔环境下完全禁用自动清理" \
    "$(grep -r 'IsBaotaSafeMode' "$PROJECT_ROOT/internal/guards/resource/" 2>/dev/null | grep -c '磁盘清理已禁用\|disabled' | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 6. 日志轮转
# ============================================================
echo -e "${YELLOW}━━━ 日志轮转 ━━━${NC}"

# 检查 LogRotationExemptions
check "LogRotationExemptions 包含 /www 路径" \
    "$(grep -c 'LogRotationExemptions' "$PROJECT_ROOT/internal/agent/safety/path_blacklist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 BaotaSafeMode 下所有 /www/ 路径豁免
check "BaotaSafeMode 下所有 /www/ 路径日志轮转豁免" \
    "$(grep -c 'baotaSafeMode.*www' "$PROJECT_ROOT/internal/agent/safety/path_blacklist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 7. 文件完整性
# ============================================================
echo -e "${YELLOW}━━━ 文件完整性 ━━━${NC}"

# 检查 FIM 排除
check "FIM 排除 /www/server/panel 及子目录" \
    "$(grep -c 'FIMExclusions' "$PROJECT_ROOT/internal/agent/safety/path_blacklist.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 FIM 排除在 ConfigGuard 中使用
check "ConfigGuard 使用 FIM 排除列表" \
    "$(grep -c 'IsFIMExcluded' "$PROJECT_ROOT/internal/guards/config/config.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 8. WebShell 扫描
# ============================================================
echo -e "${YELLOW}━━━ WebShell 扫描 ━━━${NC}"

# 检查 WebShell 排除
check "WebShell 扫描排除宝塔自身代码目录" \
    "$(grep -c 'WebShellScanExclusions' "$PROJECT_ROOT/internal/guards/security/baota_exclusions.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查配置中的 webshell_exclusions
check "config.yaml 支持 webshell_exclusions 配置" \
    "$(grep -c 'WebShellExclusions' "$PROJECT_ROOT/internal/config/config.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 9. Cron 检测
# ============================================================
echo -e "${YELLOW}━━━ Cron 检测 ━━━${NC}"

# 检查 Cron 白名单
check "Cron 白名单包含宝塔计划任务路径和命令" \
    "$(grep -c 'CronWhitelistPatterns' "$PROJECT_ROOT/internal/guards/security/baota_exclusions.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查白名单包含 /www/server/panel/script/
check "Cron 白名单包含 /www/server/panel/script/" \
    "$(grep -c '/www/server/panel/script/' "$PROJECT_ROOT/internal/guards/security/baota_exclusions.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

echo ""

# ============================================================
# 10. 安装脚本
# ============================================================
echo -e "${YELLOW}━━━ 安装脚本 ━━━${NC}"

# 检查 install.sh 检测宝塔环境
check "install.sh 检测宝塔环境并输出兼容提示" \
    "$([ -f "$PROJECT_ROOT/deploy/install.sh" ] && grep -q 'IS_BAOTA' "$PROJECT_ROOT/deploy/install.sh" && grep -q '兼容模式' "$PROJECT_ROOT/deploy/install.sh" && echo true || echo false)"

# 检查 install.sh 不修改系统全局配置
check "install.sh 不修改 sysctl/limits.conf" \
    "$([ -f "$PROJECT_ROOT/deploy/install.sh" ] && ! grep -q 'sysctl\|limits.conf' "$PROJECT_ROOT/deploy/install.sh" && echo true || echo false)"

# 检查 install.sh 端口冲突检测
check "install.sh 包含端口冲突检测" \
    "$([ -f "$PROJECT_ROOT/deploy/install.sh" ] && grep -q 'ss.*tlnp\|netstat' "$PROJECT_ROOT/deploy/install.sh" && echo true || echo false)"

echo ""

# ============================================================
# 11. 卸载脚本
# ============================================================
echo -e "${YELLOW}━━━ 卸载脚本 ━━━${NC}"

# 检查 uninstall.sh 不删除宝塔目录
check "uninstall.sh 绝不删除宝塔目录" \
    "$([ -f "$PROJECT_ROOT/deploy/uninstall.sh" ] && ! grep -q 'rm.*www/server/panel' "$PROJECT_ROOT/deploy/uninstall.sh" && echo true || echo false)"

# 检查 uninstall.sh 宝塔环境检测
check "uninstall.sh 检测宝塔环境并保留配置" \
    "$([ -f "$PROJECT_ROOT/deploy/uninstall.sh" ] && grep -q 'www/server/panel' "$PROJECT_ROOT/deploy/uninstall.sh" && echo true || echo false)"

echo ""

# ============================================================
# 12. 前端
# ============================================================
echo -e "${YELLOW}━━━ 前端 ━━━${NC}"

# 检查仪表盘宝塔警告条
check "仪表盘显示宝塔兼容模式警告条" \
    "$([ -f "$PROJECT_ROOT/web/src/views/Dashboard.vue" ] && grep -q 'baota_safe_mode\|宝塔兼容模式' "$PROJECT_ROOT/web/src/views/Dashboard.vue" && echo true || echo false)"

# 检查安全控制页面宝塔设置
check "安全控制页面增加宝塔专项设置" \
    "$([ -f "$PROJECT_ROOT/web/src/views/Safety.vue" ] && grep -q 'baota\|宝塔' "$PROJECT_ROOT/web/src/views/Safety.vue" && echo true || echo false)"

echo ""

# ============================================================
# 13. 配置
# ============================================================
echo -e "${YELLOW}━━━ 配置 ━━━${NC}"

# 检查 config.yaml 增加 baota 配置节
check "config.yaml 增加 baota 配置节" \
    "$(grep -c 'BaotaConfig' "$PROJECT_ROOT/internal/config/config.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 BaotaConfig 字段
check "BaotaConfig 包含 safe_mode/panel_path/cleanup_scope 等字段" \
    "$(grep -c 'SafeMode\|PanelPath\|CleanupScope\|LogRotationScope' "$PROJECT_ROOT/internal/config/config.go" 2>/dev/null || echo 0 | grep -q '^0$' && echo false || echo true)"

# 检查 install.sh 生成 baota 配置
check "install.sh 生成 baota 配置段" \
    "$([ -f "$PROJECT_ROOT/deploy/install.sh" ] && grep -q 'baota:' "$PROJECT_ROOT/deploy/install.sh" && echo true || echo false)"

echo ""

# ============================================================
# 14. Go 单元测试
# ============================================================
echo -e "${YELLOW}━━━ Go 单元测试 ━━━${NC}"

# 检查测试文件存在
check "safety 包有宝塔兼容性测试文件" \
    "$([ -f "$PROJECT_ROOT/internal/agent/safety/baota_test.go" ] && echo true || echo false)"

# 检查 security 包有宝塔排除测试文件
check "security 包有宝塔排除测试文件" \
    "$([ -f "$PROJECT_ROOT/internal/guards/security/baota_exclusions_test.go" ] && echo true || echo false)"

# 检查测试函数数量
TEST_FUNC_COUNT=$(grep -c '^func Test' "$PROJECT_ROOT/internal/agent/safety/baota_test.go" 2>/dev/null || echo 0)
check "safety 测试文件包含 $TEST_FUNC_COUNT 个测试函数（应 ≥ 15）" \
    "$([ "$TEST_FUNC_COUNT" -ge 15 ] && echo true || echo false)"

SECURITY_TEST_COUNT=$(grep -c '^func Test' "$PROJECT_ROOT/internal/guards/security/baota_exclusions_test.go" 2>/dev/null || echo 0)
check "security 测试文件包含 $SECURITY_TEST_COUNT 个测试函数（应 ≥ 5）" \
    "$([ "$SECURITY_TEST_COUNT" -ge 5 ] && echo true || echo false)"

echo ""

# ============================================================
# 15. Bash 集成测试
# ============================================================
echo -e "${YELLOW}━━━ Bash 集成测试 ━━━${NC}"

check "宝塔安全集成测试脚本存在" \
    "$([ -f "$PROJECT_ROOT/scripts/test_baota_safety.sh" ] && echo true || echo false)"

echo ""

# ============================================================
# 汇总
# ============================================================
echo "=========================================="
echo -e "检查结果汇总"
echo "=========================================="
echo -e "  ${GREEN}通过: $PASS${NC}"
echo -e "  ${RED}失败: $FAIL${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}有 $FAIL 项检查未通过，请修复后重新验证${NC}"
    exit 1
else
    echo -e "${GREEN}所有检查项通过！${NC}"
    exit 0
fi
