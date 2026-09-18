#!/usr/bin/env bash
# ============================================================
# ServerGuard Hub 告警风暴 502 事故 一键排查+修复脚本
# 事故：打开仪表盘后 hub 反复假死/OOM，nginx 502
# 根因：/api/alerts → GetUnresolvedAlerts() 无 LIMIT 全量加载
#       resolved=0 告警，告警堆积后拖垮整个进程
# 修复：① 缩表（7 天前未解决告警批量置已解决）
#       ② 替换带 LIMIT+索引 的修复版二进制并重启
# 用法：把本脚本和 serverguard-hub-linux-amd64-hotfix 放同一目录，bash 执行
# ============================================================
set -uo pipefail

# ===== 按实际环境修改这三项 =====
SERVICE="serverguard-hub"                  # systemd 服务名（systemctl list-units | grep serverguard 确认）
HUB_DIR="/opt/serverguard"                 # hub 安装目录（含 serverguard-hub 二进制）
DB="$HUB_DIR/data/serverguard.db"          # hub SQLite 库路径
# ================================

HOTFIX="./serverguard-hub-linux-amd64-hotfix"

echo "== 1. 事故现场取证（确认是否 OOM/重启循环）"
systemctl status "$SERVICE" --no-pager -l 2>/dev/null | head -15
echo "--- 近 2 小时服务日志中的异常 ---"
journalctl -u "$SERVICE" --since "2 hours ago" --no-pager 2>/dev/null | grep -iE "panic|fatal|killed|error" | tail -20
echo "--- 系统级 OOM 记录 ---"
dmesg -T 2>/dev/null | grep -iE "out of memory|oom.?kill" | tail -10

echo ""
echo "== 2. 资源与库文件体积"
free -h
df -h "$HUB_DIR"
ls -lh "$DB"* 2>/dev/null

echo ""
echo "== 3. 未解决告警数量（几十万+ 即为本次根因）"
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 "$DB" "SELECT COUNT(*) AS unresolved_before FROM alerts WHERE resolved=0;"
else
  echo "!! 系统无 sqlite3 命令，跳过统计（不影响后续步骤，新二进制带 LIMIT 可自愈）"
fi

echo ""
echo "== 4. 缩表：7 天前的未解决告警批量置为已解决（最近 7 天仍可在面板看到）"
if command -v sqlite3 >/dev/null 2>&1; then
  systemctl stop "$SERVICE"
  sqlite3 "$DB" "UPDATE alerts SET resolved=1, resolved_at=datetime('now') WHERE resolved=0 AND timestamp < datetime('now','-7 days');"
  sqlite3 "$DB" "SELECT COUNT(*) AS unresolved_after FROM alerts WHERE resolved=0;"
else
  echo "!! 无 sqlite3，跳过缩表，仅替换二进制（LIMIT 500 兜底，性能可接受但库体积不变）"
fi

echo ""
echo "== 5. 替换修复版二进制并重启"
if [ ! -f "$HOTFIX" ]; then
  echo "!! 当前目录找不到 $HOTFIX，请先上传后再跑本脚本"; exit 1
fi
systemctl stop "$SERVICE" 2>/dev/null
cp "$HUB_DIR/serverguard-hub" "$HUB_DIR/serverguard-hub.bak.$(date +%Y%m%d%H%M%S)"
cp "$HOTFIX" "$HUB_DIR/serverguard-hub"
chmod +x "$HUB_DIR/serverguard-hub"
systemctl start "$SERVICE"
sleep 3
systemctl status "$SERVICE" --no-pager | head -6

echo ""
echo "== 6. 验证面板（本机回环，端口按 nginx upstream 实际值调整）"
echo "curl -s http://127.0.0.1:<hub端口>/api/version  应返回 JSON 而非超时/502"
echo "完成。请再从外网访问 http://serverguard.jjtt.net/dashboard 验证仪表盘能否正常加载。"
