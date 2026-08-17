#!/bin/bash
# ServerGuard 一键发布脚本
# 作用：把本地 dist/ 下的三平台 agent 二进制上传到官网版本中心，
#       上传后所有 Agent 将在下一个检查周期自动检测到更新。
#
# 前置：先运行 make-release.ps1（会生成 dist/serverguard-agent-* 裸二进制）
#
# 用法：
#   bash deploy/seed-release.sh                       # 交互式（询问版本号/账号密码）
#   bash deploy/seed-release.sh 0.1.0                 # 指定版本号
#   SG_ADMIN_USER=admin SG_ADMIN_PASS=xxx bash deploy/seed-release.sh 0.1.0
#
# 可选环境变量：
#   SG_SITE         官网地址（默认 https://sg.jjtt.net）
#   SG_ADMIN_USER   后台账号（默认 admin）
#   SG_ADMIN_PASS   后台密码（不设置则交互询问）
#   SG_CHANNEL      发布渠道（默认 stable）
#   SG_CRITICAL     是否关键更新 true/false（默认 false）
#   SG_NOTES        更新说明（默认自动生成）

set -e

SITE="${SG_SITE:-https://sg.jjtt.net}"
CHANNEL="${SG_CHANNEL:-stable}"
CRITICAL="${SG_CRITICAL:-false}"
VERSION="$1"

# 定位项目根目录（脚本在 deploy/ 下）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"

echo ""
echo "=========================================="
echo "  ServerGuard 版本发布"
echo "=========================================="
echo "  官网:   $SITE"
echo "  渠道:   $CHANNEL"
echo ""

# 1. 版本号
if [ -z "$VERSION" ]; then
    read -p "  发布版本号（如 0.1.0）: " VERSION
fi
if [ -z "$VERSION" ]; then
    echo "  ❌ 版本号不能为空"
    exit 1
fi
VERSION="${VERSION#v}"
echo "  版本:   v$VERSION"
echo ""

# 2. 检查二进制
declare -A FILES=(
    ["linux/amd64"]="$DIST_DIR/serverguard-agent-linux-amd64"
    ["linux/arm64"]="$DIST_DIR/serverguard-agent-linux-arm64"
    ["windows/amd64"]="$DIST_DIR/serverguard-agent-windows-amd64.exe"
)

MISSING=0
for key in "${!FILES[@]}"; do
    f="${FILES[$key]}"
    if [ -f "$f" ]; then
        SIZE=$(du -h "$f" | cut -f1)
        echo "  ✅ $key  $SIZE  $(basename "$f")"
    else
        echo "  ⚠️  $key  缺失: $f（该平台将跳过）"
        MISSING=$((MISSING+1))
    fi
done
if [ "$MISSING" -eq 3 ]; then
    echo ""
    echo "  ❌ 三个平台的二进制都缺失，请先运行 make-release.ps1"
    exit 1
fi
echo ""

# 3. 登录官网后台
USER="${SG_ADMIN_USER:-admin}"
if [ -z "$SG_ADMIN_PASS" ]; then
    read -s -p "  后台密码（账号 $USER）: " SG_ADMIN_PASS
    echo ""
fi

echo "  正在登录 $SITE ..."
LOGIN_RESP=$(curl -sS --connect-timeout 10 -X POST "$SITE/api/v1/admin/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"password\":\"$SG_ADMIN_PASS\"}" 2>/dev/null || echo "")

TOKEN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
    echo "  ❌ 登录失败，响应: $LOGIN_RESP"
    exit 1
fi
echo "  ✅ 登录成功"
echo ""

# 4. 更新说明
NOTES="${SG_NOTES:-ServerGuard v$VERSION 例行更新。详见 https://sg.jjtt.net/blog}"

# 5. 逐平台上传
SUCCESS=0
FAILED=0
for key in linux/amd64 linux/arm64 windows/amd64; do
    f="${FILES[$key]}"
    [ -f "$f" ] || continue
    OS_NAME="${key%/*}"
    ARCH_NAME="${key#*/}"

    echo "  上传 v$VERSION ($OS_NAME/$ARCH_NAME) ..."
    RESP=$(curl -sS --connect-timeout 15 -X POST "$SITE/api/v1/admin/versions" \
        -H "Authorization: Bearer $TOKEN" \
        -F "version=$VERSION" \
        -F "channel=$CHANNEL" \
        -F "os=$OS_NAME" \
        -F "arch=$ARCH_NAME" \
        -F "critical=$CRITICAL" \
        -F "release_notes=$NOTES" \
        -F "file=@$f" 2>/dev/null || echo "")

    if echo "$RESP" | grep -q '"sha256"'; then
        SHA=$(echo "$RESP" | grep -o '"sha256":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo "  ✅ $OS_NAME/$ARCH_NAME 发布成功  sha256:${SHA:0:16}..."
        SUCCESS=$((SUCCESS+1))
    else
        echo "  ❌ $OS_NAME/$ARCH_NAME 发布失败: $RESP"
        FAILED=$((FAILED+1))
    fi
done

echo ""
echo "=========================================="
if [ "$FAILED" -eq 0 ]; then
    echo "  发布完成！成功 $SUCCESS 个平台"
else
    echo "  发布结束：成功 $SUCCESS，失败 $FAILED"
fi
echo "=========================================="
echo ""

# 6. 验证 /latest 已生效
echo "  验证 Agent 更新检查接口:"
for key in linux/amd64 linux/arm64 windows/amd64; do
    f="${FILES[$key]}"
    [ -f "$f" ] || continue
    OS_NAME="${key%/*}"
    ARCH_NAME="${key#*/}"
    LATEST=$(curl -sS --connect-timeout 10 "$SITE/api/v1/latest?channel=$CHANNEL&os=$OS_NAME&arch=$ARCH_NAME" 2>/dev/null || echo "")
    LVER=$(echo "$LATEST" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo "    $OS_NAME/$ARCH_NAME -> latest = v$LVER"
done
echo ""
echo "  Agent 将在下一个检查周期（默认 6h）自动升级。"
echo "  手动下载页: $SITE/download"
echo ""
