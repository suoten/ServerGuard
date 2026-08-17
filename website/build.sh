#!/usr/bin/bash
# ServerGuard Website Build Script
# Builds frontend + backend into a single binary

set -e

echo "========================================="
echo "  Building ServerGuard Website"
echo "========================================="

# 1. Build frontend
echo ""
echo "[1/4] Building frontend..."
cd "$(dirname "$0")/frontend"
if [ ! -d "node_modules" ]; then
    echo "  Installing dependencies..."
    npm install
fi

echo "  Building with Vite..."
node "node_modules/vite/bin/vite.js" build

# 2. Copy frontend dist to backend
echo ""
echo "[2/4] Copying frontend dist to backend..."
cd "$(dirname "$0")"
rm -rf backend/dist/*
cp -r frontend/dist/* backend/dist/

# 3. Build backend (embeds frontend)
echo ""
echo "[3/4] Building backend (embedding frontend)..."
cd backend
BINARY_NAME="serverguard-web"
if [ "$1" == "windows" ]; then
    BINARY_NAME="serverguard-web.exe"
fi
go build -ldflags="-s -w" -o "$BINARY_NAME" .

# 4. Done
echo ""
echo "[4/4] Build complete!"
echo "  Binary: backend/$BINARY_NAME"
echo ""
echo "  To install: bash install.sh"
echo "  To run:    cd backend && ./serverguard-web"
echo "========================================="