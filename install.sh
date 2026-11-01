#!/bin/sh
# jwtcanary 一键安装：下载单文件到 /usr/local/bin（或 PREFIX 指定的目录）
set -e
REPO_RAW="https://gcore.jsdelivr.net/gh/tomlen045/jwtcanary@main/jwtcanary.py"
PREFIX="${PREFIX:-/usr/local/bin}"

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { echo "curl or wget required"; exit 1; }

mkdir -p "$PREFIX" 2>/dev/null || { echo "cannot write $PREFIX, try: sudo $0 or PREFIX=\$HOME/bin $0"; exit 1; }

echo "-> download jwtcanary.py ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$REPO_RAW" -o "$PREFIX/jwtcanary"
else
  wget -qO "$PREFIX/jwtcanary" "$REPO_RAW"
fi
chmod +x "$PREFIX/jwtcanary"

echo "-> verify ..."
python3 "$PREFIX/jwtcanary" --help >/dev/null && echo "ok"

echo
echo "installed: jwtcanary --help"
echo "first run: jwtcanary --target https://your-api/protected-path --rs256-jwks-url https://your-sso/certs"
