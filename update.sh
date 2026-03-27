#!/bin/bash
# WireGuard Manager — Updater
# Downloads latest app.py and index.html from GitHub, restarts service
#
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/blackbox2097/wg-manager/main/update.sh)

set -e

REPO="blackbox2097/wg-manager"
BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
INSTALL_DIR="/opt/wg-manager"
SERVICE_NAME="wg-manager"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  WireGuard Manager — Updater"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $EUID -ne 0 ]]; then
  echo "✕ Please run as root or with sudo"
  exit 1
fi

if [[ ! -d "$INSTALL_DIR" ]]; then
  echo "✕ Not installed. Run install.sh first."
  exit 1
fi

echo "→ Downloading latest files..."
curl -fsSL "${RAW_BASE}/app.py"               -o "${INSTALL_DIR}/app.py"
curl -fsSL "${RAW_BASE}/templates/index.html" -o "${INSTALL_DIR}/templates/index.html"
echo "✓ Files updated"

echo "→ Restarting service..."
systemctl restart "$SERVICE_NAME"
echo "✓ Service restarted"

echo ""
echo "✓ Update complete!"
echo "  ► Logs: journalctl -u ${SERVICE_NAME} -f"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
