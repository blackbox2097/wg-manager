#!/bin/bash
# WireGuard Manager — Installer
# Pulls latest files directly from GitHub
#
# Quick install:
#   bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/wg-manager/main/install.sh)
#
# With options:
#   WG_INTERFACE=wg1 WG_MANAGER_PORT=8080 bash <(curl -fsSL ...)

set -e

REPO="blackbox2097/wg-manager"
BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

INSTALL_DIR="/opt/wg-manager"
SERVICE_NAME="wg-manager"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/wireguard/${WG_INTERFACE}.conf}"
LISTEN_PORT="${WG_MANAGER_PORT:-5000}"
SECRET_FILE="/etc/wg-manager.secret"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  WireGuard Manager — Installer"
echo "  Repo: https://github.com/${REPO}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "✕ Please run as root or with sudo"
  exit 1
fi

# ── Dependencies ─────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y --quiet curl wireguard iptables python3 python3-pip python3-venv python3-full 2>/dev/null || true

# Ensure iptables is available (nftables-only systems)
if ! command -v iptables &>/dev/null; then
  apt-get install -y iptables 2>/dev/null || true
fi

# ── WireGuard kernel module ──────────────────────────────────────────────────
modprobe wireguard 2>/dev/null || true
if ! lsmod | grep -q wireguard 2>/dev/null; then
  echo "⚠ Warning: WireGuard kernel module not loaded — install wireguard-dkms if needed"
fi

# ── IPv4 forwarding ───────────────────────────────────────────────────────────
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "✓ IPv4 forwarding enabled"

# ── Download application files from GitHub ───────────────────────────────────
echo "→ Downloading from github.com/${REPO} (${BRANCH})..."

mkdir -p "${INSTALL_DIR}/templates" "${INSTALL_DIR}/static"

curl -fsSL "${RAW_BASE}/app.py"              -o "${INSTALL_DIR}/app.py"
curl -fsSL "${RAW_BASE}/requirements.txt"    -o "${INSTALL_DIR}/requirements.txt"
curl -fsSL "${RAW_BASE}/templates/index.html" -o "${INSTALL_DIR}/templates/index.html"

echo "✓ Files downloaded"

# ── Python virtualenv + dependencies ─────────────────────────────────────────
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet
echo "✓ Python dependencies installed"

# ── JWT secret ────────────────────────────────────────────────────────────────
if [[ -f "$SECRET_FILE" ]]; then
  JWT_SECRET=$(cat "$SECRET_FILE")
  echo "✓ Reusing existing JWT secret from $SECRET_FILE"
else
  JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  echo "$JWT_SECRET" > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
  echo "✓ Generated new JWT secret → $SECRET_FILE"
fi

# ── Systemd service ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=WireGuard Manager Web UI
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="WG_INTERFACE=${WG_INTERFACE}"
Environment="WG_CONFIG_PATH=${WG_CONFIG_PATH}"
Environment="JWT_SECRET_KEY=${JWT_SECRET}"
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SERVICE_NAME}

echo ""
echo "✓ WireGuard Manager installed and started!"
echo ""
echo "  ► Web UI:  http://$(hostname -I | awk '{print $1}'):${LISTEN_PORT}"
echo "  ► Service: systemctl status ${SERVICE_NAME}"
echo "  ► Logs:    journalctl -u ${SERVICE_NAME} -f"
echo "  ► Update:  bash <(curl -fsSL ${RAW_BASE}/update.sh)"
echo ""
echo "  Interface: ${WG_INTERFACE}"
echo "  Config:    ${WG_CONFIG_PATH}"
echo "  Secret:    ${SECRET_FILE}  (keep safe!)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
