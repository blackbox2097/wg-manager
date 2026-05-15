#!/bin/bash
# WireGuard Manager - Install & Run Script
# Run as root or with sudo

set -e

INSTALL_DIR="/opt/wg-manager"
SERVICE_NAME="wg-manager"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/wireguard/${WG_INTERFACE}.conf}"
LISTEN_PORT="${WG_MANAGER_PORT:-5000}"
SECRET_FILE="/etc/wg-manager.secret"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  WireGuard Manager — Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check root
if [[ $EUID -ne 0 ]]; then
  echo "✕ Please run as root or with sudo"
  exit 1
fi

# Check dependencies
for dep in python3 pip3 wg wg-quick; do
  if ! command -v $dep &>/dev/null; then
    echo "Installing $dep..."
    apt-get install -y wireguard python3-pip 2>/dev/null || true
  fi
done

# Ensure iptables is available (may be missing on nftables-only systems)
if ! command -v iptables &>/dev/null; then
  echo "iptables not found — installing iptables-nft..."
  apt-get install -y iptables 2>/dev/null || true
  if ! command -v iptables &>/dev/null; then
    echo "⚠ Warning: iptables could not be installed. Firewall rules may not work."
  else
    echo "✓ iptables installed"
  fi
fi

# Enable IP forwarding (required for VPN routing)
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "✓ IP forwarding enabled"

# Create install dir
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static"

# Copy files — local if running from repo clone, download if piped from GitHub
REPO="blackbox2097/wg-manager"
BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

if [[ -f app.py ]]; then
  cp app.py "$INSTALL_DIR/"
else
  curl -fsSL "${RAW_BASE}/app.py" -o "$INSTALL_DIR/app.py"
fi

if [[ -f requirements.txt ]]; then
  cp requirements.txt "$INSTALL_DIR/"
else
  curl -fsSL "${RAW_BASE}/requirements.txt" -o "$INSTALL_DIR/requirements.txt"
fi

if [[ -f gunicorn_config.py ]]; then
  cp gunicorn_config.py "$INSTALL_DIR/"
else
  curl -fsSL "${RAW_BASE}/gunicorn_config.py" -o "$INSTALL_DIR/gunicorn_config.py"
fi

if [[ -f templates/index.html ]]; then
  cp templates/index.html "$INSTALL_DIR/templates/"
else
  curl -fsSL "${RAW_BASE}/templates/index.html" -o "$INSTALL_DIR/templates/index.html"
fi

# Install Python deps u virtualenv
apt-get install -y python3-venv python3-full --quiet 2>/dev/null || true
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
"$INSTALL_DIR/venv/bin/pip" install gunicorn --quiet

# AppArmor wg-quick local override (Ubuntu 25.10+)
# Keeps AppArmor active but allows bash for PostUp/PostDown scripts
if [[ -f /etc/apparmor.d/wg-quick ]]; then
  echo "Detected AppArmor wg-quick profile — applying local override..."
  mkdir -p /etc/apparmor.d/local
  cat > /etc/apparmor.d/local/wg-quick << 'AAEOF'
# WG Manager: allow bash for PostUp/PostDown firewall scripts
/{usr/,}bin/bash ix,
/etc/wireguard/wg-manager-*.sh r,
AAEOF
  apparmor_parser -r /etc/apparmor.d/wg-quick 2>/dev/null || true
  echo "✓ AppArmor wg-quick override applied"
fi

# Generate or reuse JWT secret
if [[ -f "$SECRET_FILE" ]]; then
  JWT_SECRET=$(cat "$SECRET_FILE")
  echo "✓ Reusing existing JWT secret from $SECRET_FILE"
else
  JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  echo "$JWT_SECRET" > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
  echo "✓ Generated new JWT secret → $SECRET_FILE"
fi

# Create systemd service
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
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn app:app -c ${INSTALL_DIR}/gunicorn_config.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
# Explicit capabilities (required on Ubuntu 26+ with stricter systemd 259)
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SERVICE_NAME}

echo ""
echo "✓ WireGuard Manager installed and started!"
echo ""
echo "  ► Web UI: http://$(hostname -I | awk '{print $1}'):${LISTEN_PORT}"
echo "  ► Service: systemctl status ${SERVICE_NAME}"
echo "  ► Logs:    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "  Interface: ${WG_INTERFACE}"
echo "  Config:    ${WG_CONFIG_PATH}"
echo "  Secret:    ${SECRET_FILE} (keep safe!)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"