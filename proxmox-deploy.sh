#!/bin/bash
# WireGuard Manager — Proxmox LXC Deploy Script
# Run on Proxmox host as root:
#   bash proxmox-deploy.sh
# Or pull directly from GitHub:
#   bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/wg-manager/main/proxmox-deploy.sh)

set -e

# ════════════════════════════════════════════════════════════════════════════
# Configuration — edit these or leave defaults (script will prompt if needed)
# ════════════════════════════════════════════════════════════════════════════

CT_ID="${CT_ID:-}"                        # LXC ID (e.g. 200) — auto-picked if empty
CT_HOSTNAME="${CT_HOSTNAME:-wg-manager}"
CT_PASSWORD="${CT_PASSWORD:-}"            # root password — prompted if empty
CT_STORAGE="${CT_STORAGE:-}"              # storage for rootfs — prompted if empty
CT_DISK="${CT_DISK:-4}"                   # disk size in GB
CT_RAM="${CT_RAM:-512}"                   # RAM in MB
CT_CORES="${CT_CORES:-1}"                 # CPU cores
CT_BRIDGE="${CT_BRIDGE:-vmbr0}"           # network bridge
CT_IP="${CT_IP:-}"                        # "dhcp" or "192.168.1.50/24" — prompted if empty
CT_GW="${CT_GW:-}"                        # gateway — only needed for static IP

REPO="${REPO:-YOUR_USERNAME/wg-manager}"
BRANCH="${BRANCH:-main}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
TEMPLATE_NAME=""                          # auto-detected

# ════════════════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  WireGuard Manager — Proxmox Deployer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "✕ Run as root on the Proxmox host"
  exit 1
fi

if ! command -v pct &>/dev/null; then
  echo "✕ 'pct' not found — this script must run on a Proxmox host"
  exit 1
fi

# ── Interactive prompts ───────────────────────────────────────────────────────
echo ""

# CT ID
NEXT_ID=$(pvesh get /cluster/nextid 2>/dev/null || echo "")
if [[ -z "$NEXT_ID" ]]; then
  NEXT_ID=200
  while pct status "$NEXT_ID" &>/dev/null; do NEXT_ID=$((NEXT_ID + 1)); done
fi

if [[ -z "$CT_ID" ]]; then
  echo -n "→ Container ID [default: $NEXT_ID]: "
  read -r INPUT_ID
  CT_ID="${INPUT_ID:-$NEXT_ID}"
fi

# Provjeri da ID nije zauzet
if pct status "$CT_ID" &>/dev/null; then
  echo "✕ Container ID $CT_ID already exists. Use a different ID."
  exit 1
fi
echo "  CT ID: $CT_ID"

# Storage
if [[ -z "$CT_STORAGE" ]]; then
  echo ""
  echo "Available storages:"
  pvesm status 2>/dev/null | awk 'NR>1 {printf "  %-20s %s
", $1, $2}' || echo "  (could not list storages)"
  echo -n "→ Storage [default: local]: "
  read -r INPUT_STORAGE
  CT_STORAGE="${INPUT_STORAGE:-local}"
fi
echo "  Storage: $CT_STORAGE"

# Root password
if [[ -z "$CT_PASSWORD" ]]; then
  echo ""
  echo -n "→ Root password for container: "
  read -rs CT_PASSWORD
  echo ""
  if [[ -z "$CT_PASSWORD" ]]; then
    echo "✕ Password cannot be empty"
    exit 1
  fi
fi

echo ""

# ── Ensure WireGuard module is loaded on host (shared kernel) ─────────────────
echo "→ Checking WireGuard kernel module on host..."
if ! lsmod | grep -q wireguard 2>/dev/null; then
  modprobe wireguard 2>/dev/null || true
fi
if ! lsmod | grep -q wireguard 2>/dev/null; then
  echo "⚠ Warning: wireguard module not loaded on host."
  echo "  LXC shares the host kernel — WireGuard must be available on the host."
  echo "  Try: apt-get install wireguard && modprobe wireguard"
fi

# ── Auto-detect or download Ubuntu 22.04 template ────────────────────────────
echo "→ Checking for Ubuntu 22.04 template..."
pveam update -qq 2>/dev/null || true

# Find latest ubuntu-22.04 template already on storage
TEMPLATE_NAME=$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null   | awk '{print $1}'   | grep "ubuntu-22.04"   | sort -V | tail -1)

if [[ -z "$TEMPLATE_NAME" ]]; then
  # Not downloaded yet — find available and grab latest
  TEMPLATE_NAME=$(pveam available 2>/dev/null     | awk '{print $2}'     | grep "ubuntu-22.04"     | sort -V | tail -1)

  if [[ -z "$TEMPLATE_NAME" ]]; then
    echo "✕ Could not find Ubuntu 22.04 template. Run: pveam update"
    exit 1
  fi

  echo "→ Downloading template: $TEMPLATE_NAME"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE_NAME"
  echo "✓ Template downloaded"
else
  echo "✓ Template found: $TEMPLATE_NAME"
fi

TEMPLATE_PATH="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_NAME}"

# ── Network config — prompt if not set ────────────────────────────────────────
if [[ -z "$CT_IP" ]]; then
  echo ""
  echo "Network configuration:"
  echo "  [1] DHCP"
  echo "  [2] Static IP"
  echo -n "→ Choose [1/2] (default: 1): "
  read -r NET_CHOICE
  if [[ "$NET_CHOICE" == "2" ]]; then
    echo -n "→ IP address with prefix (e.g. 192.168.1.50/24): "
    read -r CT_IP
    echo -n "→ Gateway (e.g. 192.168.1.1): "
    read -r CT_GW
  else
    CT_IP="dhcp"
  fi
fi

if [[ "$CT_IP" == "dhcp" ]]; then
  NET_CONFIG="name=eth0,bridge=${CT_BRIDGE},ip=dhcp"
else
  [[ -n "$CT_GW" ]] && GW_PART=",gw=${CT_GW}" || GW_PART=""
  NET_CONFIG="name=eth0,bridge=${CT_BRIDGE},ip=${CT_IP}${GW_PART}"
fi

# ── Create container ──────────────────────────────────────────────────────────
echo "→ Creating LXC container (ID: ${CT_ID}, hostname: ${CT_HOSTNAME})..."

pct create "$CT_ID" "$TEMPLATE_PATH" \
  --hostname   "$CT_HOSTNAME"        \
  --password   "$CT_PASSWORD"        \
  --storage    "$CT_STORAGE"         \
  --rootfs     "${CT_STORAGE}:${CT_DISK}" \
  --memory     "$CT_RAM"             \
  --cores      "$CT_CORES"           \
  --net0       "$NET_CONFIG"         \
  --ostype     ubuntu                \
  --unprivileged 0                   \
  --features   nesting=1,keyctl=1    \
  --onboot     1

echo "✓ Container created"

# ── Configure WireGuard-specific LXC options ──────────────────────────────────
# These must be added to the config file before start
CT_CONF="/etc/pve/lxc/${CT_ID}.conf"

echo "→ Applying WireGuard LXC config..."
cat >> "$CT_CONF" << 'EOF'

# WireGuard Manager requirements
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file 0 0
EOF

echo "✓ LXC config updated"

# ── IPv4 forwarding on host ───────────────────────────────────────────────────
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "✓ IPv4 forwarding enabled on host"

# ── Start container ───────────────────────────────────────────────────────────
echo "→ Starting container..."
pct start "$CT_ID"
sleep 4
echo "✓ Container started"

# ── Wait for network inside container ─────────────────────────────────────────
echo "→ Waiting for network..."
for i in $(seq 1 15); do
  if pct exec "$CT_ID" -- curl -fsSL --max-time 3 https://github.com -o /dev/null 2>/dev/null; then
    echo "✓ Network ready"
    break
  fi
  sleep 2
  if [[ $i -eq 15 ]]; then
    echo "⚠ Network not ready after 30s — continuing anyway"
  fi
done

# ── Run installer inside container ────────────────────────────────────────────
echo "→ Running installer inside container..."
pct exec "$CT_ID" -- bash -c "
  set -e
  apt-get update -qq
  apt-get install -y --quiet curl
  bash <(curl -fsSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/install.sh)
"

echo "✓ Application installed"

# ── Get container IP for summary ──────────────────────────────────────────────
CT_IP_ACTUAL=$(pct exec "$CT_ID" -- hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ WireGuard Manager deployed!"
echo ""
echo "  Container ID:  $CT_ID"
echo "  Hostname:      $CT_HOSTNAME"
echo "  IP address:    $CT_IP_ACTUAL"
echo "  Web UI:        http://${CT_IP_ACTUAL}:5000"
echo ""
echo "  Manage container:"
echo "    pct shell $CT_ID"
echo "    pct stop  $CT_ID"
echo "    pct start $CT_ID"
echo "    pct exec  $CT_ID -- journalctl -u wg-manager -f"
echo ""
echo "  Update application:"
echo "    pct exec $CT_ID -- bash <(curl -fsSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/update.sh)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"