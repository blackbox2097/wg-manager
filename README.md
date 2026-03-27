# WireGuard Manager

Web-based admin panel for managing WireGuard VPN servers.

**Features:** multi-interface, peer management, per-peer firewall rules (iptables), traffic monitoring, backup/restore, JWT auth with roles.

---

## Quick Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/wg-manager/main/install.sh)
```

Requires a Debian/Ubuntu host with root access.

### Options

```bash
# Custom interface and port
WG_INTERFACE=wg1 WG_MANAGER_PORT=8080 bash <(curl -fsSL ...)
```

---

## Update

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/wg-manager/main/update.sh)
```

---

## LXC / LXD

```bash
# 1. Install LXD on host
snap install lxd && lxd init --minimal

# 2. Launch container
lxc launch ubuntu:22.04 wg-manager

# 3. Run installer inside container
lxc exec wg-manager -- bash -c \
  "bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/wg-manager/main/install.sh)"

# 4. Get container IP
lxc list wg-manager
```

> **Note:** WireGuard kernel module must be loaded on the **host** (`modprobe wireguard`).
> LXC containers share the host kernel.

---

## Default credentials

| Username | Password |
|----------|----------|
| admin    | admin    |

**Change the password immediately after first login.**

---

## File layout

```
/opt/wg-manager/
├── app.py
├── requirements.txt
├── venv/
└── templates/
    └── index.html

/etc/wireguard/          ← WireGuard configs
/etc/wg-manager.secret   ← JWT secret (chmod 600)
```

## Service management

```bash
systemctl status wg-manager
systemctl restart wg-manager
journalctl -u wg-manager -f
```

---

## Stack

- **Backend:** Python 3, Flask, Flask-JWT-Extended, bcrypt, cryptography
- **Frontend:** Vanilla JS SPA, JetBrains Mono, dark terminal UI
- **Auth:** JWT in httpOnly cookie, roles: `admin` / `operator` / `readonly`
- **Storage:** SQLite (users, encrypted peer keys, traffic samples)
