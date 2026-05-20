# WireGuard Manager
Web-based admin panel for managing WireGuard VPN servers.
**Features:** multi-interface, peer management, per-peer firewall rules (iptables), traffic monitoring, backup/restore, JWT auth with roles.
---
## Quick Install
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blackbox2097/wg-manager/main/install.sh)
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
bash <(curl -fsSL https://raw.githubusercontent.com/blackbox2097/wg-manager/main/update.sh)
```
---
## Docker
No installation needed — pull the image and run.
```bash
docker pull ghcr.io/blackbox2097/wg-manager:latest
```
### docker-compose.yml
```yaml
services:
  wg-manager:
    image: ghcr.io/blackbox2097/wg-manager:latest
    container_name: wg-manager
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    volumes:
      - /etc/wireguard:/etc/wireguard
    environment:
      - JWT_SECRET_KEY=CHANGE_THIS_TO_A_RANDOM_STRING
      - SESSION_MINUTES=30
    devices:
      - /dev/net/tun:/dev/net/tun
```
Generate a secure `JWT_SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Enable IP forwarding on the host (required for VPN routing):
```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward=1
```
Then start the stack:
```bash
docker compose up -d
```
Web UI will be available at `http://<host-ip>:5000`.

> **Note:** `network_mode: host` is required — WireGuard creates virtual network interfaces directly on the host kernel.
---
## LXC / LXD
```bash
# 1. Install LXD on host
snap install lxd && lxd init --minimal
# 2. Launch container
lxc launch ubuntu:22.04 wg-manager
# 3. Run installer inside container
lxc exec wg-manager -- bash -c \
  "bash <(curl -fsSL https://raw.githubusercontent.com/blackbox2097/wg-manager/main/install.sh)"
# 4. Get container IP
lxc list wg-manager
```
> **Note:** WireGuard kernel module must be loaded on the **host** (`modprobe wireguard`).
> LXC containers share the host kernel.
---
## Proxmox LXC
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/blackbox2097/wg-manager/main/proxmox-deploy.sh)
```
### Options (env varijable)
```bash
CT_ID=210 CT_STORAGE=local-lvm CT_IP=192.168.1.50/24 CT_GW=192.168.1.1 \
  bash <(curl -fsSL .../proxmox-deploy.sh)
```
| Varijable | Default | Description |
|-----------|---------|------|
| `CT_ID` | auto | LXC ID |
| `CT_HOSTNAME` | wg-manager | Container Hostname |
| `CT_STORAGE` | local-lvm | Proxmox storage |
| `CT_DISK` | 4 | Disk in GB |
| `CT_RAM` | 512 | RAM in MB |
| `CT_BRIDGE` | vmbr0 | Network bridge |
| `CT_IP` | dhcp | IP address or `dhcp` |
| `CT_GW` | — | Gateway (for static IP) |
> **Note:** WireGuard kernel modul must be loaded on Proxmox host.
---
## Default credentials
| Username | Password |
|----------|----------|
| admin    | admin    |
**Change the password immediately after first login.**
---
## File layout
```
/opt/wg-manager/          ← systemd install
├── app.py
├── requirements.txt
├── venv/
└── templates/
    └── index.html
/etc/wireguard/           ← WireGuard configs + SQLite DB
/etc/wg-manager.secret    ← JWT secret (chmod 600)
```
## Service management
```bash
# systemd
systemctl status wg-manager
systemctl restart wg-manager
journalctl -u wg-manager -f

# Docker
docker compose logs -f
docker compose restart
```
---
## Stack
- **Backend:** Python 3, Flask, Flask-JWT-Extended, bcrypt, cryptography
- **Frontend:** Vanilla JS SPA, JetBrains Mono, dark terminal UI
- **Auth:** JWT in httpOnly cookie, roles: `admin` / `operator` / `readonly`
- **Storage:** SQLite (users, encrypted peer keys, traffic samples)