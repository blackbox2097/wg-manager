#!/usr/bin/env python3
"""
WireGuard Manager - Flask Backend v5
Multi-interface + auth (SQLite, JWT httpOnly cookie, roles)
"""

import os
import re
import json
import sqlite3
import secrets
import ipaddress
import subprocess
from datetime import datetime, timezone, timedelta
from functools import wraps

import bcrypt
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request, send_from_directory, make_response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, get_jwt,
    verify_jwt_in_request, set_access_cookies, unset_jwt_cookies
)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, supports_credentials=True)

# ── Config ──────────────────────────────────────────────────────────────────
WG_DIR        = os.environ.get('WG_DIR', '/etc/wireguard')
META_DIR      = os.environ.get('WG_META_DIR', WG_DIR)
DB_PATH       = os.environ.get('WG_DB_PATH', os.path.join(META_DIR, 'wg-manager.db'))
JWT_SECRET    = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
SESSION_MIN   = int(os.environ.get('SESSION_MINUTES', '30'))

app.config['JWT_SECRET_KEY']              = JWT_SECRET
app.config['JWT_ACCESS_TOKEN_EXPIRES']    = timedelta(minutes=SESSION_MIN)
app.config['JWT_TOKEN_LOCATION']          = ['cookies']
app.config['JWT_COOKIE_HTTPONLY']         = True
app.config['JWT_COOKIE_SAMESITE']         = 'Lax'
app.config['JWT_COOKIE_SECURE']           = False   # set True behind HTTPS/NPM
app.config['JWT_SESSION_COOKIE']          = False
app.config['JWT_COOKIE_CSRF_PROTECT']     = False   # LAN-only, no CSRF needed

jwt = JWTManager(app)

ROLES   = ('admin', 'operator', 'readonly')
ROLE_LVL = {'admin': 3, 'operator': 2, 'readonly': 1}


# ── Database ─────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT UNIQUE NOT NULL,
                pw_hash   TEXT NOT NULL,
                role      TEXT NOT NULL DEFAULT 'readonly',
                created   TEXT NOT NULL,
                last_login TEXT
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS peer_keys (
                iface       TEXT NOT NULL,
                pubkey      TEXT NOT NULL,
                enc_privkey TEXT NOT NULL,
                created     TEXT NOT NULL,
                PRIMARY KEY (iface, pubkey)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS traffic_samples (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                iface   TEXT NOT NULL,
                ts      INTEGER NOT NULL,
                rx_bps  INTEGER NOT NULL DEFAULT 0,
                tx_bps  INTEGER NOT NULL DEFAULT 0
            )
        ''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_traffic_iface_ts ON traffic_samples (iface, ts)')
        db.commit()
    # Create default admin if no users exist
    with get_db() as db:
        count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if count == 0:
            pw = bcrypt.hashpw(b'admin', bcrypt.gensalt()).decode()
            db.execute(
                'INSERT INTO users (username, pw_hash, role, created) VALUES (?,?,?,?)',
                ('admin', pw, 'admin', now_iso())
            )
            db.commit()
            app.logger.warning('No users found — created default admin/admin. Change this immediately!')

def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ── Auth helpers ─────────────────────────────────────────────────────────────

def require_role(*roles):
    """Decorator: require JWT + one of the given roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception:
                return jsonify({'error': 'Authentication required'}), 401
            claims = get_jwt()
            if claims.get('role') not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def require_auth(fn):
    """Decorator: require any valid JWT."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except Exception:
            return jsonify({'error': 'Authentication required'}), 401
        return fn(*args, **kwargs)
    return wrapper

def refresh_token_if_needed(response):
    """Silently refresh token on every authenticated request (sliding window)."""
    try:
        verify_jwt_in_request()
        identity = get_jwt_identity()
        claims   = get_jwt()
        new_tok  = create_access_token(
            identity=identity,
            additional_claims={'role': claims.get('role'), 'username': claims.get('username')}
        )
        set_access_cookies(response, new_tok)
    except Exception:
        pass
    return response

@app.after_request
def after_request(response):
    return refresh_token_if_needed(response)


# ── WAN detection ─────────────────────────────────────────────────────────────

def detect_wan_interface():
    override = os.environ.get('WAN_INTERFACE', '').strip()
    if override:
        return override
    try:
        r = subprocess.run('ip route get 8.8.8.8', shell=True,
                           capture_output=True, text=True, timeout=5)
        for token in r.stdout.split():
            if token not in ('8.8.8.8','via','dev','src','uid','cache') \
               and not token.replace('.','').isdigit() \
               and re.match(r'^(e|w|b|v|en|wl|br|bond|vlan|p)', token):
                return token
    except Exception:
        pass
    return 'eth0'

WAN_INTERFACE = detect_wan_interface()


_cached_public_ip = None  # populated by background thread at startup

def detect_public_ip():
    # Return cached public IP (populated at startup). Never blocks.
    return _cached_public_ip or ''

def _fetch_public_ip():
    # Background thread - fetches immediately then refreshes every 5 minutes
    import urllib.request, time
    global _cached_public_ip
    override = os.environ.get('SERVER_PUBLIC_IP', '').strip()
    if override:
        _cached_public_ip = override
        return
    while True:
        ip = ''
        for url in ['https://api.ipify.org', 'https://checkip.amazonaws.com',
                    'https://icanhazip.com']:
            try:
                with urllib.request.urlopen(url, timeout=4) as r:
                    candidate = r.read().decode().strip()
                    if candidate and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', candidate):
                        ip = candidate
                        break
            except Exception:
                continue
        if not ip:
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
            except Exception:
                ip = ''
        if ip and ip != _cached_public_ip:
            app.logger.info(f'Public IP: {ip}')
        _cached_public_ip = ip
        time.sleep(300)


# ── Key encryption ────────────────────────────────────────────────────────────

def _derive_enc_key():
    """Derive a 32-byte AES key from JWT_SECRET. Stable per installation."""
    return hashlib.sha256(JWT_SECRET.encode()).digest()

def encrypt_key(plaintext: str) -> str:
    """Encrypt a WireGuard private key. Returns base64-encoded nonce+ciphertext."""
    key   = _derive_enc_key()
    nonce = os.urandom(12)          # 96-bit nonce for AES-GCM
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), b'wg-manager-key')
    return base64.b64encode(nonce + ct).decode()

def decrypt_key(blob: str) -> str:
    """Decrypt a stored private key blob. Returns plaintext string."""
    raw   = base64.b64decode(blob.encode())
    nonce = raw[:12]
    ct    = raw[12:]
    pt    = AESGCM(_derive_enc_key()).decrypt(nonce, ct, b'wg-manager-key')
    return pt.decode()


def store_peer_key(iface, pubkey, privkey):
    with get_db() as db:
        db.execute(
            'INSERT OR REPLACE INTO peer_keys (iface, pubkey, enc_privkey, created) VALUES (?,?,?,?)',
            (iface, pubkey, encrypt_key(privkey), now_iso())
        )
        db.commit()

def get_peer_key(iface, pubkey):
    with get_db() as db:
        row = db.execute(
            'SELECT enc_privkey FROM peer_keys WHERE iface=? AND pubkey=?',
            (iface, pubkey)
        ).fetchone()
    if not row:
        return None
    try:
        return decrypt_key(row['enc_privkey'])
    except Exception:
        return None

def delete_peer_key(iface, pubkey):
    with get_db() as db:
        db.execute('DELETE FROM peer_keys WHERE iface=? AND pubkey=?', (iface, pubkey))
        db.commit()


# ── Shell helper ──────────────────────────────────────────────────────────────

def run_cmd(cmd, check=True):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=15, executable='/bin/bash')
        if check and r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip())
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'Command timed out: {cmd}')


# ── Per-interface paths ───────────────────────────────────────────────────────

def conf_path(iface):       return os.path.join(WG_DIR,  f'{iface}.conf')
def meta_path(iface):       return os.path.join(META_DIR, f'wg-manager-{iface}.json')
def iface_meta_path(iface): return os.path.join(META_DIR, f'wg-manager-{iface}-iface.json')
def postup_path(iface):     return os.path.join(META_DIR, f'wg-manager-{iface}-postup.sh')
def postdown_path(iface):   return os.path.join(META_DIR, f'wg-manager-{iface}-postdown.sh')

def load_iface_meta(iface):
    try:
        p = iface_meta_path(iface)
        if os.path.exists(p):
            return json.load(open(p))
    except Exception:
        pass
    return {}

def save_iface_meta(iface, data):
    p = iface_meta_path(iface)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(data, open(p, 'w'), indent=2)


# ── Interface discovery ───────────────────────────────────────────────────────

def list_interfaces():
    ifaces = []
    try:
        for fname in sorted(os.listdir(WG_DIR)):
            if re.match(r'^wg\d+\.conf$', fname):
                iface = fname[:-5]
                _, _, rc = run_cmd(f'ip link show {iface}', check=False)
                ifaces.append({'name': iface, 'up': rc == 0, 'conf': conf_path(iface)})
    except Exception:
        pass
    return ifaces


# ── Metadata sidecar ──────────────────────────────────────────────────────────

def load_meta(iface):
    p = meta_path(iface)
    if not os.path.exists(p): return {}
    try:
        with open(p) as f: return json.load(f)
    except Exception: return {}

def save_meta(iface, meta):
    with open(meta_path(iface), 'w') as f: json.dump(meta, f, indent=2)

def set_peer_meta(iface, pubkey, data):
    meta = load_meta(iface)
    meta.setdefault(pubkey, {}).update(data)
    save_meta(iface, meta)

def del_peer_meta(iface, pubkey):
    meta = load_meta(iface)
    meta.pop(pubkey, None)
    save_meta(iface, meta)


# ── Config parser / writer ────────────────────────────────────────────────────

def parse_wg_conf(iface):
    path = conf_path(iface)
    if not os.path.exists(path): return {}, []
    with open(path) as f: lines = f.readlines()

    interface_cfg, peers = {}, []
    section, cur, disabled_buf = None, {}, []

    for raw in lines:
        line = raw.strip()
        if line == '#!WGM disabled':
            if section == 'peer' and cur: peers.append(cur)
            section, cur, disabled_buf = 'disabled_peer', {'_enabled': False}, []
            continue
        if line == '#!WGM end' and section == 'disabled_peer':
            for bl in disabled_buf:
                bl = bl.strip().lstrip('#').strip()
                if bl == '[Peer]': continue
                if re.match(r'^Name\s*=', bl): cur['_name'] = bl.split('=',1)[1].strip()
                elif '=' in bl:
                    k, _, v = bl.partition('=')
                    cur[k.strip()] = v.strip()
            peers.append(cur); cur = {}; section = None; continue
        if section == 'disabled_peer': disabled_buf.append(raw); continue
        if line == '[Interface]':
            if section == 'peer' and cur: peers.append(cur)
            section, cur = 'interface', {}; continue
        if line == '[Peer]':
            if section == 'peer' and cur: peers.append(cur)
            section, cur = 'peer', {'_enabled': True}; continue
        if not line or line.startswith('#'):
            if section == 'peer' and line.startswith('# Name ='):
                cur['_name'] = line[len('# Name ='):].strip()
            continue
        if '=' in line:
            k, _, v = line.partition('=')
            k, v = k.strip(), v.strip()
            if section == 'interface': interface_cfg[k] = v
            elif section == 'peer': cur[k] = v

    if section == 'peer' and cur: peers.append(cur)
    return interface_cfg, peers

def write_wg_conf(iface, interface_cfg, peers):
    path = conf_path(iface)
    meta = load_meta(iface)

    # Generate firewall scripts
    write_firewall_scripts(iface, peers, meta)

    # Set PostUp/PostDown to reference the script files
    cfg = dict(interface_cfg)
    # Strip DNS from server config — wg-quick passes it to systemd-resolved
    # with ~. routing domain which overrides the server's own DNS resolution.
    cfg.pop('DNS', None)
    cfg['PostUp']   = f'bash {postup_path(iface)}'
    cfg['PostDown'] = f'bash {postdown_path(iface)}'

    lines = ['[Interface]\n']
    for k, v in cfg.items(): lines.append(f'{k} = {v}\n')
    lines.append('\n')
    for peer in peers:
        enabled = peer.get('_enabled', True)
        name    = peer.get('_name', '')
        items   = [(k, v) for k, v in peer.items() if not k.startswith('_')]
        if enabled:
            lines.append('[Peer]\n')
            if name: lines.append(f'# Name = {name}\n')
            for k, v in items: lines.append(f'{k} = {v}\n')
            lines.append('\n')
        else:
            lines.append('#!WGM disabled\n#[Peer]\n')
            if name: lines.append(f'#Name = {name}\n')
            for k, v in items: lines.append(f'#{k} = {v}\n')
            lines.append('#!WGM end\n\n')
    with open(path, 'w') as f: f.writelines(lines)


# ── Firewall script generator ──────────────────────────────────────────────────

def _peer_ip(peer):
    try:
        return str(ipaddress.ip_interface(
            peer.get('AllowedIPs', '').split(',')[0].strip()
        ).ip)
    except Exception:
        return peer.get('AllowedIPs', '').split('/')[0].strip()


def _peer_rules_lines(iface, peer_ip, ipt_rules):
    lines = []
    for r in ipt_rules:
        rtype  = r.get('type', '')
        action = r.get('action', 'ACCEPT')

        if rtype == 'internet':
            lines.append(f'iptables -A $CHAIN_NAME -s {peer_ip} -i $WIREGUARD_INTERFACE -j {action}')

        elif rtype == 'destination':
            dst = r.get('dst_ip', '').strip()
            if dst:
                lines.append(f'iptables -A $CHAIN_NAME -s {peer_ip} -i $WIREGUARD_INTERFACE -d {dst} -j {action}')

        elif rtype == 'peer_isolation':
            dst = r.get('dst_peer_ip', '').strip()
            d = f' -d {dst}' if dst else ''
            lines.append(f'iptables -A $CHAIN_NAME -s {peer_ip} -i $WIREGUARD_INTERFACE -o $WIREGUARD_INTERFACE{d} -j {action}')

        elif rtype == 'port':
            proto = r.get('proto', 'both')
            port  = r.get('port', '').strip()
            dp    = f' --dport {port}' if port else ''
            for p in (['tcp', 'udp'] if proto == 'both' else [proto or 'tcp']):
                lines.append(f'iptables -A $CHAIN_NAME -s {peer_ip} -i $WIREGUARD_INTERFACE -p {p}{dp} -j {action}')

        elif rtype == 'ratelimit':
            tag = peer_ip.replace('.', '_')
            if r.get('kbps_dl'):
                kbps = int(r['kbps_dl'])
                lines.append(f'iptables -I FORWARD -o $WIREGUARD_INTERFACE -d {peer_ip} -m hashlimit --hashlimit-above {kbps}kb/s --hashlimit-burst {kbps*2} --hashlimit-mode dstip --hashlimit-name rl_dl_{tag} -j DROP')
            if r.get('kbps_ul'):
                kbps = int(r['kbps_ul'])
                lines.append(f'iptables -I FORWARD -i $WIREGUARD_INTERFACE -s {peer_ip} -m hashlimit --hashlimit-above {kbps}kb/s --hashlimit-burst {kbps*2} --hashlimit-mode srcip --hashlimit-name rl_ul_{tag} -j DROP')

    return lines


def generate_postup_script(iface, peers, meta):
    wg_net = ''
    try:
        cfg, _ = parse_wg_conf(iface)
        addr = cfg.get('Address', '').split(',')[0].strip()
        if addr:
            wg_net = str(ipaddress.ip_interface(addr).network)
    except Exception:
        pass

    lines = [
        '#!/bin/bash',
        f'WIREGUARD_INTERFACE={iface}',
        f'WIREGUARD_LAN={wg_net}',
        f'MASQUERADE_INTERFACE={WAN_INTERFACE}',
        f'CHAIN_NAME="WIREGUARD_{iface}"',
        '',
    ]

    # nomasq RETURN rules — must be BEFORE global MASQUERADE
    nomasq_lines = []
    for peer in peers:
        pk = peer.get('PublicKey', '')
        pm = meta.get(pk, {})
        peer_ip = _peer_ip(peer)
        for r in pm.get('ipt_rules', []):
            if r.get('type') == 'nomasq':
                out = r.get('out_iface', WAN_INTERFACE).strip() or WAN_INTERFACE
                nomasq_lines.append(f'iptables -t nat -I POSTROUTING -o {out} -s {peer_ip} -j RETURN')
    if nomasq_lines:
        lines.append('# nomasq exceptions (before MASQUERADE)')
        lines.extend(nomasq_lines)
        lines.append('')

    # Global MASQUERADE
    lines += [
        '# MASQUERADE for WG subnet',
        'iptables -t nat -A POSTROUTING -o $MASQUERADE_INTERFACE -j MASQUERADE -s $WIREGUARD_LAN',
        '',
        '# Create dedicated FORWARD chain',
        'iptables -N $CHAIN_NAME',
        'iptables -A FORWARD -j $CHAIN_NAME',
        '',
        '# Accept return traffic to WG clients',
        'iptables -A $CHAIN_NAME -o $WIREGUARD_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '',
        '# Per-peer rules',
    ]

    for peer in peers:
        pk        = peer.get('PublicKey', '')
        pm        = meta.get(pk, {})
        peer_ip   = _peer_ip(peer)
        peer_name = pm.get('name') or peer.get('_name') or pk[:12]
        ipt_rules = pm.get('ipt_rules', [])
        rule_lines = _peer_rules_lines(iface, peer_ip, ipt_rules)
        if rule_lines:
            lines.append(f'# {peer_name}')
            lines.extend(rule_lines)
            lines.append('')

    lines += [
        '# Drop everything else from WG interface',
        'iptables -A $CHAIN_NAME -i $WIREGUARD_INTERFACE -j DROP',
        '',
        '# Return to FORWARD chain',
        'iptables -A $CHAIN_NAME -j RETURN',
    ]
    return '\n'.join(lines) + '\n'


def generate_postdown_script(iface):
    wg_net = ''
    try:
        cfg, _ = parse_wg_conf(iface)
        addr = cfg.get('Address', '').split(',')[0].strip()
        if addr:
            wg_net = str(ipaddress.ip_interface(addr).network)
    except Exception:
        pass

    meta   = load_meta(iface)
    _, peers = parse_wg_conf(iface)
    nomasq_lines = []
    for peer in peers:
        pk = peer.get('PublicKey', '')
        pm = meta.get(pk, {})
        peer_ip = _peer_ip(peer)
        for r in pm.get('ipt_rules', []):
            if r.get('type') == 'nomasq':
                out = r.get('out_iface', WAN_INTERFACE).strip() or WAN_INTERFACE
                nomasq_lines.append(f'iptables -t nat -D POSTROUTING -o {out} -s {peer_ip} -j RETURN 2>/dev/null || true')

    lines = [
        '#!/bin/bash',
        f'WIREGUARD_INTERFACE={iface}',
        f'WIREGUARD_LAN={wg_net}',
        f'MASQUERADE_INTERFACE={WAN_INTERFACE}',
        f'CHAIN_NAME="WIREGUARD_{iface}"',
        '',
    ]
    if nomasq_lines:
        lines.append('# Remove nomasq exceptions')
        lines.extend(nomasq_lines)
        lines.append('')
    lines += [
        '# Remove MASQUERADE',
        'iptables -t nat -D POSTROUTING -o $MASQUERADE_INTERFACE -j MASQUERADE -s $WIREGUARD_LAN 2>/dev/null || true',
        '',
        '# Remove and delete the chain',
        'iptables -D FORWARD -j $CHAIN_NAME 2>/dev/null || true',
        'iptables -F $CHAIN_NAME 2>/dev/null || true',
        'iptables -X $CHAIN_NAME 2>/dev/null || true',
    ]
    return '\n'.join(lines) + '\n'


def write_firewall_scripts(iface, peers, meta):
    for path, content in [
        (postup_path(iface),   generate_postup_script(iface, peers, meta)),
        (postdown_path(iface), generate_postdown_script(iface)),
    ]:
        with open(path, 'w') as f:
            f.write(content)
        os.chmod(path, 0o750)


def apply_firewall_scripts(iface):
    _, _, rc = run_cmd(f'ip link show {iface}', check=False)
    if rc != 0:
        return
    run_cmd(f'bash {postdown_path(iface)}', check=False)
    run_cmd(f'bash {postup_path(iface)}', check=False)


# ── WG helpers ────────────────────────────────────────────────────────────────

def reload_interface(iface):
    run_cmd(f'wg syncconf {iface} <(wg-quick strip {iface})', check=False)

def parse_wg_show(iface):
    try: out, _, rc = run_cmd(f'wg show {iface} dump', check=False)
    except Exception: return {}
    if rc != 0: return {}
    result = {}; now = datetime.now().timestamp()
    for line in out.strip().splitlines()[1:]:
        parts = line.split('\t')
        if len(parts) < 8: continue
        pk  = parts[0]; lhs = int(parts[4]) if parts[4] != '0' else 0
        result[pk] = {'endpoint': parts[2] if parts[2] != '(none)' else None,
                      'latest_handshake': lhs, 'rx_bytes': int(parts[5]),
                      'tx_bytes': int(parts[6]), 'online': lhs > 0 and (now-lhs) < 180}
    return result

def generate_keypair():
    priv, _, _ = run_cmd('wg genkey')
    pub,  _, _ = run_cmd(f'echo "{priv.strip()}" | wg pubkey')
    return priv.strip(), pub.strip()

def generate_preshared_key():
    psk, _, _ = run_cmd('wg genpsk'); return psk.strip()

def next_available_ip(interface_cfg, peers):
    server_addr = interface_cfg.get('Address','10.0.0.1/24').split(',')[0].strip()
    try:
        net  = ipaddress.ip_interface(server_addr).network
        used = {str(ipaddress.ip_interface(server_addr).ip)}
        for p in peers:
            for s in p.get('AllowedIPs','').split(','):
                s = s.strip()
                if s:
                    try: used.add(str(ipaddress.ip_interface(s).ip))
                    except Exception: pass
        for host in net.hosts():
            if str(host) not in used:
                return f'{host}/32'
    except Exception: return '10.0.0.2/32'
    return None

def fmt_bytes(b):
    for u in ['B','KB','MB','GB','TB']:
        if b < 1024: return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} PB'

def build_peer_list(iface, peers, live, meta):
    result = []
    for peer in peers:
        pk = peer.get('PublicKey',''); live_d = live.get(pk,{}); pm = meta.get(pk,{})
        key_stored = False
        try:
            with get_db() as db:
                key_stored = db.execute(
                    'SELECT 1 FROM peer_keys WHERE iface=? AND pubkey=?', (iface, pk)
                ).fetchone() is not None
        except Exception:
            pass
        result.append({'name': peer.get('_name',''), 'public_key': pk,
            'allowed_ips': peer.get('AllowedIPs',''), 'dns': peer.get('DNS','') or meta.get(pk,{}).get('dns',''),
            'preshared_key': peer.get('PresharedKey',''),
            'persistent_keepalive': peer.get('PersistentKeepalive',''),
            'key_stored': key_stored,
            'enabled': peer.get('_enabled', True),
            'endpoint': live_d.get('endpoint'),
            'online': live_d.get('online', False) and peer.get('_enabled', True),
            'latest_handshake': live_d.get('latest_handshake', 0),
            'rx_bytes': live_d.get('rx_bytes', 0), 'tx_bytes': live_d.get('tx_bytes', 0),
            'rx_human': fmt_bytes(live_d.get('rx_bytes',0)),
            'tx_human': fmt_bytes(live_d.get('tx_bytes',0)),
            'ipt_rules': pm.get('ipt_rules',[]), 'post_up': pm.get('post_up',''),
            'post_down': pm.get('post_down','')})
    return result


# ════════════════════════════════════════════════════════════════════════════
# API — Auth
# ════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data     = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','').encode()
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    with get_db() as db:
        row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not row or not bcrypt.checkpw(password, row['pw_hash'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Update last_login
    with get_db() as db:
        db.execute('UPDATE users SET last_login=? WHERE id=?', (now_iso(), row['id']))
        db.commit()

    token = create_access_token(
        identity=str(row['id']),
        additional_claims={'role': row['role'], 'username': row['username']}
    )
    resp = make_response(jsonify({
        'success':  True,
        'username': row['username'],
        'role':     row['role'],
        'session_minutes': SESSION_MIN,
    }))
    set_access_cookies(resp, token)
    return resp

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    resp = make_response(jsonify({'success': True}))
    unset_jwt_cookies(resp)
    return resp

@app.route('/api/auth/me')
@require_auth
def api_me():
    claims = get_jwt()
    return jsonify({'username': claims.get('username'), 'role': claims.get('role'),
                    'session_minutes': SESSION_MIN})


# ════════════════════════════════════════════════════════════════════════════
# API — User management (admin only)
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/auth/users')
@require_role('admin')
def api_list_users():
    with get_db() as db:
        rows = db.execute('SELECT id,username,role,created,last_login FROM users ORDER BY id').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/auth/users', methods=['POST'])
@require_role('admin')
def api_create_user():
    data = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','').strip()
    role     = data.get('role','readonly')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if role not in ROLES:
        return jsonify({'error': f'Invalid role. Must be: {", ".join(ROLES)}'}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        with get_db() as db:
            db.execute('INSERT INTO users (username,pw_hash,role,created) VALUES (?,?,?,?)',
                       (username, pw_hash, role, now_iso()))
            db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    return jsonify({'success': True, 'message': f'User {username} created.'})

@app.route('/api/auth/users/<int:uid>', methods=['PUT'])
@require_role('admin')
def api_update_user(uid):
    data     = request.json or {}
    claims   = get_jwt()
    cur_uid  = int(get_jwt_identity())

    with get_db() as db:
        row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not row:
        return jsonify({'error': 'User not found'}), 404

    # Prevent admin from demoting themselves
    if uid == cur_uid and 'role' in data and data['role'] != 'admin':
        return jsonify({'error': 'Cannot change your own role'}), 400

    updates, params = [], []
    if 'role' in data:
        if data['role'] not in ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        updates.append('role=?'); params.append(data['role'])
    if 'password' in data and data['password']:
        pw_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
        updates.append('pw_hash=?'); params.append(pw_hash)
    if not updates:
        return jsonify({'error': 'Nothing to update'}), 400

    params.append(uid)
    with get_db() as db:
        db.execute(f'UPDATE users SET {",".join(updates)} WHERE id=?', params)
        db.commit()
    return jsonify({'success': True})

@app.route('/api/auth/users/<int:uid>', methods=['DELETE'])
@require_role('admin')
def api_delete_user(uid):
    cur_uid = int(get_jwt_identity())
    if uid == cur_uid:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    with get_db() as db:
        r = db.execute('DELETE FROM users WHERE id=?', (uid,))
        db.commit()
    if r.rowcount == 0:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'success': True})

@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def api_change_password():
    data    = request.json or {}
    old_pw  = data.get('old_password','').encode()
    new_pw  = data.get('new_password','').strip()
    uid     = int(get_jwt_identity())
    if not old_pw or not new_pw:
        return jsonify({'error': 'Both old and new password required'}), 400
    if len(new_pw) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400
    with get_db() as db:
        row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not row or not bcrypt.checkpw(old_pw, row['pw_hash'].encode()):
        return jsonify({'error': 'Current password incorrect'}), 401
    pw_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    with get_db() as db:
        db.execute('UPDATE users SET pw_hash=? WHERE id=?', (pw_hash, uid))
        db.commit()
    return jsonify({'success': True, 'message': 'Password changed.'})


# ════════════════════════════════════════════════════════════════════════════
# API — Config + System
# ════════════════════════════════════════════════════════════════════════════

# ── IPv4 forwarding check ────────────────────────────────────────────────────

def check_ip_forwarding():
    """Return True if IPv4 forwarding is currently active on the host."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward') as f:
            return f.read().strip() == '1'
    except Exception:
        return None  # can't determine (non-Linux / permission issue)

def enable_ip_forwarding():
    """Attempt to enable IPv4 forwarding at runtime. Returns (success, message)."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        # Also persist across reboots if sysctl.conf doesn't have it yet
        try:
            sysctl_conf = '/etc/sysctl.conf'
            with open(sysctl_conf) as f:
                existing = f.read()
            if 'net.ipv4.ip_forward=1' not in existing:
                with open(sysctl_conf, 'a') as f:
                    f.write('\nnet.ipv4.ip_forward=1\n')
        except Exception:
            pass  # not critical — runtime enable already done
        return True, 'IPv4 forwarding enabled.'
    except PermissionError:
        return False, 'Permission denied — run as root or use install.sh.'
    except Exception as e:
        return False, str(e)


@app.route('/api/config')
@require_auth
def api_config():
    return jsonify({
        'wan_interface':    WAN_INTERFACE,
        'wg_dir':           WG_DIR,
        'server_public_ip': detect_public_ip(),
        'ip_forwarding':    check_ip_forwarding(),
    })

@app.route('/api/system/ip-forwarding', methods=['POST'])
@require_role('admin')
def api_enable_ip_forwarding():
    """Enable IPv4 forwarding at runtime (requires root)."""
    ok, msg = enable_ip_forwarding()
    if ok:
        return jsonify({'success': True, 'message': msg, 'ip_forwarding': True})
    return jsonify({'success': False, 'error': msg}), 500


@app.route('/api/<iface>/throughput')
@require_auth
def api_throughput(iface):
    def read_iface_bytes(name):
        try:
            with open('/proc/net/dev') as f:
                for line in f:
                    if line.strip().startswith(name + ':'):
                        parts = line.split(':')[1].split()
                        return int(parts[0]), int(parts[8])  # rx_bytes, tx_bytes
        except Exception:
            pass
        return None, None

    import time
    rx1, tx1 = read_iface_bytes(iface)
    if rx1 is None:
        return jsonify({'error': f'Interface {iface} not found in /proc/net/dev'}), 404
    time.sleep(1)
    rx2, tx2 = read_iface_bytes(iface)

    rx_bps = max(0, rx2 - rx1)
    tx_bps = max(0, tx2 - tx1)

    def fmt(bps):
        if bps < 1024:           return f'{bps} B/s'
        if bps < 1024*1024:      return f'{bps/1024:.1f} KB/s'
        if bps < 1024*1024*1024: return f'{bps/1024/1024:.2f} MB/s'
        return f'{bps/1024/1024/1024:.2f} GB/s'

    return jsonify({
        'iface':   iface,
        'rx_bps':  rx_bps,
        'tx_bps':  tx_bps,
        'rx_human': fmt(rx_bps),
        'tx_human': fmt(tx_bps),
    })


@app.route('/api/system')
@require_auth
def api_system():
    cpu = mem_pct = mem_used = mem_total = load1 = load5 = load15 = uptime_s = None
    try:
        import time
        def read_cpu():
            with open('/proc/stat') as f: line = f.readline()
            vals = list(map(int, line.split()[1:]))
            idle  = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return idle, sum(vals)
        i1, t1 = read_cpu(); time.sleep(0.2); i2, t2 = read_cpu()
        dt = t2 - t1; cpu = round((1-(i2-i1)/dt)*100, 1) if dt > 0 else 0.0
        meminfo = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':', 1)
                meminfo[k.strip()] = int(v.strip().split()[0])
        mem_total_kb = meminfo.get('MemTotal', 0)
        mem_avail_kb = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
        mem_used_b   = (mem_total_kb - mem_avail_kb) * 1024
        mem_total_b  = mem_total_kb * 1024
        mem_pct      = round(mem_used_b / mem_total_b * 100, 1) if mem_total_b else 0.0
        with open('/proc/loadavg') as f: parts = f.read().split()
        load1, load5, load15 = float(parts[0]), float(parts[1]), float(parts[2])
        with open('/proc/uptime') as f: uptime_s = int(float(f.read().split()[0]))
    except Exception: pass

    def fmt_mem(b):
        if b is None: return '—'
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f'{b:.0f} {u}'
            b /= 1024
        return f'{b:.1f} GB'

    def fmt_uptime(s):
        if s is None: return '—'
        d, s = divmod(s, 86400); h, s = divmod(s, 3600); m, _ = divmod(s, 60)
        parts = []
        if d: parts.append(f'{d}d')
        if h: parts.append(f'{h}h')
        parts.append(f'{m}m')
        return ' '.join(parts)

    return jsonify({'cpu_pct': cpu, 'mem_pct': mem_pct, 'mem_used': fmt_mem(mem_used_b if mem_used_b else None),
                    'mem_total': fmt_mem(mem_total_b if mem_total_b else None),
                    'load': [load1, load5, load15], 'uptime': fmt_uptime(uptime_s)})


# ════════════════════════════════════════════════════════════════════════════
# API — Interfaces
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/interfaces')
@require_auth
def api_list_interfaces():
    ifaces = list_interfaces(); result = []
    for ifc in ifaces:
        name = ifc['name']; cfg, peers = parse_wg_conf(name)
        live = parse_wg_show(name); pl = build_peer_list(name, peers, live, load_meta(name))
        im = load_iface_meta(name)
        result.append({'name': name, 'alias': im.get('alias',''), 'up': ifc['up'],
            'address': cfg.get('Address',''),
            'listen_port': cfg.get('ListenPort',''), 'total_peers': len(pl),
            'online_peers': sum(1 for p in pl if p['online']),
            'rx_bytes': sum(p['rx_bytes'] for p in pl), 'tx_bytes': sum(p['tx_bytes'] for p in pl),
            'rx_human': fmt_bytes(sum(p['rx_bytes'] for p in pl)),
            'tx_human': fmt_bytes(sum(p['tx_bytes'] for p in pl))})
    return jsonify(result)

@app.route('/api/interfaces', methods=['POST'])
@require_role('admin')
def api_create_interface():
    data = request.json; name = data.get('name','').strip()
    if not re.match(r'^wg\d+$', name):
        return jsonify({'error': 'Interface name must match wgN'}), 400
    if os.path.exists(conf_path(name)):
        return jsonify({'error': f'{name}.conf already exists'}), 400
    address = data.get('address','').strip()
    if not address: return jsonify({'error': 'Address is required'}), 400
    priv, pub = generate_keypair()
    cfg = {'PrivateKey': priv, 'Address': address}
    for k, dk in [('listen_port','ListenPort'),('post_up','PostUp'),('post_down','PostDown')]:
        if data.get(k): cfg[dk] = data[k]
    # NOTE: DNS is intentionally NOT written to the server [Interface] section.
    # wg-quick would pass it to systemd-resolved with ~. routing domain,
    # overriding the server's own DNS resolution. DNS belongs in client configs only.
    # PostUp/PostDown reference script files — generated by write_wg_conf
    cfg['PostUp']   = f'bash {postup_path(name)}'
    cfg['PostDown'] = f'bash {postdown_path(name)}'
    write_wg_conf(name, cfg, [])
    os.chmod(conf_path(name), 0o600)
    # Save external port and alias if provided
    im = {}
    if data.get('external_port'): im['external_port'] = str(data['external_port']).strip()
    if data.get('alias'):         im['alias']          = str(data['alias']).strip()
    if im: save_iface_meta(name, im)
    return jsonify({'success': True, 'message': f'{name} created.', 'public_key': pub, 'name': name})

@app.route('/api/interfaces/<iface>/up', methods=['POST'])
@require_role('admin', 'operator')
def api_interface_up(iface):
    try: run_cmd(f'wg-quick up {iface}'); return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/interfaces/<iface>/down', methods=['POST'])
@require_role('admin')
def api_interface_down(iface):
    try: run_cmd(f'wg-quick down {iface}'); return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/interfaces/<iface>/restart', methods=['POST'])
@require_role('admin')
def api_interface_restart(iface):
    run_cmd(f'wg-quick down {iface}', check=False)
    try: run_cmd(f'wg-quick up {iface}'); return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/interfaces/<iface>/toggle', methods=['POST'])
@require_role('admin')
def api_interface_toggle(iface):
    _, _, rc = run_cmd(f'ip link show {iface}', check=False)
    if rc == 0:
        run_cmd(f'wg-quick down {iface}', check=False)
        return jsonify({'success': True, 'up': False, 'message': f'{iface} down.'})
    run_cmd(f'wg-quick up {iface}', check=False)
    return jsonify({'success': True, 'up': True, 'message': f'{iface} up.'})

@app.route('/api/interfaces/<iface>/delete', methods=['POST'])
@require_role('admin')
def api_delete_interface(iface):
    if not re.match(r'^wg\d+$', iface):
        return jsonify({'error': 'Invalid interface name'}), 400
    run_cmd(f'wg-quick down {iface}', check=False)
    for p in [conf_path(iface), meta_path(iface)]:
        if os.path.exists(p): os.remove(p)
    return jsonify({'success': True})


# ════════════════════════════════════════════════════════════════════════════
# API — Per-interface status + config
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/<iface>/status')
@require_auth
def api_status(iface):
    cfg, peers = parse_wg_conf(iface); live = parse_wg_show(iface)
    _, _, iface_rc = run_cmd(f'ip link show {iface}', check=False)
    pl = build_peer_list(iface, peers, live, load_meta(iface))
    # Derive server public key from conf (works even if iface is down)
    server_pub = ''
    if cfg.get('PrivateKey'):
        derived, _, _rc = run_cmd(f'echo "{cfg["PrivateKey"]}" | wg pubkey', check=False)
        if _rc == 0 and derived.strip():
            server_pub = derived.strip()
    if not server_pub:
        live_pub, _, _ = run_cmd(f'wg show {iface} public-key', check=False)
        if live_pub.strip():
            server_pub = live_pub.strip()
    im = load_iface_meta(iface)
    return jsonify({'interface': iface, 'interface_up': iface_rc == 0,
        'server_address': cfg.get('Address',''), 'listen_port': cfg.get('ListenPort','51820'),
        'external_port': im.get('external_port', ''),
        'alias': im.get('alias', ''),
        'server_pubkey': server_pub.strip(),
        'peers': pl, 'online_count': sum(1 for p in pl if p['online']),
        'total_count': len(pl), 'config_path': conf_path(iface)})

@app.route('/api/<iface>/interface')
@require_auth
def api_get_interface(iface):
    cfg, _ = parse_wg_conf(iface); return jsonify(cfg)

@app.route('/api/<iface>/interface', methods=['PUT'])
@require_role('admin')
def api_update_interface(iface):
    data = request.json; cfg, peers = parse_wg_conf(iface)
    # NOTE: DNS excluded — must not be set in server [Interface] (breaks server DNS via systemd-resolved)
    for key in ['PrivateKey','Address','ListenPort','PostUp','PostDown','MTU','Table']:
        if key in data:
            if data[key]: cfg[key] = data[key]
            elif key in cfg: del cfg[key]
    # Save external port and alias in interface metadata
    im = load_iface_meta(iface)
    for field in ['external_port', 'alias']:
        if field in data:
            if data[field]:
                im[field] = str(data[field]).strip()
            elif field in im:
                del im[field]
    save_iface_meta(iface, im)
    write_wg_conf(iface, cfg, peers); reload_interface(iface)
    return jsonify({'success': True})


# ════════════════════════════════════════════════════════════════════════════
# API — Peers
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/peers/generate-keys')
@require_auth
def api_generate_keys():
    priv, pub = generate_keypair()
    return jsonify({'private_key': priv, 'public_key': pub, 'preshared_key': generate_preshared_key()})

@app.route('/api/<iface>/peers', methods=['POST'])
@require_role('admin', 'operator')
def api_add_peer(iface):
    data = request.json; cfg, peers = parse_wg_conf(iface)
    name = data.get('name','').strip(); priv = data.get('private_key','').strip()
    pub  = data.get('public_key','').strip(); ips = data.get('allowed_ips','').strip()
    psk  = data.get('preshared_key','').strip(); ka = data.get('persistent_keepalive','').strip()
    dns  = data.get('dns','').strip()
    if not pub:
        if not priv: priv, pub = generate_keypair()
        else:
            p, _, _ = run_cmd(f'echo "{priv}" | wg pubkey'); pub = p.strip()
    if not ips: ips = next_available_ip(cfg, peers) or '10.0.0.2/32'
    if any(p.get('PublicKey') == pub for p in peers):
        return jsonify({'error': 'Duplicate public key.'}), 400
    new_peer = {'_enabled': True}
    if name: new_peer['_name'] = name
    new_peer['PublicKey'] = pub; new_peer['AllowedIPs'] = ips
    if psk: new_peer['PresharedKey'] = psk
    if ka:  new_peer['PersistentKeepalive'] = ka
    peers.append(new_peer); write_wg_conf(iface, cfg, peers); reload_interface(iface)
    # Derive server public key — prefer conf derivation (works even if iface is down)
    server_pub = ''
    if cfg.get('PrivateKey'):
        derived, _, rc = run_cmd(f'echo "{cfg["PrivateKey"]}" | wg pubkey', check=False)
        if rc == 0 and derived.strip():
            server_pub = derived.strip()
    if not server_pub:
        # Fallback: try wg show if interface is up
        live_pub, _, _ = run_cmd(f'wg show {iface} public-key', check=False)
        if live_pub.strip():
            server_pub = live_pub.strip()
    client_conf = None
    if priv:
        pub_ip = detect_public_ip() or '<SERVER_PUBLIC_IP>'
        client_conf = (f'[Interface]\nPrivateKey = {priv}\nAddress = {ips}\n'
                       + (f'DNS = {dns}\n' if dns else '')
                       + f'\n[Peer]\nPublicKey = {server_pub.strip()}\n'
                       + f'Endpoint = {pub_ip}:{cfg.get("ListenPort","51820")}\n'
                       + f'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'
                       + (f'PresharedKey = {psk}\n' if psk else ''))
    # Store encrypted private key so admin can retrieve config later
    if priv:
        store_peer_key(iface, pub, priv)

    pub_ip = detect_public_ip() or ''
    return jsonify({'success': True, 'message': f'Peer {name or pub[:12]} added.',
                    'public_key': pub, 'private_key': priv, 'client_config': client_conf,
                    'server_pubkey': server_pub.strip(),
                    'listen_port': cfg.get('ListenPort', '51820'),
                    'allowed_ips': ips,
                    'endpoint': f'{pub_ip}:{cfg.get("ListenPort","51820")}' if pub_ip else ''})

@app.route('/api/<iface>/peers/<path:pubkey>', methods=['PUT'])
@require_role('admin', 'operator')
def api_update_peer(iface, pubkey):
    data = request.json; cfg, peers = parse_wg_conf(iface); found = False
    for peer in peers:
        if peer.get('PublicKey') != pubkey: continue
        found = True
        if 'name' in data: peer['_name'] = data['name']
        if data.get('allowed_ips'): peer['AllowedIPs'] = data['allowed_ips']
        for dk, ck in [('preshared_key','PresharedKey'),('persistent_keepalive','PersistentKeepalive')]:
            if dk in data:
                if data[dk]: peer[ck] = data[dk]
                elif ck in peer: del peer[ck]
        # DNS belongs only in client config, not in server peer section — store in metadata
        if 'dns' in data:
            if 'DNS' in peer: del peer['DNS']
            pm = load_meta(iface).get(pubkey, {})
            pm['dns'] = data['dns']
            set_peer_meta(iface, pubkey, pm)
        break
    if not found: return jsonify({'error': 'Not found'}), 404
    write_wg_conf(iface, cfg, peers); reload_interface(iface)
    return jsonify({'success': True})

@app.route('/api/<iface>/peers/<path:pubkey>', methods=['DELETE'])
@require_role('admin', 'operator')
def api_delete_peer(iface, pubkey):
    cfg, peers = parse_wg_conf(iface); orig = len(peers)
    peers = [p for p in peers if p.get('PublicKey') != pubkey]
    if len(peers) == orig: return jsonify({'error': 'Not found'}), 404
    del_peer_meta(iface, pubkey)
    delete_peer_key(iface, pubkey)
    write_wg_conf(iface, cfg, peers)
    apply_firewall_scripts(iface)
    reload_interface(iface)
    return jsonify({'success': True})

@app.route('/api/<iface>/peers/<path:pubkey>/toggle', methods=['POST'])
@require_role('admin', 'operator')
def api_toggle_peer(iface, pubkey):
    try:
        cfg, peers = parse_wg_conf(iface)
        for peer in peers:
            if peer.get('PublicKey') != pubkey: continue
            peer['_enabled'] = not peer.get('_enabled', True)
            write_wg_conf(iface, cfg, peers); reload_interface(iface)
            state = 'enabled' if peer['_enabled'] else 'disabled'
            return jsonify({'success': True, 'enabled': peer['_enabled'], 'message': f'Peer {state}.'})
        return jsonify({'error': 'Peer not found'}), 404
    except Exception as e: return jsonify({'error': str(e)}), 500


# ════════════════════════════════════════════════════════════════════════════
# API — iptables rules
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/<iface>/peers/export')
@require_role('admin')
def api_export_peers(iface):
    cfg, peers = parse_wg_conf(iface)
    meta       = load_meta(iface)
    server_pub, _, _ = run_cmd(f'wg show {iface} public-key', check=False)
    listen_port = cfg.get('ListenPort', '51820')

    lines = []
    lines.append('=' * 72)
    lines.append(f'  WireGuard Peer Export — Interface: {iface}')
    lines.append(f'  Generated: {now_iso()}')
    lines.append(f'  Server public key: {server_pub.strip()}')
    lines.append(f'  Listen port: {listen_port}')
    lines.append('=' * 72)

    for i, peer in enumerate(peers, 1):
        pubkey  = peer.get('PublicKey', '')
        name    = peer.get('_name', '')
        ips     = peer.get('AllowedIPs', '')
        psk     = peer.get('PresharedKey', '')
        ka      = peer.get('PersistentKeepalive', '')
        dns     = peer.get('DNS', '')
        enabled = peer.get('_enabled', True)

        # Decrypt private key if stored
        privkey = get_peer_key(iface, pubkey) or '(not stored)'

        # Firewall rules from metadata
        pm       = meta.get(pubkey, {})
        ipt_rules = pm.get('ipt_rules', [])
        post_up   = pm.get('post_up', '')
        post_down = pm.get('post_down', '')

        lines.append('')
        lines.append(f'Peer {i}: {name if name else "(unnamed)"}')
        lines.append('-' * 48)
        lines.append(f'  Status      : {"enabled" if enabled else "DISABLED"}')
        lines.append(f'  Name        : {name}')
        lines.append(f'  Address     : {ips}')
        lines.append(f'  Public key  : {pubkey}')
        lines.append(f'  Private key : {privkey}')
        lines.append(f'  Preshared   : {psk if psk else "(none)"}')
        if ka:  lines.append(f'  Keepalive   : {ka}s')
        if dns: lines.append(f'  DNS         : {dns}')

        if ipt_rules:
            lines.append(f'  Firewall rules ({len(ipt_rules)}):')
            for r in ipt_rules:
                rtype  = r.get('type', '')
                action = r.get('action', '')
                detail = ''
                if rtype == 'port':
                    detail = f"port {r.get('port','any')} {r.get('proto','tcp+udp')}"
                elif rtype == 'destination':
                    detail = f"dst {r.get('dst_ip','')}"
                elif rtype == 'peer_isolation':
                    detail = f"peer {r.get('dst_peer_ip','all')}"
                elif rtype == 'internet':
                    detail = 'internet forward'
                elif rtype == 'ratelimit':
                    parts = []
                    if r.get('kbps_dl'): parts.append(f"dl {r['kbps_dl']}KB/s")
                    if r.get('kbps_ul'): parts.append(f"ul {r['kbps_ul']}KB/s")
                    detail = ', '.join(parts)
                elif rtype == 'nomasq':
                    detail = f"no-masq via {r.get('out_iface','eth0')}"
                lines.append(f'    [{action:6}] {rtype} — {detail}')
        else:
            lines.append('  Firewall rules: none')

        if post_up:
            lines.append(f'  PostUp      : {post_up}')
        if post_down:
            lines.append(f'  PostDown    : {post_down}')

    lines.append('')
    lines.append('=' * 72)
    lines.append(f'  Total: {len(peers)} peer(s)')
    lines.append('=' * 72)

    text = '\n'.join(lines)
    ts   = datetime.now().strftime('%Y%m%d-%H%M%S')

    from flask import Response
    return Response(
        text,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{iface}-peers-{ts}.txt"'}
    )


@app.route('/api/<iface>/traffic/live')
@require_auth
def api_traffic_live(iface):
    import time
    rx1, tx1 = read_iface_bytes(iface)
    if rx1 is None:
        return jsonify({'rx_bps': 0, 'tx_bps': 0, 'rx_human': '0 B/s', 'tx_human': '0 B/s'})
    time.sleep(1)
    rx2, tx2 = read_iface_bytes(iface)
    rx_bps = max(0, rx2 - rx1)
    tx_bps = max(0, tx2 - tx1)

    def fmt(b):
        if b < 1024:             return f'{b} B/s'
        if b < 1024**2:          return f'{b/1024:.1f} KB/s'
        if b < 1024**3:          return f'{b/1024**2:.2f} MB/s'
        return f'{b/1024**3:.2f} GB/s'

    return jsonify({'rx_bps': rx_bps, 'tx_bps': tx_bps,
                    'rx_human': fmt(rx_bps), 'tx_human': fmt(tx_bps)})


@app.route('/api/<iface>/traffic/history')
@require_auth
def api_traffic_history(iface):
    import time
    minutes = min(int(request.args.get('minutes', 60)), 1440)
    since   = int(time.time()) - minutes * 60
    with get_db() as db:
        rows = db.execute(
            'SELECT ts, rx_bps, tx_bps FROM traffic_samples '
            'WHERE iface=? AND ts >= ? ORDER BY ts ASC',
            (iface, since)
        ).fetchall()
    return jsonify([{'ts': r['ts'], 'rx': r['rx_bps'], 'tx': r['tx_bps']} for r in rows])


@app.route('/api/<iface>/traffic/stats')
@require_auth
def api_traffic_stats(iface):
    import time
    now   = int(time.time())
    day   = now - 86400
    hour  = now - 3600

    with get_db() as db:
        def q(since):
            rows = db.execute(
                'SELECT rx_bps, tx_bps FROM traffic_samples WHERE iface=? AND ts >= ?',
                (iface, since)
            ).fetchall()
            if not rows: return {'avg_rx': 0, 'avg_tx': 0, 'max_rx': 0, 'max_tx': 0, 'samples': 0}
            return {
                'avg_rx':  int(sum(r['rx_bps'] for r in rows) / len(rows)),
                'avg_tx':  int(sum(r['tx_bps'] for r in rows) / len(rows)),
                'max_rx':  max(r['rx_bps'] for r in rows),
                'max_tx':  max(r['tx_bps'] for r in rows),
                'samples': len(rows),
            }
        stats_24h = q(day)
        stats_1h  = q(hour)

    def fmt(b):
        if b < 1024:    return f'{b} B/s'
        if b < 1024**2: return f'{b/1024:.1f} KB/s'
        return f'{b/1024**2:.2f} MB/s'

    def annotate(s):
        return {**s,
                'avg_rx_h': fmt(s['avg_rx']), 'avg_tx_h': fmt(s['avg_tx']),
                'max_rx_h': fmt(s['max_rx']), 'max_tx_h': fmt(s['max_tx'])}

    return jsonify({'h24': annotate(stats_24h), 'h1': annotate(stats_1h)})


@app.route('/api/<iface>/peers/<path:pubkey>/privkey')
@require_role('admin')
def api_get_peer_privkey(iface, pubkey):
    privkey = get_peer_key(iface, pubkey)
    if privkey is None:
        return jsonify({'error': 'Private key not found. It was either not generated here or has been deleted.'}), 404
    # Also return everything needed to build the full client config
    cfg, _ = parse_wg_conf(iface)
    # Derive server public key from conf (works even if iface is down)
    server_pub = ''
    if cfg.get('PrivateKey'):
        derived, _, rc = run_cmd(f'echo "{cfg["PrivateKey"]}" | wg pubkey', check=False)
        if rc == 0 and derived.strip():
            server_pub = derived.strip()
    if not server_pub:
        live_pub, _, _ = run_cmd(f'wg show {iface} public-key', check=False)
        if live_pub.strip():
            server_pub = live_pub.strip()
    _, peers = parse_wg_conf(iface)
    peer_data = next((p for p in peers if p.get('PublicKey') == pubkey), {})
    peer_meta = load_meta(iface).get(pubkey, {})
    pub_ip = detect_public_ip() or ''
    im = load_iface_meta(iface)
    ext_port = im.get('external_port', '') or cfg.get('ListenPort', '51820')
    return jsonify({
        'private_key':   privkey,
        'public_key':    pubkey,
        'allowed_ips':   peer_data.get('AllowedIPs', ''),
        'dns':           peer_data.get('DNS', '') or peer_meta.get('dns', ''),
        'preshared_key': peer_data.get('PresharedKey', ''),
        'server_pubkey': server_pub.strip(),
        'listen_port':   ext_port,
        'endpoint':      f'{pub_ip}:{ext_port}' if pub_ip else '',
    })


@app.route('/api/<iface>/peers/<path:pubkey>/rules')
@require_auth
def api_get_rules(iface, pubkey):
    pm = load_meta(iface).get(pubkey, {})
    return jsonify({'ipt_rules': pm.get('ipt_rules',[]), 'post_up': pm.get('post_up',''), 'post_down': pm.get('post_down','')})

@app.route('/api/<iface>/peers/<path:pubkey>/rules', methods=['PUT'])
@require_role('admin', 'operator')
def api_set_rules(iface, pubkey):
    data = request.json or {}
    cfg, peers = parse_wg_conf(iface)

    peer_ip_cidr = data.get('allowed_ips', '')
    if not peer_ip_cidr:
        for p in peers:
            if p.get('PublicKey') == pubkey:
                peer_ip_cidr = p.get('AllowedIPs', '').split(',')[0].strip(); break

    ipt_rules = data.get('ipt_rules', [])

    # Update AllowedIPs in wg.conf if new value provided
    new_allowed_ips = data.get('new_allowed_ips', '').strip()
    if new_allowed_ips:
        # Validate all CIDRs before touching the file
        for cidr in new_allowed_ips.split(','):
            cidr = cidr.strip()
            if cidr:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    return jsonify({'error': f'Invalid CIDR: {cidr}'}), 400
        # Update peer entry
        for p in peers:
            if p.get('PublicKey') == pubkey:
                p['AllowedIPs'] = ', '.join(
                    c.strip() for c in new_allowed_ips.split(',') if c.strip()
                )
                break

    # Save updated rules to metadata
    set_peer_meta(iface, pubkey, {'ipt_rules': ipt_rules, 'allowed_ips': peer_ip_cidr})

    # Regenerate wg conf + firewall scripts with updated per-peer rules
    write_wg_conf(iface, cfg, peers)
    reload_interface(iface)

    # Apply firewall scripts immediately if interface is up
    apply_firewall_scripts(iface)

    return jsonify({'success': True})

@app.route('/api/<iface>/firewall-script')
@require_auth
def api_get_firewall_script(iface):
    try:
        with open(postup_path(iface)) as f:
            up = f.read()
    except FileNotFoundError:
        up = '# Script not yet generated'
    try:
        with open(postdown_path(iface)) as f:
            down = f.read()
    except FileNotFoundError:
        down = '# Script not yet generated'
    return jsonify({'postup': up, 'postdown': down,
                    'postup_path': postup_path(iface),
                    'postdown_path': postdown_path(iface)})

@app.route('/api/<iface>/peers/<path:pubkey>/rules/preview', methods=['POST'])
@require_role('admin', 'operator')  # readonly has no reason to call preview
def api_preview_rules(iface, pubkey):
    data = request.json
    peer_ip   = data.get('allowed_ips', '10.0.0.2/32').split('/')[0]
    ipt_rules = data.get('ipt_rules', [])
    lines     = _peer_rules_lines(iface, peer_ip, ipt_rules)
    preview   = chr(10).join(lines)
    return jsonify({'post_up': preview, 'post_down': ''})



# ════════════════════════════════════════════════════════════════════════════
# API — Backup / Restore (admin only)
# ════════════════════════════════════════════════════════════════════════════

import zipfile, io, hashlib
from flask import send_file

BACKUP_VERSION = 1

@app.route('/api/backup')
@require_role('admin')
def api_backup():
    """
    Create a ZIP archive containing:
      - All wgN.conf files
      - All wg-manager-wgN.json metadata files
      - wg-manager.db (users)
      - backup-manifest.json (metadata about the backup)
    """
    buf = io.BytesIO()
    manifest = {
        'version':    BACKUP_VERSION,
        'created':    now_iso(),
        'interfaces': [],
        'files':      [],
    }

    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # wg*.conf files
        try:
            for fname in sorted(os.listdir(WG_DIR)):
                if re.match(r'^wg\d+\.conf$', fname):
                    full = os.path.join(WG_DIR, fname)
                    data = open(full, 'rb').read()
                    zf.writestr(f'wireguard/{fname}', data)
                    manifest['interfaces'].append(fname[:-5])
                    manifest['files'].append({
                        'path': f'wireguard/{fname}',
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'size': len(data),
                    })
        except Exception as e:
            app.logger.warning(f'Backup: error reading WG_DIR: {e}')

        # wg-manager-wgN.json metadata files
        try:
            for fname in sorted(os.listdir(META_DIR)):
                if re.match(r'^wg-manager-wg\d+\.json$', fname):
                    full = os.path.join(META_DIR, fname)
                    data = open(full, 'rb').read()
                    zf.writestr(f'metadata/{fname}', data)
                    manifest['files'].append({
                        'path': f'metadata/{fname}',
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'size': len(data),
                    })
        except Exception as e:
            app.logger.warning(f'Backup: error reading metadata: {e}')

        # SQLite database
        try:
            db_data = open(DB_PATH, 'rb').read()
            zf.writestr('database/wg-manager.db', db_data)
            manifest['files'].append({
                'path': 'database/wg-manager.db',
                'sha256': hashlib.sha256(db_data).hexdigest(),
                'size': len(db_data),
            })
        except Exception as e:
            app.logger.warning(f'Backup: error reading DB: {e}')

        # JWT secret — required to decrypt stored private keys
        SECRET_FILE = '/etc/wg-manager.secret'
        try:
            if os.path.exists(SECRET_FILE):
                secret_data = open(SECRET_FILE, 'rb').read()
                zf.writestr('secrets/wg-manager.secret', secret_data)
                manifest['files'].append({
                    'path': 'secrets/wg-manager.secret',
                    'sha256': hashlib.sha256(secret_data).hexdigest(),
                    'size': len(secret_data),
                    'note': 'JWT secret — required to decrypt peer private keys',
                })
                manifest['has_secret'] = True
            else:
                manifest['has_secret'] = False
                app.logger.warning('Backup: /etc/wg-manager.secret not found — peer keys may not be decryptable after restore')
        except Exception as e:
            app.logger.warning(f'Backup: error reading secret: {e}')

        zf.writestr('backup-manifest.json', json.dumps(manifest, indent=2))

    buf.seek(0)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'wg-manager-backup-{ts}.zip',
    )


@app.route('/api/restore', methods=['POST'])
@require_role('admin')
def api_restore():
    """
    Restore from a backup ZIP.
    Expects multipart/form-data with field 'backup' containing the ZIP.
    Options (JSON body fields passed as form fields):
      restore_wireguard: bool  (default true)
      restore_metadata:  bool  (default true)
      restore_users:     bool  (default true)
    """
    if 'backup' not in request.files:
        return jsonify({'error': 'No backup file provided'}), 400

    f              = request.files['backup']
    restore_wg     = request.form.get('restore_wireguard', 'true').lower() == 'true'
    restore_meta   = request.form.get('restore_metadata',  'true').lower() == 'true'
    restore_db     = request.form.get('restore_users',     'true').lower() == 'true'
    restore_secret = request.form.get('restore_secret',    'true').lower() == 'true'

    restored = []
    errors   = []

    try:
        buf = io.BytesIO(f.read())
        with zipfile.ZipFile(buf, 'r') as zf:
            names = zf.namelist()

            # Validate manifest
            if 'backup-manifest.json' not in names:
                return jsonify({'error': 'Invalid backup: missing manifest'}), 400
            manifest = json.loads(zf.read('backup-manifest.json'))
            if manifest.get('version') != BACKUP_VERSION:
                return jsonify({'error': f'Unsupported backup version: {manifest.get("version")}'}), 400

            # Bring down all WG interfaces before restoring
            active_ifaces = []
            for iname in manifest.get('interfaces', []):
                _, _, rc = run_cmd(f'ip link show {iname}', check=False)
                if rc == 0:
                    active_ifaces.append(iname)
                    run_cmd(f'wg-quick down {iname}', check=False)

            # Restore wg*.conf
            if restore_wg:
                for name in names:
                    if name.startswith('wireguard/') and name.endswith('.conf'):
                        fname = os.path.basename(name)
                        dest  = os.path.join(WG_DIR, fname)
                        try:
                            with open(dest, 'wb') as out:
                                out.write(zf.read(name))
                            os.chmod(dest, 0o600)
                            restored.append(fname)
                        except Exception as e:
                            errors.append(f'{fname}: {e}')

            # Restore metadata JSON
            if restore_meta:
                for name in names:
                    if name.startswith('metadata/') and name.endswith('.json'):
                        fname = os.path.basename(name)
                        dest  = os.path.join(META_DIR, fname)
                        try:
                            with open(dest, 'wb') as out:
                                out.write(zf.read(name))
                            restored.append(fname)
                        except Exception as e:
                            errors.append(f'{fname}: {e}')

            # Restore SQLite DB
            if restore_db and 'database/wg-manager.db' in names:
                try:
                    with open(DB_PATH, 'wb') as out:
                        out.write(zf.read('database/wg-manager.db'))
                    restored.append('wg-manager.db')
                except Exception as e:
                    errors.append(f'wg-manager.db: {e}')

            # Restore JWT secret
            if restore_secret and 'secrets/wg-manager.secret' in names:
                try:
                    secret_data = zf.read('secrets/wg-manager.secret')
                    with open('/etc/wg-manager.secret', 'wb') as out:
                        out.write(secret_data)
                    os.chmod('/etc/wg-manager.secret', 0o600)
                    # Update running app's JWT secret so keys are immediately usable
                    new_secret = secret_data.decode().strip()
                    app.config['JWT_SECRET_KEY'] = new_secret
                    restored.append('wg-manager.secret')
                except Exception as e:
                    errors.append(f'wg-manager.secret: {e}')

            # Bring interfaces back up
            for iname in active_ifaces:
                run_cmd(f'wg-quick up {iname}', check=False)

    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid ZIP file'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'success':  len(errors) == 0,
        'restored': restored,
        'errors':   errors,
        'message':  f'Restored {len(restored)} file(s).' + (f' {len(errors)} error(s).' if errors else ''),
    })


@app.route('/api/backup/manifest')
@require_role('admin')
def api_backup_manifest():
    """Return info about what would be backed up, without creating the ZIP."""
    ifaces, meta_files = [], []
    db_exists = os.path.exists(DB_PATH)
    try:
        for fname in sorted(os.listdir(WG_DIR)):
            if re.match(r'^wg\d+\.conf$', fname):
                iface = fname[:-5]
                cfg, peers = parse_wg_conf(iface)
                _, _, rc   = run_cmd(f'ip link show {iface}', check=False)
                ifaces.append({
                    'name':        iface,
                    'up':          rc == 0,
                    'peers':       len(peers),
                    'address':     cfg.get('Address', ''),
                    'listen_port': cfg.get('ListenPort', ''),
                    'conf_size':   os.path.getsize(conf_path(iface)),
                })
    except Exception: pass
    try:
        for fname in sorted(os.listdir(META_DIR)):
            if re.match(r'^wg-manager-wg\d+\.json$', fname):
                meta_files.append({'name': fname, 'size': os.path.getsize(os.path.join(META_DIR, fname))})
    except Exception: pass
    user_count = 0
    try:
        with get_db() as db:
            user_count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    except Exception: pass
    return jsonify({
        'interfaces': ifaces,
        'metadata_files': meta_files,
        'database': {'exists': db_exists, 'path': DB_PATH, 'users': user_count},
        'wg_dir': WG_DIR,
    })

# ════════════════════════════════════════════════════════════════════════════
# Error handlers
# ════════════════════════════════════════════════════════════════════════════

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback; app.logger.error(traceback.format_exc())
    return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def handle_404(e): return jsonify({'error': 'Not found'}), 404

@app.errorhandler(405)
def handle_405(e): return jsonify({'error': 'Method not allowed'}), 405


# ════════════════════════════════════════════════════════════════════════════
# Startup
# ════════════════════════════════════════════════════════════════════════════

def read_iface_bytes(iface):
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if line.strip().startswith(iface + ':'):
                    parts = line.split(':')[1].split()
                    return int(parts[0]), int(parts[8])
    except Exception:
        pass
    return None, None


def traffic_sampler():
    """Background thread: sample all wg interfaces every 10s, store in SQLite."""
    import time
    prev = {}  # {iface: (rx, tx, ts)}
    INTERVAL = 10

    while True:
        try:
            ifaces = [f[:-5] for f in os.listdir(WG_DIR)
                      if re.match(r'^wg\d+\.conf$', f)]
        except Exception:
            ifaces = []

        now = int(time.time())

        for iface in ifaces:
            rx, tx = read_iface_bytes(iface)
            if rx is None:
                continue
            if iface in prev:
                prx, ptx, pts = prev[iface]
                dt = now - pts
                if dt > 0:
                    rx_bps = max(0, (rx - prx)) // dt
                    tx_bps = max(0, (tx - ptx)) // dt
                    try:
                        with get_db() as db:
                            db.execute(
                                'INSERT INTO traffic_samples (iface, ts, rx_bps, tx_bps) VALUES (?,?,?,?)',
                                (iface, now, rx_bps, tx_bps)
                            )
                            # Cleanup older than 25h
                            db.execute(
                                'DELETE FROM traffic_samples WHERE iface=? AND ts < ?',
                                (iface, now - 90000)
                            )
                            db.commit()
                    except Exception as e:
                        app.logger.warning(f'Traffic sampler DB error: {e}')
            prev[iface] = (rx, tx, now)

        time.sleep(INTERVAL)


if __name__ == '__main__':
    init_db()
    # Warn immediately if IPv4 forwarding is off — VPN routing won't work without it
    if check_ip_forwarding() is False:
        app.logger.warning(
            '⚠  IPv4 forwarding is DISABLED. '
            'Peer traffic will not be routed. '
            'Run: echo 1 > /proc/sys/net/ipv4/ip_forward  '
            'or use the Settings page to enable it.'
        )
    import threading
    threading.Thread(target=traffic_sampler, daemon=True, name='traffic-sampler').start()
    threading.Thread(target=_fetch_public_ip, daemon=True, name='ip-detect').start()
    app.run(host='0.0.0.0', port=5000, debug=False)