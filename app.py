#!/usr/bin/env python3
"""
WireGuard Web Manager
A lightweight web interface for managing WireGuard peers.
Access via SSH port forwarding: ssh -L 5000:127.0.0.1:5000 user@server
"""

import os
import re
import time
import json
import subprocess
import secrets
import tempfile
import ipaddress
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

WG_CONFIG_DIR = Path(os.environ.get('WG_CONFIG_DIR', '/etc/wireguard'))
WG_INTERFACE   = os.environ.get('WG_INTERFACE', 'wg0')
CLIENTS_DIR    = WG_CONFIG_DIR / 'clients'


# ─── Shell helpers ────────────────────────────────────────────────────────────

def run(cmd, input=None, check=False):
    """Run a command; returns (stdout, stderr, returncode)."""
    r = subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        capture_output=True,
        text=True,
        input=input,
    )
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def wg_genkey():
    priv, _, _ = run('wg genkey', check=True)
    pub,  _, _ = run(['wg', 'pubkey'], input=priv, check=True)
    return priv, pub


def wg_genpsk():
    psk, _, _ = run('wg genpsk', check=True)
    return psk


# ─── Formatting ───────────────────────────────────────────────────────────────

def fmt_bytes(n):
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if n < 1024:
            return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} PiB'


def fmt_ago(ts):
    if not ts:
        return 'Never'
    s = time.time() - ts
    if s < 60:    return f'{int(s)}s ago'
    if s < 3600:  return f'{int(s/60)}m ago'
    if s < 86400: return f'{int(s/3600)}h ago'
    return f'{int(s/86400)}d ago'


# ─── WireGuard config file ────────────────────────────────────────────────────

class WgConfig:
    """
    Read / write a wg*.conf file while preserving structure.
    Peer names are stored as # comments immediately before each [Peer] block.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.lines = self.path.read_text().splitlines() if self.path.exists() else []

    def save(self):
        self.path.write_text('\n'.join(self.lines) + '\n')

    # ── Readers ──────────────────────────────────────────────────────────────

    def interface(self):
        result, in_iface = {}, False
        for line in self.lines:
            s = line.strip()
            if s == '[Interface]':
                in_iface = True
            elif s.startswith('['):
                in_iface = False
            elif in_iface and '=' in s and not s.startswith('#'):
                k, _, v = s.partition('=')
                result[k.strip()] = v.strip()
        return result

    def peers(self):
        """Return list of peer dicts; internal keys prefixed with _."""
        peers, i = [], 0
        while i < len(self.lines):
            s = self.lines[i].strip()
            if s == '[Peer]':
                peer = {'_idx': i, '_name': ''}
                # check for a comment on the line immediately before
                if i > 0 and self.lines[i - 1].strip().startswith('#'):
                    peer['_name'] = self.lines[i - 1].strip()[1:].strip()
                j = i + 1
                while j < len(self.lines) and not self.lines[j].strip().startswith('['):
                    ls = self.lines[j].strip()
                    if '=' in ls and not ls.startswith('#'):
                        k, _, v = ls.partition('=')
                        peer[k.strip()] = v.strip()
                    j += 1
                peers.append(peer)
                i = j
            else:
                i += 1
        return peers

    # ── Writers ──────────────────────────────────────────────────────────────

    def add_peer(self, name, pubkey, allowed_ips, psk=None, keepalive=None):
        self.lines.append('')
        if name:
            self.lines.append(f'# {name}')
        self.lines.append('[Peer]')
        self.lines.append(f'PublicKey = {pubkey}')
        if psk:
            self.lines.append(f'PresharedKey = {psk}')
        self.lines.append(f'AllowedIPs = {allowed_ips}')
        if keepalive:
            self.lines.append(f'PersistentKeepalive = {keepalive}')

    def remove_peer(self, pubkey):
        target = next((p for p in self.peers() if p.get('PublicKey') == pubkey), None)
        if not target:
            return False
        idx = target['_idx']
        end = idx + 1
        while end < len(self.lines) and not self.lines[end].strip().startswith('['):
            end += 1
        # Walk back to exclude trailing blank lines and the next peer's # name comment
        while end > idx + 1:
            prev = self.lines[end - 1].strip()
            if prev == '' or prev.startswith('#'):
                end -= 1
            else:
                break
        start = idx
        if start > 0 and self.lines[start - 1].strip().startswith('#'):
            start -= 1
        if start > 0 and self.lines[start - 1].strip() == '':
            start -= 1
        del self.lines[start:end]
        return True

    def update_peer(self, pubkey, updates):
        target = next((p for p in self.peers() if p.get('PublicKey') == pubkey), None)
        if not target:
            return False
        idx = target['_idx']

        for key, value in updates.items():
            # Handle rename (comment line)
            if key == '_name':
                if idx > 0 and self.lines[idx - 1].strip().startswith('#'):
                    if value:
                        self.lines[idx - 1] = f'# {value}'
                    else:
                        del self.lines[idx - 1]
                        idx -= 1
                elif value:
                    self.lines.insert(idx, f'# {value}')
                    idx += 1
                continue

            # Find existing key inside peer block
            j, found = idx + 1, False
            while j < len(self.lines) and not self.lines[j].strip().startswith('['):
                ls = self.lines[j].strip()
                if re.match(rf'^{re.escape(key)}\s*=', ls):
                    if value:
                        self.lines[j] = f'{key} = {value}'
                    else:
                        del self.lines[j]
                    found = True
                    break
                j += 1

            if not found and value:
                self.lines.insert(idx + 1, f'{key} = {value}')
                idx += 1

        return True


# ─── Live WireGuard data ──────────────────────────────────────────────────────

def get_live_data():
    """Parse `wg show <iface> dump`; returns (peer_dict, iface_info | None)."""
    out, _, rc = run(f'wg show {WG_INTERFACE} dump')
    if rc != 0 or not out:
        return {}, None
    lines = out.splitlines()
    iface_info, peer_data = None, {}
    for i, line in enumerate(lines):
        parts = line.split('\t')
        if i == 0 and len(parts) >= 3:
            iface_info = {'public_key': parts[1], 'listen_port': parts[2]}
        elif i > 0 and len(parts) >= 7:
            ts = int(parts[4]) if parts[4].isdigit() else 0
            peer_data[parts[0]] = {
                'endpoint':          parts[2] if parts[2] != '(none)' else None,
                'latest_handshake':  ts,
                'transfer_rx':       int(parts[5]) if parts[5].isdigit() else 0,
                'transfer_tx':       int(parts[6]) if parts[6].isdigit() else 0,
            }
    return peer_data, iface_info


# ─── Settings ────────────────────────────────────────────────────────────────

SETTINGS_PATH = WG_CONFIG_DIR / 'wg-manager-settings.json'

_smart_defaults_cache = None

def _smart_defaults():
    """Auto-detect sensible defaults from system. Cached after first call."""
    global _smart_defaults_cache
    if _smart_defaults_cache is not None:
        return _smart_defaults_cache

    cfg  = WgConfig(WG_CONFIG_DIR / f'{WG_INTERFACE}.conf')
    port = cfg.interface().get('ListenPort', '51820')

    # Try to detect public IP (several fallbacks)
    public_ip = ''
    for cmd in ['curl -s --max-time 3 ifconfig.me',
                'curl -s --max-time 3 api.ipify.org',
                'curl -s --max-time 3 icanhazip.com']:
        out, _, rc = run(cmd)
        if rc == 0 and out.strip():
            public_ip = out.strip()
            break

    endpoint = f'{public_ip}:{port}' if public_ip else f'YOUR_SERVER_IP:{port}'
    _smart_defaults_cache = {
        'default_endpoint':  endpoint,
        'default_keepalive': '25',
        'default_dns':       '',
        'default_routes':    '',
    }
    return _smart_defaults_cache

def load_settings():
    saved = {}
    if SETTINGS_PATH.exists():
        try:
            saved = json.loads(SETTINGS_PATH.read_text())
        except Exception:
            pass
    # Merge: smart defaults as base, saved values override
    defaults = _smart_defaults()
    return {**defaults, **saved}

def save_settings(data):
    SETTINGS_PATH.write_text(json.dumps(data, indent=2))


@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(load_settings())

@app.route('/api/settings', methods=['POST'])
def post_settings():
    try:
        data = request.json or {}
        allowed = {'default_endpoint', 'default_keepalive', 'default_dns', 'default_routes'}
        settings = load_settings()
        for k, v in data.items():
            if k in allowed:
                settings[k] = v.strip() if isinstance(v, str) else v
        save_settings(settings)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Client config storage ────────────────────────────────────────────────────

def _client_path(pubkey):
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = pubkey[:16].replace('/', '_').replace('+', '-')
    return CLIENTS_DIR / f'{safe}.conf'


def save_client_config(pubkey, text):
    _client_path(pubkey).write_text(text)


def load_client_config(pubkey):
    p = _client_path(pubkey)
    return p.read_text() if p.exists() else None


def derive_ips(client_ip, server_address=''):
    """
    From client_ip (e.g. '10.0.0.7', '10.0.0.7/32', or '10.0.0.7/24'), derive:
      - client_addr:    '10.0.0.7/24'  (client Interface Address)
      - server_allowed: '10.0.0.7/32'  (server-side AllowedIPs for this peer)
      - client_routes:  '10.0.0.0/24'  (client-side AllowedIPs / routes)
    When the input has /32 or no prefix, fall back to the server's subnet prefix.
    """
    try:
        iface = ipaddress.ip_interface(client_ip)
        prefix = iface.network.prefixlen

        # If /32 or bare IP, borrow subnet prefix from server Address
        if prefix == 32 and server_address:
            try:
                server_prefix = ipaddress.ip_interface(server_address).network.prefixlen
                if server_prefix < 32:
                    iface = ipaddress.ip_interface(f'{iface.ip}/{server_prefix}')
            except ValueError:
                pass

        client_addr    = str(iface)               # 10.0.0.7/24
        server_allowed = str(iface.ip) + '/32'    # 10.0.0.7/32
        client_routes  = str(iface.network)       # 10.0.0.0/24
    except ValueError:
        client_addr    = client_ip
        server_allowed = client_ip
        client_routes  = client_ip
    return client_addr, server_allowed, client_routes


def build_client_config(*, privkey, pubkey, psk, server_pubkey,
                         server_endpoint, server_port, client_addr,
                         client_routes, dns, keepalive):
    cfg = f'[Interface]\nPrivateKey = {privkey}\n'
    cfg += f'Address = {client_addr}\n'
    if dns:
        cfg += f'DNS = {dns}\n'
    cfg += f'\n[Peer]\nPublicKey = {server_pubkey}\n'
    if psk:
        cfg += f'PresharedKey = {psk}\n'
    cfg += f'AllowedIPs = {client_routes}\n'
    if server_endpoint:
        ep = server_endpoint if ':' in server_endpoint else f'{server_endpoint}:{server_port}'
        cfg += f'Endpoint = {ep}\n'
    if keepalive:
        cfg += f'PersistentKeepalive = {keepalive}\n'
    return cfg


# ─── API routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    try:
        cfg  = WgConfig(WG_CONFIG_DIR / f'{WG_INTERFACE}.conf')
        iface_cfg = cfg.interface()
        peers_cfg = cfg.peers()
        live_peers, live_iface = get_live_data()
        now = time.time()

        enriched = []
        for p in peers_cfg:
            pub  = p.get('PublicKey', '')
            live = live_peers.get(pub, {})
            ts   = live.get('latest_handshake', 0)
            enriched.append({
                'name':               p.get('_name', ''),
                'PublicKey':          pub,
                'AllowedIPs':         p.get('AllowedIPs', ''),
                'PersistentKeepalive': p.get('PersistentKeepalive', ''),
                'endpoint':           live.get('endpoint'),
                'latest_handshake':   ts,
                'latest_handshake_str': fmt_ago(ts),
                'transfer_rx':        live.get('transfer_rx', 0),
                'transfer_tx':        live.get('transfer_tx', 0),
                'transfer_rx_str':    fmt_bytes(live.get('transfer_rx', 0)),
                'transfer_tx_str':    fmt_bytes(live.get('transfer_tx', 0)),
                'online':             bool(ts and now - ts < 180),
                'has_config':         load_client_config(pub) is not None,
            })

        return jsonify({
            'running': live_iface is not None,
            'interface': {
                **iface_cfg,
                'name':        WG_INTERFACE,
                'public_key':  live_iface['public_key']  if live_iface else '',
                'listen_port': live_iface['listen_port'] if live_iface else iface_cfg.get('ListenPort', ''),
            },
            'peers':    enriched,
            'settings': load_settings(),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/peers', methods=['POST'])
def add_peer():
    try:
        d        = request.json
        settings = load_settings()

        name            = (d.get('name')            or '').strip()
        client_ip       = (d.get('client_ip')       or '').strip()
        use_psk         = bool(d.get('use_psk'))
        existing_pubkey = (d.get('pubkey')          or '').strip()

        # Field-level fallback: form value → saved default setting
        server_endpoint = (d.get('server_endpoint') or settings.get('default_endpoint')  or '').strip()
        keepalive       = (d.get('keepalive')       or settings.get('default_keepalive') or '').strip()
        dns             = (d.get('dns')             or settings.get('default_dns')        or '').strip()

        if not client_ip:
            return jsonify({'error': 'Client IP / AllowedIPs is required'}), 400

        # Use existing public key or generate a new keypair
        if existing_pubkey:
            pubkey  = existing_pubkey
            privkey = None
            psk     = wg_genpsk() if use_psk else None
        else:
            privkey, pubkey = wg_genkey()
            psk = wg_genpsk() if use_psk else None

        cfg       = WgConfig(WG_CONFIG_DIR / f'{WG_INTERFACE}.conf')
        iface_cfg = cfg.interface()

        # Check for duplicate PublicKey
        existing_peers = cfg.peers()
        existing_keys = {p.get('PublicKey') for p in existing_peers}
        if pubkey in existing_keys:
            return jsonify({'error': 'A peer with this PublicKey already exists'}), 400

        # Derive server-side AllowedIPs and client-side address/routes
        # Uses server's Address subnet to fix up bare IPs or /32 inputs
        server_address = iface_cfg.get('Address', '')
        client_addr, server_allowed, client_routes = derive_ips(client_ip, server_address)

        # Check for duplicate AllowedIPs
        existing_ips = {p.get('AllowedIPs') for p in existing_peers}
        if server_allowed in existing_ips:
            return jsonify({'error': f'AllowedIPs {server_allowed} is already assigned to another peer'}), 400
        # Allow manual override: form → saved default → auto-derived
        override = (d.get('client_routes') or settings.get('default_routes') or '').strip()
        if override:
            client_routes = override

        # Derive server public key from private key in config
        server_privkey = iface_cfg.get('PrivateKey', '')
        server_pubkey  = ''
        if server_privkey:
            server_pubkey, _, _ = run(['wg', 'pubkey'], input=server_privkey)
        server_port = iface_cfg.get('ListenPort', '51820')

        # Write config file only — apply manually via reload
        cfg.add_peer(name, pubkey, server_allowed, psk=psk, keepalive=keepalive or None)
        cfg.save()

        # Build and persist client config only when we have the private key
        client_cfg = None
        if privkey:
            client_cfg = build_client_config(
                privkey=privkey, pubkey=pubkey, psk=psk,
                server_pubkey=server_pubkey, server_endpoint=server_endpoint,
                server_port=server_port, client_addr=client_addr,
                client_routes=client_routes, dns=dns, keepalive=keepalive,
            )
            save_client_config(pubkey, client_cfg)

        resp = {'pubkey': pubkey, 'client_config': client_cfg}
        if privkey:
            resp['privkey'] = privkey
        if psk:
            resp['psk'] = psk
        return jsonify(resp)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/peers/<path:pubkey>', methods=['PUT'])
def update_peer(pubkey):
    try:
        d = request.json
        updates = {}
        if 'name' in d:        updates['_name']              = d['name']
        if 'allowed_ips' in d: updates['AllowedIPs']          = d['allowed_ips']
        if 'keepalive'   in d: updates['PersistentKeepalive'] = d['keepalive']

        cfg = WgConfig(WG_CONFIG_DIR / f'{WG_INTERFACE}.conf')
        if not cfg.update_peer(pubkey, updates):
            return jsonify({'error': 'Peer not found'}), 404
        cfg.save()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/peers/<path:pubkey>', methods=['DELETE'])
def delete_peer(pubkey):
    try:
        cfg = WgConfig(WG_CONFIG_DIR / f'{WG_INTERFACE}.conf')
        if not cfg.remove_peer(pubkey):
            return jsonify({'error': 'Peer not found'}), 404
        cfg.save()

        p = _client_path(pubkey)
        if p.exists():
            p.unlink()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/peers/<path:pubkey>/config')
def get_config(pubkey):
    cfg_text = load_client_config(pubkey)
    if not cfg_text:
        return jsonify({'error': 'Client config not saved on this server'}), 404
    return jsonify({'config': cfg_text})


@app.route('/api/peers/<path:pubkey>/qr')
def get_qr(pubkey):
    try:
        import qrcode, io
    except ImportError:
        return jsonify({'error': 'Run: pip install qrcode[pil]'}), 500
    try:
        cfg_text = load_client_config(pubkey)
        if not cfg_text:
            return jsonify({'error': 'Client config not found'}), 404
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(cfg_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return Response(buf.getvalue(), mimetype='image/png')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/interface/reload', methods=['POST'])
def reload_interface():
    """Hot-reload: sync running config from file without dropping connections."""
    try:
        stripped, err, rc = run(f'wg-quick strip {WG_INTERFACE}')
        if rc != 0:
            return jsonify({'error': err or stripped}), 500
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(stripped)
            tmp = f.name
        out, err, rc = run(f'wg syncconf {WG_INTERFACE} {tmp}')
        os.unlink(tmp)
        if rc != 0:
            return jsonify({'error': err or out}), 500
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/interface/restart', methods=['POST'])
def restart_interface():
    """Hard restart: wg-quick down/up. Drops all connections briefly."""
    try:
        run(f'wg-quick down {WG_INTERFACE}', check=False)
        out, err, rc = run(f'wg-quick up {WG_INTERFACE}')
        if rc != 0:
            return jsonify({'error': err or out}), 500
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'WireGuard Manager running on http://127.0.0.1:{port}')
    print(f'Managing interface: {WG_INTERFACE}')
    app.run(host='127.0.0.1', port=port, debug=False)
