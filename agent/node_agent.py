#!/usr/bin/env python3
import os, json, subprocess, time, socket, ssl
from flask import Flask, request, jsonify, abort, send_file
from io import BytesIO
import zipfile
from datetime import datetime
from functools import wraps
import re
import ipaddress as ipa
import subprocess, os
import requests
import hmac

try:
    from dotenv import load_dotenv
    _here = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(_here, '.env'))
except Exception:
    pass

API_KEY = os.environ.get('API_KEY','') 
WG_CONF_PATH = os.environ.get('WIREGUARD_CONF_PATH','/etc/wireguard')

app = Flask(__name__)

def require_api_key(f):
    @wraps(f)
    def inner(*a, **k):
        want = (API_KEY or '').strip()
        if not want:
            return jsonify({'error': 'Unauthorized'}), 401

        auth = (request.headers.get('Authorization') or '').strip()
        bearer = auth.split(None, 1)[1].strip() if auth.startswith('Bearer ') else ''
        xhdr = (request.headers.get('X-API-KEY') or '').strip()

        supplied = bearer or xhdr
        if supplied and hmac.compare_digest(supplied, want):
            return f(*a, **k)
        return jsonify({'error': 'Unauthorized'}), 401
    return inner


def _public_ipv4():
    try:
        return requests.get('https://api.ipify.org', timeout=2).text.strip()
    except Exception:
        return None


def _iface_up(name: str) -> bool:
    try:
        return subprocess.run(
            ['ip', 'link', 'show', 'dev', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5
        ).returncode == 0
    except Exception:
        return False
    
def _split_address(addr_field: str) -> list[str]:
    if not addr_field:
        return []
    parts = re.split(r'[,\s]+', addr_field.strip())
    return [p for p in parts if '/' in p]

def _primary_iface(addr_field: str):

    cidrs = _split_address(addr_field)
    for c in cidrs:
        try:
            ii = ipa.ip_interface(c)
            if ii.version == 4:
                return ii
        except Exception:
            pass
    for c in cidrs:
        try:
            return ipa.ip_interface(c)
        except Exception:
            pass
    return None

def _extract_ips(conf_path: str, target_net: ipa._BaseNetwork) -> set:

    used = set()
    if not (conf_path and os.path.isfile(conf_path)):
        return used
    try:
        with open(conf_path, 'r') as f:
            in_peer = False
            block = []
            for raw in f:
                line = raw.strip()
                if line.startswith('[') and line.endswith(']'):
                    if in_peer and block:
                        for L in block:
                            if L.lower().startswith('allowedips'):
                                val = L.split('=', 1)[1]
                                for c in val.split(','):
                                    c = c.strip()
                                    try:
                                        ii = ipa.ip_interface(c)
                                        if ii.network.prefixlen in (32, 128) and (ii.ip in target_net):
                                            used.add(ii.ip)
                                    except Exception:
                                        pass
                        block = []
                    in_peer = (line[1:-1].lower() == 'peer')
                else:
                    if in_peer and '=' in line:
                        block.append(line)
            if in_peer and block:
                for L in block:
                    if L.lower().startswith('allowedips'):
                        val = L.split('=', 1)[1]
                        for c in val.split(','):
                            c = c.strip()
                            try:
                                ii = ipa.ip_interface(c)
                                if ii.network.prefixlen in (32, 128) and (ii.ip in target_net):
                                    used.add(ii.ip)
                            except Exception:
                                pass
    except Exception:
        pass
    return used

def _extract_wgip(iface_name: str, target_net: ipa._BaseNetwork) -> set:

    used = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', iface_name, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) != 2:
                continue
            for c in parts[1].split(','):
                c = c.strip()
                try:
                    ii = ipa.ip_interface(c)
                    if ii.network.prefixlen in (32, 128) and (ii.ip in target_net):
                        used.add(ii.ip)
                except Exception:
                    pass
    except Exception:
        pass
    return used

def available_ips(iface_name: str, iface_addr_field: str, conf_dir: str) -> list[str]:

    ii = _primary_iface(iface_addr_field)
    if ii is None:
        return []

    net = ii.network
    iface_ip = ii.ip

    if net.version == 6 and net.prefixlen < 120:
        return []  

    conf_path = os.path.join(conf_dir, f'{iface_name}.conf')

    used_hosts = set()
    used_hosts |= _extract_ips(conf_path, net)
    used_hosts |= _extract_wgip(iface_name, net)

    return [f"{host}/{net.prefixlen}"
            for host in net.hosts()
            if host != iface_ip and host not in used_hosts]

def _read_iface(path):
    address = listen_port = private_key = mtu = dns = None
    in_iface = False
    with open(path,'r') as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith('#'): continue
            if s.startswith('[') and s.endswith(']'):
                in_iface = (s[1:-1].lower()=='interface'); continue
            if not in_iface or '=' not in s: continue
            k,v = [x.strip() for x in s.split('=',1)]
            lk = k.lower()
            if lk=='address': address=v
            elif lk=='listenport':
                try: listen_port=int(v)
                except: pass
            elif lk=='privatekey': private_key=v
            elif lk=='mtu': 
                try: mtu=int(v)
                except: pass
            elif lk=='dns': dns=v
    if not (address and listen_port and private_key): return None
    return {
        'name': os.path.splitext(os.path.basename(path))[0],
        'path': path, 'address': address, 'listen_port': listen_port,
        'mtu': mtu, 'dns': dns
    }

def hostPrefix(host_cidr):
    import ipaddress as ipa
    ip = ipa.ip_interface(host_cidr).ip
    return f"{ip}/{32 if ip.version==4 else 128}"

def _orig_host(allowed: str | None) -> str | None:
    if not allowed: 
        return None
    for c in (x.strip() for x in allowed.split(',')):
        try:
            ii = ipa.ip_interface(c)
            if ii.network.prefixlen in (32, 128):
                return hostPrefix(c)  
        except Exception:
            pass
    return None

def _route(cmd, cidr):
    try:
        subprocess.run(['ip', 'route', *cmd, 'blackhole', cidr],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

@app.route('/api/health')
@require_api_key
def health():
    return jsonify(ok=True, host=socket.gethostname(), now=int(time.time()), public_ipv4=_public_ipv4())


def _safe_iface_name(name: str) -> str:
    name = (name or '').strip()
    if not re.match(r'^[A-Za-z0-9_.-]{1,32}$', name):
        raise ValueError('Interface name may contain only letters, numbers, dot, dash, and underscore, max 32 characters')
    if name in ('.', '..') or ':' in name or '/' in name:
        raise ValueError('Invalid interface name')
    return name


def _wg_conf_dir() -> str:
    return WG_CONF_PATH if os.path.isdir(WG_CONF_PATH) else os.path.dirname(WG_CONF_PATH)


def _iface_conf_path(name: str) -> str:
    return os.path.join(_wg_conf_dir(), f'{name}.conf')

# ------------------------------------------------------------
# Node WireGuard .conf backup / restore
# ------------------------------------------------------------
def _safe_conf_filename(filename: str) -> str:
    filename = os.path.basename((filename or '').strip())

    if not filename.endswith('.conf'):
        raise ValueError('Only .conf files are allowed')

    iface = filename[:-5]
    _safe_iface_name(iface)

    return filename


def _read_node_wg_confs() -> list[tuple[str, bytes]]:
    root = _wg_conf_dir()
    out = []

    if not os.path.isdir(root):
        return out

    for fn in sorted(os.listdir(root)):
        if not fn.endswith('.conf'):
            continue

        try:
            safe = _safe_conf_filename(fn)
        except Exception:
            continue

        path = os.path.join(root, safe)

        if not os.path.isfile(path):
            continue

        try:
            with open(path, 'rb') as f:
                out.append((safe, f.read()))
        except Exception:
            pass

    return out

def _node_env_path() -> str | None:
    """
    Return this node agent's .env path if it exists.

    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]

    for p in candidates:
        try:
            if p and os.path.isfile(p):
                return p
        except Exception:
            pass

    return None

@app.get('/api/backup/wg')
@require_api_key
def node_backup_wg():

    mem = BytesIO()

    files = _read_node_wg_confs()
    env_path = _node_env_path()
    has_env = bool(env_path and os.path.isfile(env_path))

    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        for filename, data in files:
            z.writestr(f'wg/{filename}', data)

        if has_env:
            try:
                z.write(env_path, arcname='env/.env')
            except Exception:
                has_env = False

        z.writestr('meta/node.json', json.dumps({
            'ok': True,
            'host': socket.gethostname(),
            'created_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
            'wg_conf_path': _wg_conf_dir(),
            'files': [name for name, _ in files],
            'env_file': bool(has_env),
        }, indent=2))

    mem.seek(0)

    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return send_file(
        mem,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'node_wg_backup_{socket.gethostname()}_{ts}.zip',
    )

@app.post('/api/backup/wg/restore')
@require_api_key
def node_restore_wg():

    data = request.get_json(silent=True) or {}
    files = data.get('files') or {}
    bring_up = bool(data.get('bring_up', False))

    if not isinstance(files, dict) or not files:
        return jsonify(ok=False, error='no_files'), 400

    root = _wg_conf_dir()
    os.makedirs(root, exist_ok=True)

    restored = []
    errors = []
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

    for raw_name, content in files.items():
        try:
            filename = _safe_conf_filename(raw_name)
            iface = filename[:-5]

            if isinstance(content, bytes):
                text = content.decode('utf-8', 'replace')
            else:
                text = str(content or '')

            if '[Interface]' not in text or 'PrivateKey' not in text:
                raise ValueError(f'{filename} does not look like a WireGuard interface config')

            dest = os.path.join(root, filename)

            if os.path.isfile(dest):
                backup_path = f'{dest}.restorebak.{ts}'
                try:
                    os.replace(dest, backup_path)
                except Exception:
                    pass

            tmp = f'{dest}.tmp.{ts}'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(text.strip() + '\n')

            os.chmod(tmp, 0o600)
            os.replace(tmp, dest)

            restored.append(filename)

            if bring_up:
                try:
                    subprocess.run(
                        ['wg-quick', 'down', iface],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=20,
                        check=False,
                    )
                except Exception:
                    pass

                subprocess.run(
                    ['wg-quick', 'up', iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=20,
                    check=False,
                )

        except Exception as e:
            errors.append({
                'file': str(raw_name),
                'error': str(e),
            })

    return jsonify(
        ok=(len(errors) == 0),
        restored=restored,
        errors=errors,
    ), 200 if not errors else 207



def _validate_new_interface(name: str, address: str, listen_port: int):
    name = _safe_iface_name(name)
    path = _iface_conf_path(name)
    if os.path.exists(path):
        raise ValueError(f'{path} already exists')
    if _iface_up(name):
        raise ValueError(f'Interface {name} already exists on the system')
    try:
        new_net = ipa.ip_interface((address or '').strip()).network
    except Exception:
        raise ValueError('Server address must be a valid CIDR, for example 10.77.0.1/24')
    if not (1 <= int(listen_port) <= 65535):
        raise ValueError('Listen port must be between 1 and 65535')

    for fn in os.listdir(_wg_conf_dir()):
        if not fn.endswith('.conf'):
            continue
        meta = _read_iface(os.path.join(_wg_conf_dir(), fn))
        if not meta:
            continue
        if int(meta.get('listen_port') or 0) == int(listen_port):
            raise ValueError(f'Listen port {listen_port} is already used by {meta.get("name")}')
        old = _primary_iface(meta.get('address') or '')
        if old and old.network.version == new_net.version and old.network.overlaps(new_net):
            raise ValueError(f'Subnet overlaps with existing interface {meta.get("name")} ({old.network})')
    return name


def _write_interface_conf(path: str, *, address: str, listen_port: int, private_key: str, dns: str = '', mtu=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [
        '[Interface]',
        f'Address = {(address or "").strip()}',
        f'ListenPort = {int(listen_port)}',
        f'PrivateKey = {private_key.strip()}',
    ]
    dns = (dns or '').strip()
    if dns:
        lines.append(f'DNS = {dns}')
    if str(mtu or '').strip():
        lines.append(f'MTU = {int(mtu)}')
    lines.append('')
    with open(path, 'w') as f:
        f.write('\n'.join(lines))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def _first_cidr(s: str | None) -> str | None:
    """
    Return the first valid CIDR from an Interface Address.
    Prefer IPv4, otherwise return the first valid CIDR.
    Example:
      "10.8.0.1/24, fd42::1/64" -> "10.8.0.1/24"
    """
    if not s:
        return None

    v4 = None
    first = None

    for part in re.split(r'[,\s]+', str(s).strip()):
        part = part.strip()
        if not part or '/' not in part:
            continue

        try:
            ii = ipa.ip_interface(part)
        except Exception:
            continue

        if first is None:
            first = part

        if ii.version == 4 and v4 is None:
            v4 = part

    return v4 or first

@app.route('/api/interfaces/create', methods=['POST'])
@require_api_key
def create_interface():
    j = request.get_json(silent=True) or {}
    try:
        name = _safe_iface_name(j.get('name') or '')
        address = (j.get('address') or '').strip()
        listen_port = int(j.get('listen_port') or 0)
        dns = (j.get('dns') or '').strip()
        mtu = int(j.get('mtu')) if str(j.get('mtu') or '').strip() else None
        auto_up = bool(j.get('auto_up', True))

        _validate_new_interface(name, address, listen_port)
        private_key = subprocess.check_output(['wg', 'genkey'], stderr=subprocess.DEVNULL, timeout=3).decode().strip()
        path = _iface_conf_path(name)
        _write_interface_conf(
        path,
        address=address,
        listen_port=listen_port,
        private_key=private_key,
        dns='',
        mtu=None
        )

        up_error = None
        if auto_up:
            proc = subprocess.run(['wg-quick', 'up', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            if proc.returncode != 0:
                up_error = (proc.stderr or proc.stdout or '').strip() or f'wg-quick up {name} failed'

        meta = _read_iface(path) or {'name': name, 'address': address, 'listen_port': listen_port, 'mtu': mtu, 'dns': dns}
        meta['is_up'] = _iface_up(name)
        try:
            prim = _first_cidr(meta.get('address'))
            meta['available_ips'] = available_ips(name, prim, WG_CONF_PATH) if prim else []
        except Exception:
            meta['available_ips'] = []
        return jsonify(ok=True, interface=meta, up_error=up_error), 201
    except ValueError as e:
        return jsonify(error='invalid_interface', detail=str(e)), 400
    except subprocess.CalledProcessError as e:
        return jsonify(error='wg_genkey_failed', detail=str(e)), 500
    except Exception as e:
        app.logger.exception('interface create failed')
        return jsonify(error='interface_create_failed', detail=str(e)), 500


@app.route('/api/interfaces')
@require_api_key
def interfaces():

    fast = str(request.args.get('fast', '')).lower() in ('1', 'true', 'yes')

    out = []
    if os.path.isdir(WG_CONF_PATH):
        for fn in os.listdir(WG_CONF_PATH):
            if not fn.endswith('.conf'):
                continue
            conf_path = os.path.join(WG_CONF_PATH, fn)
            meta = _read_iface(conf_path)
            if not meta:
                continue

            try:
                meta['is_up'] = _iface_up(meta['name'])
            except Exception:
                meta['is_up'] = False

            if fast:
                meta['available_ips'] = []
                meta['ips_deferred'] = True
            else:
                try:
                    prim = _first_cidr(meta.get('address'))
                    if prim:
                        meta['available_ips'] = available_ips(meta['name'], prim, WG_CONF_PATH)
                    else:
                        meta['available_ips'] = []
                except Exception as e:
                    app.logger.warning("available_ips error on %s: %s", meta.get('name'), e)
                    meta['available_ips'] = []

            out.append(meta)

    return jsonify(interfaces=out, public_ipv4=_public_ipv4())


def _node_plain_ip(allowed: str) -> str:
    for item in (allowed or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            ii = ipa.ip_interface(item)
            if ii.network.prefixlen in (32, 128):
                return str(ii.ip)
        except Exception:
            pass
    return ''


def _node_ping_peer(iface: str, allowed: str) -> bool:
    ip = _node_plain_ip(allowed)
    if not ip:
        return False

    try:
        ip_obj = ipa.ip_address(ip)
        if ip_obj.version == 6:
            cmd = ['ping', '-6', '-I', iface, '-c', '1', '-W', '1', ip]
        else:
            cmd = ['ping', '-I', iface, '-c', '1', '-W', '1', ip]

        return subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        ).returncode == 0
    except Exception:
        return False


@app.route('/api/peers')
@require_api_key
def peers():
    want_iface = (request.args.get('iface') or '').strip()
    peers = []
    now = int(time.time())
    HANDSHAKE_WINDOW = int(os.environ.get('WG_ONLINE_HANDSHAKE_WINDOW', '180') or 180)

    try:
        dump = subprocess.check_output(['wg', 'show', 'all', 'dump']).decode().splitlines()

        for line in dump:
            parts = line.split('\t')
            if len(parts) != 9:
                continue

            iface = parts[0]
            if want_iface and iface != want_iface:
                continue

            peer_pub = parts[1]
            allowed_ips = parts[4] or ''
            hs = int(parts[5] or 0)
            rx_bytes = int(parts[6] or 0)
            tx_bytes = int(parts[7] or 0)

            hs_age = (now - hs) if hs > 0 else None
            hs_fresh = bool(hs > 0 and hs_age is not None and hs_age <= HANDSHAKE_WINDOW)

            probe_first = str(os.environ.get('WG_ONLINE_PROBE_FIRST', '1')).lower() not in ('0', 'false', 'no', 'off')
            handshake_fallback = str(os.environ.get('WG_ONLINE_HANDSHAKE_FALLBACK', '0')).lower() in ('1', 'true', 'yes', 'on')
            
            ping_ok = False
            probed = False

            if probe_first:
                probed = True
                ping_ok = _node_ping_peer(iface, allowed_ips)

                if ping_ok:
                    online = True
                    reason = 'probe'
                else:
                    online = bool(handshake_fallback and hs_fresh)
                    reason = 'handshake' if online else 'probe_failed'
            
            else:
                online = bool(hs_fresh)
                reason = 'handshake' if hs_fresh else 'none'



            peers.append({
                'id': peer_pub,
                'iface': iface,
                'public_key': peer_pub,
                'allowed_ips': allowed_ips,
                'rx_mib': round(rx_bytes / 1048576.0, 2),
                'tx_mib': round(tx_bytes / 1048576.0, 2),
                'latest_handshake': hs,
                'latest_handshake_age': hs_age,
                'conn_status': 'online' if online else 'offline',
                'connection_status': 'online' if online else 'offline',
                'conn_reason': reason,
                'conn_probe': bool(probed),

                # Keep this for backward compatibility only.
                'status': 'online' if online else 'offline'
            })

    except Exception:
        pass

    return jsonify(peers=peers)


@app.route('/api/peers/add', methods=['POST'])
@require_api_key
def add_peer():
    try:
        import fcntl

        j = request.get_json(silent=True) or {}

        try:
            iface = _safe_iface_name(j.get('iface') or '')
        except Exception as e:
            return jsonify(error="invalid_iface", detail=str(e)), 400

        pub = (j.get('public_key') or '').strip()
        host_cidr = (j.get('host_cidr') or '').strip()

        if not iface or not pub or not host_cidr:
            return jsonify(error="iface, public_key, and host_cidr are required"), 400

        try:
            host = hostPrefix(host_cidr)
        except Exception as e:
            return jsonify(error="invalid host_cidr", detail=str(e)), 400

        conf = os.path.join(WG_CONF_PATH, f'{iface}.conf')
        lock_path = conf + '.lock'
        os.makedirs(os.path.dirname(conf), exist_ok=True)

        def _peer_blocks_from_conf(path):
            blocks = []
            if not os.path.isfile(path):
                return blocks

            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                return blocks

            i = 0
            while i < len(lines):
                if lines[i].strip().lower() == '[peer]':
                    block = [lines[i]]
                    i += 1
                    while i < len(lines) and not lines[i].strip().startswith('['):
                        block.append(lines[i])
                        i += 1
                    blocks.append(block)
                else:
                    i += 1

            return blocks

        def _block_public_key(block):
            for line in block:
                s = line.strip()
                if s.lower().startswith('publickey') and '=' in s:
                    return s.split('=', 1)[1].strip()
            return ''

        def _block_allowed_ips(block):
            vals = []
            for line in block:
                s = line.strip()
                if s.lower().startswith('allowedips') and '=' in s:
                    raw = s.split('=', 1)[1].strip()
                    vals.extend([x.strip() for x in raw.split(',') if x.strip()])
            return vals

        def _host_matches_any(allowed_values, wanted_host):
            for val in allowed_values or []:
                try:
                    if hostPrefix(val) == wanted_host:
                        return True
                except Exception:
                    pass
            return False

        with open(lock_path, 'w') as lockf:
            fcntl.flock(lockf, fcntl.LOCK_EX)

            blocks = _peer_blocks_from_conf(conf)

            # Idempotency: same public key already exists.
            for block in blocks:
                existing_pub = _block_public_key(block)
                if existing_pub == pub:
                    try:
                        subprocess.run(
                            ['wg', 'set', iface, 'peer', pub, 'allowed-ips', host],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=6
                        )
                    except Exception:
                        pass

                    return jsonify(
                        ok=True,
                        duplicate=True,
                        reason="public_key_already_exists",
                        iface=iface,
                        public_key=pub,
                        host_cidr=host
                    ), 200

            for block in blocks:
                existing_pub = _block_public_key(block)
                allowed = _block_allowed_ips(block)

                if existing_pub and existing_pub != pub and _host_matches_any(allowed, host):
                    return jsonify(
                        error="host_cidr_already_used",
                        detail=f"{host} is already assigned to another peer",
                        iface=iface,
                        host_cidr=host
                    ), 409

            if not os.path.exists(conf):
                return jsonify(
                    error="interface_conf_not_found",
                    detail=f"{conf} does not exist. Create the interface first."
                ), 404

            try:
                subprocess.check_call(
                    ['wg', 'show', iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception:
                up = subprocess.run(
                    ['wg-quick', 'up', iface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if up.returncode != 0:
                    return jsonify(
                        error="failed_to_bring_iface_up",
                        iface=iface,
                        stderr=(up.stderr or up.stdout or '').strip()
                    ), 500

            cmd = ['wg', 'set', iface, 'peer', pub, 'allowed-ips', host]

            endpoint = (j.get('endpoint') or '').strip()
            if endpoint:
                cmd += ['endpoint', endpoint]

            keepalive = j.get('persistent_keepalive')
            try:
                keepalive = int(keepalive or 0)
            except Exception:
                keepalive = 0

            if keepalive > 0:
                cmd += ['persistent-keepalive', str(keepalive)]

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if proc.returncode != 0:
                return jsonify(
                    error="wg_set_failed",
                    stderr=(proc.stderr or '').strip()
                ), 500

            with open(conf, 'a', encoding='utf-8') as f:
                f.write('\n[Peer]\n')
                f.write(f'PublicKey = {pub}\n')
                f.write(f'AllowedIPs = {host}\n')

                if endpoint:
                    f.write(f'Endpoint = {endpoint}\n')

                if keepalive > 0:
                    f.write(f'PersistentKeepalive = {keepalive}\n')

                f.write('\n')

            try:
                os.chmod(conf, 0o600)
            except Exception:
                pass

            return jsonify(
                ok=True,
                duplicate=False,
                iface=iface,
                public_key=pub,
                host_cidr=host
            ), 200

    except Exception as e:
        app.logger.exception("add_peer failed")
        return jsonify(error="unhandled_exception", detail=str(e)), 500

def _peer_conf(pub):
    for fn in os.listdir(WG_CONF_PATH):
        if not fn.endswith('.conf'): continue
        iface = fn[:-5]
        with open(os.path.join(WG_CONF_PATH, fn)) as f:
            lines = [ln.strip() for ln in f]
        for i, ln in enumerate(lines):
            if ln.lower().startswith('publickey') and ln.split('=',1)[1].strip() == pub:
                allowed = endpoint = keep = None
                j = i
                while j < len(lines) and not lines[j].startswith('['):
                    s = lines[j].lower()
                    if s.startswith('allowedips'): allowed = lines[j].split('=',1)[1].strip()
                    if s.startswith('endpoint'):   endpoint = lines[j].split('=',1)[1].strip()
                    if s.startswith('persistentkeepalive'):
                        try: keep = int(lines[j].split('=',1)[1].strip())
                        except: keep = None
                    j += 1
                return {'iface': iface, 'allowed': allowed, 'endpoint': endpoint, 'keep': keep}
    return None

@app.route('/api/peer/<path:pub>/enable', methods=['POST'])
@require_api_key
def enable_peer(pub):
    info = _peer_conf(pub)
    if not info:
        return jsonify(error='peer_not_found'), 404

    j = request.get_json(silent=True) or {}
    host = j.get('host_cidr') or _orig_host(info.get('allowed'))

    try:
        subprocess.check_call(['wg','show',info['iface']],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        subprocess.run(['wg-quick','up',info['iface']], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = ['wg','set',info['iface'],'peer',pub]
    if info.get('allowed'):  cmd += ['allowed-ips', info['allowed']]
    if info.get('endpoint'): cmd += ['endpoint', info['endpoint']]
    if info.get('keep'):     cmd += ['persistent-keepalive', str(info['keep'])]
    subprocess.check_call(cmd)

    if host:
        _route(['del'], host)

    return jsonify(ok=True)

@app.route('/api/peer/<path:pub>/disable', methods=['POST'])
@require_api_key
def disable_peer(pub):
    j = request.get_json(silent=True) or {}
    info = _peer_conf(pub)  
    host = j.get('host_cidr') or (info and _orig_host(info.get('allowed')))

    try:
        dump = subprocess.check_output(['wg','show','all','dump']).decode().splitlines()
        for line in dump:
            parts = line.split('\t')
            if len(parts) == 9 and parts[1] == pub:
                subprocess.run(['wg','set',parts[0],'peer',pub,'remove'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
    except Exception:
        pass

    if host:
        _route(['add'], host)

    return jsonify(ok=True)

@app.route('/api/peer/<path:pub>', methods=['DELETE'])
@require_api_key
def delete_peer(pub):
    try:
        dump = subprocess.check_output(['wg','show','all','dump']).decode().splitlines()
        for line in dump:
            parts = line.split('\t')
            if len(parts) == 9 and parts[1] == pub:
                subprocess.run(['wg','set',parts[0],'peer',pub,'remove'])
                break
    except Exception:
        pass
    for fn in os.listdir(WG_CONF_PATH):
        if not fn.endswith('.conf'): continue
        p = os.path.join(WG_CONF_PATH, fn)
        lines = open(p,'r').readlines()
        out=[]; i=0
        while i<len(lines):
            if lines[i].strip().lower()=='[peer]':
                block=[lines[i]]; i+=1
                while i<len(lines) and not lines[i].strip().startswith('['):
                    block.append(lines[i]); i+=1
                if any(l.lower().startswith('publickey') and l.split('=',1)[1].strip()==pub for l in block):
                    continue
                out.extend(block)
            else:
                out.append(lines[i]); i+=1
        open(p,'w').writelines(out)
    return jsonify(ok=True)

@app.route('/api/iface/<name>/available_ips')
@require_api_key
def iface_availableIPS(name):
    conf = os.path.join(WG_CONF_PATH, f'{name}.conf')
    if not os.path.isfile(conf):
        return jsonify(error='not_found'), 404
    meta = _read_iface(conf)
    if not meta:
        return jsonify(error='bad_conf'), 400
    ips = available_ips(name, meta['address'], WG_CONF_PATH)
    return jsonify(available_ips=ips)


@app.route('/api/iface/<name>/up', methods=['POST'])
@require_api_key
def iface_up(name):
    subprocess.check_call(['wg-quick','up', name])
    return jsonify(ok=True)

@app.route('/api/iface/<name>/down', methods=['POST'])
@require_api_key
def iface_down(name):
    subprocess.check_call(['wg-quick','down', name])
    return jsonify(ok=True)

@app.route('/api/iface/<name>', methods=['DELETE'])
@require_api_key
def iface_delete(name):
    try:
        name = _safe_iface_name(name)
    except Exception as e:
        return jsonify(error='invalid_iface', detail=str(e)), 400

    conf_path = os.path.join(_wg_conf_dir(), f'{name}.conf')

    if not os.path.isfile(conf_path):
        return jsonify(error='not_found', detail=f'{name}.conf not found'), 404

    j = request.get_json(silent=True) or {}
    force = bool(j.get('force') or j.get('delete_peers'))

    peer_count = 0
    try:
        with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip().lower() == '[peer]':
                    peer_count += 1
    except Exception:
        peer_count = 0

    if peer_count and not force:
        return jsonify(
            ok=False,
            error='interface_has_peers',
            peer_count=peer_count,
            require_delete_peers=True
        ), 409

    try:
        subprocess.run(
            ['wg-quick', 'down', name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False
        )
    except Exception:
        pass

    try:
        os.remove(conf_path)
    except Exception as e:
        return jsonify(error='remove_conf_failed', detail=str(e)), 500

    try:
        lock_path = conf_path + '.lock'
        if os.path.isfile(lock_path):
            os.remove(lock_path)
    except Exception:
        pass

    return jsonify(
        ok=True,
        deleted_interface=name,
        deleted_peers=peer_count if force else 0
    )

@app.get('/api/iface/<name>/pubkey')
@require_api_key
def iface_pubkey(name):

    try:
        out = subprocess.check_output(
            ['wg', 'show', name, 'public-key'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().strip()
        if out:
            return jsonify(public_key=out)
    except Exception:
        pass

    try:
        conf_path = os.path.join(WG_CONF_PATH, f"{name}.conf")
        priv = None
        in_iface = False
        with open(conf_path, 'r') as f:
            for raw in f:
                s = raw.strip()
                if not s or s.startswith('#'): 
                    continue
                if s.startswith('[') and s.endswith(']'):
                    in_iface = (s[1:-1].lower() == 'interface')
                    continue
                if in_iface and '=' in s:
                    k, v = [x.strip() for x in s.split('=', 1)]
                    if k.lower() == 'privatekey':
                        priv = v
                        break
        if priv:
            out = subprocess.check_output(
                ['wg', 'pubkey'],
                input=(priv + '\n').encode(),
                stderr=subprocess.DEVNULL, timeout=2.0
            ).decode().strip()
            if out:
                return jsonify(public_key=out)
    except Exception:
        pass

    return jsonify(error='pubkey_unavailable'), 404

IFACE_CLEAR_MARK = {} 

@app.route('/api/iface/<name>/logs', methods=['GET', 'DELETE'])
@require_api_key
def agent_iface_logs(name):
    import subprocess, shlex, datetime

    if request.method == 'DELETE':
        IFACE_CLEAR_MARK[name] = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        return jsonify(ok=True)

    def _run(cmd):
        try:
            out = subprocess.check_output(
                shlex.split(cmd),
                stderr=subprocess.DEVNULL,
                timeout=6
            ).decode('utf-8', 'ignore')
            return out
        except Exception:
            return ''

    since = IFACE_CLEAR_MARK.get(name)  
    if since:
        since_arg = since.replace('T', ' ').split('.')[0].rstrip('Z')
        since_flag = f'--since "{since_arg}"'
    else:
        since_flag = '--since "2 days ago"'

    unit = f'wg-quick@{name}.service'
    text = _run(f'journalctl -u {unit} -n 300 --no-pager {since_flag}')
    if not text.strip():
        text = _run(f'journalctl -k -n 300 --no-pager {since_flag}')
        text = '\n'.join(
            ln for ln in text.splitlines()
            if ('wg' in ln.lower() or name in ln)
        )

    logs = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        try:
            ts = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        except Exception:
            ts = ''
        logs.append({'ts': ts, 'level': 'info', 'text': s})

    return jsonify({'logs': logs})


if __name__ == "__main__":
    import os, multiprocessing, sys

    use_gunicorn = os.getenv("USE_GUNICORN", "1") != "0"

    if not use_gunicorn:
        app.run(
            host=os.getenv("DEV_HOST", "127.0.0.1"),
            port=int(os.getenv("DEV_PORT", os.getenv("PORT", "9898"))),
            debug=os.getenv("FLASK_DEBUG", "0") == "1",
        )
        sys.exit(0)

    from gunicorn.app.base import BaseApplication

    class _Guni(BaseApplication):
        def __init__(self, wsgi_app, options=None):
            self.options = options or {}
            self.application = wsgi_app
            super().__init__()
        def load_config(self):
            cfg = {k: v for k, v in self.options.items()
                   if k in self.cfg.settings and v is not None}
            for k, v in cfg.items():
                self.cfg.set(k.lower(), v)
        def load(self):
            return self.application

    port = os.getenv("PORT") or "9898"
    bind = os.getenv("BIND") or f"0.0.0.0:{port}"
    workers = int(os.getenv("WORKERS") or (multiprocessing.cpu_count() * 2 + 1))
    threads = int(os.getenv("THREADS") or 4)
    timeout = int(os.getenv("TIMEOUT") or 60)
    graceful_timeout = int(os.getenv("GRACEFUL_TIMEOUT") or 30)
    loglevel = os.getenv("LOGLEVEL") or "info"

    options = {
        "bind": bind,
        "workers": workers,
        "worker_class": "gthread",
        "threads": threads,
        "timeout": timeout,
        "graceful_timeout": graceful_timeout,
        "accesslog": "-",
        "errorlog": "-",
        "loglevel": loglevel,
        "preload_app": False,
        "capture_output": True,
    }
    certfile = (os.getenv("AGENT_SSL_CERT") or "").strip()   # e.g. /etc/letsencrypt/live/agent.azumi.com/fullchain.pem
    keyfile  = (os.getenv("AGENT_SSL_KEY")  or "").strip()   # e.g. /etc/letsencrypt/live/agent.azumi.com/privkey.pem
    cafile   = (os.getenv("AGENT_SSL_CA")   or "").strip()   

    if certfile and keyfile:
        if not os.path.isfile(certfile):
            raise RuntimeError(f"AGENT_SSL_CERT not found: {certfile}")
        if not os.path.isfile(keyfile):
            raise RuntimeError(f"AGENT_SSL_KEY not found: {keyfile}")

        options["certfile"] = certfile
        options["keyfile"]  = keyfile

        if cafile:
            if not os.path.isfile(cafile):
                raise RuntimeError(f"AGENT_SSL_CA not found: {cafile}")
            options["ca_certs"]  = cafile
            options["cert_reqs"] = ssl.CERT_REQUIRED  

    _Guni(app, options).run()
