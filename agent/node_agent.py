#!/usr/bin/env python3
import os, json, subprocess, time, socket, ssl, sys, shutil
from pathlib import Path
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

def _private_networks() -> list[str]:

    networks = []

    try:
        output = subprocess.check_output(
            ['ip', '-o', '-4', 'addr', 'show'],
            stderr=subprocess.DEVNULL,
            timeout=4,
        ).decode('utf-8', 'replace')

        for line in output.splitlines():
            parts = line.split()

            try:
                inet_index = parts.index('inet')
                cidr = parts[inet_index + 1]
            except (ValueError, IndexError):
                continue

            try:
                interface = ipa.ip_interface(cidr)
            except ValueError:
                continue

            ip = interface.ip

            if (
                ip.is_loopback
                or ip.is_link_local
                or ip.is_unspecified
                or not ip.is_private
            ):
                continue

            network = str(interface.network)

            if network not in networks:
                networks.append(network)

    except Exception:
        app.logger.exception(
            'Failed to detect private node networks'
        )

    return networks

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

MAX_AVAILABLE_IPS = 512


def available_ips(iface_name: str, iface_addr_field: str, conf_dir: str,
                  limit: int = MAX_AVAILABLE_IPS) -> list[str]:
    """Return a bounded preview of free addresses without enumerating a subnet.

    Allocation only needs the first free host. Bounding the public preview also
    keeps IPv4 /8 and IPv6 /64 interfaces from allocating enormous lists while
    still supporting them normally.
    """

    ii = _primary_iface(iface_addr_field)
    if ii is None:
        return []

    net = ii.network
    iface_ip = ii.ip

    conf_path = os.path.join(conf_dir, f'{iface_name}.conf')

    used_hosts = set()
    used_hosts |= _extract_ips(conf_path, net)
    used_hosts |= _extract_wgip(iface_name, net)

    result = []
    max_items = max(1, int(limit or MAX_AVAILABLE_IPS))
    for host in net.hosts():
        if host == iface_ip or host in used_hosts:
            continue
        result.append(f"{host}/{net.prefixlen}")
        if len(result) >= max_items:
            break
    return result


def validate_requested_host_cidr(host_cidr: str, iface_addr_field: str) -> str:
    """Validate an explicit client host against the interface network."""
    iface = _primary_iface(iface_addr_field)
    if iface is None:
        raise ValueError('The interface has no usable Address setting.')

    candidate = ipa.ip_interface(host_cidr)
    host = candidate.ip
    net = iface.network

    if host.version != net.version or host not in net:
        raise ValueError(f'{host} is outside the interface network {net}.')
    if host == iface.ip:
        raise ValueError(f'{host} is the interface address.')

    point_to_point = 31 if net.version == 4 else 127
    if net.prefixlen < point_to_point:
        if host == net.network_address:
            raise ValueError(f'{host} is the network address.')
        if net.version == 4 and host == net.broadcast_address:
            raise ValueError(f'{host} is the broadcast address.')

    return f"{host}/{32 if host.version == 4 else 128}"

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


def _write_conf_atomic(path: str, text: str):
    """Replace an interface config atomically, preserving its mode (0600).

    A partial write here would corrupt the interface the next time wg-quick
    reads it, so the new content always lands via a temp file plus rename.
    """
    import tempfile

    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)

    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        mode = 0o600

    fd, tmp_path = tempfile.mkstemp(prefix='.wgconf.', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _conf_has_peer(path: str, pub: str) -> bool:
    """True when `path` still contains a [Peer] block for `pub`."""
    if not os.path.isfile(path):
        return False

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            in_peer = False
            for raw in handle:
                line = raw.strip()
                if line.startswith('[') and line.endswith(']'):
                    in_peer = (line[1:-1].lower() == 'peer')
                    continue
                if in_peer and line.lower().startswith('publickey') and '=' in line:
                    if line.split('=', 1)[1].strip() == pub:
                        return True
    except OSError:
        return False

    return False


def _upsert_peer_block_text(existing: str, pub: str, block_lines: list[str]) -> str:
    """Replace ``pub``'s block once, or append it when this is a new peer."""
    lines = (existing or '').splitlines(keepends=True)
    out = []
    replaced = False
    i = 0

    while i < len(lines):
        if lines[i].strip().lower() != '[peer]':
            out.append(lines[i])
            i += 1
            continue

        block = [lines[i]]
        i += 1
        while i < len(lines) and not lines[i].strip().startswith('['):
            block.append(lines[i])
            i += 1

        block_pub = ''
        for line in block:
            text = line.strip()
            if text.lower().startswith('publickey') and '=' in text:
                block_pub = text.split('=', 1)[1].strip()
                break

        if block_pub == pub:
            if not replaced:
                out.append('\n'.join(block_lines).rstrip('\n') + '\n')
                replaced = True
        else:
            out.extend(block)

    if not replaced:
        prefix = ''.join(out).rstrip('\n')
        if prefix:
            prefix += '\n\n'
        return prefix + '\n'.join(block_lines).rstrip('\n') + '\n'

    return ''.join(out)


def _runtime_has_peer(iface: str, pub: str) -> bool:
    """True when `pub` is still a live peer on `iface`."""
    try:
        out = subprocess.check_output(
            ['wg', 'show', iface, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=4,
        ).decode('utf-8', 'replace')
    except Exception:
        return False

    return any(line.split('\t', 1)[0].strip() == pub for line in out.splitlines())

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
    data = request.get_json(
        silent=True
    ) or {}

    files = data.get('files') or {}
    env_file = data.get('env_file')

    bring_up = bool(
        data.get('bring_up', False)
    )

    if not isinstance(files, dict):
        return jsonify(
            ok=False,
            error='invalid_files',
        ), 400

    if (
        not files
        and env_file in (None, '')
    ):
        return jsonify(
            ok=False,
            error='no_restore_payload',
        ), 400

    root = _wg_conf_dir()
    os.makedirs(
        root,
        exist_ok=True,
    )

    restored = []
    errors = []

    timestamp = datetime.utcnow().strftime(
        '%Y%m%d_%H%M%S'
    )

    # Restore WireGuard interface configurations
    for raw_name, content in files.items():
        try:
            filename = _safe_conf_filename(
                raw_name
            )

            interface_name = filename[:-5]

            if isinstance(content, bytes):
                text = content.decode(
                    'utf-8',
                    'replace',
                )
            else:
                text = str(content or '')

            if (
                '[Interface]' not in text
                or 'PrivateKey' not in text
            ):
                raise ValueError(
                    f'{filename} does not look like '
                    'a WireGuard interface config'
                )

            destination = os.path.join(
                root,
                filename,
            )

            # Preserve the existing config before replacement
            if os.path.isfile(destination):
                safety_copy = (
                    f'{destination}.restorebak.'
                    f'{timestamp}'
                )

                try:
                    os.replace(
                        destination,
                        safety_copy,
                    )
                except Exception:
                    pass

            temporary_path = (
                f'{destination}.tmp.{timestamp}'
            )

            with open(
                temporary_path,
                'w',
                encoding='utf-8',
            ) as handle:
                handle.write(
                    text.strip() + '\n'
                )

            os.chmod(
                temporary_path,
                0o600,
            )

            os.replace(
                temporary_path,
                destination,
            )

            restored.append(filename)

            if bring_up:
                try:
                    subprocess.run(
                        [
                            'wg-quick',
                            'down',
                            interface_name,
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=20,
                        check=False,
                    )
                except Exception:
                    pass

                up_process = subprocess.run(
                    [
                        'wg-quick',
                        'up',
                        interface_name,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                    check=False,
                )

                if up_process.returncode != 0:
                    errors.append({
                        'file': filename,
                        'error': (
                            up_process.stderr
                            or up_process.stdout
                            or (
                                'wg-quick up '
                                f'{interface_name} failed'
                            )
                        ).strip(),
                    })

        except Exception as exc:
            errors.append({
                'file': str(raw_name),
                'error': str(exc),
            })

    # Restore node-agent .env
    env_restored = False

    if env_file not in (None, ''):
        try:
            env_path = (
                _node_env_path()
                or os.path.join(
                    os.path.dirname(
                        os.path.abspath(__file__)
                    ),
                    '.env',
                )
            )

            # Preserve the current .env
            if os.path.isfile(env_path):
                safety_env = (
                    f'{env_path}.restorebak.'
                    f'{timestamp}'
                )

                os.replace(
                    env_path,
                    safety_env,
                )

            temporary_env = (
                f'{env_path}.tmp.{timestamp}'
            )

            with open(
                temporary_env,
                'w',
                encoding='utf-8',
            ) as handle:
                handle.write(
                    str(env_file)
                )

            os.chmod(
                temporary_env,
                0o600,
            )

            os.replace(
                temporary_env,
                env_path,
            )

            env_restored = True

        except Exception as exc:
            errors.append({
                'file': '.env',
                'error': str(exc),
            })

    return jsonify(
        ok=(len(errors) == 0),
        restored=restored,
        env_restored=env_restored,
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

def _egress_interface() -> str:
    try:
        output = subprocess.check_output(
            [
                'ip',
                '-4',
                'route',
                'get',
                '1.1.1.1',
            ],
            stderr=subprocess.DEVNULL,
            timeout=4,
        ).decode(
            'utf-8',
            'replace',
        )

        matches = re.findall(
            r'\bdev\s+([A-Za-z0-9_.:-]+)',
            output,
        )

        for candidate in matches:
            candidate = candidate.strip()

            if not candidate:
                continue

            if candidate == 'lo':
                continue

            if re.match(
                r'^(wg|tun|tap|docker|br-|veth)',
                candidate,
                re.IGNORECASE,
            ):
                continue

            return candidate

    except Exception:
        app.logger.exception(
            "Could not detect the node's default IPv4 egress interface"
        )

    return ''

def _wireguard_network(address_field: str) -> str:
    for raw_value in re.split(
        r"[\s,]+",
        str(address_field or "").strip(),
    ):
        value = raw_value.strip()

        if not value or "/" not in value:
            continue

        try:
            interface = ipa.ip_interface(value)
        except ValueError:
            continue

        if (
            interface.version == 4
            and interface.ip.is_private
        ):
            return str(interface.network)

    return ""


def _wg_rules(
    interface_name: str,
    address_field: str,
) -> tuple[str, str]:
    network = _wireguard_network(
        address_field
    )

    if not network:
        raise ValueError(
            "Automatic forwarding requires a private IPv4 WireGuard subnet."
        )

    egress = _egress_interface()

    if not egress:
        raise ValueError(
            "The node's default IPv4 network interface could not be detected."
        )

    if not re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,32}",
        egress,
    ):
        raise ValueError(
            "The detected outbound interface name is invalid."
        )

    post_up = (
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
        "iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null "
        "|| iptables -A FORWARD -i %i -j ACCEPT; "
        "iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null "
        "|| iptables -A FORWARD -o %i -j ACCEPT; "
        f"iptables -t nat -C POSTROUTING -s {network} "
        f"-o {egress} -j MASQUERADE 2>/dev/null "
        f"|| iptables -t nat -A POSTROUTING -s {network} "
        f"-o {egress} -j MASQUERADE"
    )

    post_down = (
        "iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true; "
        "iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true; "
        f"iptables -t nat -D POSTROUTING -s {network} "
        f"-o {egress} -j MASQUERADE 2>/dev/null || true"
    )

    return post_up, post_down

def _write_interface_conf(
    path: str,
    *,
    address: str,
    listen_port: int,
    private_key: str,
    dns: str = '',
    mtu=None,
    post_up: str = '',
    post_down: str = '',
):
    directory = os.path.dirname(path)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    lines = [
        '[Interface]',
        f'Address = {(address or "").strip()}',
        f'ListenPort = {int(listen_port)}',
        f'PrivateKey = {private_key.strip()}',
    ]

    dns = (
        dns
        or ''
    ).strip()

    if dns:
        lines.append(
            f'DNS = {dns}'
        )

    if str(mtu or '').strip():
        lines.append(
            f'MTU = {int(mtu)}'
        )

    if (
        post_up
        or ''
    ).strip():
        lines.append(
            f'PostUp = {post_up.strip()}'
        )

    if (
        post_down
        or ''
    ).strip():
        lines.append(
            f'PostDown = {post_down.strip()}'
        )

    lines.append('')

    temporary_path = (
        path
        + '.tmp'
    )

    with open(
        temporary_path,
        'w',
        encoding='utf-8',
    ) as f:
        f.write(
            '\n'.join(lines)
        )

        f.flush()
        os.fsync(
            f.fileno()
        )

    os.chmod(
        temporary_path,
        0o600,
    )

    os.replace(
        temporary_path,
        path,
    )

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
        name = _safe_iface_name(
            j.get('name') or ''
        )

        address = (
            j.get('address')
            or ''
        ).strip()

        listen_port = int(
            j.get('listen_port')
            or 0
        )

        dns = (
            j.get('dns')
            or ''
        ).strip()

        mtu = (
            int(j.get('mtu'))
            if str(j.get('mtu') or '').strip()
            else None
        )

        auto_up = bool(
            j.get('auto_up', True)
        )

        auto_firewall = bool(
            j.get('auto_firewall', True)
        )

        _validate_new_interface(
            name,
            address,
            listen_port,
        )

        post_up = ''
        post_down = ''

        if auto_firewall:
            post_up, post_down = _wg_rules(
                name,
                address,
            )

        private_key = subprocess.check_output(
            ['wg', 'genkey'],
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).decode().strip()

        path = _iface_conf_path(name)

        _write_interface_conf(
            path,
            address=address,
            listen_port=listen_port,
            private_key=private_key,
            dns='',
            mtu=mtu,
            post_up=post_up,
            post_down=post_down,
        )

        up_error = None

        if auto_up:
            proc = subprocess.run(
                [
                    'wg-quick',
                    'up',
                    name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )

            if proc.returncode != 0:
                up_error = (
                    proc.stderr
                    or proc.stdout
                    or ''
                ).strip() or (
                    f'wg-quick up {name} failed'
                )

            else:

                try:
                    subprocess.run(
                        [
                            'systemctl',
                            'enable',
                            f'wg-quick@{name}.service',
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )

                except Exception:
                    app.logger.warning(
                        'Could not enable wg-quick@%s at boot',
                        name,
                        exc_info=True,
                    )

        meta = _read_iface(path) or {
            'name': name,
            'address': address,
            'listen_port': listen_port,
            'mtu': mtu,
            'dns': dns,
        }
        meta['dns'] = dns
        meta['is_up'] = _iface_up(name)

        meta['post_up'] = post_up
        meta['post_down'] = post_down
        meta['auto_firewall'] = auto_firewall
        meta['egress_interface'] = (
            _egress_interface()
            if auto_firewall
            else ''
        )

        try:
            primary_cidr = _first_cidr(
                meta.get('address')
            )

            meta['available_ips'] = (
                available_ips(
                    name,
                    primary_cidr,
                    WG_CONF_PATH,
                )
                if primary_cidr
                else []
            )

        except Exception:
            meta['available_ips'] = []

        return jsonify(
            ok=True,
            interface=meta,
            up_error=up_error,
        ), 201

    except ValueError as e:
        return jsonify(
            error='invalid_interface',
            detail=str(e),
        ), 400

    except subprocess.CalledProcessError as e:
        return jsonify(
            error='wg_genkey_failed',
            detail=str(e),
        ), 500

    except subprocess.TimeoutExpired as e:
        app.logger.exception(
            'Interface command timed out'
        )

        return jsonify(
            error='interface_command_timeout',
            detail=str(e),
        ), 504

    except Exception as e:
        app.logger.exception(
            'interface create failed'
        )

        return jsonify(
            error='interface_create_failed',
            detail=str(e),
        ), 500

@app.route('/api/interfaces')
@require_api_key
def interfaces():

    fast = str(request.args.get('fast', '')).lower() in ('1', 'true', 'yes')

    out = []
    scope_networks = _private_networks()
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
            meta['scope_networks'] = scope_networks
            out.append(meta)

    return jsonify(interfaces=out,public_ipv4=_public_ipv4(),scope_networks=scope_networks,)


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
                'status': 'online' if online else 'offline'
            })

    except Exception:
        pass

    return jsonify(peers=peers)

def _node_version() -> str:

    version_file = _node_root() / "VERSION"

    try:
        value = (
            version_file
            .read_text(encoding="utf-8")
            .strip()
            .lstrip("vV")
        )

        if value and re.fullmatch(
            r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?",
            value,
        ):
            return value

        app.logger.warning(
            "Invalid VERSION file value: %r",
            value,
        )

    except FileNotFoundError:
        app.logger.warning(
            "VERSION file was not found: %s",
            version_file,
        )

    except Exception:
        app.logger.exception(
            "Could not read node VERSION file"
        )

    return "0.0.0"


NODE_REPO = "Azumi67/WG_Panel"

def _node_root():
    configured = (os.getenv("WG_PANEL_ROOT") or "").strip()
    if configured:
        return Path(configured).resolve()

    here = Path(__file__).resolve().parent
    return here.parent

NODE_AGENT_VERSION = _node_version()

def _node_update_status_path():
    root = _node_root()
    return root / "instance" / "node_update_status.json"


def _node_write_status(payload):
    path = _node_update_status_path()

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    temporary.write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    os.replace(
        temporary,
        path,
    )


def _node_update_lock_active() -> bool:
    lock_path = (
        _node_root()
        / "instance"
        / "update.lock"
    )

    if not lock_path.exists():
        return False

    try:
        pid = int(
            lock_path.read_text(
                encoding="utf-8"
            ).strip()
        )

        if pid <= 1:
            raise ValueError(
                "Invalid updater PID."
            )

        os.kill(pid, 0)
        return True

    except ProcessLookupError:
        try:
            lock_path.unlink(
                missing_ok=True,
            )
        except Exception:
            pass

        return False

    except PermissionError:
        return True

    except Exception:
        try:
            lock_age = (
                time.time()
                - lock_path.stat().st_mtime
            )
        except Exception:
            lock_age = 999999

        if lock_age > 300:
            try:
                lock_path.unlink(
                    missing_ok=True,
                )
            except Exception:
                pass

            return False

        return True


def _node_update_status():
    try:
        data = json.loads(
            _node_update_status_path()
            .read_text(
                encoding="utf-8"
            )
        )

        status = (
            data
            if isinstance(data, dict)
            else {}
        )

    except Exception:
        status = {
            "status": "idle",
            "stage": "idle",
            "percent": 0,
            "message": (
                "No node update is running."
            ),
            "log": [],
        }

    busy = str(
    status.get("status")
    or ""
    ).lower() in {
    "queued",
    "running",
    "backup",
    "downloading",
    "download",
    "extract",
    "install",
    "installing",
    "dependencies",
    "validate",
    "validating",
    "restart",
    "restarting",
    "rollback",
    "rolling_back",
    "rollback_restart",
    }

    if (
        busy
        and not _node_update_lock_active()
    ):
        recovered = {
            "status": "idle",
            "stage": "idle",
            "percent": 0,
            "message": (
                "Previous interrupted node "
                "update state was cleared."
            ),
            "previous_status": status.get(
                "status"
            ),
            "previous_message": status.get(
                "message"
            ),
            "recovered": True,
            "log": list(
                status.get("log")
                or []
            )[-20:],
        }

        try:
            _node_write_status(
                recovered
            )
        except Exception:
            pass

        return recovered

    return status


def _node_version_tuple(value):
    nums = re.findall(r"\d+", str(value or ""))
    parts = [int(x) for x in nums[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _node_update_source_path() -> Path:
    return (
        _node_root()
        / "instance"
        / "update_source_node.json"
    )


def _node_update_source() -> dict:
    try:
        payload = json.loads(
            _node_update_source_path()
            .read_text(
                encoding="utf-8",
            )
        )

        return (
            payload
            if isinstance(payload, dict)
            else {}
        )

    except Exception:
        return {}


def _node_latest_version():
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "WG-Panel-Node",
        "Cache-Control": "no-cache",
    }

    commit_sha = ""
    commit_url = ""
    commit_date = ""
    remote_version = None

    try:
        response = requests.get(
            (
                f"https://api.github.com/repos/"
                f"{NODE_REPO}/commits/main"
            ),
            headers=headers,
            timeout=8,
        )

        response.raise_for_status()

        payload = response.json() or {}

        commit_sha = str(
            payload.get("sha")
            or ""
        ).strip()

        commit_url = str(
            payload.get("html_url")
            or f"https://github.com/{NODE_REPO}"
        ).strip()

        commit = payload.get("commit") or {}
        author = commit.get("author") or {}

        commit_date = str(
            author.get("date")
            or ""
        ).strip()

    except Exception as exc:
        app.logger.warning(
            "Could not read GitHub main commit: %s",
            exc,
        )

    try:
        response = requests.get(
            (
                f"https://raw.githubusercontent.com/"
                f"{NODE_REPO}/main/VERSION"
            ),
            headers=headers,
            timeout=6,
        )

        if response.ok:
            candidate = (
                response.text
                .strip()
                .lstrip("vV")
            )

            if re.fullmatch(
                r"\d+(?:\.\d+){0,3}"
                r"(?:[-+][0-9A-Za-z.-]+)?",
                candidate,
            ):
                remote_version = candidate

    except Exception:
        pass

    return {
        "version": remote_version,
        "target": "main",
        "source": "main",

        "revision": commit_sha,
        "revision_short": (
            commit_sha[:8]
        ),

        "url": (
            commit_url
            or f"https://github.com/{NODE_REPO}"
        ),

        "commit_date": commit_date,
    }


@app.get("/api/system/version")
@require_api_key
def node_system_version():
    remote = (
        _node_latest_version()
        or {}
    )

    installed = (
        _node_update_source()
        or {}
    )

    current_version = str(
        _node_version()
        or "0.0.0"
    ).strip().lstrip("vV")

    latest_version = str(
        remote.get("version")
        or current_version
        or "0.0.0"
    ).strip().lstrip("vV")

    remote_revision = str(
        remote.get("revision")
        or ""
    ).strip()

    installed_revision = str(
        installed.get("revision")
        or ""
    ).strip()

    version_update_available = (
        _node_version_tuple(
            latest_version
        )
        > _node_version_tuple(
            current_version
        )
    )

    revision_update_available = bool(
        remote_revision
        and installed_revision
        and remote_revision != installed_revision
    )

    if (
        version_update_available
        and revision_update_available
    ):
        update_reason = (
            "version_and_revision"
        )

    elif version_update_available:
        update_reason = "version"

    elif revision_update_available:
        update_reason = "revision"

    else:
        update_reason = "current"

    update_available = bool(
        version_update_available
        or revision_update_available
    )

    return jsonify(
        ok=True,

        current=current_version,
        version_source="VERSION",

        latest=latest_version,

        repo=NODE_REPO,

        target="main",
        source="main",
        update_source="main",

        current_revision=(
            installed_revision
        ),

        current_revision_short=(
            installed_revision[:8]
        ),

        latest_revision=(
            remote_revision
        ),

        latest_revision_short=(
            remote_revision[:8]
        ),

        revision_tracked=bool(
            installed_revision
        ),

        commit_date=remote.get(
            "commit_date"
        ),

        version_update_available=(
            version_update_available
        ),

        revision_update_available=(
            revision_update_available
        ),

        update_available=(
            update_available
        ),

        update_reason=(
            update_reason
        ),
    )

@app.get("/api/system/update/status")
@require_api_key
def node_system_update_status():
    return jsonify(_node_update_status())


@app.post("/api/system/update")
@require_api_key
def node_system_update_start():
    data = request.get_json(
        silent=True
    ) or {}

    target = "main"

    root = _node_root()

    helper = (
        root
        / "scripts"
        / "panel_update.py"
    )

    status_file = (
        _node_update_status_path()
    )

    current = _node_update_status()

    if str(
        current.get("status")
        or ""
    ).lower() in {
        "queued",
        "running",
        "backup",
        "downloading",
        "download",
        "extract",
        "install",
        "installing",
        "dependencies",
        "validate",
        "validating",
        "restart",
        "restarting",
        "rollback",
        "rolling_back",
        "rollback_restart",
    } or _node_update_lock_active():
        return jsonify(
            ok=False,
            error="update_already_running",
            detail=(
                "A node update is already running."
            ),
        ), 409

    if not helper.is_file():
        return jsonify(
            ok=False,
            error="update_helper_missing",
            detail=(
                f"Update helper is missing: "
                f"{helper}"
            ),
        ), 500

    status_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    command = [
        sys.executable,
        str(helper),
        "--root",
        str(root),
        "--repo",
        NODE_REPO,
        "--service",
        "auto",
        "--status",
        str(status_file),
        "--scope",
        "node",
        "--target",
        target,
    ]

    queued = {
        "status": "queued",
        "stage": "queued",
        "percent": 2,
        "message": "Node update is starting…",
        "target": target,
        "launcher": "pending",
        "unit": None,
        "pid": None,
        "log": [],
    }

    try:
        _node_write_status(
            queued
        )
    except Exception as exc:
        return jsonify(
            ok=False,
            error="update_status_write_failed",
            detail=(
                "Could not initialize the "
                f"node update status: {exc}"
            ),
        ), 500

    systemd_run = shutil.which(
        "systemd-run"
    )

    launch_info = {}

    try:
        if systemd_run:
            unit_name = (
                "wg-panel-update-node-"
                f"{int(time.time())}-"
                f"{os.getpid()}"
            )

            result = subprocess.run(
                [
                    systemd_run,
                    "--unit",
                    unit_name,
                    "--collect",
                    "--quiet",
                    "--property=Type=exec",
                    "--property=KillMode=process",
                    "--property=TimeoutStopSec=10min",
                    f"--working-directory={root}",
                    "--",
                    *command,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
                check=False,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    result.stdout.strip()
                    or (
                        "systemd-run exited with "
                        f"code {result.returncode}"
                    )
                )

            launch_info = {
                "launcher": "systemd-run",
                "unit": f"{unit_name}.service",
                "pid": None,
            }

        else:
            log_file = (
                root
                / "instance"
                / "node_update_runner.log"
            )

            log_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            stream = open(
                log_file,
                "ab",
                buffering=0,
            )

            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(root),
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                )

            except Exception:
                stream.close()
                raise

            launch_info = {
                "launcher": "subprocess",
                "unit": None,
                "pid": process.pid,
            }

    except Exception as exc:
        failed = dict(queued)

        failed.update({
            "status": "failed",
            "stage": "failed",
            "percent": 100,
            "message": (
                "The node updater could not "
                "be started."
            ),
            "detail": str(exc),
        })

        try:
            _node_write_status(
                failed
            )
        except Exception:
            pass

        return jsonify(
            ok=False,
            error="update_launcher_failed",
            detail=str(exc),
            status=failed,
        ), 500

    latest_status = _node_update_status()

    latest_state = str(
        latest_status.get("status")
        or ""
    ).strip().lower()

    if latest_state in {
        "",
        "idle",
        "queued",
    }:
        latest_status.update({
            "status": "queued",
            "stage": "queued",
            "percent": max(
                2,
                int(
                    latest_status.get("percent")
                    or 0
                ),
            ),
            "message": (
                latest_status.get("message")
                or "Node update is starting…"
            ),
            "target": target,
            "launcher": launch_info.get(
                "launcher"
            ),
            "unit": launch_info.get(
                "unit"
            ),
            "pid": launch_info.get(
                "pid"
            ),
            "log": list(
                latest_status.get("log")
                or []
            ),
        })

        try:
            _node_write_status(
                latest_status
            )
        except Exception:
            pass

        queued = latest_status

    else:
        queued = latest_status

    return jsonify(
        ok=True,
        message="Node update started.",
        status=queued,
    ), 202

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

        if not iface or not pub:
            return jsonify(error="iface and public_key are required"), 400

        # host_cidr is optional: validation/allocation happens under the same
        # lock that installs the peer so config and runtime cannot race it.
        host = None

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

        def _block_value(block, key):
            wanted = key.lower()
            for line in block or []:
                text = line.strip()
                if text.lower().startswith(wanted) and '=' in text:
                    return text.split('=', 1)[1].strip()
            return ''

        def _runtime_set(wanted_host, wanted_endpoint='', wanted_keepalive=0):
            cmd = ['wg', 'set', iface, 'peer', pub, 'allowed-ips', wanted_host]
            if wanted_endpoint:
                cmd += ['endpoint', wanted_endpoint]
            if int(wanted_keepalive or 0) > 0:
                cmd += ['persistent-keepalive', str(int(wanted_keepalive))]
            return subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=12,
            )

        def _runtime_remove():
            return subprocess.run(
                ['wg', 'set', iface, 'peer', pub, 'remove'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=12,
            )

        def _restore_runtime(block):
            if not block:
                _runtime_remove()
                return
            old_allowed = (_block_allowed_ips(block) or [''])[0]
            old_endpoint = _block_value(block, 'endpoint')
            old_keepalive = _block_value(block, 'persistentkeepalive') or 0
            _runtime_remove()
            if old_allowed:
                _runtime_set(old_allowed, old_endpoint, old_keepalive)

        with open(lock_path, 'w') as lockf:
            fcntl.flock(lockf, fcntl.LOCK_EX)

            meta = _read_iface(conf) if os.path.exists(conf) else None
            if not meta:
                return jsonify(
                    error="interface_conf_not_found",
                    detail=f"{conf} does not exist. Create the interface first."
                ), 404

            if host_cidr:
                try:
                    host = validate_requested_host_cidr(host_cidr, meta['address'])
                except Exception as e:
                    return jsonify(error="invalid_host_cidr", detail=str(e)), 400

            blocks = _peer_blocks_from_conf(conf)
            previous_block = next(
                (block for block in blocks if _block_public_key(block) == pub),
                None,
            )
            duplicate = previous_block is not None

            if host is None and duplicate:
                # Updating an existing peer with no explicit address: keep the
                # address it already has. Falling through to allocation would
                # hand it a DIFFERENT host, because `available_ips` treats the
                # peer's own current address as taken and excludes it - so an
                # endpoint- or keepalive-only update would silently re-address
                # the client and invalidate its config.
                existing = (_block_allowed_ips(previous_block) or [''])[0]
                if existing:
                    try:
                        host = validate_requested_host_cidr(existing, meta['address'])
                    except Exception:
                        # An unusable existing AllowedIPs (a route, not a host)
                        # falls through to normal allocation below.
                        app.logger.warning(
                            "Peer %s on %s has an unusable AllowedIPs %r; allocating a new address",
                            pub, iface, existing,
                        )
                        host = None

            if host is None:
                free = available_ips(iface, meta['address'], WG_CONF_PATH, limit=1)
                if not free:
                    # Distinct from a host_cidr collision (also 409): this code
                    # tells the panel the pool is empty so it must NOT retry.
                    # The panel maps it to `address_pool_exhausted`.
                    return jsonify(
                        error="address_pool_exhausted",
                        detail=f"No free client address left on {iface}.",
                        iface=iface,
                    ), 409

                host = hostPrefix(free[0])

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

            endpoint = (j.get('endpoint') or '').strip()
            keepalive = j.get('persistent_keepalive')
            try:
                keepalive = int(keepalive or 0)
            except Exception:
                keepalive = 0

            # Removing before an update is intentional: omitting Endpoint or a
            # keepalive must clear the previous values, which `wg set` cannot do
            # by merely leaving those arguments out.
            if duplicate:
                removed = _runtime_remove()
                if removed.returncode != 0:
                    return jsonify(
                        error="wg_remove_before_update_failed",
                        stderr=(removed.stderr or removed.stdout or '').strip(),
                    ), 500

            proc = _runtime_set(host, endpoint, keepalive)

            if proc.returncode != 0:
                if duplicate:
                    try:
                        _restore_runtime(previous_block)
                    except Exception:
                        app.logger.exception('Could not restore peer after failed update')
                return jsonify(
                    error="wg_set_failed",
                    stderr=(proc.stderr or '').strip()
                ), 500

            block = ['', '[Peer]', f'PublicKey = {pub}', f'AllowedIPs = {host}']

            # `endpoint` here is a fixed remote-client endpoint for the SERVER's
            # peer block. The node's own public address must never land here.
            if endpoint:
                block.append(f'Endpoint = {endpoint}')

            if keepalive > 0:
                block.append(f'PersistentKeepalive = {keepalive}')

            block.append('')

            with open(conf, 'r', encoding='utf-8', errors='ignore') as f:
                existing = f.read()

            try:
                _write_conf_atomic(conf, _upsert_peer_block_text(existing, pub, block))
                if not _conf_has_peer(conf, pub) or not _runtime_has_peer(iface, pub):
                    raise RuntimeError('Peer update could not be verified in config and runtime.')
            except Exception:
                try:
                    _write_conf_atomic(conf, existing)
                except Exception:
                    app.logger.exception('Could not restore config after peer update failure')
                try:
                    _restore_runtime(previous_block)
                except Exception:
                    app.logger.exception('Could not restore runtime after config update failure')
                raise

            return jsonify(
                ok=True,
                duplicate=duplicate,
                updated=duplicate,
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

def _peerlive_transfer_bytes(pub: str) -> dict:

    try:
        dump = subprocess.check_output(
            ['wg', 'show', 'all', 'dump'],
            stderr=subprocess.PIPE,
            timeout=6,
        ).decode('utf-8', 'replace').splitlines()
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('wg show timed out') from exc
    except subprocess.CalledProcessError as exc:
        detail = (
            exc.stderr.decode('utf-8', 'replace')
            if isinstance(exc.stderr, bytes)
            else str(exc.stderr or '')
        ).strip()
        raise RuntimeError(detail or 'wg show failed') from exc

    for line in dump:
        parts = line.split('\t')

        if len(parts) != 9:
            continue

        iface = parts[0]
        peer_public_key = parts[1]

        if peer_public_key != pub:
            continue

        try:
            rx_bytes = max(0, int(parts[6] or 0))
        except (TypeError, ValueError):
            rx_bytes = 0

        try:
            tx_bytes = max(0, int(parts[7] or 0))
        except (TypeError, ValueError):
            tx_bytes = 0

        return {
            'iface': iface,
            'public_key': peer_public_key,
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'total_bytes': rx_bytes + tx_bytes,
        }

    raise LookupError('peer_not_found')


@app.route('/api/peer/<path:pub>/reset_data', methods=['POST'])
@require_api_key
def reset_peer_data(pub):

    try:
        counters = _peerlive_transfer_bytes(pub)

        return jsonify(
            ok=True,
            reset_supported=True,
            **counters,
        )

    except LookupError:
        return jsonify(
            ok=False,
            error='peer_not_found',
        ), 404

    except Exception as exc:
        app.logger.exception(
            'Could not read transfer counters for peer %s',
            pub,
        )

        return jsonify(
            ok=False,
            error='peer_transfer_read_failed',
            detail=str(exc),
        ), 500
    
@app.route('/api/peer/<path:pub>/enable', methods=['POST'])
@require_api_key
def enable_peer(pub):

    info = _peer_conf(pub)

    if not info:
        return jsonify(
            ok=False,
            error='peer_not_found',
        ), 404

    payload = request.get_json(
        silent=True
    ) or {}

    host = (
        payload.get('host_cidr')
        or _orig_host(
            info.get('allowed')
        )
    )

    interface_name = info.get('iface')

    if not interface_name:
        return jsonify(
            ok=False,
            error='peer_interface_missing',
        ), 400

    try:
        subprocess.check_call(
            [
                'wg',
                'show',
                interface_name,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

    except Exception:
        up_result = subprocess.run(
            [
                'wg-quick',
                'up',
                interface_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )

        if up_result.returncode != 0:
            return jsonify(
                ok=False,
                error='interface_enable_failed',
                detail=(
                    up_result.stderr
                    or up_result.stdout
                    or (
                        'Could not bring WireGuard '
                        'interface up.'
                    )
                ).strip(),
                interface=interface_name,
            ), 500

    command = [
        'wg',
        'set',
        interface_name,
        'peer',
        pub,
    ]

    if info.get('allowed'):
        command += [
            'allowed-ips',
            info['allowed'],
        ]

    if info.get('endpoint'):
        command += [
            'endpoint',
            info['endpoint'],
        ]

    if info.get('keep'):
        command += [
            'persistent-keepalive',
            str(info['keep']),
        ]

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=12,
        check=False,
    )

    if result.returncode != 0:
        return jsonify(
            ok=False,
            error='peer_enable_failed',
            detail=(
                result.stderr
                or result.stdout
                or 'WireGuard peer enable failed.'
            ).strip(),
            interface=interface_name,
        ), 500

    if host:
        _route(
            ['del'],
            host,
        )

    return jsonify(
        ok=True,
        enabled=True,
        interface=interface_name,
        public_key=pub,
        host_cidr=host,
    )

@app.route('/api/peer/<path:pub>/disable', methods=['POST'])
@require_api_key
def disable_peer(pub):

    payload = request.get_json(
        silent=True
    ) or {}

    info = _peer_conf(pub)

    if not info:
        return jsonify(
            ok=False,
            error='peer_not_found',
        ), 404

    host = (
        payload.get('host_cidr')
        or _orig_host(
            info.get('allowed')
        )
    )

    interface_name = info.get('iface')

    if not interface_name:
        return jsonify(
            ok=False,
            error='peer_interface_missing',
        ), 400

    result = subprocess.run(
        [
            'wg',
            'set',
            interface_name,
            'peer',
            pub,
            'remove',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=12,
        check=False,
    )

    if result.returncode != 0:
        return jsonify(
            ok=False,
            error='peer_disable_failed',
            detail=(
                result.stderr
                or result.stdout
                or 'WireGuard peer removal failed.'
            ).strip(),
            interface=interface_name,
        ), 500

    if host:
        _route(
            ['add'],
            host,
        )

    return jsonify(
        ok=True,
        enabled=False,
        interface=interface_name,
        public_key=pub,
        host_cidr=host,
    )

@app.route('/api/peer/<path:pub>', methods=['DELETE'])
@require_api_key
def delete_peer(pub):
    """Remove a peer from the runtime and from every interface config.

    Both layers are verified afterwards and reported separately, so the panel
    never deletes its own row on the strength of an unconfirmed removal.
    Each config file is rewritten atomically under its own interface lock.
    """
    import fcntl

    pub = (pub or '').strip()
    if not pub:
        return jsonify(ok=False, error='public_key_required'), 400

    conf_dir = _wg_conf_dir()
    errors = []
    runtime_removed = False
    config_removed = False
    runtime_ifaces = []

    try:
        dump = subprocess.check_output(
            ['wg', 'show', 'all', 'dump'], timeout=8
        ).decode('utf-8', 'replace').splitlines()
        for line in dump:
            parts = line.split('\t')
            if len(parts) >= 9 and parts[1] == pub:
                runtime_ifaces.append(parts[0])
    except Exception as e:
        errors.append(f'could not read the WireGuard runtime: {e}')

    for iface in runtime_ifaces:
        result = subprocess.run(
            ['wg', 'set', iface, 'peer', pub, 'remove'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12,
            check=False,
        )
        if result.returncode != 0:
            errors.append(
                f'{iface}: {(result.stderr or result.stdout or "wg set failed").strip()}'
            )
        elif _runtime_has_peer(iface, pub):
            errors.append(f'{iface}: the peer is still present after removal')
        else:
            runtime_removed = True

    if not runtime_ifaces and not errors:
        # Nothing live to remove: an interface that is down is not a failure.
        runtime_removed = True

    try:
        conf_names = [fn for fn in os.listdir(conf_dir) if fn.endswith('.conf')]
    except OSError as e:
        return jsonify(
            ok=False, error='conf_dir_unreadable', detail=str(e),
            runtime_removed=runtime_removed, config_removed=False,
        ), 500

    found_in_config = False

    for fn in conf_names:
        path = os.path.join(conf_dir, fn)
        if not _conf_has_peer(path, pub):
            continue

        found_in_config = True
        lock_path = path + '.lock'

        try:
            with open(lock_path, 'w') as lockf:
                fcntl.flock(lockf, fcntl.LOCK_EX)

                with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
                    lines = handle.readlines()

                out, i = [], 0
                while i < len(lines):
                    if lines[i].strip().lower() == '[peer]':
                        block = [lines[i]]
                        i += 1
                        while i < len(lines) and not lines[i].strip().startswith('['):
                            block.append(lines[i])
                            i += 1
                        matches = any(
                            l.strip().lower().startswith('publickey')
                            and '=' in l
                            and l.split('=', 1)[1].strip() == pub
                            for l in block
                        )
                        if not matches:
                            out.extend(block)
                    else:
                        out.append(lines[i])
                        i += 1

                _write_conf_atomic(path, ''.join(out))

                if _conf_has_peer(path, pub):
                    errors.append(f'{fn}: the peer block is still present after removal')
                else:
                    config_removed = True

        except Exception as e:
            errors.append(f'{fn}: {e}')

    if not found_in_config and not errors:
        config_removed = True

    if errors:
        return jsonify(
            ok=False,
            error='peer_removal_incomplete',
            detail='; '.join(errors),
            public_key=pub,
            runtime_removed=runtime_removed,
            config_removed=config_removed,
        ), 500

    return jsonify(
        ok=True,
        public_key=pub,
        runtime_removed=runtime_removed,
        config_removed=config_removed,
    )

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
