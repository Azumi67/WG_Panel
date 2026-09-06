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

_WG_KEY_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')


def _valid_wg_key(value):
    s = (value or '').strip()
    return s if s and _WG_KEY_RE.fullmatch(s) else ''


def _pubkey_from_priv(priv):
    priv = (priv or '').strip()
    if not priv:
        return ''
    try:
        out = subprocess.check_output(
            ['wg', 'pubkey'],
            input=(priv + '\n').encode(),
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        ).decode().strip()
        return _valid_wg_key(out)
    except Exception:
        return ''


def _iface_live_public_key(name):
    name = (name or '').strip()
    if not name:
        return ''
    try:
        out = subprocess.check_output(
            ['wg', 'show', name, 'public-key'],
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        ).decode().strip()
        return _valid_wg_key(out)
    except Exception:
        return ''


def _read_iface(path):
    address = None
    listen_port = None
    private_key = None
    mtu = None
    dns = None

    post_up = []
    post_down = []

    in_iface = False

    with open(
        path,
        'r',
        encoding='utf-8',
        errors='replace',
    ) as f:
        for raw in f:
            s = raw.strip()

            if not s or s.startswith('#'):
                continue

            if s.startswith('[') and s.endswith(']'):
                in_iface = (
                    s[1:-1]
                    .strip()
                    .lower()
                    == 'interface'
                )
                continue

            if not in_iface or '=' not in s:
                continue

            k, v = [
                x.strip()
                for x in s.split('=', 1)
            ]

            lk = k.lower()

            if lk == 'address':
                address = v

            elif lk == 'listenport':
                try:
                    listen_port = int(v)
                except Exception:
                    pass

            elif lk == 'privatekey':
                private_key = v

            elif lk == 'mtu':
                try:
                    mtu = int(v)
                except Exception:
                    pass

            elif lk == 'dns':
                dns = v

            elif lk == 'postup':
                post_up.append(v)

            elif lk == 'postdown':
                post_down.append(v)

    if not (
        address
        and listen_port
        and private_key
    ):
        return None

    name = os.path.splitext(
        os.path.basename(path)
    )[0]

    public_key = (
        _pubkey_from_priv(private_key)
        or _iface_live_public_key(name)
    )

    return {
        'name': name,

        'path': path,
        'address': address,
        'listen_port': listen_port,
        'mtu': mtu,
        'dns': dns,
        'public_key': public_key or None,

        'post_up': '\n'.join(post_up),
        'post_down': '\n'.join(post_down),

        'has_custom_hooks': bool(
            post_up or post_down
        ),
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
    """
    Return node health, uptime, version, and WireGuard interface state.

    The panel uses this information for:
    - node online/offline monitoring
    - node recovery notifications
    - interface up/down notifications
    """
    interface_states = []

    try:
        config_directory = _wg_conf_dir()

        if os.path.isdir(config_directory):
            for filename in sorted(
                os.listdir(config_directory)
            ):
                if not filename.endswith('.conf'):
                    continue

                config_path = os.path.join(
                    config_directory,
                    filename,
                )

                metadata = _read_iface(
                    config_path
                )

                if not metadata:
                    continue

                interface_name = (
                    metadata.get('name')
                    or ''
                ).strip()

                if not interface_name:
                    continue

                interface_states.append({
                    'name': interface_name,
                    'address': (
                        metadata.get('address')
                        or ''
                    ),
                    'listen_port': metadata.get(
                        'listen_port'
                    ),
                    'is_up': bool(
                        _iface_up(interface_name)
                    ),
                })

    except Exception:
        app.logger.debug(
            'Could not include interface states '
            'in node health response',
            exc_info=True,
        )

    try:
        uptime_seconds = int(
            float(
                Path('/proc/uptime')
                .read_text(
                    encoding='utf-8'
                )
                .split()[0]
            )
        )

    except Exception:
        uptime_seconds = 0

    return jsonify(
        ok=True,
        host=socket.gethostname(),
        now=int(time.time()),
        public_ipv4=_public_ipv4(),
        uptime_seconds=uptime_seconds,
        version=NODE_AGENT_VERSION,
        interfaces=interface_states,
    )


def _safe_iface_name(
    name: str,
) -> str:

    name = str(
        name or ''
    ).strip()

    if not name:
        raise ValueError(
            'Interface name is required.'
        )

    if len(name) > 32:
        raise ValueError(
            'Interface name must be 32 '
            'characters or fewer.'
        )

    if not re.fullmatch(
        r'[A-Za-z0-9_.-]+',
        name,
    ):
        raise ValueError(
            'Invalid interface name '
            f'{name!r}. '
            'Use only letters, numbers, '
            'underscore, dot, or dash.'
        )

    if name in {
        '.',
        '..',
    }:
        raise ValueError(
            'Invalid interface name.'
        )

    return name


def _wg_conf_dir() -> str:
    return WG_CONF_PATH if os.path.isdir(WG_CONF_PATH) else os.path.dirname(WG_CONF_PATH)


def _iface_conf_path(name: str) -> str:
    return os.path.join(_wg_conf_dir(), f'{name}.conf')


def _write_conf_atomic(path: str, text: str):

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
    try:
        out = subprocess.check_output(
            ['wg', 'show', iface, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=4,
        ).decode('utf-8', 'replace')
    except Exception:
        return False

    return any(line.split('\t', 1)[0].strip() == pub for line in out.splitlines())

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



def _validate_new_interface(
    name: str,
    address: str,
    listen_port: int,
):
    name = _safe_iface_name(
        name
    )

    path = _iface_conf_path(
        name
    )

    if os.path.exists(path):
        raise ValueError(
            f'{path} already exists'
        )

    if _iface_up(name):
        raise ValueError(
            f'Interface {name} already exists on the system'
        )

    address_parts = [
        value.strip()
        for value in re.split(
            r'[\s,]+',
            str(address or '').strip(),
        )
        if value.strip()
    ]

    if not address_parts:
        raise ValueError(
            'Server address is required.'
        )

    new_interfaces = []

    for value in address_parts:
        try:
            new_interfaces.append(
                ipa.ip_interface(value)
            )

        except ValueError as exc:
            raise ValueError(
                f'{value!r} is not a valid CIDR. '
                'Example: 10.77.0.1/24'
            ) from exc

    if not (
        1
        <= int(listen_port)
        <= 65535
    ):
        raise ValueError(
            'Listen port must be between 1 and 65535'
        )

    config_dir = _wg_conf_dir()

    os.makedirs(
        config_dir,
        exist_ok=True,
    )

    for filename in os.listdir(
        config_dir
    ):
        if not filename.endswith(
            '.conf'
        ):
            continue

        meta = _read_iface(
            os.path.join(
                config_dir,
                filename,
            )
        )

        if not meta:
            continue

        existing_name = (
            meta.get('name')
            or filename[:-5]
        )

        try:
            existing_port = int(
                meta.get('listen_port')
                or 0
            )
        except Exception:
            existing_port = 0

        if (
            existing_port
            and existing_port
            == int(listen_port)
        ):
            raise ValueError(
                f'Listen port {listen_port} is already '
                f'used by {existing_name}'
            )

        existing_addresses = [
            value.strip()
            for value in re.split(
                r'[\s,]+',
                str(
                    meta.get('address')
                    or ''
                ),
            )
            if value.strip()
        ]

        for existing_value in existing_addresses:
            try:
                existing_interface = (
                    ipa.ip_interface(
                        existing_value
                    )
                )
            except ValueError:
                continue

            for new_interface in (
                new_interfaces
            ):
                if (
                    existing_interface.version
                    != new_interface.version
                ):
                    continue

                if (
                    existing_interface.network
                    .overlaps(
                        new_interface.network
                    )
                ):
                    raise ValueError(
                        f'Subnet {new_interface.network} '
                        f'overlaps with existing interface '
                        f'{existing_name} '
                        f'({existing_interface.network})'
                    )

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
            "Automatic forwarding requires a private IPv4 "
            "WireGuard subnet."
        )

    egress = _egress_interface()

    if not egress:
        raise ValueError(
            "The node's default IPv4 network interface "
            "could not be detected."
        )

    if not re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,32}",
        egress,
    ):
        raise ValueError(
            "The detected outbound interface name is invalid."
        )

    post_up = "\n".join([
        "sysctl -w net.ipv4.ip_forward=1",
        "iptables -A FORWARD -i %i -j ACCEPT",
        (
            "iptables -A FORWARD -o %i "
            "-m conntrack --ctstate "
            "RELATED,ESTABLISHED -j ACCEPT"
        ),
        (
            f"iptables -t nat -A POSTROUTING "
            f"-s {network} "
            f"-o {egress} "
            "-j MASQUERADE"
        ),
    ])

    post_down = "\n".join([
        "iptables -D FORWARD -i %i -j ACCEPT",
        (
            "iptables -D FORWARD -o %i "
            "-m conntrack --ctstate "
            "RELATED,ESTABLISHED -j ACCEPT"
        ),
        (
            f"iptables -t nat -D POSTROUTING "
            f"-s {network} "
            f"-o {egress} "
            "-j MASQUERADE"
        ),
    ])

    return post_up, post_down

def _interface_hook_state(
    config_path: str,
) -> dict:

    state = {
        "has_post_up": False,
        "has_post_down": False,
    }

    if not os.path.isfile(config_path):
        return state

    try:
        with open(
            config_path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:
            in_interface = False

            for raw_line in handle:
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if (
                    line.startswith("[")
                    and line.endswith("]")
                ):
                    in_interface = (
                        line[1:-1]
                        .strip()
                        .lower()
                        == "interface"
                    )
                    continue

                if (
                    not in_interface
                    or "=" not in line
                ):
                    continue

                key = (
                    line.split("=", 1)[0]
                    .strip()
                    .lower()
                )

                if key == "postup":
                    state["has_post_up"] = True

                elif key == "postdown":
                    state["has_post_down"] = True

    except Exception:
        app.logger.exception(
            "Could not inspect WireGuard hooks in %s",
            config_path,
        )

    return state


def _config_custom_firewall(
    config_path: str,
) -> bool:
    state = _interface_hook_state(
        config_path
    )

    return bool(
        state["has_post_up"]
        or state["has_post_down"]
    )

def _existing_firewall_rules(
    config_path: str,
) -> dict:


    if not os.path.isfile(
        config_path
    ):
        return {
            'changed': False,
            'reason': 'config_missing',
        }

    metadata = _read_iface(
        config_path
    )

    if not metadata:
        return {
            'changed': False,
            'reason': 'invalid_config',
        }

    interface_name = (
        _safe_iface_name(
            metadata.get(
                'name'
            )
            or ''
        )
    )

    address = (
        metadata.get(
            'address'
        )
        or ''
    ).strip()

    hook_state = (
        _interface_hook_state(
            config_path
        )
    )

    if (
        hook_state.get(
            'has_post_up'
        )
        or hook_state.get(
            'has_post_down'
        )
    ):
        return {
            'changed': False,
            'reason': (
                'custom_rules_present'
            ),
            **hook_state,
        }

    post_up, post_down = (
        _wg_rules(
            interface_name,
            address,
        )
    )

    with open(
        config_path,
        'r',
        encoding='utf-8',
        errors='replace',
    ) as handle:
        original = handle.read()

    source_lines = (
        original.splitlines()
    )

    found_interface = False
    inside_interface = False
    insert_at = None

    for index, raw_line in enumerate(
        source_lines
    ):
        stripped = raw_line.strip()

        if not (
            stripped.startswith(
                '['
            )
            and stripped.endswith(
                ']'
            )
        ):
            continue

        section = (
            stripped[1:-1]
            .strip()
            .lower()
        )

        if section == 'interface':
            found_interface = True
            inside_interface = True
            continue

        if inside_interface:
            insert_at = index
            break

    if not found_interface:
        return {
            'changed': False,
            'reason': (
                'interface_section_missing'
            ),
        }

    if insert_at is None:
        insert_at = len(
            source_lines
        )

    additions = [
    *[
        f'PostUp = {command.strip()}'
        for command
        in str(
            post_up or ''
        ).splitlines()
        if command.strip()
    ],

    *[
        f'PostDown = {command.strip()}'
        for command
        in str(
            post_down or ''
        ).splitlines()
        if command.strip()
    ],

    '',
    ]

    updated = (
        '\n'.join(
            source_lines[:insert_at]
            + additions
            + source_lines[insert_at:]
        ).rstrip()
        + '\n'
    )

    _write_conf_atomic(
        config_path,
        updated,
    )

    runtime_applied = False
    runtime_error = ''

    if _iface_up(
        interface_name
    ):
        try:
            errors = []

            for raw_command in str(
                post_up or ''
            ).splitlines():

                raw_command = (
                    raw_command.strip()
                )

                if not raw_command:
                    continue

                command = (
                    raw_command.replace(
                        '%i',
                        interface_name,
                    )
                )

                result = subprocess.run(
                    [
                        '/bin/sh',
                        '-c',
                        command,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=20,
                    check=False,
                )

                if result.returncode != 0:
                    errors.append(
                        (
                            result.stdout
                            or command
                        ).strip()
                    )

            runtime_applied = (
                len(errors) == 0
            )

            if errors:
                runtime_error = (
                    '\n'.join(
                        errors
                    )[-2000:]
                )

        except Exception as exc:
            runtime_error = str(
                exc
            )

    return {
        'changed': True,
        'reason': (
            'managed_rules_added'
        ),
        'interface': (
            interface_name
        ),
        'post_up': post_up,
        'post_down': post_down,
        'runtime_applied': (
            runtime_applied
        ),
        'runtime_error': (
            runtime_error
        ),
    }


def _migrate_existing_rules() -> dict:

    root = _wg_conf_dir()

    summary = {
        'checked': 0,
        'updated': 0,
        'skipped': 0,
        'failed': 0,
    }

    if not os.path.isdir(
        root
    ):
        return summary

    for filename in sorted(
        os.listdir(
            root
        )
    ):
        if not filename.endswith(
            '.conf'
        ):
            continue

        config_path = os.path.join(
            root,
            filename,
        )

        summary[
            'checked'
        ] += 1

        try:
            result = (
                _existing_firewall_rules(
                    config_path
                )
            )

        except Exception as exc:
            summary[
                'failed'
            ] += 1

            app.logger.exception(
                'Could not generate '
                'firewall rules for %s: %s',
                filename,
                exc,
            )

            continue

        if result.get(
            'changed'
        ):
            summary[
                'updated'
            ] += 1

            app.logger.info(
                'Generated firewall rules '
                'for existing node '
                'interface %s',
                result.get(
                    'interface'
                )
                or filename,
            )

            if result.get(
                'runtime_error'
            ):
                app.logger.warning(
                    'Rules were saved for %s '
                    'but could not be applied '
                    'immediately: %s',
                    result.get(
                        'interface'
                    )
                    or filename,
                    result.get(
                        'runtime_error'
                    ),
                )

        elif result.get(
            'reason'
        ) in {
            'custom_rules_present',
            'config_missing',
        }:
            summary[
                'skipped'
            ] += 1

        else:
            summary[
                'failed'
            ] += 1

            app.logger.warning(
                'Firewall migration '
                'did not update %s: %s',
                filename,
                result,
            )

    return summary

def _write_interface_conf(
    path: str,
    *,
    address: str,
    listen_port: int,
    private_key: str,
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

    if str(mtu or '').strip():
        lines.append(
            f'MTU = {int(mtu)}'
        )

    for command in str(
        post_up or ''
    ).splitlines():

        command = command.strip()

        if command:
            lines.append(
                f'PostUp = {command}'
            )


    for command in str(
        post_down or ''
    ).splitlines():

        command = command.strip()

        if command:
            lines.append(
                f'PostDown = {command}'
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
            'public_key': _pubkey_from_priv(private_key) or None,
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

def _wg_runtime_endpoint_host(
    endpoint: str,
) -> str:
    """
    Extract the IP address from a WireGuard runtime endpoint.

    Examples:
        1.2.3.4:51820
        [2001:db8::1]:51820
    """

    endpoint = str(
        endpoint or ''
    ).strip()

    if not endpoint or endpoint == '(none)':
        return ''

    if endpoint.startswith('['):
        match = re.match(
            r'^\[([^\]]+)\](?::\d+)?$',
            endpoint,
        )

        host = (
            match.group(1)
            if match
            else ''
        )

    else:
        host = endpoint

        if ':' in endpoint:
            candidate, port = (
                endpoint.rsplit(
                    ':',
                    1,
                )
            )

            if port.isdigit():
                host = candidate

    try:
        return str(
            ipa.ip_address(
                host
            )
        )

    except Exception:
        return ''


def _wg_transport_path(
    endpoint: str,
) -> dict:


    host = _wg_runtime_endpoint_host(
        endpoint
    )

    result = {
        'transport_dev': '',
        'via_tunnel': False,
    }

    if not host:
        return result

    try:
        ip_obj = ipa.ip_address(
            host
        )

        command = [
            'ip',
            '-6' if ip_obj.version == 6 else '-4',
            'route',
            'get',
            host,
        ]

        output = subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).decode(
            'utf-8',
            'replace',
        )

        match = re.search(
            r'\bdev\s+([A-Za-z0-9_.:@-]+)',
            output,
        )

        if not match:
            return result

        device = (
            match.group(1)
            .split('@', 1)[0]
            .strip()
        )

        result[
            'transport_dev'
        ] = device

        result[
            'via_tunnel'
        ] = bool(
            re.match(
                (
                    r'^(?:'
                    r'tun|tap|wg|gre|gretap|'
                    r'ipip|sit|ppp'
                    r')'
                ),
                device,
                re.IGNORECASE,
            )
        )

    except Exception:
        pass

    return result

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

def _runtime_endpoint(value: str | None) -> str:


    raw = str(
        value or ''
    ).strip()

    if not raw:
        return ''

    endpoint_host = ''
    port = 0

    ipv6_match = re.fullmatch(
        r'\[([^]]+)\]:(\d+)',
        raw,
    )

    if ipv6_match:
        endpoint_host = (
            ipv6_match.group(1)
            or ''
        ).strip()

        try:
            port = int(
                ipv6_match.group(2)
            )
        except Exception as exc:
            raise ValueError(
                'Fixed client endpoint has '
                'an invalid port.'
            ) from exc

    else:

        endpoint_host, separator, port_text = (
            raw.rpartition(':')
        )

        endpoint_host = (
            endpoint_host
            or ''
        ).strip()

        port_text = (
            port_text
            or ''
        ).strip()

        if (
            not separator
            or not endpoint_host
            or not port_text
            or not port_text.isdigit()
        ):
            raise ValueError(
                'Fixed client endpoint must use '
                'host:port format.'
            )

        try:
            port = int(
                port_text
            )
        except Exception as exc:
            raise ValueError(
                'Fixed client endpoint has '
                'an invalid port.'
            ) from exc

    if not 1 <= port <= 65535:
        raise ValueError(
            'Fixed client endpoint port must be '
            'between 1 and 65535.'
        )

    try:
        resolved_ip = ipa.ip_address(
            endpoint_host
        ).compressed

    except ValueError:

        try:
            results = socket.getaddrinfo(
                endpoint_host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_DGRAM,
            )

        except socket.gaierror as exc:
            raise ValueError(
                'Could not resolve fixed client '
                f'endpoint domain: {endpoint_host}'
            ) from exc

        if not results:
            raise ValueError(
                'Could not resolve fixed client '
                f'endpoint domain: {endpoint_host}'
            )

        resolved_ip = ''

        for family, _socktype, _proto, _canonname, sockaddr in results:
            if family != socket.AF_INET:
                continue

            if not sockaddr:
                continue

            candidate = str(
                sockaddr[0]
            ).strip()

            if candidate:
                resolved_ip = candidate
                break

        if not resolved_ip:
            for _family, _socktype, _proto, _canonname, sockaddr in results:
                if not sockaddr:
                    continue

                candidate = str(
                    sockaddr[0]
                ).strip()

                if candidate:
                    resolved_ip = candidate
                    break

        if not resolved_ip:
            raise ValueError(
                'Fixed client endpoint domain '
                'did not resolve to a usable IP address.'
            )

    try:
        normalized_ip = ipa.ip_address(
            resolved_ip
        ).compressed

    except ValueError as exc:
        raise ValueError(
            'The fixed client endpoint resolved '
            'to an invalid IP address.'
        ) from exc

    if ':' in normalized_ip:
        return (
            f'[{normalized_ip}]:{port}'
        )

    return (
        f'{normalized_ip}:{port}'
    )

@app.route(
    '/api/peers/add',
    methods=['POST'],
)
@require_api_key
def add_peer():
    try:
        import fcntl

        payload = (
            request.get_json(
                silent=True
            )
            or {}
        )

        try:
            iface = _safe_iface_name(
                payload.get('iface')
                or ''
            )

        except Exception as exc:
            return jsonify(
                ok=False,
                error='invalid_iface',
                detail=str(exc),
            ), 400

        public_key = (
            payload.get('public_key')
            or ''
        ).strip()

        requested_host_cidr = (
            payload.get('host_cidr')
            or ''
        ).strip()

        if not iface or not public_key:
            return jsonify(
                ok=False,
                error='iface_and_public_key_required',
                detail=(
                    'iface and public_key '
                    'are required.'
                ),
            ), 400

        host = None

        conf = os.path.join(
            WG_CONF_PATH,
            f'{iface}.conf',
        )

        lock_path = (
            conf
            + '.lock'
        )

        os.makedirs(
            os.path.dirname(conf),
            exist_ok=True,
        )


        def _peer_blocks_from_conf(path):
            blocks = []

            if not os.path.isfile(
                path
            ):
                return blocks

            try:
                with open(
                    path,
                    'r',
                    encoding='utf-8',
                    errors='ignore',
                ) as handle:
                    lines = handle.readlines()

            except Exception:
                return blocks

            index = 0

            while index < len(lines):
                if (
                    lines[index]
                    .strip()
                    .lower()
                    == '[peer]'
                ):
                    block = [
                        lines[index]
                    ]

                    index += 1

                    while (
                        index < len(lines)
                        and not lines[index]
                        .strip()
                        .startswith('[')
                    ):
                        block.append(
                            lines[index]
                        )

                        index += 1

                    blocks.append(
                        block
                    )

                else:
                    index += 1

            return blocks


        def _block_public_key(block):
            for raw_line in (
                block or []
            ):
                line = raw_line.strip()

                if (
                    line.lower()
                    .startswith('publickey')
                    and '=' in line
                ):
                    return (
                        line.split(
                            '=',
                            1,
                        )[1]
                        .strip()
                    )

            return ''


        def _block_allowed_ips(block):
            values = []

            for raw_line in (
                block or []
            ):
                line = raw_line.strip()

                if (
                    line.lower()
                    .startswith('allowedips')
                    and '=' in line
                ):
                    raw_value = (
                        line.split(
                            '=',
                            1,
                        )[1]
                        .strip()
                    )

                    values.extend(
                        item.strip()
                        for item in raw_value.split(',')
                        if item.strip()
                    )

            return values


        def _host_matches_any(
            allowed_values,
            wanted_host,
        ):
            for value in (
                allowed_values
                or []
            ):
                try:
                    if (
                        hostPrefix(value)
                        == wanted_host
                    ):
                        return True

                except Exception:
                    pass

            return False


        def _block_value(
            block,
            key,
        ):
            wanted = (
                str(key or '')
                .strip()
                .lower()
            )

            for raw_line in (
                block or []
            ):
                line = raw_line.strip()

                if (
                    line.lower()
                    .startswith(wanted)
                    and '=' in line
                ):
                    return (
                        line.split(
                            '=',
                            1,
                        )[1]
                        .strip()
                    )

            return ''


        def _runtime_set(
            wanted_host,
            wanted_endpoint='',
            wanted_keepalive=0,
        ):
            command = [
                'wg',
                'set',
                iface,
                'peer',
                public_key,
                'allowed-ips',
                wanted_host,
            ]

            if wanted_endpoint:
                command += [
                    'endpoint',
                    wanted_endpoint,
                ]

            if int(
                wanted_keepalive
                or 0
            ) > 0:
                command += [
                    'persistent-keepalive',
                    str(
                        int(
                            wanted_keepalive
                        )
                    ),
                ]

            return subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=12,
                check=False,
            )


        def _runtime_remove():
            return subprocess.run(
                [
                    'wg',
                    'set',
                    iface,
                    'peer',
                    public_key,
                    'remove',
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=12,
                check=False,
            )


        def _restore_runtime(block):

            if not block:
                _runtime_remove()
                return

            old_allowed = (
                _block_allowed_ips(
                    block
                )
                or ['']
            )[0]

            old_endpoint = (
                _block_value(
                    block,
                    'endpoint',
                )
            )

            old_keepalive = (
                _block_value(
                    block,
                    'persistentkeepalive',
                )
                or 0
            )

            _runtime_remove()

            if not old_allowed:
                return

            runtime_old_endpoint = ''

            if old_endpoint:
                runtime_old_endpoint = (
                    _runtime_endpoint(
                        old_endpoint
                    )
                )

            restore_result = (
                _runtime_set(
                    old_allowed,
                    runtime_old_endpoint,
                    old_keepalive,
                )
            )

            if (
                restore_result.returncode
                != 0
            ):
                raise RuntimeError(
                    (
                        restore_result.stderr
                        or restore_result.stdout
                        or (
                            'Could not restore '
                            'the previous peer '
                            'runtime.'
                        )
                    ).strip()
                )

        with open(
            lock_path,
            'w',
        ) as lock_file:
            fcntl.flock(
                lock_file,
                fcntl.LOCK_EX,
            )

            metadata = (
                _read_iface(conf)
                if os.path.exists(conf)
                else None
            )

            if not metadata:
                return jsonify(
                    ok=False,
                    error=(
                        'interface_conf_not_found'
                    ),
                    detail=(
                        f'{conf} does not exist. '
                        'Create the interface first.'
                    ),
                ), 404

            if requested_host_cidr:
                try:
                    host = (
                        validate_requested_host_cidr(
                            requested_host_cidr,
                            metadata[
                                'address'
                            ],
                        )
                    )

                except Exception as exc:
                    return jsonify(
                        ok=False,
                        error=(
                            'invalid_host_cidr'
                        ),
                        detail=str(
                            exc
                        ),
                    ), 400

            blocks = (
                _peer_blocks_from_conf(
                    conf
                )
            )

            previous_block = next(
                (
                    block
                    for block in blocks
                    if (
                        _block_public_key(
                            block
                        )
                        == public_key
                    )
                ),
                None,
            )

            duplicate = (
                previous_block
                is not None
            )

            if (
                host is None
                and duplicate
            ):
                existing_host = (
                    _block_allowed_ips(
                        previous_block
                    )
                    or ['']
                )[0]

                if existing_host:
                    try:
                        host = (
                            validate_requested_host_cidr(
                                existing_host,
                                metadata[
                                    'address'
                                ],
                            )
                        )

                    except Exception:
                        app.logger.warning(
                            (
                                'Peer %s on %s has '
                                'an unusable '
                                'AllowedIPs %r; '
                                'allocating a new '
                                'address'
                            ),
                            public_key,
                            iface,
                            existing_host,
                        )

                        host = None

            if host is None:
                free_addresses = (
                    available_ips(
                        iface,
                        metadata[
                            'address'
                        ],
                        WG_CONF_PATH,
                        limit=1,
                    )
                )

                if not free_addresses:
                    return jsonify(
                        ok=False,
                        error=(
                            'address_pool_exhausted'
                        ),
                        detail=(
                            'No free client '
                            f'address left on '
                            f'{iface}.'
                        ),
                        iface=iface,
                    ), 409

                host = hostPrefix(
                    free_addresses[0]
                )

            for block in blocks:
                existing_public_key = (
                    _block_public_key(
                        block
                    )
                )

                allowed_values = (
                    _block_allowed_ips(
                        block
                    )
                )

                if (
                    existing_public_key
                    and existing_public_key
                    != public_key
                    and _host_matches_any(
                        allowed_values,
                        host,
                    )
                ):
                    return jsonify(
                        ok=False,
                        error=(
                            'host_cidr_already_used'
                        ),
                        detail=(
                            f'{host} is already '
                            'assigned to another '
                            'peer.'
                        ),
                        iface=iface,
                        host_cidr=host,
                    ), 409

            if not os.path.exists(
                conf
            ):
                return jsonify(
                    ok=False,
                    error=(
                        'interface_conf_not_found'
                    ),
                    detail=(
                        f'{conf} does not exist. '
                        'Create the interface first.'
                    ),
                ), 404

            try:
                subprocess.check_call(
                    [
                        'wg',
                        'show',
                        iface,
                    ],
                    stdout=(
                        subprocess.DEVNULL
                    ),
                    stderr=(
                        subprocess.DEVNULL
                    ),
                )

            except Exception:
                up_result = subprocess.run(
                    [
                        'wg-quick',
                        'up',
                        iface,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                    check=False,
                )

                if (
                    up_result.returncode
                    != 0
                ):
                    return jsonify(
                        ok=False,
                        error=(
                            'failed_to_bring_iface_up'
                        ),
                        iface=iface,
                        stderr=(
                            up_result.stderr
                            or up_result.stdout
                            or ''
                        ).strip(),
                    ), 500

            endpoint = (
                payload.get(
                    'endpoint'
                )
                or ''
            ).strip()

            runtime_endpoint = ''

            if endpoint:
                try:
                    runtime_endpoint = (
                        _runtime_endpoint(
                            endpoint
                        )
                    )

                except ValueError as exc:
                    return jsonify(
                        ok=False,
                        error=(
                            'invalid_fixed_endpoint'
                        ),
                        detail=str(
                            exc
                        ),
                        endpoint=endpoint,
                    ), 400

            try:
                keepalive = int(
                    payload.get(
                        'persistent_keepalive'
                    )
                    or 0
                )

            except Exception:
                keepalive = 0

            if keepalive < 0:
                keepalive = 0

            if keepalive > 65535:
                return jsonify(
                    ok=False,
                    error=(
                        'invalid_persistent_keepalive'
                    ),
                    detail=(
                        'PersistentKeepalive is '
                        'outside the accepted range.'
                    ),
                ), 400

            if duplicate:
                removed = (
                    _runtime_remove()
                )

                if (
                    removed.returncode
                    != 0
                ):
                    return jsonify(
                        ok=False,
                        error=(
                            'wg_remove_before_update_failed'
                        ),
                        stderr=(
                            removed.stderr
                            or removed.stdout
                            or ''
                        ).strip(),
                    ), 500

            runtime_result = (
                _runtime_set(
                    host,
                    runtime_endpoint,
                    keepalive,
                )
            )

            if (
                runtime_result.returncode
                != 0
            ):
                if duplicate:
                    try:
                        _restore_runtime(
                            previous_block
                        )

                    except Exception:
                        app.logger.exception(
                            'Could not restore '
                            'peer after failed '
                            'runtime update'
                        )

                return jsonify(
                    ok=False,
                    error='wg_set_failed',
                    stderr=(
                        runtime_result.stderr
                        or runtime_result.stdout
                        or ''
                    ).strip(),
                ), 500

            peer_block = [
                '',
                '[Peer]',
                (
                    'PublicKey = '
                    f'{public_key}'
                ),
                (
                    'AllowedIPs = '
                    f'{host}'
                ),
            ]

            if endpoint:
                peer_block.append(
                    f'Endpoint = {endpoint}'
                )

            if keepalive > 0:
                peer_block.append(
                    (
                        'PersistentKeepalive = '
                        f'{keepalive}'
                    )
                )

            peer_block.append('')

            with open(
                conf,
                'r',
                encoding='utf-8',
                errors='ignore',
            ) as handle:
                existing_config = (
                    handle.read()
                )

            try:
                updated_config = (
                    _upsert_peer_block_text(
                        existing_config,
                        public_key,
                        peer_block,
                    )
                )

                _write_conf_atomic(
                    conf,
                    updated_config,
                )

                if not _conf_has_peer(
                    conf,
                    public_key,
                ):
                    raise RuntimeError(
                        'Peer update was not '
                        'written to the '
                        'WireGuard config.'
                    )

                if not _runtime_has_peer(
                    iface,
                    public_key,
                ):
                    raise RuntimeError(
                        'Peer update was not '
                        'present in the '
                        'WireGuard runtime.'
                    )

            except Exception:

                try:
                    _write_conf_atomic(
                        conf,
                        existing_config,
                    )

                except Exception:
                    app.logger.exception(
                        'Could not restore '
                        'WireGuard config after '
                        'peer update failure'
                    )

                try:
                    _restore_runtime(
                        previous_block
                    )

                except Exception:
                    app.logger.exception(
                        'Could not restore '
                        'WireGuard runtime after '
                        'peer update failure'
                    )

                raise

            return jsonify(
                ok=True,
                duplicate=duplicate,
                updated=duplicate,
                iface=iface,
                public_key=public_key,
                host_cidr=host,
                endpoint=endpoint,
                runtime_endpoint=(
                    runtime_endpoint
                    if endpoint
                    else ''
                ),
            ), 200

    except subprocess.TimeoutExpired as exc:
        app.logger.exception(
            'WireGuard peer operation timed out'
        )

        return jsonify(
            ok=False,
            error='peer_operation_timeout',
            detail=str(exc),
        ), 504

    except Exception as exc:
        app.logger.exception(
            'add_peer failed'
        )

        return jsonify(
            ok=False,
            error='unhandled_exception',
            detail=str(exc),
        ), 500


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
    
@app.route(
    '/api/peer/<path:pub>/enable',
    methods=['POST'],
)
@require_api_key
def enable_peer(pub):

    info = _peer_conf(
        pub
    )

    if not info:
        return jsonify(
            ok=False,
            error='peer_not_found',
        ), 404

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    host = (
        payload.get(
            'host_cidr'
        )
        or _orig_host(
            info.get(
                'allowed'
            )
        )
    )

    interface_name = (
        info.get(
            'iface'
        )
        or ''
    ).strip()

    if not interface_name:
        return jsonify(
            ok=False,
            error='peer_interface_missing',
        ), 400

    try:
        interface_name = (
            _safe_iface_name(
                interface_name
            )
        )

    except Exception as exc:
        return jsonify(
            ok=False,
            error='invalid_iface',
            detail=str(exc),
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
        try:
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

        except subprocess.TimeoutExpired as exc:
            return jsonify(
                ok=False,
                error='interface_enable_timeout',
                detail=str(exc),
                interface=interface_name,
            ), 504

        if up_result.returncode != 0:
            return jsonify(
                ok=False,
                error='interface_enable_failed',
                detail=(
                    up_result.stderr
                    or up_result.stdout
                    or (
                        'Could not bring '
                        'WireGuard interface up.'
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

    allowed_ips = (
        info.get(
            'allowed'
        )
        or ''
    ).strip()

    if allowed_ips:
        command += [
            'allowed-ips',
            allowed_ips,
        ]

    endpoint = (
        info.get(
            'endpoint'
        )
        or ''
    ).strip()

    if endpoint:
        try:
            resolved_endpoint = (
                _runtime_endpoint(
                    endpoint
                )
            )

        except ValueError as exc:
            return jsonify(
                ok=False,
                error='invalid_fixed_endpoint',
                detail=str(exc),
                endpoint=endpoint,
                interface=interface_name,
            ), 400

        command += [
            'endpoint',
            resolved_endpoint,
        ]

    keepalive = (
        info.get(
            'keep'
        )
        or 0
    )

    try:
        keepalive = int(
            keepalive
        )

    except Exception:
        keepalive = 0

    if keepalive > 0:
        command += [
            'persistent-keepalive',
            str(
                keepalive
            ),
        ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12,
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        return jsonify(
            ok=False,
            error='peer_enable_timeout',
            detail=str(exc),
            interface=interface_name,
        ), 504

    if result.returncode != 0:
        return jsonify(
            ok=False,
            error='peer_enable_failed',
            detail=(
                result.stderr
                or result.stdout
                or (
                    'WireGuard peer '
                    'enable failed.'
                )
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
        endpoint=endpoint,
    )

@app.route('/api/peer/<path:pub>/disable', methods=['POST'])
@require_api_key
def disable_peer(pub):

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        try:
            raw = request.get_data(cache=True, as_text=True).strip()
            payload = json.loads(raw) if raw else None
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None

    if not isinstance(payload, dict):
        return jsonify(
        ok=False,
        error='invalid_payload',
        detail='The request body must be a JSON object.',
    ), 400

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

    j = request.get_json(silent=True)

    if not isinstance(j, dict):
        try:
            raw = request.get_data(cache=True, as_text=True).strip()
            j = json.loads(raw) if raw else None
        except (TypeError, ValueError, json.JSONDecodeError):
            j = None

    if not isinstance(j, dict):
        return jsonify(
        ok=False,
        error='invalid_payload',
        detail='The request body must be a JSON object.',
    ), 400
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

    pk = _iface_live_public_key(name)
    if pk:
        return jsonify(public_key=pk)

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
        pk = _pubkey_from_priv(priv)
        if pk:
            return jsonify(public_key=pk)
    except Exception:
        app.logger.warning(
            'Could not derive public key from %s.conf',
            name,
            exc_info=True,
        )

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

# ====================================================
# Traffic Control / WG forwarding policy (node agent)
# ====================================================
TRAFFIC_GEO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "traffic_geo")
TRAFFIC_NFT_TABLE = "wgpanel_traffic"
TRAFFIC_GEO_MAX_AGE = 86400


def _traffic_nft_capability():
    nft = shutil.which("nft")
    if not nft:
        return {"available": False, "usable": False, "reason": "not_installed", "detail": "The nft command was not found."}
    try:
        result = subprocess.run([nft, "list", "ruleset"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8, check=False)
        if result.returncode == 0:
            return {"available": True, "usable": True, "reason": "ready", "detail": "nftables is ready."}
        return {"available": True, "usable": False, "reason": "permission_denied", "detail": (result.stderr or result.stdout or "nft list ruleset failed").strip()[:500]}
    except Exception as exc:
        return {"available": True, "usable": False, "reason": "nft_error", "detail": str(exc)}


def _traffic_clean_iface(value):
    value = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value):
        raise ValueError("Invalid WireGuard interface name.")
    return value


def _traffic_host_addresses(value):
    out = []
    for raw in re.split(r"[\s,]+", str(value or "").strip()):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = ipa.ip_interface(raw) if "/" in raw else ipa.ip_address(raw)
            ip_obj = obj.ip if hasattr(obj, "ip") else obj
            text = str(ip_obj)
            if text not in out:
                out.append(text)
        except Exception:
            continue
    return out


def _traffic_normalize_domain(raw):
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        from urllib.parse import urlparse
        host = (urlparse(raw).hostname or "") if "://" in raw else raw.split("/", 1)[0]
        if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
            host = host.rsplit(":", 1)[0]
        host = host.strip().strip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        return host if host and len(host) <= 253 and re.fullmatch(r"[a-z0-9._-]+", host) else None
    except Exception:
        return None


def _traffic_resolve_domains(domains):
    v4, v6, warnings = set(), set(), []
    resolved = {}
    for raw in list(domains or []):
        host = _traffic_normalize_domain(raw)
        if not host:
            warnings.append(f"Invalid domain: {raw}")
            continue
        found = []
        try:
            for _family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                try:
                    ip_obj = ipa.ip_address(sockaddr[0])
                except Exception:
                    continue
                (v4 if ip_obj.version == 4 else v6).add(str(ip_obj))
                if str(ip_obj) not in found:
                    found.append(str(ip_obj))
        except Exception as exc:
            warnings.append(f"Could not resolve {host}: {exc}")
        resolved[host] = found
    return v4, v6, resolved, warnings


def _traffic_parse_cidrs(values):
    v4, v6, warnings = set(), set(), []
    for raw in list(values or []):
        raw = str(raw or "").strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                net = ipa.ip_network(raw, strict=False)
            else:
                ip_obj = ipa.ip_address(raw)
                net = ipa.ip_network(f"{ip_obj}/{32 if ip_obj.version == 4 else 128}", strict=False)
            (v4 if net.version == 4 else v6).add(str(net))
        except Exception:
            warnings.append(f"Invalid IP/CIDR: {raw}")
    return v4, v6, warnings


def _traffic_geo_path(country, version):
    os.makedirs(TRAFFIC_GEO_DIR, exist_ok=True)
    return os.path.join(TRAFFIC_GEO_DIR, f"{country.lower()}-v{version}.zone")


def _traffic_geo_url(country, version):
    cc = country.lower()
    return (f"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone" if version == 4 else f"https://www.ipdeny.com/ipv6/ipaddresses/blocks/{cc}.zone")


def _traffic_geo_networks(country, version):
    cc = str(country or "").strip().lower()
    if not re.fullmatch(r"[a-z]{2}", cc):
        raise ValueError(f"Invalid country code: {country}")
    path = _traffic_geo_path(cc, version)
    try:
        fresh = os.path.isfile(path) and (time.time() - os.path.getmtime(path) < TRAFFIC_GEO_MAX_AGE)
    except Exception:
        fresh = False
    if not fresh:
        try:
            response = requests.get(_traffic_geo_url(cc, version), timeout=12)
            response.raise_for_status()
            valid = []
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipa.ip_network(line, strict=False)
                    if net.version == version:
                        valid.append(str(net))
                except Exception:
                    continue
            if not valid:
                raise ValueError("Downloaded country list was empty or invalid.")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write("\n".join(valid) + "\n")
            os.replace(tmp, path)
        except Exception:
            if not os.path.isfile(path):
                raise
    out = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                net = ipa.ip_network(line.strip(), strict=False)
                if net.version == version:
                    out.append(str(net))
            except Exception:
                continue
    return out


def _traffic_elements(values):
    return ", ".join(sorted(set(values)))


def _traffic_apply(policies):
    capability = _traffic_nft_capability()
    if not capability.get("usable"):
        raise RuntimeError(
            capability.get("detail")
            or "nftables is unavailable"
        )

    nft = shutil.which("nft")
    if not nft:
        raise RuntimeError("The nft command was not found.")

    active = [
        p for p in list(policies or [])
        if isinstance(p, dict)
        and p.get("enabled", True)
    ]

    warnings = []
    domain_map = {}
    country_sets = {}
    policy_data = []

    for p in active:
        pid = str(
            p.get("id")
            or os.urandom(6).hex()
        )[:32]

        iface = _traffic_clean_iface(
            p.get("interface")
        )

        source_mode = str(
            p.get("source_mode")
            or "interface"
        )

        source_ips = (
            _traffic_host_addresses(
                p.get("source_ip")
            )
            if source_mode == "peer"
            else []
        )

        cidr4, cidr6, cidr_warn = (
            _traffic_parse_cidrs(
                p.get("cidrs") or []
            )
        )

        dom4, dom6, resolved, dom_warn = (
            _traffic_resolve_domains(
                p.get("domains") or []
            )
        )

        warnings.extend([
            f"{p.get('name') or pid}: {warning}"
            for warning in (
                cidr_warn + dom_warn
            )
        ])

        domain_map[pid] = resolved

        direct4 = set(cidr4) | set(dom4)
        direct6 = set(cidr6) | set(dom6)

        countries = []

        for raw_cc in list(
            p.get("countries") or []
        ):
            cc = str(
                raw_cc or ""
            ).strip().lower()

            if not re.fullmatch(
                r"[a-z]{2}",
                cc,
            ):
                warnings.append(
                    f"{p.get('name') or pid}: "
                    f"invalid country code {raw_cc}"
                )
                continue

            countries.append(cc)

            if cc not in country_sets:
                try:
                    country_sets[cc] = {
                        4: _traffic_geo_networks(
                            cc,
                            4,
                        ),
                        6: _traffic_geo_networks(
                            cc,
                            6,
                        ),
                    }

                except Exception as exc:
                    warnings.append(
                        f"Country {cc.upper()}: {exc}"
                    )
                    country_sets[cc] = {
                        4: [],
                        6: [],
                    }

        policy_data.append({
            "id": pid,
            "name": str(
                p.get("name")
                or "Traffic policy"
            ),
            "interface": iface,
            "source_mode": source_mode,
            "source_ips": source_ips,
            "direct4": sorted(direct4),
            "direct6": sorted(direct6),
            "countries": countries,
        })

    set_lines = []
    rule_lines = []

    for cc, versions in sorted(
        country_sets.items()
    ):
        for version, values in (
            (4, versions.get(4) or []),
            (6, versions.get(6) or []),
        ):
            if not values:
                continue

            nft_type = (
                "ipv4_addr"
                if version == 4
                else "ipv6_addr"
            )

            set_name = (
                f"geo_{cc}_v{version}"
            )

            set_lines.append(
                f"  set {set_name} {{ "
                f"type {nft_type}; "
                "flags interval; auto-merge; "
                "elements = { "
                f"{_traffic_elements(values)}"
                " } }"
            )

    for row in policy_data:
        safe_id = (
            re.sub(
                r"[^A-Za-z0-9_]",
                "",
                row["id"],
            )[:18]
            or os.urandom(4).hex()
        )

        for version, values in (
            (4, row["direct4"]),
            (6, row["direct6"]),
        ):
            if not values:
                continue

            nft_type = (
                "ipv4_addr"
                if version == 4
                else "ipv6_addr"
            )

            set_name = (
                f"p_{safe_id}_v{version}"
            )

            set_lines.append(
                f"  set {set_name} {{ "
                f"type {nft_type}; "
                "flags interval; auto-merge; "
                "elements = { "
                f"{_traffic_elements(values)}"
                " } }"
            )

        source_by_version = {
            4: [],
            6: [],
        }

        for src in row["source_ips"]:
            try:
                version = (
                    ipa.ip_address(src)
                    .version
                )
                source_by_version[
                    version
                ].append(src)
            except Exception:
                pass

        for version in (4, 6):
            family = (
                "ip"
                if version == 4
                else "ip6"
            )

            source_clause = ""

            if row["source_mode"] == "peer":
                sources = (
                    source_by_version[
                        version
                    ]
                )

                if not sources:
                    warnings.append(
                        f"{row['name']}: no IPv{version} "
                        "peer address, so IPv"
                        f"{version} peer-scoped blocking "
                        "was skipped"
                    )
                    continue

                if len(sources) == 1:
                    source_clause = (
                        f" {family} saddr "
                        f"{sources[0]}"
                    )
                else:
                    source_clause = (
                        f" {family} saddr {{ "
                        f"{', '.join(sources)} }}"
                    )

            base = (
                f'    iifname "{row["interface"]}"'
                f"{source_clause}"
            )

            direct = row[
                f"direct{version}"
            ]

            if direct:
                set_name = (
                    f"p_{safe_id}_v{version}"
                )

                rule_lines.append(
                    f"{base} {family} daddr "
                    f"@{set_name} counter drop "
                    f'comment "wgpanel:{safe_id}:'
                    f'direct:v{version}"'
                )

            for cc in row["countries"]:
                if not (
                    country_sets
                    .get(cc, {})
                    .get(version)
                ):
                    continue

                rule_lines.append(
                    f"{base} {family} daddr "
                    f"@geo_{cc}_v{version} "
                    "counter drop "
                    f'comment "wgpanel:{safe_id}:'
                    f'geo:{cc}:v{version}"'
                )

    table_exists = (
        subprocess.run(
            [
                nft,
                "list",
                "table",
                "inet",
                TRAFFIC_NFT_TABLE,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        ).returncode
        == 0
    )

    lines = []

    if table_exists:
        lines.append(
            f"delete table inet "
            f"{TRAFFIC_NFT_TABLE}"
        )

    lines.append(
        f"table inet {TRAFFIC_NFT_TABLE} {{"
    )

    lines.extend(set_lines)

    lines.extend([
        "  chain forward {",
        (
            "    type filter hook forward "
            "priority -10; policy accept;"
        ),
    ])

    lines.extend(rule_lines)

    lines.extend([
        "  }",
        "}",
    ])

    script = "\n".join(lines) + "\n"

    result = subprocess.run(
        [nft, "-f", "-"],
        input=script,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        detail = (
            result.stderr
            or result.stdout
            or "nftables apply failed"
        ).strip()

        raise RuntimeError(detail)

    return {
        "ok": True,
        "policies": len(policy_data),
        "rules": len(rule_lines),
        "warnings": warnings,
        "resolved_domains": domain_map,
    }


def _traffic_status():
    cap = _traffic_nft_capability()
    out = {"capability": cap, "loaded": False, "counters": {}}
    if not cap.get("usable"):
        return out
    nft = shutil.which("nft")
    proc = subprocess.run([nft, "list", "table", "inet", TRAFFIC_NFT_TABLE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8, check=False)
    if proc.returncode != 0:
        return out
    out["loaded"] = True
    for line in (proc.stdout or "").splitlines():
        mc = re.search(r'comment\s+"wgpanel:([^\"]+)"', line)
        mn = re.search(r'counter packets\s+(\d+)\s+bytes\s+(\d+)', line)
        if mc and mn:
            out["counters"][mc.group(1)] = {"packets": int(mn.group(1)), "bytes": int(mn.group(2))}
    return out


@app.get("/api/traffic-control/status")
@require_api_key
def node_traffic_control_status():
    return jsonify(ok=True, **_traffic_status())


@app.post("/api/traffic-control/apply")
@require_api_key
def node_traffic_control_apply():
    data = request.get_json(silent=True) or {}
    policies = data.get("policies") or []
    if not isinstance(policies, list):
        return jsonify(ok=False, error="invalid_policies"), 400
    try:
        return jsonify(**_traffic_apply(policies))
    except Exception as exc:
        app.logger.exception("Traffic policy apply failed")
        return jsonify(ok=False, error="traffic_apply_failed", detail=str(exc)), 500


def _traffic_nft_set_text(set_name):
    nft = shutil.which("nft")
    if not nft:
        return ""
    proc = subprocess.run(
        [nft, "list", "set", "inet", TRAFFIC_NFT_TABLE, str(set_name)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def _traffic_test_policy_local(policy):
    policy = dict(policy or {})
    pid = str(policy.get("id") or "").strip()
    name = str(policy.get("name") or "Traffic policy").strip()
    iface = _traffic_clean_iface(policy.get("interface"))
    source_mode = str(policy.get("source_mode") or "interface").strip().lower()
    source_ips = _traffic_host_addresses(policy.get("source_ip")) if source_mode == "peer" else []
    checks = []

    def add(key, label, status, detail):
        checks.append({"key": key, "label": label, "status": status, "detail": str(detail or "")})

    capability = _traffic_nft_capability()
    if not capability.get("usable"):
        add("nftables", "nftables engine", "fail", capability.get("detail") or "nftables is unavailable.")
        return {"ok": False, "policy_id": pid, "policy_name": name, "checks": checks, "counters": {"packets": 0, "bytes": 0}}

    nft = shutil.which("nft")
    table_proc = subprocess.run([nft, "list", "table", "inet", TRAFFIC_NFT_TABLE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8, check=False)
    table_text = table_proc.stdout or ""
    if table_proc.returncode != 0:
        add("table", "Live policy table", "fail", "inet wgpanel_traffic is not loaded. Re-apply the policy rules.")
        return {"ok": False, "policy_id": pid, "policy_name": name, "checks": checks, "counters": {"packets": 0, "bytes": 0}}
    add("table", "Live policy table", "pass", "inet wgpanel_traffic is loaded in the kernel.")

    iface_proc = subprocess.run(["wg", "show", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
    add("interface", "WireGuard interface", "pass" if iface_proc.returncode == 0 else "fail", f"{iface} is active." if iface_proc.returncode == 0 else f"{iface} is not active in the WireGuard runtime.")

    versions = {4, 6}
    if source_mode == "peer":
        versions = set()
        for src in source_ips:
            try:
                versions.add(ipa.ip_address(src).version)
            except Exception:
                pass
        add("scope", "Peer source scope", "pass" if source_ips else "fail", f"Live policy is expected to match only {', '.join(source_ips)} on {iface}." if source_ips else "The policy has no usable peer/source address.")

    safe_id = re.sub(r"[^A-Za-z0-9_]", "", pid)[:18]
    domains = list(policy.get("domains") or [])
    cidrs = list(policy.get("cidrs") or [])
    countries = [str(x or "").strip().lower() for x in list(policy.get("countries") or []) if str(x or "").strip()]

    def rule_line(comment):
        marker = f'comment "{comment}"'
        for line in table_text.splitlines():
            if marker in line:
                return line.strip()
        return ""

    def scope_matches(line, version):
        if not line or f'iifname "{iface}"' not in line:
            return False
        if source_mode != "peer":
            return True
        family = "ip" if version == 4 else "ip6"
        candidates = [s for s in source_ips if ipa.ip_address(s).version == version]
        return bool(candidates) and all((f"{family} saddr {s}" in line) or (s in line and f"{family} saddr" in line) for s in candidates)

    direct_needed = bool(domains or cidrs)
    for version in (4, 6):
        if version not in versions:
            if direct_needed:
                add(f"direct_v{version}", f"IPv{version} direct rule", "info", f"Skipped because this peer has no IPv{version} WireGuard source address.")
            continue
        if not direct_needed:
            continue
        line = rule_line(f"wgpanel:{pid}:direct:v{version}")
        set_name = f"p_{safe_id}_v{version}"
        set_text = _traffic_nft_set_text(set_name)
        add(f"direct_v{version}", f"IPv{version} domain/IP rule", "pass" if (line and scope_matches(line, version) and set_text) else "fail", f"DROP rule and @{set_name} are loaded with the expected {iface} scope." if (line and scope_matches(line, version) and set_text) else "The expected live DROP rule or destination set is missing. Save & apply again.")

    if domains:
        dom4, dom6, resolved, warnings = _traffic_resolve_domains(domains)
        for warning in warnings:
            add("domain_dns", "Domain resolution", "warn", warning)
        for version, values in ((4, sorted(dom4)), (6, sorted(dom6))):
            if version not in versions or not values:
                continue
            set_text = _traffic_nft_set_text(f"p_{safe_id}_v{version}")
            present = [ip for ip in values if ip in set_text]
            missing = [ip for ip in values if ip not in set_text]
            if present and not missing:
                add(f"domain_v{version}", f"IPv{version} domain addresses", "pass", f"Current DNS addresses are present in the live destination set.")
            elif present:
                add(f"domain_v{version}", f"IPv{version} domain addresses", "warn", f"DNS changed partially: {len(missing)} current address(es) are not loaded. Re-apply the policy.")
            else:
                add(f"domain_v{version}", f"IPv{version} domain addresses", "fail", "Current DNS addresses are not in the live set. Use Save & apply.")

    for cc in countries:
        if not re.fullmatch(r"[a-z]{2}", cc):
            add(f"geo_{cc}", "Geo country", "fail", f"Invalid country code: {cc}")
            continue
        for version in (4, 6):
            if version not in versions:
                continue
            set_text = _traffic_nft_set_text(f"geo_{cc}_v{version}")
            line = rule_line(f"wgpanel:{pid}:geo:{cc}:v{version}")
            good = bool(set_text and line and scope_matches(line, version))
            add(f"geo_{cc}_v{version}", f"{cc.upper()} Geo IPv{version}", "pass" if good else "fail", f"@geo_{cc}_v{version} and its scoped DROP rule are loaded." if good else "The country set or its scoped DROP rule is missing.")

    status = _traffic_status()
    packets = 0
    byte_count = 0
    for key, counter in (status.get("counters") or {}).items():
        if str(key).startswith(pid + ":"):
            packets += int((counter or {}).get("packets") or 0)
            byte_count += int((counter or {}).get("bytes") or 0)
    add("counters", "Live hit counters", "pass" if packets > 0 else "info", f"This policy has blocked {packets} packet(s) / {byte_count} byte(s)." if packets > 0 else "Rules are loaded but no real forwarded packet has matched them yet.")

    if not (domains or cidrs or countries):
        add("destinations", "Policy destinations", "fail", "The policy has no domains, IP/CIDR entries, or countries to block.")

    return {"ok": not any(x.get("status") == "fail" for x in checks), "policy_id": pid, "policy_name": name, "checks": checks, "counters": {"packets": packets, "bytes": byte_count}}


@app.post('/api/traffic-control/test')
@require_api_key
def traffic_control_test():
    data = request.get_json(silent=True) or {}
    policy = data.get("policy") or {}
    if not isinstance(policy, dict) or not str(policy.get("id") or "").strip():
        return jsonify(ok=False, error="invalid_policy", detail="A complete policy object is required."), 400
    if policy.get("enabled", True) is False:
        return jsonify(ok=False, error="policy_disabled", detail="The policy is disabled and is intentionally not loaded."), 409
    try:
        result = _traffic_test_policy_local(policy)
        return jsonify(result), 200
    except Exception as exc:
        app.logger.exception("Traffic policy test failed")
        return jsonify(ok=False, error="traffic_test_failed", detail=str(exc)), 500

def _traffic_live_set_contains(set_name, address):
    """
    Return True when *address* is covered by a live nftables set.

    Exact addresses are checked directly through nftables first.
    The fallback parser handles CIDRs / interval Geo sets and works
    with both one-line and multiline `nft list set` output.
    """
    try:
        wanted = ipa.ip_address(
            str(address or '').strip()
        )
    except Exception:
        return False

    clean_set_name = str(
        set_name or ''
    ).strip()

    if not re.fullmatch(
        r'[A-Za-z0-9_.:-]{1,128}',
        clean_set_name,
    ):
        return False

    nft = shutil.which("nft")

    if nft:
        try:
            script = (
                f"get element inet "
                f"{TRAFFIC_NFT_TABLE} "
                f"{clean_set_name} "
                f"{{ {wanted} }}\n"
            )

            result = subprocess.run(
                [nft, "-f", "-"],
                input=script,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=8,
                check=False,
            )

            if result.returncode == 0:
                return True

        except Exception:
            pass

    text_body = _traffic_nft_set_text(
        clean_set_name
    )

    if not text_body:
        return False

    match = re.search(
        r'elements\s*=\s*\{(.*?)\}',
        text_body,
        re.S,
    )

    if not match:
        return False

    for raw_token in match.group(1).split(','):
        token = ' '.join(
            raw_token.strip().split()
        )

        if not token:
            continue

        try:
            if (
                '-' in token
                and '/' not in token
            ):
                first, last = [
                    part.strip()
                    for part in token.split(
                        '-',
                        1,
                    )
                ]

                start_ip = ipa.ip_address(
                    first
                )
                end_ip = ipa.ip_address(
                    last
                )

                if (
                    start_ip.version
                    == wanted.version
                    and int(start_ip)
                    <= int(wanted)
                    <= int(end_ip)
                ):
                    return True

                continue

            if '/' in token:
                network = ipa.ip_network(
                    token,
                    strict=False,
                )

                if (
                    network.version
                    == wanted.version
                    and wanted in network
                ):
                    return True

                continue

            if (
                ipa.ip_address(token)
                == wanted
            ):
                return True

        except Exception:
            continue

    return False



def _traffic_manual_target_addresses(target):
    raw = str(target or '').strip()
    if not raw:
        raise ValueError('Enter a domain, URL, IPv4 or IPv6 address.')

    candidate = raw.strip('[]')
    try:
        return raw, '', [str(ipa.ip_address(candidate))]
    except Exception:
        pass

    host = _traffic_normalize_domain(raw)
    if not host:
        raise ValueError('The destination is not a valid domain, URL, IPv4 or IPv6 address.')

    found = []
    try:
        for _family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
            if not sockaddr:
                continue
            try:
                value = str(ipa.ip_address(sockaddr[0]))
            except Exception:
                continue
            if value not in found:
                found.append(value)
    except Exception as exc:
        raise ValueError(f'Could not resolve {host}: {exc}') from exc

    if not found:
        raise ValueError(f'{host} did not resolve to a usable IP address.')

    return raw, host, found


def _traffic_manual_test_local(policy, target):
    policy = dict(policy or {})
    pid = str(policy.get('id') or '').strip()
    iface = _traffic_clean_iface(policy.get('interface'))
    source_mode = str(policy.get('source_mode') or 'interface').strip().lower()
    source_ips = _traffic_host_addresses(policy.get('source_ip')) if source_mode == 'peer' else []

    capability = _traffic_nft_capability()
    if not capability.get('usable'):
        raise RuntimeError(capability.get('detail') or 'nftables is unavailable.')

    nft = shutil.which('nft')
    table_proc = subprocess.run(
        [nft, 'list', 'table', 'inet', TRAFFIC_NFT_TABLE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )
    if table_proc.returncode != 0:
        raise RuntimeError('inet wgpanel_traffic is not loaded. Re-apply the policy rules.')
    table_text = table_proc.stdout or ''

    original_target, hostname, addresses = _traffic_manual_target_addresses(target)
    safe_id = re.sub(r'[^A-Za-z0-9_]', '', pid)[:18]
    countries = [
        str(value or '').strip().lower()
        for value in list(policy.get('countries') or [])
        if re.fullmatch(r'[A-Za-z]{2}', str(value or '').strip())
    ]

    source_versions = {4, 6}
    if source_mode == 'peer':
        source_versions = set()
        for source in source_ips:
            try:
                source_versions.add(ipa.ip_address(source).version)
            except Exception:
                pass

    def rule_line(comment):
        marker = f'comment "{comment}"'
        for line in table_text.splitlines():
            if marker in line:
                return line.strip()
        return ''

    def scoped_rule_exists(comment, version):
        line = rule_line(comment)
        if not line or f'iifname "{iface}"' not in line:
            return False
        if source_mode != 'peer':
            return True
        family = 'ip' if version == 4 else 'ip6'
        candidates = []
        for source in source_ips:
            try:
                if ipa.ip_address(source).version == version:
                    candidates.append(source)
            except Exception:
                pass
        return bool(candidates) and all(source in line and f'{family} saddr' in line for source in candidates)

    results = []
    for address in addresses:
        ip_obj = ipa.ip_address(address)
        version = ip_obj.version
        applicable = version in source_versions
        matches = []

        if applicable:
            direct_set = f'p_{safe_id}_v{version}'
            direct_comment = f'wgpanel:{pid}:direct:v{version}'
            if (
                _traffic_live_set_contains(direct_set, address)
                and scoped_rule_exists(direct_comment, version)
            ):
                matches.append({
                    'kind': 'direct',
                    'label': 'Domain/IP set',
                    'set': direct_set,
                    'comment': direct_comment,
                })

            for cc in countries:
                geo_set = f'geo_{cc}_v{version}'
                geo_comment = f'wgpanel:{pid}:geo:{cc}:v{version}'
                if (
                    _traffic_live_set_contains(geo_set, address)
                    and scoped_rule_exists(geo_comment, version)
                ):
                    matches.append({
                        'kind': 'geo',
                        'label': f'Geo {cc.upper()}',
                        'set': geo_set,
                        'comment': geo_comment,
                    })

        results.append({
            'ip': address,
            'version': version,
            'applicable': applicable,
            'blocked': bool(applicable and matches),
            'matches': matches,
            'note': (
                '' if applicable
                else f'This peer has no IPv{version} WireGuard source address.'
            ),
        })

    applicable_rows = [row for row in results if row.get('applicable')]
    blocked_rows = [row for row in applicable_rows if row.get('blocked')]

    if not applicable_rows:
        verdict = 'not_applicable'
    elif len(blocked_rows) == len(applicable_rows):
        verdict = 'blocked'
    elif blocked_rows:
        verdict = 'partial'
    else:
        verdict = 'not_blocked'

    scope = (
        f'{iface} · peer source {", ".join(source_ips)}'
        if source_mode == 'peer'
        else f'{iface} · entire interface'
    )

    return {
        'ok': True,
        'policy_id': pid,
        'policy_name': str(policy.get('name') or 'Traffic policy'),
        'target': original_target,
        'hostname': hostname,
        'resolved': addresses,
        'verdict': verdict,
        'scope': scope,
        'results': results,
        'note': (
            'This evaluates the live nftables sets and exact scoped DROP rules. '
            'It does not generate traffic as the WireGuard peer.'
        ),
    }


@app.post('/api/traffic-control/test-destination')
@require_api_key
def traffic_control_test_destination():
    data = request.get_json(silent=True) or {}
    policy = data.get('policy') or {}
    target = str(data.get('target') or '').strip()

    if not isinstance(policy, dict) or not str(policy.get('id') or '').strip():
        return jsonify(ok=False, error='invalid_policy', detail='A complete policy object is required.'), 400
    if not target:
        return jsonify(ok=False, error='target_required', detail='Enter a domain, URL, IPv4 or IPv6 address.'), 400
    if policy.get('enabled', True) is False:
        return jsonify(ok=False, error='policy_disabled', detail='The policy is disabled and is not loaded into nftables.'), 409

    try:
        return jsonify(_traffic_manual_test_local(policy, target))
    except ValueError as exc:
        return jsonify(ok=False, error='invalid_target', detail=str(exc)), 400
    except Exception as exc:
        app.logger.exception('Traffic destination test failed')
        return jsonify(ok=False, error='traffic_destination_test_failed', detail=str(exc)), 500

if __name__ == "__main__":
    import os, multiprocessing, sys

    try:
        firewall_summary = (
            _migrate_existing_rules()
        )

        app.logger.info(
            "Existing node firewall "
            "migration: %s",
            firewall_summary,
        )

    except Exception:
        app.logger.exception(
            "Existing node firewall "
            "migration failed"
        )

    use_gunicorn = os.getenv(
        "USE_GUNICORN",
        "1"
    ) != "0"

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
