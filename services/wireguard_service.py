from __future__ import annotations
import ipaddress
import os
import re
import socket
import subprocess
from panel_core.endpoint_values import _host_port, _norm_hostport


def _host_peer(peer: Peer):
    import ipaddress as _ipa
    ip = _ipa.ip_interface(peer.address).ip
    mask = 32 if ip.version == 4 else 128
    return f"{ip}/{mask}"

def iface_devname(iface):
    import os
    name = iface.name or os.path.splitext(os.path.basename(iface.path))[0]
    return name.split(':')[-1]

_WG_KEY_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')

def _valid_wg_key(value) -> str:
    s = (value or '').strip()
    return s if s and _WG_KEY_RE.fullmatch(s) else ''

def _node_id_from_iface(iface):
    nid = getattr(iface, 'node_id', None)
    if nid is not None:
        return nid
    name = getattr(iface, 'name', '') or ''
    if ':' not in name:
        return None
    prefix = name.split(':', 1)[0]
    if prefix[:1] == 'n' and prefix[1:].isdigit():
        return int(prefix[1:])
    return None

def _assign_iface_public_key(iface, value) -> str:
    pk = _valid_wg_key(value)
    if iface is not None and pk and getattr(iface, 'public_key', None) != pk:
        iface.public_key = pk
    return pk

def _wg_transfer(peer):
    rx, tx = _wg_rx_tx(peer)
    return rx + tx

def _wg_handshake(peer):
    try:
        dev = iface_devname(peer.iface)
        out = subprocess.check_output(
            ['wg', 'show', dev, 'latest-handshakes', peer.public_key],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().strip().split()[-1]
        return int(out) if out.isdigit() else 0
    except Exception:
        return 0

def _wireguard_endpoint(value: str) -> str:

    raw = str(value or '').strip()

    if not raw:
        return ''

    try:
        host, port = _host_port(raw)

        host = str(host or '').strip()
        port = str(port or '').strip()

        if not host or not port:
            raise ValueError(
                'Fixed client endpoint must use host:port format.'
            )

        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                'Fixed client endpoint port must be a number.'
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                'Fixed client endpoint port must be between 1 and 65535.'
            )


        try:
            address = ipaddress.ip_address(
                host.strip('[]')
            )

            return _norm_hostport(
                address.compressed,
                port,
            )

        except ValueError:
            pass

        hostname = host.rstrip('.')

        if (
            not hostname
            or len(hostname) > 253
        ):
            raise ValueError(
                'Fixed client endpoint hostname is invalid.'
            )

        labels = hostname.split('.')

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?',
                    label,
                )
            ):
                raise ValueError(
                    'Fixed client endpoint hostname is invalid.'
                )


        return _norm_hostport(
            hostname,
            port,
        )

    except Exception as exc:
        raise RuntimeError(
            f'Invalid fixed client endpoint: {raw}. {exc}'
        ) from exc

def _wireguard_runtime_endpoint(value: str) -> str:

    endpoint = _wireguard_endpoint(
        value
    )

    if not endpoint:
        return ''

    host, port = _host_port(
        endpoint
    )

    host = str(
        host or ''
    ).strip().strip('[]')

    port = int(port)


    try:
        address = ipaddress.ip_address(
            host
        )

        return _norm_hostport(
            address.compressed,
            port,
        )

    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_DGRAM,
        )

    except socket.gaierror as exc:
        raise RuntimeError(
            (
                'Fixed client endpoint DNS lookup failed: '
                f'{host}. {exc}'
            )
        ) from exc

    if not results:
        raise RuntimeError(
            f'Fixed client endpoint DNS lookup returned no addresses: {host}'
        )

    ipv4 = next(
        (
            result[4][0]
            for result in results
            if result[0] == socket.AF_INET
        ),
        None,
    )

    resolved = (
        ipv4
        or results[0][4][0]
    )

    return _norm_hostport(
        resolved,
        port,
    )

def _wg_enable(peer):
    from reseller_portal.service import may_enable
    may_enable(peer)

    dev = iface_devname(peer.iface)
    host_cidr = _host_peer(peer)

    if not dev:
        raise RuntimeError('Peer interface device name is missing.')

    if not host_cidr:
        raise RuntimeError('Peer WireGuard address is missing.')

    cmd = [
        'wg',
        'set',
        dev,
        'peer',
        peer.public_key,
        'allowed-ips',
        host_cidr,
    ]


    fixed_endpoint = (getattr(peer, "peer_endpoint", None)or "").strip()

    if fixed_endpoint:
        cmd += [
        'endpoint',
        _wireguard_runtime_endpoint(
            fixed_endpoint
        ),
    ]

    if peer.persistent_keepalive:
        cmd += [
            'persistent-keepalive',
            str(int(peer.persistent_keepalive)),
        ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=12,
        check=False,
    )

    if result.returncode != 0:
        error_text = (
            result.stderr or
            result.stdout or
            'WireGuard command failed.'
        ).strip()

        raise RuntimeError(
            f'Could not enable peer on {dev}: {error_text}'
        )

    _unblackhole(host_cidr)

def _wg_disable(peer):
    dev = iface_devname(peer.iface)
    host_cidr = _host_peer(peer)

    if not dev:
        raise RuntimeError(
            'Peer interface device name is missing.'
        )

    if not host_cidr:
        raise RuntimeError(
            'Peer WireGuard address is missing.'
        )

    result = subprocess.run(
        [
            'wg',
            'set',
            dev,
            'peer',
            peer.public_key,
            'remove',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=12,
        check=False,
    )

    if result.returncode != 0:
        detail = (
            result.stderr
            or result.stdout
            or 'WireGuard peer removal failed.'
        ).strip()

        raise RuntimeError(
            f'Could not disable peer on {dev}: {detail}'
        )

    _blackhole(host_cidr)

def _blackhole(host_cidr):
    subprocess.run(['ip', 'route', 'add', 'blackhole', host_cidr],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

def _unblackhole(host_cidr):
    subprocess.run(['ip', 'route', 'del', 'blackhole', host_cidr],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

def _iface_up(name: str) -> bool:
    try:
        subprocess.check_call(
            ['wg', 'show', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5
        )
        return True
    except Exception:
        return False

def _run_capture(cmd, timeout=20.0):
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False
    )
    out = (p.stdout or b'').decode('utf-8', 'ignore')
    return p.returncode, out

def _read_iface_conf(conf_path: str | None) -> str | None:

    if not conf_path or not os.path.isfile(conf_path):
        return None

    try:
        in_iface = False
        with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                if line.startswith("[") and line.endswith("]"):
                    in_iface = (line[1:-1].strip().lower() == "interface")
                    continue

                if not in_iface or "=" not in line:
                    continue

                k, v = [x.strip() for x in line.split("=", 1)]
                if k.lower() == "address":
                    return v
    except Exception:
        pass

    return None

def _peer_in_conf(conf_path, public_key):
    try:
        with open(conf_path, 'r') as f:
            lines = f.readlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip().lower()
            if line == '[peer]':
                block = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('['):
                    block.append(lines[i]); i += 1
                for L in block:
                    if L.partition('=')[0].strip().lower() == 'publickey' and '=' in L:
                        if L.split('=', 1)[1].strip() == public_key:
                            return True
                continue
            i += 1
    except FileNotFoundError:
        return False
    return False

def _norm_conftext(txt: str) -> str:
    import re
    if txt is None:
        return ''
    txt = txt.replace('\r\n', '\n').replace('\r', '\n')
    txt = re.sub(r'\n{3,}', '\n\n', txt)
    txt = txt.strip('\n') + '\n'
    return txt

def _write_conf_atomic(conf_path: str, text_body: str):
    directory = os.path.dirname(conf_path) or '.'
    os.makedirs(directory, exist_ok=True)

    try:
        mode = os.stat(conf_path).st_mode & 0o777
    except OSError:
        mode = 0o600

    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix='.wgconf.', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text_body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, conf_path)
        tmp_path = None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

def _wg_peer_keys(dev: str) -> set:
    keys = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', dev, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
    except Exception:
        return keys

    for line in out.splitlines():
        key = line.split('\t', 1)[0].strip()
        if key:
            keys.add(key)
    return keys

def _wg_rx_tx(peer):
    try:
        out = subprocess.check_output(
            ['wg', 'show', peer.iface.name, 'transfer'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().splitlines()
        for ln in out:
            parts = ln.split()
            if len(parts) >= 3 and parts[0] == peer.public_key:
                return int(parts[1]), int(parts[2])
    except Exception:
        pass
    return 0, 0

def _latest_handshake(peer):
    try:
        out = subprocess.check_output(
            ['wg', 'show', peer.iface.name, 'latest-handshakes'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().splitlines()
        for ln in out:
            parts = ln.split()
            if len(parts) >= 2 and parts[0] == peer.public_key:
                return int(parts[1]) if parts[1].isdigit() else 0
    except Exception:
        pass
    return 0

def _wg_transfer_bytes(peer):
    rx, tx = _wg_rx_tx(peer)
    return rx + tx

def _iface_down(name: str):
    try:
        subprocess.check_call(
            ['wg-quick', 'down', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6.0
        )
        return
    except Exception:
        subprocess.run(
            ['ip', 'link', 'del', 'dev', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )

def _wireguard_network(address_field: str) -> str:

    for raw_value in re.split(
        r"[\s,]+",
        str(address_field or "").strip(),
    ):
        value = raw_value.strip()

        if not value or "/" not in value:
            continue

        try:
            interface = ipaddress.ip_interface(value)
        except ValueError:
            continue

        if (
            interface.version == 4
            and interface.ip.is_private
        ):
            return str(interface.network)

    return ""
