import ipaddress as ipa
import re
import socket


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
            if text.partition('=')[0].strip().lower() == 'publickey' and '=' in text:
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


def _first_cidr(s: str | None) -> str | None:
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
