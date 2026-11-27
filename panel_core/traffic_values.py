import ipaddress
import re
from urllib.parse import urlparse


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
            obj = ipaddress.ip_interface(raw) if "/" in raw else ipaddress.ip_address(raw)
            ip_obj = obj.ip if hasattr(obj, "ip") else obj
            text = str(ip_obj)
            if text not in out:
                out.append(text)
        except Exception:
            continue
    return out

def _traffic_normalize_destination(raw):
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        if "://" in raw:
            host = urlparse(raw).hostname or ""
        else:
            host = raw.split("/", 1)[0]
            if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
                host = host.rsplit(":", 1)[0]
        host = host.strip().strip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        if not host or len(host) > 253:
            return None
        if not re.fullmatch(r"[a-z0-9._-]+", host):
            return None
        return host
    except Exception:
        return None

def _traffic_parse_cidrs(values):
    v4, v6, warnings = set(), set(), []
    for raw in list(values or []):
        raw = str(raw or "").strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                ip_obj = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(f"{ip_obj}/{32 if ip_obj.version == 4 else 128}", strict=False)
            (v4 if net.version == 4 else v6).add(str(net))
        except Exception:
            warnings.append(f"Invalid IP/CIDR: {raw}")
    return v4, v6, warnings
