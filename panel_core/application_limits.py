import ipaddress
from datetime import date, datetime, time, timezone


def limits_key(role, aid):
    return f'app_limits:{role}:{aid}'


def parse_limits(expiry, networks):
    expiry = (expiry or '').strip()
    if expiry:
        parsed = date.fromisoformat(expiry)
        if parsed.isoformat() != expiry:
            raise ValueError('Use YYYY-MM-DD for expiration.')
    if len(networks or '') > 2048:
        raise ValueError('IP allowlist is too long.')
    parts = (networks or '').replace('\n', ',').split(',')
    result = []
    for part in parts:
        if not part.strip():
            continue
        network = ipaddress.ip_network(part.strip(), strict=True)
        if network.prefixlen == 0:
            raise ValueError('A universal IP allowlist is not allowed. Leave the list empty instead.')
        result.append(str(network))
    if len(result)>16:
        raise ValueError('Use at most 16 allowed IP networks.')
    return {'expires': expiry, 'networks': list(dict.fromkeys(result))}


def permits(limits, address=None, *, check_ip=True, now=None):
    
    if limits is None:
        return True
    if not isinstance(limits, dict) or set(limits) != {'expires','networks'}:
        return False
    if not isinstance(limits['expires'],str) or not isinstance(limits['networks'],list) or any(not isinstance(x,str) for x in limits['networks']):
        return False
    try:
        policy = parse_limits(limits['expires'], ','.join(limits['networks']))
        if policy['expires']:
            deadline = datetime.combine(date.fromisoformat(policy['expires']), time.min, tzinfo=timezone.utc)
            if (now or datetime.now(timezone.utc)) >= deadline:
                return False
        if check_ip and policy['networks']:
            ip = ipaddress.ip_address(address)
            return any(ip in ipaddress.ip_network(n) for n in policy['networks'])
        return True
    except (ValueError, TypeError, OverflowError):
        return False
