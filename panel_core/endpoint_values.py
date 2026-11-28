import ipaddress
import re


def _norm_hostport(host: str, port: int | None) -> str:
    if not host or not port:
        return ''
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f'[{host}]:{port}'
    except ValueError:
        pass
    return f'{host}:{port}'


class EndpointValidationError(ValueError):

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code
        self.detail = detail


_DNS_LABEL_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


_HOST_FORBIDDEN = ('://', '/', '@', '?', '#', '\\')


def _parse_endpoint_host(value):
    if any(ch.isspace() for ch in value):
        raise EndpointValidationError(
            'endpoint_host_whitespace',
            'The host may not contain whitespace.',
        )

    for token in _HOST_FORBIDDEN:
        if token in value:
            raise EndpointValidationError(
                'endpoint_host_not_a_host',
                'The host must be a bare name or IP address, without a scheme, '
                'path, credentials or query string.',
            )

    bracketed = value.startswith('[') and value.endswith(']')
    candidate = value[1:-1] if bracketed else value

    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    if bracketed:
        raise EndpointValidationError(
            'endpoint_host_invalid',
            'Bracketed hosts must be valid IPv6 addresses.',
        )

    if ':' in candidate:
        raise EndpointValidationError(
            'endpoint_host_has_port',
            'Put the port in the port field; the host must not contain one.',
        )

    name = candidate[:-1] if candidate.endswith('.') else candidate

    if not name or len(name) > 253:
        raise EndpointValidationError(
            'endpoint_host_invalid',
            'The host must be between 1 and 253 characters long.',
        )

    for label in name.split('.'):
        if not _DNS_LABEL_RE.match(label):
            raise EndpointValidationError(
                'endpoint_host_invalid',
                'Each DNS label must be 1 to 63 letters, digits or hyphens, and '
                'may not start or end with a hyphen.',
            )

    return name.lower()


def _parse_endpoint_port(value):
    if isinstance(value, bool):
        raise EndpointValidationError(
            'endpoint_port_invalid', 'The port must be a whole number.'
        )

    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise EndpointValidationError(
            'endpoint_port_invalid', 'The port must be a whole number.'
        )

    if not 1 <= port <= 65535:
        raise EndpointValidationError(
            'endpoint_port_range', 'The port must be between 1 and 65535.'
        )

    return port


def parse_endpoint_override(host, port):

    host_raw = '' if host is None else str(host).strip()
    port_raw = '' if port is None else str(port).strip()

    if not host_raw and not port_raw:
        return (None, None)

    if not host_raw or not port_raw:
        raise EndpointValidationError(
            'endpoint_partial',
            'Send host and port together, or send both empty to clear the override.',
        )

    return (_parse_endpoint_host(host_raw), _parse_endpoint_port(port_raw))


def parse_endpoint_string(value):

    text_value = (value or '').strip()
    if not text_value:
        return ''

    if text_value.startswith('['):
        match = re.fullmatch(r'\[([^\[\]]+)\]:([0-9]+)', text_value)
        if not match:
            raise EndpointValidationError('endpoint_invalid', 'Use [IPv6]:port.')
        host, port = match.groups()
        try:
            if ipaddress.ip_address(host).version != 6:
                raise ValueError
        except ValueError:
            raise EndpointValidationError('endpoint_host_invalid', 'Bracketed hosts must be valid IPv6 addresses.') from None
    else:
        host, port = _host_port(text_value)
    if not host or not port:
        raise EndpointValidationError(
            'endpoint_invalid',
            'The endpoint must be host:port, for example vpn.example.com:51820.',
        )

    host, port = parse_endpoint_override(host, port)
    return _norm_hostport(host, port)


def _host_port(ep: str):
    if not ep: return ('', None)
    s = ep.strip()
    if s.startswith('['):
        if ']' in s:
            host, rest = s[1:].split(']', 1)
            port = rest.lstrip(':') or None
            return (host, int(port) if port and port.isdigit() else None)
        return (s, None)
    if ':' in s:
        host, port = s.rsplit(':', 1)
        return (host, int(port) if port.isdigit() else None)
    return (s, None)
