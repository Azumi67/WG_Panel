
import ipaddress
import os


_FORWARD_HEADERS = ('HTTP_FORWARDED', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_PROTO',
                    'HTTP_X_FORWARDED_HOST', 'HTTP_X_FORWARDED_PORT', 'HTTP_X_FORWARDED_PREFIX',
                    'HTTP_X_FORWARDED_SSL', 'HTTP_X_URL_SCHEME', 'HTTP_CF_VISITOR',
                    'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP')


def networks_from_env(value=None):
    if value is None:
        value = os.getenv('WG_TRUSTED_PROXY_NETWORKS', '127.0.0.1/32,::1/128')
    result = []
    for item in value.split(','):
        if not item.strip():
            continue
        network = ipaddress.ip_network(item.strip(), strict=True)
        if network.prefixlen == 0:
            raise ValueError('A universal trusted proxy network is unsafe.')
        result.append(network)
    return tuple(result)


def _ip(value):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


class TrustedProxy:


    def __init__(self, app, networks=None):
        self.app = app
        self.networks = networks_from_env() if networks is None else tuple(networks)

    def trusted(self, address):
        return address is not None and any(address in n for n in self.networks)

    def __call__(self, environ, start_response):
        original = environ.get('REMOTE_ADDR')
        environ['werkzeug.proxy_fix.orig'] = {'REMOTE_ADDR': original,
                                              'wsgi.url_scheme': environ.get('wsgi.url_scheme')}
        direct = _ip(original)
        if self.trusted(direct):
            raw = environ.get('HTTP_X_FORWARDED_FOR', '')

            parts = raw.split(',') if raw and len(raw) <= 4096 else []
            if 0 < len(parts) <= 32:
                chain = [_ip(p.strip()) for p in parts]
                if all(ip is not None for ip in chain):
                    for address in reversed(chain):
                        environ['REMOTE_ADDR'] = str(address)
                        if not self.trusted(address):
                            break
            proto = environ.get('HTTP_X_FORWARDED_PROTO', '').strip().lower()
            if proto in ('http', 'https'):
                environ['wsgi.url_scheme'] = proto
        for name in _FORWARD_HEADERS:
            environ.pop(name, None)
        return self.app(environ, start_response)


def safe_path(path):

    for prefix in ('/api/u/', '/u/', '/s/', '/r/'):
        if path.startswith(prefix):
            return prefix + '[redacted]'
    return path
