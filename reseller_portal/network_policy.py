
import ipaddress
import re
from . import service as s


def get(account):
    return s.setting('network_policy:'+str(account.id),{}) or {}


def validate(data):
    host=str(data.get('server_host','')).strip().strip('[]')
    port=str(data.get('server_port','')).strip()
    endpoint=''
    if host or port:
        try:
            ip=ipaddress.ip_address(host)
            host='['+str(ip)+']' if ip.version==6 else str(ip)
        except ValueError:
            if len(host)>253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',host) or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
                raise ValueError('Enter a server IP or hostname without a URL scheme or path.')
        if not port.isdigit() or not 1<=int(port)<=65535:raise ValueError('Server port must be between 1 and 65535.')
        endpoint=f'{host}:{int(port)}'
    routes=[]
    for value in re.split(r'[\s,]+',str(data.get('internal_routes','')).strip()):
        if not value:continue
        try:route=str(ipaddress.ip_network(value,strict=False))
        except ValueError:raise ValueError('Internal networks must use valid CIDR notation.')
        if route not in routes:routes.append(route)
    if len(routes)>32:raise ValueError('Use at most 32 internal networks.')
    return dict(endpoint=endpoint,allow_endpoint=data.get('allow_endpoint')=='on',allow_internal=data.get('allow_internal')=='on',allow_fixed=data.get('allow_fixed')=='on',internal_routes=routes)


def apply(account,data,values):
    policy=get(account)
    if not policy:return values
    endpoint=policy.get('endpoint') or None
    if endpoint or not policy.get('allow_endpoint'):
        if data.get('endpoint') and data['endpoint']!=endpoint:raise ValueError('The server endpoint is assigned by the administrator.')
        values['endpoint']=endpoint
    elif not values.get('endpoint'):values['endpoint']=endpoint
    if values.get('peer_endpoint') and not policy.get('allow_fixed'):raise ValueError('Fixed client endpoints are not permitted for this reseller.')
    if data.get('include_internal_network') in (True,1,'1','true','on'):
        if not policy.get('allow_internal') or 'network_options' not in account.spec['permissions']:raise ValueError('Internal network presets are not permitted.')
        values['allowed_ips']=', '.join(dict.fromkeys([v.strip() for v in values['allowed_ips'].split(',')]+policy.get('internal_routes',[])))
    return values


def assigned_endpoint(account,iface,host):
    endpoint=get(account).get('endpoint')
    if endpoint:return endpoint
    endpoint=host.get('iface_endpoint_override',lambda i:None)(iface)
    if endpoint:return endpoint
    settings=host.get('_load_panel_settings',lambda:{})()
    if not iface.node_id and settings.get('tls_enabled') and settings.get('domain'):
        return host.get('_norm_hostport',lambda h,p:f'{h}:{p}')(settings['domain'],iface.listen_port)
    return None


def normalize_inherited_endpoint(account, iface, data, host):


    if not isinstance(data, dict) or not data.get('endpoint'):
        return data
    policy = get(account)
    if policy.get('endpoint') or policy.get('allow_endpoint', False):
        return data
    assigned = assigned_endpoint(account, iface, host)
    if assigned and str(data['endpoint']).strip() == assigned:
        return {**data, 'endpoint': ''}
    return data


def enforce_endpoint(account,iface,values,host,submitted=None):
    endpoint=assigned_endpoint(account,iface,host)
    if endpoint:
        explicit=values if submitted is None else submitted
        if explicit.get('endpoint') and explicit['endpoint']!=endpoint:raise ValueError('The server host and port are assigned by the administrator.')
        values={**values,'endpoint':endpoint}
    return values
