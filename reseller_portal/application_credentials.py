import hmac
import re
import secrets
from datetime import datetime, timezone
from panel_core.application_limits import parse_limits, permits

MAX_KEYS = 16
ROLE_SCOPES = {'admin': ('reviews','payment_decisions','messages'),
               'shop': ('plans','orders_read','orders_create','receipts','messages')}
ID_PATTERN = r'[a-f0-9]{10}'


def registry_key(role, aid):
    return f'app_named:{role}:{aid}'


def registry(store, role, aid):
    rows = store.setting(registry_key(role, aid), {})
    return rows if isinstance(rows, dict) else {}


def credential(store, role, aid, kid):
    row = registry(store, role, aid).get(kid)
    return row if isinstance(row, dict) else None


def issue(store, role, aid, form, allowed, administrator):
    if role not in ('admin','shop','workspace') or (role!='workspace' and not administrator):
        raise ValueError('Application issuance not allowed.')
    rows = dict(registry(store, role, aid))
    if len(rows) >= MAX_KEYS:
        raise ValueError('Revoke an unused application before issuing another.')
    label = form.get('label', '').strip()
    if not 1 <= len(label) <= 64 or any(ord(c)<32 for c in label):
        raise ValueError('Enter an application name of 1–64 characters.')
    if any(row.get('label','').casefold()==label.casefold() for row in rows.values() if isinstance(row,dict)):
        raise ValueError('Choose a unique application name.')
    scopes = set(form.getlist('named_scopes'))
    if not scopes or not scopes <= set(allowed):
        raise ValueError('Select permitted application scopes.')
    limits = parse_limits(form.get('named_expires',''), form.get('named_networks',''))
    if not permits(limits,check_ip=False):
        raise ValueError('Expiration must be in the future.')
    rate = int(form.get('named_rate',60))
    if not 1 <= rate <= 120:
        raise ValueError('Choose a rate between 1 and 120 requests per minute.')
    kid = secrets.token_hex(5)
    while kid in rows:
        kid = secrets.token_hex(5)
    key = f'wgapp.{role}.{aid}.{kid}.'+secrets.token_urlsafe(32)
    rows[kid] = {'label':label,'scopes':sorted(scopes),'limits':limits,'rate':rate,
                 'digest':store.digest(key),'created_at':datetime.now(timezone.utc).isoformat()}
    store.put(registry_key(role,aid),rows)
    return key


def change(store, role, aid, kid, action):
    rows = dict(registry(store,role,aid))
    row = rows.get(kid)
    if not isinstance(row,dict):
        raise ValueError('Application not found.')
    key = None
    if action == 'named_revoke':
        del rows[kid]
    elif action == 'named_rotate':
        if not permits(row.get('limits'),check_ip=False):
            raise ValueError('Revoke and recreate the expired application.')
        key = f'wgapp.{role}.{aid}.{kid}.'+secrets.token_urlsafe(32)
        rows[kid] = {**row,'digest':store.digest(key)}
    else:
        raise ValueError('Unsupported application action.')
    store.put(registry_key(role,aid),rows)
    return key


def matches(row, digest, address=None, *, check_ip=True):
    return bool(isinstance(row,dict) and isinstance(row.get('digest'),str) and isinstance(digest,str)
                and hmac.compare_digest(row['digest'],digest)
                and isinstance(row.get('scopes'),list) and all(isinstance(x,str) for x in row['scopes'])
                and type(row.get('rate')) is int and 1<=row['rate']<=120
                and isinstance(row.get('limits'),dict) and permits(row['limits'],address,check_ip=check_ip))


def request_prefix(kid=None):
    return 'app:'+kid+':' if kid else 'app:'


def owns_request(request_key,kid=None):
    prefix=request_prefix(kid)
    return request_key.startswith(prefix) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,80}',request_key[len(prefix):]))


def role_scope(endpoint, method):
    return {'admin_reviews':'reviews','admin_decision':'payment_decisions','send_message':'messages',
            'shop_plans':'plans','shop_orders':'orders_read' if method in ('GET','HEAD') else 'orders_create',
            'shop_receipt':'receipts'}.get(endpoint.rsplit('.',1)[-1])


def metric_keys(role,aid,kid,now):
    base=f'app9:{role}:{aid}:{kid}:'
    return base+'minute',base+'day:'+datetime.fromtimestamp(now,timezone.utc).strftime('%Y%m%d'),base+'seen'
