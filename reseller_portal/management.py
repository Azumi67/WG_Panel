
import ipaddress
import math
from datetime import datetime, timedelta
from models import db, Peer, Subscription, InterfaceConfig
from .models import Ownership, UsagePoint
from . import service as s

FIELDS=('name','data_limit_value','data_limit_unit','time_limit_days','start_on_first_use','phone_number','telegram_id')
NETWORK=('allowed_ips','dns','mtu','persistent_keepalive','endpoint','peer_endpoint')

def checkbox_value(value, label):
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        value = value.strip().lower()
        if value in ('y', 'yes', 'on', 'true', '1'):
            return True
        if value in ('', 'n', 'no', 'off', 'false', '0'):
            return False
    raise ValueError('Invalid ' + label + ' option.')


def validate_options(account,data):
    data=data or {}
    def number(key,default,low,high):
        value=data.get(key,default)
        if value in (None,''):value=default
        try:n=float(value)
        except (ValueError,TypeError):raise ValueError(f'Invalid {key}.')
        if not math.isfinite(n) or not low<=n<=high:raise ValueError(f'{key} must be between {low} and {high}.')
        return n
    def integer(key,default,low,high):
        n=number(key,default,low,high)
        if n!=int(n):raise ValueError(f'{key} must be a whole number.')
        return int(n)
    def text(key,maximum,default=''):
        raw=data.get(key,default)
        v=str(default if raw is None else raw).strip()
        if len(v)>maximum or any(ord(c)<32 for c in v):raise ValueError(f'Invalid {key}.')
        return v
    name=text('name',48)
    if not name:raise ValueError('Enter a customer name.')
    unit=data.get('data_limit_unit','Gi')
    if unit not in ('Mi','Gi'):raise ValueError('Choose MiB or GiB.')
    limit=integer('data_limit_value',0,0,account.spec['traffic_gib']*(1024 if unit=='Mi' else 1))
    days=number('time_limit_days',0,0,3650)
    hours=integer('time_limit_hours',0,0,23)
    minutes=integer('time_limit_minutes',0,0,59)
    shared=checkbox_value(data.get('customer_unlimited',False),'shared allowance')
    if shared:
        if 'customer_unlimited' not in account.spec['permissions']:raise ValueError('Shared allowance is not permitted.')
        limit=0;days=0;hours=0;minutes=0
    if limit == 0:
        unit='Mi';limit=max(1,(int(account.spec['traffic_gib'])*s.GIB-account.used_bytes)//(1024**2))
    first=checkbox_value(data.get('start_on_first_use',False),'first-use')
    nets=text('allowed_ips',256,'0.0.0.0/0, ::/0')
    try:nets=', '.join(str(ipaddress.ip_network(x.strip(),strict=False)) for x in nets.split(','))
    except ValueError:raise ValueError('Allowed IPs must contain valid CIDR networks.')
    dns=text('dns',128)
    try:dns=', '.join(str(ipaddress.ip_address(x.strip())) for x in dns.split(',')) if dns else None
    except ValueError:raise ValueError('DNS must contain IP addresses separated by commas.')
    if 'network_options' not in account.spec['permissions'] and any(k in data for k in NETWORK):
        raise ValueError('Custom network settings are not permitted.')
    def endpoint(key):
        value=text(key,253)
        if not value:return None
        import re
        match=re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9.-]*):(\d{1,5})',value)
        if not match or not 1<=int(match[2])<=65535:raise ValueError('Endpoint must be a hostname or IP followed by a valid port.')
        if match[1].startswith('['):
            try:ipaddress.IPv6Address(match[1][1:-1])
            except ValueError:raise ValueError('Invalid IPv6 endpoint.')
        return value
    values=dict(endpoint=endpoint('endpoint'),peer_endpoint=endpoint('peer_endpoint'),name=name,data_limit_value=limit,data_limit_unit=unit,time_limit_days=days+hours/24+minutes/1440,
        start_on_first_use=first,phone_number=text('phone_number',32),telegram_id=text('telegram_id',64),
        note=text('note',256),allowed_ips=nets,dns=dns,mtu=integer('mtu',1420,576,9000),persistent_keepalive=integer('persistent_keepalive',25,0,65535))
    from .network_policy import apply
    return apply(account,data,values)

def apply_options(resource,values,account):
    for key in FIELDS:setattr(resource,key,values[key])
    resource.unlimited=False
    if isinstance(resource,Peer):
        for key in NETWORK:setattr(resource,key,values[key])
    else:resource.note=values['note']

    apply_timer(resource,account)


def apply_timer(resource,account):
    if resource.start_on_first_use:
        start=resource.first_used_at
    else:
        start=resource.timer_started_at or resource.created_at or s.now()
    resource.timer_started_at=start
    resource.expires_at=min(start+timedelta(days=resource.time_limit_days),account.expires_at) if start and resource.time_limit_days else (None if resource.time_limit_days else account.expires_at)

def extend_plan_capped_customers(account, previous_expiry):
    rows = Ownership.query.filter_by(account_id=account.id, deleted=False)
    peers = Peer.query.filter(Peer.id.in_(rows.with_entities(Ownership.peer_id)))
    subscriptions = Subscription.query.filter(Subscription.id.in_(rows.with_entities(Ownership.subscription_id)))
    for query in (peers, subscriptions):
        for resource in query.filter_by(expires_at=previous_expiry):
            start = resource.first_used_at if resource.start_on_first_use else (resource.timer_started_at or resource.created_at)
            if resource.time_limit_days:
                if start is None:
                    continue
                own_expiry = start + timedelta(days=resource.time_limit_days)
                resource.expires_at = min(own_expiry, account.expires_at)
            else:
                resource.expires_at = account.expires_at


def own_subscription(account,sid):
    rows=Ownership.query.filter_by(subscription_id=sid,deleted=False).all()
    if not rows or any(r.account_id!=account.id for r in rows):raise ValueError('Subscription not found.')
    sub=db.session.get(Subscription,sid)
    if not sub:raise ValueError('Subscription not found.')

    owned={r.peer_id for r in rows}
    if any(link.peer_id not in owned for link in sub.links):raise ValueError('Subscription requires administrator review.')
    return sub,[db.session.get(Peer,r.peer_id) for r in rows if db.session.get(Peer,r.peer_id)]

def usage(resource):
    if isinstance(resource,Peer):return int(resource.used_bytes_total or 0)
    return sum(int(link.peer.used_bytes_total or 0) for link in resource.links if link.peer)

def reason(resource,account):
    if not s.active(account):return 'Plan unavailable'
    if resource.expires_at and resource.expires_at<=s.now():return 'Expired'
    limit=resource.limit_bytes()
    if limit is not None and usage(resource)>=limit:return 'Data exhausted'
    if isinstance(resource,Subscription) and not resource.enabled:return 'Paused'
    return None

def child_allowed(peer,account):
    if reason(peer,account):return False
    row=Ownership.query.filter_by(peer_id=peer.id,account_id=account.id,deleted=False).first()
    if row and row.subscription_id:
        try:sub,_=own_subscription(account,row.subscription_id)
        except ValueError:return False
        return reason(sub,account) is None
    return True

def enforce_children(account,host,rows=None):
    healthy=True
    if rows is None:
        rows = (db.session.query(Ownership, Peer).join(Peer, Peer.id == Ownership.peer_id)
                .filter(Ownership.account_id == account.id, Ownership.deleted.is_(False)).all())
    checked_subscriptions = {}
    for row, peer in rows:
        resource = db.session.get(Subscription, row.subscription_id) if row.subscription_id else peer
        if not resource:
            continue
        if resource.start_on_first_use and not resource.first_used_at and usage(resource)>0:
            resource.first_used_at=s.now();resource.timer_started_at=resource.first_used_at
            if resource.time_limit_days:resource.expires_at=min(resource.first_used_at+timedelta(days=resource.time_limit_days),account.expires_at)
        if peer.status != 'online':
            continue
        denied = bool(reason(peer, account))
        if not denied and row.subscription_id:
            if resource.id not in checked_subscriptions:
                try:
                    own_subscription(account, resource.id)
                    checked_subscriptions[resource.id] = bool(reason(resource, account))
                except ValueError:
                    checked_subscriptions[resource.id] = True
            denied = checked_subscriptions[resource.id]
        if denied and not host['_disable_peer'](peer,'reseller_customer_limit'):
            healthy=False
            s.put('enforcement_error',f'Unable to disable peer {peer.id}; retrying.')
    return healthy

def record_usage(account,cleanup=True):
    last=UsagePoint.query.filter_by(account_id=account.id).order_by(UsagePoint.id.desc()).first()
    if not last or (s.now()-last.at).total_seconds()>=15:
        db.session.add(UsagePoint(account_id=account.id,generation=account.generation,used_bytes=account.used_bytes))
    if cleanup:UsagePoint.query.filter(UsagePoint.account_id==account.id,UsagePoint.at<s.now()-timedelta(days=1)).delete(synchronize_session=False)

def target(account,kind,rid):
    if kind=='peers':
        row,p=s.own_peer(account,rid)
        if row.subscription_id:raise ValueError('Manage this peer through its subscription.')
        return p,[p]
    if kind=='subscriptions':return own_subscription(account,rid)
    raise ValueError('Unknown resource type.')

def renew_exhausted_customer(account,resource,peers,host):
    resources=[resource]+[p for p in peers if p is not resource]
    expired=[obj for obj in resources if obj.expires_at and obj.expires_at<=s.now()]
    exhausted=[obj for obj in resources if obj.limit_bytes() is not None and usage(obj)>=obj.limit_bytes()]
    grants=account.spec.get('permissions',[])
    if expired and 'reset_timer' not in grants:
        raise ValueError('Customer expired. Ask the administrator to allow timer resets or extend the customer duration.')
    if exhausted and 'reset_data' not in grants:
        raise ValueError('Customer data exhausted. Ask the administrator to allow data resets or increase the customer allowance.')
    if not expired and not exhausted:return

    db.session.commit()
    reset_peers=peers if resource in exhausted else [p for p in peers if p in exhausted]
    baselines=[]
    for p in reset_peers:
        row,_=s.own_peer(account,p.id)
        if p.iface.node_id:
            result=host['node_post'](p.iface.node,'/api/peer/'+p.public_key+'/reset_data',{},timeout=12)
            if not isinstance(result,dict) or result.get('ok') is not True:
                raise ValueError('Node could not confirm the customer data reset.')
            current=result.get('total_bytes')
            if current is None and 'rx_bytes' in result and 'tx_bytes' in result:
                current=int(result['rx_bytes'])+int(result['tx_bytes'])
        else:
            reader=host.get('_wg_transfer')
            current=reader(p) if callable(reader) else None
        if current is None:raise ValueError('Current customer usage is unavailable; activation stopped.')
        baselines.append((p,row,max(0,int(current))))
    for p,row,current in baselines:
        p.bytes_offset=current;p.used_bytes_total=0;row.observed_bytes=0
    for obj in expired:
        obj.first_used_at=None
        obj.timer_started_at=None if obj.start_on_first_use else s.now()
        obj.expires_at=(min(obj.timer_started_at+timedelta(days=obj.time_limit_days),account.expires_at)
            if obj.time_limit_days and obj.timer_started_at else None if obj.time_limit_days else account.expires_at)
    s.audit('reseller:'+str(account.id),'renew_customer_limits',
            f'{type(resource).__name__}:{resource.id}; data={bool(exhausted)}; timer={bool(expired)}')


def change(account,kind,rid,action,data,host,*,fields=None):
    resource,peers=target(account,kind,rid)
    if action=='delete':
        s.remove_many(account,[p.id for p in peers],host)
        if kind=='subscriptions' and not peers:db.session.delete(resource)
        return
    if action=='disable':
        if isinstance(resource,Subscription):resource.enabled=False
        for p in peers:
            row,_=s.own_peer(account,p.id)
            if not host['_disable_peer'](p,'reseller_manual_pause'):raise ValueError('Could not pause the configuration; retry.')
            row.blocked=False
        s.audit('reseller:'+str(account.id),action,kind+':'+str(rid))
        return
    s.require_active(account)
    if not s.sample(account,host):raise ValueError('Usage is unavailable. Try again after connectivity recovers.')
    s.require_active(account)
    if action=='edit':
        if isinstance(resource,Peer):
            from .network_policy import normalize_inherited_endpoint
            data=normalize_inherited_endpoint(account,resource.iface,data,host)
        values=validate_options(account,data)
        if resource.timer_started_at and values['start_on_first_use']!=resource.start_on_first_use:
            raise ValueError('This timer has started. Keep its start mode and adjust the duration instead.')


        if 'network_options' not in account.spec['permissions'] and isinstance(resource,Peer):
            values.update({k:getattr(resource,k) for k in NETWORK})
        from .network_policy import apply
        values=apply(account,data,values)
        from .network_policy import enforce_endpoint
        if isinstance(resource,Peer):values=enforce_endpoint(account,resource.iface,values,host,submitted=data)
        if fields is None:
            apply_options(resource,values,account)
        else:
            for key in fields:setattr(resource,key,values[key])
            if {'data_limit_value','time_limit_days'} & set(fields):resource.unlimited=False
            if {'time_limit_days','start_on_first_use'} & set(fields):apply_timer(resource,account)
        if fields is None or {'data_limit_value','time_limit_days','start_on_first_use'} & set(fields):
            enforce_children(account,host)
        if isinstance(resource,Peer) and resource.status=='online' and 'network_options' in account.spec['permissions'] and (fields is None or set(NETWORK).intersection(fields)):
            host['reapply_peer_external'](resource)
        if isinstance(resource,Subscription) and data.get('sync_existing'):
            if 'network_options' not in account.spec['permissions']:raise ValueError('Network changes are not permitted.')
            for p in peers:
                assigned=enforce_endpoint(account,p.iface,values,host,submitted=data)
                for key in NETWORK:setattr(p,key,assigned[key])
                if p.status=='online':host['reapply_peer_external'](p)
    elif action in ('enable','disable'):
        if action=='enable':renew_exhausted_customer(account,resource,peers,host)
        if action=='enable' and reason(resource,account) not in (None,'Paused'):raise ValueError('Customer limits do not permit activation.')
        if isinstance(resource,Subscription):resource.enabled=action=='enable'
        for p in peers:
            row,_=s.own_peer(account,p.id)
            if action=='disable':
                if not host['_disable_peer'](p,'reseller_manual_pause'):raise ValueError('Could not pause the configuration; retry.')
                row.blocked=False
            else:
                if not child_allowed(p,account):raise ValueError('Customer limits do not permit activation.')
                activate=host.get('activate_reseller_peer',host.get('reapply_peer_external'))
                if not callable(activate):raise ValueError('Peer activation is unavailable.')
                activate(p);p.status='online';row.blocked=False
                s.put('recovery_pending:'+str(p.id),False)
    elif action=='rotate' and kind=='subscriptions':
        import secrets
        resource.token=secrets.token_urlsafe(32)
    else:raise ValueError('Unknown action.')
    s.audit('reseller:'+str(account.id),action,kind+':'+str(rid))


def requested_address(iface,value):
    try:
        network=ipaddress.ip_interface(iface.address)
        candidate=ipaddress.ip_interface(str(value)) if '/' in str(value) else ipaddress.ip_interface(str(value)+'/32')
    except ValueError:raise ValueError('Enter a valid client address.')
    if candidate.ip not in network.network or candidate.ip in (network.ip,network.network.network_address,network.network.broadcast_address):
        raise ValueError('Choose a free client address in the selected interface.')
    return str(candidate.ip)+'/'+str(network.network.prefixlen)


def attach_existing(account,ids,data,host):
    from models import SubscriptionPeer
    import secrets
    s.require_active(account)
    if not s.setting('monitor_heartbeat') or (s.now()-datetime.fromisoformat(s.setting('monitor_heartbeat'))).total_seconds()>120:raise ValueError('Usage monitor is offline.')
    if not s.sample(account,host):raise ValueError('Current usage is unavailable.')
    s.require_active(account)
    if not isinstance(ids,list) or not 1<=len(ids)<=50 or any(type(i)!=int for i in ids) or len(set(ids))!=len(ids):raise ValueError('Select 1–50 owned standalone peers.')
    from .limits import batch,effective
    batch(account,len(ids))
    if not s.throttle('resource_create:'+str(account.id),effective(account.spec)['create_per_minute'],60):raise ValueError('Too many creation requests. Wait one minute and retry.')
    if s.counts(account)[1]>=account.spec['subscriptions']:raise ValueError('Subscription limit reached.')
    peers=[]
    for pid in ids:
        row,p=s.own_peer(account,pid)
        if row.subscription_id or SubscriptionPeer.query.filter_by(peer_id=pid).first():raise ValueError('A selected peer is already in a subscription.')
        if p.iface_id not in account.spec['interfaces']:raise ValueError('Interface is not permitted.')
        peers.append((row,p))
    values=validate_options(account,data)
    sub=Subscription(name=values['name'],token=secrets.token_urlsafe(32),enabled=True)
    apply_options(sub,values,account);db.session.add(sub);db.session.flush()
    for row,p in peers:
        row.subscription_id=sub.id
        db.session.add(SubscriptionPeer(subscription_id=sub.id,peer_id=p.id,owned=True))

        p.unlimited=False;p.data_limit_value=0;p.time_limit_days=0;p.expires_at=account.expires_at;p.start_on_first_use=False
    db.session.flush();enforce_children(account,host)
    s.audit('reseller:'+str(account.id),'attached_subscription',str(sub.id))
    return sub.id


def reset_customer(acc,section,rid,action,host):
    if action not in ('reset_data','reset_timer') or action not in acc.spec['permissions']:raise ValueError('Permission changed.')
    resource,peers=target(acc,section,rid)
    s.require_active(acc)
    if not s.sample(acc,host):raise ValueError('Current usage is unavailable; counters were not reset.')
    s.require_active(acc)

    db.session.commit()
    if action=='reset_data':
        for p in peers:
            row,_=s.own_peer(acc,p.id)
            if p.iface.node_id:
                result=host['node_post'](p.iface.node,'/api/peer/'+p.public_key+'/reset_data',{},timeout=12)
                if not isinstance(result,dict) or result.get('ok') is False:raise ValueError('Node could not confirm data reset.')
                current=result.get('total_bytes')
                if current is None:current=int(result.get('rx_bytes',0))+int(result.get('tx_bytes',0))
            else:current=host['_wg_transfer'](p)
            if current is None:raise ValueError('Runtime usage is unavailable; reset was stopped.')
            p.bytes_offset=max(0,int(current));p.used_bytes_total=0;row.observed_bytes=0
            db.session.commit()
    else:
        from datetime import timedelta
        resource.first_used_at=None
        resource.timer_started_at=None if resource.start_on_first_use else s.now()
        resource.expires_at=(min(s.now()+timedelta(days=resource.time_limit_days),acc.expires_at) if resource.time_limit_days and not resource.start_on_first_use else None if resource.time_limit_days else acc.expires_at)
    enforce_children(acc,host)
    s.audit('reseller:'+str(acc.id),action,section+':'+str(rid))


def execute_customer_actions(account, section, action, ids, options, host, *, fields=None):
    ids = list(ids)
    if not ids or len(set(ids)) != len(ids):
        raise ValueError('Select unique customer IDs.')
    if len(ids) > 1:
        from .limits import batch
        batch(account, len(ids))
    
    for rid in ids:
        target(account, section, rid)
    for rid in ids:
        if action in ('reset_data', 'reset_timer'):
            reset_customer(account, section, rid, action, host)
        else:
            change(account, section, rid, action, options, host, fields=fields)
    return dict(section=section, ids=ids)
