
from models import db, Node, InterfaceConfig
from flask import g
from .models import Account, Ownership


def annotate_owners(peers):
    ids=[p['id'] for p in peers if isinstance(p,dict) and isinstance(p.get('id'),int)]
    owners={row.peer_id:account for row,account in db.session.query(Ownership,Account).join(Account,Account.id==Ownership.account_id).filter(Ownership.peer_id.in_(ids),Ownership.deleted.is_(False)).all()} if ids else {}
    for peer in peers:
        if not isinstance(peer,dict): continue
        account=owners.get(peer.get('id'))
        peer['reseller_owner']={'id':account.id,'username':account.username} if account else None


def cached_peer_snapshot(account_id):
    from datetime import datetime
    from . import service as s
    cache = g.setdefault('_rp_peer_state_snapshots', {})
    if account_id not in cache:
        snapshot = s.setting('peer_states:'+str(account_id), {}) or {}
        try:
            fresh = (s.now()-datetime.fromisoformat(snapshot['at'])).total_seconds() < 120
        except (KeyError, TypeError, ValueError):
            fresh = False
        cache[account_id] = snapshot.get('states', {}) if fresh else None
    return cache[account_id]


def peer_states(peers,host,live=True,runtime_cache=None,owner_account_id=None,local_snapshot=None):
    if not live:
        ids=[p.id for p in peers]


        owners=({pid:owner_account_id for pid in ids} if owner_account_id is not None
                else {o.peer_id:o.account_id for o in Ownership.query.filter(Ownership.peer_id.in_(ids),Ownership.deleted.is_(False)).all()}) if ids else {}
        cached={aid:cached_peer_snapshot(aid) or {} for aid in set(owners.values())}
        result={}
        for p in peers:
            state=cached.get(owners.get(p.id),{}).get(str(p.id))
            result[p.id]={**(state or {'connection':'unknown','rx':None,'tx':None}),'enabled':p.status=='online'}
        return result
    result={}
    local=[p for p in peers if p.iface and not p.iface.node_id]
    if local_snapshot is None and local:
        try:
            local_snapshot = host['_wg_runtime_snapshot']({p.iface.name for p in local})
        except Exception:
            local_snapshot = None
    transfers,handshakes = local_snapshot[:2] if local_snapshot is not None else ({}, {})
    node_cache={(nid,name.split(':',1)[-1]):(values or {}) for (nid,name),values in (runtime_cache or {}).items()}
    for p in peers:
        state={'connection':'unknown','enabled':p.status=='online','rx':None,'tx':None}
        iface=p.iface
        if iface and not iface.node_id:
            key=(iface.name,p.public_key)
            if key in handshakes:
                rx,tx=transfers.get(key,(0,0))
                try:
                    conn=host['_peer_conn_status'](p,live_total=rx+tx,latest_handshake=handshakes[key],allow_probe=False)
                    state.update(connection=conn['conn_status'],rx=rx,tx=tx)
                except Exception: pass
        elif iface:
            key=(iface.node_id,iface.name.split(':',1)[-1])
            if key not in node_cache:
                try:
                    from urllib.parse import quote
                    data=host['node_get'](db.session.get(Node,iface.node_id),'/api/peers?iface='+quote(key[1],safe=''),timeout=3)
                    node_cache[key]={row.get('public_key'):row for row in data.get('peers',[])}
                except Exception: node_cache[key]={}
            live=node_cache[key].get(p.public_key)
            if live:
                status=live.get('conn_status') or live.get('connection_status')
                if status in ('online','offline'):state['connection']=status
                try:state.update(rx=max(0,float(live.get('rx_mib',0)))*1048576,tx=max(0,float(live.get('tx_mib',0)))*1048576)
                except (ValueError,TypeError): pass
        result[p.id]=state
    return result


def inventory_access(peer,ownership,account):
    from . import service as s
    from models import Subscription
    from .management import usage
    resource=db.session.get(Subscription,ownership.subscription_id) if ownership.subscription_id else peer
    if account.state!='active':return {'label':'Account suspended','reason':'The reseller account is suspended.','tone':'stale'}
    if account.expires_at and account.expires_at<=s.now():return {'label':'Plan expired','reason':'Renew the reseller plan to restore eligibility.','tone':'stale'}
    if account.used_bytes>=int(account.spec['traffic_gib'])*s.GIB:return {'label':'Plan traffic used','reason':'The reseller traffic allowance is exhausted.','tone':'stale'}
    if resource and resource.expires_at and resource.expires_at<=s.now():return {'label':'Customer expired','reason':'This customer’s service period ended. WireGuard interface health is separate.','tone':'stale'}
    if resource and resource.limit_bytes() and usage(resource)>=resource.limit_bytes():return {'label':'Traffic limit','reason':'This customer’s traffic allowance is exhausted.','tone':'stale'}
    if ownership.blocked:return {'label':'Blocked by plan','reason':'Plan enforcement has disabled access; the monitor will recheck eligibility.','tone':'stale'}
    if peer.status!='online':return {'label':'Access disabled','reason':'Disabled in the panel. This is not the interface or connection status.','tone':'missing'}
    return {'label':'Access enabled','reason':'Enabled in the panel; this does not imply a live connection.','tone':'ready'}


def resource_mode(value):
    if value in ('admin', 'resellers', 'all'):
        return value
    return 'admin' if value is False else 'all'


def filter_owned_resources(items, mode):
    if mode == 'all':
        return items
    return [item for item in items if bool(item.get('reseller_owner')) == (mode == 'resellers')]


def annotate_subscription_owners(items):
    ids = [item['id'] for item in items if isinstance(item.get('id'), int)]
    owners = {}
    if ids:
        rows = (db.session.query(Ownership.subscription_id, Account.id, Account.username)
                .join(Account, Account.id == Ownership.account_id)
                .filter(Ownership.subscription_id.in_(ids), Ownership.deleted.is_(False))
                .distinct().order_by(Account.id).all())
        for sid, aid, username in rows:
            owners.setdefault(sid, {'id': aid, 'username': username})
    for item in items:
        item['reseller_owner'] = owners.get(item.get('id'))


def assignment_index(accounts):
    result = {}
    for aid, username, spec in accounts:
        interfaces = (spec or {}).get('interfaces', []) if isinstance(spec, dict) else []
        if not isinstance(interfaces, (list, tuple)):
            continue
        for iid in interfaces:
            try:
                iid = int(iid)
            except (TypeError, ValueError, OverflowError):
                continue
            if iid > 0:
                result.setdefault(iid, {})[aid] = {'id': aid, 'username': username}
    return {iid: sorted(owners.values(), key=lambda owner: (owner['username'].casefold(), owner['id']))
            for iid, owners in result.items()}


def annotate_interface_assignments(payload, endpoint, node_id=None):
    assignments = assignment_index(db.session.query(Account.id, Account.username, Account.spec).filter(Account.state != 'deleted').all())
    mirrors = {}
    if assignments and (node_id is not None or endpoint == 'api_subscriptions_locations'):
        rows = (db.session.query(InterfaceConfig.id, InterfaceConfig.node_id, InterfaceConfig.name)
                .filter(InterfaceConfig.id.in_(assignments)).all())
        for iid, nid, name in rows:
            prefix, sep, short = name.partition(':')
            if sep and prefix.startswith('n') and prefix[1:].isdigit():
                nid = int(prefix[1:])
                name = short
            if nid is not None:
                mirrors[(nid, name)] = iid
    def annotate(rows, nid=None):
        for item in rows:
            if nid is not None:
                iid = mirrors.get((nid, item.get('iface') or item.get('name')))
            else:
                iid = item.get('iface_id', item.get('id'))
                try:
                    iid = int(iid)
                except (TypeError, ValueError, OverflowError):
                    iid = None
            item['reseller_assignments'] = assignments.get(iid, [])
    if endpoint == 'api_subscriptions_locations':
        annotate(payload.get('local', []))
        for node in payload.get('nodes', []):
            annotate(node.get('interfaces', []), node.get('id'))
    else:
        annotate(payload.get('interfaces', []), node_id)
