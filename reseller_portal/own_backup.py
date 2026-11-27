
import json
from models import db, Peer, Subscription, SubscriptionPeer
from sqlalchemy.orm import joinedload
from .models import Ownership, CustomerProfile
from .limits import effective
from . import service as s

MAX_EXPORT_BYTES = 8 * 1024 * 1024

def own_backup_document(acc):
    rows = Ownership.query.filter_by(account_id=acc.id, deleted=False).order_by(Ownership.id).all()
    peer_ids = sorted({r.peer_id for r in rows if r.peer_id is not None})
    sub_ids = sorted({r.subscription_id for r in rows if r.subscription_id is not None})
    peers = {p.id:p for p in (Peer.query.options(joinedload(Peer.iface)).filter(Peer.id.in_(peer_ids)).all() if peer_ids else [])}
    subs = {p.id:p for p in (Subscription.query.filter(Subscription.id.in_(sub_ids)).all() if sub_ids else [])}

    foreign = {sid for sid, aid in db.session.query(Ownership.subscription_id, Ownership.account_id)
               .filter(Ownership.subscription_id.in_(sub_ids), Ownership.deleted.is_(False)).all()
               if aid != acc.id} if sub_ids else set()
    owned_by_sub = {(r.subscription_id,r.peer_id) for r in rows}
    foreign.update(sid for sid,pid in db.session.query(SubscriptionPeer.subscription_id,SubscriptionPeer.peer_id).filter(SubscriptionPeer.subscription_id.in_(sub_ids)).all() if (sid,pid) not in owned_by_sub)
    safe_subs = set(subs) - foreign
    peer_items = [dict(id=p.id, name=p.name, interface_id=p.iface_id,
                  interface_name=p.iface.name if p.iface else '', status=p.status,
                  used_bytes=int(row.observed_bytes or 0), subscription_id=row.subscription_id,
                  blocked=bool(row.blocked)) for row in rows
                  for p in [peers.get(row.peer_id)]
                  if p is not None and (not row.subscription_id or row.subscription_id in safe_subs)]
    by_sub = {}
    for r in rows:
        if r.subscription_id in safe_subs and r.peer_id in peers:
            by_sub.setdefault(r.subscription_id, []).append(r.peer_id)
    sub_items = [dict(id=subs[sid].id, name=subs[sid].name,
                 enabled=bool(subs[sid].enabled), peer_ids=by_sub.get(sid, []))
                 for sid in sorted(safe_subs)]
    profiles = CustomerProfile.query.filter_by(account_id=acc.id).order_by(CustomerProfile.id).all()
    document = dict(format='wg-panel-reseller-metadata', schema=1,
        purpose='Read-only account export. NOT a WireGuard or database restore file.',
        created_at=s.now().isoformat()+'Z',
        account=dict(id=acc.id, username=acc.username, state=acc.state,
                     expires_at=acc.expires_at.isoformat()+'Z' if acc.expires_at else None,
                     used_bytes=int(acc.used_bytes or 0), traffic_gib=acc.spec.get('traffic_gib'),
                     peer_limit=acc.spec.get('peers'), subscription_limit=acc.spec.get('subscriptions'),
                     operation_limits=effective(acc.spec)),
        peers=peer_items, subscriptions=sub_items,
        profiles=[dict(kind=x.kind,name=x.name,is_default=x.is_default) for x in profiles],
        excluded=['private keys','public portal tokens','password hashes','2FA secrets',
                  'recovery hashes','bot tokens','payment data','other resellers','server configuration'])
    binary=json.dumps(document, ensure_ascii=False, indent=2).encode('utf-8')
    if len(binary)>MAX_EXPORT_BYTES:
        raise ValueError('Backup too large for self-service export. Ask the administrator for a scoped export.')
    return (f'reseller-{acc.id}-metadata-{s.now().strftime("%Y%m%d")}.json', binary)


def settings_document(acc):
    from . import management as m
    rows=Ownership.query.filter_by(account_id=acc.id,deleted=False).all()
    items=[];seen=set()
    for row in rows:
        kind='subscriptions' if row.subscription_id else 'peers'
        rid=row.subscription_id or row.peer_id
        if (kind,rid) in seen:continue
        seen.add((kind,rid))
        resource,_=m.target(acc,kind,rid)
        values={key:getattr(resource,key,None) for key in m.FIELDS}
        if kind=='subscriptions':values['note']=resource.note or ''
        items.append({'kind':kind,'id':rid,'values':values})
    payload={'format':'wg-panel-customer-settings','schema':1,'account_id':acc.id,
             'created_at':s.now().isoformat()+'Z','items':items}
    from panel_core.backup_keys import seal
    binary=json.dumps({'format':'wg-panel-encrypted-customer-settings',**seal(json.dumps(payload),s.encrypt)}).encode()
    if len(binary)>MAX_EXPORT_BYTES:raise ValueError('Backup exceeds the self-service size limit.')
    return f'reseller-{acc.id}-customer-settings.json',binary

def prepare_restore(acc,binary):
    from . import management as m
    if not {'backup','restore'} <= set(acc.spec['permissions']):
        raise ValueError('Backup and restore permissions are required.')
    if not binary or len(binary)>MAX_EXPORT_BYTES:raise ValueError('Invalid backup size.')
    from .recovery_archive import unwrap_recovery
    binary = unwrap_recovery(binary)
    try:wrapper=json.loads(binary)
    except (ValueError,TypeError):raise ValueError('This file is not a valid JSON backup.') from None
    if not isinstance(wrapper,dict):raise ValueError('Invalid backup document.')
    if wrapper.get('format')=='wg-panel-reseller-metadata':
        raise ValueError('This is an inventory export, not a restorable backup. Use Download backup in the Backup tab.')
    if wrapper.get('format')=='wg-panel-encrypted-customer-recovery':
        from .customer_recovery import prepare
        return prepare(acc,wrapper)
    if wrapper.get('format')!='wg-panel-encrypted-customer-settings':
        raise ValueError('Choose a reseller customer-settings backup, not an administrator backup.')
    from panel_core.backup_keys import unseal
    try:payload=json.loads(unseal(wrapper,s.decrypt))
    except Exception:raise ValueError('Backup authentication failed. The file may be damaged or the panel encryption secret may have changed.') from None
    if not isinstance(payload,dict) or payload.get('format')!='wg-panel-customer-settings' or payload.get('schema')!=1:
        raise ValueError('Unsupported customer-settings backup version.')
    if payload.get('account_id')!=acc.id:raise ValueError('This backup belongs to a different reseller account.')
    items=payload.get('items')
    if not isinstance(items,list) or len(items)>10000:raise ValueError('Invalid customer list in backup.')
    s.require_active(acc)
    prepared=[];seen=set()
    for item in items:
        if not isinstance(item,dict):raise ValueError('Invalid customer settings entry.')
        kind=item.get('kind');rid=item.get('id')
        if kind not in ('peers','subscriptions') or kind not in acc.spec['permissions'] or type(rid) is not int or (kind,rid) in seen:
            raise ValueError('Backup contains unsupported or duplicate customers.')
        seen.add((kind,rid));resource,_=m.target(acc,kind,rid)
        saved=item.get('values')
        if not isinstance(saved,dict):raise ValueError('Invalid customer settings.')
        data={k:v for k,v in saved.items() if (k in m.FIELDS or k=='note') and v is not None}
        values=m.validate_options(acc,data)
        if resource.timer_started_at and values['start_on_first_use']!=resource.start_on_first_use:
            raise ValueError('A customer timer has started since this backup. Restore its settings manually.')
        if isinstance(resource,Peer):values.update({k:getattr(resource,k) for k in m.NETWORK})
        prepared.append((resource,values))
    return payload,prepared

def inspect_document(acc,binary):
    payload,prepared=prepare_restore(acc,binary)
    if payload.get('schema')==2:
        from .customer_recovery import inspection
        return inspection(payload,prepared)
    return {'ok':True,'created_at':payload.get('created_at'),'customers':len(prepared),
            'peers':sum(isinstance(resource,Peer) for resource,_ in prepared),
            'subscriptions':sum(isinstance(resource,Subscription) for resource,_ in prepared),
            'fields':['Names and contacts','Limits and timers','Subscription notes']}

def restore_document(acc,binary,host):
    from . import management as m
    payload,prepared=prepare_restore(acc,binary)
    if payload.get('schema')==2:
        from .customer_recovery import restore
        return restore(acc,payload,prepared,host)
    if not s.sample(acc,host):raise ValueError('Usage is unavailable. Try again when connectivity recovers.')
    s.require_active(acc)
    for resource,values in prepared:m.apply_options(resource,values,acc)
    m.enforce_children(acc,host)
    s.audit('reseller:'+str(acc.id),'restore_customer_settings',str(len(prepared))+' customers')
    return len(prepared)


def recovery_document(acc):
    from .customer_recovery import document
    from .recovery_archive import pack_recovery
    _, encrypted = document(acc)
    return pack_recovery(acc.id, encrypted)
