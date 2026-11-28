import base64
import hashlib
import ipaddress
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from models import db, Peer, Subscription, SubscriptionPeer, InterfaceConfig, ShortLink
from .models import Ownership, CustomerProfile, Setting
from . import service as s, management as m

DATES=('created_at','first_used_at','timer_started_at','expires_at')
PEER_FIELDS=m.FIELDS+m.NETWORK+('public_key','private_key','address','used_bytes_total','unlimited')
SUB_FIELDS=m.FIELDS+('token','note','enabled','unlimited')

def ledger_key(aid,key):
    return 'recovery:'+str(aid)+':'+hashlib.sha256(key.encode()).hexdigest()[:40]

def stamp(value):
    return value.isoformat() if value else None

def date(value):
    if value is None:return None
    try:
        result=datetime.fromisoformat(value)
        if result.tzinfo:raise ValueError()
        return result
    except (TypeError,ValueError):raise ValueError('Invalid backup timestamp.') from None

def record(obj,fields):
    return {**{k:getattr(obj,k,None) for k in fields},**{k:stamp(getattr(obj,k,None)) for k in DATES}}

def interface(iface):
    return dict(id=iface.id,name=iface.name,node_id=iface.node_id,address=iface.address,public_key=iface.public_key)

def saved_profile(profile,acc):
    options=json.loads(json.dumps(profile.options))
    if profile.kind=='subscription':
        for desc in options.get('interfaces',[]):
            if desc.get('peer_id'):
                _,peer=s.own_peer(acc,int(desc.pop('peer_id')))
                desc['_recovery_peer_key']=peer.public_key
    return dict(kind=profile.kind,name=profile.name,options=options,is_default=profile.is_default)

def document(acc):
    from .own_backup import MAX_EXPORT_BYTES
    from .shared import design_key
    rows=Ownership.query.filter_by(account_id=acc.id,deleted=False).all()


    if len(rows)>4:
        from sqlalchemy.orm import joinedload, selectinload
        peer_ids={r.peer_id for r in rows if r.peer_id is not None}
        sub_ids={r.subscription_id for r in rows if r.subscription_id is not None}
        if peer_ids:
            (Peer.query.options(joinedload(Peer.iface),selectinload(Peer.short_links))
             .filter(Peer.id.in_(peer_ids)).all())
        if sub_ids:
            (Subscription.query.options(selectinload(Subscription.links))
             .filter(Subscription.id.in_(sub_ids)).all())
    items=[];seen=set()
    for row in rows:
        kind='subscriptions' if row.subscription_id else 'peers'
        rid=row.subscription_id or row.peer_id
        if (kind,rid) in seen:continue
        seen.add((kind,rid));resource,children=m.target(acc,kind,rid)
        peers=children if kind=='subscriptions' else [resource]
        values={k:getattr(resource,k,None) for k in m.FIELDS}
        if kind=='subscriptions':values['note']=resource.note
        entry=dict(kind=kind,id=rid,values=values,resource=record(resource,SUB_FIELDS if kind=='subscriptions' else PEER_FIELDS),peers=[])
        for peer in peers:
            link=next((x for x in resource.links if x.peer_id==peer.id),None) if kind=='subscriptions' else None
            entry['peers'].append(dict(data=record(peer,PEER_FIELDS),interface=interface(peer.iface),short_links=[dict(token=x.token,created_at=stamp(x.created_at)) for x in peer.short_links],link={k:getattr(link,k) for k in ('location_label','country_code','flag','sort_order')} if link else None))
        if kind=='subscriptions':entry['design']=s.setting(design_key(acc.id,'subscription',rid))
        items.append(entry)
    payload=dict(format='wg-panel-customer-recovery',schema=2,account_id=acc.id,account_created=stamp(acc.created_at),created_at=stamp(s.now()),items=items,
        profiles=[saved_profile(p,acc) for p in CustomerProfile.query.filter_by(account_id=acc.id).all()] if 'profiles' in acc.spec['permissions'] else [],
        designs={k:s.setting(design_key(acc.id,k)) for k,perm in (('peer','peer_template'),('subscription','portal_design')) if perm in acc.spec['permissions']})
    from panel_core.backup_keys import seal
    binary=json.dumps(dict(format='wg-panel-encrypted-customer-recovery',**seal(json.dumps(payload),s.encrypt))).encode()
    if len(binary)>MAX_EXPORT_BYTES:raise ValueError('Backup exceeds the self-service size limit.')
    return f'reseller-{acc.id}-customer-recovery.json',binary

def key_pair(data):
    try:
        private=base64.b64decode(data['private_key'],validate=True)
        public=base64.b64decode(data['public_key'],validate=True)
        derived=X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        if public!=derived:raise ValueError()
    except (ValueError,TypeError,KeyError):raise ValueError('A saved WireGuard key pair is invalid. Ask the administrator to review this customer.') from None

def prepare(acc,wrapper):
    from panel_core.backup_keys import unseal
    try:payload=json.loads(unseal(wrapper,s.decrypt))
    except Exception:raise ValueError('Backup authentication failed. Check that this file came from the same panel and its encryption secret has not changed.') from None
    if not isinstance(payload,dict) or payload.get('format')!='wg-panel-customer-recovery' or payload.get('schema')!=2:raise ValueError('Unsupported recovery backup.')
    if payload.get('account_id')!=acc.id or payload.get('account_created')!=stamp(acc.created_at):raise ValueError('This backup belongs to a different reseller account.')
    s.require_active(acc)
    items=payload.get('items')
    if not isinstance(items,list) or len(items)>10000:raise ValueError('Invalid recovery customer list.')
    grants=set(acc.spec['permissions']);prepared=[];seen=set();keys=set();addresses=set();link_tokens=set();added_peers=0;added_subs=0
    for item in items:
        if not isinstance(item,dict):raise ValueError('Invalid recovery entry.')
        kind=item.get('kind');rid=item.get('id');saved=item.get('resource');entries=item.get('peers')
        if kind not in ('peers','subscriptions') or kind not in grants or type(rid) is not int or (kind,rid) in seen:raise ValueError('Unsupported or duplicate recovery customer.')
        seen.add((kind,rid))
        if not isinstance(saved,dict) or not isinstance(entries,list) or not entries or len(entries)>10000 or (kind=='peers' and len(entries)!=1):raise ValueError('Incomplete recovery customer.')
        if not isinstance(item.get('values'),dict):raise ValueError('Invalid customer settings.')
        values=m.validate_options(acc,{k:v for k,v in item['values'].items() if v is not None and k in m.FIELDS+('note',)})
        obj=None
        if kind=='subscriptions':
            if not isinstance(saved.get('token'),str) or not 1<=len(saved['token'])<=128:raise ValueError('Invalid subscription identity.')
            obj=Subscription.query.filter_by(token=saved.get('token')).first()
            if obj:m.own_subscription(acc,obj.id)
            else:added_subs+=1
        existing=[]
        for entry in entries:
            if not isinstance(entry,dict) or not isinstance(entry.get('data'),dict) or not isinstance(entry.get('interface'),dict):raise ValueError('Invalid recovery peer entry.')
            data=entry['data'];identity=entry['interface']
            if type(identity.get('id')) is not int:raise ValueError('Invalid interface identity.')
            if not isinstance(entry.get('short_links',[]),list) or any(not isinstance(x,dict) for x in entry.get('short_links',[])):raise ValueError('Invalid customer links.')
            key=data.get('public_key')
            if not isinstance(key,str) or key in keys:raise ValueError('Duplicate or invalid peer identity.')
            keys.add(key)
            iface=db.session.get(InterfaceConfig,identity.get('id'))
            if not iface or iface.id not in acc.spec['interfaces'] or identity!=interface(iface):raise ValueError('An original interface changed or is no longer permitted. Ask the administrator to map this backup.')
            matches=Peer.query.filter_by(public_key=key).all()
            if len(matches)>1:raise ValueError('Peer key conflict. Ask the administrator to review it.')
            peer=matches[0] if matches else None
            if peer:
                owner,_=s.own_peer(acc,peer.id)
                if peer.iface_id!=iface.id or (kind=='peers' and owner.subscription_id) or (kind=='subscriptions' and (not obj or owner.subscription_id!=obj.id)):raise ValueError('Customer ownership or subscription membership has changed.')
                if kind=='peers':obj=peer
            else:
                key_pair(data)
                try:
                    address=ipaddress.ip_interface(data['address']);network=ipaddress.ip_interface(iface.address)
                    if address.ip not in network.network or address.ip==network.ip:raise ValueError()
                    host=str(address.ip)
                except (ValueError,KeyError,TypeError):raise ValueError('A saved address no longer fits its interface.') from None
                address_key=(iface.id,host)
                if address_key in addresses:raise ValueError('Duplicate address in recovery file.')
                addresses.add(address_key)
                for occupied in Peer.query.filter_by(iface_id=iface.id).all():
                    if str(ipaddress.ip_interface(occupied.address).ip)==host:raise ValueError('A saved address is now in use. No customers have been restored.')
                data=dict(data)
                network_data={k:v for k,v in data.items() if k in m.NETWORK and v is not None}
                from . import HOST
                from .network_policy import assigned_endpoint
                endpoint=assigned_endpoint(acc,iface,HOST)
                if endpoint:network_data['endpoint']=endpoint
                if 'network_options' not in grants:
                    defaults=m.validate_options(acc,{'name':data['name']})
                    if any(v!=defaults[k] for k,v in network_data.items()):raise ValueError('Restoring custom network settings requires network-options permission.')
                    network_data={}
                checked=m.validate_options(acc,{**{k:v for k,v in data.items() if k in m.FIELDS and v is not None},**network_data})
                for k in m.NETWORK:data[k]=checked[k]
                for k in DATES:date(data.get(k))
                entry={**entry,'data':data,'host':host}
                added_peers+=1
            for short in entry.get('short_links',[]):
                token=short.get('token')
                if not isinstance(token,str) or not 1<=len(token)<=96 or token in link_tokens:raise ValueError('Invalid or duplicate customer link.')
                link_tokens.add(token);found=ShortLink.query.filter_by(token=token).first()
                if found and (not peer or found.peer_id!=peer.id):raise ValueError('A customer link is now assigned to another peer.')
                date(short.get('created_at'))
            existing.append((entry,peer))
        if obj and obj.timer_started_at and values['start_on_first_use']!=obj.start_on_first_use:raise ValueError('A customer timer has started. Restore its settings manually.')
        prepared.append((item,obj,values,existing))
    pc,sc=s.counts(acc)
    if pc+added_peers>acc.spec['peers'] or sc+added_subs>acc.spec['subscriptions']:raise ValueError('Recovery would exceed the current plan customer limits.')
    profiles=payload.get('profiles',[]);designs=payload.get('designs',{})
    if not isinstance(profiles,list) or not isinstance(designs,dict):raise ValueError('Invalid saved profiles or designs.')
    for profile in profiles:
        if not isinstance(profile,dict) or profile.get('kind') not in ('peer','subscription') or not isinstance(profile.get('name'),str) or not 1<=len(profile['name'])<=64 or not isinstance(profile.get('options'),dict):raise ValueError('Invalid saved customer profile.')
        if 'profiles' in grants and profile['kind']=='peer':m.validate_options(acc,{**profile['options'],'name':'Profile'})
        if 'profiles' in grants and profile['kind']=='subscription':
            for desc in profile['options'].get('interfaces',[]):
                if desc.get('_recovery_peer_key') and desc['_recovery_peer_key'] not in keys:raise ValueError('A saved profile refers to a customer missing from this backup.')
    if 'profiles' in grants:
        from .limits import effective
        existing_profiles={(p.kind,p.name) for p in CustomerProfile.query.filter_by(account_id=acc.id).all()}
        if len(existing_profiles|{(p['kind'],p['name']) for p in profiles})>effective(acc.spec)['profile_limit']:raise ValueError('Recovery would exceed the saved profile limit.')
    return payload,prepared

def inspection(payload,prepared):
    peers=sum(len(entries) for _,_,_,entries in prepared)
    missing=sum(peer is None for _,_,_,entries in prepared for _,peer in entries)
    return dict(ok=True,created_at=payload['created_at'],customers=len(prepared),peers=peers,
        subscriptions=sum(item['kind']=='subscriptions' for item,_,_,_ in prepared),recreated_peers=missing,
        profiles=len(payload.get('profiles',[])),mode='customer-recovery',
        fields=['Peer keys and configurations','Subscriptions and portal links','Contacts and limits','Profiles and designs'],
        notice='Deleted customers return paused. Enable them after recovery to install their configuration locally or on their node. Existing access states and consumed traffic remain unchanged.')

def lifecycle(obj,saved,acc,ledger=None):
    ledger=ledger or {}
    for key in DATES:
        candidates=[date(x.get(key)) for x in (saved,ledger) if x.get(key)]
        if key=='expires_at':candidates.append(acc.expires_at)
        setattr(obj,key,min(candidates) if candidates else None)
    if not obj.created_at:obj.created_at=s.now()

def restore(acc,payload,prepared,host):
    from .shared import design_key
    current_ids=[p.id for _,_,_,entries in prepared for _,p in entries if p]
    if current_ids and not s.sample(acc,host,peer_ids=current_ids):raise ValueError('Current customer usage is unavailable. Retry when connectivity recovers.')
    s.require_active(acc)
    for item,obj,values,entries in prepared:
        kind=item['kind'];saved=item['resource']
        if obj:
            expiry=obj.expires_at;timer=obj.timer_started_at;first=obj.first_used_at
            if isinstance(obj,Peer):
                from .network_policy import enforce_endpoint
                values.update({k:getattr(obj,k) for k in m.NETWORK})
                values=enforce_endpoint(acc,obj.iface,values,host,submitted={})
            m.apply_options(obj,values,acc)
            obj.expires_at=min(x for x in (expiry,obj.expires_at,acc.expires_at) if x)
            obj.timer_started_at=timer;obj.first_used_at=first
        elif kind=='subscriptions':
            obj=Subscription(token=saved['token'],enabled=False)
            m.apply_options(obj,values,acc)
            lifecycle(obj,saved,acc,s.setting(ledger_key(acc.id,saved['token'])))
            db.session.add(obj);db.session.flush()
        for entry,peer in entries:
            if peer:continue
            data=entry['data'];ledger=s.setting(ledger_key(acc.id,data['public_key']),{})
            from .network_policy import enforce_endpoint
            data=enforce_endpoint(acc,db.session.get(InterfaceConfig,entry['interface']['id']),data,host,submitted={})
            peer=Peer(**{k:data.get(k) for k in PEER_FIELDS if k!='used_bytes_total'},iface_id=entry['interface']['id'],address_host=entry['host'],status='offline',bytes_offset=0)
            lifecycle(peer,data,acc,ledger)
            peer.used_bytes_total=max(int(data.get('used_bytes_total') or 0),int(ledger.get('used_bytes_total') or 0))
            if kind=='peers':
                m.apply_options(peer,{**values,**{k:data[k] for k in m.NETWORK}},acc)
                lifecycle(peer,data,acc,ledger)
            db.session.add(peer);db.session.flush()
            s.put('recovery_pending:'+str(peer.id),True)
            for short in entry.get('short_links',[]):
                db.session.add(ShortLink(peer_id=peer.id,token=short['token'],created_at=date(short.get('created_at')) or s.now()))
            db.session.add(Ownership(account_id=acc.id,peer_id=peer.id,subscription_id=obj.id if kind=='subscriptions' else None,observed_bytes=peer.used_bytes_total,blocked=False))
            if kind=='subscriptions':db.session.add(SubscriptionPeer(subscription_id=obj.id,peer_id=peer.id,owned=True,**{k:v for k,v in (entry.get('link') or {}).items() if k in ('location_label','country_code','flag','sort_order')}))
        if kind=='subscriptions' and item.get('design') is not None and 'portal_design' in acc.spec['permissions']:
            key=design_key(acc.id,'subscription',obj.id)
            if s.setting(key) is None:s.put(key,item['design'])
    if 'profiles' in acc.spec['permissions']:
        for profile in payload.get('profiles',[]):
            if CustomerProfile.query.filter_by(account_id=acc.id,kind=profile['kind'],name=profile['name']).first():continue
            default=bool(profile.get('is_default')) and not CustomerProfile.query.filter_by(account_id=acc.id,kind=profile['kind'],is_default=True).first()
            options=json.loads(json.dumps(profile['options']))
            if profile['kind']=='subscription':
                for desc in options.get('interfaces',[]):
                    identity=desc.pop('_recovery_peer_key',None)
                    if identity:
                        peer=Peer.query.filter_by(public_key=identity).one()
                        s.own_peer(acc,peer.id);desc['peer_id']=peer.id
            db.session.add(CustomerProfile(account_id=acc.id,kind=profile['kind'],name=profile['name'],options=options,is_default=default))
    for kind,perm in (('peer','peer_template'),('subscription','portal_design')):
        key=design_key(acc.id,kind);design=payload.get('designs',{}).get(kind)
        if perm in acc.spec['permissions'] and design is not None and s.setting(key) is None:s.put(key,design)
    s.audit('reseller:'+str(acc.id),'restore_customer_recovery',str(len(prepared))+' customers; recreated peers paused')
    return len(prepared)
