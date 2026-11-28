from panel_core.qr import PNGImage

from flask import request,g,abort,render_template,redirect,url_for,Response,session,current_app
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import OperationalError
import secrets
from contextlib import contextmanager
from models import db,Peer,InterfaceConfig,Node,Subscription,SubscriptionPeer
from sqlalchemy.orm import joinedload, selectinload
from .models import Account,Ownership,CustomerProfile
from .database import settings_transaction
from .provision_queue import submit_web
from . import service as s,management as m
from .presentation import peer_states
from .regional import zone_name
import ipaddress
import time
from threading import Lock
from datetime import timezone


def _optional_db_id(value, name):


    if value is None or value == '':
        return None
    if type(value) is int and 0 < value <= 2147483647:
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 10:
        number = int(value)
        if 0 < number <= 2147483647:
            return number
    raise ValueError('Invalid ' + name + '.')


def design_key(aid,kind,sid=None):
    return f'design:{aid}:{kind}'+(f':{sid}' if sid is not None else '')


def peer_design(peer,default):
    row=Ownership.query.filter_by(peer_id=peer.id,deleted=False).first()
    return s.setting(design_key(row.account_id,'peer'),default) if row else default


def subscription_design(sub,host):
    rows=Ownership.query.filter_by(subscription_id=sub.id,deleted=False).all()
    if not rows:return None
    if len({r.account_id for r in rows})!=1:return host['_subscription_settings_default']()
    aid=rows[0].account_id
    base=s.setting(design_key(aid,'subscription'),host['_subscription_settings_default']())
    return host['_normalize_subscription_settings'](s.setting(design_key(aid,'subscription',sub.id),{}),base=base)


_status_cache={}
_status_cache_lock=Lock()
_address_cache={}
_address_cache_lock=Lock()

def register(bp,member,host_get):
    @contextmanager
    def transaction(creating=False):
        lock=s.provisioning(g.reseller.id,host_get()) if creating else s.locked(g.reseller.id)
        with lock as usage_sample:
            acc=g.reseller
            if acc.state!='active' or not acc.spec.get('panel_access') or session.get('rp_version')!=acc.session_version:abort(403)
            yield usage_sample

    def allow(section,permission=None):
        acc=g.reseller
        if section not in acc.spec['permissions'] or permission and permission not in acc.spec['permissions']:abort(403)
        return acc
    @contextmanager
    def settings_change(section, permission):
        aid = g.reseller.id
        with settings_transaction():
            acc = db.session.get(Account, aid, with_for_update=True)
            if not acc or not acc.spec.get('panel_access') or session.get('rp_version') != acc.session_version:
                abort(403)
            g.reseller = acc
            s.require_active(acc)
            allow(section, permission)
            yield
    def interfaces():
        return InterfaceConfig.query.filter(InterfaceConfig.id.in_(g.reseller.spec['interfaces'])).all()
    def own_iface(iid=None,name=None,node=None):
        for i in interfaces():
            if iid is not None and str(i.id)==str(iid) or iid is None and i.name.split(':',1)[-1]==name and str(i.node_id or '')==str(node or ''):return i
        abort(404)
    def address_candidates(i):

        if 'choose_address' not in g.reseller.spec['permissions']:return []
        now=time.monotonic()
        with _address_cache_lock:
            cached=_address_cache.get(i.id)
            if cached and now-cached[0]<4:return list(cached[1])
        try:interface=ipaddress.ip_interface(i.address)
        except (ValueError,TypeError):return []
        used={interface.ip}
        for value, in db.session.query(Peer.address).filter_by(iface_id=i.id):
            try:used.add(ipaddress.ip_interface(value).ip)
            except (ValueError,TypeError):pass
        result=[]
        from itertools import islice
        for candidate in islice(interface.network.hosts(),len(used)+512):
            if candidate not in used:result.append(f'{candidate}/{interface.network.prefixlen}')
            if len(result)>=512:break
        with _address_cache_lock:
            if len(_address_cache)>256:_address_cache.clear()
            _address_cache[i.id]=(time.monotonic(),tuple(result))
        return result
    def _probe_iface_running(i, host):
        name = i.name.split(':', 1)[-1]
        if not i.node_id:
            probe = host.get('_iface_up')
            if not callable(probe):
                return None
            try:
                return bool(probe(name))
            except Exception:
                return None
        cache = getattr(g, '_rp_iface_node_states', None)
        if cache is None:
            cache = {}
            g._rp_iface_node_states = cache
        if i.node_id not in cache:
            cache[i.node_id] = {}
            node = db.session.get(Node, i.node_id)
            remote_get = host.get('node_get')
            if node is not None and node.enabled and callable(remote_get):
                try:
                    deadline = getattr(g, '_rp_iface_deadline', None)
                    if deadline is None:
                        deadline = time.monotonic() + .65
                        g._rp_iface_deadline = deadline
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    response = remote_get(node, '/api/interfaces?fast=1', timeout=min(.5, remaining))
                    rows = response.get('interfaces', []) if isinstance(response, dict) else response
                    for entry in rows if isinstance(rows, list) else []:
                        if isinstance(entry, dict) and type(entry.get('is_up')) is bool:
                            cache[i.node_id][str(entry.get('name') or entry.get('iface') or '')] = entry['is_up']
                except Exception:
                    pass
        return cache[i.node_id].get(name)

    def iface_running(i, host):
        key=(i.node_id or 0, i.name.split(':',1)[-1])
        now=time.monotonic()
        with _status_cache_lock:
            entry=_status_cache.get(key)
            if entry and now-entry[0] < (12 if i.node_id else 5):return entry[1]
        result=_probe_iface_running(i,host)
        with _status_cache_lock:
            if len(_status_cache)>128:
                _status_cache.clear()
            _status_cache[key]=(time.monotonic(),result)
        return result

    def iface_row(i):
        host=host_get();ips=address_candidates(i)
        from .network_policy import get
        policy=get(g.reseller)
        endpoint=policy.get('endpoint') or host.get('iface_endpoint_override',lambda i:'')(i) or ''
        if not endpoint and not i.node_id:
            settings=host.get('_load_panel_settings',lambda:{})()
            domain=settings.get('domain') if settings.get('tls_enabled') else None
            if domain:endpoint=host.get('_norm_hostport',lambda h,p:f'{h}:{p}')(domain,i.listen_port)
        try:networks=[str(ipaddress.ip_interface(i.address).network)]
        except ValueError:networks=[]
        if policy:
            endpoint=policy.get('endpoint') or endpoint
            networks=policy.get('internal_routes',[]) if policy.get('allow_internal') else []
        running = iface_running(i, host)
        return dict(available_ips=list(ips or [])[:512],endpoint=endpoint,endpoint_default=endpoint,effective_endpoint=endpoint,endpoint_locked=bool(endpoint),scope_networks=networks,id=i.id,iface_id=i.id,name=i.name.split(':',1)[-1],iface=i.name.split(':',1)[-1],node_id=i.node_id,scope='node' if i.node_id else 'local',address=i.address,server_cidr=i.address,interface_address=i.address,dns=i.dns,mtu=i.mtu,listen_port=i.listen_port,label=i.name,location=i.name,online=running,is_up=running,status_source='live' if running is not None else 'unavailable')
    def owned_peers(node_scope=False,node=None,iface_id=None):

        ids=db.session.query(Ownership.peer_id).filter(
            Ownership.account_id==g.reseller.id,Ownership.deleted.is_(False))
        if 'subscriptions' not in g.reseller.spec['permissions']:
            ids=ids.filter(Ownership.subscription_id.is_(None))
        query=Peer.query.options(joinedload(Peer.iface)).filter(Peer.id.in_(ids))
        if node_scope:
            node_id=_optional_db_id(node,'node_id')
            query=query.join(InterfaceConfig,Peer.iface_id==InterfaceConfig.id)
            query=query.filter(InterfaceConfig.node_id==node_id if node_id is not None else InterfaceConfig.node_id.is_(None))
        interface_id=_optional_db_id(iface_id,'iface_id')
        if interface_id is not None:
            query=query.filter(Peer.iface_id==interface_id)
        return query.all()

    def authorized_subscriptions(rows):


        ids={r.subscription_id for r in rows if r.subscription_id}
        if not ids:return {}
        memberships=Ownership.query.filter(Ownership.subscription_id.in_(ids),Ownership.deleted.is_(False)).all()
        by_id={}
        for row in memberships:by_id.setdefault(row.subscription_id,[]).append(row)
        subs=Subscription.query.options(selectinload(Subscription.links).joinedload(SubscriptionPeer.peer)).filter(Subscription.id.in_(ids)).all()
        allowed={}
        for sub in subs:
            own=by_id.get(sub.id,[])
            owned_ids={r.peer_id for r in own}
            if own and all(r.account_id==g.reseller.id for r in own) and all(link.peer_id in owned_ids for link in sub.links):
                allowed[sub.id]=sub
        return allowed

    def peer_row(p,states=None):
        cache=getattr(g,'_rp_bulk_peer_context',None)
        if cache is not None and p.id in cache['owners']:
            row=cache['owners'][p.id]
            sub=cache['subscriptions'].get(row.subscription_id) if row.subscription_id else None
            access_ok=cache['access'][p.id]
        else:
            row,p=s.own_peer(g.reseller,p.id)
            sub=m.own_subscription(g.reseller,row.subscription_id)[0] if row.subscription_id else None
            access_ok=m.child_allowed(p,g.reseller)
        states=states or peer_states([p],host_get(),live=False,owner_account_id=g.reseller.id);state=states[p.id]
        resource=sub or p
        result={k:getattr(p,k,None) for k in m.FIELDS+m.NETWORK}
        result.update(id=p.id,public_key=p.public_key,iface=p.iface.name.split(':',1)[-1],iface_id=p.iface_id,node_id=p.iface.node_id,scope='node' if p.iface.node_id else 'local',reseller_owner={'id':g.reseller.id,'username':g.reseller.username},address=p.address,endpoint=p.endpoint or '',endpoint_saved=p.endpoint or '',peer_endpoint=getattr(p,'peer_endpoint','') or '',status=p.status if access_ok else 'blocked',panel_status=p.status,conn_status=state['connection'],connection_status=state['connection'],data_limit=resource.data_limit_value,limit_unit=resource.data_limit_unit,used_bytes=m.usage(resource),unlimited=False,subscription_managed=bool(sub),subscription_id=row.subscription_id,subscription_name=sub.name if sub else '',rx=(state['rx'] or 0)/1048576,tx=(state['tx'] or 0)/1048576,display_timezone=zone_name())
        for key in ('created_at','first_used_at','expires_at'):
            val=getattr(resource,key,None);result[key]=val.isoformat()+'Z' if val else None;result[key+'_ts']=val.replace(tzinfo=timezone.utc).timestamp() if val else None
        expiry=min(resource.expires_at,g.reseller.expires_at) if resource.expires_at else g.reseller.expires_at
        used=m.usage(resource)
        remaining=max(0,int(g.reseller.spec['traffic_gib'])*s.GIB-g.reseller.used_bytes)
        limit=resource.limit_bytes()
        effective=min(limit,used+remaining) if limit is not None else used+remaining
        result.update(data_limit=effective/s.GIB,limit_unit='Gi',used_bytes=used,used_effective_bytes=used,remaining_bytes=max(0,effective-used),limit_bytes=effective)
        result['ttl_seconds']=max(0,(expiry-s.now()).total_seconds())
        return result
    def subscription_row(sub):
        item=host_get().get('_subscription_row_readonly',host_get()['_subscription_row'])(sub)
        first=next((link.peer for link in sub.links if link.peer),None)
        if first:item.update({key:getattr(first,key,None) for key in m.NETWORK})
        used=m.usage(sub);remaining=max(0,int(g.reseller.spec['traffic_gib'])*s.GIB-g.reseller.used_bytes)
        limit=sub.limit_bytes();effective=min(limit,used+remaining) if limit is not None else used+remaining
        expiry=min(sub.expires_at,g.reseller.expires_at) if sub.expires_at else g.reseller.expires_at
        item.update(unlimited=False,used_bytes=used,limit_bytes=effective,remaining_bytes=max(0,effective-used),ttl_seconds=max(0,(expiry-s.now()).total_seconds()))
        if 'download' not in g.reseller.spec['permissions']:
            def redact(value):
                if isinstance(value,dict):return {k:('' if 'url' in k or 'token' in k or k in ('private_key','shortlink') else redact(v)) for k,v in value.items()}
                if isinstance(value,list):return [redact(v) for v in value]
                return value
            item=redact(item)
        return item

    def input_data():
        data=request.get_json(silent=True) if request.is_json else request.form.to_dict()
        if not isinstance(data,dict):raise ValueError('Expected form settings.')
        return data
    def options(data):
        out=dict(data)
        out['data_limit_value']=data.get('data_limit_value',data.get('data_limit',0)) or 0
        out['data_limit_unit']=data.get('data_limit_unit',data.get('limit_unit','Gi')) or 'Gi'
        if m.checkbox_value(data.get('unlimited',False),'unlimited') or m.checkbox_value(data.get('customer_unlimited',False),'shared allowance'):
            raise ValueError('Set a customer traffic limit within your reseller plan.')
        out['customer_unlimited']=False
        if 'network_options' not in g.reseller.spec['permissions']:

            if any(data.get(k) not in (None,'') for k in m.NETWORK):abort(403)
            for k in m.NETWORK:out.pop(k,None)
        if data.get('address'):
            if 'choose_address' not in g.reseller.spec['permissions']:abort(403)
            out['peer_address']=data['address']
        return out
    def create_peer(data,bulk=False):
        acc=allow('peers','create')
        if bulk:allow('peers','bulk')
        iface=own_iface(data.get('iface_id') or data.get('iface'),data.get('iface_name'),data.get('node_id'))
        count=s.integer(data,'count',1,50) if bulk else 1
        from .network_policy import normalize_inherited_endpoint
        opts=options(normalize_inherited_endpoint(acc,iface,data,host_get()))
        opts['name']=str(data.get('prefix') or data.get('name') or '').strip()
        m.validate_options(acc,opts)
        return submit_web(acc,dict(section='peers',action='create',interfaces=[iface.id],options=opts,count=count,bulk=bulk))

    @bp.post('/r/shared/users')
    @member('create')
    def shared_form_create():
        try:
            response,status=create_peer(input_data())
            if status!=202:
                from . import error_page
                return error_page(response['error'],'Operation not queued'),status
            return redirect(url_for('reseller.portal',section='peers',operation=response['operation']['id']),code=303)
        except (ValueError, HTTPException, TimeoutError, OperationalError):
            raise
        except Exception:


            reference=secrets.token_hex(4)
            current_app.logger.exception(
                'Reseller web peer creation failed ref=%s account=%s route=%s',
                reference,g.reseller.id,request.endpoint)
            db.session.rollback()
            from . import error_page
            return error_page(
                'Peer creation could not be confirmed. Check your peer list before retrying. '
                'If the customer was not created, give the administrator this reference: '+reference,
                title='Creation needs review',reference=reference),500
        return redirect(url_for('reseller.portal',section='peers'),code=303)

    @bp.route('/r/shared/api/<path:path>',methods=['GET','POST','PUT','PATCH','DELETE'])
    @member()
    def shared_api(path):
        host=host_get();acc=g.reseller;method=request.method
        parts=path.split('/');node=None
        if len(parts)>2 and parts[0]=='nodes':
            node=parts[1]
            if not any(str(i.node_id)==node for i in interfaces()):abort(404)
            parts=parts[2:];path='/'.join(parts)
        if method=='GET' and path=='timezone':return {'timezone':host['_panel_timezone_name']()}
        if method=='GET' and path=='nodes':
            ids={i.node_id for i in interfaces() if i.node_id}
            return {'nodes':[{'id':n.id,'name':n.name} for n in Node.query.filter(Node.id.in_(ids)).all()]}
        if method=='GET' and path in ('interfaces','get-interfaces'):
            if not {'peers','subscriptions'} & set(acc.spec['permissions']):abort(403)
            return {'interfaces':[iface_row(i) for i in interfaces() if str(i.node_id or '')==str(node or '')]}
        if method=='GET' and len(parts)==3 and parts[0]=='iface' and parts[2]=='available_ips':
            allow('peers','create');i=own_iface(parts[1]) if not node else own_iface(name=parts[1],node=node)
            if 'choose_address' not in acc.spec['permissions']:return {'available_ips':[]}
            if not i.node_id and callable(host.get('_available_ips')):
                return {'available_ips':host['_available_ips'](i,limit=512),'revalidated_on_create':True}
            return {'available_ips':address_candidates(i),'revalidated_on_create':True}
        if path=='peers' and method=='GET':
            allow('peers');items=owned_peers(node_scope=True,node=node,iface_id=request.args.get('iface_id'))
            if request.args.get('iface'):items=[p for p in items if p.iface.name.split(':',1)[-1]==request.args['iface']]
            states=peer_states(items,host,live=False,owner_account_id=acc.id)
            owners={r.peer_id:r for r in Ownership.query.filter_by(account_id=acc.id,deleted=False).filter(Ownership.peer_id.in_([p.id for p in items])).all()}
            subs=authorized_subscriptions(list(owners.values()))
            sub_access={sid:m.reason(sub,acc) is None for sid,sub in subs.items()}
            access={p.id:(m.reason(p,acc) is None and (not owners[p.id].subscription_id or
                    sub_access.get(owners[p.id].subscription_id,False))) for p in items}
            g._rp_bulk_peer_context=dict(owners=owners,subscriptions=subs,access=access)
            return {'peers':[peer_row(p,states) for p in items]}
        if path in ('peers','peers/bulk') and method=='POST':return create_peer(input_data(),path.endswith('/bulk'))
        if parts[0]=='peer' and len(parts) in (2,3):
            if not node and len(parts)==2 and parts[1].isdigit() and method=='DELETE':
                allow('peers','delete');rid=int(parts[1])
                return submit_web(acc,dict(section='peers',action='delete',id=rid,options={}),
                                  validate=lambda:m.target(acc,'peers',rid))
            if node:
                candidates=[p for p in owned_peers() if str(p.iface.node_id)==node and p.public_key==parts[1]]
                if not candidates:abort(404)
                p=candidates[0];row,_=s.own_peer(acc,p.id)
            else:
                if not parts[1].isdigit():abort(404)
                row,p=s.own_peer(acc,int(parts[1]))
            peer_section='subscriptions' if row.subscription_id else 'peers'
            allow(peer_section)
            action=parts[2] if len(parts)==3 else ''
            if method=='GET' and not action:return peer_row(p)
            if action=='logs' and method=='GET':
                allow(peer_section,'logs')
                from models import PeerEvent
                return {'peer':peer_row(p),'logs':[{'time':e.timestamp.isoformat()+'Z','time_ts':e.timestamp.replace(tzinfo=timezone.utc).timestamp(),'event':e.event,'details':''} for e in PeerEvent.query.filter_by(peer_id=p.id).order_by(PeerEvent.id.desc()).limit(100)]}
            if action in ('config','config_qr','shortlink'):
                allow(peer_section,'download');s.require_active(acc)
                if action=='shortlink' and method in ('POST','GET'):return host['_shortlink_response_for_peer'](p)
                if method=='GET':
                    if action=='config':return Response(host['_client_conf_txt'](p),mimetype='text/plain',headers={'Content-Disposition':'attachment; filename="peer.conf"'})
                    import qrcode,io
                    buf=io.BytesIO();qrcode.make(host['_client_conf_txt'](p), image_factory=PNGImage).save(buf,format='PNG');return Response(buf.getvalue(),mimetype='image/png')
            change='delete' if method=='DELETE' and not action else 'edit' if method in ('PUT','PATCH') and not action else action
            permission={'enable':'control_access','disable':'control_access','delete':'delete','edit':'edit','reset_data':'reset_data','reset_timer':'reset_timer'}.get(change)
            if permission and method in ('POST','PUT','PATCH','DELETE'):
                allow('peers',permission)
                edit_data=input_data() if change=='edit' else {}
                if change=='edit':
                    from .network_policy import normalize_inherited_endpoint
                    edit_data=options(normalize_inherited_endpoint(acc,p.iface,edit_data,host))
                    m.validate_options(acc,edit_data)
                m.target(acc,'peers',p.id)
                return submit_web(acc,dict(section='peers',action=change,id=p.id,options=edit_data))
            abort(403)
        if path=='subscriptions/locations' and method=='GET':
            allow('subscriptions');items=[iface_row(i) for i in interfaces()]
            return {'local':[i for i in items if not i['node_id']],'nodes':[{'id':nid,'online':(True if any(i['is_up'] is True for i in items if i['node_id']==nid) else False if any(i['is_up'] is False for i in items if i['node_id']==nid) else None),'interfaces':[i for i in items if i['node_id']==nid]} for nid in {i['node_id'] for i in items if i['node_id']}]}
        if path=='subscriptions/inbounds_catalog' and method=='GET':
            allow('subscriptions')
            if 'attach_existing' not in acc.spec['permissions']:return {'inbounds':[]}
            rows=Ownership.query.filter_by(account_id=acc.id,deleted=False,subscription_id=None).all()
            ids=[row.peer_id for row in rows]
            peers=Peer.query.options(joinedload(Peer.iface)).filter(Peer.id.in_(ids)).all() if ids else []
            states=peer_states(peers,host,live=False,owner_account_id=acc.id)
            g._rp_bulk_peer_context=dict(owners={row.peer_id:row for row in rows},subscriptions={},
                access={p.id:m.reason(p,acc) is None for p in peers})
            return {'inbounds':[dict(peer_row(p,states),peer_id=p.id) for p in peers]}
        if path=='subscriptions' and method=='GET':
            allow('subscriptions')
            rows=Ownership.query.filter_by(account_id=acc.id,deleted=False).all()
            subs=authorized_subscriptions(rows)
            return {'subscriptions':[subscription_row(subs[sid]) for sid in sorted(subs)]}
        if path=='subscriptions' and method=='POST':
            allow('subscriptions','create');data=input_data();opts=options(data);opts.pop('time_limit_hours',None);opts.pop('time_limit_minutes',None);targets=data.get('targets')
            if not isinstance(targets,list) or not targets or len(targets)>100:raise ValueError('Select allowed locations.')
            if any(not isinstance(t,dict) for t in targets):raise ValueError('Invalid locations.')
            m.validate_options(acc,opts)
            if any('peer_id' in t for t in targets):
                allow('subscriptions','attach_existing')
                if not all(type(t.get('peer_id'))==int for t in targets):raise ValueError('Invalid existing peers.')
                ids=[t['peer_id'] for t in targets]
                return submit_web(acc,dict(section='subscriptions',action='attach',peer_ids=ids,options=opts),
                                  validate=lambda:[m.target(acc,'peers',rid) for rid in ids])
            ids=[own_iface(t.get('iface_id'),t.get('iface'),t.get('node_id')).id for t in targets]
            return submit_web(acc,dict(section='subscriptions',action='create',interfaces=ids,options=opts,count=1))
        if parts[0]=='subscriptions' and len(parts) in (3,4) and parts[1].isdigit() and parts[2]=='inbounds':
            return inbounds(int(parts[1]),int(parts[3]) if len(parts)==4 and parts[3].isdigit() else None)
        if parts[0]=='subscriptions' and len(parts) in (2,3) and parts[1].isdigit():
            allow('subscriptions');sid=int(parts[1]);action=parts[2] if len(parts)==3 else ''
            if method=='DELETE' and not action:
                allow('subscriptions','delete')
                return submit_web(acc,dict(section='subscriptions',action='delete',id=sid,options={}),
                                  validate=lambda:m.target(acc,'subscriptions',sid))
            sub,_=m.own_subscription(acc,sid)
            if action=='portal-settings':return design('subscription',sid,sub)
            if method=='GET' and not action:return subscription_row(sub)
            change='delete' if method=='DELETE' and not action else 'edit' if method=='PUT' and not action else action
            permission={'enable':'control_access','disable':'control_access','delete':'delete','edit':'edit','reset_data':'reset_data','reset_timer':'reset_timer'}.get(change)
            if permission and method in ('POST','PUT','DELETE'):
                allow('subscriptions',permission)
                data=options(input_data()) if change=='edit' else {}
                data.pop('time_limit_hours',None);data.pop('time_limit_minutes',None)
                if change=='edit':m.validate_options(acc,data)
                return submit_web(acc,dict(section='subscriptions',action=change,id=sid,options=data))
            abort(403)
        if path=='template_settings':return design('peer')
        if path=='subscriptions/settings':return design('subscription')
        if path=='subscriptions/template-preview' and method=='POST':
            allow('subscriptions','portal_design');data=input_data();sub=None
            if data.get('subscription_id'):sub,_=m.own_subscription(acc,int(data['subscription_id']))
            base=subscription_design(sub,host) if sub else s.setting(design_key(acc.id,'subscription'),host['_subscription_settings_default']())
            return host['_render_subscription_template_preview'](sub,data.get('settings',{}),base)

        if path in ('peer_profiles','peer_profile','peer_profile/activate','peer_profile/rename') or parts[0]=='subscription_profiles':return profiles(path)
        if path=='endpoint_presets':
            allow('peers','network_options');key='endpoint_presets:'+str(acc.id)
            if method=='GET':return {'presets':s.setting(key,[])}
            if method not in ('POST','DELETE'):abort(405)
            data=input_data();endpoint=str(data.get('host',''))+':'+str(data.get('port',''))
            m.validate_options(acc,{'name':'Preset','endpoint':endpoint})
            label=str(data.get('label','')).strip()
            if len(label)>80 or any(ord(c)<32 or c in '<>"' for c in label):raise ValueError('Invalid preset label.')
            with settings_change('peers','network_options'):
                rows=[row for row in s.setting(key,[]) if str(row['host'])+':'+str(row['port'])!=endpoint]
                if method=='POST':
                    if len(rows)>=50:raise ValueError('Preset limit reached (50).')
                    rows.append({'host':data['host'],'port':int(data['port']),'label':label})
                s.put(key,rows)
            return {'presets':rows}
        abort(403)

    def reset(section,rid,action):
        acc=allow(section,action)
        return m.reset_customer(acc,section,rid,action,host_get())

    def inbounds(sid,lid):
        from models import SubscriptionPeer
        acc=allow('subscriptions','manage_inbounds');host=host_get()
        with transaction():
            sub,peers=m.own_subscription(acc,sid);s.require_active(acc)
            if lid is not None:
                link=SubscriptionPeer.query.filter_by(id=lid,subscription_id=sid).first()
                if not link:abort(404)
                row,p=s.own_peer(acc,link.peer_id)
                if request.method=='PATCH':
                    label=str(input_data().get('location_label','')).strip()
                    if len(label)>80 or any(ord(c)<32 for c in label):raise ValueError('Invalid location label.')
                    link.location_label=label
                elif request.method=='DELETE':
                    if len(peers)<=1:raise ValueError('Keep one configuration, or delete this subscription.')
                    if request.args.get('delete_peer') in ('1','true'):
                        allow('subscriptions','delete');s.remove(acc,p.id,host)
                    else:
                        if not s.sample(acc,host):raise ValueError('Current usage is unavailable.')
                        db.session.delete(link);row.subscription_id=None

                        for key in m.FIELDS:setattr(p,key,getattr(sub,key))
                        p.unlimited=False;p.timer_started_at=sub.timer_started_at;p.first_used_at=sub.first_used_at;p.expires_at=sub.expires_at
                else:abort(405)
            elif request.method=='POST':
                allow('subscriptions','create');data=input_data();targets=data.get('targets')
                if not isinstance(targets,list) or not 1<=len(targets)<=50:raise ValueError('Select allowed locations.')
                if any('peer_id' in t for t in targets):
                    allow('subscriptions','attach_existing')
                    items=[]
                    for t in targets:
                        row,p=s.own_peer(acc,int(t.get('peer_id',0)))
                        if row.subscription_id or p.iface_id not in acc.spec['interfaces']:raise ValueError('Select an owned standalone peer.')
                        items.append((row,p))
                    if len({p.id for _,p in items})!=len(items):raise ValueError('Choose each peer once.')
                    if not s.sample(acc,host):raise ValueError('Current usage is unavailable.')
                    for row,p in items:
                        row.subscription_id=sub.id;db.session.add(SubscriptionPeer(subscription_id=sub.id,peer_id=p.id,owned=True))
                        p.unlimited=False;p.data_limit_value=0;p.time_limit_days=0;p.expires_at=acc.expires_at
                else:
                    ids=[own_iface(t.get('iface_id'),t.get('iface'),t.get('node_id')).id for t in targets]
                    opts=options(data);opts.pop('time_limit_hours',None);opts.pop('time_limit_minutes',None)
                    s.provision(acc,ids,sub.name,True,host,options=opts,existing_sub=sub)
            else:abort(405)
            db.session.flush();m.enforce_children(acc,host);s.audit('reseller:'+str(acc.id),'inbounds_changed',str(sid))
        return {'ok':True}

    def design(kind,sid=None,sub=None):
        host=host_get();section='peers' if kind=='peer' else 'subscriptions';permission='peer_template' if kind=='peer' else 'portal_design'
        allow(section,permission if request.method!='GET' else None)
        key=design_key(g.reseller.id,kind,sid)
        default={'selected':'default','appearance':{},'socials':{}} if kind=='peer' else host['_subscription_settings_default']()
        base=s.setting(design_key(g.reseller.id,kind),default)
        value=s.setting(key,base)
        if request.method=='GET':
            if sid:return {'settings':host['_normalize_subscription_settings'](value,base=base),'global_settings':base,'has_override':bool(s.setting(key)),'subscription_name':sub.name}
            return value
        allow(section,permission)
        if request.method=='DELETE' and sid:
            with settings_change(section,permission):
                m.own_subscription(g.reseller,sid)
                s.put(key,{})
            return {'ok':True}
        if request.method!='POST':abort(405)
        raw=input_data()
        if kind=='peer':
            from panel_operations.templates import validate
            value=validate(raw,base)
        else:value=host['_normalize_subscription_settings'](raw,base=base)
        with settings_change(section,permission):
            if sid:m.own_subscription(g.reseller,sid)
            s.put(key,value);s.audit('reseller:'+str(g.reseller.id),'design_saved',kind+(':'+str(sid) if sid else ''))
        return {'ok':True,'settings':value}

    def profiles(path):
        kind='subscription' if path.startswith('subscription') else 'peer'
        allow('subscriptions' if kind=='subscription' else 'peers','profiles')
        data=input_data() if request.method in ('POST','PUT') else {}
        parts=path.split('/')
        name=request.args.get('name') or data.get('name') or data.get('old') if kind=='peer' else (parts[1] if len(parts)>1 else data.get('name'))
        action=parts[-1] if parts[-1] in ('activate','rename') else ''
        def current_profiles():
            rows = CustomerProfile.query.filter_by(account_id=g.reseller.id,kind=kind).all()
            return rows, next((p for p in rows if p.name==name),None)
        if request.method=='GET':
            rows,p=current_profiles()
            if path in ('peer_profiles','subscription_profiles'):
                return {'profiles':[p.name if kind=='peer' else {'name':p.name} for p in rows],'active':next((p.name for p in rows if p.is_default),'')}
            if not p:
                if kind=='peer' and name=='Default':return {}
                abort(404)
            if kind=='peer':return p.options
            stored=p.options or {}
            if stored and not {'client','advanced','template','include'}.intersection(stored):
                client={k:v for k,v in stored.items() if k in m.FIELDS or k in ('time_limit_hours','time_limit_minutes')}
                network={k:v for k,v in stored.items() if k in m.NETWORK or k=='include_internal_network'}
                stored={'client':client}
                if network:stored['advanced']=network
            return {'profile':stored,'name':p.name}
        def checked_name(value):
            value=str(value or '').strip()
            if not 1<=len(value)<=64 or any(ord(c)<32 or c in '<>"' for c in value):raise ValueError('Enter a valid profile name (1–64 characters).')
            return value
        with settings_change('subscriptions' if kind=='subscription' else 'peers','profiles'):
            rows,p=current_profiles()
            if request.method=='DELETE':
                if not p:abort(404)
                db.session.delete(p)
            elif action=='activate':
                if not p:abort(404)
                for item in rows:item.is_default=item.id==p.id
            elif action=='rename':
                if not p:abort(404)
                new=checked_name(data.get('new_name') or data.get('new'))
                if any(item.name==new and item.id!=p.id for item in rows):raise ValueError('Profile name already exists.')
                p.name=new
            elif request.method=='POST':
                name=checked_name(name)
                if not p:
                    from .limits import profile_capacity
                    profile_capacity(g.reseller)
                raw=data if kind=='peer' else data.get('profile',{})
                if not isinstance(raw,dict):raise ValueError('Expected profile settings.')
                if kind=='peer':
                    m.validate_options(g.reseller,{**options(raw),'name':'Profile'})
                    stored={k:v for k,v in raw.items() if k in set(m.FIELDS+m.NETWORK)|{'endpoint','peer_endpoint','unlimited','time_limit_hours','time_limit_minutes'}}
                    stored.pop('name',None)
                else:
                    stored={k:v for k,v in raw.items() if k in ('include','client','advanced','interfaces','template')}
                    if 'client' in stored:m.validate_options(g.reseller,{**options(stored['client']),'name':'Profile'})
                    if stored.get('advanced'):
                        allow('subscriptions','network_options')
                        if not isinstance(stored['advanced'],dict):raise ValueError('Invalid advanced settings.')
                    for desc in stored.get('interfaces',[]):
                        if desc.get('peer_id'):s.own_peer(g.reseller,int(desc['peer_id']))
                        else:own_iface(name=desc.get('iface'),node=desc.get('node_id'))
                    if stored.get('template'):
                        allow('subscriptions','portal_design')
                        stored['template']=host_get()['_normalize_subscription_settings'](stored['template'],base=host_get()['_subscription_settings_default']())
                if not p:p=CustomerProfile(account_id=g.reseller.id,kind=kind,name=name);db.session.add(p)
                p.options=stored
                if data.get('activate'):
                    for item in rows:item.is_default=False
                    p.is_default=True
            else:abort(405)
            s.audit('reseller:'+str(g.reseller.id),'profile_updated',kind)
        return {'ok':True,'saved_name':p.name if p else name,'saved':p.options if p else {}}

    @bp.get('/r/shared/preview/template/<name>')
    @member('peer_template')
    def shared_peer_preview(name):
        allow('peers')
        return host_get()['_render_peer_template_preview'](name,s.setting(design_key(g.reseller.id,'peer'),{}))
