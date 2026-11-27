from panel_core.telegram_notices import inbox_text
from panel_core.qr import PNGImage

from datetime import timedelta
from io import BytesIO
from flask import g,request,session,abort,Response
from models import db,Peer,InterfaceConfig,PeerEvent,Subscription,SubscriptionPeer
from sqlalchemy.orm import joinedload,selectinload
from .models import Account,Ownership,Notice,UsagePoint,CustomerProfile
from . import service as s, management as m
from .presentation import peer_states
from .limits import effective
from .database import settings_transaction
from .provision_queue import submit_web,GRANTS

def register(bp,member,host_get):
    def permit(section,permission=None):
        acc=g.reseller
        if section not in acc.spec['permissions'] or (permission and permission not in acc.spec['permissions']):abort(403)
        return acc
    def fresh(section,permission,for_update=False):
        acc=db.session.get(Account,g.reseller.id,with_for_update=for_update)
        if acc.state!='active' or not acc.spec.get('panel_access') or session.get('rp_version')!=acc.session_version or section not in acc.spec['permissions'] or permission not in acc.spec['permissions']:abort(403)
        return acc
    def fields(resource):
        result={key:getattr(resource,key,None) for key in m.FIELDS}
        result.update(note=getattr(resource,'note','') or '',used_bytes=m.usage(resource),limit_bytes=resource.limit_bytes(),expires_at=resource.expires_at.isoformat()+'Z' if resource.expires_at else None,first_used=bool(resource.first_used_at))
        return result

    @bp.get('/r/api/workspace/<section>')
    @member()
    def workspace_data(section):
        if section not in ('dashboard','peers','subscriptions'):abort(404)
        acc=permit(section);host=host_get()
        if section=='dashboard':


            from .regional import zone_name
            from .models import UsagePoint
            from sqlalchemy import func, case
            from .presentation import cached_peer_snapshot
            owned=Ownership.query.filter_by(account_id=acc.id,deleted=False)
            peers_count, subs_count, blocked=owned.with_entities(func.count(Ownership.peer_id),
                func.count(func.distinct(Ownership.subscription_id)),func.count(case((Ownership.blocked.is_(True),1)))).one()
            recent=(Peer.query.options(joinedload(Peer.iface))
                .join(Ownership, Ownership.peer_id==Peer.id).filter(Ownership.account_id==acc.id,
                    Ownership.deleted.is_(False)).order_by(Ownership.peer_id.desc()).limit(6).all() if peers_count else [])
            states=peer_states(recent,host,live=False,owner_account_id=acc.id)
            last_sample=(UsagePoint.query.filter(UsagePoint.account_id==acc.id,
                UsagePoint.generation==acc.generation,UsagePoint.at>=s.now()-timedelta(minutes=15))
                .order_by(UsagePoint.at).all())
            recent_peers=[dict(id=p.id,name=p.name,address=p.address,
                  iface=p.iface.name if p.iface else '',used_bytes=int(p.used_bytes_total or 0),
                  connection=states[p.id]['connection']) for p in recent]
            snapshot=cached_peer_snapshot(acc.id)
            online=None
            if snapshot is not None:
                ids=[int(key) for key,state in snapshot.items() if key.isdecimal() and len(key)<=18 and state.get('connection')=='online']
                online=sum(owned.with_entities(func.count(Ownership.id)).filter(Ownership.peer_id.in_(ids[n:n+500])).scalar()
                           for n in range(0,len(ids),500))
            return dict(timezone=zone_name(),peers=recent_peers,subscriptions=[],interfaces=[],
                stats=dict(peers=peers_count,subscriptions=subs_count,blocked=blocked,online=online),
                account=dict(operation_limits=effective(acc.spec),username=acc.username,
                    used_bytes=acc.used_bytes,limit_bytes=acc.spec['traffic_gib']*s.GIB,
                    peer_limit=acc.spec['peers'],subscription_limit=acc.spec['subscriptions'],
                    expires_at=acc.expires_at.isoformat()+'Z',active=s.active(acc)),
                history=[dict(at=x.at.isoformat()+'Z',bytes=x.used_bytes) for x in last_sample],
                notices=[],sample_at=s.setting('monitor_heartbeat'),permissions=acc.spec['permissions'])
        rows=Ownership.query.filter_by(account_id=acc.id,deleted=False).all()
        owned={r.peer_id:r for r in rows}
        peers=(Peer.query.options(joinedload(Peer.iface)).filter(Peer.id.in_(owned)).all() if owned else [])
        states=peer_states(peers,host,live=False,owner_account_id=acc.id)
        subscription_ids={r.subscription_id for r in rows if r.subscription_id}
        subscriptions_by_id={}
        if subscription_ids:
            memberships=Ownership.query.filter(Ownership.subscription_id.in_(subscription_ids),Ownership.deleted.is_(False)).all()
            members_by_sub={}
            for row in memberships:members_by_sub.setdefault(row.subscription_id,[]).append(row)
            subs=Subscription.query.options(selectinload(Subscription.links).joinedload(SubscriptionPeer.peer)).filter(Subscription.id.in_(subscription_ids)).all()
            for sub in subs:
                members=members_by_sub.get(sub.id,[])
                owned_ids={row.peer_id for row in members}
                if members and all(row.account_id==acc.id for row in members) and all(link.peer_id in owned_ids for link in sub.links):
                    subscriptions_by_id[sub.id]=sub


        sub_reasons={sid:m.reason(sub,acc) for sid,sub in subscriptions_by_id.items()}
        output=[]
        for p in peers:
            row=owned[p.id];state=states[p.id]
            allowed=(m.reason(p,acc) is None and (not row.subscription_id or
                     (row.subscription_id in subscriptions_by_id and sub_reasons[row.subscription_id] is None)))
            item=dict(id=p.id,**fields(p),iface_id=p.iface_id,iface=p.iface.name if p.iface else '',node_id=p.iface.node_id if p.iface else None,address=p.address,status=p.status,connection=state['connection'],rx=state['rx'],tx=state['tx'],subscription_id=row.subscription_id,blocked=not allowed,**{k:getattr(p,k,None) for k in m.NETWORK})
            output.append(item)
        subscriptions=[]
        children_by_subscription={}
        for row in rows:
            if row.subscription_id in subscriptions_by_id:
                children_by_subscription.setdefault(row.subscription_id,[]).append(row.peer_id)
        for sid,sub in sorted(subscriptions_by_id.items()):
            children=children_by_subscription.get(sid,[])
            subscriptions.append(dict(id=sub.id,**fields(sub),enabled=sub.enabled,reason=sub_reasons[sid],peer_ids=children))
        interfaces=[dict(id=i.id,name=i.name,node_id=i.node_id) for i in InterfaceConfig.query.filter(InterfaceConfig.id.in_(acc.spec['interfaces'])).all()]
        history=UsagePoint.query.filter(UsagePoint.account_id==acc.id,UsagePoint.generation==acc.generation,UsagePoint.at>=s.now()-timedelta(minutes=15)).order_by(UsagePoint.at).all() if section=='dashboard' else []
        notices=Notice.query.filter_by(account_id=acc.id).order_by(Notice.id.desc()).limit(20).all() if section=='dashboard' else []
        from .regional import zone_name
        return dict(timezone=zone_name(),peers=output,subscriptions=subscriptions,interfaces=interfaces,account=dict(operation_limits=effective(acc.spec),username=acc.username,used_bytes=acc.used_bytes,limit_bytes=acc.spec['traffic_gib']*s.GIB,peer_limit=acc.spec['peers'],subscription_limit=acc.spec['subscriptions'],expires_at=acc.expires_at.isoformat()+'Z',active=s.active(acc)),history=[dict(at=x.at.isoformat()+'Z',bytes=x.used_bytes) for x in history],notices=[dict(at=n.created_at.isoformat()+'Z',body=inbox_text(s.decrypt(n.body_enc))) for n in notices],sample_at=s.setting('monitor_heartbeat'),permissions=acc.spec['permissions'])

    @bp.post('/r/api/create/<kind>')
    @member('create')
    def workspace_create(kind):
        section={'peer':'peers','subscription':'subscriptions'}.get(kind)
        if not section:abort(404)
        permit(section,'create');data=request.get_json(silent=True)
        if not isinstance(data,dict):raise ValueError('Expected a JSON object.')
        count=s.integer(data,'count',1,50) if 'count' in data else 1
        attach=kind=='subscription' and data.get('existing_peers')
        acc=g.reseller
        if count>1 and 'bulk' not in acc.spec['permissions']:abort(403)
        ids=data.get('interfaces',[])
        if not isinstance(ids,list) or len(ids)>100 or any(type(i)!=int for i in ids):raise ValueError('Select allowed interfaces.')
        m.validate_options(acc,data)
        if attach:
            if 'attach_existing' not in acc.spec['permissions']:abort(403)
            peers=data['existing_peers']
            if not isinstance(peers,list) or not 1<=len(peers)<=50 or any(type(i)!=int for i in peers):raise ValueError('Select owned peers.')
            return submit_web(acc,dict(section=section,action='attach',peer_ids=peers,options=data),
                              validate=lambda:[m.target(acc,'peers',rid) for rid in peers])
        if not ids or any(i not in acc.spec['interfaces'] for i in ids):abort(403)
        return submit_web(acc,dict(section=section,action='create',interfaces=ids,options=data,count=count))

    @bp.post('/r/api/<section>/<int:rid>/<action>')
    @member()
    def workspace_change(section,rid,action):
        if section not in ('peers','subscriptions'):abort(404)
        if action not in ('edit','delete','enable','disable','rotate','reset_data','reset_timer'):abort(404)
        permission=GRANTS[action]
        permit(section,permission);data=request.get_json(silent=True) or {}
        if not isinstance(data,dict):raise ValueError('Expected a JSON object.')
        def validate():
            m.target(g.reseller,section,rid)
            if action=='edit':m.validate_options(g.reseller,data)
        return submit_web(g.reseller,dict(section=section,action=action,id=rid,options=data),validate=validate)

    @bp.post('/r/api/<section>/bulk/<action>')
    @member('bulk')
    def workspace_bulk(section,action):
        if section not in ('peers','subscriptions') or action not in ('enable','disable','delete'):abort(404)
        permission={'delete':'delete','enable':'control_access','disable':'control_access','rotate':'rotate_link'}.get(action,'edit');permit(section,permission)
        data=request.get_json(silent=True) or {};ids=data.get('ids') if isinstance(data,dict) else None
        if not isinstance(ids,list) or not 1<=len(ids)<=50 or any(type(x)!=int for x in ids):raise ValueError('Select 1–50 resources.')
        acc=g.reseller
        if 'bulk' not in acc.spec['permissions']:abort(403)
        ids=sorted(set(ids))
        return submit_web(acc,dict(section=section,action=action,ids=ids,options={}),
                          validate=lambda:[m.target(acc,section,rid) for rid in ids])

    @bp.get('/r/api/peers/<int:pid>/logs')
    @member('logs')
    def workspace_logs(pid):
        permit('peers')
        s.own_peer(g.reseller,pid)

        return {'events':[dict(at=e.timestamp.isoformat()+'Z',event=e.event) for e in PeerEvent.query.filter_by(peer_id=pid).order_by(PeerEvent.id.desc()).limit(100).all()]}

    @bp.get('/r/api/peers/<int:pid>/qr')
    @member('download')
    def workspace_qr(pid):
        if not {'peers','subscriptions'} & set(g.reseller.spec['permissions']):abort(403)
        s.require_active(g.reseller);row,p=s.own_peer(g.reseller,pid)
        if ('subscriptions' if row.subscription_id else 'peers') not in g.reseller.spec['permissions']:abort(403)
        import qrcode
        image=qrcode.make(host_get()['_client_conf_txt'](p), image_factory=PNGImage);buf=BytesIO();image.save(buf,format='PNG')
        return Response(buf.getvalue(),mimetype='image/png')

    @bp.get('/r/api/subscriptions/<int:sid>/link')
    @member('download')
    def workspace_link(sid):
        permit('subscriptions');s.require_active(g.reseller);sub,_=m.own_subscription(g.reseller,sid)
        return {'url':s.base_url()+'/s/'+sub.token}


    @bp.get('/r/api/interfaces/<int:iid>/addresses')
    @member('choose_address')
    def workspace_addresses(iid):
        permit('peers','create')
        if iid not in g.reseller.spec['interfaces']:abort(404)
        iface=db.session.get(InterfaceConfig,iid)
        if not iface:abort(404)
        host=host_get()
        if iface.node_id:
            from models import Node
            node=db.session.get(Node,iface.node_id)
            result=host['node_get'](node,'/api/iface/'+iface.name.split(':',1)[-1]+'/available_ips',timeout=8)
            values=result.get('available_ips',[]) if isinstance(result,dict) else result
        else:values=host['_available_ips'](iface)

        safe=[]
        for value in list(values or [])[:512]:
            try:safe.append(m.requested_address(iface,value))
            except ValueError:continue
        return {'addresses':safe}

    @bp.route('/r/api/profiles/<kind>',methods=['GET','POST'])
    @member('profiles')
    def workspace_profiles(kind):
        section={'peer':'peers','subscription':'subscriptions'}.get(kind)
        if not section:abort(404)
        acc=permit(section)
        if request.method=='GET':
            return {'profiles':[dict(id=p.id,name=p.name,options=p.options,is_default=p.is_default) for p in CustomerProfile.query.filter_by(account_id=acc.id,kind=kind).order_by(CustomerProfile.id).all()]}
        data=request.get_json(silent=True)
        if not isinstance(data,dict):raise ValueError('Expected a profile.')
        with settings_transaction():
            acc=fresh(section,'profiles',for_update=True);s.require_active(acc)
            options=data.get('options')
            if not isinstance(options,dict):raise ValueError('Expected profile settings.')
            name=str(data.get('name','')).strip()
            if not 1<=len(name)<=64 or any(ord(c)<32 for c in name):raise ValueError('Enter a profile name of 1–64 characters.')
            checked=m.validate_options(acc,{**options,'name':'Profile'})
            from .limits import profile_capacity
            profile_capacity(acc)
            keep=set(m.NETWORK)|{'data_limit_value','data_limit_unit','time_limit_days','start_on_first_use'}
            if 'network_options' not in acc.spec['permissions']:keep-=set(m.NETWORK)
            stored={k:v for k,v in checked.items() if k in keep}
            ids=options.get('interfaces',[])
            if not isinstance(ids,list) or any(type(i)!=int or i not in acc.spec['interfaces'] for i in ids):raise ValueError('Profile contains an unavailable interface.')
            stored['interfaces']=list(dict.fromkeys(ids))
            profile=CustomerProfile(account_id=acc.id,kind=kind,name=name,options=stored)
            db.session.add(profile);s.audit('reseller:'+str(acc.id),'profile_created',name)
        return {'ok':True},201

    @bp.post('/r/api/profiles/<kind>/<int:pid>/<action>')
    @member('profiles')
    def workspace_profile_action(kind,pid,action):
        section={'peer':'peers','subscription':'subscriptions'}.get(kind)
        if not section or action not in ('delete','default','rename'):abort(404)
        permit(section)
        with settings_transaction():
            acc=fresh(section,'profiles',for_update=True);s.require_active(acc)
            profile=CustomerProfile.query.filter_by(id=pid,account_id=acc.id,kind=kind).first()
            if not profile:abort(404)
            if action=='delete':db.session.delete(profile)
            elif action=='default':
                for p in CustomerProfile.query.filter_by(account_id=acc.id,kind=kind):p.is_default=p.id==pid
            else:
                data=request.get_json(silent=True) or {}
                if not isinstance(data,dict):raise ValueError('Expected a profile name.')
                name=str(data.get('name','')).strip()
                if not 1<=len(name)<=64 or any(ord(c)<32 for c in name):raise ValueError('Enter a valid profile name.')
                profile.name=name
            s.audit('reseller:'+str(acc.id),'profile_'+action,str(pid))
        return {'ok':True}

    @bp.get('/r/api/export/<section>')
    @member('export')
    def workspace_export(section):
        if section not in ('peers','subscriptions'):abort(404)
        permit(section)
        import csv,io
        buf=io.StringIO();writer=csv.writer(buf);writer.writerow(['ID','Name','Usage bytes','Expiry UTC'])
        rows=Ownership.query.filter_by(account_id=g.reseller.id,deleted=False).all()
        ids={r.peer_id if section=='peers' else r.subscription_id for r in rows}
        for rid in sorted(x for x in ids if x):
            try:item=db.session.get(Peer,rid) if section=='peers' else m.own_subscription(g.reseller,rid)[0]
            except ValueError:continue
            if not item:continue
            name=item.name or ''
            if name.lstrip().startswith(('=','+','-','@')):name="'"+name
            writer.writerow([rid,name,m.usage(item),item.expires_at.isoformat() if item.expires_at else ''])
        return Response(buf.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename="'+section+'.csv"'})


    @bp.get('/r/api/subscriptions/<int:sid>/logs')
    @member('logs')
    def workspace_subscription_logs(sid):
        permit('subscriptions');_,peers=m.own_subscription(g.reseller,sid)
        return {'events':[dict(at=e.timestamp.isoformat()+'Z',event=e.event) for e in PeerEvent.query.filter(PeerEvent.peer_id.in_([p.id for p in peers])).order_by(PeerEvent.id.desc()).limit(100).all()]}
