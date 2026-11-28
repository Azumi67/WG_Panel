import hashlib
import hmac
import re
import secrets
from datetime import timezone
from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for, Response
from flask_login import current_user
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import OperationalError
from models import db, Peer, InterfaceConfig, Subscription, SubscriptionPeer
from . import service as s
from .billing import uploaded_image
from .database import settings_transaction, SettingsWriterBusy, lock_application_key
from .models import Account, ManagementBot, Order, OrderReceipt, Ownership, Plan
from .regional import zone_name
from .telegram_policy import effective, FEATURES

api = Blueprint('bot_apps', __name__, url_prefix='/api/bot-apps')
ROLES = {'admin':'Panel admin', 'shop':'Plan shop', 'workspace':'Reseller workspace'}


def key_name(role, aid):
    return 'app_key:'+role+':'+str(aid)


APP_SCOPES = ('usage','peers','subscriptions','create','bulk','edit','control_access','delete','reset_data','reset_timer','rotate_link','download','notifications')


def app_policy(aid):
    value = s.setting('app_policy:workspace:'+str(aid), {})
    if not isinstance(value,dict): value={}
    scopes=value.get('scopes',[])
    return {'enabled':value.get('enabled') is True,'self_issue':value.get('self_issue') is True,
            'scopes':[k for k in APP_SCOPES if isinstance(scopes,list) and k in scopes]}


def app_grants(account, credential=None):
    policy=app_policy(account.id)
    grants=set(policy['scopes']) & effective(account) if policy['enabled'] else set()
    return grants if credential is None else grants & set(credential.get('scopes',[]))


def workspace_access(aid):
    account = db.session.get(Account, aid)
    if not account or not account.spec.get('panel_access') or not s.active(account) or not app_policy(aid)['enabled']:
        abort(403)
    return account


def require_app_grants(account,*scopes):
    if not set(scopes)<=app_grants(account,getattr(g,'named_credential',None)):abort(403)


def authorize():
    header = request.headers.get('Authorization','')
    match = re.fullmatch(r'Bearer (wgapp\.(admin|shop|workspace)\.(\d{1,18})\.(?:([a-f0-9]{10})\.)?[A-Za-z0-9_-]{43})',header)
    if not match:abort(401)
    key, role, raw_id, kid = match.groups()
    aid = int(raw_id)
    if (role == 'workspace') != (aid > 0) or raw_id != str(aid):abort(401)
    row=None
    if kid:
        from .application_credentials import credential, matches, role_scope
        row=credential(s,role,aid,kid)
        if not row or not isinstance(row.get('digest'),str) or not hmac.compare_digest(row['digest'],s.digest(key)):abort(401)
        if not matches(row,s.digest(key),getattr(request,'remote_addr',None)):abort(403)
        if role!='workspace' and role_scope(request.endpoint,request.method) not in row['scopes']:abort(403)
        saved=row['digest']
    else:
        saved = s.setting(key_name(role,aid))
        if not isinstance(saved,str) or not hmac.compare_digest(saved,s.digest(key)):abort(401)
    if request.path.split('/')[3] != role:abort(403)
    from panel_core.application_limits import limits_key, permits
    if not permits(s.setting(limits_key(role,aid)),getattr(request,'remote_addr',None)):abort(403)
    g.app_role, g.app_account_id = role, aid
    g.app_key_digest = saved
    g.named_credential, g.named_key_id = row, kid
    return workspace_access(aid) if role=='workspace' else None


@api.before_request
def authenticate():
    from . import HOST
    if not current_app.testing and not HOST['_is_https']():abort(403)
    account = authorize()
    from .request_guard import reserve
    if g.named_key_id:
        from .request_guard import reserve_named
        if not reserve_named(g.app_role,g.app_account_id,g.named_key_id,g.named_credential['rate']):abort(429)
    if account:
        from .limits import reserve_request
        allowed = reserve_request(account.id,request.method not in ('GET','HEAD'))
    else:
        allowed = reserve([('app:'+g.app_role,120,60)])
    if not allowed:abort(429)
    if request.method == 'POST':
        limit = 5*1024*1024+65536 if request.endpoint=='bot_apps.shop_receipt' else 32768
        if request.content_length is None:abort(411)
        if request.content_length > limit:abort(413)


@api.after_request
def private(response):
    response.headers['Cache-Control']='private, no-store'
    return response


@api.errorhandler(HTTPException)
def http_error(exc):
    return (jsonify(error=exc.name),exc.code,{'Retry-After':'60'}) if exc.code==429 else (jsonify(error=exc.name),exc.code)


@api.errorhandler(ValueError)
def invalid(exc):
    return jsonify(error=str(exc)),400


@api.errorhandler(SettingsWriterBusy)
def writer_busy(exc):
    return jsonify(error='Database writer unavailable. No change was started.'),503,{'Retry-After':'2'}


@api.errorhandler(OperationalError)
def database_error(exc):
    db.session.rollback()
    current_app.logger.warning('Application database request failed: %s',getattr(exc.orig,'sqlstate',None) or getattr(exc.orig,'pgcode',None) or type(exc).__name__)
    return jsonify(error='Database request could not be confirmed. Recover the operation by request ID before retrying.'),503,{'Retry-After':'2'}


def payload():
    data = request.get_json(silent=True) if request.is_json else request.form
    if not hasattr(data,'get'):abort(400)
    return data


def buyer(data):
    tid = str(data.get('buyer_id',''))
    if not re.fullmatch(r'[1-9]\d{0,18}',tid):raise ValueError('A private Telegram buyer ID is required.')
    return tid


def summary(order):
    return dict(id=order.id,plan=order.spec.get('plan_name') or str(order.plan_id),price=order.spec['price'],
                currency=order.spec['currency'],status='awaiting_review' if order.state=='pending' and order.payment_ref else order.state,
                created_at=order.created_at.replace(tzinfo=timezone.utc).isoformat())


@api.get('/admin/reviews')
def admin_reviews():
    query=Order.awaiting_review().filter(Order.id>max(0,request.args.get('after',0,type=int))).order_by(Order.id)
    return jsonify(items=[dict(summary(o),review_url=url_for('reseller.admin_page',tab='orders',order=o.id)) for o in query.limit(50)],timezone=zone_name())


@api.get('/shop/plans')
def shop_plans():
    from .billing import terms_key
    from .bot_ui import valid_payment
    plans=Plan.query.filter_by(active=True).filter(Plan.id>max(0,request.args.get('after',0,type=int))).order_by(Plan.id).limit(50)
    return jsonify(items=[dict(id=p.id,name=p.name,terms=terms_key(p),**{k:p.spec.get(k) for k in ('price','currency','days','traffic_gib','peers','subscriptions','payment_instructions')}) for p in plans if valid_payment(p.spec)])


@api.route('/shop/orders',methods=['GET','POST'])
def shop_orders():
    from .billing import terms_key
    if request.method in ('GET','HEAD'):
        query=s.buyer_orders(buyer(request.args)).filter(Order.id>max(0,request.args.get('after',0,type=int))).order_by(Order.id)
        return jsonify(items=[summary(o) for o in query.limit(50)])
    data=payload()
    tid=buyer(data)
    with settings_transaction():
        authorize()
        try:pid=int(data.get('plan_id'))
        except (ValueError,TypeError):raise ValueError('Choose a published plan.') from None
        plan=Plan.query.filter_by(id=pid,active=True).first_or_404()
        if data.get('terms')!=terms_key(plan):raise ValueError('The offer changed. Read its current terms and confirm the purchase.')
        order=s.order_new(tid,pid)
        if data.get('language') in ('en','fa'):s.put('bot_lang:'+tid,data['language'])
        result=summary(order)
    return jsonify(result)


@api.post('/shop/orders/<int:oid>/receipt')
def shop_receipt(oid):
    data=payload()
    tid=buyer(data)
    photo=request.files.get('photo')
    image=uploaded_image(photo) if photo and photo.filename else None
    reference=data.get('reference','')
    if not isinstance(reference,str) or bool(image)==bool(reference.strip()):
        raise ValueError('Submit one receipt photo or a payment reference.')
    if image:
        reference='upload:'+hashlib.sha256(image[0]).hexdigest()
        encrypted=s.cipher().encrypt(image[0])
    with settings_transaction():
        authorize()
        order=s.buyer_orders(tid).filter_by(id=oid).with_for_update().first_or_404()
        first=not order.payment_ref
        s.receipt(tid,oid,reference)
        if image and first:
            db.session.add(OrderReceipt(order_id=oid,mime=image[1],image_enc=encrypted))
            s.put('receipt_photo:'+str(oid),{'source':'workspace','caption':''})
        result=summary(order)
    return jsonify(result)


@api.get('/workspace/customers')
def workspace_customers():
    from models import Subscription
    account=workspace_access(g.app_account_id)
    kind=request.args.get('kind','peers')
    if kind not in ('peers','subscriptions') or kind not in app_grants(account,getattr(g,'named_credential',None)):abort(403)
    model=Peer if kind=='peers' else Subscription
    column=Ownership.peer_id if kind=='peers' else Ownership.subscription_id
    owned=db.session.query(column).filter(Ownership.account_id==account.id, Ownership.deleted.is_(False))
    if kind=='peers':owned=owned.filter(Ownership.subscription_id.is_(None))
    query=model.query.filter(model.id.in_(owned),model.id>max(0,request.args.get('after',0,type=int)))
    if kind=='subscriptions':
        from sqlalchemy.orm import aliased
        from sqlalchemy import exists, and_, select
        foreign=aliased(Ownership)
        child=aliased(SubscriptionPeer)
        link_owner=aliased(Ownership)
        foreign_exists=exists(select(foreign.id).where(foreign.subscription_id==Subscription.id,foreign.deleted.is_(False),foreign.account_id!=account.id))
        child_owner=exists(select(link_owner.id).where(link_owner.subscription_id==child.subscription_id,link_owner.peer_id==child.peer_id,link_owner.account_id==account.id,link_owner.deleted.is_(False)))
        missing=exists(select(child.id).where(child.subscription_id==Subscription.id,~child_owner))
        query=query.filter(~foreign_exists,~missing)
    rows=query.order_by(model.id).limit(50)
    return jsonify(account_id=account.id,items=[dict(id=r.id,name=r.name,enabled=r.status=='online' if kind=='peers' else bool(r.enabled)) for r in rows])


@api.get('/workspace/status')
def workspace_status():
    a=workspace_access(g.app_account_id)
    require_app_grants(a,'usage')
    peers,subs=s.counts(a)
    return jsonify(account_id=a.id,username=a.username,expires_at=a.expires_at.isoformat()+'Z',
        used_bytes=int(a.used_bytes or 0),traffic_gib=a.spec['traffic_gib'],peers=peers,
        peer_limit=a.spec['peers'],subscriptions=subs,subscription_limit=a.spec['subscriptions'],
        permissions=sorted(app_grants(a,getattr(g,'named_credential',None))))


@api.get('/workspace/interfaces')
def workspace_interfaces():
    a=workspace_access(g.app_account_id)
    if not app_grants(a,getattr(g,'named_credential',None))&{'peers','subscriptions'}:abort(403)
    rows=InterfaceConfig.query.filter(InterfaceConfig.id.in_(a.spec['interfaces'])).order_by(InterfaceConfig.id).all()
    return jsonify(items=[dict(id=i.id,name=i.name,remote=bool(i.node_id)) for i in rows])


@api.get('/workspace/customers/<any(peers,subscriptions):kind>/<int:rid>')
def workspace_customer(kind,rid):
    from .management import target
    a=workspace_access(g.app_account_id);require_app_grants(a,kind)
    obj,children=target(a,kind,rid)
    result=dict(id=obj.id,name=obj.name,enabled=obj.status=='online' if kind=='peers' else bool(obj.enabled),
        data_limit_value=obj.data_limit_value,data_limit_unit=obj.data_limit_unit,time_limit_days=obj.time_limit_days,
        start_on_first_use=bool(obj.start_on_first_use),expires_at=obj.expires_at.isoformat()+'Z' if obj.expires_at else None)
    if 'edit' in app_grants(a,getattr(g,'named_credential',None)):
        from .management import NETWORK
        result.update(phone_number=obj.phone_number,telegram_id=obj.telegram_id)
        if kind=='subscriptions':result['note']=obj.note
        if kind=='peers' and 'network_options' in a.spec['permissions']:
            result.update({k:getattr(obj,k,None) for k in NETWORK})
    return jsonify(result)


@api.get('/workspace/customers/peers/<int:rid>/<any(config,qr):format>')
def workspace_peer_export(rid,format):
    from . import HOST
    from .management import target
    from .bot_customers import export_peer
    a=workspace_access(g.app_account_id);require_app_grants(a,'peers','download')
    peer,_=target(a,'peers',rid)
    result=export_peer(peer,HOST,qr=format=='qr')
    return Response(result['document'],mimetype=result.get('mime','text/plain'),headers={
        'Content-Disposition':'attachment; filename="'+result['filename']+'"','X-Content-Type-Options':'nosniff'})


def app_submit(a,op,*,validate=None):
    from .provision_queue import enqueue,JobConflict
    key=request.headers.get('Idempotency-Key','')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',key):raise ValueError('Send an Idempotency-Key of 1–80 letters, numbers, underscores or hyphens.')
    digest=g.app_key_digest
    kid=getattr(g,'named_key_id',None)
    prefix='app:'
    if kid:
        from .application_credentials import credential, matches, request_prefix
        row=credential(s,'workspace',a.id,kid)
        if not matches(row,digest,request.remote_addr):abort(401)
        prefix=request_prefix(kid)
        op={**op,'application_key_id':kid}
    elif not digest or s.setting(key_name('workspace',a.id))!=digest:abort(401)
    op={**op,'application_key_digest':digest}
    try:result=enqueue(a,op,prefix+key,commit=True,validate=validate)
    except JobConflict as exc:
        db.session.rollback();return jsonify(error=str(exc)),409
    result['status_url']='/api/bot-apps/workspace/operations/'+result['id']
    return jsonify(ok=True,operation=result),202


@api.post('/workspace/customers/<any(peers,subscriptions):kind>')
def workspace_create(kind):
    from .management import validate_options,FIELDS,NETWORK
    a=workspace_access(g.app_account_id);require_app_grants(a,kind,'create')
    data=payload();ids=data.get('interfaces');count=data.get('count',1);options=data.get('options')
    if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(type(i) is not int for i in ids) or len(set(ids))!=len(ids):raise ValueError('Send unique integer interface IDs.')
    if not set(ids)<=set(a.spec['interfaces']):abort(403)
    if type(count) is not int or not 1<=count<=50 or (kind=='subscriptions' and count!=1) or (kind=='peers' and len(ids)!=1):raise ValueError('Invalid customer count or interfaces.')
    if count>1:require_app_grants(a,'bulk')
    if not isinstance(options,dict) or set(options)-set(FIELDS+NETWORK+('note','time_limit_hours','time_limit_minutes','address','start_index')):raise ValueError('Invalid customer options.')
    if options.get('address') and ('choose_address' not in a.spec['permissions'] or kind!='peers' or count!=1):abort(403)
    validate_options(a,options)
    return app_submit(a,dict(section=kind,action='create',interfaces=ids,options=options,count=count))


@api.post('/workspace/customers/<any(peers,subscriptions):kind>/<int:rid>/actions')
def workspace_action(kind,rid):
    from .management import target,validate_options,FIELDS,NETWORK
    from .provision_queue import GRANTS
    a=workspace_access(g.app_account_id);data=payload();action=data.get('action')
    if not isinstance(action,str) or action not in ('edit','enable','disable','delete','reset_data','reset_timer','rotate'):raise ValueError('Unsupported customer action.')
    if action=='rotate' and kind!='subscriptions':raise ValueError('Link rotation is for subscriptions only.')
    require_app_grants(a,kind,GRANTS[action])
    opts=data.get('options',{})
    if not isinstance(opts,dict):raise ValueError('Invalid options.')
    if action=='edit':
        if set(opts)-set(FIELDS+NETWORK+('note','time_limit_hours','time_limit_minutes')):raise ValueError('Invalid customer options.')
        if not {'name','data_limit_value','data_limit_unit','time_limit_days','start_on_first_use'}<=set(opts):raise ValueError('Send the complete customer settings for edit.')
    elif opts:raise ValueError('Options are supported only for edit.')
    def validate():
        target(a,kind,rid)
        if action=='edit':validate_options(a,opts)
    return app_submit(a,dict(section=kind,action=action,id=rid,options=opts),validate=validate)


@api.get('/workspace/customers/subscriptions/<int:rid>/link')
def workspace_subscription_link(rid):
    from .management import target
    a=workspace_access(g.app_account_id);require_app_grants(a,'subscriptions','download')
    sub,_=target(a,'subscriptions',rid)
    return jsonify(url=s.base_url()+'/s/'+sub.token)


def app_operation_response(a,job):
    from .provision_queue import serialize
    from .application_credentials import owns_request
    if not job or not owns_request(job.request_key,getattr(g,'named_key_id',None)):abort(404)
    require_app_grants(a,job.section)
    result=serialize(job);result['status_url']='/api/bot-apps/workspace/operations/'+job.id
    return jsonify(operation=result)


@api.get('/workspace/operations/<jid>')
def workspace_operation(jid):
    from .models import ProvisionJob
    a=workspace_access(g.app_account_id)
    if not re.fullmatch(r'[a-f0-9]{32}',jid):abort(404)
    return app_operation_response(a,ProvisionJob.query.filter_by(id=jid,account_id=a.id).first())


@api.get('/workspace/operations/by-request/<key>')
def workspace_operation_by_request(key):
    from .models import ProvisionJob
    a=workspace_access(g.app_account_id)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',key):abort(404)
    return app_operation_response(a,ProvisionJob.query.filter_by(account_id=a.id,request_key='app:'+((g.named_key_id+':') if getattr(g,'named_key_id',None) else '')+key).first())


@api.post('/workspace/customers/<any(peers,subscriptions):kind>/<int:rid>/access')
def customer_access(kind,rid):
    from .management import target
    value=payload().get('enabled')
    if type(value) is not bool:raise ValueError('Send enabled as a JSON boolean.')
    account=workspace_access(g.app_account_id)
    require_app_grants(account,kind,'control_access')
    return app_submit(account,dict(section=kind,action='enable' if value else 'disable',id=rid,options={}),
                      validate=lambda:target(account,kind,rid))


@api.post('/admin/reviews/<int:oid>/<any(approve,reject):action>')
def admin_decision(oid,action):
    from . import review_order
    def check():
        authorize()
        if not getattr(g,'named_key_id',None) and not s.setting('app_review_enabled',False):abort(403)
    check()
    data=payload()
    if data.get('verified') is not True and action=='approve':
        raise ValueError('Set verified to true after confirming payment.')
    note=data.get('note','')
    if not isinstance(note,str):raise ValueError('Enter a short review note.')
    form={'verified':'yes' if data.get('verified') is True else '', 'note':note,
          'verification_method':data.get('verification_method','manual'), 'verification_reference':data.get('verification_reference','')}
    review_order(oid,action,form,'admin application',recheck=check)
    return jsonify(summary(db.session.get(Order,oid)))


@api.post('/<any(admin,shop,workspace):role>/messages')
def send_message(role):
    from . import HOST
    from .worker import telegram
    from .telegram_policy import preferences
    from .regional import display
    from panel_core.telegram_notices import card, telegram_body
    from .request_guard import reserve
    data=payload()
    body=data.get('text')
    if not isinstance(body,str) or not 1<=len(body.strip())<=2000:raise ValueError('Send a text message of 1 to 2000 characters.')
    title={'admin':('Panel update','پیام پنل مدیریت'),'shop':('Order update','پیام سفارش'),'workspace':('Workspace update','پیام پنل نمایندگی')}[role]
    if role=='workspace':
        account=workspace_access(g.app_account_id)
        bot=db.session.get(ManagementBot,account.id)
        if not bot or not bot.approved or not bot.enabled or not bot.token_enc or not account.telegram_id or 'notifications' not in app_grants(account,getattr(g,'named_credential',None)) or not preferences(account)['enabled']:abort(403)
        token,chat,lang=s.decrypt(bot.token_enc),account.telegram_id,bot.language
    elif role=='shop':
        chat=buyer(data)
        try:oid=int(data.get('order_id'))
        except (TypeError,ValueError):raise ValueError('Supply the buyer’s order ID.') from None
        s.buyer_orders(chat).filter_by(id=oid).first_or_404()
        if not s.setting('bot_enabled') or not s.setting('bot_token'):abort(409)
        token,lang=s.decrypt(s.setting('bot_token')),s.setting('bot_lang:'+chat,'en')
    else:
        chat=buyer({'buyer_id':data.get('recipient_id','')})
        settings=HOST['_load_tg_settings']()
        if not settings.get('enabled') or not settings.get('bot_token'):abort(409)
        if chat not in {str(r.get('id')) for r in HOST['_load_tg_admins']() if not r.get('muted')}:abort(403)
        token,lang=settings['bot_token'],settings.get('language','en')
    if not reserve([('app-msg:'+role+':'+chat,10,60)]):abort(429)
    fa=lang=='fa'
    message=card(title[fa],[('زمان' if fa else 'Time',display(s.now()))],body.strip())
    db.session.rollback()
    try:telegram(token,'sendMessage',{'chat_id':chat,**telegram_body(message)})
    except RuntimeError:return jsonify(error='Telegram delivery was not confirmed. Check the chat before resending.'),502
    return jsonify(ok=True)


def register(bp,admin,member):
    def manage(role,aid,administrator=False):
        key=None
        name=key_name(role,aid)
        account=db.session.get(Account,aid) if aid else None
        if aid and not account:abort(404)
        if request.method=='POST':
            action=request.form.get('action')
            if action not in ('issue','revoke','policy','credential_policy','named_issue','named_rotate','named_revoke'):abort(400)
            with settings_transaction(wait_seconds=10):
                if aid:
                    account=db.session.get(Account,aid,with_for_update=True)
                    if not account:abort(404)
                    policy=app_policy(aid)
                    if not administrator and (not policy['enabled'] or not policy['self_issue']):abort(403)
                lock_application_key(name)
                from panel_core.application_limits import limits_key, parse_limits, permits
                if action.startswith('named_'):
                    from .application_credentials import issue,change,ROLE_SCOPES
                    if aid and action!='named_revoke':workspace_access(aid)
                    if not permits(s.setting(limits_key(role,aid)),check_ip=False) and action!='named_revoke':abort(403)
                    try:
                        if action=='named_issue':
                            key=issue(s,role,aid,request.form,app_grants(account) if aid else ROLE_SCOPES[role],administrator)
                        else:key=change(s,role,aid,request.form.get('kid',''),action)
                    except (ValueError,TypeError) as exc:abort(400,description=str(exc))
                elif action=='credential_policy':
                    if not administrator:abort(403)
                    try:limits=parse_limits(request.form.get('expires',''),request.form.get('networks',''))
                    except (ValueError,TypeError):abort(400,description='Invalid expiration or IP network list.')
                    
                    if s.setting(limits_key(role,aid))!=limits:
                        s.put(limits_key(role,aid),limits)
                        s.put(name,None)
                        s.put('app_named:'+role+':'+str(aid),{})
                        if role=='admin':s.put('app_review_enabled',False)
                elif action=='policy':
                    if not aid or not administrator:abort(403)
                    enabled=request.form.get('enabled')=='on'
                    s.put('app_policy:workspace:'+str(aid),dict(enabled=enabled,self_issue=enabled and request.form.get('self_issue')=='on',scopes=[k for k in APP_SCOPES if k in request.form.getlist('scopes')]))
                    if not enabled:
                        s.put(name,None)
                        s.put('app_named:'+role+':'+str(aid),{})
                else:
                    if aid and action=='issue':workspace_access(aid)
                    version=s.digest(s.setting(name) or '')
                    if request.form.get('version')!=version:return redirect(request.path,code=303)
                    if action=='issue':
                        if not permits(s.setting(limits_key(role,aid)),check_ip=False):abort(403,description='Application expiration must be updated before issuance.')
                        key=f'wgapp.{role}.{aid}.'+secrets.token_urlsafe(32)
                    s.put(name,s.digest(key) if key else None)
                    if role=='admin':s.put('app_review_enabled',bool(key and request.form.get('review')=='on'))
                actor=current_user.username if administrator else 'reseller:'+str(aid)
                detail=role+' '+str(aid)+' '+action
                if action.startswith('named_'):
                    detail+=' application='+ (key.split('.')[3] if key else request.form.get('kid','')[:10])
                s.audit(actor,'management_bot_app_key' if aid else 'bot_app_key',detail)
        account=db.session.get(Account,aid) if aid else None
        from panel_core.application_limits import limits_key, permits
        credential_limits=s.setting(limits_key(role,aid))
        named=s.setting('app_named:'+role+':'+str(aid),{}) or {}
        named_rows=[]
        if named:
            from .application_credentials import registry, matches
            from .request_guard import named_statistics
            named_rows=[dict(id=k,label=v['label'],scopes=v['scopes'],limits=v['limits'],rate=v['rate'],active=matches(v,v['digest'],check_ip=False) and permits(credential_limits,check_ip=False) and (not aid or app_policy(aid)['enabled']),**named_statistics(role,aid,k)) for k,v in registry(s,role,aid).items() if isinstance(v,dict) and {'label','scopes','limits','rate','digest'}<=v.keys()]
        policy=app_policy(aid) if aid else {}
        directory=[];page=1;pages=1;search=''
        if role=='admin':
            page=max(1,request.args.get('page',1,type=int));search=request.args.get('q','').strip()[:80]
            query=Account.query
            if search:query=query.filter(Account.username.ilike('%'+search+'%'))
            pages=max(1,(query.count()+19)//20);page=min(page,pages)
            accounts=query.order_by(Account.id).offset((page-1)*20).limit(20).all()
            values=s.settings_many([key_name('workspace',a.id) for a in accounts]+['app_policy:workspace:'+str(a.id) for a in accounts]+['app_named:workspace:'+str(a.id) for a in accounts])
            directory=[dict(id=a.id,username=a.username,enabled=isinstance(values.get('app_policy:workspace:'+str(a.id)),dict) and values['app_policy:workspace:'+str(a.id)].get('enabled') is True,connected=bool(values.get(key_name('workspace',a.id)) or values.get('app_named:workspace:'+str(a.id)))) for a in accounts]
        admin_shell=administrator and role in ('admin','workspace')
        bot=db.session.get(ManagementBot,aid) if aid and not administrator else None
        response=current_app.make_response(render_template('settings.html' if admin_shell else 'reseller/bot_application.html',
            telegram_application_shell=admin_shell,bot_tab_available=bool(bot and bot.approved),bot_tab_grants=effective(account) if bot and bot.approved else set(),
            role=role,label=ROLES[role],credential=key,connected=bool(s.setting(name)),credential_limits=credential_limits if isinstance(credential_limits,dict) else {},credential_expired=not permits(credential_limits,check_ip=False),version=s.digest(s.setting(name) or ''),review_enabled=bool(s.setting('app_review_enabled')) if role=='admin' else False,
            reseller_mode=bool(aid and not administrator),account=account if aid and not administrator else None,managed_account=account if administrator else None,
            administrator=administrator,policy=policy,scope_choices=[(k,FEATURES[k]) for k in APP_SCOPES],grants=app_grants(account) if account else set(),
            named_rows=named_rows,named_connected=any(row['active'] for row in named_rows),directory=directory,page=page,pages=pages,search=search,section='bot',HAS_SETTINGS=administrator,HAS_NODES=administrator and 'nodes' in current_app.view_functions))
        response.headers['Cache-Control']='private, no-store'
        return response

    @bp.route('/resellers/bot-applications/<any(admin,shop):role>',methods=['GET','POST'])
    @admin
    def admin_app_key(role):
        return manage(role,0,True)

    @bp.route('/resellers/bot-applications/workspaces/<int:aid>',methods=['GET','POST'])
    @admin
    def admin_workspace_app_key(aid):
        return manage('workspace',aid,True)

    @bp.route('/r/bot-application',methods=['GET','POST'])
    @member()
    def workspace_app_key():
        return manage('workspace',g.reseller.id)
