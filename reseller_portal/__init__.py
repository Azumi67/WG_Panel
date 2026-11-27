
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
import time
import secrets
import re
from flask import Blueprint, abort, current_app, g, redirect, render_template, request, session, url_for, flash, Response, jsonify
from flask_wtf.csrf import CSRFError
from flask_login import current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import inspect, or_, cast, String, func, text
from sqlalchemy.exc import OperationalError
from models import db, Peer, Subscription, InterfaceConfig
from .models import Plan, Account, Order, Ownership, Notice, Audit, AccountSecurity, PaymentVerification
from . import service as s
from .health import setup_status
from .database import SettingsWriterBusy, settings_transaction
from .notices import account_notice
from . import renewal

bp = Blueprint('reseller', __name__, template_folder='templates',static_folder='static',static_url_path='/reseller-assets')

def _request_stage(name):
    now=time.perf_counter()
    previous=getattr(g,'_rp_stage',None)
    started=getattr(g,'_rp_stage_started',None)
    if previous and started is not None:
        timings=getattr(g,'_rp_timings',{})
        timings[previous]=timings.get(previous,0)+(now-started)*1000
        g._rp_timings=timings
    g._rp_stage=name
    g._rp_stage_started=now

@bp.before_request
def _admin_page_start():
    if request.endpoint!='reseller.static':
        g._rp_started=getattr(g,'_rp_started',time.perf_counter())

@bp.after_request
def _admin_page_timing(response):
    started=getattr(g,'_rp_started',None)
    if started is not None:
        _request_stage('complete')
        elapsed=(time.perf_counter()-started)*1000
        values=['rp-route;dur=%.1f' % elapsed]
        values.extend('rp-%s;dur=%.1f' % (name,duration)
                      for name,duration in getattr(g,'_rp_timings',{}).items())
        previous=response.headers.get('Server-Timing')
        response.headers['Server-Timing']=', '.join(([previous] if previous else [])+values)
        if elapsed>=1000:
            current_app.logger.warning('Reseller slow request endpoint=%s method=%s status=%s duration_ms=%.1f stages=%s',
                request.endpoint,request.method,response.status_code,elapsed,
                ','.join('%s:%.1f' % item for item in getattr(g,'_rp_timings',{}).items()))
    return response
HOST = None

@bp.app_template_filter('rp_inventory_access')
def inventory_access_filter(peer,ownership,account):
    from .presentation import inventory_access
    return inventory_access(peer,ownership,account)

@bp.app_template_filter('rp_datetime')
def display_datetime(value):
    from .regional import display
    from .regional import human
    return human(value)

@bp.app_template_filter('rp_time')
def time_element(value):
    from .regional import time_html
    return time_html(value)

def admin(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if (not current_user.is_authenticated and not session.get('rp_id') and request.method == 'GET'
                and request.endpoint == 'reseller.admin_page' and request.args.get('tab') == 'orders'
                and request.args.get('order', type=int)):
            target = url_for('reseller.admin_page', tab='orders', order=request.args.get('order', type=int))
            return redirect(url_for('login', next=target))
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False) or session.get('rp_id'): abort(403)
        viewer = request.headers.get('X-Panel-Viewer')
        if viewer and viewer != str(current_user.get_id()):abort(409)
        return fn(*a, **kw)
    return wrapped

WORKSPACE_PAGES = {'reseller.portal', 'reseller.billing', 'reseller.reseller_security',
                   'reseller.reseller_backup_page', 'reseller.activity', 'reseller.management_bot_settings', 'reseller.operations','reseller.workspace_app_key'}
BILLING_ENDPOINTS = {'reseller.billing', 'reseller.billing_order', 'reseller.billing_action',
                     'reseller.billing_photo', 'reseller.billing_status'}


def workspace_page():
    return (request.method in ('GET', 'HEAD') and request.endpoint in WORKSPACE_PAGES
            and request.accept_mimetypes.best != 'application/json')


def signed_out(account):
    if not workspace_page():
        return {'error':'Sign in to your workspace again.', 'code':'sign_in_required'}, 401
    if (account and account.state == 'active' and account.spec.get('panel_access')
            and secrets.compare_digest(session.get('rp_entry', ''), account.link_hash)):
        return redirect(url_for('reseller.login', token=s.decrypt(account.link_enc)))
    g.reseller_error = True
    return render_template('reseller/error.html', title='Sign in to your workspace',
                           message='Open your saved private sign-in link or choose Open workspace in your Telegram bot.',
                           recovery_url=None), 401


def landing(account):
    if account.expires_at > s.now():
        for section in ('dashboard', 'peers', 'subscriptions'):
            if section in account.spec.get('permissions', ()):
                return url_for('reseller.portal', section=section)
    return url_for('reseller.billing')


def member(permission=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            def serve_member():
                _request_stage('account-read')
                acc = db.session.get(Account, session.get('rp_id')) if session.get('rp_id') else None
                if not acc or session.get('rp_version') != acc.session_version or not session.get('rp_until') or session['rp_until'] < s.now().timestamp():
                    return signed_out(acc)
                if acc.state != 'active' or not acc.spec.get('panel_access'): abort(403)
                if acc.expires_at <= s.now() and request.endpoint not in BILLING_ENDPOINTS | {'reseller.operations','reseller.operation_status','reseller.operation_by_request'}:
                    if workspace_page():
                        return redirect(url_for('reseller.billing'))
                    return {'error':'Your plan has expired. Renew in My plan.', 'code':'plan_expired',
                            'billing_url':url_for('reseller.billing')}, 403
                if not session.get('rp_entry'):
                    session['rp_entry'] = acc.link_hash
                if permission and permission not in acc.spec['permissions']: abort(403)
                expected=request.headers.get('X-Reseller-Account') or request.form.get('rp_expected_account')
                if expected and expected!=str(acc.id):return {'error':'The signed-in account changed. Reload this tab before continuing.'},409
                from .limits import reserve_request
                _request_stage('request-budget')
                if not reserve_request(acc.id,request.method not in ('GET','HEAD','OPTIONS')):
                    return {'error':'Workspace request limit reached. Wait one minute and try again.'},429,{'Retry-After':'60'}

                if acc.state!='active' or not acc.spec.get('panel_access') or session.get('rp_version')!=acc.session_version:abort(403)
                if permission and permission not in acc.spec['permissions']:abort(403)
                g.reseller = acc
                _request_stage('handler')
                return fn(*a, **kw)


            if request.method in ('GET','HEAD'):
                started=time.perf_counter()
                for attempt in range(3):
                    try:
                        response=current_app.make_response(serve_member())


                        response.headers['Server-Timing']='reseller;dur=%.1f' % ((time.perf_counter()-started)*1000)
                        return response
                    except (OperationalError, TimeoutError) as exc:
                        if isinstance(exc, OperationalError) and not any(word in str(getattr(exc,'orig',exc)).lower() for word in ('locked','busy')):raise
                        if attempt==2:raise
                        db.session.rollback()
                        time.sleep((.10,.25)[attempt])
            return serve_member()
        return wrapped
    return decorator

def redirect_admin(tab='accounts'): return redirect(url_for('reseller.admin_page', tab=tab))
def account_data(acc, batch=None):


    pc, sc = batch.get(acc.id, (0, 0)) if batch is not None else s.counts(acc)
    try: account_url=s.link(acc)
    except Exception: account_url=None
    from .models import ManagementBot
    from .network_policy import get
    from .telegram_policy import configured
    owned=Ownership.query.filter_by(account_id=acc.id,deleted=False).order_by(Ownership.id.desc()).limit(8).all()
    twofa=db.session.get(AccountSecurity,acc.id)
    from .management_bot import connection_status
    return dict(management_connection=connection_status(acc,db.session.get(ManagementBot,acc.id)),twofa_enabled=bool(twofa and twofa.totp_secret_enc),telegram_features=configured(acc),subscription_names={sub.id:sub.name for sub in Subscription.query.filter(Subscription.id.in_([x.subscription_id for x in owned if x.subscription_id])).all()},network_policy=get(acc),management_bot=db.session.get(ManagementBot,acc.id),account=acc, peers=pc, subscriptions=sc, url=account_url, resource_count=pc, resources=[(r,db.session.get(Peer,r.peer_id)) for r in owned])

@bp.route('/resellers/resource-visibility',methods=['GET','POST'])
@admin
def resource_visibility():
    key='admin_resource_visibility:'+str(current_user.id)
    from .presentation import resource_mode
    if request.method=='POST':
        data=request.get_json(silent=True)
        if not isinstance(data,dict):abort(400)
        if 'mode' in data:
            if data['mode'] not in ('admin','resellers','all'):abort(400)
            mode=data['mode']
        elif type(data.get('show')) is bool:
            mode=resource_mode(data['show'])
        else:abort(400)
        with settings_transaction():s.put(key,mode)
    mode=resource_mode(s.setting(key,True))
    return {'mode':mode,'show':mode!='admin'}

@bp.app_template_filter('rp_actor')
def display_actor(value):
    kind,_,ident=str(value).partition(':')
    account=None
    if kind=='reseller' and ident.isdigit():account=db.session.get(Account,int(ident))
    elif kind=='telegram':account=Account.query.filter_by(telegram_id=ident).first()
    return f'{account.username} · R-{account.id} ({value})' if account else value

@bp.app_template_filter('rp_audit_details')
def display_audit_details(event):
    match=re.search(r'account=(\d+)',event.details or '')
    ident=match.group(1) if match else (event.details if event.action.startswith('account_') and str(event.details).isdigit() else None)
    account=db.session.get(Account,int(ident)) if ident else None
    return f'{account.username} · R-{account.id} — {event.details}' if account else event.details

@bp.app_template_filter('rp_payment_ready')
def payment_ready(spec):
    from .bot_ui import valid_payment
    return valid_payment(spec)

def page_query(query, per_page=None):
    size=request.args.get('per_page',15,type=int) if per_page is None else per_page
    if size not in (5,8,12,15,20,50):size=15
    total=query.count();pages=max(1,(total+size-1)//size)
    page=min(max(1,request.args.get('page',1,type=int) or 1),pages)
    return query.offset((page-1)*size).limit(size).all(),dict(page=page,pages=pages,total=total,per_page=size,start=(page-1)*size+1 if total else 0,end=min(page*size,total))

@bp.get('/resellers')
@admin
def admin_page():
    tab='plans' if request.endpoint in ('reseller.plan_save','reseller.plan_update','reseller.plan_payment') else request.args.get('tab','accounts')
    if tab not in ('accounts','plans','orders','bot','audit'):tab='accounts'

    setting_keys=('public_url','bot_enabled','bot_username','monitor_heartbeat',
                  'bot_error','enforcement_error','bot_check_at',
                  'bot_check_result','bot_welcome','bot_welcome_fa','bot_support','bot_support_fa',
                  'monitor_failed_count','monitor_last_healthy_at','bot_poll_at','bot_token')
    settings_snapshot=s.settings_many(setting_keys)

    health=setup_status(check_links=(tab=='bot'),settings=settings_snapshot,include_counts=(tab=='bot'))
    q=request.args.get('q','').strip()[:120];status=request.args.get('status','')
    pattern='%'+q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
    model={'accounts':Account,'plans':Plan,'orders':Order,'bot':Notice,'audit':Audit}[tab]
    query=Plan.catalog() if tab=='plans' else Account.query.filter(Account.state!='deleted') if tab=='accounts' else model.query
    if request.endpoint=='reseller.plan_update':query=query.filter(Plan.id==request.view_args['pid'])
    columns={'accounts':[Account.username,Account.telegram_id,Account.note], 'plans':[Plan.name,cast(Plan.spec,String)], 'orders':[Order.telegram_id,Order.payment_ref,cast(Order.id,String)], 'bot':[Notice.telegram_id,cast(Notice.account_id,String)], 'audit':[Audit.actor,Audit.action,Audit.details]}[tab]
    if q:
        matches=[column.ilike(pattern,escape='\\') for column in columns]
        if tab=='bot':matches.append(Notice.account_id.in_(db.session.query(Account.id).filter(Account.username.ilike(pattern,escape='\\'))))
        if tab=='audit':
            ids=[str(row.id) for row in Account.query.filter(Account.username.ilike(pattern,escape='\\')).all()]
            matches.append(Audit.actor.in_(['reseller:'+ident for ident in ids]))
        query=query.filter(or_(*matches))
    if tab=='accounts' and status in ('active','suspended'):query=query.filter_by(state=status)
    if tab=='plans' and status in ('published','hidden'):query=query.filter_by(active=status=='published')
    if tab == 'orders':
        selected_order = request.args.get('order', type=int)
        if selected_order is not None:
            query = query.filter(Order.id == selected_order)
        if status in ('pending', 'approved', 'rejected', 'cancelled'):
            query = query.filter_by(state=status)
        elif status in ('review', 'unpaid'):
            query = query.filter_by(state='pending').filter(
                Order.payment_ref.isnot(None) if status == 'review' else Order.payment_ref.is_(None))
    if tab=='bot':
        if status=='sent':query=query.filter(Notice.sent_at.isnot(None))
        elif status=='queued':query=query.filter(Notice.sent_at.is_(None),Notice.error.is_(None),Notice.telegram_id.isnot(None))
        elif status=='retry':query=query.filter(Notice.sent_at.is_(None),Notice.error.isnot(None),Notice.telegram_id.isnot(None))
        elif status=='failed':query=query.filter(Notice.sent_at.is_(None),Notice.error.isnot(None),Notice.telegram_id.is_(None))
    items,pager=page_query(query.order_by(model.id.desc()))
    count_batch={}
    if tab=='accounts' and items:
        ids=[a.id for a in items]
        count_batch={aid:(total,subscriptions) for aid,total,subscriptions in
            db.session.query(Ownership.account_id,func.count(Ownership.id),
                             func.count(func.distinct(Ownership.subscription_id)))
                .filter(Ownership.account_id.in_(ids),Ownership.deleted.is_(False))
                .group_by(Ownership.account_id).all()}


    orders=items if tab=='orders' else []
    photo_keys = s.settings_many('receipt_photo:'+str(o.id) for o in orders)
    if tab=='bot':
        names={str(n.account_id) for n in items if n.account_id is not None}
        all_accounts=(Account.query.with_entities(Account.id,Account.username,Account.telegram_id)
                      .filter(Account.id.in_([int(aid) for aid in names])).all() if names else [])
    elif orders:
        all_accounts=(Account.query.with_entities(Account.id,Account.username,Account.telegram_id)
                      .filter(or_(Account.id.in_([o.account_id for o in orders if o.account_id]),
                                  Account.telegram_id.in_([o.telegram_id for o in orders if o.telegram_id]))).all())
    else:
        all_accounts=[]
    return render_template('reseller/admin.html',accounts=[dict(account=a,peers=count_batch.get(a.id,(0,0))[0],subscriptions=count_batch.get(a.id,(0,0))[1]) for a in items] if tab=='accounts' else [],
        plans=items if tab=='plans' else [],available_plans=Plan.catalog().order_by(Plan.id.desc()).all() if tab=='accounts' else [],orders=orders,
        account_count=Account.query.filter(Account.state!='deleted').count() if tab=='accounts' else 0,
        pending_count=Order.awaiting_review().count() if tab=='accounts' else 0,
        interfaces=InterfaceConfig.query.all() if tab in ('accounts','plans') else [],permissions=s.PERMISSIONS,
        settings=settings_snapshot,
        health=health,form=request.form,token_set=bool(settings_snapshot.get('bot_token')),configured=health['accounts_ready'],
        account_names={str(a.id):a.username for a in all_accounts},telegram_accounts={a.telegram_id:a for a in all_accounts if a.telegram_id}, order_accounts={a.id:a for a in all_accounts},
        audit=items if tab=='audit' else [],notices=items if tab=='bot' else [],
        receipt_photos={o.id:photo_keys.get('receipt_photo:'+str(o.id)) for o in orders},
        payment_verifications={v.order_id:v for v in PaymentVerification.query.filter(PaymentVerification.order_id.in_([o.id for o in orders])).all()} if orders else {},
        tab=tab,q=q,status=status,pager=pager,log_total=pager['total'],log_page=pager['page'],log_pages=pager['pages'])

@bp.errorhandler(SettingsWriterBusy)
def settings_writer_busy(exc):
    if request.headers.get('X-Requested-With') == 'reseller-account':
        return jsonify(code='waiting_for_writer', error='Waiting for the current save to finish.'), 503, {'Retry-After':'1'}
    return operation_busy(exc)


@bp.after_request
def account_save_fragment(response):
    if request.method=='POST' and response.status_code in (302,303) and request.headers.get('X-Requested-With')=='reseller-account' and request.endpoint in ('reseller.account_action','reseller.account_network','reseller.management_bot_approval'):
        if request.headers.get('Accept') == 'application/json' and (request.endpoint != 'reseller.account_action' or request.view_args.get('action') in ('limits','permissions')):
            from flask import get_flashed_messages
            messages = get_flashed_messages(category_filter=['success'])
            return jsonify(ok=True, message=messages[-1] if messages else 'Changes saved.')
        account=db.session.get(Account,(request.view_args or {}).get('aid'))
        if account:return Response(render_template('reseller/account_fragment.html',row=account_data(account)),mimetype='text/html')
    return response

@bp.get('/resellers/plans/<int:pid>/dialog')
@admin
def plan_dialog_fragment(pid):


    p=db.session.get(Plan,pid)
    if p is None or p.spec.get('retired'):abort(404)
    response=Response(render_template('reseller/plan_dialog_fragment.html',p=p,
                                      interfaces=InterfaceConfig.query.all(),
                                      permissions=s.PERMISSIONS),mimetype='text/html')
    response.headers['Cache-Control']='private, no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    return response

@bp.get('/resellers/accounts/<int:aid>/dialog')
@admin
def account_dialog_fragment(aid):


    account=db.session.get(Account,aid)
    if account is None or account.state=='deleted':abort(404)
    response=Response(render_template('reseller/account_dialog_fragment.html',
                                     row=account_data(account)),mimetype='text/html')
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    return response

@bp.get('/resellers/accounts/<int:aid>/resources')
@admin
def account_resources(aid):
    account=db.session.get(Account,aid) or abort(404)
    if account.state=='deleted':abort(404)
    query=Ownership.query.join(Peer,Peer.id==Ownership.peer_id).filter(Ownership.account_id==aid,Ownership.deleted==False)
    q=request.args.get('q','').strip()[:100];status=request.args.get('status','')
    if q:query=query.filter(Peer.name.ilike('%'+q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%',escape='\\'))
    if status=='blocked':query=query.filter(Ownership.blocked==True)
    elif status=='paused':query=query.filter(Ownership.blocked==False,Peer.status!='online')
    elif status=='enabled':query=query.filter(Ownership.blocked==False,Peer.status=='online')
    elif status=='expired':query=query.filter(Peer.expires_at<=s.now())
    items,pager=page_query(query.order_by(Ownership.id.desc()),per_page=8)
    return render_template('reseller/resources.html',a=account,resources=[(row,db.session.get(Peer,row.peer_id)) for row in items],subscription_names={sub.id:sub.name for sub in Subscription.query.filter(Subscription.id.in_([row.subscription_id for row in items if row.subscription_id])).all()},resource_pager=pager)

@bp.post('/resellers/accounts/<int:aid>/network')
@admin
def account_network(aid):
    from .network_policy import validate
    policy=validate(request.form)
    with settings_transaction(wait_seconds=10):
        account=db.session.get(Account,aid)
        if not account or account.state=='deleted':abort(404)
        renewal.remember(account, network_policy=policy)
        s.put('network_policy:'+str(aid),policy)
        if request.form.get('apply_existing')=='on' and policy['endpoint']:
            for row in Ownership.query.filter_by(account_id=aid,deleted=False):
                peer=db.session.get(Peer,row.peer_id)
                if peer:peer.endpoint=policy['endpoint']
        s.audit(current_user.username,'account_network','account='+str(aid))
    flash('Connection settings saved. Customers must import updated configurations to use a changed endpoint.','success')
    return redirect(url_for('reseller.admin_page'),code=303)

@bp.route('/r/api/notifications',methods=['GET','POST'])
@member()
def notifications():
    import json
    from .database import settings_transaction
    from .regional import parse, zone_name
    aid=g.reseller.id;key='notice_read:'+str(aid)
    owned=Notice.query.filter_by(account_id=aid)
    from .inbox import seen_ids, mark_seen
    viewer = 'reseller:'+str(aid)
    def unread_count():
        return owned.filter(Notice.id > int(s.setting(key,0)), ~Notice.id.in_(seen_ids(viewer))).count()
    if request.method=='POST':
        data=request.get_json(silent=True)
        if not isinstance(data, dict):abort(400)
        with settings_transaction():
            if 'ids' in data:
                mark_seen(viewer, owned.with_entities(Notice.id), data['ids'])
            else:
                cursor=data.get('through')
                if type(cursor) is not int or not 0 <= cursor <= 2**63-1:abort(400)
                last=owned.filter(Notice.id<=cursor).order_by(Notice.id.desc()).first()
                if last:
                    from .models import InboxRead
                    s.put(key,max(int(s.setting(key,0)),last.id))
                    InboxRead.query.filter(InboxRead.viewer==viewer,InboxRead.item_id<=last.id).delete(synchronize_session=False)
        return {'ok':True, 'unread':unread_count()}
    if request.args.get('summary') == '1':
        return {'unread':unread_count()}
    read=int(s.setting(key,0));rows,pager=page_query(owned.order_by(Notice.id.desc()),per_page=8)
    from .models import InboxRead
    seen = {i for i, in seen_ids(viewer).filter(InboxRead.item_id.in_([n.id for n in rows]))}
    items=[]
    for n in rows:
        try:
            from panel_core.telegram_notices import inbox_text
            body=inbox_text(s.decrypt(n.body_enc))
        except Exception:body='Message unavailable.'
        kind='expiry' if 'expiry:' in n.dedupe else 'usage' if 'usage:' in n.dedupe or 'traffic:' in n.dedupe else 'admin'
        items.append(dict(id=n.id,body=body,kind=kind,at=parse(n.created_at).isoformat(),unread=n.id>read and n.id not in seen))
    latest=owned.order_by(Notice.id.desc()).first()
    return {'items':items,'pager':pager,'unread':unread_count(),'latest':latest.id if latest else 0,'timezone':zone_name()},200,{'Cache-Control':'no-store'}

@bp.get('/r/activity')
@member('logs')
def activity():
    from models import PeerEvent
    view='customers' if request.args.get('view')=='customers' else 'activity'
    q=request.args.get('q','').strip()[:80]
    pattern='%'+q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
    if view=='customers':
        grants=g.reseller.spec['permissions']
        query=db.session.query(PeerEvent,Peer).join(Peer,Peer.id==PeerEvent.peer_id).join(Ownership,Ownership.peer_id==Peer.id).filter(Ownership.account_id==g.reseller.id,Ownership.deleted.is_(False))
        scopes=[]
        if 'peers' in grants:scopes.append(Ownership.subscription_id.is_(None))
        if 'subscriptions' in grants:scopes.append(Ownership.subscription_id.isnot(None))
        query=query.filter(or_(*scopes) if scopes else False)
        if q:query=query.filter(or_(PeerEvent.event.ilike(pattern,escape='\\'),Peer.name.ilike(pattern,escape='\\')))
        items,pager=page_query(query.order_by(PeerEvent.id.desc()))

        rows=[dict(at=e.timestamp,action=e.event,details=f'{p.name} · Peer #{p.id}') for e,p in items]
    else:
        query=Audit.query.filter_by(actor='reseller:'+str(g.reseller.id))
        if q:query=query.filter(or_(Audit.action.ilike(pattern,escape='\\'),Audit.details.ilike(pattern,escape='\\')))
        rows,pager=page_query(query.order_by(Audit.id.desc()))
    return render_template('reseller/activity.html',events=rows,pager=pager,q=q,view=view,account=g.reseller,reseller_mode=True,section='logs',HAS_NODES=False,HAS_SETTINGS=False)

@bp.get('/resellers/health')
@admin
def health_status():
    from .health import heartbeat, monitor_status, service_status
    state = s.settings_many(('monitor_heartbeat',
                             'monitor_failed_count','enforcement_error','bot_poll_at'))
    result = {name:service_status(name) for name in ('worker','shop_worker','provision')}
    result['telegram']=heartbeat(state.get('bot_poll_at'))
    result['monitor'] = monitor_status(state)
    return result, 200, {'Cache-Control':'no-store'}

@bp.post('/resellers/settings')
@admin
def settings_save():


    from .database import settings_transaction
    from .worker import interactive_notice
    def retire_replies():
        Notice.query.filter(interactive_notice(),Notice.sent_at.is_(None)).update({Notice.telegram_id:None,Notice.error:'Bot connection changed.'},synchronize_session=False)
    messages_only=request.form.get('settings_section')=='messages'
    if request.form.get('settings_section') == 'disconnect':
        with settings_transaction():
            retire_replies()
            for key in ('bot_token', 'bot_username', 'bot_poll_at', 'bot_check_result', 'bot_check_at', 'bot_error'):
                s.put(key, None)
            s.put('bot_enabled', False)
            s.put('bot_offset', 0)
            s.audit(current_user.username, 'sales_bot_disconnected', 'Plan shop token removed')
        flash('Plan shop bot disconnected.', 'success')
        return redirect_admin('bot')
    with settings_transaction():
        s.cipher()
        if request.form.get('settings_section')!='messages':
            s.put('public_url',request.form.get('public_url','').strip().rstrip('/')); db.session.flush(); s.base_url()
        token='' if messages_only else request.form.get('bot_token','').strip()
        if token:
            if not re.fullmatch(r'\d{5,20}:[A-Za-z0-9_-]{20,100}',token): raise ValueError('Invalid Telegram bot token format.')
            from .management_bot import check_unique
            check_unique(token.split(':',1)[0],None,HOST,exclude_sales=True)
            previous=s.setting('bot_token')
            if not previous or s.decrypt(previous)!=token:
                retire_replies()
                s.put('bot_token',s.encrypt(token)); s.put('bot_offset',0)
                s.put('bot_username',None); s.put('bot_poll_at',None)
                s.put('bot_check_result',None)
        for key,limit in [('bot_welcome',800),('bot_welcome_fa',800),('bot_support',300),('bot_support_fa',300)]:
            if key in request.form:s.put(key,request.form.get(key,'').strip()[:limit])
        if not messages_only:
            enabled = request.form.get('bot_enabled') == 'on'
            if enabled and not s.setting('bot_token'):
                raise ValueError('Enter a BotFather token to enable the Plan shop bot.')
            s.put('bot_enabled', enabled)
        s.audit(current_user.username,'settings_updated','Plan shop settings updated.')
    flash('Settings saved. The worker applies changes automatically.','success')
    return redirect(url_for('reseller.admin_page',tab='bot',view='messages' if request.form.get('settings_section')=='messages' else 'connection'))

@bp.post('/resellers/password-policy')
@admin
def password_policy():
    from .database import settings_transaction
    with settings_transaction():
        minimum=s.integer(request.form,'password_min_length',8,64)
        s.put('password_min_length',minimum)
        s.audit(current_user.username,'password_policy',str(minimum))
    flash('Password policy saved. Applies to new passwords; existing logins are unchanged.','success')
    return redirect_admin('accounts')

@bp.post('/resellers/bot/test')
@admin
def bot_test():
    from .worker import telegram
    try:
        encrypted=s.setting('bot_token')
        if not encrypted: raise ValueError('Save a bot token first.')
        token=s.decrypt(encrypted)
        info=telegram(token,'getMe',{})
        hook=telegram(token,'getWebhookInfo',{})
        if hook.get('url'):
            result='Webhook detected. This dedicated bot must use polling; remove its webhook before starting this worker.'
        else:
            result='Telegram connection verified. No webhook is configured. Start the worker to receive commands.'
        with settings_transaction():
            if s.setting('bot_token') != encrypted:
                flash('The connected bot changed. Test the current connection again.', 'warning')
                return redirect_admin('bot')
            s.put('bot_username',info.get('username'))
            s.put('bot_check_at',s.now().isoformat())
            s.put('bot_check_result',result)
            s.audit(current_user.username,'bot_connection_test','Read-only Telegram check completed')
        flash(result,'success' if not hook.get('url') else 'warning')
    except Exception:
        flash('Connection test failed. Check the saved token, unchanged encryption key, and outbound access to api.telegram.org. No messages were sent.','error')
    return redirect_admin('bot')

@bp.route('/resellers/api/purchase-alerts', methods=['GET','POST'])
@admin
def purchase_alerts():
    from .inbox import mark_seen, seen_ids
    from .models import InboxRead
    viewer = 'admin:'+str(current_user.get_id())
    queue = Order.awaiting_review()
    unread_queue = queue.filter(~Order.id.in_(seen_ids(viewer)))
    if request.method == 'POST':
        data = request.get_json(silent=True)
        if not isinstance(data, dict):abort(400)
        with settings_transaction():
            mark_seen(viewer, queue.with_entities(Order.id), data.get('ids'))
        return {'ok':True, 'unread':unread_queue.count()}
    count = queue.count()
    unread = unread_queue.count()
    read = []
    items = []
    if count and request.args.get('summary') != '1':
        orders = queue.order_by(Order.id.in_(seen_ids(viewer)), Order.id.desc()).limit(3).all()
        read = [i for i, in seen_ids(viewer).filter(InboxRead.item_id.in_([o.id for o in orders]))]
        for order in orders:
            items.append({
                'id': order.id, 'plan': order.spec.get('plan_name') or f'Plan #{order.plan_id}',
                'amount': f"{order.spec['price']} {order.spec['currency']}",
                'href': url_for('reseller.admin_page', tab='orders', order=order.id),
            })
    response = jsonify(count=count, unread=unread, read=read, items=items, href=url_for('reseller.admin_page', tab='orders', status='review'))
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@bp.route('/resellers/api/health-alert-reads', methods=['GET','POST'])
@admin
def health_alert_reads():
    key = 'health_read:'+str(current_user.get_id())
    if request.method == 'POST':
        patch = request.get_json(silent=True)
        names = {'panel','wireguard','nodes','subscriptions','backup','telegram','security'}
        if not isinstance(patch, dict) or not set(patch) <= names:abort(400)
        if any(value is not None and (not isinstance(value,str) or len(value)>400) for value in patch.values()):abort(400)
        with settings_transaction():
            state = dict(s.setting(key, {}))
            for name,value in patch.items():
                if value is None:state.pop(name,None)
                else:state[name]=value
            s.put(key,state)
    return jsonify(s.setting(key, {}))


@bp.get('/resellers/orders/<int:oid>/receipt')
@admin
def receipt_image(oid):
    if not db.session.get(Order,oid):abort(404)
    from .receipts import photo_response
    return photo_response(oid)

@bp.post('/resellers/plans')
@admin
def plan_save():
    with settings_transaction():
        data=request.form.to_dict(); data['permissions']=request.form.getlist('permissions'); data['interfaces']=request.form.getlist('interfaces')
        data['panel_access']=request.form.get('panel_access')=='on';data['telegram_features']=request.form.getlist('telegram_features')
        from .bot_ui import payment_problem
        problem=payment_problem(data)
        if problem:raise ValueError('Payment instructions: '+problem)
        spec=s.validate_spec(data)
        name=request.form.get('name','').strip()[:80]
        if not name: raise ValueError('Plan name required.')
        db.session.add(Plan(name=name,spec=spec))
        s.audit(current_user.username,'plan_created',name)
    if request.accept_mimetypes.best=='application/json':return {'ok':True,'message':'Plan created.', 'location':url_for('reseller.admin_page',tab='plans')}
    flash('Plan created. Existing purchases keep their original terms.','success'); return redirect_admin('plans')

@bp.app_template_global('plan_form')
def plan_form(plan):
    from werkzeug.datastructures import MultiDict
    if request.endpoint=='reseller.plan_update' and request.view_args.get('pid')==plan.id:return request.form
    spec=plan.spec;data=MultiDict({k:str(v) for k,v in spec.items() if k not in ('permissions','interfaces','operation_limits','network_policy','telegram_access')})
    data['name']=plan.name
    data.setlist('permissions',spec.get('permissions',[]));data.setlist('interfaces',[str(i) for i in spec.get('interfaces',[])])
    data['panel_access']='on' if spec.get('panel_access') else ''
    for key,value in spec.get('operation_limits',{}).items():data[key]=str(value)
    policy=spec.get('network_policy',{});endpoint=policy.get('endpoint','')
    if endpoint:data['server_host'],data['server_port']=endpoint.rsplit(':',1)
    for key in ('allow_endpoint','allow_fixed','allow_internal'):data[key]='on' if policy.get(key,False) else ''
    data['internal_routes']=', '.join(policy.get('internal_routes',[]))
    telegram=spec.get('telegram_access',{});data['approved']='on' if telegram.get('approved') else ''
    data.setlist('telegram_features',telegram.get('features',[]))
    return data

@bp.post('/resellers/plans/<int:pid>')
@admin
def plan_update(pid):
    with settings_transaction():
        plan=Plan.catalog().filter_by(id=pid).first_or_404()
        data=request.form.to_dict();data['permissions']=request.form.getlist('permissions');data['interfaces']=request.form.getlist('interfaces')
        data['telegram_features']=request.form.getlist('telegram_features');data['panel_access']=request.form.get('panel_access')=='on'
        from .bot_ui import payment_problem
        problem=payment_problem(data)
        if problem:raise ValueError('Payment instructions: '+problem)
        name=request.form.get('name','').strip()
        if not name or len(name)>80:raise ValueError('Enter a plan name (1–80 characters).')
        from .limits import effective
        for key, value in effective(plan.spec).items():
            data.setdefault(key, value)
        plan.spec=s.validate_spec(data);plan.name=name
        s.audit(current_user.username,'plan_updated',str(pid))
    if request.accept_mimetypes.best=='application/json':return {'ok':True,'message':'Changes saved.', 'name':plan.name, 'row':render_template('reseller/plan_row.html',p=plan)}
    flash('Plan saved. Existing accounts and pending orders keep their purchased terms.','success')
    return redirect_admin('plans')

@bp.post('/resellers/plans/<int:pid>/payment')
@admin
def plan_payment(pid):
    with settings_transaction():
        plan=Plan.catalog().filter_by(id=pid).first_or_404()
        value=request.form.get('payment_instructions','').strip()
        from .bot_ui import payment_problem
        problem=payment_problem({'payment_instructions':value})
        if problem:raise ValueError('Payment instructions: '+problem)
        plan.spec={**plan.spec,'payment_instructions':value}
        s.audit(current_user.username,'plan_payment_updated',f'plan={pid}')
    if request.accept_mimetypes.best=='application/json':return {'ok':True,'message':'Payment instructions saved. Existing orders retain their original instructions.'}
    flash('Payment instructions saved. Existing orders retain their original instructions.','success')
    return redirect_admin('plans')

@bp.post('/resellers/plans/<int:pid>/toggle')
@admin
def plan_toggle(pid):
    with settings_transaction():
        plan=Plan.catalog().filter_by(id=pid).first_or_404()
        if not plan.active:
            from .bot_ui import payment_problem
            problem=payment_problem(plan.spec)
            if problem:raise ValueError('Cannot publish a plan: '+problem)
        plan.active=not plan.active
        s.audit(current_user.username,'plan_visibility',str(pid))
    return redirect_admin('plans')

@bp.post('/resellers/plans/<int:pid>/delete')
@admin
def delete_plan(pid):
    with settings_transaction(wait_seconds=10):
        plan = Plan.catalog().filter_by(id=pid).first_or_404()
        if request.form.get('confirm') != plan.name:
            raise ValueError('Enter the plan name to confirm deletion.')
        plan.active = False
        plan.spec = {**plan.spec, 'retired':True}
        s.audit(current_user.username, 'plan_deleted', str(pid))
    flash('Plan deleted from the catalog.', 'success')
    return redirect_admin('plans')


@bp.post('/resellers/accounts/<int:aid>/delete')
@admin
def delete_account(aid):
    from .retirement import remove_account
    with s.locked(aid,additional_interfaces=[]):
        account = db.session.get(Account, aid)
        if not account or account.state == 'deleted':abort(404)
        if request.form.get('confirm') != account.username:
            raise ValueError('Enter the reseller username to confirm deletion.')
        remove_account(account, HOST, request.form.get('transfer')=='on', current_user.username)
    flash('Reseller account deleted.', 'success')
    return redirect_admin()


@bp.post('/resellers/accounts')
@admin
def account_create():
    password = request.form.get('password')
    if password:
        s.validate_password(password)
        db.session.rollback()
        password_hash = generate_password_hash(password)
    with settings_transaction():
        plan=Plan.catalog().filter_by(id=int(request.form.get('plan_id','0'))).first_or_404()
        tid=request.form.get('telegram_id','').strip() or None
        if tid and not re.fullmatch(r'[1-9][0-9]{3,19}',tid): raise ValueError('Use the numeric Telegram user ID, not a username.')
        acc=s.new_account(request.form.get('username','').strip(),{**plan.spec,'plan_name':plan.name},tid)
        if password:
            s.validate_password(password)
            acc.password_hash = password_hash
        if request.form.get('customize_account')=='on':
            from .limits import validate as validate_limits
            from .network_policy import validate as validate_network
            from .telegram_policy import save_access
            from .models import ManagementBot
            permissions=sorted(set(request.form.getlist('permissions')) & set(s.PERMISSIONS))
            panel_access = request.form.get('panel_access') == 'on'
            from .limits import effective
            limit_data = {**effective(acc.spec), **request.form.to_dict()}
            limits = validate_limits(limit_data)
            renewal.remember_workspace(acc, permissions, panel_access, limits)
            acc.spec={**acc.spec,'permissions':permissions,'panel_access':panel_access,'operation_limits':limits}
            acc.note=request.form.get('note','')[:500]
            acc.state='suspended' if request.form.get('state')=='suspended' else 'active'
            network = validate_network(request.form)
            if network != (acc.spec.get('network_policy') or {}):
                renewal.remember(acc, network_policy=network)
            s.put('network_policy:'+str(acc.id),network)
            bot=db.session.get(ManagementBot,acc.id)
            if not bot:bot=ManagementBot(account_id=acc.id);db.session.add(bot)
            renewal.remember_telegram(acc, bot, request.form)
            bot.approved=request.form.get('approved')=='on'
            save_access(acc,request.form)
        if not acc.password_hash:
            setup_url=s.setup(acc)
            flash('Password setup link (valid 24 hours): '+setup_url,'success')
        else: setup_url=None
        if tid: s.notify(acc,'created',account_notice(acc,'created',password_url=setup_url))
        s.audit(current_user.username,'account_created',str(acc.id))
    return redirect_admin()

@contextmanager
def purchase_transaction(account_id):
    with s.account_operation(account_id):
        has_customers = (account_id is not None and db.session.query(Ownership.id)
                         .filter_by(account_id=account_id, deleted=False).first() is not None)
        db.session.rollback()
        if not has_customers:
            with settings_transaction():
                yield None, None
            return
    remote = s.prepare_remote_sample(account_id, HOST, budget=8)
    local = s.prepare_local_sample(HOST, account_id)
    with s.account_operation(account_id), s.network_operation(account_id=account_id, additional_interfaces=[]), settings_transaction():
        yield remote, local


def review_order(oid, action, form, actor, recheck=None):
    if action not in ('approve', 'reject'):
        abort(404)
    if action == 'reject':
        with settings_transaction():
            if recheck:
                recheck()
            order = db.session.get(Order, oid, with_for_update=True) or abort(404)
            if order.state != 'pending':
                raise ValueError('Order already reviewed.')
            order.state, order.reviewed_at, order.reviewer = 'rejected', s.now(), actor
            order.note = form.get('note', '')[:500]
            buyer = s.order_buyer(order)
            s.notify(buyer, 'rejected:'+str(oid), account_notice(buyer,'rejected',order=order,note=order.note,chat=order.telegram_id),
                     buyer.telegram_id if buyer else order.telegram_id)
            s.audit(actor, 'order_rejected', str(oid))
        return

    if form.get('verified') != 'yes':
        raise ValueError('Confirm that you checked the payment before approving it.')
    order = db.session.get(Order, oid) or abort(404)
    if order.state != 'pending' or not order.payment_ref:
        raise ValueError('Only an order with a receipt awaiting review can be approved.')
    buyer = s.order_buyer(order)
    account_id = buyer.id if buyer else None
    db.session.rollback()
    with purchase_transaction(account_id) as (remote, local):
        if recheck:
            recheck()
        order = db.session.get(Order, oid, with_for_update=True) or abort(404)
        if order.state != 'pending' or not order.payment_ref:
            raise ValueError('Only an order with a receipt awaiting review can be approved.')
        buyer = s.order_buyer(order)
        if (buyer.id if buyer else None) != account_id:
            raise ValueError('The reseller account changed. Refresh the order before reviewing it.')
        if buyer:
            buyer = db.session.get(Account, account_id, with_for_update=True)
        if remote is not None:
            cache = s.checked_remote_sample(account_id, remote)
            if local is not None and s.local_baselines(account_id) != local[0]:
                raise ValueError('Customer traffic changed during the check. Refresh the order and try again.')
            complete = s.sample(buyer, HOST, cache, local_snapshot=local[1] if local else None)
        else:
            complete = buyer is None or s.sample(buyer, HOST)
        if not complete:
            raise ValueError('Current usage is unavailable. The receipt stays under review. Try again when the node is online.')
        from .payment_verification import record_verified
        record_verified(order, actor, form.get('verification_method'), form.get('verification_reference'))
        s.approve(oid, actor)


@bp.post('/resellers/orders/<int:oid>/<action>')
@admin
def review(oid,action):
    review_order(oid,action,request.form,current_user.username)
    if request.accept_mimetypes.best == 'application/json':
        order = db.session.get(Order, oid)
        verification = PaymentVerification.query.filter_by(order_id=oid).first()
        buyer = s.order_buyer(order)
        row = render_template('reseller/order_row.html', o=order, buyer=buyer,
                              receipt_photos={oid: s.setting('receipt_photo:'+str(oid))},
                              payment_verifications={oid: verification})
        return {'ok': True, 'state': order.state, 'row': row}
    flash('Review saved. Delivery is queued.','success')
    return redirect_admin('orders')

@bp.post('/resellers/accounts/<int:aid>/<action>')
@admin
def account_action(aid,action):
    from .database import settings_transaction

    transaction = s.locked(aid,additional_interfaces=[]) if action in ('suspend','resume') else settings_transaction(wait_seconds=10)
    with transaction:
        acc=db.session.get(Account,aid,with_for_update=True) or abort(404)
        if acc.state=='deleted':abort(404)
        if action=='suspend':
            acc.state='suspended'; acc.session_version+=1
            for row in Ownership.query.filter_by(account_id=aid,deleted=False).all():
                peer=db.session.get(Peer,row.peer_id)
                if peer:
                    was_enabled = peer.status == 'online' or row.blocked
                    if HOST['_disable_peer'](peer,'reseller_suspended'): row.blocked=was_enabled
                    else: s.put('enforcement_error',f'Peer {peer.id} disable failed; worker will retry.')
            s.notify(acc,'suspended:'+str(acc.session_version),account_notice(acc,'suspended'))
        elif action=='resume': acc.state='active'
        elif action=='rotate':
            token=secrets.token_urlsafe(32); acc.link_hash=s.digest(token); acc.link_enc=s.encrypt(token); acc.session_version+=1
            s.notify(acc,'rotate:'+str(acc.session_version),account_notice(acc,'rotate'))
        elif action=='reset-password':
            acc.session_version+=1
            setup_url=s.setup(acc)
            flash('Password reset link (24 hours): '+setup_url,'success')
            s.notify(acc,'password:'+str(acc.session_version),account_notice(acc,'password',password_url=setup_url))
        elif action=='reset-2fa':
            if request.form.get('confirm')!='RESET TWO-FACTOR':
                raise ValueError('Type RESET TWO-FACTOR to confirm an administrator-assisted recovery.')
            reason=request.form.get('reason','').strip()[:300]
            if len(reason)<12:raise ValueError('Record a recovery reason (at least 12 characters).')
            security=db.session.get(AccountSecurity,aid)
            if not security or not security.totp_secret_enc:raise ValueError('This reseller has no enabled authenticator.')
            security.totp_secret_enc=None;security.pending_secret_enc=None
            security.recovery_hashes=[];security.last_totp_step=-1;security.enabled_at=None
            acc.session_version+=1
            s.audit(current_user.username,'account_2fa_recovery',f'account={aid}; reason={reason}')
            s.notify(acc,'totp-reset:'+str(acc.session_version),
                     account_notice(acc,'totp'))
        elif action=='permissions':
            spec=dict(acc.spec); spec['permissions']=sorted(set(request.form.getlist('permissions')) & set(s.PERMISSIONS)); spec['panel_access']=request.form.get('panel_access')=='on'
            renewal.remember_workspace(acc, spec['permissions'], spec['panel_access'])
            previous = set(acc.spec.get('permissions', ()))
            selected = set(spec['permissions'])
            access_changed = bool(acc.spec.get('panel_access')) != spec['panel_access']
            if previous - selected or (access_changed and not spec['panel_access']):
                acc.session_version += 1
            acc.spec = spec
            acc.note = request.form.get('note','')[:500]
            if previous != selected or access_changed:
                from .models import ManagementBot
                bot=db.session.get(ManagementBot,aid)
                if bot:bot.revision+=1;bot.pending=None
                s.put('bot_reply:'+str(aid),{})
        elif action=='limits':
            from .limits import validate
            limits = validate(request.form)
            from .limits import effective
            renewal.remember(acc, operation_limits=renewal.differences(effective(acc.spec), limits))
            acc.spec={**acc.spec,'operation_limits':limits}
        elif action=='notify':
            text=request.form.get('message','').strip()[:2000]
            if not text: raise ValueError('Message is required.')
            s.notify(acc,'manual:'+secrets.token_hex(10),account_notice(acc,'manual',note=text))
        else: abort(404)
        s.audit(current_user.username,'account_'+action,str(aid))
    return redirect_admin()

@bp.route('/r/<token>',methods=['GET','POST'])
def login(token):
    error=None
    _request_stage('account-read')
    if len(token)!=43: abort(404)
    link_hash = s.digest(token)
    entry = (db.session.query(Account, AccountSecurity.totp_secret_enc.isnot(None))
             .outerjoin(AccountSecurity, AccountSecurity.account_id == Account.id)
             .filter(Account.link_hash == link_hash).one_or_none())
    if entry is None:
        abort(404)
    acc, needs_code = entry
    login_username=acc.username
    if request.method=='GET' and session.get('rp_id')==acc.id and session.get('rp_version')==acc.session_version and session.get('rp_until',0)>s.now().timestamp() and acc.state=='active' and acc.spec.get('panel_access'):
        return redirect(landing(acc))
    if request.method=='POST':
        from .request_guard import reserve,login_event
        from .database import settings_transaction
        from .account_security import verify_and_consume
        account_id=acc.id;username=acc.username
        version=acc.session_version;stored_hash=acc.password_hash
        eligible=acc.state=='active' and acc.spec.get('panel_access')
        db.session.rollback()
        _request_stage('login-budget')
        allowed=reserve([('login-ip:'+s.digest(request.remote_addr or '?'),40,900),('login-account:'+str(account_id),10,900)])
        _request_stage('password')
        if not allowed:error='Too many attempts. Try again in 15 minutes.'
        elif not eligible or not stored_hash or request.form.get('username')!=username or not check_password_hash(stored_hash,request.form.get('password','')[:1024]):
            error='Invalid credentials or access unavailable.'
        else:


            _request_stage('account-recheck')
            def current_login():
                return (db.session.query(Account, AccountSecurity)
                        .outerjoin(AccountSecurity, AccountSecurity.account_id == Account.id)
                        .filter(Account.id == account_id, Account.link_hash == link_hash).one_or_none())
            def eligible_login(account):
                return bool(account and account.session_version == version and account.password_hash == stored_hash
                            and account.link_hash == link_hash and account.state == 'active' and account.spec.get('panel_access'))
            row = current_login()
            if not row or not eligible_login(row[0]):
                error = 'Invalid credentials or access unavailable.'
            elif row[1] and row[1].totp_secret_enc:
                _request_stage('two-factor')
                with settings_transaction():
                    locked_account = db.session.get(Account, account_id, with_for_update=True)
                    security = db.session.get(AccountSecurity, account_id, with_for_update=True)
                    needs_code = bool(security and security.totp_secret_enc)
                    if (not eligible_login(locked_account)
                            or not verify_and_consume(security, request.form.get('twofa_code','')[:64])):
                        error = 'Invalid credentials or access unavailable.'
                    else:
                        acc = locked_account
            else:
                _request_stage('session-check')
                acc = row[0]
        if not error:


            account_id=acc.id;version=acc.session_version
            target=landing(acc)
            entry_hash=acc.link_hash
            db.session.rollback()
            _request_stage('login-audit')
            login_event(account_id)
            session.clear();session['rp_id']=account_id;session['rp_version']=version;session['rp_until']=(s.now()+timedelta(hours=8)).timestamp()
            session['rp_entry']=entry_hash
            return redirect(target)
    _request_stage('login-render')
    return render_template('reseller/login.html',error=error, next='', show_2fa=needs_code, reseller_username=login_username)

@bp.route('/r/setup/<token>',methods=['GET','POST'])
def password_setup(token):
    if len(token)!=43: abort(404)
    acc=Account.query.filter_by(setup_hash=s.digest(token)).first()
    if not acc or not acc.setup_expires or acc.setup_expires<s.now(): abort(404)
    if request.method=='POST':
        password=request.form.get('password','')
        s.validate_password(password)
        if password!=request.form.get('confirm'):raise ValueError('Passwords do not match.')
        db.session.rollback()
        password_hash=generate_password_hash(password)
        with settings_transaction():
            acc=Account.query.filter_by(setup_hash=s.digest(token)).with_for_update().first()
            if not acc or not acc.setup_expires or acc.setup_expires<s.now():abort(404)
            s.validate_password(password)
            acc.password_hash=password_hash
            acc.setup_hash=None
            acc.setup_expires=None
            acc.session_version+=1
            target=s.link(acc)
            s.audit('reseller:'+str(acc.id),'password_changed','Setup token consumed')
        session.clear()
        return redirect(target)
    return render_template('reseller/setup.html',username=acc.username)

@bp.get('/r/backup')
@member('backup')
def reseller_backup_page():
    from .backup_service import history
    return render_template('reseller/backup.html', section='backup', reseller_mode=True,
                           account=g.reseller, backup_history=history(g.reseller.id), HAS_NODES=False, HAS_SETTINGS=False)

@bp.get('/r/backup/export')
@member('backup')
def reseller_backup_export():
    from io import BytesIO
    from flask import send_file
    from .own_backup import own_backup_document
    from .backup_service import web_snapshot
    aid=g.reseller.id
    db.session.rollback()
    try:filename,binary=web_snapshot(aid,session.get('rp_version'),own_backup_document)
    except PermissionError:abort(403)
    response = send_file(BytesIO(binary), mimetype='application/json', as_attachment=True,
                         download_name=filename, max_age=0)
    response.headers['Cache-Control'] = 'private, no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'none'; sandbox"
    return response

@bp.get('/r/backup/recovery')
@member('backup')
def reseller_backup_recovery():
    from io import BytesIO
    from flask import send_file
    from .own_backup import recovery_document
    from .backup_service import web_snapshot, record
    aid=g.reseller.id
    db.session.rollback()
    try:filename,binary=web_snapshot(aid,session.get('rp_version'),recovery_document)
    except PermissionError:abort(403)
    record(aid,'Web',filename,len(binary))
    response=send_file(BytesIO(binary),mimetype='application/zip',as_attachment=True,download_name=filename,max_age=0)
    response.headers['Cache-Control']='private, no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Backup-Created-At']=s.now().isoformat()+'Z'
    return response

@bp.post('/r/backup/inspect')
@member('restore')
def reseller_backup_inspect():
    from .own_backup import inspect_document,MAX_EXPORT_BYTES
    if 'backup' not in g.reseller.spec['permissions']:abort(403)
    upload=request.files.get('file')
    if not upload:raise ValueError('Choose a backup file.')
    response=jsonify(inspect_document(g.reseller,upload.read(MAX_EXPORT_BYTES+1)))
    response.headers['Cache-Control']='private, no-store'
    return response

@bp.post('/r/backup/restore')
@member('restore')
def reseller_backup_restore():
    from .own_backup import restore_document,MAX_EXPORT_BYTES
    if 'backup' not in g.reseller.spec['permissions']:abort(403)
    upload=request.files.get('file')
    if not upload:raise ValueError('Choose a backup file.')
    binary=upload.read(MAX_EXPORT_BYTES+1)
    aid=g.reseller.id
    with s.locked(aid):
        account=db.session.get(Account,aid)
        if not account or account.session_version!=session.get('rp_version') or not account.spec.get('panel_access') or not {'backup','restore'}<=set(account.spec.get('permissions',[])):abort(403)
        from .models import ProvisionJob
        if ProvisionJob.query.filter(ProvisionJob.account_id==aid,ProvisionJob.state.in_(['queued','running','review'])).first():
            raise ValueError('Complete or reconcile pending customer operations before restoring a backup.')
        count=restore_document(account,binary,HOST)
    return {'ok':True,'restored':count}

@bp.get('/r/security')
@member()
def reseller_security():
    sec=db.session.get(AccountSecurity,g.reseller.id)
    pending=s.decrypt(sec.pending_secret_enc) if sec and sec.pending_secret_enc and not sec.totp_secret_enc else None
    from .account_security import provisioning_uri
    return render_template('reseller/security.html',section='security',reseller_mode=True,account=g.reseller,
                           security=sec,pending=pending,provisioning_uri=provisioning_uri(g.reseller.username,pending) if pending else None,
                           recovery_codes=None)

@bp.post('/r/security/<action>')
@member()
def reseller_security_action(action):
    if action not in ('prepare','enable','cancel','disable','regenerate'):abort(404)
    from .database import settings_transaction
    from .account_security import new_secret,matched_step,new_recovery_codes,recovery_digest,verify_and_consume,provisioning_uri
    code=(request.form.get('twofa_code') or '').strip()[:64]
    password=request.form.get('password','')[:1024]
    if not g.reseller.password_hash or not check_password_hash(g.reseller.password_hash,password):
        flash('Current password is required for security changes.','error')
        return redirect(url_for('reseller.reseller_security'))
    recovery_codes=None
    with settings_transaction():
        acc=db.session.get(Account,g.reseller.id)
        if not acc or acc.session_version!=session.get('rp_version') or acc.password_hash!=g.reseller.password_hash:abort(403)
        sec=db.session.get(AccountSecurity,acc.id)
        if not sec:
            sec=AccountSecurity(account_id=acc.id,recovery_hashes=[],last_totp_step=-1)
            db.session.add(sec);db.session.flush()
        enabled=bool(sec.totp_secret_enc)
        if action=='prepare':
            if enabled:abort(400)
            sec.pending_secret_enc=s.encrypt(new_secret())
            s.audit('reseller:'+str(acc.id),'totp_prepared','Enrollment initiated')
        elif action=='cancel':
            if enabled:abort(400)
            sec.pending_secret_enc=None
        elif action=='enable':
            if enabled or not sec.pending_secret_enc:abort(400)
            secret=s.decrypt(sec.pending_secret_enc)
            matched=matched_step(secret,code)
            if matched is None:raise ValueError('Invalid authenticator code. Check your device time and retry.')
            recovery_codes=new_recovery_codes()
            sec.totp_secret_enc=sec.pending_secret_enc
            sec.pending_secret_enc=None
            sec.recovery_hashes=[recovery_digest(x) for x in recovery_codes]
            sec.last_totp_step=matched
            sec.enabled_at=s.now()
            acc.session_version+=1
            session['rp_version']=acc.session_version
            s.audit('reseller:'+str(acc.id),'totp_enabled','TOTP enabled; previous sessions revoked')
        elif action=='disable':
            if not enabled or not verify_and_consume(sec,code):raise ValueError('Valid authenticator or recovery code required.')
            sec.totp_secret_enc=None;sec.pending_secret_enc=None;sec.recovery_hashes=[];sec.last_totp_step=-1;sec.enabled_at=None
            acc.session_version+=1
            session['rp_version']=acc.session_version
            s.audit('reseller:'+str(acc.id),'totp_disabled','TOTP disabled; previous sessions revoked')
        elif action=='regenerate':
            if not enabled or not verify_and_consume(sec,code):raise ValueError('Valid authenticator or recovery code required.')
            recovery_codes=new_recovery_codes()
            sec.recovery_hashes=[recovery_digest(x) for x in recovery_codes]
            acc.session_version+=1
            session['rp_version']=acc.session_version
            s.audit('reseller:'+str(acc.id),'totp_recovery_rotated','Recovery codes rotated; previous sessions revoked')
    if recovery_codes is not None:

        return render_template('reseller/security.html',section='security',reseller_mode=True,account=acc,
                               security=sec,pending=None,provisioning_uri=None,recovery_codes=recovery_codes)
    flash('Security settings updated.','success')
    return redirect(url_for('reseller.reseller_security'))

@bp.post('/r/logout')
def logout():
    session.clear(); return render_template('reseller/signed_out.html')

@bp.get('/r/panel/<section>')
@member()
def portal(section):
    if section not in ('dashboard','peers','subscriptions'): abort(404)
    acc=g.reseller
    if section not in acc.spec['permissions']: abort(403)


    if section in ('peers','subscriptions'):
        from forms import PeerForm
        form=PeerForm()
        allowed=InterfaceConfig.query.filter(InterfaceConfig.id.in_(acc.spec['interfaces'])).all()
        form.iface.choices=[(i.id,i.name) for i in allowed]
        if allowed:form.iface.data=allowed[0].id


        bootstrap_nodes=[]
        if section=='peers':
            node_ids={i.node_id for i in allowed if i.node_id is not None}
            if node_ids:
                from models import Node
                bootstrap_nodes=[{'id':node.id,'name':node.name}
                    for node in Node.query.filter(Node.id.in_(node_ids)).all()]
        return render_template('users.html' if section=='peers' else 'subscriptions.html', form=form, reseller_mode=True, account=acc, section=section, HAS_NODES=False, HAS_SETTINGS=False, reseller_bootstrap_nodes=bootstrap_nodes)
    from .models import ManagementBot
    return render_template('reseller/workspace.html',management_bot=None,reseller_mode=True,HAS_NODES=False,HAS_SETTINGS=False,states={},section=section, account=acc, peers=[], subscriptions=[], interfaces=[], notices=[], decrypt=s.decrypt, usable=s.active(acc))

@bp.post('/r/create/<kind>')
@member('create')
def create_resource(kind):
    if kind not in ('peer','subscription'): abort(404)
    section='subscriptions' if kind=='subscription' else 'peers'
    if section not in g.reseller.spec['permissions']: abort(403)
    from .provision_queue import submit_web
    from .management import validate_options
    acc=g.reseller
    ids=request.form.getlist('interfaces',type=int)
    if not ids or any(i not in acc.spec['interfaces'] for i in ids):abort(403)
    data={'name':request.form.get('name','')}
    validate_options(acc,data)
    response,status=submit_web(acc,dict(section=section,action='create',interfaces=ids,options=data,count=1))
    if status!=202:return error_page(response['error'],'Operation not queued'),status
    return redirect(response['operation']['status_url'],code=303)

@bp.post('/r/peers/<int:pid>/delete')
@member('delete')
def delete_peer(pid):
    if 'peers' not in g.reseller.spec['permissions']: abort(403)
    from .provision_queue import submit_web
    from .management import target
    response,status=submit_web(g.reseller,dict(section='peers',action='delete',id=pid,options={}),
                               validate=lambda:target(g.reseller,'peers',pid))
    if status!=202:return error_page(response['error'],'Operation not queued'),status
    return redirect(response['operation']['status_url'],code=303)

@bp.get('/r/peers/<int:pid>/config')
@member('download')
def config(pid):
    row,peer=s.own_peer(g.reseller,pid)
    section='subscriptions' if row.subscription_id else 'peers'
    if section not in g.reseller.spec['permissions']:abort(403)
    s.require_active(g.reseller)
    text=HOST['_client_conf_txt'](peer)
    return Response(text,mimetype='text/plain',headers={'Content-Disposition':f'attachment; filename="peer-{pid}.conf"'})

@bp.get('/r/subscriptions/<int:sid>/link')
@member('download')
def subscription_link(sid):
    if 'subscriptions' not in g.reseller.spec['permissions']: abort(403)
    s.require_active(g.reseller)
    if not Ownership.query.filter_by(account_id=g.reseller.id,subscription_id=sid,deleted=False).first(): abort(404)
    from .management import own_subscription
    sub,_=own_subscription(g.reseller,sid)
    return render_template('reseller/customer_link.html', customer_url=s.base_url()+'/s/'+sub.token)

def error_page(message, title='Request not completed', retry_read=False, reference=None):
    g.reseller_error = True
    if message=='This account is suspended, expired, or out of traffic.':
        title='Account access paused'
        account=getattr(g,'reseller',None)
        if account and account.state=='suspended':message='The administrator has suspended this account. Contact them to restore access.'
        else:message='Your plan has expired or its traffic allowance is exhausted. Open My plan in your workspace to renew. Customer changes are paused until approval.'

    path=request.path
    if request.endpoint in BILLING_ENDPOINTS:
        oid = (request.view_args or {}).get('oid') or request.args.get('order',type=int)
        recovery = url_for('reseller.billing',order=oid) if oid else url_for('reseller.billing')
    elif path.startswith('/r/panel/') and (request.view_args or {}).get('section') in ('dashboard','peers','subscriptions'):
        recovery=path
    elif path=='/r/shared/users' or path.startswith('/r/peers/'):
        recovery=url_for('reseller.portal',section='peers')
    elif path.startswith('/r/subscriptions/'):
        recovery=url_for('reseller.portal',section='subscriptions')
    elif request.endpoint=='reseller.management_bot_settings':
        recovery=url_for('reseller.management_bot_settings')
    elif path=='/r/activity':
        recovery=request.full_path.rstrip('?')
    elif request.endpoint in ('reseller.review', 'reseller.receipt_image'):
        recovery=url_for('reseller.admin_page',tab='orders',_anchor='order-'+str(request.view_args['oid']))
    elif request.endpoint in ('reseller.plan_update', 'reseller.plan_save', 'reseller.plan_payment', 'reseller.plan_toggle'):
        recovery=url_for('reseller.admin_page',tab='plans')
    elif path.startswith('/resellers'):
        recovery=url_for('reseller.admin_page')
    elif request.endpoint in ('reseller.login','reseller.password_setup'):
        recovery=path
    else:
        recovery=url_for('reseller.portal',section='dashboard')
    return current_app.jinja_env.get_template('reseller/error.html').render(message=message,title=title,recovery_url=recovery,reference=reference,endpoint=request.endpoint,
                           recovery_label=('View order' if request.endpoint=='reseller.billing_action' else 'Open My plan' if request.endpoint in BILLING_ENDPOINTS
                           else 'Return to sign in' if request.endpoint=='reseller.login' else 'Try loading this page again' if retry_read else 'Return to workspace'), retry_read=retry_read)

@bp.errorhandler(OperationalError)
def database_unavailable(exc):
    db.session.rollback()

    if __import__('reseller_portal.database', fromlist=['writer_busy']).writer_busy(exc):
        return operation_busy(exc)
    current_app.logger.error('Reseller database operation failed at %s',request.endpoint)
    message='The request could not be completed. Check the current account status before trying again; contact the administrator if it continues.'
    if request.path.startswith(('/r/api/','/r/shared/api/')) or request.accept_mimetypes.best=='application/json':return {'error':message},500
    return error_page(message),500

@bp.errorhandler(TimeoutError)
def operation_busy(exc):
    db.session.rollback()
    reference = secrets.token_hex(4)
    current_app.logger.warning('Reseller request busy: ref=%s endpoint=%s method=%s stage=%s cause=%s',
                               reference, request.endpoint, request.method, getattr(g,'_rp_stage','before-handler'), type(exc).__name__)
    message=('This page is temporarily busy. Wait a few seconds, then try loading it again.' if request.method in ('GET','HEAD') else 'We couldn’t confirm your change. It may already have been applied. Check its status before trying again.')
    if isinstance(exc, (s.WorkspaceLockTimeout, SettingsWriterBusy)) and request.method == 'POST':
        message = 'Another workspace change is in progress. This action could not start. Try again in a few seconds.'
    if request.path.startswith(('/r/api/','/r/shared/api/')) or request.accept_mimetypes.best=='application/json':
        return {'error':message,'reference':reference},503,{'Retry-After':'5'}
    return error_page(message,'Workspace temporarily busy',retry_read=request.method in ('GET','HEAD'),reference=reference),503,{'Retry-After':'3'}

@bp.errorhandler(CSRFError)
def csrf_failure(exc):
    db.session.rollback()
    message='This form could not be verified. Reload the form and try again. Your changes were not saved.'
    if 'referrer' in exc.description.lower():
        message='The browser origin could not be verified. Reload the page over HTTPS. If this continues, check whether a proxy or browser privacy setting removes the Referer header. Your changes were not saved.'
    if request.path.startswith(('/r/api/','/r/shared/api/')) or request.accept_mimetypes.best=='application/json':return {'error':message},400
    return error_page(message,'Please reload the form'),400

@bp.errorhandler(ValueError)
def bad_input(exc):
    db.session.rollback()
    if request.endpoint in ('reseller.plan_save','reseller.plan_update','reseller.plan_payment','reseller.account_create') and current_user.is_authenticated and getattr(current_user,'is_admin',False):
        if request.accept_mimetypes.best=='application/json':return {'error':str(exc)},400
        flash(str(exc),'error')
        return admin_page(),400
    if request.path.startswith(('/r/api/','/r/shared/api/')) or request.accept_mimetypes.best=='application/json':
        return {'error':str(exc)},400
    if request.endpoint=='reseller.management_bot_settings':
        from .management_bot import render_settings
        return render_settings(g.reseller.id,error=str(exc)),400
    return error_page(str(exc),'Please check your input'),400

from .management_bot import register as register_management_bot
register_management_bot(bp,admin,member,lambda:HOST)

from .billing import register as register_billing
register_billing(bp,member)

from .workspace import register as register_workspace
register_workspace(bp,member,lambda:HOST)
from .shared import register as register_shared
register_shared(bp,member,lambda:HOST)
from .provision_queue import register as register_provision_queue
register_provision_queue(bp,member,admin)

from .bot_apps import api as bot_apps_api, register as register_bot_apps
register_bot_apps(bp,admin,member)

def init_app(app,host):
    global HOST
    HOST=host
    with app.app_context():
        from .database import configure
        configure(db.engine)
        migrate()
    app.register_blueprint(bp)
    host['csrf'].exempt(bot_apps_api)
    app.register_blueprint(bot_apps_api)


    from types import MethodType
    from copy import copy
    app.session_interface=copy(app.session_interface)
    original_cookie_secure=app.session_interface.get_cookie_secure
    def reseller_cookie_secure(interface,current_app):
        if request.blueprint=='reseller':return True
        return original_cookie_secure(current_app)
    app.session_interface.get_cookie_secure=MethodType(reseller_cookie_secure,app.session_interface)

    def isolate():
        if request.blueprint=='reseller' and request.endpoint!='reseller.static':
            g._rp_started=time.perf_counter()
            _request_stage('request-guards')
        if request.blueprint=='reseller':
            if not app.testing and not host['_is_https'](): abort(403, description='Reseller access requires HTTPS.')
            if request.endpoint in ('reseller.reseller_backup_restore','reseller.reseller_backup_inspect') and request.content_length is None:abort(411)
            limit = 8*1024*1024+65536 if request.endpoint in ('reseller.reseller_backup_restore','reseller.reseller_backup_inspect') else 32768
            if request.endpoint == 'reseller.billing_action' and (request.view_args or {}).get('action') == 'receipt':
                if request.content_length is None:abort(411)
                limit = 5*1024*1024+65536
            if request.content_length and request.content_length > limit: abort(413)
        if (request.endpoint or '').startswith('subscription_public'):
            sub=Subscription.query.filter_by(token=(request.view_args or {}).get('token')).first()
            row=Ownership.query.filter_by(subscription_id=sub.id,deleted=False).first() if sub else None
            if row:
                owner=db.session.get(Account,row.account_id)
                if not owner or not s.active(owner):abort(403)
                from .management import own_subscription
                try:own_subscription(owner,sub.id)
                except ValueError:abort(404)
        if session.get('rp_id') and not (request.blueprint=='reseller' or request.endpoint=='static'):
            endpoint=request.endpoint or '';args=request.view_args or {};row=None
            acc=db.session.get(Account,session['rp_id'])
            if not acc or acc.session_version!=session.get('rp_version') or acc.state!='active' or 'download' not in acc.spec['permissions'] or not session.get('rp_until') or session['rp_until']<s.now().timestamp():abort(403)
            if endpoint.startswith('subscription_public') and 'subscriptions' in acc.spec['permissions']:
                sub=Subscription.query.filter_by(token=args.get('token')).first()
                if sub:
                    from .management import own_subscription
                    try:own_subscription(acc,sub.id)
                    except ValueError:abort(404)
                    row=Ownership.query.filter_by(subscription_id=sub.id,account_id=acc.id,deleted=False).first()
            elif endpoint in ('user_peer_page','user_peer','userpeer_config') and 'peers' in acc.spec['permissions']:
                from models import ShortLink
                link=ShortLink.query.filter_by(token=args.get('token')).first()
                if link:row=Ownership.query.filter_by(peer_id=link.peer_id,account_id=acc.id,deleted=False).first()
            if not row:abort(403)
            if not s.active(acc) or not acc.spec.get('panel_access'):abort(403)
        if request.blueprint=='reseller' and request.method not in ('GET','HEAD','OPTIONS') and app.config.get('WTF_CSRF_ENABLED',True):
            host['csrf'].protect()
    app.before_request_funcs.setdefault(None,[]).insert(0,isolate)
    @app.after_request
    def admin_peer_owners(response):
        endpoint=request.endpoint
        lists=('panel_peers','node_peers','api_subscriptions')
        interfaces=('get_interfaces','node_ifaces','api_subscriptions_locations')
        if endpoint not in lists+interfaces or request.method!='GET' or response.status_code!=200 or session.get('rp_id'):return response
        admin_session=current_user.is_authenticated and (getattr(current_user,'is_admin',False) or getattr(current_user,'is_superuser',False))
        if not admin_session:
            if current_user.is_authenticated or endpoint not in interfaces:return response
            from panel_core.auth_security import match_secret
            auth=(request.headers.get('Authorization') or '').strip().split(None,1)
            bearer=auth[1].strip() if len(auth)==2 and auth[0].lower()=='bearer' else ''
            alternative=(request.headers.get('X-API-KEY') or '').strip()
            if bearer and alternative and not match_secret(bearer,alternative):return response
            if not match_secret(bearer or alternative,(current_app.config.get('API_KEY') or '').strip()):return response
        payload=response.get_json(silent=True)
        if not isinstance(payload,dict):return response
        from .presentation import annotate_owners, annotate_subscription_owners, annotate_interface_assignments, resource_mode, filter_owned_resources
        nid=(request.view_args or {}).get('nid')
        if endpoint in interfaces:
            annotate_interface_assignments(payload,endpoint,nid if endpoint=='node_ifaces' else None)
        else:
            mode=resource_mode(s.setting('admin_resource_visibility:'+str(current_user.id),True))
            if isinstance(payload.get('peers'),list):
                annotate_owners(payload['peers'])
                payload['peers']=filter_owned_resources(payload['peers'],mode)
            if isinstance(payload.get('subscriptions'),list):
                annotate_subscription_owners(payload['subscriptions'])
                payload['subscriptions']=filter_owned_resources(payload['subscriptions'],mode)
        response.set_data(current_app.json.dumps(payload));response.headers['Cache-Control']='no-store'
        return response

    @app.after_request
    def privacy(response):
        if request.endpoint=='reseller.static':


            response.headers['Cache-Control']='public, max-age=3600'
            response.headers['X-Content-Type-Options']='nosniff'
            return response
        if request.blueprint=='reseller':

            response.headers['Referrer-Policy']='strict-origin'
            response.headers['Cache-Control']='no-store'
            response.headers['X-Robots-Tag']='noindex, nofollow'
        return response
    @app.context_processor
    def context():
        if getattr(g,'reseller_error',False):
            return {'reseller_timezone':'UTC','reseller_account':None,'reseller_password_min':8}
        from .limits import effective
        from .regional import zone_name
        from .models import ManagementBot
        from .network_policy import get
        from .telegram_policy import FEATURES
        from .bot_apps import app_policy
        acc=getattr(g,'reseller',None)
        expired = bool(acc and acc.expires_at <= s.now())
        bot=db.session.get(ManagementBot,acc.id) if acc and not expired else None


        section=getattr(g,'reseller_section',None) or (request.view_args or {}).get('section')
        network=get(acc) if acc and section in ('peers','subscriptions') else {}
        password_min=s.password_min() if request.endpoint in ('reseller.admin_page','reseller.account_dialog_fragment') else 8
        return {'reseller_remaining_ms':max(0, int((acc.expires_at-s.now()).total_seconds()*1000)) if acc else 0,'reseller_plan_expired':expired,'telegram_feature_labels':FEATURES,'reseller_network_policy':network,'reseller_bot_allowed':bool(bot and bot.approved),'reseller_app_allowed':bool(acc and not expired and not (bot and bot.approved) and app_policy(acc.id)['enabled']),'reseller_timezone':zone_name(),'operation_limits':effective,'reseller_account':acc,'reseller_password_min':password_min}
    @app.cli.command('reseller-watchdog')
    def watchdog_command():
        from .watchdog import evaluate_services
        import json
        state=evaluate_services(app.instance_path,s.setting('monitor_heartbeat'),
                       s.setting('monitor_failed_count',0),s.setting('enforcement_error'))
        print(json.dumps(state,sort_keys=True))
        if not state['ok']:
            raise SystemExit(2)

    @app.cli.command('reseller-db-check')
    def database_check():
        if db.engine.dialect.name=='postgresql':
            with db.engine.connect() as connection:
                print('Database backend: PostgreSQL; select_1:', connection.execute(text('SELECT 1')).scalar())
            return
        if db.engine.dialect.name!='sqlite':
            print('Database backend:',db.engine.dialect.name)
            return
        with db.engine.connect() as connection:
            print('journal_mode:',connection.exec_driver_sql('PRAGMA journal_mode').scalar())
            print('busy_timeout_ms:',connection.exec_driver_sql('PRAGMA busy_timeout').scalar())
            result=connection.exec_driver_sql('PRAGMA quick_check').scalars().all()
            print('quick_check:', '; '.join(result))
            if result!=['ok']:raise RuntimeError('Database integrity check did not pass.')

    @app.cli.command('reseller-init')
    def init_schema():
        migrate()
        print('Reseller tables ready. Existing panel and legacy reseller data were not modified.')

def migrate():
    from .database import schema_lock
    tables=[t for name,t in db.metadata.tables.items() if name.startswith('rp_')]
    with schema_lock(db.engine):
        with db.engine.begin() as connection:
            if db.engine.dialect.name=='sqlite':connection.exec_driver_sql('PRAGMA busy_timeout=30000')
            try:
                insp=inspect(connection)
                for table in tables:
                    if insp.has_table(table.name):
                        existing={c['name'] for c in insp.get_columns(table.name)}
                        if table.name=='rp_provision_job' and 'stage' not in existing:
                            from .operation_recovery import migrate_stage
                            migrate_stage(connection)
                            existing.add('stage')
                        missing=set(table.columns.keys())-existing
                        if missing:raise RuntimeError(f'{table.name} is incompatible: missing {sorted(missing)}. No rows were deleted.')
                db.metadata.create_all(connection,tables=tables)
                from .models import buyer_order_index, notice_outbox_index, review_queue_index, usage_retention_index, throttle_retention_index, provision_execution_index, provision_ordering_index, provision_due_index
                for index in (review_queue_index, buyer_order_index, usage_retention_index, throttle_retention_index, notice_outbox_index, provision_due_index):
                    index.create(connection, checkfirst=True)
                from .queue_scheduler import migrate_execution_index
                migrate_execution_index(connection, provision_execution_index, provision_ordering_index)
            finally:
                if db.engine.dialect.name=='sqlite':connection.exec_driver_sql('PRAGMA busy_timeout=5000')
