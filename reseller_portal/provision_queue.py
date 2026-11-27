import hashlib
import json
import re
import secrets
from datetime import timedelta
from threading import Thread

from flask import abort, g, request, render_template, redirect, url_for, current_app
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import insert
from models import db
from .models import Account, ManagementBot, ProvisionJob as Job
from . import service as s, management as m
from .queue_scheduler import claim_statement, MAX_WAIT_SECONDS, MAX_PENDING_PER_ACCOUNT, PENDING_STATES

FINAL = ('completed', 'rejected', 'review', 'resolved')
GRANTS = {'create':'create','attach':'attach_existing','edit':'edit','enable':'control_access',
          'disable':'control_access','delete':'delete','reset_data':'reset_data',
          'reset_timer':'reset_timer','rotate':'rotate_link'}


class JobConflict(ValueError):
    pass


class Rejected(ValueError):
    pass


class ClaimUncertain(RuntimeError):
    def __init__(self,jid,attempt):self.jid=jid;self.attempt=attempt


def serialize(job):
    return dict(id=job.id, section=job.section, action=job.action, state=job.state,
                channel='api' if job.request_key.startswith('app:') else job.channel, created_at=job.created_at.isoformat()+'Z',
                message=job.message, result=job.result if job.state=='completed' else None,
                status_url='/r/operations/'+job.id, stage=getattr(job,'stage',None),
                started_at=job.started_at.isoformat()+'Z' if getattr(job,'started_at',None) else None,
                finished_at=job.finished_at.isoformat()+'Z' if getattr(job,'finished_at',None) else None)


def canonical(op):
    raw=json.dumps(op,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    if len(raw.encode())>65536:raise ValueError('Operation settings are too large.')
    return raw


def enqueue(account, op, key, *, bot=None, commit=False, validate=None):
    if db.engine.dialect.name!='postgresql':raise ValueError('PostgreSQL is required for provisioning.')
    if op.get('section') not in ('peers','subscriptions') or op.get('action') not in GRANTS:
        raise ValueError('Unsupported operation.')
    if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9:_-]{1,96}',key):raise ValueError('Invalid request identifier.')
    if bot is None and 'options' in op:
        allowed_options=set(m.FIELDS)|set(m.NETWORK)|{'note','time_limit_hours','time_limit_minutes','customer_unlimited','include_internal_network','sync_existing','address','start_index','phone_numbers','telegram_ids'}
        op={**op,'options':{k:v for k,v in op['options'].items() if k in allowed_options}}
    raw=canonical(op)
    signature=hashlib.sha256(raw.encode()).hexdigest()
    channel='bot' if bot is not None else 'web'
    now=s.now()
    aid=account.id
    if db.session.get_bind().dialect.name=='postgresql':
        db.session.execute(select(func.pg_advisory_xact_lock(0x574751,aid)))
    jid=secrets.token_hex(16)
    values=dict(id=jid,account_id=aid,request_key=key,fingerprint=signature,channel=channel,
        section=op['section'],action=op['action'],payload_enc=s.encrypt(raw),session_version=account.session_version,
        generation=account.generation,bot_revision=bot.revision if bot is not None else None,
        recipient=account.telegram_id if bot is not None else None,state='queued',created_at=now,
        available_at=now,attempts=0,notify_attempts=0)
    existing=Job.query.filter_by(account_id=aid,request_key=key).one_or_none()
    if existing is not None:
        if existing.fingerprint!=signature or existing.channel!=channel:
            raise JobConflict('This request identifier was already used for different settings.')
        result=serialize(existing)
        if commit:db.session.commit()
        return result
    if bot is not None or op['action'] not in ('disable','delete'):s.require_active(account)
    if validate is not None:validate()
    pending, reviews = db.session.execute(select(func.count(Job.id), func.count(Job.id).filter(Job.state=='review'))
        .where(Job.account_id==aid,Job.state.in_(PENDING_STATES))).one()
    if reviews:
        raise JobConflict('An earlier operation needs administrator reconciliation. New changes are paused for this account.')
    if pending>=MAX_PENDING_PER_ACCOUNT:
        raise JobConflict('Too many requests are waiting. Check Operations before submitting another.')
    values['message']='Queued. Earlier requests for this account will be processed first.'
    inserted=db.session.execute(insert(Job).values(**values).on_conflict_do_nothing(index_elements=[Job.account_id,Job.request_key]).returning(Job.id)).scalar_one_or_none()
    if inserted is None:
        existing=Job.query.filter_by(account_id=aid,request_key=key).one_or_none()
        if existing is None:
            raise JobConflict('The request could not be queued. Recover using the original request identifier.')
        if existing.fingerprint!=signature or existing.channel!=channel:
            raise JobConflict('This request identifier was already used for different settings.')
        jid=existing.id
    job=db.session.get(Job,jid)
    result=serialize(job)
    if commit:db.session.commit()
    return result


def submit_web(account,op,*,validate=None):
    key=request.headers.get('Idempotency-Key') or request.form.get('rp_request_id') or secrets.token_hex(16)
    try:
        data=enqueue(account,op,'web:'+key,commit=True,validate=validate)
    except JobConflict as exc:
        db.session.rollback()
        return {'error':str(exc),'operations_url':'/r/operations'},409
    return {'ok':True,'operation':data},202


def claim():
    now=s.now()
    job=db.session.execute(select(Job).from_statement(claim_statement(Job.__table__,now))).scalar_one_or_none()
    if not job:
        db.session.rollback()
        return None
    if (now-job.created_at).total_seconds()>=MAX_WAIT_SECONDS:
        job.state='rejected';job.finished_at=now;job.payload_enc=None;job.stage='not_applied'
        job.message='Request expired while waiting; no change was attempted. Submit a new request.'
        job.notify_after=now if job.channel=='bot' else None
        db.session.commit()
        return None
    jid=job.id
    job.state='running';job.started_at=now;job.attempts+=1;job.stage='preflight';job.message='Checking permissions and resources.'
    attempt=job.attempts
    try:db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        if getattr(getattr(exc.orig,'diag',None),'constraint_name',None)=='uq_rp_job_running_account':
            return None
        raise
    except Exception as exc:
        db.session.rollback()
        raise ClaimUncertain(jid,attempt) from exc
    return jid,attempt


def finish(jid,state,message,result=None,expected_attempt=None):
    job=db.session.get(Job,jid,with_for_update=True)
    if not job or job.state!='running' or (expected_attempt is not None and job.attempts!=expected_attempt):return
    job.state=state;job.message=message;job.result=result;job.finished_at=s.now()
    job.stage={'completed':'finalized','rejected':'not_applied','review':'uncertain'}.get(state,job.stage)
    if state!='review':job.payload_enc=None
    job.notify_after=s.now() if job.channel=='bot' else None


def require(account,job,op,host=None):
    if not account or account.session_version!=job.session_version or account.generation!=job.generation:
        raise Rejected('Account or plan changed. Submit a new request.')
    if not account.spec.get('panel_access') or account.state!='active' or account.expires_at<=s.now():raise Rejected('Account access changed.')
    if (job.channel=='bot' or op['action'] not in ('delete','disable')) and not s.active(account):raise Rejected('Account allowance changed.')
    perms=set(account.spec['permissions']);required={op['section'],GRANTS[op['action']]}
    if op['action']=='attach':required.add('create')
    if op.get('count',1)>1 or op.get('bulk') or op.get('ids'):required.add('bulk')
    if not required<=perms:raise Rejected('Operation permission changed.')
    if job.request_key.startswith('app:'):
        from .bot_apps import app_grants, key_name
        from panel_core.application_limits import limits_key, permits
        if not permits(s.setting(limits_key('workspace',account.id)),check_ip=False):
            raise Rejected('Application credential expired or policy invalid.')
        kid=op.get('application_key_id')
        if kid:
            from .application_credentials import credential, matches, owns_request
            row=credential(s,'workspace',account.id,kid)
            valid=owns_request(job.request_key,kid) and matches(row,op.get('application_key_digest'),check_ip=False) and required<=app_grants(account,row)
        else:
            valid=required<=app_grants(account) and bool(op.get('application_key_digest')) and s.setting(key_name('workspace',account.id))==op['application_key_digest']
        if not valid:raise Rejected('Application authorization changed. Submit a new request.')
    if job.channel=='bot':
        from .management_bot import allowed,reserved_ids
        from .telegram_policy import effective
        bot=db.session.get(ManagementBot,account.id)
        if not allowed(account,bot) or bot.revision!=job.bot_revision or account.telegram_id!=job.recipient or not required<=effective(account):
            raise Rejected('Telegram authorization changed.')
        if host is not None and bot.bot_id in reserved_ids(host):raise Rejected('Telegram bot identity changed.')
        return bot


def execute_web(a,op,host,usage,record,on_external_start,on_external_rollback):
    section,action=op['section'],op['action']
    if action=='create':
        return s.provision(a,op['interfaces'],op['options']['name'],section=='subscriptions',host,
                           options=op['options'],count=op.get('count',1),usage_sample=usage,on_created=record,on_external_start=on_external_start,on_external_rollback=on_external_rollback)
    if action=='attach':
        sid=m.attach_existing(a,op['peer_ids'],op['options'],host)
        return dict(section='subscriptions',ids=[sid])
    ids=op.get('ids') or [op['id']]
    if op.get('ids') and len(ids)==1:
        from .limits import batch
        batch(a,len(ids))
    return m.execute_customer_actions(a,section,action,ids,op.get('options',{}),host)


def rejection_message(exc):
    if isinstance(exc,Rejected):return str(exc)[:240]
    address_code=getattr(exc,'error_code',None) or getattr(exc,'code',None)
    address_messages={
        'address_conflict':'The selected IP address is already in use. Choose Automatic allocation or another available address.',
        'address_pool_exhausted':'No free client address is available on this interface. Select another interface or contact the administrator.',
        'invalid_address':'The selected address is not valid for this interface. Choose Automatic allocation or a valid address.',
        'node_no_available_ip':'The remote interface has no available client address. Choose another interface or contact the administrator.',
    }
    if address_code in address_messages:return address_messages[address_code]
    if isinstance(exc,ValueError):
        detail=str(exc).lower()
        for words,message in (
            (('usage monitor is offline',),'Usage monitor is offline. Ask the administrator to check the monitor service.'),
            (('peer limit','subscription limit','customer limit'),'The plan customer limit has been reached.'),
            (('allows at most',),'The requested batch exceeds the plan operation limit. Reduce the batch size.'),
            (('suspended, expired, or out of traffic',),'The account is suspended, expired, or out of traffic.'),
            (('usage monitor','node usage','usage is unavailable','customer traffic changed'),'Current usage could not be verified. Retry after the monitor updates.'),
            (('creation requests',),'Creation rate limit reached. Wait one minute.'),
            (('plan settings changed',),'The plan settings changed. Review the customer settings again.'),
            (('interface','address'),'Review the selected interface and client address.'),
        ):
            if any(word in detail for word in words):return message
    return 'No customer change was confirmed. Check customer settings and permissions.'


def process(jid,host):
    started=False
    ever_started=False
    try:
        job=db.session.get(Job,jid)
        if not job or job.state!='running':return
        aid=job.account_id;channel=job.channel;attempt=job.attempts
        op=json.loads(s.decrypt(job.payload_enc))
        require(db.session.get(Account,aid),job,op,host)
        if (s.now()-job.created_at).total_seconds()>=MAX_WAIT_SECONDS:raise Rejected('Request expired while waiting. Submit it again.')
        db.session.rollback()
        from .bot_customers import METADATA_FIELDS
        metadata_only=channel=='bot' and op['action']=='edit' and op.get('field') in METADATA_FIELDS
        if op['action']=='create':
            lock=s.provisioning(aid,host,[op['iface']] if channel=='bot' else op['interfaces'],split_usage=True)
        elif metadata_only:
            lock=s.account_settings(aid)
        elif op['action']=='disable':
            lock=s.targeted_disable(aid,op['section'],op.get('ids') or [op['id']])
        else:
            lock=s.locked(aid,wait_seconds=1,additional_interfaces=[])
        with lock as usage:
            job=db.session.get(Job,jid);a=db.session.get(Account,aid)
            b=require(a,job,op,host)
            if (s.now()-job.created_at).total_seconds()>=MAX_WAIT_SECONDS:raise Rejected('Request expired while waiting. Submit it again.')
            if op['action']=='create':
                if channel=='bot':
                    from .bot_customers import checked_operation
                    checked_operation(a,op,host)
                else:
                    if any(i not in a.spec['interfaces'] for i in op['interfaces']):raise Rejected('Interface permission changed.')
                    m.validate_options(a,op['options'])
            elif channel=='web':
                if op['action']=='attach':
                    for rid in op['peer_ids']:m.target(a,'peers',rid)
                    m.validate_options(a,op['options'])
                else:
                    for rid in op.get('ids') or [op['id']]:m.target(a,op['section'],rid)
                    if op['action']=='edit':m.validate_options(a,op['options'])
            else:
                m.target(a,op['section'],op['id'])
                if op['action']=='edit':
                    from .bot_customers import edit_values
                    _,values,_=edit_values(a,op,host)
                    m.validate_options(a,values)
            def external_started():
                nonlocal started,ever_started
                from .operation_recovery import mark_applying
                mark_applying(db.engine,Job.__table__,jid,attempt)
                started=ever_started=True
            if op['action']!='create':external_started()
            def external_rolled_back():
                nonlocal started
                started=False
            def record(current,result):
                current_job=db.session.get(Job,jid)
                require(current,current_job,op,host)
                finish(jid,'completed','Operation completed.',result)
            if channel=='bot':
                from .management_bot import execute
                result=execute(a,b,op,host,usage_sample=usage,on_created=record,on_external_start=external_started,on_external_rollback=external_rolled_back)
            else:result=execute_web(a,op,host,usage,record,external_started,external_rolled_back)
            finish(jid,'completed','Operation completed.',result)
        current_app.logger.info('Provision operation account=%s id=%s state=completed',aid,jid)
    except Exception as exc:
        db.session.rollback()
        job=db.session.get(Job,jid,with_for_update=True)
        if not job or job.state!='running':
            db.session.rollback();return
        if not ever_started and isinstance(exc,s.WorkspaceLockTimeout) and job.attempts<60 and (s.now()-job.created_at).total_seconds()<MAX_WAIT_SECONDS:
            job.state='queued';job.started_at=None;job.stage=None
            job.message='Waiting for the selected interface, account or a fresh usage sample.'
            job.available_at=s.now()+timedelta(seconds=min(10,job.attempts))
        elif not started:
            message=rejection_message(exc)
            finish(jid,'rejected',message)
        else:
            finish(jid,'review','Completion could not be verified. Ask the administrator to reconcile before submitting again.')
        log=current_app.logger.warning if job.state=='review' else current_app.logger.info
        log('Provision operation account=%s id=%s state=%s error=%s',job.account_id,jid,job.state,type(exc).__name__)
        db.session.commit()


def recover(jid=None,attempt=None):
    from .operation_recovery import recover_interrupted
    recover_interrupted(db.session,Job.__table__,s.now(),jid=jid,attempt=attempt)
    db.session.commit()


def run_lane(app,host,stop):
    from .worker_supervision import pulse
    uncertain=None
    while not stop.is_set():
        jid=None
        with app.app_context():
            try:
                if uncertain:
                    recover(uncertain[0],uncertain[1]);uncertain=None
                claimed=claim()
                if claimed:
                    jid,attempt=claimed
                    uncertain=claimed
                    process(jid,host)
                    uncertain=None
                pulse()
            except ClaimUncertain as exc:
                uncertain=(exc.jid,exc.attempt)
                app.logger.warning('Provision queue claim needs verification id=%s',exc.jid)
            except Exception as exc:
                app.logger.warning('Provision queue deferred: %s',type(exc).__name__)
            finally:db.session.remove()
        stop.wait(.5 if jid else 1.5)


def bot_result_payload(job, fa):
    from .management_bot import created_reply, reply
    from .bot_customers import button
    if job.state=='completed' and job.action=='create' and job.result:
        payload=created_reply(job.result,fa)
    else:
        labels={'queued':('Queued. Waiting for processing.','در صف پردازش.'),
                'running':('Processing your request.','در حال پردازش درخواست.'),
                'completed':('Operation completed.','عملیات انجام شد.'),
                'rejected':('Operation was not completed. Review the settings.','عملیات انجام نشد. تنظیمات را بررسی کنید.'),
                'review':('Administrator review required. Do not repeat the request.','نیاز به بررسی مدیر. درخواست را تکرار نکنید.'),
                'resolved':('Administrator review closed.','بررسی مدیر پایان یافت.')}
        message=labels.get(job.state,('Unknown status.','وضعیت نامشخص.'))[int(fa)]
        if job.state in ('queued','running','rejected') and job.message:
            message+=('\nجزئیات: ' if fa else '\nDetails: ')+job.message[:240]
        label=('کاربران' if job.section=='peers' else 'اشتراک‌ها') if fa else 'View customers'
        rows=[[button(label,job.section+' 0')]]
        if job.state in ('queued','running','review'):
            rows.insert(0,[button('بررسی وضعیت' if fa else 'Check status','operation '+job.id)])
        payload=reply(message,rows)
    payload['text']+='\n'+('کد پیگیری: ' if fa else 'Reference: ')+job.id
    return payload


def bot_status(account, bot, jid):
    from .management_bot import allowed, reply
    from .telegram_policy import effective
    fa=bot.language=='fa'
    job=Job.query.filter_by(id=jid,account_id=account.id,channel='bot').one_or_none() if re.fullmatch(r'[0-9a-f]{32}',jid) else None
    if (not job or not allowed(account,bot) or job.recipient!=account.telegram_id
            or job.bot_revision!=bot.revision or job.session_version!=account.session_version
            or job.generation!=account.generation or not {job.section,GRANTS.get(job.action)}<=effective(account)):
        return reply('درخواست یافت نشد یا دسترسی تغییر کرده است.' if fa else 'Operation not found or access changed.')
    return bot_result_payload(job,fa)


def notify_one():
    from .management_bot import allowed, reserved_ids
    from .telegram_policy import effective
    from .worker import telegram, TelegramTransportError
    job=Job.query.filter(Job.channel=='bot',Job.state.in_(FINAL),Job.notified_at.is_(None),
                         Job.notify_after<=s.now(),Job.notify_attempts<6).order_by(Job.notify_after,Job.id).first()
    if not job:return False
    jid=job.id;aid=job.account_id;a=db.session.get(Account,aid);b=db.session.get(ManagementBot,aid)
    if (not allowed(a,b) or b.revision!=job.bot_revision or a.telegram_id!=job.recipient
        or a.session_version!=job.session_version or a.generation!=job.generation
        or not {job.section,GRANTS[job.action]}<=effective(a)):
        job.notify_after=None;db.session.commit()
        current_app.logger.warning('Provision result suppressed account=%s id=%s reason=authorization_changed',aid,jid)
        return True
    if b.bot_id in reserved_ids(current_app.extensions['rp_queue_host']):
        job.notify_after=None;db.session.commit()
        current_app.logger.warning('Provision result suppressed account=%s id=%s reason=bot_identity_conflict',aid,jid)
        return True
    recipient=job.recipient;token=s.decrypt(b.token_enc)
    payload=bot_result_payload(job,b.language=='fa')
    db.session.rollback()
    try:telegram(token,'sendMessage',{'chat_id':recipient,**payload})
    except Exception as exc:
        job=db.session.get(Job,jid)
        if not job:return True
        job.notify_attempts+=1
        retryable=not isinstance(exc,TelegramTransportError) or exc.retryable
        retryable=retryable and job.notify_attempts<6
        delay=max(getattr(exc,'retry_after',0),min(300,10*2**job.notify_attempts))
        job.notify_after=s.now()+timedelta(seconds=delay) if retryable else None
        current_app.logger.warning('Provision result delivery %s account=%s id=%s attempt=%s error=%s code=%s',
            'retry' if retryable else 'stopped',aid,jid,job.notify_attempts,type(exc).__name__,getattr(exc,'code',None))
    else:
        job=db.session.get(Job,jid)
        if not job:return True
        job.notified_at=s.now();job.notify_after=None
        current_app.logger.info('Provision result delivered account=%s id=%s',aid,jid)
    db.session.commit()
    return True


def run_notifications(app,stop):
    from .worker_supervision import pulse
    from .worker import workspace_telegram_clients
    with workspace_telegram_clients() as connect:
        connect()
        while not stop.is_set():
            processed=False
            with app.app_context():
                try:
                    processed=notify_one()
                    pulse()
                except Exception as exc:app.logger.warning('Provision result delivery deferred: %s',type(exc).__name__)
                finally:db.session.remove()
            stop.wait(.1 if processed else 1)


def prepare(app,host,stop):
    app.extensions['rp_queue_host']=host
    while not stop.is_set():
        with app.app_context():
            try:
                recover()
                return True
            except Exception as exc:
                app.logger.warning('Provision queue startup deferred: %s',type(exc).__name__)
            finally:db.session.remove()
        stop.wait(5)
    return False


def register(bp,member,admin):
    @bp.get('/r/api/operations/request/<key>')
    @member()
    def operation_by_request(key):
        if not re.fullmatch(r'[A-Za-z0-9:_-]{1,92}',key):abort(404)
        job=Job.query.filter_by(account_id=g.reseller.id,request_key='web:'+key,channel='web').first_or_404()
        response=current_app.json.response(serialize(job))
        response.headers['Cache-Control']='private, no-store'
        return response

    @bp.get('/r/api/operations/<jid>')
    @member()
    def operation_status(jid):
        job=Job.query.filter_by(id=jid,account_id=g.reseller.id).first_or_404()
        response=current_app.json.response(serialize(job))
        response.headers['Cache-Control']='private, no-store'
        return response

    @bp.get('/r/operations')
    @bp.get('/r/operations/<jid>')
    @member()
    def operations(jid=None):
        query=Job.query.filter_by(account_id=g.reseller.id)
        if jid:query=query.filter_by(id=jid)
        from .operation_history import history_page
        history=None
        if jid:
            rows=query.all()
            if not rows:abort(404)
        else:
            rows,history=history_page(query,Job,request.args)
        return render_template('reseller/operations.html',rows=rows,administrator=False,account=g.reseller,reseller_mode=True,section='operations',HAS_NODES=False,HAS_SETTINGS=False,detail_id=jid,history=history)

    @bp.get('/resellers/operations')
    @admin
    def admin_operations():
        from .operation_history import history_page
        rows,history=history_page(Job.query,Job,request.args,administrator=True)
        details={}
        for job in rows:
            if job.state!='review' or not job.payload_enc:continue
            try:
                op=json.loads(s.decrypt(job.payload_enc))
                details[job.id]=dict(interfaces=op.get('interfaces') or ([op['iface']] if op.get('iface') else []),targets=op.get('ids') or op.get('peer_ids') or ([op['id']] if op.get('id') else []),name=str((op.get('options') or {}).get('name',''))[:48])
            except Exception:details[job.id]={}
        return render_template('reseller/operations.html',rows=rows,administrator=True,details=details,detail_id=None,history=history)

    @bp.post('/resellers/operations/<jid>/resolve')
    @admin
    def resolve_operation(jid):
        if request.form.get('confirm')!='REVIEWED':raise ValueError('Confirm the interface and database were reconciled.')
        job=db.session.get(Job,jid,with_for_update=True)
        if not job or job.state!='review':abort(404)
        job.state='resolved';job.stage='resolved';job.payload_enc=None;job.message='Administrator closed the reconciliation review.'
        from flask_login import current_user
        s.audit(current_user.username,'provision_review_closed',jid)
        db.session.commit()
        return redirect(url_for('reseller.admin_operations'))
