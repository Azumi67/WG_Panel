
import os
import time
import threading
import requests
import json
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta
from . import service as s
from .models import Account, Plan, Order, Notice
from models import db
from sqlalchemy.exc import OperationalError
from cryptography.fernet import InvalidToken
from .database import SettingsWriterBusy, settings_transaction
from .bot_runtime_log import event as bot_event
from .worker_supervision import pulse

class MessageEditUnavailable(RuntimeError):
    pass

class TelegramTransportError(RuntimeError):
    def __init__(self,message,*,retryable=True,retry_after=0,code=None):
        super().__init__(message)
        self.retryable=retryable
        self.retry_after=retry_after
        self.code=code


def validate_updates(updates):
    if not isinstance(updates,list) or any(not isinstance(u,dict) or type(u.get('update_id')) is not int or u['update_id']<0 or
            any(k in u and not isinstance(u[k],dict) for k in ('message','callback_query')) for u in updates):
        raise TelegramTransportError('Telegram getUpdates returned an unexpected result.')
    return sorted({u['update_id']:u for u in updates}.values(),key=lambda u:u['update_id'])


_telegram_http=threading.local()


@contextmanager
def workspace_telegram_clients():
    opened=[]
    lock=threading.Lock()
    def connect():
        client=requests.Session()
        _telegram_http.client=client
        with lock:opened.append(client)
    try:yield connect
    finally:
        for client in opened:client.close()


@contextmanager
def callback_answers(connect, prefix):
    slots = threading.BoundedSemaphore(8)
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix=prefix, initializer=connect) as pool:
        def acknowledge(transport, token, callback_id):
            if not slots.acquire(blocking=False):
                return
            def send():
                try:
                    transport(token, 'answerCallbackQuery', {'callback_query_id':callback_id})
                except RuntimeError:
                    pass
                finally:
                    slots.release()
            try:pool.submit(send)
            except RuntimeError:slots.release()
        yield acknowledge


def telegram(token, method, payload, *, files=None):
    if method == 'getUpdates' and 'timeout' in payload:
        timeout = (3, max(5, int(payload['timeout']) + 5))
    elif method == 'answerCallbackQuery':
        timeout = (2, 3)
    elif method in ('getMe', 'getWebhookInfo', 'setMyCommands', 'setChatMenuButton'):
        timeout = (3, 6)
    else:
        timeout = (5, 25)
    try:
        client = getattr(_telegram_http,'client',requests)
        response = client.post('https://api.telegram.org/bot'+token+'/'+method,
                                 **({'data':payload,'files':files} if files is not None else {'json':payload}),
                                 timeout=timeout, allow_redirects=False)
    except requests.Timeout:
        raise TelegramTransportError('Telegram timed out during '+method+'.') from None
    except requests.ConnectionError:
        raise TelegramTransportError('Telegram connection failed during '+method+'.') from None
    except requests.RequestException:
        raise TelegramTransportError('Telegram transport failed during '+method+'.') from None
    try:
        data = response.json()
    except ValueError:
        status = getattr(response, 'status_code', None)
        suffix = f' (HTTP {status})' if isinstance(status, int) else ''
        raise TelegramTransportError('Telegram returned a non-JSON response during '+method+suffix+'.',retryable=status not in (400,401,403,404),code=status) from None
    if not isinstance(data, dict):
        raise TelegramTransportError('Telegram did not return a usable response during '+method+'.')
    if not data.get('ok'):
        if method == 'editMessageText' and data.get('error_code') == 400:
            reason = str(data.get('description', '')).lower()
            if 'message is not modified' in reason:
                return True
            if any(text in reason for text in ("message to edit not found", "message can't be edited",
                                               "message can not be edited", "there is no text in the message to edit")):
                raise MessageEditUnavailable('The original message can no longer be edited.')
        code=data.get('error_code')
        if type(code) is not int:code=getattr(response,'status_code',None)
        parameters=data.get('parameters')
        retry=parameters.get('retry_after') if isinstance(parameters,dict) else None
        retry_after=max(1,int(retry)) if code==429 and type(retry) in (float,int) and 0<retry<=86400 else 0
        reason={400:'invalid request',401:'authentication rejected',403:'access forbidden',409:'another poller or webhook is active',429:'rate limited'}.get(code,'request rejected')
        raise TelegramTransportError('Telegram '+method+': '+reason+'.',retryable=code not in (400,401,403,404),retry_after=retry_after,code=code)
    if 'result' not in data:
        raise TelegramTransportError('Telegram response was incomplete during '+method+'.')
    return data['result']

def send_media(token,result,chat_id):
    from .bot_peer_delivery import transport_request
    method,data,files=transport_request(result,chat_id)
    return telegram(token,method,data,files=files)


def show_message(token, payload, message_id=None):
    if message_id:
        try:
            edit = {key:value for key,value in payload.items() if key!='protect_content'}
            return telegram(token, 'editMessageText', {**edit, 'message_id': message_id})
        except MessageEditUnavailable:
            pass
    return telegram(token, 'sendMessage', payload)

from .bot_ui import handle
MENU={"remove_keyboard":True}

def acknowledge_notices(confirmed):
    if confirmed:
        with settings_transaction(label='shop:delivery-receipt'):
            Notice.query.filter(Notice.id.in_(confirmed), Notice.sent_at.is_(None)).update(
                {Notice.sent_at:s.now(), Notice.error:None}, synchronize_session=False)
        confirmed.clear()

def retry_notice(notice, reason, retry_after=0):
    notice.attempts += 1
    notice.retry_at = s.now() + timedelta(seconds=max(retry_after,min(3600, 30 * 2**min(notice.attempts, 7))))
    notice.error = reason


def interactive_notice():
    return Notice.dedupe.startswith('0:0:update:') | Notice.dedupe.startswith('0:0:keyboard:')


def due_notices():
    return Notice.query.filter(Notice.sent_at.is_(None), Notice.telegram_id.isnot(None), Notice.retry_at <= s.now())


def deliver(token, expected_token=None, *, confirmed=None, stop=None, chat=None, background=False):
    from panel_core.telegram_notices import telegram_body, unpack
    from .plan_reminders import deliver_one, is_reminder
    confirmed = set() if confirmed is None else confirmed
    acknowledge_notices(confirmed)
    query = due_notices()
    if chat is not None:
        query = query.filter(interactive_notice(), Notice.telegram_id == chat)
    elif background:
        query = query.filter(~interactive_notice())
    due = query.with_entities(Notice.id).order_by(Notice.id).limit(20).all()
    db.session.rollback()
    for (nid,) in due:
        if stop is not None and stop.is_set():
            return
        with settings_transaction(label='shop:delivery-claim'):
            if expected_token is not None and (s.setting('bot_token') != expected_token or not s.setting('bot_enabled', False)):
                return
            notice = db.session.get(Notice, nid, with_for_update=True)
            if not notice or notice.sent_at or not notice.telegram_id or notice.retry_at > s.now():
                continue
            reminder = is_reminder(notice)
            if chat is not None and notice.created_at and notice.created_at < s.now()-timedelta(minutes=15):
                notice.telegram_id=None;notice.error='Interactive reply expired.'
                continue
            if not reminder:
                if notice.account_id:
                    owner = db.session.get(Account, notice.account_id)
                    if not owner or owner.telegram_id != notice.telegram_id:
                        notice.telegram_id = None
                        continue
                try:
                    body = s.decrypt(notice.body_enc)
                    payload = unpack(body)
                    if not isinstance(payload, dict) or not isinstance(payload.get('text'), str) or not isinstance(payload.get('reply_markup',{}),dict):
                        raise ValueError('Invalid message')
                    if body.startswith('RPBOT1:'):
                        from .bot_ui import refresh_workspace_button
                        if not refresh_workspace_button(payload, notice.telegram_id):
                            notice.telegram_id = None
                            continue
                        if chat is not None and Notice.query.filter(interactive_notice(), Notice.telegram_id==chat,
                                Notice.id>nid, Notice.sent_at.isnot(None)).first():
                            notice.sent_at=s.now()
                            continue
                    args = {'chat_id':notice.telegram_id, **telegram_body(payload), 'link_preview_options':{'is_disabled':True}}
                    if payload.get('workspace_owner') is not None:
                        args['protect_content'] = True
                except (InvalidToken, ValueError, TypeError):
                    retry_notice(notice, 'The saved message could not be read. Check the panel encryption key.')
                    continue
                if 'reply_markup' not in args and not body.startswith('RPNOTICE:'):
                    args['reply_markup'] = MENU
                notice.retry_at = s.now() + timedelta(minutes=2)
        if reminder:
            deliver_one(nid, telegram)
            continue
        try:
            show_message(token, args, payload.get('edit_id'))
        except RuntimeError as exc:
            bot_event('shop','WARNING','notice_delivery_deferred',error=exc)
            with settings_transaction():
                notice = db.session.get(Notice, nid, with_for_update=True)
                if notice and not notice.sent_at:
                    if isinstance(exc,TelegramTransportError) and not exc.retryable and exc.code!=401:
                        notice.telegram_id=None
                        notice.error=str(exc)[:160]
                    else:
                        retry_notice(notice, str(exc) if isinstance(exc, TelegramTransportError) else 'Delivery failed. A retry is scheduled.',getattr(exc,'retry_after',0))
        else:
            confirmed.add(nid)
            acknowledge_notices(confirmed)


def shop_wakeup(app):
    return app.extensions.setdefault('plan_shop_wakeup', threading.Event())


def run_shop_delivery(app, stop):
    from sqlalchemy import func
    wake = shop_wakeup(app)
    def send_chat(chat, token, encrypted, confirmed):
        with app.app_context():
            try:
                deliver(token, encrypted, confirmed=confirmed, stop=stop, chat=chat)
            finally:
                db.session.remove()
    with (workspace_telegram_clients() as connect,
          ThreadPoolExecutor(max_workers=4, initializer=connect, thread_name_prefix='shop-replies') as replies,
          app.app_context()):
        pending = {}
        pending_since = {}
        receipts = {}
        while not stop.is_set():
            wake.clear()
            try:
                for chat, future in list(pending.items()):
                    if future.done():
                        del pending[chat]
                        pending_since.pop(chat, None)
                        if future.exception():
                            bot_event('shop','WARNING','reply_delivery_deferred',error=future.exception())
                            app.logger.warning('Plan shop reply delivery deferred (%s).', type(future.exception()).__name__)
                        if not receipts[chat]:
                            del receipts[chat]
                config = s.settings_many(('bot_token','bot_enabled'))
                encrypted = config.get('bot_token')
                if len(pending)<4 and encrypted and config.get('bot_enabled'):
                    query = due_notices().filter(interactive_notice())
                    if pending:
                        query = query.filter(~Notice.telegram_id.in_(pending))
                    chats = [chat for chat, in query.with_entities(Notice.telegram_id).group_by(Notice.telegram_id)
                             .order_by(func.min(Notice.id)).limit(4-len(pending))]
                    chats = list(dict.fromkeys([c for c in receipts if c not in pending]+chats))[:4-len(pending)]
                    for chat in chats:
                        future = replies.submit(send_chat, chat, s.decrypt(encrypted), encrypted, receipts.setdefault(chat,set()))
                        pending[chat] = future
                        pending_since[chat] = time.monotonic()
                        future.add_done_callback(lambda _: wake.set())
                if all(time.monotonic()-at < 180 for at in pending_since.values()):
                    pulse()
            except Exception as exc:
                app.logger.warning('Plan shop reply queue will retry (%s).',type(exc).__name__)
            finally:
                db.session.remove()
            if not stop.is_set():
                wake.wait(1)


def run_shop_notices(app, stop):
    confirmed = set()
    with app.app_context():
        while not stop.is_set():
            try:
                acknowledge_notices(confirmed)
                config = s.settings_many(('bot_enabled', 'bot_token'))
                encrypted = config.get('bot_token')
                if config.get('bot_enabled') and encrypted:
                    deliver(s.decrypt(encrypted), encrypted, confirmed=confirmed, stop=stop, background=True)
                pulse()
            except (SettingsWriterBusy, OperationalError) as exc:
                from .database import writer_busy
                bot_event('shop','WARNING','delivery_database_busy' if writer_busy(exc) else 'delivery_database_error',error=exc)
                app.logger.warning('Plan shop delivery will resume when the database is ready.')
            except Exception as exc:
                bot_event('shop','ERROR','delivery_failed',error=exc)
                app.logger.error('Plan shop delivery could not finish (%s).', type(exc).__name__)
            finally:
                db.session.remove()
            stop.wait(1)


def telegram_cycle(wake=None, acknowledge=None, publish_menu=None):
    config = s.settings_many(('bot_enabled','bot_token','bot_username','bot_offset','bot_poll_at','bot_error'))
    encrypted=config.get('bot_token')
    if not config.get('bot_enabled') or not encrypted:return
    token=s.decrypt(encrypted)
    username=config.get('bot_username')
    offset=config.get('bot_offset',0)
    last_poll=config.get('bot_poll_at')
    update_health=not last_poll or config.get('bot_error') or (s.now()-datetime.fromisoformat(last_poll)).total_seconds()>=30
    db.session.rollback()
    if publish_menu:
        from panel_core.telegram_commands import SHOP
        publish_menu.submit(token,None,'shop-menu',SHOP)
    if not username:
        info=telegram(token,'getMe',{})
        with settings_transaction():
            if s.setting('bot_token')==encrypted:s.put('bot_username',info.get('username'))
    db.session.rollback()
    try:
        updates=telegram(token,'getUpdates',{'offset':offset,'timeout':10,'limit':20,'allowed_updates':['message','callback_query']})
    except TelegramTransportError as exc:
        exc.expected_token = encrypted
        raise
    try:
        updates=validate_updates(updates)
    except TelegramTransportError as exc:
        exc.expected_token=encrypted
        raise
    for update in updates:


        callback_id = (update.get('callback_query') or {}).get('id')
        if update['update_id']>=offset and callback_id:
            from .management_bot import answer_callback
            (acknowledge or answer_callback)(telegram, token, callback_id)
    for update in updates:
        if update['update_id']<offset:continue
        menu_preference=None
        with settings_transaction(label='plan-shop:update'):
            if s.setting('bot_token')!=encrypted or not s.setting('bot_enabled',False):return
            if update['update_id']>=s.setting('bot_offset',0):
                menu_preference=handle(update);s.put('bot_offset',update['update_id']+1)
        if publish_menu and menu_preference:
            from panel_core.telegram_commands import SHOP
            chat,language=menu_preference
            publish_menu.submit(token,chat,('shop',language),SHOP,language,selected=True)
        bot_event('shop','INFO','update_processed',update_id=update['update_id'],kind='callback' if update.get('callback_query') else 'message')
        if wake is not None:
            wake.set()
    if update_health:
        with settings_transaction(label='shop:poll-health', health_only=True):
            if s.setting('bot_token')!=encrypted or not s.setting('bot_enabled',False):return
            s.put('bot_error',None);s.put('bot_poll_at',s.now().isoformat())
    return True


def run_telegram(app,stop):
    consecutive_transport_errors=0
    wake = shop_wakeup(app)
    from panel_core.telegram_commands import MenuPublisher
    with workspace_telegram_clients() as connect, callback_answers(connect,'shop-buttons') as acknowledge, MenuPublisher(telegram) as publisher, app.app_context():
        connect()
        bot_event('shop','INFO','poller_started')
        while not stop.is_set():
            started = time.monotonic()
            delay = 1
            try:
                if telegram_cycle(wake, acknowledge, publisher):
                    consecutive_transport_errors=0
                    delay = max(0, .02-(time.monotonic()-started))
                pulse()
            except (SettingsWriterBusy,OperationalError) as exc:
                db.session.rollback()
                from .database import writer_busy
                bot_event('shop','WARNING','poll_database_busy' if writer_busy(exc) else 'poll_database_error',error=exc)
                app.logger.warning('Plan shop database operation deferred.')
            except (RuntimeError, ValueError) as exc:
                db.session.rollback()
                bot_event('shop','WARNING','poll_failed',error=exc)
                detail = str(exc) if isinstance(exc, TelegramTransportError) else 'Plan shop polling failed. Check the bot runtime log.'
                if isinstance(exc, TelegramTransportError):
                    consecutive_transport_errors += 1
                    delay = max(min(30, 2 ** min(consecutive_transport_errors, 5)), getattr(exc, 'retry_after', 0))
                try:
                    expected = getattr(exc, 'expected_token', None)
                    current = s.settings_many(('bot_error', 'bot_token', 'bot_enabled'))
                    if current.get('bot_enabled') and current.get('bot_error') != detail and (expected is None or current.get('bot_token') == expected):
                        app.logger.warning('%s', detail)
                        with settings_transaction(label='shop:poll-error', health_only=True):
                            if s.setting('bot_enabled', False) and s.setting('bot_token') == current.get('bot_token'):
                                s.put('bot_error', detail)
                except (SettingsWriterBusy, OperationalError):
                    db.session.rollback()
            except Exception as exc:
                bot_event('shop','ERROR','update_processing_failed',error=exc)
                app.logger.error('Plan shop updates could not be processed (%s).', type(exc).__name__)
            finally:db.session.remove()
            stop.wait(delay)


def monitor_local_samples(host):
    prepared = s.prepare_local_sample(host)
    return prepared if prepared and prepared[0] else None


def idle_write_batches(due_ids, size=5):
    if size < 1:
        raise ValueError('Batch size must be positive.')
    ordered = sorted(set(due_ids))
    for index in range(0, len(ordered), size):
        yield ordered[index:index + size]


def record_idle_accounts(ids):
    from sqlalchemy import func, or_
    from .models import UsagePoint
    from .management import record_usage
    from .plan_reminders import stage, queue_current


    for offset in range(0,len(ids),50):
        batch=ids[offset:offset+50]
        latest=(db.session.query(func.max(UsagePoint.id)).filter(UsagePoint.account_id.in_(batch))
                .group_by(UsagePoint.account_id))
        samples={row.account_id:row for row in UsagePoint.query.filter(UsagePoint.id.in_(latest))}
        due=set()
        reminders={}
        for account in Account.query.filter(Account.id.in_(batch), Account.state!='deleted'):
            point=samples.get(account.id)
            if (not point or point.generation!=account.generation or point.used_bytes!=account.used_bytes or
                    (s.now()-point.at).total_seconds()>=300):
                due.add(account.id)
            key=stage(account)
            if key:reminders[f'{account.id}:{account.generation}:{key}']=(account.id,account.telegram_id)
        if reminders:
            recorded={key for key, in db.session.query(Notice.dedupe).filter(Notice.dedupe.in_(reminders))}
            candidates=[reminders[key] for key in reminders.keys()-recorded]
            if candidates:
                owners={aid for aid,_ in candidates}
                chats={tid:aid for aid,tid in candidates if tid}
                under_review=Order.awaiting_review().with_entities(Order.account_id,Order.telegram_id).filter(
                    or_(Order.account_id.in_(owners),Order.account_id.is_(None) & Order.telegram_id.in_(chats)))
                waiting={aid if aid is not None else chats[tid] for aid,tid in under_review}
                due.update(owners-waiting)
        db.session.rollback()
        if due:


            for due_batch in idle_write_batches(due):
                with settings_transaction(label='monitor:idle-account-batch'):
                    for account in Account.query.filter(
                            Account.id.in_(due_batch),
                            Account.state != 'deleted'):
                        record_usage(account, cleanup=False)
                        queue_current(account)


def prune_monitor_history():
    from .models import Throttle, UsagePoint
    usage_before=s.now()-timedelta(days=1)
    budget_before=s.now()-timedelta(days=2)
    usage_ids=[i for i, in db.session.query(UsagePoint.id).filter(UsagePoint.at<usage_before)
               .order_by(UsagePoint.at).limit(500)]
    budget_keys=[key for key, in db.session.query(Throttle.key).filter(Throttle.until<budget_before)
                 .order_by(Throttle.until).limit(500)]
    db.session.rollback()
    if usage_ids or budget_keys:
        with settings_transaction(label='monitor:expired-history', health_only=True):
            if usage_ids:
                UsagePoint.query.filter(UsagePoint.id.in_(usage_ids),UsagePoint.at<usage_before).delete(synchronize_session=False)
            if budget_keys:
                Throttle.query.filter(Throttle.key.in_(budget_keys),Throttle.until<budget_before).delete(synchronize_session=False)
    return len(usage_ids)==500 or len(budget_keys)==500


def _monitor_io_host(host):


    operations = (
        '_disable_peer', '_wg_runtime_snapshot', '_wg_checked_runtime_snapshot',
        'node_get', 'node_post', 'activate_reseller_peer',
        'reapply_peer_external', '_wg_transfer',
    )
    checked = dict(host)
    for key in operations:
        target = host.get(key)
        if not callable(target):
            continue
        def execute(*args, _target=target, _name=key, **kwargs):
            from flask import current_app
            started=time.monotonic()
            db.session.commit()
            committed=time.monotonic()
            try:
                return _target(*args, **kwargs)
            finally:
                elapsed=time.monotonic()
                if elapsed-started>=1:
                    current_app.logger.warning('Quota monitor step=%s commit_ms=%.0f operation_ms=%.0f',
                        _name,1000*(committed-started),1000*(elapsed-committed))
        checked[key] = execute
    return checked


def run_history_cleanup(app, stop):
    from .request_guard import prune_imported_events
    with app.app_context():
        while not stop.is_set():
            delay = 300
            try:
                if prune_monitor_history():
                    delay = 10
                prune_imported_events()
                if db.engine.dialect.name == 'postgresql':
                    from .request_guard_pg import prune_expired_budgets
                    prune_expired_budgets()
                pulse()
            except (TimeoutError, OperationalError):
                app.logger.warning('Reseller history cleanup deferred; customer enforcement is unaffected.')
                delay = 30
            except Exception:
                app.logger.exception('Reseller history cleanup failed.')
                delay = 60
            finally:
                db.session.remove()
            stop.wait(delay)


def run_monitor(app,host,stop):
    from .models import Ownership
    from .request_guard import import_events
    last_health = None
    last_failures = None
    with app.app_context():
        while not stop.is_set():
            try:


                ids=[a.id for a in Account.query.filter(Account.state!='deleted').with_entities(Account.id).all()]
                occupied = {aid for aid, in db.session.query(Ownership.account_id).filter_by(deleted=False).distinct()}
                db.session.rollback()
                local_samples = monitor_local_samples(host)
                monitor_host = _monitor_io_host(host)
                failures=[]
                record_idle_accounts([aid for aid in ids if aid not in occupied])
                for aid in (aid for aid in ids if aid in occupied):
                    try:
                        prepared = s.prepare_remote_sample(aid, host)
                        restore_queue = []
                        with s.locked(aid, additional_interfaces=[]):
                            started=time.monotonic()
                            cache = s.checked_remote_sample(aid, prepared)
                            checked=time.monotonic()
                            healthy = s.tick(monitor_host, account_ids=[aid], finish=False, runtime_cache=cache, restore_queue=restore_queue, local_samples=local_samples)
                            elapsed=time.monotonic()
                            if elapsed-started>=2:
                                app.logger.warning('Quota monitor account=%s baseline_ms=%.0f enforcement_ms=%.0f',aid,1000*(checked-started),1000*(elapsed-checked))
                        for index, pid in enumerate(restore_queue):
                            if stop.is_set():
                                return
                            if index:
                                stop.wait(.05)
                            with s.locked(aid, additional_interfaces=[]):
                                account = db.session.get(Account, aid)
                                if not account or not s.active(account):
                                    break
                                try:
                                    row, peer = s.own_peer(account, pid)
                                except ValueError:
                                    continue
                                if not s.restore_plan_peer(account, row, peer, monitor_host):
                                    healthy = False
                        if not healthy:
                            failures.append(aid)
                    except s.WorkspaceLockTimeout:
                        db.session.rollback()
                        failures.append(aid)
                        app.logger.info('Reseller monitor account %s deferred: the same WireGuard interface is being changed; enforcement will retry.', aid)
                    except OperationalError as exc:
                        db.session.rollback()
                        failures.append(aid)
                        from .database import writer_busy
                        if writer_busy(exc):
                            app.logger.warning('Reseller monitor account %s deferred: database writer is busy.', aid)
                        else:
                            app.logger.exception('Reseller monitor account %s database operation failed.', aid)
                    except Exception:
                        db.session.rollback()
                        failures.append(aid)
                        app.logger.exception('Reseller monitor account %s failed; continuing other accounts.',aid)


                try:
                    with settings_transaction(label='monitor:login-audit'):
                        import_events()
                except TimeoutError:
                    app.logger.warning('Login audit import deferred; quota enforcement continues.')
                failure_state = tuple(sorted(failures))
                if (last_health is None or time.monotonic()-last_health >= 30
                        or failure_state != last_failures):


                    with settings_transaction(label='monitor:finish', health_only=not failures):
                        s.tick(host, account_ids=[], finish=True, import_audit=False)
                        s.put('monitor_failed_count',len(failures))
                        s.put('monitor_failed_at',s.now().isoformat() if failures else None)
                        if failures:
                            s.put('enforcement_error',f'Quota monitoring failed for {len(failures)} reseller account(s). Some customers may retain access until enforcement recovers.')
                        else:
                            s.put('enforcement_error',None)
                            s.put('monitor_last_healthy_at',s.now().isoformat())
                    last_health = time.monotonic()
                    last_failures = failure_state
                pulse()
            except SettingsWriterBusy:
                db.session.rollback()
                app.logger.warning('Reseller monitor will retry on the next cycle. The database writer is occupied.')
            except Exception:
                db.session.rollback()
                app.logger.exception('Reseller enforcement failed; check worker health and node connectivity.')
                last_health = None
                try:
                    with settings_transaction():
                        s.put('monitor_failed_at',s.now().isoformat())
                        s.put('enforcement_error','Reseller monitoring cycle failed. Check worker logs and node connectivity.')
                except Exception:
                    db.session.rollback()
            finally:db.session.remove()
            stop.wait(10)


def run_shop_background(app, stop):
    with workspace_telegram_clients() as connect:
        connect()
        run_shop_notices(app, stop)


def main(argv=None):
    import argparse
    from .worker_supervision import (ROLE_COMPONENTS, ROLE_HEALTH_GROUP, HEALTH_GROUPS, record,
                                     role_lock, stop_signals, supervise, ShutdownTimeout)
    parser = argparse.ArgumentParser(description='Run WG Panel background services')
    parser.add_argument('--role', choices=tuple(ROLE_COMPONENTS), default='combined')
    role = parser.parse_args(argv).role
    os.environ['WG_BACKGROUND_ROLE'] = 'reseller-worker'
    os.environ['WG_DB_POOL_ROLE'] = 'workspace' if role == 'workspace-bots' else role
    from app import app
    from . import HOST
    from .management_bot import run as run_management
    from .purchase_alerts import run as run_purchase_alerts
    stop = threading.Event()
    with role_lock(app.instance_path, role), stop_signals(stop):
        roles = ROLE_COMPONENTS[role]
        names = [name for component in roles for name in HEALTH_GROUPS[ROLE_HEALTH_GROUP[component]]]
        for name in names:record(app.instance_path,name,'starting')
        jobs = []
        if 'workspace-bots' in roles:
            jobs.append((run_management, (app, HOST, stop), 'workspace-bots'))
        if 'monitor' in roles:
            jobs.extend(((run_monitor, (app, HOST, stop), 'quota-monitor'),
                         (run_history_cleanup, (app, stop), 'reseller-history-cleanup')))
        if 'provision' in roles:
            from .provision_queue import prepare, run_lane, run_notifications
            if not prepare(app, HOST, stop):
                for name in names:record(app.instance_path,name,'stopped')
                return
            jobs.extend((run_lane, (app, HOST, stop), 'provision-lane-'+str(i)) for i in range(2))
            jobs.append((run_notifications, (app, stop), 'provision-results'))
        if 'shop' in roles:
            jobs.extend(((run_telegram, (app, stop), 'plan-shop'),
                         (run_shop_delivery, (app, stop), 'plan-shop-delivery'),
                         (run_shop_background, (app, stop), 'plan-shop-notices'),
                         (run_purchase_alerts, (app, HOST, stop), 'purchase-alerts')))
        app.logger.info('Background service started: %s', role)
        try:
            supervise(jobs, stop, app.instance_path, app.logger)
        except ShutdownTimeout:
            
            os._exit(1)


if __name__=='__main__':main()
