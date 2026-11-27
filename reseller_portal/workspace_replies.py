import json
from datetime import timedelta
from threading import Lock

from models import db
from .models import Account, ManagementBot
from . import service as s
from .database import settings_transaction
from .telegram_policy import effective
from .bot_runtime_log import event

TTL = 900
_receipts = {}
_receipt_lock = Lock()


def key(aid):
    return 'bot_reply:' + str(aid)


def binding(a, b):
    return dict(revision=b.revision, recipient=str(a.telegram_id),
                token=s.digest(b.token_enc), session=a.session_version,
                generation=a.generation, grants=sorted(effective(a)),
                expired=a.expires_at <= s.now(), active=s.active(a), language=b.language)


def stage(a, b, uid, result, message_id):
    if not result:
        return
    if 'document' in result or 'operation' in result:
        raise ValueError('Only a deferred export or a text response may be stored.')
    body=json.dumps(dict(binding=binding(a,b), result=result, message_id=message_id), ensure_ascii=False)
    if len(body.encode()) > 65536:
        raise ValueError('Response exceeds the reply queue limit.')
    s.put(key(a.id), dict(uid=uid, created=s.now().isoformat(),
                          retry_at=s.now().isoformat(), attempts=0, body=s.encrypt(body)))


def _save(aid, uid, value):
    with settings_transaction(label='management:reply-receipt'):
        row=s.setting(key(aid),{}) or {}
        if row.get('uid')==uid:
            s.put(key(aid),value)


def _finish(aid, uid, receipt):
    _save(aid,uid,{})
    with _receipt_lock:
        if _receipts.get(aid)==receipt:
            _receipts.pop(aid,None)


def _snapshot(aid, expected):
    from .management_bot import allowed
    a=db.session.get(Account,aid); b=db.session.get(ManagementBot,aid)
    if not allowed(a,b) or binding(a,b)!=expected:
        db.session.rollback()
        return None
    return a,b


def drain(aid, host, telegram, show_message):

    from datetime import datetime
    from .worker import TelegramTransportError, send_media
    row=s.setting(key(aid),{}) or {}
    if not row:
        db.session.rollback()
        return 0
    uid=row.get('uid')
    receipt=(uid,s.digest(str(row.get('body'))))
    with _receipt_lock:
        delivered=_receipts.get(aid)==receipt
    if delivered:
        db.session.rollback()
        _finish(aid,uid,receipt)
        return 0
    try:
        created=datetime.fromisoformat(row['created'])
        due=datetime.fromisoformat(row['retry_at'])
        body=json.loads(s.decrypt(row['body']))
        expected=body['binding']; result=body['result']
    except (ValueError, TypeError, KeyError, RuntimeError) as exc:
        db.session.rollback(); _finish(aid,uid,receipt)
        event('reseller','ERROR','reply_unreadable',account_id=aid,update_id=uid,error=exc)
        return 0
    except Exception as exc:
        from cryptography.fernet import InvalidToken
        if not isinstance(exc,InvalidToken): raise
        db.session.rollback(); _finish(aid,uid,receipt)
        event('reseller','ERROR','reply_unreadable',account_id=aid,update_id=uid,error=exc)
        return 0
    remaining=TTL-(s.now()-created).total_seconds()
    pair=_snapshot(aid,expected)
    if not pair or remaining<=0:
        db.session.rollback(); _finish(aid,uid,receipt)
        event('reseller','WARNING','reply_expired' if remaining<=0 else 'reply_access_changed',account_id=aid,update_id=uid)
        return 0
    delay=(due-s.now()).total_seconds()
    if delay>0:
        db.session.rollback()
        return min(delay,remaining)
    a,b=pair; token=s.decrypt(b.token_enc); chat=str(a.telegram_id)
    try:
        if 'export' in result:
            from .management_bot import prepare_export
            try:
                media=prepare_export(a,b,result,host)
            except ValueError:
                media=None
            db.session.rollback()
            current=_snapshot(aid,expected)
            if not current:
                _finish(aid,uid,receipt)
                event('reseller','WARNING','reply_access_changed',account_id=aid,update_id=uid)
                return 0
            if result['export']!='backup' and media is not None:
                from .management import target
                try:
                    target(current[0],'subscriptions' if result['export']=='subscription_link' else 'peers',result['id'])
                except ValueError:
                    media=None
            db.session.rollback()
            if media is None:
                text='دسترسی به فایل تغییر کرده است. درخواست تازه‌ای ارسال کنید.' if expected['language']=='fa' else 'File access changed. Please request a new download.'
                show_message(token,{'chat_id':chat,'text':text},None)
            elif 'document' in media:
                send_media(token,media,chat)
            else:
                show_message(token,{'chat_id':chat,**media},body.get('message_id'))
        else:
            db.session.rollback()
            show_message(token,{'chat_id':chat,**result},body.get('message_id'))
    except TelegramTransportError as exc:
        db.session.rollback()
        if not exc.retryable:
            _finish(aid,uid,receipt)
            event('reseller','WARNING','reply_rejected',account_id=aid,update_id=uid,error=exc)
            return 0
        attempts=int(row.get('attempts',0))+1
        delay=max(min(60,2**min(attempts,6)),getattr(exc,'retry_after',0))
        _save(aid,uid,{**row,'attempts':attempts,'retry_at':(s.now()+timedelta(seconds=delay)).isoformat()})
        event('reseller','WARNING','reply_deferred',account_id=aid,update_id=uid,error=exc)
        return min(delay,remaining)
    except Exception as exc:
        db.session.rollback()
        
        
        attempts=int(row.get('attempts',0))+1
        delay=min(60,2**min(attempts,6))
        _save(aid,uid,{**row,'attempts':attempts,'retry_at':(s.now()+timedelta(seconds=delay)).isoformat()})
        event('reseller','WARNING','reply_preparation_deferred',account_id=aid,update_id=uid,error=exc)
        return min(delay,remaining)
    with _receipt_lock:
        _receipts[aid]=receipt
        if len(_receipts)>4096:
            _receipts.pop(next(iter(_receipts)))
    _finish(aid,uid,receipt)
    event('reseller','INFO','response_delivered',account_id=aid,update_id=uid,kind='file' if 'export' in result else 'message')
    return 0
