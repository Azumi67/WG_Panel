
from datetime import datetime
from flask import current_app
from .worker_supervision import group_status
from cryptography.fernet import InvalidToken
from . import service as s
from .regional import human,parse
from .models import Account, Notice, Plan

def heartbeat(value, threshold=120):
    if not value:
        return {'state':'missing','label':'Not started','at':None,'age':None}
    try:
        at=parse(value)
        from datetime import timezone
        age=max(0,int((s.now().replace(tzinfo=timezone.utc)-at).total_seconds()))
        return {'state':'ready' if age<=threshold else 'stale',
                'label':'Running' if age<=threshold else 'Heartbeat stale',
                'at':human(at),'iso':at.isoformat(),'age':age}
    except (TypeError,ValueError):
        return {'state':'stale','label':'Invalid heartbeat','at':None,'age':None}

def service_status(group):
    status=group_status(current_app.instance_path,group)
    if status['at']:
        status['iso']=status['at']
        status['at']=human(parse(status['at']))
    return status


def monitor_status(settings=None):
    read=(lambda k,d=None: settings.get(k,d)) if settings is not None else s.setting
    status=heartbeat(read('monitor_heartbeat'))
    progress=service_status('monitor')
    if progress['state']!='ready':return progress
    status['components']=progress['components']
    failures=int(read('monitor_failed_count',0) or 0)
    if failures and status['state']=='ready':
        status={**status,'state':'stale','label':f'Errors · {failures} account(s)'}
    if read('enforcement_error') and status['state']=='ready':
        status={**status,'state':'stale','label':'Enforcement warning'}
    return status


def setup_status(check_links=True, settings=None, include_counts=True):
    read=(lambda k,d=None: settings.get(k,d)) if settings is not None else s.setting
    checks=[]
    key_ok=False
    try:
        s.cipher()
        key_ok=True
        checks.append(dict(name='Encryption key',state='ready',detail='Existing key accepted. Keep it unchanged.'))
    except ValueError:
        checks.append(dict(name='Encryption key',state='missing',detail='FLASK_SECRET_KEY is missing, uses the default, or is shorter than 32 characters. Have the server administrator configure it; do not replace existing encryption keys blindly.'))
    url_ok=False
    try:
        s.base_url();url_ok=True
        checks.append(dict(name='Public panel URL',state='ready',detail='HTTPS address is configured.'))
    except ValueError:
        checks.append(dict(name='Public panel URL',state='missing',detail='Save your public HTTPS address under Resellers > Plan shop bot, including its port if needed. Do not include /resellers.'))
    token=read('bot_token')
    token_ok=False
    if token and key_ok:
        try:
            s.decrypt(token);token_ok=True
        except (InvalidToken,ValueError,TypeError,AttributeError):
            checks.append(dict(name='Saved bot token',state='error',detail='The saved token cannot be decrypted with the current key. Restore the original key or review recovery before changing anything.'))
    if token_ok:checks.append(dict(name='Saved bot token',state='ready',detail='Encrypted token is saved. Use Test connection to check Telegram.'))
    elif not token:checks.append(dict(name='Saved bot token',state='missing',detail='Create a dedicated BotFather bot and save its token.'))
    links_ok=True
    if key_ok and check_links:
        for account in Account.query.filter(Account.state!='deleted').yield_per(200):
            try:s.decrypt(account.link_enc)
            except (InvalidToken,ValueError,TypeError,AttributeError):links_ok=False;break
    if not links_ok:
        checks.append(dict(name='Existing account links',state='error',detail='An existing access link cannot be decrypted. Restore the original FLASK_SECRET_KEY; account records are preserved.'))
    return dict(checks=checks,accounts_ready=key_ok and url_ok and links_ok,key_ok=key_ok,
                url_ok=url_ok,token_ok=token_ok,links_ok=links_ok,
                worker=service_status('worker'),shop_worker=service_status('shop_worker'),
                provision=service_status('provision'),
                monitor=monitor_status(settings),
                monitor_last_healthy=read('monitor_last_healthy_at'),
                telegram=heartbeat(read('bot_poll_at')),
                enabled=read('bot_enabled',False),
                plan_count=Plan.query.filter_by(active=True).count() if include_counts else 0,
                pending=Notice.query.filter(Notice.sent_at.is_(None),Notice.telegram_id.isnot(None)).count() if include_counts else 0)
