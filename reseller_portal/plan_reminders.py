from datetime import timedelta

from panel_core.telegram_notices import card, telegram_body
from models import db
from . import service as s
from .database import settings_transaction
from .models import Account, ManagementBot, Notice, Order
from .regional import display
from .telegram_text import isolated, number, persian_time, rtl_lines
from .telegram_policy import can_notify, preferences


def stage(account):
    if not account or account.state != 'active':
        return None
    remaining = account.expires_at - s.now()
    used = account.used_bytes / max(1, account.spec['traffic_gib'] * s.GIB)
    if remaining <= timedelta(0):
        return 'expiry:0'
    if used >= 1:
        return 'usage:100'
    if remaining <= timedelta(days=3):
        return 'expiry:3'
    if used >= .9:
        return 'usage:90'
    if used >= .8:
        return 'usage:80'
    return None


def awaiting_review(account):
    return s.buyer_orders(account=account).filter_by(state='pending').filter(Order.payment_ref.isnot(None)).first()


def message(account, key, language='en'):
    fa = language == 'fa'
    if key == 'expiry:0':
        title = 'اعتبار پلن تمام شد' if fa else 'Plan expired'
    elif key == 'expiry:3':
        title = 'کمتر از سه روز تا پایان پلن' if fa else 'Plan expires within three days'
    else:
        percent = key.split(':')[1]
        title = f'{number(percent)}٪ از حجم پلن مصرف شد' if fa else f'{percent}% of plan traffic used'
    fields = [('حساب' if fa else 'Account', isolated(account.username) if fa else account.username),
              ('پایان اعتبار' if fa else 'Valid until', persian_time(account.expires_at) if fa else display(account.expires_at))]
    if key.startswith('usage:'):
        fields.append(('ترافیک مصرفی' if fa else 'Traffic used', f"{number(round(account.used_bytes/s.GIB,2))} از {number(account.spec['traffic_gib'])} گیگابایت" if fa else f"{account.used_bytes/s.GIB:.2f} / {account.spec['traffic_gib']} GiB"))
    notice = card(title, fields, symbol='◷')
    if fa:notice['text'] = rtl_lines(notice['text'])
    return notice


def queue_current(account):
    key = stage(account)
    if key and not awaiting_review(account):
        bot = db.session.get(ManagementBot, account.id)
        language = bot.language if bot and bot.approved and bot.enabled else s.setting('bot_lang:'+str(account.telegram_id),'en')
        return s.notify(account, key, message(account, key, language))
    return None


def is_reminder(notice):
    parts = notice.dedupe.split(':', 3)
    return notice.account_id is not None and len(parts) == 4 and parts[2] in ('expiry', 'usage')


def deliver_one(nid, send):
    from .management_bot import allowed
    with settings_transaction():
        notice = db.session.get(Notice, nid, with_for_update=True)
        if not notice or notice.sent_at or not notice.telegram_id or notice.retry_at > s.now():
            return
        account = db.session.get(Account, notice.account_id)
        key = stage(account)
        if (not key or notice.dedupe != f'{account.id}:{account.generation}:{key}' or
                notice.telegram_id != account.telegram_id or awaiting_review(account)):
            notice.telegram_id = None
            notice.error = None
            return
        event = 'plan_expiry' if key.startswith('expiry:') else 'plan_usage'
        bot = db.session.get(ManagementBot, account.id)
        prefs = preferences(account)
        if not prefs['enabled'] or not prefs[event]:
            notice.telegram_id = None
            return
        if bot and bot.approved and bot.token_enc:
            if not allowed(account, bot) or not can_notify(account, event):
                notice.telegram_id = None
                return
            token, language = s.decrypt(bot.token_enc), bot.language
        elif s.setting('bot_enabled') and s.setting('bot_token'):
            token = s.decrypt(s.setting('bot_token'))
            language = s.setting('bot_lang:'+account.telegram_id, 'en')
        else:
            return
        old_stage = {'expiry:0':'expired', 'expiry:3':'expiry3', 'usage:100':'exhausted',
                     'usage:90':'traffic90', 'usage:80':'traffic80'}[key]
        old = s.setting('management_notice:'+str(account.id), '')
        if isinstance(old, str) and old.endswith(':'+account.expires_at.isoformat()+':'+old_stage):
            notice.telegram_id = None
            return
        payload = {'chat_id': account.telegram_id, **telegram_body(message(account, key, language)),
                   'link_preview_options': {'is_disabled': True}}
        href = s.workspace_link(account)
        if href:
            label = '⌁ ورود به پنل' if language == 'fa' else '⌁ Open workspace'
            payload['reply_markup'] = {'inline_keyboard': [[{'text': label, 'url': href}]]}
        notice.attempts += 1
        notice.retry_at = s.now() + timedelta(minutes=2)
    try:
        send(token, 'sendMessage', payload)
    except RuntimeError:
        with settings_transaction():
            notice = db.session.get(Notice, nid)
            notice.retry_at = s.now() + timedelta(seconds=min(3600, 30 * 2**min(7, notice.attempts)))
            notice.error = 'Telegram delivery will retry.'
    else:
        with settings_transaction():
            notice = db.session.get(Notice, nid)
            notice.sent_at = s.now()
            notice.error = None


def deliver_workspace(account, send):
    key = stage(account)
    if not key:
        return
    aid = account.id
    notice = Notice.query.filter_by(dedupe=f'{aid}:{account.generation}:{key}').first()
    if not notice and awaiting_review(account):
        return
    if not notice:
        with settings_transaction():
            notice = queue_current(db.session.get(Account, aid))
    if notice and notice.telegram_id and not notice.sent_at and notice.retry_at <= s.now():
        deliver_one(notice.id, send)
