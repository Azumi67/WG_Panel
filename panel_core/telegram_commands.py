import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ADMIN = (
    ('menu', 'Main dashboard', 'داشبورد اصلی'),
    ('peers', 'Manage users', 'مدیریت کاربران'),
    ('subscriptions', 'Manage subscriptions', 'مدیریت اشتراک‌ها'),
    ('profiles', 'Saved profiles', 'الگوهای ذخیره‌شده'),
    ('status', 'System status', 'وضعیت سیستم'),
    ('backup', 'Backup and restore', 'پشتیبان‌گیری و بازیابی'),
    ('traffic', 'Traffic control', 'کنترل ترافیک'),
    ('security', 'Security', 'امنیت'),
    ('updates', 'Update Center', 'مرکز به‌روزرسانی'),
    ('settings', 'Settings', 'تنظیمات'),
    ('admins', 'Administrators', 'مدیران'),
    ('id', 'My Telegram ID', 'شناسه تلگرام من'),
)
SHOP = (
    ('start', 'Main dashboard', 'داشبورد اصلی'),
    ('plans', 'Browse plans and renew', 'خرید و تمدید پلن'),
    ('status', 'My account', 'حساب من'),
    ('orders', 'My orders and receipts', 'سفارش‌ها و رسیدهای من'),
    ('link', 'Open workspace', 'ورود به پنل'),
    ('language', 'Language · زبان', 'انتخاب زبان'),
    ('id', 'My Telegram ID', 'شناسه تلگرام من'),
    ('help', 'Help and support', 'راهنما و پشتیبانی'),
)


def workspace_commands(grants, active=True, expired=False):
    grants = set(grants)
    rows = [('menu', 'Main dashboard', 'داشبورد اصلی')]
    if not expired:
        for grant, row in (
            ('peers', ('peers', 'Manage users', 'مدیریت کاربران')),
            ('subscriptions', ('subscriptions', 'Manage subscriptions', 'مدیریت اشتراک‌ها')),
            ('usage', ('usage', 'Plan and usage', 'پلن و مصرف')),
            ('logs', ('logs', 'Activity logs', 'گزارش فعالیت')),
            ('notifications', ('alerts', 'Notifications', 'اعلان‌ها')),
            ('backup', ('backup', 'Customer backup', 'پشتیبان کاربران')),
        ):
            if grant in grants:
                rows.append(row)
        if active and 'create' in grants:
            if 'peers' in grants:
                rows.insert(2, ('create', 'Create user', 'ایجاد کاربر'))
            if 'subscriptions' in grants:
                rows.append(('client', 'Create subscription', 'ایجاد اشتراک'))
        if active and 'profiles' in grants and grants.intersection(('peers', 'subscriptions')):
            rows.append(('profiles', 'Saved profiles', 'الگوهای ذخیره‌شده'))
    rows.extend((('language', 'Language · زبان', 'انتخاب زبان'), ('help', 'Help', 'راهنما')))
    return tuple(rows)


def commands(rows, language):
    return [{'command': key, 'description': fa if language == 'fa' else en} for key, en, fa in rows]


class MenuPublisher:
    def __init__(self, transport, *, clock=time.monotonic):
        self.transport = transport
        self.clock = clock
        self.lock = threading.Lock()
        self.cache = {}
        self.pending = set()
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='telegram-menu')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.pool.shutdown(wait=True, cancel_futures=True)

    @staticmethod
    def key(token, chat):
        return hashlib.sha256(token.encode()).hexdigest(), chat

    def due(self, token, chat, stamp):
        key = self.key(token, chat)
        with self.lock:
            previous = self.cache.get(key)
            return key not in self.pending and len(self.pending) < 8 and (not previous or previous[0] != stamp or self.clock() >= previous[1])

    def submit(self, token, chat, stamp, rows, language='en', selected=False):
        key = self.key(token, chat)
        with self.lock:
            previous = self.cache.get(key)
            if key in self.pending or len(self.pending) >= 8 or (previous and previous[0] == stamp and self.clock() < previous[1]):
                return False
            self.pending.add(key)
        def run():
            delay = 6 * 3600
            try:
                scope = {'type': 'default'} if chat is None else {'type': 'chat', 'chat_id': int(chat)}
                for locale, lang in (('', language), ('en', language if selected else 'en'), ('fa', language if selected else 'fa')):
                    if not self.transport(token, 'setMyCommands', {'scope': scope, 'language_code': locale, 'commands': commands(rows, lang)}):
                        raise RuntimeError('Menu registration failed')
                data = {'menu_button': {'type': 'commands'}}
                if chat is not None:
                    data['chat_id'] = int(chat)
                if not self.transport(token, 'setChatMenuButton', data):
                    raise RuntimeError('Menu button registration failed')
            except Exception as exc:
                delay = max(60, min(86400, getattr(exc, 'retry_after', 0) or 0))
                logging.getLogger(__name__).warning('Telegram menu registration deferred (%s).', type(exc).__name__)
            finally:
                with self.lock:
                    self.pending.discard(key)
                    if len(self.cache) >= 1024 and key not in self.cache:
                        self.cache.pop(next(iter(self.cache)))
                    self.cache[key] = stamp, self.clock() + delay
        try:
            self.pool.submit(run)
        except RuntimeError:
            with self.lock:
                self.pending.discard(key)
            return False
        return True
