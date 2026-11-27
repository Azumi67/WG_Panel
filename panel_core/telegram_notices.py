import json
from html import escape


def card(title, fields=(), note='', symbol='◇', buttons=()):
    title = str(title).strip()[:160]
    heading = symbol + ' ' + title
    rich = [symbol + ' <b>' + escape(title) + '</b>']
    plain = [heading]
    remaining = 3900 - len(heading)
    for label, value in fields:
        if value is None or value == '':
            continue
        label = str(label).strip()[:80]
        available = remaining - len(label) - 4
        if available < 1:
            break
        value = str(value).strip()[:min(1100, available)]
        line = label + ' · ' + value
        rich.append(escape(label) + ' · <b>' + escape(value) + '</b>')
        plain.append(line)
        remaining -= len(line) + 1
    if note and remaining > 4:
        note = str(note).strip()[:remaining-3]
        rich.append('\n' + escape(note))
        plain.append('\n' + note)
    entry = {'text':'\n'.join(rich), 'plain':'\n'.join(plain), 'parse_mode':'HTML'}
    rows = [[{'text':label, 'url':url}] for label, url in buttons if url]
    if rows:
        entry['reply_markup'] = {'inline_keyboard':rows}
    return entry


def telegram_body(entry):
    return {key: entry[key] for key in ('text','parse_mode','reply_markup') if key in entry}


def serialize(body):
    if isinstance(body, dict):
        return 'RPNOTICE:' + json.dumps(body, ensure_ascii=False)
    return body


def unpack(body):
    if body.startswith('RPNOTICE:'):
        return json.loads(body[9:])
    if body.startswith('RPBOT1:'):
        return json.loads(body[7:])
    return {'text':body}


def inbox_text(body):
    entry = unpack(body)
    return entry.get('plain', entry['text'])

PERSIAN_EVENTS = {
    'app_down':'پنل در دسترس نیست', 'app_up':'اتصال پنل برقرار شد',
    'node_down':'ارتباط با نود قطع شد', 'node_up':'ارتباط با نود برقرار شد',
    'iface_down':'رابط شبکه متوقف شد', 'iface_up':'رابط شبکه فعال شد',
    'peer_expired':'اعتبار کاربر پایان یافت', 'peer_limit':'سهمیه کاربر به پایان رسید',
    'login_success':'ورود به پنل انجام شد', 'login_fail':'درخواست ورود رد شد',
    'suspicious_4xx':'درخواست‌های ناموفق تکرار شد', 'security_block':'دسترسی مسدود شد',
    'security_release':'محدودیت دسترسی برداشته شد', 'security_auto_release':'زمان محدودیت دسترسی پایان یافت',
    'traffic_policy_change':'تنظیمات ترافیک تغییر کرد', 'traffic_apply_success':'تنظیمات ترافیک اعمال شد',
    'traffic_apply_failed':'اعمال تنظیمات ترافیک ناموفق بود', 'backup_success':'پشتیبان‌گیری انجام شد',
    'backup_failed':'پشتیبان‌گیری ناموفق بود', 'update_success':'به‌روزرسانی انجام شد', 'update_failed':'به‌روزرسانی ناموفق بود'
}
PERSIAN_FIELDS = {
    'status':'وضعیت', 'account':'حساب', 'username':'نام کاربری', 'action':'عملیات', 'active policies':'قوانین فعال',
    'address':'نشانی', 'client ip':'آی‌پی کاربر', 'error':'خطا', 'failed at':'زمان خطا', 'failed checks':'بررسی ناموفق',
    'failures':'تعداد خطاها', 'host firewall':'فایروال میزبان', 'interface':'رابط', 'listen port':'درگاه', 'local policies':'قوانین محلی',
    'location':'موقعیت', 'message':'پیام', 'node':'نود', 'node policies':'قوانین نود', 'nodes':'نودها', 'offense level':'سطح تخلف',
    'outage':'مدت قطعی', 'policies':'قوانین', 'previous reason':'دلیل قبلی', 'public ip':'آی‌پی عمومی', 'reason':'دلیل',
    'remote host':'میزبان راه دور', 'schedule time':'زمان اجرا', 'stage':'مرحله', 'target':'مقصد', 'warnings':'هشدارها',
    'window':'بازه', 'time':'زمان', 'peer':'کاربر', 'used':'مصرف', 'limit':'سقف', 'expires':'پایان اعتبار', 'expired at':'زمان انقضا',
    'device':'دستگاه', 'browser / device':'مرورگر و دستگاه', 'panel':'پنل', 'protocol':'پروتکل', 'host':'میزبان', 'user agent':'عامل کاربر',
    'blocked until':'پایان محدودیت', 'blocked at':'شروع محدودیت', 'released at':'زمان رفع محدودیت', 'proxy chain':'مسیر پروکسی'
}
PERSIAN_STATUS = {
    'authenticated':'احراز هویت شد', 'access denied':'دسترسی رد شد', 'online':'متصل', 'offline':'قطع',
    'unreachable':'در دسترس نیست', 'healthy':'سالم', 'success':'موفق', 'failed':'ناموفق', 'blocked':'مسدود',
    'released':'آزاد', 'enabled':'فعال', 'disabled':'غیرفعال', 'completed':'انجام شد', 'expired':'منقضی',
    'recovered':'بازیابی شد', 'unavailable':'در دسترس نیست', 'active':'فعال'
}


def admin_event(language, event, title, rows, footer, icon):
    if language == 'fa':
        title = PERSIAN_EVENTS.get(event,title)
        rows = [(PERSIAN_FIELDS.get(k.casefold(),k), PERSIAN_STATUS.get(str(v).casefold(),v) if k.casefold()=='status' else v) for k,v in rows]
    return card(title,rows,footer,icon)
