

from html import escape

MAX_CAPTION = 1000


def _units(value):

    return len(value.encode('utf-16-le', 'replace')) // 2


def _server_endpoint(config):
    for raw_line in config.splitlines():
        key, sep, value = raw_line.partition('=')
        if sep and key.strip().lower() == 'endpoint':
            return value.strip()[:253]
    return ''


def _brief_usage(peer):
    try:
        used = max(0, int(peer.used_bytes_total or 0)) / (1024 ** 3)
        cap = peer.limit_bytes()
    except (ValueError, TypeError, AttributeError):
        return '—'
    if cap is None:
        return f'{used:.2f} GiB / Unlimited'
    return f'{used:.2f} / {max(0, int(cap)) / (1024 ** 3):.2f} GiB'


def _expiry(peer, fa):
    when = getattr(peer, 'expires_at', None)
    if when is not None:
        try:
            return when.strftime('%Y-%m-%d %H:%M UTC')
        except (AttributeError, ValueError):
            return '—'
    if getattr(peer, 'start_on_first_use', False) and not getattr(peer, 'first_used_at', None):
        return 'از اولین اتصال' if fa else 'Starts on first connection'
    return 'نامحدود' if fa else 'Unlimited'


def caption(peer, config, short_link, *, qr=False, language='en', expires_label=None):

    fa = language == 'fa'
    kind = ('کد QR' if qr else 'تنظیمات WireGuard') if fa else ('QR code' if qr else 'WireGuard configuration')
    name = escape(str(getattr(peer, 'name', None) or f'peer-{peer.id}')[:64], quote=False)
    iface = getattr(peer, 'iface', None)
    iface_name = escape(str(getattr(iface, 'name', None) or '—')[:64], quote=False)
    address = escape(str(getattr(peer, 'address', None) or '—')[:64], quote=False)
    endpoint = escape(_server_endpoint(config) or '—', quote=False)
    usage = _brief_usage(peer)
    expires = escape(str(expires_label or _expiry(peer, fa)), quote=False)
    status = getattr(peer, 'status', None)
    state = ('فعال' if status == 'online' else 'متوقف') if fa else ('Enabled' if status == 'online' else 'Paused')
    short = escape(str(short_link or ''), quote=False)

    if fa:
        lead = (f'◇ <b>{name} · {kind}</b>\n'
                f'رابط: {iface_name} · وضعیت: {state}\n'
                f'آی‌پی کاربر: <code>{address}</code>\n'
                f'آدرس سرور: <code>{endpoint}</code>\n'
                f'مصرف: {usage}\n'
                f'اعتبار: {expires}\n')
        heading = '\n<b>متن تنظیمات</b> (فایل کامل پیوست شده است):\n'
        tail = '\n<b>لینک کوتاه</b>\n' + (short or 'در دسترس نیست')
        trimmed = '\n…'
    else:
        lead = (f'◇ <b>{name} · {kind}</b>\n'
                f'Interface: {iface_name} · Status: {state}\n'
                f'Client IP: <code>{address}</code>\n'
                f'Server endpoint: <code>{endpoint}</code>\n'
                f'Traffic: {usage}\n'
                f'Expires: {expires}\n')
        heading = '\n<b>Config preview</b> (complete file attached):\n'
        tail = '\n<b>Peer short link</b>\n' + (short or 'Unavailable')
        trimmed = '\n…'
    opener, closer = '<pre><code>', '</code></pre>'
    fixed = lead + heading + opener + closer + tail
    available = MAX_CAPTION - _units(fixed)
    if available < 0:

        lead = f'◇ <b>{name} · {kind}</b>\n'
        heading = ''
        fixed = lead + opener + closer + tail
        available = max(0, MAX_CAPTION-_units(fixed))
    raw = str(config or '')
    preview = escape(raw, quote=False)
    if _units(preview) > available:
        room = max(0, available-_units(trimmed))
        lo, hi = 0, len(raw)
        while lo < hi:
            mid = (lo+hi+1)//2
            if _units(escape(raw[:mid], quote=False)) <= room:
                lo = mid
            else:
                hi = mid-1
        preview = escape(raw[:lo].rstrip(), quote=False) + trimmed
    result = lead + heading + opener + preview + closer + tail
    if _units(result) > MAX_CAPTION:
        raise AssertionError('Telegram caption exceeds its safety budget')
    return result


def transport_request(result, chat_id):

    photo = result.get('mime') == 'image/png'
    field = 'photo' if photo else 'document'
    method = 'sendPhoto' if photo else 'sendDocument'
    content = result['document']
    if isinstance(content, str):
        content = content.encode('utf-8')
    data = {'chat_id': str(chat_id), 'protect_content': 'true'}
    if result.get('caption'):
        data['caption'] = result['caption']
        data['parse_mode'] = result.get('parse_mode', 'HTML')
    files = {field: (result['filename'], content, result.get('mime', 'text/plain'))}
    return method, data, files
