import base64
import hashlib
import struct
import hmac
import json
import time

ADMIN_SESSION_SECONDS = 8 * 60 * 60


def session_binding(account, secret):
    material = json.dumps([account.id, account.username, account.password_hash,
                           bool(account.twofa_enabled), account.totp_secret or '', int(getattr(account,'session_revision',0) or 0)],
                          separators=(',', ':')).encode()
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, b'wg-admin-session-v1\0' + material, hashlib.sha256).hexdigest()


def bind_session(session, account, secret, now=None):
    session['admin_binding'] = session_binding(account, secret)
    session['admin_until'] = int(time.time() if now is None else now) + ADMIN_SESSION_SECONDS


def session_valid(session, account, secret, now=None):
    binding = session.get('admin_binding')
    until = session.get('admin_until')
    return (isinstance(binding, str) and binding.isascii() and type(until) is int
            and (time.time() if now is None else now) < until
            and hmac.compare_digest(binding, session_binding(account, secret)))


def totp_at_step(secret, step):
    key = base64.b32decode(secret.upper() + '=' * ((-len(secret)) % 8), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(int.from_bytes(digest[offset:offset+4],"big") & 0x7fffffff) % 1000000:06d}'


def consume_admin_factor(account, code, verify_recovery, now=None):

    if not account.twofa_enabled:
        return True
    if not isinstance(code, str) or not code or len(code) > 64:
        return False
    if len(code) == 6 and code.isascii() and code.isdecimal() and account.totp_secret:
        step = int((time.time() if now is None else now) // 30)
        last = int(account.last_totp_counter or 0)
        try:
            for candidate in (step - 1, step, step + 1):
                if candidate > last and hmac.compare_digest(totp_at_step(account.totp_secret,candidate), code):
                    account.last_totp_counter = candidate
                    return True
        except (ValueError,TypeError,struct.error):
            
            pass
    codes = (account.recovery_codes or '').splitlines()
    for index, stored in enumerate(codes):
        if verify_recovery(code, stored):
            account.recovery_codes = '\n'.join(codes[:index] + codes[index+1:])
            return True
    return False


def csrf_required(method, path, browser_session, blueprint=None):
    if method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        return False
    if not path.startswith('/api/'):
        return True
    
    return bool(browser_session and blueprint != 'bot_apps')


def match_secret(supplied, expected):
    return bool(isinstance(supplied, str) and isinstance(expected, str) and supplied and expected
                and hmac.compare_digest(supplied.encode(), expected.encode()))
