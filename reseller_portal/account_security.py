
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote
from . import service as s


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def provisioning_uri(username, secret):

    label=quote('WG Panel:'+username, safe='')
    return f'otpauth://totp/{label}?secret={quote(secret)}&issuer=WG%20Panel&algorithm=SHA1&digits=6&period=30'


def code_for_step(secret, step):
    key=base64.b32decode(secret.upper()+'='*((-len(secret))%8),casefold=True)
    digest=hmac.new(key,struct.pack('>Q',step),hashlib.sha1).digest()
    pos=digest[-1]&15
    return str((int.from_bytes(digest[pos:pos+4],'big')&0x7fffffff)%1000000).zfill(6)


def matched_step(secret, code, now=None, last_step=-1):
    if not isinstance(code,str) or len(code)!=6 or not code.isascii() or not code.isdecimal():return None
    current=int((time.time() if now is None else now)//30)
    for step in (current-1,current,current+1):
        if step>last_step and hmac.compare_digest(code_for_step(secret,step),code):return step
    return None


def new_recovery_codes():

    return [secrets.token_hex(10).upper() for _ in range(10)]


def recovery_digest(code):
    normalized=code.strip().replace('-','').replace(' ','').upper()
    return hashlib.sha256(normalized.encode('ascii')).hexdigest() if len(normalized)==20 and all(c in '0123456789ABCDEF' for c in normalized) else None


def consume_recovery(row, code):
    digest=recovery_digest(code or '')
    if digest is None:return False
    existing=list(row.recovery_hashes or [])
    found=next((v for v in existing if hmac.compare_digest(v,digest)),None)
    if not found:return False
    row.recovery_hashes=[v for v in existing if v!=found]
    return True


def verify_and_consume(row, code, allow_recovery=True):
    if not row or not row.totp_secret_enc:return False

    secret=s.decrypt(row.totp_secret_enc)
    step=matched_step(secret,code,last_step=int(row.last_totp_step if row.last_totp_step is not None else -1))
    if step is not None:
        row.last_totp_step=step
        return True
    return bool(allow_recovery and consume_recovery(row,code))
