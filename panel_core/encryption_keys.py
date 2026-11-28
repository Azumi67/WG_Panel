import base64
import hashlib
from cryptography.fernet import Fernet, MultiFernet


def legacy_reseller_key(secret):
    if not isinstance(secret, str) or len(secret) < 32 or secret == 'change-me':
        raise ValueError('A stable legacy reseller encryption secret of at least 32 characters is required.')
    return base64.urlsafe_b64encode(hashlib.sha256(('reseller-portal-v1:' + secret).encode()).digest())


def reseller_cipher(secret, primary=None, previous=None, legacy_secret=None):
    keys = []
    if primary:
        keys.append(primary.strip().encode())
    if previous:
        if not primary:
            raise ValueError('Configure the primary reseller encryption key before previous keys.')
        keys.extend(value.strip().encode() for value in previous.split(',') if value.strip())
    keys.append(legacy_reseller_key(legacy_secret or secret))
    ciphers = [Fernet(key) for key in dict.fromkeys(keys)]
    return MultiFernet(ciphers) if len(ciphers) > 1 else ciphers[0]
