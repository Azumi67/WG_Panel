import os
from cryptography.fernet import Fernet, MultiFernet


def backup_cipher(primary, previous=None):
    if not primary:
        if previous:
            raise ValueError('A primary backup encryption key is required.')
        return None
    keys = [primary.strip()] + [key.strip() for key in (previous or '').split(',') if key.strip()]
    return MultiFernet([Fernet(key.encode()) for key in dict.fromkeys(keys)])


def configured_cipher():
    return backup_cipher(os.getenv('WG_BACKUP_ENCRYPTION_KEY'), os.getenv('WG_BACKUP_PREVIOUS_KEYS'))


def seal(payload, legacy_encrypt):
    cipher = configured_cipher()
    if cipher is None:
        return {'payload': legacy_encrypt(payload)}
    return {'payload': cipher.encrypt(payload.encode()).decode(), 'key_scope': 'backup-v1'}


def unseal(wrapper, legacy_decrypt):
    scope = wrapper.get('key_scope')
    if scope is None:
        return legacy_decrypt(wrapper['payload'])
    if scope != 'backup-v1':
        raise ValueError('Unknown backup encryption scope.')
    cipher = configured_cipher()
    if cipher is None:
        raise ValueError('The dedicated backup encryption key is missing.')
    return cipher.decrypt(wrapper['payload'].encode()).decode()
