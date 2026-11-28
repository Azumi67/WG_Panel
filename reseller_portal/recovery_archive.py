

import hashlib
import hmac
import io
import json
import re
import zipfile
import stat
import zlib
from datetime import datetime, timezone

ARCHIVE_FORMAT = 'wg-panel-reseller-recovery-archive'
ARCHIVE_VERSION = 1
MANIFEST = 'manifest.json'
PAYLOAD = 'customer-recovery.enc.json'
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_RECOVERY_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 4096


def _parse_payload(raw):
    if not raw or len(raw) > MAX_RECOVERY_BYTES:
        raise ValueError('Customer recovery payload is empty or exceeds the 8 MiB limit.')
    try:
        item = json.loads(raw)
    except (UnicodeError, TypeError, ValueError):
        raise ValueError('Invalid encrypted recovery payload.') from None
    if not isinstance(item, dict) or item.get('format') != 'wg-panel-encrypted-customer-recovery' \
            or not isinstance(item.get('payload'), str):
        raise ValueError('The archive does not contain an encrypted customer recovery document.')
    return item


def pack_recovery(account_id, payload):

    _parse_payload(payload)
    manifest = {
        'format': ARCHIVE_FORMAT,
        'version': ARCHIVE_VERSION,
        'payload': PAYLOAD,
        'sha256': hashlib.sha256(payload).hexdigest(),
        'encrypted': True,
        'scope': 'reseller-customers',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'notice': 'Requires the original panel encryption key and account identity. Not a PostgreSQL dump.',
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr(MANIFEST, json.dumps(manifest, separators=(',', ':')))
        archive.writestr(PAYLOAD, payload)
    result = stream.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        raise ValueError('Encrypted customer backup exceeds the 8 MiB download limit. Ask the administrator for an offline recovery export.')
    return f'reseller-{int(account_id)}-customer-recovery-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.zip', result


def unwrap_recovery(blob):

    if not isinstance(blob, (bytes, bytearray)) or not blob or len(blob) > MAX_ARCHIVE_BYTES:
        raise ValueError('Invalid recovery backup size (maximum 8 MiB).')
    if not bytes(blob).startswith(b'PK'):
        return bytes(blob)
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            infos = archive.infolist()
            if len(infos) != 2 or {x.filename for x in infos} != {MANIFEST, PAYLOAD}:
                raise ValueError('Invalid customer backup structure. Expected one manifest and one encrypted recovery file.')
            for info in infos:
                if info.is_dir() or info.flag_bits & 1 or stat.S_IFMT(info.external_attr >> 16) not in (0,stat.S_IFREG):
                    raise ValueError('Unsupported encrypted ZIP entry or directory.')
                limit = MAX_MANIFEST_BYTES if info.filename == MANIFEST else MAX_RECOVERY_BYTES
                if info.file_size > limit:
                    raise ValueError('The recovery backup contains an oversized entry.')
            with archive.open(MANIFEST) as fh:
                manifest_bytes = fh.read(MAX_MANIFEST_BYTES + 1)
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise ValueError('The recovery manifest is too large.')
            try:
                manifest = json.loads(manifest_bytes)
            except (ValueError, UnicodeError):
                raise ValueError('The recovery manifest is invalid.') from None
            if not isinstance(manifest, dict) or manifest.get('format') != ARCHIVE_FORMAT or \
                    manifest.get('version') != ARCHIVE_VERSION or manifest.get('payload') != PAYLOAD or \
                    manifest.get('encrypted') is not True:
                raise ValueError('Unsupported recovery archive version or format.')
            digest = manifest.get('sha256')
            if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
                raise ValueError('The recovery manifest has no valid checksum.')
            with archive.open(PAYLOAD) as fh:
                payload = fh.read(MAX_RECOVERY_BYTES + 1)
            if len(payload) > MAX_RECOVERY_BYTES:
                raise ValueError('The encrypted recovery document is too large.')
            if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), digest):
                raise ValueError('Backup integrity verification failed. The archive may be damaged.')
            _parse_payload(payload)
            return payload
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, NotImplementedError, zlib.error):
        raise ValueError('The recovery ZIP is damaged or cannot be read.') from None
