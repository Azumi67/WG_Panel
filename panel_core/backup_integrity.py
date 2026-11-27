import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import zipfile
import zlib
from pathlib import Path

MANIFEST = 'meta/integrity.json'
MAX_TOTAL = 2 * 1024**3
MAX_SMALL = 16 * 1024**2
MAX_ENTRIES = 10000
CHUNK = 1024**2


def _members(archive):
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ENTRIES:
        raise ValueError('Invalid backup entry count.')
    seen = set()
    total = 0
    for info in infos:
        name = info.filename
        if (not name or '\\' in name or ':' in name or name.startswith('/') or
                any(part in ('', '.', '..') for part in name.rstrip('/').split('/')) or
                any(ord(c) < 32 for c in name) or name != info.orig_filename):
            raise ValueError('Unsafe backup entry path.')
        folded = name.rstrip('/').casefold()
        if folded in seen:
            raise ValueError('Duplicate backup entry.')
        seen.add(folded)
        mode = stat.S_IFMT(info.external_attr >> 16)
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.flag_bits & 1:
            raise ValueError('Unsupported backup entry type.')
        if info.is_dir():
            continue
        if name.startswith(('db/', 'instance/', 'wg/')) and name.count('/') != 1:
            raise ValueError('Unexpected nested backup entry.')
        total += info.file_size
        if total > MAX_TOTAL or info.file_size > (MAX_TOTAL if name.startswith('db/') else MAX_SMALL):
            raise ValueError('Backup exceeds inspection size limits.')
        yield info


def _digest(archive, info):
    digest = hashlib.sha256()
    size = 0
    with archive.open(info) as source:
        while True:
            data = source.read(CHUNK)
            if not data:
                break
            size += len(data)
            if size > info.file_size:
                raise ValueError('Invalid backup entry length.')
            digest.update(data)
    if size != info.file_size:
        raise ValueError('Invalid backup entry length.')
    return {'size': size, 'sha256': digest.hexdigest()}


def add_integrity(archive):
    entries = {i.filename: _digest(archive, i) for i in _members(archive)}
    if MANIFEST in entries:
        raise ValueError('Backup already has an integrity manifest.')
    archive.writestr(MANIFEST, json.dumps({'version': 1, 'entries': entries}, separators=(',', ':')))


def verify_archive(archive):
    try:
        entries = {i.filename: _digest(archive, i) for i in _members(archive) if i.filename != MANIFEST}
        if MANIFEST not in archive.namelist():
            return 'legacy-crc-checked'
        manifest = json.loads(archive.read(MANIFEST))
        if not isinstance(manifest, dict) or manifest.get('version') != 1 or not isinstance(manifest.get('entries'), dict):
            raise ValueError('Invalid backup integrity manifest.')
        expected = manifest['entries']
        if set(expected) != set(entries):
            raise ValueError('Backup integrity manifest does not match archive contents.')
        for name, actual in entries.items():
            item = expected[name]
            if (not isinstance(item, dict) or item.get('size') != actual['size'] or
                    not isinstance(item.get('sha256'), str) or
                    not re.fullmatch(r'[0-9a-f]{64}', item['sha256']) or
                    not hmac.compare_digest(item['sha256'], actual['sha256'])):
                raise ValueError('Backup checksum verification failed.')
        return 'sha256-checked'
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, NotImplementedError, UnicodeError, zlib.error) as exc:
        raise ValueError('Backup archive is damaged or unreadable.') from exc


def destination(root, tail):
    root = Path(root).resolve()
    if not tail or Path(tail).name != tail or tail in ('.', '..') or '\\' in tail:
        raise ValueError('Unsafe restore destination.')
    dest = root / tail
    if dest.is_symlink() or (dest.exists() and not dest.is_file()):
        raise ValueError('Unsafe existing restore destination.')
    return dest


def atomic_write(dest, source):
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.restore-', dir=dest.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            while True:
                data = source.read(CHUNK)
                if not data:
                    break
                out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dest)
    finally:
        Path(tmp).unlink(missing_ok=True)


def validate_restore_files(archive):
    for info in _members(archive):
        if info.filename.startswith('instance/'):
            name = info.filename
            if not name.endswith(('.json', '.jsonl')):
                raise ValueError('Unsupported instance restore file.')
            with archive.open(info) as source:
                if name.endswith('.json'):
                    json.load(source)
                else:
                    for line in source:
                        if line.strip():
                            json.loads(line)


def validate_sqlite(path):
    import sqlite3
    from contextlib import closing
    try:
        with closing(sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)) as connection:
            if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('SQLite backup integrity check failed.')
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'peer', 'interface_config'}.issubset(tables):
                raise ValueError('SQLite backup is not a WG Panel database.')
    except sqlite3.Error as exc:
        raise ValueError('SQLite backup cannot be read.') from exc
