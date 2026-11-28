from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = 'wg-maintenance-restore-' + hashlib.sha256(os.fsencode(ROOT)).hexdigest()[:20] + '.service'
DUMP_MEMBER = 'db/wgpanel-postgresql.dump'
SETTINGS = frozenset({'peer_profiles.json', 'subscription_profiles.json', 'template_settings.json',
                      'subscription_settings.json', 'subscription_portal_overrides.json', 'endpoint_presets.json'})
TERMINAL = {'completed', 'failed', 'review'}


def private_dir(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError('Unsafe restore maintenance directory.')
    return path


def directory():
    return private_dir(ROOT / 'instance' / 'restore-maintenance')


def blocked():
    path = ROOT / 'instance' / 'restore-maintenance' / 'blocked'
    return path.exists() or path.is_symlink()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def clear_marker(marker):
    marker.unlink(missing_ok=True)
    sync_directory(marker.parent)


def startup_guard():
    if blocked():
        raise RuntimeError('PostgreSQL restore maintenance is incomplete. Review the restore service journal before starting panel writers.')


def operation_path(reference):
    if not isinstance(reference, str) or not re.fullmatch(r'[0-9a-f]{32}', reference):
        raise ValueError('Invalid restore reference.')
    return directory() / reference


def write_status(job, state, message, **extra):
    from panel_core.backup_integrity import atomic_write
    from io import BytesIO
    previous = {}
    if (job / 'status.json').is_file():
        previous = json.loads((job / 'status.json').read_text())
    now = int(time.time())
    history = status_history(previous)
    history.append({'state': state, 'message': message, 'updated_at': now})
    invocation = previous.get('invocation_id', '')
    if state == 'validating':
        invocation = os.environ.get('INVOCATION_ID', '')
    payload = {'reference': job.name, 'state': state, 'message': message, 'updated_at': now, **extra,
               'history': history[-80:]}
    if isinstance(invocation, str) and re.fullmatch(r'[0-9a-f]{32}', invocation):
        payload['invocation_id'] = invocation
    atomic_write(job / 'status.json', BytesIO(json.dumps(payload).encode()))
    sync_directory(job)
    print('[WG Panel restore] ' + state + ': ' + message, flush=True)
    return payload


def status_history(payload):
    history = payload.get('history')
    if isinstance(history, list):
        return list(history[-80:])
    if all(key in payload for key in ('state', 'message', 'updated_at')):
        return [{key: payload[key] for key in ('state', 'message', 'updated_at')}]
    return []


def read_status(reference):
    if reference == 'latest':
        jobs = [p for p in directory().iterdir() if re.fullmatch(r'[0-9a-f]{32}', p.name) and not p.is_symlink() and (p/'status.json').is_file()]
        if not jobs:
            raise FileNotFoundError
        reference = max(jobs, key=lambda p: (p/'status.json').stat().st_mtime).name
    job = operation_path(reference)
    if job.is_symlink() or not job.is_dir():
        raise FileNotFoundError
    result = json.loads((job / 'status.json').read_text())
    result['history'] = status_history(result)
    if result['state'] not in TERMINAL and not active() and time.time() - result['updated_at'] > 30:
        result = {**result, 'state': 'review', 'message': 'Restore process is no longer running. Check its journal before retrying.'}
        result['history'] = (result['history'] + [{'state': 'review', 'message': result['message'], 'updated_at': int(time.time())}])[-80:]
    return result


def active():
    from scripts.startup_upgrade import info
    if not shutil.which('systemctl'):
        return False
    return info(UNIT).get('ActiveState') in ('active', 'activating', 'deactivating', 'reloading')


def configured_url():
    from dotenv import dotenv_values
    from sqlalchemy.engine import make_url
    value = str(dotenv_values(ROOT / '.env', interpolate=False).get('DATABASE_URL') or '')
    if value.startswith('postgres://'):
        value = 'postgresql://' + value[len('postgres://'):]
    url = make_url(value)
    if (url.get_backend_name() != 'postgresql' or url.host not in ('127.0.0.1', 'localhost', '::1')
            or url.query or not url.username or not url.password or not url.database
            or url.database in ('postgres', 'template0', 'template1')
            or not re.fullmatch(r'[A-Za-z0-9_]{1,63}', url.database)
            or not re.fullmatch(r'[A-Za-z0-9_]{1,63}', url.username)):
        raise RuntimeError('Managed restore supports standard local PostgreSQL databases only.')
    return url.set(drivername='postgresql+psycopg')


def check_keys(archive):
    from dotenv import dotenv_values
    from io import StringIO
    live = dotenv_values(ROOT / '.env', interpolate=False)
    keys = ('FERNET_KEY', 'FLASK_SECRET_KEY', 'WG_RESELLER_ENCRYPTION_KEY', 'WG_RESELLER_PREVIOUS_KEYS', 'WG_RESELLER_LEGACY_SECRET')
    for key in keys[:2]:
        if not live.get(key):
            raise RuntimeError('Existing encryption keys are required.')
    if 'env/.env' in archive.namelist():
        saved = dotenv_values(stream=StringIO(archive.read('env/.env').decode()), interpolate=False)
        if any(saved.get(key) != live.get(key) for key in keys):
            raise ValueError('Backup encryption keys differ from this installation. Use the manual recovery procedure.')


def validate_source(archive, kind):
    from panel_core.backup_integrity import verify_archive, validate_restore_files
    verify_archive(archive)
    validate_restore_files(archive)
    members = [n for n in archive.namelist() if n.startswith('db/') and not n.endswith('/')]
    if members != [DUMP_MEMBER]:
        raise ValueError('Select a PostgreSQL backup containing one custom-format database dump.')
    with archive.open(DUMP_MEMBER) as source:
        if source.read(5) != b'PGDMP':
            raise ValueError('Invalid PostgreSQL custom-format dump.')
    if kind not in ('db', 'full'):
        raise ValueError('Unsupported managed restore mode.')
    if kind == 'full' and not any(n.startswith('instance/') and not n.endswith('/') for n in archive.namelist()):
        raise ValueError('Full restore requires instance settings in the archive.')
    check_keys(archive)


def preflight():
    from scripts import deployment as d, startup_upgrade as s, easy_postgres_migrate as m
    if os.geteuid() != 0 or not s.standard_panel():
        raise RuntimeError('Managed restore requires the standard root systemd installation.')
    if not all(shutil.which(name) for name in ('systemd-run', 'runuser', 'psql', 'pg_dump', 'pg_restore')):
        raise RuntimeError('PostgreSQL client tools and systemd-run are required.')
    if s.active_maintenance() or s.manual_migration_running():
        raise RuntimeError('A database upgrade is already running.')
    if blocked():
        raise RuntimeError('An interrupted restore requires review before another restore.')
    url = configured_url()
    if d.lock_active(ROOT):
        raise RuntimeError('Another maintenance or update operation is running.')
    services = d.discover_services(ROOT, 'panel')
    known, timers = m.discover_managed_units()
    allowed = {s.PANEL, s.BOT, s.WATCHDOG, s.WATCHDOG_SERVICE, *s.WORKERS}
    if set(known + timers) - allowed:
        raise RuntimeError('Additional managed units require manual restore.')
    for name in set(known) | {s.PANEL, s.BOT, *s.WORKERS}:
        if name != s.WATCHDOG_SERVICE:
            s.verify_unit_database(name, m)
    if s.PANEL not in services:
        raise RuntimeError('The standard primary panel service is not active.')
    return url, services, s.health_probe(d)


@contextmanager
def submission_lock():
    fd = os.open(directory() / 'submit.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise RuntimeError('Another restore is being submitted.') from None
    finally:
        os.close(fd)


def enqueue(path, kind, actor, restore_wg=False):
    from scripts import deployment as d
    from panel_core.backup_integrity import atomic_write
    with submission_lock():
        if active():
            raise RuntimeError('A restore is already running.')
        preflight()
        with d.deployment_lock(ROOT):
            with zipfile.ZipFile(path) as archive:
                validate_source(archive, kind)
                if restore_wg:
                    validate_wireguard_scope(archive, kind)
                size = archive.getinfo(DUMP_MEMBER).file_size
            if shutil.disk_usage(directory()).free < size * 2 + 64 * 1024**2:
                raise RuntimeError('Not enough free disk space for restore staging.')
            job = private_dir(operation_path(secrets.token_hex(16)))
            try:
                with open(path, 'rb') as stream:
                    atomic_write(job / 'backup.zip', stream)
                payload = write_status(job, 'queued', 'Restore accepted. Preparing independent maintenance.', kind=kind, restore_wg=restore_wg)
                from scripts.startup_upgrade import command
                command(['systemd-run', '--unit=' + UNIT, '--collect', '--no-block',
                         '--property=Type=exec', '--property=TimeoutStopSec=120',
                         '--property=WorkingDirectory=' + str(ROOT), str(ROOT / 'venv/bin/python'), '-u',
                         str(Path(__file__).resolve()), '--run', job.name, '--kind', kind,
                         *(['--wireguard'] if restore_wg else [])], timeout=30)
                print('[WG Panel restore] Requested by authenticated administrator ' + re.sub(r'[\r\n]', ' ', str(actor))[:64], flush=True)
                return payload
            except BaseException:
                write_status(job, 'failed', 'Restore could not be scheduled. No database was changed.')
                raise


def pg_env(url):
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env.update(PGPASSWORD=url.password or '', PGCONNECT_TIMEOUT='5')
    return env


def pg_cli(url):
    return ['--host=' + str(url.host), '--port=' + str(url.port or 5432), '--username=' + str(url.username), '--dbname=' + str(url.database)]


def sql_ident(value):
    if not re.fullmatch(r'[A-Za-z0-9_]{1,63}', value):
        raise ValueError('Invalid database identifier.')
    return '"' + value + '"'


def admin_sql(url, sql, timeout=60):
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-qAt', '-w', '-v', 'ON_ERROR_STOP=1',
                             '-h', '/var/run/postgresql', '-p', str(url.port or 5432), '-d', 'postgres'],
                            input=sql, text=True, capture_output=True, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Local PostgreSQL administrative operation failed; review PostgreSQL server logs.')
    return result.stdout.strip()


def database_oid(url, name):
    sql_ident(name)
    return admin_sql(url, "SELECT oid FROM pg_database WHERE datname='" + name + "';")


def database_defaults(url, name):
    sql_ident(name)
    return admin_sql(url, "SELECT concat_ws('|',encoding,datcollate,datctype,dattablespace,datconnlimit,COALESCE(datacl::text,''),datallowconn) FROM pg_database WHERE datname='" + name + "';")



def engine_for(url):
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool
    return create_engine(url, poolclass=NullPool, hide_parameters=True, connect_args={'connect_timeout': 5})


def canonical_index_definition(table, name, definition):
    if (table, name) != ('rp_provision_job', 'uq_rp_job_running_account'):
        return definition
    match = re.fullmatch(r'CREATE UNIQUE INDEX uq_rp_job_running_account ON (?:public\.)?rp_provision_job USING btree \(account_id\) WHERE (.+)', definition)
    if not match:
        return definition
    predicate = match.group(1)
    literals = re.findall(r"'(?:''|[^'])*'", predicate)
    if sorted(literals) not in (["'review'", "'running'"], ["'{running,review}'"], ["'{review,running}'"]):
        return definition
    normalized = re.sub(r'::(?:character varying|varchar|text)(?:\[\])?(?![A-Za-z0-9_\[])', '', predicate)
    normalized = re.sub(r'[\s()]', '', normalized)
    if normalized in {
        "state=ANYARRAY['running','review']", "state=ANYARRAY['review','running']",
        "stateIN'running','review'", "stateIN'review','running'",
        "state=ANY'{running,review}'", "state=ANY'{review,running}'",
    }:
        return 'verified unique btree account_id WHERE state IN (running, review)'
    return definition


def schema_signature(engine):
    from sqlalchemy import inspect
    inspector = inspect(engine)
    from sqlalchemy import text
    tables = {name: tuple(sorted((column['name'], str(column['type']), bool(column['nullable']))
                                 for column in inspector.get_columns(name, schema='public')))
              for name in inspector.get_table_names(schema='public')}
    with engine.connect() as conn:
        constraints = tuple(conn.execute(text("SELECT c.relname,con.conname,pg_get_constraintdef(con.oid),con.convalidated FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,con.conname")).tuples())
        index_rows = conn.execute(text("SELECT v.tablename,v.indexname,v.indexdef,i.indisunique,i.indisvalid,i.indisready,i.indislive,i.indimmediate FROM pg_indexes v JOIN pg_namespace n ON n.nspname=v.schemaname JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=v.indexname JOIN pg_index i ON i.indexrelid=c.oid WHERE v.schemaname='public' ORDER BY v.tablename,v.indexname"))
        indexes = []
        for table, name, definition, unique, valid, ready, live, immediate in index_rows:
            if (table, name) == ('rp_provision_job', 'uq_rp_job_running_account'):
                if not all((unique, valid, ready, live, immediate)):
                    raise RuntimeError('The provisioning execution index is not a valid, immediate unique index. Review database maintenance before restoring.')
                definition = canonical_index_definition(table, name, definition)
            indexes.append((table, name, definition))
        indexes = tuple(indexes)
    return tables, constraints, indexes


def schema_differences(expected, actual):
    differences = []
    old_tables, new_tables = expected[0], actual[0]
    for name in sorted(old_tables.keys() - new_tables.keys()):
        differences.append(('missing_table', name))
    for name in sorted(new_tables.keys() - old_tables.keys()):
        differences.append(('extra_table', name))
    for name in sorted(old_tables.keys() & new_tables.keys()):
        old = {column[0]: column[1:] for column in old_tables[name]}
        new = {column[0]: column[1:] for column in new_tables[name]}
        for column in sorted(old.keys() - new.keys()):
            differences.append(('missing_column', name, column))
        for column in sorted(new.keys() - old.keys()):
            differences.append(('extra_column', name, column))
        for column in sorted(old.keys() & new.keys()):
            if old[column] != new[column]:
                differences.append(('column_type_or_nullability_changed', name, column))
    for position, category in ((1, 'constraint'), (2, 'index')):
        old = {tuple(row[:2]): tuple(row[2:]) for row in expected[position]}
        new = {tuple(row[:2]): tuple(row[2:]) for row in actual[position]}
        for key in sorted(old.keys() - new.keys()):
            differences.append(('missing_' + category, *key))
        for key in sorted(new.keys() - old.keys()):
            differences.append(('extra_' + category, *key))
        for key in sorted(old.keys() & new.keys()):
            if old[key] != new[key]:
                differences.append(('changed_' + category, *key))
    return differences


def check_database(url, expected=None):
    from sqlalchemy import text
    engine = engine_for(url)
    try:
        with engine.connect() as conn:
            oid = str(conn.execute(text('SELECT oid FROM pg_database WHERE datname=current_database()')).scalar_one())
            role = conn.execute(text('SELECT current_user')).scalar_one()
            if role != url.username or oid != database_oid(url, url.database):
                raise RuntimeError('Database is not on the expected local PostgreSQL cluster.')
            privileged = conn.execute(text('SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user')).scalar_one()
            if privileged:
                raise RuntimeError('Restore requires an unprivileged application database role.')
            if not conn.execute(text('SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_database WHERE datname=current_database()')).scalar_one():
                raise RuntimeError('Application role must own the database.')
        signature = schema_signature(engine)
        if not {'admin_account', 'peer', 'interface_config', 'subscription', 'rp_account', 'rp_provision_job'}.issubset(signature[0]):
            raise RuntimeError('Backup database schema is incomplete.')
        if expected is not None and signature != expected:
            report_schema_differences(expected, signature)
            raise RuntimeError('Backup schema differs from the installed schema. See the restore journal for the differing objects. Original database is unchanged.')
        return signature, oid
    finally:
        engine.dispose()


def report_schema_differences(expected, actual):
    differences = schema_differences(expected, actual)
    print('[WG Panel restore] Schema differences (backup compared with live database): ' + str(len(differences)), flush=True)
    for difference in differences[:200]:
        print('[WG Panel restore] Schema difference: ' + json.dumps(difference, ensure_ascii=True), flush=True)
        if difference == ('changed_index', 'rp_provision_job', 'uq_rp_job_running_account'):
            key = difference[1:]
            for label, signature in (('installed', expected), ('staging', actual)):
                definition = next((row[2] for row in signature[2] if tuple(row[:2]) == key), '')
                print('[WG Panel restore] Provisioning index ' + label + ': ' + json.dumps(definition[:800], ensure_ascii=True), flush=True)
    if len(differences) > 200:
        print('[WG Panel restore] Additional schema differences omitted.', flush=True)
    return differences


def compatible_data_layout(expected, actual):
    current, saved = expected[0], actual[0]
    if current.keys() != saved.keys():
        return False
    for table in current:
        target = {column[0]: column[1:] for column in current[table]}
        source = {column[0]: column[1:] for column in saved[table]}
        missing = target.keys() - source.keys()
        if missing and not (table == 'rp_provision_job' and missing == {'stage'} and target['stage'] == ('VARCHAR(24)', True)):
            return False
        if source.keys() - target.keys():
            return False
        if any(source[name][0] != target[name][0] for name in source):
            return False
    return True


def data_inventory(url, tables):
    from sqlalchemy import text
    engine = engine_for(url)
    try:
        quote = engine.dialect.identifier_preparer.quote_identifier
        with engine.connect() as conn:
            counts = {name: conn.execute(text('SELECT count(*) FROM public.' + quote(name))).scalar_one()
                      for name in sorted(tables)}
            sequences = conn.execute(text("SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename")).scalars().all()
            positions = {name: tuple(conn.execute(text('SELECT last_value,is_called FROM public.' + quote(name))).one())
                         for name in sequences}
        return counts, positions
    finally:
        engine.dispose()


def run_pg_restore(url, dump, section=None):
    options = [] if section is None else ['--data-only'] if section == 'data' else ['--section=' + section]
    result = subprocess.run(['pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '--single-transaction', '--no-password', '--no-tablespaces',
                             *options, *pg_cli(url), str(dump)], env=pg_env(url), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=1800)
    if result.returncode:
        stage = 'staging the backup' if section is None else 'rebuilding the staging database (' + section + ')'
        raise RuntimeError('pg_restore failed while ' + stage + '; the original database has not been replaced.')


def dump_current_schema(url, path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    result = subprocess.run(['pg_dump', '--schema-only', '--format=custom', '--no-owner', '--no-acl', '--no-password', '--no-tablespaces',
                             *pg_cli(url), '--file=' + str(path)], env=pg_env(url), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
    if result.returncode or path.stat().st_size < 5:
        raise RuntimeError('Could not capture the installed database schema. Original database is unchanged.')


def align_staging_schema(url, staged, job, expected, actual, kind):
    if not compatible_data_layout(expected, actual):
        raise RuntimeError('Backup has incompatible tables or columns. A matching release or explicit schema migration is required. Original database is unchanged.')
    write_status(job, 'aligning', 'Backup data layout is compatible. Rebuilding staging with the installed schema and verifying every table and sequence.', kind=kind)
    before = data_inventory(staged, actual[0])
    schema = job / 'installed-schema.dump'
    try:
        dump_current_schema(url, schema)
        verify_no_sessions(url, staged.database)
        admin_sql(url, 'DROP DATABASE ' + sql_ident(staged.database) + ';')
        admin_sql(url, 'CREATE DATABASE ' + sql_ident(staged.database) + ' OWNER ' + sql_ident(url.username) + ' TEMPLATE template0;')
        run_pg_restore(staged, schema, 'pre-data')
        run_pg_restore(staged, job / 'incoming.dump', 'data')
        run_pg_restore(staged, schema, 'post-data')
        _, oid = check_database(staged, expected)
        if before != data_inventory(staged, expected[0]):
            raise RuntimeError('Staging row counts or sequence values changed during schema alignment. Original database is unchanged.')
        print('[WG Panel restore] Staging schema alignment and data inventory verified.', flush=True)
        return oid
    finally:
        schema.unlink(missing_ok=True)


def validate_network_and_keys(url, original, restore_wg=False):
    from sqlalchemy import text
    from dotenv import dotenv_values
    from panel_core.encryption_keys import reseller_cipher
    from cryptography.fernet import InvalidToken
    env = dotenv_values(ROOT / '.env', interpolate=False)
    cipher = reseller_cipher(env.get('FLASK_SECRET_KEY') or '', env.get('WG_RESELLER_ENCRYPTION_KEY'),
                             env.get('WG_RESELLER_PREVIOUS_KEYS'), env.get('WG_RESELLER_LEGACY_SECRET'))
    old = engine_for(original)
    target = engine_for(url)
    try:
        def inventory(conn):
            interfaces = {r[0]: tuple(r[1:]) for r in conn.execute(text('SELECT i.name,i.public_key,i.address,i.listen_port,n.base_url FROM interface_config i LEFT JOIN node n ON n.id=i.node_id'))}
            peers = {(r[0],r[1]) for r in conn.execute(text('SELECT i.name,p.public_key FROM peer p JOIN interface_config i ON i.id=p.iface_id'))}
            return interfaces, peers
        with old.connect() as conn:
            current_interfaces, current_peers = inventory(conn)
        with target.connect() as conn:
            restored_interfaces, restored_peers = inventory(conn)
            if current_interfaces != restored_interfaces:
                raise RuntimeError('Backup interface identities differ from the current server. Use coordinated manual recovery.')
            if restore_wg:
                remote_names = {name for name, identity in current_interfaces.items() if identity[-1] is not None or ':' in name}
                if {p for p in current_peers if p[0] in remote_names} != {p for p in restored_peers if p[0] in remote_names}:
                    raise RuntimeError('Remote node customer identities differ. Use coordinated manual recovery.')
            if not restore_wg and current_peers - restored_peers:
                raise RuntimeError('Current customers are absent from the backup. Reconcile their WireGuard access before restoring older database data.')
            for query in ("SELECT link_enc FROM rp_account WHERE state!='deleted'", 'SELECT token_enc FROM rp_management_bot WHERE token_enc IS NOT NULL', 'SELECT totp_secret_enc FROM rp_account_security WHERE totp_secret_enc IS NOT NULL'):
                for value, in conn.execution_options(stream_results=True).execute(text(query)):
                    if not value:
                        continue
                    try:
                        cipher.decrypt(value.encode())
                    except (InvalidToken, TypeError, ValueError, AttributeError):
                        raise RuntimeError('A restored encrypted reseller record cannot be decrypted with the current keys.') from None
    finally:
        old.dispose()
        target.dispose()


def validate_wireguard_scope(archive, kind):
    if kind != 'full':
        raise ValueError('WireGuard recovery requires a Full backup.')
    names = archive.namelist()
    if any(n.startswith('nodes/') and '/wg/' in n and n.endswith('.conf') for n in names):
        raise ValueError('Managed WireGuard recovery supports local interfaces only. Backups containing remote node configs require manual recovery.')
    members = [n for n in names if n.startswith('wg/') and n.endswith('.conf')]
    if not members or any(not re.fullmatch(r'wg/[A-Za-z0-9_=+.-]{1,15}\.conf', n) for n in members):
        raise ValueError('A Full backup with valid local WireGuard configuration files is required.')
    if not shutil.which('wg'):
        raise RuntimeError('WireGuard tools are required for network recovery.')
    return members


def parse_wireguard(raw):
    sections = []
    current = None
    try:
        for line in raw.decode('utf-8').splitlines():
            line = line.split(chr(35), 1)[0].strip()
            if not line:
                continue
            if line in ('[Interface]', '[Peer]'):
                current = (line, {})
                sections.append(current)
                continue
            key, sep, value = line.partition('=')
            key, value = key.strip(), value.strip()
            if current is None or not sep or not value:
                raise ValueError
            current[1].setdefault(key, []).append(value)
        if not sections or sections[0][0] != '[Interface]' or any(section != '[Peer]' for section, _ in sections[1:]):
            raise ValueError
        header = sections[0][1]
        allowed_header = {'PrivateKey','ListenPort','FwMark','Address','DNS','MTU','Table','PreUp','PostUp','PreDown','PostDown','SaveConfig'}
        if set(header) - allowed_header or any(len(v) != 1 for k,v in header.items() if k not in {'Address','DNS','PreUp','PostUp','PreDown','PostDown'}):
            raise ValueError
        if not re.fullmatch(r'[A-Za-z0-9+/]{43}=', header['PrivateKey'][0]):
            raise ValueError
        peers = {}
        for _, fields in sections[1:]:
            if set(fields) - {'PublicKey','PresharedKey','AllowedIPs','Endpoint','PersistentKeepalive'} or any(len(v) != 1 for k,v in fields.items() if k != 'AllowedIPs'):
                raise ValueError
            key = fields['PublicKey'][0]
            if key in peers or not re.fullmatch(r'[A-Za-z0-9+/]{43}=', key):
                raise ValueError
            if 'PresharedKey' in fields and not re.fullmatch(r'[A-Za-z0-9+/]{43}=', fields['PresharedKey'][0]):
                raise ValueError
            ips = frozenset(str(ipaddress.ip_network(ip.strip(), strict=True)) for line in fields.get('AllowedIPs', []) for ip in line.split(','))
            peers[key] = (ips, fields)
        return header, peers
    except (ValueError, KeyError, IndexError, UnicodeError):
        raise ValueError('Invalid or unsupported WireGuard configuration.') from None


def wg_command(*args, data=None):
    result = subprocess.run(['wg', *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError('WireGuard command failed during recovery. Review interface state.')
    return result.stdout


def wireguard_inventory(url):
    from sqlalchemy import text
    engine = engine_for(url)
    try:
        with engine.connect() as conn:
            interfaces = {row[0]: tuple(row[1:]) for row in conn.execute(text('SELECT name,path,address,listen_port,public_key FROM interface_config WHERE node_id IS NULL'))}
            peers = {name: {} for name in interfaces}
            for name, key, address, status in conn.execute(text('SELECT i.name,p.public_key,p.address,p.status FROM peer p JOIN interface_config i ON p.iface_id=i.id WHERE i.node_id IS NULL')):
                ip = ipaddress.ip_interface(address).ip
                if key in peers[name]:
                    raise RuntimeError('Duplicate customer key in database.')
                peers[name][key] = (frozenset({str(ipaddress.ip_network(ip))}), status)
            remote = set(conn.execute(text('SELECT i.name,p.public_key,p.address,p.status,p.peer_endpoint,p.persistent_keepalive FROM peer p JOIN interface_config i ON p.iface_id=i.id WHERE i.node_id IS NOT NULL')).tuples())
        return interfaces, peers, remote
    finally:
        engine.dispose()


def check_peer_addresses(config, records):
    if any(key not in records or ips != records[key][0] for key,(ips,_) in config.items()):
        raise RuntimeError('WireGuard peer keys or addresses do not match the corresponding database records.')


def runtime_config(peers, live_header, records):
    lines = ['[Interface]']
    for key in ('PrivateKey','ListenPort','FwMark'):
        for value in live_header.get(key, []):
            lines.append(key + ' = ' + value)
    for key, (_, fields) in peers.items():
        if records[key][1] in ('offline','blocked'):
            continue
        lines.append('[Peer]')
        for field, values in fields.items():
            lines.extend(field + ' = ' + value for value in values)
    return ('\n'.join(lines) + '\n').encode()


def wireguard_plan(job, archive, staged, original, kind):
    from dotenv import dotenv_values
    from panel_core.backup_integrity import atomic_write, destination
    from io import BytesIO
    members = validate_wireguard_scope(archive, kind)
    interfaces, peers, remote = wireguard_inventory(staged)
    old_interfaces, old_peers, old_remote = wireguard_inventory(original)
    if interfaces != old_interfaces or remote != old_remote:
        raise RuntimeError('Interface paths or remote customer state differ. Use manual recovery.')
    if set(members) != {'wg/' + name + '.conf' for name in interfaces}:
        raise RuntimeError('The backup must contain exactly the managed local interface files.')
    root = Path(dotenv_values(ROOT / '.env', interpolate=False).get('WIREGUARD_CONF_PATH') or '/etc/wireguard').resolve(strict=True)
    active_names = set(wg_command('show', 'interfaces').decode().split())
    network = private_dir(job / 'network')
    plan = []
    for member in sorted(members):
        name = Path(member).stem
        path, address, port, public = interfaces[name]
        dest = destination(root, name + '.conf')
        if Path(path).absolute() != dest or not dest.is_file():
            raise RuntimeError('Managed local interface configuration path differs.')
        saved = archive.read(member)
        current = dest.read_bytes()
        header, restored_peers = parse_wireguard(saved)
        old_header, current_peers = parse_wireguard(current)
        header_bytes = lambda raw: re.split(rb"(?m)^\s*\[Peer\]\s*$", raw, maxsplit=1)[0].strip()
        if header != old_header or header_bytes(saved) != header_bytes(current):
            raise RuntimeError('Interface settings differ. Managed restore preserves server keys, routes, hooks and interface settings.')
        if str(ipaddress.ip_interface(address)) not in {str(ipaddress.ip_interface(x.strip())) for v in header.get('Address',[]) for x in v.split(',')} or header.get('ListenPort') != [str(port)]:
            raise RuntimeError('WireGuard interface address or port differs from the database.')
        if wg_command('pubkey', data=(header['PrivateKey'][0]+'\n').encode()).decode().strip() != public:
            raise RuntimeError('WireGuard interface key differs from the database.')
        check_peer_addresses(restored_peers, peers[name])
        check_peer_addresses(current_peers, old_peers[name])
        missing = {k for k,(_,status) in peers[name].items() if status not in ('offline','blocked') and k not in restored_peers}
        if missing:
            raise RuntimeError('Active customer configurations are missing from the backup.')
        old_file = network / (name + '.previous.conf')
        new_file = network / (name + '.restored.conf')
        atomic_write(old_file, BytesIO(current))
        atomic_write(new_file, BytesIO(saved))
        old_runtime = new_runtime = None
        if name in active_names:
            live = wg_command('showconf', name)
            live_header, live_peers = parse_wireguard(live)
            check_peer_addresses(live_peers, old_peers[name])
            if live_header.get('PrivateKey') != header.get('PrivateKey') or live_header.get('ListenPort') != header.get('ListenPort'):
                raise RuntimeError('Active interface identity differs from the backup.')
            old_runtime = network / (name + '.previous.runtime')
            new_runtime = network / (name + '.restored.runtime')
            atomic_write(old_runtime, BytesIO(live))
            atomic_write(new_runtime, BytesIO(runtime_config(restored_peers, live_header, peers[name])))
        plan.append((name, dest, old_file, new_file, old_runtime, new_runtime))
    atomic_write(network / 'manifest.json', BytesIO(json.dumps([{'interface': n, 'path': str(dest), 'active': old_runtime is not None} for n,dest,_,_,old_runtime,_ in plan]).encode()))
    sync_directory(network)
    sync_directory(job)
    return plan


def verify_runtime(name, expected):
    header, peers = parse_wireguard(expected.read_bytes())
    live_header, live_peers = parse_wireguard(wg_command('showconf', name))
    if any(live_header.get(key) != header.get(key) for key in ('PrivateKey','ListenPort','FwMark')) or {k:v[0] for k,v in peers.items()} != {k:v[0] for k,v in live_peers.items()}:
        raise RuntimeError('Restored WireGuard runtime does not match the verified configuration.')
    for key, (_, fields) in peers.items():
        actual = live_peers[key][1]
        if actual.get('PresharedKey') != fields.get('PresharedKey') or int(actual.get('PersistentKeepalive',['0'])[0]) != int(fields.get('PersistentKeepalive',['0'])[0]):
            raise RuntimeError('Restored WireGuard peer settings differ.')


def apply_wireguard(plan, rollback=False):
    from panel_core.backup_integrity import atomic_write
    active_names = set(wg_command('show', 'interfaces').decode().split())
    errors = []
    for name, dest, old_file, new_file, old_runtime, new_runtime in plan:
        try:
            if (name in active_names) != (old_runtime is not None):
                raise RuntimeError('Interface activation changed during recovery.')
            selected = old_file if rollback else new_file
            runtime = old_runtime if rollback else new_runtime
            if runtime is not None:
                wg_command('syncconf', name, str(runtime))
                verify_runtime(name, runtime)
            with selected.open('rb') as source:
                atomic_write(dest, source)
            sync_directory(dest.parent)
            if dest.read_bytes() != selected.read_bytes():
                raise RuntimeError('WireGuard configuration file verification failed.')
        except Exception:
            if not rollback:
                raise
            errors.append(name)
    if errors:
        raise RuntimeError('Network rollback could not be verified for all interfaces. Keep panel writers stopped.')


def quarantine(url, original):
    from sqlalchemy import text
    old = engine_for(original)
    target = engine_for(url)
    try:
        with old.connect() as conn:
            admin_rev = conn.execute(text('SELECT COALESCE(MAX(session_revision),0) FROM admin_account')).scalar_one()
            reseller_rev = conn.execute(text('SELECT COALESCE(MAX(session_version),0) FROM rp_account')).scalar_one()
        with target.begin() as conn:
            if not conn.execute(text('SELECT COUNT(*) FROM admin_account')).scalar_one():
                raise RuntimeError('Backup has no administrator account.')
            conn.execute(text("UPDATE rp_provision_job SET state='review',stage='review',message='Restored interrupted operation; reconcile before resuming.',finished_at=NOW(),notify_after=NULL,notified_at=NOW() WHERE state='running'"))
            conn.execute(text("UPDATE rp_provision_job SET state='rejected',stage='not_applied',message='Cancelled during database restore; submit again after review.',finished_at=NOW(),payload_enc=NULL,notify_after=NULL,notified_at=NOW() WHERE state='queued'"))
            conn.execute(text("UPDATE rp_provision_job SET notified_at=NOW(),notify_after=NULL WHERE notified_at IS NULL"))
            conn.execute(text('UPDATE admin_account SET session_revision=GREATEST(session_revision,:revision)+1'), {'revision': admin_rev})
            conn.execute(text('UPDATE rp_account SET session_version=GREATEST(session_version,:revision)+1'), {'revision': reseller_rev})
    finally:
        old.dispose()
        target.dispose()


def verify_no_sessions(url, *names):
    literals = ','.join("'" + name + "'" for name in names if sql_ident(name))
    if admin_sql(url, 'SELECT count(*) FROM pg_stat_activity WHERE datname IN (' + literals + ');') != '0':
        raise RuntimeError('Additional database connections remain. No cutover was performed.')


def swap_databases(url, staged, recovery):
    live = sql_ident(url.database)
    stage = sql_ident(staged)
    old = sql_ident(recovery)
    admin_sql(url, 'BEGIN; SET LOCAL lock_timeout=\'10s\'; ALTER DATABASE ' + live + ' RENAME TO ' + old + '; ALTER DATABASE ' + stage + ' RENAME TO ' + live + '; ALTER DATABASE ' + old + ' ALLOW_CONNECTIONS false; COMMIT;')


def snapshot_settings(job, archive, kind):
    from panel_core.backup_integrity import destination, atomic_write
    selected = []
    if kind == 'full':
        for name in sorted(SETTINGS):
            member = 'instance/' + name
            if member not in archive.namelist():
                continue
            dest = destination(ROOT / 'instance', name)
            if dest.exists():
                with dest.open('rb') as source:
                    atomic_write(job / ('previous-' + name), source)
            selected.append((member, dest))
    return selected


def apply_settings(archive, selected):
    from panel_core.backup_integrity import atomic_write
    for member, dest in selected:
        with archive.open(member) as source:
            atomic_write(dest, source)


def restart_original(services, probe):
    from scripts import deployment as d, startup_upgrade as s
    d.start_services(ROOT, [s.PANEL], wait=90)
    deadline = time.monotonic() + 90
    while not probe():
        if time.monotonic() >= deadline:
            raise RuntimeError('Panel readiness could not be verified.')
        time.sleep(2)
    others = [name for name in services if name != s.PANEL]
    if others:
        d.start_services(ROOT, others, wait=150)


@contextmanager
def migration_lock():
    fd = os.open('/run/lock/wgpanel-postgresql-migration.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RuntimeError('Unsafe migration lock permissions.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def execute(reference, kind, restore_wg=False):
    from scripts import deployment as d, startup_upgrade as s
    from panel_core.backup_integrity import atomic_write
    from panel_core.postgres_backup import postgres_dump
    from io import BytesIO
    job = operation_path(reference)
    if job.is_symlink() or not job.is_dir():
        raise RuntimeError('Restore request is not queued.')
    queued = read_status(reference)
    if queued['state'] != 'queued' or bool(queued.get('restore_wg', False)) != restore_wg:
        raise RuntimeError('Restore request is not queued or its recovery scope differs.')
    deadline = time.monotonic() + 30
    while d.lock_active(ROOT):
        if time.monotonic() >= deadline:
            raise RuntimeError('Deployment lock did not become available.')
        time.sleep(.5)
    url, services, probe = preflight()
    staging, recovery = 'wg_restore_' + reference[:20], 'wg_recovery_' + reference[:20]
    original_oid = staged_oid = None
    stopping = switched = stage_created = False
    selected = []
    network_plan = []
    network_started = False
    marker = directory() / 'blocked'
    with d.deployment_lock(ROOT), migration_lock():
        try:
            with zipfile.ZipFile(job / 'backup.zip') as archive:
                write_status(job, 'validating', 'Validating backup and current database schema.', kind=kind)
                validate_source(archive, kind)
                if restore_wg:
                    validate_wireguard_scope(archive, kind)
                signature, original_oid = check_database(url)
                if database_oid(url, staging) or database_oid(url, recovery):
                    raise RuntimeError('Restore database names are already in use.')
                with archive.open(DUMP_MEMBER) as source:
                    atomic_write(job / 'incoming.dump', source)
                if subprocess.run(['pg_restore', '--list', str(job / 'incoming.dump')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60).returncode:
                    raise RuntimeError('PostgreSQL dump table of contents cannot be read.')
                write_status(job, 'staging', 'Restoring backup into a separate database. Existing services remain online.', kind=kind)
                admin_sql(url, 'CREATE DATABASE ' + sql_ident(staging) + ' OWNER ' + sql_ident(url.username) + ' TEMPLATE template0;')
                stage_created = True
                staged = url.set(database=staging)
                run_pg_restore(staged, job / 'incoming.dump')
                staged_signature, staged_oid = check_database(staged)
                if staged_signature != signature:
                    report_schema_differences(signature, staged_signature)
                    staged_oid = align_staging_schema(url, staged, job, signature, staged_signature, kind)
                if database_defaults(url, staging) != database_defaults(url, url.database):
                    raise RuntimeError('Database defaults or grants differ from standard staging settings. Use manual recovery.')
                write_status(job, 'stopping', 'Stopping panel, bots and workers for the final recovery backup.', kind=kind)
                atomic_write(marker, BytesIO(reference.encode()))
                sync_directory(marker.parent)
                stopping = True
                d.stop_services(services)
                if s.info(s.WATCHDOG_SERVICE).get('ActiveState') in ('active', 'activating'):
                    d.systemctl('stop', s.WATCHDOG_SERVICE)
                verify_no_sessions(url, url.database, staging)
                check_database(url, signature)
                selected = snapshot_settings(job, archive, kind)
                with (ROOT / '.env').open('rb') as source:
                    atomic_write(job / 'original.env', source)
                write_status(job, 'backup', 'Creating a private recovery copy of the original database.', kind=kind)
                with postgres_dump(url, timeout=1800) as dump:
                    with open(dump, 'rb') as source:
                        atomic_write(job / 'recovery.dump', source)
                if restore_wg:
                    validate_network_and_keys(staged, url, True)
                    network_plan = wireguard_plan(job, archive, staged, url, kind)
                else:
                    validate_network_and_keys(staged, url)
                quarantine(staged, url)
                verify_no_sessions(url, url.database, staging)
                atomic_write(job / 'recovery.json', BytesIO(json.dumps({'live_database': url.database, 'original_oid': original_oid, 'staging_database': staging, 'staged_oid': staged_oid, 'recovery_database': recovery, 'services': services, 'restore_wg': restore_wg}).encode()))
                sync_directory(job)
                if restore_wg:
                    write_status(job, 'wireguard', 'PostgreSQL verified. Restoring local WireGuard files and active peers before database activation.', kind=kind)
                    network_started = True
                    apply_wireguard(network_plan)
                write_status(job, 'cutover', 'Activating the verified database. Original database will be retained.', kind=kind, recovery_database=recovery)
                swap_databases(url, staging, recovery)
                switched = True
                if database_oid(url, url.database) != staged_oid or database_oid(url, recovery) != original_oid:
                    raise RuntimeError('Database identity after cutover could not be verified.')
                apply_settings(archive, selected)
                clear_marker(marker)
                write_status(job, 'restarting', 'Database restored. Starting and checking the original panel services.', kind=kind, recovery_database=recovery)
                restart_original(services, probe)
                write_status(job, 'completed', 'Restore completed. Sign in with the restored administrator credentials and review customer and WireGuard state.', kind=kind,
                             recovery_database=recovery, restored={'db': True, 'settings': bool(selected), 'wg': restore_wg, 'node_wg': False},
                             warnings=['Server settings and keys were kept. Local WireGuard files and active peers were restored.' if restore_wg else 'Server settings and keys were kept. WireGuard files were not replaced from the archive; normal startup reconciliation may change peer state.', 'Restored unfinished operations were quarantined or cancelled. Review network state before allowing heavy traffic.'])
        except BaseException as exc:
            reason = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else type(exc).__name__
            print('[WG Panel restore] Failure: ' + reason, flush=True)
            if original_oid is not None:
                try:
                    switched = switched or database_oid(url, url.database) != original_oid
                except Exception:
                    switched = True
            if switched:
                write_status(job, 'review', 'Restore cutover may have completed. Original database is retained; do not roll back automatically. Check the journal.', kind=kind, recovery_database=recovery)
            else:
                try:
                    if network_started:
                        apply_wireguard(network_plan, rollback=True)
                    if stage_created:
                        admin_sql(url, 'DROP DATABASE IF EXISTS ' + sql_ident(staging) + ';')
                    if stopping:
                        clear_marker(marker)
                        restart_original(services, probe)
                    write_status(job, 'failed', 'Restore stopped before cutover. Original database retained. ' + ('Original network restored. ' if network_started else '') + reason, kind=kind)
                except Exception:
                    write_status(job, 'review', 'Original database retained but service recovery requires review. Check the journal.', kind=kind)
            raise
        finally:
            (job / 'incoming.dump').unlink(missing_ok=True)
            (job / 'backup.zip').unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('--kind', required=True, choices=('db', 'full'))
    parser.add_argument('--wireguard', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root privileges required.')
    try:
        execute(args.run, args.kind, args.wireguard)
        return 0
    except Exception as exc:
        print('[WG Panel restore] Maintenance stopped: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), flush=True)
        try:
            job = operation_path(args.run)
            if read_status(args.run)['state'] not in TERMINAL:
                write_status(job, 'review', 'Maintenance stopped. Check the journal before retrying.')
        except Exception:
            pass
        return 2


if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
