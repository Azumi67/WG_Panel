#!/usr/bin/env python3
"""Guided, conservative PostgreSQL cutover for a local WG Panel systemd installation.

Run as root from the upgraded WG Panel project.  This tool never drops databases,
changes WireGuard interfaces, or prints credentials.  Docker and remote PostgreSQL
setups remain covered by the manual migration guide.
"""
from __future__ import annotations

import argparse
import hashlib
import fcntl
from fnmatch import fnmatch
from contextlib import closing
import stat
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import queue
import secrets
import threading
import shutil
import sqlite3
import subprocess
import sys
import time
import traceback
from urllib.parse import quote, urlsplit, unquote

ROOT = Path(__file__).resolve().parent.parent
RELEASE_ROOT = ROOT
PYTHON = ROOT / 'venv' / 'bin' / 'python'
MIGRATOR = ROOT / 'scripts' / 'migrate_sqlite_to_postgres.py'
CHECK = ROOT / 'scripts' / 'check_postgresql.py'
POSTGRES_ENV = Path('/var/lib/wgpanel-pg-migration/target.env')
STATE_FILE = POSTGRES_ENV.with_name('state.json')
BACKUP_BASE = Path('/var/backups/wgpanel/postgresql-cutover')
ROLE = 'wgpanel_migrated'
DATABASE = 'wgpanel_live'
STOP_SERVICE = re.compile(r'^(?:(?:wg[-_]?panel|wg[-_]?reseller|wg[-_]?plan|wg[-_]?shop|wg[-_]?provision|wg[-_]?monitor|reseller[-_][a-z0-9_-]+|plan[-_]?shop|telegram[-_]?bot)(?:[-_][a-z0-9_-]+)?)(?:@[a-z0-9_.-]+)?\.service$')
STOP_TIMER = re.compile(r'^(?:(?:wg[-_]?panel|wg[-_]?reseller|wg[-_]?plan|wg[-_]?shop)(?:[-_][a-z0-9_-]+)?)\.timer$')
EXCLUDE_SERVICE = re.compile(r'(?:node|agent|quick|tunnel|wireguard)|^wg-panel-rollback-restart-(?:panel|node)-|^wg-panel-update-(?:panel|node)-[0-9]+-[0-9]+\.service$', re.I)


class Stopped(Exception):
    pass


def announce(msg):
    print('[WG Panel] ' + msg, flush=True)


def migration_prompt():

    green = sys.stdin.isatty() and sys.stdout.isatty() and not os.getenv('NO_COLOR')
    word = '\033[1;32mMIGRATE\033[0m' if green else 'MIGRATE'
    return 'Type ' + word + ' to continue: '


def command(args, *, stdin=None, env=None, timeout=120, label=None):


    operation = label or Path(str(args[0])).name
    try:
        result = subprocess.run(args, input=stdin, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise Stopped(f'{operation} timed out after {timeout}s. The command may '
                      'have partially completed; review service status before retrying.') from exc
    except OSError as exc:
        raise Stopped(f'{operation} could not start ({type(exc).__name__}).') from exc
    if result.returncode:
        raise Stopped(f'{operation} failed (exit {result.returncode}). '
                      'Check the relevant system logs; command output is hidden to protect credentials.')
    return result.stdout.strip()


def read_dotenv_key(path, key):
    if not path.is_file():
        return None
    from dotenv import dotenv_values
    value = dotenv_values(path, interpolate=False).get(key)
    return value if value is None else str(value).strip()


def matches_expected_sqlite_path(database_url, sqlite_path):
    if not database_url:
        return True
    if not database_url.startswith('sqlite:///'):
        return False
    portion = database_url[len('sqlite:///'):]
    if portion.startswith('instance/'):
        expected = ROOT / portion
    elif portion.startswith('/'):
        expected = Path(portion)
    else:
        expected = ROOT / portion
    return expected.resolve() == sqlite_path.resolve()


def replace_database_url(content, url):

    lines = content.splitlines(keepends=True)
    changed = False
    output = []
    for line in lines:
        if re.match(r'^\s*(?:export\s+)?DATABASE_URL\s*=', line):
            if not changed:
                output.append('DATABASE_URL=' + url + '\n')
                changed = True
            continue
        if re.match(r'^\s*(?:export\s+)?WG_ALLOW_SQLITE_LEGACY\s*=', line):
            continue
        output.append(line)
    if not changed:
        if output and not output[-1].endswith('\n'):
            output.append('\n')
        output.append('DATABASE_URL=' + url + '\n')
    return ''.join(output)


def write_private(path, data, *, preserve_access=False):
    original_stat = path.stat() if preserve_access and path.is_file() else None
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not preserve_access:
        os.chmod(path.parent, 0o700)
    tmp = path.parent / ('.' + path.name + '.' + secrets.token_hex(6))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if original_stat is not None:
            os.chown(tmp, original_stat.st_uid, original_stat.st_gid)
            os.chmod(tmp, 0o600 | (stat.S_IMODE(original_stat.st_mode) & 0o040))
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def discover_active_units():
    services = []
    timers = []
    for typ, regex, dest in [('service', STOP_SERVICE, services), ('timer', STOP_TIMER, timers)]:
        raw = command(['systemctl', 'list-units', '--all', '--type=' + typ,
                       '--plain', '--no-legend', '--no-pager'], timeout=20,
                      label='systemd service discovery')
        for line in raw.splitlines():
            name = line.split()[0] if line.split() else ''
            if regex.match(name) and not EXCLUDE_SERVICE.search(name):
                try:
                    result = subprocess.run(['systemctl', 'is-active', name],
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            text=True, timeout=10, check=False)
                except subprocess.TimeoutExpired as exc:
                    raise Stopped('systemd unit status lookup timed out for ' + name) from exc


                status = (result.stdout or '').strip().lower()
                if status in ('active', 'activating', 'reloading') or (
                        not status and result.returncode == 0):
                    dest.append(name)
    return sorted(set(services)), sorted(set(timers))


def discover_managed_units():


    services, timers = [], []
    for typ, regex, dest in [('service', STOP_SERVICE, services),
                              ('timer', STOP_TIMER, timers)]:
        raw = command(['systemctl', 'list-units', '--all', '--type=' + typ,
                       '--plain', '--no-legend', '--no-pager'], timeout=20,
                      label='systemd managed-unit discovery')
        for line in raw.splitlines():
            fields = line.split()
            if fields and fields[0] == '●':
                fields = fields[1:]
            name = fields[0].lstrip('●') if fields else ''
            if (regex.fullmatch(name) and not EXCLUDE_SERVICE.search(name)
                    and len(fields) >= 2 and fields[1] == 'loaded'):
                dest.append(name)
    return sorted(set(services)), sorted(set(timers))


def verify_env_files(services, project_env):

    for service in services:
        value = command(['systemctl', 'show', '--property=EnvironmentFiles','--value',service],timeout=15,label='systemd environment-file inspection')
        for candidate in re.findall(r'(/[^\s()]+)', value):
            file = Path(candidate)
            if not file.is_file() or file.resolve() == project_env.resolve():
                continue
            active_db = read_dotenv_key(file, 'DATABASE_URL')
            if active_db and active_db.startswith('sqlite:'):
                raise Stopped(f'{service} loads a different environment file containing SQLite. '
                              'Review the unit EnvironmentFile setting before migration.')
        direct = command(['systemctl', 'show', '--property=Environment', '--value',service],timeout=15,label='systemd environment inspection')
        if re.search(r'(?:^|\s)DATABASE_URL=sqlite:', direct):
            raise Stopped(f'{service} overrides DATABASE_URL with SQLite in its systemd unit.')


def postgres_psql(sql):
    return command(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-q', '-A', '-t',
                    '-v', 'ON_ERROR_STOP=1', '-d', 'postgres'], stdin=sql, timeout=25, label='PostgreSQL administration query')


def postgres_ready(*, install):


    announce('Checking for Docker-managed PostgreSQL.')
    if shutil.which('docker'):
        try:
            result = subprocess.run(['docker','ps','--format','{{.Names}}'],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, timeout=8, check=False)
        except subprocess.TimeoutExpired as exc:
            raise Stopped('Docker status check timed out. Check the Docker daemon before migration.') from exc
        if result.returncode == 0 and 'wg-panel-postgres' in result.stdout.splitlines():
            raise Stopped('WG Panel PostgreSQL is running in Docker. Use the Docker-specific instructions instead.')
    if not shutil.which('psql') or not shutil.which('runuser'):
        if not install:
            raise Stopped('PostgreSQL is missing. Rerun without --no-install to install it automatically.')
        if not shutil.which('apt-get'):
            raise Stopped('Auto-install requires Ubuntu/Debian apt-get. Use the manual migration guide.')
        announce('Installing PostgreSQL from the operating-system repositories (may take several minutes).')
        command(['apt-get', 'update', '-qq'], timeout=600, label='APT package index update')
        command(['apt-get', 'install', '-y', '-qq', 'postgresql', 'postgresql-client'],
                timeout=900, label='PostgreSQL package installation')

    announce('Starting PostgreSQL if it is not running.')
    try:
        active = subprocess.run(['systemctl','is-active','--quiet','postgresql'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=12, check=False).returncode == 0
    except subprocess.TimeoutExpired as exc:
        raise Stopped('PostgreSQL systemd status check timed out. '
                      'Inspect: sudo systemctl status postgresql --no-pager') from exc
    if not active:


        command(['systemctl', 'start', '--no-block', 'postgresql'],
                timeout=20, label='PostgreSQL systemd start request')
    announce('Waiting for PostgreSQL to accept local connections.')
    ready = False
    for attempt in range(16):
        try:
            if postgres_psql('SELECT 1;').strip() == '1':
                ready = True
                break
        except Stopped:
            pass
        if attempt < 15:
            time.sleep(3)
    if not ready:
        raise Stopped('PostgreSQL did not become ready. Inspect: '
                      'sudo pg_lsclusters; sudo systemctl status postgresql --no-pager; '
                      'sudo journalctl -u postgresql -n 60 --no-pager')


    try:
        command(['systemctl', 'enable', '--no-reload', 'postgresql'],
                timeout=20, label='PostgreSQL boot enablement')
    except Stopped:
        announce('WARNING: PostgreSQL is reachable but boot enablement failed. '
                 'Run sudo systemctl enable postgresql after migration.')
    announce('Local PostgreSQL is ready.')


def create_or_reuse_database():

    state = {}
    if POSTGRES_ENV.is_file() and not STATE_FILE.is_file():
        raise Stopped('Existing migration credential file has no matching state file. Refusing to guess ownership.')
    if STATE_FILE.is_file():
        try:
            state = json.loads(STATE_FILE.read_text(encoding='utf-8'))
        except Exception:
            raise Stopped('Previous migration state cannot be read. No changes made.')
    role_exists = postgres_psql("SELECT 1 FROM pg_roles WHERE rolname='" + ROLE + "';") == '1'
    db_exists = postgres_psql("SELECT 1 FROM pg_database WHERE datname='" + DATABASE + "';") == '1'
    if (role_exists or db_exists) and (not POSTGRES_ENV.is_file() or not state.get('managed')):
        raise Stopped('A PostgreSQL target already exists but was not created by this wizard. '
                      'It will not be overwritten. Use the manual instructions for your existing target.')
    if not POSTGRES_ENV.is_file():
        password = secrets.token_urlsafe(40)
        url = f'postgresql+psycopg://{ROLE}:{quote(password, safe="")}@127.0.0.1:5432/{DATABASE}'
        write_private(POSTGRES_ENV, 'DATABASE_URL=' + url + '\n')
        state = {'managed':True, 'imported':False, 'cutover':False}
        write_private(STATE_FILE, json.dumps(state))
    else:
        url = read_dotenv_key(POSTGRES_ENV, 'DATABASE_URL')
        parsed = urlsplit(url or '')
        if (parsed.scheme != 'postgresql+psycopg' or parsed.hostname != '127.0.0.1'
                or parsed.username != ROLE or parsed.path != '/' + DATABASE):
            raise Stopped('Stored target URL is invalid. No changes made.')
    if not role_exists:

        secret = unquote(urlsplit(url).password or '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{30,}', secret):
            raise Stopped('Generated PostgreSQL credentials are not valid.')
        postgres_psql(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{secret}';")
    if not db_exists:
        postgres_psql(f'CREATE DATABASE {DATABASE} OWNER {ROLE};')
    return url, state


def snapshot_sqlite(source, target):
    with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True, timeout=30)) as origin:
        with closing(sqlite3.connect(str(target), timeout=30)) as destination:
            origin.backup(destination, pages=1024, sleep=0.1)
    with closing(sqlite3.connect(str(target))) as check:
        if check.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise Stopped('SQLite backup failed integrity check.')
        if check.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise Stopped('SQLite backup contains broken foreign keys. Migration halted.')


def source_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def backup_source(sqlite_path, backup_dir):
    backup_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(backup_dir, 0o700)
    source_env = ROOT / '.env'
    shutil.copy2(source_env, backup_dir / 'original.env')
    os.chmod(backup_dir / 'original.env', 0o600)
    snapshot_sqlite(sqlite_path, backup_dir / 'wg_panel.sqlite')
    auth = ROOT / 'instance' / 'reseller-request-guard.sqlite'
    if auth.is_file():
        snapshot_sqlite(auth, backup_dir / 'reseller-request-guard.sqlite')

    instance = ROOT / 'instance'
    if instance.is_dir():
        shutil.copytree(instance, backup_dir / 'instance', symlinks=True)
    announce('Backups saved privately under ' + str(backup_dir))


def environment_update(old, url):
    return replace_database_url(old, url)


def rollback_env(original_file):
    if original_file.is_file():
        write_private(ROOT / '.env', original_file.read_text(encoding='utf-8'), preserve_access=True)


def install_driver():
    if not PYTHON.is_file() or not MIGRATOR.is_file() or not CHECK.is_file():
        raise Stopped('Expected the updated WG Panel venv and migration files in the project directory.')
    announce('Checking PostgreSQL Python dependencies.')
    try:
        command([str(PYTHON),'-c','import psycopg; import sqlalchemy; import dotenv'],
                timeout=45, label='PostgreSQL Python dependency check')
    except Stopped as exc:
        if 'timed out' in str(exc):
            raise
        announce('Installing the PostgreSQL Python driver into the WG Panel venv.')
        command([str(PYTHON),'-m','pip','install','-r',str(MIGRATOR.parent.parent/'requirements-postgres.txt')],
                timeout=600, label='PostgreSQL Python dependency installation')
        command([str(PYTHON),'-c','import psycopg; import sqlalchemy; import dotenv'],
                timeout=45, label='PostgreSQL Python dependency verification')


def call_migration(sqlite_path, *, apply, auth_path):


    args = [str(PYTHON), '-u', str(MIGRATOR), '--sqlite', str(sqlite_path),
            '--pg-env-file', str(POSTGRES_ENV)]
    if auth_path and auth_path.is_file():
        args += ['--auth-db', str(auth_path)]
    if apply:
        args.append('--apply')
    operation = 'PostgreSQL data import' if apply else 'SQLite migration preflight'
    announce(operation + ' started.')
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True,
                                   encoding='utf-8', errors='replace', bufsize=1)
    except OSError as exc:
        raise Stopped(operation + ' could not start (' + type(exc).__name__ + ').') from exc
    output = queue.Queue()
    def reader():
        try:
            for line in process.stdout:
                output.put(line.rstrip('\r\n'))
        finally:
            output.put(None)
    worker = threading.Thread(target=reader, daemon=True)
    worker.start()
    deadline = time.monotonic() + (3600 if apply else 180)
    next_status = time.monotonic() + 10
    diagnostic = None
    preflight_summary = None
    completed_reader = False
    try:
        while not completed_reader or process.poll() is None:
            try:
                line = output.get(timeout=0.5)
            except queue.Empty:
                line = ...
            if line is None:
                completed_reader = True
            elif line is not ...:
                match = re.fullmatch(r'MIGRATION_DIAGNOSTIC ([A-Z_]{3,40}): (.{1,500})', line)
                if match:
                    diagnostic = f'{match.group(1)}: {match.group(2)}'
                    announce('Diagnostic — ' + diagnostic)
                elif re.fullmatch(r'MIGRATION_PROGRESS [0-9]+/[0-9]+ [A-Za-z0-9_]+ rows=[0-9]+', line):
                    announce('Import progress: ' + line[len('MIGRATION_PROGRESS '):])
                elif line.startswith('{'):
                    try:
                        report = json.loads(line)
                        if report.get('target_backend') == 'postgresql' and set(report) <= {'source_tables','source_rows','auth_guard_rows','target_backend','apply'}:
                            preflight_summary = (f'{report.get("source_tables",0)} tables, '
                                                 f'{report.get("source_rows",0)} rows, '
                                                 f'{report.get("auth_guard_rows",0)} auth-guard rows')
                    except (ValueError, AttributeError, TypeError):
                        pass
            now = time.monotonic()
            if now > deadline:
                raise Stopped(operation + ' timed out. Original SQLite data was not deleted.')
            if now >= next_status and process.poll() is None:
                announce(operation + ': still working; ' + str(int((3600 if apply else 180) - (deadline - now))) + 's elapsed.')
                next_status = now + 10
        rc = process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()
    if rc:
        raise Stopped(operation + ' failed (exit ' + str(rc) + '). '
                      + (diagnostic or 'No structured diagnostic was returned. Run a read-only source inspection to identify the issue.'))
    if preflight_summary:
        announce(('Verified source: ' if not apply else 'Imported: ') + preflight_summary)
    announce(operation + ' completed successfully.')


def verify_target(url):
    env = dict(os.environ)
    env['DATABASE_URL'] = url
    command([str(PYTHON), str(CHECK)], env=env, timeout=90,
            label='PostgreSQL application verification')


def restart_services(services, timers):
    ordered = sorted(services, key=lambda value:(0 if value == 'wg-panel.service' else 1, value))
    for service in ordered:
        command(['systemctl','start',service],timeout=100,
                label='Starting ' + service)
        try:
            active = subprocess.run(['systemctl','is-active','--quiet',service],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=10, check=False).returncode == 0
        except subprocess.TimeoutExpired as exc:
            raise Stopped(f'{service} restart status lookup timed out.') from exc
        if not active:
            raise Stopped(f'{service} did not become active after restart.')
    for timer in timers:
        command(['systemctl','start',timer], timeout=30,
                label='Starting ' + timer)


def stop_services(services, timers):
    for timer in timers:
        command(['systemctl','stop',timer], timeout=50,
                label='Stopping ' + timer)
    for service in sorted(services,key=lambda value:(1 if value == 'wg-panel.service' else 0,value)):
        command(['systemctl','stop',service],timeout=120,
                label='Stopping ' + service)
        try:
            active = subprocess.run(['systemctl','is-active','--quiet',service],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=10, check=False).returncode == 0
        except subprocess.TimeoutExpired as exc:
            raise Stopped(f'{service} stop status lookup timed out.') from exc
        if active:
            raise Stopped(f'{service} is still active; aborting cutover.')


def _under_root(value, cwd):
    if not value or value.startswith('-'):
        return False
    try:
        path = Path(value)
        if not path.is_absolute():
            path = Path(cwd) / path
        resolved = path.resolve(strict=False)
        return resolved == ROOT.resolve() or ROOT.resolve() in resolved.parents
    except (OSError, ValueError, RuntimeError):
        return False


def _panel_process_label(argv, cwd):


    if not argv:
        return None
    program = Path(argv[0]).name.lower()
    if not (program.startswith('python') or program.startswith('gunicorn') or
            program.startswith('uvicorn')):
        return None
    script_names = {
        'app.py': 'panel application',
        'telegram_bot.py': 'admin Telegram bot',
        'worker.py': 'reseller worker',
        'watchdog.py': 'reseller watchdog',
        'plan_shop.py': 'plan shop worker',
        'reseller_bot.py': 'reseller Telegram bot',
        'bot.py': 'workspace Telegram bot',
    }
    for argument in argv[1:]:
        if argument.endswith('.py') and _under_root(argument, cwd):
            label = script_names.get(Path(argument).name)
            if label:
                return label
    if program.startswith('python') and (
            any(arg == '-m' and argv[index + 1] in ('gunicorn', 'uvicorn')
                for index, arg in enumerate(argv[1:-1], start=1))
            or any(Path(arg).name.startswith(('gunicorn', 'uvicorn')) for arg in argv[1:])):
        if _under_root(cwd, cwd) and any('app:' in arg for arg in argv[1:]):
            return 'panel web server'
    if program.startswith('python'):
        for index, arg in enumerate(argv[1:-1], start=1):
            if arg == '-m' and argv[index + 1].startswith((
                    'reseller_portal.', 'resellers.', 'telegram_bot', 'app')):
                if _under_root(cwd, cwd) or any(_under_root(a, cwd) for a in argv[1:]):
                    return 'WG Panel module'
    if program.startswith(('gunicorn', 'uvicorn')):
        if _under_root(cwd, cwd) and any('app:' in arg or arg == 'app' for arg in argv[1:]):
            return 'panel web server'
    return None


def _systemd_unit_for_pid(pid, proc_root=Path('/proc')):
    try:
        content = (proc_root / str(pid) / 'cgroup').read_text(encoding='utf-8', errors='replace')
    except (OSError, ValueError):
        return None
    for path in content.splitlines():
        for part in reversed(path.split('/')):
            if re.fullmatch(r'[a-zA-Z0-9_.@-]+\.service', part):
                return part
    return None


def _sqlite_file_ids(sqlite_path):
    identities = set()
    for filename in (str(sqlite_path), str(sqlite_path) + '-wal', str(sqlite_path) + '-shm'):
        try:
            stat_result = os.stat(filename)
        except OSError:
            continue
        identities.add((stat_result.st_dev, stat_result.st_ino))
    return identities


def _has_sqlite_handle(pid, identities, proc_root=Path('/proc')):
    fd_dir = proc_root / str(pid) / 'fd'
    try:
        entries = list(fd_dir.iterdir())
    except (OSError, ValueError):
        return False
    for fd in entries:
        try:
            st = fd.stat()
        except (OSError, ValueError):
            continue
        if (st.st_dev, st.st_ino) in identities:
            return True
    return False


def identify_sqlite_users(sqlite_path, *, proc_root=Path('/proc')):


    identities = _sqlite_file_ids(sqlite_path)
    found = {}
    try:
        pids = sorted((int(p.name) for p in proc_root.iterdir() if p.name.isdecimal()))
    except OSError as exc:
        raise Stopped('Cannot inspect /proc processes (' + type(exc).__name__ + ').') from exc
    for pid in pids:
        if pid == os.getpid():
            continue
        proc = proc_root / str(pid)
        try:
            cmdline = (proc / 'cmdline').read_bytes().split(b'\0')
            argv = [entry.decode('utf-8', 'replace') for entry in cmdline if entry]
            cwd = os.readlink(proc / 'cwd')
        except (OSError, ValueError):
            argv = []
            cwd = ''
        role = _panel_process_label(argv, cwd)
        holds_db = _has_sqlite_handle(pid, identities, proc_root)
        if role or holds_db:
            found[pid] = (pid, role or 'SQLite database holder',
                          _systemd_unit_for_pid(pid, proc_root), holds_db)


    if proc_root == Path('/proc') and shutil.which('fuser'):
        try:
            result = subprocess.run(['fuser', str(sqlite_path)], capture_output=True,
                                    text=True, timeout=12, check=False)
        except subprocess.TimeoutExpired as exc:
            raise Stopped('SQLite open-file check (fuser) timed out.') from exc
        for token in result.stdout.split():
            if token.isdecimal():
                pid = int(token)
                if pid != os.getpid() and pid not in found:
                    found[pid] = (pid, 'SQLite database holder', _systemd_unit_for_pid(pid), True)
    return [found[pid] for pid in sorted(found)]


def report_sqlite_users(sqlite_path):
    users = identify_sqlite_users(sqlite_path)
    if not users:
        announce('No remaining WG Panel process or open SQLite database handle detected.')
        return users
    announce(f'Found {len(users)} process(es) to review. These are expected if the panel services are online:')
    for pid, role, unit, holds in users[:20]:
        announce(f'  PID {pid}: {role}; unit={unit or "unmanaged / unknown"}; '
                 f'SQLite handle={"open" if holds else "not currently open"}')
    if len(users) > 20:
        announce(f'  ... and {len(users)-20} more process(es).')
    announce('No process was stopped by this inspection. Do not terminate arbitrary PIDs.')
    return users


def check_existing_processes(sqlite_path, *, grace_seconds=0):


    deadline = time.monotonic() + max(0, grace_seconds)
    waiting_announced = False
    while True:
        users = identify_sqlite_users(sqlite_path)
        if not users:
            announce('All WG Panel processes and SQLite file handles have exited.')
            return
        if time.monotonic() >= deadline:
            report_sqlite_users(sqlite_path)
            units = sorted({unit for _, _, unit, _ in users if unit})
            unit_help = (' Check these systemd units: ' + ', '.join(units) + '.' if units else '')
            raise Stopped('SQLite may still have an active writer after service shutdown.'
                          + unit_help + ' The PIDs are shown above; inspect them before retrying. '
                          'No extra processes were killed automatically.')
        if not waiting_announced:
            announce('Waiting for stopped systemd processes to exit and release SQLite.')
            waiting_announced = True
        time.sleep(min(1.0, max(0, deadline - time.monotonic())))


def safe_error_location(exc):

    try:
        frames = traceback.extract_tb(exc.__traceback__)
        local = [frame for frame in frames if Path(frame.filename).resolve() == Path(__file__).resolve()]
        if local:
            frame = local[-1]
            return f' [wizard:{frame.name}:{frame.lineno}]'
    except Exception:
        pass
    return ''


CODE_EXCLUDES = (
    '.git', '.env', '.env.*', 'venv', '.venv', 'instance', 'backups', 'db',
    'restore_snapshots', 'logs', '__pycache__', '.pytest_cache', '.mypy_cache',
    '*.pyc', '*.db', '*.db-*', '*.sqlite*', '*.log', '*.pem', '*.key', '*.conf',
)
RETIRED_CODE = (
    'tests', 'tests_standalone', 'reseller_portal/tests',
    'reseller_portal/apply_update.py', 'reseller_portal/BASELINE_SHA256.json',
    'reseller_portal/PREVIOUS_SHA256.json', 'README.md', 'README-WG-POSTGRES-HOTFIX.txt',
    'ADMIN_ENDPOINT_PREVIEW_PATCH.txt', 'BACKUP_BOT_PARITY_2026-11-23.md', 'DOCKER.txt',
    'EASY-POSTGRESQL-SETUP.md', 'INSTALL-POSTGRES-MANAGER.txt', 'MIGRATION-TIMEOUT-RECOVERY.md',
    'POSTGRES-RESELLER-PEER-FIX.txt', 'POSTGRESQL-MIGRATION-DIAGNOSTICS-2026-11-23.md',
    'POSTGRESQL-STEP3-HOTFIX.md', 'POSTGRESQL-WRITER-CHECK-HOTFIX.md', 'PUBLIC_ACTIVATION_FIX.md',
    'RESELLER-FIX-NOV2026.md', 'RESELLER-SECURITY.md', 'RESELLER-SETUP.md',
    'RESELLER-TELEGRAM-RUNTIME-LOGS.md', 'RESELLER-VALIDATION.txt',
    'RESELLER_LOGIN_COMMIT_LATENCY_2026-11-24.md', 'RESELLER_PEER_MENU_AND_SQLITE_2026-11-22.md',
    'RESELLER_POSTGRESQL_CONCURRENCY_FIX_2026-11-23.md', 'RESELLER_RECOVERY_ZIP_AND_SQLITE_MIGRATION_2026-11-23.md',
    'RESOURCE-POLICY-UPDATE.md', 'SECURITY-AND-PERFORMANCE.md', 'STEP5-README.txt',
    'TELEGRAM_PEER_AND_APP_LOG_FIX_2026-11-23.md', 'TX_PERFORMANCE_AND_MIGRATION_UPDATE_2026-11-23.md',
)


def sync_release_code(source, destination, *, restore=False, install=False):
    args = ['rsync', '-a', '--checksum', '--include=.env.example', '--include=.env.sample']
    if restore:
        args.append('--delete')
    if install:
        args.extend(['--chown=0:0', '--chmod=go-w'])
    args.extend('--exclude='+name for name in CODE_EXCLUDES)
    args.extend([str(source).rstrip('/')+'/', str(destination).rstrip('/')+'/'])
    original = destination.stat()
    try:
        command(args, timeout=600, label='Restore previous code' if restore else 'Copy release code')
    finally:
        os.chown(destination, original.st_uid, original.st_gid)
        os.chmod(destination, stat.S_IMODE(original.st_mode))


def check_staged_release(source, destination):
    if source == destination or source.is_relative_to(destination) or destination.is_relative_to(source):
        raise Stopped('The extracted release and installed panel must be in separate directories.')
    required = ('app.py', 'config.py', 'migrate.sh', 'requirements.txt', 'requirements-postgres.txt',
                'reseller_portal/models.py', 'scripts/migrate_sqlite_to_postgres.py')
    if not all((source/name).is_file() for name in required):
        raise Stopped('Extract the complete new WG Panel release before using --upgrade.')
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in source.rglob('*')):
        raise Stopped('The extracted release contains links or special files. Use a clean release archive.')
    if not shutil.which('rsync'):
        raise Stopped('The staged upgrade requires rsync. Install it before running migration.')


def prune_retired_code(destination, source):
    for relative in RETIRED_CODE:
        if (source/relative).exists():
            continue
        path = destination/relative
        if not path.parent.resolve().is_relative_to(destination):
            raise Stopped('A retired-code path is outside the installation. Review it manually.')
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            if any(any(fnmatch(part, pattern) for pattern in CODE_EXCLUDES)
                   for entry in path.rglob('*') for part in entry.relative_to(path).parts
                   if part != '__pycache__' and not part.endswith('.pyc')):
                announce('Preserved a retired directory containing protected files: '+relative)
                continue
            shutil.rmtree(path)


def _main(argv=None):
    global ROOT, PYTHON
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,help='Existing installed panel; use only with a separate extracted release')
    parser.add_argument('--check',action='store_true',help='Show detected configuration and active services, without changes')
    parser.add_argument('--yes',action='store_true',help='Skip the one interactive confirmation')
    parser.add_argument('--no-install',action='store_true',help='Do not automatically install PostgreSQL packages')
    parser.add_argument('--startup-handoff', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--writers',action='store_true',help='Read-only process and SQLite handle inventory')
    args = parser.parse_args(argv)
    if not sys.platform.startswith('linux') or not shutil.which('systemctl'):
        print('This wizard supports Ubuntu/Debian systemd deployments only. See POSTGRESQL-MIGRATION.md.',file=sys.stderr)
        return 2
    if args.startup_handoff and (not args.yes or args.project or args.check or args.writers):
        parser.error('Startup handoff requires an unattended in-place migration.')
    staged = args.project is not None
    if staged:
        try:
            destination = args.project.resolve(strict=True)
            check_staged_release(RELEASE_ROOT, destination)
            if not (destination/'app.py').is_file() or not (destination/'venv/bin/python').is_file():
                raise Stopped('The selected installation does not contain app.py and an existing virtual environment.')
            ROOT = destination
            PYTHON = ROOT/'venv/bin/python'
        except (Stopped,OSError) as exc:
            print('Preflight stopped: '+str(exc),file=sys.stderr)
            return 2
    os.chdir(ROOT)
    project_env = ROOT / '.env'
    sqlite_path = ROOT / 'instance' / 'wg_panel.db'
    if project_env.is_symlink():
        print('A required source is a symlink. Use the manual migration guide.',file=sys.stderr)
        return 2
    if not project_env.is_file():
        print('Missing the existing .env. Nothing changed.',file=sys.stderr)
        return 2
    current_url = read_dotenv_key(project_env,'DATABASE_URL') or ''
    if current_url.startswith(('postgresql:','postgresql+','postgres:')):
        announce('Your .env already uses PostgreSQL. Migration is not needed; check the service status instead.')
        return 0
    if sqlite_path.is_symlink() or not sqlite_path.is_file():
        print('Expected a regular instance/wg_panel.db SQLite source. Nothing changed.',file=sys.stderr)
        return 2
    if not matches_expected_sqlite_path(current_url, sqlite_path):
        print('Existing DATABASE_URL points to a different SQLite source. Use the manual migration guide.',file=sys.stderr)
        return 2
    try:
        services,timers = discover_active_units()
        verify_env_files(services, project_env)
    except (Stopped, subprocess.TimeoutExpired, OSError) as exc:
        print('Preflight stopped: ' + str(exc), file=sys.stderr)
        return 2
    announce('Source: instance/wg_panel.db (SQLite). Destination: local PostgreSQL.')
    if staged:
        announce('The complete extracted release will be installed after data import and verification.')
    announce('Running services: ' + (', '.join(services) or '(none detected)'))
    announce('Running timers: ' + (', '.join(timers) or '(none detected)'))
    if args.writers:
        try:
            report_sqlite_users(sqlite_path)
        except Stopped as exc:
            print('Process inspection failed: ' + str(exc), file=sys.stderr)
            return 2
        announce('Read-only process inspection complete. Nothing was changed.')
        return 0
    if args.check:
        announce('Read-only check complete. Nothing was changed.')
        return 0
    if os.geteuid() != 0:
        print('Root privileges required. Run: sudo ./venv/bin/python scripts/easy_postgres_migrate.py',file=sys.stderr)
        return 2
    if staged:
        announce('A private copy of the existing code will be created before installing the new release.')
    if not args.yes:
        print('\nThis will install local PostgreSQL if necessary, briefly stop the panel/bots, '
              'create private backups and import your existing data. It does not touch WireGuard interfaces.\n')
        try:
            if input(migration_prompt()).strip() != 'MIGRATE':
                announce('Cancelled. Nothing changed.')
                return 0
        except (EOFError,KeyboardInterrupt):
            announce('Cancelled. Nothing changed.')
            return 0
    stopped = False
    switched = False
    services_to_stop = list(services)
    timers_to_stop = list(timers)
    services_to_restart = list(services)
    timers_to_restart = list(timers)
    backup_dir = None
    code_backup = None
    code_changed = False
    url = None
    stage = 'Python dependency check'
    try:
        announce('Step 1/8: Checking the Python dependencies.')
        install_driver()
        if staged:
            command([str(PYTHON),'-c','import flask, flask_sqlalchemy, flask_wtf, flask_login, requests, psutil, qrcode, png, cryptography, bcrypt, passlib, pyotp, telegram, gunicorn, flask_limiter'],
                    timeout=45,label='Release dependency preflight')
        stage = 'PostgreSQL installation/startup'
        announce('Step 2/8: Checking and starting local PostgreSQL.')
        postgres_ready(install=not args.no_install)
        stage = 'PostgreSQL role and database setup'
        announce('Step 3/8: Preparing the private PostgreSQL database.')
        url, state = create_or_reuse_database()
        announce('PostgreSQL database and dedicated application account prepared.')
        stage = 'PostgreSQL connection test'

        command([str(PYTHON),'-c','import os; from sqlalchemy import create_engine,text; '
                 'e=create_engine(os.environ["DATABASE_URL"],connect_args={"connect_timeout":5}); '
                 'c=e.connect(); c.execute(text("SELECT 1")); c.close(); e.dispose()'],
                env={**os.environ,'DATABASE_URL':url},timeout=45,
                label='PostgreSQL application connection test')
        stage = 'online SQLite preflight'
        announce('Step 4/8: Checking SQLite schema while panel is still online (read-only).')
        source_auth = ROOT / 'instance' / 'reseller-request-guard.sqlite'
        call_migration(sqlite_path, apply=False, auth_path=source_auth)
        stage = 'checking for additional writers'
        announce('Refreshing service inventory before the maintenance window.')
        known_services, known_timers = discover_managed_units()
        recent_services, recent_timers = discover_active_units()


        services_to_stop = sorted(set(services) | set(known_services) | set(recent_services))
        timers_to_stop = sorted(set(timers) | set(known_timers) | set(recent_timers))
        services_to_restart = sorted(set(services) | set(recent_services))
        timers_to_restart = sorted(set(timers) | set(recent_timers))
        verify_env_files(services_to_stop, project_env)
        current_users = identify_sqlite_users(sqlite_path)


        for _, _, unit, _ in current_users:
            if unit and unit in services_to_stop:
                services_to_restart = sorted(set(services_to_restart) | {unit})
        competing = [entry for entry in current_users
                     if entry[2] not in services_to_stop]
        if competing:
            announce('Additional SQLite users not owned by a detected panel service:')
            for pid, role, unit, holds in competing[:20]:
                announce(f'  PID {pid}: {role}; unit={unit or "unmanaged / unknown"}; '
                         f'SQLite handle={"open" if holds else "not currently open"}')
            raise Stopped('Additional writers must be identified and stopped before a safe cutover. '
                          'Panel services have NOT been stopped. No arbitrary processes were terminated.')
        announce('All detected SQLite users belong to panel services scheduled for shutdown.')
        announce('Services to stop: ' + (', '.join(services_to_stop) or '(none)'))
        stage = 'stopping services and creating backups'
        announce('Step 5/8: Stopping writers and backing up SQLite and settings.')
        stopped = True
        stop_services(services_to_stop, timers_to_stop)
        check_existing_processes(sqlite_path, grace_seconds=15)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(3)
        backup_dir = BACKUP_BASE / stamp
        backup_source(sqlite_path,backup_dir)
        auth = backup_dir / 'reseller-request-guard.sqlite'
        source = backup_dir / 'wg_panel.sqlite'
        digest = source_digest(source)
        auth_digest = source_digest(auth) if auth.is_file() else None
        stage = 'importing data'
        announce('Step 6/8: Rechecking the stopped SQLite backup and importing all supported customer tables.')
        if not state.get('imported'):
            call_migration(source,apply=False,auth_path=auth)
            call_migration(source,apply=True,auth_path=auth)
            state['imported'] = True
            state['source_digest'] = digest
            state['auth_digest'] = auth_digest
            state['backup_path'] = str(backup_dir)
            write_private(STATE_FILE,json.dumps(state))
        elif state.get('source_digest') != digest or state.get('auth_digest') != auth_digest:
            raise Stopped('SQLite data or authentication state changed since an earlier import. Refusing a stale PostgreSQL cutover; review the manual recovery guide.')
        stage = 'verifying PostgreSQL data'
        announce('Step 7/8: Verifying the imported database.')
        verify_target(url)
        if staged:
            stage = 'backing up previous code and installing the extracted release'
            code_backup = backup_dir/'previous-code'
            code_backup.mkdir(mode=0o700)
            sync_release_code(ROOT,code_backup)
            code_changed = True
            sync_release_code(RELEASE_ROOT,ROOT,install=True)
            prune_retired_code(ROOT,RELEASE_ROOT)
            command([str(PYTHON),'-m','py_compile',str(ROOT/'app.py'),str(ROOT/'wg.py'),str(ROOT/'config.py'),str(ROOT/'telegram_bot.py')],
                    timeout=90,label='Validate installed release syntax')
        stage = 'switching settings and restarting services'
        announce('Step 8/8: Switching DATABASE_URL and restarting the previously active services.')
        original_file = backup_dir / 'original.env'
        original_content = original_file.read_text(encoding='utf-8')
        write_private(project_env, environment_update(original_content,url), preserve_access=True)
        switched = True
        state['cutover'] = True
        write_private(STATE_FILE,json.dumps(state))
        if not args.startup_handoff:
            restart_services(services_to_restart, timers_to_restart)
        announce('SUCCESS: PostgreSQL cutover completed. Old SQLite backups are preserved at ' + str(backup_dir))
        announce('Verify a reseller login and test peer creation before allowing heavy traffic.')
        return 0
    except (Exception, KeyboardInterrupt) as exc:

        if isinstance(exc, Stopped):
            reason = str(exc)
        elif isinstance(exc, subprocess.TimeoutExpired):
            reason = 'An external command exceeded its deadline (details were unavailable).'
        else:
            reason = type(exc).__name__ + safe_error_location(exc)
        print('MIGRATION HALTED during ' + stage + ': ' + reason, file=sys.stderr)
        if switched:
            try:
                stop_services(services_to_stop, timers_to_stop)
            except Exception:
                print('CRITICAL: Could not stop every writer. Inspect the service status immediately.',file=sys.stderr)
            print('PostgreSQL remains selected. Do not restart SQLite writers: some services may have already written to PostgreSQL.',file=sys.stderr)
            print('Review service logs, then start the updated panel and previously active bots against PostgreSQL.',file=sys.stderr)
            return 2
        if code_changed and code_backup:
            try:
                sync_release_code(code_backup,ROOT,restore=True)
                announce('Previous code restored. The original SQLite configuration remains selected.')
            except Exception:
                print('CRITICAL: Could not restore the previous code. Services remain stopped. Recover from '+str(code_backup),file=sys.stderr)
                return 2
        if stopped and not args.startup_handoff:
            try:
                restart_services(services_to_restart, timers_to_restart)
                announce('Previously active panel services have been restarted.')
            except Exception:
                print('WARNING: Some services could not restart. Check: systemctl status wg-panel.service',file=sys.stderr)
        print('No SQLite database was deleted. Do not run both database backends as writers.',file=sys.stderr)
        return 2


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if any(arg in arguments for arg in ('--help', '-h', '--check', '--writers')) or os.geteuid() != 0:
        return _main(arguments)
    try:
        fd = os.open('/run/lock/wgpanel-postgresql-migration.lock',
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        print('Cannot open the migration lock. Nothing changed.', file=sys.stderr)
        return 2
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            print('Unsafe migration lock permissions. Nothing changed.', file=sys.stderr)
            return 2
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another migration is running. Nothing changed.', file=sys.stderr)
            return 2
        previous_umask = os.umask(0o077)
        try:
            return _main(arguments)
        finally:
            os.umask(previous_umask)
    finally:
        os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
