from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / 'venv/bin/python'
PANEL = 'wg-panel.service'
BOT = 'wg-panel-bot.service'
WORKERS = {'wg-monitor.service': 'monitor', 'wg-provision.service': 'provision',
           'wg-reseller-worker.service': 'workspace-bots', 'wg-plan-shop.service': 'shop'}
WATCHDOG = 'wg-reseller-watchdog.timer'
WATCHDOG_SERVICE = 'wg-reseller-watchdog.service'
STATE_BASE = Path('/var/lib/wgpanel-startup')
KEY = hashlib.sha256(os.fsencode(ROOT)).hexdigest()[:20]
UNIT = 'wg-maintenance-upgrade-' + KEY + '.service'


def log(message):
    print('[WG Panel startup] ' + message, flush=True)


def command(args, *, timeout=30, check=True):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(Path(args[0]).name + ' failed (exit ' + str(result.returncode) + ')')
    return result


def info(name):
    result = command(['systemctl', 'show', name, '--property=LoadState,ActiveState,UnitFileState,WorkingDirectory,ExecStart,Type,User,EnvironmentFiles,Environment'], check=False)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def state_dir():
    for path in (STATE_BASE, STATE_BASE / KEY):
        path.mkdir(mode=0o700, exist_ok=True)
        st = path.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise RuntimeError('Unsafe startup maintenance state directory.')
    return STATE_BASE / KEY


def read_state():
    path = state_dir() / 'state.json'
    if not path.exists() and not path.is_symlink():
        return {}
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError('Unsafe startup maintenance state file.')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get('phase') not in ('running', 'starting', 'completed', 'failed'):
        raise RuntimeError('Invalid startup maintenance state; manual review required.')
    return data


def write_state(phase, previous=()):
    directory = state_dir()
    fd, name = tempfile.mkstemp(dir=directory, prefix='.state-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'phase': phase, 'previous': sorted(set(previous)), 'at': time.time()}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, directory / 'state.json')
        fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def dotenv_database():
    path = ROOT / '.env'
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('A regular existing .env is required; no configuration was changed.')
    from dotenv import dotenv_values
    value = dotenv_values(path, interpolate=False).get('DATABASE_URL')
    return str(value or '').strip()


def database_kind(value):
    if value.startswith(('postgresql://', 'postgresql+psycopg://', 'postgres://')):
        return 'postgresql'
    if not value or value.startswith('sqlite:///'):
        return 'sqlite'
    return 'unsupported'


def managed_entrypoint():
    if not sys.platform.startswith('linux') or not os.environ.get('INVOCATION_ID') or not shutil.which('systemctl'):
        return False
    try:
        return any('/system.slice/' + PANEL in line and line.rstrip().endswith('/' + PANEL)
                   for line in Path('/proc/self/cgroup').read_text().splitlines())
    except OSError:
        return False


def belongs(unit):
    return unit.get('WorkingDirectory', '').rstrip('/') == str(ROOT) and str(ROOT) + '/' in unit.get('ExecStart', '')


def standard_panel():
    unit = info(PANEL)
    return (unit.get('LoadState') == 'loaded' and belongs(unit)
            and unit.get('Type') == 'simple' and unit.get('User') in ('', 'root', '0')
            and str(ROOT / 'app.py') in unit.get('ExecStart', '')
            and str(ROOT / '.env') in unit.get('EnvironmentFiles', '')
            and not re.search(r'(?:^|\s)"?DATABASE_URL=', unit.get('Environment', '')))


def worker_plan():
    missing = False
    for name, role in WORKERS.items():
        unit = info(name)
        if unit.get('LoadState') == 'not-found':
            missing = True
            continue
        if unit.get('LoadState') != 'loaded' or not belongs(unit):
            raise RuntimeError('Custom or masked worker requires manual review: ' + name)
        args = unit.get('ExecStart', '')
        if re.search(r'--role\s+' + re.escape(role) + r'(?:\s|;|$)', args):
            continue
        if name == 'wg-reseller-worker.service' and ('reseller_portal.worker' in args or 'reseller_portal/worker.py' in args) and (not re.search(r'--role\s+', args) or re.search(r'--role\s+combined(?:\s|;|$)', args)):
            missing = True
            continue
        raise RuntimeError('Unrecognized worker configuration: ' + name)
    return missing


def postgres_maintenance_required(state):
    return state.get('phase') in ('running', 'starting') or worker_plan()


def verify_unit_database(name, migration):
    unit = info(name)
    if unit.get('LoadState') != 'loaded':
        return
    if not belongs(unit):
        raise RuntimeError('Service belongs to another installation: ' + name)
    if re.search(r'(?:^|\s)"?DATABASE_URL=', unit.get('Environment', '')):
        raise RuntimeError('Database override in systemd unit requires manual review: ' + name)
    files = [Path(value) for value in re.findall(r'(/[^\s()]+)', unit.get('EnvironmentFiles', ''))]
    if ROOT / '.env' not in files:
        raise RuntimeError('Service does not load the existing panel .env: ' + name)
    for path in files:
        if path.resolve() != (ROOT / '.env').resolve() and migration.read_dotenv_key(path, 'DATABASE_URL') is not None:
            raise RuntimeError('Additional database environment file requires manual review: ' + name)


def manual_migration_running():
    try:
        fd = os.open('/run/lock/wgpanel-postgresql-migration.lock', os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True
    finally:
        os.close(fd)


def active_maintenance():
    return info(UNIT).get('ActiveState') in ('active', 'activating', 'reloading')


def schedule():
    if not shutil.which('systemd-run'):
        raise RuntimeError('systemd-run is unavailable; use the documented manual migration.')
    command(['systemd-run', '--unit=' + UNIT, '--collect', '--no-block',
             '--property=Type=exec', '--property=TimeoutStopSec=120',
             '--property=WorkingDirectory=' + str(ROOT), str(PYTHON), '-u',
             str(Path(__file__).resolve()), '--run'], timeout=30)
    log('Independent maintenance requested. Follow: journalctl -u ' + UNIT + ' -f')


def manual_help():
    log('Automatic maintenance stopped safely. Review journalctl -u ' + UNIT + ' --no-pager. '
        'After resolving the cause, run sudo venv/bin/python scripts/startup_upgrade.py --retry from the panel directory. '
        'Do not delete SQLite or replace encryption keys.')


def stop_legacy_entry():
    manual_help()
    command(['systemctl', 'stop', '--no-block', PANEL], check=False)
    raise SystemExit(78)


def startup_gate():
    if os.environ.get('WG_AUTO_UPGRADE') == '0' or os.environ.get('WG_ALLOW_SQLITE_LEGACY') == '1' or not managed_entrypoint():
        return
    effective = os.environ.get('DATABASE_URL', '').strip()
    kind = database_kind(effective)
    if os.geteuid() != 0:
        if kind == 'sqlite':
            log('Legacy SQLite detected. Automatic migration requires the standard root systemd installation.')
        return
    try:
        configured = dotenv_database()
        kind = database_kind(configured)
        if effective and effective != configured:
            raise RuntimeError('Service DATABASE_URL differs from .env; manual review required.')
        if kind == 'unsupported':
            return
        if not standard_panel():
            if kind == 'sqlite':
                raise RuntimeError('Nonstandard systemd configuration; use the manual migration guide.')
            return
        state = read_state()
        running = active_maintenance()
        if kind == 'postgresql':
            if running:
                return
            if state.get('phase') == 'failed':
                manual_help()
                return
            from scripts.deployment import lock_active
            if lock_active(ROOT):
                return
            if not postgres_maintenance_required(state):
                return
            schedule()
            return
        if state.get('phase') in ('running', 'starting', 'failed', 'completed') and not running:
            stop_legacy_entry()
        if not running:
            schedule()
        while True:
            time.sleep(2)
            if not active_maintenance():
                stop_legacy_entry()
    except Exception as exc:
        log('Startup preflight stopped: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
        if kind == 'sqlite':
            stop_legacy_entry()


def run_child(args, timeout):
    result = subprocess.run(args, cwd=ROOT, timeout=timeout, check=False,
                            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'})
    if result.returncode:
        raise RuntimeError(Path(args[2]).name + ' failed (exit ' + str(result.returncode) + ')')


def health_probe(deployment):
    from dotenv import dotenv_values
    env = dotenv_values(ROOT / '.env', interpolate=False)
    key = str(env.get('API_KEY') or '').strip()
    if not key:
        raise RuntimeError('Existing API_KEY is required for authenticated startup verification.')
    if str(env.get('FLASK_SECRET_KEY') or '').strip() in ('', 'change-me', 'CHANGE_ME'):
        raise RuntimeError('Existing private Flask secret is required; configure it without replacing valid keys.')
    try:
        if len(base64.urlsafe_b64decode(str(env.get('FERNET_KEY') or ''))) != 32:
            raise ValueError
    except (ValueError, TypeError):
        raise RuntimeError('Existing valid Fernet encryption key is required; do not generate a replacement for encrypted data.') from None
    if env.get('WG_DEPLOY_HEALTH_URL'):
        config = deployment.readiness_config(ROOT, 'panel')
        return lambda: deployment.readiness_ok(config)

    def read_settings(name):
        path = ROOT / 'instance' / name
        if not path.exists():
            return {}
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise RuntimeError('Invalid panel runtime settings.')
        return value

    settings = read_settings('panel_settings.json')
    runtime = read_settings('runtime.json')
    cert = Path(str(settings.get('tls_cert_path') or ''))
    private = Path(str(settings.get('tls_key_path') or ''))
    tls = bool(settings.get('tls_enabled') and cert.is_file() and private.is_file())
    if env.get('BIND'):
        bind = env['BIND']
    elif tls:
        bind = str(env.get('BIND_HOST') or '0.0.0.0') + ':' + str(settings.get('https_port') or 443)
    else:
        bind = runtime.get('bind') or str(env.get('BIND_HOST') or '0.0.0.0') + ':' + str(runtime.get('port') or settings.get('http_port') or 8000)
    parsed = urlsplit('http://' + str(bind))
    host = parsed.hostname
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1' if host == '0.0.0.0' else '::1'
    if host == 'localhost':
        host = '127.0.0.1'
    try:
        if not ipaddress.ip_address(host or '').is_loopback:
            raise ValueError
    except ValueError:
        raise RuntimeError('Set WG_DEPLOY_HEALTH_URL for a non-loopback bind before automatic maintenance.') from None
    if not parsed.port or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise RuntimeError('Invalid panel bind for startup verification.')
    headers = {'Authorization': 'Bearer ' + key}
    trusted = [h.strip() for h in str(env.get('WG_TRUSTED_HOSTS') or '').split(',') if h.strip()]
    if trusted:
        domain = str(settings.get('domain') or '').strip()
        if domain and any(domain == h or (h.startswith('.') and (domain == h[1:] or domain.endswith(h))) for h in trusted):
            headers['Host'] = domain
        elif host not in trusted and 'localhost' not in trusted:
            raise RuntimeError('Set WG_DEPLOY_HEALTH_URL for the configured trusted hosts.')
        elif 'localhost' in trusted and host not in trusted:
            headers['Host'] = 'localhost'
    fingerprint = None
    if tls:
        match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', cert.read_text(), re.S)
        if not match:
            raise RuntimeError('Panel TLS certificate cannot be read for local verification.')
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(match.group())).digest()

    def probe():
        conn = None
        try:
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, parsed.port, timeout=5, context=context)
                conn.connect()
                if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).digest() != fingerprint:
                    return False
            else:
                conn = http.client.HTTPConnection(host, parsed.port, timeout=5)
            conn.request('GET', '/api/healthz', headers=headers)
            response = conn.getresponse()
            return response.status == 200 and json.loads(response.read(4096)).get('ok') is True
        except (OSError, ValueError, AttributeError, http.client.HTTPException):
            return False
        finally:
            if conn is not None:
                conn.close()

    return probe


def maintenance():
    from scripts import deployment as d
    from scripts import easy_postgres_migrate as m
    if os.geteuid() != 0 or not standard_panel():
        raise RuntimeError('Automatic maintenance requires the standard root panel unit.')
    previous = set(read_state().get('previous', []))
    allowed = {PANEL, BOT, WATCHDOG, WATCHDOG_SERVICE, *WORKERS}
    deadline = time.monotonic() + 90
    while d.lock_active(ROOT) or manual_migration_running():
        if time.monotonic() >= deadline:
            raise RuntimeError('Existing update or migration did not finish; retry maintenance after it exits.')
        time.sleep(1)
    services, timers = m.discover_active_units()
    known_services, known_timers = m.discover_managed_units()
    if (set(known_services + known_timers + services + timers) | previous) - allowed:
        raise RuntimeError('Additional managed panel units detected; use coordinated manual maintenance.')
    for name in set(known_services + services) | {PANEL, BOT, *WORKERS}:
        verify_unit_database(name, m)
    m.verify_env_files(sorted(set(known_services + services)), ROOT / '.env')
    previous.update(services + timers)
    previous.add(PANEL)
    with d.deployment_lock(ROOT):
        current_state = read_state()
        if (database_kind(dotenv_database()) == 'postgresql'
                and current_state.get('phase') != 'failed'
                and not postgres_maintenance_required(current_state)):
            log('PostgreSQL and separated worker definitions already configured; skipping maintenance.')
            return
        write_state('running', previous)
        try:
            worker_plan()
            probe = health_probe(d)
            kind = database_kind(dotenv_database())
            if kind == 'sqlite':
                old_state = json.loads(m.STATE_FILE.read_text()) if m.STATE_FILE.exists() else {}
                if old_state.get('cutover'):
                    raise RuntimeError('A previous PostgreSQL cutover is recorded but SQLite is selected. Manual review required.')
                log('Legacy SQLite detected; starting the existing backup and PostgreSQL migration wizard.')
                run_child([str(PYTHON), '-u', str(ROOT / 'scripts/easy_postgres_migrate.py'), '--yes', '--startup-handoff'], 7200)
                if database_kind(dotenv_database()) != 'postgresql':
                    raise RuntimeError('Migration did not select PostgreSQL.')
            elif kind != 'postgresql':
                raise RuntimeError('Unsupported database configuration.')
            log('Preparing the four independent background service definitions.')
            if WATCHDOG in previous:
                command(['systemctl', 'stop', WATCHDOG], timeout=60)
            run_child([str(PYTHON), '-u', str(ROOT / 'reseller_portal/install_worker.py'), '--install', '--prepare-only', '--python', str(PYTHON)], 600)
            write_state('starting', previous)
            d.start_services(ROOT, [PANEL], wait=120)
            deadline = time.monotonic() + 120
            while not probe():
                if time.monotonic() >= deadline:
                    raise RuntimeError('Authenticated web readiness was not verified; workers were not started.')
                time.sleep(1)
            restart = list(WORKERS)
            if BOT in previous:
                restart.append(BOT)
            d.start_services(ROOT, restart, wait=150)
            if WATCHDOG in previous:
                command(['systemctl', 'start', WATCHDOG], timeout=30)
            write_state('completed', previous)
            log('Startup maintenance completed. PostgreSQL and the separated services are selected.')
        except BaseException:
            write_state('failed', previous)
            raise


def main():
    parser = argparse.ArgumentParser(description='WG Panel startup upgrade and recovery')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true', help=argparse.SUPPRESS)
    group.add_argument('--retry', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root privileges required.')
    try:
        if args.retry:
            if not standard_panel() or active_maintenance():
                raise RuntimeError('Maintenance already active or nonstandard panel unit.')
            schedule()
            return 0
        maintenance()
        return 0
    except Exception as exc:
        log('Maintenance halted: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
        try:
            state = read_state()
            write_state('failed', state.get('previous', []))
        except Exception:
            pass
        manual_help()
        return 2


if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
