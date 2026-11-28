#!/usr/bin/env python3
"""WG Panel PostgreSQL manager for Ubuntu/Debian native systemd installations.

Uses only the Python standard library. Never writes database credentials itself;
the existing conservative migration wizard performs the data cutover.
"""
from __future__ import annotations

import argparse
from collections import deque
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import textwrap
import time
from datetime import datetime, timezone
from typing import Optional

ROOT = Path(__file__).resolve().parent
WIZARD = ROOT / 'scripts' / 'easy_postgres_migrate.py'
VENV_PYTHON = ROOT / 'venv' / 'bin' / 'python'
LOG_PATH = Path('/var/log/wgpanel-postgres-manager.log')
CHECK_INTERVAL = 2
COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR')


def style(text: str, code: str) -> str:
    return f'\033[{code}m{text}\033[0m' if COLOR else text


def say(kind: str, message: str) -> None:
    key = {'OK': '1;32', 'ERROR': '1;31', 'WARN': '1;33',
           'RUN': '1;35', 'INFO': '36'}.get(kind, '0')
    tag = {'OK': '✓', 'ERROR': '×', 'WARN': '!', 'RUN': '[RUN]',
           'INFO': '•'}.get(kind, kind)
    print(f'  {style(tag, key)}  {message}', flush=True)


def state_color(text: str, good: bool) -> str:
    return style(text, '1;32' if good else '1;31')


def external_line(text: str) -> str:
    if 'MIGRATION HALTED' in text or 'failed (exit' in text:
        return style(text, '1;31')
    if 'MIGRATION_DIAGNOSTIC' in text or 'Diagnostic —' in text:
        return style(text, '1;33')
    if 'SUCCESS:' in text or 'completed successfully.' in text or 'Preflight passed' in text:
        return style(text, '1;32')
    m = re.search(r'\bStep ([1-8])/8:', text)
    if m:
        current = int(m.group(1))
        progress = '[' + style('#' * current, '1;35') + style('-' * (8 - current), '2') + ']'
        return style(text, '1;36') + '  ' + progress
    return text


def line(text=''):
    print(text, flush=True)


def private_log(message: str) -> None:

    if os.geteuid() != 0:
        return
    try:
        fd = os.open(str(LOG_PATH), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as handle:
                handle.write(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ ') + message + '\n')
        except Exception:
            raise
    except OSError:
        pass


def scrub(text: str) -> str:

    text = re.sub(r'(?i)postgres(?:ql)?(?:\+psycopg)?://[^\s\]\["\']+', '[PostgreSQL URL hidden]', text)
    text = re.sub(r'(?i)\b(password|passwd|token|secret|API_KEY|FERNET_KEY)\s*[=:]\s*[^\s,;]+', r'\1=[hidden]', text)
    return text.rstrip('\r\n')[:1200]


def run_short(args: list[str], *, timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, errors='replace', timeout=timeout, check=False)
        return p.returncode, (p.stdout or '').strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124 if isinstance(exc, subprocess.TimeoutExpired) else 127, type(exc).__name__


def _reader(process: subprocess.Popen, sink: queue.Queue):
    try:
        assert process.stdout is not None
        for part in process.stdout:
            sink.put(part)
    finally:
        sink.put(None)


def run_live(args: list[str], *, title: str, timeout: int, env: Optional[dict] = None,
             show_output: bool = True) -> bool:

    say('RUN', title)
    private_log('START ' + title)
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, text=True, encoding='utf-8',
                             errors='replace', bufsize=1, start_new_session=True, env=env)
    except OSError as exc:
        say('ERROR', f'{title}: failed to launch ({type(exc).__name__}: {scrub(str(exc))})')
        return False
    output = queue.Queue()
    worker = threading.Thread(target=_reader, args=(p, output), daemon=True)
    worker.start()
    started = time.monotonic()
    last_notice = started
    recent = deque(maxlen=12)
    finished_reader = False
    interrupted = False
    timed_out = False
    try:
        while not finished_reader or p.poll() is None:
            try:
                msg = output.get(timeout=CHECK_INTERVAL)
            except queue.Empty:
                msg = ...
            if msg is None:
                finished_reader = True
            elif msg is not ...:
                safe = scrub(msg)
                if safe:
                    recent.append(safe)
                    private_log(safe)
                    if show_output:
                        print('  ' + external_line(safe), flush=True)
            now = time.monotonic()
            if timeout and now - started > timeout:
                timed_out = True
                say('ERROR', f'{title}: deadline exceeded after {timeout}s.')
                break
            if now - last_notice >= 15 and p.poll() is None:
                say('INFO', f'{title}: still running ({int(now - started)}s elapsed)')
                last_notice = now
    except KeyboardInterrupt:
        interrupted = True
        say('WARN', 'Interrupted: cancelling the operation safely.')
    finally:
        if timed_out or interrupted:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:

            timed_out = True
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        if p.stdout is not None:
            p.stdout.close()
    if interrupted or timed_out or p.returncode:
        code = 'timeout/interrupted' if timed_out or interrupted else f'exit {p.returncode}'
        say('ERROR', f'{title} failed ({code}).')
        private_log(f'FAILED {title}: {code}')
        if recent and not show_output:
            say('INFO', 'Recent diagnostic output:')
            for text in list(recent)[-8:]:
                print('  ' + external_line(text), flush=True)
        say('INFO', f'Log: {LOG_PATH}')
        return False
    say('OK', title + ' complete.')
    private_log('DONE ' + title)
    return True


def require_root() -> bool:
    if os.geteuid() == 0:
        return True
    say('ERROR', 'Run this action as root: sudo python3 wg-postgres.py')
    return False


def backend():
    file = ROOT / '.env'
    try:
        text = file.read_text(encoding='utf-8')
    except OSError:
        return 'Not configured (.env missing)'
    for entry in reversed(text.splitlines()):
        m = re.match(r'^\s*(?:export\s+)?DATABASE_URL\s*=\s*(.+?)\s*$', entry)
        if m:
            value = m.group(1).strip().strip("'\"")
            if value.startswith(('postgresql:', 'postgresql+', 'postgres:')):
                return 'PostgreSQL'
            if value.startswith('sqlite:'):
                return 'SQLite'
            return 'Unknown database type'
    return 'Not configured (DATABASE_URL missing)'


def installed() -> bool:
    return shutil.which('psql') is not None and shutil.which('pg_lsclusters') is not None


def ready_local() -> bool:
    if not shutil.which('pg_isready'):
        return False
    code, _ = run_short(['pg_isready', '-h', '127.0.0.1', '-p', '5432'], timeout=5)
    return code == 0


def status():
    ui_header('Database diagnostics', 'PostgreSQL readiness and WG Panel services')
    b = backend()
    available = installed()
    code, state = run_short(['systemctl', 'is-active', 'postgresql'], timeout=8) if shutil.which('systemctl') else (127, 'unavailable')
    listening = ready_local()
    info = [
        'Application  ' + ui_color(b, _UI_GREEN if b == 'PostgreSQL' else _UI_YELLOW if b == 'SQLite' else _UI_RED, True),
        'Server tools ' + ui_color('Installed' if available else 'Missing', _UI_GREEN if available else _UI_RED),
        'Service      ' + ui_color(state or 'Unknown', _UI_GREEN if state == 'active' else _UI_YELLOW),
        'TCP access   ' + ui_color('ONLINE' if listening else 'OFFLINE', _UI_GREEN if listening else _UI_RED, True),
    ]
    line(ui_box('Database', info))
    if shutil.which('pg_lsclusters'):
        rc, clusters = run_short(['pg_lsclusters'], timeout=8)
        if rc == 0:
            line('\n' + ui_box('PostgreSQL clusters', [scrub(value) for value in clusters.splitlines()]))
        else:
            say('WARN', 'Cannot list PostgreSQL clusters: ' + scrub(clusters))
    services = []
    for name in ('wg-panel.service', 'wg-panel-bot.service', 'wg-reseller-worker.service', 'wg-plan-shop.service', 'wg-provision.service', 'wg-monitor.service'):
        rc, value = run_short(['systemctl', 'is-active', name], timeout=5)
        services.append(name + '  ' + ui_color(value or 'unknown', _UI_GREEN if value == 'active' else _UI_RED))
    line('\n' + ui_box('WG Panel services', services))
    return True


def check_platform():
    if not sys.platform.startswith('linux') or not shutil.which('apt-get'):
        say('ERROR', 'Automatic installation supports Debian/Ubuntu with apt only.')
        return False
    if not shutil.which('systemctl') or not Path('/run/systemd/system').is_dir():
        say('ERROR', 'systemd is not running. Use Docker or the manual database guide.')
        return False
    return True


def start_database():
    if ready_local():
        say('OK', 'PostgreSQL already accepts connections on 127.0.0.1:5432.')
        return True
    if not run_live(['systemctl', 'start', '--no-block', 'postgresql'], title='Request PostgreSQL startup', timeout=30):
        return False
    if shutil.which('pg_lsclusters') and shutil.which('pg_ctlcluster'):
        rc, records = run_short(['pg_lsclusters', '-h'], timeout=10)
        if rc == 0:
            for entry in records.splitlines():
                columns = entry.split()
                if len(columns) >= 4 and columns[2] == '5432' and columns[3] == 'down':
                    if not run_live(['pg_ctlcluster', columns[0], columns[1], 'start'],
                                    title=f'Start PostgreSQL cluster {columns[0]}/{columns[1]}', timeout=90):
                        return False
    started = time.monotonic()
    attempts = 0
    while time.monotonic() - started < 90:
        if ready_local():
            say('OK', 'PostgreSQL is ready on port 5432.')
            return True
        attempts += 1
        if attempts % 3 == 0:
            say('INFO', f'Waiting for PostgreSQL startup ({int(time.monotonic() - started)}s elapsed)')
        time.sleep(3)
    say('ERROR', 'PostgreSQL never became ready on 127.0.0.1:5432.')
    suggest_logs()
    return False


def install():
    if not require_root() or not check_platform():
        return False
    if not installed():
        env = dict(os.environ)
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        env['APT_LISTCHANGES_FRONTEND'] = 'none'
        say('INFO', 'This installs PostgreSQL from your OS repositories; it does not modify WG Panel data.')
        if not run_live(['apt-get', 'update'], title='Refresh APT package metadata', timeout=900, env=env):
            return False
        if not run_live(['apt-get', 'install', '-y', 'postgresql', 'postgresql-client'],
                        title='Install PostgreSQL server and client', timeout=1200, env=env):
            return False
    else:
        say('OK', 'PostgreSQL packages are already available; skipping APT installation.')
    if not installed():
        say('ERROR', 'PostgreSQL was installed, but pg_lsclusters or psql is still unavailable.')
        return False
    if not start_database():
        return False
    if not run_live(['systemctl', 'enable', 'postgresql'],
                    title='Enable PostgreSQL at boot', timeout=35):
        say('WARN', 'Database is running, but enable-on-boot could not be verified.')
    return True


def suggest_logs():
    say('INFO', 'Use menu option 5 to inspect PostgreSQL logs, or:')
    line('  sudo journalctl -u postgresql --no-pager -n 80')
    line('  sudo pg_lsclusters')


def check_database_login():
    if not ready_local():
        say('ERROR', 'PostgreSQL is not reachable on 127.0.0.1:5432.')
        return False
    if not shutil.which('runuser'):
        say('ERROR', 'runuser is unavailable.')
        return False
    rc, result = run_short(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-A', '-t', '-d', 'postgres', '-c', 'SELECT 1;'], timeout=12)
    if rc == 0 and result.strip() == '1':
        say('OK', 'Local PostgreSQL administrator query succeeded.')
        return True
    say('WARN', 'PostgreSQL is listening, but the postgres OS user could not execute a local query.')
    say('INFO', 'Error type/details: ' + scrub(result)[:250])
    return False


def inspect_sqlite_source() -> bool:

    sqlite_path = ROOT / 'instance' / 'wg_panel.db'
    migrator = ROOT / 'scripts' / 'migrate_sqlite_to_postgres.py'
    if not migrator.is_file() or not sqlite_path.is_file():
        say('ERROR', 'SQLite source database or migration script is missing.')
        return False
    return run_live([str(VENV_PYTHON), '-u', str(migrator),
                     '--sqlite', str(sqlite_path), '--inspect-source-only'],
                    title='Inspect SQLite schema and migration readiness (read-only)', timeout=180)


def inspect_sqlite_writers() -> bool:

    source = ROOT / 'instance' / 'wg_panel.db'
    if not WIZARD.is_file() or not source.is_file() or not VENV_PYTHON.is_file():
        say('ERROR', 'Migration wizard, virtualenv, or SQLite source is missing.')
        return False
    say('INFO', 'Running services are expected to appear. Check any unmanaged/unknown entries.')
    return run_live([str(VENV_PYTHON), '-u', str(WIZARD), '--writers'],
                    title='Inspect panel processes and SQLite holders (read-only)', timeout=90)


def inspect_resources() -> bool:
    script = ROOT / 'scripts' / 'diagnose_resource_pressure.py'
    if not script.is_file():
        say('ERROR', 'Resource diagnostics script is missing.')
        return False
    return run_live([sys.executable, '-u', str(script), '--seconds', '30'],
                    title='Inspect host and service resource pressure (read-only)', timeout=150)


def migrate(*, yes=False):
    if not require_root():
        return False
    if backend() == 'PostgreSQL':
        say('OK', 'WG Panel .env already selects PostgreSQL; migration is not needed. Use --status to verify connectivity.')
        return True
    if not WIZARD.is_file() or not VENV_PYTHON.is_file():
        say('ERROR', 'Migration wizard or virtual environment is missing. Install the latest PostgreSQL WG Panel patch first.')
        return False
    say('INFO', 'Checking migration input and active services (read-only).')
    if not run_live([str(VENV_PYTHON), str(WIZARD), '--check'],
                    title='WG Panel migration preflight', timeout=90):
        return False
    say('INFO', 'Checking the source schema before any service interruption.')
    if not inspect_sqlite_source():
        say('ERROR', 'Source inspection failed. No services were stopped and migration has not begun.')
        return False
    if not yes:
        line('\nMigration will briefly stop WG Panel and its bots, back up SQLite, import')
        line('customers and settings, and then restart previously active services.')
        line('SQLite files and the encryption key are not deleted.')
        try:
            if input('Type ' + style('MIGRATE', '1;32') + ' to continue: ').strip() != 'MIGRATE':
                say('INFO', 'Cancelled. Nothing was migrated.')
                return False
        except (KeyboardInterrupt, EOFError):
            say('INFO', 'Cancelled.')
            return False
    say('INFO', 'Preparing PostgreSQL first, while panel services remain running.')
    if not install() or not check_database_login():
        return False
    env = dict(os.environ)
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'

    ok = run_live([str(VENV_PYTHON), '-u', str(WIZARD), '--no-install', '--yes'],
                  title='WG Panel PostgreSQL data migration & service cutover',
                  timeout=5400, env=env)
    if not ok:
        say('ERROR', 'Migration did not complete successfully. The source SQLite data was not deleted by the wizard.')
        say('INFO', 'Check the detailed stage error above before considering a retry.')
        return False
    say('INFO', f'WG Panel now reports backend: {backend()}')
    if backend() != 'PostgreSQL':
        say('ERROR', 'Migration finished, but .env does not select PostgreSQL. Inspect service status before proceeding.')
        return False
    say('OK', 'WG Panel is configured to use PostgreSQL. Verify a reseller login and peer creation.')
    return True


def logs():
    if not shutil.which('journalctl'):
        say('ERROR', 'journalctl is unavailable.')
        return False
    say('INFO', 'PostgreSQL service logs (last 60 lines)')
    run_live(['journalctl', '-u', 'postgresql', '-n', '60', '--no-pager', '-o', 'short-iso'],
             title='Read PostgreSQL service logs', timeout=25)
    if shutil.which('pg_lsclusters'):
        _, result = run_short(['pg_lsclusters', '-h'], timeout=8)
        for entry in result.splitlines():
            p = entry.split()
            if len(p) >= 2 and p[0].isdigit():
                run_live(['journalctl', '-u', f'postgresql@{p[0]}-{p[1]}.service',
                          '-n', '40', '--no-pager', '-o', 'short-iso'],
                         title=f'Cluster {p[0]}/{p[1]} logs', timeout=20)
    return True


_UI_RESET = '\033[0m' if COLOR else ''
_UI_ANSI = re.compile(r'\x1b\[[0-9;]*m')


def ui_tone(rgb: str, index: int, basic: str = '37', *, bg=False) -> str:
    if not COLOR:
        return ''
    channel = 48 if bg else 38
    mode = os.environ.get('COLORTERM', '').lower()
    term = os.environ.get('TERM', '').lower()
    if mode in ('truecolor', '24bit'):
        return f'\033[{channel};2;{rgb}m'
    if any(name in term for name in ('256', 'xterm', 'screen', 'tmux')):
        return f'\033[{channel};5;{index}m'
    return f'\033[{"40" if bg else basic}m'


_UI_CYAN = ui_tone('183;168;239', 147, '36')
_UI_WHITE = ui_tone('226;231;240', 255, '37')
_UI_MUTED = ui_tone('139;151;172', 246, '37')
_UI_GREEN = ui_tone('126;199;173', 115, '32')
_UI_YELLOW = ui_tone('223;190;132', 180, '33')
_UI_RED = ui_tone('239;146;154', 210, '31')
_UI_LINE = ui_tone('57;67;86', 238, '37')
_UI_BG = ui_tone('24;29;40', 235, '40', bg=True)
_UI_KEY_BG = ui_tone('53;45;77', 237, '40', bg=True)


def ui_color(message: str, color: str, bold=False) -> str:
    return (('\033[1m' if bold else '') + color + message + _UI_RESET) if COLOR else message


def ui_visible(message: str) -> str:
    return _UI_ANSI.sub('', message)


def ui_width() -> int:
    return max(34, min(78, shutil.get_terminal_size((96, 24)).columns - 1))


def ui_wrap(message: str, width: int) -> list[str]:
    return textwrap.wrap(ui_visible(message), width=max(1, width),
                         break_long_words=True, break_on_hyphens=False) or ['']


def ui_clear() -> None:
    if COLOR and os.environ.get('TERM') != 'dumb':
        print('\033[2J\033[H', end='', flush=True)
    else:
        print()


def ui_header(head: str, subtitle: str) -> None:
    line()
    line('  ' + ui_color('▍ ', _UI_CYAN) + ui_color(head, _UI_WHITE, True))
    line('    ' + ui_color(subtitle, _UI_MUTED))
    line()


def ui_box(title: str, content: list[str]) -> str:
    width = ui_width()
    inner = width - 6
    output = [ui_color('╭' + '─' * (width - 2) + '╮', _UI_LINE)]

    def row(value=''):
        shown = ui_visible(value)
        if len(shown) > inner:
            return [row(ui_color(v, _UI_WHITE)) for v in ui_wrap(shown, inner)]
        pad = ' ' * (inner - len(shown))

        painted = value.replace(_UI_RESET, _UI_RESET + _UI_BG) if COLOR else value
        return (ui_color('│', _UI_LINE) + _UI_BG + '  ' + painted + pad +
                '  ' + _UI_RESET + ui_color('│', _UI_LINE))

    output.append(row(ui_color(title, _UI_WHITE, True)))
    output.append(row())
    for text in content:
        for part in text.splitlines() or ['']:
            item = row(part)
            if isinstance(item, list):

                output.extend(item)
            else:
                output.append(item)
    output.append(row())
    output.append(ui_color('╰' + '─' * (width - 2) + '╯', _UI_LINE))
    return '\n'.join(output)


def ui_actions(items: list[tuple[str, str, str]]) -> str:
    width = ui_width()
    columns = 2 if width >= 70 else 1
    gap = 2
    cell = (width - gap) // 2 if columns == 2 else width
    inner = cell - 4

    def tile(item):
        key, title, description = item
        rows = [ui_color('╭' + '─' * (cell - 2) + '╮', _UI_LINE)]

        def row(value):
            pad = ' ' * max(0, inner - len(ui_visible(value)))
            value = value.replace(_UI_RESET, _UI_RESET + _UI_BG) if COLOR else value
            return (ui_color('│', _UI_LINE) + _UI_BG + ' ' + value + pad +
                    ' ' + _UI_RESET + ui_color('│', _UI_LINE))

        headings = ui_wrap(title, inner - 6)
        rows.append(row(ui_color(f' {key} ', _UI_KEY_BG + _UI_CYAN, True)
                        + '  ' + ui_color(headings[0], _UI_WHITE, True)))
        for continuation in headings[1:]:
            rows.append(row('     ' + ui_color(continuation, _UI_WHITE)))
        for description_line in ui_wrap(description, inner):
            rows.append(row(ui_color(description_line, _UI_MUTED)))
        rows.append(ui_color('╰' + '─' * (cell - 2) + '╯', _UI_LINE))
        return rows

    result = []
    for index in range(0, len(items), columns):
        group = [tile(item) for item in items[index:index + columns]]
        height = max(map(len, group))
        for at in range(height):
            result.append((' ' * gap).join(lines[at] if at < len(lines) else ' ' * cell for lines in group))
    result.append('  ' + ui_color(' 0 ', _UI_KEY_BG + _UI_CYAN, True) +
                  ui_color('  Exit', _UI_MUTED))
    return '\n'.join(result)


def title():
    ui_header('WG Panel', 'PostgreSQL Manager  /  Database administration')


def render_menu() -> str:
    active_backend = backend()
    is_postgres = active_backend == 'PostgreSQL'
    is_sqlite = active_backend == 'SQLite'
    pg_ready = ready_local()
    backend_tone = _UI_GREEN if is_postgres else _UI_YELLOW if is_sqlite else _UI_RED
    backend_label = active_backend + (' (current source)' if is_sqlite else ' (active)' if is_postgres else '')
    status_rows = [
        'Database engine   ' + ui_color(backend_label, backend_tone, True),
        'PostgreSQL local  ' + ui_color('ONLINE  ●' if pg_ready else 'OFFLINE  ○',
                                       _UI_GREEN if pg_ready else _UI_RED, True),
        ui_color('Your current customer database remains unchanged until migration succeeds.', _UI_MUTED),
    ]
    actions = [
        ('1', 'Status & diagnostics', 'Database, service states and server checks'),
        ('2', 'Install / repair', 'Install and start local PostgreSQL'),
        ('3', 'Migrate SQLite', 'Back up, import and safely switch services'),
        ('4', 'Check database access', 'Test the local PostgreSQL login'),
        ('5', 'PostgreSQL logs', 'Inspect service and cluster errors'),
        ('6', 'Check migration readiness', 'Read-only SQLite compatibility check'),
        ('7', 'Inspect SQLite writers', 'Show process IDs and service owners; read-only'),
        ('8', 'Resource pressure', 'Sample CPU, memory, I/O and task limits'),
    ]
    return ui_box('Database', status_rows) + '\n\n' + ui_actions(actions)


def menu():
    while True:
        ui_clear()
        title()
        line(render_menu())
        line()
        try:
            selection = input('  ' + ui_color('Select option', _UI_WHITE)
                              + ui_color('  › ', _UI_CYAN, True)).strip()
        except (EOFError, KeyboardInterrupt):
            line()
            return 0
        try:
            if selection == '0':
                return 0
            if selection == '1':
                status()
            elif selection == '2':
                if input('  Type INSTALL to continue: ').strip() == 'INSTALL':
                    install()
            elif selection == '3':
                migrate()
            elif selection == '4':
                check_database_login()
            elif selection == '5':
                logs()
            elif selection == '6':
                inspect_sqlite_source()
            elif selection == '7':
                inspect_sqlite_writers()
            elif selection == '8':
                inspect_resources()
            else:
                say('WARN', 'Unknown menu option.')
        except KeyboardInterrupt:
            say('WARN', 'Interrupted. Check service and database status before retrying.')
        try:
            input('\n  ' + ui_color('Press Enter to return to the menu...', _UI_MUTED))
        except (EOFError, KeyboardInterrupt):
            return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument('--status', action='store_true', help='Read-only database and service status')
    commands.add_argument('--install', action='store_true', help='Install and start PostgreSQL')
    commands.add_argument('--migrate', action='store_true', help='Install PostgreSQL if needed, then migrate WG Panel')
    commands.add_argument('--check', action='store_true', help='Test PostgreSQL administrator connectivity')
    commands.add_argument('--logs', action='store_true', help='View PostgreSQL systemd logs')
    commands.add_argument('--inspect', action='store_true', help='Read-only SQLite migration compatibility inspection')
    commands.add_argument('--writers', action='store_true', help='Read-only inventory of WG Panel SQLite users')
    commands.add_argument('--resources', action='store_true', help='Read-only host and service resource pressure sample')
    parser.add_argument('--yes', action='store_true', help='Skip MIGRATE confirmation with --migrate (automation only)')
    args = parser.parse_args(argv)
    if args.status:
        return 0 if status() else 1
    if args.install:
        return 0 if install() else 1
    if args.migrate:
        return 0 if migrate(yes=args.yes) else 1
    if args.check:
        return 0 if check_database_login() else 1
    if args.logs:
        return 0 if logs() else 1
    if args.inspect:
        return 0 if inspect_sqlite_source() else 1
    if args.writers:
        return 0 if inspect_sqlite_writers() else 1
    if args.resources:
        return 0 if inspect_resources() else 1
    return menu()


if __name__ == '__main__':
    raise SystemExit(main())
