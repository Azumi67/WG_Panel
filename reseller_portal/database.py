
import fcntl
import os
import time
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from flask import current_app, has_app_context, has_request_context, request
from threading import current_thread, Lock
from contextvars import ContextVar
from sqlalchemy import event, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.engine import make_url
from sqlalchemy import text
import hashlib
from models import db

@contextmanager
def schema_lock(engine, timeout=45):
    database=engine.url.database
    if engine.dialect.name=='postgresql':
        key=int.from_bytes(hashlib.sha256(b'wg-panel-schema-v1').digest()[:8], 'big', signed=True)
        deadline=time.monotonic()+timeout
        with engine.connect() as conn:
            while True:
                acquired=conn.execute(text('SELECT pg_try_advisory_lock(:key)'), {'key':key}).scalar()
                conn.commit()
                if acquired:break
                if time.monotonic()>=deadline:raise TimeoutError('PostgreSQL schema migration is still running.')
                time.sleep(.1)
            try:yield
            finally:
                conn.execute(text('SELECT pg_advisory_unlock(:key)'),{'key':key})
                conn.commit()
        return
    if engine.dialect.name!='sqlite' or not database or database==':memory:':
        yield
        return
    path=Path(database).resolve()
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(str(path)+'.schema.lock',os.O_CREAT|os.O_RDWR,0o600)
    with os.fdopen(fd,'w') as handle:
        deadline=time.monotonic()+timeout
        while True:
            try:
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>=deadline:raise TimeoutError('Database schema initialization is still running.')
                time.sleep(.1)
        try:yield
        finally:fcntl.flock(handle,fcntl.LOCK_UN)

def configure(engine):
    if engine.dialect.name!='sqlite' or getattr(engine,'_rp_database_ready',False):return
    def connection_options(conn,record):
        cursor=conn.cursor()
        try:cursor.execute('PRAGMA busy_timeout=5000')
        finally:cursor.close()
    event.listen(engine,'connect',connection_options)

    with schema_lock(engine):
        with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as conn:
            conn.exec_driver_sql('PRAGMA busy_timeout=30000')
            try:
                mode=conn.exec_driver_sql('PRAGMA journal_mode').scalar()
                if engine.url.database not in (None,'',':memory:') and mode.lower()!='wal':
                    actual=conn.exec_driver_sql('PRAGMA journal_mode=WAL').scalar()
                    if actual.lower()!='wal':raise RuntimeError('SQLite WAL could not be enabled on the database filesystem.')
            finally:conn.exec_driver_sql('PRAGMA busy_timeout=5000')
    engine._rp_database_ready=True

class SettingsWriterBusy(TimeoutError):
    pass


def writer_busy(exc):
    if isinstance(exc, SettingsWriterBusy):
        return True
    if not isinstance(exc, OperationalError):
        return False
    code = getattr(exc.orig, 'sqlite_errorcode', None)
    if code is not None:
        return (code & 255) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    pgcode = getattr(exc.orig, 'sqlstate', None) or getattr(exc.orig, 'pgcode', None)
    if pgcode in ('55P03', '40P01', '40001'):
        return True
    return str(exc.orig).lower().startswith(('database is locked', 'database table is locked', 'database schema is locked', 'database is busy'))


_transaction_stats = ContextVar('wgpanel_reseller_transaction_stats', default=None)
_stats_install_guard = Lock()


class _TransactionStats:
    __slots__ = ('statements', 'sql_seconds', 'slowest_sql_seconds')

    def __init__(self):
        self.statements = 0
        self.sql_seconds = 0.0
        self.slowest_sql_seconds = 0.0

    def observe(self, duration):
        duration = max(0.0, duration)
        self.statements += 1
        self.sql_seconds += duration
        self.slowest_sql_seconds = max(self.slowest_sql_seconds, duration)


def _sql_before(connection, cursor, statement, parameters, context, executemany):
    stats = _transaction_stats.get()
    if stats is not None:
        context._wg_reseller_timing = (stats, time.monotonic())


def _sql_after(connection, cursor, statement, parameters, context, executemany):
    timing = getattr(context, '_wg_reseller_timing', None)
    if timing is not None:
        stats, started = timing
        context._wg_reseller_timing = None
        stats.observe(time.monotonic() - started)


def _sql_error(exception_context):
    context = getattr(exception_context, 'execution_context', None)
    timing = getattr(context, '_wg_reseller_timing', None)
    if timing is not None:
        stats, started = timing
        context._wg_reseller_timing = None
        stats.observe(time.monotonic() - started)


def _register_sql_timings(engine):
    if getattr(engine, '_wg_reseller_sql_timings', False):
        return
    with _stats_install_guard:
        if getattr(engine, '_wg_reseller_sql_timings', False):
            return
        event.listen(engine, 'before_cursor_execute', _sql_before)
        event.listen(engine, 'after_cursor_execute', _sql_after)
        event.listen(engine, 'handle_error', _sql_error)
        engine._wg_reseller_sql_timings = True


@contextmanager
def settings_transaction(wait_seconds=5, *, label=None, health_only=False):


    db.session.rollback()
    engine = db.engine
    _register_sql_timings(engine)
    stats = _TransactionStats()
    token = _transaction_stats.set(stats)
    start = time.monotonic()
    acquired = None
    commit_started = None
    commit_finished = None
    try:
        if engine.dialect.name == 'sqlite':
            deadline = start + wait_seconds
            while True:
                try:
                    db.session.execute(text('BEGIN IMMEDIATE'))
                    break
                except OperationalError as exc:
                    db.session.rollback()
                    if not writer_busy(exc):
                        raise
                    if time.monotonic() >= deadline:
                        raise SettingsWriterBusy('Waiting for the previous database write.') from exc
                    time.sleep(min(.075, max(.005, deadline-time.monotonic())))
        if engine.dialect.name == 'postgresql':
            db.session.execute(text("SELECT set_config('lock_timeout', :timeout, true)"),
                               {'timeout': str(int(max(1, wait_seconds) * 1000)) + 'ms'})


            if health_only and os.environ.get('WG_HEALTH_ASYNC_COMMIT', '1') == '1':
                db.session.execute(text("SELECT set_config('synchronous_commit', 'off', true)"))
        acquired = time.monotonic()
        yield
        commit_started = time.monotonic()
        try:
            db.session.commit()
        finally:
            commit_finished = time.monotonic()
    except BaseException:
        db.session.rollback()
        raise
    finally:
        end = time.monotonic()
        _transaction_stats.reset(token)
        if end - start >= 1 and has_app_context():
            phase = acquired if acquired is not None else end
            origin = request.endpoint if has_request_context() else current_thread().name
            import inspect
            frame = inspect.currentframe()
            frame = frame.f_back if frame else None
            while frame and frame.f_code.co_filename.endswith('contextlib.py'):
                frame = frame.f_back
            caller = (os.path.basename(frame.f_code.co_filename) + ':' + str(frame.f_lineno)) if frame else 'unknown'
            del frame
            body_end = commit_started if commit_started is not None else end


            current_app.logger.warning(
                'Reseller write timing source=%s label=%s caller=%s '
                'wait_ms=%.0f transaction_ms=%.0f body_ms=%.0f commit_ms=%.0f '
                'sql_ms=%.0f longest_sql_ms=%.0f statements=%s acquired=%s health_only=%s',
                origin, label or 'unspecified', caller,
                1000 * (phase - start), 1000 * (end - phase),
                1000 * max(0, body_end - phase),
                1000 * ((commit_finished or end) - commit_started) if commit_started is not None else 0,
                1000 * stats.sql_seconds, 1000 * stats.slowest_sql_seconds,
                stats.statements, acquired is not None, health_only)


def copy_database(source,destination):
    deadline=time.monotonic()+30
    def progress(status,remaining,total):
        if time.monotonic()>deadline:raise TimeoutError('Database snapshot could not finish in 30 seconds.')
    source_uri=Path(source).resolve().as_uri()+'?mode=ro'
    with sqlite3.connect(source_uri,uri=True,timeout=5) as src:
        with sqlite3.connect(str(destination),timeout=5) as dst:
            src.backup(dst,pages=256,progress=progress,sleep=.05)

@contextmanager
def snapshot(source):
    fd,path=tempfile.mkstemp(suffix='.sqlite');os.close(fd)
    try:
        copy_database(source,path)
        yield path
    finally:
        for suffix in ('','-wal','-shm'):
            try:os.unlink(path+suffix)
            except FileNotFoundError:pass


def lock_application_key(name):

    if db.engine.dialect.name != 'postgresql':
        return
    from .models import Setting
    from sqlalchemy.dialects.postgresql import insert
    db.session.execute(insert(Setting).values(key=name,value=None).on_conflict_do_nothing(index_elements=[Setting.key]))
    db.session.get(Setting,name,with_for_update=True,populate_existing=True)
