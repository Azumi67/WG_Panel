
import os
import sqlite3
from contextlib import contextmanager
from threading import Lock
import time
from flask import current_app
from . import service as s

_initialized = set()
_schema_guard = Lock()
_last_budget_cleanup = 0.0
_cleanup_guard = Lock()

@contextmanager
def connection(write=True):
    os.makedirs(current_app.instance_path,exist_ok=True)
    path=os.path.join(current_app.instance_path,'reseller-request-guard.sqlite')
    conn=sqlite3.connect(path,timeout=2,isolation_level=None)
    try:
        conn.execute('PRAGMA busy_timeout=2000')
        if path not in _initialized:
            with _schema_guard:
                if path not in _initialized:
                    conn.execute('PRAGMA journal_mode=WAL')
                    conn.execute('CREATE TABLE IF NOT EXISTS budgets (key TEXT PRIMARY KEY, count INTEGER NOT NULL, until REAL NOT NULL)')
                    conn.execute('CREATE INDEX IF NOT EXISTS budgets_until ON budgets(until)')
                    conn.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, at TEXT NOT NULL)')
                    _initialized.add(path)
        conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield conn
            conn.execute('COMMIT')
        except BaseException:
            if conn.in_transaction:conn.execute('ROLLBACK')
            raise
    except sqlite3.OperationalError as exc:
        if conn.in_transaction:conn.execute('ROLLBACK')
        if 'locked' in str(exc).lower() or 'busy' in str(exc).lower():
            raise TimeoutError('Authentication request store busy') from None
        raise
    finally:
        conn.close()

def reserve(items, *, touch=None):
    if current_app.extensions['sqlalchemy'].engine.dialect.name == 'postgresql':
        from .request_guard_pg import reserve as pg_reserve
        return pg_reserve(items, touch=touch)
    now=time.time() if touch else s.now().timestamp();allowed=True
    global _last_budget_cleanup
    with connection() as conn:


        if time.monotonic()-_last_budget_cleanup>90:
            with _cleanup_guard:
                if time.monotonic()-_last_budget_cleanup>90:
                    conn.execute('DELETE FROM budgets WHERE key IN (SELECT key FROM budgets WHERE until < ? ORDER BY until LIMIT 1000)', (now-86400,))
                    _last_budget_cleanup=time.monotonic()
        for key,maximum,seconds in items:


            if sqlite3.sqlite_version_info >= (3,35,0):
                count=conn.execute("""
                    INSERT INTO budgets(key,count,until) VALUES (?,1,?)
                    ON CONFLICT(key) DO UPDATE SET
                        count=CASE WHEN budgets.until > ? THEN budgets.count+1 ELSE 1 END,
                        until=CASE WHEN budgets.until > ? THEN budgets.until ELSE excluded.until END
                    RETURNING count
                """,(key,now+seconds,now,now)).fetchone()[0]
            else:
                row=conn.execute('SELECT count,until FROM budgets WHERE key=?',(key,)).fetchone()
                count,until=(row[0]+1,row[1]) if row and row[1]>now else (1,now+seconds)
                conn.execute('INSERT OR REPLACE INTO budgets VALUES (?,?,?)',(key,count,until))
            allowed=count<=maximum and allowed
        if touch:
            conn.execute("INSERT INTO budgets(key,count,until) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET until=MAX(budgets.until,excluded.until)",(touch,now+30*86400))
    return allowed

def login_event(account_id):
    if current_app.extensions['sqlalchemy'].engine.dialect.name == 'postgresql':
        from .request_guard_pg import login_event as pg_login_event
        return pg_login_event(account_id)
    with connection() as conn:
        conn.execute('INSERT INTO events(actor,at) VALUES (?,?)',('reseller:'+str(account_id),s.now().isoformat()))

def import_events():
    if current_app.extensions['sqlalchemy'].engine.dialect.name == 'postgresql':
        from .request_guard_pg import import_events as pg_import_events
        return pg_import_events()
    from datetime import datetime
    from models import db
    from .models import Audit
    cursor = int(s.setting('auth_audit_cursor',0))
    with connection(write=False) as conn:
        rows = conn.execute('SELECT id,actor,at FROM events WHERE id>? ORDER BY id LIMIT 100',(cursor,)).fetchall()
    for eid,actor,at in rows:
        db.session.add(Audit(actor=actor,action='login',details='Successful login',at=datetime.fromisoformat(at)))
    if rows:
        s.put('auth_audit_cursor', rows[-1][0])


def prune_imported_events():
    if current_app.extensions['sqlalchemy'].engine.dialect.name == 'postgresql':
        from .request_guard_pg import prune_imported_events as pg_prune_imported_events
        return pg_prune_imported_events()
    cursor = int(s.setting('auth_audit_cursor',0))
    from models import db
    db.session.rollback()
    if cursor:
        with connection() as conn:
            conn.execute('DELETE FROM events WHERE id IN (SELECT id FROM events WHERE id<=? ORDER BY id LIMIT 500)', (cursor,))


def reserve_named(role, aid, kid, rate):
    from .application_credentials import metric_keys
    now=time.time()
    minute,day,seen=metric_keys(role,aid,kid,now)
    return reserve([(minute,rate,60),(day,2147483647,172800)],touch=seen)


def named_statistics(role,aid,kid):
    from datetime import datetime,timezone
    from .application_credentials import metric_keys
    from models import db
    from .models import AuthBudget
    now=time.time()
    _,day,seen=metric_keys(role,aid,kid,now)
    if db.engine.dialect.name=='postgresql':
        rows={r.key:(r.count,r.until) for r in db.session.query(AuthBudget).filter(AuthBudget.key.in_([day,seen])).all()}
    else:
        with connection(write=False) as conn:
            rows={k:(count,until) for k,count,until in conn.execute('SELECT key,count,until FROM budgets WHERE key IN (?,?)',(day,seen))}
    last=rows.get(seen,(0,0))[1]-30*86400
    return {'requests_today':rows.get(day,(0,0))[0], 'last_used':datetime.fromtimestamp(last,timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if last>0 else None}
