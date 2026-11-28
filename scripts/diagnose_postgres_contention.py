#!/usr/bin/env python3
"""Read-only PostgreSQL wait sampling; no SQL contents or credentials printed."""
import argparse
from collections import Counter
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ACTIVITY = '''
    SELECT pid, state, wait_event_type, wait_event,
           EXTRACT(EPOCH FROM (clock_timestamp() - xact_start)) AS xact_age,
           pg_blocking_pids(pid) AS blockers
    FROM pg_stat_activity
    WHERE datname=current_database() AND pid <> pg_backend_pid()
    ORDER BY xact_age DESC NULLS LAST, pid LIMIT 100
'''


def show_settings(conn, text):
    row = conn.execute(text('''SELECT current_setting('server_version'),
           current_setting('synchronous_commit'), current_setting('fsync'),
           current_setting('full_page_writes'),
           current_setting('synchronous_standby_names') <> '' AS sync_standbys,
           current_setting('track_wal_io_timing', true)''')).one()
    print('PostgreSQL version:', row[0])
    print('Durability: synchronous_commit=%s fsync=%s full_page_writes=%s' % tuple(row[1:4]))
    print('Synchronous standbys configured:', 'yes' if row[4] else 'no')
    print('track_wal_io_timing:', row[5] or 'unavailable')


def wal_snapshot(conn, text):


    try:
        row = conn.execute(text('SELECT to_jsonb(w) FROM pg_stat_wal AS w')).scalar_one()
        return {k: row[k] for k in ('wal_write', 'wal_sync', 'wal_write_time', 'wal_sync_time', 'wal_bytes') if k in row}
    except Exception:
        return {}


def print_wal_delta(before, after):
    if not before or not after:
        print('WAL statistics unavailable on this PostgreSQL version or role.')
        return
    print('Cluster-wide WAL counters during sampling (not specific to WG Panel):')
    for k in before.keys() & after.keys():
        try:
            delta = float(after[k])-float(before[k])
        except (ValueError, TypeError):
            continue
        if delta >= 0:
            print(f'  {k}: +{delta:.2f}')
    if 'wal_sync_time' in before and 'wal_sync' in before:
        elapsed = float(after.get('wal_sync_time',0))-float(before['wal_sync_time'])
        count = float(after.get('wal_sync',0))-float(before['wal_sync'])
        if elapsed > 0 and count > 0:
            print(f'  Mean measured WAL sync: {elapsed/count:.2f} ms')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=0, help='Sample waits for up to 120 seconds (default: one snapshot)')
    parser.add_argument('--interval', type=float, default=.5, help='Sampling interval, 0.2–5 seconds')
    args = parser.parse_args(argv)
    if not 0 <= args.seconds <= 120 or not .2 <= args.interval <= 5:
        parser.error('Use --seconds 0–120 and --interval 0.2–5')
    from dotenv import dotenv_values
    from sqlalchemy import create_engine, text
    url = os.getenv('DATABASE_URL') or dotenv_values(ROOT / '.env').get('DATABASE_URL') or ''
    if not url.startswith(('postgresql://','postgresql+psycopg://','postgresql+psycopg2://','postgres://')):
        print('No PostgreSQL DATABASE_URL is configured.')
        return 2
    if url.startswith(('postgresql://','postgres://')):
        url = 'postgresql+psycopg://' + url.split('://',1)[1]
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True, hide_parameters=True, connect_args={'connect_timeout':5, 'options':'-c statement_timeout=5000'})
        print('WG Panel PostgreSQL wait diagnostics (read-only; no SQL text or credentials)', flush=True)
        with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as conn:
            show_settings(conn, text)
            before = wal_snapshot(conn, text)
            deadline = time.monotonic()+args.seconds
            counts = Counter()
            max_age = 0.0
            max_blockers = 0
            samples = 0
            print('Sampling; reproduce the slow reseller login or workspace refresh in your browser.', flush=True)
            while True:
                rows = conn.execute(text(ACTIVITY)).all()
                samples += 1
                for row in rows:
                    if row.state != 'idle':
                        counts[(row.wait_event_type or 'running',row.wait_event or 'none')] += 1
                    max_age = max(max_age, float(row.xact_age or 0))
                    max_blockers = max(max_blockers,len(row.blockers or []))
                if args.seconds == 0 or time.monotonic() >= deadline:
                    break
                time.sleep(min(args.interval,max(0,deadline-time.monotonic())))
            print('Samples:',samples,'| Max transaction age:',round(max_age,2),'s | Max blockers:',max_blockers)
            for (kind,event), count in counts.most_common(20):
                print(f'  {kind:<18} {event:<25} {count:>6} session-samples')
            print('Final snapshot: PID / state / wait type / wait event / transaction age / blockers')
            for row in rows:
                print(row.pid, row.state or '-', row.wait_event_type or '-', row.wait_event or '-',
                      round(float(row.xact_age or 0),2), ','.join(map(str,row.blockers or [])) or '-')
            if args.seconds:
                print_wal_delta(before, wal_snapshot(conn,text))
            if any(event in ('WALSync','WALWrite','WALWriteLock') for _,event in counts):
                print('WAL write/sync waits observed. Check VPS storage and host I/O.')
            if any(event=='SyncRep' for _,event in counts):
                print('Synchronous replication waits observed. Inspect standby health.')
            if max_blockers:
                print('Blocking sessions observed. Review row/advisory lock holders.')
    except Exception as exc:
        print('PostgreSQL inspection failed: '+type(exc).__name__)
        return 1
    finally:
        if engine is not None:engine.dispose()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
