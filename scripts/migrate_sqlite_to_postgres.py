#!/usr/bin/env python3
"""One-time, fail-closed migration of WG Panel's core + reseller data.

The source remains untouched. Run with all application writers STOPPED.
By default the command performs only preflight inspection. It never overwrites
populated PostgreSQL tables or migrates secrets stored in instance/. or .env.
"""
import argparse
import json
import os
import re
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, DataError, OperationalError, ProgrammingError
from sqlalchemy.schema import MetaData
from sqlalchemy.sql.sqltypes import Boolean, Date, DateTime, JSON


class MigrationPreflightError(RuntimeError):

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _safe_table_names(names, maximum=12):
    visible = sorted(str(n) for n in names)
    labels = [n if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', n)
              else '[nonstandard table name]' for n in visible[:maximum]]
    if len(visible) > maximum:
        labels.append(f'... and {len(visible) - maximum} more')
    return ', '.join(labels)


def _inspect_source(connection, tables):
    integrity = connection.execute('PRAGMA quick_check').fetchone()[0]
    if integrity != 'ok':
        raise MigrationPreflightError('SQLITE_INTEGRITY', 'SQLite quick_check failed. Restore or repair a separate backup before migrating.')
    broken = connection.execute('PRAGMA foreign_key_check').fetchmany(21)
    if broken:
        table_names = {row[0] for row in broken}
        detail = ('at least 21' if len(broken) >= 21 else str(len(broken)))
        raise MigrationPreflightError('FOREIGN_KEYS',
            f'SQLite contains {detail} broken foreign-key references in: {_safe_table_names(table_names)}. '
            'Keep the source unchanged and investigate an offline copy.')
    names = source_tables(connection)
    mapped = {table.name for table in tables}
    extras = [n for n in names-mapped if source_count(connection,n)]
    if extras:
        raise MigrationPreflightError('UNMAPPED_TABLES',
            'Source contains data in tables not covered by the current ORM migration: '
            + _safe_table_names(extras) + '. The wizard will not discard these records. '
            'Review the named tables or extend their schema mapping first.')
    info = {table.name:source_count(connection,table.name) for table in tables if table.name in names}
    columns = {table.name:source_columns(connection,table.name) for table in tables if table.name in names}
    for table in tables:
        if table.name not in names:
            continue
        present = columns[table.name]
        for col in table.columns:
            if (col.name not in present and not col.nullable
                    and col.default is None and col.server_default is None
                    and not (col.primary_key and col.autoincrement in (True, 'auto', 'ignore_fk'))):
                raise MigrationPreflightError('MISSING_REQUIRED_COLUMN',
                    f'Source table {table.name} is missing required column {col.name}. '
                    'The source and destination schema versions do not match. Do not import yet.')


    for table in tables:
        if table.name not in names:
            continue
        for col in table.columns:
            if col.name not in columns[table.name] or not isinstance(col.type, (JSON, DateTime, Date)):
                continue
            qt = '"' + table.name.replace('"','""') + '"'
            qc = '"' + col.name.replace('"','""') + '"'
            for (value,) in connection.execute('SELECT ' + qc + ' FROM ' + qt + ' WHERE ' + qc + ' IS NOT NULL'):
                try:
                    decode(value, col)
                except (ValueError, TypeError, OverflowError) as exc:
                    raise MigrationPreflightError('INVALID_SOURCE_VALUE',
                        f'Source {table.name}.{col.name} contains an invalid encoded value. '
                        'No data was changed; repair an offline copy or update the migration mapping.') from exc
    return names, info, columns


def normalize_db_url(value):
    if value.startswith('postgres://'):
        return 'postgresql+psycopg://' + value[len('postgres://'):]
    if value.startswith('postgresql://'):
        return 'postgresql+psycopg://' + value[len('postgresql://'):]
    if not value.startswith('postgresql+psycopg://'):
        raise ValueError('Target must be a postgresql+psycopg:// URL')
    return value


def source_snapshot(path, destination):
    with sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True, timeout=20) as origin:
        with sqlite3.connect(str(destination), timeout=20) as copy:
            origin.backup(copy, pages=512, sleep=.1)


def decode(value, col):
    if value is None:
        return None
    if isinstance(col.type, JSON) and isinstance(value, str):
        return json.loads(value)
    if isinstance(col.type, Boolean):
        return bool(value)
    if isinstance(col.type, DateTime) and isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    if isinstance(col.type, Date) and isinstance(value, str):
        return date.fromisoformat(value)
    return value


def source_tables(source):
    return {row[0] for row in source.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}


def source_count(source, name):

    quote='"'+name.replace('"', '""')+'"'
    return source.execute('SELECT count(*) FROM '+quote).fetchone()[0]


def source_columns(source, name):
    quote='"'+name.replace('"','""')+'"'
    return {row[1] for row in source.execute('PRAGMA table_info('+quote+')')}


def migrate(sqlite_file, pg_url, auth_db, *, apply=False, batch_size=500, source_only=False):

    from models import db
    from reseller_portal import models as reseller_models  # noqa: F401
    target = None if source_only else create_engine(normalize_db_url(pg_url), pool_pre_ping=True, hide_parameters=True)
    try:
        if target is not None and target.dialect.name != 'postgresql':
            raise RuntimeError('Refusing non-PostgreSQL target')
        with tempfile.TemporaryDirectory(prefix='wgpanel_pg_migrate_') as temp:
            snapshot=Path(temp)/'source.sqlite'
            source_snapshot(sqlite_file,snapshot)
            connection=sqlite3.connect(str(snapshot))
            connection.row_factory=sqlite3.Row
            try:
                tables=list(db.metadata.sorted_tables)
                names, info, columns = _inspect_source(connection, tables)
                auth_count=0
                auth_counts={'budgets':0,'events':0}
                auth_copy=None
                if auth_db and auth_db.is_file():
                    auth_copy=Path(temp)/'auth.sqlite'
                    source_snapshot(auth_db,auth_copy)
                    with sqlite3.connect(str(auth_copy)) as audit:
                        if audit.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                            raise MigrationPreflightError('AUTH_INTEGRITY',
                                'Authentication guard SQLite integrity check failed.')
                        auth_tables=source_tables(audit)
                        auth_extras=[n for n in auth_tables-{'budgets','events'} if source_count(audit,n)]
                        if auth_extras:
                            raise MigrationPreflightError('AUTH_UNMAPPED_TABLES',
                                'Authentication guard database has data in unexpected tables: '
                                + _safe_table_names(auth_extras) + '.')
                        if 'budgets' in auth_tables:auth_counts['budgets']=source_count(audit,'budgets')
                        if 'events' in auth_tables:auth_counts['events']=source_count(audit,'events')
                        auth_count=sum(auth_counts.values())

                groups = {
                    'core': sum(n for name, n in info.items() if not name.startswith('rp_')),
                    'reseller': sum(n for name, n in info.items() if name.startswith('rp_')),
                    'bots': sum(n for name, n in info.items() if name in (
                        'rp_management_bot', 'rp_notice', 'rp_auth_event', 'rp_auth_budget')),
                    'orders_and_billing': sum(n for name, n in info.items() if name in (
                        'rp_plan', 'rp_order', 'rp_order_receipt', 'rp_payment_verification')),
                }
                print(json.dumps({'source_tables':len(info),'source_rows':sum(info.values()),
                    'auth_guard_rows':auth_count,'target_backend':'postgresql','apply':apply,
                    'source_scope_rows':groups,'sqlite_preflight':'passed'},sort_keys=True))
                if not apply:
                    print('PREFLIGHT ONLY: no PostgreSQL data or schema was changed. Use --apply after backing up and stopping ALL writers.')
                    return

                db.metadata.create_all(target)
                with target.begin() as dest:
                    for table in tables:
                        count=dest.execute(select(func.count()).select_from(table)).scalar_one()
                        if count:
                            raise RuntimeError(f'PostgreSQL target is not empty: {table.name} contains {count} rows')
                    for table_index, table in enumerate(tables, 1):
                        if table.name not in names:continue
                        print(f"MIGRATION_PROGRESS {table_index}/{len(tables)} {table.name} rows={info[table.name]}", flush=True)
                        present=columns[table.name]
                        colnames=[c.name for c in table.columns if c.name in present]
                        quote='"'+table.name.replace('"','""')+'"'
                        cursor=connection.execute('SELECT '+','.join('"'+c.replace('"','""')+'"' for c in colnames)+' FROM '+quote)
                        copied=0
                        while True:
                            batch=cursor.fetchmany(batch_size)
                            if not batch:break
                            payload=[{c.name:decode(row[c.name],c) for c in table.columns if c.name in present} for row in batch]
                            dest.execute(table.insert(), payload)
                            copied+=len(payload)
                        if copied != info[table.name]:
                            raise RuntimeError('Row-count mismatch copying '+table.name)
                    if auth_copy:
                        with sqlite3.connect(str(auth_copy)) as audit:
                            audit.row_factory=sqlite3.Row
                            names_a=source_tables(audit)
                            if 'budgets' in names_a:
                                for row in audit.execute('SELECT key,count,until FROM budgets'):
                                    dest.execute(reseller_models.AuthBudget.__table__.insert().values(
                                        key=row['key'],count=row['count'],until=row['until']))
                            if 'events' in names_a:
                                for row in audit.execute('SELECT id,actor,at FROM events'):
                                    dest.execute(reseller_models.AuthEvent.__table__.insert().values(
                                        id=row['id'],actor=row['actor'],at=decode(row['at'],reseller_models.AuthEvent.__table__.c.at)))

                    preparer=target.dialect.identifier_preparer
                    for table in tables:
                        for pk in table.primary_key.columns:
                            if not pk.autoincrement:continue
                            name=dest.execute(text('SELECT pg_get_serial_sequence(:table, :column)'),
                                {'table':table.name,'column':pk.name}).scalar()
                            if name:
                                maximum=dest.execute(text('SELECT MAX('+preparer.quote(pk.name)+') FROM '+preparer.quote(table.name))).scalar()
                                dest.execute(text('SELECT setval(CAST(:seq AS regclass), :num, :used)'),
                                    {'seq':name,'num':maximum if maximum else 1,'used':bool(maximum)})
                    for table in tables:
                        expected=info.get(table.name,0)
                        if table.name=='rp_auth_budget' and auth_copy:
                            expected=info.get(table.name,0)+auth_counts['budgets']
                        if table.name=='rp_auth_event' and auth_copy:
                            expected=info.get(table.name,0)+auth_counts['events']
                        actual=dest.execute(select(func.count()).select_from(table)).scalar_one()
                        if actual!=expected:
                            raise RuntimeError(f'Row count validation failed for {table.name}: {actual} != {expected}')

                print('COMMITTED: PostgreSQL import complete. Keep the SQLite source and the original encryption keys for rollback.')
            finally:
                connection.close()
    finally:
        if target is not None:
            target.dispose()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sqlite',type=Path,required=True,help='Original SQLite database, e.g. instance/wg_panel.db')
    parser.add_argument('--postgres', help='Target PostgreSQL URL (avoid for secrets: the URL will appear in process arguments)')
    parser.add_argument('--pg-env-file', type=Path,
                        help='Private dotenv file containing the target DATABASE_URL; keeps credentials out of shell history and process arguments')
    parser.add_argument('--auth-db',type=Path,help='Optional instance/reseller-request-guard.sqlite')
    parser.add_argument('--apply',action='store_true',help='Explicitly permit import to an EMPTY PostgreSQL database')
    parser.add_argument('--inspect-source-only',action='store_true', help='Read-only SQLite schema and integrity inspection; no PostgreSQL credentials required')
    parser.add_argument('--batch-size',type=int,default=500)
    args=parser.parse_args()
    if not args.sqlite.is_file():
        parser.error(f'SQLite source not found: {args.sqlite}. Check the path before attempting migration.')
    if not os.access(args.sqlite, os.R_OK):
        parser.error(f'SQLite source is not readable: {args.sqlite}')
    if not 1 <= args.batch_size <= 5000:
        parser.error('--batch-size must be between 1 and 5000')
    if args.apply and args.inspect_source_only:
        parser.error('--inspect-source-only cannot be combined with --apply')
    if args.postgres and args.pg_env_file:
        parser.error('Choose either --postgres or --pg-env-file, not both')
    pg_url = args.postgres or os.environ.get('DATABASE_URL', '').strip()
    if args.pg_env_file:
        if not args.pg_env_file.is_file():
            parser.error(f'PostgreSQL environment file not found: {args.pg_env_file}')
        try:
            from dotenv import dotenv_values
            pg_url = (dotenv_values(args.pg_env_file).get('DATABASE_URL') or '').strip()
        except Exception:
            parser.error('Could not read --pg-env-file. Check its permissions and dotenv syntax.')
    if not pg_url and not args.inspect_source_only:
        parser.error('PostgreSQL DATABASE_URL is missing. Set it in a private --pg-env-file, export it, or use --postgres.')
    try:
        if not args.inspect_source_only:
            normalize_db_url(pg_url)
    except ValueError:
        parser.error('Target DATABASE_URL is not PostgreSQL. Your existing .env may still point to SQLite. Use --pg-env-file with a PostgreSQL URL.')
    auth_db=args.auth_db or args.sqlite.with_name('reseller-request-guard.sqlite')
    try:
        migrate(args.sqlite.resolve(),pg_url,auth_db,apply=args.apply,batch_size=args.batch_size,source_only=args.inspect_source_only)
    except MigrationPreflightError as error:
        print(f'MIGRATION_DIAGNOSTIC {error.code}: {error}', file=sys.stderr, flush=True)
        return 2
    except ModuleNotFoundError as error:

        missing = error.name if isinstance(error.name, str) and re.fullmatch(r'[a-zA-Z_][a-zA-Z_0-9.]{0,90}', error.name) else 'unknown'
        print(f'MIGRATION_DIAGNOSTIC MISSING_PYTHON_MODULE: {missing}. '
              'Check that you used the WG Panel virtualenv and installed its dependencies. '
              'No data was imported.', file=sys.stderr, flush=True)
        return 2
    except sqlite3.Error as error:

        print(f'MIGRATION_DIAGNOSTIC SQLITE_ERROR: {type(error).__name__}. '
              'Read the source backup integrity check before retrying.', file=sys.stderr, flush=True)
        return 2
    except SQLAlchemyError as error:

        if isinstance(error, IntegrityError):
            code, advice = 'TARGET_CONSTRAINT', 'Imported rows violate a destination unique/foreign-key constraint; check source relationships and schema versions.'
        elif isinstance(error, DataError):
            code, advice = 'TARGET_TYPE', 'Source values are incompatible with one or more destination column types.'
        elif isinstance(error, OperationalError):
            code, advice = 'TARGET_CONNECTION', 'PostgreSQL connection or transaction failed; check database logs and service status.'
        elif isinstance(error, ProgrammingError):
            code, advice = 'TARGET_SCHEMA', 'SQL/schema mismatch while creating or importing tables; check schema compatibility.'
        else:
            code, advice = 'POSTGRESQL_ERROR', 'Database operation failed. Check protected PostgreSQL logs.'
        print(f'MIGRATION_DIAGNOSTIC {code}: {advice}', file=sys.stderr, flush=True)
        return 2
    except RuntimeError as error:
        message = str(error)
        if message.startswith('PostgreSQL target is not empty:'):
            print('MIGRATION_DIAGNOSTIC TARGET_NOT_EMPTY: Database contains records; refusing to overwrite them.', file=sys.stderr, flush=True)
        elif message.startswith('Row count validation failed') or message.startswith('Row-count mismatch'):
            print('MIGRATION_DIAGNOSTIC COUNT_MISMATCH: Imported row counts did not match. Transaction rolled back.', file=sys.stderr, flush=True)
        else:
            print('MIGRATION_DIAGNOSTIC RUNTIME_ERROR: ' + type(error).__name__ + '. No import was completed.', file=sys.stderr, flush=True)
        return 2
    except Exception as error:
        print('MIGRATION_DIAGNOSTIC UNEXPECTED_ERROR: ' + type(error).__name__
              + '. No import was completed.', file=sys.stderr, flush=True)
        return 2
    return 0


if __name__=='__main__':
    raise SystemExit(main())
