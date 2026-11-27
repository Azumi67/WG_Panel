#!/usr/bin/env python3

import json
import os
import sys
from sqlalchemy import create_engine, text


def main():
    from dotenv import load_dotenv
    load_dotenv(override=False)
    raw=os.environ.get('DATABASE_URL','')
    if raw.startswith('postgres://'):
        raw='postgresql+psycopg://'+raw[len('postgres://'):]
    if raw.startswith('postgresql://'):
        raw='postgresql+psycopg://'+raw[len('postgresql://'):]
    if not raw.startswith('postgresql+psycopg://'):
        print('DATABASE_URL must be PostgreSQL',file=sys.stderr)
        return 2
    engine=create_engine(raw,hide_parameters=True,pool_pre_ping=True,connect_args={'connect_timeout':3})
    tables=('admin_account','peer','subscription','rp_account','rp_ownership','rp_order','rp_setting',
            'rp_auth_budget','rp_auth_event')
    try:
        with engine.connect() as connection:
            version=connection.execute(text('SHOW server_version')).scalar()
            result={}
            for table in tables:
                exists=connection.execute(text('SELECT to_regclass(:name)'),{'name':table}).scalar()
                if not exists:
                    result[table]=None
                    continue

                result[table]=connection.execute(text('SELECT count(*) FROM "'+table+'"')).scalar()
        print(json.dumps({'backend':'postgresql','server_version':version,'table_counts':result},sort_keys=True))
        return 0 if all(value is not None for value in result.values()) else 2
    except Exception as exc:
        print('PostgreSQL check failed: '+type(exc).__name__,file=sys.stderr)
        return 2
    finally:
        engine.dispose()


if __name__=='__main__':
    raise SystemExit(main())
