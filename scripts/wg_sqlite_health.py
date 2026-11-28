#!/usr/bin/env python3


import argparse
import pathlib
import sqlite3
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description='Check a SQLite WG Panel database via a read-only snapshot')
    parser.add_argument('database', type=pathlib.Path, help='Path to instance/wg_panel.db')
    args = parser.parse_args()
    path = args.database.resolve()
    if not path.is_file():
        parser.error('Database file does not exist')
    try:
        with tempfile.TemporaryDirectory(prefix='wg_sqlite_check_') as directory:
            uri = path.as_uri() + '?mode=ro'
            with sqlite3.connect(uri, uri=True, timeout=8) as src:
                src.execute('PRAGMA busy_timeout=8000')
                live_mode = src.execute('PRAGMA journal_mode').fetchone()[0]
                destination = pathlib.Path(directory) / 'snapshot.db'
                start = time.monotonic()
                with sqlite3.connect(str(destination), timeout=8) as dst:
                    src.backup(dst, pages=256, sleep=0.05)
                with sqlite3.connect(str(destination), timeout=8) as check:
                    integrity = [r[0] for r in check.execute('PRAGMA quick_check').fetchall()]
                    foreign_keys = check.execute('PRAGMA foreign_key_check').fetchall()
                    tables = check.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
                print('Journal mode:', live_mode)
                print('Snapshot:', 'completed')
                print('Tables:', tables)
                print('Quick check:', ', '.join(integrity[:5]))
                print('Foreign key violations:', len(foreign_keys))
                print('Snapshot time (seconds):', round(time.monotonic() - start, 2))
                print('The live database was opened read-only and was not modified.')
                return 0 if integrity == ['ok'] and not foreign_keys else 2
    except sqlite3.Error as exc:
        print('SQLite snapshot/check failed:', type(exc).__name__, str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
