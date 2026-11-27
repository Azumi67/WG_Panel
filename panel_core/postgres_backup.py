

from contextlib import contextmanager
from pathlib import Path
import os
import subprocess
import tempfile
from sqlalchemy.engine import make_url, URL


@contextmanager
def postgres_dump(sqlalchemy_url, timeout=180):
    url = make_url(sqlalchemy_url)
    if url.get_backend_name() != 'postgresql':
        raise ValueError('Expected PostgreSQL connection')
    if not url.database:
        raise ValueError('No PostgreSQL database specified')
    safe = URL.create(drivername='postgresql', username=url.username, password=None,
                      host=url.host, port=url.port, database=url.database, query=url.query)

    conninfo = safe.render_as_string(hide_password=False)
    env = os.environ.copy()
    if url.password is not None:
        env['PGPASSWORD'] = url.password
    fd, destination = tempfile.mkstemp(prefix='wgpanel_pg_dump_',suffix='.dump')
    os.close(fd)
    os.chmod(destination,0o600)
    try:
        try:
            result = subprocess.run(
                ['pg_dump','--format=custom','--no-owner','--no-acl','--dbname='+conninfo,
                 '--file='+destination], env=env, capture_output=True, text=True, timeout=timeout, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError('pg_dump not installed: install postgresql-client') from exc
        if result.returncode:

            raise RuntimeError('pg_dump failed; check PostgreSQL access, client version and server logs')
        if not Path(destination).stat().st_size:
            raise RuntimeError('pg_dump produced an empty file')
        try:
            listing=subprocess.run(['pg_restore','--list',destination],capture_output=True,timeout=30,check=False)
        except FileNotFoundError as exc:
            raise RuntimeError('pg_restore not installed: install postgresql-client') from exc
        if listing.returncode or not listing.stdout:
            raise RuntimeError('PostgreSQL archive table of contents could not be read')
        yield destination
    finally:
        try:os.unlink(destination)
        except FileNotFoundError:pass
