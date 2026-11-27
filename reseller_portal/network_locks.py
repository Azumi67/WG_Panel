

import hashlib
import logging
import time
from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import text


class NetworkLockTimeout(TimeoutError):
    pass


def _key(name):
    return int.from_bytes(
        hashlib.sha256(('wg-panel-operation:' + name).encode('utf-8')).digest()[:8],
        'big', signed=True,
    )


def _normalize(ids):
    if ids is None:
        return None
    values = sorted({int(value) for value in ids})
    if values and values[0] <= 0:
        raise ValueError('Invalid interface lock scope.')
    return values


_operation_connection = ContextVar('wg_operation_connection', default=None)


@contextmanager
def postgres_advisory_operation(engine, operations, wait_seconds=5):
    operations = list(operations)
    if not operations:
        yield
        return
    active = _operation_connection.get()
    if active is not None:
        if active[0] is not engine:
            raise RuntimeError('Cannot mix databases in one operation scope.')
        with _acquire(active[1], operations, wait_seconds):
            yield
        return
    started = time.monotonic()
    with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as connection:
        elapsed = time.monotonic() - started
        if elapsed >= .25:
            logging.getLogger(__name__).warning('Network coordination connection checkout_ms=%.0f', elapsed*1000)
        token = _operation_connection.set((engine, connection))
        try:
            with _acquire(connection, operations, wait_seconds):
                yield
        finally:
            _operation_connection.reset(token)


@contextmanager
def _acquire(connection, operations, wait_seconds):
    deadline = time.monotonic() + max(0., float(wait_seconds))
    held = []
    try:
        for key, shared in operations:
            suffix = '_shared' if shared else ''
            while True:
                try:
                    obtained = connection.execute(text(f'SELECT pg_try_advisory_lock{suffix}(:key)'), {'key': key}).scalar()
                except BaseException:
                    connection.invalidate()
                    raise
                if obtained:
                    held.append((key, shared))
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NetworkLockTimeout('The selected WireGuard interface or account is being updated.')
                time.sleep(min(.05, remaining))
        yield
    finally:
        try:
            if connection.invalidated:
                raise RuntimeError('Operation coordination connection was lost.')
            for key, shared in reversed(held):
                suffix = '_shared' if shared else ''
                if not connection.execute(text(f'SELECT pg_advisory_unlock{suffix}(:key)'), {'key': key}).scalar():
                    raise RuntimeError('PostgreSQL advisory lock ownership could not be verified.')
        except BaseException:
            connection.invalidate()
            raise


@contextmanager
def postgres_network_operation(engine, interface_ids=None, wait_seconds=5):
    interfaces = _normalize(interface_ids)
    if interfaces == []:
        yield
        return
    shared = interfaces is not None
    operations = [(_key('reseller-transaction'), shared)]
    if shared:
        operations.extend((_key('reseller-interface:' + str(i)), False) for i in interfaces)
    with postgres_advisory_operation(engine, operations, wait_seconds):
        yield
