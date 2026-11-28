import fcntl
import os
import re
import threading
import time
from contextlib import contextmanager

_local = threading.local()


class InterfaceBusy(TimeoutError):
    pass


@contextmanager
def interface_lock(directory, name, timeout=5):





    name = re.sub(r'[^A-Za-z0-9_.:-]+', '_', str(name or 'iface'))
    os.makedirs(directory, exist_ok=True)
    path = os.path.abspath(os.path.join(directory, f'{name}.alloc.lock'))
    if getattr(_local, 'pid', None) != os.getpid():
        _local.pid = os.getpid()
        _local.held = set()
    held = _local.held
    if path in held:
        yield
        return
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        deadline = time.monotonic() + max(0, timeout)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise InterfaceBusy('The selected WireGuard interface is busy.') from None
                time.sleep(min(.05, remaining))
        held.add(path)
        try:
            yield
        finally:
            held.remove(path)
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
