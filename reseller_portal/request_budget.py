
import fcntl
import json
import os
import tempfile
import time
from pathlib import Path
from threading import Lock
from flask import current_app


_read_leases = {}
_lease_lock = Lock()


def _after_fork():
    global _lease_lock
    _lease_lock = Lock()
    _read_leases.clear()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def _reserve_units(account_id, kind, maximum, seconds, units):
    account_id=int(account_id)
    if account_id <= 0 or kind not in ('read','write'):
        raise ValueError('Invalid workspace budget')
    root=Path(current_app.instance_path)/'reseller-budgets'
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    key=f'{account_id}-{kind}'
    path=root/(key+'.json')
    fd=os.open(root/(key+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
    with os.fdopen(fd,'a') as lock:
        deadline=time.monotonic()+0.5
        while True:
            try:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>=deadline:
                    raise TimeoutError('Workspace account budget busy') from None
                time.sleep(0.005)
        temporary=None
        try:
            now=time.time()
            try:
                value=json.loads(path.read_text())
                count=int(value['count']);until=float(value['until'])
                if count<0:raise ValueError('Negative counter')
            except FileNotFoundError:
                count=0;until=now+seconds
            except (ValueError,KeyError,TypeError):

                raise TimeoutError('Workspace account budget needs repair') from None
            if until<=now:
                count=0;until=now+seconds
            granted = min(units, max(0, maximum-count))
            if not granted:return 0, until
            tempfd,temporary=tempfile.mkstemp(prefix=key+'.',dir=root)
            with os.fdopen(tempfd,'w') as output:
                json.dump({'count':count+granted,'until':until},output,separators=(',',':'))
            os.replace(temporary,path)
            temporary=None
            return granted, until
        finally:
            if temporary:
                try:os.unlink(temporary)
                except FileNotFoundError:pass
            fcntl.flock(lock,fcntl.LOCK_UN)


def reserve(account_id, kind, maximum, seconds=60):
    granted, _ = _reserve_units(account_id, kind, maximum, seconds, 1)
    return bool(granted)


def reserve_read(account_id, maximum, seconds=60):

    account_id = int(account_id)
    maximum, seconds = int(maximum), int(seconds)
    key = (os.path.abspath(current_app.instance_path), account_id)

    with _lease_lock:
        entry = _read_leases.get(key)
        if entry:
            remaining, until, deadline, old_maximum, old_seconds = entry
            if (remaining > 0 and time.time() < until and time.monotonic() < deadline
                    and (maximum, seconds) == (old_maximum, old_seconds)):
                if remaining > 1:
                    _read_leases[key] = (remaining-1, until, deadline, maximum, seconds)
                else:
                    _read_leases.pop(key, None)
                return True
            _read_leases.pop(key, None)
    granted, until = _reserve_units(account_id, 'read', maximum, seconds, min(4, maximum))
    if not granted:
        return False
    if granted > 1:
        deadline = time.monotonic() + max(0, min(seconds, until-time.time()))
        with _lease_lock:
            if len(_read_leases) >= 4096:
                _read_leases.clear()

            _read_leases[key] = (granted-1, until, deadline, maximum, seconds)
    return True
