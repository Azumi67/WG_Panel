import fcntl
import json
import os
import signal
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path


ROLE_COMPONENTS = {
    'workspace-bots': ('workspace-bots',),
    'provision': ('provision',),
    'monitor': ('monitor',),
    'shop': ('shop',),
    'workspace': ('workspace-bots', 'provision', 'monitor'),
    'combined': ('workspace-bots', 'provision', 'monitor', 'shop'),
}
LOCK_NAMES = {'workspace-bots': 'reseller-worker.lock', 'shop': 'reseller-plan-shop.lock',
              'provision': 'reseller-provision.lock', 'monitor': 'reseller-monitor.lock'}
HEALTH_GROUPS = {
    'worker': ('workspace-bots',),
    'provision': ('provision-lane-0', 'provision-lane-1', 'provision-results'),
    'monitor': ('quota-monitor', 'reseller-history-cleanup'),
    'shop_worker': ('plan-shop', 'plan-shop-delivery', 'plan-shop-notices', 'purchase-alerts'),
}
ROLE_HEALTH_GROUP = {'workspace-bots':'worker','provision':'provision','monitor':'monitor','shop':'shop_worker'}
THRESHOLDS = {'reseller-history-cleanup': 420, 'quota-monitor': 180,
              'provision-lane-0': 180, 'provision-lane-1': 180,
              'provision-results': 180, 'plan-shop-notices': 240, 'purchase-alerts': 240}
_local = threading.local()


@contextmanager
def role_lock(instance, role):
    Path(instance).mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        for component in sorted(ROLE_COMPONENTS[role]):
            path = Path(instance) / LOCK_NAMES[component]
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            handle = stack.enter_context(os.fdopen(fd, 'r+'))
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError(f'The {component} worker is already running on this installation.') from None
        yield


def record(instance, component, state, *, now=None):
    directory = Path(instance) / 'worker-health'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    at = time.time() if now is None else now
    fd, path = tempfile.mkstemp(prefix='.'+component+'-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'state': state, 'at': at, 'pid': os.getpid()}, stream)
        os.replace(path, directory / (component+'.json'))
    finally:
        if os.path.exists(path):
            os.unlink(path)


def pulse():
    context = getattr(_local, 'context', None)
    if context is None:
        return
    instance, component, logger = context
    now = time.monotonic()
    if now - getattr(_local, 'last', -1e9) >= 15:
        try:
            record(instance, component, 'running')
        except OSError:
            logger.warning('Could not update worker progress: %s', component)
        else:
            _local.last = now


def component_status(instance, component, now=None):
    now = time.time() if now is None else now
    try:
        data = json.loads((Path(instance)/'worker-health'/(component+'.json')).read_text())
        at = float(data['at'])
        if not 0 < at <= now+10:
            raise ValueError('Invalid timestamp')
        age = max(0, int(now-at))
        state = data['state']
        if state not in ('starting','running','stopped','failed'):
            raise ValueError('Invalid state')
        ready = state == 'running' and age <= THRESHOLDS.get(component, 120)
        return {'state': 'ready' if ready else 'stale', 'label': 'Running' if ready else ('Progress stale' if state=='running' else state.capitalize()),
                'at': datetime.fromtimestamp(at, timezone.utc).isoformat(), 'age': age}
    except FileNotFoundError:
        return {'state':'missing','label':'Not started','at':None,'age':None}
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return {'state':'stale','label':'Invalid health record','at':None,'age':None}


def group_status(instance, group, now=None):
    parts = {name: component_status(instance, name, now) for name in HEALTH_GROUPS[group]}
    bad = [name for name, state in parts.items() if state['state']!='ready']
    ages = [x['age'] for x in parts.values() if x['age'] is not None]
    stamps = [x['at'] for x in parts.values() if x['at'] is not None]
    return {'state': 'ready' if not bad else ('missing' if all(x['state']=='missing' for x in parts.values()) else 'stale'),
            'label': 'Running' if not bad else ('Not started' if not stamps else 'Needs attention'),
            'unhealthy': bad,
            'at': min(stamps) if stamps else None, 'age': max(ages) if ages else None, 'components': parts}


@contextmanager
def stop_signals(stop):
    previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def supervise(jobs, stop, instance, logger, *, shutdown_timeout=45, poll_interval=.2):

    failures = []
    threads = []
    def run(fn, args, name):
        _local.context = (instance, name, logger)
        _local.last = -1e9
        failed = False
        try:
            record(instance, name, 'starting')
            fn(*args)
            if not stop.is_set():
                failed = True
                logger.error('Essential worker returned unexpectedly: %s', name)
        except BaseException as exc:
            failed = True
            logger.error('Essential worker failed: %s (%s)', name, type(exc).__name__)
        finally:
            if failed:
                failures.append(name)
            try:
                record(instance, name, 'failed' if failed else 'stopped')
            except OSError:
                logger.warning('Could not record worker exit: %s', name)
            if failed:
                stop.set()
    try:
        for fn, args, name in jobs:
            if stop.is_set():
                break
            thread = threading.Thread(target=run, args=(fn,args,name), name=name, daemon=True)
            thread.start()
            threads.append(thread)
        while not stop.wait(poll_interval):
            if any(not t.is_alive() for t in threads):
                break
    finally:
        stop.set()
        deadline = time.monotonic()+shutdown_timeout
        for thread in threads:
            thread.join(max(0,deadline-time.monotonic()))
    stuck = [t.name for t in threads if t.is_alive()]
    if stuck:
        for name in stuck:
            try:record(instance, name, 'failed')
            except OSError:pass
        logger.error('Worker shutdown deadline exceeded: %s', ', '.join(stuck))
        
        
        raise ShutdownTimeout(', '.join(stuck))
    if failures:
        raise RuntimeError('Essential worker failed: '+', '.join(failures))


class ShutdownTimeout(RuntimeError):
    pass
