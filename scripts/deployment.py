
import ast
import fcntl
import ipaddress
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

PANEL_UNITS = ('wg-panel.service', 'WG_Panel.service', 'wg_panel.service', 'wgpanel.service')
NODE_UNITS = ('wg-node-agent.service', 'wg-panel-agent.service', 'wg-node.service', 'wg_panel_agent.service', 'wgpanel-agent.service')
WORKER_UNITS = ('wg-panel-bot.service', 'wg-monitor.service', 'wg-provision.service', 'wg-reseller-worker.service', 'wg-plan-shop.service')
WATCHDOG = 'wg-reseller-watchdog.timer'
PROTECTED = {'.git', '.env', 'instance', 'venv', '.venv', 'backups', 'restore_snapshots', 'node_modules', '__pycache__', '.pytest_cache', '.mypy_cache', '.panel-update-backups', 'update_backups', 'db'}
PROTECTED_SUFFIXES = ('.pyc', '.pyo', '.db', '.sqlite', '.sqlite3', '.db-wal', '.db-shm', '.sqlite-wal', '.sqlite-shm', '.sqlite3-wal', '.sqlite3-shm', '.log', '.pem', '.key', '.p12', '.zip', '.tar', '.tar.gz', '.bak')
WORKER_PROGRESS = {'wg-reseller-worker.service': ('workspace-bots',), 'wg-provision.service': ('provision-lane-0','provision-lane-1','provision-results'), 'wg-monitor.service': ('quota-monitor','reseller-history-cleanup'), 'wg-plan-shop.service': ('plan-shop','plan-shop-delivery','plan-shop-notices','purchase-alerts')}


def protected(name):
    return (name in PROTECTED or name.startswith('.env.') and name not in ('.env.example','.env.sample')
            or name.lower().endswith(PROTECTED_SUFFIXES+('.env',)))


@contextmanager
def deployment_lock(root):
    directory = Path(root) / 'instance'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = directory / 'update.lock'
    fd = os.open(directory / 'update.guard', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('A deployment or snapshot is already running.') from None
        
        if legacy_active(marker):
            raise RuntimeError('An older updater is still running.')
        tmp_fd, tmp = tempfile.mkstemp(prefix='.update-pid-', dir=directory)
        try:
            with os.fdopen(tmp_fd, 'w') as stream:
                stream.write(str(os.getpid()))
            os.replace(tmp, marker)
            yield
        finally:
            Path(tmp).unlink(missing_ok=True)
            marker.unlink(missing_ok=True)


def legacy_active(marker):
    try:
        pid = int(Path(marker).read_text())
        if pid <= 1:
            return False
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except (OSError, ValueError):
        return False


def lock_active(root):
    directory = Path(root) / 'instance'
    try:
        fd = os.open(directory / 'update.guard', os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r') as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
    except FileNotFoundError:
        pass
    except OSError:
        return True
    return legacy_active(directory / 'update.lock')


def code_files(root):
    root = Path(root)
    result = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not protected(name) and not (Path(directory)/name).is_symlink()]
        for name in files:
            path = Path(directory)/name
            if not protected(name) and not path.is_symlink() and path.is_file():
                result.add(path.relative_to(root))
    return result


def validate_destinations(source, root):
    for relative in code_files(source):
        target = Path(root)
        for part in relative.parts:
            target = target / part
            if target.is_symlink():
                raise RuntimeError('Unsafe symlink in deployment destination: '+str(relative))
            if target.exists() and target != Path(root)/relative and not target.is_dir():
                raise RuntimeError('Deployment destination is not a directory: '+str(relative))
        if target.exists() and not target.is_file():
            raise RuntimeError('Deployment destination is not a regular file: '+str(relative))


def overlay(source, root, *, remove=(), include=None):
    source, root = Path(source), Path(root)
    validate_destinations(source, root)
    incoming = code_files(source) if include is None else set(include)
    
    for relative in sorted(set(remove) - incoming):
        if relative.is_absolute() or '..' in relative.parts or any(protected(part) for part in relative.parts):
            continue
        target = root/relative
        if target.is_file() and not any(p.is_symlink() for p in (target,*target.parents) if p != root.parent):
            target.unlink()
    for relative in sorted(incoming):
        target = root/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.deploy-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as out, (source/relative).open('rb') as inp:
                shutil.copyfileobj(inp, out)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temp, stat.S_IMODE((source/relative).stat().st_mode) & 0o755)
            os.replace(temp, target)
        finally:
            Path(temp).unlink(missing_ok=True)


def schema_signature(path, names):
    tree = ast.parse(Path(path).read_text())
    return {node.name: ast.dump(node, include_attributes=False) for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names}


def check_compatible(root, source, scope):
    root, source = Path(root), Path(source)
    files = ('agent/requirements.txt', 'agent/requirements.in') if scope == 'node' else (
        'models.py','reseller_portal/models.py','reseller_portal/database.py','config.py',
        'requirements.txt','requirements-postgres.txt','requirements.in','reseller_portal/install_worker.py')
    for name in files:
        a,b = root/name,source/name
        if a.is_file()!=b.is_file() or (a.is_file() and a.read_bytes()!=b.read_bytes()):
            raise RuntimeError('Migration, dependency or service definition change requires a manual upgrade: '+name)
    if scope == 'panel':
        migrations = {'_admin_columns','_peer_schema','_interface_schema','_shortlink_schema','_migrate_schema','_migrate_schema_locked','_migrate_shortlinks_json_to_db','_repair_legacy_timer_rows','_backfill_peer_address_hosts','_latest_peer_timer_event_ts','_assign_repaired_expiry','bootstrap'}
        for name, funcs in [('app.py', migrations), ('reseller_portal/__init__.py', {'migrate','init_schema'})]:
            if schema_signature(root/name,funcs)!=schema_signature(source/name,funcs):
                raise RuntimeError('Schema migration code changed; manual upgrade required: '+name)
        for name in ('backend/database_migrations.py', 'backend/bootstrap.py', 'backend/context.py'):
            a, b = root/name, source/name
            if a.is_file() != b.is_file() or (a.is_file() and a.read_bytes() != b.read_bytes()):
                raise RuntimeError('Database bootstrap or migration binding changed; manual upgrade required: '+name)


def validate_source(root, scope):
    root = Path(root)
    required = ('app.py','models.py','config.py','reseller_portal/worker.py','telegram_bot.py') if scope=='panel' else ('agent/node_agent.py','agent/node.py')
    if any(not (root/name).is_file() for name in required):
        raise RuntimeError('Incomplete source tree.')
    if scope == 'panel':
        tree = ast.parse((root/'app.py').read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            package = node.module.split('.')[0]
            if package not in ('routes', 'services', 'backend'):
                continue
            base = root/package
            if not (base/'__init__.py').is_file():
                raise RuntimeError('Incomplete backend package: '+package)
            modules = ([node.module.replace('.', '/')+'.py'] if '.' in node.module else
                       [package+'/'+alias.name+'.py' for alias in node.names])
            for module in modules:
                if not (root/module).is_file():
                    raise RuntimeError('Incomplete backend module: '+module)
    for relative in code_files(root):
        if relative.suffix == '.py':
            compile((root/relative).read_bytes(), str(relative), 'exec')


def systemctl(*args, check=True, timeout=120):
    result = subprocess.run(['systemctl',*args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('systemctl '+args[0]+' failed for '+', '.join(args[1:]))
    return result


def unit_info(name):
    result = systemctl('show',name,'--property=LoadState,ActiveState,SubState,MainPID,NRestarts,ExecStart,WorkingDirectory',check=False,timeout=15)
    if result.returncode:
        return {}
    return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)


def discover_services(root, scope, preferred='auto'):
    root = str(Path(root).resolve())
    primary = PANEL_UNITS if scope=='panel' else NODE_UNITS
    if preferred not in ('auto','','detect'):
        if preferred not in primary:
            raise RuntimeError('Unsupported primary unit; use a documented unit name.')
        primary = (preferred,)+tuple(x for x in primary if x!=preferred)
    other = NODE_UNITS if scope=='panel' else PANEL_UNITS+WORKER_UNITS
    for name in other:
        info = unit_info(name)
        if info.get('ActiveState') in ('active','activating','deactivating','reloading') and (info.get('WorkingDirectory','').rstrip('/') in (root,root+'/agent') or root+'/' in info.get('ExecStart','')):
            raise RuntimeError('Panel and node share an active source tree; use coordinated manual maintenance.')
    candidates = primary + (WORKER_UNITS+(WATCHDOG,) if scope=='panel' else ())
    active = []
    for name in candidates:
        info = unit_info(name)
        if info.get('LoadState') in (None,'not-found'):
            continue
        if info.get('ActiveState') in ('activating','deactivating','reloading'):
            raise RuntimeError('Service transitioning: '+name)
        if info.get('ActiveState') != 'active':
            continue
        
        if name != WATCHDOG and not (info.get('WorkingDirectory','').rstrip('/') in (root,root+'/agent') or root+'/' in info.get('ExecStart','')):
            raise RuntimeError('Active service belongs to a different installation: '+name)
        active.append(name)
    if sum(name in primary for name in active)!=1:
        raise RuntimeError('Exactly one active primary service is required; use manual maintenance.')
    return active


def stop_services(services):
    
    if WATCHDOG in services:
        systemctl('stop',WATCHDOG)
    units = [name for name in services if name!=WATCHDOG]
    if units:
        systemctl('stop',*units,timeout=180)
    for name in services:
        if unit_info(name).get('ActiveState') not in ('inactive','failed'):
            raise RuntimeError('Service did not stop: '+name)


def readiness_config(root, scope):
    root=Path(root)
    try:
        from dotenv import dotenv_values
        env=dotenv_values(root/('agent/.env' if scope=='node' else '.env'))
    except ImportError:
        raise RuntimeError('Deployment must use the installed service virtual environment.') from None
    
    key=str(env.get('API_KEY') or '').strip()
    if not key:
        raise RuntimeError('Missing API_KEY in service configuration; manual deployment required.')
    explicit=str(env.get('WG_DEPLOY_HEALTH_URL') or os.getenv('WG_DEPLOY_HEALTH_URL') or '').strip()
    path='/api/system/healthz' if scope=='node' else '/api/healthz'
    if explicit:
        url=explicit
    else:
        if scope=='node':
            tls=bool(env.get('AGENT_SSL_CERT') and env.get('AGENT_SSL_KEY'))
            bind=env.get('BIND') or '0.0.0.0:'+str(env.get('PORT') or '9898')
        else:
            def read(name):
                try:
                    data=json.loads((root/'instance'/name).read_text())
                    return data if isinstance(data,dict) else {}
                except FileNotFoundError:return {}
            settings=read('panel_settings.json');runtime=read('runtime.json')
            tls=bool(settings.get('tls_enabled'))
            bind=env.get('BIND') or runtime.get('bind') or str(env.get('BIND_HOST') or '0.0.0.0')+':'+str(runtime.get('port') or settings.get('http_port') or 8000)
        if tls:
            raise RuntimeError('Configure WG_DEPLOY_HEALTH_URL with a trusted HTTPS health endpoint before automatic deployment.')
        address=urlsplit('http://'+str(bind));host=address.hostname or ''
        if host=='0.0.0.0':host='127.0.0.1'
        elif host=='::':host='::1'
        if ':' in host:host='['+host+']'
        url='http://'+host+':'+str(address.port or (9898 if scope=='node' else 8000))+path
    parsed=urlsplit(url)
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or not parsed.hostname or not parsed.path.endswith(path):
        raise RuntimeError('Invalid deployment readiness URL.')
    if parsed.scheme=='http':
        try:local=ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:local=parsed.hostname=='localhost'
        if not local:raise RuntimeError('An HTTP readiness URL must use loopback; otherwise use trusted HTTPS.')
    elif parsed.scheme!='https':raise RuntimeError('Readiness URL must use HTTP or HTTPS.')
    return url,key


def readiness_ok(config):
    import requests
    url,key=config
    try:
        response=requests.get(url,headers={'Authorization':'Bearer '+key},timeout=(2,5),allow_redirects=False)
        return response.status_code==200 and response.json().get('ok') is True
    except (requests.RequestException,ValueError,AttributeError):
        return False


def start_services(root, services, *, wait=90, readiness=None):
    started = time.time()
    for name in services:
        if name!=WATCHDOG:
            systemctl('start',name,timeout=120)
    deadline = time.monotonic()+wait
    stable_since = None
    previous = None
    while time.monotonic()<deadline:
        infos = [unit_info(name) for name in services if name!=WATCHDOG]
        identity = [(i.get('MainPID'),i.get('NRestarts')) for i in infos]
        ready = all(i.get('ActiveState')=='active' and i.get('MainPID','0') not in ('','0') for i in infos)
        if ready:
            for name in services:
                for component in WORKER_PROGRESS.get(name,()):
                    try:
                        data=json.loads((Path(root)/'instance'/'worker-health'/(component+'.json')).read_text())
                        if data.get('state')!='running' or float(data['at'])<started:
                            ready=False
                    except (OSError,ValueError,TypeError,KeyError):
                        ready=False
        if ready and readiness is not None:
            ready=readiness_ok(readiness)
        if ready and identity==previous:
            if stable_since is None:stable_since=time.monotonic()
            if time.monotonic()-stable_since>=3:
                if WATCHDOG in services:systemctl('start',WATCHDOG)
                return
        else:
            stable_since=None
        previous=identity
        time.sleep(.5)
    raise RuntimeError('Service startup or fresh worker progress could not be verified.')


def select_scope(source, scope):
    source = Path(source)
    if scope=='panel':
        return code_files(source)
    return {p for p in code_files(source) if p.parts[0] in ('agent','scripts','VERSION')}


def load_manifest(root, scope):
    path = Path(root)/'instance'/('deployment_files_'+scope+'.json')
    try:
        data=json.loads(path.read_text())
        if not isinstance(data,list):return set()
        paths={Path(item) for item in data if isinstance(item,str)}
        return {p for p in paths if p.parts and not p.is_absolute() and '..' not in p.parts and not any(protected(x) for x in p.parts)}
    except (OSError,ValueError,TypeError):
        return set()


def save_manifest(root,scope,paths):
    path=Path(root)/'instance'/('deployment_files_'+scope+'.json')
    fd,temp=tempfile.mkstemp(prefix='.manifest-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(sorted(str(p) for p in paths),stream)
        os.replace(temp,path)
    finally:Path(temp).unlink(missing_ok=True)


def extract_zip(archive, destination):
    import zipfile
    destination = Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        members=z.infolist();seen=set();total=0
        if not members or len(members)>30000:raise ValueError('Invalid ZIP entry count.')
        for item in members:
            rel=Path(item.filename)
            mode=(item.external_attr>>16)&0xffff
            if not rel.parts or rel.is_absolute() or '..' in rel.parts or '\\' in item.filename or rel.as_posix() in seen or stat.S_IFMT(mode) not in (0,stat.S_IFDIR,stat.S_IFREG) or mode&0o6000:
                raise ValueError('Unsafe ZIP entry.')
            seen.add(rel.as_posix());total+=item.file_size
            if total>800*1024*1024:raise ValueError('ZIP exceeds extraction limits.')
        for item in members:
            path=destination/item.filename
            if item.is_dir():path.mkdir(parents=True,exist_ok=True)
            else:
                path.parent.mkdir(parents=True,exist_ok=True)
                with z.open(item) as src,path.open('xb') as dst:shutil.copyfileobj(src,dst,1024*1024)
                path.chmod(0o755 if (item.external_attr>>16)&0o111 else 0o644)
    return destination
