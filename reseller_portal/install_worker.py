#!/usr/bin/env python3

import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


def resource_directives():
    return '\n'.join(('CPUAccounting=yes','MemoryAccounting=yes','TasksAccounting=yes','IOAccounting=yes'))


SERVICES = {'workspace':'wg-reseller-worker.service', 'provision':'wg-provision.service',
            'monitor':'wg-monitor.service', 'shop':'wg-plan-shop.service'}
DESCRIPTIONS = {'workspace':'WG Panel reseller workspace bots', 'provision':'WG Panel customer provisioning',
                'monitor':'WG Panel reseller usage monitoring and history maintenance',
                'shop':'WG Panel plan shop and purchase notifications'}
RUN_ROLES = {'workspace':'workspace-bots', 'provision':'provision', 'monitor':'monitor', 'shop':'shop'}


def make_unit(panel, python, role='workspace'):
    if role not in SERVICES:raise ValueError('Unknown service role.')
    accounting=resource_directives()
    panel=Path(panel).absolute(); python=Path(python).absolute()
    for value in (str(panel),str(python)):
        if any(c.isspace() or c in '%"\\' for c in value):
            raise ValueError('Use paths without whitespace, %, quotes or backslashes.')
    if not (panel/'app.py').is_file() or not (panel/'reseller_portal/worker.py').is_file() or not (panel/'reseller_portal/management_bot.py').is_file():
        raise ValueError('Panel source is incomplete.')
    if not python.is_file(): raise ValueError('Python executable was not found.')
    if not (panel/'.env').is_file(): raise ValueError('Existing panel .env is required. Do not generate replacement keys.')
    return f'''[Unit]
Description={DESCRIPTIONS[role]}
After=network-online.target wg-panel.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={panel}
EnvironmentFile={panel}/.env
Environment=PYTHONUNBUFFERED=1
ExecStart={python} -m reseller_portal.worker --role {RUN_ROLES[role]}
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=mixed
UMask=0077
{accounting}

[Install]
WantedBy=multi-user.target
'''


UNIT_DIR = Path('/etc/systemd/system')


def main():
    parser=argparse.ArgumentParser(description='Install independent WG Panel worker services.')
    parser.add_argument('--install',action='store_true',help='Write the service and start/restart the worker.')
    parser.add_argument('--prepare-only', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--watchdog',action='store_true',help='Install the optional read-only progress watchdog timer.')
    parser.add_argument('--python',type=Path,default=Path(sys.executable),help='Existing panel virtual environment Python.')
    parser.add_argument('--role', choices=('all','both',*SERVICES), default='all')
    args=parser.parse_args()
    if args.prepare_only and (not args.install or args.watchdog or args.role not in ('all','both')):
        parser.error('Preparation requires installing all worker definitions without starting them.')
    roles=list(SERVICES) if args.role in ('both','all') else [args.role]
    if args.install and os.geteuid()!=0: parser.error('--install requires root (sudo).')
    try: units={role:make_unit(Path(__file__).resolve().parents[1],args.python,role) for role in roles}
    except ValueError as e: parser.error(str(e))
    if not args.install:
        for role,unit in units.items():print(SERVICES[role], unit, sep='\n')
        print('Preview only. Use --install to apply these services.')
        return
    if not shutil.which('systemctl'): parser.error('systemd is required.')
    directory = UNIT_DIR
    old_workspace = directory/SERVICES['workspace']
    if len(roles)!=len(SERVICES) and (not old_workspace.exists() or
            '--role workspace-bots' not in old_workspace.read_text() or
            not all((directory/name).exists() for name in SERVICES.values())):
        parser.error('Install all services together once to migrate from the combined workspace worker.')
    
    
    names=[SERVICES[role] for role in roles]
    existing=[name for name in names if subprocess.run(['systemctl','cat',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0]
    previous={name:(directory/name).read_bytes() if (directory/name).is_file() else None for name in names}
    active_before={name for name in existing if subprocess.run(['systemctl','is-active','--quiet',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0}
    enabled_before={name for name in existing if subprocess.run(['systemctl','is-enabled','--quiet',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0}
    changed=False
    try:
        if existing:
            subprocess.run(['systemctl','stop',*existing],check=True)
        for name in existing:
            status=subprocess.run(['systemctl','show','-p','ActiveState','--value',name],check=True,capture_output=True,text=True).stdout.strip()
            if status not in ('inactive','failed'):
                raise RuntimeError(name+' has not stopped; refusing to overlap workers.')
        changed=True
        for role, unit in units.items():
            path = directory/SERVICES[role]
            if path.exists() and path.read_text() == unit:continue
            if args.prepare_only and SERVICES[role] in existing:
                current = subprocess.run(['systemctl','show','--property=ExecStart','--value',SERVICES[role]],check=True,capture_output=True,text=True).stdout
                if re.search(r'--role\s+' + re.escape(RUN_ROLES[role]) + r'(?:\s|;|$)', current):
                    continue
            if path.exists():
                backup=path.with_name(path.name+'.backup-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
                shutil.copy2(path,backup)
            with tempfile.NamedTemporaryFile('w',dir=directory,delete=False) as tmp:
                tmp.write(unit)
            os.chmod(tmp.name,0o644)
            os.replace(tmp.name,path)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        for role in ('monitor','provision','workspace','shop'):
            if role not in roles:continue
            name=SERVICES[role]
            subprocess.run(['systemctl','enable',name],check=True)
            if not args.prepare_only:
                subprocess.run(['systemctl','start',name],check=True)
                subprocess.run(['systemctl','is-active','--quiet',name],check=True)
                print(name+' is active (check progress health after startup).')
    except Exception:
        if changed:
            
            subprocess.run(['systemctl','stop',*names],check=True)
            for name,data in previous.items():
                path=directory/name
                if data is None:
                    subprocess.run(['systemctl','disable',name],check=False)
                    path.unlink(missing_ok=True)
                else:
                    with tempfile.NamedTemporaryFile('wb',dir=directory,delete=False) as tmp:
                        tmp.write(data)
                    os.chmod(tmp.name,0o644);os.replace(tmp.name,path)
            subprocess.run(['systemctl','daemon-reload'],check=True)
            for name in existing:
                subprocess.run(['systemctl','enable' if name in enabled_before else 'disable',name],check=True)
        for name in names:
            if name in active_before:subprocess.run(['systemctl','start',name],check=True)
        raise
    if args.watchdog:
        panel=Path(__file__).resolve().parents[1]
        watchdog=panel/'reseller_portal'/'wg-reseller-watchdog.service'
        unit=watchdog.read_text().replace('/usr/local/bin/WG_Panel/venv/bin/python','__WORKER_PYTHON__').replace('/usr/local/bin/WG_Panel',str(panel)).replace('__WORKER_PYTHON__',str(args.python.absolute()))
        timer=(panel/'reseller_portal'/'wg-reseller-watchdog.timer').read_text()
        for name,content in (('wg-reseller-watchdog.service',unit),('wg-reseller-watchdog.timer',timer)):
            path=directory/name
            if path.exists() and path.read_text()!=content:
                shutil.copy2(path,path.with_name(path.name+'.backup-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')))
            with tempfile.NamedTemporaryFile('w',dir=directory,delete=False) as tmp:
                tmp.write(content)
            os.chmod(tmp.name,0o644)
            os.replace(tmp.name,path)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','enable','--now','wg-reseller-watchdog.timer'],check=True)
        print('Read-only watchdog timer enabled. It reports stale loops; it does not restart them.')
    print('Plan shop: connect its token in Resellers > Plan shop bot. Workspace bots: enable Telegram in Manage account, then connect each token in the reseller workspace.')


if __name__=='__main__': main()
