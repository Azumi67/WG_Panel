#!/usr/bin/env python3

import argparse
import datetime as dt
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

from panel_update import Status, validate, safe_extract, apply_staged, utc, deploy

NAME = re.compile(r'^(?:panel|pre_manual)_[0-9]{8}_[0-9]{6}\.tar\.gz$')
SCHEMA = ('models.py', 'reseller_portal/models.py', 'reseller_portal/database.py', 'requirements.txt')

def selected_archive(root, name):
    if not NAME.fullmatch(name or ''):
        raise ValueError('Invalid update snapshot name')
    root = Path(root).resolve()
    directory = (root / 'instance' / 'update_backups').resolve()
    archive = directory / name
    if archive.is_symlink() or not archive.is_file() or archive.resolve().parent != directory:
        raise ValueError('Update snapshot unavailable')
    if archive.stat().st_size > 500 * 1024 * 1024:
        raise ValueError('Oversized update snapshot')
    return archive

def safe_stage(archive, dest):
    safe_extract(archive, dest, code_only=True)

def compatible(root, stage):
    try:
        deploy.check_compatible(root, stage, 'panel')
        return True
    except (RuntimeError, OSError, SyntaxError):
        return False


def run_rollback(root, name, status_file):
    root = Path(root).resolve()
    if os.getenv('DOCKER_MODE','').lower() in ('1','true','yes','on'):
        raise RuntimeError('Use the previous container image to roll back.')
    with deploy.deployment_lock(root):
        status = Status(Path(status_file))
        try:
            archive = selected_archive(root,name)
            status.set(status='running',stage='validate',percent=10,message='Validating selected code snapshot')
            with tempfile.TemporaryDirectory(prefix='wg-panel-manual-rollback-') as tmp:
                stage = Path(tmp)/'stage'; stage.mkdir()
                safe_stage(archive,stage)
                own_recovery = root/'instance'/'update_backups'/('pre_manual_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S')+'.tar.gz')
                if not apply_staged(root,stage,'panel',status,own_recovery,rollback_archive=archive):
                    raise SystemExit(1)
        except Exception as exc:
            status.set(status='rollback_failed',stage='rollback_failed',percent=100,message='Manual rollback refused or failed before deployment.',failure_detail=str(exc),completed_at=utc())
            raise

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',required=True)
    parser.add_argument('--backup-name',required=True)
    parser.add_argument('--status',required=True)
    args=parser.parse_args()
    run_rollback(args.root,args.backup_name,args.status)
