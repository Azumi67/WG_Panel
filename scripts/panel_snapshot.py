#!/usr/bin/env python3
import argparse
import datetime as dt
import os
from pathlib import Path
from panel_update import Status, backup_code, deploy


def create_snapshot(root, status_path):
    root = Path(root).resolve()
    with deploy.deployment_lock(root):
        status = Status(Path(status_path))
        try:
            name = 'panel_' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S') + '.tar.gz'
            status.set(status='running', stage='backup', percent=20, message='Creating code snapshot')
            backup_code(root, root / 'instance' / 'update_backups' / name)
            status.set(status='success', stage='complete', percent=100,
                       message='Code snapshot ready to download', snapshot=name)
        except Exception as exc:
            status.set(status='failed', stage='failed', percent=100, message=str(exc))
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--status', required=True)
    args = parser.parse_args()
    create_snapshot(args.root, args.status)
