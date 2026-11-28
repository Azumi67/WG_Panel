#!/usr/bin/env python3

from __future__ import annotations
import re
import argparse, datetime as dt, json, os, shutil, subprocess, sys, tarfile, tempfile, time
from pathlib import Path
from urllib.request import Request, urlopen

try:
    from . import deployment as deploy
except ImportError:
    import deployment as deploy

EXCLUDES = {
    ".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    "instance", ".env", "backups", "restore_snapshots",
}

def atm_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.update-status-', dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(payload,stream,indent=2)
            stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:
        Path(tmp).unlink(missing_ok=True)

class Status:
    def __init__(self, path: Path):
        self.path = path
        self.data = {
            "status": "queued", "stage": "queued", "percent": 1,
            "message": "Update queued.", "started_at": utc(), "updated_at": utc(),
            "log": [], "backup": "", "target": "latest",
        }
        atm_json(self.path, self.data)

    def set(self, status=None, stage=None, percent=None, message=None, log=None, **extra):
        if status is not None: self.data["status"] = status
        if stage is not None: self.data["stage"] = stage
        if percent is not None: self.data["percent"] = int(percent)
        if message is not None: self.data["message"] = str(message)
        if log:
            self.data.setdefault("log", []).append(str(log))
            self.data["log"] = self.data["log"][-80:]
        self.data.update(extra)
        self.data["updated_at"] = utc()
        atm_json(self.path, self.data)

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def run(cmd, cwd=None, timeout=1200, check=True):
    p = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str,cmd))} failed ({p.returncode}):\n{p.stdout[-4000:]}")
    return p

def github_main_metadata(repo: str) -> dict:

    revision = ""
    commit_date = ""
    url = f"https://github.com/{repo}/commits/main"

    git = shutil.which("git")
    if git:
        try:
            result = run(
                [
                    git,
                    "ls-remote",
                    f"https://github.com/{repo}.git",
                    "refs/heads/main",
                ],
                timeout=45,
                check=False,
            )
            if result.returncode == 0:
                first = (result.stdout or "").strip().splitlines()
                if first:
                    candidate = first[0].split()[0].strip()
                    if re.fullmatch(r"[0-9a-f]{40}", candidate):
                        revision = candidate
        except Exception:
            pass

    if not revision:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "WG-Panel-Updater",
            "Cache-Control": "no-cache",
        }
        token = (
            os.getenv("GITHUB_TOKEN")
            or os.getenv("GH_TOKEN")
            or ""
        ).strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            request = Request(
                f"https://api.github.com/repos/{repo}/commits/main",
                headers=headers,
            )
            with urlopen(request, timeout=30) as response:
                payload = json.loads(
                    response.read().decode("utf-8", "replace")
                )
            revision = str(payload.get("sha") or "").strip()
            commit = payload.get("commit") or {}
            author = commit.get("author") or {}
            commit_date = str(author.get("date") or "").strip()
            url = str(payload.get("html_url") or url).strip()
        except Exception:
            pass

    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("Could not resolve the GitHub main commit")
    return {
        "revision": revision,
        "revision_short": revision[:8],
        "commit_date": commit_date,
        "url": url,
    }


def download_repo(repo: str, target: str, dest: Path) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Invalid GitHub repository")
    if target != "main":
        raise ValueError("Only the main update channel is supported")
    metadata = github_main_metadata(repo)
    revision = metadata["revision"]
    urls = [
        f"https://codeload.github.com/{repo}/tar.gz/{revision}",
        f"https://github.com/{repo}/archive/{revision}.tar.gz",
    ]

    errors = []

    for url in urls:
        for attempt in range(1, 4):
            try:
                request = Request(
                    url,
                    headers={
                        "User-Agent": "WG-Panel-Updater",
                        "Accept": "application/octet-stream",
                        "Cache-Control": "no-cache",
                    },
                )

                with (
                    urlopen(request, timeout=120) as response,
                    open(dest, "wb") as output,
                ):
                    size = 0
                    deadline = time.monotonic() + 180
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > 500 * 1024 * 1024 or time.monotonic() > deadline:
                            raise RuntimeError("Archive download exceeded its limit")
                        output.write(chunk)

                if dest.stat().st_size < 1024:
                    raise RuntimeError(
                        "Downloaded archive is unexpectedly small."
                    )

                with tarfile.open(dest, "r:gz") as archive:
                    if next(iter(archive), None) is None:
                        raise RuntimeError("Downloaded archive is empty.")

                metadata["archive_url"] = url
                return metadata

            except Exception as exc:
                errors.append(f"{url} attempt {attempt}: {exc}")
                try:
                    dest.unlink(missing_ok=True)
                except Exception:
                    pass
                if attempt < 3:
                    time.sleep(attempt * 2)

    raise RuntimeError(
        "Could not download the WG_Panel main branch. "
        + " | ".join(errors[-6:])
    )


def write_update_source(
    root: Path,
    scope: str,
    metadata: dict,
):
    marker = (
        root
        / "instance"
        / (
            "update_source_node.json"
            if scope == "node"
            else "update_source_panel.json"
        )
    )

    version = ""

    try:
        version = (
            (root / "VERSION")
            .read_text(encoding="utf-8")
            .strip()
            .lstrip("vV")
        )
    except Exception:
        pass

    payload = {
        "source": metadata.get("source", "main"),
        "target": metadata.get("target", "main"),
        "repo": metadata.get("repo"),
        "revision": metadata.get("revision"),
        "revision_short": metadata.get(
            "revision_short"
        ),
        "commit_date": metadata.get(
            "commit_date"
        ),
        "url": metadata.get("url"),
        "version": version,
        "installed_at": utc(),
    }

    atm_json(
        marker,
        payload,
    )

def excluded_name(name):
    return deploy.protected(name) or name in EXCLUDES


def safe_extract(archive, destination, code_only=False):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        members = []
        seen = set()
        for member in tar:
            rel = Path(member.name)
            if (not rel.parts or rel.is_absolute() or ".." in rel.parts
                    or "\\" in member.name or not (member.isdir() or member.isfile())
                    or member.mode & 0o6000 or rel.as_posix() in seen
                    or (code_only and any(excluded_name(part) for part in rel.parts))):
                raise ValueError("Unsafe archive entry")
            seen.add(rel.as_posix())
            total += max(member.size, 0)
            members.append(member)
            if len(members) > 30000 or total > 800 * 1024 * 1024:
                raise ValueError("Archive exceeds extraction limits")
        for member in members:
            path = destination / member.name
            if not path.resolve().is_relative_to(destination.resolve()) or path.is_symlink():
                raise ValueError("Unsafe extraction destination")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, path.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)


def backup_code(root: Path, backup_path: Path):
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    def include(member):
        parts = Path(member.name).parts
        if (any(excluded_name(part) for part in parts) or
                not (member.isfile() or member.isdir())):
            return None
        member.mode &= 0o777
        return member
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=backup_path.parent)
    os.close(fd)
    try:
        with tarfile.open(temporary, "w:gz") as tar:
            for item in root.iterdir():
                if not excluded_name(item.name):
                    tar.add(item, arcname=item.name, recursive=True, filter=include)
        os.chmod(temporary, 0o600)
        scope = 'node' if backup_path.name.startswith('node_') else 'panel'
        marker = root / 'instance' / f'update_source_{scope}.json'
        try:
            existing = json.loads(marker.read_text())
        except (OSError, ValueError):
            existing = {}
        if not isinstance(existing, dict):
            existing = {}
        revision = str(existing.get('revision') or '')
        if not revision and existing.get('source') != 'snapshot' and (root / '.git').is_dir():
            try:
                revision = run(['git', 'rev-parse', 'HEAD'], cwd=root, timeout=5).stdout.strip()
            except Exception:
                pass
        metadata = {'source': 'snapshot', 'revision': revision if re.fullmatch(r'[0-9a-fA-F]{40,64}', revision) else '',
                    'snapshot': backup_path.name, 'created_at': utc()}
        os.link(temporary, backup_path)
        atm_json(Path(str(backup_path) + '.json'), metadata)
    finally:
        Path(temporary).unlink(missing_ok=True)

def restore_source_metadata(root, backup_path):
    try:
        data = json.loads(Path(str(backup_path) + '.json').read_text())
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    revision = str(data.get('revision') or '')
    scope = 'node' if backup_path.name.startswith('node_') else 'panel'
    atm_json(root / 'instance' / f'update_source_{scope}.json', {
        'source': 'snapshot', 'snapshot': backup_path.name, 'installed_at': utc(),
        'revision': revision if re.fullmatch(r'[0-9a-fA-F]{40,64}', revision) else '',
    })


def copy_tree(src: Path, dst: Path):
    deploy.overlay(src, dst)


def restore_backup(root: Path, backup_path: Path, *, remove=()):
    with tempfile.TemporaryDirectory(prefix="wg-restore-") as tmp:
        stage = Path(tmp)
        safe_extract(backup_path, stage, code_only=True)
        deploy.overlay(stage, root, remove=remove)
        restore_source_metadata(root, backup_path)


def validate(root: Path, scope: str):
    deploy.validate_source(root, scope)

def _optional_nftables(log=None):

    import os
    import shutil
    import subprocess

    def emit(message):
        if callable(log):
            try:
                log(message)
            except Exception:
                pass

    nft = shutil.which("nft")

    if nft:
        version = ""

        try:
            version_result = subprocess.run(
                [nft, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
                check=False,
            )

            version = (
                version_result.stdout
                or ""
            ).strip()

        except Exception:
            pass

        try:
            usable_result = subprocess.run(
                [
                    nft,
                    "list",
                    "ruleset",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=8,
                check=False,
            )

            if usable_result.returncode == 0:
                return {
                    "ok": True,
                    "installed": True,
                    "usable": True,
                    "changed": False,
                    "status": "already_present",
                    "version": version,
                }

            return {
                "ok": False,
                "installed": True,
                "usable": False,
                "changed": False,
                "status": "installed_not_usable",
                "version": version,
                "detail": (
                    usable_result.stderr
                    or ""
                )[-1000:],
            }

        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "installed": True,
                "usable": False,
                "changed": False,
                "status": "check_timeout",
                "version": version,
            }

        except Exception as exc:
            return {
                "ok": False,
                "installed": True,
                "usable": False,
                "changed": False,
                "status": "check_failed",
                "version": version,
                "detail": str(exc),
            }

    apt_get = shutil.which("apt-get")

    if not apt_get:
        emit(
            "nftables is missing and apt-get is not available; "
            "continuing without Traffic Control enforcement."
        )

        return {
            "ok": False,
            "installed": False,
            "usable": False,
            "changed": False,
            "status": "unsupported_package_manager",
        }

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["APT_LISTCHANGES_FRONTEND"] = "none"

    common_options = [
        "-o",
        "Dpkg::Use-Pty=0",
        "-o",
        "DPkg::Lock::Timeout=30",
    ]

    try:
        emit(
            "nftables is missing; refreshing package metadata…"
        )

        update_result = subprocess.run(
            [
                apt_get,
                "update",
                "-o",
                "Dpkg::Use-Pty=0",
                "-o",
                "DPkg::Lock::Timeout=30",
                "-o",
                "Acquire::Retries=2",
                "-o",
                "Acquire::http::Timeout=20",
                "-o",
                "Acquire::https::Timeout=20",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
            check=False,
        )

        if update_result.returncode != 0:
            emit(
                "Could not refresh package metadata for nftables; "
                "the update will continue."
            )

            return {
                "ok": False,
                "installed": False,
                "usable": False,
                "changed": False,
                "status": "apt_update_failed",
                "detail": (
                    update_result.stdout
                    or ""
                )[-2000:],
            }

        emit(
            "Installing optional nftables dependency…"
        )

        install_result = subprocess.run(
            [
                apt_get,
                "install",
                "-y",
                "--no-install-recommends",
                *common_options,
                "nftables",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
            check=False,
        )

        if install_result.returncode != 0:
            emit(
                "nftables installation failed; "
                "the update will continue."
            )

            return {
                "ok": False,
                "installed": False,
                "usable": False,
                "changed": False,
                "status": "install_failed",
                "detail": (
                    install_result.stdout
                    or ""
                )[-2000:],
            }

    except subprocess.TimeoutExpired:
        emit(
            "nftables installation timed out; "
            "the update will continue."
        )

        return {
            "ok": False,
            "installed": False,
            "usable": False,
            "changed": False,
            "status": "timeout",
        }

    except Exception as exc:
        emit(
            "nftables installation could not be completed; "
            "the update will continue."
        )

        return {
            "ok": False,
            "installed": False,
            "usable": False,
            "changed": False,
            "status": "error",
            "detail": str(exc),
        }

    nft = shutil.which("nft")

    if not nft:
        return {
            "ok": False,
            "installed": False,
            "usable": False,
            "changed": False,
            "status": "binary_missing_after_install",
        }

    version = ""

    try:
        version_result = subprocess.run(
            [
                nft,
                "--version",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
            check=False,
        )

        version = (
            version_result.stdout
            or ""
        ).strip()

    except Exception:
        pass

    try:
        usable_result = subprocess.run(
            [
                nft,
                "list",
                "ruleset",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )

        if usable_result.returncode == 0:
            return {
                "ok": True,
                "installed": True,
                "usable": True,
                "changed": True,
                "status": "installed",
                "version": version,
            }

        return {
            "ok": False,
            "installed": True,
            "usable": False,
            "changed": True,
            "status": "installed_not_usable",
            "version": version,
            "detail": (
                usable_result.stderr
                or ""
            )[-1000:],
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "installed": True,
            "usable": False,
            "changed": True,
            "status": "check_timeout",
            "version": version,
        }

    except Exception as exc:
        return {
            "ok": False,
            "installed": True,
            "usable": False,
            "changed": True,
            "status": "check_failed",
            "version": version,
            "detail": str(exc),
        }
    
def install_requirements(root: Path, scope: str):
    pip = root / "venv/bin/pip"
    if scope == "node" and (root / "agent/venv/bin/pip").exists():
        pip = root / "agent/venv/bin/pip"
    req = root / "requirements.txt"
    if scope == "node" and (root / "agent/requirements.txt").exists():
        req = root / "agent/requirements.txt"
    if pip.exists() and req.exists():
        run([str(pip), "install", "-r", str(req)], timeout=1200)
        extra = root / 'requirements-postgres.txt'
        if scope != 'node' and extra.is_file():
            run([str(pip), 'install', '-r', str(extra)], timeout=1200)


def _service_names(scope: str) -> list[str]:
    return (
        ["wg-panel.service", "WG_Panel.service", "wg_panel.service", "wgpanel.service"]
        if scope == "panel"
        else [
            "wg-panel-agent.service",
            "wg-node.service",
            "wg_panel_agent.service",
            "wg-node-agent.service",
            "wgpanel-agent.service",
        ]
    )


def _systemd_exists(name: str) -> bool:
    result = run(
        ["systemctl", "show", name, "--property=LoadState", "--value"],
        timeout=12,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() not in {"", "not-found"}


def _unit_text(name: str) -> str:
    result = run(
        [
            "systemctl", "show", name,
            "--property=ExecStart",
            "--property=FragmentPath",
            "--property=Description",
        ],
        timeout=12,
        check=False,
    )
    return result.stdout or ""


def _listed_services(*, running_only: bool) -> list[str]:
    cmd = (
        [
            "systemctl", "list-units", "--type=service",
            "--state=running", "--no-legend", "--no-pager",
        ]
        if running_only
        else [
            "systemctl", "list-unit-files", "--type=service",
            "--no-legend", "--no-pager",
        ]
    )

    result = run(cmd, timeout=20, check=False)
    units = []

    for raw in (result.stdout or "").splitlines():
        name = raw.strip().split(None, 1)[0] if raw.strip() else ""
        if name.endswith(".service") and name not in units:
            units.append(name)

    return units


def detect_service(root: Path, scope: str) -> str:
    root_lower = str(root.resolve()).lower()

    tokens = (
        (root_lower, "/app.py", "gunicorn", "wg-panel", "wg_panel")
        if scope == "panel"
        else (
            root_lower,
            "/agent/node_agent.py",
            "/agent/node.py",
            "node_agent.py",
            "wg-panel-agent",
            "wg-node",
        )
    )

    scored = []

    for name in _listed_services(running_only=True):
        text = _unit_text(name).lower()
        score = 100 if root_lower and root_lower in text else 0

        for token in tokens[1:]:
            if token in text:
                score += 20

        if score:
            scored.append((score, name))

    if scored:
        scored.sort(reverse=True)
        return scored[0][1]

    for name in _service_names(scope):
        if _systemd_exists(name):
            return name

    for name in _listed_services(running_only=False):
        text = _unit_text(name).lower()

        if root_lower and root_lower in text:
            return name

        if scope == "panel" and "/app.py" in text and "gunicorn" in text:
            return name

        if scope == "node" and (
            "node_agent.py" in text
            or "/agent/node.py" in text
        ):
            return name

    raise RuntimeError(
        f"Could not automatically detect the systemd service for {scope} at {root}."
    )


def schedule_service_restart(
    service: str,
    *,
    scope: str,
) -> dict:
    unit_name = (
        f"wg-panel-rollback-restart-{scope}-"
        f"{int(time.time())}-{os.getpid()}"
    )

    systemd_run = shutil.which(
        "systemd-run"
    )

    if systemd_run:
        result = run(
            [
                systemd_run,
                "--unit",
                unit_name,
                "--collect",
                "--quiet",
                "--on-active=1s",
                "--property=Type=oneshot",
                "--",
                "systemctl",
                "restart",
                service,
            ],
            timeout=20,
            check=False,
        )

        if result.returncode == 0:
            return {
                "launcher": "systemd-run",
                "unit": f"{unit_name}.service",
            }

    log_path = Path(
        "/tmp"
    ) / f"{unit_name}.log"

    stream = open(
        log_path,
        "ab",
        buffering=0,
    )

    process = subprocess.Popen(
        [
            "systemctl",
            "restart",
            service,
        ],
        stdin=subprocess.DEVNULL,
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )

    return {
        "launcher": "subprocess",
        "pid": process.pid,
        "log": str(log_path),
    }


def apply_staged(root, source, scope, status, backup, *, preferred='auto', metadata=None, rollback_archive=None):

    root, source = Path(root), Path(source)
    validate(source, scope)
    deploy.check_compatible(root, source, scope)
    deploy.validate_destinations(source, root)
    services = deploy.discover_services(root, scope, preferred)
    readiness = deploy.readiness_config(root,scope)
    
    if not deploy.readiness_ok(readiness):
        raise RuntimeError('Current authenticated readiness endpoint is unavailable; use manual maintenance.')
    before = deploy.code_files(root)
    incoming = deploy.select_scope(source,scope)
    old_manifest = deploy.load_manifest(root,scope)
    introduced = incoming - before
    status.set(stage='backup', percent=45, message='Saving current code before maintenance.', services=services)
    backup_code(root, backup)
    status.set(backup=str(backup), stage='stop', percent=55, message='Stopping active panel services.')
    mutation_started = False
    try:
        deploy.stop_services(services)
        mutation_started = True
        status.set(stage='install', percent=65, message='Installing validated code; persistent data preserved.')
        deploy.overlay(source, root, remove=old_manifest-incoming, include=incoming)
        validate(root, scope)
        status.set(status='restarting', stage='restart', percent=85, message='Starting services and checking fresh progress.')
        deploy.start_services(root, services, readiness=readiness)
        if rollback_archive:
            restore_source_metadata(root, rollback_archive)
        elif metadata:
            write_update_source(root, scope, metadata)
        deploy.save_manifest(root,scope,incoming)
    except Exception as exc:
        status.set(status='running', stage='rollback', percent=94, message='Deployment failed; recovering previous code.', failure_detail=str(exc))
        try:
            deploy.stop_services(services)
            if mutation_started:
                restore_backup(root, backup, remove=introduced)
                validate(root, scope)
                deploy.save_manifest(root,scope,old_manifest)
            deploy.start_services(root, services, readiness=readiness)
        except Exception as recovery:
            status.set(status='rollback_failed', stage='rollback_failed', percent=100, message='Recovery could not be verified. Retain snapshot and inspect service journals.', rollback_detail=str(recovery), completed_at=utc())
            return False
        status.set(status='rollback_completed', stage='rollback_completed', percent=100, message='Previous code and active services recovered; database not restored.', completed_at=utc())
        return False
    status.set(status='success' if rollback_archive else 'completed', stage='complete' if rollback_archive else 'completed', percent=100,
               message='Code installed and active services passed authenticated readiness and startup checks. Live customer operations are not tested.', completed_at=utc())
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--repo', required=True)
    ap.add_argument('--service', default='auto')
    ap.add_argument('--status', required=True)
    ap.add_argument('--scope', choices=['panel','node'], required=True)
    ap.add_argument('--target', default='latest')
    ap.add_argument('--archive', type=Path, help='Locally downloaded trusted release ZIP')
    args = ap.parse_args()
    root = Path(args.root).resolve()
    if os.getenv('DOCKER_MODE','').lower() in ('1','true','yes','on'):
        raise SystemExit('Container source is immutable. Rebuild and recreate the Compose services.')
    with deploy.deployment_lock(root):
        status = Status(Path(args.status).resolve())
        try:
            status.set(status='running', stage='download', percent=10, message='Downloading a pinned main revision.')
            with tempfile.TemporaryDirectory(prefix='wg-panel-update-') as temporary:
                tmp = Path(temporary)
                if args.archive:
                    if args.archive.stat().st_size>500*1024*1024:raise RuntimeError('Archive exceeds compressed size limit.')
                    metadata={'repo':args.repo,'source':'release','target':args.target,'revision':None,'revision_short':None}
                    status.set(stage='extract',percent=30,message='Validating local release ZIP.')
                    deploy.extract_zip(args.archive,tmp/'source')
                else:
                    archive=tmp/'source.tar.gz'
                    metadata=download_repo(args.repo,'main',archive)
                    metadata['repo']=args.repo
                    status.set(stage='extract',percent=30,revision=metadata['revision'],revision_short=metadata['revision_short'],message='Validating staged source.')
                    safe_extract(archive,tmp/'source')
                source=tmp/'source'
                if not (source/'app.py').is_file() and not (source/'agent'/'node_agent.py').is_file():
                    roots=list(source.iterdir())
                    if len(roots)!=1 or not roots[0].is_dir():raise RuntimeError('Invalid repository archive layout.')
                    source=roots[0]
                stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S')
                backup = root/'instance'/'update_backups'/f'{args.scope}_{stamp}.tar.gz'
                if not apply_staged(root,source,args.scope,status,backup,preferred=args.service,metadata=metadata):
                    raise SystemExit(1)
        except Exception as exc:
            status.set(status='failed',stage='failed',percent=100,message='Update refused or failed before deployment. Check details.',failure_detail=str(exc),completed_at=utc())
            raise


if __name__ == '__main__':
    main()
