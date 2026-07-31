#!/usr/bin/env python3

from __future__ import annotations
import argparse, datetime as dt, json, os, shutil, subprocess, sys, tarfile, tempfile, time
from pathlib import Path
from urllib.request import Request, urlopen

EXCLUDES = {
    ".git", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    "instance", ".env", "backups", "restore_snapshots",
}

def atm_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)

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
    """Resolve main revision without depending on GitHub REST API quota.

    `git ls-remote` is the primary source. The REST API is only a best-effort
    fallback and a 403/rate-limit response must never abort an otherwise valid
    archive update.
    """
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
                    if len(candidate) >= 40:
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

    return {
        "revision": revision,
        "revision_short": revision[:8],
        "commit_date": commit_date,
        "url": url,
    }


def download_repo(repo: str, target: str, dest: Path) -> dict:
    """Download main without making GitHub API availability a prerequisite."""
    urls = [
        f"https://codeload.github.com/{repo}/tar.gz/refs/heads/main",
        f"https://github.com/{repo}/archive/refs/heads/main.tar.gz",
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
                    shutil.copyfileobj(response, output)

                if dest.stat().st_size < 1024:
                    raise RuntimeError(
                        "Downloaded archive is unexpectedly small."
                    )

                with tarfile.open(dest, "r:gz") as archive:
                    if not archive.getmembers():
                        raise RuntimeError("Downloaded archive is empty.")

                metadata = github_main_metadata(repo)
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
        "source": "main",
        "target": "main",
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

def backup_code(root: Path, backup_path: Path):
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(backup_path, "w:gz") as tar:
        for item in root.iterdir():
            if item.name in EXCLUDES:
                continue
            tar.add(item, arcname=item.name, recursive=True)

def copy_tree(src: Path, dst: Path):
    for item in src.iterdir():
        if item.name in EXCLUDES:
            continue
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)

def restore_backup(root: Path, backup_path: Path):
    for item in list(root.iterdir()):
        if item.name in EXCLUDES:
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink(missing_ok=True)
    with tarfile.open(backup_path, "r:gz") as tar:
        tar.extractall(root)

def validate(root: Path, scope: str):
    py = root / "venv/bin/python"
    if not py.exists():
        py = Path(sys.executable)

    targets = [root / "app.py"] if scope == "panel" else [
        root / "agent/node_agent.py",
        root / "agent/node.py",
    ]
    existing = [str(p) for p in targets if p.exists()]
    if not existing:
        raise RuntimeError("No expected Python entrypoint found after update.")
    run([str(py), "-m", "py_compile", *existing], timeout=90)

def install_requirements(root: Path, scope: str):
    pip = root / "venv/bin/pip"
    if scope == "node" and (root / "agent/venv/bin/pip").exists():
        pip = root / "agent/venv/bin/pip"
    req = root / "requirements.txt"
    if scope == "node" and (root / "agent/requirements.txt").exists():
        req = root / "agent/requirements.txt"
    if pip.exists() and req.exists():
        run([str(pip), "install", "-r", str(req)], timeout=1200)


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
    """
    Schedule the service restart outside the updater process.

    This is used after rollback so the rollback terminal status is written
    before the panel/agent service is restarted. Even if the old service
    cgroup terminates a fallback updater process, Telegram and the web UI
    still receive a final rollback result instead of remaining at 94%.
    """
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--service", default="auto")
    ap.add_argument("--status", required=True)
    ap.add_argument("--scope", choices=["panel","node"], required=True)
    ap.add_argument("--target", default="latest")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    service = str(args.service or "auto").strip()

    if service.lower() in {"", "auto", "detect"}:
        service = detect_service(root, args.scope)

    status = Status(Path(args.status).resolve())
    status.set(
        log=f"Detected systemd service: {service}",
        service=service,
    )
    stamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup = root / "instance/update_backups" / f"{args.scope}_{stamp}.tar.gz"
    lock = root / "instance/update.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)

    fd = None
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd); fd = None

        status.set(status="running", stage="backup", percent=8,
                   message="Creating rollback backup…")
        backup_code(root, backup)
        status.set(percent=18, backup=str(backup), log=f"Backup created: {backup}")

        with tempfile.TemporaryDirectory(prefix="wg-panel-update-") as tmp:
            tmp = Path(tmp)
            archive = tmp / "source.tar.gz"

            status.set(
                stage="download",
                percent=27,
                message="Downloading the main branch…",
            )

            source_metadata = download_repo(
                args.repo,
                "main",
                archive,
            )

            source_metadata["repo"] = args.repo

            status.set(
                percent=38,
                target="main",
                source="main",
                revision=source_metadata.get(
                    "revision"
                ),
                revision_short=source_metadata.get(
                    "revision_short"
                ),
                log=(
                    "Repository main branch downloaded: "
                    + str(
                        source_metadata.get(
                            "revision_short"
                        )
                        or "unknown revision"
                    )
                ),
            )

            status.set(
                stage="extract",
                percent=45,
                message="Preparing repository files…",
            )
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(tmp / "source")
            roots = [p for p in (tmp / "source").iterdir() if p.is_dir()]
            if len(roots) != 1:
                raise RuntimeError("Downloaded release layout is invalid.")
            source = roots[0]

            status.set(stage="install", percent=58, message="Installing updated code…")
            copy_tree(source, root)
            status.set(percent=70, log="Code files replaced; persistent data preserved.")

            status.set(stage="dependencies", percent=76, message="Checking dependencies…")
            install_requirements(root, args.scope)

            status.set(stage="validate", percent=87, message="Validating updated Python…")
            validate(root, args.scope)
            status.set(
                percent=93,
                log="Validation completed.",
            )

        status.set(
            status="restarting",
            stage="restart",
            percent=97,
            message=f"Restarting {service}…",
        )

        restart_info = schedule_service_restart(
            service,
            scope=args.scope,
        )

        status.set(
            restart_launcher=restart_info.get(
                "launcher"
            ),
            restart_unit=restart_info.get(
                "unit"
            ),
            restart_pid=restart_info.get(
                "pid"
            ),
            log=(
                "Detached service restart scheduled for "
                f"{service}."
            ),
        )

        write_update_source(
            root,
            args.scope,
            source_metadata,
        )

        status.set(
            status="completed",
            stage="completed",
            percent=100,
            message="Update installed successfully. Service restart was scheduled.",
            completed_at=utc(),
            restart_launcher=restart_info.get("launcher"),
            restart_unit=restart_info.get("unit"),
            restart_pid=restart_info.get("pid"),
            log=(
                f"Updated revision {source_metadata.get('revision_short') or 'unknown'} installed; "
                f"detached restart scheduled for {service}."
            ),
        )

    except Exception as exc:
        status.set(
            status="running",
            stage="rollback",
            percent=94,
            message="Update failed; restoring previous code…",
            log=str(exc),
        )

        try:
            if backup.exists():
                restore_backup(
                    root,
                    backup,
                )

                try:
                    lock.unlink(
                        missing_ok=True,
                    )
                except Exception:
                    pass

                restart_info = schedule_service_restart(
                    service,
                    scope=args.scope,
                )

                status.set(
                    status="rollback_completed",
                    stage="rollback_completed",
                    percent=100,
                    message=(
                        "Update was not installed. Previous code was restored and restart was scheduled."
                    ),
                    failure_detail=str(exc),
                    restart_launcher=restart_info.get(
                        "launcher"
                    ),
                    restart_unit=restart_info.get(
                        "unit"
                    ),
                    restart_pid=restart_info.get(
                        "pid"
                    ),
                    completed_at=utc(),
                    log=(
                        "Rollback files restored; detached "
                        f"restart scheduled for {service}."
                    ),
                )

            else:
                status.set(
                    status="rollback_failed",
                    stage="rollback_failed",
                    percent=100,
                    message=(
                        "Update failed and no rollback "
                        "backup was available."
                    ),
                    failure_detail=str(exc),
                    completed_at=utc(),
                )

        except Exception as rollback_exc:
            status.set(
                status="rollback_failed",
                stage="rollback_failed",
                percent=100,
                message=(
                    "Update failed and rollback could not "
                    "be completed."
                ),
                failure_detail=str(exc),
                rollback_detail=str(
                    rollback_exc
                ),
                completed_at=utc(),
            )
    finally:
        try: lock.unlink(missing_ok=True)
        except Exception: pass

if __name__ == "__main__":
    main()
