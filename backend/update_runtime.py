def bind_version_tuple(_panel_context):
    def _version_tuple(v: str):
        import re

        s = str(v or "").strip()
        s = s.lstrip("vV")
        nums = re.findall(r"\d+", s)

        if not nums:
            return (0, 0, 0)

        parts = [int(x) for x in nums[:3]]
        while len(parts) < 3:
            parts.append(0)

        return tuple(parts)


    def _update_source_marker(
        scope: str = "panel",
    ) -> _panel_context.Path:
        safe_scope = (
            "node"
            if str(scope).strip().lower() == "node"
            else "panel"
        )

        return (
            _panel_context.Path(_panel_context.INSTANCE_DIR)
            / f"update_source_{safe_scope}.json"
        )


    def _read_update_source(
        scope: str = "panel",
    ) -> dict:
        try:
            payload = _panel_context.json.loads(
                _panel_context._update_source_marker(scope)
                .read_text(
                    encoding="utf-8",
                )
            )

            return (
                payload
                if isinstance(payload, dict)
                else {}
            )

        except Exception:
            return {}


    def _github_latest_panel_version():

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "WG-Panel",
            "Cache-Control": "no-cache",
        }

        github_token = (
            _panel_context.os.getenv("GITHUB_TOKEN")
            or _panel_context.os.getenv("GH_TOKEN")
            or ""
        ).strip()
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        commit_sha = ""
        commit_url = ""
        commit_date = ""
        remote_version = None

        try:
            response = _panel_context.requests.get(
                (
                    f"https://api.github.com/repos/"
                    f"{_panel_context.PANEL_REPO}/commits/main"
                ),
                headers=headers,
                timeout=8,
            )

            response.raise_for_status()

            payload = response.json() or {}

            commit_sha = str(
                payload.get("sha")
                or ""
            ).strip()

            commit_url = str(
                payload.get("html_url")
                or f"https://github.com/{_panel_context.PANEL_REPO}"
            ).strip()

            commit = payload.get("commit") or {}
            author = commit.get("author") or {}

            commit_date = str(
                author.get("date")
                or ""
            ).strip()

        except Exception as exc:
            _panel_context.logging.getLogger(__name__).warning(
                "Could not read GitHub main commit: %s",
                exc,
            )


        if not commit_sha:
            try:
                git_bin = _panel_context.shutil.which("git")
                if git_bin:
                    result = _panel_context.subprocess.run(
                        [
                            git_bin,
                            "ls-remote",
                            f"https://github.com/{_panel_context.PANEL_REPO}.git",
                            "refs/heads/main",
                        ],
                        stdout=_panel_context.subprocess.PIPE,
                        stderr=_panel_context.subprocess.DEVNULL,
                        text=True,
                        timeout=12,
                        check=False,
                    )
                    if result.returncode == 0:
                        line = (result.stdout or "").strip().splitlines()
                        if line:
                            candidate = line[0].split()[0].strip()
                            if _panel_context.re.fullmatch(r"[0-9a-fA-F]{40,64}", candidate):
                                commit_sha = candidate
                                commit_url = (
                                    f"https://github.com/{_panel_context.PANEL_REPO}/commit/{candidate}"
                                )
            except Exception as exc:
                _panel_context.logging.getLogger(__name__).debug(
                    "git ls-remote fallback failed: %s",
                    exc,
                )

        try:
            response = _panel_context.requests.get(
                (
                    f"https://raw.githubusercontent.com/"
                    f"{_panel_context.PANEL_REPO}/main/VERSION"
                ),
                headers=headers,
                timeout=6,
            )

            if response.ok:
                candidate = (
                    response.text
                    .strip()
                    .lstrip("vV")
                )

                if _panel_context.re.fullmatch(
                    r"\d+(?:\.\d+){0,3}"
                    r"(?:[-+][0-9A-Za-z.-]+)?",
                    candidate,
                ):
                    remote_version = candidate

        except Exception:
            pass

        if not commit_sha and not remote_version:
            return None

        return {
            "version": remote_version,
            "target": "main",
            "url": (
                commit_url
                or f"https://github.com/{_panel_context.PANEL_REPO}"
            ),
            "source": "main",
            "revision": commit_sha,
            "revision_short": commit_sha[:8],
            "commit_date": commit_date,
        }

    return {
        '_version_tuple': _version_tuple,
        '_update_source_marker': _update_source_marker,
        '_read_update_source': _read_update_source,
        '_github_latest_panel_version': _github_latest_panel_version,
    }


def bind_read_update_status(_panel_context):
    def _read_update_status(path=_panel_context.UPDATE_STATUS_FILE):
        try:
            data = _panel_context.json.loads(_panel_context.Path(path).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {
                "status": "idle",
                "stage": "idle",
                "percent": 0,
                "message": "No update is running.",
                "log": [],
            }


    def _update_is_busy(status):
        return str(
            (status or {}).get("status")
            or ""
        ).lower() in {
            "queued",
            "running",
            "backup",
            "downloading",
            "download",
            "extract",
            "install",
            "installing",
            "dependencies",
            "validate",
            "validating",
            "restart",
            "restarting",
            "rollback",
            "rolling_back",
            "rollback_restart",
        }


    def _update_lock_active(root) -> bool:
        return _panel_context._deployment_lock_active(root)


    def _write_update_status(path,payload):
        from scripts.panel_update import atm_json
        atm_json(_panel_context.Path(path),payload)


    def _norm_update_status(root, status_file):
        status = _panel_context._read_update_status(status_file)
        if _panel_context._update_is_busy(status) and not _panel_context._update_lock_active(root):
            if status.get('status') == 'queued' and _panel_context.time.time() - float(status.get('requested_at') or 0) < 30:
                return status
            
            return dict(status, status='failed', stage='interrupted', percent=100,
                        message='Previous deployment was interrupted. Check service journals and the recovery snapshot.')
        return status


    def _launch_update(*, cmd, root, scope, log_path):
        if str(_panel_context.os.getenv('DOCKER_MODE','')).lower() in ('1','true','yes','on'):
            raise RuntimeError('Container deployment requires rebuilding and recreating services from the host.')
        systemd_run = _panel_context.shutil.which('systemd-run')
        if not systemd_run:
            raise RuntimeError('Independent systemd updater unavailable. Use manual maintenance.')
        unit_name = f'wg-panel-update-{scope}-{_panel_context.secrets.token_hex(6)}'
        result = _panel_context.subprocess.run([systemd_run,'--unit',unit_name,'--collect','--quiet',
            '--property=Type=exec','--property=TimeoutStopSec=10min',
            f'--working-directory={root}','--',*cmd], stdin=_panel_context.subprocess.DEVNULL,
            stdout=_panel_context.subprocess.PIPE,stderr=_panel_context.subprocess.STDOUT,text=True,timeout=20,check=False)
        if result.returncode:
            raise RuntimeError('Could not create independent systemd updater.')
        return {'launcher':'systemd-run','unit':unit_name+'.service'}


    def _queue_safe_update(
        *,
        root,
        service,
        status_file,
        scope,
        target="latest",
    ):
        root = _panel_context.Path(root).resolve()

        helper = (
            root
            / "scripts"
            / "panel_update.py"
        )

        if not helper.is_file():
            raise RuntimeError(
                f"Update helper is missing: {helper}"
            )

        current = _panel_context._norm_update_status(
            root,
            status_file,
        )

        if current.get('stage')=='interrupted':
            raise RuntimeError('Previous deployment was interrupted. Verify or restore the recovery snapshot before updating again.')
        if (
            _panel_context._update_is_busy(current)
            or _panel_context._update_lock_active(root)
        ):
            raise RuntimeError(
                "An update is already running "
                "for this target."
            )

        cmd = [
            _panel_context.sys.executable,
            str(helper),
            "--root",
            str(root),
            "--repo",
            _panel_context.PANEL_REPO,
            "--service",
            service,
            "--status",
            str(status_file),
            "--scope",
            scope,
            "--target",
            str(target or "latest"),
        ]

        log_path = (
            root
            / "instance"
            / "update_runner.log"
        )

        log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        queued = {
            "status": "queued",
            "stage": "queued",
            "percent": 2,
            "message": "Update is starting…",
            "requested_at": _panel_context.time.time(),
            "target": str(target or "latest"),
            "launcher": "pending",
            "unit": None,
            "pid": None,
            "log": [],
        }

        _panel_context._write_update_status(
            status_file,
            queued,
        )

        try:
            launch_info = _panel_context._launch_update(
                cmd=cmd,
                root=root,
                scope=scope,
                log_path=log_path,
            )

        except Exception as exc:
            failed = dict(queued)

            failed.update({
                "status": "failed",
                "stage": "failed",
                "percent": 100,
                "message": (
                    "The updater could not be started."
                ),
                "detail": str(exc),
            })

            _panel_context._write_update_status(
                status_file,
                failed,
            )

            raise

        return _panel_context._read_update_status(status_file)

    return {
        '_read_update_status': _read_update_status,
        '_update_is_busy': _update_is_busy,
        '_update_lock_active': _update_lock_active,
        '_write_update_status': _write_update_status,
        '_norm_update_status': _norm_update_status,
        '_launch_update': _launch_update,
        '_queue_safe_update': _queue_safe_update,
    }
