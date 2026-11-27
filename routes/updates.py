def build_routes(*,
    BASE_DIR,
    Node,
    PANEL_REPO,
    PANEL_UPDATE_TTL,
    PANEL_VERSION,
    Path,
    UPDATE_STATUS_FILE,
    _PANEL_UPDATE_CACHE,
    _github_latest_panel_version,
    _launch_update,
    _norm_update_status,
    _queue_safe_update,
    _read_update_source,
    _update_is_busy,
    _update_lock_active,
    _version_tuple,
    abort,
    csrf,
    current_app,
    current_user,
    datetime,
    db,
    jsonify,
    login_required,
    node_get,
    node_post,
    os,
    re,
    request,
    requests,
    require_api_key_or_login,
    send_file,
    shutil,
    subprocess,
    sys,
    time,
):

    @require_api_key_or_login
    def api_panel_version():
        now = int(time.time())

        fresh = (
            str(
                request.args.get("fresh")
                or ""
            )
            .strip()
            .lower()
            in {
                "1",
                "true",
                "yes",
                "on",
            }
        )

        if (
            not fresh
            and _PANEL_UPDATE_CACHE.get("data")
            and now - int(
                _PANEL_UPDATE_CACHE.get("ts")
                or 0
            ) < PANEL_UPDATE_TTL
        ):
            return jsonify(
                _PANEL_UPDATE_CACHE["data"]
            )

        remote = (
            _github_latest_panel_version()
            or {}
        )

        installed = _read_update_source(
            "panel"
        )

        current_version = str(
            PANEL_VERSION
            or "0.0.0"
        ).strip().lstrip("vV")

        latest_version = str(
            remote.get("version")
            or current_version
            or "0.0.0"
        ).strip().lstrip("vV")

        remote_revision = str(
            remote.get("revision")
            or ""
        ).strip()

        installed_revision = str(
            installed.get("revision")
            or os.getenv("WG_PANEL_REVISION")
            or os.getenv("PANEL_REVISION")
            or os.getenv("GIT_COMMIT")
            or ""
        ).strip()

        if installed.get("source") == "snapshot":
            installed_revision = str(installed.get("revision") or "")
        if not installed_revision and installed.get("source") != "snapshot":
            try:
                git_dir = Path(BASE_DIR) / ".git"
                git_bin = shutil.which("git")
                if git_bin and git_dir.exists():
                    result = subprocess.run(
                        [git_bin, "rev-parse", "HEAD"],
                        cwd=BASE_DIR,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                        timeout=4,
                        check=False,
                    )
                    candidate = (result.stdout or "").strip()
                    if result.returncode == 0 and re.fullmatch(
                        r"[0-9a-fA-F]{40,64}", candidate
                    ):
                        installed_revision = candidate
            except Exception:
                pass

        version_update_available = (
            _version_tuple(latest_version)
            > _version_tuple(current_version)
        )

        revision_comparison_complete = bool(
            remote_revision
            and installed_revision
        )

        revision_update_available = bool(
            revision_comparison_complete
            and remote_revision != installed_revision
        )

        if (
            version_update_available
            and revision_update_available
        ):
            update_reason = (
                "version_and_revision"
            )

        elif version_update_available:
            update_reason = "version"

        elif revision_update_available:
            update_reason = "revision"

        elif not revision_comparison_complete:


            update_reason = "check_incomplete"

        else:
            update_reason = "current"

        update_available = bool(
            version_update_available
            or revision_update_available
        )

        comparison_complete = bool(
            version_update_available
            or revision_comparison_complete
        )

        payload = {
            "ok": True,

            "current": current_version,
            "version_source": "VERSION",

            "repo": PANEL_REPO,

            "latest": latest_version,

            "latest_url": (
                remote.get("url")
                or f"https://github.com/{PANEL_REPO}"
            ),

            "source": "main",
            "target": "main",
            "update_source": "main",

            "current_revision": (
                installed_revision
            ),

            "current_revision_short": (
                installed_revision[:8]
            ),

            "latest_revision": (
                remote_revision
            ),

            "latest_revision_short": (
                remote_revision[:8]
            ),

            "commit_date": remote.get(
                "commit_date"
            ),

            "revision_tracked": bool(
                installed_revision
            ),

            "revision_check_ok": bool(
                remote_revision
            ),

            "comparison_complete": (
                comparison_complete
            ),

            "version_update_available": (
                version_update_available
            ),

            "revision_update_available": (
                revision_update_available
            ),

            "update_available": (
                update_available
            ),

            "update_reason": (
                update_reason
            ),

            "checked_at": (
                datetime.utcnow()
                .isoformat(
                    timespec="seconds",
                )
                + "Z"
            ),
        }

        _PANEL_UPDATE_CACHE["ts"] = now
        _PANEL_UPDATE_CACHE["data"] = payload

        return jsonify(payload)

    @require_api_key_or_login
    def api_panel_update_status():
        return jsonify(
            _norm_update_status(
                BASE_DIR,
                UPDATE_STATUS_FILE,
            )
        )

    @require_api_key_or_login
    def api_panel_update_start():
        if current_user.is_authenticated:
            if not getattr(current_user, "is_admin", False):
                abort(403)
            csrf.protect()
        data = request.get_json(silent=True) or {}
        target = "main"

        try:
            status = _queue_safe_update(
                root=BASE_DIR,
                service="auto",
                status_file=UPDATE_STATUS_FILE,
                scope="panel",
                target=target,
            )
            return jsonify(
                ok=True,
                message="Local panel update queued.",
                status=status,
            ), 202
        except RuntimeError as exc:
            return jsonify(ok=False, error="update_not_started", detail=str(exc)), 409
        except Exception as exc:
            current_app.logger.exception("Could not queue local update")
            return jsonify(ok=False, error="update_queue_failed", detail=str(exc)), 500

    @login_required
    def api_panel_rollback_candidates():
        if not getattr(current_user,'is_admin',False):abort(403)
        import re
        from pathlib import Path
        folder=Path(BASE_DIR)/'instance'/'update_backups'
        files=[]
        if folder.is_dir():
            for path in sorted(folder.iterdir(),key=lambda f:f.stat().st_mtime if f.is_file() else 0,reverse=True):
                if len(files)>=100:break
                if path.is_symlink() or not re.fullmatch(r'(?:panel|pre_manual)_\d{8}_\d{6}\.tar\.gz',path.name) or not path.is_file():continue
                files.append(dict(name=path.name,size=path.stat().st_size,
                                  created_at=datetime.utcfromtimestamp(path.stat().st_mtime).isoformat()+'Z'))
        return jsonify(ok=True,items=files,warning='Code only. Database, instance data, WireGuard and secrets are unchanged. ORM/schema incompatibility blocks rollback.')

    @login_required
    def api_panel_snapshot_download(name):
        if not getattr(current_user, 'is_admin', False):
            abort(403)
        import re
        if not re.fullmatch(r'(?:panel|pre_manual)_\d{8}_\d{6}\.tar\.gz', name):
            abort(404)
        directory = Path(BASE_DIR) / 'instance' / 'update_backups'
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.resolve().parent != directory.resolve():
            abort(404)
        response = send_file(path, as_attachment=True, download_name=name, mimetype='application/gzip')
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @login_required
    def api_panel_snapshot_create():
        csrf.protect()
        if not getattr(current_user, 'is_admin', False):
            abort(403)
        if _update_is_busy(_norm_update_status(BASE_DIR, UPDATE_STATUS_FILE)) or _update_lock_active(BASE_DIR):
            return jsonify(ok=False, error='An update or snapshot is already running'), 409
        helper = Path(BASE_DIR) / 'scripts' / 'panel_snapshot.py'
        try:
            _launch_update(cmd=[sys.executable, str(helper), '--root', str(BASE_DIR),
                                '--status', str(UPDATE_STATUS_FILE)], root=BASE_DIR,
                           scope='panel-snapshot', log_path=Path(BASE_DIR)/'instance'/'update_runner.log')
            return jsonify(ok=True, queued=True), 202
        except Exception:
            current_app.logger.exception('Could not launch code snapshot')
            return jsonify(ok=False, error='Could not start snapshot'), 503

    @login_required
    def api_panel_rollback_code():
        csrf.protect()
        if not getattr(current_user,'is_admin',False):abort(403)
        payload=request.get_json(silent=True) or {}
        if payload.get('confirm')!='ROLLBACK_CODE_ONLY':
            return jsonify(ok=False,error='Explicit code-only confirmation required'),400
        name=str(payload.get('snapshot') or '')
        import re
        if not re.fullmatch(r'(?:panel|pre_manual)_\d{8}_\d{6}\.tar\.gz',name):
            return jsonify(ok=False,error='Invalid snapshot name'),400
        folder=Path(BASE_DIR)/'instance'/'update_backups'
        candidate=folder/name
        if candidate.is_symlink() or not candidate.is_file() or candidate.resolve().parent != folder.resolve():
            return jsonify(ok=False,error='Snapshot unavailable'),404
        if _update_is_busy(_norm_update_status(BASE_DIR,UPDATE_STATUS_FILE)) or _update_lock_active(BASE_DIR):
            return jsonify(ok=False,error='An update or rollback is already running'),409
        helper=Path(BASE_DIR)/'scripts'/'panel_manual_rollback.py'
        if not helper.is_file():return jsonify(ok=False,error='Rollback helper missing'),503
        command=[sys.executable,str(helper),'--root',str(BASE_DIR),'--backup-name',name,
                 '--status',str(UPDATE_STATUS_FILE)]
        try:

            launch=_launch_update(cmd=command,root=BASE_DIR,scope='panel-rollback',
                log_path=Path(BASE_DIR)/'instance'/'update_runner.log')
            return jsonify(ok=True,queued=True,launcher=launch.get('launcher'),
                           message='Code-only rollback started. Monitor Update Center status.'),202
        except Exception:
            current_app.logger.exception('Could not launch code rollback')
            return jsonify(ok=False,error='Could not start code rollback'),503

    @require_api_key_or_login
    def api_panel_update_targets():
        inventory = request.args.get('inventory') == '1'
        query = Node.query.order_by(Node.id.asc())
        node_id = request.args.get('node_id')
        if node_id is not None:
            if not node_id.isascii() or not node_id.isdecimal() or not 0 < len(node_id) <= 10:
                return jsonify(error='Invalid node ID'), 400
            query = query.filter_by(id=int(node_id))
        nodes = query.all()
        if node_id is not None and not nodes:
            abort(404)
        cached = _PANEL_UPDATE_CACHE.get("data") or {}
        if inventory or node_id is not None or (cached and time.time() - _PANEL_UPDATE_CACHE["ts"] < PANEL_UPDATE_TTL):
            remote = {"version":cached.get("latest"), "revision":cached.get("latest_revision")}
        else:
            remote = _github_latest_panel_version() or {}

        latest_version = (
            remote.get("version")
            or PANEL_VERSION
        )

        latest_revision = str(
            remote.get("revision")
            or ""
        ).strip()

        rows = []

        for node in nodes:
            row = {
                "id": node.id,
                "name": node.name,
                "base_url": node.base_url,
                "online": False,

                "version": {
                    "current": None,
                    "latest": latest_version,
                    "target": "main",
                    "source": "main",

                    "latest_revision": (
                        latest_revision
                    ),

                    "latest_revision_short": (
                        latest_revision[:8]
                    ),

                    "update_available": False,
                },

                "update": {
                    "status": "idle",
                },
            }

            if not node.enabled:
                row["update"] = {
                    "status": "disabled",
                }

                rows.append(row)
                continue

            if inventory:
                row["update"] = {"status":"checking"}
                rows.append(row)
                continue

            try:
                version = (
                    node_get(
                        node,
                        "/api/system/version",
                        timeout=8,
                    )
                    or {}
                )

                status = (
                    node_get(
                        node,
                        "/api/system/update/status",
                        timeout=6,
                    )
                    or {}
                )

                row["online"] = True

                row["version"] = {
                    "current": (
                        str(
                            version.get("current")
                            or ""
                        ).strip()
                        or None
                    ),

                    "latest": (
                        str(
                            version.get("latest")
                            or latest_version
                            or ""
                        ).strip()
                        or None
                    ),

                    "target": "main",
                    "source": "main",

                    "current_revision": str(
                        version.get(
                            "current_revision"
                        )
                        or ""
                    ),

                    "current_revision_short": str(
                        version.get(
                            "current_revision_short"
                        )
                        or ""
                    ),

                    "latest_revision": str(
                        version.get(
                            "latest_revision"
                        )
                        or latest_revision
                        or ""
                    ),

                    "latest_revision_short": str(
                        version.get(
                            "latest_revision_short"
                        )
                        or latest_revision[:8]
                        or ""
                    ),

                    "revision_tracked": bool(
                        version.get(
                            "revision_tracked"
                        )
                    ),

                    "update_available": bool(
                        version.get(
                            "update_available"
                        )
                    ),
                }

                row["update"] = (
                    status
                    if isinstance(status, dict)
                    else {
                        "status": "idle",
                    }
                )

            except Exception as exc:
                row["update"] = {
                    "status": "offline",
                    "message": str(exc),
                }

            rows.append(row)

        return jsonify(
            ok=True,
            latest=latest_version,
            target="main",
            update_source="main",

            latest_revision=latest_revision,
            latest_revision_short=(
                latest_revision[:8]
            ),

            nodes=rows,
        )

    @require_api_key_or_login
    def api_node_update_start(nid):
        if current_user.is_authenticated:
            if not getattr(current_user, "is_admin", False):
                abort(403)
            csrf.protect()
        node = db.session.get(Node, nid) or abort(404)
        data = request.get_json(silent=True) or {}

        try:
            response = node_post(
               node,
               "/api/system/update",
               {"target": "main"},
               timeout=12,
            )
            return jsonify(response if isinstance(response, dict) else {
                "ok": True,
                "message": str(response),
            }), 202
        except requests.HTTPError as exc:
            body = getattr(getattr(exc, "response", None), "text", "") or ""
            return jsonify(
                ok=False,
                error="node_update_rejected",
                detail=body[:1000] or str(exc),
            ), 502
        except Exception as exc:
            return jsonify(
                ok=False,
                error="node_update_failed",
                detail=str(exc),
            ), 502

    @require_api_key_or_login
    def api_node_update_status(nid):
        node = db.session.get(Node, nid) or abort(404)
        try:
            data = node_get(node, "/api/system/update/status", timeout=8) or {}
            return jsonify(data if isinstance(data, dict) else {
                "status": "unknown",
                "message": str(data),
            })
        except Exception as exc:
            return jsonify(
                status="offline",
                message=str(exc),
                percent=0,
                log=[],
            ), 200

    return {
        'api_panel_version': api_panel_version,
        'api_panel_update_status': api_panel_update_status,
        'api_panel_update_start': api_panel_update_start,
        'api_panel_rollback_candidates': api_panel_rollback_candidates,
        'api_panel_snapshot_download': api_panel_snapshot_download,
        'api_panel_snapshot_create': api_panel_snapshot_create,
        'api_panel_rollback_code': api_panel_rollback_code,
        'api_panel_update_targets': api_panel_update_targets,
        'api_node_update_start': api_node_update_start,
        'api_node_update_status': api_node_update_status,
    }
