def bind_services(*,
    BACKUP_AUTO_DIR,
    BACKUP_LAST_FILE,
    BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE,
    BASE_DIR,
    BytesIO,
    DB_PATH,
    Node,
    Path,
    _json_load,
    _json_save,
    _norm_adminlog,
    _panel_filename_stamp,
    _panel_timezone,
    _panel_timezone_name,
    _read_api_key,
    app,
    current_app,
    datetime,
    db,
    json,
    jsonify,
    os,
    re,
    request,
    requests,
    secrets,
    tempfile,
    zipfile,
):

    def _save_autobackup(data_bytes: bytes, keep: int | None = None) -> dict:

        root = Path(BACKUP_AUTO_DIR)
        root.mkdir(parents=True, exist_ok=True)

        ts = _panel_filename_stamp()
        name = f"auto_full_{ts}_{secrets.token_hex(4)}.zip"
        path = root / name

        tmp = None
        try:
            with tempfile.NamedTemporaryFile(dir=root, prefix='.auto-', suffix='.tmp', delete=False) as f:
                tmp = Path(f.name)
                os.fchmod(f.fileno(), 0o600)
                f.write(data_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)

        st = path.stat()

        if keep is None:
            try:
                sched = _load_backup_schedule()
                keep = int(sched.get("keep", 7))
            except Exception:
                keep = 7

        keep = max(1, int(keep or 1))

        files = sorted((p for p in root.glob("auto_full_*.zip") if p.is_file() and not p.is_symlink()), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in files[keep:]:
            try:
                p.unlink()
            except OSError:
                pass

        return {"name": name, "size": st.st_size, "ts": int(st.st_mtime)}

    def _db_path():
        return DB_PATH if os.path.isfile(DB_PATH) else None

    def _jsonl_bundle(z: zipfile.ZipFile):
        inst = Path(app.instance_path)
        keep_suffix = {'.json', '.jsonl'}
        for p in inst.glob('*'):
            if p.is_file() and p.suffix.lower() in keep_suffix:
                z.write(p, arcname=f'instance/{p.name}')

    def _env_bundle(z: zipfile.ZipFile):
        try:
            env_path = Path(BASE_DIR) / ".env"
            if env_path.is_file():
                z.write(env_path, arcname="env/.env")
        except Exception as e:
            current_app.logger.warning("ENV bundle skipped: %s", e)

    def _backup_prefs():
        return {"include_wg": True, "send_to_telegram": False}

    def _backup_prefs_load():
        return _json_load(BACKUP_PREFS_FILE, _backup_prefs())

    def _backup_prefs_save(p):
        cur = _backup_prefs_load()
        cur.update({
            "include_wg": bool(p.get("include_wg", cur["include_wg"])),
            "send_to_telegram": bool(p.get("send_to_telegram", cur["send_to_telegram"])),
        })
        _json_save(BACKUP_PREFS_FILE, cur)
        return cur

    def _backup_restore_impl():
        import tempfile
        import zipfile
        from pathlib import Path
        from datetime import datetime

        f = request.files.get('file')

        if not f or not (f.filename or "").lower().endswith('.zip'):
            return jsonify(
                ok=False,
                error='no_file',
                message='Please upload a .zip backup file.'
            ), 400

        kind_req = (request.form.get('kind') or 'auto').lower().strip()
        restore_wg = (request.form.get('restore_wg') or '0') == '1'
        server_settings_mode = (request.form.get('server_settings_mode') or 'keep').lower().strip()
        if server_settings_mode not in ('keep', 'saved', 'custom'):
            server_settings_mode = 'keep'

        def _form_int(name, default=None):
            try:
                v = request.form.get(name)
                if v in (None, ''):
                    return default
                i = int(v)
                return i if 1 <= i <= 65535 else default
            except Exception:
                return default

        custom_port = _form_int('custom_port')
        custom_http_port = _form_int('custom_http_port')
        custom_https_port = _form_int('custom_https_port')
        custom_bind = (request.form.get('custom_bind') or '').strip()
        custom_domain = (request.form.get('custom_domain') or '').strip()
        custom_scheme = (request.form.get('custom_scheme') or 'http').lower().strip()
        custom_wg_path = (request.form.get('custom_wg_path') or '').strip()

        if custom_scheme not in ('http', 'https'):
            custom_scheme = 'http'

        db_dir = None
        tmp = tempfile.NamedTemporaryFile(delete=False)

        try:
            from panel_core.backup_integrity import MAX_TOTAL, CHUNK
            total=0
            while True:
                chunk=f.stream.read(CHUNK)
                if not chunk:break
                total+=len(chunk)
                if total>MAX_TOTAL:
                    tmp.close()
                    return jsonify(ok=False,error='backup_too_large',message='Backup exceeds the 2 GiB upload limit.'),413
                tmp.write(chunk)
            tmp.flush()
            tmp.close()

            try:
                z = zipfile.ZipFile(tmp.name, 'r')
            except Exception:
                return jsonify(
                    ok=False,
                    error='invalid_zip',
                    message='File is not a valid ZIP backup.'
                ), 400

            try:
                from panel_core.backup_integrity import verify_archive, validate_restore_files, destination, atomic_write
                try:
                    integrity = verify_archive(z)
                    validate_restore_files(z)
                except (ValueError, TypeError, UnicodeError) as exc:
                    return jsonify(ok=False, error='invalid_backup', message=str(exc)), 400

                names = z.namelist()

                has_db = any(
                    n.startswith('db/') and not n.endswith('/')
                    for n in names
                )

                has_inst = any(
                    n.startswith('instance/') and not n.endswith('/')
                    for n in names
                )

                has_wg = any(
                    n.startswith('wg/') and n.endswith('.conf')
                    for n in names
                )

                has_node_wg = any(
                    n.startswith('nodes/') and '/wg/' in n and n.endswith('.conf')
                    for n in names
                )

                kind = kind_req

                if kind == 'auto':
                    if has_db and has_inst:
                        kind = 'full'
                    elif has_db:
                        kind = 'db'
                    elif has_inst:
                        kind = 'settings'
                    else:
                        return jsonify(
                            ok=False,
                            error='unknown_layout',
                            message='Backup ZIP does not look like a panel backup.'
                        ), 400

                if kind not in ('db', 'settings', 'full'):
                    return jsonify(
                        ok=False,
                        error='invalid_restore_kind',
                        message='Restore kind must be auto, db, settings, or full.'
                    ), 400

                if db.engine.dialect.name == 'postgresql':
                    from scripts import postgres_restore as recovery
                    if recovery.blocked() or recovery.active():
                        return jsonify(ok=False, error='restore_busy', message='Another restore is running or requires review.'), 409
                    if kind in ('db', 'full'):
                        from flask_login import current_user
                        from flask_wtf.csrf import validate_csrf
                        from wtforms.validators import ValidationError
                        from models import AdminAccount
                        from reseller_portal.request_guard import reserve
                        from hashlib import sha256
                        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
                            return jsonify(ok=False, error='admin_session_required', message='Sign in as the administrator to restore PostgreSQL through the panel.'), 403
                        try:
                            validate_csrf(request.headers.get('X-CSRFToken') or request.headers.get('X-CSRF-Token'))
                        except ValidationError:
                            return jsonify(ok=False, error='csrf_required', message='Refresh the page and try again.'), 400
                        if server_settings_mode != 'keep' or (restore_wg and kind != 'full'):
                            return jsonify(ok=False, error='restore_scope', message='Managed PostgreSQL restore requires Keep current server settings. WireGuard recovery is available with Full restore only.'), 400
                        if request.form.get('restore_confirmed') != '1':
                            return jsonify(ok=False, error='confirmation_required', message='Confirm the trusted backup, recovery scope and maintenance window.'), 400
                        actor = current_user.username
                        db.session.rollback()
                        identity = sha256((request.remote_addr or '?').encode()).hexdigest()
                        if not reserve([('admin-security-ip:'+identity,25,900)]):
                            return jsonify(ok=False, error='rate_limit', message='Too many security requests. Try again in 15 minutes.'), 429
                        account = AdminAccount.query.filter_by(username=actor).first()
                        password = request.form.get('restore_password') or ''
                        if not account or len(password)>1024 or not account.verify_pw(password):
                            return jsonify(ok=False, error='invalid_password', message='Administrator password is incorrect.'), 403
                        try:
                            if db.engine.url.set(drivername='postgresql+psycopg') != recovery.configured_url():
                                raise RuntimeError('Running database configuration differs from .env; review before restoring.')
                            db.session.rollback()
                            result = recovery.enqueue(tmp.name, kind, actor, restore_wg=restore_wg)
                        except ValueError as exc:
                            return jsonify(ok=False, error='invalid_backup', message=str(exc)), 400
                        except (RuntimeError, OSError) as exc:
                            message = str(exc) if isinstance(exc, RuntimeError) else 'Restore preparation failed; check the panel logs.'
                            return jsonify(ok=False, error='restore_unavailable', message=message), 409
                        return jsonify(ok=True, queued=True, **result), 202

                inst = Path(app.instance_path)
                db_dir = inst / ("restore_tmp_db_" + secrets.token_hex(8))
                inst_dir = inst
                if server_settings_mode == 'custom' and custom_wg_path:
                    wg_dir = Path(custom_wg_path)
                else:
                    wg_dir = Path(app.config.get('WG_CONF_PATH') or '/etc/wireguard/')

                restored = {
                    "db": False,
                    "settings": False,
                    "wg": False,
                    "node_wg": False,
                }

                warnings = []
                node_restore_results = []

                restore_ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                snapshot_root = inst / "restore_snapshots" / (restore_ts + "_" + secrets.token_hex(4))
                backed_up = set()

                def _backup_existing(dest: Path, kind_name: str, rel_tail: str):
                    try:
                        if not dest.exists() or not dest.is_file():
                            return

                        key = str(dest.resolve())
                        if key in backed_up:
                            return

                        snap_path = snapshot_root / kind_name / rel_tail
                        snapshot_root.mkdir(parents=True, exist_ok=True, mode=0o700)
                        snap_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

                        if snap_path.exists():
                            i = 2
                            while True:
                                alt = snap_path.with_name(snap_path.name + f".{i}")
                                if not alt.exists():
                                    snap_path = alt
                                    break
                                i += 1

                        if kind_name=='db':
                            from reseller_portal.database import copy_database
                            copy_database(dest,snap_path)
                            os.chmod(snap_path,0o600)
                        else:
                            with dest.open("rb") as source:atomic_write(snap_path,source)
                        backed_up.add(key)

                    except Exception as e:
                        raise RuntimeError("Could not preserve an existing restore file; restore stopped.") from e

                def _safe_extract_tail(member: str) -> str:
                    _, _, tail = member.partition('/')
                    tail = tail.strip().lstrip('/')

                    parts = Path(tail).parts

                    if not tail:
                        raise ValueError('empty member path')

                    if any(part in ('', '.', '..') for part in parts):
                        raise ValueError('unsafe member path')

                    return tail

                def _extract(member: str, dest_root: Path, kind_name: str):
                    if member.endswith('/'):
                        return

                    tail = _safe_extract_tail(member)

                    dest = destination(dest_root, tail)
                    _backup_existing(dest, kind_name=kind_name, rel_tail=tail)
                    with z.open(member) as src:
                        atomic_write(dest, src)

                
                if kind in ('db', 'full'):
                    db_members = [n for n in names if n.startswith('db/') and not n.endswith('/')]
                    if len(db_members) != 1 or not db_members[0].endswith('.db'):
                        return jsonify(ok=False,error='invalid_database_archive',message='Expected exactly one SQLite database file.'),400
                if kind in ('settings','full') and not has_inst:
                    return jsonify(ok=False,error='settings_missing',message='No settings files found.'),400
                try:
                    local_targets = []
                    if kind in ('settings','full'):
                        protected = {'runtime.json','panel_settings.json','backup_schedule.json','backup_settings.json','backup_last.json','auto_backup.json'}
                        for n in names:
                            if n.endswith('/'):
                                continue
                            if n.startswith('instance/'):
                                tail=n.split('/',1)[1]
                                if tail not in protected or server_settings_mode=='saved':
                                    local_targets.append((destination(inst_dir,tail),'instance',tail))
                            if restore_wg and n.startswith('wg/') and n.endswith('.conf'):
                                tail=n.split('/',1)[1]
                                local_targets.append((destination(wg_dir,tail),'wg',tail))
                        if server_settings_mode=='custom':
                            for tail in ('runtime.json','panel_settings.json'):
                                local_targets.append((destination(inst_dir,tail),'instance',tail))
                    if kind in ('db','full'):
                        db_path=Path(DB_PATH)
                        local_targets.append((destination(db_path.parent,db_path.name),'db',db_path.name))
                    for dest,group,tail in local_targets:
                        _backup_existing(dest,group,tail)
                except (ValueError,RuntimeError,OSError) as exc:
                    return jsonify(ok=False,error='restore_preflight_failed',message='Restore preflight failed; no live files were replaced.'),400

                if kind in ("db", "full"):
                    for n in names:
                        if n.startswith("db/") and not n.endswith("/"):
                            _extract(n, db_dir, kind_name="db")

                    db_files = list(db_dir.glob("*.db"))

                    if db_files:
                        src = db_files[0]

                        try:
                            from panel_core.backup_integrity import validate_sqlite
                            validate_sqlite(src)
                            db_path = Path(DB_PATH)
                            db_path.parent.mkdir(parents=True, exist_ok=True)

                            _backup_existing(db_path, kind_name="db", rel_tail=db_path.name)

                            from reseller_portal.database import copy_database
                            db.session.remove()
                            db.engine.dispose()
                            copy_database(src,db_path)
                            restored["db"] = True

                        except Exception as e:
                            return jsonify(
                                ok=False,
                                error="db_restore_failed",
                                message=str(e)
                            ), 500
                    else:
                        warnings.append("db_requested_but_no_db_file_found")


                if kind in ("settings", "full"):
                    if has_inst:

                        server_local_files = {
                        "runtime.json",
                        "panel_settings.json",
                        "backup_schedule.json",
                        "backup_settings.json",
                        "backup_last.json",
                        "auto_backup.json",
                    }

                        skipped_server_files = []
                        restored_server_files = []

                        for n in names:
                            if not n.startswith("instance/") or n.endswith("/"):
                                continue

                            fname = os.path.basename(n)

                            if fname in server_local_files:
                                if server_settings_mode == "saved":
                                    _extract(n, inst_dir, kind_name="instance")
                                    restored_server_files.append(fname)
                                else:
                                    skipped_server_files.append(fname)
                                continue

                            _extract(n, inst_dir, kind_name="instance")

                        restored["settings"] = True

                        if skipped_server_files:
                            warnings.append(
                            "server_local_settings_protected: " +
                            ", ".join(sorted(set(skipped_server_files)))
                        )

                        if restored_server_files:
                            warnings.append(
                            "server_local_settings_restored: " +
                            ", ".join(sorted(set(restored_server_files)))
                        )

                        if server_settings_mode == "custom":
                            runtime_path = Path(app.instance_path) / "runtime.json"
                            panel_path = Path(app.instance_path) / "panel_settings.json"

                            port = custom_port or custom_http_port or custom_https_port
                            bind_host = custom_bind or "0.0.0.0"

                            if ":" in bind_host:
                                host_part, _, port_part = bind_host.rpartition(":")
                                bind_host = host_part or "0.0.0.0"
                                try:
                                    port = int(port_part)
                                except Exception:
                                    pass

                            if not port:
                                port = 443 if custom_scheme == "https" else 8000

                            runtime_payload = {
                            "bind": f"{bind_host}:{int(port)}",
                            "port": int(port),
                            "workers": 0,
                            "threads": 4,
                            "timeout": 60,
                            "graceful_timeout": 30,
                            "loglevel": "info",
                        }

                            panel_payload = {
                            "tls_enabled": custom_scheme == "https",
                            "domain": custom_domain,
                            "force_https_redirect": False,
                            "hsts": False,
                            "http_port": custom_http_port or (int(port) if custom_scheme == "http" else None),
                            "https_port": custom_https_port or (int(port) if custom_scheme == "https" else 443),
                            "tls_cert_path": "",
                            "tls_key_path": "",
                        }

                            for dest, payload in ((runtime_path,runtime_payload),(panel_path,panel_payload)):
                                dest=destination(inst, dest.name)
                                _backup_existing(dest,"instance",dest.name)
                                atomic_write(dest,BytesIO(json.dumps(payload,indent=2).encode()))

                            warnings.append(
                            "custom_server_settings_written: runtime.json, panel_settings.json"
                            )
                    else:
                        warnings.append("settings_requested_but_no_instance_files_found")


                if restore_wg and has_wg and kind in ("settings", "full"):
                    for n in names:
                        if n.startswith("wg/") and n.endswith(".conf"):
                            _extract(n, wg_dir, kind_name="wg")

                    restored["wg"] = True

                elif has_wg and not restore_wg:
                    warnings.append("wg_present_but_not_restored")


                if restore_wg and has_node_wg and kind in ("settings", "full"):
                    try:
                        node_restore_results = _restore_node_wg_zip(z, names)
                        restored["node_wg"] = any(
                            bool(x.get("ok"))
                            for x in node_restore_results
                        )

                        if not restored["node_wg"]:
                            warnings.append("node_wg_present_but_no_node_restore_success")

                    except Exception as e:
                        warnings.append(f"node_wg_restore_failed:{e}")

                elif has_node_wg and not restore_wg:
                    warnings.append("node_wg_present_but_not_restored")

                try:
                    _norm_adminlog({
                        "action": "backup_restore",
                        "details": (
                            f"kind={kind}; restore_wg={int(restore_wg)}; "
                            f"db={int(restored['db'])}; settings={int(restored['settings'])}; "
                            f"wg={int(restored['wg'])}; node_wg={int(restored['node_wg'])}"
                        ),
                        "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web",
                    })
                except Exception:
                    pass

                return jsonify(
                    ok=True,
                    kind=kind,
                    server_settings_mode=server_settings_mode,
                    detected={
                        "db": bool(has_db),
                        "settings": bool(has_inst),
                        "wg": bool(has_wg),
                        "node_wg": bool(has_node_wg),
                    },
                    restored=restored,
                    warnings=warnings,
                    node_restore_results=node_restore_results,
                    integrity=integrity,
                    partial=bool(restore_wg and has_node_wg and (not restored["node_wg"] or any(not x.get("ok") for x in node_restore_results))),
                    message="Restore processing finished. Review warnings and node results before restarting."
                )

            finally:
                try:
                    z.close()
                except Exception:
                    pass

        finally:
            if db_dir is not None:
                import shutil
                shutil.rmtree(db_dir, ignore_errors=True)
            try:
                Path(tmp.name).unlink(missing_ok=True)
            except Exception:
                pass

    def _node_backup_wg_zip(node: Node, timeout: int = 25) -> bytes:
        from panel_core.node_client import validate_base_url
        url = f"{validate_base_url(node.base_url)}/api/backup/wg"
        with requests.get(url,headers={'Authorization': f'Bearer {_read_api_key(node)}'},
                          timeout=timeout,allow_redirects=False,stream=True) as response:
            if response.status_code != 200:
                raise RuntimeError('Node backup request failed.')
            raw=bytearray()
            for chunk in response.iter_content(1024**2):
                raw.extend(chunk)
                if len(raw)>64*1024**2:raise ValueError('Node backup exceeds 64 MiB.')
            return bytes(raw)

    def _bundle_node_wg_backups(z: zipfile.ZipFile) -> list[dict]:
        results = []

        nodes = Node.query.order_by(Node.id.asc()).all()

        for node in nodes:
            rec = {
                "node_id": node.id,
                "name": node.name,
                "base_url": node.base_url,
                "ok": False,
                "files": [],
                "env_file": False,
                "error": "",
            }

            try:
                z.writestr(
                    f"nodes/{node.id}/meta.json",
                    json.dumps(
                        {
                            "node_id": node.id,
                            "name": node.name,
                            "base_url": node.base_url,
                            "enabled": bool(node.enabled),
                            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                        },
                        indent=2,
                    ),
                )

                if not node.enabled:
                    rec["error"] = "node_disabled"
                    results.append(rec)
                    continue

                raw = _node_backup_wg_zip(node)

                if not raw:
                    rec["error"] = "empty_node_backup"
                    results.append(rec)
                    continue

                try:
                    with zipfile.ZipFile(BytesIO(raw), "r") as nz:
                        from panel_core.backup_integrity import verify_archive
                        verify_archive(nz)
                        members = nz.namelist()

                        for member in members:


                            if member.startswith("wg/") and member.endswith(".conf"):
                                filename = os.path.basename(member)
                                if not filename:
                                    continue

                                data = nz.read(member)
                                z.writestr(f"nodes/{node.id}/wg/{filename}", data)
                                rec["files"].append(filename)
                                continue


                            if member == "env/.env":
                                try:
                                    data = nz.read(member)
                                    if data:
                                        z.writestr(f"nodes/{node.id}/env/.env", data)
                                        rec["env_file"] = True
                                except Exception as e:
                                    current_app.logger.warning(
                                        "Node env backup skipped node=%s url=%s error=%s",
                                        getattr(node, "id", "?"),
                                        getattr(node, "base_url", ""),
                                        e,
                                    )
                                continue

                    rec["files"] = sorted(set(rec["files"]))
                    rec["ok"] = bool(rec["files"] or rec["env_file"])

                    if not rec["ok"]:
                        rec["error"] = "node_backup_had_no_wg_or_env"

                except zipfile.BadZipFile:
                    rec["error"] = "node_backup_not_zip"
                except Exception as e:
                    rec["error"] = f"node_backup_read_failed: {type(e).__name__}"

            except Exception as e:
                rec["error"] = type(e).__name__
                current_app.logger.warning("Node backup failed node=%s error=%s",getattr(node,"id","?"),type(e).__name__)

            results.append(rec)

        return results

    def _node_wg_payloads_zip(
        z: zipfile.ZipFile,
        names: list[str],
    ) -> dict[int, dict]:
        payloads: dict[int, dict] = {}

        for member in names:

            match = re.match(
                r'^nodes/(\d+)/wg/([^/]+\.conf)$',
                member,
            )

            if match:
                node_id = int(match.group(1))
                filename = os.path.basename(
                    match.group(2)
                )

                try:
                    text = z.read(member).decode(
                        'utf-8',
                        'replace',
                    )
                except Exception:
                    continue

                payload = payloads.setdefault(
                    node_id,
                    {
                        'files': {},
                        'env_file': None,
                    },
                )

                payload['files'][filename] = text
                continue


            match = re.match(
                r'^nodes/(\d+)/env/\.env$',
                member,
            )

            if match:
                node_id = int(match.group(1))

                try:
                    text = z.read(member).decode(
                        'utf-8',
                        'replace',
                    )
                except Exception:
                    continue

                payload = payloads.setdefault(
                    node_id,
                    {
                        'files': {},
                        'env_file': None,
                    },
                )

                payload['env_file'] = text

        return payloads

    def _restore_node_wg_zip(
        z: zipfile.ZipFile,
        names: list[str],
    ) -> list[dict]:
        payloads = _node_wg_payloads_zip(
            z,
            names,
        )

        results = []

        for node_id, payload in payloads.items():
            node = db.session.get(
                Node,
                node_id,
            )

            files = payload.get('files') or {}
            env_file = payload.get('env_file')

            rec = {
                'node_id': node_id,
                'ok': False,
                'files': sorted(files.keys()),
                'env_file': bool(env_file),
                'error': '',
            }

            if not node:
                rec['error'] = (
                    'node_not_found_in_current_db'
                )
                results.append(rec)
                continue

            try:
                from panel_core.node_client import validate_base_url
                saved=json.loads(z.read(f'nodes/{node_id}/meta.json'))
                if (not isinstance(saved,dict) or saved.get('node_id')!=node_id or
                        validate_base_url(saved.get('base_url'))!=validate_base_url(node.base_url)):
                    raise ValueError('Node identity changed; restore manually after verifying the destination.')
                url=validate_base_url(node.base_url)+'/api/backup/wg/restore' 

                response = requests.post(
                    url,
                    headers={
                        'Authorization': (
                            f'Bearer {_read_api_key(node)}'
                        ),
                        'Content-Type': 'application/json',
                    },
                    json={
                        'files': files,
                        'env_file': env_file,
                        'bring_up': False,
                    },
                    timeout=35,
                    allow_redirects=False,
                )

                body=response.json()
                if response.status_code!=200 or not isinstance(body,dict) or body.get('ok') is not True:
                    rec['error']='Node restore not confirmed (HTTP '+str(response.status_code)+').'
                else:
                    rec['ok']=True

            except Exception as exc:
                rec['error']='Node restore not confirmed: '+type(exc).__name__

            results.append(rec)

        return results

    def _load_backup_schedule():
        d = _json_load(
            BACKUP_SCHEDULE_FILE,
            {},
        )

        return {
            "enabled": bool(
                d.get("enabled", False)
            ),
            "freq": d.get(
                "freq",
                "daily",
            ),
            "time": d.get(
                "time",
                "03:00",
            ),

            "timezone": _panel_timezone_name(),

            "dow": list(
                map(
                    str,
                    d.get("dow", []),
                )
            ),
            "dom": int(
                d.get("dom", 1)
            ),
            "cron": d.get(
                "cron",
                "",
            ),
            "keep": int(
                d.get("keep", 7)
            ),
            "include_wg": bool(
                d.get("include_wg", True)
            ),
            "send_to_telegram": bool(
                d.get(
                    "send_to_telegram",
                    False,
                )
            ),

            "telegram_chat_id": str(
                d.get(
                    "telegram_chat_id",
                    "",
                )
                or ""
            ).strip(),
        }

    def _save_backup_schedule(partial: dict):
        cur = _load_backup_schedule()

        cur.update({
            "enabled": bool(
                partial.get(
                    "enabled",
                    cur["enabled"],
                )
            ),
            "freq": (
                partial.get("freq")
                or cur["freq"]
            ).lower(),
            "time": (
                partial.get("time")
                or cur["time"]
            ),

            "timezone": _panel_timezone_name(),

            "dow": [
                str(x)
                for x in (
                    partial.get("dow")
                    or cur["dow"]
                    or []
                )
            ],
            "dom": int(
                partial.get("dom")
                or cur["dom"]
                or 1
            ),
            "cron": (
                partial.get("cron")
                or cur["cron"]
            ).strip(),
            "keep": max(
                1,
                int(
                    partial.get("keep")
                    or cur["keep"]
                    or 7
                ),
            ),
            "include_wg": bool(
                partial.get(
                    "include_wg",
                    cur["include_wg"],
                )
            ),
            "send_to_telegram": bool(
                partial.get(
                    "send_to_telegram",
                    cur["send_to_telegram"],
                )
            ),

            "telegram_chat_id": str(
                partial.get(
                    "telegram_chat_id",
                    cur.get(
                        "telegram_chat_id",
                        "",
                    ),
                )
                or ""
            ).strip(),
        })

        if not cur["send_to_telegram"]:
            cur["telegram_chat_id"] = ""

        _json_save(
            BACKUP_SCHEDULE_FILE,
            cur,
        )

        return cur

    def _load_backup_last():
        return _json_load(BACKUP_LAST_FILE, {})

    def _record_backup(kind: str, when_ts: int | None = None):

        last = _load_backup_last()
        if when_ts is None:
            iso = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        else:
            from datetime import timezone
            iso = datetime.fromtimestamp(int(when_ts), tz=timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
        last[f"{kind}_last"] = iso
        _json_save(BACKUP_LAST_FILE, last)

    def _backup_slot_datetime(
        slot: str,
        schedule: dict,
    ):
        raw = str(
            slot or ""
        ).strip()

        if ":" not in raw:
            return None

        _frequency, timestamp_text = (
            raw.split(
                ":",
                1,
            )
        )

        try:
            parsed = datetime.fromisoformat(
                timestamp_text
            )
        except Exception:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=_panel_timezone()
            )

        return parsed

    return {
        '_save_autobackup': _save_autobackup,
        '_db_path': _db_path,
        '_jsonl_bundle': _jsonl_bundle,
        '_env_bundle': _env_bundle,
        '_backup_prefs': _backup_prefs,
        '_backup_prefs_load': _backup_prefs_load,
        '_backup_prefs_save': _backup_prefs_save,
        '_backup_restore_impl': _backup_restore_impl,
        '_node_backup_wg_zip': _node_backup_wg_zip,
        '_bundle_node_wg_backups': _bundle_node_wg_backups,
        '_node_wg_payloads_zip': _node_wg_payloads_zip,
        '_restore_node_wg_zip': _restore_node_wg_zip,
        '_load_backup_schedule': _load_backup_schedule,
        '_save_backup_schedule': _save_backup_schedule,
        '_load_backup_last': _load_backup_last,
        '_record_backup': _record_backup,
        '_backup_slot_datetime': _backup_slot_datetime,
    }
