def build_routes(*,
    BACKUP_AUTO_DIR,
    BASE_DIR,
    BytesIO,
    InterfaceConfig,
    Node,
    PANEL_VERSION,
    Path,
    Peer,
    ShortLink,
    Subscription,
    SubscriptionPeer,
    ValidationError,
    _backup_prefs_load,
    _backup_prefs_save,
    _backup_restore_impl,
    _bundle_node_wg_backups,
    _db_path,
    _env_bundle,
    _jsonl_bundle,
    _load_backup_last,
    _load_backup_schedule,
    _next_run,
    _norm_adminlog,
    _panel_filename_stamp,
    _read_api_key,
    _record_backup,
    _save_autobackup,
    _save_backup_schedule,
    _send_zip_telegram,
    admin_required,
    app,
    current_app,
    current_user,
    datetime,
    db,
    json,
    jsonify,
    login_required,
    os,
    re,
    render_template,
    request,
    require_api_key,
    require_api_key_or_login,
    send_file,
    socket,
    validate_csrf,
    zipfile,
):

    @login_required
    def backup_page():
        return render_template('backup.html', database_backend=db.engine.dialect.name)

    @login_required
    def backup_restore():
        return _backup_restore_impl()

    @require_api_key
    def backup_restore_api():
        return _backup_restore_impl()

    @login_required
    def backup_inspect():
        import tempfile
        import zipfile
        from pathlib import Path

        f = request.files.get('file')

        if not f or not (f.filename or '').lower().endswith('.zip'):
            return jsonify(
                ok=False,
                error='no_file',
                message='Please upload a .zip backup file.'
            ), 400

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

                has_env = any(
                    n == 'env/.env'
                    for n in names
                )

                has_node_env = any(
                    n.startswith('nodes/') and n.endswith('/env/.env')
                    for n in names
                )

                local_wg_files = sorted([
                    os.path.basename(n)
                    for n in names
                    if n.startswith('wg/') and n.endswith('.conf')
                ])

                node_wg_files = []
                node_wg_nodes = {}
                node_env_files = []
                node_env_nodes = {}

                for n in names:
                    m = re.match(r'^nodes/(\d+)/wg/([^/]+\.conf)$', n)
                    if m:
                        node_id = int(m.group(1))
                        filename = os.path.basename(m.group(2))

                        node_wg_files.append({
                            'node_id': node_id,
                            'file': filename,
                            'path': n,
                        })

                        node_wg_nodes.setdefault(str(node_id), 0)
                        node_wg_nodes[str(node_id)] += 1
                        continue

                    m_env = re.match(r'^nodes/(\d+)/env/\.env$', n)
                    if m_env:
                        node_id = int(m_env.group(1))

                        node_env_files.append({
                            'node_id': node_id,
                            'file': '.env',
                            'path': n,
                        })

                        node_env_nodes.setdefault(str(node_id), 0)
                        node_env_nodes[str(node_id)] += 1
                        continue

                def _read_text(member):
                    try:
                        with z.open(member) as fh:
                            return fh.read().decode('utf-8', 'replace').strip()
                    except Exception:
                        return None

                def _read_json(member):
                    txt = _read_text(member)
                    if not txt:
                        return None
                    try:
                        return json.loads(txt)
                    except Exception:
                        return None

                created = _read_text('meta/created.txt')
                host = _read_text('meta/host.txt')
                manifest = _read_json('meta/manifest.json')
                node_wg_backup = _read_json('meta/node_wg_backup.json')

                runtime_settings = _read_json('instance/runtime.json') or {}
                panel_settings = _read_json('instance/panel_settings.json') or {}
                app_meta = _read_json('meta/app.json') or {}

                kind = 'unknown'

                if has_db and has_inst:
                    kind = 'full'
                elif has_db:
                    kind = 'db'
                elif has_inst:
                    kind = 'settings'

                contains = {
                    'database': bool(has_db),
                    'settings': bool(has_inst),
                    'local_wireguard_conf': bool(has_wg),
                    'remote_node_wireguard_conf': bool(has_node_wg),
                    'env_file': bool(has_env),
                    'remote_node_env': bool(has_node_env),
                    'short_links': any(n == 'instance/short_links.json' for n in names),
                    'manifest': bool(manifest),
                }

                counts = {
                    'local_wg_files': len(local_wg_files),
                    'node_wg_files': len(node_wg_files),
                    'node_wg_nodes': len(node_wg_nodes),
                    'node_env_files': len(node_env_files),
                    'node_env_nodes': len(node_env_nodes),
                    'instance_files': len([
                        n for n in names
                        if n.startswith('instance/') and not n.endswith('/')
                    ]),
                    'db_files': len([
                        n for n in names
                        if n.startswith('db/') and not n.endswith('/')
                    ]),
                }

                return jsonify(
                    ok=True,
                    integrity=integrity,
                    kind=kind,

                    has_db=has_db,
                    has_settings=has_inst,
                    has_wg=has_wg,
                    has_node_wg=has_node_wg,
                    has_env=has_env,
                    has_node_env=has_node_env,

                    contains=contains,
                    counts=counts,

                    local_wg_files=local_wg_files,
                    node_wg_files=node_wg_files,
                    node_wg_nodes=node_wg_nodes,
                    node_env_files=node_env_files,
                    node_env_nodes=node_env_nodes,

                    created=created,
                    host=host,

                    manifest=manifest,
                    node_wg_backup=node_wg_backup,

                    runtime=runtime_settings,
                    panel_settings=panel_settings,
                    app_meta=app_meta,
                )

            finally:
                try:
                    z.close()
                except Exception:
                    pass

        finally:
            try:
                Path(tmp.name).unlink(missing_ok=True)
            except Exception:
                pass

    @login_required
    @admin_required
    def backup_node_agent_install_command():
        node_id = request.args.get('node_id', type=int)
        node = db.session.get(Node, node_id) if node_id else None

        api_key = ''
        base_url = ''

        if node:
            try:
                api_key = _read_api_key(node)
            except Exception:
                api_key = ''
            base_url = getattr(node, 'base_url', '') or ''

        command = """sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.sh)"'"""

        return jsonify(
            ok=True,
            node_id=node_id,
            node_name=getattr(node, 'name', None) if node else None,
            base_url=base_url,
            has_api_key=bool(api_key),
            command=command,
            next_command="node",
            notes=[
                "Run the install command on the node server as root.",
                "After installation, open the node menu by running: node",
                "Use the same API key and port as the node record in this panel.",
                "Return to the panel, test the node, then restore node WireGuard configs."
            ],
        )

    @login_required
    def backups_autolist():
        root = Path(BACKUP_AUTO_DIR)
        root.mkdir(parents=True, exist_ok=True)

        files = []
        for p in root.glob('*.zip'):
            if p.is_symlink() or not p.is_file():continue
            try:
                st = p.stat()
            except OSError:
                continue
            files.append({
                "name": p.name,
                "size": st.st_size,
                "ts": int(st.st_mtime),
            })

        files.sort(key=lambda x: x["ts"], reverse=True)
        return jsonify(files=files)

    @require_api_key_or_login
    def backups_auto(fname):
        safe_name = os.path.basename(
            str(fname or '')
        )

        if (
            not safe_name
            or not safe_name.lower().endswith('.zip')
        ):
            return jsonify(
                ok=False,
                error='invalid_filename',
                message='Invalid backup filename.',
            ), 400

        backup_root = Path(
            BACKUP_AUTO_DIR
        ).resolve()

        backup_path = (
            backup_root / safe_name
        ).resolve()

        try:
            backup_path.relative_to(
                backup_root
            )
        except ValueError:
            return jsonify(
                ok=False,
                error='invalid_path',
                message='Invalid backup path.',
            ), 400

        if not backup_path.is_file():
            return jsonify(
                ok=False,
                error='not_found',
                message='The saved backup was not found.',
            ), 404

        if request.method == 'DELETE':
            try:
                file_size = backup_path.stat().st_size

                backup_path.unlink()

                current_app.logger.info(
                    'Automatic backup deleted: '
                    'file=%s size=%s',
                    safe_name,
                    file_size,
                )

                try:
                    _norm_adminlog({
                        'action': 'auto_backup_delete',
                        'details': (
                            f'file={safe_name}; '
                            f'size={file_size}'
                        ),
                        'channel': (
                            'api'
                            if (
                                request.headers.get(
                                    'Authorization'
                                )
                                or request.headers.get(
                                    'X-API-KEY'
                                )
                            )
                            else 'web'
                        ),
                    })
                except Exception:
                    pass

                return jsonify(
                    ok=True,
                    deleted=safe_name,
                    size=file_size,
                    message='Automatic backup deleted.',
                )

            except PermissionError:
                return jsonify(
                    ok=False,
                    error='permission_denied',
                    message=(
                        'The panel does not have permission '
                        'to delete this backup.'
                    ),
                ), 403

            except Exception as exc:
                current_app.logger.exception(
                    'Could not delete automatic backup '
                    '%s: %s',
                    safe_name,
                    exc,
                )

                return jsonify(
                    ok=False,
                    error='delete_failed',
                    message=str(exc),
                ), 500

        download = (
            request.args.get('download')
            == '1'
        )

        response=send_file(str(backup_path),mimetype='application/zip',as_attachment=True,download_name=backup_path.name,conditional=True)
        response.headers['Cache-Control']='private, no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        return response

    @require_api_key_or_login
    def inspect_saved_auto_backup(fname):
        safe_name = os.path.basename(
            str(fname or '')
        )

        if (
            not safe_name
            or not safe_name.lower().endswith('.zip')
        ):
            return jsonify(
                ok=False,
                error='invalid_filename',
                message='Invalid backup filename.',
            ), 400

        backup_root = Path(BACKUP_AUTO_DIR).resolve()
        backup_path = (
            backup_root / safe_name
        ).resolve()

        try:
            backup_path.relative_to(backup_root)
        except ValueError:
            return jsonify(
                ok=False,
                error='invalid_path',
                message='Invalid backup path.',
            ), 400

        if not backup_path.is_file():
            return jsonify(
                ok=False,
                error='not_found',
                message=(
                    'The saved backup file was not found.'
                ),
            ), 404

        try:
            with zipfile.ZipFile(
                backup_path,
                'r',
            ) as archive:
                from panel_core.backup_integrity import verify_archive
                try:integrity=verify_archive(archive)
                except ValueError as exc:return jsonify(ok=False,error='invalid_backup',message=str(exc)),400
                names = archive.namelist()

                def existing_files(prefix):
                    return [
                        name
                        for name in names
                        if (
                            name.startswith(prefix)
                            and not name.endswith('/')
                        )
                    ]

                def read_text(member):
                    if member not in names:
                        return None

                    try:
                        return (
                            archive.read(member)
                            .decode(
                                'utf-8',
                                'replace',
                            )
                            .strip()
                        )
                    except Exception:
                        return None

                def read_json(member):
                    text = read_text(member)

                    if not text:
                        return None

                    try:
                        return json.loads(text)
                    except Exception:
                        return None

                db_files = existing_files('db/')
                instance_files = existing_files(
                    'instance/'
                )

                local_wg_files = sorted([
                    os.path.basename(name)
                    for name in names
                    if (
                        name.startswith('wg/')
                        and name.endswith('.conf')
                    )
                ])

                node_wg_files = []
                node_wg_nodes = {}

                node_env_files = []
                node_env_nodes = {}

                for member in names:
                    match = re.match(
                        r'^nodes/(\d+)/wg/'
                        r'([^/]+\.conf)$',
                        member,
                    )

                    if match:
                        node_id = int(
                            match.group(1)
                        )

                        filename = os.path.basename(
                            match.group(2)
                        )

                        node_wg_files.append({
                            'node_id': node_id,
                            'file': filename,
                            'path': member,
                        })

                        node_key = str(node_id)

                        node_wg_nodes[node_key] = (
                            node_wg_nodes.get(
                                node_key,
                                0,
                            )
                            + 1
                        )

                        continue

                    match = re.match(
                        r'^nodes/(\d+)/env/\.env$',
                        member,
                    )

                    if match:
                        node_id = int(
                            match.group(1)
                        )

                        node_env_files.append({
                            'node_id': node_id,
                            'file': '.env',
                            'path': member,
                        })

                        node_key = str(node_id)

                        node_env_nodes[node_key] = (
                            node_env_nodes.get(
                                node_key,
                                0,
                            )
                            + 1
                        )

                has_db = bool(db_files)
                has_settings = bool(
                    instance_files
                )
                has_wg = bool(
                    local_wg_files
                )
                has_node_wg = bool(
                    node_wg_files
                )
                has_env = (
                    'env/.env'
                    in names
                )
                has_node_env = bool(
                    node_env_files
                )

                if has_db and has_settings:
                    kind = 'full'
                elif has_db:
                    kind = 'db'
                elif has_settings:
                    kind = 'settings'
                else:
                    kind = 'unknown'

                manifest = (
                    read_json(
                        'meta/manifest.json'
                    )
                    or {}
                )

                node_backup_results = (
                    read_json(
                        'meta/node_wg_backup.json'
                    )
                    or []
                )

                runtime_settings = (
                    read_json(
                        'instance/runtime.json'
                    )
                    or {}
                )

                panel_settings = (
                    read_json(
                        'instance/panel_settings.json'
                    )
                    or {}
                )

                app_meta = (
                    read_json(
                        'meta/app.json'
                    )
                    or {}
                )

                contains = {
                    'database': has_db,
                    'settings': has_settings,
                    'env_file': has_env,
                    'local_wireguard_conf': (
                        has_wg
                    ),
                    'remote_node_wireguard_conf': (
                        has_node_wg
                    ),
                    'remote_node_env': (
                        has_node_env
                    ),
                    'short_links': (
                        'instance/short_links.json'
                        in names
                    ),
                    'manifest': bool(manifest),
                }

                counts = {
                    'db_files': len(
                        db_files
                    ),
                    'instance_files': len(
                        instance_files
                    ),
                    'local_wg_files': len(
                        local_wg_files
                    ),
                    'node_wg_files': len(
                        node_wg_files
                    ),
                    'node_wg_nodes': len(
                        node_wg_nodes
                    ),
                    'node_env_files': len(
                        node_env_files
                    ),
                    'node_env_nodes': len(
                        node_env_nodes
                    ),
                }

                stat = backup_path.stat()

                return jsonify(
                    ok=True,
                    integrity=integrity,
                    filename=backup_path.name,
                    size=stat.st_size,
                    modified=int(
                        stat.st_mtime
                    ),
                    kind=kind,
                    created=read_text(
                        'meta/created.txt'
                    ),
                    host=read_text(
                        'meta/host.txt'
                    ),

                    has_db=has_db,
                    has_settings=has_settings,
                    has_wg=has_wg,
                    has_node_wg=has_node_wg,
                    has_env=has_env,
                    has_node_env=has_node_env,

                    contains=contains,
                    counts=counts,

                    local_wg_files=(
                        local_wg_files
                    ),
                    node_wg_files=(
                        node_wg_files
                    ),
                    node_wg_nodes=(
                        node_wg_nodes
                    ),
                    node_env_files=(
                        node_env_files
                    ),
                    node_env_nodes=(
                        node_env_nodes
                    ),

                    manifest=manifest,
                    node_wg_backup=(
                        node_backup_results
                    ),
                    runtime=runtime_settings,
                    panel_settings=(
                        panel_settings
                    ),
                    app_meta=app_meta,
                )

        except zipfile.BadZipFile:
            return jsonify(
                ok=False,
                error='invalid_zip',
                message=(
                    'The saved file is not a valid '
                    'ZIP backup.'
                ),
            ), 400

        except Exception as exc:
            app.logger.exception(
                'Saved auto-backup inspection '
                'failed for %s: %s',
                safe_name,
                exc,
            )

            return jsonify(
                ok=False,
                error='inspection_failed',
                message=str(exc),
            ), 500

    @require_api_key_or_login
    def backup_get():
        return jsonify(_backup_prefs_load())

    @require_api_key_or_login
    def backup_post():
        data = request.get_json(silent=True) or {}
        saved = _backup_prefs_save(data)
        return jsonify(ok=True, prefs=saved)

    @require_api_key_or_login
    def backup_db():
        postgres = db.engine.dialect.name == 'postgresql'
        dbp = _db_path() if not postgres else None
        if not postgres and (not dbp or not os.path.isfile(dbp)):
            return jsonify(error='db_not_found_or_not_sqlite'), 404

        mem = BytesIO()
        with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
            if postgres:
                from panel_core.postgres_backup import postgres_dump
                with postgres_dump(db.engine.url) as dump_path:
                    z.write(dump_path, arcname='db/wgpanel-postgresql.dump')
                z.writestr('meta/database-engine.txt', 'postgresql (pg_dump custom format)\n')
            else:
                from reseller_portal.database import snapshot
                with snapshot(dbp) as snapshot_path:
                    z.write(snapshot_path, arcname=f'db/{os.path.basename(dbp)}')
            z.writestr('meta/created.txt', datetime.utcnow().isoformat(timespec='seconds') + 'Z')
            from panel_core.backup_integrity import add_integrity
            add_integrity(z)

        mem.seek(0)

        ts = _panel_filename_stamp()
        fname = f'wgpanel_db_{ts}.zip'

        try:
            _norm_adminlog({
                "action": "backup_db",
                "details": f"file={fname} size={mem.getbuffer().nbytes}B",
                "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
            })
        except Exception:
            pass

        try: _record_backup('db')
        except Exception as e: current_app.logger.debug("record_backup(db) failed: %s", e)

        resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
        resp.headers['Cache-Control'] = 'private, no-store'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Backup-Integrity'] = 'sha256'
        resp.headers['X-Backup-Kind'] = 'db'
        resp.headers['X-Backup-Timestamp'] = ts
        return resp

    @require_api_key_or_login
    def backup_last_get():

        last = _load_backup_last() or {}
        def to_epoch(iso):
            try:
                from datetime import datetime, timezone
                return int(datetime.fromisoformat(iso.replace('Z','+00:00')).timestamp())
            except Exception:
                return 0

        candidates = [to_epoch(last.get(k,'')) for k in ('db_last','settings_last','full_last')]
        best = max(candidates) if any(candidates) else 0
        return jsonify(last_backup_ts = (best if best > 0 else None))

    @require_api_key_or_login
    def backup_last_post():
        data = request.get_json(silent=True) or {}
        kind = (data.get('kind') or 'full').lower()
        try:
            ts = int(data.get('last_backup_ts')) if data.get('last_backup_ts') is not None else None
        except Exception:
            ts = None
        try:
            _record_backup(kind, ts)
        except Exception as e:
            current_app.logger.debug("record_backup(%s) failed: %s", kind, e)
        return jsonify(ok=True)

    @require_api_key_or_login
    def backup_settings():
        mem = BytesIO()
        with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
            _jsonl_bundle(z)
            z.writestr('meta/created.txt', datetime.utcnow().isoformat(timespec='seconds') + 'Z')
            from panel_core.backup_integrity import add_integrity
            add_integrity(z)

        mem.seek(0)

        ts = _panel_filename_stamp()
        fname = f'wgpanel_settings_{ts}.zip'

        try:
            _norm_adminlog({
                "action": "backup_settings",
                "details": f"file={fname} size={mem.getbuffer().nbytes}B",
                "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
            })
        except Exception:
            pass

        try: _record_backup('settings')
        except Exception as e: current_app.logger.debug("record_backup(settings) failed: %s", e)

        resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
        resp.headers['Cache-Control'] = 'private, no-store'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Backup-Integrity'] = 'sha256'
        resp.headers['X-Backup-Kind'] = 'settings'
        resp.headers['X-Backup-Timestamp'] = ts
        return resp

    @require_api_key_or_login
    def backup_full():
        prefs = _backup_prefs_load()
        database_backend = db.engine.dialect.name
        dbp = _db_path() if database_backend != 'postgresql' else None
        if database_backend != 'postgresql' and not dbp:
            return jsonify(error='db_not_found_or_not_sqlite'), 404
        database_included = False

        include_wg = (
            request.args.get('wg') or
            ('1' if prefs.get('include_wg') else '0')
        ) == '1'

        send_tg = (
            request.args.get('tg') or
            ('1' if prefs.get('send_to_telegram') else '0')
        ) == '1'

        auto_flag = (request.args.get('auto') or '0') == '1'
        selected_chat_id = (request.args.get("chat_id")or "").strip()
        
        if current_user.is_authenticated and (send_tg or auto_flag):
            try:validate_csrf(request.headers.get('X-CSRFToken') or request.headers.get('X-CSRF-Token'))
            except ValidationError:return jsonify(error='A valid CSRF token is required for backup delivery or storage.'),400

        node_wg_results = []
        saved_auto_backup = None

        mem = BytesIO()

        with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:


            if database_backend == 'postgresql':
                from panel_core.postgres_backup import postgres_dump
                with postgres_dump(db.engine.url) as dump_path:
                    z.write(dump_path, arcname='db/wgpanel-postgresql.dump')
                database_included = True
                z.writestr('meta/database-engine.txt', 'postgresql (pg_dump custom format)\n')
            elif dbp and os.path.isfile(dbp):
                from reseller_portal.database import snapshot
                with snapshot(dbp) as snapshot_path:
                    z.write(snapshot_path, arcname=f'db/{os.path.basename(dbp)}')
                database_included = True


            _jsonl_bundle(z)


            _env_bundle(z)


            if include_wg:

                wgdir = app.config.get('WG_CONF_PATH') or '/etc/wireguard/'

                try:
                    for p in Path(wgdir).glob('*.conf'):
                        if p.is_file():
                            z.write(p, arcname=f'wg/{p.name}')
                except Exception as e:
                    current_app.logger.debug("Local WG bundle skipped: %s", e)


                try:
                    node_wg_results = _bundle_node_wg_backups(z)
                except Exception as e:
                    current_app.logger.warning("Node backup bundle skipped: %s", e)
                    node_wg_results = [{
                        'ok': False,
                        'files': [],
                        'env_file': False,
                        'error': str(e),
                    }]

            created_at = datetime.utcnow().isoformat(timespec='seconds') + 'Z'

            z.writestr('meta/created.txt', created_at)
            z.writestr('meta/host.txt', socket.gethostname())

            z.writestr(
                'meta/app.json',
                json.dumps({
                    'database_backend': database_backend,
                    'db_uri': db.engine.url.render_as_string(hide_password=True),
                    'wg_conf_path': app.config.get('WG_CONF_PATH') or '/etc/wireguard/',
                }, indent=2)
            )

            z.writestr(
                'meta/node_wg_backup.json',
                json.dumps(node_wg_results, indent=2)
            )


            try:
                from reseller_portal.models import (Account as RpAccount, Plan as RpPlan,
                    Ownership as RpOwnership, AccountSecurity as RpAccountSecurity,
                    PaymentVerification as RpPaymentVerification, ManagementBot as RpManagementBot)
                reseller_counts = {
                    'resellers': RpAccount.query.count(),
                    'reseller_plans': RpPlan.query.count(),
                    'reseller_ownership_rows': RpOwnership.query.count(),
                    'reseller_2fa_records': RpAccountSecurity.query.count(),
                    'manual_payment_verifications': RpPaymentVerification.query.count(),
                    'reseller_management_bots': RpManagementBot.query.count(),
                }
            except Exception:
                reseller_counts = {}

            try:
                manifest_counts = {
                    'nodes': Node.query.count(),
                    'interfaces': InterfaceConfig.query.count(),
                    'peers': Peer.query.count(),
                    'subscriptions': Subscription.query.count(),
                    'subscription_peers': SubscriptionPeer.query.count(),
                    'short_links': ShortLink.query.count(),
                }
            except Exception:
                manifest_counts = {}

            try:
                local_wg_count = 0
                if include_wg:
                    wgdir = app.config.get('WG_CONF_PATH') or '/etc/wireguard/'
                    local_wg_count = len([
                        p for p in Path(wgdir).glob('*.conf')
                        if p.is_file()
                    ])
            except Exception:
                local_wg_count = 0

            node_wg_count = 0
            node_env_count = 0

            try:
                for rec in node_wg_results or []:
                    node_wg_count += len(rec.get('files') or [])
                    if rec.get('env_file'):
                        node_env_count += 1
            except Exception:
                node_wg_count = 0
                node_env_count = 0

            panel_env_exists = bool((Path(BASE_DIR) / '.env').is_file())

            z.writestr(
                'meta/manifest.json',
                json.dumps({
                    'created_at': created_at,
                    'kind': 'full',
                    'panel_version': PANEL_VERSION,
                    'contains': {
                        'database': database_included,
                        'instance_json': True,
                        'env_file': bool(panel_env_exists),
                        'remote_node_env': bool(node_env_count > 0),
                        'short_links': True,
                        'subscriptions': True,
                        'nodes_metadata': True,
                        'reseller_tables_in_db_snapshot': database_included,
                        'reseller_2fa_and_payment_records': database_included,
                        'local_wireguard_conf': bool(include_wg and local_wg_count > 0),
                        'remote_node_wireguard_conf': bool(include_wg and node_wg_count > 0),
                    },
                    'counts': {
                        **manifest_counts,
                        **reseller_counts,
                        'local_wg_files': int(local_wg_count or 0),
                        'node_wg_files': int(node_wg_count or 0),
                        'node_env_files': int(node_env_count or 0),
                    },
                    'node_wg_backup': node_wg_results,
                }, indent=2)
            )
            from panel_core.backup_integrity import add_integrity
            add_integrity(z)

        mem.seek(0)

        ts = _panel_filename_stamp()
        fname = f'wgpanel_full_backup_{ts}.zip'
        data = mem.getvalue()


        if auto_flag:
            try:
                schedule = (_load_backup_schedule())
                keep = int(schedule.get("keep",7,))
            except Exception:
                keep = 7

            try:
                saved_auto_backup = (_save_autobackup(data,keep=keep,))
            except Exception as e:
                saved_auto_backup = None
                current_app.logger.error("Automatic backup storage failed: %s", type(e).__name__)


        telegram_ok = None
        telegram_message = ""

        if send_tg:
            telegram_ok, telegram_message = (
                _send_zip_telegram(data,fname,chat_id=selected_chat_id or None,))

        if send_tg and telegram_ok is False:
            current_app.logger.warning("Backup Telegram send failed: %s",telegram_message,)


        try:
            node_wg_count = 0
            node_env_count = 0

            for rec in node_wg_results or []:
                node_wg_count += len(rec.get('files') or [])
                if rec.get('env_file'):
                    node_env_count += 1

            _norm_adminlog({
                "action": "backup_full",
                "details": (
                    f"file={fname} size={len(data)}B "
                    f"wg={int(include_wg)} tg={int(send_tg)} auto={int(auto_flag)} "
                    f"node_wg_nodes={len(node_wg_results or [])} "
                    f"node_wg_files={node_wg_count} "
                    f"node_env_files={node_env_count}"
                ),
                "channel": (
                    "api"
                    if request.headers.get('Authorization') or request.headers.get('X-API-KEY')
                    else "web"
                ),
            })
        except Exception:
            pass

        try:
            _record_backup('full')
        except Exception as e:
            current_app.logger.debug("record_backup(full) failed: %s", e)

        out = BytesIO(data)
        out.seek(0)

        resp = send_file(
            out,
            mimetype='application/zip',
            as_attachment=True,
            download_name=fname,
        )

        try:
            node_env_count = sum(
                1 for rec in (node_wg_results or [])
                if rec.get('env_file')
            )
        except Exception:
            node_env_count = 0

        resp.headers['Cache-Control'] = 'private, no-store'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Backup-Integrity'] = 'sha256'
        resp.headers['X-Backup-Kind'] = 'full'
        resp.headers['X-Backup-Timestamp'] = ts
        resp.headers['X-Backup-WG'] = (
            '1'
            if include_wg
            else '0'
        )
        resp.headers['X-Backup-TG'] = (
           '1'
           if send_tg
           else '0'
        )
        resp.headers['X-Backup-AUTO'] = (
            '1'
            if auto_flag
            else '0'
        )
        resp.headers['X-Backup-Node-WG'] = str(
            len(
                node_wg_results
                or []
            )
        )
        resp.headers['X-Backup-Node-ENV'] = str(
            node_env_count
        )

        if isinstance(
            saved_auto_backup,
            dict,
        ):
            saved_name = str(
                saved_auto_backup.get(
                    'name'
                )
                or ''
            ).strip()

            try:
                saved_size = int(
                    saved_auto_backup.get(
                        'size'
                    )
                    or 0
                )
            except Exception:
                saved_size = 0

            try:
                saved_timestamp = int(saved_auto_backup.get('ts')or 0)
            except Exception:
                saved_timestamp = 0

            if saved_name:
                resp.headers[
                    'X-Backup-Saved-Name'
                ] = saved_name

            resp.headers[
                'X-Backup-Saved-Size'
            ] = str(
                saved_size
            )

            resp.headers[
                'X-Backup-Saved-Timestamp'
            ] = str(
                saved_timestamp
            )

        return resp

    @require_api_key_or_login
    def backup_status():
        return jsonify(_load_backup_last())

    @require_api_key_or_login
    def backup_schedule_get():
        s = _load_backup_schedule()
        s["next_run"] = _next_run(s)
        return jsonify(s)

    @require_api_key_or_login
    def backup_schedule_post():
        data = request.get_json(silent=True) or {}
        s = _save_backup_schedule(data)
        s["next_run"] = _next_run(s)
        return jsonify(ok=True, **s)

    return {
        'backup_page': backup_page,
        'backup_restore': backup_restore,
        'backup_restore_api': backup_restore_api,
        'backup_inspect': backup_inspect,
        'backup_node_agent_install_command': backup_node_agent_install_command,
        'backups_autolist': backups_autolist,
        'backups_auto': backups_auto,
        'inspect_saved_auto_backup': inspect_saved_auto_backup,
        'backup_get': backup_get,
        'backup_post': backup_post,
        'backup_db': backup_db,
        'backup_last_get': backup_last_get,
        'backup_last_post': backup_last_post,
        'backup_settings': backup_settings,
        'backup_full': backup_full,
        'backup_status': backup_status,
        'backup_schedule_get': backup_schedule_get,
        'backup_schedule_post': backup_schedule_post,
    }
