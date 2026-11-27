def build_routes(*,
    ADMIN_LOG_FILE,
    BytesIO,
    LOGS_SETTINGS_FILE,
    Path,
    _app_log_line,
    _application_log_paths,
    _applymute_log,
    _last_cleared,
    _load_retention,
    _norm_adminlog,
    _panel_display_datetime,
    _panel_filename_stamp,
    _panel_filter_datetime_utc_naive,
    _panel_timezone_name,
    _read_admin_logs,
    _read_tail,
    _save_retention,
    _utc_timestamp_iso,
    app,
    csrf,
    json,
    jsonify,
    login_required,
    now_ts,
    render_template,
    request,
    require_api_key_or_login,
    send_file,
    zipfile,
):

    @login_required
    def logs_retention():
        return jsonify(retention=_load_retention())

    @login_required
    def logs_retention_post():
        data = request.get_json(silent=True) or {}
        incoming = data.get("retention") or {}
        cur = _load_retention()

        for key in ("app", "tg_app", "tg_admin", "iface"):
            v = incoming.get(key)
            if isinstance(v, dict):
                cur[key]["max_mb"] = int(v.get("max_mb") or 0)
                cur[key]["max_age_days"] = int(v.get("max_age_days") or 0)
                cur[key]["daily_clear"] = bool(v.get("daily_clear") or False)

        _save_retention(cur)
        return jsonify(ok=True)

    @login_required
    def logs_page():
        return render_template('logs.html')

    @login_required
    def logs_settings_get():
        if LOGS_SETTINGS_FILE.exists():
            with open(LOGS_SETTINGS_FILE, 'r') as f:
                try:
                    cfg = json.load(f)
                except Exception:
                    cfg = {}
        else:
            cfg = {}

        cfg.setdefault('enabled', True)
        cfg.setdefault('include_debug', False)
        cfg.setdefault('persist', True)
        cfg.setdefault('telegram_notify', False)
        cfg.setdefault('retention_days', 7)
        cfg.setdefault('max_file_mb', 10)
        cfg.setdefault('rotate_files', 5)
        cfg.setdefault('mutes', [])
        cfg.setdefault('sources', {'app': True, 'admin': True, 'telegram': True, 'iface': True})
        cfg.setdefault('mute_save', False)
        cfg.setdefault('keep_last_lines', 0)

        return jsonify(cfg)

    @login_required
    def logs_settings_post():
        payload = request.get_json(force=True, silent=True) or {}
        LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOGS_SETTINGS_FILE, 'w') as f:
            json.dump(payload, f, indent=2)

        _applymute_log()

        return jsonify(ok=True)

    @login_required
    def logs_backup():
        source = request.args.get('source','app')
        iface  = request.args.get('iface','')
        files = []
        if source == 'app':
            files = [path for _, path in _application_log_paths()]
        elif source == 'admin':
            files = [Path(app.instance_path) / 'admin.log']
        elif source == 'telegram':
            files = [Path(app.instance_path) / 'telegram.log']
        elif source == 'iface' and iface:
            files = [Path(app.instance_path) / f'iface_{iface}.log']

        mem = BytesIO()
        with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
            for p in files:
                if p.exists():
                    z.write(p, arcname=p.name)
        mem.seek(0)
        ts = _panel_filename_stamp()
        return send_file(mem, mimetype='application/zip',
                         as_attachment=True, download_name=f'logs_backup_{source}_{ts}.zip')

    @login_required
    def app_logs():
        selected = (request.args.get('service') or '').strip()
        paths = _application_log_paths()
        if selected and selected not in {role for role, _ in paths}:
            return jsonify(ok=False, error='Unknown service'), 400
        if selected:
            paths = [(role, path) for role, path in paths if role == selected]
        if request.method == 'DELETE':
            try:
                for _, path in paths:
                    if path.exists():
                        with path.open('w'):pass
                _last_cleared("app")
            except OSError:
                return jsonify(ok=False, error="Could not clear selected logs"), 500
            return jsonify(ok=True)

        q = (request.args.get('q') or '').lower().strip()
        level = (request.args.get('level') or '').lower().strip()
        limit = max(10, min(int(request.args.get('limit') or 500), 2000))
        merged = []
        for role, path in paths:
            last_stamp = ''
            for line in _read_tail(str(path), 200_000).splitlines():
                rec = _app_log_line(line)
                if not rec:continue
                last_stamp = rec.get('ts') or last_stamp
                if role != 'panel':rec['msg'] = '['+role+'] '+rec['msg']
                if level and rec['level'] != level:continue
                if q and q not in (rec['msg'] or '').lower():continue
                rec['source'] = role
                merged.append((last_stamp, rec))
        merged.sort(key=lambda item:item[0])
        out = [row for _, row in merged[-limit:]]
        for rec in out:
            if rec.get('ts'):
                rec['time_display'] = _panel_display_datetime(rec['ts'],seconds=True)
        return jsonify(
            logs=out,
            display_timezone=_panel_timezone_name(),
            server_epoch=now_ts(),
        )

    @csrf.exempt
    @require_api_key_or_login
    def admin_logs():
        if request.method == 'GET':
            q        = (request.args.get('q') or '').strip().lower()
            action   = (request.args.get('action') or '').strip().lower()
            channel  = (request.args.get('channel') or '').strip().lower()
            limit    = max(10, min(int(request.args.get('limit') or 1000), 5000))
            from_s   = request.args.get('from') or ''
            to_s     = request.args.get('to') or ''
            logs     = _read_admin_logs(max_lines=max(1000, limit * 5))

            from_dt = _panel_filter_datetime_utc_naive(from_s)
            to_dt = _panel_filter_datetime_utc_naive(to_s)

            def in_range(ts_iso: str) -> bool:
                t = _panel_filter_datetime_utc_naive(ts_iso)

                if t is None:
                    return True

                if from_dt and t < from_dt:
                    return False

                if to_dt and t > to_dt:
                    return False

                return True

            def matches(rec: dict) -> bool:
                if q and q not in json.dumps(rec, ensure_ascii=False).lower():
                    return False
                if action and (rec.get('action', '').lower() != action):
                    return False
                if channel and (rec.get('channel', '').lower() != channel):
                    return False
                ts = rec.get('ts')
                if ts and not in_range(ts):
                    return False
                return True

            out = [r for r in logs if matches(r)]
            visible = []

            for rec in out[:limit]:
                row = dict(rec)
                normalized = _utc_timestamp_iso(
                    row.get('ts')
                )

                if normalized:
                    row['ts'] = normalized
                    row['time_display'] = _panel_display_datetime(
                        normalized,
                        seconds=True,
                    )

                visible.append(row)

            return jsonify(
                logs=visible,
                display_timezone=_panel_timezone_name(),
                server_epoch=now_ts(),
            )

        if request.method == 'DELETE':
            try:
                from flask_login import current_user as cu
                if not getattr(cu, "is_authenticated", False):
                    return jsonify(error="auth_required"), 401
            except Exception:
                return jsonify(error="auth_required"), 401

            ch = (request.args.get('channel') or '').strip().lower()
            try:
                if not ch:
                    open(ADMIN_LOG_FILE, 'w').close()
                    _last_cleared("tg_admin")
                else:
                    kept = []
                    with open(ADMIN_LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            try:
                                j = json.loads(line)
                                if (j.get('channel', '').lower() != ch):
                                    kept.append(line)
                            except Exception:
                                kept.append(line)
                    with open(ADMIN_LOG_FILE, 'w', encoding='utf-8') as f:
                        f.writelines(kept)
            except Exception:
                pass
            return jsonify(ok=True)

        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            data = {}

        _norm_adminlog(data)
        return jsonify(ok=True), 201

    return {
        'logs_retention': logs_retention,
        'logs_retention_post': logs_retention_post,
        'logs_page': logs_page,
        'logs_settings_get': logs_settings_get,
        'logs_settings_post': logs_settings_post,
        'logs_backup': logs_backup,
        'app_logs': app_logs,
        'admin_logs': admin_logs,
    }
