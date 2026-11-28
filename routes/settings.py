def build_routes(*,
    Path,
    TEMPLATE_SETTINGS_FILE,
    _int_or_none,
    _is_https,
    _load_panel_settings,
    _load_presets,
    _load_runtime,
    _load_template_settings,
    _panel_base,
    _panel_timezone,
    _panel_timezone_name,
    _public_ipv4,
    _render_peer_template_preview,
    _save_panel_settings,
    _save_presets,
    _save_runtime,
    _save_template_settings,
    _valid_timezone_name,
    admin_required,
    app,
    csrf,
    current_app,
    current_user,
    datetime,
    jsonify,
    login_required,
    now_ts,
    os,
    render_template,
    request,
    require_api_key_or_login,
    signal,
    subprocess,
    threading,
    time,
    timezone,
):

    @login_required
    @admin_required
    def runtime_get():
        saved = _load_runtime() or {}
        port_env = os.getenv('PORT')
        eff = {
            'bind':    os.getenv('BIND') or '',
            'port':    int(port_env) if (port_env and port_env.isdigit()) else None,
            'workers': _int_or_none(os.getenv('WORKERS')),
            'threads': _int_or_none(os.getenv('THREADS')),
            'timeout': _int_or_none(os.getenv('TIMEOUT')),
            'graceful_timeout': _int_or_none(os.getenv('GRACEFUL_TIMEOUT')),
            'loglevel': (os.getenv('LOGLEVEL') or '').lower() or None,
        }
        return jsonify(saved=saved, effective=eff, requires_restart=True)

    @login_required
    @admin_required
    def api_panel_restart():
        svc = os.getenv("PANEL_SERVICE_NAME", "wg-panel.service")

        try:
            try:
                next_base = _panel_base()
            except Exception:
                next_base = None

            current_app.logger.warning(
                "panel_restart requested by user=%s ip=%s service=%s next_base=%r",
                getattr(current_user, "username", "?"),
                request.remote_addr,
                svc,
                next_base,
            )

            docker_mode = str(os.getenv("DOCKER_MODE") or "").strip().lower() in {
                "1", "true", "yes", "on"
            } or Path("/.dockerenv").exists()

            if docker_mode:

                def _restart_container_process():
                    time.sleep(0.8)
                    os.kill(os.getpid(), signal.SIGTERM)

                threading.Thread(
                    target=_restart_container_process,
                    name="panel-container-restart",
                    daemon=True,
                ).start()
                return jsonify(
                    ok=True,
                    restarting=True,
                    service="docker-container",
                    next_url=next_base,
                )

            subprocess.Popen(["systemctl", "restart", svc])

            return jsonify(ok=True, restarting=True, service=svc, next_url=next_base)
        except Exception as e:
            current_app.logger.exception("panel_restart failed: %s", e)
            return jsonify(error=str(e)), 500

    @csrf.exempt
    @login_required
    @admin_required
    def runtime_post():
        data = request.get_json(silent=True) or {}
        cur  = _load_runtime() or {}
        new  = dict(cur)

        current_app.logger.debug(
            "runtime_post called by user=%s ip=%s payload=%r current=%r",
            getattr(current_user, "username", "?"),
            request.remote_addr,
            data,
            cur,
        )

        def as_int_or_none(val):
            try:
                return int(val)
            except Exception:
                return None

        try:
            if 'bind' in data and isinstance(data.get('bind'), str):
                raw_bind = data['bind']
                new['bind'] = raw_bind.strip() or (cur.get('bind') or '0.0.0.0')
                current_app.logger.debug("runtime_post bind field raw=%r resolved=%r", raw_bind, new['bind'])

            if 'port' in data and data['port'] is not None:
                raw_port = data['port']
                p = as_int_or_none(raw_port)
                if p is None:
                    raise ValueError(f"port must be a number (got {raw_port!r})")
                new['port'] = p
                current_app.logger.debug("runtime_post port field raw=%r int=%r", raw_port, p)

                b = (new.get('bind') or cur.get('bind') or os.getenv('BIND') or '0.0.0.0').strip()
                if ':' in b:
                    host, _sep, _old = b.rpartition(':')
                    host = host or '0.0.0.0'
                    new['bind'] = f'{host}:{new["port"]}'
                else:
                    new['bind'] = b
                current_app.logger.debug("runtime_post normalized bind=%r", new['bind'])

            if 'workers' in data and data['workers'] is not None:
                new['workers'] = as_int_or_none(data['workers']) or 0
            if 'threads' in data and data['threads'] is not None:
                new['threads'] = as_int_or_none(data['threads']) or 4
            if 'timeout' in data and data['timeout'] is not None:
                new['timeout'] = as_int_or_none(data['timeout']) or 60
            if 'graceful_timeout' in data and data['graceful_timeout'] is not None:
                new['graceful_timeout'] = as_int_or_none(data['graceful_timeout']) or 30
            if 'loglevel' in data and data['loglevel']:
                ll_raw = str(data['loglevel']).strip().lower()
                new['loglevel'] = ll_raw
                current_app.logger.debug("runtime_post loglevel raw=%r normalized=%r", data['loglevel'], ll_raw)

            if 'ssl_certfile' in data and data['ssl_certfile']:
                new['ssl_certfile'] = data['ssl_certfile'].strip()
            if 'ssl_keyfile' in data and data['ssl_keyfile']:
                new['ssl_keyfile'] = data['ssl_keyfile'].strip()

            current_app.logger.debug("runtime_post final new config=%r", new)

            _save_runtime(new)
            current_app.logger.info(
                "runtime_saved user=%s ip=%s from=%s to=%s",
                getattr(current_user, 'username', '?'),
                request.remote_addr,
                cur,
                new,
            )
            return jsonify(ok=True, saved=new, requires_restart=True)

        except Exception as exc:
            current_app.logger.warning(
                "runtime_post failed user=%s ip=%s error=%s payload=%r partial_new=%r",
                getattr(current_user, "username", "?"),
                request.remote_addr,
                exc,
                data,
                new,
                exc_info=True,
            )
            return jsonify(error=str(exc)), 400

    @login_required
    def settings_page():
        return render_template('settings.html')

    @login_required
    def api_settings():

        if request.method == 'GET':
            s = _load_panel_settings() or {}
            xfp = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip().lower()
            detected_https = bool(_is_https())
            certp = (s.get("tls_cert_path") or "").strip()
            keyp  = (s.get("tls_key_path")  or "").strip()
            tls_cert_exists = bool(certp and os.path.isfile(certp))
            tls_key_exists  = bool(keyp and os.path.isfile(keyp))
            tls_effective   = bool(getattr(app, "_tls_enabled_effective", False))

            domain = (s.get('domain') or '').strip()
            if not domain:
                try:
                    from urllib.parse import urlparse
                    env_panel = (os.getenv('PANEL') or '').strip()
                    if env_panel:
                        domain = (urlparse(env_panel).hostname or '').strip() or domain
                except Exception:
                    pass
                if not domain:
                    domain = (request.host or '').split(':', 1)[0].strip()

            def _to_int(v):
                try:
                    if v is None or v == "":
                        return None
                    return int(v)
                except Exception:
                    return None

            s_out = dict(s)
            s_out["http_port"] = _to_int(s.get("http_port"))
            s_out["https_port"] = _to_int(s.get("https_port"))

            return jsonify({
            **s_out,
            "tls_enabled": bool(s.get("tls_enabled")),
            "tls_effective": tls_effective,
            "tls_cert_exists": tls_cert_exists,
            "tls_key_exists": tls_key_exists,
            "domain": domain,
            "current_scheme": "https" if detected_https else "http",
            "cookie_secure": bool(app.config.get("SESSION_COOKIE_SECURE", False)),
            "detected_https": bool(detected_https),
         })


        data = request.get_json(silent=True) or {}
        cur = _load_panel_settings() or {}

        def _port(v):
            if v in (None, ""):
                return None
            try:
                i = int(v)
            except Exception:
                return None
            return i if 1 <= i <= 65535 else None

        tls_enabled = bool(data.get("tls_enabled", False))
        domain      = (data.get("domain") or "").strip()

        force_https = bool(data.get("force_https_redirect", False))
        hsts        = bool(data.get("hsts", False))
        requested_timezone = (
            data.get("timezone")
            if "timezone" in data
            else cur.get("timezone")
            )

        panel_timezone = _valid_timezone_name(
            requested_timezone
        )

        if not panel_timezone:
            return jsonify(
                ok=False,
                error="invalid_timezone",
                message=(
                "Timezone must be a valid "
                "IANA timezone such as "
                "Asia/Tehran or Europe/Amsterdam."
                ),
            ), 400

        if not tls_enabled:
            force_https = False
            hsts = False

        http_port  = _port(data.get("http_port"))
        https_port = _port(data.get("https_port"))


        if tls_enabled and https_port is None:
            https_port = _port(cur.get("https_port"))
        if (not tls_enabled) and http_port is None:
            http_port = _port(cur.get("http_port"))

        tls_cert_path = (cur.get("tls_cert_path") or "").strip()
        tls_key_path  = (cur.get("tls_key_path")  or "").strip()

        payload = {
            "tls_enabled": tls_enabled,
            "domain": domain,
            "force_https_redirect": force_https,
            "hsts": hsts,
            "http_port": http_port,
            "https_port": https_port,
            "tls_cert_path": tls_cert_path,
            "tls_key_path": tls_key_path,
            "timezone": panel_timezone,
        }

        _save_panel_settings(payload)

        try:
            xfp = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
            serving_https = (xfp == "https") or bool(request.is_secure)
            if serving_https:
                app.config.update(
                    SESSION_COOKIE_SECURE=True,
                    REMEMBER_COOKIE_SECURE=True,
                    SESSION_COOKIE_SAMESITE="Lax",
                )
        except Exception:
            pass

        try:
            next_url = _panel_base()
        except Exception:
            next_url = None

        return jsonify(ok=True, settings=payload, next_url=next_url, requires_restart=False)

    @require_api_key_or_login
    def api_timezone():
        tz_name = _panel_timezone_name()
        tz = _panel_timezone()

        now_utc = datetime.now(
            timezone.utc
        )

        now_local = now_utc.astimezone(
            tz
        )

        return jsonify(
            ok=True,
            timezone=tz_name,
            server_epoch=now_ts(),
            utc_now=now_utc.isoformat(
                timespec="seconds"
            ).replace(
                "+00:00",
                "Z",
            ),
            local_now=now_local.isoformat(
                timespec="seconds"
            ),
            utc_offset=now_local.strftime(
                "%z"
            ),
        )

    @login_required
    def template_settings_get():
        return jsonify(_load_template_settings())

    @login_required
    def template_settings_post():
        from panel_operations.templates import validate
        import fcntl
        lock_path = TEMPLATE_SETTINGS_FILE + '.lock'
        os.makedirs(app.instance_path, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                cur = validate(request.get_json(silent=True), _load_template_settings())
            except (ValueError, TypeError) as exc:
                return jsonify(error=str(exc)), 400
            _save_template_settings(cur)
        return jsonify(ok=True, settings=cur)

    @login_required
    def preview_template(name):
        return _render_peer_template_preview(name, _load_template_settings())

    @require_api_key_or_login
    def endpoint_presets():
        if request.method == 'GET':
            return jsonify(presets=_load_presets(), public_ipv4=_public_ipv4())

        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            host = (data.get('host') or '').strip()
            port = int(data.get('port') or 0)
            label = (data.get('label') or '').strip() or f"{host}:{port}"
            if not host or port <= 0:
                return jsonify(error='host and port required'), 400
            presets = _load_presets()
            updated = False
            for p in presets:
                if p.get('host') == host and int(p.get('port') or 0) == port:
                    p.update({'label': label}); updated = True; break
            if not updated:
                presets.append({'label': label, 'host': host, 'port': port})
            _save_presets(presets)
            return jsonify(success=True, presets=presets)

        data = request.get_json(silent=True) or {}
        host = (data.get('host') or '').strip()
        port = int(data.get('port') or 0)
        presets = [p for p in _load_presets() if not (p.get('host') == host and int(p.get('port') or 0) == port)]
        _save_presets(presets)
        return jsonify(success=True, presets=presets)

    return {
        'runtime_get': runtime_get,
        'api_panel_restart': api_panel_restart,
        'runtime_post': runtime_post,
        'settings_page': settings_page,
        'api_settings': api_settings,
        'api_timezone': api_timezone,
        'template_settings_get': template_settings_get,
        'template_settings_post': template_settings_post,
        'preview_template': preview_template,
        'endpoint_presets': endpoint_presets,
    }
