def launch(context):
    Config = context.Config
    LOG_LEVEL = context.LOG_LEVEL
    SchemaMigrationError = context.SchemaMigrationError
    _applymute_log = context._applymute_log
    _load_panel_settings = context._load_panel_settings
    _load_runtime = context._load_runtime
    _start_web_background = context._start_web_background
    _web_worker_initialized = context._web_worker_initialized
    app = context.app
    bootstrap = context.bootstrap
    db = context.db
    os = context.os
    psutil = context.psutil
    sys = context.sys
    time = context.time
    import multiprocessing, ssl

    use_gunicorn = os.getenv("USE_GUNICORN", "1") != "0"

    def _tls_paths():
        try:
            s = _load_panel_settings() or {}
        except Exception:
            s = {}
        cert = (s.get("tls_cert_path") or "").strip()
        key  = (s.get("tls_key_path")  or "").strip()
        return cert, key

    cert_path, key_path = _tls_paths()

    try:
        ps = _load_panel_settings() or {}
    except Exception:
        ps = {}

    def _valid_port(x, dflt):
        try:
            i = int(x)
            return i if 1 <= i <= 65535 else dflt
        except Exception:
            return dflt

    http_port  = _valid_port(ps.get("http_port")  or 8000, 8000)
    https_port = _valid_port(ps.get("https_port") or 443, 443)

    tls_toggle = bool(ps.get("tls_enabled"))
    tls_files  = bool(
        cert_path and key_path and
        os.path.isfile(cert_path) and os.path.isfile(key_path)
    )
    tls_enabled = bool(tls_toggle and tls_files)

    try:
        rt = _load_runtime() or {}
    except Exception:
        rt = {}

    bind_from_rt = (rt.get("bind") or "").strip()
    try:
        port_from_rt = int(rt.get("port") or 0)
    except Exception:
        port_from_rt = 0

    host = (os.getenv("BIND_HOST") or "0.0.0.0").strip()
    bind_from_env = (os.getenv("BIND") or "").strip()

    if bind_from_env:
        bind = bind_from_env
    elif tls_enabled:
        bind = f"{host}:{https_port}"
    else:
        if bind_from_rt:
            bind = bind_from_rt
        else:
            eff_http_port = port_from_rt if port_from_rt else http_port
            eff_http_port = _valid_port(eff_http_port, 8000)
            bind = f"{host}:{eff_http_port}"

    app._tls_enabled_effective = bool(tls_enabled)

    app.config["PREFERRED_URL_SCHEME"] = "https" if tls_enabled else "http"
    cookie_secure = bool(tls_enabled or Config.SECURE_COOKIES)
    app.config.update(
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if not use_gunicorn:
        ssl_ctx = (cert_path, key_path) if tls_enabled else None

        if tls_enabled:
            chosen_port = int(os.getenv("DEV_PORT", str(https_port)))
        else:
            try:
                rt2 = _load_runtime() or {}
                rt_port = int(rt2.get("port") or 0)
            except Exception:
                rt_port = 0
            http_base = rt_port if rt_port else http_port
            chosen_port = int(os.getenv("DEV_PORT", str(_valid_port(http_base, 8000))))

        bootstrap()
        _start_web_background()
        app.run(
            host=os.getenv("DEV_HOST", "127.0.0.1"),
            port=chosen_port,
            debug=os.getenv("FLASK_DEBUG", "0") == "1",
            ssl_context=ssl_ctx,
        )
        sys.exit(0)

    from gunicorn.app.base import BaseApplication

    try:
        if int(rt.get("workers", 0)) > 0:
            os.environ["WORKERS"] = str(rt["workers"])
        if "threads" in rt:
            os.environ["THREADS"] = str(rt.get("threads", 4))
        if "timeout" in rt:
            os.environ["TIMEOUT"] = str(rt.get("timeout", 60))
        if "graceful_timeout" in rt:
            os.environ["GRACEFUL_TIMEOUT"] = str(rt.get("graceful_timeout", 30))
        if "loglevel" in rt:
            os.environ["LOGLEVEL"] = (rt.get("loglevel") or "info").lower()
    except Exception:
        pass

    class _Guni(BaseApplication):
        def __init__(self, wsgi_app, options=None):
            self.options = options or {}
            self.application = wsgi_app
            super().__init__()

        def load_config(self):
            cfg = {k: v for k, v in self.options.items()
                   if k in self.cfg.settings and v is not None}
            for k, v in cfg.items():
                self.cfg.set(k.lower(), v)

        def load(self):
            return self.application

    def _env_int(name, dflt):
        try:
            return int(os.getenv(name) or dflt)
        except Exception:
            return dflt

    cpu_based_default_workers = 1 if psutil.virtual_memory().total < 2 * 1024**3 else min(2, multiprocessing.cpu_count())
    workers          = max(1, _env_int("WORKERS", cpu_based_default_workers))
    threads          = max(1, min(8, _env_int("THREADS", 4)))
    timeout          = _env_int("TIMEOUT", 60)
    graceful_timeout = _env_int("GRACEFUL_TIMEOUT", 30)
    loglevel         = (os.getenv("LOGLEVEL") or "info").lower()

    app.logger.handlers[:] = []
    app.logger.propagate = True
    try:
        app.logger.setLevel(LOG_LEVEL)
    except Exception:
        pass
    try:
        _applymute_log()
    except Exception:
        pass

    context.APP_START_TS = int(time.time())
    app.logger.info("Panel started (TLS=%s, bind=%s)", "on" if tls_enabled else "off", bind)
    from importlib.metadata import version as _package_version
    app.logger.info(
        "Gunicorn runtime: version=%s worker=gthread workers=%s timeout=%ss",
        _package_version("gunicorn"), workers, timeout,
    )

    def _worker_abort(worker):
        import faulthandler
        faulthandler.dump_traceback(file=sys.stderr, all_threads=True)

    from panel_core.http_worker import ssl_context as bounded_ssl_context, heartbeat_directory
    options = {
        "worker_abort": _worker_abort,
        "post_worker_init": _web_worker_initialized,
        "bind": bind,
        "workers": workers,
        "worker_class": "panel_core.http_worker.BoundedThreadWorker",
        "ssl_context": bounded_ssl_context,
        "worker_tmp_dir": heartbeat_directory(),
        "threads": threads,
        "control_socket_disable": True,
        "timeout": timeout,
        "graceful_timeout": graceful_timeout,

        "accesslog": None,

        "forwarded_allow_ips": "",
        "errorlog": "-",
        "loglevel": loglevel,
        "preload_app": False,
        "capture_output": True,
    }

    if tls_enabled:
        if not os.path.isfile(cert_path):
            raise RuntimeError(f"TLS cert not found: {cert_path}")
        if not os.path.isfile(key_path):
            raise RuntimeError(f"TLS key not found: {key_path}")
        options["certfile"] = cert_path
        options["keyfile"]  = key_path

        app.config.update(
            SESSION_COOKIE_SECURE=True,
            REMEMBER_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE="Lax",
        )

    try:
        bootstrap()
    except SchemaMigrationError as e:
        app.logger.critical(
            "Refusing to start: the database schema could not be migrated: %s", e
        )
        raise SystemExit(1)
    except Exception as e:
        app.logger.exception("bootstrap failed: %s", e)
        raise SystemExit(1)

    with app.app_context():
        db.session.remove()
        for engine in db.engines.values():
            engine.dispose()

    _Guni(app, options).run()
