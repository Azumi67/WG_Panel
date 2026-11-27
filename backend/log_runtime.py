def bind_read_admin_logs(_panel_context):
    def _read_admin_logs(max_lines=2000):
        rows = []
        try:
            with open(_panel_context.ADMIN_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(_panel_context.json.loads(line))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        return rows[-max_lines:]


    def _whoami_logs() -> tuple[str, str]:
        try:
            from flask_login import current_user as cu
            if cu and getattr(cu, "is_authenticated", False):
                aid = str(getattr(cu, "id", "") or getattr(cu, "username", "") or "")
                uname = getattr(cu, "username", None) or ""
                return aid, uname
        except Exception:
            pass
        try:
            from flask import session
            aid = str(session.get("user_id") or session.get("username") or "")
            uname = str(session.get("username") or "")
            return aid, uname
        except Exception:
            return "", ""


    def _load_log_settings():
        try:
            with open(_panel_context.LOGS_SETTINGS_FILE, "r", encoding="utf-8") as f:
                return _panel_context.json.load(f)
        except Exception:
            return {}


    def _save_log_settings(data: dict):
        _panel_context.LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_panel_context.LOGS_SETTINGS_FILE, "w", encoding="utf-8") as f:
            _panel_context.json.dump(data, f, indent=2)


    def _src_defaults(d=None):
        d = d or {}
        return {
            "max_mb":         int(d.get("max_mb") or 0),
            "max_age_days":   int(d.get("max_age_days") or 0),
            "daily_clear":    bool(d.get("daily_clear") or False),
            "last_daily_utc": d.get("last_daily_utc") or "",
            "last_cleared_utc": d.get("last_cleared_utc") or "",
        }


    def _load_retention():
        settings = _panel_context._load_log_settings()
        r = settings.get("retention") or {}
        return {
            "app":      _panel_context._src_defaults(r.get("app")),
            "tg_app":   _panel_context._src_defaults(r.get("tg_app")),
            "tg_admin": _panel_context._src_defaults(r.get("tg_admin")),
            "iface":    _panel_context._src_defaults(r.get("iface")),
        }


    def _save_retention(ret: dict):
        settings = _panel_context._load_log_settings()
        settings["retention"] = ret
        _panel_context._save_log_settings(settings)


    def _last_cleared(persist_key: str | None):

        if not persist_key:
            return
        try:
            cur = _panel_context._load_retention()
            group = persist_key.split(":", 1)[0]
            if group not in cur:
                cur[group] = _panel_context._src_defaults()
            cur[group]["last_cleared_utc"] = _panel_context.datetime.utcnow().isoformat(
                timespec="seconds"
            ) + "Z"
            _panel_context._save_retention(cur)
        except Exception:
            pass


    def run_log():
        try:
            cfg = _panel_context._load_retention()
        except Exception:
            cfg = {}

        def conf(key):
            return cfg.get(key) or {}

        try:
            for _, path in _panel_context._application_log_paths():
                _panel_context._may_autoclear(path, conf("app"), persist_key="app")
        except Exception:
            pass

        try:
            _panel_context._may_autoclear(_panel_context.Path(_panel_context.TELEGRAM_LOG_FILE), conf("tg_app"), persist_key="tg_app")
        except Exception:
            pass

        try:
            _panel_context._may_autoclear(_panel_context.Path(_panel_context.TELEGRAM_ADMIN_LOG_FILE), conf("tg_admin"), persist_key="tg_admin")
        except Exception:
            pass

        try:
            iface_dir = _panel_context.Path(_panel_context.INSTANCE_DIR) / "iface_logs"
            if iface_dir.is_dir():
                for p in iface_dir.glob("*.log"):
                    key = f"iface:{p.stem}"
                    _panel_context._may_autoclear(p, conf("iface"), persist_key=key)
        except Exception:
            pass

    return {
        '_read_admin_logs': _read_admin_logs,
        '_whoami_logs': _whoami_logs,
        '_load_log_settings': _load_log_settings,
        '_save_log_settings': _save_log_settings,
        '_src_defaults': _src_defaults,
        '_load_retention': _load_retention,
        '_save_retention': _save_retention,
        '_last_cleared': _last_cleared,
        'run_log': run_log,
    }


def bind_retention_loop(_panel_context):
    def _retention_loop():
        while True:
            try:
                _panel_context.run_log()
            except Exception as exc:
                try:
                    _panel_context.app.logger.exception("Log retention sweep failed: %s", exc)
                except Exception:
                    pass

            _panel_context.time.sleep(_panel_context._RETENTION_INTERVAL_SEC)


    def _start_retention():
        pass
        if _panel_context._RETENTION_THREAD_STARTED:
            return

        _panel_context._RETENTION_THREAD_STARTED = True
        t = _panel_context.threading.Thread(
            target=_panel_context._retention_loop,
            name="log-retention",
            daemon=True,
        )
        t.start()


    def _may_autoclear(path: _panel_context.Path, rules: dict, persist_key: str | None = None):
        try:
            p = _panel_context.Path(path)
            if not p.exists():
                return

            max_mb = int(rules.get("max_mb") or 0)
            if max_mb > 0 and p.stat().st_size > (max_mb * 1024 * 1024):
                open(p, "w").close()
                _panel_context._last_cleared(persist_key)
                return

            max_days = int(rules.get("max_age_days") or 0)
            if max_days > 0:
                import time
                age_days = (time.time() - p.stat().st_mtime) / 86400.0
                if age_days > max_days:
                    open(p, "w").close()
                    _panel_context._last_cleared(persist_key)
                    return

            if rules.get("daily_clear"):
                now = _panel_context.datetime.utcnow()
                today = now.strftime("%Y-%m-%d")
                last  = rules.get("last_daily_utc") or ""
                if last != today and 3 <= now.hour < 4:
                    open(p, "w").close()
                    if persist_key:
                        try:
                            cur = _panel_context._load_retention()
                            group = persist_key.split(":", 1)[0]
                            if group not in cur:
                                cur[group] = _panel_context._src_defaults()
                            cur[group]["last_daily_utc"] = today
                            cur[group]["last_cleared_utc"] = now.isoformat(timespec="seconds") + "Z"
                            _panel_context._save_retention(cur)
                        except Exception:
                            pass
                    else:
                        _panel_context._last_cleared(persist_key)
        except Exception:
            pass

    return {
        '_retention_loop': _retention_loop,
        '_start_retention': _start_retention,
        '_may_autoclear': _may_autoclear,
    }


def bind_read_tail(_panel_context):
    def _read_tail(path: str, max_bytes: int = 50000) -> str:
        try:
            with open(path, 'rb') as f:
                f.seek(0, _panel_context.os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - max_bytes), _panel_context.os.SEEK_SET)
                data = f.read().decode('utf-8', errors='replace')
            return data
        except Exception:
            return ""

    return {
        '_read_tail': _read_tail,
    }


def bind_norm_adminlog(_panel_context):
    def _norm_adminlog(entry: dict):

        channel = (entry.get("channel") or
                   ("web" if (hasattr(_panel_context.current_app, "login_manager") and
                              hasattr(_panel_context.sys.modules.get(__name__), "login") and
                              ("session" in _panel_context.request.headers or _panel_context.request.cookies)) else "api"))

        row = {
            "ts": _panel_context.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "request_id": entry.get("request_id") or _panel_context.secrets.token_hex(6),
            "channel": channel,
            "admin_id": str(entry.get("admin_id") or ""),
            "admin_username": entry.get("admin_username") or "",
            "action": entry.get("action") or "",
            "resource": {
                "peer_id": entry.get("peer_id"),
                "iface": entry.get("iface"),
                "scope": entry.get("scope"),
            },
            "details": entry.get("details") or "",
            "result": entry.get("result") or "ok",
            "meta": {
                "bot_host": entry.get("bot_host") or "",
                "user_agent": _panel_context.request.headers.get("User-Agent", "") if channel == "web" else "",
            },
        }
        _panel_context._extend_file(_panel_context.ADMIN_LOG_FILE, _panel_context.json.dumps(row, ensure_ascii=False), source='admin')


    def logpanel_action(action: str, details: str = ""):
        _panel_context._norm_adminlog({"action": action, "details": details})


    def _will_persist() -> bool:
        s = _panel_context._load_log_settings() or {}
        return bool(s.get('enabled', True) and s.get('persist', True) and not s.get('mute_save', False))


    def _auto_trim(path: str | _panel_context.Path):
        try:
            s = _panel_context._load_log_settings() or {}
            n = int(s.get('keep_last_lines') or 0)
            p = _panel_context.Path(path)
            if n > 0 and p.exists():
                with p.open('r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                if len(lines) > n:
                    with p.open('w', encoding='utf-8') as f:
                        f.writelines(lines[-n:])
        except Exception:
            pass


    def _log_save(source: str) -> bool:
        s = _panel_context._load_log_settings() or {}
        if not s.get('enabled', True): return False
        if s.get('mute_save', False):  return False
        if not s.get('persist', True): return False
        return bool((s.get('sources') or {}).get(source, True))


    def _extend_file(path: str | _panel_context.Path, text: str, source: str = 'app'):
        if not _panel_context._log_save(source):
            return
        p = _panel_context.Path(path); p.parent.mkdir(parents=True, exist_ok=True)
        if not text.endswith('\n'): text += '\n'
        try:
            with p.open('a', encoding='utf-8') as f:
                f.write(text)
        except Exception:
            pass
        _panel_context._auto_trim(p)


    def _applymute_log():
        try:
            s = _panel_context._load_log_settings() or {}
            allow = bool(s.get('enabled', True) and s.get('persist', True) and not s.get('mute_save', False))
            target_level = _panel_context.logging.CRITICAL + 10 if not allow else _panel_context.logging.INFO
            root = _panel_context.logging.getLogger()
            for h in root.handlers:
                if isinstance(h, _panel_context.RotatingFileHandler):
                    h.setLevel(target_level)
        except Exception:
            pass


    def _write_json(path: str, obj: dict):
        _panel_context.os.makedirs(_panel_context.app.instance_path, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            _panel_context.json.dump(obj, f, indent=2)


    def _read_json(path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return _panel_context.json.load(f)
        except Exception:
            return {}


    def _now_iso():
        return _panel_context.datetime.utcnow().isoformat(timespec='seconds') + 'Z'


    def _json_load(path, default):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return _panel_context.json.load(f)
        except Exception:
            return default

    return {
        '_norm_adminlog': _norm_adminlog,
        'logpanel_action': logpanel_action,
        '_will_persist': _will_persist,
        '_auto_trim': _auto_trim,
        '_log_save': _log_save,
        '_extend_file': _extend_file,
        '_applymute_log': _applymute_log,
        '_write_json': _write_json,
        '_read_json': _read_json,
        '_now_iso': _now_iso,
        '_json_load': _json_load,
    }


def bind_parse_tg(_panel_context):
    def _parse_tg(s: str):

        s = (s or '').rstrip('\n')
        m = _panel_context.re.match(r'^\[([0-9T:\-]{19}Z)\]\s*(.*)$', s)
        ts_iso, text = (m.group(1), m.group(2)) if m else (None, s)

        ts_dt = None
        if ts_iso:
            try:
                ts_dt = _panel_context.datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                ts_dt = None

        low = text.lower()
        if _panel_context.HEARTBEAT_WORD in low:
            kind = 'heartbeat'
        elif 'error' in low:
            kind = 'error'
        elif 'warn' in low:
            kind = 'warning'
        else:
            kind = 'info'

        return {'ts_iso': ts_iso, 'ts_dt': ts_dt, 'text': text, 'kind': kind, 'raw': s}


    def _in_range(dt, from_s, to_s):
        if not dt:
            return True

        if dt.tzinfo is not None:
            dt = dt.astimezone(
                _panel_context.timezone.utc
            ).replace(
                tzinfo=None
            )

        ok = True

        if from_s:
            boundary = _panel_context._panel_filter_datetime_utc_naive(
                from_s
            )

            if boundary is not None:
                ok = ok and dt >= boundary

        if to_s:
            boundary = _panel_context._panel_filter_datetime_utc_naive(
                to_s
            )

            if boundary is not None:
                ok = ok and dt <= boundary

        return ok

    return {
        '_parse_tg': _parse_tg,
        '_in_range': _in_range,
    }


def initialize_paths(context):
    os = context.os
    app = context.app
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    os.makedirs(app.instance_path, exist_ok=True)
    APP_LOG_FILE = os.path.join(app.instance_path, 'app.log')
    _WORKER_LOG_ROLES = ('workspace', 'shop', 'provision', 'monitor', 'combined')
    _worker_log_role = os.environ.get('WG_DB_POOL_ROLE') if os.environ.get('WG_BACKGROUND_ROLE') == 'reseller-worker' else None
    APP_LOG_WRITE_FILE = (os.path.join(app.instance_path, 'worker-'+_worker_log_role+'.log')
                          if _worker_log_role in _WORKER_LOG_ROLES else APP_LOG_FILE)
    context.namespace.update({
        'LOG_LEVEL': LOG_LEVEL,
        'APP_LOG_FILE': APP_LOG_FILE,
        '_WORKER_LOG_ROLES': _WORKER_LOG_ROLES,
        '_worker_log_role': _worker_log_role,
        'APP_LOG_WRITE_FILE': APP_LOG_WRITE_FILE,
    })


def initialize_app_logger(context):
    app = context.app
    RotatingFileHandler = context.RotatingFileHandler
    APP_LOG_WRITE_FILE = context.APP_LOG_WRITE_FILE
    logging = context.logging
    _utc_log_formatter = context._utc_log_formatter
    if not app.logger.handlers:
        handler = RotatingFileHandler(APP_LOG_WRITE_FILE, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
        handler.setLevel(logging.INFO)
        fmt = _utc_log_formatter("%(asctime)s [%(levelname)s] %(message)s")
        handler.setFormatter(fmt)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)


def initialize_root_logging(context):
    app = context.app
    _utc_log_formatter = context._utc_log_formatter
    RotatingFileHandler = context.RotatingFileHandler
    APP_LOG_WRITE_FILE = context.APP_LOG_WRITE_FILE
    LOG_LEVEL = context.LOG_LEVEL
    logging = context.logging
    sys = context.sys
    _formatter = _utc_log_formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    _file = RotatingFileHandler(APP_LOG_WRITE_FILE, maxBytes=2_000_000, backupCount=5, encoding='utf-8')
    _file.setLevel(LOG_LEVEL)
    _file.setFormatter(_formatter)
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(_file)

    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(_formatter)
        sh.setLevel(LOG_LEVEL)
        root.addHandler(sh)

    for name in ('werkzeug', 'gunicorn.error', 'gunicorn.access', 'urllib3', 'requests'):
        lg = logging.getLogger(name)
        lg.setLevel(LOG_LEVEL)
        lg.propagate = True


    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

    logging.captureWarnings(True)


def initialize_telegram_paths(context):
    os = context.os
    app = context.app
    Path = context.Path
    TELEGRAM_ADMINS_FILE   = os.path.join(app.instance_path, 'telegram_admins.json')
    TELEGRAM_SETTINGS_FILE = os.path.join(app.instance_path, 'telegram_settings.json')
    TELEGRAM_LOG_FILE        = os.path.join(app.instance_path, 'telegram.log')
    TELEGRAM_ADMIN_LOG_FILE  = os.path.join(app.instance_path, 'telegram_admin_log.jsonl')
    ADMIN_LOG_FILE = os.path.join(app.instance_path, 'admin_logs.jsonl')
    TELEGRAM_HB_FILE       = os.path.join(app.instance_path, 'telegram_heartbeat.json')
    LOGS_SETTINGS_FILE = Path(app.instance_path) / "logs_settings.json"
    LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOGS_SETTINGS_FILE = Path(app.instance_path) / 'logs_settings.json'
    context.namespace.update({
        'TELEGRAM_ADMINS_FILE': TELEGRAM_ADMINS_FILE,
        'TELEGRAM_SETTINGS_FILE': TELEGRAM_SETTINGS_FILE,
        'TELEGRAM_LOG_FILE': TELEGRAM_LOG_FILE,
        'TELEGRAM_ADMIN_LOG_FILE': TELEGRAM_ADMIN_LOG_FILE,
        'ADMIN_LOG_FILE': ADMIN_LOG_FILE,
        'TELEGRAM_HB_FILE': TELEGRAM_HB_FILE,
        'LOGS_SETTINGS_FILE': LOGS_SETTINGS_FILE,
    })
