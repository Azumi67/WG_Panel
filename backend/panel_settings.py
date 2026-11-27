def bind_panel_base(_panel_context):
    def _panel_base() -> str:
        s = _panel_context._load_panel_settings() or {}
        tls_enabled = bool(s.get('tls_enabled'))
        domain = (s.get('domain') or '').strip()

        req_host = (_panel_context.request.host or '').split(':', 1)[0]
        host = domain or req_host or 'localhost'

        def _env_port() -> int | None:
            b = (_panel_context.os.getenv('BIND') or '').strip()
            if b and ':' in b:
                try:
                    return int(b.rsplit(':', 1)[1])
                except Exception:
                    pass
            p = (_panel_context.os.getenv('PORT') or _panel_context.os.getenv('HTTPS_PORT') or '').strip()
            try:
                return int(p) if p else None
            except Exception:
                return None

        if tls_enabled:
            cfg_port = s.get('https_port')
            try:
                cfg_port = int(cfg_port) if cfg_port else None
            except Exception:
                cfg_port = None

            port = cfg_port or _env_port() or 443
            netloc = f"{host}:{port}" if port and port != 443 else host
            return f"https://{netloc}/"

        rt = _panel_context._load_runtime() or {}
        rport = None
        try:
            rport = int(rt.get('port') or 0) or None
        except Exception:
            rport = None

        pub_ip = _panel_context._public_ipv4() or req_host or 'localhost'
        if rport and rport != 80:
            return f"http://{pub_ip}:{rport}/"
        return f"http://{pub_ip}/"

    return {
        '_panel_base': _panel_base,
    }


def bind_valid_timezone_name(_panel_context):
    def _valid_timezone_name(value: str) -> str | None:
        value = str(value or "").strip()
        if not value:
            return None

        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(value)
            return value
        except Exception:
            return None


    def _detect_system_timezone_name() -> str:

        try:
            backup_file = _panel_context.namespace.get("BACKUP_SCHEDULE_FILE")
            if backup_file and _panel_context.os.path.isfile(backup_file):
                data = _panel_context._json_load(backup_file, {})
                candidate = _panel_context._valid_timezone_name(
                    data.get("timezone")
                )
                if candidate:
                    return candidate
        except Exception:
            pass

        try:
            with open(
                "/etc/timezone",
                "r",
                encoding="utf-8",
            ) as timezone_file:
                candidate = _panel_context._valid_timezone_name(
                    timezone_file.read().strip()
                )
                if candidate:
                    return candidate
        except Exception:
            pass

        try:
            target = _panel_context.os.path.realpath(
                "/etc/localtime"
            )

            marker = "/zoneinfo/"

            if marker in target:
                candidate = _panel_context._valid_timezone_name(
                    target.split(
                        marker,
                        1,
                    )[1]
                )

                if candidate:
                    return candidate
        except Exception:
            pass

        try:
            tzinfo = (
                _panel_context.datetime.now()
                .astimezone()
                .tzinfo
            )

            candidate = _panel_context._valid_timezone_name(
                getattr(
                    tzinfo,
                    "key",
                    "",
                )
            )

            if candidate:
                return candidate
        except Exception:
            pass

        return "UTC"


    def _panel_timezone_name() -> str:
        try:
            settings = _panel_context._load_panel_settings() or {}

            candidate = _panel_context._valid_timezone_name(
                settings.get("timezone")
            )

            if candidate:
                return candidate
        except Exception:
            pass

        return _panel_context._detect_system_timezone_name()


    def _panel_timezone():
        from zoneinfo import ZoneInfo

        try:
            return ZoneInfo(
                _panel_context._panel_timezone_name()
            )
        except Exception:
            return ZoneInfo("UTC")


    def _panel_local_datetime(value):

        parsed = _panel_context._tg_parse_datetime(
            value
        )

        if parsed is None:
            return None

        return parsed.astimezone(
            _panel_context._panel_timezone()
        )


    def _panel_display_datetime(value, *, seconds=False):
        local_value = _panel_context._panel_local_datetime(value)
        if local_value is None:
            return None
        return local_value.strftime(
            '%Y-%m-%d %H:%M:%S' if seconds else '%Y-%m-%d %H:%M'
        )


    def _panel_filename_stamp(value=None):
        parsed = _panel_context._tg_parse_datetime(
            value if value is not None else _panel_context.datetime.now(_panel_context.timezone.utc)
        )
        if parsed is None:
            parsed = _panel_context.datetime.now(_panel_context.timezone.utc)
        return parsed.astimezone(_panel_context._panel_timezone()).strftime('%Y%m%d_%H%M%S')


    def _utc_timestamp_iso(value):
        parsed = _panel_context._tg_parse_datetime(value)
        if parsed is None:
            return None
        return parsed.astimezone(_panel_context.timezone.utc).isoformat(
            timespec='seconds'
        ).replace('+00:00', 'Z')


    def _panel_filter_datetime_utc_naive(value):
        if value in (None, ''):
            return None

        try:
            if isinstance(value, _panel_context.datetime):
                parsed = value
            elif isinstance(value, (int, float)):
                parsed = _panel_context.datetime.fromtimestamp(
                    float(value),
                    tz=_panel_context.timezone.utc,
                )
            else:
                raw = str(value).strip()

                if not raw:
                    return None

                if _panel_context.re.fullmatch(r'\d+(?:\.\d+)?', raw):
                    parsed = _panel_context.datetime.fromtimestamp(
                        float(raw),
                        tz=_panel_context.timezone.utc,
                    )
                else:
                    if raw.endswith('Z'):
                        raw = raw[:-1] + '+00:00'

                    parsed = _panel_context.datetime.fromisoformat(raw)

        except Exception:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=_panel_context._panel_timezone()
            )

        return parsed.astimezone(
            _panel_context.timezone.utc
        ).replace(
            tzinfo=None
        )

    return {
        '_valid_timezone_name': _valid_timezone_name,
        '_detect_system_timezone_name': _detect_system_timezone_name,
        '_panel_timezone_name': _panel_timezone_name,
        '_panel_timezone': _panel_timezone,
        '_panel_local_datetime': _panel_local_datetime,
        '_panel_display_datetime': _panel_display_datetime,
        '_panel_filename_stamp': _panel_filename_stamp,
        '_utc_timestamp_iso': _utc_timestamp_iso,
        '_panel_filter_datetime_utc_naive': _panel_filter_datetime_utc_naive,
    }


def bind_load_panel_settings(_panel_context):
    def _load_panel_settings():


        try:
            stamp = _panel_context.os.stat(_panel_context.PANEL_SETTINGS_FILE).st_mtime_ns
        except OSError:
            stamp = None
        if (_panel_context._panel_settings_cache["data"] is not None and
                _panel_context._panel_settings_cache["stamp"] == stamp):
            return dict(_panel_context._panel_settings_cache["data"])
        try:
            with open(_panel_context.PANEL_SETTINGS_FILE, "r", encoding="utf-8") as f:
                j = _panel_context.json.load(f) or {}
        except (OSError,ValueError):
            j = {}

        def _port(v, default=None):
            if v in (None, ""):
                return default
            try:
                p = int(v)
                return p if 1 <= p <= 65535 else default
            except Exception:
                return default

        timezone_name = _panel_context._valid_timezone_name(
        j.get("timezone")
    )

        if not timezone_name:
            timezone_name = (_panel_context._detect_system_timezone_name())

        normalized = {"tls_enabled": bool(j.get("tls_enabled",False,)),

            "domain": (j.get("domain")or "").strip(),

            "force_https_redirect": bool(j.get("force_https_redirect",False,)),

            "hsts": bool(j.get("hsts",False,)),

            "http_port": _port(j.get("http_port"),None,),

            "https_port": _port(j.get("https_port"),443,),

            "tls_cert_path": (j.get("tls_cert_path")or "").strip(),

            "tls_key_path": (j.get("tls_key_path")or "").strip(),

            "timezone": timezone_name,
            }
        _panel_context._panel_settings_cache["stamp"] = stamp
        _panel_context._panel_settings_cache["data"] = normalized
        return dict(normalized)


    def _is_https(req=None) -> bool:
        return bool((req or _panel_context.request).is_secure)


    def _save_panel_settings(j: dict):
        _panel_context.os.makedirs(_panel_context.app.instance_path, exist_ok=True)
        with open(_panel_context.PANEL_SETTINGS_FILE, 'w') as f:
            _panel_context.json.dump(j, f, indent=2)


    def _server_host() -> str | None:
        s = _panel_context._load_panel_settings()
        if s.get('tls_enabled') and s.get('domain'):
            return s['domain']
        try:
            return _panel_context._public_ipv4()
        except Exception:
            return None

    return {
        '_load_panel_settings': _load_panel_settings,
        '_is_https': _is_https,
        '_save_panel_settings': _save_panel_settings,
        '_server_host': _server_host,
    }


def bind_load_template_settings(_panel_context):
    def _load_template_settings():
        _panel_context.os.makedirs(_panel_context.app.instance_path, exist_ok=True)
        try:
            with open(_panel_context.TEMPLATE_SETTINGS_FILE, 'r') as f:
                j = _panel_context.json.load(f)
        except FileNotFoundError:
            j = {}
        if not isinstance(j, dict):
            raise ValueError('Template settings must be a JSON object')
        j.setdefault('selected', 'default')
        j.setdefault('socials', {
            'telegram': '',
            'whatsapp': '',
            'instagram': '',
            'phone': '',
            'website': '',
            'email': '',
        })
        return j


    def _save_template_settings(j: dict):
        from panel_operations.templates import atomic_save
        atomic_save(_panel_context.TEMPLATE_SETTINGS_FILE, j)

    return {
        '_load_template_settings': _load_template_settings,
        '_save_template_settings': _save_template_settings,
    }
