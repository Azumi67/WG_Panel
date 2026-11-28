def bind_services(*,
    TELEGRAM_ADMINS_FILE,
    TELEGRAM_SETTINGS_FILE,
    _TG_EVENT_LAST,
    _TG_EVENT_LOCK,
    _json_load,
    _json_save,
    _panel_display_datetime,
    _panel_timezone,
    _tg_human_bytes,
    _tg_human_delta,
    _tg_parse_datetime,
    _utc_timestamp_iso,
    current_app,
    datetime,
    re,
    requests,
    socket,
    threading,
    time,
    timezone,
):

    def _load_tg_settings():
        s = _json_load(TELEGRAM_SETTINGS_FILE, {})
        notify = s.get('notify') or {}

        defaults = {
            'app_down': True,
            'app_up': True,
            'node_down': True,
            'node_up': True,
            'iface_down': True,
            'iface_up': True,
            'peer_expired': True,
            'peer_limit': True,
            'reseller_purchase': True,
            'login_success': True,
            'login_fail': True,
            'suspicious_4xx': True,
            'security_block': True,
            'security_release': True,
            'security_auto_release': False,
            'traffic_policy_change': False,
            'traffic_apply_success': False,
            'traffic_apply_failed': True,
            'backup_success': False,
            'backup_failed': True,
            'update_success': True,
            'update_failed': True,
        }

        return {
            'enabled': bool(s.get('enabled', False)),
            'language':'fa' if s.get('language')=='fa' else 'en',
            'notify': {
                key: bool(notify.get(key, default))
                for key, default in defaults.items()
            },
            'bot_token': (s.get('bot_token') or '').strip(),
        }

    def _tg_system_timezone():
        try:
            return _panel_timezone()
        except Exception:
            return timezone.utc

    def _tg_human_datetime(
        value,
        *,
        relative: bool = False,
        seconds: bool = False,
        fallback: str = "—",
        language: str = "en",
    ) -> str:
        parsed = _tg_parse_datetime(value)

        if parsed is None:
            return fallback if value in (None, "", "—") else str(value)

        local_tz = _tg_system_timezone()
        local_dt = parsed.astimezone(local_tz)
        now = datetime.now(timezone.utc).astimezone(local_tz)

        date_format = "%Y-%m-%d" if language == "fa" else "%d %b %Y"
        clock_format = "%H:%M:%S" if seconds else "%H:%M"
        absolute = local_dt.strftime(date_format + " · " + clock_format)

        if not relative:
            return absolute

        delta = (now - local_dt).total_seconds()
        human = _tg_human_delta(delta)

        return f"{absolute} ({human})"

    def _tg_now_text() -> str:
        return _tg_human_datetime(
            datetime.now(timezone.utc),
            relative=False,
            seconds=True,
        )

    def _tg_event_escape(value) -> str:
        import html

        return html.escape(
            str(value or ''),
            quote=True,
        )

    def _tg_event_enabled(event_key: str) -> bool:
        settings = _load_tg_settings() or {}

        if not settings.get('enabled'):
            return False

        notify = settings.get('notify') or {}

        return bool(
            notify.get(
                str(event_key or '').strip(),
                False,
            )
        )

    def _send_telegram_event(
        event_key: str,
        title: str,
        *,
        status: str = '',
        details: list[tuple[str, object]] | None = None,
        dedupe_key: str = '',
        dedupe_seconds: int = 60,
    ) -> None:

        event_key = str(
            event_key or ''
        ).strip()

        if not event_key:
            return

        if not _tg_event_enabled(
            event_key
        ):
            return

        settings = (
            _load_tg_settings()
            or {}
        )

        bot_token = str(
            settings.get('bot_token')
            or ''
        ).strip()

        recipients = [
            str(
                admin.get('id')
                or ''
            ).strip()
            for admin in (
                _load_tg_admins()
                or []
            )
            if (
                str(
                    admin.get('id')
                    or ''
                ).strip()
                and not admin.get('muted')
            )
        ]

        if not bot_token or not recipients:
            return


        event_identity = (
            event_key,
            str(
                dedupe_key
                or title
                or event_key
            ).strip(),
        )

        monotonic_now = (
            time.monotonic()
        )

        with _TG_EVENT_LOCK:

            previous_time = float(
                _TG_EVENT_LAST.get(
                    event_identity
                )
                or 0
            )

            if (
                dedupe_seconds > 0
                and previous_time
                and (
                    monotonic_now
                    - previous_time
                    < dedupe_seconds
                )
            ):
                return

            _TG_EVENT_LAST[
                event_identity
            ] = monotonic_now

            if len(_TG_EVENT_LAST) > 1000:

                expiry_time = (
                    monotonic_now
                    - 86400
                )

                for old_key, old_time in list(
                    _TG_EVENT_LAST.items()
                ):

                    if (
                        float(
                            old_time
                            or 0
                        )
                        < expiry_time
                    ):

                        _TG_EVENT_LAST.pop(
                            old_key,
                            None,
                        )


        icon_map = {
            'app_down': '⊘',
            'app_up': '●',

            'node_down': '○',
            'node_up': '●',

            'iface_down': '○',
            'iface_up': '●',

            'peer_expired': '◇',
            'peer_limit': '◆',

            'login_success': '●',
            'login_fail': '⊘',

            'suspicious_4xx': '◆',
            'security_block': '⊘',
            'security_release': '◇',
            'security_auto_release': '◇',

            'traffic_policy_change': '◇',
            'traffic_apply_success': '●',
            'traffic_apply_failed': '⊘',

            'backup_success': '●',
            'backup_failed': '⊘',

            'update_success': '●',
            'update_failed': '⊘',
        }

        icon = icon_map.get(
            event_key,
            '◇',
        )

        clean_title = re.sub(
            r'^[●○◆◇◷⌂⊘✦↥↻]+\s*',
            '',
            str(
                title or ''
            ).strip(),
        )

        clean_status = str(
            status or ''
        ).strip()


        language = settings.get('language', 'en')
        timestamp = _tg_human_datetime(datetime.now(timezone.utc), seconds=True, language=language)

        hostname = str(
            socket.gethostname()
            or 'panel'
        ).strip()


        time_labels = {
            'time',
            'timestamp',

            'created',
            'created at',

            'updated',
            'updated at',

            'started',
            'started at',

            'completed',
            'completed at',

            'failed at',

            'blocked at',
            'blocked until',

            'released at',

            'expires',
            'expires at',

            'last seen',
            'last run',

            'next run',
            'next check',

            'recovered at',

            'schedule time',
            'scheduled for',
        }

        rows = []

        for label, value in (
            details or []
        ):

            if value in (
                None,
                '',
            ):
                continue

            clean_label = str(
                label or ''
            ).strip()

            if not clean_label:
                continue

            label_key = (
                clean_label.lower()
            )

            if label_key in time_labels:

                clean_value = _tg_human_datetime(value, language=language)

            else:

                clean_value = str(
                    value
                    if value is not None
                    else ''
                ).strip()

            if not clean_value:
                continue

            rows.append(
                (
                    clean_label,
                    clean_value,
                )
            )


        if clean_status:
            rows.insert(0, ('Status',clean_status))
        from panel_core.telegram_notices import admin_event
        message_text = admin_event(settings.get('language','en'), event_key, clean_title, rows, f'{timestamp} · {hostname}', icon)['text']

        flask_app = (
            current_app
            ._get_current_object()
        )


        def worker():

            with flask_app.app_context():

                for chat_id in recipients:

                    try:

                        response = requests.post(
                            (
                                'https://api.telegram.org/'
                                f'bot{bot_token}/sendMessage'
                            ),
                            json={
                                'chat_id': chat_id,
                                'text': message_text,
                                'parse_mode': 'HTML',
                                'disable_web_page_preview': True,
                            },
                            timeout=8,
                        )

                        if not response.ok:

                            flask_app.logger.warning(
                                'Telegram event failed: '
                                'event=%s '
                                'chat_id=%s '
                                'status=%s '
                                'response=%s',
                                event_key,
                                chat_id,
                                response.status_code,
                                response.text[:300],
                            )

                    except Exception:

                        flask_app.logger.debug(
                            'Telegram event failed: '
                            'event=%s '
                            'chat_id=%s',
                            event_key,
                            chat_id,
                            exc_info=True,
                        )

        threading.Thread(
            target=worker,
            name=(
                'telegram-event-'
                + event_key[:40]
            ),
            daemon=True,
        ).start()

    def _save_tg_settings(partial):
        cur = _load_tg_settings()
        if 'bot_token' in partial and partial['bot_token'] is None:
            partial.pop('bot_token')
        cur.update({k:v for k,v in partial.items() if k != 'notify'})
        if 'notify' in partial:
            cur['notify'].update(partial['notify'])
        _json_save(TELEGRAM_SETTINGS_FILE, cur)

    def _load_tg_admins():
        a = _json_load(
            TELEGRAM_ADMINS_FILE,
            [],
        )

        out = []

        for x in a:
            created_at = _utc_timestamp_iso(
                x.get('created_at')
            )

            out.append({
                'id': str(
                    x.get('id')
                    or x.get('tg_id')
                    or ''
                ),
                'username': (
                    x.get('username')
                    or ''
                ).lstrip('@'),
                'note': x.get('note') or '',
                'muted': bool(
                    x.get('muted', False)
                ),
                'created_at': created_at,
                'created_at_display': _panel_display_datetime(
                    created_at
                ),
            })

        return [
            x
            for x in out
            if x['id']
        ]

    def _save_tg_admins(admins):
        rows = []

        for admin in admins or []:
            rows.append({
                'id': str(
                    admin.get('id')
                    or admin.get('tg_id')
                    or ''
                ),
                'username': (
                    admin.get('username')
                    or ''
                ).lstrip('@'),
                'note': admin.get('note') or '',
                'muted': bool(
                    admin.get('muted', False)
                ),
                'created_at': _utc_timestamp_iso(
                    admin.get('created_at')
                ),
            })

        _json_save(
            TELEGRAM_ADMINS_FILE,
            [
                row
                for row in rows
                if row['id']
            ],
        )

    def _tg_chatid():
        admins = _load_tg_admins() or []
        for a in admins:
            if not a.get('muted') and (a.get('id') or '').strip():
                return str(a['id'])
        return None

    def _send_zip_telegram(
        data_bytes: bytes,
        filename: str,
        chat_id: str | None = None,
        caption: str | None = None,
    ) -> tuple[bool, str]:
        settings = _load_tg_settings()

        if not settings.get("enabled"):
            return False, "Telegram disabled."

        token = (
            settings.get("bot_token")
            or ""
        ).strip()

        if not token:
            return False, "Telegram token missing."

        selected_chat_id = str(
            chat_id
            or _tg_chatid()
            or ""
        ).strip()

        if not selected_chat_id:
            return False, (
                "No active Telegram administrator selected."
            )

        active_admin_ids = {
            str(
                admin.get("id")
                or ""
            ).strip()
            for admin in (
                _load_tg_admins()
                or []
            )
            if (
                not admin.get("muted")
                and str(
                    admin.get("id")
                    or ""
                ).strip()
            )
        }

        if selected_chat_id not in active_admin_ids:
            return False, (
                "Selected Telegram recipient is not an "
                "active panel administrator."
            )

        size_bytes = len(
            data_bytes
            or b""
        )

        if not caption:
            try:
                size_text = _tg_human_bytes(
                    size_bytes
                )
            except Exception:
                size_text = (
                    f"{size_bytes} bytes"
                )

            created_at = _tg_now_text()

            caption = "\n".join([
                "<b>WG Panel backup</b>",
                "",
                "<b>Status</b> · Completed",
                (
                    "<b>File</b> · "
                    f"<code>{_tg_event_escape(filename)}</code>"
                ),
                (
                    "<b>Size</b> · "
                    f"{_tg_event_escape(size_text)}"
                ),
                (
                    "<b>Created</b> · "
                    f"{_tg_event_escape(created_at)}"
                ),
            ])

        if len(caption) > 1000:
            caption = caption[:997] + "..."

        try:
            response = requests.post(
                (
                    "https://api.telegram.org/bot"
                    f"{token}/sendDocument"
                ),
                data={
                    "chat_id": selected_chat_id,
                    "disable_notification": "true",
                    "caption": caption,
                    "parse_mode": "HTML",
                },
                files={
                    "document": (
                        filename,
                        data_bytes,
                        "application/zip",
                    )
                },
                timeout=60,
                allow_redirects=False,
            )

            try:
                payload = (
                    response.json()
                    or {}
                )
            except Exception:
                payload = {}

            if (
                response.ok
                and payload.get("ok")
            ):
                return (
                    True,
                    "Backup document sent to Telegram.",
                )

            description = str(
                payload.get("description")
                or response.text
                or ""
            )[:300]

            return (
                False,
                (
                    "Telegram error "
                    f"{response.status_code}: "
                    f"{description}"
                ),
            )

        except Exception as exc:
            return (
                False,
                f"Telegram delivery failed: {type(exc).__name__}",
            )

    return {
        '_load_tg_settings': _load_tg_settings,
        '_tg_system_timezone': _tg_system_timezone,
        '_tg_human_datetime': _tg_human_datetime,
        '_tg_now_text': _tg_now_text,
        '_tg_event_escape': _tg_event_escape,
        '_tg_event_enabled': _tg_event_enabled,
        '_send_telegram_event': _send_telegram_event,
        '_save_tg_settings': _save_tg_settings,
        '_load_tg_admins': _load_tg_admins,
        '_save_tg_admins': _save_tg_admins,
        '_tg_chatid': _tg_chatid,
        '_send_zip_telegram': _send_zip_telegram,
    }
