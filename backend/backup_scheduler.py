def bind_login_or_session(_panel_context):
    def login_or_session(fn):
        @_panel_context.wraps(fn)
        def wrapper(*a, **kw):
            from flask import request, session, jsonify
            if 'user_id' in session:
                return fn(*a, **kw)
            token = request.headers.get('X-CSRF-Token') or request.args.get('csrf')
            if token and token == session.get('csrf_token'):
                return fn(*a, **kw)
            return jsonify({"error": "Unauthorized"}), 401
        return wrapper

    return {
        'login_or_session': login_or_session,
    }


def bind_run_scheduled_backup(_panel_context):
    def _run_scheduled_backup(
        sched: dict,
        slot: str,
    ) -> dict:

        from urllib.parse import urlencode

        send_to_telegram = bool(
            sched.get(
                "send_to_telegram",
                False,
            )
        )

        telegram_chat_id = str(
            sched.get(
                "telegram_chat_id",
                "",
            )
            or ""
        ).strip()

        query = {
            "auto": "1",
            "wg": (
                "1"
                if sched.get(
                    "include_wg",
                    True,
                )
                else "0"
            ),
            "tg": "0",
        }

        request_path = (
            "/api/backup/full?"
            + urlencode(query)
        )

        with _panel_context.app.test_request_context(
            request_path
        ):
            backup_function = _panel_context.backup_full

            while hasattr(
                backup_function,
                "__wrapped__",
            ):
                backup_function = (
                    backup_function.__wrapped__
                )

            response = backup_function()

            if isinstance(response, tuple):
                flask_response = response[0]
                tuple_status = (
                    response[1]
                    if len(response) > 1
                    else None
                )
            else:
                flask_response = response
                tuple_status = None

            status_code = int(
                tuple_status
                or getattr(
                    flask_response,
                    "status_code",
                    200,
                )
                or 200
            )

            if status_code >= 400:
                raise RuntimeError(
                    "backup endpoint returned "
                    f"HTTP {status_code}"
                )

            headers = getattr(
                flask_response,
                "headers",
                {},
            )

            saved_name = str(
                headers.get(
                    "X-Backup-Saved-Name"
                )
                or ""
            ).strip()

            try:
                saved_size = int(
                    headers.get(
                        "X-Backup-Saved-Size"
                    )
                    or 0
                )
            except Exception:
                saved_size = 0

            try:
                saved_timestamp = int(
                    headers.get(
                        "X-Backup-Saved-Timestamp"
                    )
                    or 0
                )
            except Exception:
                saved_timestamp = 0

        if not saved_name:
            raise RuntimeError(
                "The backup response did not confirm "
                "a locally saved automatic archive."
            )

        backup_root = _panel_context.Path(
            _panel_context.BACKUP_AUTO_DIR
        ).resolve()

        backup_path = (
            backup_root
            / _panel_context.os.path.basename(saved_name)
        ).resolve()

        try:
            backup_path.relative_to(
                backup_root
            )
        except ValueError:
            raise RuntimeError(
                "Automatic backup path validation failed."
            )

        if not backup_path.is_file():
            raise RuntimeError(
                "Automatic backup was created but the stored "
                f"ZIP could not be found: {saved_name}"
            )

        try:
            data_bytes = backup_path.read_bytes()
        except Exception as exc:
            raise RuntimeError(
                "Could not read the stored automatic backup: "
                f"{exc}"
            ) from exc

        if not data_bytes:
            raise RuntimeError(
                "The stored automatic backup is empty."
            )

        if not data_bytes.startswith(b"PK"):
            raise RuntimeError(
                "The stored automatic backup is not a valid ZIP."
            )

        saved_size = len(data_bytes)

        completed_at = (
            _panel_context.datetime.utcnow()
            .isoformat(
                timespec="seconds"
            )
            + "Z"
        )

        telegram_sent = False
        telegram_message = ""

        if send_to_telegram:
            if not telegram_chat_id:
                raise RuntimeError(
                    "Telegram delivery is enabled, but no "
                    "Telegram administrator is selected."
                )

            scheduled_dt = _panel_context._backup_slot_datetime(
                slot,
                sched,
            )

            schedule_text = _panel_context._tg_human_datetime(
                scheduled_dt,
                seconds=False,
            )

            completed_text = _panel_context._tg_human_datetime(
                completed_at,
                seconds=False,
            )

            try:
                size_text = _panel_context._tg_human_bytes(
                    saved_size
                )
            except Exception:
                size_text = (
                    f"{saved_size} bytes"
                )

            caption = "\n".join([
                "<b>Automatic backup completed</b>",
                "",
                "<b>Status</b> · Completed",
                (
                    "<b>Schedule time</b> · "
                    f"{_panel_context._tg_event_escape(schedule_text)}"
                ),
                (
                    "<b>Completed at</b> · "
                    f"{_panel_context._tg_event_escape(completed_text)}"
                ),
                (
                    "<b>File</b> · "
                    f"<code>{_panel_context._tg_event_escape(saved_name)}</code>"
                ),
                (
                    "<b>Size</b> · "
                    f"{_panel_context._tg_event_escape(size_text)}"
                ),
            ])

            telegram_sent, telegram_message = (
                _panel_context._send_zip_telegram(
                    data_bytes,
                    saved_name,
                    chat_id=telegram_chat_id,
                    caption=caption,
                )
            )

            if not telegram_sent:
                raise RuntimeError(
                    "Backup was stored locally, but Telegram "
                    "document delivery failed: "
                    f"{telegram_message}"
                )

            _panel_context.app.logger.info(
                "Automatic backup delivered to Telegram: "
                "file=%s chat_id=%s size=%s",
                saved_name,
                telegram_chat_id,
                saved_size,
            )

        backup_metadata = {
            "filename": saved_name,
            "name": saved_name,
            "size": saved_size,
            "size_bytes": saved_size,
            "timestamp": saved_timestamp,
            "telegram_requested": send_to_telegram,
            "telegram_sent": telegram_sent,
            "telegram_message": telegram_message,
        }

        state = _panel_context._json_load(
            _panel_context._BACKUP_SCHEDULER_STATE_FILE,
            {},
        )

        if not isinstance(
            state,
            dict,
        ):
            state = {}

        state.update({
            "last_slot": slot,
            "last_success": completed_at,
            "last_success_at": completed_at,
            "last_file": saved_name,
            "last_size": saved_size,
            "last_error": "",
            "last_error_at": "",
            "last_telegram_sent": (
                telegram_sent
                if send_to_telegram
                else None
            ),
            "last_telegram_message": (
                telegram_message
                if send_to_telegram
                else ""
            ),
        })

        _panel_context._json_save(
            _panel_context._BACKUP_SCHEDULER_STATE_FILE,
            state,
        )

        return backup_metadata


    def _backup_scheduler_loop():

        lock_handle = None

        try:
            lock_handle = open(
                _panel_context._BACKUP_SCHEDULER_LOCK_FILE,
                "a+",
            )

            _panel_context.fcntl.flock(
                lock_handle.fileno(),
                _panel_context.fcntl.LOCK_EX
                | _panel_context.fcntl.LOCK_NB,
            )

        except Exception:
            if lock_handle:
                try:
                    lock_handle.close()
                except Exception:
                    pass

            return

        while True:
            try:
                with _panel_context.app.app_context():
                    schedule = _panel_context._load_backup_schedule()

                    slot = _panel_context._backup_due_slot(
                        schedule
                    )

                    state = _panel_context._json_load(
                        _panel_context._BACKUP_SCHEDULER_STATE_FILE,
                        {},
                    )

                    if not isinstance(
                        state,
                        dict,
                    ):
                        state = {}

                    if (
                        slot
                        and state.get("last_slot")
                        != slot
                    ):
                        try:

                            backup_result = (
                                _panel_context._run_scheduled_backup(
                                    schedule,
                                    slot,
                                )
                            )

                            completed_at = (
                                _panel_context.datetime.utcnow()
                                .isoformat(
                                    timespec="seconds"
                                )
                                + "Z"
                            )

                            _panel_context.app.logger.info(
                                "Automatic backup completed: "
                                "slot=%s",
                                slot,
                            )

                            notification_details = [
                                (
                                    "Schedule time",
                                    _panel_context._backup_slot_datetime(
                                        slot,
                                        schedule,
                                    )
                                    or slot,
                                ),
                                (
                                    "Completed at",
                                    completed_at,
                                ),
                            ]

                            if isinstance(
                                backup_result,
                                dict,
                            ):
                                backup_filename = str(
                                    backup_result.get(
                                        "filename"
                                    )
                                    or backup_result.get(
                                        "file"
                                    )
                                    or backup_result.get(
                                        "name"
                                    )
                                    or ""
                                ).strip()

                                backup_size = (
                                    backup_result.get(
                                        "size"
                                    )
                                    or backup_result.get(
                                        "size_bytes"
                                    )
                                )

                                if backup_filename:
                                    notification_details.append(
                                        (
                                            "File",
                                            backup_filename,
                                        )
                                    )

                                if backup_size not in (
                                    None,
                                    "",
                                ):
                                    notification_details.append(
                                        (
                                            "Size bytes",
                                            backup_size,
                                        )
                                    )

                            if not schedule.get(
                                "send_to_telegram",
                                False,
                            ):
                                _panel_context._send_telegram_event(
                                    "backup_success",
                                    (
                                        "● Automatic backup "
                                        "completed"
                                    ),
                                    status="Completed",
                                    details=(
                                        notification_details
                                    ),
                                    dedupe_key=(
                                        f"backup-success:{slot}"
                                    ),
                                    dedupe_seconds=0,
                                )


                        except Exception as exc:
                            failed_at = (
                                _panel_context.datetime.utcnow()
                                .isoformat(
                                    timespec="seconds"
                                )
                                + "Z"
                            )

                            failure_state = _panel_context._json_load(
                                _panel_context._BACKUP_SCHEDULER_STATE_FILE,
                                {},
                            )

                            if not isinstance(
                                failure_state,
                                dict,
                            ):
                                failure_state = {}

                            failure_state.update({

                                "last_slot": slot,

                                "last_error": str(
                                    exc
                                ),

                                "last_error_at": (
                                    failed_at
                                ),
                            })

                            _panel_context._json_save(
                                _panel_context._BACKUP_SCHEDULER_STATE_FILE,
                                failure_state,
                            )

                            _panel_context.app.logger.exception(
                                "Automatic backup failed: "
                                "slot=%s error=%s",
                                slot,
                                exc,
                            )

                            _panel_context._send_telegram_event(
                                "backup_failed",
                                (
                                    "● Automatic backup "
                                    "failed"
                                ),
                                status="Failed",
                                details=[
                                    (
                                        "Schedule time",
                                        _panel_context._backup_slot_datetime(
                                            slot,
                                            schedule,
                                        )
                                        or slot,
                                    ),
                                    (
                                        "Failed at",
                                        failed_at,
                                    ),
                                    (
                                        "Error",
                                        str(
                                            exc
                                        )[:300],
                                    ),
                                ],
                                dedupe_key=(
                                    f"backup-failed:{slot}"
                                ),
                                dedupe_seconds=300,
                            )

            except Exception as exc:
                try:
                    _panel_context.app.logger.exception(
                        "Backup scheduler sweep failed: %s",
                        exc,
                    )
                except Exception:
                    pass

            _panel_context.time.sleep(
                _panel_context._BACKUP_SCHEDULER_INTERVAL_SEC
            )


    def _start_backup_scheduler():
        pass

        if _panel_context._BACKUP_SCHEDULER_STARTED:
            return

        _panel_context._BACKUP_SCHEDULER_STARTED = True

        thread = _panel_context.threading.Thread(
            target=_panel_context._backup_scheduler_loop,
            name='auto-backup-scheduler',
            daemon=True,
        )

        thread.start()

    return {
        '_run_scheduled_backup': _run_scheduled_backup,
        '_backup_scheduler_loop': _backup_scheduler_loop,
        '_start_backup_scheduler': _start_backup_scheduler,
    }


def initialize_scheduler(context):
    os = context.os
    app = context.app
    _BACKUP_SCHEDULER_STARTED = False
    _BACKUP_SCHEDULER_INTERVAL_SEC = 30

    _BACKUP_SCHEDULER_STATE_FILE = os.path.join(
        app.instance_path,
        'backup_scheduler_state.json',
    )

    _BACKUP_SCHEDULER_LOCK_FILE = os.path.join(
        app.instance_path,
        'backup_scheduler.lock',
    )
    context.namespace.update({
        '_BACKUP_SCHEDULER_STARTED': _BACKUP_SCHEDULER_STARTED,
        '_BACKUP_SCHEDULER_INTERVAL_SEC': _BACKUP_SCHEDULER_INTERVAL_SEC,
        '_BACKUP_SCHEDULER_STATE_FILE': _BACKUP_SCHEDULER_STATE_FILE,
        '_BACKUP_SCHEDULER_LOCK_FILE': _BACKUP_SCHEDULER_LOCK_FILE,
    })
