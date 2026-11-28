def build_routes(*,
    TELEGRAM_ADMIN_LOG_FILE,
    TELEGRAM_HB_FILE,
    TELEGRAM_LOG_FILE,
    TELEGRAM_SETTINGS_FILE,
    _app_log_line,
    _extend_file,
    _in_range,
    _json_load,
    _json_save,
    _last_cleared,
    _load_tg_admins,
    _load_tg_settings,
    _now_iso,
    _panel_display_datetime,
    _panel_timezone_name,
    _parse_tg,
    _read_tail,
    _save_tg_admins,
    _save_tg_settings,
    _utc_timestamp_iso,
    abort,
    admin_required,
    app,
    csrf,
    current_app,
    from_ts,
    isoz,
    json,
    jsonify,
    login_required,
    now_ts,
    os,
    request,
    requests,
    require_api_key,
    require_api_key_or_login,
):

    @login_required
    def tg_test():
        try:
            s = _load_tg_settings()
            if not s.get('enabled'):
                return jsonify(error="Telegram is disabled."), 400

            token = (s.get('bot_token') or '').strip()
            if not token:
                return jsonify(error="Bot token is not set."), 400

            admins = _load_tg_admins() or []
            recips = []
            for a in admins:
                chat_id = a.get('id') or a.get('tg_id') or a.get('chat_id')
                if chat_id and not a.get('muted'):
                    recips.append(chat_id)

            if not recips:
                return jsonify(error="No active (unmuted) admins with valid IDs."), 400

            from panel_core.telegram_notices import card
            message = (card('آزمایش ارسال', [('کانال','ربات مدیریت پنل')], 'ارسال اعلان به این گفتگو فعال است.') if s.get('language')=='fa' else card('Test delivery', [('Channel','Panel admin bot')], 'Your panel notifications can reach this chat.'))['text']
            failures = []
            for chat_id in recips:
                try:
                    r = requests.post(
                        f"https://api.telegram.org/bot{token}/sendMessage",
                        json={"chat_id": chat_id,
                              "text": message,
                              "parse_mode": "HTML"},
                        timeout=(6, 15)
                    )
                    if r.status_code != 200:
                        failures.append({"chat_id": chat_id, "status": r.status_code, "body": r.text[:200]})
                except requests.exceptions.ConnectTimeout:
                    failures.append({"chat_id": chat_id, "error": "Connection to Telegram timed out. Check outbound HTTPS, DNS and proxy settings."})
                except requests.exceptions.ReadTimeout:
                    failures.append({"chat_id": chat_id, "error": "Telegram response timed out. Delivery is uncertain; the message was not automatically resent."})
                except requests.exceptions.SSLError:
                    failures.append({"chat_id": chat_id, "error": "TLS verification failed while connecting to Telegram."})
                except requests.exceptions.ConnectionError:
                    failures.append({"chat_id": chat_id, "error": "Could not connect to Telegram. Check outbound network access and DNS."})
                except Exception as e:
                    failures.append({"chat_id": chat_id, "error": type(e).__name__})

            if failures and len(failures) == len(recips):
                current_app.logger.warning("Telegram test failed: %s", failures)
                return jsonify(error="Telegram delivery failed. Check the connection and recipient details below.",
                               detail=failures[:3]), 502

            if failures:
                current_app.logger.warning("Telegram test partial failure: %s", failures)
                return jsonify(ok=False, sent=len(recips)-len(failures), failures=len(failures)), 207

            return jsonify(ok=True, sent=len(recips))
        except Exception:
            current_app.logger.exception("Telegram test error")
            return jsonify(error="Server error while sending test"), 500

    @login_required
    def tg_settings_get():
        s = _load_tg_settings()
        return jsonify(
            enabled=s['enabled'],
            language=s['language'],
            has_token=bool(s['bot_token']),
            notify=s['notify']
        )

    @login_required
    def tg_settings_post():
        data = request.get_json() or {}
        enabled = bool(data.get('enabled', False))
        notify  = data.get('notify') or {}
        changes={'notify':notify}
        if 'enabled' in data:changes['enabled']=enabled
        if 'language' in data:
            if data['language'] not in ('en','fa'):return jsonify(error='Choose English or Persian.'),400
            changes['language']=data['language']
        _save_tg_settings(changes)
        return jsonify(ok=True)

    @login_required
    def tg_token_set():
        data = request.get_json() or {}
        tok = (data.get('bot_token') or '').strip()
        if not tok:
            return jsonify(error='bot_token required'), 400
        _save_tg_settings({'bot_token': tok})
        return jsonify(ok=True)

    @login_required
    def tg_token_clear():
        s = _load_tg_settings()
        s['bot_token'] = ''
        _json_save(TELEGRAM_SETTINGS_FILE, s)
        return jsonify(ok=True, warning=('The panel token was cleared, but an admin bot token remains configured in TG_BOT_TOKEN or TELEGRAM_BOT_TOKEN. Remove it from the server configuration and restart the panel and admin bot service before reusing that bot.' if os.getenv('TG_BOT_TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') else ''))

    @require_api_key_or_login
    def tg_admins_get():
        return jsonify(
            admins=_load_tg_admins(),
            display_timezone=_panel_timezone_name(),
            server_epoch=now_ts(),
        )

    @login_required
    def tg_admins_post():
        data = request.get_json() or {}
        tg_id = str(data.get('tg_id') or data.get('id') or '').strip()
        if not tg_id.isdigit():
            return jsonify(error='tg_id numeric'), 400
        username = (data.get('username') or '').lstrip('@').strip()
        note = (data.get('note') or '').strip()
        muted = bool(data.get('muted', False))

        admins = _load_tg_admins()
        found = next((a for a in admins if a['id'] == tg_id), None)
        if found:
            found.update({
                'username': username,
                'note': note,
                'muted': muted,
            })
        else:
            admins.append({
                'id': tg_id,
                'username': username,
                'note': note,
                'muted': muted,
                'created_at': _now_iso(),
            })
        _save_tg_admins(admins)
        return jsonify(ok=True, admins=admins)

    @login_required
    def tg_admins_del(tg_id):
        admins = [a for a in _load_tg_admins() if a['id'] != str(tg_id)]
        _save_tg_admins(admins)
        return jsonify(ok=True, admins=admins)

    @login_required
    def tg_logs_get():

        fmt   = (request.args.get('format') or 'json').lower().strip()
        level = (request.args.get('level') or '').lower().strip()
        q     = (request.args.get('q') or '').lower().strip()
        from_s = request.args.get('from') or ''
        to_s   = request.args.get('to') or ''
        limit  = int(request.args.get('limit') or 500)

        tail = _read_tail(TELEGRAM_LOG_FILE, 20000) or ""
        lines = tail.splitlines()

        if fmt == 'txt':
            return jsonify(logs=tail if tail else '(no logs yet)')

        out = []
        for s in lines:
            rec = _parse_tg(s)
            if level and rec.get('kind') != level:
                continue
            if q and q not in rec.get('raw','').lower():
                continue
            if not _in_range(rec.get('ts_dt'), from_s, to_s):
                continue
            out.append({
                "ts":   rec.get("ts_iso"),
                "kind": rec.get("kind"),
                "text": rec.get("text"),
            })

        out = out[-max(50, min(limit, 2000)):]

        for row in out:
            if row.get('ts'):
                row['time_display'] = _panel_display_datetime(
                    row['ts'],
                    seconds=True,
                )

        return jsonify(
            logs=out,
            display_timezone=_panel_timezone_name(),
            server_epoch=now_ts(),
        )

    @login_required
    def tg_logs_del():
        try:
            open(TELEGRAM_LOG_FILE, 'w').close()
            _last_cleared("tg_app")
        except Exception as exc:
            app.logger.warning('Telegram log clear failed (%s)', type(exc).__name__)
            return jsonify(ok=False, error='log_clear_failed'), 500
        return jsonify(ok=True)

    @login_required
    @admin_required
    def telegram_worker_logs(stream):

        from reseller_portal.bot_runtime_log import log_path, NAMES
        if stream not in NAMES:
            abort(404)
        try:
            limit = max(10, min(int(request.args.get('limit') or 500), 2000))
        except (ValueError, TypeError):
            return jsonify(error='Invalid limit'), 400
        level = (request.args.get('level') or '').lower().strip()
        q = (request.args.get('q') or '').lower().strip()[:128]
        if level and level not in ('info','warning','error'):
            return jsonify(logs=[], display_timezone=_panel_timezone_name())
        tail = _read_tail(str(log_path(app.instance_path, stream)), 500_000) or ''
        output = []
        for line in tail.splitlines():
            rec = _app_log_line(line)
            if not rec.get('ts') or (level and rec['level'] != level) or (q and q not in rec['msg'].lower()):
                continue
            rec['time_display'] = _panel_display_datetime(rec['ts'], seconds=True)
            output.append(rec)
        return jsonify(logs=output[-limit:], display_timezone=_panel_timezone_name(), server_epoch=now_ts())

    @login_required
    def tg_status():
        hb = _json_load(
            TELEGRAM_HB_FILE,
            {},
        )

        last = int(
            hb.get('ts')
            or 0
        )

        sec = max(
            15,
            int(
                current_app.config.get(
                    'TG_HEARTBEAT_SEC',
                    60,
                )
                or 60
            ),
        )

        heartbeat_age = (
            max(
                0,
                now_ts() - last,
            )
            if last
            else None
        )

        heartbeat_fresh = bool(
            last
            and heartbeat_age
            <= max(
                180,
                sec * 4,
            )
        )
        process_alive = False

        try:
            pid = int(
                hb.get('pid')
                or 0
            )

            if pid > 1:
                os.kill(
                    pid,
                    0,
                )
                process_alive = True

        except ProcessLookupError:
            process_alive = False

        except PermissionError:
            process_alive = True

        except Exception:
            process_alive = False

        online = bool(
            heartbeat_fresh
            or process_alive
        )

        if heartbeat_fresh:
            state = 'online'

        elif process_alive:
            state = 'running_heartbeat_stale'

        else:
            state = 'offline'

        return jsonify(
            bot_online=online,
            state=state,
            heartbeat_fresh=heartbeat_fresh,
            process_alive=process_alive,
            heartbeat_age_seconds=heartbeat_age,
            heartbeat_interval_seconds=sec,
            last_seen=(
                isoz(
                    from_ts(last)
                )
                if last
                else None
            ),
            pid=hb.get('pid'),
            version=hb.get('version'),
        )

    @csrf.exempt
    @require_api_key
    def tg_heartbeat():
        data = (
            request.get_json(
                silent=True,
            )
            or {}
        )

        rec = {
            'ts': now_ts(),
            'pid': data.get('pid'),
            'version': (
                data.get('version')
                or 'unknown'
            ),
            'panel': (
                data.get('panel')
                or ''
            ),
            'service': (
                data.get('service')
                or 'telegram-bot'
            ),
        }

        _json_save(
            TELEGRAM_HB_FILE,
            rec,
        )

        _extend_file(
            TELEGRAM_LOG_FILE,
            (
                f"[{isoz(from_ts(rec['ts']))}] "
                f"heartbeat "
                f"pid={rec['pid']} "
                f"v={rec['version']} "
                f"service={rec['service']}"
            ),
            source='telegram',
        )

        return jsonify(
            ok=True,
            server_ts=rec['ts'],
        )

    @login_required
    def tg_admin_logs():
        tail = _read_tail(
            TELEGRAM_ADMIN_LOG_FILE,
            20000,
        )

        rows = []

        for line in tail.splitlines():
            try:
                row = json.loads(line)

                normalized = _utc_timestamp_iso(
                    row.get('ts')
                )

                if normalized:
                    row['ts'] = normalized
                    row['time_display'] = _panel_display_datetime(
                        normalized,
                        seconds=True,
                    )

                rows.append(row)

            except Exception:
                continue

        return jsonify({
            'logs': rows,
            'display_timezone': _panel_timezone_name(),
            'server_epoch': now_ts(),
        })

    @login_required
    def tg_adminlogs_clear():
        with open(TELEGRAM_ADMIN_LOG_FILE, 'w', encoding='utf-8') as f:
            pass
        return jsonify(ok=True)

    @csrf.exempt
    @require_api_key
    def tg_adminlog():

        data = request.get_json(silent=True) or {}
        rec = {
            "ts": _now_iso(),
            "admin_id": str(data.get("admin_id") or ""),
            "admin_username": data.get("admin_username") or "",
            "action": data.get("action") or "",
            "details": data.get("details") or ""
        }
        _extend_file(TELEGRAM_ADMIN_LOG_FILE, json.dumps(rec, ensure_ascii=False))
        _extend_file(TELEGRAM_LOG_FILE, f"[{rec['ts']}] admin {rec['admin_id']} {rec['action']} {rec['details']}")
        return jsonify(ok=True, recorded=True)

    return {
        'tg_test': tg_test,
        'tg_settings_get': tg_settings_get,
        'tg_settings_post': tg_settings_post,
        'tg_token_set': tg_token_set,
        'tg_token_clear': tg_token_clear,
        'tg_admins_get': tg_admins_get,
        'tg_admins_post': tg_admins_post,
        'tg_admins_del': tg_admins_del,
        'tg_logs_get': tg_logs_get,
        'tg_logs_del': tg_logs_del,
        'telegram_worker_logs': telegram_worker_logs,
        'tg_status': tg_status,
        'tg_heartbeat': tg_heartbeat,
        'tg_admin_logs': tg_admin_logs,
        'tg_adminlogs_clear': tg_adminlogs_clear,
        'tg_adminlog': tg_adminlog,
    }
