def build_routes(*,
    _HTTP_4XX_LOCK_FILE,
    _HTTP_4XX_STATE_FILE,
    _HTTP_SECURITY_SETTINGS_FILE,
    _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC,
    _http_security_active_blocks,
    _http_security_add_history_locked,
    _http_security_cleanup_expired,
    _http_security_client_ip,
    _http_security_firewall_remove,
    _http_security_geo,
    _http_security_int,
    _http_security_network_contains,
    _http_security_nft_status,
    _http_security_normalize_ip,
    _http_security_normalize_networks,
    _http_security_stat_add_locked,
    _http_security_stats_24h,
    _http_security_temp_allows_locked,
    _json_load,
    _json_save,
    _load_http_security_settings,
    _send_telegram_event,
    _tg_human_duration,
    fcntl,
    ipaddress,
    jsonify,
    login_required,
    re,
    request,
    require_api_key_or_login,
    time,
):

    @login_required
    def http_security_capabilities_get():
        settings = _load_http_security_settings()

        return jsonify(
            ok=True,
            firewall=_http_security_nft_status(settings),
            geo={
                "enabled": bool(settings.get("enrich_ip")),
                "provider": "ipwho.is",
                "external_lookup": True,
                "display_only": True,
                "cache_seconds": 86400,
            },
        )

    @require_api_key_or_login
    def http_security_settings_get():
        _http_security_cleanup_expired(send_notifications=True)
        settings = _load_http_security_settings()
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        temporary_allow = _http_security_temp_allows_locked(state if isinstance(state, dict) else {})
        return jsonify(
            ok=True,
            settings=settings,
            active_blocks=_http_security_active_blocks(state, settings=settings),
            temporary_allow=temporary_allow,
            stats_24h=_http_security_stats_24h(state),
            firewall=_http_security_nft_status(settings),
        )

    @require_api_key_or_login
    def http_security_settings_post():
        payload = request.get_json(silent=True) or {}
        allowed = {
            "enabled", "response_mode", "ip_source", "block_scope", "threshold", "window_seconds",
            "sensitive_threshold", "rate_limit_threshold", "login_threshold", "login_window_seconds",
            "cooldown_seconds", "block_seconds", "max_block_seconds", "escalate", "enrich_ip",
            "firewall_enabled", "firewall_after_offenses", "trusted_networks", "deny_networks",
        }
        partial = {key: payload[key] for key in allowed if key in payload}

        if "response_mode" in partial and str(partial["response_mode"]).lower() not in {"monitor", "block"}:
            return jsonify(ok=False, error="invalid_response_mode"), 400
        if "ip_source" in partial and str(partial["ip_source"]).lower() not in {"direct", "effective"}:
            return jsonify(ok=False, error="invalid_ip_source"), 400
        if "block_scope" in partial and str(partial["block_scope"]).lower() not in {"all", "auth_admin"}:
            return jsonify(ok=False, error="invalid_block_scope"), 400

        for key in ("trusted_networks", "deny_networks"):
            if key not in partial:
                continue
            raw_values = partial[key]
            if isinstance(raw_values, str):
                raw_values = re.split(r"[\r\n,]+", raw_values)
            if not isinstance(raw_values, list):
                return jsonify(ok=False, error=f"invalid_{key}"), 400
            checked = []
            for item in raw_values:
                value = str(item or "").strip()
                if not value:
                    continue
                try:
                    if "/" not in value:
                        ip = ipaddress.ip_address(value)
                        value = f"{ip}/{32 if ip.version == 4 else 128}"
                    else:
                        value = str(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    return jsonify(ok=False, error="invalid_network", field=key, value=value), 400
                if value not in checked:
                    checked.append(value)
            partial[key] = checked

        proposed = _load_http_security_settings()
        proposed.update(partial)
        proposed["trusted_networks"] = _http_security_normalize_networks(proposed.get("trusted_networks"))
        proposed["deny_networks"] = _http_security_normalize_networks(proposed.get("deny_networks"))

        current_ip = _http_security_client_ip(proposed)
        if current_ip != "unknown" and _http_security_network_contains(current_ip, proposed.get("deny_networks")):
            return jsonify(
                ok=False,
                error="would_block_current_admin",
                message="The permanent deny list contains your current client IP. Remove it before saving.",
                ip=current_ip,
            ), 409

        if bool(proposed.get("firewall_enabled")):
            firewall_status = _http_security_nft_status(proposed)

            if not firewall_status.get("usable"):
                return jsonify(
                    ok=False,
                    error="nftables_unavailable",
                    message=(
                        "Host-firewall escalation cannot be enabled because nftables "
                        "is unavailable to the WG Panel service. Application-level "
                        "blocking is still active."
                    ),
                    firewall=firewall_status,
                ), 409

        _json_save(_HTTP_SECURITY_SETTINGS_FILE, proposed)
        settings = _load_http_security_settings()

        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        return jsonify(
            ok=True,
            settings=settings,
            active_blocks=_http_security_active_blocks(state, settings=settings),
            temporary_allow=_http_security_temp_allows_locked(state if isinstance(state, dict) else {}),
            stats_24h=_http_security_stats_24h(state),
            firewall=_http_security_nft_status(settings),
        )

    @require_api_key_or_login
    def http_security_unban():
        payload = request.get_json(silent=True) or {}
        client_ip = _http_security_normalize_ip(payload.get("ip"))
        if client_ip == "unknown":
            return jsonify(ok=False, error="invalid_ip"), 400

        now = int(time.time())
        released = False
        reason = ""
        offenses = 0
        lock_handle = None
        try:
            lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            state = _json_load(_HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            clients = state.get("clients")
            if not isinstance(clients, dict):
                clients = {}
            record = clients.get(client_ip)
            if isinstance(record, dict):
                released = int(record.get("blocked_until") or 0) > now
                reason = str(record.get("block_reason") or "")
                offenses = int(record.get("offenses") or 0)
                record["blocked_until"] = 0
                record["block_active"] = False
                record["block_reason"] = ""
                record["firewall_active"] = False
                record["events"] = []
                clients[client_ip] = record
            if released:
                _http_security_stat_add_locked(state, now, client_ip, releases=1)
                _http_security_add_history_locked(
                    state,
                    event_type="manual_release",
                    ip=client_ip,
                    category="release",
                    action="manual_release",
                    reason=reason or "Released by administrator",
                    details={"offenses": offenses},
                    now=now,
                )
            state["clients"] = clients
            state["updated_at"] = now
            _json_save(_HTTP_4XX_STATE_FILE, state)
        finally:
            if lock_handle:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                lock_handle.close()

        _http_security_firewall_remove(client_ip)
        if released:
            _send_telegram_event(
                "security_release",
                "◇ HTTP security block released",
                status="Manually released",
                details=[("Client IP", client_ip), ("Previous reason", reason or "Temporary block"), ("Offense level", offenses)],
                dedupe_key=f"security-manual-release:{client_ip}:{now}",
                dedupe_seconds=0,
            )

        return jsonify(ok=True, ip=client_ip, active_blocks=_http_security_active_blocks())

    @require_api_key_or_login
    def http_security_events_get():
        settings = _load_http_security_settings()
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        history = state.get("history") if isinstance(state, dict) else []
        if not isinstance(history, list):
            history = []

        event_type = str(request.args.get("type") or "").strip().lower()
        category = str(request.args.get("category") or "").strip().lower()
        ip_filter = str(request.args.get("ip") or "").strip()
        limit = _http_security_int(request.args.get("limit"), 150, 1, 500)

        rows = []
        for row in reversed(history):
            if not isinstance(row, dict):
                continue
            if event_type and str(row.get("type") or "").lower() != event_type:
                continue
            if category and str(row.get("category") or "").lower() != category:
                continue
            if ip_filter and ip_filter not in str(row.get("ip") or ""):
                continue
            item = dict(row)
            if settings.get("enrich_ip") and item.get("ip"):
                item["geo"] = _http_security_geo(item.get("ip"), settings)
            rows.append(item)
            if len(rows) >= limit:
                break

        return jsonify(ok=True, events=rows, stats_24h=_http_security_stats_24h(state))

    @login_required
    def http_security_events_clear():
        lock_handle = None
        try:
            lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            state = _json_load(_HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            state["history"] = []
            state["updated_at"] = int(time.time())
            _json_save(_HTTP_4XX_STATE_FILE, state)
        finally:
            if lock_handle:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                lock_handle.close()
        return jsonify(ok=True)

    @login_required
    def http_security_temporary_allow_add():
        payload = request.get_json(silent=True) or {}
        raw = str(payload.get("network") or "").strip()
        duration = _http_security_int(payload.get("duration_seconds"), 3600, 60, _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC)
        normalized = _http_security_normalize_networks([raw])
        if not normalized:
            return jsonify(ok=False, error="invalid_network"), 400
        network = normalized[0]
        now = int(time.time())
        expires_at = now + duration

        lock_handle = None
        try:
            lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            state = _json_load(_HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            rows = _http_security_temp_allows_locked(state, now)
            rows = [row for row in rows if str(row.get("network")) != network]
            rows.append({"network": network, "expires_at": expires_at})
            state["temporary_allow"] = rows
            _http_security_add_history_locked(
                state,
                event_type="temporary_allow",
                category="access_list",
                action="allow",
                reason=f"Temporary allow added for {_tg_human_duration(duration)}",
                details={"network": network, "expires_at": expires_at},
                now=now,
            )
            _json_save(_HTTP_4XX_STATE_FILE, state)
        finally:
            if lock_handle:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                lock_handle.close()
        return jsonify(ok=True, network=network, expires_at=expires_at, temporary_allow=_http_security_temp_allows_locked(_json_load(_HTTP_4XX_STATE_FILE, {})))

    @login_required
    def http_security_temporary_allow_remove():
        payload = request.get_json(silent=True) or {}
        normalized = _http_security_normalize_networks([payload.get("network")])
        if not normalized:
            return jsonify(ok=False, error="invalid_network"), 400
        network = normalized[0]
        now = int(time.time())
        lock_handle = None
        try:
            lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            state = _json_load(_HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            rows = _http_security_temp_allows_locked(state, now)
            state["temporary_allow"] = [row for row in rows if str(row.get("network")) != network]
            _http_security_add_history_locked(
                state,
                event_type="temporary_allow_removed",
                category="access_list",
                action="remove_allow",
                reason="Temporary allow removed",
                details={"network": network},
                now=now,
            )
            _json_save(_HTTP_4XX_STATE_FILE, state)
        finally:
            if lock_handle:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                lock_handle.close()
        return jsonify(ok=True, network=network, temporary_allow=_http_security_temp_allows_locked(_json_load(_HTTP_4XX_STATE_FILE, {})))

    return {
        'http_security_capabilities_get': http_security_capabilities_get,
        'http_security_settings_get': http_security_settings_get,
        'http_security_settings_post': http_security_settings_post,
        'http_security_unban': http_security_unban,
        'http_security_events_get': http_security_events_get,
        'http_security_events_clear': http_security_events_clear,
        'http_security_temporary_allow_add': http_security_temporary_allow_add,
        'http_security_temporary_allow_remove': http_security_temporary_allow_remove,
    }
