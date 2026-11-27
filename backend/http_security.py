def bind_load_http_security_settings(_panel_context):
    def _load_http_security_settings():
        try:
            stamp = _panel_context.os.stat(_panel_context._HTTP_SECURITY_SETTINGS_FILE).st_mtime_ns
        except OSError:
            stamp = 0

        if _panel_context._HTTP_SECURITY_SETTINGS_CACHE["stamp"] == stamp:
            return dict(_panel_context._HTTP_SECURITY_SETTINGS_CACHE["settings"])

        raw = _panel_context._json_load(_panel_context._HTTP_SECURITY_SETTINGS_FILE, {})
        if not isinstance(raw, dict):
            raw = {}

        settings = dict(_panel_context._HTTP_SECURITY_DEFAULTS)
        settings.update(raw)

        settings["enabled"] = bool(settings.get("enabled", True))
        settings["response_mode"] = (
            "block" if str(settings.get("response_mode") or "").lower() == "block" else "monitor"
        )
        settings["ip_source"] = (
            "effective" if str(settings.get("ip_source") or "").lower() == "effective" else "direct"
        )
        settings["block_scope"] = (
            "auth_admin" if str(settings.get("block_scope") or "").lower() == "auth_admin" else "all"
        )
        settings["threshold"] = _panel_context._http_security_int(settings.get("threshold"), 20, 3, 500)
        settings["window_seconds"] = _panel_context._http_security_int(settings.get("window_seconds"), 60, 10, 3600)
        settings["sensitive_threshold"] = _panel_context._http_security_int(settings.get("sensitive_threshold"), 3, 1, 50)
        settings["rate_limit_threshold"] = _panel_context._http_security_int(settings.get("rate_limit_threshold"), 10, 1, 200)
        settings["login_threshold"] = _panel_context._http_security_int(settings.get("login_threshold"), 5, 2, 100)
        settings["login_window_seconds"] = _panel_context._http_security_int(settings.get("login_window_seconds"), 600, 60, 86400)
        settings["cooldown_seconds"] = _panel_context._http_security_int(settings.get("cooldown_seconds"), 600, 30, 86400)
        settings["block_seconds"] = _panel_context._http_security_int(settings.get("block_seconds"), 900, 60, 604800)
        settings["max_block_seconds"] = _panel_context._http_security_int(settings.get("max_block_seconds"), 86400, 60, 2592000)
        settings["max_block_seconds"] = max(settings["block_seconds"], settings["max_block_seconds"])
        settings["escalate"] = bool(settings.get("escalate", True))
        settings["enrich_ip"] = bool(settings.get("enrich_ip", False))
        settings["firewall_enabled"] = bool(settings.get("firewall_enabled", False))
        settings["firewall_after_offenses"] = _panel_context._http_security_int(
            settings.get("firewall_after_offenses"), 3, 1, 20
        )
        settings["trusted_networks"] = _panel_context._http_security_normalize_networks(settings.get("trusted_networks"))
        settings["deny_networks"] = _panel_context._http_security_normalize_networks(settings.get("deny_networks"))

        _panel_context._HTTP_SECURITY_SETTINGS_CACHE.update(stamp=stamp, settings=dict(settings))
        return settings


    def _save_http_security_settings(settings):
        normalized = _panel_context._load_http_security_settings()
        normalized.update(settings or {})
        _panel_context._json_save(_panel_context._HTTP_SECURITY_SETTINGS_FILE, normalized)
        return _panel_context._load_http_security_settings()


    def _http_security_direct_ip():
        original = _panel_context.request.environ.get("werkzeug.proxy_fix.orig") or {}
        if isinstance(original, dict):
            value = _panel_context._http_security_normalize_ip(original.get("REMOTE_ADDR"))
            if value != "unknown":
                return value
        return _panel_context._http_security_normalize_ip(_panel_context.request.remote_addr)


    def _http_security_effective_ip():
        return _panel_context._http_security_normalize_ip(_panel_context.request.remote_addr)


    def _http_security_client_ip(settings=None):
        settings = settings or _panel_context._load_http_security_settings()
        return (
            _panel_context._http_security_effective_ip()
            if settings.get("ip_source") == "effective"
            else _panel_context._http_security_direct_ip()
        )


    def _http_security_is_trusted(client_ip, settings=None):
        settings = settings or _panel_context._load_http_security_settings()
        return _panel_context._http_security_network_contains(client_ip, settings.get("trusted_networks"))


    def _http_security_is_denied(client_ip, settings=None):
        settings = settings or _panel_context._load_http_security_settings()
        return _panel_context._http_security_network_contains(client_ip, settings.get("deny_networks"))


    def _http_security_temp_allows_locked(state, now=None):
        now = int(now or _panel_context.time.time())
        rows = state.get("temporary_allow") if isinstance(state, dict) else []
        if not isinstance(rows, list):
            rows = []
        active = []
        changed = False
        for row in rows:
            if not isinstance(row, dict):
                changed = True
                continue
            network = str(row.get("network") or "").strip()
            expires_at = int(row.get("expires_at") or 0)
            if not network or expires_at <= now:
                changed = True
                continue
            active.append({"network": network, "expires_at": expires_at})
        if changed:
            state["temporary_allow"] = active
        return active


    def _http_security_is_temporarily_allowed(client_ip, state=None, now=None):
        now = int(now or _panel_context.time.time())
        if state is None:
            state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
        rows = _panel_context._http_security_temp_allows_locked(state if isinstance(state, dict) else {}, now)
        return _panel_context._http_security_network_contains(client_ip, [row.get("network") for row in rows])


    def _http_security_sensitive_path(path):
        return bool(_panel_context._HTTP_SECURITY_SENSITIVE_RE.search(str(path or "")))


    def _http_security_add_history_locked(state, *, event_type, ip="", category="", action="", reason="", path="", status=0, details=None, now=None):
        now = int(now or _panel_context.time.time())
        history = state.get("history")
        if not isinstance(history, list):
            history = []
        row = {
            "ts": now,
            "type": str(event_type or "event")[:48],
            "ip": _panel_context._http_security_normalize_ip(ip) if ip else "",
            "category": str(category or "")[:64],
            "action": str(action or "")[:64],
            "reason": str(reason or "")[:320],
            "path": _panel_context.safe_path(str(path or ""))[:300],
            "status": int(status or 0),
            "details": details if isinstance(details, dict) else {},
        }
        history.append(row)
        state["history"] = history[-_panel_context._HTTP_SECURITY_HISTORY_LIMIT:]
        return row


    def _http_security_stat_add_locked(state, now, ip, **counts):
        buckets = state.get("stats_hours")
        if not isinstance(buckets, dict):
            buckets = {}
        hour = str((int(now) // 3600) * 3600)
        bucket = buckets.get(hour)
        if not isinstance(bucket, dict):
            bucket = {"ips": []}
        for key, value in counts.items():
            bucket[key] = int(bucket.get(key) or 0) + int(value or 0)
        normalized_ip = _panel_context._http_security_normalize_ip(ip)
        ips = bucket.get("ips")
        if not isinstance(ips, list):
            ips = []
        if normalized_ip != "unknown" and normalized_ip not in ips and len(ips) < 1000:
            ips.append(normalized_ip)
        bucket["ips"] = ips
        buckets[hour] = bucket
        cutoff = int(now) - (72 * 3600)
        for key in list(buckets.keys()):
            try:
                if int(key) < cutoff:
                    buckets.pop(key, None)
            except Exception:
                buckets.pop(key, None)
        state["stats_hours"] = buckets


    def _http_security_stats_24h(state=None, now=None):
        now = int(now or _panel_context.time.time())
        if state is None:
            state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
        buckets = state.get("stats_hours") if isinstance(state, dict) else {}
        if not isinstance(buckets, dict):
            buckets = {}
        totals = {
            "rejected": 0,
            "sensitive": 0,
            "blocks": 0,
            "monitor_triggers": 0,
            "releases": 0,
            "login_failures": 0,
            "rate_limited": 0,
            "unique_ips": 0,
        }
        ips = set()
        cutoff = now - 86400
        for key, bucket in buckets.items():
            try:
                if int(key) < cutoff or not isinstance(bucket, dict):
                    continue
            except Exception:
                continue
            for name in ("rejected", "sensitive", "blocks", "monitor_triggers", "releases", "login_failures", "rate_limited"):
                totals[name] += int(bucket.get(name) or 0)
            for value in bucket.get("ips") or []:
                if _panel_context._http_security_normalize_ip(value) != "unknown":
                    ips.add(str(value))
        totals["unique_ips"] = len(ips)
        return totals


    def _http_security_geo(ip, settings=None):
        settings = settings or _panel_context._load_http_security_settings()
        if not settings.get("enrich_ip"):
            return {}
        ip = _panel_context._http_security_normalize_ip(ip)
        if ip == "unknown":
            return {}
        try:
            address = _panel_context.ipaddress.ip_address(ip)
            if not address.is_global:
                return {}
        except Exception:
            return {}

        now = _panel_context.time.time()
        with _panel_context._HTTP_SECURITY_GEO_CACHE_LOCK:
            cached = _panel_context._HTTP_SECURITY_GEO_CACHE.get(ip)
            if isinstance(cached, dict) and now - float(cached.get("_ts") or 0) < 86400:
                return {k: v for k, v in cached.items() if k != "_ts"}

        result = {}
        try:
            response = _panel_context.requests.get(f"https://ipwho.is/{ip}", timeout=3)
            if response.ok:
                payload = response.json() or {}
                if payload.get("success", True):
                    connection = payload.get("connection") or {}
                    result = {
                        "country": str(payload.get("country") or "")[:80],
                        "country_code": str(payload.get("country_code") or "")[:8],
                        "asn": str(connection.get("asn") or "")[:40],
                        "provider": str(connection.get("isp") or connection.get("org") or "")[:120],
                    }
        except Exception:
            result = {}

        with _panel_context._HTTP_SECURITY_GEO_CACHE_LOCK:
            _panel_context._HTTP_SECURITY_GEO_CACHE[ip] = {"_ts": now, **result}
            if len(_panel_context._HTTP_SECURITY_GEO_CACHE) > 500:
                oldest = sorted(_panel_context._HTTP_SECURITY_GEO_CACHE.items(), key=lambda item: float((item[1] or {}).get("_ts") or 0))[:100]
                for key, _ in oldest:
                    _panel_context._HTTP_SECURITY_GEO_CACHE.pop(key, None)
        return result


    def _http_security_nft_install_command():
        if _panel_context.shutil.which("apt-get"):
            return "sudo apt-get update && sudo apt-get install -y nftables"
        if _panel_context.shutil.which("dnf"):
            return "sudo dnf install -y nftables"
        if _panel_context.shutil.which("yum"):
            return "sudo yum install -y nftables"
        if _panel_context.shutil.which("pacman"):
            return "sudo pacman -S --needed nftables"
        return "Install the nftables package with your operating system package manager."


    def _http_security_nft_status(settings=None):
        nft = _panel_context.shutil.which("nft")
        configured = bool((settings or {}).get("firewall_enabled")) if isinstance(settings, dict) else None

        base = {
            "backend": "nftables",
            "available": bool(nft),
            "usable": False,
            "privileged": False,
            "configured": configured,
            "effective": False,
            "table": _panel_context._HTTP_SECURITY_NFT_TABLE,
            "reason": "not_installed" if not nft else "checking",
            "detail": "",
            "install_command": _panel_context._http_security_nft_install_command(),
            "check_command": "sudo nft list ruleset",
            "automatic_install": False,
        }

        if not nft:
            base["detail"] = (
                "The nft executable was not found. "
                "Application-level blocking is still active."
            )
            return base

        try:
            proc = _panel_context.subprocess.run(
                [nft, "list", "ruleset"],
                stdout=_panel_context.subprocess.DEVNULL,
                stderr=_panel_context.subprocess.PIPE,
                text=True,
                timeout=3,
                check=False,
            )
        except Exception as exc:
            base["reason"] = "check_failed"
            base["detail"] = str(exc)[:300]
            return base

        if proc.returncode == 0:
            base["usable"] = True
            base["privileged"] = True
            base["reason"] = "ready"
            base["detail"] = (
                "WG Panel can read/manage nftables through "
                "the current service permissions."
            )
            base["effective"] = (
                bool(configured)
                if configured is not None
                else False
            )
            return base

        detail = (
            proc.stderr
            or "nft list ruleset failed"
        ).strip()[:300]

        low = detail.lower()

        base["reason"] = (
            "permission_denied"
            if (
                "operation not permitted" in low
                or "permission denied" in low
                or "must be root" in low
            )
            else "unusable"
        )
        base["detail"] = detail

        return base


    def _http_security_nft_run_script(script):
        status = _panel_context._http_security_nft_status()
        nft = _panel_context.shutil.which("nft")
        if not status.get("usable") or not nft:
            return False, "nftables is unavailable or the panel process lacks root/CAP_NET_ADMIN"
        try:
            proc = _panel_context.subprocess.run(
                [nft, "-f", "-"],
                input=str(script),
                text=True,
                stdout=_panel_context.subprocess.PIPE,
                stderr=_panel_context.subprocess.PIPE,
                timeout=4,
                check=False,
            )
            if proc.returncode != 0:
                return False, (proc.stderr or proc.stdout or "nft failed").strip()[:300]
            return True, ""
        except Exception as exc:
            return False, str(exc)[:300]


    def _http_security_nft_ensure():
        status = _panel_context._http_security_nft_status()
        nft = _panel_context.shutil.which("nft")
        if not status.get("usable") or not nft:
            return False, "nftables is unavailable or the panel process lacks root/CAP_NET_ADMIN"
        check = _panel_context.subprocess.run(
            [nft, "list", "table", "inet", _panel_context._HTTP_SECURITY_NFT_TABLE],
            stdout=_panel_context.subprocess.DEVNULL,
            stderr=_panel_context.subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        if check.returncode == 0:
            return True, ""
        script = f"""
table inet {_panel_context._HTTP_SECURITY_NFT_TABLE} {{
    set {_panel_context._HTTP_SECURITY_NFT_V4_SET} {{ type ipv4_addr; flags timeout; }}
    set {_panel_context._HTTP_SECURITY_NFT_V6_SET} {{ type ipv6_addr; flags timeout; }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @{_panel_context._HTTP_SECURITY_NFT_V4_SET} drop
        ip6 saddr @{_panel_context._HTTP_SECURITY_NFT_V6_SET} drop
    }}
}}
"""
        return _panel_context._http_security_nft_run_script(script)


    def _http_security_firewall_add(ip, seconds):
        ip = _panel_context._http_security_normalize_ip(ip)
        if ip == "unknown":
            return False, "invalid IP"
        ok, detail = _panel_context._http_security_nft_ensure()
        if not ok:
            return False, detail
        version = _panel_context.ipaddress.ip_address(ip).version
        set_name = _panel_context._HTTP_SECURITY_NFT_V4_SET if version == 4 else _panel_context._HTTP_SECURITY_NFT_V6_SET
        seconds = _panel_context._http_security_int(seconds, 900, 60, 2592000)
        _panel_context._http_security_nft_run_script(
            f"delete element inet {_panel_context._HTTP_SECURITY_NFT_TABLE} {set_name} {{ {ip} }}\n"
        )
        return _panel_context._http_security_nft_run_script(
            f"add element inet {_panel_context._HTTP_SECURITY_NFT_TABLE} {set_name} {{ {ip} timeout {seconds}s }}\n"
        )


    def _http_security_firewall_remove(ip):
        ip = _panel_context._http_security_normalize_ip(ip)
        if ip == "unknown":
            return False, "invalid IP"
        status = _panel_context._http_security_nft_status()
        if not status.get("usable"):
            return False, "nftables unavailable"
        version = _panel_context.ipaddress.ip_address(ip).version
        set_name = _panel_context._HTTP_SECURITY_NFT_V4_SET if version == 4 else _panel_context._HTTP_SECURITY_NFT_V6_SET
        return _panel_context._http_security_nft_run_script(
            f"delete element inet {_panel_context._HTTP_SECURITY_NFT_TABLE} {set_name} {{ {ip} }}\n"
        )


    def _http_security_apply_block_locked(record, settings, now, reason):
        current_block = int(record.get("blocked_until") or 0)
        if current_block > now:
            return False, 0, int(record.get("offenses") or 1)

        last_offense = int(record.get("last_offense") or 0)
        if last_offense and now - last_offense >= _panel_context._HTTP_SECURITY_OFFENSE_RESET_SEC:
            record["offenses"] = 0

        offenses = max(0, int(record.get("offenses") or 0)) + 1
        record["offenses"] = offenses
        record["last_offense"] = now
        multiplier = (2 ** max(0, offenses - 1)) if settings.get("escalate") else 1
        block_seconds = min(settings["max_block_seconds"], settings["block_seconds"] * multiplier)
        record["blocked_until"] = now + block_seconds
        record["block_started_at"] = now
        record["block_reason"] = reason
        record["block_active"] = True
        return True, block_seconds, offenses


    def _http_security_active_blocks(state=None, current_epoch=None, settings=None):
        current_epoch = int(current_epoch or _panel_context.time.time())
        settings = settings or _panel_context._load_http_security_settings()
        if state is None:
            state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
        clients = state.get("clients") if isinstance(state, dict) else {}
        if not isinstance(clients, dict):
            clients = {}

        rows = []
        for ip, record in clients.items():
            if not isinstance(record, dict):
                continue
            blocked_until = int(record.get("blocked_until") or 0)
            if blocked_until <= current_epoch:
                continue
            rows.append({
                "ip": ip,
                "reason": str(record.get("block_reason") or "Threshold reached"),
                "category": str(record.get("block_category") or ""),
                "offenses": int(record.get("offenses") or 1),
                "blocked_until": blocked_until,
                "remaining_seconds": max(0, blocked_until - current_epoch),
                "last_seen": int(record.get("last_seen") or 0),
                "firewall": bool(record.get("firewall_active")),
                "geo": _panel_context._http_security_geo(ip, settings),
            })
        return sorted(rows, key=lambda row: row["blocked_until"], reverse=True)


    def _http_security_cleanup_expired(send_notifications=True):
        now = int(_panel_context.time.time())
        released = []
        lock_handle = None
        try:
            lock_handle = open(_panel_context._HTTP_4XX_LOCK_FILE, "a+")
            _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_EX)
            state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            _panel_context._http_security_temp_allows_locked(state, now)
            clients = state.get("clients")
            if not isinstance(clients, dict):
                clients = {}

            for ip, record in clients.items():
                if not isinstance(record, dict):
                    continue
                blocked_until = int(record.get("blocked_until") or 0)
                if blocked_until and blocked_until <= now and bool(record.get("block_active")):
                    reason = str(record.get("block_reason") or "Temporary block expired")
                    offenses = int(record.get("offenses") or 1)
                    record["block_active"] = False
                    record["blocked_until"] = 0
                    record["block_reason"] = ""
                    record["firewall_active"] = False
                    _panel_context._http_security_stat_add_locked(state, now, ip, releases=1)
                    _panel_context._http_security_add_history_locked(
                        state,
                        event_type="auto_release",
                        ip=ip,
                        category="release",
                        action="auto_release",
                        reason=reason,
                        details={"offenses": offenses},
                        now=now,
                    )
                    released.append((ip, reason, offenses))
            state["clients"] = clients
            state["updated_at"] = now
            _panel_context._json_save(_panel_context._HTTP_4XX_STATE_FILE, state)
        except Exception:
            _panel_context.app.logger.debug("HTTP security expiry cleanup failed", exc_info=True)
        finally:
            if lock_handle:
                try:
                    _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    lock_handle.close()
                except Exception:
                    pass

        if send_notifications:
            for ip, reason, offenses in released:
                _panel_context._send_telegram_event(
                    "security_auto_release",
                    "◇ HTTP security block expired",
                    status="Automatically released",
                    details=[
                        ("Client IP", ip),
                        ("Previous reason", reason),
                        ("Offense level", offenses),
                    ],
                    dedupe_key=f"security-auto-release:{ip}:{now}",
                    dedupe_seconds=0,
                )
        return released


    def _http_security_cleanup_loop():
        while True:
            try:
                with _panel_context.app.app_context():
                    _panel_context._http_security_cleanup_expired(send_notifications=True)
            except Exception:
                pass
            _panel_context.time.sleep(30)


    def _start_http_security_cleanup():
        pass
        if _panel_context._HTTP_SECURITY_CLEANUP_STARTED:
            return
        _panel_context._HTTP_SECURITY_CLEANUP_STARTED = True
        _panel_context.threading.Thread(
            target=_panel_context._http_security_cleanup_loop,
            name="http-security-cleanup",
            daemon=True,
        ).start()


    @_panel_context.app.before_request
    def _http_security_enforce_temporary_block():
        settings = _panel_context._load_http_security_settings()
        if not settings.get("enabled"):
            return None

        client_ip = _panel_context._http_security_client_ip(settings)
        if client_ip == "unknown":
            return None

        if _panel_context._http_security_is_denied(client_ip, settings):
            _panel_context.g.http_security_blocked = True
            return _panel_context.make_response(_panel_context.jsonify(
                ok=False,
                error="permanently_blocked",
                message="This client is denied by the panel security policy.",
            ), 403)


        if settings.get("response_mode") != "block":
            return None
        if not _panel_context._http_security_scope_applies(_panel_context.request.path, settings.get("block_scope")):
            return None
        if _panel_context._http_security_is_trusted(client_ip, settings):
            return None
        state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
        if _panel_context._http_security_is_temporarily_allowed(client_ip, state=state):
            return None

        clients = state.get("clients") if isinstance(state, dict) else {}
        record = clients.get(client_ip) if isinstance(clients, dict) else None
        blocked_until = int((record or {}).get("blocked_until") or 0)
        now = int(_panel_context.time.time())

        if blocked_until <= now:
            return None

        _panel_context.g.http_security_blocked = True
        retry_after = max(1, blocked_until - now)
        response = _panel_context.make_response(_panel_context.jsonify(
            ok=False,
            error="temporarily_blocked",
            message="This client is temporarily blocked by panel HTTP security.",
            retry_after=retry_after,
        ), 403)
        response.headers["Retry-After"] = str(retry_after)
        return response


    def _record_suspicious_4xx(response):
        if getattr(_panel_context.g, "http_security_blocked", False):
            return

        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code not in _panel_context._HTTP_4XX_STATUSES:
            return

        request_path = str(_panel_context.request.path or "")
        if _panel_context._suspicious_4xx_ignored_path(request_path):
            return

        settings = _panel_context._load_http_security_settings()
        if not settings.get("enabled"):
            return

        client_ip = _panel_context._http_security_client_ip(settings)
        if client_ip == "unknown":
            return
        if _panel_context._http_security_is_denied(client_ip, settings):
            return
        state_snapshot = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
        if _panel_context._http_security_is_trusted(client_ip, settings) or _panel_context._http_security_is_temporarily_allowed(client_ip, state_snapshot):
            return

        now = int(_panel_context.time.time())
        window_start = now - settings["window_seconds"]
        sensitive_now = _panel_context._http_security_sensitive_path(request_path)
        category_now = _panel_context._http_security_classify(request_path, status_code)
        lock_handle = None
        should_alert = False
        did_block = False
        block_seconds = 0
        offenses = 0
        reason = ""
        trigger_category = category_now
        request_count = 0
        sensitive_count = 0
        rate_limit_count = 0
        status_counts = {}
        recent_paths = []
        firewall_should_apply = False

        try:
            lock_handle = open(_panel_context._HTTP_4XX_LOCK_FILE, "a+")
            _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_EX)
            state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            clients = state.get("clients")
            if not isinstance(clients, dict):
                clients = {}

            _panel_context._http_security_temp_allows_locked(state, now)
            _panel_context._http_security_stat_add_locked(
                state, now, client_ip,
                rejected=1,
                sensitive=(1 if sensitive_now else 0),
                rate_limited=(1 if status_code == 429 else 0),
            )

            stale_after = max(settings["cooldown_seconds"] * 4, settings["max_block_seconds"] * 2, 86400)
            for old_ip, old_record in list(clients.items()):
                if not isinstance(old_record, dict):
                    clients.pop(old_ip, None)
                    continue
                last_seen = int(old_record.get("last_seen") or 0)
                blocked_until = int(old_record.get("blocked_until") or 0)
                offenses_old = int(old_record.get("offenses") or 0)
                if blocked_until <= now and offenses_old <= 0 and now - last_seen > stale_after:
                    clients.pop(old_ip, None)

            record = clients.get(client_ip)
            if not isinstance(record, dict):
                record = {"events": [], "login_events": [], "last_alert": 0, "last_seen": 0, "offenses": 0}

            events = record.get("events")
            if not isinstance(events, list):
                events = []
            events = [event for event in events if isinstance(event, dict) and int(event.get("ts") or 0) >= window_start]
            events.append({
                "ts": now,
                "status": status_code,
                "path": _panel_context.safe_path(request_path)[:240],
                "method": str(_panel_context.request.method or "")[:16],
                "sensitive": bool(sensitive_now),
                "category": category_now,
            })
            events = events[-300:]
            record["events"] = events
            record["last_seen"] = now

            request_count = len(events)
            sensitive_count = sum(1 for event in events if bool(event.get("sensitive")))
            rate_limit_count = sum(1 for event in events if int(event.get("status") or 0) == 429)
            for event in events:
                key = str(event.get("status") or "unknown")
                status_counts[key] = status_counts.get(key, 0) + 1
            for event in reversed(events):
                value = str(event.get("path") or "").strip()
                if value and value not in recent_paths:
                    recent_paths.append(value)
                if len(recent_paths) >= 5:
                    break

            triggered_sensitive = sensitive_count >= settings["sensitive_threshold"]
            triggered_rate = rate_limit_count >= settings["rate_limit_threshold"]
            triggered_generic = request_count >= settings["threshold"]
            triggered = triggered_sensitive or triggered_rate or triggered_generic
            if triggered:
                if triggered_sensitive:
                    trigger_category = category_now if sensitive_now else "sensitive_scan"
                    reason = f"Sensitive-path threshold reached ({sensitive_count}/{settings['sensitive_threshold']})"
                elif triggered_rate:
                    trigger_category = "rate_limit"
                    reason = f"429 threshold reached ({rate_limit_count}/{settings['rate_limit_threshold']})"
                else:
                    trigger_category = "generic_4xx"
                    reason = f"4xx threshold reached ({request_count}/{settings['threshold']})"

                last_alert = int(record.get("last_alert") or 0)
                if now - last_alert >= settings["cooldown_seconds"]:
                    should_alert = True
                    record["last_alert"] = now

                if settings.get("response_mode") == "block":
                    did_block, block_seconds, offenses = _panel_context._http_security_apply_block_locked(record, settings, now, reason)
                    if did_block:
                        record["block_category"] = trigger_category
                        should_alert = True
                        record["last_alert"] = now
                        _panel_context._http_security_stat_add_locked(state, now, client_ip, blocks=1)
                        _panel_context._http_security_add_history_locked(
                            state,
                            event_type="block",
                            ip=client_ip,
                            category=trigger_category,
                            action="temporary_block",
                            reason=reason,
                            path=request_path,
                            status=status_code,
                            details={"duration_seconds": block_seconds, "offenses": offenses},
                            now=now,
                        )
                        firewall_should_apply = bool(
                            settings.get("firewall_enabled")
                            and offenses >= settings.get("firewall_after_offenses", 3)
                        )
                elif should_alert:
                    _panel_context._http_security_stat_add_locked(state, now, client_ip, monitor_triggers=1)
                    _panel_context._http_security_add_history_locked(
                        state,
                        event_type="monitor_trigger",
                        ip=client_ip,
                        category=trigger_category,
                        action="monitor",
                        reason=reason,
                        path=request_path,
                        status=status_code,
                        details={"requests": request_count, "sensitive": sensitive_count, "rate_limited": rate_limit_count},
                        now=now,
                    )

            clients[client_ip] = record
            state["clients"] = clients
            state["updated_at"] = now
            _panel_context._json_save(_panel_context._HTTP_4XX_STATE_FILE, state)

        except Exception:
            _panel_context.app.logger.debug("HTTP security tracker failed", exc_info=True)
        finally:
            if lock_handle:
                try:
                    _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    lock_handle.close()
                except Exception:
                    pass

        firewall_detail = ""
        if did_block and firewall_should_apply:
            fw_ok, firewall_detail = _panel_context._http_security_firewall_add(client_ip, block_seconds)
            if fw_ok:
                lock_handle = None
                try:
                    lock_handle = open(_panel_context._HTTP_4XX_LOCK_FILE, "a+")
                    _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_EX)
                    state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
                    clients = state.get("clients") if isinstance(state, dict) else {}
                    if isinstance(clients, dict) and isinstance(clients.get(client_ip), dict):
                        clients[client_ip]["firewall_active"] = True
                        state["clients"] = clients
                        _panel_context._json_save(_panel_context._HTTP_4XX_STATE_FILE, state)
                finally:
                    if lock_handle:
                        try:
                            _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_UN)
                        except Exception:
                            pass
                        lock_handle.close()
            else:
                _panel_context.app.logger.warning("HTTP security nftables escalation failed for %s: %s", client_ip, firewall_detail)

        if not should_alert:
            return

        event_key = "security_block" if did_block else "suspicious_4xx"
        details = [
            ("Client IP", client_ip),
            ("Category", trigger_category.replace("_", " ").title()),
            ("Requests", request_count),
            ("Sensitive requests", sensitive_count),
            ("429 responses", rate_limit_count),
            ("Window", _panel_context._tg_human_duration(settings["window_seconds"])),
            ("Statuses", ", ".join(f"{k}×{v}" for k, v in sorted(status_counts.items()))),
            ("Reason", reason or "Threshold reached"),
            ("Action", (f"Blocked for {_panel_context._tg_human_duration(block_seconds)}" if did_block else "Monitor only")),
            ("Recent paths", " | ".join(recent_paths)[:700]),
            ("Last method", _panel_context.request.method),
            ("User agent", str(_panel_context.request.headers.get("User-Agent") or "")[:300]),
        ]
        if did_block and settings.get("firewall_enabled"):
            details.append(("Host firewall", "Applied" if not firewall_detail else f"Not applied · {firewall_detail}"))
        geo = _panel_context._http_security_geo(client_ip, settings)
        if geo:
            details.append(("Network", " · ".join(filter(None, [geo.get("country_code"), geo.get("asn"), geo.get("provider")]))))

        _panel_context._send_telegram_event(
            event_key,
            "◆ Suspicious HTTP activity detected",
            status=("Temporarily blocked" if did_block else "Threshold reached"),
            details=details,
            dedupe_key=f"http-security:{event_key}:{client_ip}",
            dedupe_seconds=(0 if did_block else settings["cooldown_seconds"]),
        )


    def _http_security_record_login_failure(username="", failure_type="credentials"):
        settings = _panel_context._load_http_security_settings()
        if not settings.get("enabled"):
            return
        client_ip = _panel_context._http_security_client_ip(settings)
        if client_ip == "unknown" or _panel_context._http_security_is_denied(client_ip, settings):
            return
        state_snapshot = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
        if _panel_context._http_security_is_trusted(client_ip, settings) or _panel_context._http_security_is_temporarily_allowed(client_ip, state_snapshot):
            return

        now = int(_panel_context.time.time())
        window_start = now - settings["login_window_seconds"]
        lock_handle = None
        should_alert = False
        did_block = False
        block_seconds = 0
        offenses = 0
        count = 0
        reason = ""
        firewall_should_apply = False

        try:
            lock_handle = open(_panel_context._HTTP_4XX_LOCK_FILE, "a+")
            _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_EX)
            state = _panel_context._json_load(_panel_context._HTTP_4XX_STATE_FILE, {})
            if not isinstance(state, dict):
                state = {}
            clients = state.get("clients")
            if not isinstance(clients, dict):
                clients = {}
            record = clients.get(client_ip)
            if not isinstance(record, dict):
                record = {"events": [], "login_events": [], "last_alert": 0, "last_seen": 0, "offenses": 0}

            login_events = record.get("login_events")
            if not isinstance(login_events, list):
                login_events = []
            login_events = [event for event in login_events if isinstance(event, dict) and int(event.get("ts") or 0) >= window_start]
            login_events.append({
                "ts": now,
                "type": str(failure_type or "credentials")[:32],
                "username": str(username or "")[:120],
            })
            login_events = login_events[-200:]
            record["login_events"] = login_events
            record["last_seen"] = now
            count = len(login_events)
            _panel_context._http_security_stat_add_locked(state, now, client_ip, login_failures=1)

            if count >= settings["login_threshold"]:
                reason = f"Login-failure threshold reached ({count}/{settings['login_threshold']})"
                last_alert = int(record.get("last_login_alert") or 0)
                if now - last_alert >= settings["cooldown_seconds"]:
                    should_alert = True
                    record["last_login_alert"] = now

                if settings.get("response_mode") == "block":
                    did_block, block_seconds, offenses = _panel_context._http_security_apply_block_locked(record, settings, now, reason)
                    if did_block:
                        record["block_category"] = "auth_bruteforce"
                        should_alert = True
                        record["last_login_alert"] = now
                        _panel_context._http_security_stat_add_locked(state, now, client_ip, blocks=1)
                        _panel_context._http_security_add_history_locked(
                            state,
                            event_type="block",
                            ip=client_ip,
                            category="auth_bruteforce",
                            action="temporary_block",
                            reason=reason,
                            details={"duration_seconds": block_seconds, "offenses": offenses, "username": str(username or "")[:120]},
                            now=now,
                        )
                        firewall_should_apply = bool(
                            settings.get("firewall_enabled")
                            and offenses >= settings.get("firewall_after_offenses", 3)
                        )
                elif should_alert:
                    _panel_context._http_security_stat_add_locked(state, now, client_ip, monitor_triggers=1)
                    _panel_context._http_security_add_history_locked(
                        state,
                        event_type="login_trigger",
                        ip=client_ip,
                        category="auth_bruteforce",
                        action="monitor",
                        reason=reason,
                        details={"username": str(username or "")[:120], "count": count},
                        now=now,
                    )

            clients[client_ip] = record
            state["clients"] = clients
            state["updated_at"] = now
            _panel_context._json_save(_panel_context._HTTP_4XX_STATE_FILE, state)
        except Exception:
            _panel_context.app.logger.debug("HTTP security login tracker failed", exc_info=True)
        finally:
            if lock_handle:
                try:
                    _panel_context.fcntl.flock(lock_handle.fileno(), _panel_context.fcntl.LOCK_UN)
                except Exception:
                    pass
                lock_handle.close()

        firewall_detail = ""
        if did_block and firewall_should_apply:
            fw_ok, firewall_detail = _panel_context._http_security_firewall_add(client_ip, block_seconds)
            if not fw_ok:
                _panel_context.app.logger.warning("HTTP security nftables escalation failed for login offender %s: %s", client_ip, firewall_detail)

        if should_alert:
            _panel_context._send_telegram_event(
                "security_block" if did_block else "suspicious_4xx",
                "◆ Repeated authentication failures",
                status=("Temporarily blocked" if did_block else "Threshold reached"),
                details=[
                    ("Client IP", client_ip),
                    ("Account", username or "unknown"),
                    ("Failures", count),
                    ("Window", _panel_context._tg_human_duration(settings["login_window_seconds"])),
                    ("Reason", reason),
                    ("Action", f"Blocked for {_panel_context._tg_human_duration(block_seconds)}" if did_block else "Monitor only"),
                    ("Host firewall", "Requested" if did_block and firewall_should_apply else "Application only"),
                ],
                dedupe_key=f"security-login-threshold:{client_ip}",
                dedupe_seconds=(0 if did_block else settings["cooldown_seconds"]),
            )


    @_panel_context.app.after_request
    def _suspicious_4xx_after_request(response):
        try:
            _panel_context._record_suspicious_4xx(response)
        except Exception:
            _panel_context.app.logger.debug("Could not inspect 4xx response", exc_info=True)
        return response

    return {
        '_load_http_security_settings': _load_http_security_settings,
        '_save_http_security_settings': _save_http_security_settings,
        '_http_security_direct_ip': _http_security_direct_ip,
        '_http_security_effective_ip': _http_security_effective_ip,
        '_http_security_client_ip': _http_security_client_ip,
        '_http_security_is_trusted': _http_security_is_trusted,
        '_http_security_is_denied': _http_security_is_denied,
        '_http_security_temp_allows_locked': _http_security_temp_allows_locked,
        '_http_security_is_temporarily_allowed': _http_security_is_temporarily_allowed,
        '_http_security_sensitive_path': _http_security_sensitive_path,
        '_http_security_add_history_locked': _http_security_add_history_locked,
        '_http_security_stat_add_locked': _http_security_stat_add_locked,
        '_http_security_stats_24h': _http_security_stats_24h,
        '_http_security_geo': _http_security_geo,
        '_http_security_nft_install_command': _http_security_nft_install_command,
        '_http_security_nft_status': _http_security_nft_status,
        '_http_security_nft_run_script': _http_security_nft_run_script,
        '_http_security_nft_ensure': _http_security_nft_ensure,
        '_http_security_firewall_add': _http_security_firewall_add,
        '_http_security_firewall_remove': _http_security_firewall_remove,
        '_http_security_apply_block_locked': _http_security_apply_block_locked,
        '_http_security_active_blocks': _http_security_active_blocks,
        '_http_security_cleanup_expired': _http_security_cleanup_expired,
        '_http_security_cleanup_loop': _http_security_cleanup_loop,
        '_start_http_security_cleanup': _start_http_security_cleanup,
        '_http_security_enforce_temporary_block': _http_security_enforce_temporary_block,
        '_record_suspicious_4xx': _record_suspicious_4xx,
        '_http_security_record_login_failure': _http_security_record_login_failure,
        '_suspicious_4xx_after_request': _suspicious_4xx_after_request,
    }


def initialize_state(context):
    os = context.os
    app = context.app
    re = context.re
    threading = context.threading
    _HTTP_4XX_STATE_FILE = os.path.join(app.instance_path, "suspicious_4xx_state.json")
    _HTTP_4XX_LOCK_FILE = os.path.join(app.instance_path, "suspicious_4xx_state.lock")
    _HTTP_SECURITY_SETTINGS_FILE = os.path.join(app.instance_path, "http_security_settings.json")
    _HTTP_SECURITY_SETTINGS_CACHE = {"stamp": None, "settings": {}}
    _HTTP_4XX_STATUSES = {401, 403, 404, 405, 429}

    _HTTP_SECURITY_DEFAULTS = {
        "enabled": True,
        "response_mode": "monitor",
        "ip_source": "direct",
        "block_scope": "all",
        "threshold": 20,
        "window_seconds": 60,
        "sensitive_threshold": 3,
        "rate_limit_threshold": 10,
        "login_threshold": 5,
        "login_window_seconds": 600,
        "cooldown_seconds": 600,
        "block_seconds": 900,
        "max_block_seconds": 86400,
        "escalate": True,
        "enrich_ip": False,
        "firewall_enabled": False,
        "firewall_after_offenses": 3,
        "trusted_networks": ["127.0.0.1/32", "::1/128"],
        "deny_networks": [],
    }

    _HTTP_SECURITY_OFFENSE_RESET_SEC = 7 * 24 * 60 * 60
    _HTTP_SECURITY_HISTORY_LIMIT = 500
    _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC = 7 * 24 * 60 * 60
    _HTTP_SECURITY_NFT_TABLE = "wgpanel_security"
    _HTTP_SECURITY_NFT_V4_SET = "blocked_v4"
    _HTTP_SECURITY_NFT_V6_SET = "blocked_v6"
    _HTTP_SECURITY_CLEANUP_STARTED = False
    _HTTP_SECURITY_GEO_CACHE = {}
    _HTTP_SECURITY_GEO_CACHE_LOCK = threading.Lock()

    _HTTP_SECURITY_SENSITIVE_RE = re.compile(
        r"(?:^|/)\.env(?:[./~_-]|$)|"
        r"(?:^|/)\.(?:git|svn|hg|aws|ssh)(?:/|$)|"
        r"(?:^|/)(?:wp-admin|wp-login\.php|phpmyadmin)(?:/|$)|"
        r"(?:^|/)(?:credentials?|secrets?|config|settings?)(?:\.(?:json|ya?ml|ini|conf|php|py|js|bak|old|orig|save|zip|tar|gz)|/|$)|"
        r"(?:^|/)(?:docker-?compose|compose)(?:\.[^/]+)?$|"
        r"\.(?:bak|old|orig|save|swp|sql|sqlite|db)(?:$|[?#])",
        re.IGNORECASE,
    )
    context.namespace.update({
        '_HTTP_4XX_STATE_FILE': _HTTP_4XX_STATE_FILE,
        '_HTTP_4XX_LOCK_FILE': _HTTP_4XX_LOCK_FILE,
        '_HTTP_SECURITY_SETTINGS_FILE': _HTTP_SECURITY_SETTINGS_FILE,
        '_HTTP_SECURITY_SETTINGS_CACHE': _HTTP_SECURITY_SETTINGS_CACHE,
        '_HTTP_4XX_STATUSES': _HTTP_4XX_STATUSES,
        '_HTTP_SECURITY_DEFAULTS': _HTTP_SECURITY_DEFAULTS,
        '_HTTP_SECURITY_OFFENSE_RESET_SEC': _HTTP_SECURITY_OFFENSE_RESET_SEC,
        '_HTTP_SECURITY_HISTORY_LIMIT': _HTTP_SECURITY_HISTORY_LIMIT,
        '_HTTP_SECURITY_TEMP_ALLOW_MAX_SEC': _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC,
        '_HTTP_SECURITY_NFT_TABLE': _HTTP_SECURITY_NFT_TABLE,
        '_HTTP_SECURITY_NFT_V4_SET': _HTTP_SECURITY_NFT_V4_SET,
        '_HTTP_SECURITY_NFT_V6_SET': _HTTP_SECURITY_NFT_V6_SET,
        '_HTTP_SECURITY_CLEANUP_STARTED': _HTTP_SECURITY_CLEANUP_STARTED,
        '_HTTP_SECURITY_GEO_CACHE': _HTTP_SECURITY_GEO_CACHE,
        '_HTTP_SECURITY_GEO_CACHE_LOCK': _HTTP_SECURITY_GEO_CACHE_LOCK,
        '_HTTP_SECURITY_SENSITIVE_RE': _HTTP_SECURITY_SENSITIVE_RE,
    })
