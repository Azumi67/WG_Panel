def build_routes(*,
    InterfaceConfig,
    Peer,
    current_app,
    db,
    jsonify,
    login_required,
    now_ts,
    psutil,
    re,
    render_template,
    require_api_key,
    require_api_key_or_login,
    subprocess,
    text,
    time,
):

    @require_api_key_or_login
    def healthz():
        try:
            db.session.execute(text('SELECT 1'))
            db.session.rollback()
        except Exception:
            db.session.rollback()
            return jsonify(ok=False, error='database_unavailable'), 503
        return jsonify(ok=True, ts=now_ts()), 200

    @login_required
    def api_docs_page():
        return render_template('api_docs.html')

    @login_required
    def index():
        return render_template('index.html')

    @require_api_key
    def stats_mini():
        try:
            cpu = round(
                psutil.cpu_percent(
                    interval=0.2,
                )
                or 0.0,
                1,
            )

            mem = round(
                psutil.virtual_memory().percent
                or 0.0,
                1,
            )

            disk = round(
                psutil.disk_usage('/').percent
                or 0.0,
                1,
            )

            uptime_secs = max(
                0,
                int(
                    time.time()
                    - psutil.boot_time()
                ),
            )

            if uptime_secs >= 48 * 3600:
                days = (
                    uptime_secs
                    // 86400
                )

                hours = (
                    uptime_secs
                    % 86400
                ) // 3600

                uptime_value = int(days)
                uptime_unit = 'd'

                uptime_str = (
                    f'{days}d'
                    + (
                        f' {hours}h'
                        if hours
                        else ''
                    )
                )

            else:
                hours = (
                    uptime_secs
                    // 3600
                )

                uptime_value = int(hours)
                uptime_unit = 'h'
                uptime_str = f'{hours}h'

            active_within_seconds = 180
            now_epoch = int(
                time.time()
            )

            handshake_map = {}

            try:
                process = subprocess.run(
                    [
                        'wg',
                        'show',
                        'all',
                        'latest-handshakes',
                    ],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )

                if process.returncode == 0:
                    for raw_line in (
                        process.stdout
                        or ''
                    ).splitlines():

                        parts = (
                            raw_line.split()
                        )

                        if len(parts) < 3:
                            continue

                        iface_name = parts[0]
                        public_key = parts[1]
                        raw_timestamp = parts[2]

                        try:
                            timestamp = int(
                                raw_timestamp
                                or 0
                            )

                        except Exception:
                            timestamp = 0

                        handshake_map[
                            (
                                iface_name,
                                public_key,
                            )
                        ] = timestamp

            except Exception:
                handshake_map = {}

            activity = {
                'active': 0,
                'idle': 0,
                'blocked': 0,
                'total': 0,
            }

            rows = (
                db.session.query(
                    Peer.status,
                    Peer.public_key,
                    InterfaceConfig.name,
                )
                .join(
                    InterfaceConfig,
                    Peer.iface_id
                    == InterfaceConfig.id,
                )
                .all()
            )

            for (
                stored_status,
                public_key,
                iface_name,
            ) in rows:

                activity['total'] += 1

                stored_status = str(
                    stored_status
                    or ''
                ).lower()

                iface_name = str(
                    iface_name
                    or ''
                )

                if stored_status == 'blocked':
                    activity['blocked'] += 1
                    continue

                is_node = bool(
                    re.match(
                        r'^n\d+:',
                        iface_name,
                    )
                )

                if is_node:
                    if stored_status == 'online':
                        activity['active'] += 1

                    else:
                        activity['idle'] += 1

                    continue

                device_name = (
                    iface_name
                    .split(':')[-1]
                )

                handshake = int(
                    handshake_map.get(
                        (
                            device_name,
                            public_key,
                        )
                    )
                    or handshake_map.get(
                        (
                            iface_name,
                            public_key,
                        )
                    )
                    or 0
                )

                if (
                    handshake
                    and now_epoch - handshake
                    <= active_within_seconds
                ):
                    activity['active'] += 1

                else:
                    activity['idle'] += 1

            counts = {
                'active': activity['active'],
                'idle': activity['idle'],
                'blocked': activity['blocked'],
                'total': activity['total'],
                'activity_window_seconds': (
                    active_within_seconds
                ),

                'online': activity['active'],
                'offline': activity['idle'],
            }

            return jsonify({
                'cpu': cpu,
                'mem': mem,
                'disk': disk,
                'uptime_value': uptime_value,
                'uptime_unit': uptime_unit,
                'uptime_str': uptime_str,
                'counts': counts,
            }), 200

        except Exception:
            current_app.logger.exception(
                'Mini stats failed'
            )

            return jsonify(
                error='stats_unavailable',
            ), 503

    return {
        'healthz': healthz,
        'api_docs_page': api_docs_page,
        'index': index,
        'stats_mini': stats_mini,
    }
