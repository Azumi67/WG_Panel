def bind_load_node_notification_state(_panel_context):
    def _load_node_notification_state() -> dict:
        state = _panel_context._json_load(
            _panel_context._NODE_NOTIFY_MONITOR_STATE_FILE,
            {},
        )

        return (
            state
            if isinstance(state, dict)
            else {}
        )


    def _save_node_notification_state(
        state: dict,
    ) -> None:
        _panel_context._json_save(
            _panel_context._NODE_NOTIFY_MONITOR_STATE_FILE,
            state,
        )


    def _local_notification_states() -> dict:
        states = {}

        interfaces = (
            _panel_context.InterfaceConfig.query
            .filter(
                _panel_context.InterfaceConfig.node_id.is_(None)
            )
            .order_by(
                _panel_context.InterfaceConfig.id.asc()
            )
            .all()
        )

        for interface in interfaces:
            interface_name = (
                getattr(
                    interface,
                    'name',
                    None,
                )
                or ''
            ).strip()

            if not interface_name:
                continue

            try:
                is_up = (
                    _panel_context.subprocess.run(
                        [
                            'wg',
                            'show',
                            interface_name,
                        ],
                        stdout=_panel_context.subprocess.DEVNULL,
                        stderr=_panel_context.subprocess.DEVNULL,
                        timeout=4,
                        check=False,
                    ).returncode
                    == 0
                )
            except Exception:
                is_up = False

            states[interface_name] = {
                'is_up': bool(is_up),
                'address': (
                    getattr(
                        interface,
                        'address',
                        None,
                    )
                    or ''
                ),
                'listen_port': (
                    getattr(
                        interface,
                        'listen_port',
                        None,
                    )
                ),
            }

        return states


    def _check_local_notifications(
        state: dict,
    ) -> None:

        local_key = (
            '__local_interfaces__'
        )

        previous_interfaces = (
            state.get(
                local_key
            )
            or {}
        )

        current_interfaces = (
            _panel_context._local_notification_states()
        )

        next_interfaces = {}

        confirmation_checks = 2

        for interface_name, current in (
            current_interfaces.items()
        ):
            observed_up = bool(
                current.get(
                    'is_up'
                )
            )

            previous = (
                previous_interfaces.get(
                    interface_name
                )
            )

            if not isinstance(
                previous,
                dict,
            ):
                next_interfaces[
                    interface_name
                ] = {
                    'is_up': observed_up,
                    'pending_state': None,
                    'pending_checks': 0,
                    'address': (
                        current.get(
                            'address'
                        )
                        or ''
                    ),
                    'listen_port': (
                        current.get(
                            'listen_port'
                        )
                    ),
                }

                continue

            confirmed_up = bool(
                previous.get(
                    'is_up'
                )
            )

            pending_state = (
                previous.get(
                    'pending_state'
                )
            )

            try:
                pending_checks = int(
                    previous.get(
                        'pending_checks'
                    )
                    or 0
                )
            except Exception:
                pending_checks = 0

            if observed_up == confirmed_up:
                pending_state = None
                pending_checks = 0

            else:
                if (
                    pending_state
                    == observed_up
                ):
                    pending_checks += 1

                else:
                    pending_state = (
                        observed_up
                    )

                    pending_checks = 1

                if (
                    pending_checks
                    >= confirmation_checks
                ):
                    old_up = confirmed_up

                    confirmed_up = (
                        observed_up
                    )

                    pending_state = None
                    pending_checks = 0

                    if (
                        old_up
                        and not confirmed_up
                    ):
                        _panel_context._send_telegram_event(
                            'iface_down',
                            (
                                'WireGuard interface '
                                'went offline'
                            ),
                            status='Offline',
                            details=[
                                (
                                    'Location',
                                    'Local panel',
                                ),
                                (
                                    'Interface',
                                    interface_name,
                                ),
                                (
                                    'Address',
                                    current.get(
                                        'address'
                                    ),
                                ),
                                (
                                    'Listen port',
                                    current.get(
                                        'listen_port'
                                    ),
                                ),
                            ],
                            dedupe_key=(
                                'local-interface-down:'
                                f'{interface_name}'
                            ),
                            dedupe_seconds=300,
                        )

                    elif (
                        not old_up
                        and confirmed_up
                    ):
                        _panel_context._send_telegram_event(
                            'iface_up',
                            (
                                'WireGuard interface '
                                'came online'
                            ),
                            status='Online',
                            details=[
                                (
                                    'Location',
                                    'Local panel',
                                ),
                                (
                                    'Interface',
                                    interface_name,
                                ),
                                (
                                    'Address',
                                    current.get(
                                        'address'
                                    ),
                                ),
                                (
                                    'Listen port',
                                    current.get(
                                        'listen_port'
                                    ),
                                ),
                            ],
                            dedupe_key=(
                                'local-interface-up:'
                                f'{interface_name}'
                            ),
                            dedupe_seconds=120,
                        )

            next_interfaces[
                interface_name
            ] = {
                'is_up': confirmed_up,
                'pending_state': (
                    pending_state
                ),
                'pending_checks': (
                    pending_checks
                ),
                'address': (
                    current.get(
                        'address'
                    )
                    or ''
                ),
                'listen_port': (
                    current.get(
                        'listen_port'
                    )
                ),
            }

        state[
            local_key
        ] = next_interfaces


    def _check_node_notifications(
        state: dict,
    ) -> None:
        current_epoch = int(
            _panel_context.time.time()
        )

        nodes = (
            _panel_context.Node.query
            .order_by(
                _panel_context.Node.id.asc()
            )
            .all()
        )

        for node in nodes:
            state_key = (f'node:{node.id}')

            if not node.enabled:
                state.pop(state_key,None,)
                continue

            previous = (
                state.get(state_key)
                or {}
            )

            previous_online = (
                previous.get('online')
            )

            previous_interfaces = (
                previous.get('interfaces')
                or {}
            )

            failed_checks = int(
                previous.get('failed_checks')
                or 0
            )

            health = {}
            interfaces = []
            online_now = False
            error_text = ''

            if node.enabled:
                try:
                    health = (
                        _panel_context.node_get(
                            node,
                            '/api/health',
                            timeout=6,
                        )
                        or {}
                    )

                    online_now = bool(
                        isinstance(health, dict)
                        and health.get(
                            'ok',
                            True,
                        )
                    )

                    if online_now:

                        if isinstance(health,dict,):
                            health_interfaces = (health.get("interfaces"))

                            if isinstance(health_interfaces,list,):
                                interfaces = (health_interfaces)


                        if not interfaces:
                            try:
                                interface_response = (_panel_context.node_get(node,"/api/interfaces?fast=1",timeout=10,)or {})
                                if isinstance(interface_response,dict,):
                                    fallback_interfaces = (interface_response.get("interfaces")or [])

                                if isinstance(fallback_interfaces,list,):
                                    interfaces = (fallback_interfaces)

                            except Exception as exc:
                                _panel_context.app.logger.debug(
                                    "Could not load fallback interface "
                                    "state for node %s: %s",
                                    node.id,
                                    exc,
                                )

                except Exception as exc:
                    online_now = False
                    error_text = str(exc)

            if online_now:
                failed_checks = 0
                confirmed_online = True
            else:
                failed_checks += 1

                confirmed_online = (
                    failed_checks < 2
                )

            first_observation = (
                previous_online is None
            )

            if first_observation:
                previous_online = (
                    confirmed_online
                )

            if (
                not first_observation
                and previous_online
                and not confirmed_online
            ):
                _panel_context._send_telegram_event(
                    'node_down',
                    '● Node went offline',
                    status='Offline',
                    details=[
                        ('Node', node.name),
                        (
                            'Address',
                            node.base_url,
                        ),
                        (
                            'Failed checks',
                            failed_checks,
                        ),
                        (
                            'Error',
                            error_text[:240],
                        ),
                    ],
                    dedupe_key=(
                        f'node-down:{node.id}'
                    ),
                    dedupe_seconds=300,
                )

            elif (
                not first_observation
                and not previous_online
                and confirmed_online
            ):
                offline_since = int(
                    previous.get(
                        'offline_since'
                    )
                    or current_epoch
                )

                outage_seconds = max(
                    0,
                    current_epoch
                    - offline_since,
                )

                _panel_context._send_telegram_event(
                    'node_up',
                    '● Node came online',
                    status='Recovered',
                    details=[
                        ('Node', node.name),
                        (
                            'Address',
                            node.base_url,
                        ),
                        (
                        'Outage',_panel_context._tg_human_duration(outage_seconds),),
                        (
                            'Remote host',
                            (
                                health.get('host')
                                if isinstance(
                                    health,
                                    dict,
                                )
                                else ''
                            ),
                        ),
                        (
                            'Public IP',
                            (
                                health.get(
                                    'public_ipv4'
                                )
                                if isinstance(
                                    health,
                                    dict,
                                )
                                else ''
                            ),
                        ),
                    ],
                    dedupe_key=(
                        f'node-up:{node.id}'
                    ),
                    dedupe_seconds=60,
                )

            current_interfaces = {}

            if confirmed_online:
                for interface in interfaces:
                    if not isinstance(
                        interface,
                        dict,
                    ):
                        continue

                    interface_name = str(
                        interface.get('name')
                        or ''
                    ).strip()

                    if not interface_name:
                        continue

                    is_up = bool(
                        interface.get('is_up')
                    )

                    current_interfaces[
                        interface_name
                    ] = {
                        'is_up': is_up,
                        'address': (
                            interface.get('address')
                            or ''
                        ),
                        'listen_port': (
                            interface.get(
                                'listen_port'
                            )
                        ),
                    }

                    old_interface = (
                        previous_interfaces.get(
                            interface_name
                        )
                    )

                    if not isinstance(
                        old_interface,
                        dict,
                    ):
                        continue

                    old_up = bool(
                        old_interface.get(
                            'is_up'
                        )
                    )

                    if old_up and not is_up:
                        _panel_context._send_telegram_event(
                            'iface_down',
                            '● WireGuard interface went down',
                            status='Down',
                            details=[
                                ('Node', node.name),
                                (
                                    'Interface',
                                    interface_name,
                                ),
                                (
                                    'Address',
                                    interface.get(
                                        'address'
                                    ),
                                ),
                                (
                                    'Listen port',
                                    interface.get(
                                        'listen_port'
                                    ),
                                ),
                            ],
                            dedupe_key=(
                                f'node-interface-down:'
                                f'{node.id}:'
                                f'{interface_name}'
                            ),
                            dedupe_seconds=180,
                        )

                    elif not old_up and is_up:
                        _panel_context._send_telegram_event(
                            'iface_up',
                            '● WireGuard interface came up',
                            status='Up',
                            details=[
                                ('Node', node.name),
                                (
                                    'Interface',
                                    interface_name,
                                ),
                                (
                                    'Address',
                                    interface.get(
                                        'address'
                                    ),
                                ),
                                (
                                    'Listen port',
                                    interface.get(
                                        'listen_port'
                                    ),
                                ),
                            ],
                            dedupe_key=(
                                f'node-interface-up:'
                                f'{node.id}:'
                                f'{interface_name}'
                            ),
                            dedupe_seconds=60,
                        )

            if confirmed_online:
                offline_since = 0
            else:
                offline_since = int(
                    previous.get(
                        'offline_since'
                    )
                    or current_epoch
                )

            state[state_key] = {
                'online': bool(
                    confirmed_online
                ),
                'failed_checks': (
                    failed_checks
                ),
                'offline_since': (
                    offline_since
                ),
                'interfaces': (
                    current_interfaces
                    if confirmed_online
                    else previous_interfaces
                ),
                'checked_at': (
                    current_epoch
                ),
            }


    def _check_update_notifications(
        state: dict,
    ) -> None:
        update_state_key = (
            '__update_notifications__'
        )

        previous = (
            state.get(update_state_key)
            or {}
        )

        current = {}


        try:
            panel_status = (
                _panel_context._read_update_status(
                    _panel_context.UPDATE_STATUS_FILE
                )
                or {}
            )
        except Exception:
            panel_status = {}

        panel_state = str(
            panel_status.get('status')
            or ''
        ).strip().lower()

        panel_stage = str(
            panel_status.get('stage')
            or ''
        ).strip().lower()

        panel_identity = (
            panel_status.get('target')
            or panel_status.get('revision')
            or panel_status.get('message')
            or panel_state
        )

        current['panel'] = {
            'status': panel_state,
            'stage': panel_stage,
            'identity': str(
                panel_identity or ''
            ),
        }

        previous_panel = (
            previous.get('panel')
            or {}
        )

        previous_panel_state = str(
            previous_panel.get('status')
            or ''
        ).strip().lower()

        if (
            previous_panel_state
            and previous_panel_state
            != panel_state
        ):
            if panel_state in {
                'success',
                'succeeded',
                'complete',
                'completed',
                'done',
            }:
                _panel_context._send_telegram_event(
                    'update_success',
                    '● Panel update completed',
                    status='Completed',
                    details=[
                        (
                            'Target',
                            panel_status.get(
                                'target'
                            ),
                        ),
                        (
                            'Message',
                            panel_status.get(
                                'message'
                            ),
                        ),
                    ],
                    dedupe_key=(
                        'panel-update-success:'
                        + str(panel_identity)
                    ),
                    dedupe_seconds=0,
                )

            elif panel_state in {
                'failed',
                'error',
                'rollback_failed',
            }:
                _panel_context._send_telegram_event(
                    'update_failed',
                    '● Panel update or rollback failed',
                    status='Failed',
                    details=[
                        ('Stage', panel_stage),
                        (
                            'Message',
                            panel_status.get(
                                'message'
                            ),
                        ),
                        (
                            'Error',
                            panel_status.get(
                                'detail'
                            )
                            or panel_status.get(
                                'error'
                            ),
                        ),
                    ],
                    dedupe_key=(
                        'panel-update-failed:'
                        + str(panel_identity)
                    ),
                    dedupe_seconds=300,
                )


        for node in (
            _panel_context.Node.query
            .filter_by(enabled=True)
            .order_by(_panel_context.Node.id.asc())
            .all()
        ):
            node_key = (
                f'node:{node.id}'
            )

            try:
                node_status = (
                    _panel_context.node_get(
                        node,
                        '/api/system/update/status',
                        timeout=7,
                    )
                    or {}
                )
            except Exception:
                continue

            node_state = str(
                node_status.get('status')
                or ''
            ).strip().lower()

            node_stage = str(
                node_status.get('stage')
                or ''
            ).strip().lower()

            node_identity = (
                node_status.get('target')
                or node_status.get('revision')
                or node_status.get('message')
                or node_state
            )

            current[node_key] = {
                'status': node_state,
                'stage': node_stage,
                'identity': str(
                    node_identity or ''
                ),
            }

            old_node = (
                previous.get(node_key)
                or {}
            )

            old_node_state = str(
                old_node.get('status')
                or ''
            ).strip().lower()

            if (
                not old_node_state
                or old_node_state
                == node_state
            ):
                continue

            if node_state in {
                'success',
                'succeeded',
                'complete',
                'completed',
                'done',
            }:
                _panel_context._send_telegram_event(
                    'update_success',
                    '● Node update completed',
                    status='Completed',
                    details=[
                        ('Node', node.name),
                        (
                            'Target',
                            node_status.get(
                                'target'
                            ),
                        ),
                        (
                            'Message',
                            node_status.get(
                                'message'
                            ),
                        ),
                    ],
                    dedupe_key=(
                        f'node-update-success:'
                        f'{node.id}:'
                        f'{node_identity}'
                    ),
                    dedupe_seconds=0,
                )

            elif node_state in {
                'failed',
                'error',
                'rollback_failed',
            }:
                _panel_context._send_telegram_event(
                    'update_failed',
                    '● Node update or rollback failed',
                    status='Failed',
                    details=[
                        ('Node', node.name),
                        ('Stage', node_stage),
                        (
                            'Message',
                            node_status.get(
                                'message'
                            ),
                        ),
                        (
                            'Error',
                            node_status.get(
                                'detail'
                            )
                            or node_status.get(
                                'error'
                            ),
                        ),
                    ],
                    dedupe_key=(
                        f'node-update-failed:'
                        f'{node.id}:'
                        f'{node_identity}'
                    ),
                    dedupe_seconds=300,
                )

        state[update_state_key] = current


    def _node_monitor_once() -> None:
        state = (
            _panel_context._load_node_notification_state()
        )

        _panel_context._check_local_notifications(
            state
        )

        _panel_context._check_node_notifications(
            state
        )

        _panel_context._check_update_notifications(
            state
        )

        _panel_context._save_node_notification_state(
            state
        )


    def _node_monitor_loop() -> None:
        lock_handle = None

        try:
            lock_handle = open(
                _panel_context._NODE_NOTIFY_MONITOR_LOCK_FILE,
                'a+',
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
                    _panel_context._node_monitor_once()

            except Exception:
                _panel_context.app.logger.exception(
                    'Node notification monitor failed'
                )

            _panel_context.time.sleep(
                _panel_context._NODE_NOTIFY_INTERVAL_SEC
            )


    def _node_notify_monitor() -> None:
        pass

        with _panel_context._NODE_NOTIFY_MONITOR_THREAD_LOCK:
            if _panel_context._NODE_NOTIFY_MONITOR_STARTED:
                return

            _panel_context._NODE_NOTIFY_MONITOR_STARTED = True

            monitor_thread = _panel_context.threading.Thread(
                target=(
                    _panel_context._node_monitor_loop
                ),
                name='node-notification-monitor',
                daemon=True,
            )

            monitor_thread.start()

    return {
        '_load_node_notification_state': _load_node_notification_state,
        '_save_node_notification_state': _save_node_notification_state,
        '_local_notification_states': _local_notification_states,
        '_check_local_notifications': _check_local_notifications,
        '_check_node_notifications': _check_node_notifications,
        '_check_update_notifications': _check_update_notifications,
        '_node_monitor_once': _node_monitor_once,
        '_node_monitor_loop': _node_monitor_loop,
        '_node_notify_monitor': _node_notify_monitor,
    }


def initialize_state(context):
    os = context.os
    app = context.app
    threading = context.threading
    _NODE_NOTIFY_MONITOR_STARTED = False
    _NODE_NOTIFY_MONITOR_THREAD_LOCK = threading.Lock()

    _NODE_NOTIFY_MONITOR_STATE_FILE = os.path.join(
        app.instance_path,
        'node_notification_state.json',
    )

    _NODE_NOTIFY_MONITOR_LOCK_FILE = os.path.join(
        app.instance_path,
        'node_notification_monitor.lock',
    )

    try:
        _NODE_NOTIFY_INTERVAL_SEC = max(
            15,
            int(
                os.getenv(
                    'WG_NODE_NOTIFY_INTERVAL_SEC',
                    '30',
                )
            ),
        )
    except Exception:
        _NODE_NOTIFY_INTERVAL_SEC = 30
    context.namespace.update({
        '_NODE_NOTIFY_MONITOR_STARTED': _NODE_NOTIFY_MONITOR_STARTED,
        '_NODE_NOTIFY_MONITOR_THREAD_LOCK': _NODE_NOTIFY_MONITOR_THREAD_LOCK,
        '_NODE_NOTIFY_MONITOR_STATE_FILE': _NODE_NOTIFY_MONITOR_STATE_FILE,
        '_NODE_NOTIFY_MONITOR_LOCK_FILE': _NODE_NOTIFY_MONITOR_LOCK_FILE,
        '_NODE_NOTIFY_INTERVAL_SEC': _NODE_NOTIFY_INTERVAL_SEC,
    })
