def bind_disable_peer(_panel_context):
    def _disable_peer(peer, reason: str, status: str = 'offline', *, commit=True):
        try:
            nid = getattr(peer.iface, 'node_id', None)
            if nid is not None:
                n = _panel_context.db.session.get(_panel_context.Node, nid)
                payload = {}
                try:
                    payload['host_cidr'] = _panel_context._host_peer(peer)
                except Exception:
                    pass
                response = _panel_context.node_post(n, f'/api/peer/{peer.public_key}/disable', payload)
                if not isinstance(response, dict) or response.get('ok') is False:
                    raise RuntimeError('Node did not confirm peer disable.')
            else:
                _panel_context._wg_disable(peer)
            previous_status = peer.status
            peer.status = status
            if not (reason.startswith('reseller_') and previous_status == status):
                _panel_context.log_event(peer, reason, f'status → {status}', commit=commit)
            return True
        except Exception:
            _panel_context.current_app.logger.exception("Disable failed for peer %s", getattr(peer, 'id', '?'))
            return False


    def _expire():
        return _panel_context._run_expiry_once('manual')


    def _expire_without_autoflush(interface_ids=None):
        from reseller_portal.models import Setting as ResellerSetting
        recovery_pending={int(row.key.split(':',1)[1]) for row in ResellerSetting.query.filter(ResellerSetting.key.like('recovery_pending:%')).all() if row.value is True}
        now = _panel_context.now_ts()
        changed = False


        pending_notifications = []
        subscription_by_peer = {}
        subscriptions_by_id = {}
        try:
            links = _panel_context.SubscriptionPeer.query
            if interface_ids is not None:
                links = links.join(_panel_context.Peer, _panel_context.Peer.id == _panel_context.SubscriptionPeer.peer_id).filter(_panel_context.Peer.iface_id.in_(interface_ids))
            for link in links.all():
                sub = getattr(link, 'subscription', None)
                if sub is None:
                    sub = _panel_context.db.session.get(_panel_context.Subscription, link.subscription_id)
                if sub is None:
                    continue
                subscription_by_peer[int(link.peer_id)] = sub
                subscriptions_by_id[int(sub.id)] = sub
        except Exception:
            _panel_context.current_app.logger.exception('Could not build subscription lifecycle map')
            raise

        from sqlalchemy.orm import joinedload
        peer_query = _panel_context.Peer.query.options(joinedload(_panel_context.Peer.iface))
        if interface_ids is not None:
            peer_query = peer_query.filter(_panel_context.Peer.iface_id.in_(interface_ids))
        peers = peer_query.all()
        failed_interfaces = set()
        local_names = {p.iface.name for p in peers if p.id not in recovery_pending and p.iface and not p.iface.node_id}
        transfers, handshakes = _panel_context._wg_runtime_snapshot(local_names, failures=failed_interfaces)
        for peer in peers:
            if peer.id in recovery_pending:continue

            linked_subscription = subscription_by_peer.get(int(peer.id))
            should_track_first_use = True

            if (
                should_track_first_use
                and not getattr(
                    peer,
                    'first_used_at',
                    None,
                )
            ):
                hs = handshakes.get((peer.iface.name, peer.public_key), 0) if peer.iface else 0

                if hs and hs > 0:
                    peer.first_used_at = _panel_context.from_ts(hs)

                    if linked_subscription is not None:
                        existing_sub_first = _panel_context.to_ts(getattr(linked_subscription, 'first_used_at', None))
                        if not existing_sub_first or hs < existing_sub_first:
                            linked_subscription.first_used_at = _panel_context.from_ts(hs)
                        _panel_context._apply_subscription_timer(linked_subscription)
                        _panel_context._sync_all_subscription_peers(linked_subscription, rename=False)
                    else:
                        if getattr(peer, 'start_on_first_use', False):
                            peer.timer_started_at = _panel_context.from_ts(hs)

                        if (
                            getattr(
                                peer,
                                'start_on_first_use',
                                False,
                            )
                            and getattr(
                                peer,
                                'time_limit_days',
                                None,
                            )
                            and not getattr(
                                peer,
                                'unlimited',
                                False,
                            )
                        ):
                            first_use_expiry_ts = _panel_context.add_days_ts(
                                hs,
                                float(peer.time_limit_days),
                            )
                            peer.expires_at = _panel_context.from_ts(first_use_expiry_ts)

                    _panel_context.log_event(
                        peer,
                        'first_use',
                        (
                            'First WireGuard '
                            'handshake recorded'
                        ),
                        commit=False,
                    )

                    changed = True

            if (
                linked_subscription is None
                and not getattr(
                    peer,
                    'start_on_first_use',
                    False,
                )
                and getattr(
                    peer,
                    'time_limit_days',
                    None,
                )
                and not getattr(
                    peer,
                    'expires_at',
                    None,
                )
                and not getattr(
                    peer,
                    'unlimited',
                    False,
                )
            ):
                if not getattr(peer, 'timer_started_at', None):
                    peer.timer_started_at = (
                        getattr(peer, 'created_at', None)
                        or _panel_context.from_ts(now)
                    )
                _panel_context._sync_effective_expiry(peer)

                changed = True

            interface = getattr(
                peer,
                'iface',
                None,
            )

            is_node = bool(
                getattr(
                    interface,
                    'node_id',
                    None,
                )
                is not None
            )

            total_bytes = None

            if not is_node and interface and interface.name not in failed_interfaces:
                total_bytes = sum(transfers.get((interface.name, peer.public_key), (0, 0)))

                (
                    used_effective,
                    _delta,
                    usage_changed,
                ) = _panel_context._accumulate_peer_usage(
                    peer,
                    total_bytes,
                )

                if usage_changed:
                    changed = True

            else:
                used_effective = int(
                    getattr(
                        peer,
                        'used_bytes_total',
                        0,
                    )
                    or 0
                )

            if linked_subscription is not None:
                continue


            expiry_ts = _panel_context._effective_expiry_ts(peer)
            if _panel_context.to_ts(getattr(peer, 'expires_at', None)) != expiry_ts:
                peer.expires_at = _panel_context.from_ts(expiry_ts)
                changed = True

            if (
                expiry_ts
                and now >= expiry_ts
                and peer.status != 'blocked'
            ):
                disabled = _panel_context._disable_peer(
                    peer,
                    'expired',
                    status='blocked',
                    commit=False,
                )

                if disabled:
                    peer_name = (
                        getattr(
                            peer,
                            'name',
                            None,
                        )
                        or getattr(
                            peer,
                            'friendly_name',
                            None,
                        )
                        or f'Peer {peer.id}'
                    )

                    interface_name = (
                        getattr(
                            interface,
                            'name',
                            None,
                        )
                        or ''
                    )

                    node_name = ''

                    if is_node:
                        node = getattr(
                            interface,
                            'node',
                            None,
                        )

                        node_name = (
                            getattr(
                                node,
                                'name',
                                None,
                            )
                            or ''
                        )

                    pending_notifications.append({
                    'event_key': 'peer_expired',
                    'title': 'Peer expired',
                    'status': 'Disabled',

                    'details': [('Peer',f'{peer_name} · ID {peer.id}',),
                    ('Location',node_name or 'Local panel',),
                    ('Interface',interface_name,),
                    ('Address',getattr(peer,'address','',) or '',),
                    ('Phone',getattr(peer,'phone_number','',) or '',),
                    ('Telegram',getattr(peer,'telegram_id','',) or '',),
                    ('Active since',_panel_context._tg_human_datetime(getattr(peer,'first_used_at',None,)),),
                    ('Expired at',_panel_context._tg_human_datetime(_panel_context.from_ts(expiry_ts)),),],

                    'dedupe_key': (f'peer-expired:{peer.id}'),
                    'dedupe_seconds': 0,})

                changed = True


            limit_bytes = (
                peer.limit_bytes()
                if hasattr(
                    peer,
                    'limit_bytes',
                )
                else None
            )

            if (
                limit_bytes is not None
                and peer.status != 'blocked'
                and used_effective >= limit_bytes
            ):
                if total_bytes is not None:
                    _panel_context._accumulate_peer_usage(
                        peer,
                        total_bytes,
                    )

                disabled = _panel_context._disable_peer(
                    peer,
                    'limit_reached',
                    status='blocked',
                    commit=False,
                )

                if disabled:
                    peer_name = (
                        getattr(
                            peer,
                            'name',
                            None,
                        )
                        or getattr(
                            peer,
                            'friendly_name',
                            None,
                        )
                        or f'Peer {peer.id}'
                    )

                    interface_name = (
                        getattr(
                            interface,
                            'name',
                            None,
                        )
                        or ''
                    )

                    node_name = ''

                    if is_node:
                        node = getattr(
                            interface,
                            'node',
                            None,
                        )

                        node_name = (
                            getattr(
                                node,
                                'name',
                                None,
                            )
                            or ''
                        )

                    pending_notifications.append({
                    'event_key': 'peer_limit',
                    'title': 'Peer traffic limit reached',
                    'status': 'Disabled',

                    'details': [('Peer',f'{peer_name} · ID {peer.id}',),
                    ('Location',node_name or 'Local panel',),
                    ('Interface',interface_name,),
                    ('Address',getattr(peer,'address','',) or '',),
                    ('Phone',getattr(peer,'phone_number','',) or '',),
                    ('Telegram',getattr(peer,'telegram_id','',) or '',),
                    ('Usage',_panel_context._tg_human_bytes(used_effective),),
                    ('Data limit',_panel_context._tg_human_bytes(limit_bytes),),
                    ('Active since',_panel_context._tg_human_datetime(getattr(peer,'first_used_at',None,)),),],

                    'dedupe_key': (f'peer-limit:{peer.id}'),
                    'dedupe_seconds': 0,})
                changed = True

        for sub in subscriptions_by_id.values():
            try:
                before = (
                    _panel_context.to_ts(getattr(sub, 'first_used_at', None)),
                    _panel_context.to_ts(getattr(sub, 'timer_started_at', None)),
                    _panel_context.to_ts(getattr(sub, 'expires_at', None)),
                    tuple(
                        (
                            int(getattr(link.peer, 'id', 0) or 0),
                            _panel_context.to_ts(getattr(link.peer, 'first_used_at', None)),
                            _panel_context.to_ts(getattr(link.peer, 'timer_started_at', None)),
                            _panel_context.to_ts(getattr(link.peer, 'expires_at', None)),
                        )
                        for link in (getattr(sub, 'links', []) or [])
                        if getattr(link, 'peer', None) is not None
                    ),
                )
                _panel_context._apply_subscription_timer(sub)
                _panel_context._sync_all_subscription_peers(sub, rename=False)
                after = (
                    _panel_context.to_ts(getattr(sub, 'first_used_at', None)),
                    _panel_context.to_ts(getattr(sub, 'timer_started_at', None)),
                    _panel_context.to_ts(getattr(sub, 'expires_at', None)),
                    tuple(
                        (
                            int(getattr(link.peer, 'id', 0) or 0),
                            _panel_context.to_ts(getattr(link.peer, 'first_used_at', None)),
                            _panel_context.to_ts(getattr(link.peer, 'timer_started_at', None)),
                            _panel_context.to_ts(getattr(link.peer, 'expires_at', None)),
                        )
                        for link in (getattr(sub, 'links', []) or [])
                        if getattr(link, 'peer', None) is not None
                    ),
                )
                if before != after:
                    changed = True
                used = sum(int(getattr(link.peer, 'used_bytes_total', 0) or 0)
                           for link in sub.links if link.peer is not None)
                access = _panel_context.subscription_access(sub, used_bytes=used)
                if not access.get('allowed'):
                    if _panel_context._block_subscription_runtime(
                        sub,
                        'subscription_' + str(access.get('reason') or 'blocked'),
                        recovery_pending=recovery_pending,
                        commit=False,
                    ):
                        changed = True
            except Exception:
                _panel_context.current_app.logger.exception(
                    'Subscription lifecycle enforcement failed for subscription %s',
                    getattr(sub, 'id', '?'),
                )

        return pending_notifications


    def _send_expiry_notifications(notifications):
        for notification in notifications or ():
            try:
                _panel_context._send_telegram_event(
                    notification['event_key'],
                    notification['title'],
                    status=notification.get(
                        'status',
                        '',
                    ),
                    details=notification.get(
                        'details',
                        [],
                    ),
                    dedupe_key=notification.get(
                        'dedupe_key',
                        '',
                    ),
                    dedupe_seconds=int(
                        notification.get(
                            'dedupe_seconds',
                            60,
                        )
                    ),
                )

            except Exception:
                _panel_context.app.logger.exception(
                    'Could not queue Telegram peer '
                    'enforcement notification: %s',
                    notification.get(
                        'event_key',
                    ),
                )

    return {
        '_disable_peer': _disable_peer,
        '_expire': _expire,
        '_expire_without_autoflush': _expire_without_autoflush,
        '_send_expiry_notifications': _send_expiry_notifications,
    }


def bind_expiry_membership_rows(_panel_context):
    def _expiry_membership_rows():
        return _panel_context.db.session.query(_panel_context.SubscriptionPeer.subscription_id, _panel_context.Peer.iface_id).join(
            _panel_context.Peer, _panel_context.Peer.id == _panel_context.SubscriptionPeer.peer_id).all()


    def _run_expiry_once(source: str = 'manual') -> bool:
        pass
        if not _panel_context._EXPIRY_LOCK.acquire(blocking=False):
            return False
        try:
            from reseller_portal import service as reseller_service
            from reseller_portal.network_locks import NetworkLockTimeout, postgres_network_operation
            from reseller_portal.expiry_scope import interface_groups, scope_is_closed
            ids = [i for i, in _panel_context.db.session.query(_panel_context.Peer.iface_id).distinct().all()]
            if not ids:
                return True
            scoped = _panel_context.db.engine.dialect.name == 'postgresql'
            groups = interface_groups(ids, _panel_context._expiry_membership_rows()) if scoped else [None]
            _panel_context.db.session.rollback()
            deferred = []
            pending_notifications = []
            failed = False
            for group in groups:
                started = _panel_context.time.monotonic()
                try:
                    if group is None:
                        with reseller_service.locked(wait_seconds=5), _panel_context.db.session.no_autoflush:
                            acquired = _panel_context.time.monotonic()
                            notifications = _panel_context._expire_without_autoflush()
                    else:
                        with postgres_network_operation(_panel_context.db.engine, interface_ids=group, wait_seconds=2), _panel_context.db.session.no_autoflush:
                            acquired = _panel_context.time.monotonic()
                            if not scope_is_closed(group, _panel_context._expiry_membership_rows()):
                                _panel_context.db.session.rollback()
                                deferred.append(group)
                                continue
                            notifications = _panel_context._expire_without_autoflush(group)
                            _panel_context.db.session.commit()
                    finished = _panel_context.time.monotonic()
                    if finished - acquired >= 5:
                        _panel_context.app.logger.warning('Expiry sweep timing source=%s interfaces=%s lock_wait_ms=%.0f sweep_commit_ms=%.0f',
                                           source, group, 1000 * (acquired-started), 1000 * (finished-acquired))
                    pending_notifications.extend(notifications)
                except (NetworkLockTimeout, reseller_service.WorkspaceLockTimeout):
                    _panel_context.db.session.rollback()
                    deferred.append(group)
                except Exception:
                    _panel_context.db.session.rollback()
                    failed = True
                    _panel_context.app.logger.exception('Expiry enforcement failed source=%s interfaces=%s', source, group)
                finally:
                    _panel_context.db.session.rollback()
            finished = _panel_context.time.monotonic()
            if deferred:
                if _panel_context._EXPIRY_DEFERRED_SINCE is None:
                    _panel_context._EXPIRY_DEFERRED_SINCE = finished
                _panel_context._EXPIRY_DEFERRED_ATTEMPTS += 1
                if finished - _panel_context._EXPIRY_LAST_CONTENTION_WARNING >= 60:
                    _panel_context._EXPIRY_LAST_CONTENTION_WARNING = finished
                    _panel_context.app.logger.warning('Expiry enforcement deferred for interface groups=%s; other groups were processed. '
                                       'Retry next interval (deferred_attempts=%s elapsed_s=%.1f).',
                                       deferred, _panel_context._EXPIRY_DEFERRED_ATTEMPTS, finished-_panel_context._EXPIRY_DEFERRED_SINCE)
            elif not failed and _panel_context._EXPIRY_DEFERRED_SINCE is not None:
                _panel_context.app.logger.info('Expiry network lock recovered after %.1fs and %s deferred attempts.',
                                finished-_panel_context._EXPIRY_DEFERRED_SINCE, _panel_context._EXPIRY_DEFERRED_ATTEMPTS)
                _panel_context._EXPIRY_DEFERRED_SINCE = None
                _panel_context._EXPIRY_DEFERRED_ATTEMPTS = 0
                _panel_context._EXPIRY_LAST_CONTENTION_WARNING = 0.0
            _panel_context._send_expiry_notifications(pending_notifications)
            return not deferred and not failed
        except Exception:
            _panel_context.db.session.rollback()
            _panel_context.app.logger.exception('Expiry enforcement failed (%s)', source)
            return False
        finally:
            _panel_context._EXPIRY_LOCK.release()


    def _expiry_enforcer_loop():

        import fcntl
        path=_panel_context.os.path.join(_panel_context.app.instance_path,'panel-expiry-leader.lock')
        with open(path,'a') as leader:
            while True:
                try:fcntl.flock(leader,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:_panel_context.time.sleep(5)
            _panel_context._expiry_leader_loop()


    def _expiry_leader_loop():
        while True:
            try:
                with _panel_context.app.app_context():
                    _panel_context._run_expiry_once('background')
            except Exception as exc:
                _panel_context.app.logger.warning('Expiry loop failed (%s)', type(exc).__name__)

            _panel_context.time.sleep(_panel_context._EXPIRY_INTERVAL_SEC)


    def _start_expiry_enforcer():
        pass

        if _panel_context.os.environ.get('WG_BACKGROUND_ROLE') in ('reseller-worker','maintenance'):return
        if _panel_context._EXPIRY_THREAD_STARTED:
            return

        _panel_context._EXPIRY_THREAD_STARTED = True

        t = _panel_context.threading.Thread(
            target=_panel_context._expiry_enforcer_loop,
            name='peer-expiry-enforcer',
            daemon=True,
        )
        t.start()


    def _expiry_tick_on_requests():
        return None


    def _on_boot():
        for peer in _panel_context.Peer.query.all():
            try:
                if (peer.iface and
                    (getattr(peer.iface, 'node_id', None) is not None or
                     ':' in (peer.iface.name or ''))):
                    continue

                if peer.status in ('offline', 'blocked'):
                    _panel_context._wg_disable(peer)
                else:
                    _panel_context._wg_enable(peer)
                _panel_context._sync_peer(peer)
            except Exception as e:
                _panel_context.current_app.logger.warning("Reconcile peer %s failed: %s", peer.name, e)
        _panel_context.db.session.commit()

    return {
        '_expiry_membership_rows': _expiry_membership_rows,
        '_run_expiry_once': _run_expiry_once,
        '_expiry_enforcer_loop': _expiry_enforcer_loop,
        '_expiry_leader_loop': _expiry_leader_loop,
        '_start_expiry_enforcer': _start_expiry_enforcer,
        '_expiry_tick_on_requests': _expiry_tick_on_requests,
        '_on_boot': _on_boot,
    }


def initialize_state(context):
    os = context.os
    threading = context.threading
    _EXPIRY_THREAD_STARTED = False
    _EXPIRY_LOCK = threading.Lock()
    _EXPIRY_LAST_TS = 0.0
    _EXPIRY_LAST_CONTENTION_WARNING = 0.0
    _EXPIRY_DEFERRED_SINCE = None
    _EXPIRY_DEFERRED_ATTEMPTS = 0

    try:
        _EXPIRY_INTERVAL_SEC = max(5, int(os.getenv('WG_EXPIRY_INTERVAL_SEC', '15')))
    except Exception:
        _EXPIRY_INTERVAL_SEC = 15
    context.namespace.update({
        '_EXPIRY_THREAD_STARTED': _EXPIRY_THREAD_STARTED,
        '_EXPIRY_LOCK': _EXPIRY_LOCK,
        '_EXPIRY_LAST_TS': _EXPIRY_LAST_TS,
        '_EXPIRY_LAST_CONTENTION_WARNING': _EXPIRY_LAST_CONTENTION_WARNING,
        '_EXPIRY_DEFERRED_SINCE': _EXPIRY_DEFERRED_SINCE,
        '_EXPIRY_DEFERRED_ATTEMPTS': _EXPIRY_DEFERRED_ATTEMPTS,
        '_EXPIRY_INTERVAL_SEC': _EXPIRY_INTERVAL_SEC,
    })
