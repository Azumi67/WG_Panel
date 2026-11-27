def build_routes(*,
    AddressAllocationError,
    BytesIO,
    ClientConfigIncomplete,
    InterfaceConfig,
    Node,
    NodePeerInstallError,
    PNGImage,
    Peer,
    PeerCreateCompensation,
    PeerRemovalError,
    Subscription,
    SubscriptionPeer,
    _apply_subscription_timer,
    _attach_subscription_target,
    _available_ips,
    _client_config_txt,
    _effective_subscription_settings,
    _flag_from_cc,
    _load_subscription_portal_overrides,
    _load_subscription_settings,
    _lookup_geo,
    _normalize_subscription_settings,
    _peer_client_conf_or_502,
    _private_networks,
    _public_host_peer,
    _render_subscription_template_preview,
    _reset_subscription_data,
    _reset_subscription_timer,
    _save_subscription_portal_overrides,
    _save_subscription_settings,
    _sub_bool,
    _sub_config_url,
    _sub_float,
    _sub_int,
    _sub_public_url,
    _subscription_access_or_403,
    _subscription_data_exhausted,
    _subscription_enabled,
    _subscription_list_runtime,
    _subscription_peer_runtime,
    _subscription_public_payload,
    _subscription_row,
    _subscription_settings_public,
    _subscription_time_expired,
    _sync_all_subscription_peers,
    _token,
    _update_subscription_payload,
    abort,
    address_error_response,
    current_app,
    db,
    from_ts,
    func,
    iface_endpoint_override,
    jsonify,
    login_required,
    logpanel_action,
    node_get,
    now_ts,
    peer_removal_response,
    qrcode,
    re,
    remove_peer_everywhere,
    render_template,
    request,
    require_api_key_or_login,
    resolve_client_endpoint,
    resolve_client_endpoint_cheap,
    send_file,
    time,
    zipfile,
):

    @login_required
    def subscriptions_page():
        return render_template('subscriptions.html')

    @require_api_key_or_login
    def api_subscription_settings():
        if request.method == 'GET':
            return jsonify(_load_subscription_settings())
        saved = _save_subscription_settings(request.get_json(silent=True) or {})
        return jsonify(ok=True, settings=saved)

    @require_api_key_or_login
    def api_subscription_template_preview():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):return jsonify(error='Expected preview settings'),400
        try:sub = db.session.get(Subscription, int(payload['subscription_id'])) if payload.get('subscription_id') else None
        except (ValueError,TypeError):sub=None
        base = _effective_subscription_settings(sub) if sub else _load_subscription_settings()
        return _render_subscription_template_preview(sub, payload.get('settings', {}), base)

    @require_api_key_or_login
    def api_subscription_portal_settings(
        sid,
    ):
        sub = (
            db.session.get(
                Subscription,
                sid,
            )
            or abort(404)
        )

        store = (
            _load_subscription_portal_overrides()
        )

        key = str(
            sub.id
        )

        if request.method == 'GET':
            override = (
                store.get(key)
                if isinstance(
                    store.get(key),
                    dict,
                )
                else {}
            )

            return jsonify(
                ok=True,
                subscription_id=sub.id,
                subscription_name=sub.name,

                has_override=bool(
                    override
                ),

                override=override,

                settings=(
                    _effective_subscription_settings(
                        sub
                    )
                ),

                global_settings=(
                    _load_subscription_settings()
                ),
            )

        if request.method == 'DELETE':
            existed = (
                key in store
            )

            store.pop(
                key,
                None,
            )

            _save_subscription_portal_overrides(
                store
            )

            return jsonify(
                ok=True,
                removed=existed,
                subscription_id=sub.id,
                settings=(
                    _load_subscription_settings()
                ),
            )

        payload = (
            request.get_json(
                silent=True
            )
            or {}
        )

        global_settings = (
            _load_subscription_settings()
        )

        normalized = (
            _normalize_subscription_settings(
                payload,
                base=global_settings,
            )
        )

        override = {}

        for field in payload.keys():

            if (
                field == 'support'
                and isinstance(
                    payload.get('support'),
                    dict,
                )
            ):
                override['support'] = {
                    support_key: (
                        normalized[
                            'support'
                        ].get(
                            support_key,
                            '',
                        )
                    )
                    for support_key
                    in payload['support'].keys()
                    if support_key
                    in normalized['support']
                }

            elif (
                field in normalized
                and field != 'socials'
            ):
                override[
                    field
                ] = normalized[
                    field
                ]

        store[
            key
        ] = override

        _save_subscription_portal_overrides(
            store
        )

        return jsonify(
            ok=True,
            subscription_id=sub.id,
            subscription_name=sub.name,
            has_override=True,
            override=override,

            settings=(
                _effective_subscription_settings(
                    sub
                )
            ),
        )

    @require_api_key_or_login
    def api_subscriptions_locations():

        local_locations = []

        for iface in InterfaceConfig.query.order_by(
            InterfaceConfig.name
        ).all():

            iface_name = (
                getattr(iface, 'name', '')
                or ''
            )

            is_node_interface = (
                getattr(iface, 'node_id', None)
                is not None
                or (
                    iface_name.startswith('n')
                    and ':' in iface_name
                )
            )

            if is_node_interface:
                continue

            interface_address = (
                getattr(iface, 'address', None)
                or ''
            )

            endpoint_override = iface_endpoint_override(iface)
            endpoint_value = resolve_client_endpoint(iface)

            local_locations.append({
                'scope': 'local',
                'iface_id': iface.id,
                'iface': iface_name,
                'label': iface_name,
                'interface_address': interface_address,
                'server_cidr': interface_address,
                'endpoint': endpoint_value,
                'endpoint_override': endpoint_override,
                'endpoint_source': (
                    'override' if endpoint_override
                    else ('auto' if endpoint_value else 'none')
                ),
                'scope_networks': _private_networks(),
                'listen_port': iface.listen_port,
                'dns': iface.dns or '',
                'mtu': iface.mtu,
                'available': len(
                    _available_ips(iface)
                ),
            })

        node_locations = []

        for node in Node.query.order_by(
            Node.name
        ).all():

            interfaces = []

            try:
                remote_payload = node_get(
                    node,
                    '/api/interfaces',
                    timeout=10,
                ) or {}

                if isinstance(remote_payload, dict):
                    node_scope_networks = (
                    remote_payload.get('scope_networks')
                    or []
                )
                else:
                    node_scope_networks = []

                if not isinstance(node_scope_networks, list):
                    node_scope_networks = [
                        value.strip()
                        for value in str(
                            node_scope_networks or ''
                        ).split(',')
                        if value.strip()
                    ]

                node_scope_networks = list(
                    dict.fromkeys(node_scope_networks)
                )

                if isinstance(remote_payload, dict):
                    remote_interfaces = (
                        remote_payload.get('interfaces')
                        or []
                    )
                else:
                    remote_interfaces = (
                        remote_payload
                        or []
                    )

                if not isinstance(
                    remote_interfaces,
                    list,
                ):
                    remote_interfaces = []

                for item in remote_interfaces:
                    if not isinstance(item, dict):
                        continue

                    remote_name = (
                        item.get('name')
                        or item.get('iface')
                        or ''
                    ).strip()

                    if not remote_name:
                        continue

                    mirror_name = (
                        f'n{node.id}:{remote_name}'
                    )

                    mirror = (
                        InterfaceConfig.query
                        .filter_by(name=mirror_name)
                        .first()
                    )

                    interface_address = (
                        item.get('address')
                        or (
                            mirror.address
                            if mirror
                            else ''
                        )
                        or ''
                    )

                    endpoint_override = (
                        iface_endpoint_override(mirror)
                        if mirror is not None
                        else ''
                    )

                    interfaces.append({
                        'scope': 'node',
                        'node_id': node.id,
                        'node_name': node.name,

                        'iface_id': (
                            mirror.id
                            if mirror
                            else None
                        ),

                        'iface': remote_name,

                        'label': (
                            f'{node.name} · '
                            f'{remote_name}'
                        ),

                        'interface_address': interface_address,
                        'server_cidr': interface_address,
                        'scope_networks': list(dict.fromkeys((item.get('scope_networks')if isinstance(item.get('scope_networks'),list,)else node_scope_networks)or node_scope_networks)),

                        'listen_port': (
                            item.get('listen_port')
                        ),

                        'dns': (
                            item.get('dns')
                            or ''
                        ),

                        'mtu': item.get('mtu'),
                        'endpoint': endpoint_override,
                        'endpoint_override': endpoint_override,
                        'endpoint_source': 'override' if endpoint_override else 'auto',

                        'available': len(
                            item.get('available_ips')
                            or []
                        ),
                    })

            except Exception:
                current_app.logger.exception(
                    'Failed to load subscription '
                    'interfaces from node_id=%s',
                    node.id,
                )

                mirrored_interfaces = (
                    InterfaceConfig.query
                    .filter(
                        InterfaceConfig.name.like(
                            f'n{node.id}:%'
                        )
                    )
                    .all()
                )

                for iface in mirrored_interfaces:
                    stored_name = (
                        iface.name
                        or ''
                    )

                    remote_name = (
                        stored_name.split(':', 1)[1]
                        if ':' in stored_name
                        else stored_name
                    )

                    interface_address = (
                        iface.address
                        or ''
                    )

                    endpoint_override = iface_endpoint_override(iface)

                    interfaces.append({
                        'scope': 'node',
                        'node_id': node.id,
                        'node_name': node.name,
                        'iface_id': iface.id,
                        'iface': remote_name,

                        'label': (
                            f'{node.name} · '
                            f'{remote_name}'
                        ),

                        'interface_address': interface_address,
                        'server_cidr': interface_address,

                        'listen_port': (
                            iface.listen_port
                        ),

                        'dns': iface.dns or '',
                        'mtu': iface.mtu,

                        'endpoint': endpoint_override,
                        'endpoint_override': endpoint_override,
                        'endpoint_source': 'override' if endpoint_override else 'auto',

                        'available': len(
                            _available_ips(iface)
                        ),
                    })

            node_locations.append({
                'id': node.id,
                'name': node.name,
                'online': bool(node.enabled),
                'interfaces': interfaces,
            })

        return jsonify(
            local=local_locations,
            nodes=node_locations,
        )

    @require_api_key_or_login
    def api_subscriptions_inbounds_catalog():
        inbounds = []
        for p in Peer.query.order_by(Peer.name).all():
            iface = p.iface
            raw = iface.name if iface else ''
            node_id = getattr(iface, 'node_id', None) if iface else None
            linked = SubscriptionPeer.query.filter_by(peer_id=p.id).first()
            inbounds.append({
                'peer_id': p.id,
                'scope': 'node' if node_id is not None or raw.startswith('n') and ':' in raw else 'local',
                'node_id': node_id,
                'node_name': (getattr(iface.node, 'name', '') if getattr(iface, 'node', None) else ''),
                'iface': raw.split(':',1)[1] if raw.startswith('n') and ':' in raw else raw,
                'name': p.name,
                'address': p.address,
                'endpoint': resolve_client_endpoint_cheap(iface, explicit=p.endpoint),
                'allowed_ips': p.allowed_ips or '',
                'dns': p.dns or '',
                'status': p.status or 'offline',
                'used_bytes': int(getattr(p, 'used_bytes_total', 0) or 0),
                'phone_number': p.phone_number or '',
                'telegram_id': p.telegram_id or '',
                'already_linked': bool(linked),
                'subscription_id': linked.subscription_id if linked else None,
                'location_label': linked.location_label if linked else '',
            })
        return jsonify(inbounds=inbounds)

    @require_api_key_or_login
    def api_subscriptions():
        if request.method == 'GET':
            from sqlalchemy.orm import selectinload
            rows = Subscription.query.options(selectinload(Subscription.links).joinedload(SubscriptionPeer.peer).joinedload(Peer.iface)).order_by(Subscription.created_at.desc()).all()

            runtime = {}
            stamp = time.monotonic()
            for sub in rows:
                for link in sub.links:
                    peer = link.peer
                    if peer is None or peer.id in runtime:continue
                    key = (peer.id, peer.public_key, peer.iface_id)
                    entry = _subscription_list_runtime.get(key)
                    if entry and stamp-entry[0] < 5:
                        runtime[peer.id] = entry[1]
                    else:
                        runtime[peer.id] = _subscription_peer_runtime(peer)
                        if len(_subscription_list_runtime)>4096:_subscription_list_runtime.clear()
                        _subscription_list_runtime[key] = (time.monotonic(),runtime[peer.id])
            return jsonify(subscriptions=[_subscription_row(sub,read_only=True,cached_runtime=runtime) for sub in rows])
        data = request.get_json(silent=True) or {}
        created_ts = now_ts()
        sub = Subscription(
            name=(data.get('name')or 'Subscription').strip(),

            token=_token(),

            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),

            note=(data.get('note')or '').strip(),

            data_limit_value=_sub_int(data.get('data_limit_value'),0,),

            data_limit_unit=(data.get('data_limit_unit')or 'Gi'),

            time_limit_days=_sub_float(data.get('time_limit_days'),0,),

            start_on_first_use=_sub_bool(data.get('start_on_first_use')),

            unlimited=_sub_bool(data.get('unlimited')),

            phone_number=(data.get('phone_number')or '').strip(),

            telegram_id=(data.get('telegram_id')or '').strip(),

            enabled=True,
        )
        _apply_subscription_timer(sub)
        db.session.add(sub)
        db.session.flush()
        targets = data.get('targets') or []
        compensation = PeerCreateCompensation()
        try:
            for idx, target in enumerate(targets):
                _attach_subscription_target(
                    sub, target or {}, data, idx=idx, total=len(targets),
                    compensation=compensation,
                )
            _sync_all_subscription_peers(sub, rename=True)
            db.session.commit()
            return jsonify(ok=True, subscription=_subscription_row(sub)), 201
        except AddressAllocationError as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            if cleanup_failures:
                return jsonify(
                    error='subscription_create_cleanup_failed',
                    detail=str(e),
                    address_error=e.error_code,
                    cleanup_complete=False,
                    cleanup_failures=cleanup_failures,
                ), 502
            return address_error_response(e)
        except NodePeerInstallError as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            return jsonify(
                error=e.code,
                detail=e.detail,
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else e.status
        except Exception as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            current_app.logger.exception('subscription create failed')
            return jsonify(
                error='subscription_create_failed',
                detail=str(e),
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else 500

    @require_api_key_or_login
    def api_subscription_get(sid):
        sub = db.session.get(Subscription, sid) or abort(404)
        return jsonify(subscription=_subscription_row(sub))

    @require_api_key_or_login
    def api_subscription_update(sid):
        sub = db.session.get(Subscription, sid) or abort(404)
        data = request.get_json(silent=True) or {}
        try:
            _update_subscription_payload(sub, data, reset_timer=_sub_bool(data.get('reset_timer')))
            db.session.commit()
            return jsonify(ok=True, subscription=_subscription_row(sub))
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception('subscription update failed')
            return jsonify(error='subscription_update_failed', detail=str(e)), 500

    @require_api_key_or_login
    def api_subscription_add_inbounds(sid):
        sub = db.session.get(Subscription, sid) or abort(404)
        data = request.get_json(silent=True) or {}
        targets = data.get('targets') or []
        compensation = PeerCreateCompensation()
        try:
            base = db.session.query(func.max(SubscriptionPeer.sort_order)).filter_by(subscription_id=sub.id).scalar() or 0
            for off, target in enumerate(targets):
                _attach_subscription_target(
                    sub, target or {}, data,
                    idx=base + off + 1,
                    total=len(getattr(sub, 'links', []) or []) + len(targets),
                    compensation=compensation,
                )
            _sync_all_subscription_peers(sub, rename=True)
            db.session.commit()
            return jsonify(ok=True, subscription=_subscription_row(sub))
        except AddressAllocationError as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            if cleanup_failures:
                return jsonify(
                    error='subscription_add_inbound_cleanup_failed',
                    detail=str(e),
                    address_error=e.error_code,
                    cleanup_complete=False,
                    cleanup_failures=cleanup_failures,
                ), 502
            return address_error_response(e)
        except NodePeerInstallError as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            return jsonify(
                error=e.code,
                detail=e.detail,
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else e.status
        except Exception as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            current_app.logger.exception('subscription add inbound failed')
            return jsonify(
                error='subscription_add_inbound_failed',
                detail=str(e),
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else 500

    @require_api_key_or_login
    def api_subscription_patch_inbound(sid, link_id):
        link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sid).first() or abort(404)
        data = request.get_json(silent=True) or {}
        link.location_label = (data.get('location_label') or '').strip()
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(link.subscription))

    @require_api_key_or_login
    def api_subscription_remove_inbound(sid, link_id):
        link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sid).first() or abort(404)
        sub = link.subscription
        delete_peer = _sub_bool(request.args.get('delete_peer'))
        peer = link.peer

        if delete_peer and peer:
            if not bool(getattr(link, 'owned', False)):
                return jsonify(
                    ok=False,
                    error='peer_not_owned',
                    detail=(
                        f'Peer {peer.name} was attached to this subscription, not created '
                        f'by it. Detach it here and delete it from the peers page instead.'
                    ),
                ), 409

            try:
                remove_peer_everywhere(peer)
            except PeerRemovalError as e:
                current_app.logger.error(
                    'subscription inbound peer delete failed at %s stage: %s', e.phase, e
                )
                return peer_removal_response(e, peer_id=peer.id)
        else:
            db.session.delete(link)
            db.session.flush()

        _sync_all_subscription_peers(sub, rename=True)
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub))

    @require_api_key_or_login
    def api_subscription_delete(sid):
        sub = db.session.get(Subscription, sid) or abort(404)

        delete_peers = request.args.get('delete_peers')
        delete_peers = True if delete_peers is None else _sub_bool(delete_peers)

        owned, attached = [], []
        for link in list(sub.links or []):
            if not link.peer:
                continue
            if delete_peers and bool(getattr(link, 'owned', False)):
                owned.append(link.peer)
            else:
                attached.append(link.peer)

        deleted, failures = 0, []

        for peer in owned:
            peer_id = peer.id
            peer_name = peer.name
            try:
                remove_peer_everywhere(peer)
                deleted += 1
            except PeerRemovalError as e:
                current_app.logger.error(
                    'subscription %s: peer %s could not be removed at the %s stage: %s',
                    sid, peer_id, e.phase, e,
                )
                failures.append({'peer_id': peer_id, 'name': peer_name, 'phase': e.phase,
                                 'detail': str(e)})

        if failures:
            db.session.rollback()
            return jsonify(
                ok=False,
                error='subscription_delete_incomplete',
                deleted=deleted,
                detached=0,
                failed=len(failures),
                failures=failures,
            ), 502

        try:
            db.session.delete(sub)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception('subscription delete failed')
            return jsonify(error='subscription_delete_failed', detail=str(e)), 500

        return jsonify(
            ok=True,
            deleted_peers=bool(delete_peers),
            deleted=deleted,
            detached=len(attached),
            failed=0,
        )

    @require_api_key_or_login
    def api_subscription_disable(sid):

        sub = (
            db.session.get(
                Subscription,
                sid,
            )
            or abort(404)
        )

        try:
            result = (
                _subscription_enabled(
                    sub,
                    False,
                )
            )

            if (
                result['total'] > 0
                and result['changed'] == 0
            ):
                db.session.rollback()

                return jsonify(
                    ok=False,
                    error='subscription_disable_failed',
                    detail=(
                        'None of the attached configs '
                        'could be disabled.'
                    ),
                    result=result,
                ), 409

            sub.enabled = False

            db.session.commit()

            partial = result['failed'] > 0

            if partial:
                message = (
                    'Subscription was disabled, but one or more '
                    'attached configs could not be stopped.'
                )
            elif result['changed']:
                message = (
                    'Subscription and all attached configs '
                    'were disabled.'
                )
            else:
                message = (
                    'Subscription was disabled. '
                    'It has no attached configs.'
                )

            try:
                logpanel_action(
                    'subscription_disable',
                    (
                        f'sid={sub.id}; '
                        f'total={result["total"]}; '
                        f'disabled={result["changed"]}; '
                        f'failed={result["failed"]}; '
                        'data_preserved=1; timer_preserved=1'
                    ),
                )
            except Exception:
                pass

            return jsonify(
                ok=not partial,
                partial=partial,
                enabled=False,
                data_reset=False,
                timer_reset=False,
                message=message,
                result=result,
                subscription=_subscription_row(sub),
            ), 207 if partial else 200

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Subscription disable failed: %s',
                sid,
            )

            return jsonify(
                ok=False,
                error='subscription_disable_failed',
                detail=str(exc),
            ), 500

    @require_api_key_or_login
    def api_subscription_enable(sid):

        sub = (
            db.session.get(
                Subscription,
                sid,
            )
            or abort(404)
        )

        try:
            runtime_result = (
                _subscription_enabled(
                    sub,
                    True,
                )
            )

            if (
                runtime_result['total'] > 0
                and runtime_result['changed'] == 0
            ):
                db.session.rollback()

                return jsonify(
                    ok=False,
                    error='subscription_enable_failed',
                    detail=(
                        'None of the attached configs '
                        'could be enabled.'
                    ),
                    result={
                        'runtime': runtime_result,
                    },
                ), 409

            data_result = (
                _reset_subscription_data(
                    sub
                )
            )

            timer_result = (
                _reset_subscription_timer(
                    sub
                )
            )

            sub.enabled = True

            db.session.commit()

            failure_count = (
                int(
                    runtime_result.get(
                        'failed',
                        0,
                    )
                    or 0
                )
                + int(
                    data_result.get(
                        'enable_failed',
                        0,
                    )
                    or 0
                )
                + int(
                    timer_result.get(
                        'enable_failed',
                        0,
                    )
                    or 0
                )
                + len(
                    data_result.get(
                        'errors',
                        [],
                    )
                    or []
                )
                + len(
                    timer_result.get(
                        'errors',
                        [],
                    )
                    or []
                )
            )

            partial = failure_count > 0

            if partial:
                message = (
                    'Subscription was enabled and its timer and data '
                    'were reset, but one or more attached configs '
                    'reported an error.'
                )
            elif runtime_result['changed']:
                message = (
                    'Subscription and all attached configs were enabled. '
                    'Data usage and timer were reset.'
                )
            else:
                message = (
                    'Subscription was enabled. '
                    'Data usage and timer were reset.'
                )

            try:
                logpanel_action(
                    'subscription_enable',
                    (
                        f'sid={sub.id}; '
                        f'total={runtime_result["total"]}; '
                        f'enabled={runtime_result["changed"]}; '
                        f'failed={failure_count}; '
                        'data_reset=1; timer_reset=1'
                    ),
                )
            except Exception:
                pass

            return jsonify(
                ok=not partial,
                partial=partial,
                enabled=True,
                data_reset=True,
                timer_reset=True,
                message=message,
                result={
                    'runtime': runtime_result,
                    'data': data_result,
                    'timer': timer_result,
                },
                subscription=_subscription_row(sub),
            ), 207 if partial else 200

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Subscription enable failed: %s',
                sid,
            )

            return jsonify(
                ok=False,
                error='subscription_enable_failed',
                detail=str(exc),
            ), 500

    @require_api_key_or_login
    def api_subscription_reset_data(sid):
        sub = db.session.get(Subscription, sid) or abort(404)

        try:
            result = _reset_subscription_data(sub)
            db.session.commit()

            timer_expired = _subscription_time_expired(sub)

            if result['errors']:
                message = (
                    'Data was reset for some configs, but one or more node '
                    'counters could not be read.'
                )
            elif timer_expired and result['still_blocked']:
                message = (
                    'Data was reset, but the subscription remains blocked '
                    'because its timer is expired. Reset the timer as well.'
                )
            elif result['enable_failed']:
                message = (
                    'Data was reset, but one or more configs could not be '
                    're-enabled.'
                )
            elif result['reactivated']:
                message = 'Data was reset and blocked configs were re-enabled.'
            else:
                message = 'Subscription data was reset.'

            return jsonify(
                ok=not bool(result['errors']),
                partial=bool(result['errors']),
                message=message,
                reason=(
                    'timer_expired'
                    if timer_expired and result['still_blocked']
                    else (
                        'enable_failed'
                        if result['enable_failed']
                        else None
                    )
                ),
                result=result,
                subscription=_subscription_row(sub),
            ), 207 if result['errors'] else 200

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Subscription reset data failed'
            )

            return jsonify(
                error='subscription_reset_data_failed',
                detail=str(exc),
            ), 500

    @require_api_key_or_login
    def api_subscription_reset_timer(sid):
        sub = db.session.get(Subscription, sid) or abort(404)

        try:
            result = _reset_subscription_timer(sub)
            db.session.commit()

            data_exhausted = _subscription_data_exhausted(sub)

            if data_exhausted and result['still_blocked']:
                message = (
                    'Timer was reset, but the subscription remains blocked '
                    'because its data allowance is exhausted. Reset data as well.'
                )
            elif result['enable_failed']:
                message = (
                    'Timer was reset, but one or more configs could not be '
                    're-enabled.'
                )
            elif result['reactivated']:
                message = 'Timer was reset and blocked configs were re-enabled.'
            else:
                message = 'Subscription timer was reset.'

            return jsonify(
                ok=not bool(result['errors']),
                partial=bool(result['errors']),
                message=message,
                reason=(
                    'data_exhausted'
                    if data_exhausted and result['still_blocked']
                    else (
                        'enable_failed'
                        if result['enable_failed']
                        else None
                    )
                ),
                result=result,
                subscription=_subscription_row(sub),
            ), 207 if result['errors'] else 200

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Subscription reset timer failed'
            )

            return jsonify(
                error='subscription_reset_timer_failed',
                detail=str(exc),
            ), 500

    @require_api_key_or_login
    def api_subscription_shortlink(sid):
        sub = db.session.get(Subscription, sid) or abort(404)
        return jsonify(url=_sub_public_url(sub), config_url=_sub_config_url(sub), token=sub.token)

    def subscription_public_page(
        token,
    ):
        sub = (
            Subscription.query
            .filter_by(
                token=token
            )
            .first()
            or abort(404)
        )

        cfg = (
            _subscription_settings_public(
                sub
            )
        )

        socials = (
            cfg.get(
                'socials'
            )
            or {}
        )

        portal_title = (
            cfg.get(
                'portal_title'
            )
            or sub.name
        )

        return render_template(
            'subscription_public.html',

            sub=sub,

            data=(
                _subscription_public_payload(
                    sub
                )
            ),

            portal_settings=cfg,

            sub_layout=cfg.get(
                'layout',
                'aurora',
            ),

            sub_display_mode=cfg.get(
                'display_mode',
                'hybrid',
            ),

            sub_animation=cfg.get(
                'animation',
                'balanced',
            ),

            sub_background=cfg.get(
                'background',
                'aurora',
            ),

            portal_label=cfg.get(
                'portal_label',
                'Secure WireGuard portal',
            ),

            portal_icon=cfg.get(
                'portal_icon',
                'fas fa-bolt',
            ),

            portal_title=portal_title,

            portal_subtitle=cfg.get(
                'portal_subtitle',
                (
                    'Your account is ready. '
                    'Install WireGuard, then '
                    'scan QR or import a config.'
                ),
            ),

            support_portal_label=cfg.get(
                'portal_label',
                'Secure WireGuard portal',
            ),

            support_portal_icon=cfg.get(
                'portal_icon',
                'fas fa-bolt',
            ),

            support_portal_title=(
                portal_title
            ),

            support_portal_subtitle=cfg.get(
                'portal_subtitle',
                (
                    'Your account is ready. '
                    'Install WireGuard, then '
                    'scan QR or import a config.'
                ),
            ),

            support_telegram=socials.get(
                'telegram',
                '',
            ),

            support_whatsapp=socials.get(
                'whatsapp',
                '',
            ),

            support_instagram=socials.get(
                'instagram',
                '',
            ),

            support_phone=socials.get(
                'phone',
                '',
            ),

            support_website=socials.get(
                'website',
                '',
            ),

            support_email=socials.get(
                'email',
                '',
            ),
        )

    def subscription_public_api(token):
        sub = Subscription.query.filter_by(token=token).first() or abort(404)
        return jsonify(subscription=_subscription_public_payload(sub))

    def subscription_public_config(token):
        sub = Subscription.query.filter_by(token=token).first() or abort(404)

        revoked = _subscription_access_or_403(sub)
        if revoked:
            return revoked

        mem = BytesIO()
        used_names = set()
        skipped_incomplete = 0

        with zipfile.ZipFile(
            mem,
            'w',
            zipfile.ZIP_DEFLATED,
        ) as z:

            for index, link in enumerate(
                sorted(
                    sub.links,
                    key=lambda x: (
                        x.sort_order or 0,
                        x.id or 0,
                    ),
                ),
                start=1,
            ):
                peer = getattr(link, 'peer', None)

                if not peer:
                    continue

                safe_peer = re.sub(
                    r'[^A-Za-z0-9_.-]+',
                    '_',
                    peer.name or f'peer-{peer.id}',
                ).strip('._')

                base = safe_peer or f'peer-{peer.id}'

                safe_location = re.sub(
                    r'[^A-Za-z0-9_.-]+',
                    '_',
                    (
                        getattr(
                            link,
                            'location_label',
                            '',
                        )
                        or ''
                    ),
                ).strip('._')

                if safe_location:
                    candidate = (
                        f'{base}-{safe_location}'
                    )
                else:
                    candidate = base

                entry = f'{candidate}.conf'

                normalized = entry.lower()

                if normalized in used_names:
                    entry = (
                        f'{candidate}-{index}.conf'
                    )
                    normalized = entry.lower()

                if normalized in used_names:
                    entry = (
                        f'{base}-peer{peer.id}.conf'
                    )
                    normalized = entry.lower()

                suffix = 2

                while normalized in used_names:
                    entry = (
                        f'{base}-peer{peer.id}-{suffix}.conf'
                    )
                    normalized = entry.lower()
                    suffix += 1

                try:
                    cfg = _client_config_txt(peer)
                except ClientConfigIncomplete as exc:
                    skipped_incomplete += 1
                    current_app.logger.error(
                        'Skipping subscription config for peer id=%s iface=%s: %s',
                        getattr(peer, 'id', '?'),
                        getattr(getattr(peer, 'iface', None), 'name', '?'),
                        exc.reason,
                    )
                    continue

                used_names.add(normalized)

                z.writestr(
                    entry,
                    cfg,
                )

        mem.seek(0)

        if not used_names and skipped_incomplete:
            return jsonify(
                ok=False,
                error='server_public_key_unavailable',
                message=(
                    'No client configs could be built because a server '
                    'PublicKey is missing.'
                ),
            ), 502

        fname = re.sub(
            r'[^A-Za-z0-9_.-]+',
            '_',
            sub.name or 'subscription',
        ).strip('._') or 'subscription'

        return send_file(
            mem,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'{fname}.zip',
        )

    def subscription_public_inbound_config(
        token,
        link_id,
    ):
        sub = (
            Subscription.query
            .filter_by(token=token)
            .first()
            or abort(404)
        )

        revoked = _subscription_access_or_403(sub)
        if revoked:
            return revoked

        link = (
            SubscriptionPeer.query
            .filter_by(
                id=link_id,
                subscription_id=sub.id,
            )
            .first()
            or abort(404)
        )

        peer = link.peer or abort(404)

        cfg, err = _peer_client_conf_or_502(peer)
        if err:
            return err

        safe_name = re.sub(
            r'[^A-Za-z0-9_.-]+',
            '_',
            peer.name or f'peer-{peer.id}',
        ).strip('._') or f'peer-{peer.id}'

        mem = BytesIO(
            cfg.encode('utf-8')
        )

        response = send_file(
            mem,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'{safe_name}.conf',
            max_age=0,
        )

        response.headers[
            'X-Content-Type-Options'
        ] = 'nosniff'

        response.headers[
            'Cache-Control'
        ] = (
            'private, no-store, no-cache, '
            'must-revalidate, max-age=0'
        )

        return response

    def subscription_public_inbound_qr(token, link_id):
        sub = Subscription.query.filter_by(token=token).first() or abort(404)

        revoked = _subscription_access_or_403(sub)
        if revoked:
            return revoked

        link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
        peer = link.peer or abort(404)
        cfg, err = _peer_client_conf_or_502(peer)
        if err:
            return err
        img = qrcode.make(cfg, image_factory=PNGImage)
        bio = BytesIO()
        img.save(bio, format='PNG')
        bio.seek(0)
        return send_file(bio, mimetype='image/png')

    def subscription_public_inbound_geo(token, link_id):
        sub = Subscription.query.filter_by(token=token).first() or abort(404)
        revoked = _subscription_access_or_403(sub)
        if revoked:
            return revoked

        link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
        peer = link.peer or abort(404)

        host = _public_host_peer(peer)
        geo = _lookup_geo(host)

        cc = (geo.get('country_code') or '').strip().upper()
        flag = geo.get('flag') or _flag_from_cc(cc)
        country = geo.get('country') or cc or ''

        changed = False

        if cc and (link.country_code or '').strip().upper() != cc:
            link.country_code = cc
            changed = True

        if flag and flag != '🌐' and (link.flag or '').strip() != flag:
            link.flag = flag
            changed = True

        if country and (link.location_label or '').strip() != country:
            link.location_label = country
            changed = True

        if changed:
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        return jsonify(
            country=country,
            country_code=cc,
            flag=flag,
            public_host=host
        )

    return {
        'subscriptions_page': subscriptions_page,
        'api_subscription_settings': api_subscription_settings,
        'api_subscription_template_preview': api_subscription_template_preview,
        'api_subscription_portal_settings': api_subscription_portal_settings,
        'api_subscriptions_locations': api_subscriptions_locations,
        'api_subscriptions_inbounds_catalog': api_subscriptions_inbounds_catalog,
        'api_subscriptions': api_subscriptions,
        'api_subscription_get': api_subscription_get,
        'api_subscription_update': api_subscription_update,
        'api_subscription_add_inbounds': api_subscription_add_inbounds,
        'api_subscription_patch_inbound': api_subscription_patch_inbound,
        'api_subscription_remove_inbound': api_subscription_remove_inbound,
        'api_subscription_delete': api_subscription_delete,
        'api_subscription_disable': api_subscription_disable,
        'api_subscription_enable': api_subscription_enable,
        'api_subscription_reset_data': api_subscription_reset_data,
        'api_subscription_reset_timer': api_subscription_reset_timer,
        'api_subscription_shortlink': api_subscription_shortlink,
        'subscription_public_page': subscription_public_page,
        'subscription_public_api': subscription_public_api,
        'subscription_public_config': subscription_public_config,
        'subscription_public_inbound_config': subscription_public_inbound_config,
        'subscription_public_inbound_qr': subscription_public_inbound_qr,
        'subscription_public_inbound_geo': subscription_public_inbound_geo,
    }
