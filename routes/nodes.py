def build_routes(*,
    AddressAllocationError,
    BytesIO,
    EndpointApplyError,
    EndpointValidationError,
    InterfaceConfig,
    Node,
    NodeIfaceLookupError,
    NodePeerInstallError,
    PNGImage,
    Peer,
    PeerCreateCompensation,
    PeerEvent,
    PeerRemovalError,
    SubscriptionPeer,
    _accumulate_peer_usage,
    _apply_endpoint_default,
    _apply_request_flags,
    _assign_iface_public_key,
    _conv_time_limit,
    _delete_shortlinks_for_peer_ids,
    _effective_client_endpoint,
    _effective_expiry_ts,
    _endpoint_default_payload,
    _host_peer,
    _linked_subscription_timer_response,
    _node_endpoint_fallback,
    _node_mirror_for_endpoint_default,
    _node_peer_by_publickey,
    _node_peer_live_total_bytes,
    _norm_base_url,
    _panel_display_datetime,
    _panel_timezone_name,
    _peer_client_conf_or_502,
    _persist_iface_public_key,
    _probably_encrypt,
    _rollback_node_created_peer,
    _shortlink_response_for_peer,
    _start_timer_cycle,
    _sub_bool,
    _sync_all_subscription_peers,
    _valid_wg_key,
    _validate_node_base_url,
    abort,
    add_days_ts,
    address_error_response,
    admin_required,
    and_,
    csrf,
    current_app,
    current_user,
    datetime,
    db,
    ensure_node_mirror_iface,
    from_ts,
    iface_endpoint_override,
    isoz,
    jsonify,
    log_event,
    login_required,
    logpanel_action,
    make_response,
    node_delete,
    node_get,
    node_install_peer,
    node_post,
    now_ts,
    or_,
    parse_endpoint_override,
    peer_removal_response,
    qrcode,
    remove_peer_everywhere,
    render_template,
    request,
    requests,
    require_api_key_or_login,
    resolve_client_endpoint_cheap,
    send_file,
    subprocess,
    to_ts,
    urlparse,
):

    @csrf.exempt
    @require_api_key_or_login
    def node_peer_config(nid, pub):
        peer = _node_peer_by_publickey(nid, pub)

        text, err = _peer_client_conf_or_502(peer)
        if err:
            return err

        if request.args.get("download"):
            resp = make_response(text)
            fname = f"{peer.name or 'peer'}-{peer.id}.conf".replace(" ", "_")
            resp.headers["Content-Type"] = "text/plain; charset=utf-8"
            resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
            return resp

        return current_app.response_class(
            text,
            mimetype="text/plain; charset=utf-8"
        )

    @csrf.exempt
    @require_api_key_or_login
    def node_peer_config_qr(nid, pub):
        peer = _node_peer_by_publickey(nid, pub)

        text, err = _peer_client_conf_or_502(peer)
        if err:
            return err

        img = qrcode.make(text, image_factory=PNGImage)
        bio = BytesIO()
        img.save(bio, format="PNG")
        bio.seek(0)

        return send_file(
            bio,
            mimetype="image/png",
            as_attachment=False,
            download_name=f"{peer.name or 'peer'}-{peer.id}.png",
        )

    @require_api_key_or_login
    def node_peer_shortlink(nid, pub):
        pub = (pub or '').strip()

        if not pub:
            abort(404)

        peer = (
            db.session.query(Peer)
            .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
            .filter(Peer.public_key == pub)
            .filter(or_(
                InterfaceConfig.name.like(f"n{nid}:%"),
                InterfaceConfig.node_id == nid
            ))
            .first()
        )

        if not peer:
            abort(404)

        return _shortlink_response_for_peer(peer)

    @require_api_key_or_login
    def node_peer_logs(nid, pub):
        pub = (pub or '').strip()

        if not pub:
            abort(404)

        peer = (
            db.session.query(Peer)
            .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
            .filter(Peer.public_key == pub)
            .filter(or_(
                InterfaceConfig.name.like(f"n{nid}:%"),
                InterfaceConfig.node_id == nid
            ))
            .first()
        )

        if not peer:
            abort(404)

        if request.method == 'DELETE':
            try:
                cnt = PeerEvent.query.filter_by(peer_id=peer.id).delete(
                    synchronize_session=False
                )
                db.session.commit()

                try:
                    logpanel_action(
                        "node_peer_logs_clear",
                        f"node={nid}; pid={peer.id}; deleted={int(cnt or 0)}"
                    )
                except Exception:
                    pass

                return jsonify(ok=True, deleted=int(cnt or 0))

            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("Failed to clear node peer logs")
                return jsonify(ok=False, error="clear_failed", detail=str(e)), 500

        try:
            rows = (
                PeerEvent.query
                .filter_by(peer_id=peer.id)
                .order_by(PeerEvent.timestamp.desc())
                .limit(500)
                .all()
            )

            logs = []
            for e in reversed(rows):
                ts = getattr(e, 'timestamp', None)
                event = getattr(e, 'event', '') or ''
                details = getattr(e, 'details', '') or ''

                logs.append({
                    'time': isoz(ts) if ts else '',
                    'ts': isoz(ts) if ts else '',
                    'level': 'info',
                    'event': event,
                    'details': details,
                    'text': f"{event}: {details}".strip(': ')
                })

            return jsonify(logs=logs)

        except Exception as e:
            current_app.logger.exception("Node peer logs failed")
            return jsonify(ok=False, error="logs_failed", detail=str(e)), 500

    @admin_required
    def node_peer_delete(nid, pub):
        n = Node.query.get_or_404(nid)

        p = (
            db.session.query(Peer)
            .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
            .filter(Peer.public_key == pub)
            .filter(or_(
                InterfaceConfig.name.like(f"n{nid}:%"),
                InterfaceConfig.node_id == nid
            ))
            .first()
        )

        if p is None:
            try:
                node_delete(n, f'/api/peer/{pub}')
            except Exception as e:
                current_app.logger.exception("Node peer delete failed")
                return jsonify(error="node_delete_failed", detail=str(e)), 502
            return jsonify(ok=True, shortlinks_removed=0)

        peer_id = p.id
        try:
            removed_shortlinks = remove_peer_everywhere(p)
        except PeerRemovalError as e:
            current_app.logger.error(
                "node peer delete failed at %s stage for node_id=%s pub=%s: %s", e.phase, nid, pub, e
            )
            return peer_removal_response(e, peer_id=peer_id)

        return jsonify(ok=True, shortlinks_removed=removed_shortlinks)

    @admin_required
    def node_health(nid):
        n = Node.query.get_or_404(nid)
        try:
            j = node_get(n, '/api/health')
            n.last_seen = datetime.utcnow(); db.session.commit()
            return jsonify(online=True, info=j)
        except Exception:
            return jsonify(online=False), 200

    @admin_required
    def node_summary(nid):
        n = Node.query.get_or_404(nid)

        info = {}
        online = False

        if n.enabled:
            try:
                h = node_get(n, '/api/health', timeout=6) or {}
                online = True
                n.last_seen = datetime.utcnow()
                db.session.commit()
                info = {
                    'host': h.get('host') or '',
                    'public_ipv4': h.get('public_ipv4') or '',
                    'public_ipv6': h.get('public_ipv6') or '',
                }
            except Exception:
                online = False

        iface_summary = {'count': 0, 'up': 0, 'names': []}
        if n.enabled and online:
            try:
                data = node_get(n, '/api/interfaces?fast=1', timeout=10) or {}
                interfaces = data.get('interfaces') if isinstance(data, dict) else data
                names = []
                up_count = 0
                for it in interfaces or []:
                    name = (it or {}).get('name')
                    if not name:
                        continue
                    names.append(name)
                    if it.get('is_up'):
                        up_count += 1
                iface_summary = {'count': len(names), 'up': up_count, 'names': names}
            except Exception:
                pass

        peers_q = (db.session.query(Peer)
                   .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
                   .filter(or_(InterfaceConfig.name.like(f"n{nid}:%"),
                               InterfaceConfig.node_id == nid)))
        peers = peers_q.all()

        peer_counts = {'total': len(peers), 'online': 0, 'offline': 0, 'blocked': 0}
        for p in peers:
            st = (p.status or '').lower()
            if st in peer_counts:
                peer_counts[st] += 1

        last_seen = n.last_seen

        return jsonify({
            'id': n.id,
            'name': n.name,
            'enabled': n.enabled,
            'online': bool(n.enabled and online),
            'last_seen': last_seen.isoformat() + 'Z' if last_seen else None,
            'info': info,
            'interfaces': iface_summary,
            'peers': peer_counts,
        })

    @require_api_key_or_login
    def node_ifaces(nid):
        node = db.session.get(Node, nid)

        if not node:
            return jsonify(
                ok=False,
                error='node_not_found',
                detail=f'Node {nid} was not found.',
            ), 404

        if request.method == 'POST':
            payload = request.get_json(
                silent=True,
            ) or {}

            if not isinstance(payload, dict):
                return jsonify(
                    ok=False,
                    error='invalid_payload',
                    detail='The request body must be a JSON object.',
                ), 400

            requested_name = str(
                payload.get('name')
                or payload.get('iface')
                or ''
            ).strip()

            if not requested_name:
                return jsonify(
                    ok=False,
                    error='interface_name_required',
                    detail='Interface name is required.',
                ), 400

            try:
                created = node_post(
                    node,
                    '/api/interfaces/create',
                    payload,
                    timeout=30,
                )

            except requests.HTTPError as exc:
                response = getattr(
                    exc,
                    'response',
                    None,
                )

                status_code = getattr(
                    response,
                    'status_code',
                    None,
                )

                response_text = str(
                    getattr(
                        response,
                        'text',
                        '',
                    )
                    or ''
                ).strip()

                current_app.logger.exception(
                    (
                        'Node interface creation failed: '
                        'node_id=%s interface=%s '
                        'upstream_status=%s'
                    ),
                    nid,
                    requested_name,
                    status_code,
                )

                return jsonify(
                    ok=False,
                    error='node_interface_create_failed',
                    detail=(
                        response_text[:1200]
                        or str(exc)
                    ),
                    node_id=nid,
                    node_name=node.name,
                    interface=requested_name,
                    upstream_status=status_code,
                ), 502

            except requests.RequestException as exc:
                current_app.logger.exception(
                    (
                        'Node interface creation connection failed: '
                        'node_id=%s interface=%s'
                    ),
                    nid,
                    requested_name,
                )

                return jsonify(
                    ok=False,
                    error='node_unreachable',
                    detail=str(exc),
                    node_id=nid,
                    node_name=node.name,
                    interface=requested_name,
                ), 502

            except Exception as exc:
                current_app.logger.exception(
                    (
                        'Unexpected node interface creation failure: '
                        'node_id=%s interface=%s'
                    ),
                    nid,
                    requested_name,
                )

                return jsonify(
                    ok=False,
                    error='node_interface_create_failed',
                    detail=str(exc),
                    node_id=nid,
                    node_name=node.name,
                    interface=requested_name,
                ), 500

            created_iface = None

            if isinstance(created, dict):
                candidate = (
                    created.get('interface')
                    or created.get('iface')
                    or created
                )

                if isinstance(candidate, dict):
                    created_iface = candidate

            if not isinstance(created_iface, dict):
                created_iface = {}

            iface_name = str(
                created_iface.get('name')
                or created_iface.get('iface')
                or requested_name
            ).strip()

            if not iface_name:
                return jsonify(
                    ok=False,
                    error='node_interface_create_invalid_response',
                    detail=(
                        'The node reported success but did not return '
                        'an interface name.'
                    ),
                    result=created,
                ), 502

            address = str(
                created_iface.get('address')
                or created_iface.get('server_cidr')
                or payload.get('address')
                or payload.get('server_cidr')
                or '10.0.0.1/24'
            ).strip()

            try:
                listen_port = int(
                    created_iface.get('listen_port')
                    or payload.get('listen_port')
                    or 51820
                )
            except (TypeError, ValueError):
                listen_port = 51820

            if not 1 <= listen_port <= 65535:
                listen_port = 51820

            mtu = (
                created_iface.get('mtu')
                if created_iface.get('mtu') not in (None, '')
                else payload.get('mtu')
            )

            try:
                mtu = (
                    int(mtu)
                    if mtu not in (None, '')
                    else None
                )
            except (TypeError, ValueError):
                mtu = None

            dns = str(
                created_iface.get('dns')
                or payload.get('dns')
                or ''
            ).strip() or None

            db_iface_name = f'n{nid}:{iface_name}'

            try:
                iface = (
                    InterfaceConfig.query
                    .filter_by(
                        name=db_iface_name,
                    )
                    .first()
                )

                if not iface:
                    iface = (
                        InterfaceConfig.query
                        .filter_by(
                            node_id=node.id,
                            name=iface_name,
                        )
                        .first()
                    )

                if not iface:
                    iface = InterfaceConfig(
                        name=db_iface_name,
                        path=f'/etc/wireguard/{iface_name}.conf',
                        address=address,
                        listen_port=listen_port,
                        private_key='(remote)',
                        mtu=mtu,
                        dns=dns,
                    )

                    try:
                        iface.node_id = node.id
                    except Exception:
                        pass

                    pk = _valid_wg_key(created_iface.get('public_key') or '')
                    if pk:
                        _assign_iface_public_key(iface, pk)
                    else:
                        iface.public_key = None

                    db.session.add(iface)

                else:
                    iface.name = db_iface_name
                    iface.path = (
                        created_iface.get('path')
                        or f'/etc/wireguard/{iface_name}.conf'
                    )
                    iface.address = address
                    iface.listen_port = listen_port
                    iface.mtu = mtu
                    iface.dns = dns

                    if not getattr(
                        iface,
                        'private_key',
                        None,
                    ):
                        iface.private_key = '(remote)'

                    try:
                        iface.node_id = node.id
                    except Exception:
                        pass

                    pk = _valid_wg_key(created_iface.get('public_key') or '')
                    if pk:
                        _assign_iface_public_key(iface, pk)
                    else:
                        iface.public_key = None

                db.session.commit()

            except Exception as exc:
                db.session.rollback()

                current_app.logger.exception(
                    (
                        'Remote interface was created but local '
                        'database synchronization failed: '
                        'node_id=%s interface=%s'
                    ),
                    nid,
                    iface_name,
                )

                return jsonify(
                    ok=False,
                    error='node_interface_created_db_sync_failed',
                    detail=str(exc),
                    node_id=nid,
                    interface=iface_name,
                    remote_result=created,
                ), 500

            response_body = (
                dict(created)
                if isinstance(created, dict)
                else {
                    'result': created,
                }
            )

            response_body.update({
                'ok': True,
                'interface_name': iface_name,
                'db_interface_name': db_iface_name,
                'node_id': nid,
            })

            return jsonify(
                response_body
            ), 201

        try:
            data = node_get(
                node,
                '/api/interfaces',
                timeout=15,
            ) or {}

        except requests.HTTPError as exc:
            response = getattr(
                exc,
                'response',
                None,
            )

            status_code = getattr(
                response,
                'status_code',
                None,
            )

            response_text = str(
                getattr(
                    response,
                    'text',
                    '',
                )
                or ''
            ).strip()

            current_app.logger.exception(
                (
                    'Node interface list failed: '
                    'node_id=%s node=%s upstream_status=%s'
                ),
                nid,
                node.name,
                status_code,
            )

            return jsonify(
                ok=False,
                error='node_interfaces_failed',
                detail=(
                    response_text[:1200]
                    or str(exc)
                ),
                node_id=nid,
                node_name=node.name,
                upstream_status=status_code,
            ), 502

        except requests.RequestException as exc:
            current_app.logger.exception(
                (
                    'Could not connect to node interface API: '
                    'node_id=%s node=%s'
                ),
                nid,
                node.name,
            )

            return jsonify(
                ok=False,
                error='node_unreachable',
                detail=str(exc),
                node_id=nid,
                node_name=node.name,
            ), 502

        except Exception as exc:
            current_app.logger.exception(
                (
                    'Unexpected node interface list failure: '
                    'node_id=%s node=%s'
                ),
                nid,
                node.name,
            )

            return jsonify(
                ok=False,
                error='node_interfaces_failed',
                detail=str(exc),
                node_id=nid,
                node_name=node.name,
            ), 500

        if isinstance(data, dict):
            base = (
                data.get('interfaces')
                or []
            )

            node_scope_networks = (
                data.get('scope_networks')
                or []
            )

            remote_public_ipv4 = str(
                data.get('public_ipv4')
                or ''
            ).strip()

        elif isinstance(data, list):
            base = data
            node_scope_networks = []
            remote_public_ipv4 = ''

        else:
            base = []
            node_scope_networks = []
            remote_public_ipv4 = ''

        if not isinstance(base, list):
            current_app.logger.warning(
                (
                    'Node interface API returned an invalid '
                    'interfaces value: node_id=%s type=%s'
                ),
                nid,
                type(base).__name__,
            )

            base = []

        if not isinstance(
            node_scope_networks,
            list,
        ):
            node_scope_networks = [
                value.strip()
                for value in str(
                    node_scope_networks
                    or ''
                ).split(',')
                if value.strip()
            ]

        node_scope_networks = list(
            dict.fromkeys(
                str(value).strip()
                for value in node_scope_networks
                if str(value).strip()
            )
        )

        interfaces = []

        for raw_item in base:
            if not isinstance(
                raw_item,
                dict,
            ):
                continue

            item = dict(
                raw_item
            )

            name = str(
                item.get('name')
                or item.get('iface')
                or ''
            ).strip()

            if not name:
                continue

            item_scope_networks = (
                item.get('scope_networks')
                or node_scope_networks
                or []
            )

            if not isinstance(
                item_scope_networks,
                list,
            ):
                item_scope_networks = [
                    value.strip()
                    for value in str(
                        item_scope_networks
                        or ''
                    ).split(',')
                    if value.strip()
                ]

            item_scope_networks = list(
                dict.fromkeys(
                    str(value).strip()
                    for value in item_scope_networks
                    if str(value).strip()
                )
            )

            interface_address = str(
                item.get('address')
                or item.get('server_cidr')
                or item.get('interface_address')
                or ''
            ).strip()

            item.update({
                'name': name,
                'iface': name,
                'address': interface_address,
                'server_cidr': interface_address,
                'scope_networks': item_scope_networks,
            })

            mirror = InterfaceConfig.query.filter_by(name=f'n{nid}:{name}').first()

            if mirror is not None:
                remote_pk = _valid_wg_key(item.get('public_key') or '')
                if remote_pk:
                    _persist_iface_public_key(mirror, remote_pk)

                override = iface_endpoint_override(mirror)
                host = (getattr(mirror, 'endpoint_host', None) or '').strip() or None
                port = getattr(mirror, 'endpoint_port', None)

                item.update({
                    'endpoint_host': host,
                    'endpoint_port': int(port) if port else None,
                    'endpoint_override': override,
                    'auto_endpoint': '',
                    'effective_endpoint': override,
                    'endpoint_source': 'override' if override else 'none',
                })
            else:

                item.update({
                    'endpoint_host': None,
                    'endpoint_port': None,
                    'endpoint_override': '',
                    'auto_endpoint': '',
                    'effective_endpoint': '',
                    'endpoint_source': 'none',
                })

            try:
                available_result = node_get(
                    node,
                    (
                        f'/api/iface/'
                        f'{name}/available_ips'
                    ),
                    timeout=8,
                ) or {}

                if isinstance(
                    available_result,
                    dict,
                ):
                    available_ips = (
                        available_result.get(
                            'available_ips',
                            [],
                        )
                        or []
                    )
                else:
                    available_ips = []

                item['available_ips'] = (
                    available_ips
                    if isinstance(
                        available_ips,
                        list,
                    )
                    else []
                )

            except Exception as exc:
                current_app.logger.debug(
                    (
                        'Could not load available IPs for '
                        'node_id=%s interface=%s: %s'
                    ),
                    nid,
                    name,
                    exc,
                )

                item['available_ips'] = []

            interfaces.append(
                item
            )

        public_ipv4 = remote_public_ipv4

        if not public_ipv4:
            try:
                health = node_get(
                    node,
                    '/api/health',
                    timeout=6,
                ) or {}

                if isinstance(
                    health,
                    dict,
                ):
                    public_ipv4 = str(
                        health.get('public_ipv4')
                        or ''
                    ).strip()

            except Exception:
                public_ipv4 = ''

        if not public_ipv4:
            try:
                parsed_node_url = urlparse(
                    str(
                        getattr(
                            node,
                            'base_url',
                            '',
                        )
                        or ''
                    ).strip()
                )

                public_ipv4 = str(
                    parsed_node_url.hostname
                    or ''
                ).strip()

            except Exception:
                public_ipv4 = ''

        return jsonify(
            ok=True,
            node_id=nid,
            node_name=node.name,
            interfaces=interfaces,
            public_ipv4=public_ipv4,
            scope_networks=node_scope_networks,
        )

    @admin_required
    def node_iface_available_ips(nid, name):
        n = Node.query.get_or_404(nid)
        return jsonify(node_get(n, f'/api/iface/{name}/available_ips', timeout=8))

    @login_required
    def node_iface_toggle(nid, name, action):
        import requests
        n = Node.query.get_or_404(nid)
        if action not in ('up', 'down'):
            return jsonify(error='invalid_action'), 400
        try:
            node_post(n, f'/api/iface/{name}/{action}')
            return jsonify(ok=True)
        except requests.HTTPError as e:
            current_app.logger.exception("Node iface toggle failed: %s %s", n.base_url, e)
            code = getattr(getattr(e, 'response', None), 'status_code', None)
            return jsonify(error='node_toggle_failed', detail=str(e), status=code), 502

    @login_required
    def node_iface_delete(nid, name):
        n = Node.query.get_or_404(nid)
        data = request.get_json(silent=True) or {}
        delete_peers = _sub_bool(
            data.get('delete_peers')
            if 'delete_peers' in data
            else request.args.get('delete_peers')
        )

        try:
            res = node_delete(
                n,
                f'/api/iface/{name}',
                payload={'delete_peers': bool(delete_peers), 'force': bool(delete_peers)},
                timeout=30
            )
        except requests.HTTPError as e:
            body = getattr(e.response, 'text', '') if getattr(e, 'response', None) else ''
            code = getattr(getattr(e, 'response', None), 'status_code', None)
            try:
                j = e.response.json()
            except Exception:
                j = {}

            if code == 409:
                return jsonify(j or {
                    'error': 'interface_has_peers',
                    'detail': body[:800] if body else ''
                }), 409

            current_app.logger.exception("Node interface delete failed")
            return jsonify(
                error='node_interface_delete_failed',
                detail=str(e),
                status=code,
                body=body[:800] if body else ''
            ), 502
        except Exception as e:
            current_app.logger.exception("Node interface delete failed")
            return jsonify(error='node_interface_delete_failed', detail=str(e)), 502

        db_iface_names = [
            f'n{nid}:{name}',
            name,
        ]

        q = InterfaceConfig.query.filter(
            or_(
                InterfaceConfig.name.in_(db_iface_names),
                and_(InterfaceConfig.node_id == nid, InterfaceConfig.name == name)
            )
        )

        iface = q.first()
        deleted_local_peers = 0
        subscription_link_count = 0
        affected_subs = set()

        try:
            if iface:
                peers = Peer.query.filter_by(iface_id=iface.id).all()
                deleted_local_peers = len(peers)
                peer_ids = [p.id for p in peers]

                if peer_ids:
                    try:
                        _delete_shortlinks_for_peer_ids(peer_ids)
                    except Exception:
                        current_app.logger.exception(
                            "shortlink cleanup failed during node interface delete"
                        )

                    links = SubscriptionPeer.query.filter(
                        SubscriptionPeer.peer_id.in_(peer_ids)
                    ).all()

                    subscription_link_count = len(links)

                    for link in links:
                        if link.subscription:
                            affected_subs.add(link.subscription)

                    SubscriptionPeer.query.filter(
                        SubscriptionPeer.peer_id.in_(peer_ids)
                    ).delete(synchronize_session=False)

                for p in peers:
                    try:
                        db.session.delete(p)
                    except Exception:
                        pass

                db.session.delete(iface)
                db.session.flush()

                for sub in affected_subs:
                    try:
                        _sync_all_subscription_peers(sub, rename=True)
                    except Exception:
                        current_app.logger.exception(
                            "Failed to sync subscription after node interface delete: %s",
                            getattr(sub, 'id', '?')
                        )

                db.session.commit()

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Failed to clean local DB after node interface delete")
            return jsonify(
                error='node_interface_deleted_but_db_cleanup_failed',
                detail=str(e),
                node_result=res
            ), 500

        try:
            logpanel_action(
                "node_interface_delete",
                f"node={nid}; iface={name}; delete_peers={bool(delete_peers)}; peers={deleted_local_peers}"
            )
        except Exception:
            pass

        return jsonify(
            ok=True,
            node_result=res,
            deleted_interface=name,
            deleted_local_peers=deleted_local_peers,
            subscription_link_count=subscription_link_count
        )

    @require_api_key_or_login
    def api_node_iface_endpoint_default_get(nid, name):
        node = db.session.get(Node, nid)

        if node is None:
            return jsonify(
                ok=False, error='node_not_found', detail=f'Node {nid} was not found.'
            ), 404

        iface = InterfaceConfig.query.filter_by(name=f'n{nid}:{name}').first()

        if iface is not None:
            return jsonify(
                ok=True,
                **_endpoint_default_payload(iface, scope='node', node=node),
            )

        try:
            auto = (_node_endpoint_fallback(node, name) or '').strip()
        except Exception:
            auto = ''

        return jsonify(
            ok=True,
            scope='node',
            node_id=nid,
            iface=name,
            iface_id=None,
            listen_port=None,
            endpoint_host=None,
            endpoint_port=None,
            endpoint_override='',
            auto_endpoint=auto,
            effective_endpoint=auto,
            endpoint_source='auto' if auto else 'none',
        )

    @require_api_key_or_login
    def api_node_iface_endpoint_default_put(nid, name):
        node = db.session.get(Node, nid)

        if node is None:
            return jsonify(
                ok=False, error='node_not_found', detail=f'Node {nid} was not found.'
            ), 404

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify(
                ok=False,
                error='invalid_payload',
                detail='The request body must be a JSON object.',
            ), 400

        try:
            host, port = parse_endpoint_override(data.get('host'), data.get('port'))
        except EndpointValidationError as exc:
            return jsonify(ok=False, error=exc.code, detail=exc.detail), 400

        try:
            iface, remote = _node_mirror_for_endpoint_default(node, name)
        except NodeIfaceLookupError as exc:
            return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status

        iface.endpoint_host = host
        iface.endpoint_port = port
        db.session.commit()

        current_app.logger.info(
            'Endpoint default %s for node %s interface %s: host=%s port=%s',
            'cleared' if host is None else 'saved',
            nid, name, host or '-', port or '-',
        )

        return jsonify(
            ok=True,
            **_endpoint_default_payload(
                iface, scope='node', node=node, remote_iface=remote
            ),
        )

    @require_api_key_or_login
    def api_node_iface_endpoint_default_apply(nid, name):
        node = db.session.get(Node, nid)

        if node is None:
            return jsonify(
                ok=False, error='node_not_found', detail=f'Node {nid} was not found.'
            ), 404

        dry_run, overwrite_explicit = _apply_request_flags(
            request.get_json(silent=True)
        )

        remote = None

        if dry_run:

            iface = InterfaceConfig.query.filter_by(name=f'n{nid}:{name}').first()

            if iface is None:
                try:
                    auto = (_node_endpoint_fallback(node, name) or '').strip()
                except Exception:
                    auto = ''

                return jsonify(
                    ok=True,
                    scope='node',
                    iface=name,
                    effective_endpoint=auto,
                    total_peers=0,
                    eligible=0,
                    skipped_explicit=0,
                    dry_run=True,
                    would_update=0,
                )
        else:
            try:
                iface, remote = _node_mirror_for_endpoint_default(node, name)
            except NodeIfaceLookupError as exc:
                return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status

        try:
            result = _apply_endpoint_default(
                iface, dry_run=dry_run, overwrite_explicit=overwrite_explicit,
                scope='node', node=node, remote_iface=remote,
            )
        except EndpointApplyError as exc:
            return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status
        except Exception as exc:
            db.session.rollback()
            current_app.logger.exception('Applying the node endpoint default failed')
            return jsonify(
                ok=False, error='endpoint_apply_failed', detail=str(exc)
            ), 500

        return jsonify(ok=True, **result)

    @admin_required
    def node_peers(nid):
        n = Node.query.get_or_404(nid)

        if request.method == 'GET':
            iface = (request.args.get('iface') or '').strip()
            iface_id = (request.args.get('iface_id') or '').strip()

            if not iface and iface_id:
                parts = iface_id.split(':', 1)
                if len(parts) == 2:
                    iface = parts[1]

            try:
                node_data = node_get(n, '/api/peers' + (f'?iface={iface}' if iface else '')) or {}
                runtime = {p.get('public_key'): p for p in (node_data.get('peers') or [])}
            except Exception as e:
                current_app.logger.debug("node_get peers failed for node %s: %s", n.id, e)
                runtime = {}

            try:
                ifaces = node_get(n, '/api/interfaces') or []
                port_by_name = {i.get('name'): i.get('listen_port') for i in ifaces}
            except Exception:
                port_by_name = {}

            try:
                h = node_get(n, '/api/health') or {}
                node_pub_ip = (h.get('public_ipv4') or '').strip()
            except Exception:
                node_pub_ip = ''

            q = Peer.query.join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
            if iface:
                ns = f"n{nid}:{iface}"
                q = q.filter(or_(
                    InterfaceConfig.name == ns,
                    and_(InterfaceConfig.node_id == nid, InterfaceConfig.name == iface)
                ))
            else:
                q = q.filter(or_(
                    InterfaceConfig.name.like(f"n{nid}:%"),
                    InterfaceConfig.node_id == nid
                ))

            out, dirty = [], False
            for p in q.all():
                r = runtime.get(p.public_key)
                rs = ((r or {}).get('conn_status') or (r or {}).get('connection_status') or (r or {}).get('status') or '').strip()

                if r:
                    rx = r.get('rx_mib', 0) or 0
                    tx = r.get('tx_mib', 0) or 0

                    try:
                        rx_mib = float(rx)
                    except Exception:
                        rx_mib = 0.0

                    try:
                        tx_mib = float(tx)
                    except Exception:
                        tx_mib = 0.0

                    live_total = int((rx_mib + tx_mib) * 1024 * 1024)
                    used_total, _delta, usage_changed = _accumulate_peer_usage(p, live_total)
                    if usage_changed:
                        dirty = True
                    used_live = used_total
                else:
                    rx_mib = 0.0
                    tx_mib = 0.0
                    live_total = int(getattr(p, 'bytes_offset', 0) or 0)
                    used_live = int(getattr(p, 'used_bytes_total', 0) or 0)

                if not getattr(p, 'first_used_at', None):

                    try:
                        handshake_ts = int((r or {}).get('latest_handshake')or 0)
                    except Exception:
                        handshake_ts = 0

                    if handshake_ts > 0:
                        p.first_used_at = from_ts(
                            handshake_ts
                        )
                        p.timer_started_at = from_ts(handshake_ts)

                        if (
                            getattr(p,'start_on_first_use',False,)
                            and getattr(p,'time_limit_days',None,)
                            and not getattr(p,'unlimited',False,)):
                            p.expires_at = from_ts(
                                add_days_ts(
                                    handshake_ts,
                                    float(
                                        p.time_limit_days
                                    ),
                                )
                            )

                        dirty = True


                exp_ts      = _effective_expiry_ts(p)
                ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None

                p_iface    = p.iface
                iface_raw  = p_iface.name if p_iface else ''
                iface_disp = iface_raw.split(':', 1)[1] if iface_raw.startswith(f"n{nid}:") else iface_raw

                if p.status == 'blocked':
                    status = 'blocked'
                elif p.status == 'online':
                    status = 'online'
                else:
                    status = rs or (p.status or 'offline')

                out.append({
                    'id': p.id,
                    'node_id': nid,
                    'panel_status': p.status,
                    'conn_status': rs if rs in ('online', 'offline') else 'offline',
                    'connection_status': rs if rs in ('online', 'offline') else 'offline',
                    'latest_handshake': (r or {}).get('latest_handshake'),
                    'latest_handshake_age': (r or {}).get('latest_handshake_age'),
                    'conn_reason': (r or {}).get('conn_reason') or 'none',
                    'iface': iface_disp,
                    'iface_raw': iface_raw,
                    'name': p.name,
                    'listen_port': (p_iface.listen_port if p_iface else None) or port_by_name.get(iface_disp),
                    'server_public_ip': node_pub_ip,
                    'address': p.address,
                    'endpoint': resolve_client_endpoint_cheap(p_iface, explicit=p.endpoint),
                    'endpoint_saved': p.endpoint or '',
                    'peer_endpoint': getattr(p, 'peer_endpoint', None) or '',
                    'allowed_ips': p.allowed_ips or '',
                    'persistent_keepalive': p.persistent_keepalive,
                    'mtu': p.mtu,
                    'dns': p.dns,
                    'status': status,
                    'data_limit': getattr(p, 'data_limit_value', None),
                    'limit_unit': getattr(p, 'data_limit_unit', None),
                    'unlimited': getattr(p, 'unlimited', False),
                    'time_limit_days': getattr(p, 'time_limit_days', None),
                    'display_timezone': _panel_timezone_name(),
                    'start_on_first_use': getattr(p, 'start_on_first_use', False),
                    'first_used_at': isoz(getattr(p, 'first_used_at', None)),
                    'first_used_at_display': _panel_display_datetime(getattr(p, 'first_used_at', None)),
                    'expires_at': isoz(from_ts(exp_ts)),
                    'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
                    'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
                    'created_at': isoz(getattr(p, 'created_at', None)),
                    'created_at_display': _panel_display_datetime(getattr(p, 'created_at', None)),
                    'created_at_ts': to_ts(getattr(p, 'created_at', None)),
                    'expires_at_ts': exp_ts,
                    'ttl_seconds': ttl_seconds,
                    'used_bytes': used_live,
                    'used_bytes_db': used_live,
                    'rx': str(rx_mib),
                    'tx': str(tx_mib),
                    'phone_number': getattr(p, 'phone_number', '') or '',
                    'telegram_id': getattr(p, 'telegram_id', '') or '',
                    'public_key': p.public_key,
                })

            if dirty:
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()

            return jsonify(peers=out), 200

        data = request.get_json(silent=True) or {}
        iface_name = (data.get('iface') or '').strip()
        if not iface_name:
            return jsonify(error='iface is required'), 400

        try:
            priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
            pub = subprocess.check_output(
                ['wg', 'pubkey'], input=(priv + '\n').encode()
            ).strip().decode()
        except Exception as exc:
            return jsonify(error='key_generation_failed', detail=str(exc)), 500

        remote_iface = {}
        try:
            remote_payload = node_get(n, '/api/interfaces', timeout=10) or {}
            rows = remote_payload.get('interfaces') or [] if isinstance(remote_payload, dict) else remote_payload
            remote_iface = next(
                (row for row in (rows or []) if str((row or {}).get('name') or '') == iface_name),
                {},
            ) or {}
        except Exception:
            current_app.logger.warning(
                'Could not refresh node %s interface %s before peer create',
                nid, iface_name, exc_info=True,
            )

        iface = ensure_node_mirror_iface(
            n, iface_name, remote_iface,
            listen_port=data.get('listen_port'),
            server_cidr=data.get('server_cidr'),
            mtu=data.get('mtu'),
            dns=data.get('dns'),
        )
        peer_endpoint = (data.get('peer_endpoint') or '').strip()
        allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()

        try:
            address = node_install_peer(
                n, iface_name, iface,
                public_key=pub,
                requested_address=(data.get('address') or '').strip(),
                peer_endpoint=peer_endpoint,
                keepalive=data.get('persistent_keepalive') or 0,
                mtu=data.get('mtu'),
                dns=data.get('dns'),
                allowed_ips=allowed_ips,
            )
        except AddressAllocationError as exc:
            db.session.rollback()
            return address_error_response(exc)
        except NodePeerInstallError as exc:

            try:
                _rollback_node_created_peer(n, pub)
            except Exception:
                current_app.logger.exception('Ambiguous node create cleanup failed for %s', pub)
            db.session.rollback()
            return jsonify(error=exc.code, detail=exc.detail), exc.status

        compensation = PeerCreateCompensation()
        compensation.register_node(n, pub)
        created_ts = now_ts()
        try:
            peer = Peer(
                iface_id=iface.id,
                name=(data.get('name') or '').strip() or 'peer',
                public_key=pub,
                private_key=priv,
                created_at=from_ts(created_ts),
                timer_started_at=from_ts(created_ts),
                address=address,
                allowed_ips=allowed_ips,
                endpoint=(data.get('endpoint') or '').strip() or None,
                peer_endpoint=peer_endpoint or None,
                persistent_keepalive=data.get('persistent_keepalive') or None,
                mtu=data.get('mtu') or None,
                dns=(data.get('dns') or '').strip() or None,
                status='online',
                data_limit_value=int(data.get('data_limit_value') or 0),
                data_limit_unit=data.get('data_limit_unit') or 'Mi',
                start_on_first_use=_sub_bool(data.get('start_on_first_use')),
                time_limit_days=_conv_time_limit(data),
                unlimited=_sub_bool(data.get('unlimited')),
                phone_number=(data.get('phone_number') or '').strip(),
                telegram_id=(data.get('telegram_id') or '').strip(),
            )

            if (
                peer.time_limit_days
                and not peer.start_on_first_use
                and not peer.unlimited
            ):
                peer.expires_at = from_ts(
                    add_days_ts(created_ts, peer.time_limit_days)
                )

            db.session.add(peer)
            db.session.commit()
        except Exception as exc:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            current_app.logger.exception('DB save failed after legacy node peer create')
            return jsonify(
                error='db_save_failed', detail=str(exc),
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else 500

        return jsonify(
            ok=True, id=peer.id, address=peer.address,
            endpoint=_effective_client_endpoint(peer),
            peer_endpoint=peer.peer_endpoint or '',
        )

    @login_required
    def nodes():
        return render_template('nodes.html')

    @login_required
    def ui_nodes():
        rows = Node.query.order_by(Node.name).all()
        now = datetime.utcnow()
        FRESH_SEC = 180
        out = []
        for n in rows:
            last_seen = n.last_seen
            is_fresh = bool(last_seen and (now - last_seen).total_seconds() <= FRESH_SEC)
            out.append({
                'id': n.id,
                'name': n.name,
                'base_url': n.base_url,
                'enabled': n.enabled,
                'last_seen': last_seen.isoformat() + 'Z' if last_seen else None,
                'online': bool(n.enabled and is_fresh),
            })
        return jsonify(nodes=out)

    @require_api_key_or_login
    def api_nodes():

        if request.method == 'GET':
            rows = Node.query.order_by(Node.name).all()
            now = datetime.utcnow()
            FRESH_SEC = 180
            out = []
            for n in rows:
                last_seen = n.last_seen
                is_fresh = bool(last_seen and (now - last_seen).total_seconds() <= FRESH_SEC)
                out.append({
                    'id': n.id,
                    'name': n.name,
                    'base_url': n.base_url,
                    'enabled': n.enabled,
                    'last_seen': last_seen.isoformat() + 'Z' if last_seen else None,
                    'online': bool(n.enabled and is_fresh),
                })
            return jsonify(nodes=out)


        if not (getattr(current_user, "is_authenticated", False) and getattr(current_user, "is_admin", False)):
            return jsonify(error="admin required"), 403

        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip()
        api_key = (data.get('api_key') or '').strip()

        base_url = _norm_base_url(data.get('base_url') or '')

        if not name or not api_key:
            return jsonify(error='Invalid input'), 400

        ok, reason = _validate_node_base_url(base_url)
        if not ok:
            return jsonify(error=reason), 400

        dup = (Node.query.filter_by(name=name).first() or
               Node.query.filter_by(base_url=base_url).first())
        if dup:
            return jsonify(error='Node name or base_url already exists'), 409

        n = Node(
            name=name,
            base_url=base_url,
            api_key=_probably_encrypt(api_key),
            enabled=True
        )
        db.session.add(n)
        db.session.commit()
        return jsonify(ok=True, id=n.id), 201

    @admin_required
    def node_disable_peer(nid, pub):
        n = Node.query.get_or_404(nid)
        p = (db.session.query(Peer)
             .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
             .filter(Peer.public_key == pub)
             .filter(or_(InterfaceConfig.name.like(f"n{nid}:%"),
                         InterfaceConfig.node_id == nid))
             .first())

        payload = {}
        if p:
            try:
                payload['host_cidr'] = _host_peer(p)
            except Exception:
                pass

        node_post(n, f'/api/peer/{pub}/disable', payload)

        if p:
            p.status = 'offline'
            log_event(p, 'disabled', 'Node: disabled (blackhole requested)')
            db.session.commit()
        return jsonify(ok=True)

    @admin_required
    def node_enable_peer(nid, pub):

        n = Node.query.get_or_404(nid)

        p = (
            db.session.query(Peer)
            .join(
                InterfaceConfig,
                Peer.iface_id == InterfaceConfig.id
            )
            .filter(Peer.public_key == pub)
            .filter(or_(
                InterfaceConfig.name.like(f"n{nid}:%"),
                InterfaceConfig.node_id == nid
            ))
            .first()
        )

        if not p:
            return jsonify(
                success=False,
                error='peer_not_found'
            ), 404

        payload = {}

        try:
            payload['host_cidr'] = _host_peer(p)
        except Exception:
            pass

        try:
            node_post(
                n,
                f'/api/peer/{pub}/enable',
                payload,
                timeout=15
            )

            current_live_total = int(
                _node_peer_live_total_bytes(n, p) or 0
            )
            current_live_total = max(0, current_live_total)

            p.bytes_offset = current_live_total
            p.used_bytes_total = 0
            p.first_used_at = None
            p.timer_started_at = None

            try:
                time_limit_days = float(
                    getattr(p, 'time_limit_days', 0) or 0
                )
            except (TypeError, ValueError):
                time_limit_days = 0.0

            if getattr(p, 'unlimited', False):
                p.expires_at = None

            elif getattr(p, 'start_on_first_use', False):
                p.expires_at = None

            elif time_limit_days > 0:
                _start_timer_cycle(p)

            else:
                p.expires_at = None

            p.status = 'online'

            db.session.commit()

            try:
                log_event(
                    p,
                    'enabled',
                    (
                        'Node peer enabled; timer and data reset; '
                        f'new traffic offset={current_live_total}'
                    )
                )

                logpanel_action(
                    'node_peer_enable',
                    (
                        f'node={nid}; pid={p.id}; '
                        f'timer_reset=1; data_reset=1; '
                        f'unlimited={int(bool(getattr(p, "unlimited", False)))}; '
                        f'offset={current_live_total}'
                    )
                )
            except Exception:
                pass

            return jsonify(
                success=True,
                ok=True,
                status='online',
                timer_reset=True,
                data_reset=True,
                unlimited=bool(getattr(p, 'unlimited', False)),
                used_bytes_total=0,
                bytes_offset=current_live_total
            )

        except requests.HTTPError as exc:
            db.session.rollback()

            response = getattr(exc, 'response', None)
            upstream_status = getattr(response, 'status_code', None)
            upstream_body = getattr(response, 'text', '') or ''

            current_app.logger.exception(
                'Node peer enable failed: node=%s peer=%s',
                nid,
                pub
            )

            return jsonify(
                success=False,
                error='node_enable_failed',
                detail=str(exc),
                upstream_status=upstream_status,
                upstream_body=upstream_body[:800]
            ), 502

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Node peer enable failed: node=%s peer=%s',
                nid,
                pub
            )

            return jsonify(
                success=False,
                error='node_enable_failed',
                detail=str(exc)
            ), 502

    @login_required
    def node_reset_peer_data_only(nid, pub):
        n = Node.query.get_or_404(nid)
        p = _node_peer_by_publickey(nid,pub,)

        current = _node_peer_live_total_bytes(n, p)

        p.bytes_offset = int(current or 0)
        p.used_bytes_total = 0

        db.session.commit()

        try:
            log_event(p, 'reset_data', f'Node: offset set to {current}; status kept as {p.status}')
            logpanel_action("node_peer_reset_data", f"node={nid}; pid={p.id}; new_offset={current}; status_kept={p.status}")
        except Exception:
            pass

        return jsonify(ok=True, success=True, status=p.status)

    @login_required
    def node_reset_peer_timer_only(nid, pub):
        n = Node.query.get_or_404(nid)
        p = _node_peer_by_publickey(nid,pub,)

        try:
            shared_response = _linked_subscription_timer_response(
                p,
                'node_peer_reset_timer_subscription',
            )
            if shared_response is not None:
                return shared_response
        except Exception as exc:
            db.session.rollback()
            current_app.logger.exception(
                'Shared subscription timer reset failed for node peer %s',
                getattr(p, 'id', '?'),
            )
            return jsonify(
                error='subscription_timer_reset_failed',
                detail=str(exc),
            ), 500

        tl_days = getattr(p, 'time_limit_days', None)
        try:
            tl_days_f = float(tl_days) if tl_days is not None else 0.0
        except Exception:
            tl_days_f = 0.0

        p.first_used_at = None
        p.timer_started_at = None

        if getattr(p, 'unlimited', False) or tl_days_f <= 0:
            p.expires_at = None
            detail = 'Node timer cleared; peer re-enabled'
        elif getattr(p, 'start_on_first_use', False):
            p.expires_at = None
            detail = 'Node timer cleared; will start on first use; peer re-enabled'
        else:
            _start_timer_cycle(p)
            detail = f'Node timer restarted for {tl_days_f} days; peer re-enabled'

        payload = {}
        try:
            payload['host_cidr'] = _host_peer(p)
        except Exception:
            pass

        try:
            node_post(n, f'/api/peer/{pub}/enable', payload)
            p.status = 'online'
        except Exception as e:
            db.session.commit()
            current_app.logger.exception("Node reset timer enable failed")
            return jsonify(error="node_reset_timer_failed", detail=str(e)), 502

        db.session.commit()

        try:
            log_event(p, 'reset_timer', detail)
            logpanel_action("node_peer_reset_timer", f"node={nid}; pid={p.id}; {detail}")
        except Exception:
            pass

        return jsonify(ok=True, success=True, status=p.status)

    @admin_required
    def node_one(nid):
        n = Node.query.get_or_404(nid)

        if request.method == 'DELETE':
            db.session.delete(n)
            db.session.commit()
            return jsonify(ok=True)

        data = request.get_json(silent=True) or {}
        updated = False

        if 'enabled' in data:
            n.enabled = bool(data['enabled'])
            updated = True

        if 'name' in data:
            new_name = (data.get('name') or '').strip()
            if new_name:
                exists = Node.query.filter(Node.id != n.id, Node.name == new_name).first()
                if exists:
                    return jsonify(error='name already exists'), 409
                n.name = new_name
                updated = True
            else:
                return jsonify(error='invalid name'), 400

        if 'base_url' in data:
            new_url = _norm_base_url(data.get('base_url') or '')
            ok, reason = _validate_node_base_url(new_url)
            if not ok:
                return jsonify(error=reason), 400


            exists = Node.query.filter(Node.id != n.id, Node.base_url == new_url).first()
            if exists:
                return jsonify(error='base_url already exists'), 409
            n.base_url = new_url
            updated = True

        if 'api_key' in data:
            new_key = (data.get('api_key') or '').strip()
            if not new_key:
                return jsonify(error='invalid api_key'), 400
            n.api_key = _probably_encrypt(new_key)
            updated = True

        if updated:
            db.session.commit()

        return jsonify(ok=True, id=n.id)

    @admin_required
    def node_iface_logs(nid, name):
        n = Node.query.get_or_404(nid)

        if request.method == 'DELETE':
            try:
                node_delete(n, f'/api/iface/{name}/logs', timeout=12)
                return jsonify(ok=True)
            except Exception as e:
                current_app.logger.warning(
                    "node_iface_logs DELETE failed for %s on node %s: %s",
                    name, nid, e
                )
                return jsonify(ok=False, error="node_clear_failed"), 502
        from urllib.parse import urlencode
        params = {
            'limit': request.args.get('limit', 500),
            'q': (request.args.get('q') or '').strip(),
        }
        qs = urlencode({k: v for k, v in params.items() if str(v or '').strip()})
        node_path = f"/api/iface/{name}/logs" + (f"?{qs}" if qs else "")

        try:
            data = node_get(n, node_path, timeout=12)
        except Exception as e:
            current_app.logger.warning("node_iface_logs failed for %s on %s: %s", name, n, e)
            return jsonify(logs=[])
        return jsonify(logs=(data.get('logs', []) if isinstance(data, dict) else []))

    return {
        'node_peer_config': node_peer_config,
        'node_peer_config_qr': node_peer_config_qr,
        'node_peer_shortlink': node_peer_shortlink,
        'node_peer_logs': node_peer_logs,
        'node_peer_delete': node_peer_delete,
        'node_health': node_health,
        'node_summary': node_summary,
        'node_ifaces': node_ifaces,
        'node_iface_available_ips': node_iface_available_ips,
        'node_iface_toggle': node_iface_toggle,
        'node_iface_delete': node_iface_delete,
        'api_node_iface_endpoint_default_get': api_node_iface_endpoint_default_get,
        'api_node_iface_endpoint_default_put': api_node_iface_endpoint_default_put,
        'api_node_iface_endpoint_default_apply': api_node_iface_endpoint_default_apply,
        'node_peers': node_peers,
        'nodes': nodes,
        'ui_nodes': ui_nodes,
        'api_nodes': api_nodes,
        'node_disable_peer': node_disable_peer,
        'node_enable_peer': node_enable_peer,
        'node_reset_peer_data_only': node_reset_peer_data_only,
        'node_reset_peer_timer_only': node_reset_peer_timer_only,
        'node_one': node_one,
        'node_iface_logs': node_iface_logs,
    }
