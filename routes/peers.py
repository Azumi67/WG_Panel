def build_routes(*,
    AddressAllocationError,
    AddressPoolExhausted,
    BytesIO,
    EndpointValidationError,
    IntegrityError,
    InterfaceConfig,
    Node,
    NodePeerInstallError,
    PNGImage,
    Peer,
    PeerCreateCompensation,
    PeerEvent,
    PeerForm,
    PeerRemovalError,
    Subscription,
    SubscriptionPeer,
    _available_ips,
    _check_iface_up,
    _clear_timer_cycle,
    _conv_time_limit,
    _effective_client_endpoint,
    _effective_expiry_ts,
    _host_peer,
    _iface_up,
    _linked_subscription_timer_response,
    _load_template_settings,
    _panel_display_datetime,
    _panel_timezone_name,
    _peer_by_public_key_or_404,
    _peer_client_conf_or_502,
    _peer_conn_status,
    _peer_from_shortlink_token,
    _preview_peer_usage,
    _public_ipv4,
    _remove_peer_quiet,
    _rollback_node_created_peer,
    _shortlink_for_peer,
    _shortlink_from_peer_id,
    _shortlink_response_for_peer,
    _start_timer_cycle,
    _sub_limit_bytes,
    _subscription_peer_runtime,
    _sync_effective_expiry,
    _sync_peer,
    _unblackhole,
    _wg_disable,
    _wg_disable_quiet,
    _wg_enable,
    _wg_runtime_snapshot,
    _wg_transfer,
    _wireguard_endpoint,
    abort,
    add_days_ts,
    address_error_response,
    allocate_peer_address,
    csrf,
    current_app,
    db,
    effective_peer_state,
    ensure_node_mirror_iface,
    flash,
    from_ts,
    func,
    iface_devname,
    install_local_peer,
    interface_allocation_lock,
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
    parse_endpoint_string,
    peer_removal_response,
    qrcode,
    re,
    reapply_peer_external,
    redirect,
    remove_peer_everywhere,
    render_template,
    request,
    requests,
    require_api_key,
    require_api_key_or_login,
    resolve_client_endpoint_cheap,
    send_file,
    subprocess,
    subscription_access,
    time,
    to_ts,
    url_for,
):

    @require_api_key_or_login
    def api_shortlink(pid):
        p = db.session.get(Peer, pid) or abort(404)
        return _shortlink_response_for_peer(p)

    @require_api_key_or_login
    def api_shortlink_by_public_key(public_key):
        public_key = (public_key or '').strip()
        if not public_key:
            abort(404)

        peer = Peer.query.filter_by(public_key=public_key).first()
        if not peer:
            abort(404)

        return _shortlink_response_for_peer(peer)

    def user_peer_page(token):
        peer = _peer_from_shortlink_token(token)

        from reseller_portal.shared import peer_design
        ts = peer_design(peer, _load_template_settings())
        sel = (ts.get('selected') or 'default').lower()
        s   = ts.get('socials') or {}

        tmap = {
            'default': 'user_peer.html',
            'compact': 'user_peer_compact.html',
            'minimal': 'user_peer_minimal.html',
            'pro':     'user_peer_pro.html',
        }
        tpl = tmap.get(sel, 'user_peer.html')

        return render_template(
            tpl,
            token=token,
            peer_appearance=ts.get('appearance', {}),
            support_telegram = (s.get('telegram')  or ''),
            support_whatsapp = (s.get('whatsapp')  or ''),
            support_instagram= (s.get('instagram') or ''),
            support_phone    = (s.get('phone')     or ''),
            support_website  = (s.get('website')   or ''),
            support_email    = (s.get('email')     or ''),
        )

    def user_peer(token):
        p = _peer_from_shortlink_token(token)

        total = _wg_transfer(p)
        used_total = _preview_peer_usage(p, total)
        used_live = 0
        exp_ts = _effective_expiry_ts(p)
        ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None
        used_db = int(getattr(p, 'used_bytes_total', 0) or 0)
        unit = getattr(p, 'data_limit_unit', 'Mi') or 'Mi'
        lim_val = int(getattr(p, 'data_limit_value', 0) or 0)
        lim_bytes = 0
        if lim_val and not getattr(p, 'unlimited', False):
            lim_bytes = lim_val * (1024*1024 if unit == 'Mi' else 1024*1024*1024)

        used_eff = used_total
        if lim_bytes:
            used_eff = min(used_eff, lim_bytes)

        if getattr(p, 'status', '') == 'blocked' and lim_bytes:
            used_eff = lim_bytes

        return jsonify({
        'name': p.name,
        'iface': p.iface.name,
        'address': p.address,
        'endpoint': _effective_client_endpoint(p),
        'peer_endpoint': getattr(p, 'peer_endpoint', None) or '',
        'status': p.status,
        'unlimited': bool(getattr(p, 'unlimited', False)),
        'limit_unit': unit,
        'data_limit': lim_val,
        'used_bytes': used_eff,
        'used_bytes_db': used_db,
        'used_effective_bytes': used_eff,
        'time_limit_days': getattr(p, 'time_limit_days', None),
        'display_timezone': _panel_timezone_name(),
        'start_on_first_use': bool(getattr(p, 'start_on_first_use', False)),
        'first_used_at': isoz(getattr(p, 'first_used_at', None)),
        'first_used_at_display': _panel_display_datetime(getattr(p, 'first_used_at', None)),
        'created_at': isoz(getattr(p, 'created_at', None)),
        'created_at_ts': to_ts(getattr(p, 'created_at', None)),
        'timer_started_at': isoz(getattr(p, 'timer_started_at', None)),
        'timer_started_at_ts': to_ts(getattr(p, 'timer_started_at', None)),
        'expires_at': isoz(from_ts(exp_ts)),
        'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
        'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
        'expires_at_ts': exp_ts,
        'ttl_seconds': ttl_seconds,
        'allowed_ips': p.allowed_ips or '0.0.0.0/0, ::/0',
        'dns': p.dns or p.iface.dns or '',
        'mtu': p.mtu or p.iface.mtu or None
        })

    def userpeer_config(token):
        p = _peer_from_shortlink_token(token)

        cfg, err = _peer_client_conf_or_502(p)
        if err:
            return err

        safe_name = re.sub(
            r'[^A-Za-z0-9_.-]+',
            '_',
            p.name or f'peer-{p.id}',
        ).strip('._') or f'peer-{p.id}'

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

    @csrf.exempt
    @require_api_key_or_login
    def api_peer_config_by_public_key(public_key):
        peer = _peer_by_public_key_or_404(public_key)

        cfg, err = _peer_client_conf_or_502(peer)
        if err:
            return err

        if not cfg or not cfg.strip():
            return jsonify(
                ok=False,
                error="config_empty",
                message="The peer configuration is empty.",
            ), 404

        safe_name = re.sub(
            r"[^A-Za-z0-9_.-]+",
            "_",
            peer.name or f"peer-{peer.id}",
        ).strip("._") or f"peer-{peer.id}"

        response = make_response(cfg.strip() + "\n", 200)
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = (
            "private, no-store, no-cache, must-revalidate, max-age=0"
        )

        if request.args.get("download") == "1":
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{safe_name}.conf"'
            )

        return response

    @csrf.exempt
    @require_api_key_or_login
    def api_peer_config_qr_by_public_key(public_key):
        peer = _peer_by_public_key_or_404(public_key)

        cfg, err = _peer_client_conf_or_502(peer)
        if err:
            return err

        if not cfg or not cfg.strip():
            return jsonify(
                ok=False,
                error="config_empty",
                message="The peer configuration is empty.",
            ), 404

        safe_name = re.sub(
            r"[^A-Za-z0-9_.-]+",
            "_",
            peer.name or f"peer-{peer.id}",
        ).strip("._") or f"peer-{peer.id}"

        img = qrcode.make(cfg, image_factory=PNGImage)
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        response = send_file(
            buf,
            mimetype="image/png",
            as_attachment=False,
            download_name=f"{safe_name}.png",
            max_age=0,
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = (
            "private, no-store, no-cache, must-revalidate, max-age=0"
        )
        return response

    @login_required
    def peer_clear_total(pid):
        p = Peer.query.get_or_404(pid)

        prev = int(getattr(p, 'used_bytes_total', 0) or 0)
        p.used_bytes_total = 0
        db.session.commit()

        log_event(p, 'clear_total', f'Lifetime cleared (was {prev} bytes)')
        return jsonify(success=True, cleared=prev)

    @login_required
    def clear_peer_logs(pid):
        p = db.session.get(Peer, pid) or abort(404)
        try:
            cnt = (PeerEvent.query.filter_by(peer_id=pid).delete(synchronize_session=False) or 0)
            db.session.commit()
            logpanel_action("peer_logs_clear", f"pid={p.id}; {cnt} events")
            return jsonify(ok=True, deleted=int(cnt))
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Clear peer logs failed")
            return jsonify(ok=False, error="clear_failed", detail=str(e)), 500

    @login_required
    def users():
        form = PeerForm()
        ifaces = InterfaceConfig.query.order_by(InterfaceConfig.name.asc()).all()
        form.iface.choices = [(i.id, i.name) for i in ifaces]
        sel_iface = None
        if request.method == 'POST' and form.iface.data:
            sel_iface = db.session.get(InterfaceConfig, form.iface.data)
        else:
            arg_iface_id = request.args.get('iface_id', type=int)
            arg_iface_nm = (request.args.get('iface') or '').strip()
            if arg_iface_id:
                sel_iface = db.session.get(InterfaceConfig, arg_iface_id)
                if sel_iface:
                    form.iface.data = sel_iface.id
            elif arg_iface_nm:
                sel_iface = InterfaceConfig.query.filter_by(name=arg_iface_nm).first()
                if sel_iface:
                    form.iface.data = sel_iface.id
            if not sel_iface and form.iface.choices:
                sel_iface = db.session.get(InterfaceConfig, form.iface.choices[0][0])
                if sel_iface:
                    form.iface.data = sel_iface.id

        form.address.choices = [(ip, ip) for ip in (_available_ips(sel_iface) if sel_iface and request.method=='POST' else [])]

        if request.method == 'GET':
            if hasattr(form, 'time_limit_hours') and form.time_limit_hours.data is None:
                form.time_limit_hours.data = 0
            if sel_iface:
                if form.mtu.data is None:
                    form.mtu.data = sel_iface.mtu
                if form.dns.data is None:
                    form.dns.data = sel_iface.dns

        if form.validate_on_submit():
            iface = sel_iface or (db.session.get(InterfaceConfig, form.iface.data) if form.iface.data else None)
            if not iface:
                flash('Please select an interface.', 'error')
                return render_template('users.html', form=form)

            priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
            pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()

            combined_days = _conv_time_limit({
                'time_limit_days': (
                    getattr(
                        form,
                        'time_limit_days',
                        None,
                    )
                    and form.time_limit_days.data
                ),

                'time_limit_hours': (
                    getattr(
                        form,
                        'time_limit_hours',
                        None,
                    )
                    and form.time_limit_hours.data
                ),

                'time_limit_minutes': (
                    getattr(
                        form,
                        'time_limit_minutes',
                        None,
                    )
                    and form.time_limit_minutes.data
                ),
            })
            created_ts = now_ts()

            peer = Peer(
                iface_id=iface.id,
                name=form.name.data,
                public_key=pub,
                private_key=priv,
                allowed_ips=form.allowed_ips.data,
                endpoint=form.endpoint.data,
                peer_endpoint=(form.peer_endpoint.data or '').strip() or None,
                persistent_keepalive=form.persistent_keepalive.data,
                mtu=form.mtu.data,
                dns=form.dns.data,
                status='offline',
                data_limit_value=int(getattr(form, 'data_limit', None) and (form.data_limit.data or 0)),
                data_limit_unit=getattr(form, 'limit_unit', None) and form.limit_unit.data,
                time_limit_days=combined_days,
                created_at=from_ts(created_ts),
                timer_started_at=from_ts(created_ts),
                start_on_first_use=bool(getattr(form, 'start_on_first_use', None) and form.start_on_first_use.data),
                unlimited=bool(getattr(form, 'unlimited', None) and form.unlimited.data),
                phone_number=getattr(form, 'phone_number', None) and form.phone_number.data,
                telegram_id=getattr(form, 'telegram_id', None) and form.telegram_id.data,
            )

            if (
                peer.time_limit_days
                and not peer.start_on_first_use
                and not peer.unlimited
            ):
                peer.expires_at = from_ts(
                    add_days_ts(
                        created_ts,
                        float(
                             peer.time_limit_days
                        ),
                    )
                )

            installed = False

            with interface_allocation_lock(iface):
                try:
                    peer.address = allocate_peer_address(iface, requested=form.address.data)
                except AddressAllocationError as e:
                    flash(str(e), 'error')
                    return render_template('users.html', form=form)

                try:
                    db.session.add(peer)
                    db.session.flush()

                    install_local_peer(peer)
                    installed = True
                    peer.status = 'online'

                    db.session.add(
                        PeerEvent(
                            peer_id=peer.id,

                            timestamp=peer.created_at,

                            event='created',

                            details=(
                                f"iface={iface.name}; "
                                f"limit={getattr(peer,'data_limit_value',0)}"
                                f"{getattr(peer,'data_limit_unit','')}; "
                                f"days={peer.time_limit_days}; "
                                f"unlimited={peer.unlimited}"
                            ),
                        )
                    )
                    db.session.commit()
                    flash('Peer created & enabled', 'success')

                except Exception as e:
                    if installed:
                        _wg_disable_quiet(peer)
                        _remove_peer_quiet(peer)
                    db.session.rollback()
                    current_app.logger.exception("Peer create failed for %s: %s", form.name.data, e)
                    flash(
                        'Peer was not created: the interface could not accept it. '
                        'Bring the interface up and try again.',
                        'error',
                    )
                    return render_template('users.html', form=form)

            try:
                _shortlink_for_peer(peer)
            except Exception:
                current_app.logger.exception("shortlink create failed for local peer %s", peer.id)

            return redirect(url_for('users'))

        return render_template('users.html', form=form)

    @login_required
    def api_peer_counts():
        scope = (request.args.get('scope') or 'local').strip().lower()

        ACTIVE_WITHIN_SECONDS = 180

        def _wg_dump_all():
            try:
                p = subprocess.run(
                    ['wg', 'show', 'all', 'dump'],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                if p.returncode != 0:
                    return {}
                m = {}
                for raw in (p.stdout or '').splitlines():
                    if not raw.strip():
                        continue
                    parts = raw.split('\t')
                    if len(parts) < 9:
                        continue
                    iface = parts[0]
                    pubkey = parts[1]
                    try:
                        hs = int(parts[5] or '0')
                    except Exception:
                        hs = 0
                    m.setdefault(iface, {})[pubkey] = hs
                return m
            except Exception:
                return {}

        def _counts_peers(peer_rows, hs_map):
            now = int(time.time())
            out = {'online': 0, 'offline': 0, 'blocked': 0}
            for st, pubkey, ifname in peer_rows:
                st = (st or 'offline').lower()
                if st == 'blocked':
                    out['blocked'] += 1
                    continue

                hs = 0
                try:
                    hs = int((hs_map.get(ifname) or {}).get(pubkey) or 0)
                except Exception:
                    hs = 0

                if hs and (now - hs) <= ACTIVE_WITHIN_SECONDS:
                    out['online'] += 1
                else:
                    out['offline'] += 1
            return out

        base_rows = db.session.query(Peer.status, Peer.public_key, InterfaceConfig.name).join(InterfaceConfig)

        if scope not in ('local', 'nodes', 'total'):
            return jsonify(error="invalid_scope", allow=['local', 'nodes', 'total']), 400

        if scope == 'nodes':
            q = db.session.query(Peer.status, func.count(Peer.id)).join(InterfaceConfig)
            q = q.filter(InterfaceConfig.name.regexp_match('^n[0-9]+:'))
            rows = q.group_by(Peer.status).all()
            counts = {'online': 0, 'offline': 0, 'blocked': 0}
            for st, c in rows:
                st = (st or '').lower()
                if st in counts:
                    counts[st] = int(c)
            return jsonify(counts=counts), 200

        hs_map = _wg_dump_all()

        local_rows = base_rows.filter(~InterfaceConfig.name.regexp_match('^n[0-9]+:')).all()
        local_counts = _counts_peers(local_rows, hs_map)

        if scope == 'local':
            return jsonify(counts=local_counts), 200

        qn = db.session.query(Peer.status, func.count(Peer.id)).join(InterfaceConfig)
        qn = qn.filter(InterfaceConfig.name.regexp_match('^n[0-9]+:'))
        rowsn = qn.group_by(Peer.status).all()
        node_counts = {'online': 0, 'offline': 0, 'blocked': 0}
        for st, c in rowsn:
            st = (st or '').lower()
            if st in node_counts:
                node_counts[st] = int(c)

        counts = {
            'online':  int(local_counts['online']  + node_counts['online']),
            'offline': int(local_counts['offline'] + node_counts['offline']),
            'blocked': int(local_counts['blocked'] + node_counts['blocked']),
        }
        return jsonify(counts=counts), 200

    @require_api_key_or_login
    def peers_create():
        data = request.get_json(silent=True) or {}

        scope = (data.get('scope') or 'local').strip().lower()
        if scope not in ('local', 'node'):
            return jsonify(error='scope must be local or node'), 400

        def _as_int(v, default=None):
            try:
                if v is None or v == '':
                    return default
                return int(v)
            except Exception:
                return default

        def _as_bool(v):
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                return bool(v)
            return str(v or '').strip().lower() in ('1', 'true', 'yes', 'on')

        def _clean_keepalive(v):
            n = _as_int(v, None)
            return n if n and n > 0 else None

        def _clean_mtu(v):
            n = _as_int(v, None)
            return n if n and n > 0 else None


        if scope == 'node':
            nid = _as_int(data.get('node_id') or data.get('nodeId'), 0)
            iface_name = (
                data.get('iface_name') or
                data.get('ifaceName') or
                data.get('iface') or
                ''
            ).strip()

            if not nid or not iface_name:
                return jsonify(error='node_id and iface_name required for node scope'), 400

            n = Node.query.get_or_404(nid)

            name = (data.get('name') or '').strip() or 'peer'
            endpoint = (data.get('endpoint') or '').strip()
            allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()
            keepalive = _clean_keepalive(data.get('persistent_keepalive'))
            mtu = _clean_mtu(data.get('mtu'))
            dns = (data.get('dns') or '').strip() or None

            phone = (data.get('phone_number') or data.get('phone') or '').strip()
            tg = (data.get('telegram_id') or data.get('telegram') or '').strip()

            combined_days = _conv_time_limit(data)
            created_ts = now_ts()

            data_limit_value = _as_int(
                data.get('data_limit_value') if data.get('data_limit_value') is not None else data.get('data_limit'),
                0
            )
            data_limit_unit = (
                data.get('data_limit_unit') or
                data.get('limit_unit') or
                'Mi'
            )

            start_on_first_use = _as_bool(data.get('start_on_first_use'))
            unlimited = _as_bool(data.get('unlimited'))

            node_ifaces = {}
            remote_iface = {}
            try:
                node_ifaces = node_get(
                    n,
                    "/api/interfaces",
                    timeout=10,
                ) or {}

                if isinstance(node_ifaces, dict):
                    rows = node_ifaces.get("interfaces") or []
                else:
                    rows = node_ifaces or []

                if not isinstance(rows, list):
                    rows = []

                remote_iface = next(
                    (
                        row
                        for row in rows
                        if str((row or {}).get("name") or "") == iface_name
                    ),
                    {},
                ) or {}

            except Exception:
                current_app.logger.exception(
                    "Failed to fetch node interfaces for node_id=%s",
                    nid,
                )
                node_ifaces = {}
                remote_iface = {}

            try:
                node_post(n, f"/api/iface/{iface_name}/up", {})
            except Exception:
                pass

            try:
                priv = subprocess.check_output(
                    ['wg', 'genkey'],
                    stderr=subprocess.DEVNULL,
                    timeout=3
                ).strip().decode()

                pub = subprocess.check_output(
                    ['wg', 'pubkey'],
                    input=(priv + '\n').encode(),
                    stderr=subprocess.DEVNULL,
                    timeout=3
                ).strip().decode()
            except Exception as e:
                current_app.logger.exception("key generation failed")
                return jsonify(error="key_generation_failed", detail=str(e)), 500

            iface = ensure_node_mirror_iface(
                n, iface_name, remote_iface,
                mtu=mtu, dns=dns,
                listen_port=data.get('listen_port'),
                server_cidr=data.get('server_cidr'),
            )

            try:
                addr = node_install_peer(
                    n, iface_name, iface,
                    public_key=pub,
                    requested_address=(data.get('address') or '').strip(),
                    peer_endpoint=(data.get('peer_endpoint') or '').strip(),
                    keepalive=keepalive or 0,
                    mtu=mtu,
                    dns=dns,
                    allowed_ips=allowed_ips,
                )
            except AddressAllocationError as e:
                db.session.rollback()
                return address_error_response(e)
            except NodePeerInstallError as e:
                cleanup_failures = []
                try:
                    _rollback_node_created_peer(n, pub)
                except Exception as cleanup_exc:
                    cleanup_failures.append({
                        'scope': 'node', 'public_key': pub, 'detail': str(cleanup_exc),
                    })
                    current_app.logger.exception(
                        'Ambiguous node create cleanup failed for %s', pub
                    )
                db.session.rollback()
                current_app.logger.warning(
                    "node_create_failed node_id=%s iface=%s: %s", nid, iface_name, e.detail
                )
                return jsonify(
                    error=e.code, detail=e.detail,
                    cleanup_complete=not cleanup_failures,
                    cleanup_failures=cleanup_failures,
                ), 502 if cleanup_failures else e.status

            compensation = PeerCreateCompensation()
            compensation.register_node(n, pub)
            try:
                peer = Peer(
                    iface_id=iface.id,
                    name=name,
                    public_key=pub,
                    private_key=priv,
                    created_at=from_ts(created_ts),
                    timer_started_at=from_ts(created_ts),
                    address=addr,
                    allowed_ips=allowed_ips,
                    endpoint=endpoint or None,
                    peer_endpoint=(data.get('peer_endpoint') or '').strip() or None,
                    persistent_keepalive=keepalive,
                    mtu=mtu,
                    dns=dns,
                    status='online',
                    data_limit_value=data_limit_value,
                    data_limit_unit=data_limit_unit,
                    start_on_first_use=start_on_first_use,
                    time_limit_days=combined_days,
                    unlimited=unlimited,
                    phone_number=phone or '',
                    telegram_id=tg or '',
                )

                if (
                    peer.time_limit_days
                    and not peer.start_on_first_use
                    and not peer.unlimited
                ):
                    peer.expires_at = from_ts(
                        add_days_ts(
                            created_ts,
                            float(
                                peer.time_limit_days
                            ),
                        )
                    )
            except Exception as e:
                cleanup_failures = compensation.rollback()
                db.session.rollback()
                return jsonify(
                    error='peer_prepare_failed', detail=str(e),
                    cleanup_complete=not cleanup_failures,
                    cleanup_failures=cleanup_failures,
                ), 502 if cleanup_failures else 400

            short_token = None
            short_url = None
            try:
                db.session.add(peer)
                db.session.flush()
                try:
                    short_token, short_url = _shortlink_for_peer(peer)
                except Exception:
                    current_app.logger.exception(
                        "shortlink create failed for node peer %s",
                        getattr(peer, "id", "?")
                    )
                try:
                    log_event(
                        peer,
                        'created',
                        f"node create; node_id={nid}; iface={iface_name}; "
                        f"Limit={peer.data_limit_value}{peer.data_limit_unit or ''}; "
                        f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
                    )
                except Exception:
                    pass

                try:
                    logpanel_action(
                        "peer_create",
                        f"pid={peer.id}; scope=node; node_id={nid}; iface={iface_name}; "
                        f"unlimited={peer.unlimited}; days={peer.time_limit_days}"
                    )
                except Exception:
                    pass

                db.session.commit()

            except Exception as e:
                cleanup_failures = compensation.rollback()
                db.session.rollback()
                current_app.logger.exception("DB save failed after node peer create: %s", e)
                return jsonify(
                    error="db_save_failed", detail=str(e),
                    cleanup_complete=not cleanup_failures,
                    cleanup_failures=cleanup_failures,
                ), 502 if cleanup_failures else 500

            return jsonify(
                success=True,
                ok=True,
                scope='node',
                node_id=nid,
                iface=iface_name,
                id=peer.id,
                public_key=peer.public_key,
                shortlink=short_url or '',
                shortlink_token=short_token or '',
                address=peer.address,
                endpoint=_effective_client_endpoint(peer),
                peer_endpoint=peer.peer_endpoint or '',
                phone_number=peer.phone_number or '',
                telegram_id=peer.telegram_id or ''
            ), 200


        iface_id = data.get('iface_id')
        if not iface_id:
            return jsonify(error='iface_id required'), 400

        try:
            iface_id = int(iface_id)
        except Exception:
            return jsonify(error='invalid iface_id'), 400

        iface = db.session.get(InterfaceConfig, iface_id)
        if not iface:
            return jsonify(error='Interface not found'), 404

        try:
            priv = subprocess.check_output(
                ['wg', 'genkey'],
                stderr=subprocess.DEVNULL,
                timeout=3
            ).strip().decode()

            pub = subprocess.check_output(
                ['wg', 'pubkey'],
                input=(priv + '\n').encode(),
                stderr=subprocess.DEVNULL,
                timeout=3
            ).strip().decode()
        except Exception as e:
            current_app.logger.exception("key generation failed")
            return jsonify(error="key_generation_failed", detail=str(e)), 500

        combined_days = _conv_time_limit(data)
        created_ts = now_ts()

        phone = (data.get('phone_number') or data.get('phone') or '').strip()
        tg = (data.get('telegram_id') or data.get('telegram') or '').strip()

        allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()

        try:
            endpoint = parse_endpoint_string(data.get('endpoint'))
        except EndpointValidationError as exc:
            return jsonify(error=exc.code, detail=exc.detail, field='endpoint'), 400

        peer_endpoint = (data.get('peer_endpoint') or '').strip()
        keepalive = _clean_keepalive(data.get('persistent_keepalive'))
        mtu = _clean_mtu(data.get('mtu'))
        dns = (data.get('dns') or '').strip() or None

        data_limit_value = _as_int(
            data.get('data_limit_value') if data.get('data_limit_value') is not None else data.get('data_limit'),
            0
        )
        data_limit_unit = (
            data.get('data_limit_unit') or
            data.get('limit_unit') or
            'Mi'
        )

        peer = Peer(
            iface_id=iface.id,
            name=(data.get('name') or '').strip() or 'peer',
            public_key=pub,
            private_key=priv,
            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),
            allowed_ips=allowed_ips,
            endpoint=endpoint or None,
            peer_endpoint=peer_endpoint or None,
            persistent_keepalive=keepalive,
            mtu=mtu,
            dns=dns,
            status='online',
            data_limit_value=data_limit_value,
            data_limit_unit=data_limit_unit,
            start_on_first_use=_as_bool(data.get('start_on_first_use')),
            time_limit_days=combined_days,
            unlimited=_as_bool(data.get('unlimited')),
            phone_number=phone or '',
            telegram_id=tg or '',
        )

        if peer.time_limit_days and not peer.start_on_first_use and not peer.unlimited:
            exp_ts = add_days_ts(created_ts, float(peer.time_limit_days))
            peer.expires_at = from_ts(exp_ts)

        short_token = None
        short_url = None
        installed = False

        with interface_allocation_lock(iface):
            try:
                peer.address = allocate_peer_address(iface, requested=data.get('address'))
            except AddressAllocationError as e:
                return address_error_response(e)

            try:
                db.session.add(peer)
                db.session.flush()

                install_local_peer(peer)
                installed = True

                try:
                    log_event(
                        peer,
                        'created',
                        f"Limit={peer.data_limit_value}{peer.data_limit_unit or ''}; "
                        f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
                    )
                except Exception:
                    pass

                try:
                    logpanel_action(
                        "peer_create",
                        f"pid={peer.id}; scope=local; iface={iface.name}; "
                        f"unlimited={peer.unlimited}; days={peer.time_limit_days}"
                    )
                except Exception:
                    pass

                db.session.commit()

            except Exception as e:
                if installed:
                    _wg_disable_quiet(peer)
                    _remove_peer_quiet(peer)
                db.session.rollback()
                current_app.logger.exception("local peer create failed: %s", e)
                return jsonify(error="local_create_failed", detail=str(e)), 500

        try:
            short_token, short_url = _shortlink_for_peer(peer)
        except Exception:
            current_app.logger.exception(
                "shortlink create failed for local peer %s", getattr(peer, "id", "?")
            )

        return jsonify(
            success=True,
            ok=True,
            scope='local',
            id=peer.id,
            public_key=peer.public_key,
            shortlink=short_url or '',
            shortlink_token=short_token or '',
            address=peer.address,
            endpoint=_effective_client_endpoint(peer),
            peer_endpoint=peer.peer_endpoint or '',
            phone_number=peer.phone_number or '',
            telegram_id=peer.telegram_id or ''
        ), 200

    @require_api_key_or_login
    def panel_peers():

        try:
            server_public_ip = _public_ipv4()
        except Exception:
            server_public_ip = ''

        output = []

        interface_id = request.args.get(
            'iface_id',
            type=int,
        )

        interface_name_filter = (
            request.args.get('iface') or ''
        ).strip()

        try:
            from sqlalchemy.orm import joinedload
            query = Peer.query.options(joinedload(Peer.iface))

            if interface_id is not None:
                query = query.filter(
                    Peer.iface_id == interface_id
                )

            elif interface_name_filter:
                query = (
                    query
                    .join(InterfaceConfig)
                    .filter(
                        InterfaceConfig.name
                        == interface_name_filter
                    )
                )

            peers = query.all()

        except Exception:
            current_app.logger.exception(
                "Failed to query peers"
            )

            return jsonify(
                peers=[],
                error='peer_query_failed',
            ), 200

        subscription_context_by_peer = {}
        try:
            peer_ids = [int(peer.id) for peer in peers if getattr(peer, 'id', None)]
            if peer_ids:
                links = (
                    SubscriptionPeer.query
                    .filter(SubscriptionPeer.peer_id.in_(peer_ids))
                    .all()
                )
                subscription_cache = {}
                for link in links:
                    sub = getattr(link, 'subscription', None)
                    if sub is None:
                        sub = db.session.get(Subscription, link.subscription_id)
                    if sub is None:
                        continue
                    sid = int(sub.id)
                    if sid not in subscription_cache:
                        try:
                            shared_used = sum(int(link.peer.used_bytes_total or 0) for link in sub.links if link.peer)
                        except Exception:
                            current_app.logger.exception(
                                "Failed to aggregate subscription usage for peer list: subscription=%s",
                                sid,
                            )
                            shared_used = 0
                        subscription_cache[sid] = {
                            'subscription': sub,
                            'used_bytes': shared_used,
                            'access': subscription_access(sub, used_bytes=shared_used),
                            'expires_at_ts': _effective_expiry_ts(sub),
                            'limit_bytes': _sub_limit_bytes(sub),
                        }
                    subscription_context_by_peer[int(link.peer_id)] = subscription_cache[sid]
        except Exception:
            current_app.logger.exception(
                "Failed to resolve subscription context while listing peers"
            )
            subscription_context_by_peer = {}

        transfer_map, handshake_map = _wg_runtime_snapshot(
            [
                getattr(
                    getattr(peer, 'iface', None),
                    'name',
                    '',
                )
                for peer in peers
            ]
        )

        current_timestamp = now_ts()

        for peer in peers:
            try:
                interface = getattr(
                    peer,
                    'iface',
                    None,
                )

                database_interface_name = (
                    getattr(interface, 'name', '') or ''
                ).strip()

                runtime_key = (
                    database_interface_name,
                    peer.public_key,
                )

                subscription_context = subscription_context_by_peer.get(int(peer.id))
                subscription = (subscription_context or {}).get('subscription')
                subscription_access_state = (subscription_context or {}).get('access')
                lifecycle_state = effective_peer_state(
                    getattr(peer, 'status', None),
                    subscription_access_state,
                )

                rx_bytes, tx_bytes = transfer_map.get(
                    runtime_key,
                    (0, 0),
                )

                try:
                    rx_bytes = max(0, int(rx_bytes or 0))
                except (TypeError, ValueError):
                    rx_bytes = 0

                try:
                    tx_bytes = max(0, int(tx_bytes or 0))
                except (TypeError, ValueError):
                    tx_bytes = 0

                live_total = rx_bytes + tx_bytes

                used_bytes = _preview_peer_usage(peer, live_total)

                connection = _peer_conn_status(
                    peer,
                    live_total=live_total,
                    latest_handshake=handshake_map.get(
                        runtime_key,
                        0,
                    ),
                    allow_probe=False,
                )

                rx_mib = str(
                    round(
                        rx_bytes / 1024 / 1024,
                        2,
                    )
                )

                tx_mib = str(
                    round(
                        tx_bytes / 1024 / 1024,
                        2,
                    )
                )

                expires_timestamp = (
                    (subscription_context or {}).get('expires_at_ts')
                    if subscription_context
                    else _effective_expiry_ts(peer)
                )
                expires_at = from_ts(expires_timestamp)

                ttl_seconds = (
                    max(
                        0,
                        int(expires_timestamp) - current_timestamp,
                    )
                    if expires_timestamp
                    else None
                )

                shortlink_token = ''
                shortlink_url = ''

                try:
                    (
                        shortlink_token,
                        shortlink_url,
                    ) = _shortlink_from_peer_id(
                        peer.id
                    )


                except Exception:
                    current_app.logger.exception(
                        "Shortlink attach failed while listing peer %s",
                        getattr(peer, 'id', '?'),
                    )

                output.append({
                    'id': peer.id,

                    'shortlink': shortlink_url or '',
                    'shortlink_token': shortlink_token or '',

                    'name': peer.name,
                    'iface': database_interface_name,
                    'listen_port': getattr(
                        interface,
                        'listen_port',
                        None,
                    ),

                    'server_public_ip': server_public_ip,

                    'address': peer.address,
                    'endpoint': resolve_client_endpoint_cheap(interface, explicit=peer.endpoint),
                    'endpoint_saved': peer.endpoint or '',
                    'peer_endpoint': getattr(peer, 'peer_endpoint', None) or '',
                    'allowed_ips': peer.allowed_ips or '',

                    'persistent_keepalive':
                        peer.persistent_keepalive,

                    'mtu': peer.mtu,
                    'dns': peer.dns,

                    'status': lifecycle_state['status'],
                    'panel_status': peer.status,
                    'status_reason': lifecycle_state['reason'],
                    'status_reason_label': lifecycle_state['label'],
                    'subscription_managed': bool(subscription),
                    'subscription_id': getattr(subscription, 'id', None),
                    'subscription_name': getattr(subscription, 'name', '') or '',
                    'subscription_access': subscription_access_state or None,

                    'conn_status':
                        connection['conn_status'],

                    'connection_status':
                        connection['connection_status'],

                    'latest_handshake':
                        connection['latest_handshake'],

                    'latest_handshake_age':
                        connection['latest_handshake_age'],

                    'conn_reason':
                        connection['conn_reason'],

                    'conn_probe':
                        connection.get(
                            'conn_probe',
                            False,
                        ),

                    'data_limit': (
                        getattr(subscription, 'data_limit_value', None)
                        if subscription is not None
                        else getattr(peer, 'data_limit_value', None)
                    ),

                    'limit_unit': (
                        getattr(subscription, 'data_limit_unit', None)
                        if subscription is not None
                        else getattr(peer, 'data_limit_unit', None)
                    ),

                    'unlimited': bool(
                        getattr(
                            subscription if subscription is not None else peer,
                            'unlimited',
                            False,
                        )
                    ),

                    'time_limit_days': getattr(
                        subscription if subscription is not None else peer,
                        'time_limit_days',
                        None,
                    ),

                    'start_on_first_use': bool(
                        getattr(
                            subscription if subscription is not None else peer,
                            'start_on_first_use',
                            False,
                        )
                    ),

                    'created_at': isoz(
                        getattr(
                            peer,
                            'created_at',
                            None,
                        )
                    ),

                    'display_timezone': _panel_timezone_name(),

                    'created_at_display': _panel_display_datetime(
                        getattr(peer, 'created_at', None)
                    ),

                    'created_at_ts': to_ts(
                        getattr(
                            peer,
                            'created_at',
                            None,
                        )
                    ),

                    'first_used_at': isoz(
                        getattr(
                            peer,
                            'first_used_at',
                            None,
                        )
                    ),

                    'first_used_at_display': _panel_display_datetime(
                        getattr(peer, 'first_used_at', None)
                    ),

                    'first_used_at_ts': to_ts(
                        getattr(
                            peer,
                            'first_used_at',
                            None,
                        )
                    ),

                    'expires_at': isoz(
                        expires_at
                    ),

                    'expires_at_display': _panel_display_datetime(
                        expires_at
                    ),

                    'expires_at_ts':
                        expires_timestamp,

                    'ttl_seconds':
                        ttl_seconds,

                    'used_bytes': (
                        int((subscription_context or {}).get('used_bytes') or 0)
                        if subscription_context
                        else used_bytes
                    ),

                    'used_bytes_db':
                        used_bytes,

                    'phone_number': (
                        getattr(
                            peer,
                            'phone_number',
                            '',
                        ) or ''
                    ),

                    'telegram_id': (
                        getattr(
                            peer,
                            'telegram_id',
                            '',
                        ) or ''
                    ),

                    'rx': rx_mib,
                    'tx': tx_mib,
                })

            except Exception:
                current_app.logger.exception(
                    "Failed to serialize peer %s",
                    getattr(peer, 'id', '?'),
                )

        return jsonify(
            peers=output,
        ), 200

    @csrf.exempt
    @require_api_key_or_login
    def panel_peers_bulk():
        data = request.get_json(silent=True) or {}

        scope = (data.get('scope') or 'local').strip().lower()
        if scope not in ('local', 'node'):
            return jsonify(error="scope must be 'local' or 'node'"), 400

        if scope == 'node':
            nid = data.get('node_id') or data.get('nodeId')
            iface_name = (data.get('iface_name') or data.get('ifaceName') or '').strip()

            if not nid or not iface_name:
                return jsonify(error="node_id and iface_name are required for node scope"), 400

            try:
                nid = int(nid)
            except Exception:
                return jsonify(error="invalid node_id"), 400

            try:
                count = int(data.get('count') or data.get('bulkPeerCount') or 0)
            except Exception:
                count = 0

            if count < 1:
                return jsonify(error="count is required"), 400

            n = Node.query.get_or_404(nid)

            prefix = (data.get('prefix') or data.get('name_prefix') or 'b').strip() or 'b'

            combined_days = _conv_time_limit({
                'time_limit_days': data.get('time_limit_days'),
                'time_limit_hours': data.get('time_limit_hours'),
                'time_limit_minutes': data.get('time_limit_minutes'),
            })

            allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()
            endpoint = (data.get('endpoint') or '').strip()

            try:
                keepalive = int(data.get('persistent_keepalive') or 0)
            except Exception:
                keepalive = 0

            try:
                mtu = int(data.get('mtu')) if str(data.get('mtu') or '').strip() else None
            except Exception:
                mtu = None

            dns = (data.get('dns') or '').strip() or None

            try:
                dlim_val = int(data.get('data_limit_value') or data.get('data_limit') or 0)
            except Exception:
                dlim_val = 0

            dlim_unit = data.get('data_limit_unit') or data.get('limit_unit') or 'Mi'

            start_on_first_use = bool(data.get('start_on_first_use') or False)
            unlimited = bool(data.get('unlimited') or False)

            def _social_list(val):
                if val is None:
                    return []
                if isinstance(val, list):
                    return [str(x).strip() for x in val if str(x).strip()]
                return [s for s in (t.strip() for t in re.split(r'[\n,]+', str(val))) if s]

            phones = _social_list(
                data.get('phone_numbers') or
                data.get('phone_number') or
                data.get('phones') or
                data.get('mobile_numbers') or
                data.get('mobiles')
            )

            tgs = _social_list(
                data.get('telegram_ids') or
                data.get('telegram_id') or
                data.get('telegrams') or
                data.get('telegram')
            )

            node_ifaces = {}
            remote_iface = {}
            try:
                node_ifaces = node_get(
                    n,
                    "/api/interfaces",
                    timeout=10,
                ) or {}

                if isinstance(node_ifaces, dict):
                    rows = node_ifaces.get("interfaces") or []
                else:
                    rows = node_ifaces or []

                if not isinstance(rows, list):
                    rows = []

                remote_iface = next(
                    (
                        row
                        for row in rows
                        if str((row or {}).get("name") or "") == iface_name
                    ),
                    {},
                ) or {}

            except Exception:
                current_app.logger.exception(
                    "Failed to fetch node interfaces for node_id=%s",
                    nid,
                )
                node_ifaces = {}
                remote_iface = {}


            try:
                avail = node_get(n, f"/api/iface/{iface_name}/available_ips", timeout=10)
                if isinstance(avail, dict):
                    avail_ips = avail.get("available_ips", []) or []
                else:
                    avail_ips = avail or []

                if not isinstance(avail_ips, list):
                    avail_ips = []
            except Exception as e:
                current_app.logger.exception(
                    "node bulk available_ips failed node_id=%s iface=%s",
                    nid,
                    iface_name
                )
                return jsonify(error="node_available_ips_failed", detail=str(e)), 502

            if not avail_ips:
                return jsonify(error="No available IPs for this node interface"), 409

            requested_count = count

            try:
                node_post(n, f"/api/iface/{iface_name}/up", {})
            except Exception:
                pass

            iface = ensure_node_mirror_iface(
                n, iface_name, remote_iface,
                mtu=mtu, dns=dns,
                listen_port=data.get('listen_port'),
                server_cidr=data.get('server_cidr'),
            )

            rx = re.compile(rf'^{re.escape(prefix)}(\d+)$')
            existing = {
                m.group(1)
                for (nm,) in db.session.query(Peer.name)
                    .filter(Peer.iface_id == iface.id)
                    .all()
                for m in [rx.match(nm)] if m
            }

            next_num = 1
            if existing:
                try:
                    next_num = max(int(x) for x in existing) + 1
                except Exception:
                    next_num = 1

            created, errors = [], []
            shortlinks_by_id = {}
            pool_exhausted = False

            for i in range(count):
                pub = ''
                try:
                    priv = subprocess.check_output(
                        ['wg', 'genkey'],
                        stderr=subprocess.DEVNULL,
                        timeout=3
                    ).strip().decode()

                    pub = subprocess.check_output(
                        ['wg', 'pubkey'],
                        input=(priv + '\n').encode(),
                        stderr=subprocess.DEVNULL,
                        timeout=3
                    ).strip().decode()

                    name = f"{prefix}{next_num + i}"
                    created_ts = now_ts()

                    try:
                        addr = node_install_peer(
                            n, iface_name, iface,
                            public_key=pub,
                            peer_endpoint=(data.get('peer_endpoint') or '').strip(),
                            keepalive=keepalive or 0,
                            mtu=mtu,
                            dns=dns,
                            allowed_ips=allowed_ips,
                        )
                    except NodePeerInstallError as e:
                        if e.code == 'address_pool_exhausted':

                            pool_exhausted = True
                            break
                        raise

                    peer = Peer(
                        iface_id=iface.id,
                        name=name,
                        public_key=pub,
                        private_key=priv,
                        created_at=from_ts(created_ts),
                        timer_started_at=from_ts(created_ts),
                        address=addr,
                        allowed_ips=allowed_ips,
                        endpoint=endpoint or None,
                        peer_endpoint=(data.get('peer_endpoint') or '').strip() or None,
                        persistent_keepalive=keepalive if keepalive > 0 else None,
                        mtu=mtu,
                        dns=dns,
                        status='online',
                        data_limit_value=dlim_val,
                        data_limit_unit=dlim_unit,
                        time_limit_days=combined_days,
                        start_on_first_use=start_on_first_use,
                        unlimited=unlimited,
                        phone_number=phones[i] if i < len(phones) else '',
                        telegram_id=tgs[i] if i < len(tgs) else '',
                    )

                    if (
                        peer.time_limit_days
                        and not peer.start_on_first_use
                        and not peer.unlimited
                    ):
                        peer.expires_at = from_ts(
                            add_days_ts(
                                created_ts,
                                float(
                                    peer.time_limit_days
                                ),
                            )
                        )

                    db.session.add(peer)
                    db.session.flush()

                    try:
                        token, url = _shortlink_for_peer(peer)
                        shortlinks_by_id[int(peer.id)] = {
                            "token": token or "",
                            "url": url or "",
                        }
                    except Exception:
                        current_app.logger.exception(
                            "shortlink create failed for node bulk peer %s",
                            getattr(peer, "id", "?")
                        )

                    try:
                        db.session.add(
                            PeerEvent(
                                peer_id=peer.id,

                                timestamp=peer.created_at,

                                event='created',

                                details=(
                                    f"node bulk; "
                                    f"node_id={nid}; "
                                    f"iface={iface_name}; "
                                    f"Limit={peer.data_limit_value}"
                                    f"{peer.data_limit_unit or ''}; "
                                    f"days={peer.time_limit_days}; "
                                    f"unlimited={peer.unlimited}"
                            ),
                        )
                    )
                    except Exception:
                        pass

                    created.append(peer)

                except requests.HTTPError as e:

                    body = getattr(e.response, 'text', '') if getattr(e, 'response', None) else ''
                    current_app.logger.exception(
                        "node bulk create failed node_id=%s iface=%s index=%s",
                        nid,
                        iface_name,
                        i
                    )
                    errors.append({
                        'index': i,
                        'error': str(e),
                        'body': body[:800] if body else '',
                    })

                    if pub:
                        try:
                            node_delete(n, f"/api/peer/{pub}")
                        except Exception:
                            pass

                except NodePeerInstallError as e:

                    current_app.logger.exception(
                        "node bulk create failed node_id=%s iface=%s index=%s code=%s",
                        nid, iface_name, i, e.code
                    )
                    errors.append({
                        'index': i,
                        'error': e.code,
                        'detail': e.detail,
                    })

                    if pub:
                        try:
                            node_delete(n, f"/api/peer/{pub}")
                        except Exception:
                            pass

                except Exception as e:
                    current_app.logger.exception(
                        "node bulk create failed node_id=%s iface=%s index=%s",
                        nid,
                        iface_name,
                        i
                    )
                    errors.append({'index': i, 'error': str(e)})

                    if pub:
                        try:
                            node_delete(n, f"/api/peer/{pub}")
                        except Exception:
                            pass

            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("node bulk DB commit failed: %s", e)

                for peer in created:
                    try:
                        node_delete(n, f"/api/peer/{peer.public_key}")
                    except Exception:
                        pass

                return jsonify(error="node_bulk_db_commit_failed", detail=str(e)), 500

            for peer in created:
                try:
                    logpanel_action(
                        "peer_create",
                        f"pid={peer.id}; scope=node_bulk; node_id={nid}; iface={iface_name}; "
                        f"unlimited={peer.unlimited}; days={peer.time_limit_days}"
                    )
                except Exception:
                    pass

            return jsonify(
                ok=True,
                success=True,
                scope='node',
                node_id=nid,
                iface=iface_name,
                created=len(created),
                errors=errors,
                requested_count=requested_count,
                pool_exhausted=pool_exhausted,
                first_name=created[0].name if created else None,
                last_name=created[-1].name if created else None,
                peers=[{
                    'id': p.id,
                    'node_id': nid,
                    'name': p.name,
                    'iface': iface_name,
                    'public_key': p.public_key,
                    'address': p.address,
                    'shortlink': (shortlinks_by_id.get(int(p.id)) or {}).get('url', ''),
                    'shortlink_token': (shortlinks_by_id.get(int(p.id)) or {}).get('token', ''),
                    'phone_number': getattr(p, 'phone_number', '') or '',
                    'telegram_id': getattr(p, 'telegram_id', '') or '',
                } for p in created]
            ), 200

        iface_id = data.get('iface_id') or data.get('iface') or data.get('ifaceId')
        iface_name = (data.get('iface_name') or data.get('ifaceName') or '').strip()

        count = int(data.get('count') or data.get('bulkPeerCount') or 0)

        iface = None
        if iface_id:
            iface = db.session.get(InterfaceConfig, int(iface_id))
        elif iface_name:
            iface = db.session.query(InterfaceConfig).filter(InterfaceConfig.name == iface_name).first()

        if not iface or count < 1:
            if count < 1:
                return jsonify(error="count is required"), 400
            return jsonify(error="Interface not found"), 404

        iface_id = iface.id


        prefix = (data.get('prefix') or data.get('name_prefix') or 'b').strip() or 'b'

        combined_days = _conv_time_limit({
            'time_limit_days': data.get('time_limit_days'),
            'time_limit_hours': data.get('time_limit_hours'),
            'time_limit_minutes': data.get('time_limit_minutes'),
        })

        rx = re.compile(rf'^{re.escape(prefix)}(\d+)$')
        existing = {
            m.group(1)
            for (nm,) in db.session.query(Peer.name)
                                   .filter(Peer.iface_id == iface.id)
                                   .all()
            for m in [rx.match(nm)] if m
        }
        next_num = 1
        if existing:
            try:
                next_num = max(int(x) for x in existing) + 1
            except ValueError:
                next_num = 1

        allowed_ips = (data.get('allowed_ips') or '').strip()
        endpoint = (data.get('endpoint') or '').strip()
        keepalive = data.get('persistent_keepalive')
        mtu = data.get('mtu')
        dns = data.get('dns')
        dlim_val = data.get('data_limit_value') or 0
        dlim_unit = data.get('data_limit_unit')
        start_on_first_use = bool(data.get('start_on_first_use') or False)
        unlimited = bool(data.get('unlimited') or False)

        def _social_list(val):
            if val is None:
                return []
            if isinstance(val, list):
                return [str(x).strip() for x in val if str(x).strip()]
            return [s for s in (t.strip() for t in re.split(r'[\n,]+', str(val))) if s]

        phones = _social_list(
            data.get('phone_numbers') or
            data.get('phone_number')  or
            data.get('phones') or
            data.get('mobile_numbers') or
            data.get('mobiles')
        )
        tgs = _social_list(
            data.get('telegram_ids') or
            data.get('telegram_id')   or
            data.get('telegrams') or
            data.get('telegram')
        )

        peer_endpoint = (data.get('peer_endpoint') or '').strip()

        created, errors = [], []
        shortlinks_by_id = {}
        pool_exhausted = False

        with interface_allocation_lock(iface):
            for i in range(count):
                peer = None
                installed = False
                try:
                    addr = allocate_peer_address(iface)

                    priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
                    pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()
                    name = f"{prefix}{next_num + i}"
                    created_ts = now_ts()

                    peer = Peer(
                        iface_id=iface.id, name=name,
                        public_key=pub, private_key=priv,
                        created_at=from_ts(created_ts),
                        timer_started_at=from_ts(created_ts),
                        address=addr, allowed_ips=allowed_ips,
                        endpoint=endpoint or None,
                        peer_endpoint=peer_endpoint or None,
                        persistent_keepalive=keepalive,
                        mtu=mtu, dns=dns,
                        status='online',
                        data_limit_value=int(dlim_val) if dlim_val else 0,
                        data_limit_unit=dlim_unit,
                        time_limit_days=combined_days,
                        start_on_first_use=start_on_first_use,
                        unlimited=unlimited,
                        phone_number=phones[i] if i < len(phones) else '',
                        telegram_id=tgs[i] if i < len(tgs) else '',
                    )

                    if (
                        peer.time_limit_days
                        and not peer.start_on_first_use
                        and not peer.unlimited
                    ):
                        peer.expires_at = from_ts(
                            add_days_ts(
                                created_ts,
                                float(
                                    peer.time_limit_days
                                ),
                            )
                        )

                    db.session.add(peer)
                    db.session.flush()

                    install_local_peer(peer)
                    installed = True

                    db.session.add(
                        PeerEvent(
                            peer_id=peer.id,

                            timestamp=peer.created_at,

                            event='created',

                            details=(
                                f"bulk; "
                                f"Limit={peer.data_limit_value}"
                                f"{peer.data_limit_unit or ''}; "
                                f"days={peer.time_limit_days}; "
                                f"unlimited={peer.unlimited}"
                            ),
                        )
                    )
                    db.session.commit()
                    created.append(peer)

                except AddressPoolExhausted:
                    db.session.rollback()
                    pool_exhausted = True
                    break
                except Exception as e:
                    if installed and peer is not None:
                        _wg_disable_quiet(peer)
                        _remove_peer_quiet(peer)
                    db.session.rollback()
                    current_app.logger.exception("bulk create failed at index %s: %s", i, e)
                    errors.append({'index': i, 'error': str(e)})

        for peer in created:
            try:
                token, url = _shortlink_for_peer(peer)
                shortlinks_by_id[int(peer.id)] = {"token": token or "", "url": url or ""}
            except Exception:
                current_app.logger.exception(
                    "shortlink create failed for bulk peer %s", getattr(peer, "id", "?")
                )

            try:
                logpanel_action(
                    "peer_create",
                    f"pid={peer.id}; iface={iface.name}; unlimited={peer.unlimited}; "
                    f"days={peer.time_limit_days}"
                )
            except Exception:
                pass


        return jsonify(
            ok=True,
            scope='local',
            iface=iface.name,
            created=len(created),
            errors=errors,
            requested_count=count,
            pool_exhausted=pool_exhausted,
            first_name=created[0].name if created else None,
            last_name=created[-1].name if created else None,
            peers=[{
                'id': p.id,
                'name': p.name,
                'address': p.address,
                'shortlink': (shortlinks_by_id.get(int(p.id)) or {}).get('url', ''),
                'shortlink_token': (shortlinks_by_id.get(int(p.id)) or {}).get('token', ''),
                'phone_number': getattr(p, 'phone_number', '') or '',
                'telegram_id': getattr(p, 'telegram_id', '') or ''
            } for p in created]
        ), 200

    @csrf.exempt
    @require_api_key_or_login
    def api_enable(pid):

        p = db.session.get(Peer, pid) or abort(404)
        iface = getattr(p, 'iface', None)

        if not iface:
            return jsonify(
                success=False,
                error='peer_interface_missing',
                detail='This peer is not attached to a WireGuard interface.'
            ), 409

        if getattr(iface, 'node_id', None) is not None:
            return jsonify(
                success=False,
                error='remote_peer',
                detail='This peer belongs to a remote node.'
            ), 409

        dev = ''
        host_cidr = ''

        try:
            dev = iface_devname(iface)
            host_cidr = _host_peer(p)

            if not dev:
                raise RuntimeError(
                    'The peer interface has no valid device name.'
                )

            if not host_cidr:
                raise RuntimeError(
                    'The peer has no valid WireGuard host address.'
                )

            if not _iface_up(dev):
                _check_iface_up(iface)

            if not _iface_up(dev):
                return jsonify(
                    success=False,
                    error='interface_down',
                    detail=f"WireGuard interface '{dev}' is not running.",
                    interface=dev,
                    hint=(
                        f"Run: systemctl status "
                        f"wg-quick@{dev} --no-pager"
                    )
                ), 409

            try:
                _unblackhole(host_cidr)
            except Exception:
                current_app.logger.warning(
                    'Could not remove blackhole route for peer %s, route %s',
                    pid,
                    host_cidr,
                    exc_info=True
                )

            _wg_enable(p)
            _sync_peer(p)

            try:
                live_total = int(_wg_transfer(p) or 0)
            except Exception:
                current_app.logger.warning(
                    'Could not read WireGuard transfer value for peer %s',
                    pid,
                    exc_info=True
                )
                live_total = 0

            live_total = max(0, live_total)

            p.bytes_offset = live_total
            p.used_bytes_total = 0
            p.first_used_at = None
            p.timer_started_at = None

            try:
                time_limit_days = float(
                    getattr(p, 'time_limit_days', 0) or 0
                )
            except (TypeError, ValueError):
                time_limit_days = 0.0

            unlimited = bool(
                getattr(p, 'unlimited', False)
            )

            start_on_first_use = bool(
                getattr(p, 'start_on_first_use', False)
            )

            if unlimited:
                p.expires_at = None

            elif start_on_first_use:
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
                        'Peer enabled; timer and data reset; '
                        f'unlimited={int(unlimited)}; '
                        f'offset={live_total}'
                    )
                )

                logpanel_action(
                    'peer_enable',
                    (
                        f'pid={p.id}; '
                        f'iface={dev}; '
                        f'host_cidr={host_cidr}; '
                        f'timer_reset=1; '
                        f'data_reset=1; '
                        f'unlimited={int(unlimited)}; '
                        f'offset={live_total}'
                    )
                )
            except Exception:
                current_app.logger.warning(
                    'Peer %s was enabled, but enable logging failed',
                    pid,
                    exc_info=True
                )

            return jsonify(
                success=True,
                ok=True,
                message='Peer enabled. Timer and data usage were reset.',
                status='online',
                interface=dev,
                host_cidr=host_cidr,
                timer_reset=True,
                data_reset=True,
                unlimited=unlimited,
                used_bytes_total=0,
                bytes_offset=live_total
            )

        except RuntimeError as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Peer enable failed for peer %s on interface %s',
                pid,
                dev or 'unknown'
            )

            return jsonify(
                success=False,
                error='peer_enable_failed',
                detail=str(exc),
                interface=dev,
                host_cidr=host_cidr,
                hint=(
                    f"Run: wg show {dev}; "
                    f"ip route show {host_cidr}; "
                    f"systemctl status wg-quick@{dev} --no-pager"
                ) if dev else ''
            ), 409

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Unexpected enable failure for peer %s',
                pid
            )

            return jsonify(
                success=False,
                error='peer_enable_unexpected_error',
                detail=str(exc),
                interface=dev,
                host_cidr=host_cidr
            ), 500

    @require_api_key
    def reset_data(pid):
        p = db.session.get(Peer, pid) or abort(404)

        try:
            current = int(_wg_transfer(p) or 0)
        except Exception:
            current = 0

        try:
            p.bytes_offset = max(0, current)
            p.used_bytes_total = 0

            db.session.commit()

            try:
                log_event(
                    p,
                    'reset_data',
                    (
                        f'Traffic usage reset; runtime offset={current}; '
                        f'status preserved as {p.status}'
                    )
                )
                logpanel_action(
                    'peer_reset_data',
                    (
                        f'pid={p.id}; offset={current}; '
                        f'status_preserved={p.status}; timer_preserved=1'
                    )
                )
            except Exception:
                pass

            return jsonify(
                success=True,
                status=p.status,
                timer_preserved=True,
                data_reset=True
            )

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Data reset failed for peer %s',
                pid
            )

            return jsonify(
                success=False,
                error='reset_data_failed',
                detail=str(exc)
            ), 500

    @require_api_key
    def api_reset_timer(pid):
        p = db.session.get(Peer, pid) or abort(404)

        try:
            shared_response = _linked_subscription_timer_response(
                p,
                'peer_reset_timer_subscription',
            )
            if shared_response is not None:
                return shared_response
        except Exception as exc:
            db.session.rollback()
            current_app.logger.exception(
                'Shared subscription timer reset failed for peer %s',
                pid,
            )
            return jsonify(
                success=False,
                error='subscription_timer_reset_failed',
                detail=str(exc),
            ), 500

        iface = getattr(p, 'iface', None)
        if not iface:
            return jsonify(
                success=False,
                error='peer_interface_missing',
                detail='This peer is not attached to a WireGuard interface.'
            ), 409

        original_bytes_offset = int(
            getattr(p, 'bytes_offset', 0) or 0
        )
        original_used_total = int(
            getattr(p, 'used_bytes_total', 0) or 0
        )

        try:
            time_limit = float(
                getattr(p, 'time_limit_days', 0) or 0
            )
        except (TypeError, ValueError):
            time_limit = 0.0

        try:
            p.first_used_at = None
            p.timer_started_at = None

            if getattr(p, 'unlimited', False) or time_limit <= 0:
                p.expires_at = None
                detail = 'Timer cleared'

            elif getattr(p, 'start_on_first_use', False):
                p.expires_at = None
                detail = 'Timer cleared; timer will start on first use'

            else:
                _start_timer_cycle(p)
                detail = f'Timer restarted for {time_limit:g} days'

            is_node_peer = (
                getattr(iface, 'node_id', None) is not None
                or ':' in str(getattr(iface, 'name', '') or '')
            )

            if is_node_peer:
                node = db.session.get(
                    Node,
                    getattr(iface, 'node_id', None)
                )

                if not node:
                    return jsonify(
                        success=False,
                        error='node_not_found',
                        detail='The node for this peer was not found.'
                    ), 404

                node_post(
                    node,
                    f'/api/peer/{p.public_key}/enable',
                    {
                        'host_cidr': _host_peer(p),
                        'reset_timer': False,
                        'reset_data': False,
                        'preserve_usage': True,
                    },
                    timeout=15
                )

            else:
                dev = iface_devname(iface)

                if not _iface_up(dev):
                    _check_iface_up(iface)

                if not _iface_up(dev):
                    raise RuntimeError(
                        f"WireGuard interface '{dev}' is not running."
                    )

                _wg_enable(p)
                _sync_peer(p)

            p.status = 'online'
            p.bytes_offset = original_bytes_offset
            p.used_bytes_total = original_used_total

            db.session.commit()

            try:
                log_event(
                    p,
                    'reset_timer',
                    (
                        f'{detail}; peer enabled; '
                        f'data usage preserved at {original_used_total} bytes'
                    )
                )
                logpanel_action(
                    'peer_reset_timer',
                    (
                        f'pid={p.id}; {detail}; '
                        f'data_preserved=1; used={original_used_total}; '
                        f'offset={original_bytes_offset}'
                    )
                )
            except Exception:
                pass

            return jsonify(
                success=True,
                status=p.status,
                timer_reset=True,
                data_preserved=True,
                used_bytes_total=original_used_total
            )

        except requests.HTTPError as exc:
            db.session.rollback()

            response = getattr(exc, 'response', None)
            status_code = getattr(response, 'status_code', None)
            response_text = getattr(response, 'text', '') or ''

            current_app.logger.exception(
                'Node timer reset enable failed for peer %s',
                pid
            )

            return jsonify(
                success=False,
                error='node_enable_failed',
                detail=str(exc),
                node_status=status_code,
                node_body=response_text[:800]
            ), 502

        except subprocess.CalledProcessError as exc:
            db.session.rollback()

            try:
                dev = iface_devname(iface)
            except Exception:
                dev = ''

            current_app.logger.exception(
                'Timer reset enable failed for peer %s',
                pid
            )

            return jsonify(
                success=False,
                error='wg_failed',
                detail='The timer was not reset because the peer could not be enabled.',
                interface=dev,
                returncode=getattr(exc, 'returncode', None),
                data_preserved=True
            ), 409

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Timer reset failed for peer %s',
                pid
            )

            return jsonify(
                success=False,
                error='reset_timer_failed',
                detail=str(exc),
                data_preserved=True
            ), 500

    @csrf.exempt
    @require_api_key_or_login
    def api_disable(pid):
        p = db.session.get(Peer, pid) or abort(404)
        _wg_disable(p)
        p.status = 'offline'; db.session.commit(); log_event(p, 'disabled')
        logpanel_action("peer_disable", f"pid={p.id}; iface={p.iface}")
        return jsonify(success=True)

    @csrf.exempt
    @require_api_key_or_login
    def api_edit(pid):
        data = request.get_json(silent=True) or {}

        if not isinstance(data, dict):
            return jsonify(
                success=False,
                ok=False,
                error='invalid_payload',
                detail='The request body must be a JSON object.',
            ), 400

        p = db.session.get(Peer, pid) or abort(404)

        original = {
            'name': p.name,
            'address': p.address,
            'allowed_ips': p.allowed_ips,
            'endpoint': p.endpoint,
            'peer_endpoint': p.peer_endpoint,
            'persistent_keepalive': p.persistent_keepalive,
            'mtu': p.mtu,
            'dns': p.dns,
            'data_limit_value': p.data_limit_value,
            'data_limit_unit': p.data_limit_unit,
            'time_limit_days': p.time_limit_days,
            'start_on_first_use': p.start_on_first_use,
            'unlimited': p.unlimited,
            'phone_number': p.phone_number,
            'telegram_id': p.telegram_id,
        }


        if (
            'time_limit_days' in data
            or 'time_limit_hours' in data
        ):
            data['time_limit_days'] = _conv_time_limit(
                data
            )

            data.pop(
                'time_limit_hours',
                None,
            )

        for field in (
            'name',
            'allowed_ips',
            'endpoint',
            'peer_endpoint',
            'dns',
            'phone_number',
            'telegram_id',
        ):
            if field in data:
                value = data.get(field)

                data[field] = (
                    str(value).strip()
                    if value is not None
                    else ''
                )

        if 'endpoint' in data:
            try:
                data['endpoint'] = parse_endpoint_string(
                    data['endpoint']
                )

            except EndpointValidationError as exc:
                return jsonify(
                    success=False,
                    ok=False,
                    error=exc.code,
                    detail=exc.detail,
                    field='endpoint',
                ), 400

        for field in (
            'persistent_keepalive',
            'mtu',
        ):
            if field in data:
                raw = data.get(field)

                if raw in (
                    '',
                    None,
                ):
                    data[field] = None

                else:
                    try:
                        data[field] = int(raw)

                    except Exception:
                        return jsonify(
                            success=False,
                            ok=False,
                            error='invalid_number',
                            detail=(
                                f'{field} must be a number.'
                            ),
                        ), 400


        if 'data_limit_value' in data:
            raw = data.get(
                'data_limit_value'
            )

            try:
                data[
                    'data_limit_value'
                ] = (
                    int(float(raw))
                    if str(raw or '').strip()
                    else 0
                )

            except Exception:
                return jsonify(
                    success=False,
                    ok=False,
                    error='invalid_data_limit',
                    detail='Traffic limit must be numeric.',
                ), 400

        for field in (
            'start_on_first_use',
            'unlimited',
        ):
            if field in data:
                value = data.get(field)

                if isinstance(
                    value,
                    bool,
                ):
                    data[field] = value

                else:
                    data[field] = (
                        str(value)
                        .strip()
                        .lower()
                        in (
                            '1',
                            'true',
                            'yes',
                            'on',
                        )
                    )

        if 'address' in data:
            requested_address = str(
                data.get('address')
                or ''
            ).strip()

            if not requested_address:
                return jsonify(
                    success=False,
                    ok=False,
                    error='invalid_address',
                    detail=(
                        'address may not be empty; '
                        'omit the field to leave it unchanged.'
                    ),
                ), 400

            if (
                requested_address
                != str(
                    original.get('address')
                    or ''
                ).strip()
            ):
                try:
                    data['address'] = (
                        allocate_peer_address(
                            p.iface,
                            requested=requested_address,
                            exclude_peer_id=p.id,
                            exclude_address=p.address,
                        )
                    )

                except AddressAllocationError as exc:
                    return address_error_response(
                        exc
                    )

            else:
                data['address'] = (
                    original.get('address')
                )

        if 'peer_endpoint' in data:
            submitted_peer_endpoint = str(
                data.get('peer_endpoint')
                or ''
            ).strip()

            original_peer_endpoint = str(
                original.get('peer_endpoint')
                or ''
            ).strip()

            if (
                submitted_peer_endpoint
                and submitted_peer_endpoint
                != original_peer_endpoint
            ):
                try:
                    data['peer_endpoint'] = _wireguard_endpoint(
                        submitted_peer_endpoint
                    )

                except Exception as exc:
                    return jsonify(
                    success=False,
                    ok=False,
                    error='invalid_fixed_endpoint',
                    detail=str(exc),
                    field='peer_endpoint',
                ), 400

            else:
                data['peer_endpoint'] = (
                submitted_peer_endpoint
                if submitted_peer_endpoint != original_peer_endpoint
                else original_peer_endpoint
            )

        supported_fields = (
            'name',
            'address',
            'allowed_ips',
            'endpoint',
            'peer_endpoint',
            'persistent_keepalive',
            'mtu',
            'dns',
            'data_limit_value',
            'data_limit_unit',
            'time_limit_days',
            'start_on_first_use',
            'unlimited',
            'phone_number',
            'telegram_id',
        )

        changed = []

        for field in supported_fields:
            if field not in data:
                continue

            new_value = data[field]
            old_value = original.get(
                field
            )

            if field in (
                'endpoint',
                'peer_endpoint',
                'dns',
                'phone_number',
                'telegram_id',
                'allowed_ips',
                'name',
            ):
                old_cmp = str(
                    old_value or ''
                ).strip()

                new_cmp = str(
                    new_value or ''
                ).strip()

            elif field in (
                'persistent_keepalive',
                'mtu',
            ):
                old_cmp = (
                    int(old_value)
                    if old_value not in (
                        None,
                        '',
                    )
                    else None
                )

                new_cmp = (
                    int(new_value)
                    if new_value not in (
                        None,
                        '',
                    )
                    else None
                )

            else:
                old_cmp = old_value
                new_cmp = new_value

            if old_cmp == new_cmp:
                continue

            setattr(
                p,
                field,
                new_value,
            )

            changed.append(
                field
            )

        if not changed:
            return jsonify(
                success=True,
                ok=True,
                changed=[],
                message='No changes were necessary.',
            ), 200

        if any(
            field in changed
            for field in (
                'time_limit_days',
                'start_on_first_use',
                'unlimited',
            )
        ):
            if getattr(
                p,
                'unlimited',
                False,
            ):
                _clear_timer_cycle(p)

            elif getattr(
                p,
                'time_limit_days',
                None,
            ):
                if (
                    getattr(
                        p,
                        'start_on_first_use',
                        False,
                    )
                    and not getattr(
                        p,
                        'first_used_at',
                        None,
                    )
                ):
                    _clear_timer_cycle(p)

                else:
                    if getattr(p, 'start_on_first_use', False):
                        p.timer_started_at = getattr(p, 'first_used_at', None)
                        _sync_effective_expiry(p)
                    else:
                        _start_timer_cycle(p)

            else:
                _clear_timer_cycle(p)

        external_fields = {
            'address',
            'peer_endpoint',
            'persistent_keepalive',
        }

        external_changed = bool(
            external_fields.intersection(
                changed
            )
        )

        external_attempted = False

        try:
            db.session.flush()

            if external_changed:
                external_attempted = True

                reapply_peer_external(
                    p
                )

            db.session.commit()

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                'Peer %s edit failed; '
                'restoring previous state',
                pid,
            )

            recovery_error = None

            if external_attempted:
                previous = db.session.get(
                    Peer,
                    pid,
                )

                if previous is not None:
                    try:
                        reapply_peer_external(
                            previous
                        )

                    except Exception as restore_exc:
                        recovery_error = str(
                            restore_exc
                        )

                        current_app.logger.exception(
                            'Could not restore peer %s '
                            'after failed edit',
                            pid,
                        )

            if recovery_error:
                return jsonify(
                    success=False,
                    ok=False,
                    error='peer_edit_recovery_failed',
                    detail=str(exc),
                    recovery_detail=recovery_error,
                    saved_fields=[],
                    recoverable=True,
                ), 502

            if isinstance(
                exc,
                IntegrityError,
            ):
                status = 409

            elif external_attempted:
                status = 502

            else:
                status = 500

            return jsonify(
                success=False,
                ok=False,
                error=(
                    'peer_reapply_failed'
                    if external_attempted
                    else 'peer_edit_failed'
                ),
                detail=str(exc),
                saved_fields=[],
                rolled_back=True,
            ), status

        try:
            log_event(
                p,
                'edited',
                (
                    'Fields: '
                    + ', '.join(
                        changed
                    )
                ),
            )

            logpanel_action(
                'peer_edit',
                (
                    f'pid={p.id}; fields='
                    + ', '.join(
                        changed
                    )
                ),
            )

        except Exception:
            current_app.logger.warning(
                'Peer %s was edited but '
                'audit logging failed',
                pid,
                exc_info=True,
            )

        return jsonify(
            success=True,
            ok=True,
            changed=changed,
            runtime_reapplied=(
                external_changed
            ),
        )

    @csrf.exempt
    @require_api_key_or_login
    def api_edit_node_peer(nid, pub):
        Node.query.get_or_404(nid)

        pub = (pub or '').strip()

        if not pub:
            return jsonify(
                success=False,
                ok=False,
                error='peer_not_found',
                detail='Peer public key is required.',
            ), 404

        p = (
            db.session.query(Peer)
            .join(
                InterfaceConfig,
                Peer.iface_id == InterfaceConfig.id,
            )
            .filter(Peer.public_key == pub)
            .filter(
                or_(
                    InterfaceConfig.name.like(f'n{nid}:%'),
                    InterfaceConfig.node_id == nid,
                )
            )
            .first()
        )

        if p is None:
            return jsonify(
                success=False,
                ok=False,
                error='peer_not_found',
                detail='No peer with that public key exists on this node.',
            ), 404

        return api_edit(p.id)

    @csrf.exempt
    @require_api_key_or_login
    def api_delete(pid):
        p = db.session.get(Peer, pid) or abort(404)

        try:
            remove_peer_everywhere(p)
        except PeerRemovalError as e:
            current_app.logger.error(
                "peer delete failed at %s stage for pid=%s: %s",
                e.phase,
                pid,
                e,
            )
            return peer_removal_response(
                e,
                peer_id=pid,
            )

        logpanel_action(
            "peer_delete",
            f"pid={pid}",
        )

        return jsonify(
            success=True,
            ok=True,
        )

    @login_required
    def peer_logs(pid):
        p = db.session.get(Peer, pid) or abort(404)

        rows = (
            PeerEvent.query
            .filter_by(peer_id=pid)
            .order_by(PeerEvent.timestamp.desc())
            .limit(500)
            .all()
        )

        def event_level(event_name):
            name = str(event_name or '').strip().lower()

            if any(word in name for word in (
                'error',
                'failed',
                'failure',
            )):
                return 'error'

            if any(word in name for word in (
                'blocked',
                'expired',
                'limit',
                'disabled',
                'warning',
            )):
                return 'warning'

            return 'info'

        logs = []

        for event in rows:
            timestamp = isoz(
                getattr(
                    event,
                    'timestamp',
                    None,
                )
            )

            event_name = str(
                getattr(
                    event,
                    'event',
                    '',
                )
                or ''
            ).strip()

            details = str(
                getattr(
                    event,
                    'details',
                    '',
                )
                or ''
            ).strip()

            logs.append({
                'time': timestamp,
                'ts': timestamp,
                'timestamp': timestamp,
                'time_display': _panel_display_datetime(
                    getattr(event, 'timestamp', None)
                ),

                'event': event_name,
                'details': details,

                'level': event_level(
                    event_name
                ),

                'text': (
                    details
                    or event_name
                    or 'Peer event'
                ),
            })

        try:
            runtime = _subscription_peer_runtime(
                p
            )
        except Exception:
            current_app.logger.debug(
                'Could not load live runtime for peer log pid=%s',
                pid,
                exc_info=True,
            )

            runtime = {
                'connected': False,
                'conn_status': 'offline',
                'connection_status': 'disconnected',
                'connection_label': 'Disconnected',
                'latest_handshake': 0,
                'latest_handshake_age': None,
                'last_activity_at': None,
                'runtime_available': False,
            }

        iface = getattr(
            p,
            'iface',
            None,
        )

        iface_raw = str(
            getattr(
                iface,
                'name',
                '',
            )
            or ''
        ).strip()

        node = (
            getattr(
                iface,
                'node',
                None,
            )
            if iface
            else None
        )

        is_node = bool(
            iface
            and (
                getattr(
                    iface,
                    'node_id',
                    None,
                )
                is not None
                or re.match(
                    r'^n\d+:',
                    iface_raw,
                )
            )
        )

        interface_name = (
            iface_raw.split(
                ':',
                1,
            )[1]
            if (
                is_node
                and ':' in iface_raw
            )
            else iface_raw
        )

        return jsonify(
            ok=True,

            peer={
                'id': p.id,
                'name': p.name or '',
                'display_timezone': _panel_timezone_name(),

                'created_at': isoz(
                    getattr(
                        p,
                        'created_at',
                        None,
                    )
                ),

                'created_at_ts': to_ts(getattr(p,'created_at',None,)),

                'created_at_display': _panel_display_datetime(
                    getattr(p, 'created_at', None)
                ),

                'first_used_at': isoz(getattr(p,'first_used_at',None,)),

                'first_used_at_ts': to_ts(getattr(p,'first_used_at',None,)),

                'first_used_at_display': _panel_display_datetime(
                    getattr(p, 'first_used_at', None)
                ),

                'expires_at': isoz(from_ts(_effective_expiry_ts(p))),

                'expires_at_display': _panel_display_datetime(
                    from_ts(_effective_expiry_ts(p))
                ),

                'expires_at_ts': _effective_expiry_ts(p),

                'ttl_seconds': (
                    max(0, _effective_expiry_ts(p) - now_ts())
                    if _effective_expiry_ts(p)
                    else None
                ),

                'time_limit_days': getattr(p, 'time_limit_days', None),

                'start_on_first_use': bool(
                    getattr(p, 'start_on_first_use', False)
                ),

                'panel_status': (p.status or 'offline'),

                'scope': (
                    'node'
                    if is_node
                    else 'local'
                ),

                'node_id': (
                    getattr(
                        iface,
                        'node_id',
                        None,
                    )
                    if iface
                    else None
                ),

                'node_name': (
                    getattr(
                        node,
                        'name',
                        '',
                    )
                    or ''
                ),

                'iface': interface_name,

                'connected': bool(
                    runtime.get(
                        'connected'
                    )
                ),

                'connection_label': (
                    runtime.get(
                        'connection_label'
                    )
                    or 'Disconnected'
                ),

                'latest_handshake': int(
                    runtime.get(
                        'latest_handshake'
                    )
                    or 0
                ),

                'latest_handshake_age': (
                    runtime.get(
                        'latest_handshake_age'
                    )
                ),

                'last_activity_at': (
                    runtime.get(
                        'last_activity_at'
                    )
                ),
            },

            runtime=runtime,

            logs=logs,
        )

    return {
        'api_shortlink': api_shortlink,
        'api_shortlink_by_public_key': api_shortlink_by_public_key,
        'user_peer_page': user_peer_page,
        'user_peer': user_peer,
        'userpeer_config': userpeer_config,
        'api_peer_config_by_public_key': api_peer_config_by_public_key,
        'api_peer_config_qr_by_public_key': api_peer_config_qr_by_public_key,
        'peer_clear_total': peer_clear_total,
        'clear_peer_logs': clear_peer_logs,
        'users': users,
        'api_peer_counts': api_peer_counts,
        'peers_create': peers_create,
        'panel_peers': panel_peers,
        'panel_peers_bulk': panel_peers_bulk,
        'api_enable': api_enable,
        'reset_data': reset_data,
        'api_reset_timer': api_reset_timer,
        'api_disable': api_disable,
        'api_edit': api_edit,
        'api_edit_node_peer': api_edit_node_peer,
        'api_delete': api_delete,
        'peer_logs': peer_logs,
    }
