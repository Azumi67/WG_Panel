def build_routes(*,
    EndpointApplyError,
    EndpointValidationError,
    IFACE_LOG_DIR,
    InterfaceConfig,
    Path,
    Peer,
    SubscriptionPeer,
    _apply_endpoint_default,
    _apply_request_flags,
    _available_ips,
    _check_iface_up,
    _copy_local_iface_from_parsed,
    _delete_shortlinks_for_peer_ids,
    _derive_wg_public_key,
    _egress_interface,
    _endpoint_default_payload,
    _iface_down,
    _iface_log,
    _iface_up,
    _ifacelog_path,
    _last_cleared,
    _load_retention,
    _local_iface_or_error,
    _may_autoclear,
    _panel_display_datetime,
    _panel_timezone_name,
    _private_networks,
    _sub_bool,
    _sync_all_subscription_peers,
    _wg_disable,
    _wg_firewall_rules,
    _wg_peer_keys,
    abort,
    app,
    csrf,
    current_app,
    db,
    find_iface,
    glob,
    iface_devname,
    iface_endpoint_override,
    ipaddress,
    json,
    jsonify,
    login_required,
    logpanel_action,
    now_ts,
    os,
    parse_endpoint_override,
    re,
    request,
    require_api_key_or_login,
    shlex,
    subprocess,
    tempfile,
):

    @login_required
    def iface_status(iid):
        ret = _load_retention()["iface"]
        _may_autoclear(Path(_ifacelog_path(iid)), ret, persist_key="iface")
        iface = db.session.get(InterfaceConfig, iid) or abort(404)
        try:
            dev = iface_devname(iface)
        except Exception as e:
            current_app.logger.exception("iface_devname failed: %s", e)
            return jsonify(error="bad_iface_name"), 500

        try:
            up = _iface_up(dev)
            return jsonify({'is_up': up, 'name': iface.name, 'dev': dev})
        except Exception as e:
            current_app.logger.exception("iface status failed: %s", e)
            return jsonify(error="iface_status_failed"), 500

    @login_required
    def iface_logs(iid):
        p = _ifacelog_path(iid)

        if request.method == 'DELETE':
            try:
                Path(IFACE_LOG_DIR).mkdir(parents=True, exist_ok=True)
                if os.path.exists(p):
                    open(p, 'w').close()
                try:
                    _last_cleared("iface")
                except Exception:
                    pass
            except Exception:
                current_app.logger.exception("Failed to clear iface log %s", iid)
                return jsonify(ok=False, error="clear_failed"), 500

            return jsonify(ok=True)


        ret = _load_retention()["iface"]
        _may_autoclear(Path(p), ret, persist_key="iface")

        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()[-20000:]
        except Exception:
            txt = ''

        if not txt.strip():
            iface = db.session.get(InterfaceConfig, iid) or abort(404)
            name = iface_devname(iface)

            def _run(cmd):
                try:
                    out = subprocess.check_output(
                        shlex.split(cmd),
                        stderr=subprocess.DEVNULL,
                        timeout=6
                    ).decode('utf-8', 'ignore')
                    return out
                except Exception:
                    return ''

            unit = f'wg-quick@{name}.service'
            txt = _run(f'journalctl -u {unit} -n 300 --no-pager --since "2 days ago"')
            if not txt.strip():

                k = _run('journalctl -k -n 300 --no-pager')
                txt = '\n'.join(
                    ln for ln in k.splitlines()
                    if ('wg' in ln.lower() or name in ln)
                )

        out = []
        for line in txt.splitlines():
            s = line.strip()
            ts = ''; msg = s; lvl = 'info'
            if s.startswith('[') and ']' in s:
                br = s.find(']')
                ts = s[1:br].strip()
                msg = s[br+1:].strip()
            out.append({'ts': ts, 'level': lvl, 'text': msg})

        for row in out:
            if row.get('ts'):
                row['time_display'] = _panel_display_datetime(
                    row['ts'],
                    seconds=True,
                )

        return jsonify({
            'logs': out,
            'display_timezone': _panel_timezone_name(),
            'server_epoch': now_ts(),
        })

    @require_api_key_or_login
    def iface_settings(iid):
        iface = db.session.get(InterfaceConfig, iid) or abort(404)

        if (
            getattr(iface, 'node_id', None) is not None
            or ':' in (getattr(iface, 'name', '') or '')
        ):
            return jsonify(
                ok=False,
                error='remote_interface',
                detail=(
                    'This interface belongs to a remote node. '
                    'Use the node interface API instead.'
                ),
            ), 400

        dev = iface_devname(iface)

        if request.method == 'GET':
            return jsonify(
                ok=True,
                id=iface.id,
                name=iface.name,
                path=iface.path,
                address=iface.address,
                listen_port=iface.listen_port,
                dns=iface.dns,
                mtu=iface.mtu,
                is_up=_iface_up(dev),
                **{
                    k: v for k, v in _endpoint_default_payload(iface).items()
                    if k not in ('iface_id', 'iface', 'listen_port', 'scope')
                },
            )

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify(
                ok=False,
                error='invalid_payload',
                detail='The request body must be a JSON object.',
            ), 400

        def optional_int(value, field, minimum, maximum):

            if value is None:
                return None

            if isinstance(value, str):
                value = value.strip()
                if not value:
                    return None

            try:
                number = int(value)
            except (TypeError, ValueError):
                raise ValueError(
                    f'{field} must be an integer between '
                    f'{minimum} and {maximum}.'
                )

            if not minimum <= number <= maximum:
                raise ValueError(
                    f'{field} must be between {minimum} and {maximum}.'
                )

            return number

        try:
            updates = {}

            if 'dns' in data:
                dns_value = data.get('dns')
                updates['dns'] = (
                    str(dns_value).strip()
                    if dns_value not in (None, '')
                    else None
                )

            if 'mtu' in data:
                updates['mtu'] = optional_int(
                    data.get('mtu'),
                    'MTU',
                    576,
                    9000,
                )

            if 'listen_port' in data:
                listen_port = optional_int(
                    data.get('listen_port'),
                    'Listen port',
                    1,
                    65535,
                )

                if listen_port is None:
                    return jsonify(
                        ok=False,
                        error='listen_port_required',
                        detail='Listen port cannot be empty.',
                    ), 400

                updates['listen_port'] = listen_port

        except ValueError as exc:
            return jsonify(
                ok=False,
                error='invalid_interface_setting',
                detail=str(exc),
            ), 400

        if not updates:
            return jsonify(
                ok=True,
                changed=False,
                message='No interface settings changed.',
                interface={
                    'id': iface.id,
                    'name': iface.name,
                    'listen_port': iface.listen_port,
                    'dns': iface.dns,
                    'mtu': iface.mtu,
                    'is_up': _iface_up(dev),
                },
            )

        is_up = _iface_up(dev)

        if is_up and 'listen_port' in updates:
            result = subprocess.run(
                [
                    'wg',
                    'set',
                    dev,
                    'listen-port',
                    str(updates['listen_port']),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=12,
                check=False,
            )

            if result.returncode != 0:
                detail = (
                    result.stderr
                    or result.stdout
                    or 'wg set listen-port failed.'
                ).strip()

                _iface_log(
                    iid,
                    f'Failed to set ListenPort on {dev}: {detail}',
                )

                return jsonify(
                    ok=False,
                    error='wg_set_listen_port_failed',
                    detail=detail,
                    interface=dev,
                    is_up=True,
                ), 409

        if is_up and 'mtu' in updates and updates['mtu'] is not None:
            result = subprocess.run(
                [
                    'ip',
                    'link',
                    'set',
                    'dev',
                    dev,
                    'mtu',
                    str(updates['mtu']),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=12,
                check=False,
            )

            if result.returncode != 0:
                detail = (
                    result.stderr
                    or result.stdout
                    or 'ip link set MTU failed.'
                ).strip()

                _iface_log(
                    iid,
                    f'Failed to set MTU on {dev}: {detail}',
                )

                return jsonify(
                    ok=False,
                    error='ip_set_mtu_failed',
                    detail=detail,
                    interface=dev,
                    is_up=True,
                ), 409

        old_values = {
            key: getattr(iface, key, None)
            for key in updates
        }

        try:
            for key, value in updates.items():
                setattr(iface, key, value)

            db.session.flush()

            conf_path = Path(iface.path) if iface.path else None

            if conf_path and conf_path.is_file():
                original = conf_path.read_text(
                    encoding='utf-8',
                    errors='replace',
                )

                lines = original.splitlines(keepends=True)
                output = []
                in_interface = False
                found_interface = False

                managed_keys = {
                    'dns': 'DNS',
                    'mtu': 'MTU',
                    'listenport': 'ListenPort',
                }

                for raw in lines:
                    stripped = raw.strip()

                    if stripped.startswith('[') and stripped.endswith(']'):
                        if in_interface:

                            if 'mtu' in updates and updates['mtu'] is not None:
                                output.append(f"MTU = {updates['mtu']}\n")
                            if 'listen_port' in updates:
                                output.append(
                                    f"ListenPort = {updates['listen_port']}\n"
                                )

                        in_interface = (
                            stripped[1:-1].strip().lower()
                            == 'interface'
                        )
                        found_interface = found_interface or in_interface
                        output.append(raw)
                        continue

                    if in_interface and '=' in stripped:
                        key = stripped.split('=', 1)[0].strip().lower()

                        remove = (
                            (key == 'dns' and 'dns' in updates)
                            or (key == 'mtu' and 'mtu' in updates)
                            or (
                                key == 'listenport'
                                and 'listen_port' in updates
                            )
                        )

                        if remove:
                            continue

                    output.append(raw)

                if in_interface:

                    if 'mtu' in updates and updates['mtu'] is not None:
                        output.append(f"MTU = {updates['mtu']}\n")
                    if 'listen_port' in updates:
                        output.append(
                            f"ListenPort = {updates['listen_port']}\n"
                        )

                if not found_interface:
                    raise RuntimeError(
                        f'{conf_path} does not contain an [Interface] section.'
                    )

                new_text = ''.join(output)

                fd, temp_name = tempfile.mkstemp(
                    prefix=f'.{conf_path.name}.',
                    dir=str(conf_path.parent),
                    text=True,
                )

                try:
                    with os.fdopen(
                        fd,
                        'w',
                        encoding='utf-8',
                    ) as handle:
                        handle.write(new_text)
                        handle.flush()
                        os.fsync(handle.fileno())

                    os.chmod(temp_name, 0o600)
                    os.replace(temp_name, conf_path)

                finally:
                    try:
                        if os.path.exists(temp_name):
                            os.unlink(temp_name)
                    except OSError:
                        pass

            db.session.commit()

        except Exception as exc:
            db.session.rollback()

            try:
                if is_up and 'listen_port' in old_values:
                    old_port = old_values.get('listen_port')
                    if old_port:
                        subprocess.run(
                            [
                                'wg',
                                'set',
                                dev,
                                'listen-port',
                                str(old_port),
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=8,
                            check=False,
                        )

                if is_up and 'mtu' in old_values:
                    old_mtu = old_values.get('mtu')
                    if old_mtu:
                        subprocess.run(
                            [
                                'ip',
                                'link',
                                'set',
                                'dev',
                                dev,
                                'mtu',
                                str(old_mtu),
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=8,
                            check=False,
                        )
            except Exception:
                pass

            current_app.logger.exception(
                'Failed to save interface settings: '
                'interface_id=%s device=%s',
                iid,
                dev,
            )

            _iface_log(
                iid,
                f'Interface settings save failed: {exc}',
            )

            return jsonify(
                ok=False,
                error='interface_save_failed',
                detail=str(exc),
                interface=dev,
                is_up=_iface_up(dev),
            ), 500

        _iface_log(
            iid,
            (
                'Interface settings saved: '
                + ', '.join(
                    f'{key}={value!r}'
                    for key, value in updates.items()
                )
            ),
        )

        return jsonify(
            ok=True,
            changed=True,
            message='Interface settings saved.',
            interface={
                'id': iface.id,
                'name': iface.name,
                'path': iface.path,
                'address': iface.address,
                'listen_port': iface.listen_port,
                'dns': iface.dns,
                'mtu': iface.mtu,
                'is_up': _iface_up(dev),
            },
        )

    @require_api_key_or_login
    def api_iface_endpoint_default_get(iid):
        iface, error = _local_iface_or_error(iid)

        if error is not None:
            return error

        return jsonify(ok=True, **_endpoint_default_payload(iface))

    @require_api_key_or_login
    def api_iface_endpoint_default_put(iid):
        iface, error = _local_iface_or_error(iid)

        if error is not None:
            return error

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

        iface.endpoint_host = host
        iface.endpoint_port = port
        db.session.commit()

        current_app.logger.info(
            'Endpoint default %s for local interface %s: host=%s port=%s',
            'cleared' if host is None else 'saved',
            iface.name, host or '-', port or '-',
        )

        return jsonify(ok=True, **_endpoint_default_payload(iface))

    @require_api_key_or_login
    def api_iface_endpoint_default_apply(iid):
        iface, error = _local_iface_or_error(iid)

        if error is not None:
            return error

        dry_run, overwrite_explicit = _apply_request_flags(
            request.get_json(silent=True)
        )

        try:
            result = _apply_endpoint_default(
                iface, dry_run=dry_run, overwrite_explicit=overwrite_explicit,
            )
        except EndpointApplyError as exc:
            return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status
        except Exception as exc:
            db.session.rollback()
            current_app.logger.exception('Applying the endpoint default failed')
            return jsonify(
                ok=False, error='endpoint_apply_failed', detail=str(exc)
            ), 500

        return jsonify(ok=True, **result)

    @require_api_key_or_login
    def iface_updown(iid, action):
        iface = (
            db.session.get(
                InterfaceConfig,
                iid,
            )
            or abort(404)
        )

        if action not in ('up', 'down'):
            return jsonify(
                ok=False,
                error='invalid_action',
                detail='Action must be up or down.',
            ), 400

        if (
            getattr(
                iface,
                'node_id',
                None,
            )
            is not None
            or ':' in (
                getattr(
                    iface,
                    'name',
                    '',
                )
                or ''
            )
        ):
            return jsonify(
                ok=False,
                error='remote_interface',
                detail=(
                    'This interface belongs to a node. '
                    'Use the node interface endpoint.'
                ),
            ), 400

        dev = iface_devname(
            iface
        )

        try:
            if action == 'up':

                _check_iface_up(
                    iface
                )

                is_up = _iface_up(
                    dev
                )

                if not is_up:
                    raise RuntimeError(
                        f'Interface {dev} did not become active.'
                    )

                try:
                    subprocess.run(
                        [
                            'systemctl',
                            'enable',
                            f'wg-quick@{dev}.service',
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )
                except Exception:
                    current_app.logger.warning(
                        'Could not enable wg-quick@%s at boot',
                        dev,
                        exc_info=True,
                    )

                _iface_log(
                    iid,
                    (
                        f'Interface {dev} brought up '
                        'from Settings.'
                    ),
                )

                return jsonify(
                    ok=True,
                    action='up',
                    name=dev,
                    is_up=True,
                    message=(
                        f'Interface {dev} is active.'
                    ),
                )

            if not _iface_up(dev):
                return jsonify(
                    ok=True,
                    action='down',
                    name=dev,
                    is_up=False,
                    message=(
                        f'Interface {dev} is already down.'
                    ),
                )

            proc = subprocess.run(
                [
                    'wg-quick',
                    'down',
                    dev,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
                check=False,
            )

            output = (
                proc.stdout
                or ''
            ).strip()

            _iface_log(
                iid,
                (
                    f'$ wg-quick down {dev}\n'
                    f'{output}'
                ).rstrip(),
            )

            is_up = _iface_up(
                dev
            )

            if (
                proc.returncode != 0
                and is_up
            ):
                return jsonify(
                    ok=False,
                    error='wg_quick_down_failed',
                    detail=(
                        output
                        or f'wg-quick down {dev} failed.'
                    ),
                    is_up=True,
                ), 409

            try:
                subprocess.run(
                    [
                        'systemctl',
                        'disable',
                        f'wg-quick@{dev}.service',
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except Exception:
                current_app.logger.warning(
                    'Could not disable wg-quick@%s at boot',
                    dev,
                    exc_info=True,
                )

            return jsonify(
                ok=True,
                action='down',
                name=dev,
                is_up=False,
                message=(
                    f'Interface {dev} is down.'
                ),
            )

        except subprocess.TimeoutExpired as exc:
            current_app.logger.exception(
                'Interface %s timed out: %s',
                action,
                dev,
            )

            _iface_log(
                iid,
                (
                    f'Interface {action} timed out: '
                    f'{exc}'
                ),
            )

            return jsonify(
                ok=False,
                error='interface_command_timeout',
                detail=str(exc),
                name=dev,
                is_up=_iface_up(dev),
            ), 504

        except RuntimeError as exc:
            current_app.logger.exception(
                'Interface %s failed for %s',
                action,
                dev,
            )

            _iface_log(
                iid,
                (
                    f'Interface {action} failed: '
                    f'{exc}'
                ),
            )

            return jsonify(
                ok=False,
                error=f'interface_{action}_failed',
                detail=str(exc),
                name=dev,
                is_up=_iface_up(dev),
                hint=(
                    'Open Interface Logs for the complete '
                    'wg-quick and manual recovery output.'
                ),
            ), 409

        except Exception as exc:
            current_app.logger.exception(
                'Unexpected interface %s failure for %s',
                action,
                dev,
            )

            _iface_log(
                iid,
                (
                    f'Unexpected interface {action} error: '
                    f'{exc}'
                ),
            )

            return jsonify(
                ok=False,
                error='interface_action_failed',
                detail=str(exc),
                name=dev,
                is_up=_iface_up(dev),
            ), 500

    @require_api_key_or_login
    def iface_available_ips(iface_id):
        iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
        return jsonify(available_ips=_available_ips(iface))

    @require_api_key_or_login
    def get_interfaces():
        paths = []
        p = app.config['WG_CONF_PATH']
        if os.path.isdir(p):
            paths = glob.glob(os.path.join(p, '*.conf'))
        elif os.path.isfile(p):
            paths = [p]

        for conf in paths:
            name = os.path.splitext(os.path.basename(conf))[0]
            parsed = find_iface(conf)
            if not parsed:
                continue

            existing = InterfaceConfig.query.filter_by(name=name).first()
            if not existing:
                pk = _derive_wg_public_key(parsed.private_key)
                if pk:
                    parsed.public_key = pk
                db.session.add(parsed)
            else:
                _copy_local_iface_from_parsed(existing, parsed)
                db.session.add(existing)
        db.session.commit()

        out = []

        scope_networks = _private_networks()

        for i in InterfaceConfig.query.all():
            if ':' in (i.name or ''):
                continue

            row = {
                'id': i.id,
                'name': i.name,
                'address': i.address or '',
                'server_cidr': i.address or '',
                'scope_networks': scope_networks,
                'listen_port': i.listen_port,
                'mtu': i.mtu,
                'dns': i.dns,
                'available_ips': _available_ips(i),
                'is_up': _iface_up(i.name),
            }

            override = iface_endpoint_override(i)
            row.update({
                'endpoint_host': (getattr(i, 'endpoint_host', None) or '').strip() or None,
                'endpoint_port': int(i.endpoint_port) if getattr(i, 'endpoint_port', None) else None,
                'endpoint_override': override,
                'auto_endpoint': '',
                'effective_endpoint': override,
                'endpoint_source': 'override' if override else 'none',
            })
            out.append(row)

        return jsonify({'interfaces': out})

    @login_required
    def create_local_interface():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            try:
                raw = request.get_data(cache=True, as_text=True).strip()
                data = json.loads(raw) if raw else None
            except (TypeError, ValueError, json.JSONDecodeError):
                data = None

        if not isinstance(data, dict):
            current_app.logger.warning(
                "Invalid interface-create payload: "
                "content_type=%r mimetype=%r body=%r",
                request.content_type,
                request.mimetype,
                request.get_data(cache=True, as_text=True)[:500],
            )

            return jsonify(
                ok=False,
                error="invalid_payload",
                detail="The request body must be a JSON object.",
            ), 400

        name = str(
            data.get("name")
            or data.get("iface")
            or data.get("interface_name")
            or ""
        ).strip()

        address = str(
            data.get("address")
            or ""
        ).strip()

        dns = str(
            data.get("dns")
            or ""
        ).strip() or None

        auto_up = bool(
            data.get("auto_up", True)
        )

        auto_firewall = bool(
            data.get("auto_firewall", True)
        )

        if not name:
            return jsonify(
                ok=False,
                error="interface_name_required",
                detail="Interface name is required.",
            ), 400

        if not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,32}",
            name,
        ):
            return jsonify(
                ok=False,
                error="invalid_name",
                detail=(
                    f"Invalid interface name {name!r}. "
                    "Use 1-32 characters: letters, numbers, "
                    "underscore, dot, or dash."
                ),
            ), 400

        if not address:
            return jsonify(
                ok=False,
                error="address_required",
                detail=(
                    "WireGuard interface address is required. "
                    "Example: 10.77.0.1/24"
                ),
            ), 400

        address_parts = [
            value.strip()
            for value in re.split(r"[\s,]+", address)
            if value.strip()
        ]

        if not address_parts:
            return jsonify(
                ok=False,
                error="invalid_address",
                detail="No valid WireGuard address was supplied.",
            ), 400

        parsed_addresses = []

        for value in address_parts:
            try:
                parsed_addresses.append(
                    ipaddress.ip_interface(value)
                )
            except ValueError:
                return jsonify(
                    ok=False,
                    error="invalid_address",
                    detail=(
                        f"{value!r} is not a valid CIDR. "
                        "Example: 10.77.0.1/24"
                    ),
                ), 400

        address = ", ".join(
            str(value)
            for value in parsed_addresses
        )

        try:
            listen_port = int(
                data.get("listen_port")
            )
        except (TypeError, ValueError):
            return jsonify(
                ok=False,
                error="invalid_listen_port",
                detail="Listen port must be a number between 1 and 65535.",
            ), 400

        if not 1 <= listen_port <= 65535:
            return jsonify(
                ok=False,
                error="invalid_listen_port",
                detail="Listen port must be between 1 and 65535.",
            ), 400

        raw_mtu = data.get("mtu")

        try:
            mtu = (
                int(raw_mtu)
                if raw_mtu not in (None, "")
                and str(raw_mtu).strip()
                else None
            )
        except (TypeError, ValueError):
            return jsonify(
                ok=False,
                error="invalid_mtu",
                detail="MTU must be a number between 576 and 9000.",
            ), 400

        if mtu is not None and not 576 <= mtu <= 9000:
            return jsonify(
                ok=False,
                error="invalid_mtu",
                detail="MTU must be between 576 and 9000.",
            ), 400

        existing = (
            InterfaceConfig.query
            .filter_by(name=name)
            .first()
        )

        if existing:
            return jsonify(
                ok=False,
                error="interface_exists",
                detail=f"Interface {name} already exists in the panel.",
            ), 409

        wg_dir = (
            app.config.get("WG_CONF_PATH")
            or "/etc/wireguard"
        )

        if os.path.isfile(wg_dir):
            wg_dir = os.path.dirname(wg_dir)

        try:
            os.makedirs(
                wg_dir,
                exist_ok=True,
            )
        except Exception as exc:
            return jsonify(
                ok=False,
                error="wireguard_directory_failed",
                detail=str(exc),
            ), 500

        conf_path = os.path.join(
            wg_dir,
            f"{name}.conf",
        )

        if os.path.exists(conf_path):
            return jsonify(
                ok=False,
                error="config_exists",
                detail=f"{conf_path} already exists.",
            ), 409

        if _iface_up(name):
            return jsonify(
                ok=False,
                error="interface_exists_system",
                detail=(
                    f"Interface {name} already exists "
                    "on the operating system."
                ),
            ), 409

        try:
            for iface in InterfaceConfig.query.all():
                if (
                    int(iface.listen_port or 0)
                    == listen_port
                ):
                    return jsonify(
                        ok=False,
                        error="listen_port_in_use",
                        detail=(
                            f"Listen port {listen_port} is already "
                            f"used by {iface.name}."
                        ),
                    ), 409
        except Exception:
            current_app.logger.exception(
                "Could not validate existing interface ports"
            )

        post_up = ""
        post_down = ""
        egress_interface = ""

        if auto_firewall:
            try:
                post_up, post_down = _wg_firewall_rules(
                    name,
                    address,
                )

                egress_interface = _egress_interface()

            except ValueError as exc:
                return jsonify(
                    ok=False,
                    error="auto_firewall_failed",
                    detail=str(exc),
                    hint=(
                        "Disable automatic firewall rules if you "
                        "want to create the interface without "
                        "PostUp/PostDown forwarding rules."
                    ),
                ), 400

            except Exception as exc:
                current_app.logger.exception(
                    "Automatic firewall generation failed for %s",
                    name,
                )

                return jsonify(
                    ok=False,
                    error="auto_firewall_failed",
                    detail=str(exc),
                ), 500

        try:
            private_key = (
                subprocess.check_output(
                    ["wg", "genkey"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                .decode()
                .strip()
            )

        except Exception as exc:
            current_app.logger.exception(
                "wg genkey failed"
            )

            return jsonify(
                ok=False,
                error="wg_genkey_failed",
                detail=str(exc),
            ), 500

        lines = [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {address}",
            f"ListenPort = {listen_port}",
        ]

        if mtu is not None:
            lines.append(
                f"MTU = {mtu}"
            )

        for command in str(
            post_up or "").splitlines():

            command = command.strip()

            if command:
                lines.append(f"PostUp = {command}")


        for command in str(
            post_down or "").splitlines():

            command = command.strip()

            if command:
                lines.append(f"PostDown = {command}")

        lines.append("")

        config_text = "\n".join(lines)

        temp_path = (
            conf_path
            + ".tmp"
        )

        try:
            with open(
                temp_path,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    config_text
                )

                handle.flush()
                os.fsync(
                    handle.fileno()
                )

            os.chmod(
                temp_path,
                0o600,
            )

            os.replace(
                temp_path,
                conf_path,
            )

        except Exception as exc:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

            return jsonify(
                ok=False,
                error="write_config_failed",
                detail=str(exc),
            ), 500

        iface = InterfaceConfig(
            name=name,
            path=conf_path,
            address=address,
            listen_port=listen_port,
            private_key=private_key,
            mtu=mtu,
            dns=dns,
            post_up=post_up or None,
            post_down=post_down or None,
        )

        try:
            db.session.add(iface)
            db.session.commit()

        except Exception as exc:
            db.session.rollback()

            try:
                os.remove(conf_path)
            except Exception:
                pass

            current_app.logger.exception(
                "Could not save interface %s",
                name,
            )

            return jsonify(
                ok=False,
                error="database_save_failed",
                detail=str(exc),
            ), 500

        up_error = None

        if auto_up:
            try:
                proc = subprocess.run(
                    [
                        "wg-quick",
                        "up",
                        name,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                    check=False,
                )

                if proc.returncode != 0:
                    up_error = (
                        proc.stderr
                        or proc.stdout
                        or f"wg-quick up {name} failed"
                    ).strip()

                else:
                    try:
                        subprocess.run(
                            [
                                "systemctl",
                                "enable",
                                f"wg-quick@{name}.service",
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=10,
                            check=False,
                        )
                    except Exception:
                        current_app.logger.warning(
                            "Could not enable wg-quick@%s",
                            name,
                            exc_info=True,
                        )

            except Exception as exc:
                up_error = str(exc)

        return jsonify(
            ok=True,

            interface={
                "id": iface.id,
                "name": iface.name,
                "path": iface.path,
                "address": iface.address,
                "listen_port": iface.listen_port,
                "dns": iface.dns,
                "mtu": iface.mtu,
                "available_ips": _available_ips(iface),
                "is_up": _iface_up(name),
                "post_up": post_up,
                "post_down": post_down,
                "auto_firewall": auto_firewall,
                "egress_interface": egress_interface,
            },

            up_error=up_error,
        ), 201

    @csrf.exempt
    @require_api_key_or_login
    def iface_enable(iface_id):
        iface = db.session.get(InterfaceConfig, iface_id) or abort(404)

        try:
            _check_iface_up(iface)
        except Exception as e:
            current_app.logger.exception("Interface enable failed for %s", iface.name)
            return jsonify(
                success=False,
                error="interface_enable_failed",
                detail=str(e),
                hint="Open the interface logs in the panel, or run: journalctl -u wg-quick@%s -n 80 --no-pager" % iface_devname(iface)
            ), 409

        return jsonify(success=True, is_up=True)

    @csrf.exempt
    @require_api_key_or_login
    def iface_disable(iface_id):
        iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
        _iface_down(iface.name)
        return jsonify(success=True, is_up=False)

    @csrf.exempt
    @require_api_key_or_login
    def iface_delete(iface_id):
        iface = db.session.get(InterfaceConfig, iface_id) or abort(404)

        if getattr(iface, 'node_id', None) is not None or ':' in (iface.name or ''):
            return jsonify(
                success=False,
                error='node_interface_delete_not_supported_here',
                detail='Delete node interfaces through the node interface API.'
            ), 400

        data = request.get_json(silent=True) or {}
        delete_peers = _sub_bool(
            data.get('delete_peers')
            if 'delete_peers' in data
            else request.args.get('delete_peers')
        )

        peers = Peer.query.filter_by(iface_id=iface.id).all()
        peer_count = len(peers)

        peer_ids = [p.id for p in peers]
        subscription_link_count = 0
        affected_subs = set()

        if peer_ids:
            links = SubscriptionPeer.query.filter(SubscriptionPeer.peer_id.in_(peer_ids)).all()
            subscription_link_count = len(links)
            for link in links:
                if link.subscription:
                    affected_subs.add(link.subscription)

        if peer_count and not delete_peers:
            return jsonify(
                success=False,
                error='interface_has_peers',
                detail=f'Interface {iface.name} has {peer_count} peer(s).',
                peer_count=peer_count,
                subscription_link_count=subscription_link_count,
                require_delete_peers=True
            ), 409

        dev = iface_devname(iface)
        conf_path = iface.path or ''

        try:
            try:
                _iface_down(dev)
            except Exception:
                current_app.logger.exception("Failed to bring interface down before delete: %s", dev)

            if _iface_up(dev):
                current_app.logger.warning(
                    "%s is still up after bringing it down; removing its peers individually",
                    dev,
                )
                for peer in peers:
                    try:
                        _wg_disable(peer)
                    except Exception:
                        current_app.logger.exception(
                            "Failed to remove peer %s from the %s runtime",
                            getattr(peer, 'id', '?'), dev,
                        )

                still_live = _wg_peer_keys(dev) & {p.public_key for p in peers if p}
                if still_live:
                    db.session.rollback()
                    return jsonify(
                        success=False,
                        error='interface_still_up',
                        detail=(
                            f'{dev} could not be brought down and {len(still_live)} of its '
                            f'peer(s) are still live in the runtime. Nothing was deleted; '
                            f'bring the interface down manually and retry.'
                        ),
                        live_peers=len(still_live),
                    ), 502

            _delete_shortlinks_for_peer_ids([p.id for p in peers if p])

            deleted_peers = 0
            if delete_peers:
                for peer in peers:
                    SubscriptionPeer.query.filter_by(peer_id=peer.id).delete(
                        synchronize_session=False
                    )
                    db.session.delete(peer)
                    deleted_peers += 1
                db.session.flush()

            if conf_path:
                try:
                    wg_dir = app.config.get("WG_CONF_PATH") or "/etc/wireguard"
                    allowed_dir = wg_dir if os.path.isdir(wg_dir) else os.path.dirname(wg_dir)
                    allowed_dir = os.path.abspath(allowed_dir)
                    real_conf = os.path.abspath(conf_path)

                    if real_conf.startswith(allowed_dir + os.sep) and os.path.isfile(real_conf):
                        os.remove(real_conf)
                except Exception:
                    current_app.logger.exception("Could not remove interface config file: %s", conf_path)

            try:
                log_path = _ifacelog_path(iface.id)
                if log_path and os.path.isfile(log_path):
                    os.remove(log_path)
            except Exception:
                pass

            db.session.delete(iface)
            db.session.flush()

            for sub in affected_subs:
                try:
                    _sync_all_subscription_peers(sub, rename=True)
                except Exception:
                    current_app.logger.exception(
                        "Failed to sync subscription after interface delete: %s",
                        getattr(sub, 'id', '?')
                    )

            db.session.commit()

            try:
                logpanel_action(
                    "interface_delete",
                    f"iface={dev}; delete_peers={bool(delete_peers)}; peers={peer_count}"
                )
            except Exception:
                pass

            return jsonify(
                success=True,
                deleted_interface=dev,
                deleted_peers=deleted_peers
            )

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Interface delete failed for %s", iface.name)
            return jsonify(
                success=False,
                error='interface_delete_failed',
                detail=str(e)
            ), 500

    return {
        'iface_status': iface_status,
        'iface_logs': iface_logs,
        'iface_settings': iface_settings,
        'api_iface_endpoint_default_get': api_iface_endpoint_default_get,
        'api_iface_endpoint_default_put': api_iface_endpoint_default_put,
        'api_iface_endpoint_default_apply': api_iface_endpoint_default_apply,
        'iface_updown': iface_updown,
        'iface_available_ips': iface_available_ips,
        'get_interfaces': get_interfaces,
        'create_local_interface': create_local_interface,
        'iface_enable': iface_enable,
        'iface_disable': iface_disable,
        'iface_delete': iface_delete,
    }
