def bind_http_url(_panel_context):
    def _http_url(u: str) -> bool:
        try:
            p = _panel_context.urlparse((u or '').strip())
            return p.scheme in ('http', 'https') and bool(p.netloc)
        except Exception:
            return False


    def _safe_url(target: str) -> bool:
        if not isinstance(target,str) or not target or '\\' in target or any(ord(c)<32 or ord(c)==127 for c in target):
            return False
        ref = _panel_context.urlparse(_panel_context.request.host_url)
        try:
            test = _panel_context.urlparse(_panel_context.urljoin(_panel_context.request.host_url, target))
            return test.scheme == ref.scheme and test.netloc == ref.netloc and not test.username and not test.password
        except ValueError:
            return False


    def _norm_base_url(u: str) -> str:
        u = (u or '').strip()
        return u[:-1] if u.endswith('/') else u


    def _validate_node_base_url(base_url: str) -> tuple[bool, str]:
        base_url = (base_url or '').strip().rstrip('/')
        if not _panel_context._http_url(base_url):
            return False, 'invalid base_url'

        try:
            _panel_context._node_client.validate_base_url(base_url)
            p = _panel_context.urlparse(base_url)
            scheme = (p.scheme or '').lower()

            if scheme not in ('http', 'https'):
                return False, 'nodes must use http or https'

            host = (p.hostname or '').strip()
            if not host:
                return False, 'invalid host'

            if host in ('localhost', '127.0.0.1', '::1'):
                return False, 'loopback hosts are not allowed'

            infos = []
            try:
                infos = _panel_context.socket.getaddrinfo(host, p.port or (443 if scheme == 'https' else 80), type=_panel_context.socket.SOCK_STREAM)
            except Exception:
                infos = []

            for info in infos:
                addr = info[4][0]
                try:
                    ip = _panel_context.ipaddress.ip_address(addr)
                except Exception:
                    continue

                if (
                    ip.is_loopback or ip.is_private or ip.is_link_local or
                    ip.is_multicast or ip.is_reserved or ip.is_unspecified
                ):
                    return False, f'host resolves to non-public IP ({ip})'

            if host == '169.254.169.254':
                return False, 'metadata IP is not allowed'

        except Exception:
            return False, 'invalid base_url'

        return True, ''

    return {
        '_http_url': _http_url,
        '_safe_url': _safe_url,
        '_norm_base_url': _norm_base_url,
        '_validate_node_base_url': _validate_node_base_url,
    }


def bind_probably_encrypt(_panel_context):
    def _probably_encrypt(s: str) -> str:
        if _panel_context._fernet and s:
            return _panel_context._fernet.encrypt(s.encode()).decode()
        return s


    def _probably_decrypt(s: str) -> str:
        if _panel_context._fernet and s:
            try:
                return _panel_context._fernet.decrypt(s.encode()).decode()
            except Exception:
                return s
        return s


    def _read_api_key(node) -> str:
        raw = (getattr(node, 'api_key', None) or '').strip()
        if not raw:
            return ''


        if raw.startswith('enc$'):
            token = raw[4:].strip()
            for f in (_panel_context._fernet, _panel_context.fernet):
                if not f:
                    continue
                try:
                    return f.decrypt(token.encode()).decode()
                except Exception:
                    pass

            try:
                _panel_context.current_app.logger.warning(
                    "Failed to decrypt legacy node api_key (id=%s)",
                    getattr(node, 'id', '?')
                )
            except Exception:
                pass
            return ''

        return _panel_context._probably_decrypt(raw)

    return {
        '_probably_encrypt': _probably_encrypt,
        '_probably_decrypt': _probably_decrypt,
        '_read_api_key': _read_api_key,
    }


def bind_endpoint_fallback(_panel_context):
    def _endpoint_fallback(iface) -> str:

        host = _panel_context._server_host()
        port = getattr(iface, 'listen_port', None)
        return _panel_context._norm_hostport(host, port) if host and port else ''


    def _node_endpoint_fallback(
        node,
        iface_name: str,
        remote_iface=None,
        interfaces_payload=None,
    ) -> str:

        remote_iface = (
            remote_iface
            if isinstance(remote_iface, dict)
            else {}
        )

        interfaces_payload = (
            interfaces_payload
            if isinstance(interfaces_payload, dict)
            else {}
        )

        host = str(
            interfaces_payload.get('public_ipv4') or ''
        ).strip()

        if not host:
            try:
                health = _panel_context.node_get(
                    node,
                    '/api/health',
                    timeout=6,
                ) or {}

                if isinstance(health, dict):
                    host = str(
                        health.get('public_ipv4') or ''
                    ).strip()

            except Exception:
                host = ''

        if not host:
            try:
                parsed = _panel_context.urlparse(
                    (
                        getattr(node, 'base_url', '')
                        or ''
                    ).strip()
                )

                host = (
                    parsed.hostname
                    or ''
                ).strip()

            except Exception:
                host = ''

        try:
            port = int(
                remote_iface.get('listen_port') or 0
            )
        except Exception:
            port = 0

        if not port and iface_name:
            try:
                data = _panel_context.node_get(
                    node,
                    '/api/interfaces',
                    timeout=10,
                ) or {}

                rows = (
                    data.get('interfaces', [])
                    if isinstance(data, dict)
                    else data
                )

                for row in rows or []:
                    if str(
                        (row or {}).get('name') or ''
                    ) == str(iface_name):

                        port = int(
                            (row or {}).get('listen_port')
                            or 0
                        )
                        break

            except Exception:
                port = 0

        if not host or not port:
            return ''

        return _panel_context._norm_hostport(host, port)


    def remote_iface_name(iface):
        name = (getattr(iface, 'name', '') or '').strip()
        return name.split(':', 1)[1] if ':' in name else name


    def iface_endpoint_override(iface):
        if iface is None:
            return ''

        host = (getattr(iface, 'endpoint_host', None) or '').strip()
        port = getattr(iface, 'endpoint_port', None)

        if not host or not port:
            if host or port:

                _panel_context.current_app.logger.warning(
                    'Interface %s has an incomplete endpoint override '
                    '(host=%r port=%r); ignoring it.',
                    getattr(iface, 'name', '?'), host, port,
                )
            return ''

        return _panel_context._norm_hostport(host, int(port))


    def _safe_explicit_endpoint(explicit):
        explicit = (explicit or '').strip()
        if not explicit:
            return ''

        try:
            return _panel_context.parse_endpoint_string(explicit)
        except _panel_context.EndpointValidationError as exc:
            _panel_context.current_app.logger.warning(
                'Ignoring malformed peer endpoint %r: %s', explicit, exc.detail,
            )
            return ''


    def resolve_client_endpoint(iface, explicit=None, *, node=None, remote_iface=None):

        explicit = _panel_context._safe_explicit_endpoint(explicit)
        if explicit:
            return explicit

        if iface is None:
            return ''

        override = _panel_context.iface_endpoint_override(iface)
        if override:

            return override

        try:
            if getattr(iface, 'node_id', None) is not None:
                return (_panel_context._node_endpoint_fallback(
                    node or getattr(iface, 'node', None),
                    _panel_context.remote_iface_name(iface),
                    remote_iface,
                ) or '').strip()

            return (_panel_context._endpoint_fallback(iface) or '').strip()

        except Exception:
            _panel_context.current_app.logger.warning(
                'Endpoint auto-detection failed for interface %s',
                getattr(iface, 'name', '?'), exc_info=True,
            )
            return ''


    def resolve_client_endpoint_cheap(iface, explicit=None):

        explicit = _panel_context._safe_explicit_endpoint(explicit)
        if explicit:
            return explicit

        if iface is None:
            return ''

        override = _panel_context.iface_endpoint_override(iface)
        if override:
            return override

        if getattr(iface, 'node_id', None) is not None:
            return ''

        try:
            return (_panel_context._endpoint_fallback(iface) or '').strip()
        except Exception:
            _panel_context.current_app.logger.warning(
                'Endpoint auto-detection failed for interface %s',
                getattr(iface, 'name', '?'), exc_info=True,
            )
            return ''


    def _public_key_from_node_payload(payload) -> str:
        if isinstance(payload, str):
            direct = _panel_context._valid_wg_key(payload)
            if direct:
                return direct
            try:
                payload = _panel_context.json.loads(payload)
            except Exception:
                return ''
        if isinstance(payload, dict):
            return _panel_context._valid_wg_key(payload.get('public_key') or '')
        return ''


    def _persist_iface_public_key(iface, pk: str) -> str:
        pk = _panel_context._assign_iface_public_key(iface, pk)
        iface_id = getattr(iface, 'id', None) if iface is not None else None
        if not pk or not iface_id:
            return pk
        try:
            with _panel_context.db.engine.begin() as conn:
                conn.execute(
                    _panel_context.text(
                        'UPDATE interface_config SET public_key = :pk WHERE id = :iface_id'
                    ),
                    {'pk': pk, 'iface_id': iface_id},
                )
        except Exception:
            _panel_context.current_app.logger.warning(
                'Could not persist public_key for interface %s',
                getattr(iface, 'name', '?'),
                exc_info=True,
            )
        return pk


    def _http_error_is_pubkey_unavailable(exc) -> bool:
        response = getattr(exc, 'response', None)
        status = getattr(response, 'status_code', None)
        if status == 404:
            return True
        if response is None:
            return False
        try:
            payload = _panel_context._node_client.decode_response(response)
        except Exception:
            return False
        return (
            isinstance(payload, dict)
            and (payload.get('error') or '') == 'pubkey_unavailable'
        )


    def _fetch_node_iface_public_key(iface) -> str:
        nid = _panel_context._node_id_from_iface(iface)
        if nid is None:
            return ''
        n = _panel_context.db.session.get(_panel_context.Node, nid)
        if n is None:
            _panel_context.current_app.logger.warning(
                'No node row for interface %s (node_id=%s)',
                getattr(iface, 'name', '?'),
                nid,
            )
            return ''

        dev = _panel_context.iface_devname(iface)
        use_list = False

        try:
            j = _panel_context.node_get(n, f'/api/iface/{dev}/pubkey', timeout=6)
            pk = _panel_context._public_key_from_node_payload(j)
            if pk:
                return pk
            if isinstance(j, dict) and (j.get('error') or '') == 'pubkey_unavailable':
                use_list = True
        except _panel_context.requests.HTTPError as exc:
            if _panel_context._http_error_is_pubkey_unavailable(exc):
                use_list = True
            else:
                _panel_context.current_app.logger.warning(
                    'Node pubkey endpoint failed for interface %s',
                    getattr(iface, 'name', '?'),
                    exc_info=True,
                )
                return ''
        except _panel_context.requests.RequestException:
            _panel_context.current_app.logger.warning(
                'Node pubkey endpoint unreachable for interface %s',
                getattr(iface, 'name', '?'),
                exc_info=True,
            )
            return ''
        except Exception:
            _panel_context.current_app.logger.warning(
                'Node pubkey endpoint failed for interface %s',
                getattr(iface, 'name', '?'),
                exc_info=True,
            )
            return ''

        if not use_list:
            return ''

        try:
            data = _panel_context.node_get(n, '/api/interfaces?fast=1', timeout=6) or {}
            rows = data.get('interfaces') if isinstance(data, dict) else data
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                if str(row.get('name') or '') == str(dev):
                    pk = _panel_context._valid_wg_key(row.get('public_key') or '')
                    if pk:
                        return pk
                    break
        except _panel_context.requests.RequestException:
            _panel_context.current_app.logger.warning(
                'Node interface listing failed while resolving public key for %s',
                getattr(iface, 'name', '?'),
                exc_info=True,
            )
            return ''
        except Exception:
            _panel_context.current_app.logger.warning(
                'Node interface listing failed while resolving public key for %s',
                getattr(iface, 'name', '?'),
                exc_info=True,
            )

        return ''


    def _server_publickey(iface, *, persist=False):
        if iface is None:
            return ''

        iface_id = getattr(iface, 'id', None)
        cache = None
        if iface_id is not None:
            try:
                cache = _panel_context.g._server_pubkey_cache
            except Exception:
                try:
                    cache = _panel_context.g._server_pubkey_cache = {}
                except Exception:
                    cache = None
            if cache is not None and iface_id in cache:
                return cache[iface_id]

        result = _panel_context._resolve_server_publickey(iface, persist=persist)
        if cache is not None:
            cache[iface_id] = result
        return result


    def _resolve_server_publickey(iface, *, persist=False):
        if _panel_context._iface_is_node(iface):
            stored = _panel_context._valid_wg_key(getattr(iface, 'public_key', None) or '')
            pk = _panel_context._fetch_node_iface_public_key(iface) if not stored else ''
            if not pk and stored:
                return stored
            if pk:
                if persist and pk != stored:
                    _panel_context._persist_iface_public_key(iface, pk)
                return pk
            _panel_context.current_app.logger.error(
                'No server public key for node interface %s',
                getattr(iface, 'name', '?'),
            )
            return ''

        pk = _panel_context._derive_wg_public_key(getattr(iface, 'private_key', None))
        if pk:
            stored = _panel_context._valid_wg_key(getattr(iface, 'public_key', None) or '')
            if persist and pk != stored:
                _panel_context._persist_iface_public_key(iface, pk)
            return pk

        stored = _panel_context._valid_wg_key(getattr(iface, 'public_key', None) or '')
        if stored:
            return stored

        _panel_context.current_app.logger.error(
            'No server public key for interface %s',
            getattr(iface, 'name', '?'),
        )
        return ''


    def _node_peer_by_publickey(nid: int, pub: str):
        pub = (pub or "").strip()

        if not pub:
            _panel_context.abort(404)

        q = (
            _panel_context.db.session.query(_panel_context.Peer)
            .join(_panel_context.InterfaceConfig, _panel_context.Peer.iface_id == _panel_context.InterfaceConfig.id)
            .filter(_panel_context.or_(
                _panel_context.InterfaceConfig.name.like(f"n{nid}:%"),
                _panel_context.InterfaceConfig.node_id == nid
            ))
        )

        if pub.isdigit():
            peer = q.filter(_panel_context.Peer.id == int(pub)).first()
        else:
            peer = q.filter(_panel_context.Peer.public_key == pub).first()

        if not peer:
            _panel_context.abort(404)

        return peer


    def _effective_client_endpoint(peer: _panel_context.Peer) -> str:
        from reseller_portal.models import Ownership,Account
        from reseller_portal.network_policy import assigned_endpoint
        owner=Ownership.query.filter_by(peer_id=peer.id,deleted=False).first()
        if owner:
            account=_panel_context.db.session.get(Account,owner.account_id)
            if account:
                assigned=assigned_endpoint(account,peer.iface,_panel_context.namespace)
                if assigned:return assigned
        return _panel_context.resolve_client_endpoint(
            getattr(peer, 'iface', None),
            explicit=getattr(peer, 'endpoint', None),
        )

    return {
        '_endpoint_fallback': _endpoint_fallback,
        '_node_endpoint_fallback': _node_endpoint_fallback,
        'remote_iface_name': remote_iface_name,
        'iface_endpoint_override': iface_endpoint_override,
        '_safe_explicit_endpoint': _safe_explicit_endpoint,
        'resolve_client_endpoint': resolve_client_endpoint,
        'resolve_client_endpoint_cheap': resolve_client_endpoint_cheap,
        '_public_key_from_node_payload': _public_key_from_node_payload,
        '_persist_iface_public_key': _persist_iface_public_key,
        '_http_error_is_pubkey_unavailable': _http_error_is_pubkey_unavailable,
        '_fetch_node_iface_public_key': _fetch_node_iface_public_key,
        '_server_publickey': _server_publickey,
        '_resolve_server_publickey': _resolve_server_publickey,
        '_node_peer_by_publickey': _node_peer_by_publickey,
        '_effective_client_endpoint': _effective_client_endpoint,
    }


def bind_client_conf_txt(_panel_context):
    def _client_conf_txt(peer: _panel_context.Peer) -> str:

        iface = peer.iface
        server_pub = ""
        try:
            if iface is not None:
                server_pub = _panel_context._valid_wg_key(_panel_context._server_publickey(iface))
        except Exception:
            _panel_context.current_app.logger.warning(
                'Could not resolve server public key for peer %s',
                getattr(peer, 'id', '?'),
                exc_info=True,
            )
            server_pub = ""

        if not server_pub:
            raise _panel_context.ClientConfigIncomplete('server_public_key_unavailable')

        dns_val = ""
        try:
            dns_val = _panel_context._effective_dns(peer) or ""
        except Exception:
            dns_val = (peer.dns or (iface.dns if iface is not None else "") or "")

        ep = _panel_context._effective_client_endpoint(peer)

        mtu_val = peer.mtu or (iface.mtu if iface is not None else None)

        lines = []
        lines.append("[Interface]")
        lines.append(f"PrivateKey = {peer.private_key}")
        lines.append(f"Address = {peer.address}")
        if dns_val:
            lines.append(f"DNS = {dns_val}")
        if mtu_val:
            lines.append(f"MTU = {mtu_val}")
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {server_pub}")
        if ep:
            lines.append(f"Endpoint = {ep}")
        lines.append(f"AllowedIPs = {peer.allowed_ips or '0.0.0.0/0, ::/0'}")
        if peer.persistent_keepalive:
            lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
        lines.append("")

        return "\n".join(lines)


    def _client_config_txt(peer: _panel_context.Peer) -> str:
        return _panel_context._client_conf_txt(peer)


    def _peer_client_conf_or_502(peer: _panel_context.Peer):
        try:
            return _panel_context._client_conf_txt(peer), None
        except _panel_context.ClientConfigIncomplete as exc:
            iface = getattr(peer, 'iface', None)
            _panel_context.current_app.logger.error(
                'Cannot build client config for peer id=%s iface=%s: %s',
                getattr(peer, 'id', '?'),
                getattr(iface, 'name', '?'),
                exc.reason,
            )
            return None, (
                _panel_context.jsonify(
                    ok=False,
                    error='server_public_key_unavailable',
                    message=(
                        'The server PublicKey for this interface is not available. '
                        'The config would not connect.'
                    ),
                ),
                502,
            )


    def _peer_by_public_key_or_404(public_key: str):
        public_key = (public_key or "").strip()

        if not public_key:
            _panel_context.abort(404)

        if public_key.isdigit():
            peer = _panel_context.db.session.get(_panel_context.Peer, int(public_key))
        else:
            peer = _panel_context.Peer.query.filter_by(public_key=public_key).first()

        if not peer:
            _panel_context.abort(404)

        return peer

    return {
        '_client_conf_txt': _client_conf_txt,
        '_client_config_txt': _client_config_txt,
        '_peer_client_conf_or_502': _peer_client_conf_or_502,
        '_peer_by_public_key_or_404': _peer_by_public_key_or_404,
    }


def bind_node_peer_diagnostic_runtime(_panel_context):
    def _node_peer_diagnostic_runtime(node, peer):
        iface = _panel_context.iface_devname(peer.iface)
        payload = {'interface': iface, 'public_key': peer.public_key}
        try:
            result = _panel_context.node_post(node, '/api/operations/peer-diagnostic', payload, timeout=12)
            if isinstance(result, dict) and result.get('ok') is not False:
                return {
                    'runtime': result.get('runtime') if isinstance(result.get('runtime'), dict) else {},
                    'path_stages': result.get('path_stages') if isinstance(result.get('path_stages'), list) else [],
                    'source': 'peer_diagnostic',
                }
        except Exception:
            _panel_context.current_app.logger.debug(
                'Node does not expose the current peer diagnostic endpoint; using authenticated compatibility fallback',
                exc_info=True,
            )

        runtime = {
            'interface_state': 'unknown',
            'peer_present': None,
            'online': False,
            'latest_handshake_age': None,
            'reason': 'legacy_fallback',
        }
        try:
            data = _panel_context.node_get(node, '/api/peers?iface=' + iface, timeout=10) or {}
            rows = data.get('peers') if isinstance(data, dict) else []
            for row in rows or []:
                if str((row or {}).get('public_key') or '') != str(peer.public_key or ''):
                    continue
                runtime.update({
                    'interface_state': 'up',
                    'peer_present': True,
                    'online': str((row or {}).get('connection_status') or (row or {}).get('conn_status') or '').lower() == 'online',
                    'latest_handshake_age': (row or {}).get('latest_handshake_age'),
                    'reason': str((row or {}).get('conn_reason') or 'legacy_peer_list'),
                })
                break
        except Exception:
            _panel_context.current_app.logger.debug('Legacy node peer runtime lookup failed', exc_info=True)

        path_stages = []
        try:
            report = _panel_context.node_get(node, '/api/operations/diagnostic', timeout=12) or {}
            for finding in report.get('checks', []) if isinstance(report, dict) else []:
                if isinstance(finding, dict) and finding.get('id') == 'network_path':
                    raw = finding.get('path_stages')
                    if isinstance(raw, list):
                        path_stages = [item for item in raw if isinstance(item, dict)]
                    break
        except Exception:
            _panel_context.current_app.logger.debug('Legacy node Operations path lookup failed', exc_info=True)

        return {'runtime': runtime, 'path_stages': path_stages, 'source': 'legacy_fallback'}

    return {
        '_node_peer_diagnostic_runtime': _node_peer_diagnostic_runtime,
    }


def initialize_node_encryption(context):
    os = context.os
    _fernet = None
    try:
        from cryptography.fernet import Fernet
        key = os.environ.get('FERNET_KEY')
        if key:
            _fernet = Fernet(key)
    except Exception:
        _fernet = None


    FERNET_KEY = os.environ.get('FERNET_KEY')
    if not FERNET_KEY:
        raise RuntimeError("FERNET_KEY is not set. Generate one and export it before starting the app.")
    fernet = Fernet(FERNET_KEY.encode())
    context.namespace.update({
        '_fernet': _fernet,
        'FERNET_KEY': FERNET_KEY,
        'fernet': fernet,
    })
