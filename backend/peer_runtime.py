def bind_ifacelog_path(_panel_context):
    def _ifacelog_path(iid: int) -> str:
        return _panel_context.os.path.join(_panel_context.IFACE_LOG_DIR, f'{iid}.log')


    def _iface_log(iid: int, text: str):
        ts = _panel_context.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        _panel_context._extend_file(_panel_context._ifacelog_path(iid), f"[{ts}] {text}")


    def _clear_retention():
        ret = _panel_context._load_retention()["iface"]
        try:
            for p in _panel_context.Path(_panel_context.IFACE_LOG_DIR).glob('*.log'):
                _panel_context._may_autoclear(p, ret, persist_key="iface")
        except Exception:
            pass


    def _load_presets():
        try:
            with open(_panel_context.ENDPOINT_PRESETS_FILE, 'r') as f:
                return _panel_context.json.load(f)
        except Exception:
            return []


    def _save_presets(presets):
        try:
            _panel_context.os.makedirs(_panel_context.app.instance_path, exist_ok=True)
            with open(_panel_context.ENDPOINT_PRESETS_FILE, 'w') as f:
                _panel_context.json.dump(presets, f, indent=2)
                f.flush(); _panel_context.os.fsync(f.fileno())
        except Exception as e:
            _panel_context.current_app.logger.warning("Couldn't save endpoint presets: %s", e)


    def _token():
        return _panel_context.secrets.token_urlsafe(16)


    def _shortlink_url(token):
        return _panel_context.url_for('user_peer_page', token=token, _external=True)


    def _peer_from_shortlink_token(token):
        token = (token or "").strip()
        if not token:
            _panel_context.abort(404)

        link = _panel_context.ShortLink.query.filter_by(token=token).first()
        if not link:
            _panel_context.abort(404)
        from reseller_portal.models import Ownership, Account
        from reseller_portal.service import active as reseller_active
        row=Ownership.query.filter_by(peer_id=link.peer_id,deleted=False).first()
        if row:
            owner=_panel_context.db.session.get(Account,row.account_id)
            if not owner or not reseller_active(owner):_panel_context.abort(403)

        try:
            link.last_used_at = _panel_context.datetime.utcnow()
            _panel_context.db.session.commit()
        except Exception:
            _panel_context.db.session.rollback()

        return _panel_context.db.session.get(_panel_context.Peer, link.peer_id) or _panel_context.abort(404)


    def _delete_shortlinks_for_peer_ids(peer_ids):
        ids = []
        for x in peer_ids or []:
            try:
                ids.append(int(x))
            except Exception:
                pass

        if not ids:
            return 0

        removed = (
            _panel_context.ShortLink.query
            .filter(_panel_context.ShortLink.peer_id.in_(ids))
            .delete(synchronize_session=False)
        )
        _panel_context.db.session.flush()
        return int(removed or 0)


    def _shortlink_from_peer_id(pid):
        try:
            pid = int(pid)
        except Exception:
            return None, None

        link = _panel_context.ShortLink.query.filter_by(peer_id=pid).first()
        if not link:
            return None, None

        return link.token, _panel_context._shortlink_url(link.token)


    def _shortlink_for_peer(peer: _panel_context.Peer):
        if not peer or not getattr(peer, "id", None):
            return None, None

        existing = _panel_context.ShortLink.query.filter_by(peer_id=peer.id).first()
        if existing:
            return existing.token, _panel_context._shortlink_url(existing.token)

        token = None
        for _ in range(12):
            candidate = _panel_context._token()
            if not _panel_context.ShortLink.query.filter_by(token=candidate).first():
                token = candidate
                break

        if not token:
            token = _panel_context.secrets.token_urlsafe(24)

        link = _panel_context.ShortLink(token=token, peer_id=peer.id)
        _panel_context.db.session.add(link)
        _panel_context.db.session.commit()

        return token, _panel_context._shortlink_url(token)


    def _shortlink_response_for_peer(peer: _panel_context.Peer):
        token, url = _panel_context._shortlink_for_peer(peer)
        if not token or not url:
            _panel_context.abort(404)
        return _panel_context.jsonify(url=url, token=token)

    return {
        '_ifacelog_path': _ifacelog_path,
        '_iface_log': _iface_log,
        '_clear_retention': _clear_retention,
        '_load_presets': _load_presets,
        '_save_presets': _save_presets,
        '_token': _token,
        '_shortlink_url': _shortlink_url,
        '_peer_from_shortlink_token': _peer_from_shortlink_token,
        '_delete_shortlinks_for_peer_ids': _delete_shortlinks_for_peer_ids,
        '_shortlink_from_peer_id': _shortlink_from_peer_id,
        '_shortlink_for_peer': _shortlink_for_peer,
        '_shortlink_response_for_peer': _shortlink_response_for_peer,
    }


def bind_render_peer_template_preview(_panel_context):
    def _render_peer_template_preview(name, settings):
        name = (name or '').lower()
        tmap = {
            'default': 'user_peer.html',
            'compact': 'user_peer_compact.html',
            'minimal': 'user_peer_minimal.html',
            'pro':     'user_peer_pro.html',
        }
        tpl = tmap.get(name)
        if not tpl:
            _panel_context.abort(404)

        socials = {
            'telegram': '@preview',
            'whatsapp': '',
            'instagram': '',
            'phone': '',
            'website': '',
            'email': '',
        }

        html = _panel_context.render_template(
            tpl,
            token="PREVIEW_TOKEN",
            preview=True,
            peer_appearance=settings.get('appearance', {}),
            support_telegram=socials['telegram'],
            support_whatsapp=socials['whatsapp'],
            support_instagram=socials['instagram'],
            support_phone=socials['phone'],
            support_website=socials['website'],
            support_email=socials['email'],
        )

        from panel_operations.templates import prepare_preview
        html = prepare_preview(html, _panel_context.app.root_path)


        stub = f"""
<script>
  (function() {{
    try {{
      window.PREVIEW = true;
      const now = Math.floor(Date.now()/1000);
      const mock = {{
        ok: true,
        name: "b1",
        address: "10.66.66.2/24",
        endpoint: "167.71.78.88:57015",
        status: "offline",
        unlimited: false,
        limit_unit: "Mi",
        data_limit: 1024,
        used_bytes: 5632 * 1024 * 1024,
        expires_at_ts: now + 14*24*3600,
        ttl_seconds:  14*24*3600
      }};
      const respond = (o) => Promise.resolve({{
        ok: true, status: 200,
        json: async () => o, text: async () => JSON.stringify(o)
      }});
      const originalFetch = window.fetch;
      window.fetch = function(url, opts) {{
        try {{
          const u = (typeof url === 'string') ? url : (url && url.url) || '';
          if (u.includes('/api/u/') || u.includes('/api/peer/')) return respond(mock);
        }} catch(_){{}}
        return respond({{}});
      }};
      document.addEventListener('click', function(e){{
        const a = e.target.closest('a[href]'); if (a) e.preventDefault();
      }}, true);
    }} catch(_){{}}
  }})();
</script>"""

        idx = html.rfind('</body>')
        html = html[:idx] + stub + html[idx:] if idx != -1 else html + stub
        resp = _panel_context.make_response(html)
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Content-Security-Policy'] = (
        "frame-ancestors 'self'; "
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-src 'none'"
    )

        return resp

    return {
        '_render_peer_template_preview': _render_peer_template_preview,
    }


def bind_node_get(_panel_context):
    def node_get(n: _panel_context.Node, path: str, timeout=6):
        return _panel_context._node_client.get(n.base_url, path, _panel_context._read_api_key(n), timeout=timeout)


    def node_post(n: _panel_context.Node, path: str, payload=None, timeout=30):
        return _panel_context._node_client.post(n.base_url, path, _panel_context._read_api_key(n), payload, timeout=timeout)


    def node_delete(n: _panel_context.Node, path: str, payload=None, timeout=30):
        return _panel_context._node_client.delete(n.base_url, path, _panel_context._read_api_key(n), payload, timeout=timeout)


    def _peer_ping_ok(peer, timeout_sec: float = 0.8) -> bool:

        ip = _panel_context._peer_ip_plain(peer)
        if not ip:
            return False

        try:
            dev = _panel_context.iface_devname(peer.iface)
        except Exception:
            dev = getattr(getattr(peer, 'iface', None), 'name', '') or ''

        if not dev:
            return False

        try:
            ip_obj = _panel_context.ipaddress.ip_address(ip)
            if ip_obj.version == 6:
                cmd = ['ping', '-6', '-I', dev, '-c', '1', '-W', '1', ip]
            else:
                cmd = ['ping', '-I', dev, '-c', '1', '-W', '1', ip]

            return _panel_context.subprocess.run(
                cmd,
                stdout=_panel_context.subprocess.DEVNULL,
                stderr=_panel_context.subprocess.DEVNULL,
                timeout=max(1.0, float(timeout_sec) + 0.5)
            ).returncode == 0
        except Exception:
            return False


    def _peer_conn_status(
        peer,
        *,
        live_total: int | None = None,
        latest_handshake: int | None = None,
        handshake_window: int | None = None,
        allow_probe: bool = True,
    ) -> dict:
        now = _panel_context.now_ts()

        try:
            if handshake_window is None:
                handshake_window = int(
                    _panel_context.os.environ.get(
                        'WG_ONLINE_HANDSHAKE_WINDOW',
                        '45',
                    )
                )
            else:
                handshake_window = int(handshake_window)
        except (TypeError, ValueError):
            handshake_window = 45

        handshake_window = max(5, handshake_window)

        probe_first = str(
            _panel_context.os.environ.get(
                'WG_ONLINE_PROBE_FIRST',
                '1',
            )
        ).strip().lower() not in (
            '0',
            'false',
            'no',
            'off',
        )

        handshake_fallback = str(
            _panel_context.os.environ.get(
                'WG_ONLINE_HANDSHAKE_FALLBACK',
                '1',
            )
        ).strip().lower() in (
            '1',
            'true',
            'yes',
            'on',
        )

        try:
            if latest_handshake is None:
                handshake = int(
                    _panel_context._latest_handshake(peer) or 0
                )
            else:
                handshake = int(
                    latest_handshake or 0
                )
        except (TypeError, ValueError):
            handshake = 0
        except Exception:
            _panel_context.current_app.logger.debug(
                "Could not read handshake for peer %s",
                getattr(peer, 'id', '?'),
                exc_info=True,
            )
            handshake = 0

        handshake = max(0, handshake)

        handshake_age = (
            max(0, now - handshake)
            if handshake > 0
            else None
        )

        handshake_fresh = bool(
            handshake > 0
            and handshake_age is not None
            and handshake_age <= handshake_window
        )

        try:
            if live_total is None:
                live = int(
                    _panel_context._wg_transfer(peer) or 0
                )
            else:
                live = int(
                    live_total or 0
                )
        except (TypeError, ValueError):
            live = 0
        except Exception:
            _panel_context.current_app.logger.debug(
                "Could not read live transfer counter for peer %s",
                getattr(peer, 'id', '?'),
                exc_info=True,
            )
            live = 0

        live = max(0, live)

        try:
            offset = int(
                getattr(peer, 'bytes_offset', 0) or 0
            )
        except (TypeError, ValueError):
            offset = 0

        offset = max(0, offset)

        traffic_now = live > offset

        panel_status = str(
            getattr(peer, 'status', '') or ''
        ).strip().lower()

        panel_enabled = panel_status == 'online'
        panel_blocked = panel_status == 'blocked'

        ping_ok = False
        probed = False

        if (
            allow_probe
            and panel_enabled
            and probe_first
        ):
            probed = True

            try:
                ping_ok = bool(
                    _panel_context._peer_ping_ok(peer)
                )
            except Exception:
                ping_ok = False

            if ping_ok:
                online = True
                reason = 'probe'

            elif handshake_fallback and handshake_fresh:
                online = True
                reason = 'handshake'

            elif traffic_now:
                online = True
                reason = 'traffic'

            else:
                online = False
                reason = 'probe_failed'

        else:
            if panel_blocked:
                online = False
                reason = 'blocked'

            elif handshake_fresh:
                online = True
                reason = 'handshake'

            elif traffic_now:
                online = True
                reason = 'traffic'

            elif not panel_enabled:
                online = False
                reason = 'disabled'

            else:
                online = False
                reason = 'no_recent_activity'

        connection_status = (
            'online'
            if online
            else 'offline'
        )

        return {
            'conn_status': connection_status,
            'connection_status': connection_status,

            'latest_handshake': handshake,
            'latest_handshake_age': handshake_age,

            'conn_reason': reason,
            'conn_probe': bool(probed),
            'probe_ok': bool(ping_ok),

            'traffic_now': bool(traffic_now),
            'live_total': int(live),

            'handshake_fresh': bool(handshake_fresh),
            'handshake_window': int(handshake_window),
        }


    def _endpoint_default_payload(iface, *, scope=None, node=None, remote_iface=None):

        if scope is None:
            scope = 'node' if getattr(iface, 'node_id', None) is not None else 'local'

        host = (getattr(iface, 'endpoint_host', None) or '').strip() or None
        port = getattr(iface, 'endpoint_port', None)
        override = _panel_context.iface_endpoint_override(iface)

        auto = ''
        try:
            if scope == 'node':
                auto = (_panel_context._node_endpoint_fallback(
                    node or getattr(iface, 'node', None),
                    _panel_context.remote_iface_name(iface),
                    remote_iface,
                ) or '').strip()
            else:
                auto = (_panel_context._endpoint_fallback(iface) or '').strip()
        except Exception:
            _panel_context.current_app.logger.debug(
                'Endpoint auto-detection unavailable for %s',
                getattr(iface, 'name', '?'), exc_info=True,
            )
            auto = ''

        effective = override or auto

        payload = {
            'scope': scope,
            'iface_id': iface.id,
            'iface': _panel_context.remote_iface_name(iface) if scope == 'node' else (iface.name or ''),
            'listen_port': iface.listen_port,
            'endpoint_host': host,
            'endpoint_port': int(port) if port else None,
            'endpoint_override': override,
            'auto_endpoint': auto,
            'effective_endpoint': effective,
            'endpoint_source': 'override' if override else ('auto' if auto else 'none'),
        }

        if scope == 'node':
            payload['node_id'] = getattr(iface, 'node_id', None)

        if not effective:
            payload['warning'] = (
                'No endpoint could be determined. Exported configs will have no '
                'Endpoint line until an override is saved.'
            )

        return payload


    def _local_iface_or_error(iid):
        iface = _panel_context.db.session.get(_panel_context.InterfaceConfig, iid)

        if iface is None:
            return None, (_panel_context.jsonify(
                ok=False,
                error='iface_not_found',
                detail=f'Interface {iid} was not found.',
            ), 404)

        if (
            getattr(iface, 'node_id', None) is not None
            or ':' in (getattr(iface, 'name', '') or '')
        ):
            return None, (_panel_context.jsonify(
                ok=False,
                error='remote_interface',
                detail=(
                    'This interface belongs to a remote node. '
                    'Use the node interface API instead.'
                ),
            ), 400)

        return iface, None

    return {
        'node_get': node_get,
        'node_post': node_post,
        'node_delete': node_delete,
        '_peer_ping_ok': _peer_ping_ok,
        '_peer_conn_status': _peer_conn_status,
        '_endpoint_default_payload': _endpoint_default_payload,
        '_local_iface_or_error': _local_iface_or_error,
    }


def bind_node_mirror_for_endpoint_default(_panel_context):
    def _node_mirror_for_endpoint_default(node, name):

        db_name = f'n{node.id}:{name}'
        iface = _panel_context.InterfaceConfig.query.filter_by(name=db_name).first()

        if iface is not None:
            return iface, {}

        try:
            listing = _panel_context.node_get(node, '/api/interfaces', timeout=10) or {}
        except Exception as exc:
            raise _panel_context.NodeIfaceLookupError(
                'node_unreachable', 502,
                f'Node {node.id} could not be reached: {exc}',
            )

        rows = listing.get('interfaces') if isinstance(listing, dict) else listing

        remote = next(
            (
                row for row in (rows or [])
                if isinstance(row, dict)
                and str(row.get('name') or row.get('iface') or '').strip() == name
            ),
            None,
        )

        if remote is None:
            raise _panel_context.NodeIfaceLookupError(
                'node_iface_not_found', 404,
                f'Node {node.id} has no interface named {name}.',
            )

        iface = _panel_context.ensure_node_mirror_iface(node, name, remote_iface=remote)
        _panel_context.db.session.commit()

        return iface, remote

    return {
        '_node_mirror_for_endpoint_default': _node_mirror_for_endpoint_default,
    }


def bind_apply_endpoint_default(_panel_context):
    def _apply_endpoint_default(iface, *, dry_run, overwrite_explicit,
                                scope='local', node=None, remote_iface=None):

        effective = _panel_context.resolve_client_endpoint(iface, node=node, remote_iface=remote_iface)

        if not effective:
            raise _panel_context.EndpointApplyError(
                'endpoint_unavailable', 409,
                'No endpoint could be determined for this interface, so there is '
                'nothing to apply.',
            )

        peers = _panel_context.Peer.query.filter_by(iface_id=iface.id).all()
        explicit = [p for p in peers if (p.endpoint or '').strip()]
        candidates = peers if overwrite_explicit else [
            p for p in peers if not (p.endpoint or '').strip()
        ]

        targets = [p for p in candidates if (p.endpoint or '').strip() != effective]

        result = {
            'scope': scope,
            'iface': _panel_context.remote_iface_name(iface) if scope == 'node' else (iface.name or ''),
            'effective_endpoint': effective,
            'total_peers': len(peers),
            'eligible': len(targets),
            'skipped_explicit': 0 if overwrite_explicit else len(explicit),
            'dry_run': bool(dry_run),
        }

        if dry_run:
            result['would_update'] = len(targets)
            return result

        for peer in targets:
            peer.endpoint = effective

        _panel_context.db.session.commit()

        _panel_context.current_app.logger.info(
            'Applied endpoint %s to %s peers on interface %s',
            effective, len(targets), iface.name,
        )

        result['updated'] = len(targets)
        return result


    def _apply_request_flags(data):
        data = data if isinstance(data, dict) else {}
        return (
            _panel_context._sub_bool(data.get('dry_run')),
            _panel_context._sub_bool(data.get('overwrite_explicit')),
        )


    def _node_peer_live_total_bytes(node, peer):

        try:
            iface_raw = peer.iface.name if peer.iface else ''
            iface_name = iface_raw.split(':', 1)[1] if ':' in iface_raw else iface_raw

            data = _panel_context.node_get(node, '/api/peers' + (f'?iface={iface_name}' if iface_name else ''), timeout=8) or {}
            rows = data.get('peers') if isinstance(data, dict) else []
            for row in rows or []:
                if row.get('public_key') == peer.public_key:
                    rx_mib = float(row.get('rx_mib') or 0)
                    tx_mib = float(row.get('tx_mib') or 0)
                    return int((rx_mib + tx_mib) * 1024 * 1024)
        except Exception:
            _panel_context.current_app.logger.debug("Could not read node live transfer for peer %s", getattr(peer, 'id', '?'))

        return 0


    def _linked_subscription_for_peer(peer):
        if not peer or not getattr(peer, 'id', None):
            return None

        link = (
            _panel_context.SubscriptionPeer.query
            .filter_by(peer_id=peer.id)
            .first()
        )
        if not link:
            return None

        sub = getattr(link, 'subscription', None)
        if sub is None:
            sub = _panel_context.db.session.get(_panel_context.Subscription, link.subscription_id)
        return sub


    def _reset_peer_timer_via_subscription(peer):
        sub = _panel_context._linked_subscription_for_peer(peer)
        if sub is None:
            return None

        result = _panel_context._reset_subscription_timer(sub)
        data_exhausted = _panel_context._subscription_data_exhausted(sub)

        return {
            'subscription': sub,
            'result': result,
            'data_exhausted': bool(data_exhausted),
        }


    def _linked_subscription_timer_response(peer, action_name):
        shared = _panel_context._reset_peer_timer_via_subscription(peer)
        if shared is None:
            return None

        sub = shared['subscription']
        result = shared['result']
        data_exhausted = shared['data_exhausted']

        _panel_context.db.session.commit()

        still_blocked_for_data = bool(
            data_exhausted
            and int(result.get('still_blocked', 0) or 0) > 0
        )
        partial = bool(
            result.get('errors')
            or int(result.get('enable_failed', 0) or 0) > 0
        )

        if still_blocked_for_data:
            message = (
                'Shared subscription timer was reset, but the client remains '
                'blocked because its shared data allowance is exhausted.'
            )
        elif partial:
            message = (
                'Shared subscription timer was reset, but one or more attached '
                'configs could not be re-enabled.'
            )
        else:
            message = (
                'Shared subscription timer reset. All attached configs now use '
                'the same timer cycle.'
            )

        try:
            _panel_context.logpanel_action(
                action_name,
                (
                    f'pid={peer.id}; subscription_id={sub.id}; '
                    f'reset_peers={int(result.get("reset_peers", 0) or 0)}; '
                    f'reactivated={int(result.get("reactivated", 0) or 0)}; '
                    f'still_blocked={int(result.get("still_blocked", 0) or 0)}; '
                    'shared_timer=1'
                ),
            )
        except Exception:
            pass

        response = _panel_context.jsonify(
            ok=not partial,
            success=True,
            partial=partial,
            status=getattr(peer, 'status', None),
            timer_reset=True,
            subscription_managed=True,
            subscription_id=sub.id,
            subscription_name=getattr(sub, 'name', '') or '',
            reset_peers=int(result.get('reset_peers', 0) or 0),
            reactivated=int(result.get('reactivated', 0) or 0),
            message=message,
            still_blocked_reason=(
                'data_limit' if still_blocked_for_data else None
            ),
            result=result,
        )
        return response, (207 if partial else 200)

    return {
        '_apply_endpoint_default': _apply_endpoint_default,
        '_apply_request_flags': _apply_request_flags,
        '_node_peer_live_total_bytes': _node_peer_live_total_bytes,
        '_linked_subscription_for_peer': _linked_subscription_for_peer,
        '_reset_peer_timer_via_subscription': _reset_peer_timer_via_subscription,
        '_linked_subscription_timer_response': _linked_subscription_timer_response,
    }
