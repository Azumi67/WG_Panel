def bind_write_json_atomic(_panel_context):
    def _write_json_atomic(
        path,
        payload,
    ):
        _panel_context.os.makedirs(
            _panel_context.os.path.dirname(path),
            exist_ok=True,
        )

        temporary = (
            path
            + '.tmp'
        )

        with open(
            temporary,
            'w',
            encoding='utf-8',
        ) as handle:
            _panel_context.json.dump(
                payload,
                handle,
                indent=2,
                ensure_ascii=False,
            )

        _panel_context.os.replace(
            temporary,
            path,
        )


    def _effective_subscription_settings(
        sub=None,
    ):
        if sub is not None:
            from reseller_portal.shared import subscription_design
            tenant_settings = subscription_design(sub, _panel_context.namespace)
            if tenant_settings is not None:
                return tenant_settings
        global_settings = (
            _panel_context._load_subscription_settings()
        )

        if sub is None:
            return global_settings

        override = (
            _panel_context._subscription_portal_override(
                sub
            )
        )

        if not override:
            return global_settings

        return _panel_context._normalize_subscription_settings(
            override,
            base=global_settings,
        )


    def _subscription_row_readonly(sub):
        from reseller_portal.presentation import peer_states
        peers=[link.peer for link in sub.links if link.peer]
        states=peer_states(peers,_panel_context.namespace,live=False)
        cached={}
        for peer in peers:
            connection=states.get(peer.id,{}).get('connection','unknown')
            cached[peer.id]={'connected':connection=='online','conn_status':connection,
                'connection_status':connection,'connection_label':{'online':'Connected','offline':'Disconnected'}.get(connection,'Awaiting refresh'),
                'runtime_available':connection!='unknown'}
        return _panel_context._subscription_row(sub, read_only=True, cached_runtime=cached)

    return {
        '_write_json_atomic': _write_json_atomic,
        '_effective_subscription_settings': _effective_subscription_settings,
        '_subscription_row_readonly': _subscription_row_readonly,
    }


def bind_flag_from_cc(_panel_context):
    def _flag_from_cc(cc: str) -> str:
        cc = (cc or '').strip().upper()
        if not _panel_context.re.match(r'^[A-Z]{2}$', cc):
            return '🌐'
        return ''.join(chr(127397 + ord(ch)) for ch in cc)


    def _load_geo_cache() -> dict:
        try:
            with open(_panel_context.GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
                data = _panel_context.json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}


    def _save_geo_cache(data: dict):
        try:
            _panel_context.os.makedirs(_panel_context.app.instance_path, exist_ok=True)
            with open(_panel_context.GEO_CACHE_FILE, 'w', encoding='utf-8') as f:
                _panel_context.json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass


    def _i_public_host(host: str) -> bool:
        host = (host or '').strip().strip('[]')
        if not host:
            return False
        try:
            ip = _panel_context.ipaddress.ip_address(host)
            return bool(ip.is_global)
        except Exception:
            low = host.lower()
            return low not in ('localhost',) and not low.endswith('.local')


    def _endpoint_host(endpoint: str) -> str:
        endpoint = (endpoint or '').strip()
        if not endpoint:
            return ''
        if endpoint.startswith('[') and ']' in endpoint:
            return endpoint[1:].split(']', 1)[0]
        if ':' in endpoint:
            return endpoint.rsplit(':', 1)[0]
        return endpoint


    def _node_public_host(iface) -> str:
        try:
            nid = getattr(iface, 'node_id', None)
            if nid is None:
                nm = getattr(iface, 'name', '') or ''
                m = _panel_context.re.match(r'^n(\d+):', nm)
                nid = int(m.group(1)) if m else None
            if nid is None:
                return ''
            n = _panel_context.db.session.get(_panel_context.Node, int(nid))
            if not n:
                return ''
            try:
                h = _panel_context.node_get(n, '/api/health', timeout=5) or {}
                pub = (h.get('public_ipv4') or h.get('ipv4') or h.get('public_ip') or '').strip()
                if pub:
                    return pub
            except Exception:
                pass
            return (_panel_context._geo_urlparse(n.base_url or '').hostname or '').strip()
        except Exception:
            return ''


    def _public_host_peer(peer) -> str:
        try:
            iface = peer.iface
        except Exception:
            iface = None

        iface_name = getattr(iface, 'name', '') or ''
        is_node = bool(
            iface and (
                getattr(iface, 'node_id', None) is not None or
                _panel_context.re.match(r'^n\d+:', iface_name)
            )
        )

        if is_node:
            host = _panel_context._node_public_host(iface)
            if _panel_context._i_public_host(host):
                return host

            try:
                nid = getattr(iface, 'node_id', None)
                if nid is None:
                    m = _panel_context.re.match(r'^n(\d+):', iface_name)
                    nid = int(m.group(1)) if m else None
                n = _panel_context.db.session.get(_panel_context.Node, int(nid)) if nid is not None else None
                if n:
                    host = _panel_context._endpoint_host(getattr(n, 'base_url', '') or '')
                    if _panel_context._i_public_host(host):
                        return host
            except Exception:
                pass

            return ''

        try:
            host = _panel_context._public_ipv4(force=True)
        except TypeError:
            host = _panel_context._public_ipv4()
        except Exception:
            host = ''

        if _panel_context._i_public_host(host):
            return host

        if iface:
            host = _panel_context._endpoint_host(_panel_context._endpoint_fallback(iface))
            if _panel_context._i_public_host(host):
                return host

        return ''


    def _lookup_geo(host: str) -> dict:
        host = (host or '').strip().strip('[]')
        if not _panel_context._i_public_host(host):
            return {'country': '', 'country_code': '', 'flag': '🌐'}

        now = int(_panel_context._geo_time.time())
        cache = _panel_context._load_geo_cache()
        old = cache.get(host) or {}
        if old and (now - int(old.get('ts') or 0) < _panel_context.GEO_CACHE_TTL):
            return old

        headers = {'User-Agent': 'WG-Panel/1.0 (+subscription geo)'}
        providers = [
            ('ipwho', f'https://ipwho.is/{host}'),
            ('ipapi', f'https://ipapi.co/{host}/json/'),
            ('ipapi2', f'http://ip-api.com/json/{host}?fields=status,country,countryCode'),
        ]

        for provider, url in providers:
            try:
                r = _panel_context.requests.get(url, headers=headers, timeout=4)
                if not r.ok:
                    continue
                j = r.json() or {}
                country = ''
                cc = ''
                if provider == 'ipwho':
                    if j.get('success') is False:
                        continue
                    country = (j.get('country') or '').strip()
                    cc = (j.get('country_code') or '').strip().upper()
                elif provider == 'ipapi':
                    country = (j.get('country_name') or '').strip()
                    cc = (j.get('country_code') or j.get('country') or '').strip().upper()
                else:
                    if j.get('status') != 'success':
                        continue
                    country = (j.get('country') or '').strip()
                    cc = (j.get('countryCode') or '').strip().upper()

                if cc or country:
                    geo = {'country': country or cc, 'country_code': cc, 'flag': _panel_context._flag_from_cc(cc), 'ts': now}
                    cache[host] = geo
                    _panel_context._save_geo_cache(cache)
                    return geo
            except Exception:
                continue

        return {'country': '', 'country_code': '', 'flag': '🌐', 'ts': now}


    def _peer_used_for_subscription(peer, *, read_only=False) -> int:
        try:
            iface = getattr(peer, 'iface', None)
            is_node = bool(
                iface and (
                    getattr(iface, 'node_id', None) is not None or
                    _panel_context.re.match(r'^n\d+:', getattr(iface, 'name', '') or '')
                )
            )

            if is_node:
                return int(getattr(peer, 'used_bytes_total', 0) or 0)

            total = _panel_context._wg_transfer(peer)
            if read_only:
                return int(_panel_context._preview_peer_usage(peer, total))
            used, _delta, changed = _panel_context._accumulate_peer_usage(peer, total)
            if changed:
                _panel_context.db.session.commit()
            return int(used)

        except Exception:
            return int(getattr(peer, 'used_bytes_total', 0) or 0)


    def subscription_access(sub, used_bytes=None) -> dict:
        try:
            used = int(_panel_context._sub_used_bytes(sub) if used_bytes is None else used_bytes)
        except Exception:
            used = 0
        return _panel_context.compute_subscription_access(
            enabled=bool(getattr(sub, 'enabled', True)),
            unlimited=bool(getattr(sub, 'unlimited', False)),
            expires_at_ts=_panel_context._effective_expiry_ts(sub),
            now_ts=_panel_context.now_ts(),
            limit_bytes=_panel_context._sub_limit_bytes(sub),
            used_bytes=used,
        )


    def _subscription_inbound_state(sub):
        links = getattr(sub, 'links', None) or []
        usable = sum(
            1 for link in links
            if getattr(link, 'peer', None) is not None
            and str(getattr(getattr(link, 'peer', None), 'status', '') or '').lower() != 'removed'
        )
        return {'inbound_count': usable, 'has_inbounds': usable > 0}


    def _subscription_access_or_403(sub):
        access = _panel_context.subscription_access(sub)
        if access['allowed']:
            return None

        return _panel_context.jsonify(
            ok=False,
            error='subscription_access_revoked',
            reason=access['reason'],
            message=access['message'],
        ), 403


    def _subscription_public_payload(sub) -> dict:
        links = sorted(list(getattr(sub, 'links', []) or []), key=lambda x: (x.sort_order or 0, x.id or 0))
        limit_bytes = sub.limit_bytes() if hasattr(sub, 'limit_bytes') else None
        used_bytes = 0
        locs = []
        dirty = False

        for link in links:
            peer = getattr(link, 'peer', None)
            if not peer:
                continue
            used_bytes += _panel_context._peer_used_for_subscription(peer, read_only=True)

        access = _panel_context.subscription_access(sub, used_bytes=used_bytes)
        access.update(_panel_context._subscription_inbound_state(sub))
        may_disclose_topology = bool(access['allowed'])

        for link in links:
            peer = getattr(link, 'peer', None)
            if not peer:
                continue

            host = _panel_context._public_host_peer(peer) if may_disclose_topology else ''

            cc = (getattr(link, 'country_code', '') or '').strip().upper()
            flag = (getattr(link, 'flag', '') or '').strip()
            label = (getattr(link, 'location_label', '') or '').strip()
            if host:
                geo = _panel_context._lookup_geo(host)
                new_cc = (geo.get('country_code') or '').strip().upper()
                new_flag = geo.get('flag') or _panel_context._flag_from_cc(new_cc)
                new_label = geo.get('country') or new_cc or ''
                if new_cc and new_cc != cc:
                    cc = new_cc
                    flag = new_flag
                    label = new_label
                    link.country_code = cc
                    link.flag = flag
                    link.location_label = label
                    dirty = True
                elif new_cc and not cc:
                    cc = new_cc
                    flag = new_flag
                    label = new_label
                    link.country_code = cc
                    link.flag = flag
                    link.location_label = label
                    dirty = True

            endpoint = ''
            if may_disclose_topology and getattr(peer, 'iface', None):
                endpoint = _panel_context.resolve_client_endpoint_cheap(
                    peer.iface, explicit=getattr(peer, 'endpoint', '')
                )
            elif may_disclose_topology:
                endpoint = getattr(peer, 'endpoint', '') or ''

            locs.append({
                'link_id': link.id,
                'peer_id': peer.id,
                'name': peer.name,
                'status': peer.status,
                'endpoint': endpoint,
                'public_host': host,
                'location_label': label,
                'country_code': cc,
                'flag': flag or _panel_context._flag_from_cc(cc),
            })

        if dirty:
            try:
                _panel_context.db.session.commit()
            except Exception:
                _panel_context.db.session.rollback()

        exp_ts = _panel_context._effective_expiry_ts(sub)
        ttl_seconds = max(0, exp_ts - _panel_context.now_ts()) if exp_ts else None

        if limit_bytes is not None:
            used_bytes = min(int(used_bytes), int(limit_bytes))

        return {
            'id': sub.id,
            'name': sub.name,
            'token': sub.token,
            'display_timezone': _panel_context._panel_timezone_name(),
            'enabled': bool(getattr(sub, 'enabled', True)),
            'unlimited': bool(getattr(sub, 'unlimited', False)),
            'limit_bytes': limit_bytes,
            'used_bytes': int(used_bytes),
            'data_limit_value': getattr(sub, 'data_limit_value', 0) or 0,
            'data_limit_unit': getattr(sub, 'data_limit_unit', 'Gi') or 'Gi',
            'start_on_first_use': bool(getattr(sub, 'start_on_first_use', False)),
            'first_used_at': _panel_context.isoz(getattr(sub, 'first_used_at', None)),
            'first_used_at_display': _panel_context._panel_display_datetime(getattr(sub, 'first_used_at', None)),
            'expires_at': _panel_context.isoz(_panel_context.from_ts(exp_ts)),
            'expires_at_display': _panel_context._panel_display_datetime(_panel_context.from_ts(exp_ts)),
            'expires_at_ts': exp_ts,
            'ttl_seconds': ttl_seconds,
            'access': access,
            'locations': locs,
        }


    def _subscription_settings_public(
        sub=None,
    ):
        settings = (
            _panel_context._effective_subscription_settings(
                sub
            )
        )

        support = (
            settings.get('support')
            or {}
        )

        result = dict(
            settings
        )

        result[
            'socials'
        ] = {
            'telegram': support.get(
                'telegram',
                '',
            ),

            'whatsapp': support.get(
                'whatsapp',
                '',
            ),

            'instagram': support.get(
                'instagram',
                '',
            ),

            'phone': support.get(
                'phone',
                '',
            ),

            'website': support.get(
                'website',
                '',
            ),

            'email': support.get(
                'email',
                '',
            ),
        }

        result[
            'has_override'
        ] = bool(
            sub
            and _panel_context._subscription_portal_override(
                sub
            )
        )

        return result

    return {
        '_flag_from_cc': _flag_from_cc,
        '_load_geo_cache': _load_geo_cache,
        '_save_geo_cache': _save_geo_cache,
        '_i_public_host': _i_public_host,
        '_endpoint_host': _endpoint_host,
        '_node_public_host': _node_public_host,
        '_public_host_peer': _public_host_peer,
        '_lookup_geo': _lookup_geo,
        '_peer_used_for_subscription': _peer_used_for_subscription,
        'subscription_access': subscription_access,
        '_subscription_inbound_state': _subscription_inbound_state,
        '_subscription_access_or_403': _subscription_access_or_403,
        '_subscription_public_payload': _subscription_public_payload,
        '_subscription_settings_public': _subscription_settings_public,
    }
