import ipaddress
import re
import os
import subprocess


def _first_cidr(address_field: str | None) -> str | None:

    if not address_field:
        return None
    parts = [p.strip() for p in re.split(r'[,\s]+', address_field) if p.strip()]
    v4, vX = None, None
    for p in parts:
        if '/' not in p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4 and not v4:
                v4 = p
            if not vX:
                vX = p
        except Exception:
            continue
    return v4 or vX

def _safe_ip(cidr):
    import ipaddress as _ipa
    try:
        return _ipa.ip_interface(cidr).ip
    except Exception:
        return None

def _wg_allowed_ips(iface):
    used = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', iface.name, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) != 2:
                continue
            for c in parts[1].split(','):
                h = _safe_ip(c.strip())
                if h is not None:
                    used.add(h)
    except Exception:
        pass
    return used

def _conf_allowed_ips(iface):
    used = set()
    p = iface.path
    if not (p and os.path.isfile(p)):
        return used
    try:
        with open(p, 'r') as f:
            in_peer, buf = False, []
            for raw in f:
                line = raw.strip()
                if line.startswith('[') and line.endswith(']'):
                    if in_peer:
                        for L in buf:
                            if L.lower().startswith('allowedips'):
                                for c in L.split('=', 1)[1].split(','):
                                    h = _safe_ip(c.strip())
                                    if h is not None:
                                        used.add(h)
                        buf = []
                    in_peer = (line[1:-1].lower() == 'peer')
                else:
                    if in_peer and '=' in line:
                        buf.append(line)
            if in_peer and buf:
                for L in buf:
                    if L.lower().startswith('allowedips'):
                        for c in L.split('=', 1)[1].split(','):
                            h = _safe_ip(c.strip())
                            if h is not None:
                                used.add(h)
    except Exception:
        pass
    return used

MAX_ENUMERATED_HOSTS = 8192

class AddressAllocationError(Exception):

    http_status = 400
    error_code = 'address_error'

class AddressInvalid(AddressAllocationError):

    http_status = 400
    error_code = 'invalid_address'

class AddressConflict(AddressAllocationError):

    http_status = 409
    error_code = 'address_conflict'

class AddressPoolExhausted(AddressConflict):

    error_code = 'address_pool_exhausted'

def _iface_is_node(iface) -> bool:
    name = getattr(iface, 'name', '') or ''
    return getattr(iface, 'node_id', None) is not None or (':' in name)

def _usable_hosts(net):

    for index, host in enumerate(net.hosts()):
        if index >= MAX_ENUMERATED_HOSTS:
            return
        yield host

def _validate_requested_host(ip_iface, requested):
    text = str(requested or '').strip()
    if not text:
        return None

    try:
        candidate = ipaddress.ip_interface(text)
    except ValueError:
        raise AddressInvalid(f'{text} is not a valid IP address.')

    host = candidate.ip
    net = ip_iface.network

    if host.version != net.version:
        raise AddressInvalid(
            f'{host} is IPv{host.version} but the interface network is IPv{net.version}.'
        )

    if host not in net:
        raise AddressInvalid(f'{host} is outside the interface network {net}.')

    point_to_point = 31 if net.version == 4 else 127
    if net.prefixlen < point_to_point:
        if host == net.network_address:
            raise AddressInvalid(f'{host} is the network address of {net}.')
        if net.version == 4 and host == net.broadcast_address:
            raise AddressInvalid(f'{host} is the broadcast address of {net}.')

    return host

def peer_address_host(address):
    host = _safe_ip(address)
    return str(host) if host is not None else None

class PeerRemovalError(Exception):

    def __init__(self, phase, message, status=500):
        super().__init__(message)
        self.phase = phase
        self.status = status

def _peer_ip_plain(peer) -> str:
    try:
        return str(ipaddress.ip_interface(peer.address).ip)
    except Exception:
        return ''

def bind_services(*,
    AddressAllocationError,
    AddressConflict,
    AddressInvalid,
    AddressPoolExhausted,
    InterfaceConfig,
    MAX_ENUMERATED_HOSTS,
    NodePeerInstallError,
    Peer,
    PeerEvent,
    PeerRemovalError,
    SubscriptionPeer,
    _ALLOC_LOCK_DIR,
    _assign_iface_public_key,
    _check_iface_up,
    _conf_allowed_ips,
    _delete_shortlinks_for_peer_ids,
    _first_cidr,
    _host_peer,
    _iface_is_node,
    _iface_up,
    _norm_conftext,
    _peer_in_conf,
    _read_iface_conf,
    _safe_ip,
    _unblackhole,
    _usable_hosts,
    _validate_requested_host,
    _wg_allowed_ips,
    _wg_disable,
    _wg_enable,
    _wg_peer_keys,
    _write_conf_atomic,
    contextmanager,
    current_app,
    db,
    from_ts,
    iface_devname,
    ipaddress,
    jsonify,
    node_delete,
    node_get,
    node_post,
    now_ts,
    os,
    requests,
):

    def interface_ip_interface(iface):

        if not iface:
            return None

        addr_field = None
        if not _iface_is_node(iface):
            addr_field = _read_iface_conf(getattr(iface, 'path', None))

        if not addr_field:
            addr_field = getattr(iface, 'address', None)

        cidr = _first_cidr(addr_field)
        if not cidr:
            return None

        if (not _iface_is_node(iface)) and addr_field and getattr(iface, 'address', None) != addr_field:
            try:
                iface.address = addr_field
                db.session.add(iface)
                db.session.commit()
            except Exception:
                db.session.rollback()

        try:
            return ipaddress.ip_interface(cidr)
        except ValueError:
            return None

    def _db_peer_hosts(iface, exclude_peer_id=None):

        hosts = set()
        iface_id = getattr(iface, 'id', None)
        if not iface_id:
            return hosts

        for address, address_host in db.session.query(Peer.address, Peer.address_host).filter(
            Peer.iface_id == iface_id,
            Peer.id != exclude_peer_id if exclude_peer_id else True,
        ):
            host = _safe_ip(address_host) or _safe_ip(address)
            if host is not None:
                hosts.add(host)

        return hosts

    def _reserved_hosts(iface, ip_iface, *, exclude_peer_id=None, exclude_address=None, extra=()):

        net = ip_iface.network
        reserved = {ip_iface.ip}

        point_to_point = 31 if net.version == 4 else 127
        if net.prefixlen < point_to_point:
            reserved.add(net.network_address)
            if net.version == 4:
                reserved.add(net.broadcast_address)

        reserved |= _db_peer_hosts(iface, exclude_peer_id=exclude_peer_id)

        if not _iface_is_node(iface):
            reserved |= _wg_allowed_ips(iface)
            reserved |= _conf_allowed_ips(iface)

        for value in extra or ():
            host = _safe_ip(value)
            if host is not None:
                reserved.add(host)

        own_host = _safe_ip(exclude_address)
        if own_host is not None and own_host != ip_iface.ip:
            reserved.discard(own_host)

        return reserved

    def allocate_peer_address(iface, requested=None, *, exclude_peer_id=None,
                              exclude_address=None, extra_reserved=()):

        ip_iface = interface_ip_interface(iface)
        if ip_iface is None:
            raise AddressInvalid(
                f'Interface {getattr(iface, "name", "?")} has no usable Address= setting.'
            )

        net = ip_iface.network
        reserved = _reserved_hosts(
            iface, ip_iface,
            exclude_peer_id=exclude_peer_id,
            exclude_address=exclude_address,
            extra=extra_reserved,
        )

        host = _validate_requested_host(ip_iface, requested)
        if host is not None:
            if host in reserved:
                raise AddressConflict(
                    f'{host} is already in use on {getattr(iface, "name", "?")}.'
                )
            return f'{host}/{net.prefixlen}'

        for candidate in _usable_hosts(net):
            if candidate not in reserved:
                return f'{candidate}/{net.prefixlen}'

        raise AddressPoolExhausted(f'No free client address left in {net}.')

    def address_error_response(exc: AddressAllocationError):
        return jsonify(error=exc.error_code, detail=str(exc)), exc.http_status

    def client_address_on(iface, value):

        host = _safe_ip(value)
        if host is None:
            return None

        ip_iface = interface_ip_interface(iface)
        if ip_iface is None:
            return str(value).strip()

        return f'{host}/{ip_iface.network.prefixlen}'

    def node_install_peer(node, iface_name, mirror, *, public_key, requested_address=None,
                          peer_endpoint='', keepalive=0, mtu=None, dns=None,
                          allowed_ips='0.0.0.0/0, ::/0', attempts=3):

        host_cidr = None
        if requested_address:
            host_cidr = allocate_peer_address(mirror, requested=requested_address)

        last_error = None

        for attempt in range(max(1, attempts)):
            payload = {
                'iface': iface_name,
                'public_key': public_key,
                'endpoint': (peer_endpoint or '').strip(),
                'persistent_keepalive': keepalive or 0,
                'mtu': mtu,
                'dns': dns,
                'allowed_ips': allowed_ips,
            }
            if host_cidr:
                payload['host_cidr'] = host_cidr

            try:
                response = node_post(node, '/api/peers/add', payload) or {}
            except requests.HTTPError as e:
                status = getattr(getattr(e, 'response', None), 'status_code', 0)
                body = getattr(getattr(e, 'response', None), 'text', '') or ''
                agent_code = _node_agent_error_code(getattr(e, 'response', None))

                if (
                    agent_code == 'address_pool_exhausted'
                    or (status == 409 and not host_cidr and 'pool' in body)
                ):
                    raise NodePeerInstallError(
                        'address_pool_exhausted', 409,
                        f'The node interface {iface_name} has no free client address.',
                    )

                if requested_address and status in (400, 409):
                    raise NodePeerInstallError(
                        'address_conflict', 409,
                        f'The requested address is not available on {iface_name}.',
                    )

                needs_panel_side_address = (
                    status == 400 and not host_cidr and 'host_cidr' in body
                )
                retryable_conflict = (
                    agent_code == 'host_cidr_already_used'
                    and not requested_address
                    and attempt + 1 < attempts
                )

                if needs_panel_side_address or retryable_conflict:
                    host_cidr = _node_pick_available_ip(node, iface_name, mirror)
                    last_error = e
                    continue

                raise NodePeerInstallError('node_create_failed', 502, body[:800] or str(e))
            except NodePeerInstallError:
                raise
            except AddressAllocationError:
                raise
            except Exception as e:
                raise NodePeerInstallError('node_create_failed', 502, str(e))

            assigned = ''
            if isinstance(response, dict):
                assigned = str(response.get('host_cidr') or '').strip()

            assigned = assigned or host_cidr
            if not assigned:
                raise NodePeerInstallError(
                    'node_create_failed', 502,
                    'The node did not report the address it assigned.'
                )

            address = client_address_on(mirror, assigned)
            if not address:
                raise NodePeerInstallError(
                    'node_create_failed', 502, f'The node returned an unusable address {assigned!r}.'
                )
            return address

        raise NodePeerInstallError(
            'node_create_failed', 502,
            f'Could not reserve an address on {iface_name}: {last_error}'
        )

    def node_reapply_peer(peer):
        from reseller_portal.service import may_enable
        may_enable(peer)
        iface = getattr(peer, 'iface', None)
        node = getattr(iface, 'node', None)
        if iface is None or node is None:
            raise NodePeerInstallError(
                'node_update_failed', 500, 'The peer node or interface is unavailable.'
            )

        payload = {
            'iface': iface_devname(iface),
            'public_key': peer.public_key,
            'host_cidr': _host_peer(peer),
            'endpoint': (getattr(peer, 'peer_endpoint', None) or '').strip(),
            'persistent_keepalive': getattr(peer, 'persistent_keepalive', None) or 0,
            'mtu': getattr(peer, 'mtu', None),
            'dns': getattr(peer, 'dns', None),
        }

        try:
            response = node_post(node, '/api/peers/add', payload) or {}
        except requests.HTTPError as exc:
            body = getattr(getattr(exc, 'response', None), 'text', '') or ''
            raise NodePeerInstallError('node_update_failed', 502, body[:800] or str(exc))
        except Exception as exc:
            raise NodePeerInstallError('node_update_failed', 502, str(exc))

        if isinstance(response, dict) and response.get('ok') is False:
            raise NodePeerInstallError(
                'node_update_failed', 502,
                str(response.get('detail') or response.get('error') or 'The node rejected the update.'),
            )

        if isinstance(response, dict) and response.get('duplicate') and response.get('updated') is not True:
            raise NodePeerInstallError(
                'node_update_unsupported', 502,
                'The node agent does not support full peer updates; update the node agent first.',
            )

        return response

    def _node_agent_error_code(response):

        if response is None:
            return ''
        try:
            body = response.json()
        except Exception:
            return ''
        if isinstance(body, dict):
            return str(body.get('error') or '').strip().lower()
        return ''

    def _node_pick_available_ip(node, iface_name, mirror):
        try:
            available = node_get(node, f'/api/iface/{iface_name}/available_ips')
            if isinstance(available, dict):
                available = available.get('available_ips') or []
            if isinstance(available, list) and available:
                return available[0]
        except Exception:
            current_app.logger.warning(
                'Could not read available_ips from node %s iface %s',
                getattr(node, 'id', '?'), iface_name, exc_info=True,
            )

        if mirror is not None:
            return allocate_peer_address(mirror)

        raise NodePeerInstallError('node_no_available_ip', 409, f'No free address on {iface_name}.')

    def ensure_node_mirror_iface(node, iface_name, remote_iface=None, *, mtu=None, dns=None,
                                 listen_port=None, server_cidr=None):
        remote_iface = remote_iface or {}
        db_iface_name = f'n{node.id}:{iface_name}'
        iface = InterfaceConfig.query.filter_by(name=db_iface_name).first()

        address = (remote_iface.get('address') or server_cidr or '').strip()

        try:
            port = int(remote_iface.get('listen_port') or listen_port or 51820)
        except Exception:
            port = 51820

        if not iface:
            iface = InterfaceConfig(
                name=db_iface_name,
                path=f'/etc/wireguard/{iface_name}.conf',
                address=address or '10.0.0.1/24',
                listen_port=port,
                private_key='(remote)',
                mtu=remote_iface.get('mtu') or mtu,
                dns=remote_iface.get('dns') or dns,
                node_id=node.id,
            )
            _assign_iface_public_key(iface, remote_iface.get('public_key'))
            db.session.add(iface)
            db.session.flush()
            return iface

        changed = False
        if address and iface.address != address:
            iface.address = address
            changed = True
        if remote_iface.get('listen_port') and iface.listen_port != port:
            iface.listen_port = port
            changed = True
        if remote_iface.get('mtu') and iface.mtu != remote_iface.get('mtu'):
            iface.mtu = remote_iface.get('mtu')
            changed = True
        if remote_iface.get('dns') and iface.dns != remote_iface.get('dns'):
            iface.dns = remote_iface.get('dns')
            changed = True
        if getattr(iface, 'node_id', None) != node.id:
            iface.node_id = node.id
            changed = True
        before_pk = getattr(iface, 'public_key', None)
        _assign_iface_public_key(iface, remote_iface.get('public_key'))
        if getattr(iface, 'public_key', None) != before_pk:
            changed = True

        if changed:
            db.session.flush()

        return iface

    def resolve_requested_peer_address(iface, value, *, allow_legacy_interface_address=False):

        text = str(value or '').strip()
        if not text:
            return None

        try:
            candidate = ipaddress.ip_interface(text)
        except ValueError:
            raise AddressInvalid(f'{text} is not a valid IP address.')

        ip_iface = interface_ip_interface(iface)
        if (
            allow_legacy_interface_address
            and ip_iface is not None
            and candidate.ip == ip_iface.ip
        ):
            return None

        return text

    def requested_peer_address_from_target(iface, target):
        explicit = str((target or {}).get('peer_address') or '').strip()
        if explicit:
            return resolve_requested_peer_address(iface, explicit)

        return resolve_requested_peer_address(
            iface,
            (target or {}).get('address'),
            allow_legacy_interface_address=True,
        )

    @contextmanager
    def interface_allocation_lock(iface):
        from panel_core.interface_lock import interface_lock
        with interface_lock(_ALLOC_LOCK_DIR, iface.name):
            yield

    def _available_ips(iface, limit=MAX_ENUMERATED_HOSTS):

        if not iface:
            return []

        try:
            ip_iface = interface_ip_interface(iface)
            if ip_iface is None:
                return []

            net = ip_iface.network
            reserved = _reserved_hosts(iface, ip_iface)

            out = []
            for host in _usable_hosts(net):
                if host in reserved:
                    continue
                out.append(f'{host}/{net.prefixlen}')
                if len(out) >= limit:
                    break
            return out

        except Exception as e:
            current_app.logger.exception(
                "_available_ips failed for iface=%r: %s", getattr(iface, "name", None), e
            )
            return []

    def log_event(peer, event, details='', *, commit=True):
        e = PeerEvent(
            peer_id=peer.id,
            timestamp=from_ts(now_ts()),
            event=event,
            details=details,
        )
        db.session.add(e)
        if commit:
            db.session.commit()

    def _peer_to_conf(peer: Peer):
        with interface_allocation_lock(peer.iface):
            conf_path = getattr(peer.iface, 'path', None)
            if not conf_path:
                raise RuntimeError('The interface has no configuration file path.')

            if _peer_in_conf(conf_path, peer.public_key):
                return

            block_lines = [
                '[Peer]',
                f'PublicKey = {peer.public_key}',
                f'AllowedIPs = {_host_peer(peer)}',
            ]

            fixed_endpoint = (getattr(peer, 'peer_endpoint', None) or '').strip()
            if fixed_endpoint:
                block_lines.append(f'Endpoint = {fixed_endpoint}')
            if peer.persistent_keepalive:
                block_lines.append(f'PersistentKeepalive = {peer.persistent_keepalive}')

            block_txt = '\n'.join(block_lines) + '\n'

            existing = ''
            if os.path.isfile(conf_path):
                with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
                    existing = f.read()

            existing = (existing or '').replace('\r\n', '\n').replace('\r', '\n').rstrip('\n')
            combined = block_txt if existing.strip() == '' else existing + '\n\n' + block_txt

            _write_conf_atomic(conf_path, _norm_conftext(combined))

            if not _peer_in_conf(conf_path, peer.public_key):
                raise RuntimeError(f'Peer block was not persisted to {conf_path}.')

    def _remove_peer(peer: Peer):
        with interface_allocation_lock(peer.iface):

            conf_path = getattr(peer.iface, 'path', None)
            if not conf_path:
                return
            if not os.path.isfile(conf_path):
                return

            with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            out_lines, i = [], 0
            while i < len(lines):
                line = lines[i]
                if line.strip().lower() == '[peer]':
                    block = [line]
                    i += 1
                    while i < len(lines) and not lines[i].strip().startswith('['):
                        block.append(lines[i]); i += 1

                    has_pk = any(
                        l.partition('=')[0].strip().lower() == 'publickey'
                        and '=' in l
                        and l.split('=', 1)[1].strip() == peer.public_key
                        for l in block
                    )
                    if not has_pk:
                        out_lines.extend(block)
                else:
                    out_lines.append(line); i += 1

            _write_conf_atomic(conf_path, _norm_conftext(''.join(out_lines)))

            if _peer_in_conf(conf_path, peer.public_key):
                raise RuntimeError(f'Peer block is still present in {conf_path}.')

    def _sync_peer(peer: Peer):
        with interface_allocation_lock(peer.iface):
            _remove_peer(peer)
            _peer_to_conf(peer)

    def _wg_disable_quiet(peer: Peer):
        try:
            _wg_disable(peer)
        except Exception:
            current_app.logger.warning(
                "Could not roll back runtime peer %s on %s",
                getattr(peer, 'public_key', '?'),
                getattr(getattr(peer, 'iface', None), 'name', '?'),
                exc_info=True,
            )

    def _remove_peer_quiet(peer: Peer):
        try:
            _remove_peer(peer)
        except Exception:
            current_app.logger.warning(
                "Could not roll back config peer %s",
                getattr(peer, 'public_key', '?'),
                exc_info=True,
            )

    def _rollback_local_created_peer(peer: Peer):
        errors = []
        dev = iface_devname(peer.iface) if getattr(peer, 'iface', None) else ''
        if dev and _iface_up(dev):
            try:
                _wg_disable(peer)
                if peer.public_key in _wg_peer_keys(dev):
                    raise RuntimeError(f'{peer.public_key} is still present in {dev}.')
            except Exception as exc:
                errors.append(f'runtime: {exc}')

        try:
            _remove_peer(peer)
        except Exception as exc:
            errors.append(f'config: {exc}')

        if errors:
            raise RuntimeError('; '.join(errors))

    def _rollback_node_created_peer(node, public_key):
        response = node_delete(node, f'/api/peer/{public_key}') or {}
        if isinstance(response, dict) and response.get('ok') is False:
            raise RuntimeError(
                str(response.get('detail') or response.get('error') or 'node cleanup failed')
            )

    def _peer_is_on_node(peer: Peer) -> bool:
        iface = getattr(peer, 'iface', None)
        if iface is None:
            return False
        return _iface_is_node(iface)

    def activate_reseller_peer(peer: Peer):
        from reseller_portal.service import may_enable
        may_enable(peer)
        if _peer_is_on_node(peer):
            node_reapply_peer(peer)
            response=node_post(peer.iface.node, f'/api/peer/{peer.public_key}/enable',
                               {'host_cidr':_host_peer(peer)}, timeout=12)
            if not isinstance(response,dict) or response.get('ok') is not True:
                raise ValueError('The node could not confirm activation.')
        else:
            dev=iface_devname(peer.iface)
            if not _iface_up(dev):_check_iface_up(peer.iface)
            if not _iface_up(dev):raise ValueError('The assigned interface is not running.')
            _wg_enable(peer)
            _sync_peer(peer)
            _unblackhole(_host_peer(peer))

    def reapply_peer_external(peer: Peer):
        from reseller_portal.service import may_enable
        may_enable(peer)
        if _peer_is_on_node(peer):
            node_reapply_peer(peer)
            return

        _wg_enable(peer)
        _sync_peer(peer)

    def remove_peer_everywhere(peer: Peer):

        if _peer_is_on_node(peer):
            _remove_node_peer(peer)
        else:
            _remove_local_peer_runtime_and_config(peer)

        return _delete_peer_rows(peer)

    def _remove_local_peer_runtime_and_config(peer: Peer):
        dev = iface_devname(peer.iface) if getattr(peer, 'iface', None) else ''

        if dev and _iface_up(dev):
            try:
                _wg_disable(peer)
            except Exception as e:
                raise PeerRemovalError('runtime', str(e), 502)

            if peer.public_key in _wg_peer_keys(dev):
                raise PeerRemovalError(
                    'runtime',
                    f'{peer.public_key} is still present in the {dev} runtime.',
                    502,
                )

        try:
            _remove_peer(peer)
        except Exception as e:
            raise PeerRemovalError('config', str(e), 500)

    def _remove_node_peer(peer: Peer):
        node = getattr(getattr(peer, 'iface', None), 'node', None)
        if node is None:
            raise PeerRemovalError('node', 'The node for this peer is unknown.', 500)

        try:
            response = node_delete(node, f'/api/peer/{peer.public_key}') or {}
        except Exception as e:
            raise PeerRemovalError('node', str(e), 502)

        if not isinstance(response, dict):
            return

        if response.get('ok') is False:
            raise PeerRemovalError(
                'node', str(response.get('error') or 'The node reported a failure.'), 502
            )

        for key, phase in (('runtime_removed', 'runtime'), ('config_removed', 'config')):
            if key in response and not response.get(key):
                raise PeerRemovalError(
                    phase,
                    f'The node did not confirm {phase} removal of {peer.public_key}.',
                    502,
                )

    def _delete_peer_rows(peer: Peer):

        try:
            removed_shortlinks = _delete_shortlinks_for_peer_ids([peer.id])
            SubscriptionPeer.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
            PeerEvent.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
            db.session.delete(peer)
            db.session.commit()
            return int(removed_shortlinks or 0)
        except Exception as e:
            db.session.rollback()
            raise PeerRemovalError('database', str(e), 500)

    def peer_removal_response(exc: PeerRemovalError, peer_id=None):
        return jsonify(
            ok=False,
            error='peer_removal_failed',
            phase=exc.phase,
            detail=str(exc),
            peer_id=peer_id,
            recoverable=True,
        ), exc.status

    def install_local_peer(peer: Peer):

        _check_iface_up(peer.iface)
        _wg_enable(peer)

        try:
            _sync_peer(peer)
        except Exception:
            _wg_disable_quiet(peer)
            raise

    return {
        'interface_ip_interface': interface_ip_interface,
        '_db_peer_hosts': _db_peer_hosts,
        '_reserved_hosts': _reserved_hosts,
        'allocate_peer_address': allocate_peer_address,
        'address_error_response': address_error_response,
        'client_address_on': client_address_on,
        'node_install_peer': node_install_peer,
        'node_reapply_peer': node_reapply_peer,
        '_node_agent_error_code': _node_agent_error_code,
        '_node_pick_available_ip': _node_pick_available_ip,
        'ensure_node_mirror_iface': ensure_node_mirror_iface,
        'resolve_requested_peer_address': resolve_requested_peer_address,
        'requested_peer_address_from_target': requested_peer_address_from_target,
        'interface_allocation_lock': interface_allocation_lock,
        '_available_ips': _available_ips,
        'log_event': log_event,
        '_peer_to_conf': _peer_to_conf,
        '_remove_peer': _remove_peer,
        '_sync_peer': _sync_peer,
        '_wg_disable_quiet': _wg_disable_quiet,
        '_remove_peer_quiet': _remove_peer_quiet,
        '_rollback_local_created_peer': _rollback_local_created_peer,
        '_rollback_node_created_peer': _rollback_node_created_peer,
        '_peer_is_on_node': _peer_is_on_node,
        'activate_reseller_peer': activate_reseller_peer,
        'reapply_peer_external': reapply_peer_external,
        'remove_peer_everywhere': remove_peer_everywhere,
        '_remove_local_peer_runtime_and_config': _remove_local_peer_runtime_and_config,
        '_remove_node_peer': _remove_node_peer,
        '_delete_peer_rows': _delete_peer_rows,
        'peer_removal_response': peer_removal_response,
        'install_local_peer': install_local_peer,
    }
