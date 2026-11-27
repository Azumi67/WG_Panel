def bind_int_or_none(_panel_context):
    def _int_or_none(v):
        try:
            return int(v) if v is not None and str(v).strip() != '' else None
        except Exception:
            return None


    def _derive_wg_public_key(priv) -> str:
        priv = (priv or '').strip()
        if not priv or priv == '(remote)':
            return ''

        cache = None
        try:
            cache = _panel_context.g._wg_pubkey_cache
        except Exception:
            try:
                cache = _panel_context.g._wg_pubkey_cache = {}
            except Exception:
                cache = None
        if cache is not None and priv in cache:
            return cache[priv]

        try:
            out = _panel_context.subprocess.check_output(
                ['wg', 'pubkey'],
                input=(priv + '\n').encode(),
                stderr=_panel_context.subprocess.DEVNULL,
                timeout=2.0,
            )
            pk = _panel_context._valid_wg_key(out.decode().strip())
        except Exception:
            pk = ''

        if cache is not None:
            cache[priv] = pk
        return pk


    def _copy_local_iface_from_parsed(existing, parsed):
        new_priv = getattr(parsed, 'private_key', None)
        if (existing.private_key or '') != (new_priv or ''):
            existing.public_key = None
        existing.path = parsed.path
        existing.address = parsed.address
        existing.listen_port = parsed.listen_port
        existing.private_key = new_priv
        existing.mtu = parsed.mtu
        existing.dns = parsed.dns
        existing.post_up = parsed.post_up
        existing.post_down = parsed.post_down
        pk = _panel_context._derive_wg_public_key(new_priv)
        if pk:
            _panel_context._assign_iface_public_key(existing, pk)
        return existing


    def _wg_runtime_snapshot(iface_names, *, failures=None):

        transfers = {}
        handshakes = {}

        names = {
            str(name or '').strip()
            for name in iface_names
            if str(name or '').strip()
        }

        for iface_name in sorted(names):
            try:
                dev = iface_name.split(':')[-1]

                lines = _panel_context.subprocess.check_output(
                    ['wg', 'show', dev, 'dump'],
                    stderr=_panel_context.subprocess.DEVNULL,
                    timeout=2.0,
                ).decode(
                    errors='replace'
                ).splitlines()

                for line in lines[1:]:
                    columns = line.split('\t')

                    if len(columns) < 8:
                        columns = line.split()

                    if len(columns) < 8:
                        continue

                    public_key = columns[0].strip()

                    if not public_key:
                        continue

                    try:
                        latest_handshake = int(columns[4] or 0)
                    except (TypeError, ValueError):
                        latest_handshake = 0

                    try:
                        rx_bytes = int(columns[5] or 0)
                        tx_bytes = int(columns[6] or 0)
                    except (TypeError, ValueError):
                        rx_bytes = 0
                        tx_bytes = 0

                    key = (iface_name, public_key)

                    transfers[key] = (rx_bytes, tx_bytes)
                    handshakes[key] = latest_handshake

            except (
                _panel_context.subprocess.TimeoutExpired,
                _panel_context.subprocess.CalledProcessError,
                FileNotFoundError,
                OSError,
            ):
                if failures is not None:failures.add(iface_name)
                continue

            except Exception:
                if failures is not None:failures.add(iface_name)
                _panel_context.current_app.logger.debug(
                    "WireGuard runtime snapshot failed for %s",
                    iface_name,
                    exc_info=True,
                )

        return transfers, handshakes


    def _wg_checked_runtime_snapshot(iface_names):
        unavailable = set()
        transfers, handshakes = _panel_context._wg_runtime_snapshot(iface_names, failures=unavailable)
        return transfers, handshakes, unavailable


    def _accumulate_peer_usage(peer, live_total=None):
        changed = False

        try:
            if live_total is None:
                live = int(_panel_context._wg_transfer(peer) or 0)
            else:
                live = int(live_total or 0)
        except (TypeError, ValueError):
            live = 0
        except Exception:
            _panel_context.current_app.logger.debug(
                "Could not read live traffic for peer %s",
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

        try:
            persisted = int(
                getattr(peer, 'used_bytes_total', 0) or 0
            )
        except (TypeError, ValueError):
            persisted = 0

        offset = max(0, offset)
        persisted = max(0, persisted)


        if live == 0 and offset > 0:
            return int(persisted), 0, False

        if live < offset:
            offset = 0

            if int(getattr(peer, 'bytes_offset', 0) or 0) != 0:
                peer.bytes_offset = 0
                changed = True

        delta = max(0, live - offset)

        if delta > 0:
            persisted += delta

            peer.used_bytes_total = persisted
            peer.bytes_offset = live
            changed = True

        else:
            if getattr(peer, 'used_bytes_total', None) is None:
                peer.used_bytes_total = persisted
                changed = True

            if getattr(peer, 'bytes_offset', None) is None:
                peer.bytes_offset = live
                changed = True

        return (
            int(persisted),
            int(delta),
            bool(changed),
        )


    def _preview_peer_usage(peer, live_total):
        from types import SimpleNamespace
        snapshot = SimpleNamespace(bytes_offset=peer.bytes_offset,
                                   used_bytes_total=peer.used_bytes_total)
        return _panel_context._accumulate_peer_usage(snapshot, live_total)[0]


    def _fix_route(iid: int, wgquick_output: str):
        if "RTNETLINK answers: File exists" not in (wgquick_output or ""):
            return False

        fixed_any = False
        for ln in (wgquick_output or "").splitlines():
            s = ln.strip()

            if not s.startswith("[#] ip "):
                continue
            if " route add " not in s:
                continue


            cmdline = s.replace("[#] ", "", 1)
            cmdline = cmdline.replace(" route add ", " route replace ", 1)

            rc, out = _panel_context._run_capture(_panel_context.shlex.split(cmdline), timeout=6.0)
            _panel_context._iface_log(iid, f"$ {cmdline}\n{out}".rstrip())
            if rc == 0:
                fixed_any = True

        return fixed_any


    def _check_iface_up(iface: _panel_context.InterfaceConfig):
        if not iface:
            return

        if getattr(iface, 'node_id', None) is not None or (':' in (iface.name or '')):
            return

        dev = _panel_context.iface_devname(iface)
        iid = int(getattr(iface, "id", 0) or 0)

        if _panel_context._iface_up(dev):
            return

        cmd = ['wg-quick', 'up', dev]
        rc, out = _panel_context._run_capture(cmd, timeout=20.0)
        _panel_context._iface_log(iid, f"$ {' '.join(cmd)}\n{out}".rstrip())

        if rc == 0 and _panel_context._iface_up(dev):
            return

        recovered = _panel_context._fix_route(iid, out)
        if recovered and _panel_context._iface_up(dev):
            _panel_context._iface_log(iid, "Recovered from route-exists error; interface is up.")
            return

        _panel_context.current_app.logger.warning(
            "wg-quick up %s failed (rc=%s); trying manual bring-up",
            dev,
            rc
        )

        rc0, out0 = _panel_context._run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
        _panel_context._iface_log(iid, f"$ ip link del dev {dev}\n{out0}".rstrip())

        c = ['ip', 'link', 'add', 'dev', dev, 'type', 'wireguard']
        rc1, out1 = _panel_context._run_capture(c, timeout=6.0)
        _panel_context._iface_log(iid, f"$ {' '.join(c)}\n{out1}".rstrip())
        if rc1 != 0:
            raise RuntimeError(f"Could not create interface {dev}: {out1.strip() or 'ip link add failed'}")

        private_key = (getattr(iface, 'private_key', None) or '').strip()

        if not private_key and iface.path and _panel_context.os.path.isfile(iface.path):
            try:
                with open(iface.path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip().lower().startswith('privatekey'):
                            private_key = line.split('=', 1)[1].strip()
                            break
            except Exception:
                private_key = ''

        if not private_key:
            _panel_context._run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
            raise RuntimeError(f"Missing private key for interface {dev}")

        key_file = None
        try:
            fd, key_file = _panel_context.tempfile.mkstemp(prefix=f'{dev}_key_', text=True)
            with _panel_context.os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(private_key + '\n')
            _panel_context.os.chmod(key_file, 0o600)

            listen_port = int(getattr(iface, 'listen_port', 0) or 0)
            if not (1 <= listen_port <= 65535):
                listen_port = 51820

            c = ['wg', 'set', dev, 'private-key', key_file, 'listen-port', str(listen_port)]
            rc2, out2 = _panel_context._run_capture(c, timeout=10.0)
            _panel_context._iface_log(iid, f"$ wg set {dev} private-key <hidden> listen-port {listen_port}\n{out2}".rstrip())
            if rc2 != 0:
                _panel_context._run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
                raise RuntimeError(f"Could not configure WireGuard interface {dev}: {out2.strip() or 'wg set failed'}")
        finally:
            if key_file:
                try:
                    _panel_context.os.remove(key_file)
                except Exception:
                    pass

        address = (getattr(iface, 'address', None) or '').strip()

        if not address and iface.path and _panel_context.os.path.isfile(iface.path):
            try:
                with open(iface.path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip().lower().startswith('address'):
                            address = line.split('=', 1)[1].strip()
                            break
            except Exception:
                address = ''

        if address:
            for addr in [x.strip() for x in address.split(',') if x.strip()]:
                c = ['ip', 'address', 'add', addr, 'dev', dev]
                rc3, out3 = _panel_context._run_capture(c, timeout=6.0)
                _panel_context._iface_log(iid, f"$ {' '.join(c)}\n{out3}".rstrip())

                if rc3 != 0 and 'File exists' not in out3:
                    _panel_context._run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
                    raise RuntimeError(f"Could not add address {addr} to {dev}: {out3.strip() or 'ip address add failed'}")


        mtu = getattr(iface, 'mtu', None)
        try:
            mtu = int(mtu) if mtu not in (None, '') else None
        except Exception:
            mtu = None

        if mtu:
            c = ['ip', 'link', 'set', 'mtu', str(mtu), 'dev', dev]
            rc4, out4 = _panel_context._run_capture(c, timeout=6.0)
            _panel_context._iface_log(iid, f"$ {' '.join(c)}\n{out4}".rstrip())


        c = ['ip', 'link', 'set', 'up', 'dev', dev]
        rc5, out5 = _panel_context._run_capture(c, timeout=6.0)
        _panel_context._iface_log(iid, f"$ {' '.join(c)}\n{out5}".rstrip())

        if rc5 != 0:
            _panel_context._run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
            raise RuntimeError(f"Could not bring interface {dev} up: {out5.strip() or 'ip link set up failed'}")

        if not _panel_context._iface_up(dev):
            _panel_context._run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
            raise RuntimeError(f"Interface {dev} bring-up failed; see Interface logs for details.")

    return {
        '_int_or_none': _int_or_none,
        '_derive_wg_public_key': _derive_wg_public_key,
        '_copy_local_iface_from_parsed': _copy_local_iface_from_parsed,
        '_wg_runtime_snapshot': _wg_runtime_snapshot,
        '_wg_checked_runtime_snapshot': _wg_checked_runtime_snapshot,
        '_accumulate_peer_usage': _accumulate_peer_usage,
        '_preview_peer_usage': _preview_peer_usage,
        '_fix_route': _fix_route,
        '_check_iface_up': _check_iface_up,
    }


def bind_public_ipv4(_panel_context):
    def _public_ipv4(force=False):
        now = _panel_context.time.time()
        if not force and (now - _panel_context._public_ip_cache['ts'] < (3600 if _panel_context._public_ip_cache['ip'] else 30)):
            return _panel_context._public_ip_cache['ip']
        try:
            ip = _panel_context.requests.get('https://api.ipify.org', timeout=2).text.strip()
            if ip:
                _panel_context._public_ip_cache['ip'] = ip
                _panel_context._public_ip_cache['ts'] = now
                return ip
        except Exception:
            pass
        _panel_context._public_ip_cache['ts'] = now
        return _panel_context._public_ip_cache['ip']


    def _public_ipv6():

        try:
            now = _panel_context.time.time()

            if not _panel_context._ipv6_cache["val"] and now - _panel_context._ipv6_cache["ts"] < 30:
                return ""

            if _panel_context._ipv6_cache["val"] and (now - _panel_context._ipv6_cache["ts"] < 600):
                v = (_panel_context._ipv6_cache["val"] or "").strip()
                try:
                    ip = _panel_context.ipaddress.ip_address(v)
                    if ip.version == 6 and ip.is_global:
                        return v
                except Exception:
                    pass
                _panel_context._ipv6_cache.update(ts=now, val="")

            r = _panel_context.requests.get("https://api64.ipify.org", timeout=1.5)
            if not r.ok:
                _panel_context._ipv6_cache["ts"] = now
                return _panel_context._ipv6_cache["val"]

            v = (r.text or "").strip()

            try:
                ip = _panel_context.ipaddress.ip_address(v)
                if ip.version == 6 and ip.is_global:
                    _panel_context._ipv6_cache.update(ts=now, val=v)
                    return v
            except Exception:
                pass

            _panel_context._ipv6_cache.update(ts=now, val="")
            return ""
        except Exception:
            _panel_context._ipv6_cache["ts"] = _panel_context.time.time()
            return _panel_context._ipv6_cache.get("val") or ""


    def find_iface(path):
        post_up, post_down = [], []
        address = listen_port = private_key = mtu = dns = None
        in_iface = False
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    in_iface = (line[1:-1] == 'Interface')
                    continue
                if not in_iface or '=' not in line:
                    continue
                key, val = [s.strip() for s in line.split('=', 1)]
                lk = key.lower()
                if lk == 'address':
                    address = val
                elif lk == 'listenport':
                    try: listen_port = int(val)
                    except: pass
                elif lk == 'privatekey':
                    private_key = val
                elif lk == 'mtu':
                    try: mtu = int(val)
                    except: pass
                elif lk == 'dns':
                    dns = val
                elif lk == 'postup':
                    post_up.append(val)
                elif lk == 'postdown':
                    post_down.append(val)
        if not (address and listen_port and private_key):
            return None
        return _panel_context.InterfaceConfig(
            name=_panel_context.os.path.splitext(_panel_context.os.path.basename(path))[0],
            path=path, address=address,
            listen_port=listen_port,
            private_key=private_key,
            mtu=mtu, dns=dns,
            post_up='\n'.join(post_up),
            post_down='\n'.join(post_down)
        )

    return {
        '_public_ipv4': _public_ipv4,
        '_public_ipv6': _public_ipv6,
        'find_iface': find_iface,
    }


def bind_keep_peer_address_host_in_sync(_panel_context):
    @_panel_context.event.listens_for(_panel_context.Peer, 'before_insert')
    @_panel_context.event.listens_for(_panel_context.Peer, 'before_update')
    def _keep_peer_address_host_in_sync(mapper, connection, target):

        target.address_host = _panel_context.peer_address_host(target.address)

    return {
        '_keep_peer_address_host_in_sync': _keep_peer_address_host_in_sync,
    }


def bind_read_lastip(_panel_context):
    def _read_lastip():
        try:
            with open(_panel_context.LAST_PUBLIC_IP_FILE, 'r') as f:
                return (f.read() or '').strip()
        except Exception:
            return ''


    def _write_lastip(ip):
        try:
            _panel_context.os.makedirs(_panel_context.app.instance_path, exist_ok=True)
            with open(_panel_context.LAST_PUBLIC_IP_FILE, 'w') as f:
                f.write((ip or '').strip())
        except Exception:
            pass


    def repoint_endpoints():
        cur = _panel_context._public_ipv4(force=True) or ''
        prev = _panel_context._read_lastip()
        if not cur or not prev or cur == prev:
            if cur and cur != prev: _panel_context._write_lastip(cur)
            return

        changed = 0
        for p in _panel_context.Peer.query.all():

            override = _panel_context.iface_endpoint_override(getattr(p, 'iface', None))
            if override and (p.endpoint or '').strip() == override:
                continue

            host, port = _panel_context._host_port(p.endpoint or '')
            if host == prev:
                p.endpoint = f"{cur}:{port}" if port else cur
                changed += 1
        if changed:
            _panel_context.db.session.commit()
            _panel_context.current_app.logger.info("Repointed %s peer endpoints from %s to %s", changed, prev, cur)

        _panel_context._write_lastip(cur)

    return {
        '_read_lastip': _read_lastip,
        '_write_lastip': _write_lastip,
        'repoint_endpoints': repoint_endpoints,
    }


def bind_global_ip(_panel_context):
    def _global_ip(ip: str) -> bool:
        try:
            addr = _panel_context.ipaddress.ip_address(ip)
            return addr.is_global
        except Exception:
            return False


    def _wg_endpoint_ips(timeout=1.5):
        ips = set()
        try:
            p = _panel_context.subprocess.run(
                ["wg", "show", "all", "endpoints"],
                capture_output=True, text=True, timeout=timeout
            )
            if p.returncode != 0:
                return ips

            for line in p.stdout.splitlines():
                line = line.strip()
                if not line or "(none)" in line:
                    continue
                tok = line.split()[-1]
                host = tok
                if host.startswith('['):
                    host = host.split(']')[0].lstrip('[')
                else:
                    if ':' in host:
                        host = host.rsplit(':', 1)[0]
                if _panel_context._global_ip(host):
                    ips.add(host)
        except Exception:
            pass
        return ips

    return {
        '_global_ip': _global_ip,
        '_wg_endpoint_ips': _wg_endpoint_ips,
    }


def bind_rate_mb(_panel_context):
    def _rate_mb(cur_bytes, prev_bytes, dt):
        if dt <= 0:
            return 0.0
        return max(0.0, (cur_bytes - prev_bytes) / dt / (1024 * 1024))

    return {
        '_rate_mb': _rate_mb,
    }
