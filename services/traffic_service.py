def bind_services(*,
    InterfaceConfig,
    Peer,
    TRAFFIC_GEO_DIR,
    TRAFFIC_GEO_MAX_AGE,
    TRAFFIC_NFT_TABLE,
    TRAFFIC_POLICY_FILE,
    _json_load,
    _json_save,
    _traffic_clean_iface,
    _traffic_host_addresses,
    _traffic_normalize_destination,
    _traffic_parse_cidrs,
    ipaddress,
    os,
    re,
    requests,
    secrets,
    shutil,
    socket,
    subprocess,
    time,
):

    def _traffic_default_config():
        return {
            "enabled": True,
            "policies": [],
        }

    def _traffic_load_config():
        data = _json_load(TRAFFIC_POLICY_FILE, _traffic_default_config())
        if not isinstance(data, dict):
            data = _traffic_default_config()
        policies = data.get("policies")
        if not isinstance(policies, list):
            policies = []
        return {
            "enabled": bool(data.get("enabled", True)),
            "policies": policies,
        }

    def _traffic_save_config(data):
        payload = {
            "enabled": bool((data or {}).get("enabled", True)),
            "policies": list((data or {}).get("policies") or []),
        }
        _json_save(TRAFFIC_POLICY_FILE, payload)
        return payload

    def _traffic_nft_capability():
        nft = shutil.which("nft")
        if not nft:
            return {
                "available": False,
                "usable": False,
                "reason": "not_installed",
                "detail": "The nft command was not found.",
            }
        try:
            result = subprocess.run(
                [nft, "list", "ruleset"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=8,
                check=False,
            )
            if result.returncode == 0:
                return {
                    "available": True,
                    "usable": True,
                    "reason": "ready",
                    "detail": "nftables is available and the panel can read the ruleset.",
                }
            return {
                "available": True,
                "usable": False,
                "reason": "permission_denied",
                "detail": (result.stderr or result.stdout or "nft list ruleset failed").strip()[:500],
            }
        except Exception as exc:
            return {
                "available": True,
                "usable": False,
                "reason": "nft_error",
                "detail": str(exc),
            }

    def _traffic_resolve_domains(domains):
        v4, v6, warnings = set(), set(), []
        resolved = {}
        for raw in list(domains or []):
            host = _traffic_normalize_destination(raw)
            if not host:
                warnings.append(f"Invalid domain: {raw}")
                continue
            found = []
            try:
                for family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                    candidate = sockaddr[0]
                    try:
                        ip_obj = ipaddress.ip_address(candidate)
                    except Exception:
                        continue
                    if ip_obj.version == 4:
                        v4.add(str(ip_obj))
                    else:
                        v6.add(str(ip_obj))
                    if str(ip_obj) not in found:
                        found.append(str(ip_obj))
            except Exception as exc:
                warnings.append(f"Could not resolve {host}: {exc}")
            resolved[host] = found
        return v4, v6, resolved, warnings

    def _traffic_geo_cache_path(country, version):
        os.makedirs(TRAFFIC_GEO_DIR, exist_ok=True)
        return os.path.join(TRAFFIC_GEO_DIR, f"{country.lower()}-v{version}.zone")

    def _traffic_geo_url(country, version):
        cc = country.lower()
        if version == 4:
            return f"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
        return f"https://www.ipdeny.com/ipv6/ipaddresses/blocks/{cc}.zone"

    def _traffic_geo_networks(country, version, *, force=False):
        cc = str(country or "").strip().lower()
        if not re.fullmatch(r"[a-z]{2}", cc):
            raise ValueError(f"Invalid country code: {country}")
        path = _traffic_geo_cache_path(cc, version)
        fresh = False
        try:
            fresh = os.path.isfile(path) and (time.time() - os.path.getmtime(path) < TRAFFIC_GEO_MAX_AGE)
        except Exception:
            fresh = False
        if force or not fresh:
            try:
                response = requests.get(_traffic_geo_url(cc, version), timeout=12)
                response.raise_for_status()
                text_body = response.text
                valid = []
                for line in text_body.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        if net.version == version:
                            valid.append(str(net))
                    except Exception:
                        continue
                if not valid:
                    raise ValueError("Downloaded country list was empty or invalid.")
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(valid) + "\n")
                os.replace(tmp, path)
            except Exception:
                if not os.path.isfile(path):
                    raise
        networks = []
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.version == version:
                        networks.append(str(net))
                except Exception:
                    continue
        return networks

    def _traffic_set_elements(values):
        return ", ".join(sorted(set(values)))

    def _traffic_apply_local(policies):
        capability = _traffic_nft_capability()
        if not capability.get("usable"):
            raise RuntimeError(
                capability.get("detail")
                or "nftables is unavailable"
            )

        nft = shutil.which("nft")
        if not nft:
            raise RuntimeError("The nft command was not found.")

        active = [
            p for p in list(policies or [])
            if isinstance(p, dict)
            and p.get("enabled", True)
        ]

        warnings = []
        domain_map = {}
        country_sets = {}
        policy_data = []

        for p in active:
            pid = str(
                p.get("id")
                or secrets.token_hex(6)
            )[:32]

            iface = _traffic_clean_iface(
                p.get("interface")
            )

            source_mode = str(
                p.get("source_mode")
                or "interface"
            )

            source_ips = (
                _traffic_host_addresses(
                    p.get("source_ip")
                )
                if source_mode == "peer"
                else []
            )

            cidr4, cidr6, cidr_warn = (
                _traffic_parse_cidrs(
                    p.get("cidrs") or []
                )
            )

            dom4, dom6, resolved, dom_warn = (
                _traffic_resolve_domains(
                    p.get("domains") or []
                )
            )

            warnings.extend([
                f"{p.get('name') or pid}: {warning}"
                for warning in (
                    cidr_warn + dom_warn
                )
            ])

            domain_map[pid] = resolved

            direct4 = set(cidr4) | set(dom4)
            direct6 = set(cidr6) | set(dom6)

            countries = []

            for raw_cc in list(
                p.get("countries") or []
            ):
                cc = str(
                    raw_cc or ""
                ).strip().lower()

                if not re.fullmatch(
                    r"[a-z]{2}",
                    cc,
                ):
                    warnings.append(
                        f"{p.get('name') or pid}: "
                        f"invalid country code {raw_cc}"
                    )
                    continue

                countries.append(cc)

                if cc not in country_sets:
                    try:
                        country_sets[cc] = {
                            4: _traffic_geo_networks(
                                cc,
                                4,
                            ),
                            6: _traffic_geo_networks(
                                cc,
                                6,
                            ),
                        }

                    except Exception as exc:
                        warnings.append(
                            f"Country {cc.upper()}: {exc}"
                        )
                        country_sets[cc] = {
                            4: [],
                            6: [],
                        }

            policy_data.append({
                "id": pid,
                "name": str(
                    p.get("name")
                    or "Traffic policy"
                ),
                "interface": iface,
                "source_mode": source_mode,
                "source_ips": source_ips,
                "direct4": sorted(direct4),
                "direct6": sorted(direct6),
                "countries": countries,
            })

        set_lines = []
        rule_lines = []

        for cc, versions in sorted(
            country_sets.items()
        ):
            for version, values in (
                (4, versions.get(4) or []),
                (6, versions.get(6) or []),
            ):
                if not values:
                    continue

                nft_type = (
                    "ipv4_addr"
                    if version == 4
                    else "ipv6_addr"
                )

                set_name = (
                    f"geo_{cc}_v{version}"
                )

                set_lines.append(
                    f"  set {set_name} {{ "
                    f"type {nft_type}; "
                    "flags interval; auto-merge; "
                    "elements = { "
                    f"{_traffic_set_elements(values)}"
                    " } }"
                )

        for row in policy_data:
            safe_id = (
                re.sub(
                    r"[^A-Za-z0-9_]",
                    "",
                    row["id"],
                )[:18]
                or secrets.token_hex(4)
            )

            for version, values in (
                (4, row["direct4"]),
                (6, row["direct6"]),
            ):
                if not values:
                    continue

                nft_type = (
                    "ipv4_addr"
                    if version == 4
                    else "ipv6_addr"
                )

                set_name = (
                    f"p_{safe_id}_v{version}"
                )

                set_lines.append(
                    f"  set {set_name} {{ "
                    f"type {nft_type}; "
                    "flags interval; auto-merge; "
                    "elements = { "
                    f"{_traffic_set_elements(values)}"
                    " } }"
                )

            source_by_version = {
                4: [],
                6: [],
            }

            for src in row["source_ips"]:
                try:
                    version = (
                        ipaddress.ip_address(src)
                        .version
                    )
                    source_by_version[
                        version
                    ].append(src)
                except Exception:
                    pass

            for version in (4, 6):
                family = (
                    "ip"
                    if version == 4
                    else "ip6"
                )

                source_clause = ""

                if row["source_mode"] == "peer":
                    sources = (
                        source_by_version[
                            version
                        ]
                    )

                    if not sources:
                        warnings.append(
                            f"{row['name']}: no IPv{version} "
                            "peer address, so IPv"
                            f"{version} peer-scoped blocking "
                            "was skipped"
                        )
                        continue

                    if len(sources) == 1:
                        source_clause = (
                            f" {family} saddr "
                            f"{sources[0]}"
                        )
                    else:
                        source_clause = (
                            f" {family} saddr {{ "
                            f"{', '.join(sources)} }}"
                        )

                base = (
                    f'    iifname "{row["interface"]}"'
                    f"{source_clause}"
                )

                direct = row[
                    f"direct{version}"
                ]

                if direct:
                    set_name = (
                        f"p_{safe_id}_v{version}"
                    )

                    rule_lines.append(
                        f"{base} {family} daddr "
                        f"@{set_name} counter drop "
                        f'comment "wgpanel:{safe_id}:'
                        f'direct:v{version}"'
                    )

                for cc in row["countries"]:
                    if not (
                        country_sets
                        .get(cc, {})
                        .get(version)
                    ):
                        continue

                    rule_lines.append(
                        f"{base} {family} daddr "
                        f"@geo_{cc}_v{version} "
                        "counter drop "
                        f'comment "wgpanel:{safe_id}:'
                        f'geo:{cc}:v{version}"'
                    )

        table_exists = (
            subprocess.run(
                [
                    nft,
                    "list",
                    "table",
                    "inet",
                    TRAFFIC_NFT_TABLE,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                check=False,
            ).returncode
            == 0
        )

        lines = []

        if table_exists:
            lines.append(
                f"delete table inet "
                f"{TRAFFIC_NFT_TABLE}"
            )

        lines.append(
            f"table inet {TRAFFIC_NFT_TABLE} {{"
        )

        lines.extend(set_lines)

        lines.extend([
            "  chain forward {",
            (
                "    type filter hook forward "
                "priority -10; policy accept;"
            ),
        ])

        lines.extend(rule_lines)

        lines.extend([
            "  }",
            "}",
        ])

        script = "\n".join(lines) + "\n"

        result = subprocess.run(
            [nft, "-f", "-"],
            input=script,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            detail = (
                result.stderr
                or result.stdout
                or "nftables apply failed"
            ).strip()

            raise RuntimeError(detail)

        return {
            "ok": True,
            "policies": len(policy_data),
            "rules": len(rule_lines),
            "warnings": warnings,
            "resolved_domains": domain_map,
        }

    def _traffic_local_status():
        capability = _traffic_nft_capability()
        result = {
            "capability": capability,
            "loaded": False,
            "counters": {},
        }
        if not capability.get("usable"):
            return result
        nft = shutil.which("nft")
        proc = subprocess.run(
            [nft, "list", "table", "inet", TRAFFIC_NFT_TABLE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        if proc.returncode != 0:
            return result
        result["loaded"] = True
        text_body = proc.stdout or ""
        for line in text_body.splitlines():
            m_comment = re.search(r'comment\s+"wgpanel:([^\"]+)"', line)
            m_counter = re.search(r'counter packets\s+(\d+)\s+bytes\s+(\d+)', line)
            if m_comment and m_counter:
                key = m_comment.group(1)
                result["counters"][key] = {
                    "packets": int(m_counter.group(1)),
                    "bytes": int(m_counter.group(2)),
                }
        return result

    def _traffic_targets_payload():
        peers_by_iface = {}
        for peer in Peer.query.order_by(Peer.name.asc()).all():
            peers_by_iface.setdefault(peer.iface_id, []).append({
                "id": peer.id,
                "name": peer.name,
                "address": peer.address,
                "public_key": peer.public_key,
            })

        interfaces = []
        for iface in InterfaceConfig.query.order_by(InterfaceConfig.node_id.asc().nullsfirst(), InterfaceConfig.name.asc()).all():
            peers = peers_by_iface.get(iface.id, [])
            interfaces.append({
                "id": iface.id,
                "name": iface.name,
                "address": iface.address,
                "node_id": iface.node_id,
                "node_name": iface.node.name if iface.node else "Local panel",
                "location": "node" if iface.node_id else "local",
                "peers": peers,
            })
        return interfaces

    def _traffic_normalize_policy(data):
        data = data or {}


        policy_id = re.sub(
            r"[^A-Za-z0-9_-]", "", str(data.get("id") or "")
        )[:32] or secrets.token_hex(8)
        name = str(data.get("name") or "Traffic policy").strip()[:80]
        location = str(data.get("location") or "local").strip().lower()
        if location not in {"local", "node"}:
            raise ValueError("location must be local or node")
        node_id = int(data.get("node_id") or 0) or None
        iface = _traffic_clean_iface(data.get("interface"))
        source_mode = str(data.get("source_mode") or "interface").strip().lower()
        if source_mode not in {"interface", "peer"}:
            raise ValueError("source_mode must be interface or peer")
        source_ip = str(data.get("source_ip") or "").strip()
        if source_mode == "peer" and not _traffic_host_addresses(source_ip):
            raise ValueError("A peer/source address is required for peer scope.")

        def clean_list(key, max_items=100):
            raw = data.get(key) or []
            if isinstance(raw, str):
                raw = re.split(r"[\n,]+", raw)
            return [str(x).strip() for x in list(raw) if str(x).strip()][:max_items]

        return {
            "id": policy_id,
            "name": name,
            "enabled": bool(data.get("enabled", True)),
            "location": location,
            "node_id": node_id if location == "node" else None,
            "interface": iface,
            "source_mode": source_mode,
            "source_ip": source_ip if source_mode == "peer" else "",
            "domains": clean_list("domains", 100),
            "cidrs": clean_list("cidrs", 200),
            "countries": [x.upper() for x in clean_list("countries", 50)],
        }

    def _traffic_nft_set_text(set_name):
        nft = shutil.which("nft")
        if not nft:
            return ""
        proc = subprocess.run(
            [nft, "list", "set", "inet", TRAFFIC_NFT_TABLE, str(set_name)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        return proc.stdout if proc.returncode == 0 else ""

    def _traffic_test_policy_local(policy):
        policy = dict(policy or {})
        pid = str(policy.get("id") or "").strip()
        name = str(policy.get("name") or "Traffic policy").strip()
        iface = _traffic_clean_iface(policy.get("interface"))
        source_mode = str(policy.get("source_mode") or "interface").strip().lower()
        source_ips = _traffic_host_addresses(policy.get("source_ip")) if source_mode == "peer" else []
        checks = []

        def add(key, label, status, detail):
            checks.append({
                "key": key,
                "label": label,
                "status": status,
                "detail": str(detail or ""),
            })

        capability = _traffic_nft_capability()
        if not capability.get("usable"):
            add("nftables", "nftables engine", "fail", capability.get("detail") or "nftables is unavailable.")
            return {
                "ok": False,
                "policy_id": pid,
                "policy_name": name,
                "checks": checks,
                "counters": {"packets": 0, "bytes": 0},
            }

        nft = shutil.which("nft")
        table_proc = subprocess.run(
            [nft, "list", "table", "inet", TRAFFIC_NFT_TABLE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        table_text = table_proc.stdout or ""
        if table_proc.returncode != 0:
            add("table", "Live policy table", "fail", "inet wgpanel_traffic is not loaded. Re-apply the policy rules.")
            return {
                "ok": False,
                "policy_id": pid,
                "policy_name": name,
                "checks": checks,
                "counters": {"packets": 0, "bytes": 0},
            }
        add("table", "Live policy table", "pass", "inet wgpanel_traffic is loaded in the kernel.")

        iface_proc = subprocess.run(
            ["wg", "show", iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        add(
            "interface",
            "WireGuard interface",
            "pass" if iface_proc.returncode == 0 else "fail",
            f"{iface} is active." if iface_proc.returncode == 0 else f"{iface} is not active in the WireGuard runtime.",
        )

        versions = {4, 6}
        if source_mode == "peer":
            versions = set()
            for src in source_ips:
                try:
                    versions.add(ipaddress.ip_address(src).version)
                except Exception:
                    pass
            if source_ips:
                add("scope", "Peer source scope", "pass", f"Live policy is expected to match only {', '.join(source_ips)} on {iface}.")
            else:
                add("scope", "Peer source scope", "fail", "The policy has no usable peer/source address.")

        safe_id = re.sub(r"[^A-Za-z0-9_]", "", pid)[:18]
        configured_domains = list(policy.get("domains") or [])
        configured_cidrs = list(policy.get("cidrs") or [])
        configured_countries = [str(x or "").strip().lower() for x in list(policy.get("countries") or []) if str(x or "").strip()]

        def rule_line(comment):
            marker = f'comment "{comment}"'
            for line in table_text.splitlines():
                if marker in line:
                    return line.strip()
            return ""

        def scope_matches(line, version):
            if not line or f'iifname "{iface}"' not in line:
                return False
            if source_mode != "peer":
                return True
            family = "ip" if version == 4 else "ip6"
            candidates = [s for s in source_ips if ipaddress.ip_address(s).version == version]
            return bool(candidates) and all((f"{family} saddr {s}" in line) or (s in line and f"{family} saddr" in line) for s in candidates)

        direct_needed = bool(configured_domains or configured_cidrs)
        for version in (4, 6):
            if version not in versions:
                if direct_needed:
                    add(f"direct_v{version}", f"IPv{version} direct rule", "info", f"Skipped because this peer has no IPv{version} WireGuard source address.")
                continue
            if not direct_needed:
                continue
            comment = f"wgpanel:{pid}:direct:v{version}"
            line = rule_line(comment)
            set_name = f"p_{safe_id}_v{version}"
            set_text = _traffic_nft_set_text(set_name)
            if line and scope_matches(line, version) and set_text:
                add(f"direct_v{version}", f"IPv{version} domain/IP rule", "pass", f"DROP rule and @{set_name} are loaded with the expected {iface} scope.")
            else:
                add(f"direct_v{version}", f"IPv{version} domain/IP rule", "fail", "The expected live DROP rule or destination set is missing. Save & apply again.")

        if configured_domains:
            dom4, dom6, resolved, warnings = _traffic_resolve_domains(configured_domains)
            for warning in warnings:
                add("domain_dns", "Domain resolution", "warn", warning)
            for version, values in ((4, sorted(dom4)), (6, sorted(dom6))):
                if version not in versions:
                    continue
                if not values:
                    continue
                set_name = f"p_{safe_id}_v{version}"
                set_text = _traffic_nft_set_text(set_name)
                present = [ip for ip in values if ip in set_text]
                missing = [ip for ip in values if ip not in set_text]
                if present and not missing:
                    add(f"domain_v{version}", f"IPv{version} domain addresses", "pass", f"Current DNS addresses are present in the live set: {', '.join(present[:4])}{'…' if len(present) > 4 else ''}")
                elif present:
                    add(f"domain_v{version}", f"IPv{version} domain addresses", "warn", f"DNS changed partially. {len(present)} current address(es) are loaded and {len(missing)} are not. Re-apply the policy.")
                else:
                    add(f"domain_v{version}", f"IPv{version} domain addresses", "fail", "Current DNS addresses are not in the live set. The domain changed since the last apply; refresh the live policy rules.")

        for cc in configured_countries:
            if not re.fullmatch(r"[a-z]{2}", cc):
                add(f"geo_{cc}", "Geo country", "fail", f"Invalid country code: {cc}")
                continue
            for version in (4, 6):
                if version not in versions:
                    continue
                set_name = f"geo_{cc}_v{version}"
                set_text = _traffic_nft_set_text(set_name)
                comment = f"wgpanel:{pid}:geo:{cc}:v{version}"
                line = rule_line(comment)
                if set_text and line and scope_matches(line, version):
                    add(f"geo_{cc}_v{version}", f"{cc.upper()} Geo IPv{version}", "pass", f"@{set_name} and its scoped DROP rule are loaded.")
                else:
                    add(f"geo_{cc}_v{version}", f"{cc.upper()} Geo IPv{version}", "fail", "The country set or its scoped DROP rule is missing.")

        status = _traffic_local_status()
        packets = 0
        byte_count = 0
        for key, counter in (status.get("counters") or {}).items():
            if str(key).startswith(pid + ":"):
                packets += int((counter or {}).get("packets") or 0)
                byte_count += int((counter or {}).get("bytes") or 0)
        add(
            "counters",
            "Live hit counters",
            "pass" if packets > 0 else "info",
            f"This policy has blocked {packets} packet(s) / {byte_count} byte(s)." if packets > 0 else "Rules are loaded but no real forwarded packet has matched them yet.",
        )

        if not (configured_domains or configured_cidrs or configured_countries):
            add("destinations", "Policy destinations", "fail", "The policy has no domains, IP/CIDR entries, or countries to block.")

        overall = not any(row.get("status") == "fail" for row in checks)
        return {
            "ok": overall,
            "policy_id": pid,
            "policy_name": name,
            "checks": checks,
            "counters": {"packets": packets, "bytes": byte_count},
        }

    def _traffic_live_set_contains(set_name, address):
        try:
            wanted = ipaddress.ip_address(
                str(address or '').strip()
            )
        except Exception:
            return False

        clean_set_name = str(
            set_name or ''
        ).strip()

        if not re.fullmatch(
            r'[A-Za-z0-9_.:-]{1,128}',
            clean_set_name,
        ):
            return False

        nft = shutil.which("nft")

        if nft:
            try:
                script = (
                    f"get element inet "
                    f"{TRAFFIC_NFT_TABLE} "
                    f"{clean_set_name} "
                    f"{{ {wanted} }}\n"
                )

                result = subprocess.run(
                    [nft, "-f", "-"],
                    input=script,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=8,
                    check=False,
                )

                if result.returncode == 0:
                    return True

            except Exception:
                pass

        text_body = _traffic_nft_set_text(
            clean_set_name
        )

        if not text_body:
            return False

        match = re.search(
            r'elements\s*=\s*\{(.*?)\}',
            text_body,
            re.S,
        )

        if not match:
            return False

        for raw_token in match.group(1).split(','):
            token = ' '.join(
                raw_token.strip().split()
            )

            if not token:
                continue

            try:
                if (
                    '-' in token
                    and '/' not in token
                ):
                    first, last = [
                        part.strip()
                        for part in token.split(
                            '-',
                            1,
                        )
                    ]

                    start_ip = ipaddress.ip_address(
                        first
                    )
                    end_ip = ipaddress.ip_address(
                        last
                    )

                    if (
                        start_ip.version
                        == wanted.version
                        and int(start_ip)
                        <= int(wanted)
                        <= int(end_ip)
                    ):
                        return True

                    continue

                if '/' in token:
                    network = ipaddress.ip_network(
                        token,
                        strict=False,
                    )

                    if (
                        network.version
                        == wanted.version
                        and wanted in network
                    ):
                        return True

                    continue

                if (
                    ipaddress.ip_address(token)
                    == wanted
                ):
                    return True

            except Exception:
                continue

        return False

    def _traffic_manual_target_addresses(target):
        raw = str(target or '').strip()
        if not raw:
            raise ValueError('Enter a domain, URL, IPv4 or IPv6 address.')

        candidate = raw.strip('[]')
        try:
            return raw, '', [str(ipaddress.ip_address(candidate))]
        except Exception:
            pass

        host = _traffic_normalize_destination(raw)
        if not host:
            raise ValueError('The destination is not a valid domain, URL, IPv4 or IPv6 address.')

        found = []
        try:
            for _family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                if not sockaddr:
                    continue
                try:
                    value = str(ipaddress.ip_address(sockaddr[0]))
                except Exception:
                    continue
                if value not in found:
                    found.append(value)
        except Exception as exc:
            raise ValueError(f'Could not resolve {host}: {exc}') from exc

        if not found:
            raise ValueError(f'{host} did not resolve to a usable IP address.')

        return raw, host, found

    def _traffic_manual_test_local(policy, target):
        policy = dict(policy or {})
        pid = str(policy.get('id') or '').strip()
        iface = _traffic_clean_iface(policy.get('interface'))
        source_mode = str(policy.get('source_mode') or 'interface').strip().lower()
        source_ips = _traffic_host_addresses(policy.get('source_ip')) if source_mode == 'peer' else []

        capability = _traffic_nft_capability()
        if not capability.get('usable'):
            raise RuntimeError(capability.get('detail') or 'nftables is unavailable.')

        nft = shutil.which('nft')
        table_proc = subprocess.run(
            [nft, 'list', 'table', 'inet', TRAFFIC_NFT_TABLE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        if table_proc.returncode != 0:
            raise RuntimeError('inet wgpanel_traffic is not loaded. Re-apply the policy rules.')
        table_text = table_proc.stdout or ''

        original_target, hostname, addresses = _traffic_manual_target_addresses(target)
        safe_id = re.sub(r'[^A-Za-z0-9_]', '', pid)[:18]
        countries = [
            str(value or '').strip().lower()
            for value in list(policy.get('countries') or [])
            if re.fullmatch(r'[A-Za-z]{2}', str(value or '').strip())
        ]

        source_versions = {4, 6}
        if source_mode == 'peer':
            source_versions = set()
            for source in source_ips:
                try:
                    source_versions.add(ipaddress.ip_address(source).version)
                except Exception:
                    pass

        def rule_line(comment):
            marker = f'comment "{comment}"'
            for line in table_text.splitlines():
                if marker in line:
                    return line.strip()
            return ''

        def scoped_rule_exists(comment, version):
            line = rule_line(comment)
            if not line or f'iifname "{iface}"' not in line:
                return False
            if source_mode != 'peer':
                return True
            family = 'ip' if version == 4 else 'ip6'
            candidates = []
            for source in source_ips:
                try:
                    if ipaddress.ip_address(source).version == version:
                        candidates.append(source)
                except Exception:
                    pass
            return bool(candidates) and all(source in line and f'{family} saddr' in line for source in candidates)

        results = []
        for address in addresses:
            ip_obj = ipaddress.ip_address(address)
            version = ip_obj.version
            applicable = version in source_versions
            matches = []

            if applicable:
                direct_set = f'p_{safe_id}_v{version}'
                direct_comment = f'wgpanel:{pid}:direct:v{version}'
                if (
                    _traffic_live_set_contains(direct_set, address)
                    and scoped_rule_exists(direct_comment, version)
                ):
                    matches.append({
                        'kind': 'direct',
                        'label': 'Domain/IP set',
                        'set': direct_set,
                        'comment': direct_comment,
                    })

                for cc in countries:
                    geo_set = f'geo_{cc}_v{version}'
                    geo_comment = f'wgpanel:{pid}:geo:{cc}:v{version}'
                    if (
                        _traffic_live_set_contains(geo_set, address)
                        and scoped_rule_exists(geo_comment, version)
                    ):
                        matches.append({
                            'kind': 'geo',
                            'label': f'Geo {cc.upper()}',
                            'set': geo_set,
                            'comment': geo_comment,
                        })

            results.append({
                'ip': address,
                'version': version,
                'applicable': applicable,
                'blocked': bool(applicable and matches),
                'matches': matches,
                'note': (
                    '' if applicable
                    else f'This peer has no IPv{version} WireGuard source address.'
                ),
            })

        applicable_rows = [row for row in results if row.get('applicable')]
        blocked_rows = [row for row in applicable_rows if row.get('blocked')]

        if not applicable_rows:
            verdict = 'not_applicable'
        elif len(blocked_rows) == len(applicable_rows):
            verdict = 'blocked'
        elif blocked_rows:
            verdict = 'partial'
        else:
            verdict = 'not_blocked'

        scope = (
            f'{iface} · peer source {", ".join(source_ips)}'
            if source_mode == 'peer'
            else f'{iface} · entire interface'
        )

        return {
            'ok': True,
            'policy_id': pid,
            'policy_name': str(policy.get('name') or 'Traffic policy'),
            'target': original_target,
            'hostname': hostname,
            'resolved': addresses,
            'verdict': verdict,
            'scope': scope,
            'results': results,
            'note': (
                'This evaluates the live nftables sets and exact scoped DROP rules. '
                'It does not generate traffic as the WireGuard peer.'
            ),
        }

    return {
        '_traffic_default_config': _traffic_default_config,
        '_traffic_load_config': _traffic_load_config,
        '_traffic_save_config': _traffic_save_config,
        '_traffic_nft_capability': _traffic_nft_capability,
        '_traffic_resolve_domains': _traffic_resolve_domains,
        '_traffic_geo_cache_path': _traffic_geo_cache_path,
        '_traffic_geo_url': _traffic_geo_url,
        '_traffic_geo_networks': _traffic_geo_networks,
        '_traffic_set_elements': _traffic_set_elements,
        '_traffic_apply_local': _traffic_apply_local,
        '_traffic_local_status': _traffic_local_status,
        '_traffic_targets_payload': _traffic_targets_payload,
        '_traffic_normalize_policy': _traffic_normalize_policy,
        '_traffic_nft_set_text': _traffic_nft_set_text,
        '_traffic_test_policy_local': _traffic_test_policy_local,
        '_traffic_live_set_contains': _traffic_live_set_contains,
        '_traffic_manual_target_addresses': _traffic_manual_target_addresses,
        '_traffic_manual_test_local': _traffic_manual_test_local,
    }
