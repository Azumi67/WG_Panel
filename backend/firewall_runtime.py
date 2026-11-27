def bind_private_networks(_panel_context):
    def _private_networks():

        networks = []

        try:
            for interface_name, addresses in _panel_context.psutil.net_if_addrs().items():
                if interface_name == 'lo':
                    continue

                for address in addresses:
                    if getattr(address, 'family', None) != _panel_context.socket.AF_INET:
                        continue

                    ip_value = (
                        getattr(address, 'address', '')
                        or ''
                    ).split('%', 1)[0]

                    netmask = getattr(address, 'netmask', None)

                    if not ip_value or not netmask:
                        continue

                    try:
                        interface = _panel_context.ipaddress.ip_interface(
                            f"{ip_value}/{netmask}"
                        )

                        if (
                            interface.ip.is_loopback
                            or interface.ip.is_link_local
                            or interface.ip.is_unspecified
                        ):
                            continue

                        if not interface.ip.is_private:
                            continue

                        network = str(interface.network)

                        if network not in networks:
                            networks.append(network)

                    except (ValueError, TypeError):
                        continue

        except Exception:
            _panel_context.current_app.logger.exception(
                'Failed to detect local private networks'
            )

        return networks


    def _egress_interface() -> str:

        try:
            output = _panel_context.subprocess.check_output(
                [
                    'ip',
                    '-4',
                    'route',
                    'get',
                    '1.1.1.1',
                ],
                stderr=_panel_context.subprocess.DEVNULL,
                timeout=4,
            ).decode(
                'utf-8',
                'replace',
            )

            matches = _panel_context.re.findall(
                r'\bdev\s+([A-Za-z0-9_.:-]+)',
                output,
            )

            for candidate in matches:
                candidate = (
                    candidate
                    or ''
                ).strip()

                if not candidate:
                    continue

                if candidate == 'lo':
                    continue

                if _panel_context.re.match(
                    r'^(wg|tun|tap|docker|br-|veth)',
                    candidate,
                    _panel_context.re.IGNORECASE,
                ):
                    continue

                return candidate

        except Exception:
            _panel_context.current_app.logger.exception(
                'Could not detect the default '
                'IPv4 egress interface'
            )


        try:
            output = _panel_context.subprocess.check_output(
                [
                    'ip',
                    '-4',
                    'route',
                    'show',
                    'default',
                ],
                stderr=_panel_context.subprocess.DEVNULL,
                timeout=4,
            ).decode(
                'utf-8',
                'replace',
            )

            matches = _panel_context.re.findall(
                r'\bdev\s+([A-Za-z0-9_.:-]+)',
                output,
            )

            for candidate in matches:
                candidate = (
                    candidate
                    or ''
                ).strip()

                if not candidate:
                    continue

                if candidate == 'lo':
                    continue

                if _panel_context.re.match(
                    r'^(wg|tun|tap|docker|br-|veth)',
                    candidate,
                    _panel_context.re.IGNORECASE,
                ):
                    continue

                return candidate

        except Exception:
            _panel_context.current_app.logger.exception(
                'Could not detect IPv4 egress '
                'from the default route'
            )

        return ''


    def _wg_firewall_rules(
        interface_name: str,
        address_field: str,
    ) -> tuple[str, str]:

        network = _panel_context._wireguard_network(
            address_field
        )

        if not network:
            raise ValueError(
                "Automatic forwarding requires a private IPv4 "
                "WireGuard subnet."
            )

        egress = _panel_context._egress_interface()

        if not egress:
            raise ValueError(
                "The default IPv4 network interface "
                "could not be detected."
            )

        if not _panel_context.re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,32}",
            egress,
        ):
            raise ValueError(
                "The detected outbound interface name is invalid."
            )

        post_up = "\n".join([
            "sysctl -w net.ipv4.ip_forward=1",
            "iptables -A FORWARD -i %i -j ACCEPT",
            (
                "iptables -A FORWARD -o %i "
                "-m conntrack --ctstate "
                "RELATED,ESTABLISHED -j ACCEPT"
            ),
            (
                f"iptables -t nat -A POSTROUTING "
                f"-s {network} "
                f"-o {egress} "
                "-j MASQUERADE"
            ),
        ])

        post_down = "\n".join([
            "iptables -D FORWARD -i %i -j ACCEPT",
            (
                "iptables -D FORWARD -o %i "
                "-m conntrack --ctstate "
                "RELATED,ESTABLISHED -j ACCEPT"
            ),
            (
                f"iptables -t nat -D POSTROUTING "
                f"-s {network} "
                f"-o {egress} "
                "-j MASQUERADE"
            ),
        ])

        return post_up, post_down


    def _inject_firewall_rules(
        config_path: str,
        interface_name: str,
        address_field: str,
    ) -> dict:


        if not _panel_context.os.path.isfile(config_path):
            return {
                "changed": False,
                "reason": "config_missing",
            }

        try:
            with open(
                config_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                original = handle.read()

        except OSError as exc:
            return {
                "changed": False,
                "reason": "read_failed",
                "detail": str(exc),
            }

        in_interface = False
        has_post_up = False
        has_post_down = False

        for raw_line in original.splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                in_interface = (
                    line[1:-1].strip().lower()
                    == "interface"
                )
                continue

            if not in_interface or "=" not in line:
                continue

            key = (
                line.split("=", 1)[0]
                .strip()
                .lower()
            )

            if key == "postup":
                has_post_up = True

            elif key == "postdown":
                has_post_down = True

        if has_post_up or has_post_down:
            return {
                "changed": False,
                "reason": "custom_rules_present",
                "has_post_up": has_post_up,
                "has_post_down": has_post_down,
            }

        try:
            post_up, post_down = _panel_context._wg_firewall_rules(
                interface_name,
                address_field,
            )

        except ValueError as exc:
            return {
                "changed": False,
                "reason": "rule_generation_failed",
                "detail": str(exc),
            }

        lines = original.splitlines()

        insert_at = None
        inside_interface = False
        found_interface = False

        for index, raw_line in enumerate(lines):
            line = raw_line.strip()

            if not (
                line.startswith("[")
                and line.endswith("]")
            ):
                continue

            section = (
                line[1:-1]
                .strip()
                .lower()
            )

            if section == "interface":
                inside_interface = True
                found_interface = True
                continue

            if inside_interface:
                insert_at = index
                break

        if not found_interface:
            return {
                "changed": False,
                "reason": "interface_section_missing",
            }

        if insert_at is None:
            insert_at = len(lines)

        additions = [
        *[
            f"PostUp = {command.strip()}"
            for command
            in str(
                post_up or ""
            ).splitlines()
            if command.strip()
        ],

        *[
            f"PostDown = {command.strip()}"
            for command
            in str(
                post_down or ""
            ).splitlines()
            if command.strip()
        ],

        "",
        ]

        new_lines = (
            lines[:insert_at]
            + additions
            + lines[insert_at:]
        )

        updated = (
            "\n".join(new_lines)
            .rstrip()
            + "\n"
        )

        directory = (
            _panel_context.os.path.dirname(config_path)
            or "."
        )

        fd, temporary_path = _panel_context.tempfile.mkstemp(
            prefix=".wg-panel-firewall.",
            dir=directory,
        )

        try:
            try:
                original_mode = (
                    _panel_context.os.stat(config_path).st_mode
                    & 0o777
                )
            except OSError:
                original_mode = 0o600

            with _panel_context.os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(updated)
                handle.flush()
                _panel_context.os.fsync(handle.fileno())

            _panel_context.os.chmod(
                temporary_path,
                original_mode,
            )

            _panel_context.os.replace(
                temporary_path,
                config_path,
            )

            temporary_path = ""

        finally:
            if (
                temporary_path
                and _panel_context.os.path.exists(temporary_path)
            ):
                try:
                    _panel_context.os.unlink(
                        temporary_path
                    )
                except OSError:
                    pass

        runtime_applied = False
        runtime_error = ""

        if _panel_context._iface_up(interface_name):
            runtime_applied = False
            runtime_error = ""

        if _panel_context._iface_up(
            interface_name
        ):
            try:
                errors = []

                for raw_command in str(
                    post_up or "").splitlines():

                    raw_command = (raw_command.strip())

                    if not raw_command:
                        continue

                    command = (
                        raw_command.replace(
                            "%i",
                            _panel_context.shlex.quote(
                                interface_name
                            ),
                        )
                    )

                    result = _panel_context.subprocess.run(
                        [
                            "/bin/sh",
                            "-c",
                            command,
                        ],
                        stdout=_panel_context.subprocess.PIPE,
                        stderr=_panel_context.subprocess.STDOUT,
                        text=True,
                        timeout=20,
                        check=False,
                    )

                    if result.returncode != 0:
                        errors.append(
                            (
                                result.stdout
                                or command
                            ).strip()
                        )

                runtime_applied = (
                    len(errors) == 0
                )

                if errors:
                    runtime_error = (
                        "\n".join(
                            errors
                        )[-2000:]
                    )

            except Exception as exc:
                runtime_error = str(
                    exc
                )

            try:
                result = _panel_context.subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                    ],
                    stdout=_panel_context.subprocess.PIPE,
                    stderr=_panel_context.subprocess.STDOUT,
                    text=True,
                    timeout=20,
                    check=False,
                )

                runtime_applied = (
                    result.returncode == 0
                )

                if result.returncode != 0:
                    runtime_error = (
                        result.stdout
                        or ""
                    ).strip()[-2000:]

            except Exception as exc:
                runtime_error = str(exc)

        return {
            "changed": True,
            "reason": "managed_rules_added",
            "post_up": post_up,
            "post_down": post_down,
            "runtime_applied": runtime_applied,
            "runtime_error": runtime_error,
        }


    def local_firewall_rules() -> dict:
        configured_path = (
            _panel_context.app.config.get("WG_CONF_PATH")
            or _panel_context.app.config.get(
                "WIREGUARD_CONF_PATH"
            )
            or "/etc/wireguard"
        )

        if _panel_context.os.path.isdir(configured_path):
            paths = sorted(
                _panel_context.glob.glob(
                    _panel_context.os.path.join(
                        configured_path,
                        "*.conf",
                    )
                )
            )
        elif _panel_context.os.path.isfile(configured_path):
            paths = [configured_path]
        else:
            paths = []

        summary = {
            "checked": 0,
            "updated": 0,
            "skipped": 0,
            "failed": 0,
        }

        for config_path in paths:
            parsed = _panel_context.find_iface(config_path)

            if not parsed:
                summary["skipped"] += 1
                continue

            summary["checked"] += 1

            result = _panel_context._inject_firewall_rules(
                config_path,
                parsed.name,
                parsed.address,
            )

            if result.get("changed"):
                summary["updated"] += 1

                _panel_context.app.logger.info(
                    "Added automatic firewall rules to "
                    "legacy interface %s; runtime_applied=%s",
                    parsed.name,
                    result.get("runtime_applied"),
                )

                if result.get("runtime_error"):
                    _panel_context.app.logger.warning(
                        "Legacy interface %s was updated, "
                        "but its runtime firewall rules "
                        "could not be applied immediately: %s",
                        parsed.name,
                        result["runtime_error"],
                    )

            elif result.get("reason") in {
                "custom_rules_present",
                "config_missing",
            }:
                summary["skipped"] += 1

            else:
                summary["failed"] += 1

                _panel_context.app.logger.warning(
                    "Could not add firewall rules to "
                    "legacy interface %s: %s",
                    parsed.name,
                    result,
                )

        return summary

    return {
        '_private_networks': _private_networks,
        '_egress_interface': _egress_interface,
        '_wg_firewall_rules': _wg_firewall_rules,
        '_inject_firewall_rules': _inject_firewall_rules,
        'local_firewall_rules': local_firewall_rules,
    }
