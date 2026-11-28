def build_routes(*,
    Node,
    _send_telegram_event,
    _traffic_apply_local,
    _traffic_load_config,
    _traffic_local_status,
    _traffic_manual_test_local,
    _traffic_normalize_policy,
    _traffic_save_config,
    _traffic_targets_payload,
    _traffic_test_policy_local,
    current_app,
    db,
    jsonify,
    login_required,
    node_get,
    node_post,
    request,
    require_api_key_or_login,
):

    @require_api_key_or_login
    def traffic_control_get():
        cfg = _traffic_load_config()
        node_status = {}
        for node in Node.query.filter(Node.enabled.is_(True)).order_by(Node.id.asc()).all():
            try:
                node_status[str(node.id)] = node_get(node, "/api/traffic-control/status", timeout=8) or {}
            except Exception as exc:
                node_status[str(node.id)] = {"ok": False, "error": str(exc)}
        return jsonify(
            ok=True,
            enabled=cfg["enabled"],
            policies=cfg["policies"],
            targets=_traffic_targets_payload(),
            local=_traffic_local_status(),
            nodes=node_status,
            geo_provider="IPdeny",
            domain_mode="resolved_ip",
        )

    @require_api_key_or_login
    def traffic_control_save():
        data = request.get_json(
            silent=True
        ) or {}

        try:
            previous = _traffic_load_config()

            raw_policies = (
                data.get("policies")
                or []
            )

            if not isinstance(
                raw_policies,
                list,
            ):
                raise ValueError(
                    "policies must be a list"
                )

            policies = [
                _traffic_normalize_policy(
                    item
                )
                for item in raw_policies
            ]

            seen = set()

            for policy in policies:
                if policy["id"] in seen:
                    raise ValueError(
                        "Duplicate policy id: "
                        f"{policy['id']}"
                    )

                seen.add(
                    policy["id"]
                )

            enabled = bool(
                data.get(
                    "enabled",
                    True,
                )
            )

            cfg = _traffic_save_config({
                "enabled": enabled,
                "policies": policies,
            })

            previous_enabled = bool(
                previous.get(
                    "enabled",
                    True,
                )
            )

            previous_policies = (
                previous.get("policies")
                if isinstance(
                    previous,
                    dict,
                )
                else []
            ) or []

            changed = bool(
                previous_enabled != enabled
                or previous_policies != policies
            )

            if changed:
                local_count = sum(
                    1
                    for policy in policies
                    if policy.get(
                        "location"
                    ) == "local"
                )

                node_count = sum(
                    1
                    for policy in policies
                    if policy.get(
                        "location"
                    ) == "node"
                )

                active_count = sum(
                    1
                    for policy in policies
                    if policy.get(
                        "enabled",
                        True,
                    )
                )

                _send_telegram_event(
                    "traffic_policy_change",
                    (
                        "Traffic Control "
                        "policy changed"
                    ),
                    status=(
                        "Enabled"
                        if enabled
                        else "Disabled"
                    ),
                    details=[
                        (
                            "Policies",
                            len(policies),
                        ),
                        (
                            "Active policies",
                            active_count,
                        ),
                        (
                            "Local policies",
                            local_count,
                        ),
                        (
                            "Node policies",
                            node_count,
                        ),
                    ],
                    dedupe_key=(
                        "traffic-policy:"
                        f"{int(enabled)}:"
                        f"{len(policies)}:"
                        f"{active_count}"
                    ),
                    dedupe_seconds=2,
                )

            return jsonify(
                ok=True,
                **cfg,
            )

        except ValueError as exc:
            return jsonify(
                ok=False,
                error="invalid_policy",
                detail=str(exc),
            ), 400

    @require_api_key_or_login
    def traffic_control_apply():
        cfg = _traffic_load_config()

        policies = (
            cfg["policies"]
            if cfg.get("enabled", True)
            else []
        )

        local_policies = [
            p for p in policies
            if p.get("location") == "local"
        ]

        node_groups = {}

        for p in policies:
            if p.get("location") != "node":
                continue

            nid = int(
                p.get("node_id") or 0
            )

            if nid:
                node_groups.setdefault(
                    nid,
                    [],
                ).append(p)

        result = {
            "local": None,
            "nodes": {},
            "warnings": [],
        }

        errors = []

        try:
            result["local"] = (
                _traffic_apply_local(
                    local_policies
                )
            )

            result["warnings"].extend(
                (result["local"] or {})
                .get("warnings")
                or []
            )

        except Exception as exc:
            detail = str(exc).strip()

            result["local"] = {
                "ok": False,
                "error": detail,
            }

            errors.append(
                f"Local panel: {detail}"
            )

            current_app.logger.exception(
                "Local Traffic Control apply failed"
            )

        for nid, rows in node_groups.items():
            node = db.session.get(
                Node,
                nid,
            )

            if not node or not node.enabled:
                detail = (
                    "node_not_found_or_disabled"
                )

                result["nodes"][str(nid)] = {
                    "ok": False,
                    "error": detail,
                }

                errors.append(
                    f"Node {nid}: {detail}"
                )
                continue

            try:
                remote = (
                    node_post(
                        node,
                        "/api/traffic-control/apply",
                        {"policies": rows},
                        timeout=45,
                    )
                    or {}
                )

                result["nodes"][
                    str(nid)
                ] = remote

                result["warnings"].extend(
                    remote.get("warnings")
                    or []
                )

                if not remote.get("ok"):
                    detail = str(
                        remote.get("detail")
                        or remote.get("error")
                        or "remote apply failed"
                    ).strip()

                    errors.append(
                        f"{node.name or ('Node ' + str(nid))}: "
                        f"{detail}"
                    )

            except Exception as exc:
                detail = str(exc).strip()

                result["nodes"][
                    str(nid)
                ] = {
                    "ok": False,
                    "error": detail,
                }

                errors.append(
                    f"{node.name or ('Node ' + str(nid))}: "
                    f"{detail}"
                )

                current_app.logger.exception(
                    "Node Traffic Control apply failed: node=%s",
                    nid,
                )

        local_ok = bool(
            (result.get("local") or {})
            .get("ok")
        )

        nodes_ok = (
            all(
                bool(value.get("ok"))
                for value in result[
                    "nodes"
                ].values()
            )
            if result["nodes"]
            else True
        )

        ok = bool(
            local_ok
            and nodes_ok
        )

        response = {
            "ok": ok,
            **result,
        }

        if errors:
            response["detail"] = (
            " | ".join(
                errors
            )[:1800]
        )

        active_policy_count = len(
            policies
        )

        local_policy_count = len(
            local_policies
        )

        node_policy_count = sum(
            len(rows)
            for rows in (
                node_groups.values()
            )
        )

        if ok:
            _send_telegram_event(
                "traffic_apply_success",
                (
                    "Traffic Control "
                    "rules applied"
                ),
                status="Active",
                details=[
                    (
                        "Policies",
                        active_policy_count,
                    ),
                    (
                        "Local policies",
                        local_policy_count,
                    ),
                    (
                        "Node policies",
                        node_policy_count,
                    ),
                    (
                        "Nodes",
                        len(node_groups),
                    ),
                    (
                        "Warnings",
                        len(
                            result.get(
                                "warnings"
                            )
                            or []
                        ),
                    ),
                ],
                dedupe_key=(
                    "traffic-apply-success:"
                    f"{active_policy_count}:"
                    f"{len(node_groups)}"
                ),
                dedupe_seconds=5,
            )

        else:
            _send_telegram_event(
                "traffic_apply_failed",
                (
                    "Traffic Control "
                    "apply failed"
                ),
                status="Failed",
                details=[
                    (
                        "Policies",
                        active_policy_count,
                    ),
                    (
                        "Local policies",
                        local_policy_count,
                    ),
                    (
                        "Node policies",
                        node_policy_count,
                    ),
                    (
                        "Nodes",
                        len(node_groups),
                    ),
                    (
                        "Error",
                        response.get(
                            "detail"
                        )
                        or (
                            "Traffic Control "
                            "could not be applied."
                        ),
                    ),
                ],
                dedupe_key=(
                    "traffic-apply-failed:"
                    + str(
                        response.get(
                            "detail"
                        )
                        or "unknown"
                    )[:180]
                ),
                dedupe_seconds=60,
            )

        return jsonify(
            **response
        ), (
            200
            if ok
            else 502
        )

    @login_required
    def traffic_control_status():
        return jsonify(ok=True, **_traffic_local_status())

    @login_required
    def traffic_control_test():
        data = request.get_json(silent=True) or {}
        policy_id = str(data.get("policy_id") or "").strip()
        if not policy_id:
            return jsonify(ok=False, error="policy_id_required", detail="policy_id is required."), 400

        cfg = _traffic_load_config()
        policy = next((p for p in cfg.get("policies", []) if str((p or {}).get("id") or "") == policy_id), None)
        if not policy:
            return jsonify(ok=False, error="policy_not_found", detail="The saved traffic policy was not found."), 404
        if policy.get("enabled", True) is False:
            return jsonify(ok=False, error="policy_disabled", detail="The policy is disabled and is intentionally not loaded."), 409

        if policy.get("location") == "node":
            node_id = int(policy.get("node_id") or 0)
            node = db.session.get(Node, node_id)
            if not node or not node.enabled:
                return jsonify(ok=False, error="node_not_found_or_disabled", detail="The policy node is missing or disabled."), 404
            try:
                result = node_post(node, "/api/traffic-control/test", {"policy": policy}, timeout=20) or {}
                return jsonify(result), 200
            except Exception as exc:
                return jsonify(ok=False, error="node_test_failed", detail=str(exc)), 502

        try:
            result = _traffic_test_policy_local(policy)
            return jsonify(result), 200
        except Exception as exc:
            current_app.logger.exception("Traffic policy test failed")
            return jsonify(ok=False, error="traffic_test_failed", detail=str(exc)), 500

    @require_api_key_or_login
    def traffic_control_test_destination():
        data = request.get_json(silent=True) or {}
        policy_id = str(data.get('policy_id') or '').strip()
        target = str(data.get('target') or '').strip()

        if not policy_id:
            return jsonify(ok=False, error='policy_id_required', detail='policy_id is required.'), 400
        if not target:
            return jsonify(ok=False, error='target_required', detail='Enter a domain, URL, IPv4 or IPv6 address.'), 400

        cfg = _traffic_load_config()
        policy = next(
            (
                row for row in cfg.get('policies', [])
                if str((row or {}).get('id') or '') == policy_id
            ),
            None,
        )
        if not policy:
            return jsonify(ok=False, error='policy_not_found', detail='The saved traffic policy was not found.'), 404
        if policy.get('enabled', True) is False:
            return jsonify(ok=False, error='policy_disabled', detail='The policy is disabled and is not loaded into nftables.'), 409

        if policy.get('location') == 'node':
            node_id = int(policy.get('node_id') or 0)
            node = db.session.get(Node, node_id)
            if not node or not node.enabled:
                return jsonify(ok=False, error='node_not_found_or_disabled', detail='The policy node is missing or disabled.'), 404
            try:
                result = node_post(
                    node,
                    '/api/traffic-control/test-destination',
                    {'policy': policy, 'target': target},
                    timeout=20,
                ) or {}
                return jsonify(result), 200
            except Exception as exc:
                return jsonify(ok=False, error='node_destination_test_failed', detail=str(exc)), 502

        try:
            return jsonify(_traffic_manual_test_local(policy, target))
        except ValueError as exc:
            return jsonify(ok=False, error='invalid_target', detail=str(exc)), 400
        except Exception as exc:
            current_app.logger.exception('Traffic destination test failed')
            return jsonify(ok=False, error='traffic_destination_test_failed', detail=str(exc)), 500

    return {
        'traffic_control_get': traffic_control_get,
        'traffic_control_save': traffic_control_save,
        'traffic_control_apply': traffic_control_apply,
        'traffic_control_status': traffic_control_status,
        'traffic_control_test': traffic_control_test,
        'traffic_control_test_destination': traffic_control_test_destination,
    }
