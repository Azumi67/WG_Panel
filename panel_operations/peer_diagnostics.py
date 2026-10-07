"""Read-only peer-specific connection diagnosis for WG Panel."""
from __future__ import annotations
import ipaddress
import json
from urllib.parse import urlencode
from typing import Any
from .checks import network_path_snapshot


def _stage(key: str, label: str, state: str, detail: str, *, hint: str = "", href: str = "") -> dict[str, Any]:
    if state not in {"ready", "review", "attention", "not_required", "unknown"}:
        state = "unknown"
    return {"id": key, "label": label, "state": state, "detail": detail, "hint": hint, "href": href}


def _subscription_context(context, peer):
    links = list(getattr(peer, "subscription_links", []) or [])
    if not links:
        return None, None
    link = links[0]
    sub = getattr(link, "subscription", None)
    if sub is None:
        db = context.get("db")
        model = context.get("Subscription")
        if db is not None and model is not None:
            sub = db.session.get(model, getattr(link, "subscription_id", None))
    if sub is None:
        return None, None
    access_fn = context.get("subscription_access")
    try:
        used = sum(
            max(0, int(getattr(getattr(link, "peer", None), "used_bytes_total", 0) or 0))
            for link in (getattr(sub, "links", []) or [])
            if getattr(link, "peer", None) is not None
        )
    except Exception:
        used = 0
    try:
        access = access_fn(sub, used_bytes=used) if callable(access_fn) else None
    except Exception:
        access = None
    return sub, access


def _allowed_ips_state(value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    if not raw:
        return "attention", "No AllowedIPs are configured for this peer."
    valid = 0
    invalid = 0
    for token in raw.replace(" ", "").split(","):
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
            valid += 1
        except ValueError:
            invalid += 1
    if invalid:
        return "attention", f"{invalid} invalid AllowedIPs entr{'y' if invalid == 1 else 'ies'} detected."
    return "ready", f"{valid} AllowedIPs entr{'y' if valid == 1 else 'ies'} configured."


def _summarize(stages):
    attention = sum(1 for item in stages if item.get("state") == "attention")
    review = sum(1 for item in stages if item.get("state") in {"review", "unknown"})
    if attention:
        state = "attention"
        headline = f"{attention} connection stage{'s' if attention != 1 else ''} need attention"
    elif review:
        state = "review"
        headline = f"{review} connection stage{'s' if review != 1 else ''} to review"
    else:
        state = "ready"
        headline = "No blocking condition was detected"
    return state, headline


def _local_runtime(context, device, public_key):
    """Read kernel state once"""
    result = {"interface_state": "unknown", "peer_present": None}
    run = context.get("_run_capture")
    if not callable(run) or not device:
        return result
    try:
        rc, output = run(["ip", "-j", "link", "show", "dev", device], timeout=3.0)
        if rc == 0:
            links = json.loads(output)
            if isinstance(links, list):
                match = next((item for item in links if item.get("ifname") == device), None)
                result["interface_state"] = ("up" if "UP" in match.get("flags", []) else "down") if match else "down"
    except Exception:
        pass
    try:
        rc, output = run(["wg", "show", device, "dump"], timeout=3.0)
        if rc != 0:
            return result
        lines = output.strip().splitlines()
        if not lines or len(lines[0].split("\t")) < 4:
            return result
        if result["interface_state"] == "unknown":
            result["interface_state"] = "up"
        rows = [line.split("\t") for line in lines[1:]]
        if any(len(row) < 8 for row in rows):
            return result
        result["peer_present"] = False
        for row in rows:
            if row[0] == public_key:
                result.update(peer_present=True, latest_handshake=int(row[4]), live_total=int(row[5]) + int(row[6]))
                break
    except Exception:
        result["peer_present"] = None
    return result


def diagnose_peer(context: dict[str, Any], peer, *, remote_runtime: dict | None = None, remote_path: list | None = None) -> dict[str, Any]:
    """Compose a read-only diagnosis for a local or node-backed DB peer."""
    iface = getattr(peer, "iface", None)
    iface_name = str(getattr(iface, "name", "") or "")
    dev_name = iface_name.split(":")[-1] if iface_name else ""
    node_id = getattr(iface, "node_id", None)
    node_resolver = context.get("_node_id_from_iface")
    if node_id is None and iface is not None and callable(node_resolver):
        node_id = node_resolver(iface)
    remote = node_id is not None or (":" in iface_name)
    stages: list[dict[str, Any]] = []
    runtime = (remote_runtime or {}) if remote else _local_runtime(context, dev_name, str(getattr(peer, "public_key", "") or ""))
    target = {"from": "peer", "interface": dev_name, "peer": int(getattr(peer, "id", 0) or 0)}
    if node_id is not None:
        target["node"] = node_id
    operations_href = "/operations?" + urlencode(target)
    access_blocked = False

    sub, access = _subscription_context(context, peer)
    if access is not None and access.get("allowed") is False:
        access_blocked = True
        label = str(access.get("label") or access.get("reason") or "Subscription blocks access")
        stages.append(_stage("access", "Access policy", "attention", label, hint="Resolve the subscription lifecycle condition before testing network transport.", href="/subscriptions"))
    else:
        panel_status = str(getattr(peer, "status", "") or "offline").lower()
        if panel_status in {"blocked", "disabled", "offline"}:
            access_blocked = True
            stages.append(_stage("access", "Access policy", "attention", f"Peer panel state is {panel_status}.", hint="Enable the peer if it is intended to have access.", href="/users"))
        else:
            stages.append(_stage("access", "Access policy", "ready", "Peer access is enabled." if sub is None else "Subscription and peer access are enabled.", href="/users"))

    if not iface or not dev_name:
        stages.append(_stage("interface", "WireGuard interface", "attention", "The peer is not attached to a valid interface.", href="/users"))
    else:
        iface_state = str(runtime.get("interface_state") or "unknown")
        state = "ready" if iface_state == "up" else ("attention" if iface_state == "down" else "review")
        detail = f"{dev_name} is active." if iface_state == "up" else (f"{dev_name} is not active." if iface_state == "down" else f"Runtime state for {dev_name} could not be confirmed.")
        stages.append(_stage("interface", "WireGuard interface", state, detail,
            hint="Check this interface in Peers. If it is unexpectedly stopped, review a read-only host diagnostic before applying any repair.", href=operations_href))

    present = runtime.get("peer_present")
    if remote and runtime.get("reason") in {"wg_show_failed", "runtime_unavailable", "legacy_fallback"}:
        present = None
    if access_blocked:
        stages.append(_stage("runtime", "Peer runtime", "not_required",
            "Access is disabled by panel policy; a missing peer or handshake is expected.",
            hint="Review Access policy first. Re-enabling access is an explicit administrator action."))
    elif present is None:
        stages.append(_stage("runtime", "Peer runtime", "unknown",
            "The runtime probe did not return enough evidence to confirm this peer.",
            hint="Check WireGuard command permissions or node connectivity, then run Diagnose again. No restart is implied by a failed probe.", href=operations_href))
    elif not present:
        stages.append(_stage("runtime", "Peer runtime", "attention",
            "The peer public key is absent from the selected interface runtime.",
            hint="Confirm the selected interface and that this peer is enabled in Peers. Review host findings before deciding whether to reapply it.", href=operations_href))
    else:
        connection = runtime
        if not remote:
            conn_fn = context.get("_peer_conn_status")
            try:
                connection = conn_fn(peer, live_total=runtime.get("live_total", 0), latest_handshake=runtime.get("latest_handshake", 0), allow_probe=False) if callable(conn_fn) else {}
            except Exception:
                connection = {}
        online = connection.get("online") is True or connection.get("connection_status") == "online"
        detail = "Peer has current WireGuard activity." if online else "Peer is installed. No recent activity was confirmed."
        age = connection.get("latest_handshake_age")
        if age is not None:
            detail += f" Latest handshake {int(age)}s ago."
        stages.append(_stage("runtime", "Handshake & runtime", "ready" if online else "review", detail,
            hint="Connect the client and run Diagnose again; an idle client is not automatically a fault." if not online else ""))

    allowed_state, allowed_detail = _allowed_ips_state(getattr(peer, "allowed_ips", "") or "")
    stages.append(_stage("allowed_ips", "AllowedIPs", allowed_state, allowed_detail, hint="Review routing intent before changing AllowedIPs.", href="/users"))

    endpoint_fn = context.get("_effective_client_endpoint")
    try:
        endpoint = str(endpoint_fn(peer) or "").strip() if callable(endpoint_fn) else str(getattr(peer, "endpoint", "") or "").strip()
    except Exception:
        endpoint = str(getattr(peer, "endpoint", "") or "").strip()
    stages.append(_stage(
        "endpoint", "Client endpoint",
        "ready" if endpoint else "attention",
        endpoint if endpoint else "No client endpoint could be resolved.",
        hint="Confirm the exported host/port for this interface.", href="/users",
    ))

    host_stages = remote_path if remote else None
    if host_stages is None and not remote:
        try:
            host_stages = network_path_snapshot(context.get("app"), context)
        except Exception:
            host_stages = []
    for item in host_stages or []:
        key = str(item.get("id") or "")
        if key == "wireguard":
            continue
        stages.append(_stage(
            "host_" + key,
            str(item.get("label") or key.replace("_", " ").title()),
            str(item.get("state") or "review"),
            str(item.get("detail") or "Host readiness could not be confirmed."),
            hint="Run a read-only host diagnostic in Panel Center to see evidence and guided next steps. Repairs require separate confirmation.",
            href=operations_href,
        ))

    overall, headline = _summarize(stages)
    return {
        "ok": True,
        "peer": {
            "id": int(getattr(peer, "id", 0) or 0),
            "name": str(getattr(peer, "name", "") or "Peer"),
            "address": str(getattr(peer, "address", "") or ""),
            "interface": dev_name,
            "node_id": node_id,
            "remote": bool(remote),
            "subscription_id": int(getattr(sub, "id", 0) or 0) if sub is not None else None,
            "public_key": str(getattr(peer, "public_key", "") or ""),
            "allowed_ips": str(getattr(peer, "allowed_ips", "") or ""),
            "endpoint": endpoint,
            "limits": {k: getattr(sub if sub is not None else peer, k, None) for k in ("data_limit_value", "data_limit_unit", "time_limit_days", "unlimited")},
            "subscription_name": str(getattr(sub, "name", "") or "") if sub is not None else "",
        },
        "operations_href": operations_href,
        "state": overall,
        "headline": headline,
        "stages": stages,
        "read_only": True,
    }
