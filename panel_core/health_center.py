"""Read-only Dashboard Health Center  WG Panel"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_ts(value) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return int(value)
        if getattr(value, "tzinfo", None) is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    except Exception:
        return None


def _item(key: str, label: str, state: str, summary: str, *, detail: str = "", href: str = "") -> dict[str, Any]:
    state = state if state in {"healthy", "review", "attention", "unknown"} else "unknown"
    return {
        "id": key,
        "label": label,
        "state": state,
        "summary": summary,
        "detail": detail,
        "href": href,
    }


def build_health_center(context: dict[str, Any], *, now_ts: int | None = None) -> dict[str, Any]:
    """Build a compact, read-only panel health summary.

    ``context`` is normally ``globals()`` from app.py.  Every subsystem is
    guarded independently so one degraded optional component cannot make the
    whole endpoint fail.
    """
    now = int(now_ts if now_ts is not None else datetime.now(timezone.utc).timestamp())
    items: list[dict[str, Any]] = []

    # Panel/database 
    try:
        db = context.get("db")
        sql_text = context.get("text")
        if db is None or not callable(sql_text):
            raise RuntimeError("database context unavailable")
        db.session.execute(sql_text("SELECT 1"))
        items.append(_item("panel", "Panel & database", "healthy", "Panel database is reachable.", href="/logs"))
    except Exception:
        items.append(_item("panel", "Panel & database", "attention", "Database health could not be confirmed.", detail="Open Operations or panel logs before making changes.", href="/operations"))

    # Local interfaces 
    try:
        InterfaceConfig = context.get("InterfaceConfig")
        rows = InterfaceConfig.query.filter_by(node_id=None).all() if InterfaceConfig is not None else []
        count = len(rows)
        if count:
            items.append(_item("wireguard", "Local WireGuard", "healthy", f"{count} local interface{'s' if count != 1 else ''} configured.", detail="Use Peers or Operations for runtime state and repair.", href="/users"))
        else:
            items.append(_item("wireguard", "Local WireGuard", "review", "No local WireGuard interface is configured.", detail="This is valid for a node-only deployment.", href="/users"))
    except Exception:
        items.append(_item("wireguard", "Local WireGuard", "unknown", "Interface inventory could not be read.", href="/operations"))

    # Nodes 
    try:
        Node = context.get("Node")
        rows = Node.query.filter_by(enabled=True).all() if Node is not None else []
        stale = 0
        fresh = 0
        for node in rows:
            last = _utc_ts(getattr(node, "last_seen", None))
            if last is not None and now - last <= 180:
                fresh += 1
            else:
                stale += 1
        if not rows:
            state, summary = "healthy", "No enabled remote nodes."
        elif stale:
            state, summary = "attention", f"{stale} of {len(rows)} enabled node{'s' if len(rows) != 1 else ''} have stale health."
        else:
            state, summary = "healthy", f"All {fresh} enabled node{'s are' if fresh != 1 else ' is'} fresh."
        items.append(_item("nodes", "Remote nodes", state, summary, detail="Node freshness uses the existing 180-second health window.", href="/nodes"))
    except Exception:
        items.append(_item("nodes", "Remote nodes", "unknown", "Node health could not be summarized.", href="/nodes"))

    # Subscriptions 
    try:
        Subscription = context.get("Subscription")
        subscription_access = context.get("subscription_access")
        rows = Subscription.query.all() if Subscription is not None else []
        review = 0
        active = 0
        disabled = 0
        for sub in rows:
            if not bool(getattr(sub, "enabled", True)):
                disabled += 1
            if callable(subscription_access):
                used = sum(
                    max(0, int(getattr(getattr(link, "peer", None), "used_bytes_total", 0) or 0))
                    for link in (getattr(sub, "links", []) or [])
                    if getattr(link, "peer", None) is not None
                )
                access = subscription_access(sub, used_bytes=used)
                reason = str((access or {}).get("reason") or "")
                if reason in {"expired", "data_exhausted", "disabled"}:
                    review += 1
                else:
                    active += 1
            else:
                active += 1
        if review:
            state = "review"
            summary = f"{review} subscription{'s' if review != 1 else ''} need lifecycle review."
        else:
            state = "healthy"
            summary = f"{len(rows)} subscription{'s' if len(rows) != 1 else ''}; no lifecycle review items."
        detail = f"Active/ready: {active}. Disabled: {disabled}."
        items.append(_item("subscriptions", "Subscriptions", state, summary, detail=detail, href="/subscriptions"))
    except Exception:
        items.append(_item("subscriptions", "Subscriptions", "unknown", "Subscription lifecycle could not be summarized.", href="/subscriptions"))

    # Automatic backup 
    try:
        load_sched = context.get("_load_backup_schedule")
        load_last = context.get("_load_backup_last")
        sched = load_sched() if callable(load_sched) else {}
        last = load_last() if callable(load_last) else {}
        enabled = bool((sched or {}).get("enabled"))
        latest = None
        for key in ("full_last", "db_last", "settings_last"):
            raw = str((last or {}).get(key) or "").strip()
            if not raw:
                continue
            try:
                ts = int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
            except Exception:
                continue
            latest = max(latest or ts, ts)
        if enabled:
            state = "healthy" if latest else "review"
            summary = "Automatic backup is enabled." if latest else "Automatic backup is enabled; no completed backup is recorded yet."
        else:
            state = "review"
            summary = "Automatic backup is not scheduled."
        detail = f"Last recorded backup: {max(0, now-latest)//3600}h ago." if latest else ""
        items.append(_item("backup", "Automatic backup", state, summary, detail=detail, href="/backup"))
    except Exception:
        items.append(_item("backup", "Automatic backup", "unknown", "Backup status could not be summarized.", href="/backup"))

    # Telegram 
    try:
        hb_path = context.get("TELEGRAM_HB_FILE")
        json_load = context.get("_json_load")
        hb = json_load(hb_path, {}) if hb_path and callable(json_load) else {}
        last = int((hb or {}).get("ts") or 0)
        age = max(0, now - last) if last else None
        if last and age <= 180:
            state = "healthy"
            summary = "Telegram bot heartbeat is fresh."
        elif last:
            state = "review"
            summary = "Telegram heartbeat is stale."
        else:
            state = "review"
            summary = "No Telegram heartbeat is recorded."
        detail = f"Last heartbeat {age}s ago." if age is not None else "Telegram can be intentionally disabled."
        items.append(_item("telegram", "Telegram", state, summary, detail=detail, href="/settings#telegram"))
    except Exception:
        items.append(_item("telegram", "Telegram", "unknown", "Telegram health could not be summarized.", href="/settings"))

    # HTTP protection 
    try:
        loader = context.get("_load_http_security_settings")
        settings = loader() if callable(loader) else {}
        enabled = bool((settings or {}).get("enabled", True))
        mode = str((settings or {}).get("response_mode") or "monitor")
        if enabled:
            state = "healthy"
            summary = f"HTTP protection is enabled in {mode} mode."
        else:
            state = "review"
            summary = "HTTP protection is disabled."
        items.append(_item("security", "HTTP protection", state, summary, href="/settings#security"))
    except Exception:
        items.append(_item("security", "HTTP protection", "unknown", "HTTP protection state could not be read.", href="/settings"))

    counts = {"healthy": 0, "review": 0, "attention": 0, "unknown": 0}
    for item in items:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    if counts["attention"]:
        overall = "attention"
        headline = f"{counts['attention']} item{'s' if counts['attention'] != 1 else ''} need attention"
    elif counts["review"] or counts["unknown"]:
        overall = "review"
        n = counts["review"] + counts["unknown"]
        headline = f"{n} item{'s' if n != 1 else ''} to review"
    else:
        overall = "healthy"
        headline = "Panel health looks good"

    return {
        "ok": True,
        "ts": now,
        "state": overall,
        "headline": headline,
        "counts": counts,
        "items": items,
    }
