"""subscription policy for WG Panel"""
from __future__ import annotations
from typing import Any, Mapping


_REASON_LABELS = {
    "": "Ready",
    "disabled": "Disabled by administrator",
    "expired": "Subscription expired",
    "data_exhausted": "Data limit reached",
    "peer_blocked": "Peer blocked",
    "peer_disabled": "Peer disabled",
}

_REASON_MESSAGES = {
    "disabled": "This subscription has been disabled. Please contact support.",
    "expired": "This subscription has expired. Please renew it to continue.",
    "data_exhausted": "This subscription has used all of its data allowance.",
}


def reason_label(reason: str | None) -> str:
    """Return a stable short label for a lifecycle reason."""
    key = str(reason or "").strip().lower()
    return _REASON_LABELS.get(key, key.replace("_", " ").strip().title() or "Ready")


def compute_subscription_access(
    *,
    enabled: bool,
    unlimited: bool,
    expires_at_ts: int | float | None,
    now_ts: int | float,
    limit_bytes: int | None,
    used_bytes: int | float | None,
) -> dict[str, Any]:
    """Return the canonical access decision for one subscription.

    Precedence is deliberate and stable:
      1. an explicit administrator disable always wins;
      2. unlimited subscriptions ignore timer/data limits;
      3. expiry is evaluated before shared data exhaustion;
      4. otherwise access is allowed.
    """
    if not bool(enabled):
        reason = "disabled"
    elif bool(unlimited):
        reason = ""
    else:
        try:
            expiry = int(expires_at_ts) if expires_at_ts is not None else None
        except (TypeError, ValueError, OverflowError):
            expiry = None
        try:
            now = int(now_ts)
        except (TypeError, ValueError, OverflowError):
            now = 0
        if expiry is not None and expiry > 0 and expiry <= now:
            reason = "expired"
        else:
            try:
                limit = int(limit_bytes) if limit_bytes is not None else None
            except (TypeError, ValueError, OverflowError):
                limit = None
            try:
                used = max(0, int(used_bytes or 0))
            except (TypeError, ValueError, OverflowError):
                used = 0
            reason = "data_exhausted" if limit is not None and limit > 0 and used >= limit else ""

    return {
        "allowed": not bool(reason),
        "reason": reason,
        "label": reason_label(reason),
        "message": _REASON_MESSAGES.get(reason, ""),
    }


def effective_peer_state(
    peer_status: str | None,
    subscription_access: Mapping[str, Any] | None = None,
) -> dict[str, str | bool]:
    """Explain a peer's effective administrative state.

    For subscription-managed peers the subscription access decision is the
    authoritative reason when it denies access.  Otherwise the peer's own
    administrative state is used.
    """
    status = str(peer_status or "offline").strip().lower() or "offline"
    access = dict(subscription_access or {})
    if access and access.get("allowed") is False:
        reason = str(access.get("reason") or "peer_blocked")
        return {
            "status": "blocked",
            "reason": reason,
            "label": reason_label(reason),
            "subscription_managed": True,
        }
    if status == "blocked":
        return {
            "status": "blocked",
            "reason": "peer_blocked",
            "label": reason_label("peer_blocked"),
            "subscription_managed": bool(access),
        }
    if status in {"offline", "disabled"}:
        return {
            "status": status,
            "reason": "peer_disabled",
            "label": reason_label("peer_disabled"),
            "subscription_managed": bool(access),
        }
    return {
        "status": status,
        "reason": "",
        "label": "Enabled",
        "subscription_managed": bool(access),
    }
