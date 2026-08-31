from __future__ import annotations

import asyncio
import io
import math
import re
from urllib.parse import quote
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.constants import ParseMode

PAGE_SIZE = 6

CREATE_FIELDS = [
    ("name", "Client name", ""),
    ("note", "Administrative note, or - to leave empty", ""),
    ("data_limit_value", "Shared data limit value, 0 for no data cap", "0"),
    ("data_limit_unit", "Data unit: Mi or Gi", "Gi"),
    ("time_limit_days", "Active days, 0 for none", "0"),
    ("time_limit_hours", "Additional active hours, 0 for none", "0"),
    ("time_limit_minutes", "Additional active minutes, 0 for none", "0"),
    ("phone_number", "Phone number, or - to leave empty", ""),
    ("telegram_id", "Telegram username/ID, or - to leave empty", ""),
    ("start_on_first_use", "Start timer on first use? yes/no", "yes"),
    ("unlimited", "Unlimited client? yes/no", "no"),
    ("allowed_ips", "Allowed IPs", "0.0.0.0/0, ::/0"),
    ("include_internal_network", "Include detected local/private networks? yes/no", "no"),
    ("endpoint", "Server endpoint override, or - for automatic", ""),
    ("peer_endpoint", "Fixed client endpoint (stable host:UDP port), or - for normal clients", ""),
    ("persistent_keepalive", "Persistent keepalive in seconds", "25"),
    ("mtu", "MTU", "1280"),
    ("dns", "DNS servers", "1.1.1.1, 1.0.0.1"),
]

CLIENT_INFO_FIELDS = [
    ("name", "Client name", ""),
    ("note", "Administrative note, or - to leave empty", ""),
    ("data_limit_value", "Shared data limit value, 0 for no cap", "0"),
    ("data_limit_unit", "Data unit", "Gi"),
    ("time_limit_days", "Active days, 0 for none", "0"),
    ("time_limit_hours", "Additional active hours, 0 for none", "0"),
    ("time_limit_minutes", "Additional active minutes, 0 for none", "0"),
    ("phone_number", "Phone number, or - to leave empty", ""),
    ("telegram_id", "Telegram username/ID, or - to leave empty", ""),
    ("start_on_first_use", "Start timer on first use?", "yes"),
    ("unlimited", "Unlimited client?", "no"),
]

ADVANCED_CREATE_FIELDS = CREATE_FIELDS
ADVANCED_WG_FIELDS = [
    ("allowed_ips", "Allowed IPs", "0.0.0.0/0, ::/0"),
    ("include_internal_network", "Include detected local/private networks?", "no"),
    ("endpoint", "Server endpoint override, or - for automatic", ""),
    ("peer_endpoint", "Fixed client endpoint (stable host:UDP port), or - for normal clients", ""),
    ("persistent_keepalive", "Persistent keepalive in seconds", "25"),
    ("mtu", "MTU", "1280"),
    ("dns", "DNS servers", "1.1.1.1, 1.0.0.1"),
]

EDIT_FIELDS = [
    ("name", "Client name"),
    ("note", "Administrative note"),
    ("phone_number", "Phone number"),
    ("telegram_id", "Telegram username/ID"),
    ("data_limit_value", "Shared data limit"),
    ("data_limit_unit", "Data unit"),
    ("time_limit_days", "Active time"),
    ("start_on_first_use", "Start on first use"),
    ("unlimited", "Unlimited mode"),
]


def _html(g, value):
    return g["html"](value)


def _api(g, method, path, payload=None, timeout=25):
    return g["_api_data"](method, path, payload=payload, timeout=timeout)


def _clear_client_input_state(context):
    for key in (
        "v58_client_search",
        "v58_client_create",
        "v58_client_edit",
    ):
        context.user_data.pop(key, None)


def _subscription_profiles(g):
    """Load the same subscription profiles used by the web panel.

    The current panel stores subscription profiles behind /api/subscription_profiles
    with separate client/advanced/interfaces/template sections.  Telegram only
    needs the client and advanced values for its create wizard, so those sections
    are flattened while leaving interface/template data untouched in the panel.
    """
    try:
        listing = _api(g, "GET", "/api/subscription_profiles", timeout=15)
        if not isinstance(listing, dict) or listing.get("ok") is False:
            return []

        rows = []
        for meta in listing.get("profiles") or []:
            name = str((meta or {}).get("name") or "").strip()
            if not name:
                continue
            detail = _api(
                g,
                "GET",
                f"/api/subscription_profiles/{quote(name, safe='')}",
                timeout=15,
            )
            profile = detail.get("profile") if isinstance(detail, dict) else None
            if not isinstance(profile, dict):
                continue

            include = profile.get("include") if isinstance(profile.get("include"), dict) else {}
            values = {}
            client_values = profile.get("client")
            advanced_values = profile.get("advanced")

            if isinstance(client_values, dict) and (include.get("client", True)):
                values.update(client_values)
            if isinstance(advanced_values, dict) and (include.get("advanced", True)):
                values.update(advanced_values)

            if isinstance(profile.get("interfaces"), list):
                values["_saved_interfaces"] = profile.get("interfaces")
            if isinstance(profile.get("template"), dict):
                values["_saved_template"] = profile.get("template")

            rows.append((name, values))
        return rows
    except Exception:
        return []


def _client_create_keyboard(key, default):
    rows = []
    if key in {"start_on_first_use", "unlimited", "include_internal_network"}:
        rows.append([
            InlineKeyboardButton("◇ Yes", callback_data=f"client:create:set:{key}:yes"),
            InlineKeyboardButton("◇ No", callback_data=f"client:create:set:{key}:no"),
        ])
    elif key == "data_limit_unit":
        rows.append([
            InlineKeyboardButton("◇ MiB", callback_data=f"client:create:set:{key}:Mi"),
            InlineKeyboardButton("◇ GiB", callback_data=f"client:create:set:{key}:Gi"),
        ])
    rows.append([
        InlineKeyboardButton("◇ Default", callback_data="client:create:default"),
        InlineKeyboardButton("✕ Cancel", callback_data="client:list:1"),
    ])
    return InlineKeyboardMarkup(rows)


def _safe_filename(value, fallback="wireguard"):
    name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        str(value or fallback),
    ).strip("._")
    return name or fallback


def _subscription_links(g, sid):
    row = _api(
        g,
        "GET",
        f"/api/subscriptions/{int(sid)}/shortlink",
        timeout=15,
    )
    return row if isinstance(row, dict) else {}


def _public_location_urls(g, sid, link_id):
    links = _subscription_links(g, sid)
    portal = str(
        links.get("url")
        or links.get("public_url")
        or ""
    ).strip()
    token = str(links.get("token") or "").strip()

    if not token:
        return {
            "portal": portal,
            "config": "",
            "qr": "",
            "all_config": str(links.get("config_url") or "").strip(),
        }

    panel = str(g.get("PANEL") or "").rstrip("/")
    base = f"{panel}/s/{token}/inbound/{int(link_id)}"

    return {
        "portal": portal or f"{panel}/s/{token}",
        "config": f"{base}/config",
        "qr": f"{base}/qr",
        "all_config": str(links.get("config_url") or "").strip(),
    }


def _get_response(g, url, timeout=30):
    getter = g.get("_get")
    if not getter:
        raise RuntimeError("Telegram HTTP helper is unavailable")
    return getter(url, session="api", timeout=timeout)


async def _send_subscription_bundle(g, update, sid, link_id):
    """Send config and QR as two complete cards, each with content and short link."""
    row = client(g, sid)
    loc = next((item for item in (row.get("locations") or [])
                if int(item.get("link_id") or 0) == int(link_id)), None)
    if not loc:
        raise RuntimeError("Config is not attached to this client")

    urls = _public_location_urls(g, sid, link_id)
    if not urls.get("config"):
        raise RuntimeError("Subscription public token is unavailable")

    cfg_response = await asyncio.to_thread(_get_response, g, urls["config"], 35)
    if not getattr(cfg_response, "ok", False):
        raise RuntimeError(f"Config request failed with HTTP {getattr(cfg_response, 'status_code', '?')}")

    cfg_bytes = bytes(getattr(cfg_response, "content", b"") or b"")
    if not cfg_bytes:
        raise RuntimeError("The returned config is empty")
    cfg_text = cfg_bytes.decode("utf-8", "replace")

    display_name = str(loc.get("name") or f"peer-{loc.get('peer_id') or link_id}")
    name = _safe_filename(display_name)
    portal = str(urls.get("portal") or "").strip()
    short_text = _html(g, portal or "Unavailable")
    cfg_block = f"<pre><code>{_html(g, cfg_text)}</code></pre>"

    caption = (
        f"📄 <b>{_html(g, display_name)}.conf</b>\n"
        f"{cfg_block}\n"
        f"🔗 <b>Short link</b>: {short_text}"
    )
    if len(caption) > 1024:
        room = max(120, 820 - len(portal) - len(display_name))
        preview = cfg_text[:room].rstrip() + "\n…"
        caption = (
            f"📄 <b>{_html(g, display_name)}.conf</b>\n"
            f"<pre><code>{_html(g, preview)}</code></pre>\n"
            f"🔗 <b>Short link</b>: {short_text}"
        )

    message = update.effective_message
    await message.reply_document(
        document=InputFile(io.BytesIO(cfg_bytes), filename=f"{name}.conf"),
        caption=caption,
        parse_mode=ParseMode.HTML,
    )

    qr_bytes = b""
    if urls.get("qr"):
        try:
            qr_response = await asyncio.to_thread(_get_response, g, urls["qr"], 35)
            if getattr(qr_response, "ok", False):
                qr_bytes = bytes(getattr(qr_response, "content", b"") or b"")
        except Exception:
            qr_bytes = b""

    if qr_bytes:
        qr_caption = (
            f"▦ <b>{_html(g, display_name)} · QR</b>\n"
            f"{cfg_block}\n"
            f"🔗 <b>Short link</b>: {short_text}"
        )
        if len(qr_caption) > 1024:
            room = max(120, 820 - len(portal) - len(display_name))
            preview = cfg_text[:room].rstrip() + "\n…"
            qr_caption = (
                f"▦ <b>{_html(g, display_name)} · QR</b>\n"
                f"<pre><code>{_html(g, preview)}</code></pre>\n"
                f"🔗 <b>Short link</b>: {short_text}"
            )
        await message.reply_photo(
            photo=InputFile(io.BytesIO(qr_bytes), filename=f"{name}.png"),
            caption=qr_caption,
            parse_mode=ParseMode.HTML,
        )
    else:
        await message.reply_text(
            "⚠️ QR is unavailable. The .conf card and short link above are valid.",
            parse_mode=ParseMode.HTML,
        )
    return urls


def _err(data):
    if not isinstance(data, dict):
        return str(data)
    return str(data.get("detail") or data.get("message") or data.get("error") or "Unknown error")


def _bool(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y", "enabled"}


def _client_field_icon(key: str) -> str:
    return {
        "name": "◇",
        "note": "✦",
        "data_limit_value": "◫",
        "data_limit_unit": "◈",
        "time_limit_days": "◷",
        "time_limit_hours": "◴",
        "time_limit_minutes": "◶",
        "phone_number": "⌕",
        "telegram_id": "✧",
        "start_on_first_use": "▷",
        "unlimited": "∞",
        "allowed_ips": "◎",
        "include_internal_network": "⌘",
        "endpoint": "⌁",
        "peer_endpoint": "◎",
        "persistent_keepalive": "⋄",
        "mtu": "↔",
        "dns": "◉",
    }.get(key, "◆")


def _value(key, raw):
    value = str(raw or "").strip()
    if value == "-":
        value = ""
    if key == "data_limit_value":
        return max(0, int(float(value or 0)))
    if key in {"time_limit_days", "time_limit_hours", "time_limit_minutes"}:
        return max(0.0, float(value or 0))
    if key in {"persistent_keepalive", "mtu"}:
        return max(0, int(float(value or 0)))
    if key in {"start_on_first_use", "unlimited", "enabled", "include_internal_network"}:
        return _bool(value)
    if key == "data_limit_unit":
        return "Mi" if value.lower().startswith("mi") else "Gi"
    return value


def _bytes(value):
    try:
        size = float(max(0, int(value or 0)))
    except Exception:
        size = 0.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return "0 B"


def clients(g):
    data = _api(g, "GET", "/api/subscriptions", timeout=30)
    rows = data.get("subscriptions") if isinstance(data, dict) else []
    return rows if isinstance(rows, list) else []


def client(g, sid):
    data = _api(g, "GET", f"/api/subscriptions/{int(sid)}", timeout=20)
    row = data.get("subscription") if isinstance(data, dict) else None
    return row if isinstance(row, dict) else {}


def status(row):
    counts = row.get("runtime_counts") or {}
    if int(counts.get("blocked") or 0) > 0 or str(row.get("status") or "").lower() == "blocked":
        return "🔴", "Blocked"
    if row.get("enabled"):
        return "🟢", "Enabled"
    return "🟡", "Disabled"


def time_text(g, row):
    if row.get("unlimited"):
        return "Unlimited"
    ttl = row.get("ttl_seconds")
    if ttl is None:
        if row.get("start_on_first_use") and not row.get("first_used_at"):
            return "Waiting for first use"
        return "No limit"
    try:
        ttl = int(ttl)
    except Exception:
        return str(ttl)
    if ttl <= 0:
        return "Expired"
    return g["human_ttl"](ttl)


def _limit_bytes(row):
    """Accept both current and legacy subscription API field names."""
    raw = row.get("limit_bytes")
    if raw in (None, ""):
        raw = row.get("data_limit_bytes")
    try:
        if raw not in (None, ""):
            return max(0, int(raw))
    except Exception:
        pass

    if _bool(row.get("unlimited")):
        return 0
    try:
        value = max(0, int(float(row.get("data_limit_value") or 0)))
    except Exception:
        value = 0
    unit = str(row.get("data_limit_unit") or "Gi").strip().lower()
    return value * (1024 ** 2 if unit.startswith("mi") else 1024 ** 3)


def data_text(row):
    used_bytes = max(0, int(row.get("used_bytes") or 0))
    used = _bytes(used_bytes)
    limit = _limit_bytes(row)
    if not limit:
        return f"{used} used · unlimited"
    remaining = row.get("remaining_bytes")
    try:
        remaining = max(0, int(remaining)) if remaining is not None else max(0, limit - used_bytes)
    except Exception:
        remaining = max(0, limit - used_bytes)
    return f"{used} / {_bytes(limit)} · {_bytes(remaining)} left"


def _duration_parts(days_value):
    try:
        minutes = max(0, int(round(float(days_value or 0) * 1440)))
    except Exception:
        minutes = 0
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    return days, hours, mins


def _duration_text(days_value):
    days, hours, mins = _duration_parts(days_value)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    return " ".join(parts) or "No timer"

def render_list(g, page=1, query=""):
    rows = clients(g)
    needle = str(query or "").strip().lower()
    if needle:
        rows = [r for r in rows if needle in " ".join(str(r.get(k) or "") for k in ("id", "name", "phone_number", "telegram_id", "note")).lower()]
    pages = max(1, math.ceil(len(rows) / PAGE_SIZE))
    page = max(1, min(int(page or 1), pages))
    visible = rows[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
    enabled = sum(1 for r in rows if r.get("enabled"))
    blocked = sum(1 for r in rows if status(r)[1] == "Blocked")
    lines = [
        "⌘ <b>Clients & Subscriptions</b>",
        f"◇ Total <code>{len(rows)}</code>   ● Enabled <code>{enabled}</code>   ⊘ Blocked <code>{blocked}</code>",
    ]
    if needle:
        lines += ["", f"⌕ Search: <code>{_html(g, query)}</code>"]
    lines += ["", f"Page <code>{page}/{pages}</code>" if visible else "No matching clients."]
    kb = []
    for r in visible:
        sid = int(r.get("id") or 0)
        _icon, state = status(r)
        state_icon = "●" if state == "Enabled" else "⊘" if state == "Blocked" else "○"
        name = str(r.get("name") or f"Client {sid}")
        count = int((r.get("runtime_counts") or {}).get("total") or len(r.get("locations") or []))
        kb.append([InlineKeyboardButton(f"{state_icon} {name} · {count} config{'s' if count != 1 else ''}", callback_data=f"client:open:{sid}")])
    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("‹ Previous", callback_data=f"client:list:{page-1}"))
    if page < pages:
        nav.append(InlineKeyboardButton("Next ›", callback_data=f"client:list:{page+1}"))
    if nav:
        kb.append(nav)
    kb += [
        [InlineKeyboardButton("＋ New client", callback_data="client:new"), InlineKeyboardButton("⌕ Search", callback_data="client:search")],
        [InlineKeyboardButton("↻ Refresh", callback_data=f"client:list:{page}"), InlineKeyboardButton("⌂ Dashboard", callback_data="home:main")],
    ]
    return "\n".join(lines), InlineKeyboardMarkup(kb)

def render_client(g, sid):
    r = client(g, sid)
    if not r:
        return "Client not found.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Clients", callback_data="client:list:1")]])

    _icon, state = status(r)
    state_icon = "●" if state == "Enabled" else "⊘" if state == "Blocked" else "○"
    counts = r.get("runtime_counts") or {}
    locations = r.get("locations") or []
    name = str(r.get("name") or f"Client {sid}")
    links = _subscription_links(g, sid)
    portal = str(links.get("url") or links.get("public_url") or "").strip()
    all_config = str(links.get("config_url") or "").strip()

    total = int(counts.get("total") or len(locations))
    active = int(counts.get("enabled") or counts.get("online") or 0)
    disabled = int(counts.get("disabled") or counts.get("offline") or 0)
    blocked = int(counts.get("blocked") or 0)

    lines = [
        f"◇ <b>{_html(g, name)}</b>",
        f"ID <code>{int(r.get('id') or sid)}</code>   {state_icon} <b>{state}</b>",
        "",
        f"◫ <b>Data</b>   {_html(g, data_text(r))}",
        f"◷ <b>Time</b>   {_html(g, time_text(g, r))}",
        f"⌘ <b>Configs</b> <code>{total}</code>   ● {active}   ○ {disabled}   ⊘ {blocked}",
    ]

    meta = []
    if r.get("phone_number"):
        meta.append(f"☎ {_html(g, r.get('phone_number'))}")
    if r.get("telegram_id"):
        meta.append(f"⌁ {_html(g, r.get('telegram_id'))}")
    if meta:
        lines += ["", "   ".join(meta)]
    if r.get("note"):
        lines += ["", f"✦ {_html(g, r.get('note'))}"]
    lines += ["", f"⌁ <b>Short link</b>  {_html(g, portal) if portal else 'Unavailable'}"]

    keyboard = []
    if r.get("enabled"):
        keyboard.append([InlineKeyboardButton("◫ Disable client", callback_data=f"client:disable:confirm:{sid}")])
    else:
        keyboard.append([InlineKeyboardButton("◇ Enable + reset", callback_data=f"client:enable:confirm:{sid}")])
    keyboard += [
        [InlineKeyboardButton("✦ Edit", callback_data=f"client:edit:{sid}"), InlineKeyboardButton("▦ Configs", callback_data=f"client:configs:{sid}:1")],
        [InlineKeyboardButton("↺ Reset data", callback_data=f"client:reset_data:confirm:{sid}"), InlineKeyboardButton("◷ Reset timer", callback_data=f"client:reset_timer:confirm:{sid}")],
    ]
    links_row = []
    if portal:
        links_row.append(InlineKeyboardButton("◈ Public portal", url=portal))
    if all_config:
        links_row.append(InlineKeyboardButton("⇩ All configs", url=all_config))
    if links_row:
        keyboard.append(links_row)
    if portal:
        keyboard.append([InlineKeyboardButton("⧉ Show short link", callback_data=f"client:showlink:{sid}")])
    keyboard += [
        [InlineKeyboardButton("⌫ Delete", callback_data=f"client:delete:confirm:{sid}"), InlineKeyboardButton("↻ Refresh", callback_data=f"client:open:{sid}")],
        [InlineKeyboardButton("◀ Clients", callback_data="client:list:1")],
    ]
    return "\n".join(lines), InlineKeyboardMarkup(keyboard)

def render_edit(g, sid):
    r = client(g, sid)
    if not r:
        return "Client not found.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Clients", callback_data="client:list:1")]])

    def shown_value(key, value):
        if key == "time_limit_days":
            return _duration_text(value)
        if key == "data_limit_value":
            unit = str(r.get("data_limit_unit") or "Gi")
            return f"{int(value or 0)} {unit}"
        if value is True:
            return "Yes"
        if value is False:
            return "No"
        return str(value if value not in (None, "") else "—")

    rows = []
    symbols = {
        "name": "◇", "note": "✦", "phone_number": "☎", "telegram_id": "⌁",
        "data_limit_value": "◫", "data_limit_unit": "◈", "time_limit_days": "◷",
        "start_on_first_use": "▷", "unlimited": "∞",
    }
    for key, label in EDIT_FIELDS:
        shown = shown_value(key, r.get(key))
        if len(shown) > 24:
            shown = shown[:23] + "…"
        rows.append([InlineKeyboardButton(f"{symbols.get(key, '◇')} {label} · {shown}", callback_data=f"client:field:{sid}:{key}")])
    rows.append([InlineKeyboardButton("◀ Client", callback_data=f"client:open:{sid}")])
    return f"✦ <b>Edit {_html(g, r.get('name') or sid)}</b>\n\nChoose the setting you want to change.", InlineKeyboardMarkup(rows)

def render_configs(g, sid, page=1):
    r = client(g, sid)
    if not r: return "Client not found.", InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Clients", callback_data="client:list:1")]])
    locs = r.get("locations") or []
    pages = max(1, math.ceil(len(locs)/PAGE_SIZE)); page=max(1,min(int(page),pages)); visible=locs[(page-1)*PAGE_SIZE:page*PAGE_SIZE]
    lines=[f"🖧 <b>Configs · {_html(g, r.get('name') or sid)}</b>","",f"Attached: <code>{len(locs)}</code>"]
    rows=[]
    for loc in visible:
        link=int(loc.get("link_id") or 0); name=str(loc.get("name") or f"Peer {loc.get('peer_id')}"); iface=str(loc.get("iface") or "—"); node=str(loc.get("node_name") or "Local")
        icon={"online":"🟢","blocked":"🔴"}.get(str(loc.get("status") or "").lower(),"🟡")
        rows.append([InlineKeyboardButton(f"{icon} {name} · {node} · {iface}",callback_data=f"client:config:{sid}:{link}")])
    nav=[]
    if page>1: nav.append(InlineKeyboardButton("‹ Prev",callback_data=f"client:configs:{sid}:{page-1}"))
    if page<pages: nav.append(InlineKeyboardButton("Next ›",callback_data=f"client:configs:{sid}:{page+1}"))
    if nav: rows.append(nav)
    rows += [[InlineKeyboardButton("➕ Attach existing config",callback_data=f"client:add:{sid}:1")],[InlineKeyboardButton("⬅️ Client",callback_data=f"client:open:{sid}")]]
    return "\n".join(lines),InlineKeyboardMarkup(rows)


def render_config(g, sid, link):
    r = client(g, sid)
    loc = next(
        (
            item
            for item in (r.get("locations") or [])
            if int(item.get("link_id") or 0) == int(link)
        ),
        None,
    )

    if not loc:
        return (
            "Config not found.",
            InlineKeyboardMarkup([[
                InlineKeyboardButton(
                    "◀ Configs",
                    callback_data=f"client:configs:{sid}:1",
                )
            ]]),
        )

    urls = _public_location_urls(
        g,
        sid,
        link,
    )

    lines = [
        f"▦ <b>{_html(g, loc.get('name') or 'Config')}</b>",
        "",
        f"Scope: <code>{_html(g, loc.get('scope') or 'local')}</code>",
        f"Node: <code>{_html(g, loc.get('node_name') or 'Local')}</code>",
        f"Interface: <code>{_html(g, loc.get('iface') or '—')}</code>",
        f"Address: <code>{_html(g, loc.get('address') or '—')}</code>",
        f"Endpoint: <code>{_html(g, loc.get('endpoint') or '—')}</code>",
        f"Status: <code>{_html(g, loc.get('status') or '—')}</code>",
        "",
        (
            f"🔗 <b>Short link</b>: "
            f"{_html(g, urls.get('portal') or 'Unavailable')}"
        ),
        "",
        "Use <b>CFG + QR</b> to receive the actual config file, "
        "config content, QR image, and short link.",
    ]

    rows = [
        [
            InlineKeyboardButton(
                "▣ CFG + QR",
                callback_data=f"client:sendcfg:{sid}:{link}",
            )
        ],
    ]

    portal = urls.get("portal")
    config_url = urls.get("config")

    external = []

    if portal:
        external.append(
            InlineKeyboardButton(
                "◈ Portal",
                url=portal,
            )
        )

    if config_url:
        external.append(
            InlineKeyboardButton(
                "⇩ Download",
                url=config_url,
            )
        )

    if external:
        rows.append(external)

    rows += [
        [
            InlineKeyboardButton(
                "⌁ Detach only",
                callback_data=f"client:detachq:{sid}:{link}:0",
            ),
            InlineKeyboardButton(
                "⌫ Detach + delete",
                callback_data=f"client:detachq:{sid}:{link}:1",
            ),
        ],
        [
            InlineKeyboardButton(
                "◀ Configs",
                callback_data=f"client:configs:{sid}:1",
            )
        ],
    ]

    return (
        "\n".join(lines),
        InlineKeyboardMarkup(rows),
    )


def render_catalog(g,sid,page=1):
    data=_api(g,"GET","/api/subscriptions/inbounds_catalog",timeout=30); catalog=[x for x in (data.get("inbounds") or []) if not x.get("already_linked")]
    pages=max(1,math.ceil(len(catalog)/PAGE_SIZE));page=max(1,min(int(page),pages));visible=catalog[(page-1)*PAGE_SIZE:page*PAGE_SIZE]
    lines=["➕ <b>Attach existing config</b>","",f"Available: <code>{len(catalog)}</code>"]
    rows=[]
    for x in visible:
        pid=int(x.get("peer_id") or 0); name=str(x.get("name") or f"Peer {pid}"); iface=str(x.get("iface") or "—"); node=str(x.get("node_name") or "")
        rows.append([InlineKeyboardButton(f"{name} · {node+' · ' if node else ''}{iface}",callback_data=f"client:attach:{sid}:{pid}")])
    nav=[]
    if page>1: nav.append(InlineKeyboardButton("‹ Prev",callback_data=f"client:add:{sid}:{page-1}"))
    if page<pages: nav.append(InlineKeyboardButton("Next ›",callback_data=f"client:add:{sid}:{page+1}"))
    if nav: rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Configs",callback_data=f"client:configs:{sid}:1")])
    return "\n".join(lines),InlineKeyboardMarkup(rows)



def _subscription_create_locations(g):
    data = _api(g, "GET", "/api/subscriptions/locations", timeout=30)
    rows = []
    for item in data.get("local") or []:
        rows.append({**item, "scope": "local"})
    for node in data.get("nodes") or []:
        for item in node.get("interfaces") or []:
            rows.append({
                **item,
                "scope": "node",
                "node_id": item.get("node_id") or node.get("id"),
                "node_name": item.get("node_name") or node.get("name"),
            })
    return rows


def _subscription_existing_configs(g):
    data = _api(g, "GET", "/api/subscriptions/inbounds_catalog", timeout=30)
    return [x for x in (data.get("inbounds") or []) if not x.get("already_linked")]


def _target_label(item, kind):
    if kind == "existing":
        src = item.get("node_name") or "Local"
        return f"{item.get('name') or 'Config'} · {src} · {item.get('iface') or ''}"[:60]
    src = item.get("node_name") or "Local"
    return f"{src} · {item.get('iface') or item.get('label') or 'Interface'}"[:60]


def _target_payload(item, kind, index):
    if kind == "existing":
        return {
            "peer_id": int(item.get("peer_id") or 0),
            "scope": item.get("scope") or "local",
            "location_label": item.get("location_label") or item.get("name") or "",
            "flag": item.get("flag") or "",
            "country_code": item.get("country_code") or "",
        }
    return {
        "scope": item.get("scope") or "local",
        "iface_id": item.get("iface_id"),
        "iface": item.get("iface"),
        "node_id": item.get("node_id"),
        "label": item.get("label"),
        "location": item.get("location") or item.get("node_name"),
        "address": item.get("address") or item.get("server_cidr") or "",
        "server_cidr": item.get("server_cidr") or item.get("address") or "",
        "peer_name": "",
    }


async def _show_subscription_source_menu(g, update, context):
    create = context.user_data.get("v58_client_create") or {}
    create["stage"] = "source"
    create.setdefault("selected_targets", [])
    context.user_data["v58_client_create"] = create
    await g["edit_send"](
        update,
        "⌘ <b>Configs for this client</b>\n\nChoose where the client should work. Optional WireGuard values can be changed before selecting configs.",
        InlineKeyboardMarkup([
            [InlineKeyboardButton("⌁ Advanced WireGuard options", callback_data="client:create:advanced")],
            [InlineKeyboardButton("ⓘ Fixed client endpoint guide", callback_data="client:create:fixedhelp")],
            [InlineKeyboardButton("⊕ Create new configs", callback_data="client:create:source:new")],
            [InlineKeyboardButton("◇ Use existing configs", callback_data="client:create:source:existing")],
            [InlineKeyboardButton("✕ Cancel", callback_data="client:list:1")],
        ]),
    )


async def _show_subscription_target_picker(g, update, context, kind):
    create = context.user_data.get("v58_client_create") or {}
    items = await asyncio.to_thread(
        _subscription_create_locations if kind == "new" else _subscription_existing_configs,
        g,
    )
    create["target_kind"] = kind
    create["target_items"] = items
    create.setdefault("selected_indexes", [])
    create["selected_indexes"] = []
    context.user_data["v58_client_create"] = create
    rows = []
    for idx, item in enumerate(items[:70]):
        rows.append([InlineKeyboardButton(
            "◇ " + _target_label(item, kind),
            callback_data=f"client:create:target:{kind}:{idx}",
        )])
    rows.append([InlineKeyboardButton("✓ Create client with selected", callback_data="client:create:targets:done")])
    rows.append([InlineKeyboardButton("◀ Source", callback_data="client:create:source")])
    text = "⊕ <b>Create new configs</b>" if kind == "new" else "◇ <b>Use existing configs</b>"
    text += "\n\nTap one or more entries. Selected entries change to ◆."
    if not items:
        text += "\n\n<i>No compatible entries were returned by the panel.</i>"
    await g["edit_send"](update, text, InlineKeyboardMarkup(rows))


async def _refresh_subscription_target_picker(g, update, context):
    create = context.user_data.get("v58_client_create") or {}
    kind = create.get("target_kind") or "new"
    items = create.get("target_items") or []
    chosen = {int(x) for x in (create.get("selected_indexes") or [])}
    rows = []
    for idx, item in enumerate(items[:70]):
        mark = "◆" if idx in chosen else "◇"
        rows.append([InlineKeyboardButton(
            f"{mark} {_target_label(item, kind)}",
            callback_data=f"client:create:target:{kind}:{idx}",
        )])
    rows.append([InlineKeyboardButton(f"✓ Create with {len(chosen)} selected", callback_data="client:create:targets:done")])
    rows.append([InlineKeyboardButton("◀ Source", callback_data="client:create:source")])
    await g["edit_send"](
        update,
        ("⊕ <b>Create new configs</b>" if kind == "new" else "◇ <b>Use existing configs</b>")
        + f"\n\nSelected: <code>{len(chosen)}</code>",
        InlineKeyboardMarkup(rows),
    )


def _local_telegram_settings(g):
    path = g.get("TELEGRAM_SETTINGS_FILE")
    if not path:
        return {}

    try:
        return g["_load_json"](path)
    except Exception:
        return {}


def diagnostics(g):
    version = g["panel_version_info"](fresh=False)
    update = g["panel_update_status"]()
    tg = _local_telegram_settings(g)
    admins = g["current_admins_full"]()
    notify = (
        (tg.get("notify") or {})
        if isinstance(tg, dict)
        else {}
    )

    installed = str(
        version.get("current")
        or g.get("PROJECT_VERSION")
        or "unknown"
    )
    latest = str(version.get("latest") or "")
    update_state = str(update.get("status") or "idle").lower()
    updater_text = (
        "Ready"
        if update_state == "idle"
        else update_state.replace("_", " ").title()
    )

    groups = (
        (
            "Panel and nodes",
            (
                ("app_down", "Panel stopped / unreachable"),
                ("app_up", "Panel started / recovered"),
                ("node_down", "Node went offline"),
                ("node_up", "Node came online"),
            ),
        ),
        (
            "WireGuard",
            (
                ("iface_down", "Interface went down"),
                ("iface_up", "Interface came up"),
                ("peer_expired", "Peer expired"),
                ("peer_limit", "Peer traffic limit reached"),
            ),
        ),
        (
            "Security",
            (
                ("login_success", "Successful login"),
                ("login_fail", "Failed login"),
                ("suspicious_4xx", "Suspicious HTTP activity"),
                ("security_block", "Temporary block applied"),
                ("security_release", "Manual security release"),
                ("security_auto_release", "Automatic security release"),
            ),
        ),
        (
            "Traffic Control",
            (
                ("traffic_policy_change", "Policy configuration changed"),
                ("traffic_apply_success", "Rules applied successfully"),
                ("traffic_apply_failed", "Rule application failed"),
            ),
        ),
        (
            "Backups and updates",
            (
                ("backup_success", "Backup completed"),
                ("backup_failed", "Backup failed"),
                ("update_success", "Update completed"),
                ("update_failed", "Update / rollback failed"),
            ),
        ),
    )

    all_keys = [
        key
        for _group, items in groups
        for key, _label in items
    ]
    enabled_count = sum(
        1
        for key in all_keys
        if bool(notify.get(key))
    )

    lines = [
        "⚙ <b>Settings</b>",
        "<i>Bot integration and protected panel controls</i>",
        "",
        "<b>Telegram integration</b>",
        (
            f"{'●' if tg.get('enabled') else '○'} "
            f"Service       "
            f"{'Enabled' if tg.get('enabled') else 'Disabled'}"
        ),
        (
            f"{'●' if tg.get('bot_token') else '○'} "
            f"Bot token     "
            f"{'Configured' if tg.get('bot_token') else 'Missing'}"
        ),
        f"♙ Administrators <code>{len(admins)}</code>",
        f"◇ Rules          <code>{enabled_count}/{len(all_keys)}</code> enabled",
        "",
        "<b>Panel runtime</b>",
        f"◇ Installed      <code>v{_html(g, installed)}</code>",
        (
            f"↥ Available      "
            f"<code>{('v' + _html(g, latest)) if latest else 'not detected'}</code>"
        ),
        f"◷ Updater        {_html(g, updater_text)}",
        f"✦ Bot            <code>{_html(g, g.get('BOT_VERSION') or 'wg-bot')}</code>",
    ]

    for group_name, items in groups:
        lines.extend([
            "",
            f"<b>{_html(g, group_name)}</b>",
        ])
        for key, label in items:
            lines.append(
                f"{'●' if notify.get(key) else '○'} "
                f"{_html(g, label)}"
            )

    lines.extend([
        "",
        "<b>Traffic note</b>",
        "◇ Traffic Control notifications cover configuration and apply results.",
        "◇ Block counters remain available in the web panel; they are not per-packet Telegram events.",
        "",
        "<i>TLS, ports, certificates, and account security remain in the authenticated web panel.</i>",
    ])

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "⚙ Open panel settings",
                url=f"{g['PANEL'].rstrip('/')}/settings",
            )
        ],
        [
            InlineKeyboardButton(
                "↥ Update center",
                callback_data="home:system",
            ),
            InlineKeyboardButton(
                "♙ Administrators",
                callback_data="home:admins",
            ),
        ],
        [
            InlineKeyboardButton(
                "↻ Refresh",
                callback_data="home:settings",
            ),
            InlineKeyboardButton(
                "← Dashboard",
                callback_data="home:main",
            ),
        ],
    ])

    return "\n".join(lines), keyboard


async def handle_callback(g, update, context):
    data=update.callback_query.data
    edit=g["edit_send"]
    if not (data.startswith("client:") or data=="home:settings"):
        return False
    if data.startswith("client:list:"):
        _clear_client_input_state(context)
        page = int(data.rsplit(":", 1)[-1])
        text, kb = await asyncio.to_thread(
            render_list,
            g,
            page,
            "",
        )
        await edit(update, text, kb)
        return True
    if data == "client:search":
        _clear_client_input_state(context)
        context.user_data["v58_client_search"] = True
        await edit(
            update,
            (
                "⌕ <b>Search clients</b>\n\n"
                "Send a name, ID, phone number, Telegram ID, or note.\n"
                "Send <code>-</code> to cancel."
            ),
            InlineKeyboardMarkup([[
                InlineKeyboardButton(
                    "✕ Cancel",
                    callback_data="client:list:1",
                )
            ]]),
        )
        return True

    if data == "client:new":
        _clear_client_input_state(context)
        profiles = _subscription_profiles(g)
        rows = [[InlineKeyboardButton("⊕ Enter client information", callback_data="client:new:start")]]
        if profiles:
            rows.append([InlineKeyboardButton("⌘ Use subscription profile", callback_data="client:new:profile")])
        rows.append([InlineKeyboardButton("✕ Cancel", callback_data="client:list:1")])
        await edit(
            update,
            "⊕ <b>Create subscription client</b>\n\nEnter the client policy, then create new local/node configs or attach existing configs—matching the web subscription workflow.",
            InlineKeyboardMarkup(rows),
        )
        return True

    if data == "client:new:start":
        fields = CLIENT_INFO_FIELDS
        context.user_data["v58_client_create"] = {
            "step": 0,
            "data": {
                "start_on_first_use": True,
                "unlimited": False,
                "allowed_ips": "0.0.0.0/0, ::/0",
                "persistent_keepalive": 25,
                "mtu": 1280,
                "dns": "1.1.1.1, 1.0.0.1",
                "endpoint": "",
                "peer_endpoint": "",
                "include_internal_network": False,
            },
            "mode": "subscription",
            "fields": fields,
            "stage": "fields",
        }
        key, prompt, default = fields[0]
        await edit(
            update,
            f"⊕ <b>Create client · 1/{len(fields)}</b>\n\n{_client_field_icon(key)} <b>{_html(g, prompt)}</b>",
            _client_create_keyboard(key, default),
        )
        return True

    if data == "client:new:profile":
        profiles = _subscription_profiles(g)
        if not profiles:
            await edit(update, "No subscription-compatible profiles were found.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Back", callback_data="client:new")]]))
            return True
        rows = [[InlineKeyboardButton(f"◇ {name}", callback_data=f"client:new:useprofile:{name}")] for name, _ in profiles]
        rows.append([InlineKeyboardButton("◀ Back", callback_data="client:new")])
        await edit(update, "⌘ <b>Select a subscription profile</b>", InlineKeyboardMarkup(rows))
        return True

    if data.startswith("client:new:useprofile:"):
        name = data.split(":", 3)[-1]
        values = dict(dict(_subscription_profiles(g)).get(name) or {})
        if not values:
            await edit(update, "Profile not found.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Back", callback_data="client:new")]]))
            return True
        prepared = {"start_on_first_use": True, "unlimited": False}
        for key, _prompt, _default in CREATE_FIELDS:
            if key in values and values[key] not in (None, ""):
                prepared[key] = values[key]
        missing = [f for f in CLIENT_INFO_FIELDS if f[0] not in prepared]
        if not missing:
            missing = [("name", "Client name", "")]
            prepared.pop("name", None)
        context.user_data["v58_client_create"] = {
            "step": 0,
            "data": prepared,
            "mode": "profile",
            "profile": name,
            "fields": missing,
        }
        key, prompt, default = missing[0]
        await edit(
            update,
            f"⌘ <b>Profile: {_html(g, name)}</b>\n\n{_client_field_icon(key)} <b>{_html(g, prompt)}</b>"
            + (f"\n◇ <b>Default</b>: <code>{_html(g, default)}</code>" if default else ""),
            _client_create_keyboard(key, default),
        )
        return True

    if data.startswith("client:create:set:") or data == "client:create:default":
        create = context.user_data.get("v58_client_create")
        if not create:
            await edit(update, "Creation session expired.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Clients", callback_data="client:list:1")]]))
            return True
        fields = create.get("fields") or CLIENT_INFO_FIELDS
        step = int(create.get("step") or 0)
        if step >= len(fields):
            await _show_subscription_source_menu(g, update, context)
            return True
        key, _prompt, default = fields[step]
        value = default
        if data.startswith("client:create:set:"):
            _, _, _, sent_key, value = data.split(":", 4)
            if sent_key != key:
                return True
        try:
            create.setdefault("data", {})[key] = _value(key, value)
        except Exception as exc:
            await edit(update, f"⚠️ Invalid value: <code>{_html(g, exc)}</code>", _client_create_keyboard(key, default))
            return True
        create["step"] = step + 1
        context.user_data["v58_client_create"] = create
        if create["step"] >= len(fields):
            await _show_subscription_source_menu(g, update, context)
            return True
        nkey, prompt, ndefault = fields[create["step"]]
        await edit(
            update,
            f"{('⌁ <b>Advanced WireGuard options' if create.get('stage') == 'advanced' else '⊕ <b>Create client')} · {create['step']+1}/{len(fields)}</b>\n\n"
            f"{_client_field_icon(nkey)} <b>{_html(g, prompt)}</b>"
            + (f"\n◇ <b>Default</b>: <code>{_html(g, ndefault)}</code>" if ndefault else ""),
            _client_create_keyboard(nkey, ndefault),
        )
        return True

    if data == "client:create:fixedhelp":
        await edit(
            update,
            (
                "ⓘ <b>Fixed client endpoint</b>\n\n"
                "Use this only when the client itself always has a stable public host/IP "
                "and a reachable forwarded UDP port. It is stored on the server-side peer.\n\n"
                "Typical cases include a site-to-site peer or a stable client behind a "
                "load balancer/NAT rule that always forwards the same UDP port.\n\n"
                "Leave it empty for phones, laptops, roaming clients, carrier NAT, and "
                "changing addresses. The normal server endpoint is used automatically."
            ),
            InlineKeyboardMarkup([[InlineKeyboardButton("◀ Back", callback_data="client:create:source")]]),
        )
        return True

    if data == "client:create:advanced":
        create = context.user_data.get("v58_client_create")
        if not create:
            await edit(update, "Creation session expired.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Clients", callback_data="client:list:1")]]))
            return True
        create["step"] = 0
        create["fields"] = ADVANCED_WG_FIELDS
        create["stage"] = "advanced"
        context.user_data["v58_client_create"] = create
        key, prompt, default = ADVANCED_WG_FIELDS[0]
        await edit(
            update,
            f"⌁ <b>Advanced WireGuard options · 1/{len(ADVANCED_WG_FIELDS)}</b>\n\n{_client_field_icon(key)} <b>{_html(g, prompt)}</b>",
            _client_create_keyboard(key, default),
        )
        return True

    if data == "client:create:source":
        await _show_subscription_source_menu(g, update, context)
        return True

    if data in {"client:create:source:new", "client:create:source:existing"}:
        kind = "new" if data.endswith(":new") else "existing"
        await _show_subscription_target_picker(g, update, context, kind)
        return True

    if data.startswith("client:create:target:"):
        _, _, _, kind, idx_s = data.split(":", 4)
        create = context.user_data.get("v58_client_create") or {}
        idx = int(idx_s)
        selected = {int(x) for x in (create.get("selected_indexes") or [])}
        if idx in selected:
            selected.remove(idx)
        else:
            selected.add(idx)
        create["selected_indexes"] = sorted(selected)
        create["target_kind"] = kind
        context.user_data["v58_client_create"] = create
        await _refresh_subscription_target_picker(g, update, context)
        return True

    if data == "client:create:targets:done":
        create = context.user_data.get("v58_client_create") or {}
        items = create.get("target_items") or []
        kind = create.get("target_kind") or "new"
        selected = [int(x) for x in (create.get("selected_indexes") or [])]
        if not selected:
            await update.callback_query.answer("Select at least one config or interface.", show_alert=True)
            return True
        create["selected_targets"] = [
            _target_payload(items[idx], kind, pos)
            for pos, idx in enumerate(selected)
            if 0 <= idx < len(items)
        ]
        context.user_data["v58_client_create"] = create
        await _submit_client_create(g, update, context)
        return True

    if data == "client:create:retry":
        create = context.user_data.get("v58_client_create")
        if create:
            create["submitting"] = False
            context.user_data["v58_client_create"] = create
            await _submit_client_create(g, update, context)
        return True

    if data.startswith("client:open:"):
        _clear_client_input_state(context)
        sid = int(data.rsplit(":", 1)[-1])
        text, kb = await asyncio.to_thread(
            render_client,
            g,
            sid,
        )
        await edit(update, text, kb)
        return True
    if data.startswith("client:edit:"):
        text,kb=await asyncio.to_thread(render_edit,g,int(data.rsplit(":",1)[-1])); await edit(update,text,kb); return True
    if data.startswith("client:field:"):
        _,_,sid,key=data.split(":",3); context.user_data["v58_client_edit"]={"sid":int(sid),"key":key}; label = next((lbl for k, lbl in EDIT_FIELDS if k == key), key.replace("_", " ").title())
        current = client(g, int(sid)).get(key)
        if key == "time_limit_days":
            current = _duration_text(current)
        await edit(update, f"✦ <b>Edit {_html(g, label)}</b>\n\nCurrent: <code>{_html(g, current if current not in (None, '') else '—')}</code>\n\nSend the new value. For active time, decimal days are accepted (for example <code>1.5</code> = 1 day 12 hours). Use <code>-</code> to clear optional text.", InlineKeyboardMarkup([[InlineKeyboardButton("◀ Cancel", callback_data=f"client:edit:{sid}")]])); return True
    if data.startswith("client:showlink:"):
        sid = int(data.rsplit(":", 1)[-1])
        links = await asyncio.to_thread(
            _subscription_links,
            g,
            sid,
        )
        portal = str(
            links.get("url")
            or links.get("public_url")
            or ""
        ).strip()
        await edit(
            update,
            (
                "🔗 <b>Subscription short link</b>\n\n"
                f"<code>{_html(g, portal or 'Unavailable')}</code>"
            ),
            InlineKeyboardMarkup([[
                InlineKeyboardButton(
                    "◀ Client",
                    callback_data=f"client:open:{sid}",
                )
            ]]),
        )
        return True

    if data.startswith("client:sendcfg:"):
        _, _, sid, link = data.split(":", 3)
        sid = int(sid)
        link = int(link)

        try:
            await _send_subscription_bundle(
                g,
                update,
                sid,
                link,
            )
            text, kb = await asyncio.to_thread(
                render_config,
                g,
                sid,
                link,
            )
            await edit(
                update,
                "✅ <b>Config bundle sent.</b>\n\n" + text,
                kb,
            )
        except Exception as exc:
            await edit(
                update,
                (
                    "❌ <b>Could not send config bundle.</b>\n\n"
                    f"<code>{_html(g, exc)}</code>"
                ),
                InlineKeyboardMarkup([[
                    InlineKeyboardButton(
                        "◀ Config",
                        callback_data=f"client:config:{sid}:{link}",
                    )
                ]]),
            )
        return True

    if data.startswith("client:configs:"):
        _,_,sid,page=data.split(":",3); text,kb=await asyncio.to_thread(render_configs,g,int(sid),int(page)); await edit(update,text,kb); return True
    if data.startswith("client:config:"):
        _,_,sid,link=data.split(":",3); text,kb=await asyncio.to_thread(render_config,g,int(sid),int(link)); await edit(update,text,kb); return True
    if data.startswith("client:add:"):
        _,_,sid,page=data.split(":",3); text,kb=await asyncio.to_thread(render_catalog,g,int(sid),int(page)); await edit(update,text,kb); return True
    if data.startswith("client:attach:"):
        _,_,sid,pid=data.split(":",3); result=await asyncio.to_thread(_api,g,"POST",f"/api/subscriptions/{int(sid)}/inbounds",{"targets":[{"peer_id":int(pid)}]},45)
        if not result.get("ok"): await edit(update,f"❌ <b>Attach failed</b>\n\n<code>{_html(g,_err(result))}</code>",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back",callback_data=f"client:add:{sid}:1")]])); return True
        text,kb=await asyncio.to_thread(render_configs,g,int(sid),1); await edit(update,"✅ Config attached.\n\n"+text,kb); return True
    if data.startswith("client:detachq:"):
        _,_,sid,link,delete=data.split(":",4); warn="The peer will also be deleted." if delete=="1" else "The peer remains in Peers."; kb=InlineKeyboardMarkup([[InlineKeyboardButton("✅ Confirm",callback_data=f"client:detach:{sid}:{link}:{delete}")],[InlineKeyboardButton("⬅️ Cancel",callback_data=f"client:config:{sid}:{link}")]]); await edit(update,f"⚠️ <b>Detach config?</b>\n\n{warn}",kb); return True
    if data.startswith("client:detach:"):
        _,_,sid,link,delete=data.split(":",4); result=await asyncio.to_thread(_api,g,"DELETE",f"/api/subscriptions/{int(sid)}/inbounds/{int(link)}?delete_peer={delete}",None,45)
        if not result.get("ok"): await edit(update,f"❌ <b>Detach failed</b>\n\n<code>{_html(g,_err(result))}</code>",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back",callback_data=f"client:configs:{sid}:1")]])); return True
        text,kb=await asyncio.to_thread(render_configs,g,int(sid),1); await edit(update,"✅ Config detached.\n\n"+text,kb); return True
    for action in ("enable","disable","reset_data","reset_timer"):
        if data.startswith(f"client:{action}:confirm:"):
            sid=int(data.rsplit(":",1)[-1]); warnings={"enable":"Enabling resets data and timer.","disable":"Disabling preserves data and timer.","reset_data":"Shared usage will be cleared.","reset_timer":"The shared timer will restart."}; kb=InlineKeyboardMarkup([[InlineKeyboardButton("✅ Confirm",callback_data=f"client:{action}:run:{sid}")],[InlineKeyboardButton("⬅️ Cancel",callback_data=f"client:open:{sid}")]]); await edit(update,f"⚠️ <b>Confirm action?</b>\n\n{warnings[action]}",kb); return True
        if data.startswith(f"client:{action}:run:"):
            sid=int(data.rsplit(":",1)[-1]); result=await asyncio.to_thread(_api,g,"POST",f"/api/subscriptions/{sid}/{action}",None,45)
            if not result.get("ok") and not result.get("partial"): await edit(update,f"❌ <b>Action failed</b>\n\n<code>{_html(g,_err(result))}</code>",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Client",callback_data=f"client:open:{sid}")]])); return True
            text,kb=await asyncio.to_thread(render_client,g,sid); await edit(update,"✅ Action completed.\n\n"+text,kb); return True
    if data.startswith("client:delete:confirm:"):
        sid=int(data.rsplit(":",1)[-1]); kb=InlineKeyboardMarkup([[InlineKeyboardButton("🗑 Delete client + peers",callback_data=f"client:delete:{sid}:1")],[InlineKeyboardButton("🔗 Delete client only",callback_data=f"client:delete:{sid}:0")],[InlineKeyboardButton("⬅️ Cancel",callback_data=f"client:open:{sid}")]]); await edit(update,"⚠️ <b>Delete client?</b>\n\nChoose whether attached peers should also be deleted.",kb); return True
    if data.startswith("client:delete:"):
        _,_,sid,peers=data.split(":",3); result=await asyncio.to_thread(_api,g,"DELETE",f"/api/subscriptions/{int(sid)}?delete_peers={peers}",None,45)
        if not result.get("ok"): await edit(update,f"❌ <b>Delete failed</b>\n\n<code>{_html(g,_err(result))}</code>",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Client",callback_data=f"client:open:{sid}")]])); return True
        text,kb=await asyncio.to_thread(render_list,g,1,""); await edit(update,"✅ Client deleted.\n\n"+text,kb); return True
    if data=="home:settings":
        text,kb=await asyncio.to_thread(diagnostics,g); await edit(update,text,kb); return True
    return False


async def _submit_client_create(g, update, context):
    create = context.user_data.get("v58_client_create")
    if not create or create.get("submitting"):
        return True
    create["submitting"] = True
    context.user_data["v58_client_create"] = create
    payload = dict(create.get("data") or {})
    payload["targets"] = list(create.get("selected_targets") or [])
    days = float(payload.pop("time_limit_days", 0) or 0)
    hours = float(payload.pop("time_limit_hours", 0) or 0)
    minutes = float(payload.pop("time_limit_minutes", 0) or 0)
    payload["time_limit_days"] = days + hours / 24.0 + minutes / 1440.0
    result = await asyncio.to_thread(_api, g, "POST", "/api/subscriptions", payload, 45)
    if not result.get("ok"):
        create["submitting"] = False
        context.user_data["v58_client_create"] = create
        await g["send_text"](
            update,
            "❌ <b>Create failed</b>\n\n<code>" + _html(g, _err(result)) + "</code>",
            kb=InlineKeyboardMarkup([
                [InlineKeyboardButton("↻ Retry", callback_data="client:create:retry")],
                [InlineKeyboardButton("✕ Cancel", callback_data="client:list:1")],
            ]),
        )
        return True
    context.user_data.pop("v58_client_create", None)
    sid = int((result.get("subscription") or {}).get("id") or result.get("id") or 0)
    if not sid:
        await g["send_text"](update, "❌ Client was created but the API did not return its ID.", kb=InlineKeyboardMarkup([[InlineKeyboardButton("◀ Clients", callback_data="client:list:1")]]))
        return True
    out, kb = await asyncio.to_thread(render_client, g, sid)
    links = await asyncio.to_thread(_subscription_links, g, sid)
    portal = str(links.get("url") or links.get("public_url") or "").strip()
    await g["send_text"](
        update,
        "✅ <b>Client created.</b>\n\n🔗 <b>Short link</b>: " + _html(g, portal or "Unavailable") + "\n\n" + out,
        kb=kb,
    )
    return True


async def handle_text(g, update, context):
    text=(update.message.text or "").strip()
    if context.user_data.get("v58_client_search"):
        context.user_data.pop("v58_client_search",None); query="" if text=="-" else text; out,kb=await asyncio.to_thread(render_list,g,1,query); await g["send_text"](update,out,kb=kb); return True
    edit_state=context.user_data.get("v58_client_edit")
    if edit_state:
        sid=int(edit_state["sid"]);key=edit_state["key"]
        try: value=_value(key,text)
        except Exception as exc: await g["send_text"](update,f"⚠️ Invalid value: {_html(g,exc)}",kb=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Edit",callback_data=f"client:edit:{sid}")]])); return True
        result=await asyncio.to_thread(_api,g,"PUT",f"/api/subscriptions/{sid}",{key:value},35)
        if not result.get("ok"): await g["send_text"](update,f"❌ Save failed.\n<code>{_html(g,_err(result))}</code>",kb=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Edit",callback_data=f"client:edit:{sid}")]])); return True
        context.user_data.pop("v58_client_edit",None); out,kb=await asyncio.to_thread(render_edit,g,sid); await g["send_text"](update,"✅ Saved.\n\n"+out,kb=kb); return True
    create = context.user_data.get("v58_client_create")

    if create:
        if create.get("submitting"):
            await g["send_text"](
                update,
                "⏳ A client is already being created. Please wait a moment.",
                kb=InlineKeyboardMarkup([[(InlineKeyboardButton("◀ Clients", callback_data="client:list:1"))]]),
            )
            return True
        fields = create.get("fields") or CLIENT_INFO_FIELDS
        step = int(create.get("step") or 0)

        if step < 0 or step >= len(fields):
            context.user_data.pop("v58_client_create", None)
            await g["send_text"](
                update,
                "⚠️ The create session was invalid and has been reset.",
                kb=InlineKeyboardMarkup([[
                    InlineKeyboardButton(
                        "◀ Clients",
                        callback_data="client:list:1",
                    )
                ]]),
            )
            return True

        key, prompt, default = fields[step]

        try:
            create["data"][key] = _value(
                key,
                default if text == "-" else text,
            )
        except Exception as exc:
            await g["send_text"](
                update,
                f"⚠️ Invalid value: {_html(g, exc)}",
                kb=InlineKeyboardMarkup([[
                    InlineKeyboardButton(
                        "✕ Cancel",
                        callback_data="client:list:1",
                    )
                ]]),
            )
            return True

        step += 1
        create["step"] = step
        context.user_data["v58_client_create"] = create

        if step < len(fields):
            key, prompt, default = fields[step]
            icon = _client_field_icon(key)
            await g["send_text"](
                update,
                (
                    f"{('⌁ <b>Advanced WireGuard options' if create.get('stage') == 'advanced' else '⊕ <b>Create client subscription')} · "
                    f"{step + 1}/{len(fields)}</b>\n\n"
                    f"{icon} <b>{_html(g, prompt)}</b>"
                    + (
                        f"\n◇ <b>Default</b>: <code>{_html(g, default)}</code>"
                        if default
                        else ""
                    )
                    + "\n\nSend <code>-</code> to accept the suggested value or leave an optional field empty."
                ),
                kb=_client_create_keyboard(key, default),
            )
            return True

        await _show_subscription_source_menu(g, update, context)
        return True

    return False
