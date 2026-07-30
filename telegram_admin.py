from __future__ import annotations

import asyncio
import math
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

PAGE_SIZE = 6
CREATE_FIELDS = [
    ("name", "Client name", ""),
    ("phone_number", "Phone number, or - to leave empty", ""),
    ("telegram_id", "Telegram username/ID, or - to leave empty", ""),
    ("data_limit_value", "Shared data limit value, 0 for no data cap", "0"),
    ("data_limit_unit", "Data unit: Mi or Gi", "Gi"),
    ("time_limit_days", "Active days, 0 for no time limit", "0"),
    ("start_on_first_use", "Start timer on first use? yes/no", "yes"),
    ("unlimited", "Unlimited subscription mode? yes/no", "no"),
    ("note", "Administrative note, or - to leave empty", ""),
]
EDIT_FIELDS = [
    ("name", "Client name"),
    ("phone_number", "Phone number"),
    ("telegram_id", "Telegram username/ID"),
    ("data_limit_value", "Shared data limit"),
    ("data_limit_unit", "Data unit"),
    ("time_limit_days", "Active days"),
    ("start_on_first_use", "Start on first use"),
    ("unlimited", "Unlimited mode"),
    ("note", "Administrative note"),
]


def _html(g, value):
    return g["html"](value)


def _api(g, method, path, payload=None, timeout=25):
    return g["_api_data"](method, path, payload=payload, timeout=timeout)


def _err(data):
    if not isinstance(data, dict):
        return str(data)
    return str(data.get("detail") or data.get("message") or data.get("error") or "Unknown error")


def _bool(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y", "enabled"}


def _value(key, raw):
    value = str(raw or "").strip()
    if value == "-":
        value = ""
    if key == "data_limit_value":
        return max(0, int(float(value or 0)))
    if key == "time_limit_days":
        return max(0.0, float(value or 0))
    if key in {"start_on_first_use", "unlimited", "enabled"}:
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


def data_text(row):
    used = _bytes(row.get("used_bytes"))
    if row.get("data_limit_bytes") in (None, 0, "0"):
        return f"{used} used · no cap"
    return f"{used} used · {_bytes(row.get('remaining_bytes'))} left"


def render_list(g, page=1, query=""):
    rows = clients(g)
    needle = str(query or "").strip().lower()
    if needle:
        rows = [r for r in rows if needle in " ".join(str(r.get(k) or "") for k in ("id","name","phone_number","telegram_id","note")).lower()]
    pages = max(1, math.ceil(len(rows) / PAGE_SIZE))
    page = max(1, min(int(page or 1), pages))
    visible = rows[(page-1)*PAGE_SIZE:page*PAGE_SIZE]
    enabled = sum(1 for r in rows if r.get("enabled"))
    blocked = sum(1 for r in rows if status(r)[1] == "Blocked")
    lines = ["👤 <b>Clients & Subscriptions</b>", "", f"Total <code>{len(rows)}</code> · Enabled <code>{enabled}</code> · Blocked <code>{blocked}</code>"]
    if needle:
        lines.append(f"Search: <code>{_html(g, query)}</code>")
    lines += ["", f"Page <code>{page}/{pages}</code>" if visible else "No matching clients."]
    kb = []
    for r in visible:
        sid = int(r.get("id") or 0)
        icon, _ = status(r)
        name = str(r.get("name") or f"Client {sid}")
        count = int((r.get("runtime_counts") or {}).get("total") or len(r.get("locations") or []))
        kb.append([InlineKeyboardButton(f"{icon} {name} · {count} config{'s' if count != 1 else ''}", callback_data=f"client:open:{sid}")])
    nav = []
    if page > 1: nav.append(InlineKeyboardButton("‹ Prev", callback_data=f"client:list:{page-1}"))
    if page < pages: nav.append(InlineKeyboardButton("Next ›", callback_data=f"client:list:{page+1}"))
    if nav: kb.append(nav)
    kb += [
        [InlineKeyboardButton("➕ New client", callback_data="client:new"), InlineKeyboardButton("🔎 Search", callback_data="client:search")],
        [InlineKeyboardButton("🔄 Refresh", callback_data=f"client:list:{page}"), InlineKeyboardButton("⬅️ Home", callback_data="home:main")],
    ]
    return "\n".join(lines), InlineKeyboardMarkup(kb)


def render_client(g, sid):
    r = client(g, sid)
    if not r:
        return "Client not found.", InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Clients", callback_data="client:list:1")]])
    icon, state = status(r)
    counts = r.get("runtime_counts") or {}
    locations = r.get("locations") or []
    name = str(r.get("name") or f"Client {sid}")
    lines = [
        f"👤 <b>{_html(g, name)}</b>",
        f"ID <code>{int(r.get('id') or sid)}</code> · {icon} <b>{state}</b>", "",
        f"📦 <b>Data</b>: {_html(g, data_text(r))}",
        f"⏳ <b>Time</b>: {_html(g, time_text(g, r))}",
        f"🖧 <b>Configs</b>: <code>{int(counts.get('total') or len(locations))}</code> (🟢 {int(counts.get('enabled') or 0)} · 🟡 {int(counts.get('disabled') or 0)} · 🔴 {int(counts.get('blocked') or 0)})",
    ]
    contact = []
    if r.get("phone_number"): contact.append(f"☎️ {_html(g, r.get('phone_number'))}")
    if r.get("telegram_id"): contact.append(f"Telegram {_html(g, r.get('telegram_id'))}")
    if contact: lines += ["", " · ".join(contact)]
    if r.get("note"): lines += ["", f"📝 {_html(g, r.get('note'))}"]
    keyboard = []
    if r.get("enabled"):
        keyboard.append([InlineKeyboardButton("⏸ Disable", callback_data=f"client:disable:confirm:{sid}")])
    else:
        keyboard.append([InlineKeyboardButton("▶️ Enable + reset", callback_data=f"client:enable:confirm:{sid}")])
    keyboard += [
        [InlineKeyboardButton("✏️ Edit", callback_data=f"client:edit:{sid}"), InlineKeyboardButton("🖧 Configs", callback_data=f"client:configs:{sid}:1")],
        [InlineKeyboardButton("♻️ Reset data", callback_data=f"client:reset_data:confirm:{sid}"), InlineKeyboardButton("⏱ Reset timer", callback_data=f"client:reset_timer:confirm:{sid}")],
    ]
    links = _api(g, "GET", f"/api/subscriptions/{int(sid)}/shortlink", timeout=15)
    linkrow = []
    if links.get("url") or links.get("public_url"): linkrow.append(InlineKeyboardButton("🌐 Portal", url=links.get("url") or links.get("public_url")))
    if links.get("config_url"): linkrow.append(InlineKeyboardButton("📥 Config", url=links.get("config_url")))
    if linkrow: keyboard.append(linkrow)
    keyboard += [
        [InlineKeyboardButton("🗑 Delete", callback_data=f"client:delete:confirm:{sid}"), InlineKeyboardButton("🔄 Refresh", callback_data=f"client:open:{sid}")],
        [InlineKeyboardButton("⬅️ Clients", callback_data="client:list:1")],
    ]
    return "\n".join(lines), InlineKeyboardMarkup(keyboard)


def render_edit(g, sid):
    r = client(g, sid)
    if not r: return "Client not found.", InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Clients", callback_data="client:list:1")]])
    rows = []
    for key, label in EDIT_FIELDS:
        value = r.get(key)
        shown = "Yes" if value is True else "No" if value is False else str(value if value not in (None, "") else "—")
        if len(shown) > 18: shown = shown[:17] + "…"
        rows.append([InlineKeyboardButton(f"{label}: {shown}", callback_data=f"client:field:{sid}:{key}")])
    rows.append([InlineKeyboardButton("⬅️ Client", callback_data=f"client:open:{sid}")])
    return f"✏️ <b>Edit {_html(g, r.get('name') or sid)}</b>\n\nChoose a field.", InlineKeyboardMarkup(rows)


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
    r=client(g,sid); loc=next((x for x in (r.get("locations") or []) if int(x.get("link_id") or 0)==int(link)),None)
    if not loc: return "Config not found.",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Configs",callback_data=f"client:configs:{sid}:1")]])
    lines=[f"🖧 <b>{_html(g,loc.get('name') or 'Config')}</b>","",f"Scope: <code>{_html(g,loc.get('scope') or 'local')}</code>",f"Node: <code>{_html(g,loc.get('node_name') or 'local')}</code>",f"Interface: <code>{_html(g,loc.get('iface') or '—')}</code>",f"Address: <code>{_html(g,loc.get('address') or '—')}</code>",f"Status: <code>{_html(g,loc.get('status') or '—')}</code>",f"Used: <code>{_html(g,_bytes(loc.get('used_bytes')))}</code>"]
    kb=InlineKeyboardMarkup([[InlineKeyboardButton("🔗 Detach only",callback_data=f"client:detachq:{sid}:{link}:0"),InlineKeyboardButton("🗑 Detach + delete",callback_data=f"client:detachq:{sid}:{link}:1")],[InlineKeyboardButton("⬅️ Configs",callback_data=f"client:configs:{sid}:1")]])
    return "\n".join(lines),kb


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


def _local_telegram_settings(g):
    path = g.get("TELEGRAM_SETTINGS_FILE")
    if not path:
        return {}

    try:
        return g["_load_json"](path)
    except Exception:
        return {}


def diagnostics(g):
    version = g["panel_version_info"](
        fresh=False,
    )
    update = g["panel_update_status"]()
    tg = _local_telegram_settings(g)
    admins = g["current_admins_full"]()
    notify = (
        tg.get("notify")
        or {}
    ) if isinstance(tg, dict) else {}

    installed = str(
        version.get("current")
        or g.get("PROJECT_VERSION")
        or "unknown"
    )

    latest = str(
        version.get("latest")
        or ""
    )

    source = str(
        version.get("source")
        or ""
    ).strip()

    update_state = str(
        update.get("status")
        or "idle"
    ).lower()

    updater_text = (
        "Ready"
        if update_state == "idle"
        else update_state.replace("_", " ").title()
    )

    telegram_text = (
        "Enabled"
        if tg.get("enabled")
        else "Disabled"
    )

    token_text = (
        "Configured"
        if tg.get("bot_token")
        else "Missing"
    )

    def enabled_text(key):
        return (
            "On"
            if notify.get(key)
            else "Off"
        )

    lines = [
        "<b>Bot Administration</b>",
        "",
        "<b>System</b>",
        (
            f"Panel version   <code>v{_html(g, installed)}</code>"
        ),
        (
            f"Latest version  <code>v{_html(g, latest)}</code>"
            if latest
            else "Latest version  <i>Not detected</i>"
        ),
        (
            f"Update source   {_html(g, source or 'GitHub')}"
        ),
        (
            f"Updater         {_html(g, updater_text)}"
        ),
        "",
        "<b>Telegram</b>",
        (
            f"Integration     {_html(g, telegram_text)}"
        ),
        (
            f"Bot token       {_html(g, token_text)}"
        ),
        (
            f"Administrators  <code>{len(admins)}</code>"
        ),
        "",
        "<b>Notifications</b>",
        (
            "Panel / Interface   "
            f"{enabled_text('app_down')} / "
            f"{enabled_text('iface_down')}"
        ),
        (
            "Login / Security    "
            f"{enabled_text('login_fail')} / "
            f"{enabled_text('suspicious_4xx')}"
        ),
        "",
        (
            "<i>Configuration changes remain available "
            "in the authenticated web panel.</i>"
        ),
    ]

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "Panel settings",
                url=f"{g['PANEL'].rstrip('/')}/settings",
            ),
            InlineKeyboardButton(
                "GitHub",
                url="https://github.com/Azumi67/WG_Panel",
            ),
        ],
        [
            InlineKeyboardButton(
                "Refresh",
                callback_data="home:settings",
            ),
            InlineKeyboardButton(
                "Home",
                callback_data="home:main",
            ),
        ],
    ])

    return (
        "\n".join(lines),
        keyboard,
    )


async def handle_callback(g, update, context):
    data=update.callback_query.data
    edit=g["edit_send"]
    if not (data.startswith("client:") or data=="home:settings"):
        return False
    if data.startswith("client:list:"):
        page=int(data.rsplit(":",1)[-1]); text,kb=await asyncio.to_thread(render_list,g,page,""); await edit(update,text,kb); return True
    if data=="client:search":
        context.user_data["v58_client_search"]=True; await edit(update,"🔎 <b>Search clients</b>\n\nSend name, ID, phone, Telegram ID, or note. Send <code>-</code> to cancel.",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Clients",callback_data="client:list:1")]])); return True
    if data=="client:new":
        context.user_data["v58_client_create"]={"step":0,"data":{}}; key,prompt,default=CREATE_FIELDS[0]; await edit(update,f"➕ <b>New client · 1/{len(CREATE_FIELDS)}</b>\n\n{_html(g,prompt)}"+(f"\nDefault: <code>{_html(g,default)}</code>" if default else "")+"\n\nSend <code>-</code> for default.",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel",callback_data="client:list:1")]])); return True
    if data.startswith("client:open:"):
        text,kb=await asyncio.to_thread(render_client,g,int(data.rsplit(":",1)[-1])); await edit(update,text,kb); return True
    if data.startswith("client:edit:"):
        text,kb=await asyncio.to_thread(render_edit,g,int(data.rsplit(":",1)[-1])); await edit(update,text,kb); return True
    if data.startswith("client:field:"):
        _,_,sid,key=data.split(":",3); context.user_data["v58_client_edit"]={"sid":int(sid),"key":key}; await edit(update,f"✏️ <b>Edit {_html(g,key.replace('_',' ').title())}</b>\n\nSend the new value. Use <code>-</code> to clear optional text.",InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel",callback_data=f"client:edit:{sid}")]])); return True
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
    create=context.user_data.get("v58_client_create")
    if create:
        step=int(create.get("step") or 0);key,prompt,default=CREATE_FIELDS[step]
        try: create["data"][key]=_value(key,default if text=="-" else text)
        except Exception as exc: await g["send_text"](update,f"⚠️ Invalid value: {_html(g,exc)}",kb=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel",callback_data="client:list:1")]])); return True
        step+=1;create["step"]=step;context.user_data["v58_client_create"]=create
        if step<len(CREATE_FIELDS):
            _,prompt,default=CREATE_FIELDS[step];await g["send_text"](update,f"➕ <b>New client · {step+1}/{len(CREATE_FIELDS)}</b>\n\n{_html(g,prompt)}"+(f"\nDefault: <code>{_html(g,default)}</code>" if default else "")+"\n\nSend <code>-</code> for default.",kb=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel",callback_data="client:list:1")]])); return True
        context.user_data.pop("v58_client_create",None);result=await asyncio.to_thread(_api,g,"POST","/api/subscriptions",create["data"],45)
        if not result.get("ok"): await g["send_text"](update,f"❌ <b>Create failed</b>\n\n<code>{_html(g,_err(result))}</code>",kb=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Clients",callback_data="client:list:1")]])); return True
        sid=int((result.get("subscription") or {}).get("id") or 0);out,kb=await asyncio.to_thread(render_client,g,sid);await g["send_text"](update,"✅ <b>Client created.</b>\n\nUse <b>Configs</b> to attach existing peers.\n\n"+out,kb=kb);return True
    return False
