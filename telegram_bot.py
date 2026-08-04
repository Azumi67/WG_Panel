#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import time, threading
from datetime import datetime, time as dtime, timezone
import os, io, json, logging, math, re, asyncio
from functools import wraps
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional, Set
import requests
from requests import HTTPError, RequestException
from requests.exceptions import HTTPError
from zoneinfo import ZoneInfo
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile, InputMediaPhoto, InputMediaDocument
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CommandHandler, ContextTypes, CallbackQueryHandler,
    MessageHandler, filters
)
from telegram.error import BadRequest
import telegram_admin as admin_azumi
import html as py_html
import qrcode
try:
    from telegram.helpers import escape as tg_escape   
except Exception:
    def tg_escape(s):
        return py_html.escape('' if s is None else str(s), quote=False)

try:
    from dotenv import load_dotenv
    for candidate in (
        Path.cwd() / ".env",
        Path(__file__).with_name(".env"),
        Path(__file__).parent / "instance" / ".env",
    ):
        if candidate.exists():
            load_dotenv(candidate, override=False)
except Exception:
    pass

HERE = Path(__file__).parent.resolve()

def _read_project_version() -> str:
    candidates = (HERE / "VERSION", HERE.parent / "VERSION")
    for version_file in candidates:
        try:
            value = version_file.read_text(encoding="utf-8").strip().lstrip("vV")
            if value and re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?", value):
                return value
        except FileNotFoundError:
            continue
        except Exception:
            logging.getLogger(__name__).exception("Could not read VERSION from %s", version_file)
    return "0.0.0"

PROJECT_VERSION = _read_project_version()
BOT_VERSION = f"wg-bot-{PROJECT_VERSION}"
INSTANCE_DIR = Path(os.getenv("PANEL_INSTANCE_PATH", HERE / "instance")).resolve()
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
TELEGRAM_SETTINGS_FILE = INSTANCE_DIR / "telegram_settings.json"
PANEL_SETTINGS_FILE = INSTANCE_DIR / "panel_settings.json"
RUNTIME_FILE        = INSTANCE_DIR / "runtime.json"

_ENV_PANEL = (
    os.getenv("PANEL_BASE_URL")
    or os.getenv("PANEL")
    or ""
).strip().rstrip("/")


def _load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _safe_int(v, default: int) -> int:
    try:
        i = int(v)
        if 1 <= i <= 65535:
            return i
    except Exception:
        pass
    return default


def _detect_panel_base() -> str:

    settings = _load_json(PANEL_SETTINGS_FILE)
    runtime  = _load_json(RUNTIME_FILE)

    tls_on = bool(settings.get("tls_enabled"))

    runtime_port = _safe_int(os.getenv("PORT") or runtime.get("port") or 8000, 8000)
    https_port   = _safe_int(settings.get("https_port") or 443, 443)

    if _ENV_PANEL:
        return _ENV_PANEL

    if tls_on:
        if runtime_port == https_port:
            return f"https://127.0.0.1:{runtime_port}"

        return f"http://127.0.0.1:{runtime_port}"

    return f"http://127.0.0.1:{runtime_port}"


PANEL = _detect_panel_base().rstrip("/")
API_KEY = (os.getenv("PANEL_API_KEY") or os.getenv("API_KEY") or "").strip()

BOT_TOKEN = (
    os.getenv("TG_BOT_TOKEN")
    or os.getenv("TELEGRAM_BOT_TOKEN")  
    or ""
).strip()

def load_bot_token() -> str:
    if BOT_TOKEN:
        return BOT_TOKEN
    try:
        with open(TELEGRAM_SETTINGS_FILE, "r", encoding="utf-8") as f:
            j = json.load(f)
        return (j.get("bot_token") or "").strip()
    except Exception:
        return ""

api = requests.Session()
if API_KEY:
    api.headers.update({
        "Authorization": f"Bearer {API_KEY}",
        "X-API-KEY": API_KEY,
    })

# _________ Optional: session login (OFF by default)

USE_PANEL_SESSION = os.getenv("USE_PANEL_SESSION", "0") == "1"
PANEL_ADMIN_USER = os.getenv("PANEL_ADMIN_USER", "").strip()
PANEL_ADMIN_PASS = os.getenv("PANEL_ADMIN_PASS", "").strip()

sess = requests.Session()

def _login_session() -> None:
    if not (PANEL_ADMIN_USER and PANEL_ADMIN_PASS):
        raise RuntimeError("Session login requested but PANEL_ADMIN_USER/PASS not set")
    g = sess.get(f"{PANEL}/login", timeout=10, allow_redirects=True)
    g.raise_for_status()
    csrf = sess.cookies.get("csrf_token", "")
    if not csrf:
        raise RuntimeError("No CSRF cookie from GET /login")
    data = {"username": PANEL_ADMIN_USER, "password": PANEL_ADMIN_PASS, "csrf_token": csrf}
    headers = {"Referer": f"{PANEL}/login"}
    p = sess.post(f"{PANEL}/login", data=data, headers=headers, timeout=10, allow_redirects=False)
    if p.status_code in (302, 303):
        loc = p.headers.get("Location") or "/"
        sess.get(f"{PANEL}{loc}", timeout=10, allow_redirects=True)
        return
    raise RuntimeError(f"Panel login failed: {p.status_code}")

def _login(func):
    if not USE_PANEL_SESSION:
        @wraps(func)
        def _no_login(*args, **kwargs):
            return func(*args, **kwargs)
        return _no_login

    @wraps(func)
    def _wrap(*args, **kwargs):
        try:
            r = sess.get(f"{PANEL}/", timeout=6)
            if r.status_code in (401, 403):
                _login_session()
        except Exception:
            _login_session()
        return func(*args, **kwargs)
    return _wrap


_admin_cache = {"ids": set(), "ts": 0.0, "full": [], "ttl": 90.0}

def _fetch_admins() -> list[dict]:
    try:
        r = api.get(f"{PANEL}/api/telegram/admins", timeout=8) 
        r.raise_for_status()
        return r.json().get("admins", []) or []
    except Exception:
        return []

def _refresh_admin(force: bool = False) -> None:
    now = time.time()
    if not force and (now - _admin_cache["ts"] < _admin_cache["ttl"]):
        return
    full = _fetch_admins()
    ids  = {str(a.get("id")) for a in full if a.get("id")}
    _admin_cache.update({"ids": ids, "full": full, "ts": now})

def current_admin_ids() -> set[str]:
    _refresh_admin()
    return set(_admin_cache["ids"])

def current_admins_full() -> list[dict]:
    _refresh_admin()
    return list(_admin_cache["full"])

def recipients() -> Set[str]:
    return {str(a["id"]) for a in current_admins_full() if not a.get("muted")}


def log_admin(uid: str, uname: str, action: str, details: str = ""):
    try:
        payload = {
            "admin_id": str(uid or ""),
            "admin_username": str(uname or ""),
            "action": action,
            "details": details,
            "via": "telegram",   
            "channel": "telegram",   
        }
        _post_soft(f"{PANEL}/api/admin_logs", session="api", json=payload)
    except Exception:
        pass

def _log_admin_update(update: "Update", action: str, details: str = ""):

    try:
        u = getattr(update, "effective_user", None)
        uid = str(getattr(u, "id", "") or "")
        uname = str(getattr(u, "username", "") or "")
        log_admin(uid, uname, action, details)
        try:
            log_tg(uid, uname, action, details)
        except Exception:
            pass
    except Exception:
        pass

def _peer_details(*, pid=None, name=None, iface=None, scope=None, node=None,
                      created=None, count=None, base=None):
    parts = []
    if pid is not None:           parts.append(f"peer_id={pid}")
    if name:                      parts.append(f"name={name}")
    if iface:                     parts.append(f"iface={iface}")
    if scope:                     parts.append(f"scope={scope}")
    if node:                      parts.append(f"node={node}")
    if created is not None and count is not None:
                                  parts.append(f"created={created}/{count}")
    if base:                      parts.append(f"base={base}")
    return "; ".join(parts)


def log_tg(uid: str, uname: str, action: str, details: str = ""):
    try:
        _post_soft(f"{PANEL}/api/telegram/admin_log", session="api", json={
            "admin_id": str(uid or ""),
            "admin_username": str(uname or ""),
            "action": action,
            "details": details,
        })
    except Exception:
        pass

class PanelLogHandler(logging.Handler):
    _local = threading.local()
    def __init__(self, admin_id="bot", admin_username="bot", level=logging.INFO):
        super().__init__(level); self.admin_id=str(admin_id); self.admin_username=str(admin_username)
    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._local, "active", False): return
        if record.name.startswith(("urllib3","requests","httpcore","httpx","telegram")): return
        try:
            self._local.active=True
            log_tg(self.admin_id, self.admin_username, "log", f"{(record.levelname or 'INFO').upper()}: {self.format(record)}")
        except Exception:
            pass
        finally:
            self._local.active=False


def csrf_headers(extra: dict | None = None) -> dict:
    tok = (sess.cookies.get("csrf_token") or "").strip()
    hdr = {
        "X-CSRFToken": tok,          
        "X-CSRF-Token": tok,        
        "Referer": PANEL,            
    }
    if extra:
        hdr.update(extra)
    return hdr

async def _create_single_peer(panel_base, iface_id, payload, session="api"):
    body = {**(payload or {}), "iface_id": int(iface_id)}
    response = await asyncio.to_thread(_post_soft, f"{panel_base}/api/peers", session=session, json=body, timeout=30)
    data = _json_txt(response)
    if not getattr(response, "ok", False):
        if isinstance(data, dict):
            detail = str(data.get("detail") or data.get("message") or data.get("error") or "")
        else:
            detail = str(data or "")
        raise RuntimeError(detail or f"Peer creation failed with HTTP {response.status_code}.")
    if isinstance(data, dict):
        peer = data.get("peer") or {}
        return data.get("id") or (peer.get("id") if isinstance(peer, dict) else None)
    return None

def _post_soft(url: str, session="auto", **kw):
    timeout = kw.pop("timeout", 12)

    if session == "api":
        return api.post(url, timeout=timeout, **kw)
    if session == "sess":
        return sess.post(url, timeout=timeout, **kw)

    if API_KEY:
        try:
            r = api.post(url, timeout=timeout, **kw)
            r.raise_for_status()
            return r
        except HTTPError as e:
            sc = getattr(getattr(e, "response", None), "status_code", None)
            if sc not in (401, 403):
                return e.response  
        except RequestException:
            pass

    return sess.post(url, timeout=timeout, **kw)


def _put_soft(url, **kw):
    try:
        return _put(url, **kw)
    except HTTPError as e:
        return e.response
    except Exception:
        timeout = kw.pop("timeout", 20)
        try:
            return sess.put(url, timeout=timeout, **kw)
        except Exception as ee:
            raise ee

def get_shortlink(pid: int, peer: Optional[Dict[str, Any]] = None) -> str:
    peer = peer or {}

    for key in ("shortlink", "short_link", "shortlink_url", "public_url", "url"):
        value = str(peer.get(key) or "").strip()
        if value:
            return value

    try:
        response = _get(
            f"{PANEL}/api/peer/{int(pid)}/shortlink",
            session="api",
            timeout=20,
        )
        data = response.json()
        if isinstance(data, dict):
            for key in ("url", "shortlink", "short_link", "public_url"):
                value = str(data.get(key) or "").strip()
                if value:
                    return value

            token = str(data.get("token") or "").strip()
            if token:
                return f"{PANEL.rstrip('/')}/u/{token}"
    except Exception:
        logging.getLogger(__name__).exception(
            "Could not obtain short link for peer %s", pid
        )

    try:
        refreshed = peer_by_id(int(pid)) if "peer_by_id" in globals() else None
        if isinstance(refreshed, dict):
            for key in ("shortlink", "short_link", "shortlink_url", "public_url", "url"):
                value = str(refreshed.get(key) or "").strip()
                if value:
                    return value
    except Exception:
        pass

    return ""

def _peer_lines(p: Dict[str, Any]) -> str:
    ttl = human_ttl(p.get("ttl_seconds"))
    used_mib = int(p.get("used_bytes", 0)) / (1024 * 1024)
    limit_val  = p.get("data_limit") or p.get("data_limit_value") or 0
    limit_unit = p.get("limit_unit") or p.get("data_limit_unit") or ""
    unlimited  = "Yes" if bool(p.get("unlimited")) else "No"
    addr = p.get("address") or "—"
    endpoint = p.get("endpoint") or "—"
    rx = p.get("rx") or 0
    tx = p.get("tx") or 0
    iface = p.get("iface") or "—"
    status = p.get("status") or "—"
    return "\n".join([
        f"⌘ <b>Interface</b>: {iface}   •   <b>Status</b>: {status}",
        f"◎ <b>Address</b>: {addr}",
        f"⌁ <b>Endpoint</b>: {endpoint}",
        f"▦ <b>Used</b>: {used_mib:.2f} MiB   •   <b>TTL</b>: {ttl}",
        f"◫ <b>Limit</b>: {limit_val} {limit_unit}   •   <b>Unlimited</b>: {unlimited}",
        f"↓ <b>RX</b>: {rx} MiB   •   ↑ <b>TX</b>: {tx} MiB",
    ])

def _peer_more_info(p: Dict[str, Any]) -> str:
    def g(k, alt=None): 
        v = p.get(k, p.get(alt) if alt else None)
        return "—" if v in (None, "", []) else str(v)

    lines = [
        f"◇ <b>{html(g('name'))}</b> (id {html(str(p.get('id')))} )",
        f"⌘ <b>Interface</b>: {html(g('iface','interface'))} • <b>Status</b>: {html(str(p.get('status') or '—'))}",
        f"◎ <b>Address</b>: {html(g('address', 'ip'))} • <b>MTU</b>: {html(g('mtu'))}",
        f"⌁ <b>Endpoint</b>: {html(g('endpoint'))}",
        f"◇ <b>Public key</b>: <code>{html(g('public_key'))}</code>",
        f"◷ <b>Created</b>: {html(g('created_at'))} • <b>First used</b>: {html(g('first_used'))}",
        f"◷ <b>Expires</b>: {html(g('expires_at'))} • <b>TTL</b>: {html(human_ttl(p.get('ttl_seconds')))}",
        f"◫ <b>Limit</b>: {html(str(p.get('data_limit_value') or p.get('data_limit') or 0))} {html(g('data_limit_unit','limit_unit'))} • <b>Unlimited</b>: { 'Yes' if p.get('unlimited') else 'No' }",
        f"↓ RX: {html(str(p.get('rx') or 0))} MiB • ↑ TX: {html(str(p.get('tx') or 0))} MiB",
        f"☎ <b>Phone</b>: {html(g('phone_number'))} • <b>Telegram</b>: {html(g('telegram_id'))}",
        f"◉ <b>DNS</b>: {html(', '.join(p.get('dns')) if isinstance(p.get('dns'), list) else str(p.get('dns') or '—'))}",
    ]
    return "\n".join(lines)

def scope_keyboard(prefix: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⌘ Local", callback_data=f"{prefix}:scope:local"),
         InlineKeyboardButton("⌁ Node",  callback_data=f"{prefix}:scope:node")],
        [InlineKeyboardButton("← Back", callback_data="home")]
    ])

def _bundle_kb(p: Dict[str, Any]) -> InlineKeyboardMarkup:
    """Keyboard for the bundle card: no enable/disable here."""
    pid = int(p.get("id"))
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("↻ Refresh", callback_data=f"peer:bundle:{pid}"),
         InlineKeyboardButton("◇ Edit",    callback_data=f"peer:edit:{pid}")],
        [InlineKeyboardButton("← Back",     callback_data="peers:menu")]
    ])


def _html_pre(s: str) -> str:

    return f"<pre><code>{html(s)}</code></pre>"

def _caption(p: Dict[str, Any], short_url: Optional[str], cfg: str) -> str:
    name     = p.get("name") or f"peer-{p.get('id')}"
    iface    = p.get("iface") or p.get("interface") or "—"
    status   = (p.get("status") or "—").lower()
    address  = p.get("address") or "—"
    endpoint = p.get("endpoint") or "—"
    used_mib = (int(p.get("used_bytes", 0)) / (1024 * 1024)) if str(p.get("used_bytes", "0")).isdigit() else 0
    ttl      = human_ttl(p.get("ttl_seconds")) if "human_ttl" in globals() else (p.get("ttl_seconds") or "—")
    rx_mib   = p.get("rx") or 0
    tx_mib   = p.get("tx") or 0
    shortlnk = short_url or "—"

    return (
        f"▦ <b>{html(name)}</b> (id {html(str(p.get('id')))} )\n"
        f"⌘ <b>Interface</b>: {html(str(iface))}   •   <b>Status</b>: {html(status)}\n"
        f"◎ <b>Address</b>: {html(str(address))}\n"
        f"⌁ <b>Endpoint</b>: {html(str(endpoint))}\n"
        f"⌁ <b>Link</b>: {html(shortlnk)}\n"
        f"▦ <b>Used</b>: {used_mib:.2f} MiB   •   <b>TTL</b>: {html(str(ttl))}\n"
        f"↓ <b>RX</b>: {html(str(rx_mib))} MiB   •   ↑ <b>TX</b>: {html(str(tx_mib))} MiB"
    )


MAX_CAPTION = 1024  

def _cap_render(cfg_text: str, short: str | None) -> str:

    shortline = f"⌁ Link: {tg_escape(short) if short else '—'}"
    body = f"<pre><code>{tg_escape(cfg_text)}</code></pre>\n{shortline}"
    return body if len(body) <= MAX_CAPTION else ""

async def send_peers(update: Update, pid: int):
    """Send the peer config and QR as two self-contained Telegram cards."""
    p = peer_by_id(pid) if 'peer_by_id' in globals() else get_peer(pid)
    if not p:
        await edit_send(update, "Peer not found.", KB.peers_index())
        return

    raw_name = str(p.get("name") or f"peer-{pid}").strip()
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw_name).strip("._") or f"peer-{pid}"

    try:
        short = get_shortlink(pid, p) if "get_shortlink" in globals() else ""
    except Exception:
        short = ""

    try:
        cfg = _peer_config(pid, short) or ""
    except Exception as exc:
        logging.getLogger(__name__).exception("Could not fetch peer config %s", pid)
        await edit_send(
            update,
            (
                "⊘ <b>The peer exists, but its configuration could not be exported.</b>\n\n"
                f"<code>{html(str(exc))}</code>"
            ),
            KB.back(f"peer:open:{pid}"),
        )
        return

    short_text = tg_escape(short) if short else "Unavailable"
    cfg_block = f"<pre><code>{tg_escape(cfg)}</code></pre>"
    full_caption = (
        f"◇ <b>{tg_escape(raw_name)} · Configuration</b>\n<i>WireGuard client profile</i>\n\n"
        f"{cfg_block}\n"
        f"⌁ <b>Short link</b>\n{short_text}"
    )
    if len(full_caption) > 1024:
        room = max(120, 820 - len(short_text) - len(raw_name))
        preview = cfg[:room].rstrip() + "\n…"
        full_caption = (
            f"◇ <b>{tg_escape(raw_name)} · Configuration</b>\n<i>WireGuard client profile</i>\n\n"
            f"<pre><code>{tg_escape(preview)}</code></pre>\n"
            f"⌁ <b>Short link</b>\n{short_text}"
        )

    message = update.effective_message
    await message.reply_document(
        document=InputFile(io.BytesIO(cfg.encode("utf-8")), filename=f"{safe_name}.conf"),
        caption=full_caption,
        parse_mode=ParseMode.HTML,
    )

    try:
        png = _peer_qr(pid, cfg)
    except Exception:
        png = b""
        logging.getLogger(__name__).exception("Could not fetch peer QR %s", pid)

    if png:
        qr_caption = (
            f"▦ <b>{tg_escape(raw_name)} · QR code</b>\n<i>Scan with a WireGuard client</i>\n\n"
            f"{cfg_block}\n"
            f"⌁ <b>Short link</b>\n{short_text}"
        )
        if len(qr_caption) > 1024:
            room = max(120, 820 - len(short_text) - len(raw_name))
            preview = cfg[:room].rstrip() + "\n…"
            qr_caption = (
                f"▦ <b>{tg_escape(raw_name)} · QR code</b>\n<i>Scan with a WireGuard client</i>\n\n"
                f"<pre><code>{tg_escape(preview)}</code></pre>\n"
                f"⌁ <b>Short link</b>\n{short_text}"
            )
        try:
            await message.reply_photo(
                photo=InputFile(io.BytesIO(png), filename=f"{safe_name}.png"),
                caption=qr_caption,
                parse_mode=ParseMode.HTML,
                reply_markup=_bundle_kb(p),
            )
        except BadRequest as exc:
            logging.getLogger(__name__).warning(
                "Telegram photo processing failed for peer %s; sending QR as document: %s",
                pid, exc,
            )
            await message.reply_document(
                document=InputFile(io.BytesIO(png), filename=f"{safe_name}-QR.png"),
                caption=qr_caption,
                parse_mode=ParseMode.HTML,
                reply_markup=_bundle_kb(p),
            )
    else:
        await message.reply_text(
            "⊘ <b>QR code unavailable</b>\n\nThe configuration file and short link above are valid.",
            reply_markup=_bundle_kb(p),
            parse_mode=ParseMode.HTML,
        )

def _nonempty(val) -> bool:
    return val is not None and str(val) != ""

def _for_skip(key: str, val, *, profile_mode: bool) -> bool:

    if val is None:
        return False

    s = str(val).strip()
    if s == "":
        return False

    if profile_mode and key in {"time_limit_days", "time_limit_hours"}:
        if s in {"0", "0.0"}:
            return False

    return True

def _nonempty_bytes(b: bytes) -> bool:
    return isinstance(b, (bytes, bytearray)) and len(b) > 0

def _looks_like_html_doc(text: str) -> bool:
    sample = str(text or '').lstrip().lower()
    return sample.startswith('<!doctype html') or sample.startswith('<html')

def admin_only(func):
    @wraps(func)
    async def wrapper(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ):
        chat = getattr(
            update,
            "effective_chat",
            None,
        )

        if (
            chat
            and getattr(chat, "type", None) != "private"
        ):
            try:
                await context.bot.send_message(
                    chat_id=chat.id,
                    parse_mode=ParseMode.HTML,
                    text=(
                        "⊘ <b>Private access only</b>\n\n"
                        "◇ <b>Status</b>  Group access blocked\n"
                        "⌁ <b>Reason</b>  This bot only accepts commands "
                        "inside a private conversation.\n\n"
                        "Open the bot directly and send your command again."
                    ),
                    disable_web_page_preview=True,
                )

            except Exception:
                logging.debug(
                    "Could not send private-chat warning",
                    exc_info=True,
                )

            return

        user = getattr(
            update,
            "effective_user",
            None,
        )

        uid = str(
            getattr(user, "id", "")
            or ""
        )

        ids = current_admin_ids()

        if (
            not uid
            or uid not in ids
        ):
            try:
                effective_chat = getattr(
                    update,
                    "effective_chat",
                    None,
                )

                if not effective_chat:
                    return

                await context.bot.send_message(
                    chat_id=effective_chat.id,
                    parse_mode=ParseMode.HTML,
                    text=(
                        "⊘ <b>Access denied</b>\n"
                        "<i>This Telegram account is not registered "
                        "as a panel administrator.</i>\n\n"
                        "◇ <b>Your Telegram ID</b>\n"
                        f"<code>{html(uid or 'unknown')}</code>\n\n"
                        "⌁ <b>Authorization required</b>\n"
                        "Ask an existing administrator to add this ID from:\n"
                        "<code>Panel → Settings → Telegram → Administrators</code>\n\n"
                        "◆ <b>Status</b>  Unauthorized"
                    ),
                    disable_web_page_preview=True,
                )

            except Exception:
                logging.debug(
                    "Could not send unauthorized-access warning "
                    "to Telegram user %s",
                    uid or "unknown",
                    exc_info=True,
                )

            return

        return await func(
            update,
            context,
        )

    return wrapper


@admin_only
async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_html(f"◇ Your Telegram ID: <b>{update.effective_user.id}</b>")

@admin_only
async def cmd_admins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    rows = current_admins_full()
    if not rows:
        await update.message.reply_text("No admins configured in panel.")
        return
    lines = ["<b>Admins</b>"]
    for a in rows:
        u = f"@{a['username']}" if a.get("username") else ""
        mute = "○" if a.get("muted") else "●"
        note = f" — {a.get('note','')}" if a.get("note") else ""
        lines.append(f"• <code>{a['id']}</code> {u} {mute}{note}")
    await update.message.reply_html("\n".join(lines))

@admin_only
async def cmd_reload_admins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await asyncio.to_thread(_refresh_admin, True)
    await update.message.reply_text("Admin list reloaded from panel.")

@admin_only
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_text(update, render_home(update), kb=KB.home())

@admin_only
async def cmd_updates(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text, keyboard = await asyncio.to_thread(render_update_center, fresh=True)
    await send_text(update, text, kb=keyboard)



@admin_only
async def cmd_subscriptions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text_out, keyboard = await asyncio.to_thread(admin_azumi.render_list, globals(), 1, "")
    await send_text(update, text_out, kb=keyboard)


@admin_only
async def cmd_clients(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text_out, keyboard = render_clients()
    await send_text(update, text_out, kb=keyboard)


@admin_only
async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text_out, keyboard = await asyncio.to_thread(admin_azumi.diagnostics, globals())
    await send_text(update, text_out, kb=keyboard)


def html(value: Any) -> str:
    return py_html.escape("" if value is None else str(value), quote=False)

def pre(txt: str) -> str:
    return f"<pre>{html(txt.strip())}</pre>"

def _who(update):
    u = getattr(update, "effective_user", None)
    uid = str(getattr(u, "id", "") or "")
    uname = getattr(u, "username", "") or ""
    uline = f"@{uname}" if uname else "—"
    return uid, uline

def _fmt_pct(v) -> str:
    try:
        return f"{float(v):.1f}%"
    except Exception:
        s = str(v).strip()
        if not s:
            return "—"
        return s if s.endswith("%") else f"{s}%"

def _fmt_int(v, default=0) -> int:
    try:
        return int(v)
    except Exception:
        return default

def _fmt_uptime_from_stats(st: dict) -> str:
    if st.get("uptime_str"):
        return str(st["uptime_str"]).strip()

    if "uptime_value" in st and "uptime_unit" in st:
        return f"{st['uptime_value']}{st['uptime_unit']}"

    secs = _fmt_int(st.get("uptime", 0), 0)
    if secs <= 0:
        return "—"

    d = secs // 86400
    h = (secs % 86400) // 3600
    m = (secs % 3600) // 60

    if d > 0:
        return f"{d}d {h}h"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"

def render_home(update) -> str:
    uid, uline = _who(update)
    try:
        st = peer_stats() or {}
    except Exception:
        st = {}

    cpu = _fmt_pct(st.get("cpu", "—"))
    mem = _fmt_pct(st.get("mem", "—"))
    disk = _fmt_pct(st.get("disk", "—"))
    upt = _fmt_uptime_from_stats(st)
    counts = st.get("counts") or {}
    active = _fmt_int(
        counts.get("active", counts.get("online", 0)),
        0,
    )
    idle = _fmt_int(
        counts.get("idle", counts.get("offline", 0)),
        0,
    )
    blocked = _fmt_int(counts.get("blocked", 0), 0)
    total = _fmt_int(
        counts.get("total", active + idle + blocked),
        active + idle + blocked,
    )
    activity_window = _fmt_int(
        counts.get("activity_window_seconds", 180),
        180,
    )
    activity_minutes = max(1, int(math.ceil(activity_window / 60)))

    panel_url = str(PANEL or "").strip()
    panel_line = f'<a href="{html(panel_url)}">Open panel</a>' if panel_url else "Unavailable"

    return "\n".join([
        "◇ <b>Dashboard</b>",
        f"♙ <b>{html(uline)}</b>  <code>{html(uid)}</code>",
        f"⌁ {panel_line}",
        "",
        "▦ <b>System</b>",
        f"<pre>CPU     {html(cpu):>7}   Memory  {html(mem):>7}\nDisk    {html(disk):>7}   Uptime  {html(upt):>7}</pre>",
        "⌘ <b>Peer activity</b>",
        (
            f"● Active ≤{activity_minutes}m <code>{active}</code>   "
            f"○ No recent handshake <code>{idle}</code>"
        ),
        f"⊘ Blocked <code>{blocked}</code>   ◇ Total <code>{total}</code>",
        "",
        f"✦ <b>Bot</b> <code>{html(BOT_VERSION)}</code>",
    ])
def file_zip(b: bytes) -> bool:
    return isinstance(b, (bytes, bytearray)) and b[:4] == b'PK\x03\x04'

def _safe_zip(r, label="backup"):
    ct = (r.headers.get("content-type") or "").lower()
    body = r.content
    if not file_zip(body):
        text = r.text[:400] if hasattr(r, "text") else ""
        raise RuntimeError(f"{label} did not return a valid ZIP (content-type={ct}). "
                           f"Server said: {text or 'no text'}")
    return body


def human_ttl(ttl: Optional[int]) -> str:
    if not ttl: return "—"
    d, r = divmod(ttl, 86400); h, r = divmod(r, 3600); m, _ = divmod(r, 60)
    out = []
    if d: out.append(f"{d}d")
    if h: out.append(f"{h}h")
    if m: out.append(f"{m}m")
    return " ".join(out) or "0m"

async def edit_send(update: Update, text: str, kb=None):
    m = update.callback_query.message if update.callback_query else update.effective_message
    try:
        await m.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    except Exception:
        await m.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)

async def send_text(update: Update, text: str, kb=None):
    await (update.effective_message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=kb))

def _node_peer(p: dict) -> bool:
    s = str(p.get("scope") or "").lower()
    if s == "node": return True
    if p.get("node_id") is not None: return True
    if p.get("node"): return True
    return False

def _peer_location(p: dict) -> str:
    if not _node_peer(p):
        return "⌘ Local"
    nid  = p.get("node_id")
    nlab = p.get("node_name") or p.get("node") or (f"Node {nid}" if nid is not None else "Node")
    return f"⌁ {nlab}"


FIELD_MAP = {
    "keepalive": "persistent_keepalive",
}
def _payload_api(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        if v in ("", None):
            continue
        key = FIELD_MAP.get(k, k)
        if key in ("data_limit_value", "persistent_keepalive", "time_limit_days", "time_limit_hours", "mtu"):
            try:
                out[key] = int(v)
            except Exception:
                continue
        elif key in ("start_on_first_use", "unlimited", "include_internal_network"):
            out[key] = bool(int(v)) if str(v).isdigit() else (str(v).lower() in ("true","yes","on","y"))
        else:
            out[key] = v
    return out

def _edit_label(key: str) -> str:
    for k, prompt, _ in EDIT_FIELDS:
        if k == key:
            clean = re.sub(r"\s*\(enter to skip\)\s*$", "", prompt, flags=re.I).strip()
            return clean
    return key.replace("_", " ").title()

def _bool01(v) -> str:
    s = str(v).strip().lower()
    if s in {"1","true","yes","on","y"}:  return "1"
    if s in {"0","false","no","off","n"}: return "0"
    return "0" if s == "" else s  

def _float(x):
    try: return float(x)
    except Exception: return None

def _current_value(peer: Dict[str, Any] | None, key: str) -> str:

    def _peer_val(k):
        if not peer: return None
        if k == "data_limit_value":
            return peer.get("data_limit_value", peer.get("data_limit"))
        if k == "data_limit_unit":
            return peer.get("data_limit_unit", peer.get("limit_unit"))
        api_key = FIELD_MAP.get(k, k)     
        return peer.get(api_key, peer.get(k))

    if key in {"start_on_first_use", "unlimited"}:
        v = _peer_val(key)
        if v is None: v = PANEL_DEFAULTS.get(key, 0)
        return _bool01(v)

    if key == "time_limit_days":
        v_days = _peer_val("time_limit_days")
        f = _float(v_days)
        if f is not None:
            if f < 0: f = 0.0
            return str(int(math.floor(f)))
        dv = PANEL_DEFAULTS.get("time_limit_days", 0)
        return str(int(dv) if isinstance(dv, (int, float)) else 0)

    if key == "time_limit_hours":
        v_days = _peer_val("time_limit_days")
        fd = _float(v_days)
        if fd is not None:
            if fd < 0: fd = 0.0
            hrs = int(round((fd - math.floor(fd)) * 24))
            return str(hrs)
        v_hours = _peer_val("time_limit_hours")
        try:
            return str(int(v_hours))
        except Exception:
            dv = PANEL_DEFAULTS.get("time_limit_hours", 0)
            return str(int(dv) if isinstance(dv, (int, float)) else 0)

    v = _peer_val(key)
    if v in (None, ""):
        v = PANEL_DEFAULTS.get(key, "")
    return "" if v is None else str(v)

def _raise_if_login_html(response, requested_url: str) -> None:
    """Turn silent Flask login redirects into an actionable API-auth error."""
    final_url = str(getattr(response, "url", "") or "")
    history = list(getattr(response, "history", []) or [])
    redirected_to_login = any(
        "/login" in str(getattr(item, "headers", {}).get("Location", ""))
        for item in history
    ) or "/login" in final_url

    ctype = str(getattr(response, "headers", {}).get("content-type", "") or "").lower()
    body = str(getattr(response, "text", "") or "")
    if redirected_to_login or ("text/html" in ctype and _looks_like_html_doc(body)):
        raise RuntimeError(
            "Panel returned the login HTML instead of API data for "
            f"{requested_url}. Check the route decorator/order in app.py and ensure "
            "the Telegram API key matches the panel API_KEY."
        )


def _get(url: str, session="auto", **kw):
    timeout = kw.pop("timeout", 12)

    if session == "api":
        r = api.get(url, timeout=timeout, **kw)
        r.raise_for_status()
        _raise_if_login_html(r, url)
        return r

    if session == "sess":
        r = sess.get(url, timeout=timeout, **kw)
        r.raise_for_status()
        return r

    if API_KEY:
        try:
            r = api.get(url, timeout=timeout, **kw)
            r.raise_for_status()
            _raise_if_login_html(r, url)
            return r
        except HTTPError as e:
            sc = getattr(getattr(e, "response", None), "status_code", None)
            if sc not in (401, 403):
                raise
        except RequestException:
            pass

    r = sess.get(url, timeout=timeout, **kw)
    r.raise_for_status()
    _raise_if_login_html(r, url)
    return r

def _post(url: str, session="auto", **kw):
    timeout = kw.pop("timeout", 20)

    if session == "api":
        r = api.post(url, timeout=timeout, **kw)
        r.raise_for_status()
        return r

    if session == "sess":
        h = kw.pop("headers", {})
        h = {**csrf_headers(), **h}
        r = sess.post(url, timeout=timeout, headers=h, **kw)
        r.raise_for_status()
        return r

    if API_KEY:
        try:
            r = api.post(url, timeout=timeout, **kw)
            r.raise_for_status()
            return r
        except HTTPError as e:
            sc = getattr(getattr(e, "response", None), "status_code", None)
            if sc not in (401, 403):
                raise
        except RequestException:
            pass

    h = kw.pop("headers", {})
    h = {**csrf_headers(), **h}
    r = sess.post(url, timeout=timeout, headers=h, **kw)
    r.raise_for_status()
    return r

def _put(url: str, session="auto", **kw):
    timeout = kw.pop("timeout", 20)

    if session == "api":
        r = api.put(url, timeout=timeout, **kw)
        r.raise_for_status()
        return r

    if session == "sess":
        h = kw.pop("headers", {})
        h = {**csrf_headers(), **h}
        r = sess.put(url, timeout=timeout, headers=h, **kw)
        r.raise_for_status()
        return r

    if API_KEY:
        try:
            r = api.put(url, timeout=timeout, **kw)
            r.raise_for_status()
            return r
        except HTTPError as e:
            sc = getattr(getattr(e, "response", None), "status_code", None)
            if sc not in (401, 403):
                raise
        except RequestException:
            pass

    h = kw.pop("headers", {})
    h = {**csrf_headers(), **h}
    r = sess.put(url, timeout=timeout, headers=h, **kw)
    r.raise_for_status()
    return r

def _backup_schedule() -> dict:
    try:
        r = _get(f"{PANEL}/api/backup/schedule", session="auto", timeout=15)
        return _json_txt(r) if r is not None else {}
    except Exception as e:
        logging.debug("Backup schedule fetch failed: %s", e)
        return {}


def _epoch_iso_z(iso: str | None) -> int:
    if not iso:
        return 0
    try:
        return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())
    except Exception:
        return 0

def _set_backup_schedule(payload: dict) -> dict:
    try:
        r = _post(f"{PANEL}/api/backup/schedule", session="auto", json=payload, timeout=12)
        return _json_txt(r)
    except Exception:
        return {"ok": False}

    
def kb_backup_schedule(s: dict) -> InlineKeyboardMarkup:
    enabled = bool(s.get("enabled"))
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("○ Disable schedule" if enabled else "● Enable schedule", callback_data="backup:schedule:toggle")],
        [InlineKeyboardButton("▣ Run and store now", callback_data="backup:schedule:run_now")],
        [InlineKeyboardButton("◇ Test in 2 minutes", callback_data="backup:schedule:test_2m")],
        [InlineKeyboardButton("↻ Refresh", callback_data="backup:schedule")],
        [InlineKeyboardButton("← Backup", callback_data="backup:menu")],
    ])


def _delete(url: str, session="auto", **kw):
    timeout = kw.pop("timeout", 12)

    if session == "api":
        r = api.delete(url, timeout=timeout, **kw)
        r.raise_for_status()
        return r

    if session == "sess":
        h = kw.pop("headers", {})
        h = {**csrf_headers(), **h}
        r = sess.delete(url, timeout=timeout, headers=h, **kw)
        r.raise_for_status()
        return r

    if API_KEY:
        try:
            r = api.delete(url, timeout=timeout, **kw)
            r.raise_for_status()
            return r
        except HTTPError as e:
            sc = getattr(getattr(e, "response", None), "status_code", None)
            if sc not in (401, 403):
                raise
        except RequestException:
            pass

    h = kw.pop("headers", {})
    h = {**csrf_headers(), **h}
    r = sess.delete(url, timeout=timeout, headers=h, **kw)
    r.raise_for_status()
    return r


def list_nodes() -> list[dict]:
    r = _get(f"{PANEL}/api/nodes", session="api")
    j = _json_txt(r)
    return j.get("nodes", []) if isinstance(j, dict) else []

def list_node_ifaces(nid: int) -> list[dict]:
    r = _get(f"{PANEL}/api/nodes/{nid}/interfaces", session="api")
    j = _json_txt(r)
    return j.get("interfaces", j if isinstance(j, list) else [])


def _json_txt(r):
    try:
        return r.json()
    except Exception:
        return {"text": r.text}
    
def _json(resp):
    ct = (resp.headers.get("content-type") or "").lower()
    return ct.startswith("application/json")

def peer_enable(pid: int):

    try:
        r = _post(f"{PANEL}/api/peer/{pid}/enable", session="api")
        return r.json() if _json(r) else {"ok": True}
    except HTTPError as e:
        sc = getattr(e.response, "status_code", None)
        if sc in (400, 409, 503):
            try:
                p = get_peer(pid) or {}
                iid = p.get("iface_id")
                if not iid:
                    for i in (peer_ifaces() or []):
                        if str(i.get("name")) == str(p.get("iface")):
                            iid = int(i["id"])
                            break
                if iid:
                    _post(f"{PANEL}/api/iface/{iid}/enable", session="api")
                    r2 = _post(f"{PANEL}/api/peer/{pid}/enable", session="api")
                    return r2.json() if _json(r2) else {"ok": True}
            except Exception:
                pass
        raise

def peer_disable(pid: int):
    r = _post(f"{PANEL}/api/peer/{pid}/disable", session="api")
    return r.json() if _json(r) else {"ok": True}

def peer_reset_usage(pid: int):

    r = _post_soft(f"{PANEL}/api/peer/{pid}/reset_usage")
    if r.status_code in (404, 405):
        r = _post_soft(f"{PANEL}/api/peer/{pid}/reset_data")

    if r.status_code in (401, 403):
        r = _post_soft(f"{PANEL}/api/peer/{pid}/reset_usage", session="sess")
        if r.status_code in (404, 405):
            r = _post_soft(f"{PANEL}/api/peer/{pid}/reset_data", session="sess")

    r.raise_for_status()
    return _json_txt(r)


def peer_reset_timer(pid: int):

    r = _post_soft(f"{PANEL}/api/peer/{pid}/reset_timer")
    if r.status_code in (401, 403):
        r = _post_soft(f"{PANEL}/api/peer/{pid}/reset_timer", session="sess")
    r.raise_for_status()
    return _json_txt(r)


def peer_stats():
    r = _get(f"{PANEL}/api/stats/mini", session="api")
    return _json_txt(r) or {}

def peer_ifaces() -> List[Dict[str, Any]]:
    j = _get(f"{PANEL}/api/get-interfaces").json()
    return j.get("interfaces", j)

def list_peers(iface_id: Optional[int] = None) -> List[Dict[str, Any]]:
    r = _get(f"{PANEL}/api/peers")
    r.raise_for_status()
    peers = r.json().get("peers", []) or []
    if iface_id is None:
        return peers
    id2name = _iface_id()
    iname = id2name.get(int(iface_id))
    if not iname:
        return peers
    return [p for p in peers if str(p.get("iface")) == iname]

def get_peer(pid: int):
    for p in list_peers():
        if int(p.get("id")) == int(pid):
            return p
    return None

def _iface_id() -> dict:
    return {int(i["id"]): str(i["name"]) for i in peer_ifaces()}

def map_iface_name() -> dict:
    m = {}
    for i in peer_ifaces():
        m[str(i["name"])] = int(i["id"])
    return m

def peer_by_id(pid: int) -> Optional[Dict[str, Any]]:
    for p in list_peers():
        if int(p.get("id")) == int(pid):
            return p
    return None

def update_peer(pid: int, payload: Dict[str, Any]) -> Dict[str, Any]:

    try:
        r = _put(f"{PANEL}/api/peer/{pid}", json=payload, session="api")
        try:
            return r.json()
        except Exception:
            return {"ok": r.ok, "status": r.status_code, "text": (r.text or "")[:500]}
    except HTTPError as e:
        body = ""
        try:
            body = (e.response.text or "")[:500]
        except Exception:
            body = str(e)
        raise HTTPError(f"{e} — {body}")

def delete_peer(pid: int) -> None:
    _delete(f"{PANEL}/api/peer/{pid}", session="api", timeout=30)

def _peer_public_token(short_url: str) -> str:
    match = re.search(r"/u/([^/?#]+)", str(short_url or ""))
    return match.group(1) if match else ""

def _peer_config(pid: int, short_url: str = "") -> str:
    attempts = [
        (f"{PANEL}/api/peer/{int(pid)}/config?download=1", "api"),
        (f"{PANEL}/api/peer/{int(pid)}/config", "api"),
    ]

    token = _peer_public_token(short_url)
    if token:
        attempts.append((f"{PANEL}/api/u/{token}/config", "api"))

    errors = []
    for url, session_name in attempts:
        try:
            r = _get(url, session=session_name, timeout=30)
            body = r.text or ""
            ctype = str(r.headers.get("content-type") or "").lower()

            if "application/json" in ctype:
                try:
                    payload = r.json()
                except Exception:
                    payload = {}
                detail = payload.get("message") or payload.get("detail") or payload.get("error")
                errors.append(f"{url}: {detail or 'JSON returned instead of config'}")
                continue

            if "text/html" in ctype or _looks_like_html_doc(body):
                errors.append(f"login/HTML response from {url}")
                continue

            if "[Interface]" in body and "PrivateKey" in body:
                return body.strip() + "\n"

            if body.strip():
                errors.append(f"invalid WireGuard config returned by {url}")
            else:
                errors.append(f"empty response from {url}")
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    raise RuntimeError("Peer configuration is unavailable: " + "; ".join(errors[-3:]))

def _peer_qr(pid: int, cfg_text: str = "") -> bytes:
    if cfg_text.strip():
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=7,
            border=4,
        )
        qr.add_data(cfg_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        out = io.BytesIO()
        img.save(out, format="PNG", optimize=False)
        out.seek(0)
        return out.read()

    r = _get(
        f"{PANEL}/api/peer/{pid}/config_qr",
        session="api",
        timeout=60,
    )
    ctype = str(r.headers.get("content-type") or "").lower()
    if "text/html" in ctype:
        raise RuntimeError("Panel returned HTML instead of the peer QR image.")
    return r.content


def bulk_create(iface_id: int, count: int, body: Dict[str, Any]) -> Dict[str, Any]:

    payload: Dict[str, Any] = {"iface_id": int(iface_id), "count": int(count)}
    payload.update(body or {})

    def _audit(action: str, details: str = "") -> None:
        try:
            log_admin("telegram", "bot", action, details)
        except Exception:
            pass
        try:
            if "log_tg" in globals():
                log_tg("telegram", "bot", action, details)
        except Exception:
            pass

    safe_keys = sorted(list(payload.keys()))
    _audit("bulk_create_request", f"iface_id={iface_id} count={count} keys={safe_keys}")

    try:
        r = _post(f"{PANEL}/api/peers/bulk", session="api", json=payload)
    except Exception as e:
        _audit("bulk_create_http_error", f"{type(e).__name__}: {e}")
        return {
            "ok": False,
            "error": "http_error",
            "detail": f"{type(e).__name__}: {e}",
        }

    text = getattr(r, "text", "") or ""
    preview = text[:400].replace("\n", "\\n")
    status = getattr(r, "status_code", None)
    ok = getattr(r, "ok", None)

    _audit("bulk_create_response", f"status={status} ok={ok} body_preview={preview}")

    try:
        j = r.json()

        if isinstance(j, dict):
            j.setdefault("_http_status", status)
            j.setdefault("_http_ok", bool(ok) if ok is not None else None)
            return j

        return {
            "_http_status": status,
            "_http_ok": bool(ok) if ok is not None else None,
            "data": j,
        }

    except Exception as e:
        _audit("bulk_create_json_error", f"{type(e).__name__}: {e}; body_preview={preview}")

        return {
            "ok": False,
            "error": "non_json_response",
            "status": status,
            "body_preview": preview,
        }

PROFILES_FILE = INSTANCE_DIR / "peer_profiles.json"
PANEL_DEFAULTS: Dict[str, Any] = {

    "allowed_ips": "0.0.0.0/0, ::/0",
    "endpoint": "",
    "persistent_keepalive": 25,  
    "data_limit_value": 0,
    "data_limit_unit": "Mi",     
    "start_on_first_use": False,  
    "time_limit_days": 0,
    "time_limit_hours": 0,
    "time_limit_minutes": 0,
    "unlimited": False,
    "include_internal_network": False,
    "note": "",
    "phone_number": "",
    "telegram_id": "",
    "dns": "",
    "mtu": "",
}

PROFILE_KEYS = set(PANEL_DEFAULTS.keys()) | {"name", "use_for"}

def _profiles_load() -> Dict[str, Any]:

    def _c_bool(v):
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in {"1", "true", "yes", "on"}

    def _normalize(v):
        u = str(v).strip().capitalize()
        return "Gi" if u.startswith("Gi") else "Mi"

    if PROFILES_FILE.exists():
        try:
            with PROFILES_FILE.open("r", encoding="utf-8") as f:
                j = json.load(f)
            if not isinstance(j, dict):
                raise ValueError("profiles json not a dict")
            j.setdefault("default", None)
            j.setdefault("profiles", {})
            profs = j["profiles"]

            changed = False
            for p in profs.values():
                if "name_prefix" in p:
                    if not p.get("name") and p.get("name_prefix"):
                        p["name"] = p.get("name_prefix", "")
                    p.pop("name_prefix", None)
                    changed = True

                if "keepalive" in p and "persistent_keepalive" not in p:
                    try:
                        p["persistent_keepalive"] = int(p.pop("keepalive"))
                    except Exception:
                        p.pop("keepalive", None)
                    changed = True
                else:
                    p.pop("keepalive", None)

                for bk in ("start_on_first_use", "unlimited"):
                    if bk in p:
                        b = _c_bool(p[bk])
                        if p[bk] != b:
                            p[bk] = b
                            changed = True

                if "data_limit_unit" in p:
                    unit = _normalize(p.get("data_limit_unit", "Mi"))
                    if p.get("data_limit_unit") != unit:
                        p["data_limit_unit"] = unit
                        changed = True

                scope = str(p.get("use_for", "both")).lower()
                if scope not in ("single", "bulk", "both"):
                    scope = "both"
                    changed = True
                p["use_for"] = scope

                # for k in list(p.keys()):
                #     if k not in PROFILE_KEYS:
                #         p.pop(k, None); changed = True

            if not j["default"] or j["default"] not in profs:
                if profs:
                    j["default"] = next(iter(profs.keys()))
                else:
                    base = {k: v for k, v in PANEL_DEFAULTS.items() if k in PROFILE_KEYS}
                    base["use_for"] = "both"
                    profs["default"] = base
                    j["default"] = "default"
                    changed = True

            if changed:
                _profiles_save(j)
            return j
        except Exception:
            pass

    seed_base = {k: v for k, v in PANEL_DEFAULTS.items() if k in PROFILE_KEYS}
    seed_base["use_for"] = "both"
    seed = {
        "default": "default",
        "profiles": {
            "default": seed_base
        }
    }
    _profiles_save(seed)
    return seed


def _profiles_save(data: Dict[str, Any]) -> None:
    data = {"default": data.get("default"), "profiles": data.get("profiles", {})}

    PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROFILES_FILE.with_suffix(".tmp")

    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass

    tmp.replace(PROFILES_FILE)

    try:
        os.chmod(PROFILES_FILE, 0o600)
    except Exception:
        pass


def default_profile(scope: str) -> Optional[str]:

    base = _profiles_load()
    profs = (base.get("profiles") or {})
    dname = base.get("default")

    def _ok(name: str) -> bool:
        p = profs.get(name) or {}
        use = str(p.get("use_for", "both")).lower()
        if scope in ("single", "bulk"):
            return use in ("peer", "single", "bulk", "both", "all")
        return use in (scope, "all")

    if dname and dname in profs and _ok(dname):
        return dname

    for name in profs.keys():
        if _ok(name):
            return name

    return None

def profiles_list() -> List[str]:
    return list(_profiles_load().get("profiles", {}).keys())

def profiles_list_for(scope: str) -> list[str]:
    base = _profiles_load()
    out = []
    for n, vals in (base.get("profiles") or {}).items():
        use = str((vals or {}).get("use_for", "both")).lower()
        if scope in ("single", "bulk"):
            ok = use in ("peer", "single", "bulk", "both", "all")
        else:
            ok = use in (scope, "all")
        if ok:
            out.append(n)
    return out

def profile_get(name: str) -> Dict[str, Any]:
    return _profiles_load().get("profiles", {}).get(name, {}).copy()


def profile_set(name: str, values: Dict[str, Any]) -> None:
    base = _profiles_load()

    prof = {k: v for k, v in (values or {}).items() if k in PROFILE_KEYS}

    scope = str(prof.get("use_for") or "peer").lower()
    if scope in ("single", "bulk", "both", "all"):
        scope = "peer"
    if scope not in ("peer", "subscription"):
        scope = "peer"
    prof["use_for"] = scope

    base.setdefault("profiles", {})[name] = prof
    _profiles_save(base)


def profile_delete(name: str) -> None:
    base = _profiles_load()
    base.get("profiles", {}).pop(name, None)
    if base.get("default") == name:
        base["default"] = None
    _profiles_save(base)


def profile_default() -> Optional[str]:
    return _profiles_load().get("default")


def profile_set_default(name: Optional[str]) -> None:
    base = _profiles_load()
    if name and name not in base.get("profiles", {}):
        raise KeyError("profile not found")
    base["default"] = name
    _profiles_save(base)

def profile_scope(scope: str) -> tuple[Optional[str], Dict[str, Any]]:

    name = default_profile(scope) 
    if name:
        return name, profile_get(name) or {}
    vals = {k: v for k, v in PANEL_DEFAULTS.items() if k in PROFILE_KEYS}
    return None, vals

BOOL_KEYS = {"start_on_first_use", "unlimited", "include_internal_network"}
UNIT_KEYS = {"data_limit_unit"}  

def menu_kb(flow: str, key: str, allow_skip: bool = True) -> InlineKeyboardMarkup:
    rows = []

    if key in ("start_on_first_use", "unlimited", "include_internal_network"):
        rows.append([
            InlineKeyboardButton("1 (Yes)", callback_data=f"wiz:{flow}:set:{key}:1"),
            InlineKeyboardButton("0 (No)",  callback_data=f"wiz:{flow}:set:{key}:0"),
        ])
    elif key == "data_limit_unit":
        rows.append([
            InlineKeyboardButton("Mi", callback_data=f"wiz:{flow}:set:{key}:Mi"),
            InlineKeyboardButton("Gi", callback_data=f"wiz:{flow}:set:{key}:Gi"),
        ])

    ctrl = []
    if allow_skip:
        ctrl.append(InlineKeyboardButton("⏭ Skip (use default)", callback_data=f"wiz:{flow}:skip"))
    ctrl.append(InlineKeyboardButton("⊘ Cancel", callback_data=f"wiz:{flow}:cancel"))
    rows.append(ctrl)

    rows.append([InlineKeyboardButton("← Back", callback_data="peers:menu")])
    return InlineKeyboardMarkup(rows)


_PROFILE_LABELS = [
    ("name",                 "Friendly name"),
    ("allowed_ips",          "Allowed IPs"),
    ("endpoint",             "Endpoint (host:port)"),
    ("persistent_keepalive", "Keepalive (s)"),
    ("mtu",                  "MTU"),
    ("dns",                  "DNS"),
    ("data_limit_value",     "Traffic limit value"),
    ("data_limit_unit",      "Unit (Mi/Gi)"),
    ("time_limit_days",      "Active days"),
    ("time_limit_hours",     "Active hours"),
    ("start_on_first_use",   "Start on first use"),
    ("unlimited",            "Unlimited"),
    ("phone_number",         "Phone numbers (bulk: comma-separated)"),
    ("telegram_id",          "Telegram IDs (bulk: comma-separated)"),
]

def kb_profile(pname: str):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("Friendly name",     callback_data=f"profiles:editkey:{pname}:name")],
        [InlineKeyboardButton("Allowed IPs",       callback_data=f"profiles:editkey:{pname}:allowed_ips"),
         InlineKeyboardButton("Endpoint",          callback_data=f"profiles:editkey:{pname}:endpoint")],
        [InlineKeyboardButton("Keepalive (s)",     callback_data=f"profiles:editkey:{pname}:persistent_keepalive"),
         InlineKeyboardButton("MTU",               callback_data=f"profiles:editkey:{pname}:mtu")],
        [InlineKeyboardButton("DNS",               callback_data=f"profiles:editkey:{pname}:dns")],

        [InlineKeyboardButton("Traffic limit",     callback_data=f"profiles:editkey:{pname}:data_limit_value"),
         InlineKeyboardButton("Unit (Mi/Gi)",      callback_data=f"profiles:unit:{pname}")],

        [InlineKeyboardButton("Active days",       callback_data=f"profiles:editkey:{pname}:time_limit_days"),
         InlineKeyboardButton("Active hours",      callback_data=f"profiles:editkey:{pname}:time_limit_hours")],

        [InlineKeyboardButton("Toggle: Start on first use", callback_data=f"profiles:toggle:{pname}:start_on_first_use")],
        [InlineKeyboardButton("Toggle: Unlimited",          callback_data=f"profiles:toggle:{pname}:unlimited")],

        [InlineKeyboardButton("← Back", callback_data=f"profiles:open:{pname}")],
    ])


def _api_data(method: str, path: str, *, payload: dict | None = None, timeout: int = 15) -> dict:
    try:
        url = f"{PANEL}{path}"
        if method.upper() == "GET":
            response = _get(url, session="api" if API_KEY else "auto", timeout=timeout)
        elif method.upper() == "POST":
            response = _post(url, session="api" if API_KEY else "auto", json=payload or {}, timeout=timeout)
        elif method.upper() == "PUT":
            response = _put(url, session="api" if API_KEY else "auto", json=payload or {}, timeout=timeout)
        elif method.upper() == "DELETE":
            response = _delete(url, session="api" if API_KEY else "auto", json=payload or {}, timeout=timeout)
        else:
            raise ValueError(f"Unsupported method: {method}")
        data = _json_txt(response)
        return data if isinstance(data, dict) else {"ok": bool(response.ok), "result": data}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)}

GITHUB_REPO = "Azumi67/WG_Panel"
GITHUB_MAIN_ARCHIVE = (
    "https://codeload.github.com/"
    f"{GITHUB_REPO}/tar.gz/refs/heads/main"
)


def _normalize_version(value: Any) -> str:
    text = str(value or "").strip().lstrip("vV")

    if re.fullmatch(
        r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?",
        text,
    ):
        return text

    return ""


def _version_tuple(value: Any) -> tuple:
    text = _normalize_version(value)
    numbers = [
        int(piece)
        for piece in re.findall(r"\d+", text)[:4]
    ]

    while len(numbers) < 4:
        numbers.append(0)

    return tuple(numbers)


def _github_source_info(*, fresh: bool = False) -> dict:
    cache = getattr(
        _github_source_info,
        "_cache",
        {
            "value": {},
            "ts": 0.0,
        },
    )

    now = time.time()

    if (
        not fresh
        and cache["value"]
        and now - cache["ts"] < 180
    ):
        return dict(cache["value"])

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "WG-Panel-Telegram-Bot",
    }

    errors = []

    raw_version_urls = (
        (
            "https://raw.githubusercontent.com/"
            f"{GITHUB_REPO}/main/VERSION"
        ),
        (
            "https://raw.githubusercontent.com/"
            f"{GITHUB_REPO}/refs/heads/main/VERSION"
        ),
    )

    for url in raw_version_urls:
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=12,
            )

            if response.status_code == 200:
                version = _normalize_version(response.text)

                if version:
                    result = {
                        "ok": True,
                        "latest": version,
                        "target": "main",
                        "source": "remote VERSION",
                        "main_available": True,
                    }

                    _github_source_info._cache = {
                        "value": result,
                        "ts": now,
                    }
                    return dict(result)

            errors.append(
                f"remote VERSION HTTP {response.status_code}"
            )

        except Exception as exc:
            errors.append(
                f"remote VERSION: {type(exc).__name__}: {exc}"
            )

    try:
        response = requests.get(
            (
                "https://api.github.com/repos/"
                f"{GITHUB_REPO}/releases/latest"
            ),
            headers=headers,
            timeout=12,
        )

        if response.status_code == 200:
            payload = response.json() or {}
            version = _normalize_version(
                payload.get("tag_name")
            )

            if version:
                result = {
                    "ok": True,
                    "latest": version,
                    "target": version,
                    "source": "GitHub release",
                    "main_available": True,
                }

                _github_source_info._cache = {
                    "value": result,
                    "ts": now,
                }
                return dict(result)

        errors.append(
            f"release API HTTP {response.status_code}"
        )

    except Exception as exc:
        errors.append(
            f"release API: {type(exc).__name__}: {exc}"
        )

    try:
        response = requests.get(
            (
                "https://api.github.com/repos/"
                f"{GITHUB_REPO}/tags?per_page=30"
            ),
            headers=headers,
            timeout=12,
        )

        if response.status_code == 200:
            payload = response.json() or []
            versions = []

            for item in payload:
                if not isinstance(item, dict):
                    continue

                raw_name = str(
                    item.get("name")
                    or ""
                ).strip()

                normalized = _normalize_version(raw_name)

                if normalized:
                    versions.append(
                        (
                            _version_tuple(normalized),
                            normalized,
                            raw_name,
                        )
                    )

            if versions:
                versions.sort(reverse=True)
                _, version, raw_target = versions[0]

                result = {
                    "ok": True,
                    "latest": version,
                    "target": raw_target,
                    "source": "GitHub tag",
                    "main_available": True,
                }

                _github_source_info._cache = {
                    "value": result,
                    "ts": now,
                }
                return dict(result)

        errors.append(
            f"tags API HTTP {response.status_code}"
        )

    except Exception as exc:
        errors.append(
            f"tags API: {type(exc).__name__}: {exc}"
        )

    try:
        response = requests.get(
            GITHUB_MAIN_ARCHIVE,
            headers=headers,
            timeout=20,
            stream=True,
            allow_redirects=True,
        )

        main_ok = (
            response.status_code == 200
            and "gzip" in (
                response.headers.get(
                    "content-type",
                    "",
                ).lower()
            )
        )

        response.close()

        if main_ok:
            result = {
                "ok": True,
                "latest": "",
                "target": "main",
                "source": "main branch",
                "main_available": True,
                "detail": (
                    "The repository main branch is reachable, "
                    "but no remote VERSION, release, or semantic tag exists."
                ),
            }

            _github_source_info._cache = {
                "value": result,
                "ts": now,
            }
            return dict(result)

        errors.append(
            f"main archive HTTP {response.status_code}"
        )

    except Exception as exc:
        errors.append(
            f"main archive: {type(exc).__name__}: {exc}"
        )

    result = {
        "ok": False,
        "latest": "",
        "target": "",
        "source": "unavailable",
        "main_available": False,
        "detail": " | ".join(errors[-4:]),
    }

    _github_source_info._cache = {
        "value": result,
        "ts": now,
    }
    return dict(result)

def panel_version_info(*, fresh: bool = False) -> dict:
    panel_data = _api_data(
        "GET",
        "/api/panel/version"
        + ("?fresh=1" if fresh else ""),
        timeout=15,
    )

    if not isinstance(panel_data, dict):
        panel_data = {}

    current = (
        _normalize_version(panel_data.get("current"))
        or PROJECT_VERSION
    )

    latest = _normalize_version(
        panel_data.get("latest")
    )

    source = str(
        panel_data.get("source")
        or ""
    ).strip()

    target = str(
        panel_data.get("target")
        or latest
        or ""
    ).strip()

    remote = {}

    if not latest:
        remote = _github_source_info(
            fresh=fresh,
        )

        latest = _normalize_version(
            remote.get("latest")
        )

        source = str(
            remote.get("source")
            or source
            or ""
        ).strip()

        target = str(
            remote.get("target")
            or target
            or ""
        ).strip()

    result = dict(panel_data)
    result["current"] = current
    result["latest"] = latest
    result["source"] = source
    result["target"] = target
    result["main_available"] = bool(
        panel_data.get("main_available")
        or remote.get("main_available")
    )

    if latest:
        result["update_available"] = (
            _version_tuple(latest)
            > _version_tuple(current)
        )
        result["ok"] = True

    elif result["main_available"]:
        result["ok"] = True
        result["update_available"] = False
        result["detail"] = str(
            remote.get("detail")
            or panel_data.get("detail")
            or (
                "The main branch is reachable, but the repository "
                "does not publish a remote VERSION, release, or tag."
            )
        )

    else:
        result["ok"] = False
        result["detail"] = str(
            remote.get("detail")
            or panel_data.get("detail")
            or panel_data.get("error")
            or "The repository could not be reached."
        )

    return result
def panel_update_status() -> dict: return _api_data("GET", "/api/panel/update/status", timeout=10)
def panel_update_targets() -> dict: return _api_data("GET", "/api/panel/update/targets", timeout=20)
def start_panel_update(target: str = "main") -> dict: return _api_data("POST", "/api/panel/update", payload={"target": "main"}, timeout=20)
def start_node_update(node_id: int, target: str = "main") -> dict: return _api_data("POST", f"/api/nodes/{int(node_id)}/update", payload={"target": "main"}, timeout=20)
def node_update_status(node_id: int) -> dict: return _api_data("GET", f"/api/nodes/{int(node_id)}/update/status", timeout=12)

def _update_state(status: dict) -> str:
    return str(
        (status or {}).get("status")
        or "idle"
    ).strip().lower()


def _update_stage(status: dict) -> str:
    return str(
        (status or {}).get("stage")
        or _update_state(status)
        or "idle"
    ).strip().lower()


def _update_busy(status: dict) -> bool:
    return _update_state(status) in {
        "queued",
        "running",
        "backup",
        "downloading",
        "download",
        "extract",
        "install",
        "installing",
        "dependencies",
        "validate",
        "validating",
        "restart",
        "restarting",
        "rollback",
        "rolling_back",
    }


def _update_terminal(status: dict) -> bool:
    return _update_state(status) in {
        "completed",
        "complete",
        "done",
        "success",
        "rollback_completed",
        "failed",
        "error",
        "rollback_failed",
        "cancelled",
        "canceled",
    }


def _update_percent(status: dict) -> int:
    try:
        return max(
            0,
            min(
                100,
                int(
                    (status or {}).get("percent")
                    or 0
                ),
            ),
        )
    except Exception:
        return 0


def _update_status_icon(status: dict) -> str:
    state = _update_state(status)
    stage = _update_stage(status)

    if state in {
        "completed",
        "complete",
        "done",
        "success",
    }:
        return "●"

    if state == "rollback_completed":
        return "○"

    if state in {
        "failed",
        "error",
        "rollback_failed",
        "cancelled",
        "canceled",
        "offline",
    }:
        return "⊘"

    if state in {
        "restart",
        "restarting",
    } or stage in {
        "restart",
        "restarting",
    }:
        return "◐"

    if state in {
        "rollback",
        "rolling_back",
    } or stage in {
        "rollback",
        "rolling_back",
    }:
        return "○"

    if state in {
        "install",
        "installing",
        "dependencies",
    } or stage in {
        "install",
        "installing",
        "dependencies",
    }:
        return "◆"

    if state in {
        "validate",
        "validating",
    } or stage in {
        "validate",
        "validating",
    }:
        return "◐"

    if state in {
        "queued",
    }:
        return "○"

    if _update_busy(status):
        return "◉"

    return "○"


def _update_stage_label(status: dict) -> str:
    state = _update_state(status)
    stage = _update_stage(status)

    labels = {
        "idle": "Ready",
        "queued": "Queued",
        "running": "Working",
        "backup": "Creating rollback backup",
        "download": "Downloading main",
        "downloading": "Downloading main",
        "extract": "Preparing files",
        "install": "Installing",
        "installing": "Installing",
        "dependencies": "Installing dependencies",
        "validate": "Validating",
        "validating": "Validating",
        "restart": "Restarting",
        "restarting": "Restarting",
        "rollback": "Rolling back",
        "rolling_back": "Rolling back",
        "completed": "Completed",
        "complete": "Completed",
        "done": "Completed",
        "success": "Completed",
        "rollback_completed": "Previous version restored",
        "rollback_failed": "Rollback failed",
        "failed": "Failed",
        "error": "Failed",
        "cancelled": "Cancelled",
        "canceled": "Cancelled",
        "offline": "Offline",
    }

    return labels.get(
        stage,
        labels.get(
            state,
            stage.replace("_", " ").title(),
        ),
    )


def _update_status_line(status: dict) -> str:
    return (
        f"{_update_status_icon(status)} "
        f"<b>{html(_update_stage_label(status))}</b> · "
        f"<code>{_update_percent(status)}%</code>"
    )


def _update_progress_bar(percent: int) -> str:
    percent = max(0, min(100, int(percent or 0)))
    filled = min(10, percent // 10)
    return (
        "▓" * filled
        + "░" * (10 - filled)
    )


def _update_live_text(
    status: dict,
    *,
    target_name: str,
    node_name: str | None = None,
    temporarily_unreachable: bool = False,
) -> str:
    state = _update_state(status)
    percent = _update_percent(status)
    label = _update_stage_label(status)
    icon = _update_status_icon(status)

    title = (
        f"⌘ <b>Updating node · {html(node_name or target_name)}</b>"
        if node_name
        else "↑ <b>Updating WG Panel</b>"
    )

    message = str(
        (status or {}).get("message")
        or ""
    ).strip()

    revision = str(
        (status or {}).get("revision_short")
        or (status or {}).get("revision")
        or ""
    ).strip()[:8]

    lines = [
        title,
        "",
        (
            f"{icon} <b>{html(label)}</b> · "
            f"<code>{percent}%</code>"
        ),
        (
            f"<code>{_update_progress_bar(percent)}</code>"
        ),
    ]

    if temporarily_unreachable:
        lines.extend([
            "",
            (
                "↻ The panel is restarting or temporarily "
                "unreachable. Telegram is still monitoring it."
            ),
        ])

    elif message:
        lines.extend([
            "",
            f"✦ {html(message)}",
        ])

    if revision:
        lines.append(
            f"✦ Main revision: <code>{html(revision)}</code>"
        )

    if state in {
        "completed",
        "complete",
        "done",
        "success",
    }:
        lines.extend([
            "",
            "● <b>Update completed successfully.</b>",
        ])

    elif state == "rollback_completed":
        lines.extend([
            "",
            (
                "⊘ <b>The update failed, but the previous "
                "version was restored successfully.</b>"
            ),
        ])

    elif state in {
        "failed",
        "error",
    }:
        lines.extend([
            "",
            "⊘ <b>Update failed.</b>",
        ])

    elif not _update_terminal(status):
        lines.extend([
            "",
            (
                "◷ <i>The update is running. This message "
                "refreshes automatically.</i>"
            ),
        ])

    return "\n".join(lines)


def _update_live_keyboard(
    *,
    node_id: int | None = None,
    terminal: bool = False,
) -> InlineKeyboardMarkup:
    callback = (
        f"system:node:{int(node_id)}"
        if node_id is not None
        else "home:system"
    )

    label = (
        "← Node update"
        if node_id is not None
        else "← Update Center"
    )

    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "↻ Refresh status",
                callback_data=callback,
            )
        ],
        [
            InlineKeyboardButton(
                label,
                callback_data=callback,
            )
        ],
    ])


async def _safe_edit_update_message(
    bot,
    chat_id: int,
    message_id: int,
    text_out: str,
    keyboard,
) -> bool:
    try:
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text_out,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        return True

    except BadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return True
        logging.debug(
            "Could not edit Telegram update message: %s",
            exc,
        )
        return False

    except Exception as exc:
        logging.debug(
            "Could not edit Telegram update message: %s",
            exc,
        )
        return False


async def _monitor_update_message(
    application,
    *,
    chat_id: int,
    message_id: int,
    target_name: str = "main",
    node_id: int | None = None,
    node_name: str | None = None,
):
    """
    Keep one Telegram message synchronized with updater status.

    The panel may be temporarily unreachable while its service restarts.
    That is treated as progress, not as immediate failure.
    """
    last_render = ""
    unreachable_polls = 0
    started_at = time.monotonic()
    maximum_seconds = 15 * 60

    while (
        time.monotonic() - started_at
        < maximum_seconds
    ):
        try:
            if node_id is None:
                status = await asyncio.to_thread(
                    panel_update_status,
                )
            else:
                status = await asyncio.to_thread(
                    node_update_status,
                    int(node_id),
                )

            route_failed = bool(
                not isinstance(status, dict)
                or status.get("ok") is False
                or (
                    status.get("error")
                    and not status.get("status")
                )
            )

            if route_failed:
                unreachable_polls += 1

                temporary = {
                    "status": "restarting",
                    "stage": "restarting",
                    "percent": 97,
                    "message": (
                        "Waiting for the updated service "
                        "to become available…"
                    ),
                }

                rendered = _update_live_text(
                    temporary,
                    target_name=target_name,
                    node_name=node_name,
                    temporarily_unreachable=True,
                )

                if rendered != last_render:
                    await _safe_edit_update_message(
                        application.bot,
                        chat_id,
                        message_id,
                        rendered,
                        _update_live_keyboard(
                            node_id=node_id,
                            terminal=False,
                        ),
                    )
                    last_render = rendered

                if unreachable_polls >= 60:
                    final = {
                        "status": "error",
                        "stage": "offline",
                        "percent": 97,
                        "message": (
                            "The updater status endpoint did not "
                            "return after the service restart."
                        ),
                    }

                    await _safe_edit_update_message(
                        application.bot,
                        chat_id,
                        message_id,
                        _update_live_text(
                            final,
                            target_name=target_name,
                            node_name=node_name,
                        ),
                        _update_live_keyboard(
                            node_id=node_id,
                            terminal=True,
                        ),
                    )
                    return

            else:
                unreachable_polls = 0

                rendered = _update_live_text(
                    status,
                    target_name=target_name,
                    node_name=node_name,
                )

                if rendered != last_render:
                    await _safe_edit_update_message(
                        application.bot,
                        chat_id,
                        message_id,
                        rendered,
                        _update_live_keyboard(
                            node_id=node_id,
                            terminal=_update_terminal(status),
                        ),
                    )
                    last_render = rendered

                if _update_terminal(status):
                    return

                if (
                    _update_state(status) == "idle"
                    and time.monotonic() - started_at > 20
                ):
                    return

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            logging.debug(
                "Telegram update monitor poll failed: %s",
                exc,
            )

        await asyncio.sleep(3)

    timeout_status = {
        "status": "error",
        "stage": "timeout",
        "percent": 0,
        "message": (
            "Telegram stopped monitoring after 15 minutes. "
            "Open Update Center to check the final status."
        ),
    }

    await _safe_edit_update_message(
        application.bot,
        chat_id,
        message_id,
        _update_live_text(
            timeout_status,
            target_name=target_name,
            node_name=node_name,
        ),
        _update_live_keyboard(
            node_id=node_id,
            terminal=True,
        ),
    )


def _start_update_monitor(
    context,
    update: Update,
    *,
    target_name: str = "main",
    node_id: int | None = None,
    node_name: str | None = None,
):
    message = (
        update.callback_query.message
        if update.callback_query
        else update.effective_message
    )

    if not message:
        return

    task = context.application.create_task(
        _monitor_update_message(
            context.application,
            chat_id=int(message.chat_id),
            message_id=int(message.message_id),
            target_name=target_name,
            node_id=node_id,
            node_name=node_name,
        ),
        name=(
            f"wg-update-node-{node_id}"
            if node_id is not None
            else "wg-update-panel"
        ),
    )

    monitors = context.application.bot_data.setdefault(
        "update_monitors",
        set(),
    )
    monitors.add(task)
    task.add_done_callback(
        lambda completed: monitors.discard(completed)
    )

def render_node_updates():
    targets = panel_update_targets()
    nodes = (targets.get("nodes") if isinstance(targets, dict) else []) or []
    rows = []
    online = sum(1 for n in nodes if n.get("online"))
    pending = sum(1 for n in nodes if n.get("online") and (n.get("version") or {}).get("update_available"))
    lines = [
        "⌘ <b>Node updates</b>",
        "<i>Inspect and update remote agents</i>",
        "",
        f"● Online      <code>{online}/{len(nodes)}</code>",
        f"↥ Pending     <code>{pending}</code>",
    ]
    if not nodes:
        lines.extend(["", "No nodes are configured."])
    else:
        lines.extend(["", "<b>Nodes</b>"])
    for node in nodes:
        nid=int(node.get("id") or 0)
        name=str(node.get("name") or f"Node {nid}")
        online_state=bool(node.get("online"))
        v=node.get("version") or {}
        cur=str(v.get("current") or "—")
        avail=bool(v.get("update_available"))
        icon="↥" if online_state and avail else ("●" if online_state else "○")
        state="update available" if online_state and avail else ("online" if online_state else "offline")
        lines.append(f"{icon} <b>{html(name)}</b> · <code>v{html(cur)}</code> · {state}")
        rows.append([InlineKeyboardButton(f"{icon} {name}", callback_data=f"system:node:{nid}")])
    rows.append([InlineKeyboardButton("↻ Refresh",callback_data="system:nodes"),InlineKeyboardButton("← Update center",callback_data="home:system")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def render_node_update(node_id:int):
    targets=panel_update_targets()
    nodes=(targets.get("nodes") if isinstance(targets,dict) else []) or []
    node=next((n for n in nodes if int(n.get("id") or 0)==int(node_id)),None)
    if not node:
        return "Node not found.", KB.back("system:nodes")
    name=str(node.get("name") or f"Node {node_id}")
    online=bool(node.get("online"))
    v=node.get("version") or {}
    cur=str(v.get("current") or "—")
    latest=str(v.get("latest") or "—")
    avail=bool(v.get("update_available"))
    status=node.get("update") or node_update_status(node_id) or {}
    lines=[
        f"⌘ <b>{html(name)}</b>",
        "<i>Remote node update status</i>",
        "",
        f"{'●' if online else '○'} Connectivity   {'Online' if online else 'Offline'}",
        f"◇ Installed      <code>v{html(cur)}</code>",
        f"↥ Available      <code>v{html(latest)}</code>",
        f"◷ Updater        {_update_status_line(status)}",
    ]
    msg=str(status.get("message") or "").strip()
    if msg:
        lines += ["",f"✦ {html(msg[:320])}"]
    rows=[[InlineKeyboardButton("↻ Refresh",callback_data=f"system:node:{node_id}")]]
    if online and avail and not _update_busy(status):
        rows.append([InlineKeyboardButton(f"↥ Update {name}",callback_data=f"system:nodeupdate:confirm:{node_id}")])
    rows.append([InlineKeyboardButton("← Nodes",callback_data="system:nodes")])
    return "\n".join(lines),InlineKeyboardMarkup(rows)


def _human_bytes(value: Any) -> str:
    try:
        amount = max(0, int(value or 0))
    except Exception:
        amount = 0

    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(amount)
    unit = units[0]

    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024.0

    return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"


def list_subscriptions() -> list[dict]:
    data = _api_data("GET", "/api/subscriptions", timeout=20)
    rows = data.get("subscriptions") if isinstance(data, dict) else []
    return rows if isinstance(rows, list) else []


def get_subscription(subscription_id: int) -> dict:
    data = _api_data(
        "GET",
        f"/api/subscriptions/{int(subscription_id)}",
        timeout=15,
    )
    row = data.get("subscription") if isinstance(data, dict) else None
    return row if isinstance(row, dict) else {}


def subscription_action(subscription_id: int, action: str) -> dict:
    allowed = {"enable", "disable", "reset_data", "reset_timer"}
    if action not in allowed:
        return {"ok": False, "error": "unsupported_action"}
    return _api_data(
        "POST",
        f"/api/subscriptions/{int(subscription_id)}/{action}",
        timeout=45,
    )


def subscription_links(subscription_id: int) -> dict:
    return _api_data(
        "GET",
        f"/api/subscriptions/{int(subscription_id)}/shortlink",
        timeout=12,
    )


def render_subscriptions(page: int = 1):
    subscriptions = list_subscriptions()
    per_page = 7
    pages = max(1, math.ceil(len(subscriptions) / per_page))
    page = max(1, min(int(page or 1), pages))
    start_index = (page - 1) * per_page
    visible = subscriptions[start_index:start_index + per_page]

    enabled = sum(1 for row in subscriptions if row.get("enabled"))
    blocked = sum(
        1 for row in subscriptions
        if (
            str(row.get("status") or "").lower() == "blocked"
            or int((row.get("runtime_counts") or {}).get("blocked") or 0) > 0
        )
    )

    lines = [
        "⌁ <b>Subscriptions</b>",
        "",
        f"◇ <b>Total</b>: <code>{len(subscriptions)}</code>",
        f"● <b>Enabled</b>: <code>{enabled}</code>",
        f"⊘ <b>Blocked</b>: <code>{blocked}</code>",
    ]

    rows = []
    if not visible:
        lines.extend(["", "No subscriptions have been created."])
    else:
        lines.extend(["", f"Page <code>{page}/{pages}</code>"])

    for row in visible:
        sid = int(row.get("id") or 0)
        name = str(row.get("name") or f"Subscription {sid}")
        counts = row.get("runtime_counts") or {}
        is_blocked = int(counts.get("blocked") or 0) > 0
        icon = "⊘" if is_blocked else ("●" if row.get("enabled") else "○")
        rows.append([
            InlineKeyboardButton(
                f"{icon} {name}",
                callback_data=f"subs:open:{sid}",
            )
        ])

    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("‹ Prev", callback_data=f"subs:list:{page-1}"))
    if page < pages:
        nav.append(InlineKeyboardButton("Next ›", callback_data=f"subs:list:{page+1}"))
    if nav:
        rows.append(nav)

    rows.extend([
        [InlineKeyboardButton("↻ Refresh", callback_data=f"subs:list:{page}")],
        [InlineKeyboardButton("← Home", callback_data="home:main")],
    ])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def _subscription_time(row: dict) -> str:
    if row.get("unlimited"):
        return "Unlimited"
    ttl = row.get("ttl_seconds")
    if ttl is not None:
        return human_ttl(ttl)
    expires = row.get("expires_at")
    return str(expires or "Not started")


def render_subscription(subscription_id: int):
    row = get_subscription(subscription_id)
    if not row:
        return "Subscription not found.", KB.back("subs:list:1")

    sid = int(row.get("id") or subscription_id)
    name = str(row.get("name") or f"Subscription {sid}")
    enabled = bool(row.get("enabled"))
    counts = row.get("runtime_counts") or {}
    locations = row.get("locations") or row.get("inbounds") or []
    used = int(row.get("used_bytes") or 0)
    remaining = row.get("remaining_bytes")
    limit = row.get("limit_bytes")

    state = "⊘ Blocked" if int(counts.get("blocked") or 0) else ("● Enabled" if enabled else "○ Disabled")
    data_line = (
        f"{_human_bytes(used)} used · Unlimited"
        if row.get("unlimited") or limit is None
        else f"{_human_bytes(used)} used · {_human_bytes(remaining)} left"
    )

    lines = [
        f"⌁ <b>{html(name)}</b>",
        f"◇ <code>{sid}</code> · {state}",
        "",
        f"▦ <b>Data</b>: {html(data_line)}",
        f"◷ <b>Time</b>: {html(_subscription_time(row))}",
        f"◎ <b>Configs</b>: <code>{int(counts.get('total') or len(locations))}</code>",
        f"● Active: <code>{int(counts.get('enabled') or 0)}</code>  ○ Off: <code>{int(counts.get('disabled') or 0)}</code>  ⊘ Blocked: <code>{int(counts.get('blocked') or 0)}</code>",
    ]

    phone = str(row.get("phone_number") or "").strip()
    tg_id = str(row.get("telegram_id") or "").strip()
    if phone or tg_id:
        lines.extend([
            "",
            f"☎ {html(phone or '—')}  ·  Telegram {html(tg_id or '—')}",
        ])

    rows = []
    if enabled:
        rows.append([InlineKeyboardButton("○ Disable", callback_data=f"subs:disable:confirm:{sid}")])
    else:
        rows.append([InlineKeyboardButton("▷ Enable + reset", callback_data=f"subs:enable:confirm:{sid}")])

    rows.append([
        InlineKeyboardButton("↺ Reset data", callback_data=f"subs:reset_data:confirm:{sid}"),
        InlineKeyboardButton("◷ Reset timer", callback_data=f"subs:reset_timer:confirm:{sid}"),
    ])

    links = subscription_links(sid)
    public_url = str(links.get("url") or "").strip()
    config_url = str(links.get("config_url") or "").strip()
    link_row = []
    if public_url.startswith(("http://", "https://")):
        link_row.append(InlineKeyboardButton("⌁ Client portal", url=public_url))
    if config_url.startswith(("http://", "https://")):
        link_row.append(InlineKeyboardButton("↓ Config", url=config_url))
    if link_row:
        rows.append(link_row)

    rows.extend([
        [InlineKeyboardButton("↻ Refresh", callback_data=f"subs:open:{sid}")],
        [InlineKeyboardButton("← Subscriptions", callback_data="subs:list:1")],
    ])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def render_clients():
    text = "\n".join([
        "▣ <b>WireGuard Clients</b>",
        "",
        "Install the official WireGuard application, then open a subscription portal or import a <code>.conf</code> file.",
        "",
        "For customer-specific QR codes and configs, open <b>Subscriptions</b> and select the customer.",
    ])
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("◇ Windows", url="https://www.wireguard.com/install/"), InlineKeyboardButton("◇ macOS", url="https://apps.apple.com/app/wireguard/id1451685025")],
        [InlineKeyboardButton("◇ Android", url="https://play.google.com/store/apps/details?id=com.wireguard.android"), InlineKeyboardButton("▣ iPhone/iPad", url="https://apps.apple.com/app/wireguard/id1441195209")],
        [InlineKeyboardButton("◇ Linux", url="https://www.wireguard.com/install/")],
        [InlineKeyboardButton("⌁ Subscriptions", callback_data="subs:list:1")],
        [InlineKeyboardButton("← Home", callback_data="home:main")],
    ])
    return text, keyboard


def telegram_settings_data() -> dict:
    return _api_data("GET", "/api/telegram/settings", timeout=12)


def save_telegram_notifications(notify: dict, enabled: bool = True) -> dict:
    return _api_data(
        "POST",
        "/api/telegram/settings",
        payload={"enabled": bool(enabled), "notify": notify},
        timeout=15,
    )


def subscription_portal_settings() -> dict:
    return _api_data("GET", "/api/subscriptions/settings", timeout=12)


def render_bot_settings():
    tg = telegram_settings_data()
    notify = tg.get("notify") or {}
    portal = subscription_portal_settings()

    notification_groups = (
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
                ("login_success", "Successful admin login"),
                ("login_fail", "Failed login / 2FA"),
                ("suspicious_4xx", "Suspicious 4xx activity"),
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
        for _group, items in notification_groups
        for key, _label in items
    ]
    enabled_count = sum(
        1
        for key in all_keys
        if bool(notify.get(key))
    )

    def mark(key: str) -> str:
        return "●" if bool(notify.get(key)) else "○"

    lines = [
        "⚙ <b>Bot settings</b>",
        "<i>Telegram integration and notification policy</i>",
        "",
        "<b>Integration</b>",
        (
            f"{'●' if tg.get('enabled') else '○'} "
            f"Service       "
            f"{'Enabled' if tg.get('enabled') else 'Disabled'}"
        ),
        (
            f"{'●' if tg.get('has_token') else '○'} "
            f"Bot token     "
            f"{'Configured' if tg.get('has_token') else 'Missing'}"
        ),
        f"◇ Rules         <code>{enabled_count}/{len(all_keys)}</code> enabled",
    ]

    for group_name, items in notification_groups:
        lines.extend([
            "",
            f"<b>{html(group_name)}</b>",
        ])
        for key, label in items:
            lines.append(
                f"{mark(key)} {html(label)}"
            )

    lines.extend([
        "",
        "<b>Subscription portal</b>",
        f"◇ Layout       <code>{html(portal.get('layout') or 'aurora')}</code>",
        f"◇ Statistics   <code>{html(portal.get('display_mode') or 'hybrid')}</code>",
        f"◇ Motion       <code>{html(portal.get('animation') or 'rich')}</code>",
        "",
        "<i>TLS, certificates, ports, and runtime workers remain web-only.</i>",
    ])

    rows = [
        [
            InlineKeyboardButton(
                f"{mark('app_down')} Panel down",
                callback_data="settings:notify:app_down",
            ),
            InlineKeyboardButton(
                f"{mark('app_up')} Panel up",
                callback_data="settings:notify:app_up",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('node_down')} Node down",
                callback_data="settings:notify:node_down",
            ),
            InlineKeyboardButton(
                f"{mark('node_up')} Node up",
                callback_data="settings:notify:node_up",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('iface_down')} Interface down",
                callback_data="settings:notify:iface_down",
            ),
            InlineKeyboardButton(
                f"{mark('iface_up')} Interface up",
                callback_data="settings:notify:iface_up",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('peer_expired')} Peer expired",
                callback_data="settings:notify:peer_expired",
            ),
            InlineKeyboardButton(
                f"{mark('peer_limit')} Peer limit",
                callback_data="settings:notify:peer_limit",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('login_success')} Login success",
                callback_data="settings:notify:login_success",
            ),
            InlineKeyboardButton(
                f"{mark('login_fail')} Login rejected",
                callback_data="settings:notify:login_fail",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('suspicious_4xx')} Suspicious 4xx",
                callback_data="settings:notify:suspicious_4xx",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('backup_success')} Backup success",
                callback_data="settings:notify:backup_success",
            ),
            InlineKeyboardButton(
                f"{mark('backup_failed')} Backup failed",
                callback_data="settings:notify:backup_failed",
            ),
        ],
        [
            InlineKeyboardButton(
                f"{mark('update_success')} Update success",
                callback_data="settings:notify:update_success",
            ),
            InlineKeyboardButton(
                f"{mark('update_failed')} Update failed",
                callback_data="settings:notify:update_failed",
            ),
        ],
        [
            InlineKeyboardButton(
                "◆ Critical only",
                callback_data="settings:notify:preset:critical",
            ),
            InlineKeyboardButton(
                "● Select all",
                callback_data="settings:notify:preset:all",
            ),
        ],
        [
            InlineKeyboardButton(
                "○ Clear all",
                callback_data="settings:notify:preset:none",
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
    ]

    return "\n".join(lines), InlineKeyboardMarkup(rows)


def render_update_center(*, fresh: bool = False):
    version = panel_version_info(fresh=fresh)
    status = panel_update_status()
    targets = panel_update_targets()

    current = str(version.get("current") or PROJECT_VERSION or "unknown")
    latest = str(version.get("latest") or "")
    source = str(version.get("source") or "main").strip()
    target = str(version.get("target") or "").strip()
    main_available = bool(version.get("main_available"))
    available = bool(latest and version.get("update_available"))

    state = str(status.get("status") or "idle").lower()
    if status.get("ok") is False:
        updater = "⊘ Unavailable"
    elif state == "idle":
        updater = "● Ready"
    elif _update_busy(status):
        updater = f"◷ {_update_status_line(status)}"
    else:
        updater = f"◇ {_update_status_line(status)}"

    nodes = (targets.get("nodes") if isinstance(targets, dict) else []) or []
    online = [n for n in nodes if n.get("online")]
    node_updates = [n for n in online if (n.get("version") or {}).get("update_available")]

    if latest:
        release = "↥ Update available" if available else "● Current"
        remote = f"v{html(latest)}"
    elif main_available:
        release = "◇ Main branch available"
        remote = "main"
    else:
        release = "⊘ Check unavailable"
        remote = "not detected"

    lines = [
        "↥ <b>Update center</b>",
        "<i>Panel and node release management</i>",
        "",
        "<b>Panel release</b>",
        f"◇ Installed   <code>v{html(current)}</code>",
        f"↥ Available   <code>{remote}</code>",
        f"⌁ Source      <code>{html(source or 'main')}</code>",
        f"◆ State       {release}",
        "",
        "<b>Updater</b>",
        f"◷ Local       {updater}",
        f"⌘ Nodes       <code>{len(online)}/{len(nodes)}</code> online",
        f"↥ Pending     <code>{len(node_updates)}</code> node update(s)",
    ]

    message = str(status.get("message") or "").strip()
    if message and message.lower() not in {"no update is running.", "no node update is running."}:
        lines.extend(["", f"✦ {html(message[:360])}"])

    rows = [
        [InlineKeyboardButton("↻ Check releases", callback_data="system:refresh"), InlineKeyboardButton("⌘ Manage nodes", callback_data="system:nodes")],
        [InlineKeyboardButton("◇ Repository", url="https://github.com/Azumi67/WG_Panel"), InlineKeyboardButton("✦ Releases", url="https://github.com/Azumi67/WG_Panel/releases")],
    ]
    if not _update_busy(status):
        if available:
            rows.append([InlineKeyboardButton(f"↥ Install v{latest}", callback_data=f"system:update:confirm:{target or latest}")])
        elif main_available and not latest:
            rows.append([InlineKeyboardButton("↥ Update from main", callback_data="system:update:confirm:main")])
    rows.append([InlineKeyboardButton("← Dashboard", callback_data="home:main")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


class KB:
    @staticmethod
    def home():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("◇ Peers", callback_data="peers:menu"), InlineKeyboardButton("⌘ Subscriptions", callback_data="client:list:1")],
            [InlineKeyboardButton("✦ Profiles", callback_data="profiles:menu"), InlineKeyboardButton("▣ Backups", callback_data="backup:menu")],
            [InlineKeyboardButton("↥ Update center", callback_data="home:system"), InlineKeyboardButton("⚙ Settings", callback_data="home:settings")],
            [InlineKeyboardButton("♙ Administrators", callback_data="home:admins"), InlineKeyboardButton("↻ Refresh", callback_data="home:refresh")],
        ])


    @staticmethod
    def back(to: str, label: str = "← Back"):
        return InlineKeyboardMarkup([[InlineKeyboardButton(label, callback_data=to)]])
    
    @staticmethod
    def wizard(flow: str = "pnew", allow_skip: bool = False) -> InlineKeyboardMarkup:

        rows = []
        if allow_skip:
            rows.append([InlineKeyboardButton("⏭ Skip", callback_data=f"wiz:{flow}:skip")])
        rows.append([
            InlineKeyboardButton("⊘ Cancel", callback_data=f"wiz:{flow}:cancel"),
            InlineKeyboardButton("← Back",  callback_data="profiles:menu"),
        ])
        return InlineKeyboardMarkup(rows)

    @staticmethod
    def peers_index():
        return InlineKeyboardMarkup([
           [InlineKeyboardButton("＋ Create peer", callback_data="peers:create"),
            InlineKeyboardButton("▦ Bulk create", callback_data="peers:bulk")],
           [InlineKeyboardButton("⌕ Find / peer status", callback_data="peers:status")],
           [InlineKeyboardButton("⌂ Main menu", callback_data="home:main")]
        ])


    @staticmethod
    def profiles_menu():
        names = profiles_list()
        rows = []
        if not names:
            rows.append([InlineKeyboardButton("＋ New profile", callback_data="profiles:new")])
            rows.append([InlineKeyboardButton("↺ Restore default profile", callback_data="profiles:restore")])
        else:
            d = profile_default()
            for n in names:
                star = "☆ " if d == n else ""
                rows.append([InlineKeyboardButton(f"{star}{n}", callback_data=f"profiles:open:{n}")])
            rows.append([InlineKeyboardButton("＋ New profile", callback_data="profiles:new")])
        rows.append([InlineKeyboardButton("← Back to Home", callback_data="home:main")])
        return InlineKeyboardMarkup(rows)

    @staticmethod
    def pages(prefix: str, page: int, pages: int, back_cb: str, extra_rows=None):

        try:
            page = max(1, int(page))
            pages = max(1, int(pages))
        except Exception:
            page, pages = 1, 1
        page = min(page, pages)

        rows = []
        if extra_rows:
            rows.extend(extra_rows)

        left = []
        if page > 1:
            left.append(InlineKeyboardButton("« 1", callback_data=f"{prefix}:1"))
            left.append(InlineKeyboardButton("‹ Prev", callback_data=f"{prefix}:{page-1}"))
        else:
            left.append(InlineKeyboardButton("« 1", callback_data="noop"))
            left.append(InlineKeyboardButton("‹ Prev", callback_data="noop"))

        mid = [InlineKeyboardButton(f"• {page} •", callback_data="noop")]

        right = []
        if page < pages:
            right.append(InlineKeyboardButton("Next ›", callback_data=f"{prefix}:{page+1}"))
            right.append(InlineKeyboardButton(f"» {pages}", callback_data=f"{prefix}:{pages}"))
        else:
            right.append(InlineKeyboardButton("Next ›", callback_data="noop"))
            right.append(InlineKeyboardButton(f"» {pages}", callback_data="noop"))

        rows.append(left + mid + right)
        rows.append([InlineKeyboardButton("← Back", callback_data=back_cb)])
        return InlineKeyboardMarkup(rows)


def kb_backup_menu(prefs: dict | None = None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("◇ Database", callback_data="backup:run:db"), InlineKeyboardButton("✦ Settings", callback_data="backup:run:settings")],
        [InlineKeyboardButton("▣ Full backup", callback_data="backup:run:full"), InlineKeyboardButton("↺ Restore", callback_data="backup:restore")],
        [InlineKeyboardButton("◷ Schedule", callback_data="backup:schedule"), InlineKeyboardButton("⚙ Preferences", callback_data="backup:prefs")],
        [InlineKeyboardButton("← Dashboard", callback_data="home:main")],
    ])


def kb_backup_prefs(prefs: dict) -> InlineKeyboardMarkup:
    inc = "● ON" if prefs.get("include_wg") else "○ OFF"
    tg  = "● ON" if prefs.get("send_to_telegram") else "○ OFF"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"⌘ Include WireGuard configs · {inc}", callback_data="backup:prefs:toggle:wg")],
        [InlineKeyboardButton(f"↗ Send copy to Telegram · {tg}", callback_data="backup:prefs:toggle:tg")],
        [InlineKeyboardButton("← Backup", callback_data="backup:menu")],
    ])

async def _send_zipfile(
    update,
    content: bytes,
    filename: str,
    *,
    kind: str = "backup",
):
    bio = io.BytesIO(content)
    bio.seek(0)

    caption = "\n".join([
        "▣ <b>WG Panel backup</b>",
        "",
        f"◇ Type      <code>{html(kind.title())}</code>",
        f"◇ File      <code>{html(filename)}</code>",
        f"◇ Size      <code>{html(_human_bytes(len(content)))}</code>",
        (
            "◇ Created   <code>"
            + html(
                datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
            )
            + "</code>"
        ),
        "",
        "⌁ <i>Keep this archive private. It may contain keys, tokens, and panel settings.</i>",
    ])

    await update.effective_chat.send_document(
        document=InputFile(
            bio,
            filename=filename,
        ),
        caption=caption,
        parse_mode=ParseMode.HTML,
        disable_content_type_detection=True,
    )


BACKUP_STATE_FILE = str(INSTANCE_DIR / "tg_backup_state.json")
AUTO_BACKUP_DIR   = (INSTANCE_DIR / "backups")

def _load_backup_state() -> dict:
    try:
        with open(BACKUP_STATE_FILE, "r") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _save_backup_state(st: dict) -> None:
    try:
        os.makedirs(os.path.dirname(BACKUP_STATE_FILE), exist_ok=True)
        with open(BACKUP_STATE_FILE, "w") as f:
            json.dump(st, f)
    except Exception:
        pass

def _auto_backupname(kind: str = "full", ts: datetime | None = None) -> str:
    ts = ts or datetime.utcnow()
    stamp = ts.strftime("%Y%m%d_%H%M%S")
    return f"auto_{kind}_{stamp}.zip"

def _p_autobackups(kind: str, keep: int) -> None:
    if keep is None:
        return
    try:
        keep = int(keep)
    except Exception:
        keep = 7
    if keep <= 0:
        return

    try:
        AUTO_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(AUTO_BACKUP_DIR.glob(f"auto_{kind}_*.zip"), key=lambda p: p.stat().st_mtime)
        extra = len(files) - keep
        if extra > 0:
            for p in files[:extra]:
                try:
                    p.unlink()
                except Exception:
                    pass
    except Exception:
        pass

def _store_backuppanel(url: str, dest_path: Path, session: str = "api", timeout: int = 900) -> tuple[bool, str]:
    import tempfile

    AUTO_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".tmp_auto_", suffix=".zip", dir=str(AUTO_BACKUP_DIR))
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    r = None
    try:
        r = _get(url, session=session, timeout=timeout, stream=True, allow_redirects=True)

        with open(tmp_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=256 * 1024):
                if chunk:
                    f.write(chunk)

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(str(tmp_path), str(dest_path))
        return True, str(dest_path)

    except Exception as e:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        return False, str(e)

    finally:
        try:
            if r is not None:
                r.close()
        except Exception:
            pass



def _last_backup() -> int | None:

    try:
        r = _get(f"{PANEL}/api/backup/last", session="api")
        j = _json_txt(r)
        ts = j.get("last_backup_ts") or j.get("ts") or j.get("last")
        if isinstance(ts, (int, float)) and ts > 0:
            return int(ts)
    except Exception:
        pass

    try:
        j = _get(f"{PANEL}/api/backup/prefs", session="api").json()
        ts = j.get("last_backup_ts")
        if isinstance(ts, (int, float)) and ts > 0:
            return int(ts)
    except Exception:
        pass

    return None

def _fmt_when(ts: int | None) -> str:
    if not ts:
        return "Never"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))


def _backup_filename(kind: str, when_ts: int | None = None) -> str:
    safe = {"db":"db", "settings":"settings", "full":"full"}.get(kind, "backup")
    ts = int(when_ts or time.time())
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(ts))
    return f"{safe}-backup-{stamp}.zip"


def _headers_filename(r):
    cd = r.headers.get("content-disposition", "")
    m = re.search(r'filename="?([^";]+)"?', cd, re.I)
    return m.group(1) if m else "backup.zip"

# ____ State constants
STATE = {
    "CREATE": "wizard:create",
    "BULK":   "wizard:bulk",
    "EDIT":   "wizard:edit",
    "SEARCH": "wizard:search",
    "P_NEW":  "wizard:profile_new",
    "P_EDIT": "wizard:profile_edit",
}
STATE["EDIT_ONE"] = "wizard:edit_one"
STATE["P_EDIT_ONE"] = "wizard:profile_edit_one"
STATE["BACKUP_RESTORE_WAIT"] = "backup_restore_wait"

BASIC_CREATE_FIELDS = [
    ("name", "Friendly name", ""),
    ("data_limit_value", "Data limit value (0 = no cap)", str(PANEL_DEFAULTS["data_limit_value"])),
    ("data_limit_unit", "Data limit unit", PANEL_DEFAULTS["data_limit_unit"]),
    ("time_limit_days", "Active days (0 = no timer)", str(PANEL_DEFAULTS["time_limit_days"])),
    ("unlimited", "Unlimited mode", str(PANEL_DEFAULTS["unlimited"])),
]

ADVANCED_CREATE_FIELDS = [
    ("name", "Friendly name", ""),
    ("allowed_ips", "Allowed IPs", PANEL_DEFAULTS["allowed_ips"]),
    ("endpoint", "Endpoint override (leave automatic when empty)", PANEL_DEFAULTS["endpoint"]),
    ("keepalive", "Persistent keepalive (seconds)", str(PANEL_DEFAULTS["persistent_keepalive"])),
    ("data_limit_value", "Data limit value (0 = no cap)", str(PANEL_DEFAULTS["data_limit_value"])),
    ("data_limit_unit", "Data limit unit", PANEL_DEFAULTS["data_limit_unit"]),
    ("start_on_first_use", "Start timer on first usage", str(PANEL_DEFAULTS["start_on_first_use"])),
    ("time_limit_days", "Active days (0 = no timer)", str(PANEL_DEFAULTS["time_limit_days"])),
    ("time_limit_hours", "Additional active hours", str(PANEL_DEFAULTS["time_limit_hours"])),
    ("unlimited", "Unlimited mode", str(PANEL_DEFAULTS["unlimited"])),
    ("phone_number", "Phone number (optional)", PANEL_DEFAULTS["phone_number"]),
    ("telegram_id", "Telegram ID/username (optional)", PANEL_DEFAULTS["telegram_id"]),
    ("dns", "DNS servers", PANEL_DEFAULTS["dns"]),
    ("mtu", "MTU", PANEL_DEFAULTS["mtu"]),
]

CREATE_FIELDS = ADVANCED_CREATE_FIELDS

BULK_FIELDS = [
    ("count", "How many peers to create?", "5"),
    *CREATE_FIELDS
]

EDIT_FIELDS = [
    ("name", "New name (enter to skip)", None),
    ("endpoint", "Endpoint host:port (enter to skip)", None),
    ("dns", "DNS (comma-separated, enter to skip)", None),
    ("mtu", "MTU (enter to skip)", None),
    ("phone_number", "Phone number (enter to skip)", None),
    ("telegram_id", "Telegram ID/username (enter to skip)", None),
    ("data_limit_value", "Data limit value (enter to skip)", None),
    ("data_limit_unit", "Data limit unit Mi/Gi (enter to skip)", None),
    ("start_on_first_use", "Start timer on first usage? 1/0 (enter to skip)", None),
    ("unlimited", "Unlimited mode? 1/0 (enter to skip)", None),
    ("time_limit_days", "Time limit days (enter to skip)", None),
    ("time_limit_hours", "Time limit hours (enter to skip)", None),
]

# ____ /start
@admin_only
async def start(update, context):
    await send_text(update, render_home(update), kb=KB.home())

# ____ callback 
@admin_only
async def on_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data

    def _admin_ident():
        uid = str(update.effective_user.id) if update.effective_user else ""
        uname = (update.effective_user.username or "") if update.effective_user else ""
        return uid, uname

    def _log_admin(action: str, details: str):
        try:
            uid, uname = _admin_ident()
            log_admin(uid, uname, action, details)
            log_tg(uid, uname, action, details)
        except Exception:
            pass

    if await admin_azumi.handle_callback(globals(), update, context):
        return

    if data.startswith("subs:list:"):
        try:
            page = int(data.rsplit(":", 1)[-1])
        except Exception:
            page = 1
        text_out, keyboard = await asyncio.to_thread(render_subscriptions, page)
        await edit_send(update, text_out, keyboard)
        return

    if data.startswith("subs:open:"):
        sid = int(data.rsplit(":", 1)[-1])
        text_out, keyboard = await asyncio.to_thread(render_subscription, sid)
        await edit_send(update, text_out, keyboard)
        return

    for action, title, warning in (
        ("enable", "Enable subscription", "Enabling resets both data usage and the timer."),
        ("disable", "Disable subscription", "Disabling preserves the current timer and data usage."),
        ("reset_data", "Reset subscription data", "This clears shared usage counters and may reactivate data-blocked configs."),
        ("reset_timer", "Reset subscription timer", "This restarts the subscription timer and may reactivate time-blocked configs."),
    ):
        prefix = f"subs:{action}:confirm:"
        if data.startswith(prefix):
            sid = int(data.rsplit(":", 1)[-1])
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("● Confirm", callback_data=f"subs:{action}:run:{sid}")],
                [InlineKeyboardButton("← Cancel", callback_data=f"subs:open:{sid}")],
            ])
            await edit_send(update, f"⊘ <b>{title}?</b>\n\n{warning}", kb)
            return

        run_prefix = f"subs:{action}:run:"
        if data.startswith(run_prefix):
            sid = int(data.rsplit(":", 1)[-1])
            result = await asyncio.to_thread(subscription_action, sid, action)
            if not result.get("ok") and not result.get("partial"):
                await edit_send(
                    update,
                    "⊘ <b>Subscription action failed</b>\n\n"
                    f"<code>{html(result.get('detail') or result.get('error') or result)}</code>",
                    KB.back(f"subs:open:{sid}"),
                )
                return
            _log_admin(f"subscription_{action}", f"sid={sid}")
            text_out, keyboard = await asyncio.to_thread(render_subscription, sid)
            message = str(result.get("message") or "Action completed.")
            await edit_send(update, f"● {html(message)}\n\n{text_out}", keyboard)
            return

    # Client applications
    if data == "home:clients":
        text_out, keyboard = render_clients()
        await edit_send(update, text_out, keyboard)
        return

    # settings
    if data == "home:settings":
        text_out, keyboard = await asyncio.to_thread(render_bot_settings)
        await edit_send(update, text_out, keyboard)
        return

    if data.startswith("settings:notify:preset:"):
        preset = data.rsplit(":", 1)[-1]
        current = await asyncio.to_thread(telegram_settings_data)
        notify = dict(current.get("notify") or {})

        all_keys = {
            "app_down", "app_up", "node_down", "node_up",
            "iface_down", "iface_up", "peer_expired", "peer_limit",
            "login_success", "login_fail", "suspicious_4xx",
            "backup_success", "backup_failed",
            "update_success", "update_failed",
        }
        critical_keys = {
            "app_down", "node_down", "iface_down",
            "login_fail", "suspicious_4xx",
            "backup_failed", "update_failed",
        }

        if preset == "all":
            for key in all_keys:
                notify[key] = True
        elif preset == "critical":
            for key in all_keys:
                notify[key] = key in critical_keys
        elif preset == "none":
            for key in all_keys:
                notify[key] = False
        else:
            await q.answer("Unsupported preset.", show_alert=True)
            return

        result = await asyncio.to_thread(
            save_telegram_notifications,
            notify,
            bool(current.get("enabled", True)),
        )
        if not result.get("ok"):
            await q.answer(
                str(result.get("detail") or result.get("error") or "Save failed"),
                show_alert=True,
            )
            return

        _log_admin("telegram_notification_preset", f"preset={preset}")
        text_out, keyboard = await asyncio.to_thread(render_bot_settings)
        await edit_send(update, text_out, keyboard)
        return

    if data.startswith("settings:notify:"):
        key = data.rsplit(":", 1)[-1]
        allowed = {
            "app_down", "app_up", "node_down", "node_up",
            "iface_down", "iface_up", "peer_expired", "peer_limit",
            "login_success", "login_fail", "suspicious_4xx",
            "backup_success", "backup_failed",
            "update_success", "update_failed",
        }
        if key not in allowed:
            await q.answer("Unsupported setting.", show_alert=True)
            return

        current = await asyncio.to_thread(telegram_settings_data)
        notify = dict(current.get("notify") or {})
        notify[key] = not bool(notify.get(key))

        result = await asyncio.to_thread(
            save_telegram_notifications,
            notify,
            bool(current.get("enabled", True)),
        )
        if not result.get("ok"):
            await q.answer(
                str(result.get("detail") or result.get("error") or "Save failed"),
                show_alert=True,
            )
            return

        _log_admin(
            "telegram_notification_toggle",
            f"key={key}; enabled={int(bool(notify[key]))}",
        )
        text_out, keyboard = await asyncio.to_thread(render_bot_settings)
        await edit_send(update, text_out, keyboard)
        return

    # Update Center
    if data in {"home:system", "system:refresh"}:
        text, keyboard = await asyncio.to_thread(render_update_center, fresh=(data == "system:refresh")); await edit_send(update, text, keyboard); return
    if data.startswith("system:update:confirm:"):
        target = data.split(
            ":",
            3,
        )[-1].strip() or "main"

        label = (
            "● Install main branch"
            if target == "main"
            else f"● Install {target}"
        )

        kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    label,
                    callback_data=(
                        "system:update:start:"
                        f"{target}"
                    ),
                )
            ],
            [
                InlineKeyboardButton(
                    "← Cancel",
                    callback_data="home:system",
                )
            ],
        ])

        await edit_send(
            update,
            (
                "⊘ <b>Update local panel?</b>\n\n"
                "A rollback backup is created before files are replaced. "
                "The selected GitHub source is downloaded, Python is "
                "validated, and the detected panel service is restarted."
            ),
            kb,
        )
        return

    if data.startswith("system:update:start:"):
        target = "main"

        await edit_send(
            update,
            (
                "↑ <b>Updating WG Panel</b>\n\n"
                "○ <b>Starting updater…</b> · <code>2%</code>\n"
                "<code>░░░░░░░░░░</code>\n\n"
                "◷ <i>The request was accepted. Telegram will "
                "show live progress here.</i>"
            ),
            _update_live_keyboard(
                terminal=False,
            ),
        )

        result = await asyncio.to_thread(
            start_panel_update,
            target,
        )

        if not result.get("ok"):
            await edit_send(
                update,
                (
                    "⊘ <b>Could not start panel update</b>\n\n"
                    f"<code>{html(result.get('detail') or result.get('error') or result)}</code>"
                ),
                KB.back("home:system"),
            )
            return

        _log_admin(
            "panel_update_start",
            "target=main",
        )

        queued_status = (
            result.get("status")
            if isinstance(
                result.get("status"),
                dict,
            )
            else {
                "status": "queued",
                "stage": "queued",
                "percent": 2,
                "message": (
                    "Updater accepted the request and "
                    "is preparing the rollback backup."
                ),
            }
        )

        await edit_send(
            update,
            _update_live_text(
                queued_status,
                target_name="main",
            ),
            _update_live_keyboard(
                terminal=False,
            ),
        )

        _start_update_monitor(
            context,
            update,
            target_name="main",
        )
        return
    if data == "system:nodes":
        text,keyboard=await asyncio.to_thread(render_node_updates); await edit_send(update,text,keyboard); return
    if data.startswith("system:node:"):
        try: node_id=int(data.rsplit(":",1)[-1])
        except Exception: await q.answer("Invalid node.",show_alert=True); return
        text,keyboard=await asyncio.to_thread(render_node_update,node_id); await edit_send(update,text,keyboard); return
    if data.startswith("system:nodeupdate:confirm:"):
        try: node_id=int(data.rsplit(":",1)[-1])
        except Exception: await q.answer("Invalid node.",show_alert=True); return
        kb=InlineKeyboardMarkup([[InlineKeyboardButton("● Start node update",callback_data=f"system:nodeupdate:start:{node_id}")],[InlineKeyboardButton("← Cancel",callback_data=f"system:node:{node_id}")]])
        await edit_send(update,"⊘ <b>Update this node?</b>\n\nThe node creates a rollback backup, validates node_agent.py, and restarts its automatically detected service.",kb); return
    if data.startswith("system:nodeupdate:start:"):
        try:
            node_id = int(
                data.rsplit(":", 1)[-1]
            )
        except Exception:
            await q.answer(
                "Invalid node.",
                show_alert=True,
            )
            return

        targets = await asyncio.to_thread(
            panel_update_targets,
        )

        node_row = next(
            (
                row
                for row in (
                    targets.get("nodes")
                    if isinstance(targets, dict)
                    else []
                ) or []
                if int(row.get("id") or 0) == node_id
            ),
            {},
        )

        node_name = str(
            node_row.get("name")
            or f"Node {node_id}"
        )

        await edit_send(
            update,
            (
                f"⌘ <b>Updating node · {html(node_name)}</b>\n\n"
                "○ <b>Starting updater…</b> · <code>2%</code>\n"
                "<code>░░░░░░░░░░</code>\n\n"
                "◷ <i>The request was accepted. Telegram will "
                "show live progress here.</i>"
            ),
            _update_live_keyboard(
                node_id=node_id,
                terminal=False,
            ),
        )

        result = await asyncio.to_thread(
            start_node_update,
            node_id,
            "main",
        )

        if not result.get("ok"):
            await edit_send(
                update,
                (
                    "⊘ <b>Could not start node update</b>\n\n"
                    f"<code>{html(result.get('detail') or result.get('error') or result)}</code>"
                ),
                KB.back(
                    f"system:node:{node_id}"
                ),
            )
            return

        _log_admin(
            "node_update_start",
            f"node_id={node_id}; target=main",
        )

        queued_status = (
            result.get("status")
            if isinstance(
                result.get("status"),
                dict,
            )
            else {
                "status": "queued",
                "stage": "queued",
                "percent": 2,
                "message": (
                    "Node updater accepted the request and "
                    "is preparing the rollback backup."
                ),
            }
        )

        await edit_send(
            update,
            _update_live_text(
                queued_status,
                target_name="main",
                node_name=node_name,
            ),
            _update_live_keyboard(
                node_id=node_id,
                terminal=False,
            ),
        )

        _start_update_monitor(
            context,
            update,
            target_name="main",
            node_id=node_id,
            node_name=node_name,
        )
        return


    #  __Profiles
    if data == "profiles:menu":
        await edit_send(
            update,
            "✦ <b>Profiles</b>\nSave reusable peer or subscription defaults. Peer profiles work for both single and bulk peer creation.",
            KB.profiles_menu()
        ); return

    if data == "profiles:restore":
        seed_base = {k: v for k, v in PANEL_DEFAULTS.items() if k in PROFILE_KEYS}
        seed_base["use_for"] = "single"
        _profiles_save({"default_single": "default", "profiles": {"default": seed_base}})
        _log_admin("profiles_restore", "restored default profile")
        await edit_send(update, "↺ Restored the default profile.", KB.profiles_menu()); return

    if data == "profiles:new":
        context.user_data[STATE["P_NEW"]] = {"name": None, "stage": "await_name"}
        await edit_send(
           update,
           "＋ <b>New profile</b>\nSend a name for this profile (e.g. <code>work</code>, <code>family</code>).",
           KB.wizard(flow="pnew", allow_skip=False)
        ); return
    
    if data.startswith("profiles:new:type:"):
        profile_type = data.rsplit(":", 1)[-1]
        if profile_type not in ("peer", "subscription"):
            profile_type = "peer"

        st = context.user_data.get(STATE["P_NEW"]) or {}
        pname = st.get("name")
        if not pname:
            await update.callback_query.answer("Missing name.", show_alert=True)
            return

        base = _profiles_load()
        base.setdefault("profiles", {})
        base["profiles"][pname] = {
            "use_for": profile_type,
            "name": "",
            "allowed_ips": "0.0.0.0/0, ::/0",
            "endpoint": "",
            "persistent_keepalive": 25,
            "mtu": 1280,
            "dns": "1.1.1.1, 1.0.0.1",
            "data_limit_value": 0,
            "data_limit_unit": "Gi",
            "time_limit_days": 0,
            "time_limit_hours": 0,
            "start_on_first_use": True,
            "unlimited": False,
            "phone_number": "",
            "telegram_id": "",
        }
        _profiles_save(base)

        context.user_data.pop(STATE["P_NEW"], None)
        await edit_send(update, profile_summary(pname), kb_profile_editor(pname))
        return

    if data == "wiz:pnew:cancel":
       context.user_data.pop(STATE.get("P_NEW"), None) 
       await edit_send(update, "⊘ Cancelled.", KB.back("profiles:menu"))
       return


    if data.startswith("profiles:open:") or data.startswith("profiles:edit:"):
        pname = data.split(":", 2)[-1]
        p = profile_get(pname)
        if not p:
            await edit_send(update, "Profile not found.", KB.profiles_menu()); return
        await edit_send(update, profile_summary(pname), kb_profile_editor(pname)); return

    if data.startswith("profiles:del:"):
        name = data.split(":", 2)[-1]
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("● Yes, delete", callback_data=f"profiles:delconfirm:{name}")],
            [InlineKeyboardButton("← Back", callback_data=f"profiles:open:{name}")]
        ])
        await edit_send(update, f"⌫ Delete profile <b>{html(name)}</b>?", kb); return


    if data.startswith("profiles:delconfirm:"):
        name = data.split(":", 2)[-1]
        profile_delete(name)
        _log_admin("profile_delete", f"name={name}")
        await edit_send(update, "⌫ Deleted.", KB.profiles_menu()); return

    if data.startswith("profiles:setdef:"):
        name = data.split(":", 2)[-1]
        try:
            profile_set_default(name)
            _log_admin("profile_set_default", f"name={name}")
            await edit_send(update, f"☆ Default profile set to <b>{html(name)}</b>.", KB.profiles_menu()); return
        except KeyError:
            await edit_send(update, "Profile not found.", KB.profiles_menu()); return

    if data.startswith("profiles:scope:"):
        pname = data.split(":", 2)[-1]
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("◇ Peer profile", callback_data=f"profiles:settype:{pname}:peer")],
            [InlineKeyboardButton("⌘ Subscription profile", callback_data=f"profiles:settype:{pname}:subscription")],
            [InlineKeyboardButton("← Back", callback_data=f"profiles:open:{pname}")],
        ])
        await edit_send(update, f"Choose the type for <b>{html(pname)}</b>:", kb); return

    if data.startswith("profiles:settype:"):
        _, _, pname, profile_type = data.split(":", 3)
        if profile_type not in ("peer", "subscription"):
            profile_type = "peer"
        p = profile_get(pname) or {}
        p["use_for"] = profile_type
        profile_set(pname, p)
        _log_admin("profile_set_type", f"name={pname}; type={profile_type}")
        await edit_send(update, profile_summary(pname), kb_profile_editor(pname)); return

    if data.startswith("profiles:editkey:"):
        _, _, pname, key = data.split(":", 3)
        valid_keys = {k for k in PROFILE_KEYS}
        if key not in valid_keys:
            await edit_send(update, "Unsupported field.", kb_profile_editor(pname)); return
        context.user_data[STATE["P_EDIT_ONE"]] = {"pname": pname, "key": key}

        p = profile_get(pname) or {}
        scope = str(p.get("use_for", "both")).lower()

        note = ""
        if key == "endpoint":
            note = "\n\nFormat: <code>host:port</code>  e.g. <code>203.0.113.4:51820</code> or <code>vpn.example.com:51820</code>"
        elif key == "allowed_ips":
            note = "\n\nExamples: <code>0.0.0.0/0, ::/0</code>  or  <code>10.0.0.0/24</code>"
        elif key == "phone_number":
            note = ("\n\nBulk tip: comma or newline in order (e.g. <code>0912..., 0935..., 0901...</code>)."
                    if scope in ("bulk", "both") else "\n\nSingle: one phone number (optional).")
        elif key == "telegram_id":
            note = ("\n\nBulk tip: comma/newline; leading <code>@</code> optional (e.g. <code>@alice, bob</code>)."
                    if scope in ("bulk", "both") else "\n\nSingle: one Telegram username/ID (optional).")

        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⊘ Cancel", callback_data=f"profiles:editcancel:{pname}")],
            [InlineKeyboardButton("← Back",  callback_data=f"profiles:open:{pname}")]
        ])
        await edit_send(update, f"◇ <b>{html(pname)}</b> → <b>{html(key)}</b>{note}\n\nSend the new value.", kb)
        return

    if data.startswith("profiles:editcancel:"):
        pname = data.split(":", 2)[-1]
        context.user_data.pop(STATE["P_EDIT_ONE"], None)
        await edit_send(update, profile_summary(pname), kb_profile_editor(pname)); return

    if data.startswith("profiles:unit:"):
        pname = data.split(":", 2)[-1]
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("MiB", callback_data=f"profiles:setunit:{pname}:Mi"),
             InlineKeyboardButton("GiB", callback_data=f"profiles:setunit:{pname}:Gi")],
            [InlineKeyboardButton("← Back", callback_data=f"profiles:open:{pname}")],
            [InlineKeyboardButton("⌂ Home", callback_data="home:main")]

        ])
        await edit_send(update, f"Select unit for <b>{html(pname)}</b>:", kb); return

    if data.startswith("profiles:setunit:"):
        _, _, pname, unit = data.split(":", 3)
        p = profile_get(pname) or {}
        p["data_limit_unit"] = "Gi" if unit == "Gi" else "Mi"
        profile_set(pname, {k: v for k, v in p.items() if k in PROFILE_KEYS})
        _log_admin("profile_set_unit", f"name={pname}; unit={unit}")
        await edit_send(update, f"● Unit set to <b>{unit}</b>.", kb_profile_editor(pname)); return

    if data.startswith("profiles:toggle:"):
        _, _, pname, key = data.split(":", 3)
        if key not in ("start_on_first_use", "unlimited", "include_internal_network"):
            await edit_send(update, "Unsupported toggle.", kb_profile_editor(pname)); return
        p = profile_get(pname) or {}
        p[key] = not bool(p.get(key, False))
        profile_set(pname, {k: v for k, v in p.items() if k in PROFILE_KEYS})
        _log_admin("profile_toggle", f"name={pname}; key={key}; value={p[key]}")
        state = "ON" if p[key] else "OFF"
        await edit_send(update, f"● <b>{key}</b> is now <b>{state}</b>.", kb_profile_editor(pname)); return

    # ___ Peers index
    if data == "peers:menu":
        await edit_send(update, "◇ <b>Peers</b>", KB.peers_index()); return

    # ___ (Local / Node)
    if data == "peers:create":
        for state_key in (
            STATE.get("CREATE"),
            STATE.get("BULK"),
            "STATUS_SEARCH",
            "status_search_term",
        ):
            if state_key:
                context.user_data.pop(state_key, None)

        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⌘ Local", callback_data="create:scope:local"),
             InlineKeyboardButton("⌁ Node",  callback_data="create:scope:node")],
            [InlineKeyboardButton("← Back", callback_data="peers:menu")]
        ])
        await edit_send(update, "＋ <b>Create peer</b>\nChoose target:", kb); return

    if data.startswith("create:scope:"):
        scope = data.split(":")[-1]
        if scope == "local":
            ifaces = peer_ifaces()
            rows = [[InlineKeyboardButton(f"{i['name']} (id {i['id']})",
                                          callback_data=f"create:iface:{i['id']}")] for i in ifaces]
            rows.append([InlineKeyboardButton("← Back", callback_data="peers:create")])
            await edit_send(update, "＋ <b>Create peer (local)</b>\nChoose interface:", InlineKeyboardMarkup(rows))
        else:
            nodes = list_nodes()
            if not nodes:
                await edit_send(update, "No nodes found or offline.", KB.back("peers:create")); return
            rows = [[InlineKeyboardButton(f"{n.get('name','node')} (id {n.get('id')})",
                                          callback_data=f"create:node:{n['id']}")] for n in nodes]
            rows.append([InlineKeyboardButton("← Back", callback_data="peers:create")])
            await edit_send(update, "Select node:", InlineKeyboardMarkup(rows))
        return

    if data.startswith("create:node:") and data.count(":") == 2:
        nid = int(data.split(":")[-1])
        ifs = list_node_ifaces(nid)
        rows = [[InlineKeyboardButton(i["name"], callback_data=f"create:node:{nid}:iface:{i['name']}")] for i in ifs]
        rows.append([InlineKeyboardButton("← Back", callback_data="peers:create")])
        await edit_send(update, "Select interface:", InlineKeyboardMarkup(rows)); return

    if data.startswith("create:node:") and ":iface:" in data:
        parts = data.split(":")
        nid   = int(parts[2])
        iname = parts[-1]
        rows = [
            [InlineKeyboardButton("◇ Enter peer details", callback_data=f"create:node:manual:{nid}:{iname}")],
            [InlineKeyboardButton("✦ Choose saved profile", callback_data=f"create:node:pickprof:{nid}:{iname}")],
            [InlineKeyboardButton("＋ Create a profile", callback_data="profiles:new")],
        ]
        dname = default_profile("single")
        if dname:
            rows.insert(1, [InlineKeyboardButton(f"☆ Use default: {dname}", callback_data=f"create:node:useprofdef:{nid}:{iname}")])
        rows.append([InlineKeyboardButton("← Back", callback_data=f"create:node:{nid}")])
        kb = InlineKeyboardMarkup(rows)
        await edit_send(update, f"＋ <b>Create on node</b>\nInterface: <b>{html(iname)}</b>\nChoose manual input or a saved profile. A default button appears only when a default profile exists.", kb)
        return

    if data.startswith("create:node:manual:"):
        _, _, mode, nid_s, iname = data.split(":", 4)
        fields = ADVANCED_CREATE_FIELDS
        st = {
            "scope": "node",
            "node_id": int(nid_s),
            "iface_name": iname,
            "step": 0,
            "data": {},
            "defaults": PANEL_DEFAULTS.copy(),
            "selected_profile": None,
            "skip_filled": False,
            "ask_missing_profile": False,
            "fields": fields,
        }
        context.user_data[STATE["CREATE"]] = st
        await create_step(update, context)
        return

    if data.startswith("create:node:useprofdef:"):
        _, _, _, nid_s, iname = data.split(":", 4)
        nid = int(nid_s)

        prof_name, profvals = profile_scope("single")
        profvals = profvals or {}

        defaults = {}

        for k, v in profvals.items():
            if v is None:
                continue
            if isinstance(v, str):
                v = v.strip()

            if k == "telegram_id":
                v = (v or "").lstrip("@").strip()
            if k == "phone_number":
                v = (v or "").strip()

            if v != "":
                defaults[k] = v

        st = {
        "step": 0,
        "scope": "node",
        "node_id": nid,
        "iface_name": iname,
        "selected_profile": prof_name,
        "data": {},
        "defaults": defaults,
        "ask_missing_profile": True,
    }

        context.user_data[STATE["CREATE"]] = st
        await create_step(update, context)
        return


    if data.startswith("create:node:pickprof:"):
        _, _, _, nid_s, iname = data.split(":", 4)
        nid = int(nid_s)
        names = profiles_list_for("single")
        if not names:
            await edit_send(update, "No compatible profiles (Single/Both) found.", KB.back(f"create:node:{nid}")); return
        rows = [[InlineKeyboardButton(f"✦ {n}", callback_data=f"create:node:useprof:{nid}:{iname}:{n}")] for n in names]
        rows.append([InlineKeyboardButton("← Back", callback_data=f"create:node:{nid}:iface:{iname}")])
        await edit_send(update, "✦ <b>Select a profile</b>:", InlineKeyboardMarkup(rows)); return

    if data.startswith("create:node:useprof:"):
        _, _, _, nid_s, iname, name = data.split(":", 5)
        nid = int(nid_s)

        profvals = profile_get(name) or {}
        defaults = _profile_defaults(profvals)

        st = {
        "step": 0,
        "scope": "node",
        "node_id": nid,
        "iface_name": iname,
        "selected_profile": name,
        "data": {},
        "defaults": defaults,
        "ask_missing_profile": True,
        "skip_filled": True,
    }

        context.user_data[STATE["CREATE"]] = st
        await create_step(update, context)
        return


    if data.startswith("create:iface:"):
        iface_id = int(data.split(":")[-1])
        context.user_data[STATE["CREATE"]] = {
            "iface_id": iface_id,
            "step": 0,
            "data": {},
            "defaults": {},
            "selected_profile": None, "skip_filled": False,
            "ask_missing_profile": True, 
        }
        rows = [
            [InlineKeyboardButton("◇ Enter peer details", callback_data="create:mode:manual")],
            [InlineKeyboardButton("✦ Use peer profile", callback_data=f"create:pickprof:{iface_id}")],
            [InlineKeyboardButton("＋ Create a profile", callback_data="profiles:new")],
        ]
        dname = default_profile("single")
        if dname:
            rows.insert(1, [InlineKeyboardButton(f"☆ Use default: {dname}", callback_data=f"create:useprofdef:{iface_id}")])
        rows.append([InlineKeyboardButton("← Back", callback_data="create:scope:local")])
        kb = InlineKeyboardMarkup(rows)
        await edit_send(update, "＋ <b>Create (local)</b>\nChoose manual input or a saved profile. A default button appears only when a default profile exists.", kb); return

    if data.startswith("create:useprofdef:"):
        iface_id = int(data.split(":")[-1])
        st = context.user_data.get(STATE["CREATE"], {})
        if int(iface_id) != int(st.get("iface_id", -1)):
            await edit_send(update, "Please pick the interface again.", KB.back("peers:create"))
            return

        dname = default_profile("single")
        if not dname:
            await edit_send(update, "No compatible default profile (Single/Both).", KB.back(f"create:iface:{iface_id}"))
            return

        profvals = profile_get(dname) or {}
        defaults = _profile_defaults(profvals)

        st["defaults"] = defaults
        st["selected_profile"] = dname
        st["skip_filled"] = True

        st["ask_missing_profile"] = True

        st["step"] = 0
        st["data"] = {}

        context.user_data[STATE["CREATE"]] = st
        await create_step(update, context)
        return


    if data.startswith("create:pickprof:"):
        iface_id = int(data.split(":")[-1])
        names = profiles_list_for("single")
        if not names:
            await edit_send(update, "No compatible profiles (Single/Both) found.", KB.back(f"create:iface:{iface_id}")); return
        rows = [[InlineKeyboardButton(f"✦ {n}", callback_data=f"create:useprof:{iface_id}:{n}")] for n in names]
        rows.append([InlineKeyboardButton("← Back", callback_data=f"create:iface:{iface_id}")])
        await edit_send(update, "✦ <b>Select a profile</b>:", InlineKeyboardMarkup(rows)); return

    if data.startswith("create:useprof:"):
        _, _, iface_id, name = data.split(":", 3)
        st = context.user_data.get(STATE["CREATE"], {})
        if int(iface_id) != int(st.get("iface_id", -1)):
            await edit_send(update, "Please pick the interface again.", KB.back("peers:create"))
            return

        profvals = profile_get(name) or {}
        defaults = _profile_defaults(profvals)

        st["defaults"] = defaults
        st["selected_profile"] = name
        st["skip_filled"] = True
        st["ask_missing_profile"] = True
        st["step"] = 0
        st["data"] = {}

        context.user_data[STATE["CREATE"]] = st
        await create_step(update, context)
        return


    if data in {"create:mode:quick", "create:mode:advanced", "create:mode:manual"}:
        st = context.user_data.get(STATE["CREATE"], {})
        st.pop("selected_profile", None)
        st["skip_filled"] = False
        st["ask_missing_profile"] = False
        st["defaults"] = PANEL_DEFAULTS.copy()
        st["fields"] = ADVANCED_CREATE_FIELDS
        st["step"] = 0
        st["data"] = {}
        st.pop("submitting", None)
        context.user_data[STATE["CREATE"]] = st
        await create_step(update, context)
        return

    
    if data == "home:main" or data == "home:refresh":
       await edit_send(update, render_home(update), KB.home())
       return
    
    
    if data == "home:admins":
        try:
            r = _get(f"{PANEL}/api/telegram/admins", session="api")
            j = _json_txt(r) or {}
            admins = j.get("admins", []) or []
        except Exception:
            admins = []

        active = sum(1 for a in admins if not a.get("muted"))
        muted = len(admins) - active
        lines = [
            "♙ <b>Administrators</b>",
            "<i>Telegram access and notification recipients</i>",
            "",
            f"● Active      <code>{active}</code>",
            f"○ Muted       <code>{muted}</code>",
            f"◇ Total       <code>{len(admins)}</code>",
        ]
        rows = []
        if admins:
            lines.extend(["", "<b>Access list</b>"])
            for a in admins:
                aid = str(a.get("id") or "—")
                username = str(a.get("username") or "").lstrip("@")
                note = str(a.get("note") or "").strip()
                icon = "○" if a.get("muted") else "●"
                display = f"@{username}" if username else f"ID {aid}"
                suffix = f" · {html(note)}" if note else ""
                lines.append(f"{icon} <b>{html(display)}</b> · <code>{html(aid)}</code>{suffix}")
        else:
            lines.extend(["", "No administrators are configured in the panel."])

        rows.extend([
            [InlineKeyboardButton("⚙ Open admin settings", url=f"{PANEL.rstrip('/')}/settings")],
            [InlineKeyboardButton("↻ Refresh", callback_data="home:admins"), InlineKeyboardButton("← Dashboard", callback_data="home:main")],
        ])
        await edit_send(update, "\n".join(lines), InlineKeyboardMarkup(rows))
        return
    
    if data == "home:help":
        txt = (
        "◇ <b>Help & Overview</b>\n\n"

        "<b>Core Features</b>\n"
        "• <b>Peers</b> — Create, bulk-create, view status, and manage WireGuard peers.\n"
        "• <b>Profiles</b> — Save reusable presets (Single / Bulk) and apply them during peer creation.\n"
        "• <b>Status</b> — View system metrics and peer connectivity statistics.\n"
        "• <b>Admins</b> — Control who can access and operate this bot (configured in the panel).\n\n"

        "<b>Recommended Usage</b>\n"
        "• Use <b>Profiles</b> to avoid re-entering limits, DNS, MTU, and other settings.\n"
        "• In <b>Create</b> and <b>Bulk</b> wizards, prefer the on-screen <b>Cancel</b> and <b>Skip</b> buttons.\n"
        "• Use <b>Peer Status</b> for searching and filtering peers.\n\n"

        "<b>System Notes</b>\n"
        "• This bot communicates with the panel using the configured API/session.\n"
        "• Actions follow panel-side permissions and limits.\n\n"

        "<i>For advanced configuration and access control, use the panel interface.</i>"
        )
        await edit_send(update, txt, KB.back("home:main"))
        return


    # ___ Bulk 
    if data == "peers:bulk":
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⌘ Local", callback_data="bulk:scope:local"),
             InlineKeyboardButton("⌁ Node",  callback_data="bulk:scope:node")],
            [InlineKeyboardButton("← Back", callback_data="peers:menu")]
        ])
        await edit_send(update, "▦ <b>Bulk create</b>\nChoose target:", kb); return

    if data.startswith("bulk:scope:"):
        scope = data.split(":")[-1]
        if scope == "local":
            ifaces = peer_ifaces()
            rows = [[InlineKeyboardButton(f"{i['name']} (id {i['id']})",
                                          callback_data=f"bulk:iface:{i['id']}")] for i in ifaces]
            rows.append([InlineKeyboardButton("← Back", callback_data="peers:bulk")])
            await edit_send(update, "▦ <b>Bulk create (local)</b>\nChoose interface:", InlineKeyboardMarkup(rows))
        else:
            nodes = list_nodes()
            if not nodes:
                await edit_send(update, "No nodes found or offline.", KB.back("peers:bulk")); return
            rows = [[InlineKeyboardButton(f"{n.get('name','node')} (id {n.get('id')})",
                                          callback_data=f"bulk:node:{n['id']}")] for n in nodes]
            rows.append([InlineKeyboardButton("← Back", callback_data="peers:bulk")])
            await edit_send(update, "Select node for bulk:", InlineKeyboardMarkup(rows))
        return

    if data.startswith("bulk:node:") and data.count(":") == 2:
        nid = int(data.split(":")[-1])
        ifs = list_node_ifaces(nid)
        rows = [[InlineKeyboardButton(i["name"], callback_data=f"bulk:node:{nid}:iface:{i['name']}")] for i in ifs]
        rows.append([InlineKeyboardButton("← Back", callback_data="peers:bulk")])
        await edit_send(update, "Select interface:", InlineKeyboardMarkup(rows)); return

    if data.startswith("bulk:node:") and ":iface:" in data:
        parts = data.split(":")
        nid   = int(parts[2]); iname = parts[-1]
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("☆ Use default",     callback_data=f"bulk:node:useprofdef:{nid}:{iname}")],
            [InlineKeyboardButton("✦ Choose profile", callback_data=f"bulk:node:pickprof:{nid}:{iname}")],
            [InlineKeyboardButton("◇ Manual input", callback_data=f"bulk:node:manual:{nid}:{iname}")],
            [InlineKeyboardButton("← Back",           callback_data=f"bulk:node:{nid}")],
        ])
        await edit_send(update, f"▦ <b>Bulk on node</b>\nInterface: <b>{html(iname)}</b>\nChoose manual input or a saved profile. A default button appears only when a default profile exists.", kb)
        return
    
    if data.startswith("bulk:node:manual:"):
        _, _, _, nid_s, iname = data.split(":", 4)
        nid = int(nid_s)

        st = context.user_data.get(STATE["BULK"], {})
        st["scope"] = "node"
        st["node_id"] = nid
        st["iface_name"] = iname

        st["ask_missing_profile"] = False
        st["skip_filled"] = False
        st["selected_profile"] = None

        st["defaults"] = dict(PANEL_DEFAULTS)
        st["defaults"].setdefault("count", "5")

        st["step"] = 0
        st["data"] = {}
        context.user_data[STATE["BULK"]] = st

        await bulk_step(update, context)
        return

    
    if data.startswith("bulk:node:pickprof:"):
        _, _, _, nid_s, iname = data.split(":", 4)
        nid = int(nid_s)

        names = profiles_list_for("bulk")
        if not names:
            await edit_send(
                update,
                "No compatible profiles (Bulk/Both) found.",
                KB.back(f"bulk:node:{nid}:iface:{iname}")
            )
            return
        rows = [
            [InlineKeyboardButton(f"✦ {n}", callback_data=f"bulk:node:useprof:{nid}:{iname}:{n}")]
            for n in names
        ]
        rows.append([InlineKeyboardButton("← Back", callback_data=f"bulk:node:{nid}:iface:{iname}")])
        
        await edit_send(update, "✦ <b>Select a profile</b>:", InlineKeyboardMarkup(rows))
        return

    if data.startswith("bulk:node:useprofdef:"):
        _, _, _, nid_s, iname = data.split(":", 4)
        nid = int(nid_s)

        dname = default_profile("bulk")
        if not dname:
            await edit_send(update, "No compatible default profile (Bulk/Both).",
                        KB.back(f"bulk:node:{nid}:iface:{iname}"))
            return

        profvals = profile_get(dname) or {}
        defaults_from_profile = _profile_defaults(profvals)

        context.user_data[STATE["BULK"]] = {
        "scope": "node",
        "node_id": nid,
        "iface_name": iname,

        "step": 0,
        "data": {},

        "defaults": {**defaults_from_profile, "count": "5"},

        "selected_profile": dname,
        "skip_filled": True,
        "ask_missing_profile": True,
    }

        await bulk_step(update, context)
        return

    if data.startswith("bulk:node:useprof:"):
        _, _, _, nid_s, iname, name = data.split(":", 5)
        nid = int(nid_s)

        profvals = profile_get(name) or {}
        defaults_from_profile = _profile_defaults(profvals)

        context.user_data[STATE["BULK"]] = {
        "scope": "node",
        "node_id": nid,
        "iface_name": iname,

        "step": 0,
        "data": {},

        "defaults": {**defaults_from_profile, "count": "5"},

        "selected_profile": name,
        "skip_filled": True,
        "ask_missing_profile": True,
    }

        await bulk_step(update, context)
        return


    if data.startswith("bulk:iface:"):
        iface_id = int(data.split(":")[-1])
        context.user_data[STATE["BULK"]] = {
            "iface_id": iface_id, "step": 0, "data": {},
            "defaults": {"count": "5"},
            "selected_profile": None, "skip_filled": False,
            "ask_missing_profile": True,
        }
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("☆ Use default",     callback_data=f"bulk:useprofdef:{iface_id}")],
            [InlineKeyboardButton("✦ Choose profile", callback_data=f"bulk:pickprof:{iface_id}")],
            [InlineKeyboardButton("◇ Manual input",  callback_data="bulk:mode:manual")],
            [InlineKeyboardButton("← Back",           callback_data="bulk:scope:local")],
        ])
        await edit_send(update, "▦ <b>Bulk (local)</b>\nChoose manual input or a saved profile. A default button appears only when a default profile exists.", kb); return

    if data.startswith("bulk:useprofdef:"):
        iface_id = int(data.split(":")[-1])
        st = context.user_data.get(STATE["BULK"], {})
        if int(iface_id) != int(st.get("iface_id", -1)):
            await edit_send(update, "Please pick the interface again.", KB.back("peers:bulk"))
            return

        dname = default_profile("bulk")
        if not dname:
            await edit_send(update, "No compatible default profile (Bulk/Both).", KB.back(f"bulk:iface:{iface_id}"))
            return

        profvals = profile_get(dname) or {}
        defaults = _profile_defaults(profvals)

        st["defaults"] = {**defaults, "count": st.get("defaults", {}).get("count", "5")}
        st["selected_profile"] = dname
        st["skip_filled"] = True
        st["ask_missing_profile"] = True
        st["step"] = 0
        st["data"] = {}

        context.user_data[STATE["BULK"]] = st
        await bulk_step(update, context)
        return

    if data.startswith("bulk:pickprof:"):
        iface_id = int(data.split(":")[-1])
        names = profiles_list_for("bulk")
        if not names:
            await edit_send(update, "No compatible profiles (Bulk/Both) found.", KB.back(f"bulk:iface:{iface_id}")); return
        rows = [[InlineKeyboardButton(f"✦ {n}", callback_data=f"bulk:useprof:{iface_id}:{n}")] for n in names]
        rows.append([InlineKeyboardButton("← Back", callback_data=f"bulk:iface:{iface_id}")])
        await edit_send(update, "✦ <b>Select a profile</b>:", InlineKeyboardMarkup(rows)); return

    if data.startswith("bulk:useprof:"):
        _, _, iface_id, name = data.split(":", 3)
        st = context.user_data.get(STATE["BULK"], {})
        if int(iface_id) != int(st.get("iface_id", -1)):
            await edit_send(update, "Please pick the interface again.", KB.back("peers:bulk"))
            return

        profvals = profile_get(name) or {}
        defaults = _profile_defaults(profvals)

        st["defaults"] = {**defaults, "count": st.get("defaults", {}).get("count", "5")}
        st["selected_profile"] = name
        st["skip_filled"] = True
        st["ask_missing_profile"] = True
        st["step"] = 0
        st["data"] = {}

        context.user_data[STATE["BULK"]] = st
        await bulk_step(update, context)
        return
 
    if data == "bulk:mode:manual":
        st = context.user_data.get(STATE["BULK"], {})
        st.pop("selected_profile", None)

        st["skip_filled"] = False
        st["ask_missing_profile"] = True
        st["defaults"] = {"count": st.get("defaults", {}).get("count", "5")} 

        st["step"] = 0
        st["data"] = {}
        context.user_data[STATE["BULK"]] = st
        await bulk_step(update, context)
        return


    # ___ Status 
    if data == "peers:status":
        context.user_data.pop("status_iface", None)
        context.user_data.pop("status_scope", None)
        context.user_data.pop("status_node",  None)
        context.user_data.pop("status_node_name", None)
        context.user_data.pop("status_search_term", None)
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⌘ Local", callback_data="status:scope:local"),
             InlineKeyboardButton("⌁ Node",  callback_data="status:scope:node")],
            [InlineKeyboardButton("← Back", callback_data="peers:menu")]
        ])
        await edit_send(update, "⌕ <b>Peer status</b>\nChoose where to browse:", kb); return

    if data == "status:scope:local":
        context.user_data["status_scope"] = "local"
        ifaces = peer_ifaces()
        rows = [[InlineKeyboardButton("All interfaces", callback_data="status:iface:all")]]
        rows += [[InlineKeyboardButton(f"{i['name']} (id {i['id']})",
                                    callback_data=f"status:iface:{i['id']}")] for i in ifaces]
        rows.append([InlineKeyboardButton("← Back", callback_data="peers:status")])
        await edit_send(update, "⌘ <b>Local</b>\nPick interface:", InlineKeyboardMarkup(rows)); return

    if data == "status:scope:node":
        nodes = list_nodes()
        if not nodes:
            await edit_send(update, "No nodes found or offline.", KB.back("peers:status")); return
        rows = [[InlineKeyboardButton("All nodes", callback_data="status:node:all")]]
        rows += [[InlineKeyboardButton(f"{n.get('name','node')} (id {n.get('id')})",
                                    callback_data=f"status:node:{n['id']}")] for n in nodes]
        rows.append([InlineKeyboardButton("← Back", callback_data="peers:status")])
        await edit_send(update, "⌁ <b>Node</b>\nPick scope:", InlineKeyboardMarkup(rows)); return

    if data.startswith("status:node:"):
        _, _, v = data.split(":", 2)
        if v == "all":
            context.user_data["status_scope"] = "node"
            context.user_data["status_node"]  = None
            context.user_data["status_node_name"] = "All nodes"
            context.user_data["status_iface"] = "all"
            await _peer_page(update, context, page=1); return
        nid = int(v)
        context.user_data["status_scope"] = "node"
        context.user_data["status_node"]  = nid
        try:
            n = next((x for x in list_nodes() if int(x.get("id")) == nid), None)
            context.user_data["status_node_name"] = (n or {}).get("name") or f"Node {nid}"
        except Exception:
            context.user_data["status_node_name"] = f"Node {nid}"
        ifs = list_node_ifaces(nid)
        rows = [[InlineKeyboardButton("All interfaces (node)", callback_data="status:iface:all")]]
        rows += [[InlineKeyboardButton(i["name"], callback_data=f"status:iface:{i['name']}")] for i in ifs]
        rows.append([InlineKeyboardButton("← Back", callback_data="status:scope:node")])
        await edit_send(update, f"⌁ <b>{html(context.user_data['status_node_name'])}</b>\nPick interface:",
                        InlineKeyboardMarkup(rows)); return

    if data.startswith("status:iface:"):
        which = data.split(":")[-1]
        context.user_data["status_iface"] = which
        await _peer_page(update, context, page=1); return

    if data.startswith("plist:page:"):
        page = int(data.split(":")[-1])
        await _peer_page(update, context, page=page); return

    if data == "status:search":
        context.user_data["STATUS_SEARCH"] = True
        await edit_send(update, "⌕ Send a search term (name/address/endpoint). Send '-' to clear.", KB.back("peers:status")); return
    if data == "status:clearsearch":
        context.user_data.pop("status_search_term", None)
        context.user_data.pop("STATUS_SEARCH", None)
        await _peer_page(update, context, page=1); return

    # ___ Peer stuff
    if data.startswith("peer:open:"):
        pid = int(data.split(":")[-1])
        await _peer_detail_view(update, context, pid)
        return

    if data.startswith("peer:bundle:") or data.startswith("peer:cfg:") or data.startswith("peer:qr:"):
        pid = int(data.split(":")[-1])
        await send_peers(update, pid); return

    if data.startswith("peer:toggle:"):
        pid = int(data.split(":")[-1])
        p_now = peer_by_id(pid) if 'peer_by_id' in globals() else get_peer(pid)
        if not p_now:
            await edit_send(update, "Peer not found.", KB.peers_index()); return
        status_now = (p_now.get("status") or "").lower()
        try:
            if status_now != "online":
                peer_enable(pid)
                action = "peer_enable"
            else:
                peer_disable(pid)
                action = "peer_disable"
        except Exception as e:
            await edit_send(update, f"⊘ {html(str(e))}", KB.back(f"peer:open:{pid}")); return

        _log_admin(action, f"pid={pid}; scope=local")
        await _peer_detail_view(update, context, pid)
        return

    if data.startswith("peer:resetdata:"):
        pid = int(data.split(":")[-1])
        try:
            peer_reset_usage(pid)
            _log_admin("peer_reset_data", f"pid={pid}; scope=local")
            await edit_send(update, "● Data usage reset.", KB.back(f"peer:open:{pid}"))
        except Exception as e:
            await edit_send(update, f"⊘ Reset data failed: <code>{html(str(e))}</code>", KB.back(f"peer:open:{pid}"))
        return

    if data.startswith("peer:resettimer:"):
        pid = int(data.split(":")[-1])
        try:
            peer_reset_timer(pid)
            _log_admin("peer_reset_timer", f"pid={pid}; scope=local")
            await edit_send(update, "● Timer reset.", KB.back(f"peer:open:{pid}"))
        except Exception as e:
            await edit_send(update, f"⊘ Reset timer failed: <code>{html(str(e))}</code>", KB.back(f"peer:open:{pid}"))
        return

    if data.startswith("peer:more:"):
        pid = int(data.split(":")[-1])
        p = peer_by_id(pid) if 'peer_by_id' in globals() else get_peer(pid)
        if not p:
            await edit_send(update, "Peer not found.", KB.peers_index()); return
        await edit_send(update, _peer_more_info(p), KB.back(f"peer:open:{pid}")); return

    if data.startswith("peer:disable:") or data.startswith("peer:enable:"):
        pid = int(data.split(":")[-1])
        q.data = f"peer:toggle:{pid}"
        return await on_cb(update, context)

    if data.startswith("peer:delete:"):
        pid = int(data.split(":")[-1])
        k = InlineKeyboardMarkup([
            [InlineKeyboardButton("● Yes, delete", callback_data=f"peer:delete:confirm:{pid}")],
            [InlineKeyboardButton("← Back", callback_data=f"peer:open:{pid}")]
        ])
        await edit_send(update, "⌫ Confirm delete this peer?", k); return

    if data.startswith("peer:delete:confirm:"):
        pid = int(data.split(":")[-1])
        delete_peer(pid)
        _log_admin("peer_delete", f"pid={pid}; scope=local")
        await edit_send(update, "⌫ Deleted.", KB.peers_index()); return

    if data.startswith("peer:edit:"):
        pid = int(data.split(":")[-1])
        await _edit_menu(update, pid); return

    if data.startswith("edit:field:"):
        _, _, pid_s, key = data.split(":", 3)
        pid = int(pid_s)
        try:
            p = peer_by_id(pid) if 'peer_by_id' in globals() else get_peer(pid)
        except Exception:
            p = None
        cur = _current_value(p, key)
        context.user_data[STATE["EDIT_ONE"]] = {"pid": pid, "key": key}
        hint = f"\n(current: <code>{html(cur)}</code>)" if cur != "" else ""
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⊘ Cancel", callback_data=f"edit:cancel:{pid}")],
            [InlineKeyboardButton("← Back",   callback_data=f"peer:open:{pid}")]
            ])
        await edit_send(
            update,
            f"◇ <b>Edit</b> — {html(_edit_label(key))}{hint}\n\nSend the new value.",
            kb
        ); return
    
    if data.startswith("edit:cancel:"):
        pid = int(data.split(":")[-1])
        context.user_data.pop(STATE["EDIT_ONE"], None)
        await _edit_menu(update, pid)
        return

    if data in ("wiz:create:skip", "wiz:bulk:skip"):
        flow = "CREATE" if data.startswith("wiz:create") else "BULK"
        st = context.user_data.get(STATE[flow])
        if st:
            step = int(st.get("step", 0))
            seq = (st.get("fields") or ADVANCED_CREATE_FIELDS) if flow == "CREATE" else BULK_FIELDS
            if 0 <= step < len(seq):
                st["step"] = step + 1
                context.user_data[STATE[flow]] = st
                await (create_step if flow == "CREATE" else bulk_step)(update, context)
        return
    
    if data == "backup:menu":
        try:
            prefs = _get(f"{PANEL}/api/backup/prefs", session="api").json()
        except Exception:
            prefs = {}
        last_ts = _last_backup()
        sched = _backup_schedule()
        enabled = bool(sched.get("enabled"))
        when = str(sched.get("time") or "03:00")
        freq = str(sched.get("freq") or "daily")
        tz = str(sched.get("timezone") or "UTC")
        next_run = str(sched.get("next_run") or "—")
        header = "\n".join([
            "▣ <b>Backup center</b>",
            "<i>Create, restore, and schedule protected archives</i>",
            "",
            "<b>Overview</b>",
            f"◇ Last backup   {html(_fmt_when(last_ts))}",
            f"{'●' if enabled else '○'} Schedule      {'Enabled' if enabled else 'Disabled'}",
            f"◷ Frequency     <code>{html(freq)}</code> · <code>{html(when)}</code> {html(tz)}",
            f"↥ Next run      <code>{html(next_run)}</code>",
            "",
            "Choose an operation below.",
        ])
        await edit_send(update, header, kb_backup_menu(prefs))
        return
    
    if data == "backup:schedule":
        s = _backup_schedule()
        enabled = bool(s.get("enabled"))
        freq = str(s.get("freq") or "daily")
        run_time = str(s.get("time") or "03:00")
        timezone_name = str(s.get("timezone") or "UTC")
        next_run = str(s.get("next_run") or "—")
        keep = int(s.get("keep") or 7)

        msg = "\n".join([
            "◷ <b>Automatic backup</b>",
            "<i>Protected archive schedule</i>",
            "",
            "<b>Schedule</b>",
            (
                f"{'●' if enabled else '○'} Status       "
                f"{'Enabled' if enabled else 'Disabled'}"
            ),
            f"◇ Frequency    <code>{html(freq)}</code>",
            f"◇ Time         <code>{html(run_time)} {html(timezone_name)}</code>",
            f"◇ Retention    <code>{keep}</code> archive(s)",
            f"◇ Next run     <code>{html(next_run)}</code>",
            "",
            "<b>Contents</b>",
            (
                f"{'●' if s.get('include_wg') else '○'} "
                "WireGuard configurations"
            ),
            (
                f"{'●' if s.get('send_to_telegram') else '○'} "
                "Telegram delivery"
            ),
            "",
            "⌁ <i>Automatic backups are stored by the panel scheduler.</i>",
        ])

        await edit_send(update, msg, kb_backup_schedule(s))
        return

    if data == "backup:schedule:toggle":
        s = _backup_schedule()
        payload = dict(s)
        payload["enabled"] = not bool(s.get("enabled", False))
        _set_backup_schedule(payload)
        s2 = _backup_schedule()
        await edit_send(
            update,
            (
                "● <b>Backup schedule saved</b>\n\n"
                "◇ The new automatic-backup policy is active."
            ),
            kb_backup_schedule(s2),
        )
        return
    
    if data == "backup:schedule:test_2m":
        st = _load_backup_state()
        fire_at = int(time.time()) + 120
        st["test_fire_at"] = fire_at
        st["test_fired_at"] = 0
        _save_backup_state(st)

        await edit_send(
            update,
            f"◇ Test armed.\n"
            f"The bot will store an auto-backup in ~2 minutes.\n"
            f"• Fire at (epoch): <code>{fire_at}</code>\n\n"
            f"Tip: keep this chat open and use ↻ Refresh after 2 minutes.",
            InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="backup:schedule")]])
            )
        return


    if data == "backup:schedule:run_now":
        s = _backup_schedule()
        wg = "1" if s.get("include_wg") else "0"
        tg = "1" if s.get("send_to_telegram") else "0"
        try:
            await edit_send(update, "◷ <b>Creating automatic backup</b>\n\n◇ Building and storing the protected archive…",
                            InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="backup:schedule")]])
                            )
            chat_id = str(s.get("telegram_chat_id") or "").strip()
            url = (
                f"{PANEL}/api/backup/full?auto=1&wg={wg}&tg={tg}"
                f"&chat_id={chat_id}"
            )
            dest = (AUTO_BACKUP_DIR / _auto_backupname("full"))
            ok, info = await asyncio.to_thread(_store_backuppanel, url, dest, "api", 900)
            if ok:
                _p_autobackups("full", s.get("keep", 7))
                await edit_send(
                    update,
                    (
                        "● <b>Automatic backup completed</b>\n\n"
                        f"◇ File   <code>{html(dest.name)}</code>\n"
                        f"◇ Size   <code>{html(_human_bytes(dest.stat().st_size if dest.exists() else 0))}</code>\n"
                        f"◇ Path   <code>{html(str(dest))}</code>"
                    ),
                                InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="backup:schedule")]])
                )
            else:
                await edit_send(
                    update,
                    (
                        "⊘ <b>Automatic backup failed</b>\n\n"
                        f"◇ Error  <code>{html(info)}</code>"
                    ),
                                InlineKeyboardMarkup([[InlineKeyboardButton("← Back", callback_data="backup:schedule")]])
                )
        
        except Exception as e:
            await edit_send(
                update,
                (
                    "⊘ <b>Automatic backup failed</b>\n\n"
                    f"◇ Error  <code>{html(str(e))}</code>"
                ),
                InlineKeyboardMarkup([[
                    InlineKeyboardButton(
                        "← Back",
                        callback_data="backup:schedule",
                    )
                ]]),
            )
        return

    if data == "backup:restore":
        context.user_data[STATE["BACKUP_RESTORE_WAIT"]] = {"kind": "auto"}

        msg = (
        "↺ <b>Restore backup</b>\n\n"
        "Please send the <b>.zip</b> backup file here.\n"
        "• Recommended: <b>Auto-detect</b> mode\n"
        "• The bot will restore DB / Settings based on the ZIP layout.\n\n"
        "<i>Tip:</i> Use backups created by this panel (DB, Settings, or Full)."
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⊘ Cancel", callback_data="backup:restore:cancel")],
            [InlineKeyboardButton("← Back", callback_data="backup:menu")],
        ])
        await edit_send(update, msg, kb)
        return

    if data == "backup:restore:cancel":
        context.user_data.pop(STATE["BACKUP_RESTORE_WAIT"], None)
        await edit_send(
            update,
            "▣ <b>Backup center</b>\n<i>Restore operation cancelled.</i>",
            kb_backup_menu(),
        )
        return

    
    if data == "backup:prefs":
        try:
            r = _get(f"{PANEL}/api/backup/prefs", session="sess")
            prefs = r.json()
        except Exception:
            prefs = {"include_wg": True, "send_to_telegram": False}
        msg = ("⚙ <b>Backup preferences</b>\n"
               f"• Include WG *.conf: <b>{'ON' if prefs.get('include_wg') else 'OFF'}</b>\n"
               f"• Send to Telegram: <b>{'ON' if prefs.get('send_to_telegram') else 'OFF'}</b>")
        await edit_send(update, msg, kb_backup_prefs(prefs))
        return
    
    if data.startswith("backup:prefs:toggle:"):
        which = data.split(":")[-1]
        cur = {}
        try:
            cur = _get(f"{PANEL}/api/backup/prefs", session="sess").json()
        except Exception:
            cur = {"include_wg": True, "send_to_telegram": False}
        if which == "wg":
            cur["include_wg"] = not bool(cur.get("include_wg"))
        elif which == "tg":
            cur["send_to_telegram"] = not bool(cur.get("send_to_telegram"))
        try:
            _post(f"{PANEL}/api/backup/prefs", session="sess", json=cur)
        except Exception:
            pass
        await edit_send(
            update,
            ("● Saved.\n\n"
             f"• Include WG *.conf: <b>{'ON' if cur.get('include_wg') else 'OFF'}</b>\n"
             f"• Send to Telegram: <b>{'ON' if cur.get('send_to_telegram') else 'OFF'}</b>"),
            kb_backup_prefs(cur)
        )
        return
    
    if data == "backup:run:db":
        try:
            r = _get(f"{PANEL}/api/backup/db", session="api")
            if r.status_code == 404:
               r2 = _get(f"{PANEL}/api/backup/settings", session="api")
               content = _safe_zip(r2, "Settings backup")
               await _send_zipfile(update, content, _backup_filename("settings"), kind="settings")
               await edit_send(update, "ℹ️ DB-only backup isn’t available on this setup; sent settings-only instead.", KB.back("backup:menu"))
               return
            content = _safe_zip(r, "DB backup")
            await _send_zipfile(update, content, _backup_filename("db"), kind="database")
            uid, uname = _admin_ident()
            fname = _headers_filename(r)
            _log_admin("backup_db", f"file={fname} size={len(content)}B")

        except Exception as e:
            await edit_send(update, f"⊘ DB backup failed: <code>{html(str(e))}</code>", KB.back("backup:menu"))
        return
    
    if data == "backup:run:settings":
        try:
            r = _get(f"{PANEL}/api/backup/settings", session="api")
            content = _safe_zip(r, "Settings backup")
            await _send_zipfile(update, content, _backup_filename("settings"), kind="settings")
            uid, uname = _admin_ident()
            fname = _headers_filename(r)
            _log_admin("backup_settings", f"file={fname} size={len(content)}B")
        except Exception as e:
            await edit_send(update, f"⊘ Settings backup failed: <code>{html(str(e))}</code>", KB.back("backup:menu"))
        return
    
    if data == "backup:run:full":
        try:
            prefs = {}
            try:
                prefs = _get(f"{PANEL}/api/backup/prefs", session="api").json()
            except Exception:
                prefs = {"include_wg": True, "send_to_telegram": False}

            wg = "1" if prefs.get("include_wg") else "0"
            tg = "1" if prefs.get("send_to_telegram") else "0"

            if tg == "1":
                _get(f"{PANEL}/api/backup/full?wg={wg}&tg=1", session="api")
                await edit_send(
                    update,
                    "↗ <b>Full backup initiated</b>\n"
                    "The panel is sending the backup to Telegram admins (based on Preferences).",
                    KB.back("backup:menu"),
                )
                _log_admin("backup_full", f"file=sent_via_panel wg={int(wg=='1')} tg=1")
            else:
                r = _get(f"{PANEL}/api/backup/full?wg={wg}&tg=0", session="api")
                content = _safe_zip(r, "Full backup")
                await _send_zipfile(update, content, _backup_filename("full"), kind="full")
                fname = _headers_filename(r)
                _log_admin("backup_full", f"file={fname} size={len(content)}B wg={int(wg=='1')} tg=0")

        except Exception as e:
            await edit_send(update, f"⊘ Full backup failed: <code>{html(str(e))}</code>", KB.back("backup:menu"))
        return

    

    if data in ("wiz:create:cancel", "wiz:bulk:cancel"):
        for k in list(STATE.values()):
            context.user_data.pop(k, None)
        await edit_send(update, "⊘ Cancelled.", KB.home()); return

    if data.startswith("wiz:create:set:") or data.startswith("wiz:bulk:set:"):
        _, flow, _set, key, val = data.split(":", 4)
        flowkey = "CREATE" if flow == "create" else "BULK"
        st = context.user_data.get(STATE[flowkey])
        if st:
            step = int(st.get("step", 0))
            seq = (st.get("fields") or ADVANCED_CREATE_FIELDS) if flowkey == "CREATE" else BULK_FIELDS
            if 0 <= step < len(seq) and seq[step][0] == key:
                st.setdefault("data", {})[key] = val
                st["step"] = step + 1
                context.user_data[STATE[flowkey]] = st
                await (create_step if flowkey == "CREATE" else bulk_step)(update, context)
        return

    if data == "wiz:create:submit":
        st = context.user_data.get(STATE["CREATE"])
        if st:
            st["submitting"] = False
            st["step"] = len(st.get("fields") or ADVANCED_CREATE_FIELDS)
            context.user_data[STATE["CREATE"]] = st
            await create_step(update, context)
        return

    if data == "noop":
        return


# ___ Peer list & pagi
async def _peer_page(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 1):

    import math

    scope     = str(context.user_data.get("status_scope") or "local").lower()  
    iface_sel = context.user_data.get("status_iface", "all")                   
    node_sel  = context.user_data.get("status_node")                           
    search_q  = (context.user_data.get("status_search_term") or "").strip().lower()

    try:
        page = max(1, int(page))
    except Exception:
        page = 1

    def _status_dot(p):
        s = str(p.get("status") or "").lower()
        if "online" in s or s in {"1","true"}: return "●"
        if "blocked" in s:                     return "⊘"
        return "○"

    def _loc_label(p):
        nid   = p.get("node_id")
        nname = p.get("node_name") or p.get("node") or ""
        iname = p.get("iface") or p.get("interface") or ""
        if nid is not None:
            base = f"⌁ {nname or ('node ' + str(nid))}"
            return f"{base} — {iname}" if iname else base
        return f"⌘ local — {iname}" if iname else "⌘ local"

    def _haystack(p):
        return " ".join([
            str(p.get("name") or ""),
            str(p.get("address") or ""),
            str(p.get("endpoint") or ""),
            str(p.get("iface") or p.get("interface") or ""),
            str(p.get("phone_number") or ""),
            ("@" + str(p.get("telegram_id") or "")),
        ]).lower()

    def list_node_peers(nid: int, iface_name: str | None) -> list[dict]:
        paths = []
        if iface_name:
            paths += [f"{PANEL}/api/nodes/{nid}/peers?iface={iface_name}",
                      f"{PANEL}/api/peers?scope=node&node_id={nid}&iface={iface_name}"]
        paths += [f"{PANEL}/api/nodes/{nid}/peers",
                  f"{PANEL}/api/peers?scope=node&node_id={nid}",
                  f"{PANEL}/api/peers?scope=node"]
        for url in paths:
            try:
                r = _get(url, session="sess")
                j = _json_txt(r)
                if isinstance(j, dict) and isinstance(j.get("peers"), list):
                    peers = j["peers"]
                elif isinstance(j, list):
                    peers = j
                else:
                    continue
                for p in peers:
                    p.setdefault("node_id", nid)
                if "scope=node" in url and nid is not None:
                    peers = [p for p in peers if str(p.get("node_id")) == str(nid)]
                if iface_name:
                    peers = [p for p in peers if str(p.get("iface") or p.get("interface")) == str(iface_name)]
                return peers
            except Exception:
                continue
        return []

    peers: list[dict] = []
    if scope == "local":
        if iface_sel == "all":
            peers = list_peers(None) or []
            iface_label = "all interfaces"
        else:
            try:
                iid = int(iface_sel)
            except Exception:
                iid = None
            peers = list_peers(iid) or []
            iface_label = _iface_id().get(iid, str(iface_sel))
        scope_label = "⌘ Local"
    else:
        if node_sel is None:
            nodes = list_nodes()
            if not nodes:
                await edit_send(update, "No nodes found or offline.", KB.back("peers:menu")); return
            rows = [[InlineKeyboardButton(f"{n.get('name','node')} (id {n.get('id')})",
                                          callback_data=f"status:nodepick:{n['id']}")] for n in nodes]
            rows.append([InlineKeyboardButton("← Back", callback_data="peers:menu")])
            await edit_send(update, "⌁ <b>Select a node</b>:", InlineKeyboardMarkup(rows)); return

        iname = None if iface_sel == "all" else str(iface_sel)
        peers = list_node_peers(int(node_sel), iname) or []
        node_name = context.user_data.get("status_node_name") or ""
        scope_label = f"⌁ {node_name or ('node ' + str(node_sel))}"
        iface_label = "all interfaces" if iface_sel == "all" else str(iface_sel)

    if search_q:
        peers = [p for p in peers if search_q in _haystack(p)]

    peers.sort(key=lambda x: (str(x.get("name") or ""), int(x.get("id") or 0)))
    per_page = 10
    total = len(peers)
    pages = max(1, math.ceil((total or 1) / per_page))
    page = min(page, pages)
    start, end = (page - 1) * per_page, min(page * per_page, total)
    page_peers = peers[start:end]

    peer_rows = []
    if page_peers:
        for p in page_peers:
            pid   = int(p.get("id"))
            name  = p.get("name") or f"peer-{pid}"
            label = f"{name} (id {pid}) • {_status_dot(p)} • {_loc_label(p)}"
            peer_rows.append([InlineKeyboardButton(label, callback_data=f"peer:open:{pid}")])
    else:
        peer_rows.append([InlineKeyboardButton("No peers found", callback_data="noop")])

    search_label = "⊘ Clear manual search" if search_q else "⌕ Search manually"
    search_row   = [InlineKeyboardButton(
        search_label,
        callback_data=("status:clearsearch" if search_q else "status:search")
    )]

    context.user_data["status_page"] = page

    kb = KB.pages(
        "plist:page",
        page,
        pages,
        back_cb="peers:status",
        extra_rows=[*peer_rows, search_row],
    )

    scope_chip = f"{scope_label} — {iface_label}"
    sub = f"Showing {min(total, end) if total else 0} of {total} • Page {page}/{pages}"
    if search_q:
        sub += f" • Filter: “{html(search_q)}”"
    header = f"⌕ <b>Peer status</b> — {html(scope_chip)}\n"

    await edit_send(update, header + sub, kb)

def kb_peer_detail(p: dict, back_cb: str) -> InlineKeyboardMarkup:
    pid = int(p.get("id"))
    status = (p.get("status") or "").lower()
    is_online = "online" in status

    toggle_label = "⊘ Disable" if is_online else "● Enable"

    rows = [
        [
            InlineKeyboardButton("◇ CFG/QR", callback_data=f"peer:bundle:{pid}"),
        ],
        [
            InlineKeyboardButton(toggle_label, callback_data=f"peer:toggle:{pid}"),
            InlineKeyboardButton("↺ Data",    callback_data=f"peer:resetdata:{pid}"),
            InlineKeyboardButton("◷ Timer",   callback_data=f"peer:resettimer:{pid}"),
        ],
        [
            InlineKeyboardButton("◇ Edit",   callback_data=f"peer:edit:{pid}"),
            InlineKeyboardButton("⌫ Delete", callback_data=f"peer:delete:{pid}"),
        ],
        [InlineKeyboardButton("← Back", callback_data=back_cb)],
    ]
    return InlineKeyboardMarkup(rows)


async def _peer_detail_view(update: Update, context: ContextTypes.DEFAULT_TYPE, pid: int):
    p = peer_by_id(pid) if 'peer_by_id' in globals() else get_peer(pid)
    if not p:
        await edit_send(update, "Peer not found.", KB.peers_index())
        return

    if context.user_data.get("status_scope"):
        page = int(context.user_data.get("status_page") or 1)
        back_cb = f"plist:page:{page}"
    else:
        back_cb = "peers:menu"

    text = _peer_more_info(p)  
    await edit_send(update, text, kb_peer_detail(p, back_cb))


async def _edit_menu(update: Update, pid: int):
    p = peer_by_id(pid) if 'peer_by_id' in globals() else get_peer(pid)
    if not p:
        await edit_send(update, "Peer not found.", KB.peers_index()); return

    rows = []
    for key, _prompt, _ in EDIT_FIELDS:
        cur = _current_value(p, key)
        display = (cur[:28] + "…") if len(cur) > 30 else (cur if cur != "" else "—")
        rows.append([
            InlineKeyboardButton(
                f"◇ { _edit_label(key) }  →  {display}",
                callback_data=f"edit:field:{pid}:{key}"
            )
        ])
    rows.append([InlineKeyboardButton("← Back", callback_data=f"peer:open:{pid}")])
    await edit_send(
        update,
        f"◇ <b>Edit peer</b> — {html(p.get('name') or f'peer-{pid}')}\nChoose a field to edit:",
        InlineKeyboardMarkup(rows)
    )

def _profile_defaults(profvals: dict) -> dict:

    profvals = profvals or {}
    defaults: dict = {}

    def _as_str(v) -> str:
        return "" if v is None else str(v).strip()

    def _norm_csv(v) -> str:
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            return ", ".join(str(x).strip() for x in v if str(x).strip())
        return str(v).strip()

    for k, v in profvals.items():
        if v is None:
            continue

        if k in {"dns", "allowed_ips"}:
            v = _norm_csv(v)

        if k == "telegram_id":
            v = _as_str(v).lstrip("@")
        elif k == "phone_number":
            v = _as_str(v)
        else:
            v = _as_str(v)

        if v != "":
            defaults[k] = v

    return defaults


# ___ Wizards 
async def create_step(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get(STATE["CREATE"])
    if not st:
        await send_text(update, "⊘ Creation session expired. Start again from Peers → ＋ Create.", KB.peers_index())
        return

    if st.get("submitting"):
        await send_text(update, "◷ A peer is already being created. Please wait a moment.", KB.peers_index())
        return

    step     = int(st.get("step", 0))
    answers  = st.setdefault("data", {})

    scope    = (st.get("scope") or "local").strip().lower()  
    iface_id = st.get("iface_id")
    node_id  = st.get("node_id")
    iname    = st.get("iface_name")

    selected_profile = st.get("selected_profile")
    ask_missing_profile = bool(st.get("ask_missing_profile") or selected_profile)

    defaults = st.get("defaults")
    if defaults is None:
        defaults = {}
    if not ask_missing_profile:
        defaults = defaults or PANEL_DEFAULTS
    else:
        defaults = defaults or {} 

    def _prefill_for(key: str, def_base):

        if ask_missing_profile:
            v = defaults.get(key, None)
            return "" if v is None else str(v)
        v = defaults.get(key, def_base)
        return "" if v is None else str(v)

    def _default_prompt(key: str, def_base):

        if ask_missing_profile:
            v = defaults.get(key, None)
            return "" if v is None else str(v)
        v = defaults.get(key, def_base)
        return "" if v is None else str(v)

    fields = st.get("fields") or ADVANCED_CREATE_FIELDS

    while step < len(fields):
        key, _, def_base = fields[step]
        prefill = _prefill_for(key, def_base)

        if st.get("skip_filled") and _for_skip(key, prefill, profile_mode=ask_missing_profile):
            answers.setdefault(key, str(prefill))
            step += 1
            st["step"] = step
            continue
        break

    if step >= len(fields):
        nm = (answers.get("name") or defaults.get("name") or "").strip()
        if not nm:
            try:
                name_idx = next(i for i, (k, _, _) in enumerate(fields) if k == "name")
            except StopIteration:
                name_idx = 0
            st["step"] = name_idx
            context.user_data[STATE["CREATE"]] = st
            await create_step(update, context)
            return

        merged = {k: v for k, v in answers.items() if v != ""}
        if ask_missing_profile:
            base = {**defaults}  
        else:
            base = {**defaults}  

        payload = _payload_api({**base, **merged})

        phone = (payload.get("phone_number") or payload.get("phone") or "").strip()
        tg    = (payload.get("telegram_id")  or payload.get("telegram") or "").lstrip("@").strip()
        if phone:
            payload["phone_number"] = phone
        else:
            payload.pop("phone_number", None)

        if tg:
            payload["telegram_id"] = tg
        else:
            payload.pop("telegram_id", None)

        payload.setdefault("address", "")

        payload["name"] = nm

        if scope == "node":
            if not node_id or not iname:
                await send_text(update, "⊘ Create failed: node target missing. Choose a node/interface again.", KB.peers_index())
                return
            body = {
                **payload,
                "scope": "node",
                "node_id": int(node_id),
                "iface_name": str(iname),
                "address": payload.get("address", "")
            }
        else:
            if not iface_id:
                await send_text(update, "⊘ Create failed: iface_id missing. Choose an interface first.", KB.peers_index())
                return
            body = {**payload, "iface_id": int(iface_id)}

        st["submitting"] = True
        context.user_data[STATE["CREATE"]] = st

        r = _post_soft(f"{PANEL}/api/peers", session="api", json=body)
        j = _json_txt(r)
        if not (200 <= r.status_code < 300 and isinstance(j, dict)):
            st["submitting"] = False
            context.user_data[STATE["CREATE"]] = st
            await send_text(
                update,
                f"⊘ Create failed ({r.status_code}): {html(str(j))}",
                InlineKeyboardMarkup([
                    [InlineKeyboardButton("↻ Retry submission", callback_data="wiz:create:submit")],
                    [InlineKeyboardButton("◇ Cancel", callback_data="wiz:create:cancel")],
                ]),
            )
            return

        pid = j.get("id") or ((j.get("peer") or {}).get("id"))
        if not pid:
            st["submitting"] = False
            context.user_data[STATE["CREATE"]] = st
            await send_text(update, f"⊘ Create failed: {html(str(j))}", KB.peers_index())
            return

        context.user_data.pop(STATE["CREATE"], None)

        try:
            await send_peers(update, int(pid))
        except Exception as exc:
            logging.getLogger(__name__).exception(
                "Peer %s was created but bundle delivery failed",
                pid,
            )
            short = get_shortlink(int(pid))
            await send_text(
                update,
                (
                    f"● <b>Peer created.</b>\n"
                    f"ID: <code>{int(pid)}</code>\n"
                    f"⌁ <b>Short link</b>: "
                    f"{html(short) if short else 'Unavailable'}\n\n"
                    f"⊘ Telegram could not send the complete bundle: "
                    f"<code>{html(str(exc))}</code>"
                ),
                KB.back(f"peer:open:{int(pid)}"),
            )

        uid   = str(update.effective_user.id)
        uname = (update.effective_user.username or "") if update.effective_user else ""
        try:
            if scope == "node":
                iface_label = str(iname)
                details = _peer_details(pid=pid, name=nm, iface=iface_label, scope="node")
            else:
                try:
                    iface_label = _iface_id().get(int(iface_id), str(iface_id))
                except Exception:
                    iface_label = str(iface_id)
                details = _peer_details(pid=pid, name=nm, iface=iface_label, scope="local")

            log_tg(uid, uname, "peer_create", details)
            log_admin(uid, uname, "peer_create", details)
        except Exception:
            pass

        return

    key, prompt, def_base = fields[step]

    default = _default_prompt(key, def_base)

    show_profile = bool(selected_profile)
    tag = f"\n✦ Using profile: <b>{html(selected_profile)}</b>" if show_profile else "\n◇ Manual input"

    mode_label = "Quick" if fields == BASIC_CREATE_FIELDS else "Advanced"
    breadcrumb = f"⊕ Create · {mode_label} ({step+1}/{len(fields)})"
    hint = f"\n(default: <code>{html(default)}</code>)" if default != "" else ""
    kb = menu_kb("create", key, allow_skip=True)

    await edit_send(update, f"{breadcrumb}{tag}\n{prompt}{hint}", kb)


async def bulk_step(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get(STATE["BULK"])
    if not st:
        await send_text(update, "⊘ Bulk session expired. Start again from Peers → ▦ Bulk.", KB.peers_index())
        return

    # Session + mode (local vs node)
    step     = int(st.get("step", 0))
    selected = st.get("selected_profile")

    scope      = (st.get("scope") or "local").lower()  
    iface_id   = st.get("iface_id")                    
    node_id    = st.get("node_id")                     
    iface_name = st.get("iface_name")                  

    ask_missing_profile = bool(st.get("ask_missing_profile") or selected)

    if ask_missing_profile:
        defaults = st.get("defaults") or {"count": "5"}
    else:
        defaults = st.get("defaults") or {**PANEL_DEFAULTS, "count": "5"}

    while step < len(BULK_FIELDS):
        key, _, def_base = BULK_FIELDS[step]
        default_val = defaults.get(key, def_base)

        if key != "count" and st.get("skip_filled") and _for_skip(key, default_val, profile_mode=ask_missing_profile):
            st.setdefault("data", {}).setdefault(key, str(default_val))
            step += 1
            st["step"] = step
            continue
        break

    if step >= len(BULK_FIELDS):

        if scope == "node":
            if not node_id or not iface_name:
                await send_text(
                    update,
                    "⊘ Bulk failed: node target missing. Choose node + interface again.",
                    KB.peers_index(),
                )
                return
        else:
            if not iface_id:
                await send_text(
                    update,
                    "⊘ Bulk failed: iface_id missing. Choose an interface first.",
                    KB.peers_index(),
                )
                return

        body = {k: v for k, v in (st.get("data") or {}).items() if v != ""}
        payload = {**defaults, **body}

        try:
            count = int(payload.pop("count", "0") or "0")
        except Exception:
            count = 0
        if count <= 0:
            await send_text(update, "⊘ Invalid count.", KB.peers_index())
            return

        for k, _prompt, def_base in BULK_FIELDS:
            if k == "count":
                continue
            if (k not in payload) or (payload[k] is None) or (str(payload[k]).strip() == ""):
                if not ask_missing_profile:
                    if def_base not in (None, ""):
                        payload[k] = def_base

        payload = _payload_api(payload)

        base = (payload.pop("name", "") or payload.pop("base_name", "") or "").strip()
        if base:
            payload["base_name"] = base
            payload["name_prefix"] = base

        import re

        def _to_list(val):
            if val is None:
                return []
            if isinstance(val, list):
                return [str(x).strip() for x in val if str(x).strip()]
            return [s.strip() for s in re.split(r"[\n,]+", str(val)) if s.strip()]

        phones_raw = payload.pop("phone_numbers", payload.pop("phone_number", ""))
        tgs_raw    = payload.pop("telegram_ids",  payload.pop("telegram_id",  ""))

        phones = _to_list(phones_raw)
        tgs    = [s.lstrip("@") for s in _to_list(tgs_raw)]

        if phones:
            payload["phone_numbers"] = phones
        if tgs:
            payload["telegram_ids"] = tgs

        ok = False
        created = 0
        errors = 0

        if scope == "node":
            api_payload = dict(payload)
            api_payload.update(
                {
                    "scope": "node",
                    "node_id": int(node_id),
                    "iface_name": str(iface_name),
                    "count": int(count),
                }
            )

            r = _post(f"{PANEL}/api/peers/bulk", session="api", json=api_payload)
            j = _json_txt(r)

            ok = bool(isinstance(j, dict) and (j.get("created") or j.get("success") or j.get("ok")))
            created = int((j.get("created") if isinstance(j, dict) else 0) or 0)
            errors = 0  
        else:
            payload["iface_id"] = int(iface_id)
            res = bulk_create(iface_id, count, payload)
            if not isinstance(res, dict) or res.get("error"):
                err = (res.get("error") if isinstance(res, dict) else "bad_response")
                await edit_send(update,
                                f"⊘ Bulk failed.\n\n◇ Error: <code>{html(str(err))}</code>",
                                KB.home()
                )
                return
            ok = bool(res.get("ok"))
            created = int(res.get("created") or 0)
            errors = len(res.get("errors") or [])

        if scope == "node":
            iface_label = str(iface_name)
        else:
            try:
                iface_label = _iface_id().get(int(iface_id), str(iface_id))
            except Exception:
                iface_label = str(iface_id)

        summary = f"▦ Bulk create on <b>{html(iface_label)}</b>: <b>{created}</b> of <b>{count}</b> peers"
        if selected:
            summary += f"\n✦ Using profile: <b>{html(selected)}</b>"
        if base:
            summary += f"\n◇ Names: <code>{html(base)}1 … {html(base)}{count}</code>"
        if phones:
            summary += f"\n☎ Phone numbers mapped in order: <b>{len(phones)}</b>"
        if tgs:
            summary += f"\n✧ Telegram IDs mapped in order: <b>{len(tgs)}</b>"
        if errors:
            summary += f"\n⊘ Errors: <b>{errors}</b> (see panel logs for details)"
        if not ok and created <= 0:
            summary += "\n⊘ Bulk operation may have failed (check panel logs)."

        try:
            uid   = str(update.effective_user.id)
            uname = (update.effective_user.username or "") if update.effective_user else ""

            details = _peer_details(
                created=created,
                count=count,
                iface=iface_label,
                scope=scope,
                base=base or None
            )
            log_tg(uid, uname, "peer_bulk_create", details)
            log_admin(uid, uname, "peer_bulk_create", details)
        except Exception:
            pass

        context.user_data.pop(STATE["BULK"], None)
        await send_text(update, summary, KB.peers_index())
        return

    key, prompt, def_base = BULK_FIELDS[step]
    base_val = defaults.get(key, def_base)
    default = "" if base_val is None else str(base_val)

    show_profile = bool(selected)
    tag = f"\n✦ Using profile: <b>{html(selected)}</b>" if show_profile else "\n◇ Manual input"

    extra = ""
    if not selected and key in {"name", "base_name"}:
        default = ""

    if key == "phone_number":
        extra = "\n⌕ Tip: For bulk, use commas or new lines to assign per-peer phones in order (e.g. <code>0912..., 0935..., 0901...</code>)."
        if not selected:
            default = ""
    elif key == "telegram_id":
        extra = "\n↗ Tip: For bulk, use commas or new lines; leading <code>@</code> is optional (e.g. <code>@azumi, josh, @jackie</code>)."
        if not selected:
            default = ""

    breadcrumb = f"▦ Bulk ({step+1}/{len(BULK_FIELDS)})"
    hint = f"\n(default: <code>{html(default)}</code>)" if default != "" else ""
    kb = menu_kb("bulk", key, allow_skip=(key != "count"))
    await edit_send(update, f"{breadcrumb}{tag}\n{prompt}{hint}{extra}", kb)

async def edit_step(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get(STATE["EDIT"], {})
    step = st.get("step", 0)
    pid = st.get("pid")

    if step >= len(EDIT_FIELDS):
        body_raw = st.get("data", {})
        payload = _payload_api(body_raw)  
        if payload:
            update_peer(pid, payload)                   
        context.user_data.pop(STATE["EDIT"], None)
        await send_text(update, "● Saved.", KB.peers_index())
        return

    key, prompt, def_base = EDIT_FIELDS[step]
    default = "" if def_base is None else str(def_base)
    breadcrumb = f"◇ Edit ({step+1}/{len(EDIT_FIELDS)})"
    hint = f"\n(current: <code>{html(default)}</code>)" if default != "" else ""
    await edit_send(
        update,
        f"{breadcrumb}\n{prompt}{hint}\n\nSend '-' to cancel.",
        KB.back(f"peer:open:{pid}")
    )


# ____ Profile editor
PROFILE_FIELDS = [
    ("name",                 "Friendly name",                          ""),
    ("allowed_ips",          "Allowed IPs",                            ""),
    ("endpoint",             "Endpoint (host:port)",                   ""),
    ("persistent_keepalive", "Keepalive (s)",                          ""),
    ("mtu",                  "MTU",                                    ""),
    ("dns",                  "DNS",                                    ""),

    ("data_limit_value",     "Traffic limit value",                    ""),
    ("data_limit_unit",      "Unit (Mi/Gi)",                           "Mi"),

    ("time_limit_days",      "Active days",                            ""),
    ("time_limit_hours",     "Active hours (0–23)",                     ""),
    ("start_on_first_use",   "Start timer on first use (1/0)",          ""),
    ("unlimited",            "Unlimited (1/0)",                         ""),

    ("phone_number",         "Phone numbers (comma-separated for bulk)",""),
    ("telegram_id",          "Telegram IDs (comma-separated for bulk)",""),
]


def _fmt_bool(v):
    s = str(v).strip().lower()
    return "True" if s in {"1","true","yes","on"} else "False"

def profile_summary(pname: str) -> str:
    p = profile_get(pname) or {}
    is_def = (profile_default() == pname)
    scope = (p.get("use_for") or "both").lower()
    scope_txt = "Subscription profile" if scope == "subscription" else "Peer profile"

    def _phone_display():
        v = str(p.get("phone_number") or "").strip()
        if not v:
            arr = p.get("phone_numbers")
            if isinstance(arr, list) and arr:
                v = ", ".join(str(x) for x in arr if str(x).strip())
        return v

    def _tg_display():
        v = str(p.get("telegram_id") or "").strip()
        if not v:
            arr = p.get("telegram_ids")
            if isinstance(arr, list) and arr:
                v = ", ".join(str(x) for x in arr if str(x).strip())
        return v

    phone_label = "Phone number" if scope == "single" else "Phone numbers (bulk: comma-separated)"
    tg_label    = "Telegram ID"  if scope == "single" else "Telegram IDs (bulk: comma-separated)"

    labels = [
        ("name",                 "Friendly name",               lambda: str(p.get("name") or "")),
        ("allowed_ips",          "Allowed IPs",                 lambda: str(p.get("allowed_ips") or "")),
        ("endpoint",             "Endpoint (host:port)",        lambda: str(p.get("endpoint") or "")),
        ("persistent_keepalive", "Keepalive (s)",               lambda: str(p.get("persistent_keepalive") or "")),
        ("mtu",                  "MTU",                         lambda: str(p.get("mtu") or "")),
        ("dns",                  "DNS",                         lambda: str(p.get("dns") or "")),
        ("data_limit_value",     "Traffic limit value",         lambda: str(p.get("data_limit_value") or "")),
        ("data_limit_unit",      "Unit (Mi/Gi)",                lambda: str(p.get("data_limit_unit") or "Mi")),
        ("time_limit_days",      "Active days",                 lambda: str(p.get("time_limit_days") or "")),
        ("time_limit_hours",     "Active hours",                lambda: str(p.get("time_limit_hours") or "")),
        ("start_on_first_use",   "Start on first use",          lambda: "True" if str(p.get("start_on_first_use")).lower() in {"1","true","yes","on"} else "False"),
        ("unlimited",            "Unlimited",                   lambda: "True" if str(p.get("unlimited")).lower() in {"1","true","yes","on"} else "False"),
        ("phone_number",         phone_label,                   _phone_display),
        ("telegram_id",          tg_label,                      _tg_display),
    ]

    lines = [f"✦ <b>Profile:</b> {html(pname)}"]
    if is_def:
        lines.append("☆ default")
    lines.append(f"◆ <b>Scope:</b> {scope_txt}")

    for _key, label, getv in labels:
        val = getv()
        lines.append(f"<b>{html(label)}</b>: <code>{html(val)}</code>")

    return "\n".join(lines)


def kb_profile_editor(pname: str) -> InlineKeyboardMarkup:

    p = profile_get(pname) or {}
    scope = str(p.get("use_for", "single")).lower()

    phone_btn = "Phone number" if scope == "single" else "Phone numbers"
    tg_btn    = "Telegram ID"  if scope == "single" else "Telegram IDs"

    def B(label: str, cb: str) -> InlineKeyboardButton:
        return InlineKeyboardButton(label, callback_data=cb)

    rows = [
        [B("◇ Name", f"profiles:editkey:{pname}:name"),
         B("✦ Note", f"profiles:editkey:{pname}:note")],
        [B("◎ Allowed IPs", f"profiles:editkey:{pname}:allowed_ips"),
         B("⌁ Endpoint", f"profiles:editkey:{pname}:endpoint")],
        [B("⋄ Keepalive", f"profiles:editkey:{pname}:persistent_keepalive"),
         B("↔ MTU", f"profiles:editkey:{pname}:mtu")],
        [B("◉ DNS", f"profiles:editkey:{pname}:dns"),
         B("⌘ Internal networks", f"profiles:toggle:{pname}:include_internal_network")],
        [B("◫ Data limit", f"profiles:editkey:{pname}:data_limit_value"),
         B("◈ Unit", f"profiles:unit:{pname}")],
        [B("◷ Days", f"profiles:editkey:{pname}:time_limit_days"),
         B("◴ Hours", f"profiles:editkey:{pname}:time_limit_hours")],
        [B("◶ Minutes", f"profiles:editkey:{pname}:time_limit_minutes"),
         B("▷ First use", f"profiles:toggle:{pname}:start_on_first_use")],
        [B("∞ Unlimited", f"profiles:toggle:{pname}:unlimited"),
         B(phone_btn, f"profiles:editkey:{pname}:phone_number")],
        [B(tg_btn, f"profiles:editkey:{pname}:telegram_id"),
         B("⌘ Profile type", f"profiles:scope:{pname}")],
        [B("☆ Set default", f"profiles:setdef:{pname}"),
         B("⌫ Delete", f"profiles:del:{pname}")],
        [B("← Profiles", "profiles:menu")],
    ]

    return InlineKeyboardMarkup(rows)


async def profile_new_step(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get(STATE["P_NEW"])
    if st["name"] is None:
        await edit_send(update, "＋ Send a name for this profile.", KB.back("profiles:menu")); return

    step = st["step"]
    if step >= len(PROFILE_FIELDS):
        profile_set(st["name"], st["data"]) 
        await send_text(update, f"● Saved profile <b>{html(st['name'])}</b>.", KB.profiles_menu())
        context.user_data.pop(STATE["P_NEW"], None)
        return

    key, prompt, default = PROFILE_FIELDS[step]
    breadcrumb = f"＋ New profile ({step+1}/{len(PROFILE_FIELDS)})"
    hint = f"\n(default: <code>{html(str(default))}</code>)" if default != "" else ""

    await edit_send(
       update,
       f"{breadcrumb}\n{prompt}{hint}",
       KB.wizard(flow="pnew", allow_skip=(default != ""))
    )

async def profile_edit_process(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get(STATE["P_EDIT"]) 
    step = st["step"]

    if step >= len(PROFILE_FIELDS):
        current = st.get("defaults", {})
        newvals = {k: v for k,v in st["data"].items() if v != ""}
        profile_set(st["name"], {**current, **newvals})
        await send_text(update, f"● Updated profile <b>{html(st['name'])}</b>.", KB.profiles_menu())
        context.user_data.pop(STATE["P_EDIT"], None)
        return

    key, prompt, def_base = PROFILE_FIELDS[step]
    default = str(st.get("defaults", {}).get(key, def_base) or "")
    breadcrumb = f"◇ Edit profile <b>{html(st['name'])}</b> ({step+1}/{len(PROFILE_FIELDS)})"
    hint = f"\n(current: <code>{html(str(default))}</code>)" if default != "" else ""
    await edit_send(update, f"{breadcrumb}\n{prompt}{hint}\n\nSend '-' to cancel.", KB.back(f"profiles:open:{st['name']}"))

async def wizard_choose_node(update: Update):
    nodes = list_nodes()
    if not nodes:
        return await edit_send(update, "No nodes found or offline.", KB.peers_index())
    rows = [[InlineKeyboardButton(f"{n.get('name','node')} (id {n.get('id')})",
                                  callback_data=f"create:node:{n['id']}")] for n in nodes]
    rows.append([InlineKeyboardButton("← Back", callback_data="peers:create")])
    await edit_send(update, "Select node:", InlineKeyboardMarkup(rows))

async def wizard_bulk_node(update: Update):
    nodes = list_nodes()
    if not nodes:
        return await edit_send(update, "No nodes found or offline.", KB.peers_index())
    rows = [[InlineKeyboardButton(f"{n.get('name','node')} (id {n.get('id')})",
                                  callback_data=f"bulk:node:{n['id']}")] for n in nodes]
    rows.append([InlineKeyboardButton("← Back", callback_data="peers:bulk")])
    await edit_send(update, "Select node for bulk:", InlineKeyboardMarkup(rows))


@admin_only
async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()

    if await admin_azumi.handle_text(globals(), update, context):
        return

    stp1 = context.user_data.get(STATE.get("P_EDIT_ONE"))
    if stp1:
        pname = stp1["pname"]; key = stp1["key"]
        if text == "-":
            context.user_data.pop(STATE["P_EDIT_ONE"], None)
            await edit_send(update, profile_summary(pname), kb_profile_editor(pname))
            return

        val = text
        int_keys   = {"persistent_keepalive", "mtu", "data_limit_value", "time_limit_days", "time_limit_hours"}
        bool_keys  = {"start_on_first_use", "unlimited"}
        unit_keys  = {"data_limit_unit"}
        try:
            if key in int_keys:
                val = int(text)
            elif key in bool_keys:
                val = text.strip().lower() in {"1", "true", "yes", "on"}
            elif key in unit_keys:
                v = text.strip().capitalize()
                val = "Gi" if v.startswith("Gi") else "Mi"
        except Exception:
            await edit_send(update, "⊘ Invalid value type.", kb_profile_editor(pname))
            return

        p = profile_get(pname) or {}
        p[key] = val
        profile_set(pname, {k: v for k, v in p.items() if k in PROFILE_KEYS})

        context.user_data.pop(STATE["P_EDIT_ONE"], None)
        await edit_send(update, profile_summary(pname), kb_profile_editor(pname))
        return


    st1 = context.user_data.get(STATE.get("EDIT_ONE"))
    if st1:
        pid = st1["pid"]; key = st1["key"]
        if text == "-":
            context.user_data.pop(STATE["EDIT_ONE"], None)
            await _edit_menu(update, pid)
            return

        payload = _payload_api({key: text})
        try:
            update_peer(pid, payload)  
            await send_text(update, "● Saved.")
        except Exception as e:
            await send_text(update, f"⊘ {html(str(e))}")
        context.user_data.pop(STATE["EDIT_ONE"], None)
        await _edit_menu(update, pid)
        return


    if text == "-":
        for k in list(STATE.values()):
            context.user_data.pop(k, None)
        await send_text(update, "⊘ Cancelled.", KB.home())
        return

    stc = context.user_data.get(STATE.get("CREATE"))
    if stc:
        step = int(stc.get("step", 0))
        fields = stc.get("fields") or ADVANCED_CREATE_FIELDS
        if 0 <= step < len(fields):
            key, _prompt, _def = fields[step]
            stc["data"][key] = text  
            stc["step"] = step + 1
            context.user_data[STATE["CREATE"]] = stc
            await create_step(update, context)
            return

    stb = context.user_data.get(STATE.get("BULK"))
    if stb:
        step = int(stb.get("step", 0))
        if 0 <= step < len(BULK_FIELDS):
            key, _prompt, _def = BULK_FIELDS[step]
            stb["data"][key] = text
            stb["step"] = step + 1
            context.user_data[STATE["BULK"]] = stb
            await bulk_step(update, context)
            return

    stpnew = context.user_data.get(STATE.get("P_NEW"))
    if stpnew:
        name = text
        if not name:
            await send_text(update, "Please send a non-empty name or '-' to cancel.", KB.back("profiles:menu"))
            return
        if profile_get(name):
            await send_text(update, "⊘ A profile with that name already exists. Send another name or '-' to cancel.",
                            KB.back("profiles:menu"))
            return

        stpnew["name"] = name
        context.user_data[STATE["P_NEW"]] = stpnew

        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("◇ Peer profile", callback_data="profiles:new:type:peer")],
            [InlineKeyboardButton("⌘ Subscription profile", callback_data="profiles:new:type:subscription")],
            [InlineKeyboardButton("⊘ Cancel", callback_data="wiz:pnew:cancel"),
             InlineKeyboardButton("← Back", callback_data="profiles:menu")]
        ])
        await edit_send(update, f"＋ <b>{html(name)}</b>\nChoose the profile type:", kb)
        return

    stp = context.user_data.get(STATE.get("P_EDIT"))
    if stp:
        step = int(stp.get("step", 0))
        try:
            fields_seq = PROFILE_FIELDS 
        except Exception:
            fields_seq = [f for f in CREATE_FIELDS if f[0] != "count"]
        if 0 <= step < len(fields_seq):
            key, _prompt, _def = fields_seq[step]
            stp["data"][key] = text
            stp["step"] = step + 1
            context.user_data[STATE["P_EDIT"]] = stp
        await profile_edit_process(update, context)
        return

    if context.user_data.get(STATE.get("SEARCH")):
        term = text.lower()
        try:
            peers = list_peers(None)
        except Exception:
            peers = []
        matches = []
        for p in peers:
            name = str(p.get("name") or "")
            addr = str(p.get("address") or p.get("ip") or "")
            pk   = str(p.get("public_key") or "")
            if term in name.lower() or term in addr.lower() or term in pk.lower():
                pid = int(p.get("id"))
                label = f"{name or 'peer-'+str(pid)} (id {pid})"
                matches.append([
                    InlineKeyboardButton(label, callback_data=f"peer:open:{pid}"),
                    InlineKeyboardButton("⌫",  callback_data=f"peer:delete:{pid}")
                ])
        if not matches:
            matches = [[InlineKeyboardButton("No matches", callback_data="noop")]]
        matches.append([InlineKeyboardButton("← Back", callback_data="peers:menu")])
        await edit_send(update, f"⌕ Results for <b>{html(text)}</b>:", InlineKeyboardMarkup(matches))
        return

    await send_text(update, "◇ I didn't catch that. Use the buttons below.", KB.home())

async def on_doc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = context.user_data.get(STATE.get("BACKUP_RESTORE_WAIT"))
    if not st:
        return

    doc = getattr(getattr(update, "message", None), "document", None)
    if not doc:
        return

    filename = (doc.file_name or "").strip()
    if not filename.lower().endswith(".zip"):
        await update.message.reply_html("⊘ Please send a <b>.zip</b> file.")
        return

    try:
        tg_file = await context.bot.get_file(doc.file_id)
        data_bytes = await tg_file.download_as_bytearray()
        data_bytes = bytes(data_bytes)
    except Exception as e:
        _log_admin_update(update, "restore_download_failed", f"{type(e).__name__}: {e}")
        await update.message.reply_html("⊘ Failed to download the file from Telegram.")
        return

    restore_wg = "0"
    try:
        prefs_r = api.get(f"{PANEL}/api/backup/prefs", timeout=20)
        prefs = prefs_r.json() if prefs_r.ok else {}
        restore_wg = "1" if prefs.get("include_wg") else "0"
    except Exception:
        restore_wg = "0"

    kind = (st.get("kind") or "auto").lower()

    try:
        files = {"file": (filename, data_bytes, "application/zip")}
        form = {"kind": kind, "restore_wg": restore_wg}

        r = api.post(f"{PANEL}/api/backup/restore_api", data=form, files=files, timeout=60)
        preview = (r.text or "")[:400].replace("\n", "\\n")
        _log_admin_update(update, "restore_api_resp", f"status={r.status_code} ok={r.ok} body={preview}")

        try:
            j = r.json()
        except Exception:
            j = {"ok": False, "error": "non_json_response", "body_preview": preview, "status": r.status_code}

        if (not r.ok) or (not isinstance(j, dict)) or (not j.get("ok")):
            await update.message.reply_html(
                "⊘ <b>Restore failed</b>\n"
                f"<code>{html(str(j)[:800])}</code>"
            )
        else:
            restored = j.get("restored") or {}
            warnings = j.get("warnings") or []
            msg = (
                "● <b>Restore completed</b>\n"
                f"• Kind: <code>{html(str(j.get('kind','?')))}</code>\n"
                f"• DB: <b>{'YES' if restored.get('db') else 'NO'}</b>\n"
                f"• Settings: <b>{'YES' if restored.get('settings') else 'NO'}</b>\n"
                f"• WG conf: <b>{'YES' if restored.get('wg') else 'NO'}</b>\n"
            )
            if warnings:
                msg += "\n⊘ <b>Warnings</b>\n" + "\n".join(f"• <code>{html(str(w))}</code>" for w in warnings)

            msg += "\n\n<i>If services do not reflect changes, restart the panel and Wireguard services.</i>"
            await update.message.reply_html(msg)

    except Exception as e:
        _log_admin_update(update, "restore_api_error", f"{type(e).__name__}: {e}")
        await update.message.reply_html("⊘ Restore request failed. Check panel logs.")
    finally:
        context.user_data.pop(STATE["BACKUP_RESTORE_WAIT"], None)


async def start_create_with_profile(update: Update, context: ContextTypes.DEFAULT_TYPE, name: str):
    ifaces = peer_ifaces()
    rows = [[InlineKeyboardButton(f"{i['name']} (id {i['id']})", callback_data=f"create:iface:{i['id']}")] for i in ifaces]
    rows.append([InlineKeyboardButton("← Back", callback_data="profiles:menu")])
    context.user_data["_pending_profile_create"] = name
    await edit_send(update, f"＋ <b>Create</b> using profile <b>{html(name)}</b>\nChoose interface:", InlineKeyboardMarkup(rows))

async def start_bulk_with_profile(update: Update, context: ContextTypes.DEFAULT_TYPE, name: str):
    ifaces = peer_ifaces()
    rows = [[InlineKeyboardButton(f"{i['name']} (id {i['id']})", callback_data=f"bulk:iface:{i['id']}")] for i in ifaces]
    rows.append([InlineKeyboardButton("← Back", callback_data="profiles:menu")])
    context.user_data["_pending_profile_bulk"] = name
    await edit_send(update, f"▦ <b>Bulk</b> using profile <b>{html(name)}</b>\nChoose interface:", InlineKeyboardMarkup(rows))

def _state_get_int(st: dict, key: str, default: int = 0) -> int:
    try:
        return int(st.get(key) or default)
    except Exception:
        return default


TELEGRAM_ADMINS_FILE = INSTANCE_DIR / "telegram_admins.json"
def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _notify_app(
    event_key: str,
) -> bool:
    """
    Return whether a panel availability notification is enabled.

    Supported keys:
        app_down
        app_up
    """
    settings = _read_json(
        TELEGRAM_SETTINGS_FILE,
        {},
    )

    if not bool(
        settings.get(
            "enabled",
            False,
        )
    ):
        return False

    notify = (
        settings.get("notify")
        or {}
    )

    defaults = {
        "app_down": True,
        "app_up": True,
    }

    event_key = str(
        event_key or ""
    ).strip()

    if event_key not in defaults:
        return False

    return bool(
        notify.get(
            event_key,
            defaults[event_key],
        )
    )

def _admin_unmuted() -> list[str]:
    admins = _read_json(TELEGRAM_ADMINS_FILE, [])
    out = []
    for a in admins:
        tg_id = str(a.get("id") or a.get("tg_id") or "").strip()
        if tg_id.isdigit() and not bool(a.get("muted", False)):
            out.append(tg_id)
    return out

async def _panel_watchdog(
    stop_event: asyncio.Event,
    bot,
):
    interval_sec = 20
    fail_threshold = 3

    fails = 0
    was_down = False
    down_since = None
    last_error = ""

    def utc_now_text() -> str:
        return datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

    def duration_text(
        seconds: float,
    ) -> str:
        seconds = max(
            0,
            int(seconds or 0),
        )

        days, remainder = divmod(
            seconds,
            86400,
        )

        hours, remainder = divmod(
            remainder,
            3600,
        )

        minutes, secs = divmod(
            remainder,
            60,
        )

        parts = []

        if days:
            parts.append(
                f"{days}d"
            )

        if hours or days:
            parts.append(
                f"{hours}h"
            )

        if minutes or hours or days:
            parts.append(
                f"{minutes}m"
            )

        parts.append(
            f"{secs}s"
        )

        return " ".join(parts)

    async def broadcast(
        text: str,
    ) -> int:
        chat_ids = list(
            _admin_unmuted()
            or []
        )

        if not chat_ids:
            logging.error(
                "Panel watchdog has no unmuted Telegram "
                "administrators. INSTANCE_DIR=%s",
                INSTANCE_DIR,
            )
            return 0

        delivered = 0

        for chat_id in chat_ids:
            try:
                await bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )

                delivered += 1

                logging.info(
                    "Panel watchdog alert delivered "
                    "to chat_id=%s",
                    chat_id,
                )

            except Exception:
                logging.exception(
                    "Could not deliver panel watchdog "
                    "alert to chat_id=%s",
                    chat_id,
                )

        if delivered == 0:
            logging.error(
                "Panel watchdog alert was not delivered "
                "to any configured administrator."
            )

        return delivered

    logging.info(
        "Panel watchdog started: panel=%s "
        "interval=%ss threshold=%s",
        PANEL,
        interval_sec,
        fail_threshold,
    )

    while not stop_event.is_set():
        ok = False
        error_text = ""
        status_code = None

        try:
            response = await asyncio.to_thread(
                _get,
                f"{PANEL}/api/healthz",
                session=(
                    "api"
                    if API_KEY
                    else "auto"
                ),
                timeout=6,
            )

            status_code = int(
                response.status_code
            )

            ok = (
                status_code == 200
            )

            if not ok:
                error_text = (
                    f"HTTP {status_code}"
                )

        except Exception as exc:
            error_text = (
                f"{type(exc).__name__}: {exc}"
            )

            ok = False

        if ok:
            if fails:
                logging.info(
                    "Panel watchdog health check recovered "
                    "after %s failed check(s).",
                    fails,
                )

            fails = 0
            last_error = ""

            if was_down:
                outage = (
                    time.monotonic()
                    - down_since
                    if down_since is not None
                    else 0
                )

                logging.info(
                    "Panel recovered: panel=%s outage=%s",
                    PANEL,
                    duration_text(outage),
                )

                if _notify_app("app_up"):
                    await broadcast(
                        "● <b>Panel is back online</b>\n\n"
                        "◇ <b>Status</b>  Healthy\n"
                        f"⌁ <b>Panel</b>  "
                        f"<code>{html(PANEL)}</code>\n"
                        f"◷ <b>Recovered</b>  "
                        f"<code>{utc_now_text()}</code>\n"
                        f"↥ <b>Outage</b>  "
                        f"<code>{duration_text(outage)}</code>\n\n"
                        "The authenticated health check is "
                        "responding normally again."
                    )

                else:
                    logging.warning(
                        "Panel recovery detected, but app is up "
                        "notifications are disabled."
                    )

                was_down = False
                down_since = None

        else:
            fails += 1

            last_error = (
                error_text
                or last_error
                or "Health check failed"
            )

            logging.warning(
                "Panel watchdog check failed %s/%s: "
                "panel=%s status=%s error=%s",
                fails,
                fail_threshold,
                PANEL,
                status_code,
                last_error,
            )

            if (
                not was_down
                and fails >= fail_threshold
            ):
                was_down = True
                down_since = time.monotonic()

                logging.error(
                    "Panel declared unavailable after "
                    "%s failed checks: panel=%s error=%s",
                    fails,
                    PANEL,
                    last_error,
                )

                if _notify_app("app_down"):
                    await broadcast(
                        "⊘ <b>Panel availability alert</b>\n\n"
                        "◇ <b>Status</b>  Unreachable\n"
                        f"⌁ <b>Panel</b>  "
                        f"<code>{html(PANEL)}</code>\n"
                        f"◷ <b>Detected</b>  "
                        f"<code>{utc_now_text()}</code>\n"
                        f"↻ <b>Checks failed</b>  "
                        f"<code>{fails}</code>\n"
                        f"✦ <b>Last error</b>  "
                        f"<code>{html(last_error[:500])}</code>\n\n"
                        f"The bot will retry every "
                        f"{interval_sec} seconds and report "
                        "recovery automatically."
                    )

                else:
                    logging.warning(
                        "Panel outage detected, but app_down "
                        "notifications are disabled."
                    )

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=interval_sec,
            )

        except asyncio.TimeoutError:
            pass

        except asyncio.CancelledError:
            logging.info(
                "Panel watchdog task cancelled."
            )
            raise

        except Exception:
            logging.exception(
                "Unexpected error while waiting in "
                "panel watchdog loop."
            )

    logging.info(
        "Panel watchdog stopped."
    )

HB_SEC = max(15, int(os.getenv("TG_HEARTBEAT_SEC", "60") or "60"))

async def _heartbeat_loop(stop_event: asyncio.Event):
    """Publish an immediate heartbeat, then continue at the configured interval."""

    if not API_KEY and not USE_PANEL_SESSION:
        logging.warning(
            "Heartbeat disabled: set PANEL_API_KEY/API_KEY or enable "
            "USE_PANEL_SESSION=1."
        )
        return

    consecutive_failures = 0

    while not stop_event.is_set():
        try:
            if API_KEY:
                response = await asyncio.to_thread(
                    api.post,
                    f"{PANEL}/api/telegram/heartbeat",
                    json={
                        "pid": os.getpid(),
                        "version": BOT_VERSION,
                        "panel": PANEL,
                        "service": "wg-panel-telegram",
                    },
                    timeout=12,
                )
            else:
                await asyncio.to_thread(_login_session)
                response = await asyncio.to_thread(
                    sess.post,
                    f"{PANEL}/api/telegram/heartbeat",
                    json={
                        "pid": os.getpid(),
                        "version": BOT_VERSION,
                        "panel": PANEL,
                        "service": "wg-panel-telegram",
                    },
                    headers=csrf_headers(),
                    timeout=12,
                )

            response.raise_for_status()
            consecutive_failures = 0

        except Exception as exc:
            consecutive_failures += 1
            detail = ""
            response_obj = getattr(exc, "response", None)
            if response_obj is not None:
                try:
                    detail = (
                        f" HTTP {response_obj.status_code}: "
                        f"{(response_obj.text or '')[:300]}"
                    )
                except Exception:
                    detail = ""

            log_fn = logging.warning if consecutive_failures <= 3 else logging.error
            log_fn(
                "Telegram heartbeat failed (%s consecutive): %s%s",
                consecutive_failures,
                exc,
                detail,
            )

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=HB_SEC,
            )
        except asyncio.TimeoutError:
            pass


async def on_error(update, context):
    logging.exception("Unhandled bot error: %s", getattr(context, "error", None))

def _spawn(name: str, coro):
    task = asyncio.create_task(
        coro,
        name=name,
    )

    def _task_finished(done_task: asyncio.Task):
        try:
            exception = done_task.exception()

        except asyncio.CancelledError:
            return

        except Exception:
            logging.exception(
                "Could not inspect background task %s",
                name,
            )
            return

        if exception is not None:
            logging.error(
                "Background task %s stopped unexpectedly",
                name,
                exc_info=(
                    type(exception),
                    exception,
                    exception.__traceback__,
                ),
            )

        else:
            logging.warning(
                "Background task %s exited unexpectedly without an exception",
                name,
            )

    task.add_done_callback(
        _task_finished
    )

    return task

TG_BACKUP_TICK_SEC = 30
TG_BACKUP_SCHEDULER_ENABLED = os.getenv("TG_BACKUP_SCHEDULER_ENABLED", "0") == "1"  

def _bot_tz_schedule(sched: dict):
    from datetime import timezone
    try:
        from zoneinfo import ZoneInfo
        tzname = (sched.get("timezone") or "UTC").strip()
        return ZoneInfo(tzname)
    except Exception:
        return timezone.utc


def _hhmm(s: str):
    try:
        hh, mm = (s or "").strip().split(":")
        h, m = int(hh), int(mm)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h, m
    except Exception:
        pass
    return 3, 0  


def _days_month(y: int, m: int) -> int:
    import calendar
    return calendar.monthrange(y, m)[1]

def _load_tg_backup_state() -> dict:
    f = INSTANCE_DIR / "tg_backup_state.json"
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_tg_backup_state(st: dict) -> None:
    f = INSTANCE_DIR / "tg_backup_state.json"
    try:
        f.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _fetch_schedule_from_panel() -> dict:
    try:
        return _get(f"{PANEL}/api/backup/schedule", session="api").json()
    except Exception:
        return {}


async def _run_storebackup(sched: dict, *, reason: str | None = None) -> tuple[bool, str]:

    include_wg       = bool(sched.get("include_wg", True))
    send_to_telegram = bool(sched.get("send_to_telegram", False))

    wg = "1" if include_wg else "0"
    tg = "1" if send_to_telegram else "0"

    url = f"{PANEL}/api/backup/full?auto=1&wg={wg}&tg={tg}"

    reason_str = reason or "unspecified"

    try:
        r = _get(url, session="api", timeout=900, stream=True)
        try:
            info = "ok"

            ctype = (r.headers.get("content-type") or "").lower()

            if "application/json" in ctype:
                try:
                    j = r.json()
                    info = (
                        j.get("file")
                        or j.get("filename")
                        or j.get("path")
                        or j.get("message")
                        or "ok"
                    )
                except Exception:
                    info = "ok"

            cd = r.headers.get("content-disposition") or ""
            if "filename=" in cd.lower():
                part = cd.split("filename=", 1)[1].strip()
                if part.startswith('"') and '"' in part[1:]:
                    info = part.split('"', 2)[1]
                else:
                    info = part.split(";", 1)[0].strip().strip('"').strip("'")

            if getattr(r, "ok", True) is False:
                info = f"http {getattr(r, 'status_code', '??')}"

            return True, info
        finally:
            try:
                r.close()
            except Exception:
                pass

    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _schedule_due(sched: dict, now_ts: int) -> tuple[str | None, str | None]:
    """
    Returns (slot_id, due_local_iso) for the most recent scheduled occurrence <= now,
    but only if it's within a reasonable catch-up window (so you don't fire ancient missed runs).

    slot_id is stable per slot, so you can do once-per-slot with st["last_slot_id"].
    """
    try:
        from datetime import datetime, timedelta, timezone
        from calendar import monthrange

        tz = _bot_tz_schedule(sched)

        freq = str(sched.get("freq") or "daily").lower()
        hhmm = str(sched.get("time") or "03:00")
        dom  = int(sched.get("dom") or 1)
        dows = sched.get("dow") or []

        try:
            dows = [int(x) for x in dows]
        except Exception:
            dows = []

        CATCHUP_MAX_SEC = 36 * 3600  

        def parse_hhmm(s: str) -> tuple[int, int]:
            try:
                a, b = s.split(":")
                return int(a), int(b)
            except Exception:
                return 3, 0

        hh, mm = parse_hhmm(hhmm)

        now_utc   = datetime.fromtimestamp(int(now_ts), tz=timezone.utc)
        now_local = now_utc.astimezone(tz)

        def at_local(d: datetime) -> datetime:
            return d.replace(hour=hh, minute=mm, second=0, microsecond=0)

        due_local = None

        if freq == "daily":
            cand = at_local(now_local)
            if cand > now_local:
                cand -= timedelta(days=1)
            due_local = cand

        elif freq == "weekly":
            if not dows:
                dows = [1]  

            base_today = at_local(now_local)
            for back in range(0, 8):
                cand = base_today - timedelta(days=back)
                if cand.weekday() in dows and cand <= now_local:
                    due_local = cand
                    break

        elif freq == "monthly":
            dom = max(1, min(31, int(dom)))
            y, m = now_local.year, now_local.month

            day_this = min(dom, monthrange(y, m)[1])
            cand = at_local(now_local.replace(day=day_this))
            if cand > now_local:
                if m == 1:
                    y, m = y - 1, 12
                else:
                    m -= 1
                day_prev = min(dom, monthrange(y, m)[1])
                cand = at_local(now_local.replace(year=y, month=m, day=day_prev))
            due_local = cand

        else:
            return (None, None)

        if not due_local:
            return (None, None)

        age_sec = int((now_local - due_local).total_seconds())
        if age_sec < 0 or age_sec > CATCHUP_MAX_SEC:
            return (None, None)

        slot_id = f"{freq}:{due_local.strftime('%Y-%m-%dT%H:%M')}@{str(tz)}"
        return (slot_id, due_local.isoformat(timespec="seconds"))

    except Exception:
        return (None, None)


async def _backup_scheduler(stop_event: asyncio.Event, reason: str = "tick") -> None:

    if stop_event.is_set():
        return

    sched = _backup_schedule()
    st    = _load_backup_state()
    now_ts = int(time.time())

    test_fire_at = _state_get_int(st, "test_fire_at", 0)
    test_fired   = _state_get_int(st, "test_fired_at", 0)

    if test_fire_at and now_ts >= test_fire_at and test_fired < test_fire_at:
        ok, info = await _run_storebackup(sched or {}, reason="test_timer")
        st["test_fired_at"]  = now_ts
        st["test_last_ok"]   = bool(ok)
        st["test_last_info"] = info
        _save_backup_state(st)
        return

    if not bool((sched or {}).get("enabled", False)):
        return

    slot_id, due_local_iso = _schedule_due(sched, now_ts)
    if not slot_id:
        return

    if st.get("last_slot_id") == slot_id:
        return

    ok, info = await _run_storebackup(sched, reason=reason)

    st["last_slot_id"]         = slot_id
    st["last_slot_due_local"]  = due_local_iso
    st["last_slot_fired_at"]   = now_ts
    st["last_slot_ok"]         = bool(ok)
    st["last_slot_info"]       = info

    st["last_fired_for"] = now_ts

    _save_backup_state(st)



async def _backup_scheduler_loop(stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            await _backup_scheduler(stop_event, reason="loop")
            await asyncio.wait_for(stop_event.wait(), timeout=25)
        except asyncio.TimeoutError:
            continue
        except Exception:
            logging.exception("Backup scheduler loop error")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=25)
            except Exception:
                pass


async def _admin_refresh_loop(stop_event: asyncio.Event):
    while not stop_event.is_set():
        try: await asyncio.to_thread(_refresh_admin, True)
        except Exception as exc: logging.warning("Admin refresh failed: %s", exc)
        try: await asyncio.wait_for(stop_event.wait(), timeout=90)
        except asyncio.TimeoutError: pass

async def _on_startup(application):
    stop_event=application.bot_data.get("stop_event") or asyncio.Event(); application.bot_data["stop_event"]=stop_event
    tasks=[_spawn("admin_refresh",_admin_refresh_loop(stop_event)),_spawn("heartbeat",_heartbeat_loop(stop_event)),_spawn("panel_watchdog",_panel_watchdog(stop_event,application.bot))]
    if TG_BACKUP_SCHEDULER_ENABLED: tasks.append(_spawn("backup_scheduler",_backup_scheduler_loop(stop_event)))
    else: logging.info("Telegram backup scheduler disabled; the panel app scheduler is authoritative.")
    application.bot_data["background_tasks"]=tasks

async def _on_shutdown(application):
    stop_event = application.bot_data.get(
        "stop_event"
    )

    if stop_event:
        stop_event.set()

    monitors = list(
        application.bot_data.get(
            "update_monitors"
        )
        or []
    )

    for task in monitors:
        task.cancel()

    tasks = (
        application.bot_data.get(
            "background_tasks"
        )
        or []
    )

    all_tasks = [
        *tasks,
        *monitors,
    ]

    if all_tasks:
        _, pending = await asyncio.wait(
            all_tasks,
            timeout=8,
        )

        for task in pending:
            task.cancel()

@admin_only
async def cmd_peers(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    await send_text(
        update,
        (
            "◇ <b>Peers</b>\n"
            "<i>Create, search, inspect, and manage WireGuard peers.</i>"
        ),
        kb=KB.peers_index(),
    )


@admin_only
async def cmd_profiles(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    await send_text(
        update,
        (
            "✦ <b>Peer profiles</b>\n"
            "<i>Manage reusable settings for peer creation.</i>"
        ),
        kb=KB.profiles_menu(),
    )


@admin_only
async def cmd_backups(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    update.callback_query = None

    await send_text(
        update,
        (
            "▣ <b>Backups</b>\n"
            "<i>Open backup management from the button below.</i>"
        ),
        kb=InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "▣ Open backups",
                    callback_data="backup:menu",
                )
            ],
            [
                InlineKeyboardButton(
                    "⌂ Main menu",
                    callback_data="home:main",
                )
            ],
        ]),
    )


@admin_only
async def cmd_admin_panel(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):
    await send_text(
        update,
        (
            "♙ <b>Administrators</b>\n"
            "<i>View and manage authorized Telegram administrators.</i>"
        ),
        kb=InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "♙ Open administrators",
                    callback_data="home:admins",
                )
            ],
            [
                InlineKeyboardButton(
                    "⌂ Main menu",
                    callback_data="home:main",
                )
            ],
        ]),
    )

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    token = load_bot_token()

    if not token:
        raise SystemExit(
            "Missing bot token. "
            "Save it in Panel → Settings → Telegram."
        )

    if not API_KEY and not USE_PANEL_SESSION:
        raise SystemExit(
            "Missing PANEL_API_KEY/API_KEY. "
            "The bot requires the panel API key."
        )

    logging.info(
        "Starting WG Panel Telegram bot %s",
        BOT_VERSION,
    )

    logging.info(
        "Panel API target: %s",
        PANEL,
    )

    application = (
        Application.builder()
        .token(token)
        .post_init(_on_startup)
        .post_shutdown(_on_shutdown)
        .build()
    )

    application.add_error_handler(
        on_error
    )

    application.add_handler(
        CommandHandler(
            [
                "start",
                "menu",
                "home",
                "help",
            ],
            start,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "peers",
                "peer",
            ],
            cmd_peers,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "profiles",
                "profile",
            ],
            cmd_profiles,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "subscriptions",
                "subscription",
                "subs",
            ],
            cmd_subscriptions,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "clients",
                "client",
            ],
            cmd_clients,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "backup",
                "backups",
            ],
            cmd_backups,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "status",
                "dashboard",
            ],
            cmd_status,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "updates",
                "update",
            ],
            cmd_updates,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "settings",
                "setting",
            ],
            cmd_settings,
        )
    )

    application.add_handler(
        CommandHandler(
            "id",
            cmd_id,
        )
    )

    application.add_handler(
        CommandHandler(
            [
                "admins",
                "administrators",
            ],
            cmd_admins,
        )
    )

    application.add_handler(
        CommandHandler(
            "reload_admins",
            cmd_reload_admins,
        )
    )

    application.add_handler(
        CallbackQueryHandler(
            on_cb
        )
    )

    application.add_handler(
        MessageHandler(
            filters.Document.ALL,
            on_doc,
        )
    )

    application.add_handler(
        MessageHandler(
            filters.TEXT
            & ~filters.COMMAND,
            on_text,
        )
    )

    root_logger = logging.getLogger()

    if not any(
        isinstance(
            handler,
            PanelLogHandler,
        )
        for handler in root_logger.handlers
    ):
        panel_handler = PanelLogHandler(
            admin_id="bot",
            admin_username="bot",
        )

        panel_handler.setFormatter(
            logging.Formatter(
                "%(name)s - %(message)s"
            )
        )

        root_logger.addHandler(
            panel_handler
        )

    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=False,
        close_loop=True,
    )

if __name__ == "__main__":
    main()
