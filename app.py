#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scripts.postgres_restore import startup_guard
startup_guard()

if __name__ == "__main__":
    from scripts.startup_upgrade import startup_gate
    startup_gate()

from services.subscription_service import (
    SUBSCRIPTION_LAYOUTS,
    SUBSCRIPTION_LAYOUT_ALIASES,
    _sub_bool,
    _sub_float,
    _sub_int,
    _subscription_settings_default,
    _subscription_portal_icons,
    _subscription_portal_icon,
    _subscription_text,
    _subscription_choice,
    _subscription_number,
    _normalize_subscription_settings,
    _sub_limit_bytes,
    _sub_ttl_seconds,
)

from services.wireguard_service import (
    _host_peer,
    iface_devname,
    _WG_KEY_RE,
    _valid_wg_key,
    _node_id_from_iface,
    _assign_iface_public_key,
    _wg_transfer,
    _wg_rx_tx,
    _wg_transfer_bytes,
    _wg_handshake,
    _wireguard_endpoint,
    _wireguard_runtime_endpoint,
    _wg_enable,
    _wg_disable,
    _blackhole,
    _unblackhole,
    _iface_up,
    _run_capture,
    _peer_in_conf,
    _norm_conftext,
    _write_conf_atomic,
    _wg_peer_keys,
    _latest_handshake,
    _iface_down,
    _wireguard_network,
    _read_iface_conf,
)

from services.peer_service import (
    MAX_ENUMERATED_HOSTS,
    AddressAllocationError,
    AddressInvalid,
    AddressConflict,
    AddressPoolExhausted,
    PeerRemovalError,
    _first_cidr,
    _safe_ip,
    _wg_allowed_ips,
    _conf_allowed_ips,
    _iface_is_node,
    _usable_hosts,
    _validate_requested_host,
    peer_address_host,
    _peer_ip_plain,
)

from panel_core.http_security_values import (
    _http_security_int,
    _http_security_normalize_networks,
    _http_security_normalize_ip,
    _http_security_network_contains,
    _suspicious_4xx_ignored_path,
    _http_security_classify,
    _http_security_scope_applies,
)

from panel_core.traffic_values import (
    _traffic_clean_iface,
    _traffic_host_addresses,
    _traffic_normalize_destination,
    _traffic_parse_cidrs,
)

from panel_core.notification_values import (
    _tg_human_bytes,
    _tg_human_duration,
    _tg_parse_datetime,
    _tg_human_delta,
)

from panel_core.log_values import (
    _app_log_timestamp_utc,
    _app_log_line,
)

from panel_core.backup_schedule import (
    _next_run,
    _cron_field_match,
    _backup_due_slot,
)

from panel_core.endpoint_values import (
    EndpointValidationError,
    _parse_endpoint_host,
    _parse_endpoint_port,
    parse_endpoint_override,
    parse_endpoint_string,
    _host_port,
    _norm_hostport,
)

from panel_core.customer_timers import (
    now_ts,
    to_ts,
    from_ts,
    add_days_ts,
    _timer_duration_days,
    _timer_anchor_ts,
    _effective_expiry_ts,
    _sync_effective_expiry,
    _start_timer_cycle,
    _clear_timer_cycle,
    isoz,
    _conv_time_limit,
)

from panel_core.qr import PNGImage
from panel_core.private_json import save_private_json as _json_save
import os, glob, subprocess, time, shlex, logging, ipaddress, psutil, requests, json, tempfile, sys, zipfile, datetime as dt, platform, re, qrcode, multiprocessing, threading, shutil, signal
from io import BytesIO
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from flask import (
    Flask, render_template, redirect, url_for, flash, request,
    jsonify, abort, current_app, make_response, send_file, session, g
)

from sqlalchemy.exc import OperationalError, IntegrityError
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from functools import wraps
from contextlib import contextmanager
import fcntl
import socket
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from dotenv import load_dotenv
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH      = os.path.join(INSTANCE_DIR, "wg_panel.db")
load_dotenv(os.path.join(BASE_DIR, '.env'))
from config import Config
import time as _geo_time
from urllib.parse import urlparse as _geo_urlparse
from models import (
    db,
    InterfaceConfig,
    Peer,
    PeerEvent,
    Node,
    Admin2FA,
    AdminAccount,
    Subscription,
    SubscriptionPeer,
    ShortLink,
)
from forms import PeerForm
from auth import require_api_key, admin_required, require_api_key_or_login
from panel_core.security import hash_recovery, verify_recovery, generate_recovery_codes as _gen_recovery
from panel_core.profiles import register_profile_routes, panel_default_dns as _panel_default_dns
from panel_core.subscription_policy import compute_subscription_access, effective_peer_state
from panel_core import node_client as _node_client
from scripts.deployment import lock_active as _deployment_lock_active
from panel_core.auth_security import bind_session, session_valid, consume_admin_factor, csrf_required, match_secret
from panel_core.health_center import build_health_center
from panel_operations.peer_diagnostics import diagnose_peer
from sqlalchemy import or_, and_, text, inspect, func, event
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from wtforms.validators import ValidationError
from urllib.parse import urlparse, urljoin
import secrets
import pyotp
import bcrypt
from werkzeug.exceptions import HTTPException
from panel_core.trusted_proxy import TrustedProxy, safe_path


from backend.context import RuntimeContext
from backend import database_migrations as _database_migrations_backend
from backend import http_middleware as _http_middleware_backend
from backend import node_runtime as _node_runtime_backend
from backend import log_runtime as _log_runtime_backend
from backend import update_runtime as _update_runtime_backend
from backend import http_security as _http_security_backend
from backend import node_monitor as _node_monitor_backend
from backend import security_notifications as _security_notifications_backend
from backend import backup_scheduler as _backup_scheduler_backend
from backend import runtime_settings as _runtime_settings_backend
from backend import wireguard_runtime as _wireguard_runtime_backend
from backend import peer_runtime as _peer_runtime_backend
from backend import panel_settings as _panel_settings_backend
from backend import expiry_enforcement as _expiry_enforcement_backend
from backend import bootstrap as _bootstrap_backend
from backend import firewall_runtime as _firewall_runtime_backend
from backend import subscription_runtime as _subscription_runtime_backend

_backend_context = RuntimeContext(globals())


def _project_version() -> str:

    version_file = Path(BASE_DIR) / "VERSION"

    try:
        value = (
            version_file
            .read_text(encoding="utf-8")
            .strip()
            .lstrip("vV")
        )

        if value and re.fullmatch(
            r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?",
            value,
        ):
            return value

        logging.getLogger(__name__).warning(
            "Invalid VERSION file value: %r",
            value,
        )

    except FileNotFoundError:
        logging.getLogger(__name__).warning(
            "VERSION file was not found: %s",
            version_file,
        )

    except Exception:
        logging.getLogger(__name__).exception(
            "Could not read VERSION file"
        )

    return "0.0.0"


PANEL_VERSION = _project_version()
PANEL_REPO = "Azumi67/WG_Panel"
PANEL_UPDATE_TTL = 1800
_PANEL_UPDATE_CACHE = {
    "ts": 0,
    "data": None,
}

app = Flask(__name__)
app.wsgi_app = TrustedProxy(app.wsgi_app)


def _ssl_context():

    import ssl, os
    s = _load_panel_settings() or {}
    cert = (s.get('tls_cert_path') or '').strip()
    key  = (s.get('tls_key_path')  or '').strip()

    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
    return None


_bound = _database_migrations_backend.bind_admin_columns(_backend_context)
_admin_columns = _bound['_admin_columns']
_migrate_shortlinks_json_to_db = _bound['_migrate_shortlinks_json_to_db']
del _bound


class SchemaMigrationError(RuntimeError):
    pass


_bound = _database_migrations_backend.bind_shortlink_schema(_backend_context)
_shortlink_schema = _bound['_shortlink_schema']
_peer_schema = _bound['_peer_schema']
_backfill_peer_address_hosts = _bound['_backfill_peer_address_hosts']
_interface_schema = _bound['_interface_schema']
del _bound

_bootstrap_backend.configure_application(_backend_context)
configure_database = _backend_context.namespace['configure_database']

_bound = _http_middleware_backend.bind_effective_dns(_backend_context)
_effective_dns = _bound['_effective_dns']
del _bound


_log_runtime_backend.initialize_paths(_backend_context)
LOG_LEVEL = _backend_context.namespace['LOG_LEVEL']
APP_LOG_FILE = _backend_context.namespace['APP_LOG_FILE']
_WORKER_LOG_ROLES = _backend_context.namespace['_WORKER_LOG_ROLES']
_worker_log_role = _backend_context.namespace['_worker_log_role']
APP_LOG_WRITE_FILE = _backend_context.namespace['APP_LOG_WRITE_FILE']

_bound = _http_middleware_backend.bind_application_log_paths(_backend_context)
_application_log_paths = _bound['_application_log_paths']
_utc_log_formatter = _bound['_utc_log_formatter']
del _bound

_log_runtime_backend.initialize_app_logger(_backend_context)

app.config["PROPAGATE_EXCEPTIONS"] = True

_bound = _http_middleware_backend.bind_unhandled(_backend_context)
_unhandled = _bound['_unhandled']
del _bound

_log_runtime_backend.initialize_root_logging(_backend_context)

app.config["WTF_CSRF_CHECK_DEFAULT"] = False
csrf = CSRFProtect(app)
from reseller_portal import init_app as init_reseller_portal
init_reseller_portal(app, globals())
from panel_core.assets import install_asset_revisions
install_asset_revisions(app)

_bound = _http_middleware_backend.bind_csrf_protect_ui(_backend_context)
_csrf_protect_ui = _bound['_csrf_protect_ui']
del _bound


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(Config.SECURE_COOKIES),
    REMEMBER_COOKIE_SECURE=bool(Config.SECURE_COOKIES),
)

_bound = _http_middleware_backend.bind_inject_nav_flags(_backend_context)
inject_nav_flags = _bound['inject_nav_flags']
inject_panel_timezone = _bound['inject_panel_timezone']
del _bound


_original_cookie_secure = app.session_interface.get_cookie_secure

_bound = _http_middleware_backend.bind_request_cookie_secure(_backend_context)
_request_cookie_secure = _bound['_request_cookie_secure']
del _bound

app.session_interface.get_cookie_secure = _request_cookie_secure

_bound = _http_middleware_backend.bind_log_request(_backend_context)
_log_request = _bound['_log_request']
cache_headers = _bound['cache_headers']
inject_sec_headers = _bound['inject_sec_headers']
_https_redirect = _bound['_https_redirect']
_maybe_hsts = _bound['_maybe_hsts']
security_headers = _bound['security_headers']
del _bound

_bound = _node_runtime_backend.bind_http_url(_backend_context)
_http_url = _bound['_http_url']
_safe_url = _bound['_safe_url']
_norm_base_url = _bound['_norm_base_url']
_validate_node_base_url = _bound['_validate_node_base_url']
del _bound


_node_runtime_backend.initialize_node_encryption(_backend_context)
_fernet = _backend_context.namespace['_fernet']
FERNET_KEY = _backend_context.namespace['FERNET_KEY']
fernet = _backend_context.namespace['fernet']

_bound = _node_runtime_backend.bind_probably_encrypt(_backend_context)
_probably_encrypt = _bound['_probably_encrypt']
_probably_decrypt = _bound['_probably_decrypt']
_read_api_key = _bound['_read_api_key']
del _bound


_log_runtime_backend.initialize_telegram_paths(_backend_context)
TELEGRAM_ADMINS_FILE = _backend_context.namespace['TELEGRAM_ADMINS_FILE']
TELEGRAM_SETTINGS_FILE = _backend_context.namespace['TELEGRAM_SETTINGS_FILE']
TELEGRAM_LOG_FILE = _backend_context.namespace['TELEGRAM_LOG_FILE']
TELEGRAM_ADMIN_LOG_FILE = _backend_context.namespace['TELEGRAM_ADMIN_LOG_FILE']
ADMIN_LOG_FILE = _backend_context.namespace['ADMIN_LOG_FILE']
TELEGRAM_HB_FILE = _backend_context.namespace['TELEGRAM_HB_FILE']
LOGS_SETTINGS_FILE = _backend_context.namespace['LOGS_SETTINGS_FILE']

_bound = _log_runtime_backend.bind_read_admin_logs(_backend_context)
_read_admin_logs = _bound['_read_admin_logs']
_whoami_logs = _bound['_whoami_logs']
_load_log_settings = _bound['_load_log_settings']
_save_log_settings = _bound['_save_log_settings']
_src_defaults = _bound['_src_defaults']
_load_retention = _bound['_load_retention']
_save_retention = _bound['_save_retention']
_last_cleared = _bound['_last_cleared']
run_log = _bound['run_log']
del _bound

_RETENTION_THREAD_STARTED = False
_RETENTION_INTERVAL_SEC = 1 * 60


_bound = _log_runtime_backend.bind_retention_loop(_backend_context)
_retention_loop = _bound['_retention_loop']
_start_retention = _bound['_start_retention']
_may_autoclear = _bound['_may_autoclear']
del _bound

if os.environ.get("WG_BACKGROUND_ROLE") not in ("reseller-worker", "maintenance"):
    ret = _load_retention()["app"]
    for _, path in _application_log_paths():
        _may_autoclear(path, ret, persist_key="app")

_bound = _log_runtime_backend.bind_read_tail(_backend_context)
_read_tail = _bound['_read_tail']
del _bound


@login_required
def app_status():
    started = globals().get('APP_START_TS', int(time.time()))
    uptime  = now_ts() - int(started)
    hb   = _json_load(TELEGRAM_HB_FILE, {})
    last = int(hb.get('ts') or 0)
    sec  = int(current_app.config.get('TG_HEARTBEAT_SEC', 60) or 60)
    bot_online = (now_ts() - last) <= max(120, sec * 2)

    return jsonify({
        'app': {
            'online': True,
            'since': isoz(from_ts(started)),
            'uptime': uptime
        },
        'telegram': {
            'online': bool(bot_online),
            'last_seen': isoz(from_ts(last)) if last else None
        }
    })

_bound = _update_runtime_backend.bind_version_tuple(_backend_context)
_version_tuple = _bound['_version_tuple']
_update_source_marker = _bound['_update_source_marker']
_read_update_source = _bound['_read_update_source']
_github_latest_panel_version = _bound['_github_latest_panel_version']
del _bound


_bound = _log_runtime_backend.bind_norm_adminlog(_backend_context)
_norm_adminlog = _bound['_norm_adminlog']
logpanel_action = _bound['logpanel_action']
_will_persist = _bound['_will_persist']
_auto_trim = _bound['_auto_trim']
_log_save = _bound['_log_save']
_extend_file = _bound['_extend_file']
_applymute_log = _bound['_applymute_log']
_write_json = _bound['_write_json']
_read_json = _bound['_read_json']
_now_iso = _bound['_now_iso']
_json_load = _bound['_json_load']
del _bound


_TG_EVENT_LOCK = threading.Lock()
_TG_EVENT_LAST = {}


_http_security_backend.initialize_state(_backend_context)
_HTTP_4XX_STATE_FILE = _backend_context.namespace['_HTTP_4XX_STATE_FILE']
_HTTP_4XX_LOCK_FILE = _backend_context.namespace['_HTTP_4XX_LOCK_FILE']
_HTTP_SECURITY_SETTINGS_FILE = _backend_context.namespace['_HTTP_SECURITY_SETTINGS_FILE']
_HTTP_SECURITY_SETTINGS_CACHE = _backend_context.namespace['_HTTP_SECURITY_SETTINGS_CACHE']
_HTTP_4XX_STATUSES = _backend_context.namespace['_HTTP_4XX_STATUSES']
_HTTP_SECURITY_DEFAULTS = _backend_context.namespace['_HTTP_SECURITY_DEFAULTS']
_HTTP_SECURITY_OFFENSE_RESET_SEC = _backend_context.namespace['_HTTP_SECURITY_OFFENSE_RESET_SEC']
_HTTP_SECURITY_HISTORY_LIMIT = _backend_context.namespace['_HTTP_SECURITY_HISTORY_LIMIT']
_HTTP_SECURITY_TEMP_ALLOW_MAX_SEC = _backend_context.namespace['_HTTP_SECURITY_TEMP_ALLOW_MAX_SEC']
_HTTP_SECURITY_NFT_TABLE = _backend_context.namespace['_HTTP_SECURITY_NFT_TABLE']
_HTTP_SECURITY_NFT_V4_SET = _backend_context.namespace['_HTTP_SECURITY_NFT_V4_SET']
_HTTP_SECURITY_NFT_V6_SET = _backend_context.namespace['_HTTP_SECURITY_NFT_V6_SET']
_HTTP_SECURITY_CLEANUP_STARTED = _backend_context.namespace['_HTTP_SECURITY_CLEANUP_STARTED']
_HTTP_SECURITY_GEO_CACHE = _backend_context.namespace['_HTTP_SECURITY_GEO_CACHE']
_HTTP_SECURITY_GEO_CACHE_LOCK = _backend_context.namespace['_HTTP_SECURITY_GEO_CACHE_LOCK']
_HTTP_SECURITY_SENSITIVE_RE = _backend_context.namespace['_HTTP_SECURITY_SENSITIVE_RE']

_bound = _http_security_backend.bind_load_http_security_settings(_backend_context)
_load_http_security_settings = _bound['_load_http_security_settings']
_save_http_security_settings = _bound['_save_http_security_settings']
_http_security_direct_ip = _bound['_http_security_direct_ip']
_http_security_effective_ip = _bound['_http_security_effective_ip']
_http_security_client_ip = _bound['_http_security_client_ip']
_http_security_is_trusted = _bound['_http_security_is_trusted']
_http_security_is_denied = _bound['_http_security_is_denied']
_http_security_temp_allows_locked = _bound['_http_security_temp_allows_locked']
_http_security_is_temporarily_allowed = _bound['_http_security_is_temporarily_allowed']
_http_security_sensitive_path = _bound['_http_security_sensitive_path']
_http_security_add_history_locked = _bound['_http_security_add_history_locked']
_http_security_stat_add_locked = _bound['_http_security_stat_add_locked']
_http_security_stats_24h = _bound['_http_security_stats_24h']
_http_security_geo = _bound['_http_security_geo']
_http_security_nft_install_command = _bound['_http_security_nft_install_command']
_http_security_nft_status = _bound['_http_security_nft_status']
_http_security_nft_run_script = _bound['_http_security_nft_run_script']
_http_security_nft_ensure = _bound['_http_security_nft_ensure']
_http_security_firewall_add = _bound['_http_security_firewall_add']
_http_security_firewall_remove = _bound['_http_security_firewall_remove']
_http_security_apply_block_locked = _bound['_http_security_apply_block_locked']
_http_security_active_blocks = _bound['_http_security_active_blocks']
_http_security_cleanup_expired = _bound['_http_security_cleanup_expired']
_http_security_cleanup_loop = _bound['_http_security_cleanup_loop']
_start_http_security_cleanup = _bound['_start_http_security_cleanup']
_http_security_enforce_temporary_block = _bound['_http_security_enforce_temporary_block']
_record_suspicious_4xx = _bound['_record_suspicious_4xx']
_http_security_record_login_failure = _bound['_http_security_record_login_failure']
_suspicious_4xx_after_request = _bound['_suspicious_4xx_after_request']
del _bound


_node_monitor_backend.initialize_state(_backend_context)
_NODE_NOTIFY_MONITOR_STARTED = _backend_context.namespace['_NODE_NOTIFY_MONITOR_STARTED']
_NODE_NOTIFY_MONITOR_THREAD_LOCK = _backend_context.namespace['_NODE_NOTIFY_MONITOR_THREAD_LOCK']
_NODE_NOTIFY_MONITOR_STATE_FILE = _backend_context.namespace['_NODE_NOTIFY_MONITOR_STATE_FILE']
_NODE_NOTIFY_MONITOR_LOCK_FILE = _backend_context.namespace['_NODE_NOTIFY_MONITOR_LOCK_FILE']
_NODE_NOTIFY_INTERVAL_SEC = _backend_context.namespace['_NODE_NOTIFY_INTERVAL_SEC']

_bound = _node_monitor_backend.bind_load_node_notification_state(_backend_context)
_load_node_notification_state = _bound['_load_node_notification_state']
_save_node_notification_state = _bound['_save_node_notification_state']
_local_notification_states = _bound['_local_notification_states']
_check_local_notifications = _bound['_check_local_notifications']
_check_node_notifications = _bound['_check_node_notifications']
_check_update_notifications = _bound['_check_update_notifications']
_node_monitor_once = _bound['_node_monitor_once']
_node_monitor_loop = _bound['_node_monitor_loop']
_node_notify_monitor = _bound['_node_notify_monitor']
del _bound


_SECURITY_NOTIFY_LOCK = threading.Lock()
_SECURITY_NOTIFY_LAST = {}


_bound = _security_notifications_backend.bind_security_html_escape(_backend_context)
_security_html_escape = _bound['_security_html_escape']
_request_client_ip = _bound['_request_client_ip']
_request_device_summary = _bound['_request_device_summary']
_security_notify_enabled = _bound['_security_notify_enabled']
_send_security_notification = _bound['_send_security_notification']
del _bound


if os.environ.get("WG_BACKGROUND_ROLE") not in ("reseller-worker", "maintenance"):
    ret = _load_retention()["tg_app"]
    _may_autoclear(Path(TELEGRAM_LOG_FILE), ret, persist_key="tg_app")


UPDATE_HELPER = Path(BASE_DIR) / "scripts" / "panel_update.py"
UPDATE_STATUS_FILE = Path(app.instance_path) / "update_status.json"
UPDATE_LOCK_FILE = Path(app.instance_path) / "update.lock"


_bound = _update_runtime_backend.bind_read_update_status(_backend_context)
_read_update_status = _bound['_read_update_status']
_update_is_busy = _bound['_update_is_busy']
_update_lock_active = _bound['_update_lock_active']
_write_update_status = _bound['_write_update_status']
_norm_update_status = _bound['_norm_update_status']
_launch_update = _bound['_launch_update']
_queue_safe_update = _bound['_queue_safe_update']
del _bound


BACKUP_PREFS_FILE = os.path.join(app.instance_path, 'backup_settings.json')
BACKUP_SCHEDULE_FILE = os.path.join(app.instance_path, 'backup_schedule.json')
BACKUP_LAST_FILE     = os.path.join(app.instance_path, 'backup_last.json')
BACKUP_AUTO_DIR = os.path.join(app.instance_path, 'backups')
Path(BACKUP_AUTO_DIR).mkdir(parents=True, exist_ok=True)


_bound = _backup_scheduler_backend.bind_login_or_session(_backend_context)
login_or_session = _bound['login_or_session']
del _bound


_backup_scheduler_backend.initialize_scheduler(_backend_context)
_BACKUP_SCHEDULER_STARTED = _backend_context.namespace['_BACKUP_SCHEDULER_STARTED']
_BACKUP_SCHEDULER_INTERVAL_SEC = _backend_context.namespace['_BACKUP_SCHEDULER_INTERVAL_SEC']
_BACKUP_SCHEDULER_STATE_FILE = _backend_context.namespace['_BACKUP_SCHEDULER_STATE_FILE']
_BACKUP_SCHEDULER_LOCK_FILE = _backend_context.namespace['_BACKUP_SCHEDULER_LOCK_FILE']

_bound = _backup_scheduler_backend.bind_run_scheduled_backup(_backend_context)
_run_scheduled_backup = _bound['_run_scheduled_backup']
_backup_scheduler_loop = _bound['_backup_scheduler_loop']
_start_backup_scheduler = _bound['_start_backup_scheduler']
del _bound


RUNTIME_FILE = os.path.join(app.instance_path, 'runtime.json')
ALLOWED_LOGLEVELS = {'debug', 'info', 'warning', 'error', 'critical'}
RESERVED_PORTS    = {22, 25, 53, 80, 443}
ALLOWED_BINDS     = {'0.0.0.0', '127.0.0.1'}

_bound = _runtime_settings_backend.bind_load_runtime(_backend_context)
_load_runtime = _bound['_load_runtime']
_save_runtime = _bound['_save_runtime']
_confirm_runtime = _bound['_confirm_runtime']
del _bound


_bound = _wireguard_runtime_backend.bind_int_or_none(_backend_context)
_int_or_none = _bound['_int_or_none']
_derive_wg_public_key = _bound['_derive_wg_public_key']
_copy_local_iface_from_parsed = _bound['_copy_local_iface_from_parsed']
_wg_runtime_snapshot = _bound['_wg_runtime_snapshot']
_wg_checked_runtime_snapshot = _bound['_wg_checked_runtime_snapshot']
_accumulate_peer_usage = _bound['_accumulate_peer_usage']
_preview_peer_usage = _bound['_preview_peer_usage']
_fix_route = _bound['_fix_route']
_check_iface_up = _bound['_check_iface_up']
del _bound


ENDPOINT_PRESETS_FILE = os.path.join(app.instance_path, 'endpoint_presets.json')
IFACE_LOG_DIR = os.path.join(app.instance_path, 'iface_logs')
os.makedirs(IFACE_LOG_DIR, exist_ok=True)

_bound = _peer_runtime_backend.bind_ifacelog_path(_backend_context)
_ifacelog_path = _bound['_ifacelog_path']
_iface_log = _bound['_iface_log']
_clear_retention = _bound['_clear_retention']
_load_presets = _bound['_load_presets']
_save_presets = _bound['_save_presets']
_token = _bound['_token']
_shortlink_url = _bound['_shortlink_url']
_peer_from_shortlink_token = _bound['_peer_from_shortlink_token']
_delete_shortlinks_for_peer_ids = _bound['_delete_shortlinks_for_peer_ids']
_shortlink_from_peer_id = _bound['_shortlink_from_peer_id']
_shortlink_for_peer = _bound['_shortlink_for_peer']
_shortlink_response_for_peer = _bound['_shortlink_response_for_peer']
del _bound


HEARTBEAT_WORD = "heartbeat"

_bound = _log_runtime_backend.bind_parse_tg(_backend_context)
_parse_tg = _bound['_parse_tg']
_in_range = _bound['_in_range']
del _bound

if os.environ.get("WG_BACKGROUND_ROLE") not in ("reseller-worker", "maintenance"):
    ret = _load_retention()["tg_admin"]
    _may_autoclear(Path(TELEGRAM_ADMIN_LOG_FILE), ret, persist_key="tg_admin")


_bound = _peer_runtime_backend.bind_render_peer_template_preview(_backend_context)
_render_peer_template_preview = _bound['_render_peer_template_preview']
del _bound


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

from services.authentication_service import bind_authentication
_bound = bind_authentication(
    Admin2FA=Admin2FA,
    InvalidToken=InvalidToken,
    UserMixin=UserMixin,
    app=app,
    bcrypt=bcrypt,
    db=db,
    fernet=fernet,
    json=json,
    login_manager=login_manager,
    request=request,
    session=session,
    session_valid=session_valid,
)
_create_twofa = _bound['_create_twofa']
_set_secret = _bound['_set_secret']
_get_secret = _bound['_get_secret']
_hash_codes = _bound['_hash_codes']
_recovery = _bound['_recovery']
Admin = _bound['Admin']
load_user = _bound['load_user']
_admin_security_budget = _bound['_admin_security_budget']
del _bound


_public_ip_cache = {'ip': None, 'ts': 0}
_ipv6_cache = {"ts": 0, "val": ""}

_bound = _wireguard_runtime_backend.bind_public_ipv4(_backend_context)
_public_ipv4 = _bound['_public_ipv4']
_public_ipv6 = _bound['_public_ipv6']
find_iface = _bound['find_iface']
del _bound


class NodePeerInstallError(Exception):


    def __init__(self, code, status=502, detail='', message=None):
        super().__init__(message or code)
        self.code = code
        self.status = status
        self.detail = detail


_bound = _wireguard_runtime_backend.bind_keep_peer_address_host_in_sync(_backend_context)
_keep_peer_address_host_in_sync = _bound['_keep_peer_address_host_in_sync']
del _bound


_ALLOC_LOCK_DIR = os.path.join(app.instance_path, 'locks')


class PeerCreateCompensation:

    def __init__(self):
        self._actions = []

    def register_local(self, peer):
        self._actions.append(
            ('local', getattr(peer, 'public_key', ''), lambda: _rollback_local_created_peer(peer))
        )

    def register_node(self, node, public_key):
        self._actions.append(
            ('node', public_key, lambda: _rollback_node_created_peer(node, public_key))
        )

    def rollback(self):
        failures = []
        for scope, public_key, action in reversed(self._actions):
            try:
                action()
            except Exception as exc:
                app.logger.exception(
                    'Could not compensate %s peer creation for %s', scope, public_key
                )
                failures.append({
                    'scope': scope,
                    'public_key': public_key,
                    'detail': str(exc),
                })
        self._actions.clear()
        return failures


PANEL_SETTINGS_FILE = os.path.join(app.instance_path, 'panel_settings.json')

_bound = _panel_settings_backend.bind_panel_base(_backend_context)
_panel_base = _bound['_panel_base']
del _bound


PANEL_SETTINGS_FILE = os.path.join(app.instance_path, "panel_settings.json")

_bound = _panel_settings_backend.bind_valid_timezone_name(_backend_context)
_valid_timezone_name = _bound['_valid_timezone_name']
_detect_system_timezone_name = _bound['_detect_system_timezone_name']
_panel_timezone_name = _bound['_panel_timezone_name']
_panel_timezone = _bound['_panel_timezone']
_panel_local_datetime = _bound['_panel_local_datetime']
_panel_display_datetime = _bound['_panel_display_datetime']
_panel_filename_stamp = _bound['_panel_filename_stamp']
_utc_timestamp_iso = _bound['_utc_timestamp_iso']
_panel_filter_datetime_utc_naive = _bound['_panel_filter_datetime_utc_naive']
del _bound

_panel_settings_cache = {"stamp":None,"data":None}

_bound = _panel_settings_backend.bind_load_panel_settings(_backend_context)
_load_panel_settings = _bound['_load_panel_settings']
_is_https = _bound['_is_https']
_save_panel_settings = _bound['_save_panel_settings']
_server_host = _bound['_server_host']
del _bound


_bound = _node_runtime_backend.bind_endpoint_fallback(_backend_context)
_endpoint_fallback = _bound['_endpoint_fallback']
_node_endpoint_fallback = _bound['_node_endpoint_fallback']
remote_iface_name = _bound['remote_iface_name']
iface_endpoint_override = _bound['iface_endpoint_override']
_safe_explicit_endpoint = _bound['_safe_explicit_endpoint']
resolve_client_endpoint = _bound['resolve_client_endpoint']
resolve_client_endpoint_cheap = _bound['resolve_client_endpoint_cheap']
_public_key_from_node_payload = _bound['_public_key_from_node_payload']
_persist_iface_public_key = _bound['_persist_iface_public_key']
_http_error_is_pubkey_unavailable = _bound['_http_error_is_pubkey_unavailable']
_fetch_node_iface_public_key = _bound['_fetch_node_iface_public_key']
_server_publickey = _bound['_server_publickey']
_resolve_server_publickey = _bound['_resolve_server_publickey']
_node_peer_by_publickey = _bound['_node_peer_by_publickey']
_effective_client_endpoint = _bound['_effective_client_endpoint']
del _bound


class ClientConfigIncomplete(Exception):

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_bound = _node_runtime_backend.bind_client_conf_txt(_backend_context)
_client_conf_txt = _bound['_client_conf_txt']
_client_config_txt = _bound['_client_config_txt']
_peer_client_conf_or_502 = _bound['_peer_client_conf_or_502']
_peer_by_public_key_or_404 = _bound['_peer_by_public_key_or_404']
del _bound


TEMPLATE_SETTINGS_FILE = os.path.join(app.instance_path, 'template_settings.json')

_bound = _panel_settings_backend.bind_load_template_settings(_backend_context)
_load_template_settings = _bound['_load_template_settings']
_save_template_settings = _bound['_save_template_settings']
del _bound


_bound = _expiry_enforcement_backend.bind_disable_peer(_backend_context)
_disable_peer = _bound['_disable_peer']
_expire = _bound['_expire']
_expire_without_autoflush = _bound['_expire_without_autoflush']
_send_expiry_notifications = _bound['_send_expiry_notifications']
del _bound

_expiry_enforcement_backend.initialize_state(_backend_context)
_EXPIRY_THREAD_STARTED = _backend_context.namespace['_EXPIRY_THREAD_STARTED']
_EXPIRY_LOCK = _backend_context.namespace['_EXPIRY_LOCK']
_EXPIRY_LAST_TS = _backend_context.namespace['_EXPIRY_LAST_TS']
_EXPIRY_LAST_CONTENTION_WARNING = _backend_context.namespace['_EXPIRY_LAST_CONTENTION_WARNING']
_EXPIRY_DEFERRED_SINCE = _backend_context.namespace['_EXPIRY_DEFERRED_SINCE']
_EXPIRY_DEFERRED_ATTEMPTS = _backend_context.namespace['_EXPIRY_DEFERRED_ATTEMPTS']
_EXPIRY_INTERVAL_SEC = _backend_context.namespace['_EXPIRY_INTERVAL_SEC']

_bound = _expiry_enforcement_backend.bind_expiry_membership_rows(_backend_context)
_expiry_membership_rows = _bound['_expiry_membership_rows']
_run_expiry_once = _bound['_run_expiry_once']
_expiry_enforcer_loop = _bound['_expiry_enforcer_loop']
_expiry_leader_loop = _bound['_expiry_leader_loop']
_start_expiry_enforcer = _bound['_start_expiry_enforcer']
_expiry_tick_on_requests = _bound['_expiry_tick_on_requests']
_on_boot = _bound['_on_boot']
del _bound


LAST_PUBLIC_IP_FILE = os.path.join(app.instance_path, 'last_public_ipv4.txt')

_bound = _wireguard_runtime_backend.bind_read_lastip(_backend_context)
_read_lastip = _bound['_read_lastip']
_write_lastip = _bound['_write_lastip']
repoint_endpoints = _bound['repoint_endpoints']
del _bound


_TIME_REPAIR_BACKUP = os.path.join(
    app.instance_path,
    'wg_panel.db.pre-time-fix-v5.bak',
)


_bound = _database_migrations_backend.bind_latest_peer_timer_event_ts(_backend_context)
_latest_peer_timer_event_ts = _bound['_latest_peer_timer_event_ts']
_assign_repaired_expiry = _bound['_assign_repaired_expiry']
_repair_legacy_timer_rows = _bound['_repair_legacy_timer_rows']
_migrate_schema = _bound['_migrate_schema']
_migrate_schema_locked = _bound['_migrate_schema_locked']
del _bound


_bound = _bootstrap_backend.bind_bootstrap(_backend_context)
bootstrap = _bound['bootstrap']
del _bound


_bound = _peer_runtime_backend.bind_node_get(_backend_context)
node_get = _bound['node_get']
node_post = _bound['node_post']
node_delete = _bound['node_delete']
_peer_ping_ok = _bound['_peer_ping_ok']
_peer_conn_status = _bound['_peer_conn_status']
_endpoint_default_payload = _bound['_endpoint_default_payload']
_local_iface_or_error = _bound['_local_iface_or_error']
del _bound


class NodeIfaceLookupError(Exception):

    def __init__(self, code, status, detail):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


_bound = _peer_runtime_backend.bind_node_mirror_for_endpoint_default(_backend_context)
_node_mirror_for_endpoint_default = _bound['_node_mirror_for_endpoint_default']
del _bound


class EndpointApplyError(Exception):

    def __init__(self, code, status, detail):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


_bound = _peer_runtime_backend.bind_apply_endpoint_default(_backend_context)
_apply_endpoint_default = _bound['_apply_endpoint_default']
_apply_request_flags = _bound['_apply_request_flags']
_node_peer_live_total_bytes = _bound['_node_peer_live_total_bytes']
_linked_subscription_for_peer = _bound['_linked_subscription_for_peer']
_reset_peer_timer_via_subscription = _bound['_reset_peer_timer_via_subscription']
_linked_subscription_timer_response = _bound['_linked_subscription_timer_response']
del _bound


@admin_required
def health_center_api():
    try:
        return jsonify(build_health_center(globals()))
    except Exception:
        current_app.logger.exception('Health Center aggregation failed')
        return jsonify(ok=False, error='health_center_failed'), 500


_bound = _node_runtime_backend.bind_node_peer_diagnostic_runtime(_backend_context)
_node_peer_diagnostic_runtime = _bound['_node_peer_diagnostic_runtime']
del _bound


@admin_required
def peer_diagnose_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or type(data.get('peer_id')) is not int or data['peer_id'] < 1:
        return jsonify(ok=False, error='invalid_peer_id'), 400

    peer = db.session.get(Peer, data['peer_id'])
    if peer is None:
        return jsonify(ok=False, error='peer_not_found'), 404

    iface = getattr(peer, 'iface', None)
    node_id = _node_id_from_iface(iface) if iface is not None else None
    try:
        if node_id is not None:
            node = db.session.get(Node, int(node_id))
            if node is None or not node.enabled:
                return jsonify(ok=False, error='node_unavailable'), 409
            remote = _node_peer_diagnostic_runtime(node, peer)
            report = diagnose_peer(
                globals(),
                peer,
                remote_runtime=remote.get('runtime'),
                remote_path=remote.get('path_stages'),
            )
            report['node_source'] = remote.get('source')
        else:
            report = diagnose_peer(globals(), peer)
        return jsonify(report)
    except Exception:
        current_app.logger.exception('Peer diagnosis failed for peer %s', getattr(peer, 'id', '?'))
        return jsonify(ok=False, error='peer_diagnosis_failed'), 500


_bound = _wireguard_runtime_backend.bind_global_ip(_backend_context)
_global_ip = _bound['_global_ip']
_wg_endpoint_ips = _bound['_wg_endpoint_ips']
del _bound


_prev_net = {"ts": 0, "rx": 0, "tx": 0}

_bound = _wireguard_runtime_backend.bind_rate_mb(_backend_context)
_rate_mb = _bound['_rate_mb']
del _bound


@login_required
def api_stats():
    if request.args.get('view') == 'host':
        ipv4 = _public_ipv4() or ''
        ipv6 = _public_ipv6() or ''
        if ':' not in ipv6 or ipv6 == ipv4:
            ipv6 = ''
        return jsonify(hostname=socket.gethostname(), platform=platform.platform(), ipv4=ipv4, ipv6=ipv6)

    cpu_pct = psutil.cpu_percent(interval=None)
    cores   = psutil.cpu_count(logical=False) or psutil.cpu_count()
    threads = psutil.cpu_count(logical=True)
    try:
        l1, l5, l15 = os.getloadavg()
    except Exception:
        l1 = l5 = l15 = 0.0
    load_pct = round((l1 / max(1, threads)) * 100, 1)


    vm   = psutil.virtual_memory()
    swap = psutil.swap_memory()
    mem = {
        "percent": vm.percent,
        "used_mb": round(vm.used      / (1024*1024), 1),
        "free_mb": round(vm.available / (1024*1024), 1),
        "total_mb": round(vm.total    / (1024*1024), 1),
        "swap_used_mb":  round(swap.used  / (1024*1024), 1),
        "swap_total_mb": round(swap.total / (1024*1024), 1),
        "swap_percent":  swap.percent
    }


    du = psutil.disk_usage('/')
    disk = {
        "percent":  du.percent,
        "used_gb":  round(du.used  / (1024**3), 2),
        "free_gb":  round(du.free  / (1024**3), 2),
        "total_gb": round(du.total / (1024**3), 2),
    }


    io  = psutil.net_io_counters()
    now = time.time()
    global _prev_net
    dt = now - (_prev_net["ts"] or now)
    rx_rate = _rate_mb(io.bytes_recv, _prev_net["rx"], dt) if _prev_net["ts"] else 0.0
    tx_rate = _rate_mb(io.bytes_sent, _prev_net["tx"], dt) if _prev_net["ts"] else 0.0
    _prev_net = {"ts": now, "rx": io.bytes_recv, "tx": io.bytes_sent}
    net = {
        "rx_rate_mb":   round(rx_rate, 2),
        "tx_rate_mb":   round(tx_rate, 2),
        "rx_total_mb":  round(io.bytes_recv / (1024*1024), 1),
        "tx_total_mb":  round(io.bytes_sent / (1024*1024), 1),
    }


    if request.args.get('view') == 'live':
        return jsonify(cpu=round(cpu_pct, 1), mem=mem, disk=disk, net=net,
                       uptime=max(0, int(time.time() - psutil.boot_time())))

    try:
        conns = psutil.net_connections(kind='inet')
        total_conn  = len(conns)
        uniq_remote = len({c.raddr.ip for c in conns if c.raddr})
    except Exception:
        conns = []
        total_conn = uniq_remote = 0


    listen_ports = {
        c.laddr.port for c in conns
        if getattr(c, "status", None) == psutil.CONN_LISTEN and getattr(c, "laddr", None)
    }

    public_ips = set()
    try:
        for c in conns:
            if not (getattr(c, "raddr", None) and getattr(c, "laddr", None)):
                continue
            if c.status == psutil.CONN_ESTABLISHED and c.laddr.port in listen_ports:
                ip = c.raddr.ip
                if _global_ip(ip):
                    public_ips.add(ip)
    except Exception:
        pass

    public_ips |= _wg_endpoint_ips()
    unique_public = {
        "count": len(public_ips),
        "list": sorted(public_ips)[:20]
    }

    uptime        = max(0, int(time.time() - psutil.boot_time()))
    ipv4          = _public_ipv4() or ''
    ipv6          = _public_ipv6()
    if ipv6 and (':' not in str(ipv6) or str(ipv6).strip() == str(ipv4).strip()):
        ipv6 = ''
    hostname      = socket.gethostname()
    platform_str  = platform.platform()
    kernel        = platform.release()
    arch          = platform.machine()
    cpu_model     = platform.processor() or ""


    counts = {
        "online":  db.session.query(Peer).filter_by(status='online').count(),
        "offline": db.session.query(Peer).filter_by(status='offline').count(),
        "blocked": db.session.query(Peer).filter_by(status='blocked').count(),
    }

    return jsonify({
        "cpu": round(cpu_pct, 1),
        "cores": cores,
        "threads": threads,
        "load": [round(l1,2), round(l5,2), round(l15,2)],
        "load_pct": load_pct,

        "mem": mem,
        "disk": disk,

        "rx": net["rx_rate_mb"],
        "tx": net["tx_rate_mb"],
        "net": net,
        "uptime": uptime,
        "hostname": hostname,
        "platform": platform_str,
        "kernel": kernel,
        "arch": arch,
        "cpu_model": cpu_model,

        "ipv4": ipv4,
        "ipv6": ipv6,

        "counts": counts,
        "connections": {
            "total": total_conn,
            "unique": uniq_remote
        },

        "unique_public_ips": unique_public
    })


_bound = _firewall_runtime_backend.bind_private_networks(_backend_context)
_private_networks = _bound['_private_networks']
_egress_interface = _bound['_egress_interface']
_wg_firewall_rules = _bound['_wg_firewall_rules']
_inject_firewall_rules = _bound['_inject_firewall_rules']
local_firewall_rules = _bound['local_firewall_rules']
del _bound


SUBSCRIPTION_SETTINGS_FILE = os.path.join(
    app.instance_path,
    'subscription_settings.json',
)

SUBSCRIPTION_PORTAL_OVERRIDES_FILE = os.path.join(
    app.instance_path,
    'subscription_portal_overrides.json',
)


_bound = _subscription_runtime_backend.bind_write_json_atomic(_backend_context)
_write_json_atomic = _bound['_write_json_atomic']
_effective_subscription_settings = _bound['_effective_subscription_settings']
_subscription_row_readonly = _bound['_subscription_row_readonly']
del _bound


_subscription_list_runtime = {}


GEO_CACHE_FILE = os.path.join(app.instance_path, 'subscription_geo_cache.json')
GEO_CACHE_TTL = 7 * 24 * 3600


_bound = _subscription_runtime_backend.bind_flag_from_cc(_backend_context)
_flag_from_cc = _bound['_flag_from_cc']
_load_geo_cache = _bound['_load_geo_cache']
_save_geo_cache = _bound['_save_geo_cache']
_i_public_host = _bound['_i_public_host']
_endpoint_host = _bound['_endpoint_host']
_node_public_host = _bound['_node_public_host']
_public_host_peer = _bound['_public_host_peer']
_lookup_geo = _bound['_lookup_geo']
_peer_used_for_subscription = _bound['_peer_used_for_subscription']
subscription_access = _bound['subscription_access']
_subscription_inbound_state = _bound['_subscription_inbound_state']
_subscription_access_or_403 = _bound['_subscription_access_or_403']
_subscription_public_payload = _bound['_subscription_public_payload']
_subscription_settings_public = _bound['_subscription_settings_public']
del _bound


TRAFFIC_POLICY_FILE = os.path.join(INSTANCE_DIR, "traffic_policies.json")
TRAFFIC_GEO_DIR = os.path.join(INSTANCE_DIR, "traffic_geo")
TRAFFIC_NFT_TABLE = "wgpanel_traffic"
TRAFFIC_GEO_MAX_AGE = 86400


from services import peer_service as _peer_service
from services import subscription_service as _subscription_service
from services import notification_service as _notification_service
from services import backup_service as _backup_service
from services import traffic_service as _traffic_service
_bound = _peer_service.bind_services(
    AddressAllocationError=AddressAllocationError,
    AddressConflict=AddressConflict,
    AddressInvalid=AddressInvalid,
    AddressPoolExhausted=AddressPoolExhausted,
    InterfaceConfig=InterfaceConfig,
    MAX_ENUMERATED_HOSTS=MAX_ENUMERATED_HOSTS,
    NodePeerInstallError=NodePeerInstallError,
    Peer=Peer,
    PeerEvent=PeerEvent,
    PeerRemovalError=PeerRemovalError,
    SubscriptionPeer=SubscriptionPeer,
    _ALLOC_LOCK_DIR=_ALLOC_LOCK_DIR,
    _assign_iface_public_key=_assign_iface_public_key,
    _check_iface_up=_check_iface_up,
    _conf_allowed_ips=_conf_allowed_ips,
    _delete_shortlinks_for_peer_ids=_delete_shortlinks_for_peer_ids,
    _first_cidr=_first_cidr,
    _host_peer=_host_peer,
    _iface_is_node=_iface_is_node,
    _iface_up=_iface_up,
    _norm_conftext=_norm_conftext,
    _peer_in_conf=_peer_in_conf,
    _read_iface_conf=_read_iface_conf,
    _safe_ip=_safe_ip,
    _unblackhole=_unblackhole,
    _usable_hosts=_usable_hosts,
    _validate_requested_host=_validate_requested_host,
    _wg_allowed_ips=_wg_allowed_ips,
    _wg_disable=_wg_disable,
    _wg_enable=_wg_enable,
    _wg_peer_keys=_wg_peer_keys,
    _write_conf_atomic=_write_conf_atomic,
    contextmanager=contextmanager,
    current_app=current_app,
    db=db,
    from_ts=from_ts,
    iface_devname=iface_devname,
    ipaddress=ipaddress,
    jsonify=jsonify,
    node_delete=node_delete,
    node_get=node_get,
    node_post=node_post,
    now_ts=now_ts,
    os=os,
    requests=requests,
)
interface_ip_interface = _bound['interface_ip_interface']
_db_peer_hosts = _bound['_db_peer_hosts']
_reserved_hosts = _bound['_reserved_hosts']
allocate_peer_address = _bound['allocate_peer_address']
address_error_response = _bound['address_error_response']
client_address_on = _bound['client_address_on']
node_install_peer = _bound['node_install_peer']
node_reapply_peer = _bound['node_reapply_peer']
_node_agent_error_code = _bound['_node_agent_error_code']
_node_pick_available_ip = _bound['_node_pick_available_ip']
ensure_node_mirror_iface = _bound['ensure_node_mirror_iface']
resolve_requested_peer_address = _bound['resolve_requested_peer_address']
requested_peer_address_from_target = _bound['requested_peer_address_from_target']
interface_allocation_lock = _bound['interface_allocation_lock']
_available_ips = _bound['_available_ips']
log_event = _bound['log_event']
_peer_to_conf = _bound['_peer_to_conf']
_remove_peer = _bound['_remove_peer']
_sync_peer = _bound['_sync_peer']
_wg_disable_quiet = _bound['_wg_disable_quiet']
_remove_peer_quiet = _bound['_remove_peer_quiet']
_rollback_local_created_peer = _bound['_rollback_local_created_peer']
_rollback_node_created_peer = _bound['_rollback_node_created_peer']
_peer_is_on_node = _bound['_peer_is_on_node']
activate_reseller_peer = _bound['activate_reseller_peer']
reapply_peer_external = _bound['reapply_peer_external']
remove_peer_everywhere = _bound['remove_peer_everywhere']
_remove_local_peer_runtime_and_config = _bound['_remove_local_peer_runtime_and_config']
_remove_node_peer = _bound['_remove_node_peer']
_delete_peer_rows = _bound['_delete_peer_rows']
peer_removal_response = _bound['peer_removal_response']
install_local_peer = _bound['install_local_peer']
del _bound
_bound = _subscription_service.bind_services(
    InterfaceConfig=InterfaceConfig,
    Node=Node,
    Peer=Peer,
    SUBSCRIPTION_PORTAL_OVERRIDES_FILE=SUBSCRIPTION_PORTAL_OVERRIDES_FILE,
    SUBSCRIPTION_SETTINGS_FILE=SUBSCRIPTION_SETTINGS_FILE,
    SubscriptionPeer=SubscriptionPeer,
    _accumulate_peer_usage=_accumulate_peer_usage,
    _check_iface_up=_check_iface_up,
    _clear_timer_cycle=_clear_timer_cycle,
    _disable_peer=_disable_peer,
    _effective_expiry_ts=_effective_expiry_ts,
    _host_peer=_host_peer,
    _iface_up=_iface_up,
    _normalize_subscription_settings=_normalize_subscription_settings,
    _panel_display_datetime=_panel_display_datetime,
    _panel_timezone_name=_panel_timezone_name,
    _start_timer_cycle=_start_timer_cycle,
    _sub_bool=_sub_bool,
    _sub_float=_sub_float,
    _sub_int=_sub_int,
    _sub_limit_bytes=_sub_limit_bytes,
    _sub_ttl_seconds=_sub_ttl_seconds,
    _subscription_public_payload=_subscription_public_payload,
    _sync_effective_expiry=_sync_effective_expiry,
    _sync_peer=_sync_peer,
    _wg_disable=_wg_disable,
    _wg_enable=_wg_enable,
    _wg_runtime_snapshot=_wg_runtime_snapshot,
    _wg_transfer=_wg_transfer,
    _write_json_atomic=_write_json_atomic,
    abort=abort,
    allocate_peer_address=allocate_peer_address,
    app=app,
    current_app=current_app,
    datetime=datetime,
    db=db,
    effective_peer_state=effective_peer_state,
    ensure_node_mirror_iface=ensure_node_mirror_iface,
    from_ts=from_ts,
    g=g,
    iface_devname=iface_devname,
    install_local_peer=install_local_peer,
    interface_allocation_lock=interface_allocation_lock,
    ipaddress=ipaddress,
    isoz=isoz,
    json=json,
    log_event=log_event,
    node_get=node_get,
    node_install_peer=node_install_peer,
    node_post=node_post,
    now_ts=now_ts,
    os=os,
    parse_endpoint_string=parse_endpoint_string,
    re=re,
    render_template=render_template,
    requested_peer_address_from_target=requested_peer_address_from_target,
    subprocess=subprocess,
    subscription_access=subscription_access,
    to_ts=to_ts,
    url_for=url_for,
)
_load_subscription_settings = _bound['_load_subscription_settings']
_save_subscription_settings = _bound['_save_subscription_settings']
_load_subscription_portal_overrides = _bound['_load_subscription_portal_overrides']
_save_subscription_portal_overrides = _bound['_save_subscription_portal_overrides']
_subscription_portal_override = _bound['_subscription_portal_override']
_sub_used_bytes = _bound['_sub_used_bytes']
_sub_public_url = _bound['_sub_public_url']
_sub_config_url = _bound['_sub_config_url']
_apply_subscription_timer = _bound['_apply_subscription_timer']
_sync_peer_subscription = _bound['_sync_peer_subscription']
_sync_all_subscription_peers = _bound['_sync_all_subscription_peers']
_block_subscription_runtime = _bound['_block_subscription_runtime']
_subscription_peer_runtime = _bound['_subscription_peer_runtime']
_subscription_row = _bound['_subscription_row']
_network_int_cidr = _bound['_network_int_cidr']
_apnd_allowed_route = _bound['_apnd_allowed_route']
_peer_payload_subscription = _bound['_peer_payload_subscription']
_stage_reseller_peer = _bound['_stage_reseller_peer']
_create_subscription_peer = _bound['_create_subscription_peer']
_attach_subscription_target = _bound['_attach_subscription_target']
_update_subscription_payload = _bound['_update_subscription_payload']
_reset_subscription_data = _bound['_reset_subscription_data']
_reset_subscription_timer = _bound['_reset_subscription_timer']
_subscription_data_exhausted = _bound['_subscription_data_exhausted']
_subscription_time_expired = _bound['_subscription_time_expired']
_enable_subscription = _bound['_enable_subscription']
_disable_subscription = _bound['_disable_subscription']
_subscription_enabled = _bound['_subscription_enabled']
_render_subscription_template_preview = _bound['_render_subscription_template_preview']
del _bound
_bound = _notification_service.bind_services(
    TELEGRAM_ADMINS_FILE=TELEGRAM_ADMINS_FILE,
    TELEGRAM_SETTINGS_FILE=TELEGRAM_SETTINGS_FILE,
    _TG_EVENT_LAST=_TG_EVENT_LAST,
    _TG_EVENT_LOCK=_TG_EVENT_LOCK,
    _json_load=_json_load,
    _json_save=_json_save,
    _panel_display_datetime=_panel_display_datetime,
    _panel_timezone=_panel_timezone,
    _tg_human_bytes=_tg_human_bytes,
    _tg_human_delta=_tg_human_delta,
    _tg_parse_datetime=_tg_parse_datetime,
    _utc_timestamp_iso=_utc_timestamp_iso,
    current_app=current_app,
    datetime=datetime,
    re=re,
    requests=requests,
    socket=socket,
    threading=threading,
    time=time,
    timezone=timezone,
)
_load_tg_settings = _bound['_load_tg_settings']
_tg_system_timezone = _bound['_tg_system_timezone']
_tg_human_datetime = _bound['_tg_human_datetime']
_tg_now_text = _bound['_tg_now_text']
_tg_event_escape = _bound['_tg_event_escape']
_tg_event_enabled = _bound['_tg_event_enabled']
_send_telegram_event = _bound['_send_telegram_event']
_save_tg_settings = _bound['_save_tg_settings']
_load_tg_admins = _bound['_load_tg_admins']
_save_tg_admins = _bound['_save_tg_admins']
_tg_chatid = _bound['_tg_chatid']
_send_zip_telegram = _bound['_send_zip_telegram']
del _bound
_bound = _backup_service.bind_services(
    BACKUP_AUTO_DIR=BACKUP_AUTO_DIR,
    BACKUP_LAST_FILE=BACKUP_LAST_FILE,
    BACKUP_PREFS_FILE=BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE=BACKUP_SCHEDULE_FILE,
    BASE_DIR=BASE_DIR,
    BytesIO=BytesIO,
    DB_PATH=DB_PATH,
    Node=Node,
    Path=Path,
    _json_load=_json_load,
    _json_save=_json_save,
    _norm_adminlog=_norm_adminlog,
    _panel_filename_stamp=_panel_filename_stamp,
    _panel_timezone=_panel_timezone,
    _panel_timezone_name=_panel_timezone_name,
    _read_api_key=_read_api_key,
    app=app,
    current_app=current_app,
    datetime=datetime,
    db=db,
    json=json,
    jsonify=jsonify,
    os=os,
    re=re,
    request=request,
    requests=requests,
    secrets=secrets,
    tempfile=tempfile,
    zipfile=zipfile,
)
_save_autobackup = _bound['_save_autobackup']
_db_path = _bound['_db_path']
_jsonl_bundle = _bound['_jsonl_bundle']
_env_bundle = _bound['_env_bundle']
_backup_prefs = _bound['_backup_prefs']
_backup_prefs_load = _bound['_backup_prefs_load']
_backup_prefs_save = _bound['_backup_prefs_save']
_backup_restore_impl = _bound['_backup_restore_impl']
_node_backup_wg_zip = _bound['_node_backup_wg_zip']
_bundle_node_wg_backups = _bound['_bundle_node_wg_backups']
_node_wg_payloads_zip = _bound['_node_wg_payloads_zip']
_restore_node_wg_zip = _bound['_restore_node_wg_zip']
_load_backup_schedule = _bound['_load_backup_schedule']
_save_backup_schedule = _bound['_save_backup_schedule']
_load_backup_last = _bound['_load_backup_last']
_record_backup = _bound['_record_backup']
_backup_slot_datetime = _bound['_backup_slot_datetime']
del _bound
_bound = _traffic_service.bind_services(
    InterfaceConfig=InterfaceConfig,
    Peer=Peer,
    TRAFFIC_GEO_DIR=TRAFFIC_GEO_DIR,
    TRAFFIC_GEO_MAX_AGE=TRAFFIC_GEO_MAX_AGE,
    TRAFFIC_NFT_TABLE=TRAFFIC_NFT_TABLE,
    TRAFFIC_POLICY_FILE=TRAFFIC_POLICY_FILE,
    _json_load=_json_load,
    _json_save=_json_save,
    _traffic_clean_iface=_traffic_clean_iface,
    _traffic_host_addresses=_traffic_host_addresses,
    _traffic_normalize_destination=_traffic_normalize_destination,
    _traffic_parse_cidrs=_traffic_parse_cidrs,
    ipaddress=ipaddress,
    os=os,
    re=re,
    requests=requests,
    secrets=secrets,
    shutil=shutil,
    socket=socket,
    subprocess=subprocess,
    time=time,
)
_traffic_default_config = _bound['_traffic_default_config']
_traffic_load_config = _bound['_traffic_load_config']
_traffic_save_config = _bound['_traffic_save_config']
_traffic_nft_capability = _bound['_traffic_nft_capability']
_traffic_resolve_domains = _bound['_traffic_resolve_domains']
_traffic_geo_cache_path = _bound['_traffic_geo_cache_path']
_traffic_geo_url = _bound['_traffic_geo_url']
_traffic_geo_networks = _bound['_traffic_geo_networks']
_traffic_set_elements = _bound['_traffic_set_elements']
_traffic_apply_local = _bound['_traffic_apply_local']
_traffic_local_status = _bound['_traffic_local_status']
_traffic_targets_payload = _bound['_traffic_targets_payload']
_traffic_normalize_policy = _bound['_traffic_normalize_policy']
_traffic_nft_set_text = _bound['_traffic_nft_set_text']
_traffic_test_policy_local = _bound['_traffic_test_policy_local']
_traffic_live_set_contains = _bound['_traffic_live_set_contains']
_traffic_manual_target_addresses = _bound['_traffic_manual_target_addresses']
_traffic_manual_test_local = _bound['_traffic_manual_test_local']
del _bound

from routes import registry as _route_registry
from routes import logs as _logs_routes
from routes import updates as _updates_routes
from routes import security as _security_routes
from routes import telegram as _telegram_routes
from routes import backup as _backup_routes
from routes import dashboard as _dashboard_routes
from routes import settings as _settings_routes
from routes import interfaces as _interfaces_routes
from routes import peers as _peers_routes
from routes import nodes as _nodes_routes
from routes import authentication as _authentication_routes
from routes import subscriptions as _subscriptions_routes
from routes import traffic as _traffic_routes

_route_views = {}
_route_views.update(_logs_routes.build_routes(
    ADMIN_LOG_FILE=ADMIN_LOG_FILE,
    BytesIO=BytesIO,
    LOGS_SETTINGS_FILE=LOGS_SETTINGS_FILE,
    Path=Path,
    _app_log_line=_app_log_line,
    _application_log_paths=_application_log_paths,
    _applymute_log=_applymute_log,
    _last_cleared=_last_cleared,
    _load_retention=_load_retention,
    _norm_adminlog=_norm_adminlog,
    _panel_display_datetime=_panel_display_datetime,
    _panel_filename_stamp=_panel_filename_stamp,
    _panel_filter_datetime_utc_naive=_panel_filter_datetime_utc_naive,
    _panel_timezone_name=_panel_timezone_name,
    _read_admin_logs=_read_admin_logs,
    _read_tail=_read_tail,
    _save_retention=_save_retention,
    _utc_timestamp_iso=_utc_timestamp_iso,
    app=app,
    csrf=csrf,
    json=json,
    jsonify=jsonify,
    login_required=login_required,
    now_ts=now_ts,
    render_template=render_template,
    request=request,
    require_api_key_or_login=require_api_key_or_login,
    send_file=send_file,
    zipfile=zipfile,
))
_route_views.update(_updates_routes.build_routes(
    BASE_DIR=BASE_DIR,
    Node=Node,
    PANEL_REPO=PANEL_REPO,
    PANEL_UPDATE_TTL=PANEL_UPDATE_TTL,
    PANEL_VERSION=PANEL_VERSION,
    Path=Path,
    UPDATE_STATUS_FILE=UPDATE_STATUS_FILE,
    _PANEL_UPDATE_CACHE=_PANEL_UPDATE_CACHE,
    _github_latest_panel_version=_github_latest_panel_version,
    _launch_update=_launch_update,
    _norm_update_status=_norm_update_status,
    _queue_safe_update=_queue_safe_update,
    _read_update_source=_read_update_source,
    _update_is_busy=_update_is_busy,
    _update_lock_active=_update_lock_active,
    _version_tuple=_version_tuple,
    abort=abort,
    csrf=csrf,
    current_app=current_app,
    current_user=current_user,
    datetime=datetime,
    db=db,
    jsonify=jsonify,
    login_required=login_required,
    node_get=node_get,
    node_post=node_post,
    os=os,
    re=re,
    request=request,
    requests=requests,
    require_api_key_or_login=require_api_key_or_login,
    send_file=send_file,
    shutil=shutil,
    subprocess=subprocess,
    sys=sys,
    time=time,
))
_route_views.update(_security_routes.build_routes(
    _HTTP_4XX_LOCK_FILE=_HTTP_4XX_LOCK_FILE,
    _HTTP_4XX_STATE_FILE=_HTTP_4XX_STATE_FILE,
    _HTTP_SECURITY_SETTINGS_FILE=_HTTP_SECURITY_SETTINGS_FILE,
    _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC=_HTTP_SECURITY_TEMP_ALLOW_MAX_SEC,
    _http_security_active_blocks=_http_security_active_blocks,
    _http_security_add_history_locked=_http_security_add_history_locked,
    _http_security_cleanup_expired=_http_security_cleanup_expired,
    _http_security_client_ip=_http_security_client_ip,
    _http_security_firewall_remove=_http_security_firewall_remove,
    _http_security_geo=_http_security_geo,
    _http_security_int=_http_security_int,
    _http_security_network_contains=_http_security_network_contains,
    _http_security_nft_status=_http_security_nft_status,
    _http_security_normalize_ip=_http_security_normalize_ip,
    _http_security_normalize_networks=_http_security_normalize_networks,
    _http_security_stat_add_locked=_http_security_stat_add_locked,
    _http_security_stats_24h=_http_security_stats_24h,
    _http_security_temp_allows_locked=_http_security_temp_allows_locked,
    _json_load=_json_load,
    _json_save=_json_save,
    _load_http_security_settings=_load_http_security_settings,
    _send_telegram_event=_send_telegram_event,
    _tg_human_duration=_tg_human_duration,
    fcntl=fcntl,
    ipaddress=ipaddress,
    jsonify=jsonify,
    login_required=login_required,
    re=re,
    request=request,
    require_api_key_or_login=require_api_key_or_login,
    time=time,
))
_route_views.update(_telegram_routes.build_routes(
    TELEGRAM_ADMIN_LOG_FILE=TELEGRAM_ADMIN_LOG_FILE,
    TELEGRAM_HB_FILE=TELEGRAM_HB_FILE,
    TELEGRAM_LOG_FILE=TELEGRAM_LOG_FILE,
    TELEGRAM_SETTINGS_FILE=TELEGRAM_SETTINGS_FILE,
    _app_log_line=_app_log_line,
    _extend_file=_extend_file,
    _in_range=_in_range,
    _json_load=_json_load,
    _json_save=_json_save,
    _last_cleared=_last_cleared,
    _load_tg_admins=_load_tg_admins,
    _load_tg_settings=_load_tg_settings,
    _now_iso=_now_iso,
    _panel_display_datetime=_panel_display_datetime,
    _panel_timezone_name=_panel_timezone_name,
    _parse_tg=_parse_tg,
    _read_tail=_read_tail,
    _save_tg_admins=_save_tg_admins,
    _save_tg_settings=_save_tg_settings,
    _utc_timestamp_iso=_utc_timestamp_iso,
    abort=abort,
    admin_required=admin_required,
    app=app,
    csrf=csrf,
    current_app=current_app,
    from_ts=from_ts,
    isoz=isoz,
    json=json,
    jsonify=jsonify,
    login_required=login_required,
    now_ts=now_ts,
    os=os,
    request=request,
    requests=requests,
    require_api_key=require_api_key,
    require_api_key_or_login=require_api_key_or_login,
))
_route_views.update(_backup_routes.build_routes(
    BACKUP_AUTO_DIR=BACKUP_AUTO_DIR,
    BASE_DIR=BASE_DIR,
    BytesIO=BytesIO,
    InterfaceConfig=InterfaceConfig,
    Node=Node,
    PANEL_VERSION=PANEL_VERSION,
    Path=Path,
    Peer=Peer,
    ShortLink=ShortLink,
    Subscription=Subscription,
    SubscriptionPeer=SubscriptionPeer,
    ValidationError=ValidationError,
    _backup_prefs_load=_backup_prefs_load,
    _backup_prefs_save=_backup_prefs_save,
    _backup_restore_impl=_backup_restore_impl,
    _bundle_node_wg_backups=_bundle_node_wg_backups,
    _db_path=_db_path,
    _env_bundle=_env_bundle,
    _jsonl_bundle=_jsonl_bundle,
    _load_backup_last=_load_backup_last,
    _load_backup_schedule=_load_backup_schedule,
    _next_run=_next_run,
    _norm_adminlog=_norm_adminlog,
    _panel_filename_stamp=_panel_filename_stamp,
    _read_api_key=_read_api_key,
    _record_backup=_record_backup,
    _save_autobackup=_save_autobackup,
    _save_backup_schedule=_save_backup_schedule,
    _send_zip_telegram=_send_zip_telegram,
    admin_required=admin_required,
    app=app,
    current_app=current_app,
    current_user=current_user,
    datetime=datetime,
    db=db,
    json=json,
    jsonify=jsonify,
    login_required=login_required,
    os=os,
    re=re,
    render_template=render_template,
    request=request,
    require_api_key=require_api_key,
    require_api_key_or_login=require_api_key_or_login,
    send_file=send_file,
    socket=socket,
    validate_csrf=validate_csrf,
    zipfile=zipfile,
))
_route_views.update(_dashboard_routes.build_routes(
    InterfaceConfig=InterfaceConfig,
    Peer=Peer,
    current_app=current_app,
    db=db,
    jsonify=jsonify,
    login_required=login_required,
    now_ts=now_ts,
    psutil=psutil,
    re=re,
    render_template=render_template,
    require_api_key=require_api_key,
    require_api_key_or_login=require_api_key_or_login,
    subprocess=subprocess,
    text=text,
    time=time,
))
_route_views.update(_settings_routes.build_routes(
    Path=Path,
    TEMPLATE_SETTINGS_FILE=TEMPLATE_SETTINGS_FILE,
    _int_or_none=_int_or_none,
    _is_https=_is_https,
    _load_panel_settings=_load_panel_settings,
    _load_presets=_load_presets,
    _load_runtime=_load_runtime,
    _load_template_settings=_load_template_settings,
    _panel_base=_panel_base,
    _panel_timezone=_panel_timezone,
    _panel_timezone_name=_panel_timezone_name,
    _public_ipv4=_public_ipv4,
    _render_peer_template_preview=_render_peer_template_preview,
    _save_panel_settings=_save_panel_settings,
    _save_presets=_save_presets,
    _save_runtime=_save_runtime,
    _save_template_settings=_save_template_settings,
    _valid_timezone_name=_valid_timezone_name,
    admin_required=admin_required,
    app=app,
    csrf=csrf,
    current_app=current_app,
    current_user=current_user,
    datetime=datetime,
    jsonify=jsonify,
    login_required=login_required,
    now_ts=now_ts,
    os=os,
    render_template=render_template,
    request=request,
    require_api_key_or_login=require_api_key_or_login,
    signal=signal,
    subprocess=subprocess,
    threading=threading,
    time=time,
    timezone=timezone,
))
_route_views.update(_interfaces_routes.build_routes(
    EndpointApplyError=EndpointApplyError,
    EndpointValidationError=EndpointValidationError,
    IFACE_LOG_DIR=IFACE_LOG_DIR,
    InterfaceConfig=InterfaceConfig,
    Path=Path,
    Peer=Peer,
    SubscriptionPeer=SubscriptionPeer,
    _apply_endpoint_default=_apply_endpoint_default,
    _apply_request_flags=_apply_request_flags,
    _available_ips=_available_ips,
    _check_iface_up=_check_iface_up,
    _copy_local_iface_from_parsed=_copy_local_iface_from_parsed,
    _delete_shortlinks_for_peer_ids=_delete_shortlinks_for_peer_ids,
    _derive_wg_public_key=_derive_wg_public_key,
    _egress_interface=_egress_interface,
    _endpoint_default_payload=_endpoint_default_payload,
    _iface_down=_iface_down,
    _iface_log=_iface_log,
    _iface_up=_iface_up,
    _ifacelog_path=_ifacelog_path,
    _last_cleared=_last_cleared,
    _load_retention=_load_retention,
    _local_iface_or_error=_local_iface_or_error,
    _may_autoclear=_may_autoclear,
    _panel_display_datetime=_panel_display_datetime,
    _panel_timezone_name=_panel_timezone_name,
    _private_networks=_private_networks,
    _sub_bool=_sub_bool,
    _sync_all_subscription_peers=_sync_all_subscription_peers,
    _wg_disable=_wg_disable,
    _wg_firewall_rules=_wg_firewall_rules,
    _wg_peer_keys=_wg_peer_keys,
    abort=abort,
    app=app,
    csrf=csrf,
    current_app=current_app,
    db=db,
    find_iface=find_iface,
    glob=glob,
    iface_devname=iface_devname,
    iface_endpoint_override=iface_endpoint_override,
    ipaddress=ipaddress,
    json=json,
    jsonify=jsonify,
    login_required=login_required,
    logpanel_action=logpanel_action,
    now_ts=now_ts,
    os=os,
    parse_endpoint_override=parse_endpoint_override,
    re=re,
    request=request,
    require_api_key_or_login=require_api_key_or_login,
    shlex=shlex,
    subprocess=subprocess,
    tempfile=tempfile,
))
_route_views.update(_peers_routes.build_routes(
    AddressAllocationError=AddressAllocationError,
    AddressPoolExhausted=AddressPoolExhausted,
    BytesIO=BytesIO,
    EndpointValidationError=EndpointValidationError,
    IntegrityError=IntegrityError,
    InterfaceConfig=InterfaceConfig,
    Node=Node,
    NodePeerInstallError=NodePeerInstallError,
    PNGImage=PNGImage,
    Peer=Peer,
    PeerCreateCompensation=PeerCreateCompensation,
    PeerEvent=PeerEvent,
    PeerForm=PeerForm,
    PeerRemovalError=PeerRemovalError,
    Subscription=Subscription,
    SubscriptionPeer=SubscriptionPeer,
    _available_ips=_available_ips,
    _check_iface_up=_check_iface_up,
    _clear_timer_cycle=_clear_timer_cycle,
    _conv_time_limit=_conv_time_limit,
    _effective_client_endpoint=_effective_client_endpoint,
    _effective_expiry_ts=_effective_expiry_ts,
    _host_peer=_host_peer,
    _iface_up=_iface_up,
    _linked_subscription_timer_response=_linked_subscription_timer_response,
    _load_template_settings=_load_template_settings,
    _panel_display_datetime=_panel_display_datetime,
    _panel_timezone_name=_panel_timezone_name,
    _peer_by_public_key_or_404=_peer_by_public_key_or_404,
    _peer_client_conf_or_502=_peer_client_conf_or_502,
    _peer_conn_status=_peer_conn_status,
    _peer_from_shortlink_token=_peer_from_shortlink_token,
    _preview_peer_usage=_preview_peer_usage,
    _public_ipv4=_public_ipv4,
    _remove_peer_quiet=_remove_peer_quiet,
    _rollback_node_created_peer=_rollback_node_created_peer,
    _shortlink_for_peer=_shortlink_for_peer,
    _shortlink_from_peer_id=_shortlink_from_peer_id,
    _shortlink_response_for_peer=_shortlink_response_for_peer,
    _start_timer_cycle=_start_timer_cycle,
    _sub_limit_bytes=_sub_limit_bytes,
    _subscription_peer_runtime=_subscription_peer_runtime,
    _sync_effective_expiry=_sync_effective_expiry,
    _sync_peer=_sync_peer,
    _unblackhole=_unblackhole,
    _wg_disable=_wg_disable,
    _wg_disable_quiet=_wg_disable_quiet,
    _wg_enable=_wg_enable,
    _wg_runtime_snapshot=_wg_runtime_snapshot,
    _wg_transfer=_wg_transfer,
    _wireguard_endpoint=_wireguard_endpoint,
    abort=abort,
    add_days_ts=add_days_ts,
    address_error_response=address_error_response,
    allocate_peer_address=allocate_peer_address,
    csrf=csrf,
    current_app=current_app,
    db=db,
    effective_peer_state=effective_peer_state,
    ensure_node_mirror_iface=ensure_node_mirror_iface,
    flash=flash,
    from_ts=from_ts,
    func=func,
    iface_devname=iface_devname,
    install_local_peer=install_local_peer,
    interface_allocation_lock=interface_allocation_lock,
    isoz=isoz,
    jsonify=jsonify,
    log_event=log_event,
    login_required=login_required,
    logpanel_action=logpanel_action,
    make_response=make_response,
    node_delete=node_delete,
    node_get=node_get,
    node_install_peer=node_install_peer,
    node_post=node_post,
    now_ts=now_ts,
    or_=or_,
    parse_endpoint_string=parse_endpoint_string,
    peer_removal_response=peer_removal_response,
    qrcode=qrcode,
    re=re,
    reapply_peer_external=reapply_peer_external,
    redirect=redirect,
    remove_peer_everywhere=remove_peer_everywhere,
    render_template=render_template,
    request=request,
    requests=requests,
    require_api_key=require_api_key,
    require_api_key_or_login=require_api_key_or_login,
    resolve_client_endpoint_cheap=resolve_client_endpoint_cheap,
    send_file=send_file,
    subprocess=subprocess,
    subscription_access=subscription_access,
    time=time,
    to_ts=to_ts,
    url_for=url_for,
))
_route_views.update(_nodes_routes.build_routes(
    AddressAllocationError=AddressAllocationError,
    BytesIO=BytesIO,
    EndpointApplyError=EndpointApplyError,
    EndpointValidationError=EndpointValidationError,
    InterfaceConfig=InterfaceConfig,
    Node=Node,
    NodeIfaceLookupError=NodeIfaceLookupError,
    NodePeerInstallError=NodePeerInstallError,
    PNGImage=PNGImage,
    Peer=Peer,
    PeerCreateCompensation=PeerCreateCompensation,
    PeerEvent=PeerEvent,
    PeerRemovalError=PeerRemovalError,
    SubscriptionPeer=SubscriptionPeer,
    _accumulate_peer_usage=_accumulate_peer_usage,
    _apply_endpoint_default=_apply_endpoint_default,
    _apply_request_flags=_apply_request_flags,
    _assign_iface_public_key=_assign_iface_public_key,
    _conv_time_limit=_conv_time_limit,
    _delete_shortlinks_for_peer_ids=_delete_shortlinks_for_peer_ids,
    _effective_client_endpoint=_effective_client_endpoint,
    _effective_expiry_ts=_effective_expiry_ts,
    _endpoint_default_payload=_endpoint_default_payload,
    _host_peer=_host_peer,
    _linked_subscription_timer_response=_linked_subscription_timer_response,
    _node_endpoint_fallback=_node_endpoint_fallback,
    _node_mirror_for_endpoint_default=_node_mirror_for_endpoint_default,
    _node_peer_by_publickey=_node_peer_by_publickey,
    _node_peer_live_total_bytes=_node_peer_live_total_bytes,
    _norm_base_url=_norm_base_url,
    _panel_display_datetime=_panel_display_datetime,
    _panel_timezone_name=_panel_timezone_name,
    _peer_client_conf_or_502=_peer_client_conf_or_502,
    _persist_iface_public_key=_persist_iface_public_key,
    _probably_encrypt=_probably_encrypt,
    _rollback_node_created_peer=_rollback_node_created_peer,
    _shortlink_response_for_peer=_shortlink_response_for_peer,
    _start_timer_cycle=_start_timer_cycle,
    _sub_bool=_sub_bool,
    _sync_all_subscription_peers=_sync_all_subscription_peers,
    _valid_wg_key=_valid_wg_key,
    _validate_node_base_url=_validate_node_base_url,
    abort=abort,
    add_days_ts=add_days_ts,
    address_error_response=address_error_response,
    admin_required=admin_required,
    and_=and_,
    csrf=csrf,
    current_app=current_app,
    current_user=current_user,
    datetime=datetime,
    db=db,
    ensure_node_mirror_iface=ensure_node_mirror_iface,
    from_ts=from_ts,
    iface_endpoint_override=iface_endpoint_override,
    isoz=isoz,
    jsonify=jsonify,
    log_event=log_event,
    login_required=login_required,
    logpanel_action=logpanel_action,
    make_response=make_response,
    node_delete=node_delete,
    node_get=node_get,
    node_install_peer=node_install_peer,
    node_post=node_post,
    now_ts=now_ts,
    or_=or_,
    parse_endpoint_override=parse_endpoint_override,
    peer_removal_response=peer_removal_response,
    qrcode=qrcode,
    remove_peer_everywhere=remove_peer_everywhere,
    render_template=render_template,
    request=request,
    requests=requests,
    require_api_key_or_login=require_api_key_or_login,
    resolve_client_endpoint_cheap=resolve_client_endpoint_cheap,
    send_file=send_file,
    subprocess=subprocess,
    to_ts=to_ts,
    urlparse=urlparse,
))
_route_views.update(_authentication_routes.build_routes(
    Admin=Admin,
    Admin2FA=Admin2FA,
    AdminAccount=AdminAccount,
    InvalidToken=InvalidToken,
    _admin_security_budget=_admin_security_budget,
    _gen_recovery=_gen_recovery,
    _http_security_record_login_failure=_http_security_record_login_failure,
    _is_https=_is_https,
    _norm_adminlog=_norm_adminlog,
    _request_client_ip=_request_client_ip,
    _safe_url=_safe_url,
    _send_security_notification=_send_security_notification,
    app=app,
    bind_session=bind_session,
    consume_admin_factor=consume_admin_factor,
    current_app=current_app,
    current_user=current_user,
    db=db,
    fernet=fernet,
    flash=flash,
    hash_recovery=hash_recovery,
    json=json,
    jsonify=jsonify,
    login_required=login_required,
    login_user=login_user,
    logout_user=logout_user,
    match_secret=match_secret,
    os=os,
    pyotp=pyotp,
    redirect=redirect,
    render_template=render_template,
    request=request,
    secrets=secrets,
    session=session,
    session_valid=session_valid,
    time=time,
    url_for=url_for,
    verify_recovery=verify_recovery,
))
_route_views.update(_subscriptions_routes.build_routes(
    AddressAllocationError=AddressAllocationError,
    BytesIO=BytesIO,
    ClientConfigIncomplete=ClientConfigIncomplete,
    InterfaceConfig=InterfaceConfig,
    Node=Node,
    NodePeerInstallError=NodePeerInstallError,
    PNGImage=PNGImage,
    Peer=Peer,
    PeerCreateCompensation=PeerCreateCompensation,
    PeerRemovalError=PeerRemovalError,
    Subscription=Subscription,
    SubscriptionPeer=SubscriptionPeer,
    _apply_subscription_timer=_apply_subscription_timer,
    _attach_subscription_target=_attach_subscription_target,
    _available_ips=_available_ips,
    _client_config_txt=_client_config_txt,
    _effective_subscription_settings=_effective_subscription_settings,
    _flag_from_cc=_flag_from_cc,
    _load_subscription_portal_overrides=_load_subscription_portal_overrides,
    _load_subscription_settings=_load_subscription_settings,
    _lookup_geo=_lookup_geo,
    _normalize_subscription_settings=_normalize_subscription_settings,
    _peer_client_conf_or_502=_peer_client_conf_or_502,
    _private_networks=_private_networks,
    _public_host_peer=_public_host_peer,
    _render_subscription_template_preview=_render_subscription_template_preview,
    _reset_subscription_data=_reset_subscription_data,
    _reset_subscription_timer=_reset_subscription_timer,
    _save_subscription_portal_overrides=_save_subscription_portal_overrides,
    _save_subscription_settings=_save_subscription_settings,
    _sub_bool=_sub_bool,
    _sub_config_url=_sub_config_url,
    _sub_float=_sub_float,
    _sub_int=_sub_int,
    _sub_public_url=_sub_public_url,
    _subscription_access_or_403=_subscription_access_or_403,
    _subscription_data_exhausted=_subscription_data_exhausted,
    _subscription_enabled=_subscription_enabled,
    _subscription_list_runtime=_subscription_list_runtime,
    _subscription_peer_runtime=_subscription_peer_runtime,
    _subscription_public_payload=_subscription_public_payload,
    _subscription_row=_subscription_row,
    _subscription_settings_public=_subscription_settings_public,
    _subscription_time_expired=_subscription_time_expired,
    _sync_all_subscription_peers=_sync_all_subscription_peers,
    _token=_token,
    _update_subscription_payload=_update_subscription_payload,
    abort=abort,
    address_error_response=address_error_response,
    current_app=current_app,
    db=db,
    from_ts=from_ts,
    func=func,
    iface_endpoint_override=iface_endpoint_override,
    jsonify=jsonify,
    login_required=login_required,
    logpanel_action=logpanel_action,
    node_get=node_get,
    now_ts=now_ts,
    peer_removal_response=peer_removal_response,
    qrcode=qrcode,
    re=re,
    remove_peer_everywhere=remove_peer_everywhere,
    render_template=render_template,
    request=request,
    require_api_key_or_login=require_api_key_or_login,
    resolve_client_endpoint=resolve_client_endpoint,
    resolve_client_endpoint_cheap=resolve_client_endpoint_cheap,
    send_file=send_file,
    time=time,
    zipfile=zipfile,
))
_route_views.update(_traffic_routes.build_routes(
    Node=Node,
    _send_telegram_event=_send_telegram_event,
    _traffic_apply_local=_traffic_apply_local,
    _traffic_load_config=_traffic_load_config,
    _traffic_local_status=_traffic_local_status,
    _traffic_manual_test_local=_traffic_manual_test_local,
    _traffic_normalize_policy=_traffic_normalize_policy,
    _traffic_save_config=_traffic_save_config,
    _traffic_targets_payload=_traffic_targets_payload,
    _traffic_test_policy_local=_traffic_test_policy_local,
    current_app=current_app,
    db=db,
    jsonify=jsonify,
    login_required=login_required,
    node_get=node_get,
    node_post=node_post,
    request=request,
    require_api_key_or_login=require_api_key_or_login,
))
_route_views.update({
    'api_stats': api_stats,
    'app_status': app_status,
    'health_center_api': health_center_api,
    'peer_diagnose_api': peer_diagnose_api,
})
logs_retention = _route_views['logs_retention']
logs_retention_post = _route_views['logs_retention_post']
logs_page = _route_views['logs_page']
logs_settings_get = _route_views['logs_settings_get']
logs_settings_post = _route_views['logs_settings_post']
logs_backup = _route_views['logs_backup']
app_logs = _route_views['app_logs']
admin_logs = _route_views['admin_logs']
api_panel_version = _route_views['api_panel_version']
api_panel_update_status = _route_views['api_panel_update_status']
api_panel_update_start = _route_views['api_panel_update_start']
api_panel_rollback_candidates = _route_views['api_panel_rollback_candidates']
api_panel_snapshot_download = _route_views['api_panel_snapshot_download']
api_panel_snapshot_create = _route_views['api_panel_snapshot_create']
api_panel_rollback_code = _route_views['api_panel_rollback_code']
api_panel_update_targets = _route_views['api_panel_update_targets']
api_node_update_start = _route_views['api_node_update_start']
api_node_update_status = _route_views['api_node_update_status']
http_security_capabilities_get = _route_views['http_security_capabilities_get']
http_security_settings_get = _route_views['http_security_settings_get']
http_security_settings_post = _route_views['http_security_settings_post']
http_security_unban = _route_views['http_security_unban']
http_security_events_get = _route_views['http_security_events_get']
http_security_events_clear = _route_views['http_security_events_clear']
http_security_temporary_allow_add = _route_views['http_security_temporary_allow_add']
http_security_temporary_allow_remove = _route_views['http_security_temporary_allow_remove']
tg_test = _route_views['tg_test']
tg_settings_get = _route_views['tg_settings_get']
tg_settings_post = _route_views['tg_settings_post']
tg_token_set = _route_views['tg_token_set']
tg_token_clear = _route_views['tg_token_clear']
tg_admins_get = _route_views['tg_admins_get']
tg_admins_post = _route_views['tg_admins_post']
tg_admins_del = _route_views['tg_admins_del']
tg_logs_get = _route_views['tg_logs_get']
tg_logs_del = _route_views['tg_logs_del']
telegram_worker_logs = _route_views['telegram_worker_logs']
tg_status = _route_views['tg_status']
tg_heartbeat = _route_views['tg_heartbeat']
tg_admin_logs = _route_views['tg_admin_logs']
tg_adminlogs_clear = _route_views['tg_adminlogs_clear']
tg_adminlog = _route_views['tg_adminlog']
backup_page = _route_views['backup_page']
backup_restore = _route_views['backup_restore']
backup_restore_api = _route_views['backup_restore_api']
backup_inspect = _route_views['backup_inspect']
backup_node_agent_install_command = _route_views['backup_node_agent_install_command']
backups_autolist = _route_views['backups_autolist']
backups_auto = _route_views['backups_auto']
inspect_saved_auto_backup = _route_views['inspect_saved_auto_backup']
backup_get = _route_views['backup_get']
backup_post = _route_views['backup_post']
backup_db = _route_views['backup_db']
backup_last_get = _route_views['backup_last_get']
backup_last_post = _route_views['backup_last_post']
backup_settings = _route_views['backup_settings']
backup_full = _route_views['backup_full']
backup_status = _route_views['backup_status']
backup_schedule_get = _route_views['backup_schedule_get']
backup_schedule_post = _route_views['backup_schedule_post']
healthz = _route_views['healthz']
api_docs_page = _route_views['api_docs_page']
index = _route_views['index']
stats_mini = _route_views['stats_mini']
runtime_get = _route_views['runtime_get']
api_panel_restart = _route_views['api_panel_restart']
runtime_post = _route_views['runtime_post']
settings_page = _route_views['settings_page']
api_settings = _route_views['api_settings']
api_timezone = _route_views['api_timezone']
template_settings_get = _route_views['template_settings_get']
template_settings_post = _route_views['template_settings_post']
preview_template = _route_views['preview_template']
endpoint_presets = _route_views['endpoint_presets']
iface_status = _route_views['iface_status']
iface_logs = _route_views['iface_logs']
iface_settings = _route_views['iface_settings']
api_iface_endpoint_default_get = _route_views['api_iface_endpoint_default_get']
api_iface_endpoint_default_put = _route_views['api_iface_endpoint_default_put']
api_iface_endpoint_default_apply = _route_views['api_iface_endpoint_default_apply']
iface_updown = _route_views['iface_updown']
iface_available_ips = _route_views['iface_available_ips']
get_interfaces = _route_views['get_interfaces']
create_local_interface = _route_views['create_local_interface']
iface_enable = _route_views['iface_enable']
iface_disable = _route_views['iface_disable']
iface_delete = _route_views['iface_delete']
api_shortlink = _route_views['api_shortlink']
api_shortlink_by_public_key = _route_views['api_shortlink_by_public_key']
user_peer_page = _route_views['user_peer_page']
user_peer = _route_views['user_peer']
userpeer_config = _route_views['userpeer_config']
api_peer_config_by_public_key = _route_views['api_peer_config_by_public_key']
api_peer_config_qr_by_public_key = _route_views['api_peer_config_qr_by_public_key']
peer_clear_total = _route_views['peer_clear_total']
clear_peer_logs = _route_views['clear_peer_logs']
users = _route_views['users']
api_peer_counts = _route_views['api_peer_counts']
peers_create = _route_views['peers_create']
panel_peers = _route_views['panel_peers']
panel_peers_bulk = _route_views['panel_peers_bulk']
api_enable = _route_views['api_enable']
reset_data = _route_views['reset_data']
api_reset_timer = _route_views['api_reset_timer']
api_disable = _route_views['api_disable']
api_edit = _route_views['api_edit']
api_edit_node_peer = _route_views['api_edit_node_peer']
api_delete = _route_views['api_delete']
peer_logs = _route_views['peer_logs']
node_peer_config = _route_views['node_peer_config']
node_peer_config_qr = _route_views['node_peer_config_qr']
node_peer_shortlink = _route_views['node_peer_shortlink']
node_peer_logs = _route_views['node_peer_logs']
node_peer_delete = _route_views['node_peer_delete']
node_health = _route_views['node_health']
node_summary = _route_views['node_summary']
node_ifaces = _route_views['node_ifaces']
node_iface_available_ips = _route_views['node_iface_available_ips']
node_iface_toggle = _route_views['node_iface_toggle']
node_iface_delete = _route_views['node_iface_delete']
api_node_iface_endpoint_default_get = _route_views['api_node_iface_endpoint_default_get']
api_node_iface_endpoint_default_put = _route_views['api_node_iface_endpoint_default_put']
api_node_iface_endpoint_default_apply = _route_views['api_node_iface_endpoint_default_apply']
node_peers = _route_views['node_peers']
nodes = _route_views['nodes']
ui_nodes = _route_views['ui_nodes']
api_nodes = _route_views['api_nodes']
node_disable_peer = _route_views['node_disable_peer']
node_enable_peer = _route_views['node_enable_peer']
node_reset_peer_data_only = _route_views['node_reset_peer_data_only']
node_reset_peer_timer_only = _route_views['node_reset_peer_timer_only']
node_one = _route_views['node_one']
node_iface_logs = _route_views['node_iface_logs']
login = _route_views['login']
register_twofa_begin = _route_views['register_twofa_begin']
register_twofa_confirm = _route_views['register_twofa_confirm']
register = _route_views['register']
admin_status = _route_views['admin_status']
admin_change_password = _route_views['admin_change_password']
admin_rename = _route_views['admin_rename']
twofa_begin = _route_views['twofa_begin']
twofa_confirm = _route_views['twofa_confirm']
twofa_disable = _route_views['twofa_disable']
logout = _route_views['logout']
subscriptions_page = _route_views['subscriptions_page']
api_subscription_settings = _route_views['api_subscription_settings']
api_subscription_template_preview = _route_views['api_subscription_template_preview']
api_subscription_portal_settings = _route_views['api_subscription_portal_settings']
api_subscriptions_locations = _route_views['api_subscriptions_locations']
api_subscriptions_inbounds_catalog = _route_views['api_subscriptions_inbounds_catalog']
api_subscriptions = _route_views['api_subscriptions']
api_subscription_get = _route_views['api_subscription_get']
api_subscription_update = _route_views['api_subscription_update']
api_subscription_add_inbounds = _route_views['api_subscription_add_inbounds']
api_subscription_patch_inbound = _route_views['api_subscription_patch_inbound']
api_subscription_remove_inbound = _route_views['api_subscription_remove_inbound']
api_subscription_delete = _route_views['api_subscription_delete']
api_subscription_disable = _route_views['api_subscription_disable']
api_subscription_enable = _route_views['api_subscription_enable']
api_subscription_reset_data = _route_views['api_subscription_reset_data']
api_subscription_reset_timer = _route_views['api_subscription_reset_timer']
api_subscription_shortlink = _route_views['api_subscription_shortlink']
subscription_public_page = _route_views['subscription_public_page']
subscription_public_api = _route_views['subscription_public_api']
subscription_public_config = _route_views['subscription_public_config']
subscription_public_inbound_config = _route_views['subscription_public_inbound_config']
subscription_public_inbound_qr = _route_views['subscription_public_inbound_qr']
subscription_public_inbound_geo = _route_views['subscription_public_inbound_geo']
traffic_control_get = _route_views['traffic_control_get']
traffic_control_save = _route_views['traffic_control_save']
traffic_control_apply = _route_views['traffic_control_apply']
traffic_control_status = _route_views['traffic_control_status']
traffic_control_test = _route_views['traffic_control_test']
traffic_control_test_destination = _route_views['traffic_control_test_destination']
_route_registry.register_routes(app, _route_views)
del _route_views


from panel_operations import register_operations
register_operations(app, globals())

from panel_operations.profile import profile_bp
app.register_blueprint(profile_bp)

_bound = _bootstrap_backend.bind_reconcile_web_startup(_backend_context)
_reconcile_web_startup = _bound['_reconcile_web_startup']
del _bound


from panel_core.runtime import BackgroundLeader
_WEB_BACKGROUND = BackgroundLeader(
    os.path.join(app.instance_path, 'panel-background-leader.lock'),
    [_reconcile_web_startup, _start_http_security_cleanup, _start_retention,
     _start_expiry_enforcer, _start_backup_scheduler, _node_notify_monitor],
    app.logger,
)


_bound = _bootstrap_backend.bind_start_web_background(_backend_context)
_start_web_background = _bound['_start_web_background']
_web_worker_initialized = _bound['_web_worker_initialized']
del _bound


if __name__ == "__main__":
    from backend.launcher import launch
    launch(_backend_context)
