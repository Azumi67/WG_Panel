import os, glob, subprocess, time, shlex, logging, ipaddress, psutil, requests, json, tempfile, sys, zipfile, datetime as dt, ipaddress, platform, re, qrcode, multiprocessing, threading
from io import BytesIO
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, redirect, url_for, flash, request,
    jsonify, abort, current_app, make_response, send_file, session, g
)
from sqlalchemy.exc import OperationalError
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from functools import wraps
import zipfile, socket
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from dotenv import load_dotenv
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH      = os.path.join(INSTANCE_DIR, "wg_panel.db")
load_dotenv(os.path.join(BASE_DIR, '.env'))
from config import Config
from models import db, InterfaceConfig, Peer, PeerEvent, Node, Admin2FA, AdminAccount
from forms import PeerForm
from auth import require_api_key, admin_required, require_api_key_or_login
from sqlalchemy import or_, and_, text, inspect, func
from flask_wtf.csrf import CSRFProtect, generate_csrf
from urllib.parse import urlparse, urljoin
import secrets, hashlib, string, pyotp
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

def hash_recovery(code: str) -> str:
    return "sha256$" + hashlib.sha256(code.encode("utf-8")).hexdigest()

def verify_recovery(code: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("sha256$"):
        return stored == hash_recovery(code)
    try:
        import bcrypt as pybcrypt   
        if stored.startswith("$2") or stored.startswith("$bcrypt$"):
            return pybcrypt.checkpw(code.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        pass
    return False

def _gen_recovery(n=10, length=10):
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


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

# ==================================================================
def _admin_columns():
    insp = inspect(db.engine)
    if not insp.has_table('admin_account'):
        db.create_all()
        return

    cols = {c['name'] for c in insp.get_columns('admin_account')}
    to_add = []
    if 'totp_secret' not in cols:
        to_add.append(("totp_secret", "TEXT"))
    if 'recovery_codes' not in cols:
        to_add.append(("recovery_codes", "TEXT"))
    if 'twofa_enabled' not in cols:
        to_add.append(("twofa_enabled", "INTEGER DEFAULT 0"))
    if 'last_totp_counter' not in cols:
        to_add.append(("last_totp_counter", "INTEGER DEFAULT 0"))

    if to_add:
        with db.engine.begin() as conn:
            for name, typ in to_add:
                conn.execute(text(f'ALTER TABLE admin_account ADD COLUMN {name} {typ}'))

app.config.from_object(Config)
os.makedirs(app.instance_path, exist_ok=True)
db.init_app(app)

PEER_PROFILE_FILE  = os.path.join(app.instance_path, 'peer_profile.json')         
PEER_PROFILES_FILE = os.path.join(app.instance_path, 'peer_profiles.json')       

_DEF_PROFILE = {
    'dns': '1.1.1.1, 1.0.0.1',
    'allowed_ips': '0.0.0.0/0, ::/0',
    'persistent_keepalive': None, 
    'mtu': None,                  
    'endpoint': '',
    'data_limit_value': 0,
    'data_limit_unit': 'Gi',
    'start_on_first_use': False,
    'unlimited': False,
    'time_limit_days': 0,
    'time_limit_hours': 0,
}

def _migrate_single_profile():
    os.makedirs(app.instance_path, exist_ok=True)
    if not os.path.exists(PEER_PROFILES_FILE) and os.path.exists(PEER_PROFILE_FILE):
        try:
            with open(PEER_PROFILE_FILE, 'r') as f:
                single = json.load(f)
        except Exception:
            single = {}
        base = dict(_DEF_PROFILE); base.update({k: single.get(k, base[k]) for k in base.keys()})
        data = {"active": "Default", "profiles": {"Default": base}}
        with open(PEER_PROFILES_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        # try: os.remove(PEER_PROFILE_FILE)
        # except Exception: pass

def _load_profiles():
    os.makedirs(app.instance_path, exist_ok=True)
    _migrate_single_profile()
    try:
        with open(PEER_PROFILES_FILE, 'r') as f:
            d = json.load(f)
    except Exception:
        d = {}
    if 'profiles' not in d or not isinstance(d['profiles'], dict):
        d['profiles'] = {}
    d.setdefault('active', 'Default')
    if 'Default' not in d['profiles']:
        d['profiles']['Default'] = dict(_DEF_PROFILE)
    return d

def _save_profiles(d):
    os.makedirs(app.instance_path, exist_ok=True)
    with open(PEER_PROFILES_FILE, 'w') as f:
        json.dump(d, f, indent=2)

def _get_profile(name: str | None):
    d = _load_profiles()
    name = (name or d.get('active') or 'Default')
    prof = dict(_DEF_PROFILE)
    prof.update(d['profiles'].get(name, {}))
    return prof

def _set_profile(name: str, data: dict):
    d = _load_profiles()
    base = dict(_DEF_PROFILE)
    for k in base.keys():
        if k in data:
            base[k] = data[k]
    d['profiles'][name] = base
    _save_profiles(d)

def _set_active_profile(name: str):
    d = _load_profiles()
    if name in d['profiles']:
        d['active'] = name
        _save_profiles(d)

def _panel_default_dns():
    return (_get_profile(None).get('dns') or '1.1.1.1, 1.0.0.1').strip()

# ___ API (multi)___
@app.route('/api/peer_profile', methods=['DELETE'])
@login_required
def delete_apipeer_profile():
    name = (request.args.get('name') or '').strip()
    if not name:
        return jsonify(error="name_required"), 400
    d = _load_profiles()
    if name == 'Default':
        return jsonify(error="cannot_delete_default"), 400
    if name not in d['profiles']:
        return jsonify(error="not_found"), 404
    if d.get('active') == name:
        d['active'] = 'Default'
    d['profiles'].pop(name, None)
    _save_profiles(d)
    return jsonify(ok=True, profiles=sorted(d['profiles'].keys()), active=d['active'])

@app.get('/api/peer_profiles')
@login_required
def list_apipeer_profiles():
    d = _load_profiles()
    names = sorted((d.get('profiles') or {}).keys())
    return jsonify(profiles=names, active=d.get('active') or 'Default')

@app.route('/api/peer_profile/rename', methods=['POST'])
@login_required
def rename_apipeer_profile():
    data = request.get_json(force=True, silent=True) or {}
    old = (data.get('old') or '').strip()
    new = (data.get('new') or '').strip()
    if not old or not new:
        return jsonify(error="old_and_new_required"), 400
    d = _load_profiles()
    if old not in d['profiles']:
        return jsonify(error="not_found"), 404
    if new in d['profiles']:
        return jsonify(error="exists"), 409
    d['profiles'][new] = d['profiles'].pop(old)
    if d.get('active') == old:
        d['active'] = new
    _save_profiles(d)
    return jsonify(ok=True, active=d['active'])

@app.route('/api/peer_profile', methods=['GET'])
@login_required
def get_apipeer_profile():
    name = (request.args.get('name') or '').strip() or None
    return jsonify(_get_profile(name))

@app.route('/api/peer_profile', methods=['POST'])
@login_required
def save_apipeer_profile():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get('name') or 'Default').strip() or 'Default'
    payload = {k: v for k, v in data.items() if k != 'name'}
    _set_profile(name, payload)
    return jsonify(ok=True, saved_name=name, saved=_get_profile(name))

@app.route('/api/peer_profile/activate', methods=['POST'])
@login_required
def activate_apipeer_profile():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get('name') or 'Default').strip() or 'Default'
    _set_active_profile(name)
    return jsonify(ok=True, active=name)

def _effective_dns(peer):
    return (peer.dns or getattr(peer.iface, 'dns', None) or _panel_default_dns())

#---------------
# logging 
#_______________
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
os.makedirs(app.instance_path, exist_ok=True)
APP_LOG_FILE = os.path.join(app.instance_path, 'app.log')

if not app.logger.handlers:
    handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    handler.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


app.config["PROPAGATE_EXCEPTIONS"] = True

@app.errorhandler(Exception)
def _unhandled(e):
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled exception")
    return "Internal Server Error", 500

_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
_file = RotatingFileHandler(APP_LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding='utf-8')
_file.setLevel(LOG_LEVEL)
_file.setFormatter(_formatter)
root = logging.getLogger()
root.setLevel(LOG_LEVEL)
if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
    root.addHandler(_file)

if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(_formatter)
    sh.setLevel(LOG_LEVEL)
    root.addHandler(sh)

for name in ('werkzeug', 'gunicorn.error', 'gunicorn.access', 'urllib3', 'requests', 'sqlalchemy.engine'):
    lg = logging.getLogger(name)
    lg.setLevel(LOG_LEVEL)
    lg.propagate = True  

#-----------------
# Secure cookie
#__________________
logging.captureWarnings(True)
app.config["WTF_CSRF_CHECK_DEFAULT"] = False
csrf = CSRFProtect(app)

@app.before_request
def _csrf_protect_ui():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.path.startswith("/api/"):
            return  
        csrf.protect()


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

@app.context_processor
def inject_nav_flags():
    v = set(current_app.view_functions.keys())
    return {'HAS_NODES': 'nodes' in v, 'HAS_SETTINGS': 'settings_page' in v}


#--------------------------
# Allow Plain Http
#_________________________
@app.before_request
def _dev_cookie():
    current_app.config['SESSION_COOKIE_SECURE'] = bool(_is_https())

@app.after_request
def _log_request(resp):
    try:
        app.logger.info('HTTP %s %s %s', request.method, request.path, resp.status_code)
    except Exception:
        pass
    return resp


@app.after_request
def cache_headers(resp):
    if request.path.startswith('/static/') and (request.path.endswith('.css') or request.path.endswith('.js')):
        resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp

#------------------
# CSRF Injection
#__________________
@app.after_request
def inject_sec_headers(resp):
    secure_now = _is_https()

    try:
        secure_flag = bool(secure_now)

        resp.set_cookie(
            "csrf_token",
            generate_csrf(),
            samesite="Lax",
            secure=secure_flag,
            httponly=False,  
        )
    except Exception as e:
        app.logger.debug("inject_sec_headers: failed to set csrf_token cookie: %s", e)

    resp.headers.setdefault('X-Frame-Options', 'DENY')
    try:
        s = _load_panel_settings()
        if s.get('hsts') and secure_now:
            resp.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            )
    except Exception:
        pass
    try:
        if _is_https():
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" in ct:
                add = "upgrade-insecure-requests; block-all-mixed-content"
                cur = (resp.headers.get("Content-Security-Policy") or "").strip()
                if cur:
                    if "upgrade-insecure-requests" not in cur:
                        resp.headers["Content-Security-Policy"] = cur.rstrip("; ") + "; " + add
                else:
                    resp.headers["Content-Security-Policy"] = add
    except Exception:
        pass


    return resp

@app.before_request
def _https_redirect():
    try:
        s = _load_panel_settings() or {}
        if not s.get("force_https_redirect"):
            return

        xf_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if request.is_secure or xf_proto == "https":
            return

        if not bool(getattr(app, "_tls_enabled_effective", False)):
            return

        if (request.path or "").startswith("/api/"):
            return

        host = (s.get("domain") or "").strip() or request.host.split(":", 1)[0]

        https_port = s.get("https_port")
        try:
            https_port = int(https_port) if https_port else 443
        except Exception:
            https_port = 443

        netloc = f"{host}:{https_port}" if https_port and https_port != 443 else host

        full = request.full_path
        if full.endswith("?"):
            full = full[:-1]

        return redirect(f"https://{netloc}{full}", code=301)

    except Exception as e:
        current_app.logger.warning("HTTPS redirect skipped: %s", e)
        return


#@app.before_request
#def maybe_force_https():
    # Force redirect only when: toggle ON, certs loaded, and current request is NOT secure
#    try:
#        s = _load_panel_settings()
#    except Exception:
#        s = {}
#    if s.get('force_https_redirect') and getattr(app, '_tls_enabled_effective', False) and not request.is_secure:
        # Preserve host/path/query and switch to https
#        url = request.url.replace('http://', 'https://', 1)
 #       return redirect(url, code=301)


@app.after_request
def _maybe_hsts(resp):
    try:
        s = _load_panel_settings()
        if s.get('hsts') and request.is_secure:
            resp.headers.setdefault('Strict-Transport-Security',
                                    'max-age=31536000; includeSubDomains; preload')
    except Exception:
        pass
    return resp


@app.after_request
def security_headers(resp):
    p = (request.path or '').lower()

    resp.headers['X-Frame-Options'] = 'DENY'

    if p.startswith('/preview/'):
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "style-src-elem 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "          
            "object-src 'none'; base-uri 'none'; "
            "form-action 'none'; "
            "frame-ancestors 'self'"
        )

    if (
        p.endswith(('.woff2','.woff','.ttf','.otf')) or
        p.startswith('/static/fonts/') or
        p.startswith('/static/vendor/fa/webfonts/')
    ):
        resp.headers.setdefault('Access-Control-Allow-Origin', '*')
        if p.endswith('.woff2'): resp.headers.setdefault('Content-Type','font/woff2')
        elif p.endswith('.woff'): resp.headers.setdefault('Content-Type','font/woff')
        elif p.endswith('.ttf'):  resp.headers.setdefault('Content-Type','font/ttf')
        elif p.endswith('.otf'):  resp.headers.setdefault('Content-Type','font/otf')

    return resp

def _http_url(u: str) -> bool:
    try:
        p = urlparse((u or '').strip())
        return p.scheme in ('http', 'https') and bool(p.netloc)
    except Exception:
        return False

def _safe_url(target: str) -> bool:
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target or ''))
    return (test.scheme in ('http','https')) and (ref.netloc == test.netloc)

def _norm_base_url(u: str) -> str:
    u = (u or '').strip()
    return u[:-1] if u.endswith('/') else u

def _validate_node_base_url(base_url: str) -> tuple[bool, str]:
    """Validate a node base_url to reduce SSRF risk.

    Rules:
      - must be a valid URL
      - HTTPS only
      - must not resolve to loopback/private/link-local/reserved/multicast/unspecified
    """
    base_url = (base_url or '').strip().rstrip('/')
    if not _http_url(base_url):
        return False, 'invalid base_url'

    try:
        p = urlparse(base_url)
        if (p.scheme or '').lower() != 'https':
            return False, 'nodes must use https'

        host = (p.hostname or '').strip()
        if not host:
            return False, 'invalid host'
        if host in ('localhost', '127.0.0.1', '::1'):
            return False, 'loopback hosts are not allowed'

        infos = []
        try:
            infos = socket.getaddrinfo(host, p.port or 443, type=socket.SOCK_STREAM)
        except Exception:
            infos = []

        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except Exception:
                continue
            if (
                ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or
                ip.is_reserved or ip.is_unspecified
            ):
                return False, f'host resolves to non-public IP ({ip})'

        if host == '169.254.169.254':
            return False, 'metadata IP is not allowed'

    except Exception:
        return False, 'invalid base_url'

    return True, ''

#--------------------------------
# Fernet encryption at rest
#_______________________________
_fernet = None
try:
    from cryptography.fernet import Fernet
    key = os.environ.get('FERNET_KEY') 
    if key:
        _fernet = Fernet(key)
except Exception:
    _fernet = None


FERNET_KEY = os.environ.get('FERNET_KEY')
if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY is not set. Generate one and export it before starting the app.")
fernet = Fernet(FERNET_KEY.encode())

def _probably_encrypt(s: str) -> str:
    if _fernet and s:
        return _fernet.encrypt(s.encode()).decode()
    return s

def _probably_decrypt(s: str) -> str:
    if _fernet and s:
        try:
            return _fernet.decrypt(s.encode()).decode()
        except Exception:
            return s 
    return s

def _read_api_key(n):
    k = (n.api_key or '').strip()
    if k.startswith('enc$') and _FERNET:
        try:
            return _FERNET.decrypt(k[4:].encode()).decode()
        except Exception:
            current_app.logger.warning("Failed to decrypt node api_key (id=%s)", n.id)
            return ''
    return k

def _read_api_key(node) -> str:
    return _probably_decrypt(node.api_key or '')

#-------------------------------------------------
# Time helpers (no timezones; epoch)
#_________________________________________________
TELEGRAM_ADMINS_FILE   = os.path.join(app.instance_path, 'telegram_admins.json')
TELEGRAM_SETTINGS_FILE = os.path.join(app.instance_path, 'telegram_settings.json')
TELEGRAM_LOG_FILE        = os.path.join(app.instance_path, 'telegram.log')
TELEGRAM_ADMIN_LOG_FILE  = os.path.join(app.instance_path, 'telegram_admin_log.jsonl')
ADMIN_LOG_FILE = os.path.join(app.instance_path, 'admin_logs.jsonl')
TELEGRAM_HB_FILE       = os.path.join(app.instance_path, 'telegram_heartbeat.json')
LOGS_SETTINGS_FILE = Path(app.instance_path) / "logs_settings.json"
LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
LOGS_SETTINGS_FILE = Path(app.instance_path) / 'logs_settings.json'

#------------------------------
# Admin logs, IP, Whose
#______________________________

def _read_admin_logs(max_lines=2000):
    rows = []
    try:
        with open(ADMIN_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return rows[-max_lines:]


def _whoami_logs() -> tuple[str, str]:
    try:
        from flask_login import current_user as cu 
        if cu and getattr(cu, "is_authenticated", False):
            aid = str(getattr(cu, "id", "") or getattr(cu, "username", "") or "")
            uname = getattr(cu, "username", None) or ""
            return aid, uname
    except Exception:
        pass
    try:
        from flask import session
        aid = str(session.get("user_id") or session.get("username") or "")
        uname = str(session.get("username") or "")
        return aid, uname
    except Exception:
        return "", ""

#----------------------------------
# Accept several common formats
#__________________________________
def _app_log_line(s: str):
    s = (s or '').rstrip('\n')
    m = re.match(r'^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:,\d{3})?)\s+([A-Z]+)\s+([^:]+):\s*(.*)$', s)
    if m:
        ts, level, _name, msg = m.groups()
    else:
        m = re.match(r'^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:,\d{3})?)\s+([A-Z]+)\s+(.*)$', s)
        if m:
            ts, level, msg = m.group(1), m.group(2), m.group(3)
        else:
            m = re.search(r'\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b', s)
            level = (m.group(1) if m else 'INFO').upper()
            ts = ''
            msg = s
    if ts:
        ts = ts.replace(' ', 'T').split(',')[0] + 'Z'
    return {'ts': ts, 'level': level.lower(), 'msg': msg}


def _load_log_settings():
    try:
        with open(LOGS_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_log_settings(data: dict):
    LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOGS_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _src_defaults(d=None):
    d = d or {}
    return {
        "max_mb":         int(d.get("max_mb") or 0),
        "max_age_days":   int(d.get("max_age_days") or 0),
        "daily_clear":    bool(d.get("daily_clear") or False),
        "last_daily_utc": d.get("last_daily_utc") or "",
        "last_cleared_utc": d.get("last_cleared_utc") or "",
    }

def _load_retention():
    settings = _load_log_settings()
    r = settings.get("retention") or {}
    return {
        "app":      _src_defaults(r.get("app")),
        "tg_app":   _src_defaults(r.get("tg_app")),
        "tg_admin": _src_defaults(r.get("tg_admin")),
        "iface":    _src_defaults(r.get("iface")),
    }

def _save_retention(ret: dict):
    settings = _load_log_settings()
    settings["retention"] = ret
    _save_log_settings(settings)

def _last_cleared(persist_key: str | None):

    if not persist_key:
        return
    try:
        cur = _load_retention()
        group = persist_key.split(":", 1)[0] 
        if group not in cur:
            cur[group] = _src_defaults()
        cur[group]["last_cleared_utc"] = datetime.utcnow().isoformat(
            timespec="seconds"
        ) + "Z"
        _save_retention(cur)
    except Exception:
        pass

@app.get("/api/logs/retention")
@login_required
def logs_retention():
    return jsonify(retention=_load_retention())

@app.post("/api/logs/retention")
@login_required
def logs_retention_post():
    data = request.get_json(silent=True) or {}
    incoming = data.get("retention") or {}
    cur = _load_retention()

    for key in ("app", "tg_app", "tg_admin", "iface"):
        v = incoming.get(key)
        if isinstance(v, dict):
            cur[key]["max_mb"] = int(v.get("max_mb") or 0)
            cur[key]["max_age_days"] = int(v.get("max_age_days") or 0)
            cur[key]["daily_clear"] = bool(v.get("daily_clear") or False)

    _save_retention(cur)
    return jsonify(ok=True)

def run_log():
    """
    One-shot retention sweep.
    Applies retention rules from logs_settings.json to all log sources.
.
    """
    try:
        cfg = _load_retention()
    except Exception:
        cfg = {}

    def conf(key):
        return cfg.get(key) or {}

    try:
        _may_autoclear(Path(APP_LOG_FILE), conf("app"), persist_key="app")
    except Exception:
        pass

    try:
        _may_autoclear(Path(TELEGRAM_LOG_FILE), conf("tg_app"), persist_key="tg_app")
    except Exception:
        pass

    try:
        _may_autoclear(Path(TELEGRAM_ADMIN_LOG_FILE), conf("tg_admin"), persist_key="tg_admin")
    except Exception:
        pass

    try:
        iface_dir = Path(INSTANCE_DIR) / "iface_logs"
        if iface_dir.is_dir():
            for p in iface_dir.glob("*.log"):
                key = f"iface:{p.stem}"
                _may_autoclear(p, conf("iface"), persist_key=key)
    except Exception:
        pass

_RETENTION_THREAD_STARTED = False
_RETENTION_INTERVAL_SEC = 1 * 60  


def _retention_loop():
    while True:
        try:
            run_log()
        except Exception as exc:
            try:
                app.logger.exception("Log retention sweep failed: %s", exc)
            except Exception:
                pass

        time.sleep(_RETENTION_INTERVAL_SEC)


def _start_retention():
    """
    Start the background log-retention thread once per process.

    """
    global _RETENTION_THREAD_STARTED
    if _RETENTION_THREAD_STARTED:
        return

    _RETENTION_THREAD_STARTED = True
    t = threading.Thread(
        target=_retention_loop,
        name="log-retention",
        daemon=True,
    )
    t.start()

def _may_autoclear(path: Path, rules: dict, persist_key: str | None = None):
    """
    Apply retention rules [Truncate] to a single log file.
    - max_mb: when file exceeds size
    - max_age_days:  when file too old
    - daily_clear: once per day between 03:00–03:59 UTC
    """
    try:
        p = Path(path)
        if not p.exists():
            return

        max_mb = int(rules.get("max_mb") or 0)
        if max_mb > 0 and p.stat().st_size > (max_mb * 1024 * 1024):
            open(p, "w").close()
            _last_cleared(persist_key)
            return

        max_days = int(rules.get("max_age_days") or 0)
        if max_days > 0:
            import time
            age_days = (time.time() - p.stat().st_mtime) / 86400.0
            if age_days > max_days:
                open(p, "w").close()
                _last_cleared(persist_key)
                return

        if rules.get("daily_clear"):
            now = datetime.utcnow()
            today = now.strftime("%Y-%m-%d")
            last  = rules.get("last_daily_utc") or ""
            if last != today and 3 <= now.hour < 4:
                open(p, "w").close()
                if persist_key:
                    try:
                        cur = _load_retention()
                        group = persist_key.split(":", 1)[0]
                        if group not in cur:
                            cur[group] = _src_defaults()
                        cur[group]["last_daily_utc"] = today
                        cur[group]["last_cleared_utc"] = now.isoformat(timespec="seconds") + "Z"
                        _save_retention(cur)
                    except Exception:
                        pass
                else:
                    _last_cleared(persist_key)
    except Exception:
        pass

ret = _load_retention()["app"]
_may_autoclear(Path(APP_LOG_FILE), ret, persist_key="app")

def _read_tail(path: str, max_bytes: int = 50000) -> str:
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes), os.SEEK_SET)
            data = f.read().decode('utf-8', errors='replace')
        return data
    except Exception:
        return ""

@app.get('/logs')
@login_required
def logs_page():
    return render_template('logs.html')

@app.get('/api/logs/settings')
@login_required
def logs_settings_get():
    if LOGS_SETTINGS_FILE.exists():
        with open(LOGS_SETTINGS_FILE, 'r') as f:
            try:
                cfg = json.load(f)
            except Exception:
                cfg = {}
    else:
        cfg = {}

    cfg.setdefault('enabled', True)
    cfg.setdefault('include_debug', False)
    cfg.setdefault('persist', True)
    cfg.setdefault('telegram_notify', False)
    cfg.setdefault('retention_days', 7)
    cfg.setdefault('max_file_mb', 10)
    cfg.setdefault('rotate_files', 5)
    cfg.setdefault('mutes', [])
    cfg.setdefault('sources', {'app': True, 'admin': True, 'telegram': True, 'iface': True})
    cfg.setdefault('mute_save', False)
    cfg.setdefault('keep_last_lines', 0)  

    return jsonify(cfg)


@app.post('/api/logs/settings')
@login_required
def logs_settings_post():
    payload = request.get_json(force=True, silent=True) or {}
    LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOGS_SETTINGS_FILE, 'w') as f:
        json.dump(payload, f, indent=2)

    _applymute_log()

    return jsonify(ok=True)


@app.get('/api/logs/backup')
@login_required
def logs_backup():
    source = request.args.get('source','app')
    iface  = request.args.get('iface','')
    files = []
    if source == 'app':
        files = [Path(app.instance_path) / 'app.log']
    elif source == 'admin':
        files = [Path(app.instance_path) / 'admin.log']
    elif source == 'telegram':
        files = [Path(app.instance_path) / 'telegram.log']
    elif source == 'iface' and iface:
        files = [Path(app.instance_path) / f'iface_{iface}.log']

    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in files:
            if p.exists():
                z.write(p, arcname=p.name)
    mem.seek(0)
    ts = dt.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return send_file(mem, mimetype='application/zip',
                     as_attachment=True, download_name=f'logs_backup_{source}_{ts}.zip')

@app.get('/api/app_status')
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

@app.route('/api/app_logs', methods=['GET','DELETE'])
@login_required
def app_logs():
    if request.method == 'DELETE':
        try:
            open(APP_LOG_FILE, 'w').close()
            _last_cleared("app")
        except Exception:
            pass
        return jsonify(ok=True)

    q = (request.args.get('q') or '').lower().strip()
    level = (request.args.get('level') or '').lower().strip()
    limit = max(10, min(int(request.args.get('limit') or 500), 2000))
    text = _read_tail(APP_LOG_FILE, 200_000)
    out = []
    for line in text.splitlines():
        rec = _app_log_line(line)
        if not rec: 
            continue
        if level and rec['level'] != level:
            continue
        if q and q not in (rec['msg'] or '').lower():
            continue
        out.append(rec)
    return jsonify(logs=out[-limit:])


def _norm_adminlog(entry: dict):

    channel = (entry.get("channel") or
               ("web" if (hasattr(current_app, "login_manager") and
                          hasattr(sys.modules.get(__name__), "login") and
                          ("session" in request.headers or request.cookies)) else "api"))

    row = {
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "request_id": entry.get("request_id") or secrets.token_hex(6),
        "channel": channel,
        "admin_id": str(entry.get("admin_id") or ""),
        "admin_username": entry.get("admin_username") or "",
        "action": entry.get("action") or "",
        "resource": {
            "peer_id": entry.get("peer_id"),
            "iface": entry.get("iface"),
            "scope": entry.get("scope"),
        },
        "details": entry.get("details") or "",
        "result": entry.get("result") or "ok",
        "meta": {
            "bot_host": entry.get("bot_host") or "",
            "user_agent": request.headers.get("User-Agent", "") if channel == "web" else "",
        },
    }
    _extend_file(ADMIN_LOG_FILE, json.dumps(row, ensure_ascii=False), source='admin')

def logpanel_action(action: str, details: str = ""):
    _norm_adminlog({"action": action, "details": details})

#----------------------
# 2FA
#______________________
def _create_twofa(username: str) -> Admin2FA:
    rec = Admin2FA.query.filter_by(username=username).first()
    if not rec:
        rec = Admin2FA(username=username, enabled=False)
        db.session.add(rec)
        db.session.commit()
    return rec

def _set_secret(rec, secret_b32: str):
    rec.secret_enc = fernet.encrypt(secret_b32.encode()).decode()
    db.session.commit()

def _get_secret(rec) -> str | None:
    if not rec.secret_enc:
        return None
    try:
        return fernet.decrypt(rec.secret_enc.encode()).decode()
    except InvalidToken:
        return None

def _hash_codes(codes: list[str]) -> str:
    hashes = [bcrypt.hashpw(c.encode(), bcrypt.gensalt()).decode() for c in codes]
    return json.dumps(hashes)


def _recovery(rec: Admin2FA, code: str) -> bool:
    arr = json.loads(rec.recovery_hashes or "[]")
    for i, h in enumerate(arr):
        if bcrypt.checkpw(code.encode(), h.encode()):
            arr.pop(i)
            rec.recovery_hashes = json.dumps(arr)
            db.session.commit()
            return True
    return False

@csrf.exempt
@app.route('/api/admin_logs', methods=['GET', 'POST', 'DELETE'])
def admin_logs():
    if request.method == 'GET':
        try:
            from flask_login import current_user as cu
            if not (getattr(cu, "is_authenticated", False) or request.headers.get("X-API-KEY")):
                return jsonify(error="auth_required"), 401
        except Exception:
            if not request.headers.get("X-API-KEY"):
                return jsonify(error="auth_required"), 401

        q        = (request.args.get('q') or '').strip().lower()
        action   = (request.args.get('action') or '').strip().lower()
        channel  = (request.args.get('channel') or '').strip().lower()  
        limit    = max(10, min(int(request.args.get('limit') or 1000), 5000))
        from_s   = request.args.get('from') or ''
        to_s     = request.args.get('to') or ''
        logs     = _read_admin_logs(max_lines=max(1000, limit * 5))  

        def _iso_z(s: str):
            if not s:
                return None
            try:
                if s.endswith('Z'):
                    s = s[:-1]
                return datetime.fromisoformat(s)
            except Exception:
                return None

        from_dt = _iso_z(from_s)
        to_dt   = _iso_z(to_s)

        def in_range(ts_iso: str) -> bool:
            try:
                t = datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                return True
            if from_dt and t < from_dt: return False
            if to_dt   and t > to_dt:   return False
            return True

        def matches(rec: dict) -> bool:
            if q and q not in json.dumps(rec, ensure_ascii=False).lower():
                return False
            if action and (rec.get('action', '').lower() != action):
                return False
            if channel and (rec.get('channel', '').lower() != channel):  
                return False
            ts = rec.get('ts')
            if ts and not in_range(ts):
                return False
            return True

        out = [r for r in logs if matches(r)]
        return jsonify(logs=out[:limit])

    if request.method == 'DELETE':
        try:
            from flask_login import current_user as cu
            if not getattr(cu, "is_authenticated", False):
                return jsonify(error="auth_required"), 401
        except Exception:
            return jsonify(error="auth_required"), 401

        ch = (request.args.get('channel') or '').strip().lower() 
        try:
            if not ch:
                open(ADMIN_LOG_FILE, 'w').close()
                _last_cleared("tg_admin")
            else:
                kept = []
                with open(ADMIN_LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        try:
                            j = json.loads(line)
                            if (j.get('channel', '').lower() != ch):
                                kept.append(line)
                        except Exception:
                            kept.append(line)
                with open(ADMIN_LOG_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(kept)
        except Exception:
            pass
        return jsonify(ok=True)

    if not request.headers.get("X-API-KEY"):
        try:
            from flask_login import current_user as cu
            if not getattr(cu, "is_authenticated", False):
                return jsonify(error="auth_required"), 401
        except Exception:
            return jsonify(error="auth_required"), 401

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}

    _norm_adminlog(data)  
    return jsonify(ok=True), 201


def _load_log_settings():
    try:
        with open(LOGS_SETTINGS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def _will_persist() -> bool:
    s = _load_log_settings() or {}
    return bool(s.get('enabled', True) and s.get('persist', True) and not s.get('mute_save', False))

def _auto_trim(path: str | Path):
    try:
        s = _load_log_settings() or {}
        n = int(s.get('keep_last_lines') or 0)
        p = Path(path)
        if n > 0 and p.exists():
            with p.open('r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            if len(lines) > n:
                with p.open('w', encoding='utf-8') as f:
                    f.writelines(lines[-n:])
    except Exception:
        pass

def _log_save(source: str) -> bool:
    s = _load_log_settings() or {}
    if not s.get('enabled', True): return False
    if s.get('mute_save', False):  return False
    if not s.get('persist', True): return False
    return bool((s.get('sources') or {}).get(source, True))

def _extend_file(path: str | Path, text: str, source: str = 'app'):
    if not _log_save(source):
        return
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith('\n'): text += '\n'
    try:
        with p.open('a', encoding='utf-8') as f:
            f.write(text)
    except Exception:
        pass
    _auto_trim(p)

def _applymute_log():
    try:
        s = _load_log_settings() or {}
        allow = bool(s.get('enabled', True) and s.get('persist', True) and not s.get('mute_save', False))
        target_level = logging.CRITICAL + 10 if not allow else logging.INFO
        root = logging.getLogger()
        for h in root.handlers:
            if isinstance(h, RotatingFileHandler):
                h.setLevel(target_level)
    except Exception:
        pass


def _read_tail(path: str, max_bytes=10000) -> str:
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes), os.SEEK_SET)
            return f.read().decode('utf-8', errors='replace')
    except Exception:
        return ''

def _write_json(path: str, obj: dict):
    os.makedirs(app.instance_path, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2)

def _read_json(path: str) -> dict:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _now_iso():
    return datetime.utcnow().isoformat(timespec='seconds') + 'Z'

def _json_load(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default

def _json_save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600) 
    except Exception:
        pass

#------------------------
# Telegram Settings
#________________________

def _load_tg_settings():
    s = _json_load(TELEGRAM_SETTINGS_FILE, {})
    return {
        'enabled': bool(s.get('enabled', False)),
        'notify': {
            'app_down':      bool(s.get('notify', {}).get('app_down', True)),
            'iface_down':    bool(s.get('notify', {}).get('iface_down', True)),
            'login_fail':    bool(s.get('notify', {}).get('login_fail', True)),
            'suspicious_4xx':bool(s.get('notify', {}).get('suspicious_4xx', True)),
        },
        'bot_token': (s.get('bot_token') or '').strip()
    }

def _save_tg_settings(partial):
    cur = _load_tg_settings()
    if 'bot_token' in partial and partial['bot_token'] is None:
        partial.pop('bot_token')
    cur.update({k:v for k,v in partial.items() if k != 'notify'})
    if 'notify' in partial:
        cur['notify'].update(partial['notify'])
    _json_save(TELEGRAM_SETTINGS_FILE, cur)


def _load_tg_admins():
    a = _json_load(TELEGRAM_ADMINS_FILE, [])
    out = []
    for x in a:
        out.append({
            'id': str(x.get('id') or x.get('tg_id') or ''),
            'username': (x.get('username') or '').lstrip('@'),
            'note': x.get('note') or '',
            'muted': bool(x.get('muted', False))
        })
    return [x for x in out if x['id']]

def _save_tg_admins(admins):
    _json_save(TELEGRAM_ADMINS_FILE, admins)


@app.route('/api/telegram/test', methods=['POST'])
@login_required
def tg_test():
    try:
        s = _load_tg_settings()
        if not s.get('enabled'):
            return jsonify(error="Telegram is disabled."), 400

        token = (s.get('bot_token') or '').strip()
        if not token:
            return jsonify(error="Bot token is not set."), 400

        admins = _load_tg_admins() or []
        recips = []
        for a in admins:
            chat_id = a.get('id') or a.get('tg_id') or a.get('chat_id')
            if chat_id and not a.get('muted'):
                recips.append(chat_id)

        if not recips:
            return jsonify(error="No active (unmuted) admins with valid IDs."), 400

        failures = []
        for chat_id in recips:
            try:
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat_id,
                          "text": "✅ <b>Test</b>: panel → Telegram notifications are working.",
                          "parse_mode": "HTML"},
                    timeout=6
                )
                if r.status_code != 200:
                    failures.append({"chat_id": chat_id, "status": r.status_code, "body": r.text[:200]})
            except Exception as e:
                failures.append({"chat_id": chat_id, "error": str(e)})

        if failures and len(failures) == len(recips):
            current_app.logger.warning("Telegram test failed: %s", failures)
            return jsonify(error="Telegram API rejected all recipients. Have you DMed /start to the bot?",
                           detail=failures[:3]), 502

        if failures:
            current_app.logger.warning("Telegram test partial failure: %s", failures)
            return jsonify(ok=False, sent=len(recips)-len(failures), failures=len(failures)), 207

        return jsonify(ok=True, sent=len(recips))
    except Exception:
        current_app.logger.exception("Telegram test error")
        return jsonify(error="Server error while sending test"), 500


@app.get('/api/telegram/settings')
@login_required
def tg_settings_get():
    s = _load_tg_settings()
    return jsonify(
        enabled=s['enabled'],
        has_token=bool(s['bot_token']),
        notify=s['notify']
    )

@app.post('/api/telegram/settings')
@login_required
def tg_settings_post():
    data = request.get_json() or {}
    enabled = bool(data.get('enabled', False))
    notify  = data.get('notify') or {}
    _save_tg_settings({'enabled': enabled, 'notify': notify})
    return jsonify(ok=True)

@app.post('/api/telegram/token')
@login_required
def tg_token_set():
    data = request.get_json() or {}
    tok = (data.get('bot_token') or '').strip()
    if not tok:
        return jsonify(error='bot_token required'), 400
    _save_tg_settings({'bot_token': tok})
    return jsonify(ok=True)

@app.delete('/api/telegram/token')
@login_required
def tg_token_clear():
    s = _load_tg_settings()
    s['bot_token'] = ''
    _json_save(TELEGRAM_SETTINGS_FILE, s)
    return jsonify(ok=True)

@app.get('/api/telegram/admins')
@require_api_key
def tg_admins_get():
    return jsonify(admins=_load_tg_admins())

@app.post('/api/telegram/admins')
@login_required
def tg_admins_post():
    data = request.get_json() or {}
    tg_id = str(data.get('tg_id') or data.get('id') or '').strip()
    if not tg_id.isdigit():
        return jsonify(error='tg_id numeric'), 400
    username = (data.get('username') or '').lstrip('@').strip()
    note = (data.get('note') or '').strip()
    muted = bool(data.get('muted', False))

    admins = _load_tg_admins()
    found = next((a for a in admins if a['id'] == tg_id), None)
    if found:
        found.update({'username': username, 'note': note, 'muted': muted})
    else:
        admins.append({'id': tg_id, 'username': username, 'note': note, 'muted': muted})
    _save_tg_admins(admins)
    return jsonify(ok=True, admins=admins)

@app.delete('/api/telegram/admins/<tg_id>')
@login_required
def tg_admins_del(tg_id):
    admins = [a for a in _load_tg_admins() if a['id'] != str(tg_id)]
    _save_tg_admins(admins)
    return jsonify(ok=True, admins=admins)

ret = _load_retention()["tg_app"]
_may_autoclear(Path(TELEGRAM_LOG_FILE), ret, persist_key="tg_app")

@app.get('/api/telegram/logs')
@login_required
def tg_logs_get():

    fmt   = (request.args.get('format') or 'json').lower().strip()
    level = (request.args.get('level') or '').lower().strip()
    q     = (request.args.get('q') or '').lower().strip()
    from_s = request.args.get('from') or ''
    to_s   = request.args.get('to') or ''
    limit  = int(request.args.get('limit') or 500)

    tail = _read_tail(TELEGRAM_LOG_FILE, 20000) or ""
    lines = tail.splitlines()

    if fmt == 'txt':
        return jsonify(logs=tail if tail else '(no logs yet)')

    out = []
    for s in lines:
        rec = _parse_tg(s) 
        if level and rec.get('kind') != level:
            continue
        if q and q not in rec.get('raw','').lower():
            continue
        if not _in_range(rec.get('ts_dt'), from_s, to_s):
            continue
        out.append({
            "ts":   rec.get("ts_iso"),
            "kind": rec.get("kind"),
            "text": rec.get("text"),
        })

    out = out[-max(50, min(limit, 2000)):]
    return jsonify(logs=out)


@app.delete('/api/telegram/logs')
@login_required
def tg_logs_del():
    try:
        open(TELEGRAM_LOG_FILE, 'w').close()
        _last_cleared("tg_app")
    except Exception:
        pass
    return jsonify(ok=True)

#------------------------
# Backup
#________________________
BACKUP_PREFS_FILE = os.path.join(app.instance_path, 'backup_settings.json')
BACKUP_SCHEDULE_FILE = os.path.join(app.instance_path, 'backup_schedule.json')
BACKUP_LAST_FILE     = os.path.join(app.instance_path, 'backup_last.json')
BACKUP_AUTO_DIR = os.path.join(app.instance_path, 'backups')
Path(BACKUP_AUTO_DIR).mkdir(parents=True, exist_ok=True)

def _save_autobackup(data_bytes: bytes, keep: int | None = None) -> dict:

    root = Path(BACKUP_AUTO_DIR)
    root.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    name = f"auto_full_{ts}.zip"
    path = root / name

    with open(path, "wb") as f:
        f.write(data_bytes)

    st = path.stat()

    if keep is None:
        try:
            sched = _load_backup_schedule()
            keep = int(sched.get("keep", 7))
        except Exception:
            keep = 7

    keep = max(1, int(keep or 1))

    files = sorted(root.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files[keep:]:
        try:
            p.unlink()
        except OSError:
            pass

    return {"name": name, "size": st.st_size, "ts": int(st.st_mtime)}

@app.get('/backup')
@login_required
def backup_page():
    return render_template('backup.html')

def _db_path():
    return DB_PATH if os.path.isfile(DB_PATH) else None

def _jsonl_bundle(z: zipfile.ZipFile):
    inst = Path(app.instance_path)
    keep_suffix = {'.json', '.jsonl'}
    for p in inst.glob('*'):
        if p.is_file() and p.suffix.lower() in keep_suffix:
            z.write(p, arcname=f'instance/{p.name}')

def _backup_prefs():
    return {"include_wg": True, "send_to_telegram": False}

def _backup_prefs_load():
    return _json_load(BACKUP_PREFS_FILE, _backup_prefs())

def _backup_prefs_save(p):
    cur = _backup_prefs_load()
    cur.update({
        "include_wg": bool(p.get("include_wg", cur["include_wg"])),
        "send_to_telegram": bool(p.get("send_to_telegram", cur["send_to_telegram"])),
    })
    _json_save(BACKUP_PREFS_FILE, cur)
    return cur

def _backup_restore_impl():

    import tempfile, zipfile
    from pathlib import Path
    from datetime import datetime

    f = request.files.get('file')
    if not f or not (f.filename or "").lower().endswith('.zip'):
        return jsonify(ok=False, error='no_file', message='Please upload a .zip backup file.'), 400

    kind_req = (request.form.get('kind') or 'auto').lower()
    restore_wg = (request.form.get('restore_wg') or '0') == '1'

    tmp = tempfile.NamedTemporaryFile(delete=False)
    f.save(tmp)
    tmp.flush()
    tmp.seek(0)

    try:
        z = zipfile.ZipFile(tmp.name, 'r')
    except Exception:
        return jsonify(ok=False, error='invalid_zip', message='File is not a valid ZIP backup.'), 400

    names = z.namelist()
    has_db   = any(n.startswith('db/') for n in names)
    has_inst = any(n.startswith('instance/') for n in names)
    has_wg   = any(n.startswith('wg/') for n in names)

    kind = kind_req
    if kind == 'auto':
        if has_db and has_inst:
            kind = 'full'
        elif has_db:
            kind = 'db'
        elif has_inst:
            kind = 'settings'
        else:
            return jsonify(
                ok=False,
                error='unknown_layout',
                message='Backup ZIP does not look like a panel backup.'
            ), 400

    inst = Path(app.instance_path)
    db_dir = inst / "restore_tmp_db"
    inst_dir = inst
    wg_dir = Path("/etc/wireguard")

    restored = {"db": False, "settings": False, "wg": False}
    warnings = []

    restore_ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    snapshot_root = inst / "restore_snapshots" / restore_ts
    backed_up = set()  

    def _backup_existing(dest: Path, kind_name: str, rel_tail: str):

        try:
            if not dest.exists() or not dest.is_file():
                return

            key = str(dest.resolve())
            if key in backed_up:
                return

            snap_path = snapshot_root / kind_name / rel_tail
            snap_path.parent.mkdir(parents=True, exist_ok=True)

            if snap_path.exists():
                i = 2
                while True:
                    alt = snap_path.with_name(snap_path.name + f".{i}")
                    if not alt.exists():
                        snap_path = alt
                        break
                    i += 1

            dest.rename(snap_path)
            backed_up.add(key)
        except Exception:
            pass

    def _extract(member: str, dest_root: Path, kind_name: str):
        if member.endswith('/'):
            return

        _, _, tail = member.partition('/')
        tail = tail.strip().lstrip('/')

        if '.' in Path(tail).parts:
            return

        dest_root.mkdir(parents=True, exist_ok=True)
        dest = dest_root / tail

        _backup_existing(dest, kind_name=kind_name, rel_tail=tail)

        with z.open(member) as src, open(dest, 'wb') as out:
            out.write(src.read())

    try:
        if kind in ("db", "full"):
            for n in names:
                if n.startswith("db/") and not n.endswith("/"):
                    _extract(n, db_dir, kind_name="db")

            db_files = list(db_dir.glob("*.db"))
            if db_files:
                src = db_files[0]
                try:
                    db_path = Path(DB_PATH)
                    db_path.parent.mkdir(parents=True, exist_ok=True)

                    _backup_existing(db_path, kind_name="db", rel_tail=db_path.name)

                    src.replace(db_path)
                    restored["db"] = True
                except Exception as e:
                    return jsonify(ok=False, error="db_restore_failed", message=str(e)), 500

        if kind in ("settings", "full"):
            for n in names:
                if n.startswith("instance/") and not n.endswith("/"):
                    _extract(n, inst_dir, kind_name="instance")
            restored["settings"] = True

        if restore_wg and has_wg and kind in ("settings", "full"):
            for n in names:
                if n.startswith("wg/") and n.endswith(".conf"):
                    _extract(n, wg_dir, kind_name="wg")
            restored["wg"] = True
        elif has_wg and not restore_wg:
            warnings.append("wg_present_but_not_restored")

    finally:
        try:
            z.close()
        except Exception:
            pass
        try:
            Path(tmp.name).unlink(missing_ok=True)
        except Exception:
            pass

    return jsonify(
        ok=True,
        kind=kind,
        restored=restored,
        warnings=warnings,
        message="Restore completed. Restart may be required."
    )


@app.post('/api/backup/restore')
@login_required
def backup_restore():
    return _backup_restore_impl()

@app.post('/api/backup/restore_api')
@require_api_key
def backup_restore_api():
    return _backup_restore_impl()

@app.post('/api/backup/inspect')
@login_required
def backup_inspect():
    """
    Inspect an uploaded backup ZIP without restoring anything.
    Returns what it contains (db/settings/WG)
    """
    import tempfile, zipfile

    f = request.files.get('file')
    if not f or not f.filename.lower().endswith('.zip'):
        return jsonify(ok=False, error='no_file',
                       message='Please upload a .zip backup file.'), 400

    tmp = tempfile.NamedTemporaryFile(delete=False)
    f.save(tmp)
    tmp.flush()
    tmp.seek(0)

    try:
        z = zipfile.ZipFile(tmp, 'r')
    except Exception:
        return jsonify(ok=False, error='invalid_zip',
                       message='File is not a valid ZIP backup.'), 400

    names = z.namelist()
    has_db   = any(n.startswith('db/') for n in names)
    has_inst = any(n.startswith('instance/') for n in names)
    has_wg   = any(n.startswith('wg/') for n in names)

    kind = 'unknown'
    if has_db and has_inst:
        kind = 'full'
    elif has_db:
        kind = 'db'
    elif has_inst:
        kind = 'settings'

    def _read_text(member):
        try:
            with z.open(member) as fh:
                return fh.read().decode('utf-8', 'replace').strip()
        except Exception:
            return None

    created = _read_text('meta/created.txt')
    host    = _read_text('meta/host.txt')

    return jsonify(
        ok=True,
        kind=kind,
        has_db=has_db,
        has_settings=has_inst,
        has_wg=has_wg,
        created=created,
        host=host,
    )

@app.get('/api/backups/auto')
@login_required
def backups_autolist():
    """
    Return list of auto backup ZIPs in instance/backups:
    { "files": [ {name, size, ts} }
    TS is in UNIX timestamp
    """
    root = Path(BACKUP_AUTO_DIR)
    root.mkdir(parents=True, exist_ok=True)

    files = []
    for p in root.glob('*.zip'):
        try:
            st = p.stat()
        except OSError:
            continue
        files.append({
            "name": p.name,
            "size": st.st_size,
            "ts": int(st.st_mtime),
        })

    files.sort(key=lambda x: x["ts"], reverse=True)
    return jsonify(files=files)


@app.get('/api/backups/file/<path:fname>')
@login_required
def backups_auto(fname):

    safe_name = os.path.basename(fname)
    path = Path(BACKUP_AUTO_DIR) / safe_name
    if not path.is_file():
        abort(404)

    return send_file(
        str(path),
        mimetype='application/zip',
        as_attachment=False,
        download_name=path.name,
    )



@app.get('/api/backup/prefs')
@require_api_key_or_login
def backup_get():
    return jsonify(_backup_prefs_load())

@app.post('/api/backup/prefs')
@require_api_key_or_login
def backup_post():
    data = request.get_json(silent=True) or {}
    saved = _backup_prefs_save(data)
    return jsonify(ok=True, prefs=saved)

def _tg_chatid():
    admins = _load_tg_admins() or []
    for a in admins:
        if not a.get('muted') and (a.get('id') or '').strip():
            return str(a['id'])
    return None

def _send_zip_telegram(data_bytes: bytes, filename: str) -> tuple[bool, str]:
    s = _load_tg_settings()
    if not s.get('enabled'):
        return False, "Telegram disabled."
    token = (s.get('bot_token') or '').strip()
    if not token:
        return False, "Telegram token missing."
    chat_id = _tg_chatid()
    if not chat_id:
        return False, "No active Telegram admins."

    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendDocument",
            data={"chat_id": chat_id, "disable_notification": True, "caption": filename},
            files={"document": (filename, data_bytes, "application/zip")},
            timeout=30
        )
        j = {}
        try: j = r.json()
        except Exception: pass
        if r.ok and j.get("ok"):
            return True, "Sent to Telegram."
        return False, f"Telegram error: {r.status_code} {str(j)[:200] or r.text[:200]}"
    except Exception as e:
        return False, f"Telegram exception: {e!s}"


@app.get('/api/backup/db')
@require_api_key_or_login
def backup_db():
    dbp = _db_path()
    if not dbp or not os.path.isfile(dbp):
        return jsonify(error='db_not_found_or_not_sqlite'), 404

    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(dbp, arcname=f'db/{os.path.basename(dbp)}')
        z.writestr('meta/created.txt', datetime.utcnow().isoformat(timespec='seconds') + 'Z')
    mem.seek(0)

    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    fname = f'wgpanel_db_{ts}.zip'

    try:
        _norm_adminlog({
            "action": "backup_db",
            "details": f"file={fname} size={mem.getbuffer().nbytes}B",
            "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
        })
    except Exception:
        pass

    try: _record_backup('db')
    except Exception as e: current_app.logger.debug("record_backup(db) failed: %s", e)

    resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
    resp.headers['X-Backup-Kind'] = 'db'
    resp.headers['X-Backup-Timestamp'] = ts
    return resp


@app.get('/api/backup/last')
@require_api_key_or_login
def backup_last_get():

    last = _load_backup_last() or {}
    def to_epoch(iso):
        try:
            from datetime import datetime, timezone
            return int(datetime.fromisoformat(iso.replace('Z','+00:00')).timestamp())
        except Exception:
            return 0

    candidates = [to_epoch(last.get(k,'')) for k in ('db_last','settings_last','full_last')]
    best = max(candidates) if any(candidates) else 0
    return jsonify(last_backup_ts = (best if best > 0 else None))

@app.post('/api/backup/last')
@require_api_key_or_login
def backup_last_post():
    data = request.get_json(silent=True) or {}
    kind = (data.get('kind') or 'full').lower()
    try:
        ts = int(data.get('last_backup_ts')) if data.get('last_backup_ts') is not None else None
    except Exception:
        ts = None
    try:
        _record_backup(kind, ts)
    except Exception as e:
        current_app.logger.debug("record_backup(%s) failed: %s", kind, e)
    return jsonify(ok=True)


# ____ Backup Settings ______

@app.get('/api/backup/settings')
@require_api_key_or_login
def backup_settings():
    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        _jsonl_bundle(z)
        z.writestr('meta/created.txt', datetime.utcnow().isoformat(timespec='seconds') + 'Z')
    mem.seek(0)

    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    fname = f'wgpanel_settings_{ts}.zip'

    try:
        _norm_adminlog({
            "action": "backup_settings",
            "details": f"file={fname} size={mem.getbuffer().nbytes}B",
            "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
        })
    except Exception:
        pass

    try: _record_backup('settings')
    except Exception as e: current_app.logger.debug("record_backup(settings) failed: %s", e)

    resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
    resp.headers['X-Backup-Kind'] = 'settings'
    resp.headers['X-Backup-Timestamp'] = ts
    return resp


# _______ Full Backup _________

def login_or_session(fn):
    """Allow session cookie OR valid XSRF token for direct downloads."""
    @wraps(fn)
    def wrapper(*a, **kw):
        from flask import request, session, jsonify
        if 'user_id' in session:
            return fn(*a, **kw)
        token = request.headers.get('X-CSRF-Token') or request.args.get('csrf')
        if token and token == session.get('csrf_token'):
            return fn(*a, **kw)
        return jsonify({"error": "Unauthorized"}), 401
    return wrapper


@app.get('/api/backup/full')
@require_api_key_or_login
def backup_full():
    prefs = _backup_prefs_load()
    include_wg = (request.args.get('wg') or ('1' if prefs.get('include_wg') else '0')) == '1'
    send_tg    = (request.args.get('tg') or ('1' if prefs.get('send_to_telegram') else '0')) == '1'
    auto_flag  = (request.args.get('auto') or '0') == '1'

    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        dbp = _db_path()
        if dbp and os.path.isfile(dbp):
            z.write(dbp, arcname=f'db/{os.path.basename(dbp)}')
        _jsonl_bundle(z)
        if include_wg:
            wgdir = app.config.get('WG_CONF_PATH') or '/etc/wireguard/'
            try:
                for p in Path(wgdir).glob('*.conf'):
                    z.write(p, arcname=f'wg/{p.name}')
            except Exception as e:
                current_app.logger.debug("WG bundle skipped: %s", e)
        z.writestr('meta/created.txt', datetime.utcnow().isoformat(timespec='seconds') + 'Z')
        z.writestr('meta/host.txt', socket.gethostname())
        z.writestr('meta/app.json', json.dumps({
            'db_uri': app.config.get('SQLALCHEMY_DATABASE_URI', ''),
            'wg_conf_path': app.config.get('WG_CONF_PATH') or '/etc/wireguard/'
        }, indent=2))
    mem.seek(0)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    fname = f'wgpanel_full_backup_{ts}.zip'
    data = mem.getvalue()

    if auto_flag:
        try:
            sched = _load_backup_schedule()
            keep = int(sched.get("keep", 7))
        except Exception:
            keep = 7
        try:
            _save_autobackup(data, keep=keep)
        except Exception as e:
            current_app.logger.debug("auto backup store failed: %s", e)

    if send_tg:
        ok, msg = _send_zip_telegram(data, fname)
        if not ok:
            current_app.logger.warning("Backup Telegram send failed: %s", msg)

    mem = BytesIO(data)
    mem.seek(0)

    try:
        _norm_adminlog({
            "action": "backup_full",
            "details": f"file={fname} size={len(data)}B wg={int(include_wg)} tg={int(send_tg)} auto={int(auto_flag)}",
            "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
        })
    except Exception:
        pass

    try:
        _record_backup('full')
    except Exception as e:
        current_app.logger.debug("record_backup(full) failed: %s", e)

    resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
    resp.headers['X-Backup-Kind'] = 'full'
    resp.headers['X-Backup-Timestamp'] = ts
    resp.headers['X-Backup-WG'] = '1' if include_wg else '0'
    resp.headers['X-Backup-TG'] = '1' if send_tg else '0'
    resp.headers['X-Backup-AUTO'] = '1' if auto_flag else '0'
    return resp


def _load_backup_schedule():
    d = _json_load(BACKUP_SCHEDULE_FILE, {})
    return {
        "enabled": bool(d.get("enabled", False)),
        "freq": d.get("freq", "daily"),
        "time": d.get("time", "03:00"),
        "timezone": (d.get("timezone") or "UTC"),  
        "dow":  list(map(str, d.get("dow", []))),
        "dom":  int(d.get("dom", 1)),
        "cron": d.get("cron", ""),
        "keep": int(d.get("keep", 7)),
        "include_wg": bool(d.get("include_wg", False)),
        "send_to_telegram": bool(d.get("send_to_telegram", False)),
    }


def _save_backup_schedule(partial: dict):
    cur = _load_backup_schedule()
    cur.update({
        "enabled": bool(partial.get("enabled", cur["enabled"])),
        "freq": (partial.get("freq") or cur["freq"]).lower(),
        "time": partial.get("time") or cur["time"],
        "timezone": (partial.get("timezone") or cur.get("timezone") or "UTC"), 
        "dow":  [str(x) for x in (partial.get("dow") or cur["dow"] or [])],
        "dom":  int(partial.get("dom") or cur["dom"] or 1),
        "cron": (partial.get("cron") or cur["cron"]).strip(),
        "keep": max(1, int(partial.get("keep") or cur["keep"] or 7)),
        "include_wg": bool(partial.get("include_wg", cur["include_wg"])),
        "send_to_telegram": bool(partial.get("send_to_telegram", cur["send_to_telegram"])),
    })
    _json_save(BACKUP_SCHEDULE_FILE, cur)
    return cur

def _load_backup_last():
    return _json_load(BACKUP_LAST_FILE, {})

#__________ISO8601_________
def _record_backup(kind: str, when_ts: int | None = None):

    last = _load_backup_last()
    if when_ts is None:
        iso = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    else:
        from datetime import timezone
        iso = datetime.fromtimestamp(int(when_ts), tz=timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
    last[f"{kind}_last"] = iso
    _json_save(BACKUP_LAST_FILE, last)


def _next_run(sched: dict) -> str | None:
    if not sched.get("enabled"):
        return None

    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo
    from calendar import monthrange

    tzname = (sched.get("timezone") or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tzname)
    except Exception:
        tz = ZoneInfo("UTC")

    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone(tz)

    hh, mm = (sched.get("time") or "03:00").split(":")
    hh, mm = int(hh), int(mm)

    def at_local(base_local, h, m):
        return base_local.replace(hour=h, minute=m, second=0, microsecond=0)

    freq = (sched.get("freq") or "daily").lower()

    cand_local = None

    if freq == "daily":
        cand_local = at_local(now_local, hh, mm)
        if cand_local <= now_local:
            cand_local += timedelta(days=1)

    elif freq == "weekly":
        dows = [int(x) for x in (sched.get("dow") or [])] or [1]  
        best = None
        for d in range(8):
            tmp = at_local(now_local, hh, mm) + timedelta(days=d)
            if tmp.weekday() in dows and tmp > now_local:
                best = tmp
                break
        cand_local = best

    elif freq == "monthly":
        dom = max(1, min(31, int(sched.get("dom") or 1)))
        y, m = now_local.year, now_local.month

        day = min(dom, monthrange(y, m)[1])
        cand_local = at_local(now_local.replace(day=day), hh, mm)

        if cand_local <= now_local:
            m = 1 if m == 12 else m + 1
            y = y + 1 if m == 1 else y
            day = min(dom, monthrange(y, m)[1])
            cand_local = at_local(now_local.replace(year=y, month=m, day=day), hh, mm)

    else:
        return None

    if not cand_local:
        return None

    cand_utc = cand_local.astimezone(timezone.utc)
    return cand_utc.isoformat(timespec="seconds").replace("+00:00", "Z")


# _____ Backup Status (for the "last, pills + banner") _______
@app.get('/api/backup/status')
@require_api_key_or_login
def backup_status():
    return jsonify(_load_backup_last())

# _____ Backup Schedule  _____
@app.get('/api/backup/schedule')
@require_api_key_or_login
def backup_schedule_get():
    s = _load_backup_schedule()
    s["next_run"] = _next_run(s)
    return jsonify(s)

@app.post('/api/backup/schedule')
@require_api_key_or_login
def backup_schedule_post():
    data = request.get_json(silent=True) or {}
    s = _save_backup_schedule(data)
    s["next_run"] = _next_run(s)
    return jsonify(ok=True, **s)


# _____ Runtime (port/threads/loglevel) Settings _______
RUNTIME_FILE = os.path.join(app.instance_path, 'runtime.json')
ALLOWED_LOGLEVELS = {'debug', 'info', 'warning', 'error', 'critical'}
RESERVED_PORTS    = {22, 25, 53, 80, 443}
ALLOWED_BINDS     = {'0.0.0.0', '127.0.0.1'}

def _load_runtime():
    try:
        with open(RUNTIME_FILE, 'r') as f:
            s = json.load(f)
    except Exception:
        s = {}
    def _i(x):
        try:
            return int(x)
        except Exception:
            return None
    return {
        'bind':             (s.get('bind') or '').strip(),
        'port':             _i(s.get('port')),                     
        'workers':          _i(s.get('workers')),
        'threads':          _i(s.get('threads')),
        'timeout':          _i(s.get('timeout')),
        'graceful_timeout': _i(s.get('graceful_timeout')),
        'loglevel':         (s.get('loglevel') or os.getenv('LOGLEVEL') or 'info').lower(),
    }


def _save_runtime(payload: dict):
    cur = _load_runtime()
    cur.update({k: v for k, v in payload.items() if v is not None})
    _json_save(RUNTIME_FILE, cur)

def _confirm_runtime(p):
    bind = (p.get('bind') or '').strip()
    if bind:
        if ':' not in bind:
            raise ValueError('bind must be "host:port"')
        host, port_s = bind.rsplit(':', 1)
        if host not in ALLOWED_BINDS:
            raise ValueError('bind host not allowed')
        try:
            port = int(port_s)
        except Exception:
            raise ValueError('port must be a number')
    else:
        host = ''
        try:
            port = int(p.get('port'))
        except Exception:
            raise ValueError('port must be provided and be a number')

    if not (1024 <= port <= 65535):
        raise ValueError('port must be 1024–65535')
    if port in RESERVED_PORTS:
        raise ValueError('port is reserved')

    try:
        workers = int(p.get('workers', 0))
        threads = int(p.get('threads', 4))
        timeout = int(p.get('timeout', 60))
        gtime   = int(p.get('graceful_timeout', 30))
    except Exception:
        raise ValueError('numeric fields must be integers')

    workers = max(0, min(workers, 16))      
    threads = max(1, min(threads, 64))
    timeout = max(10, min(timeout, 600))
    gtime   = max(5,  min(gtime,   600))

    ll = (p.get('loglevel') or 'info').lower()
    if ll not in ALLOWED_LOGLEVELS:
        raise ValueError('invalid loglevel')

    return {
        'bind': f'{host}:{port}' if bind else '',
        'port': port,
        'workers': workers,
        'threads': threads,
        'timeout': timeout,
        'graceful_timeout': gtime,
        'loglevel': ll,
    }

@app.get("/api/healthz")
@require_api_key_or_login
def healthz():
    return jsonify(ok=True, ts=now_ts()), 200


@app.get('/api/runtime')
@login_required
@admin_required
def runtime_get():
    saved = _load_runtime() or {}
    port_env = os.getenv('PORT')
    eff = {
        'bind':    os.getenv('BIND') or '',
        'port':    int(port_env) if (port_env and port_env.isdigit()) else None,
        'workers': _int_or_none(os.getenv('WORKERS')),
        'threads': _int_or_none(os.getenv('THREADS')),
        'timeout': _int_or_none(os.getenv('TIMEOUT')),
        'graceful_timeout': _int_or_none(os.getenv('GRACEFUL_TIMEOUT')),
        'loglevel': (os.getenv('LOGLEVEL') or '').lower() or None,
    }
    return jsonify(saved=saved, effective=eff, requires_restart=True)


def _int_or_none(v):
    try:
        return int(v) if v is not None and str(v).strip() != '' else None
    except Exception:
        return None

@app.post("/api/panel/restart")
@login_required
@admin_required
def api_panel_restart():
    """
    Trigger a restart of the panel service (systemd).

    """
    svc = os.getenv("PANEL_SERVICE_NAME", "wg-panel.service")

    try:
        try:
            next_base = _panel_base()
        except Exception:
            next_base = None

        current_app.logger.warning(
            "panel_restart requested by user=%s ip=%s service=%s next_base=%r",
            getattr(current_user, "username", "?"),
            request.remote_addr,
            svc,
            next_base,
        )

        subprocess.Popen(["systemctl", "restart", svc])

        return jsonify(ok=True, restarting=True, service=svc, next_url=next_base)
    except Exception as e:
        current_app.logger.exception("panel_restart failed: %s", e)
        return jsonify(error=str(e)), 500

@csrf.exempt  
@app.post('/api/runtime')
@login_required
@admin_required
def runtime_post():
    data = request.get_json(silent=True) or {}
    cur  = _load_runtime() or {}
    new  = dict(cur)

    current_app.logger.debug(
        "runtime_post called by user=%s ip=%s payload=%r current=%r",
        getattr(current_user, "username", "?"),
        request.remote_addr,
        data,
        cur,
    )

    def as_int_or_none(val):
        try:
            return int(val)
        except Exception:
            return None

    try:
        if 'bind' in data and isinstance(data.get('bind'), str):
            raw_bind = data['bind']
            new['bind'] = raw_bind.strip() or (cur.get('bind') or '0.0.0.0')
            current_app.logger.debug("runtime_post bind field raw=%r resolved=%r", raw_bind, new['bind'])

        if 'port' in data and data['port'] is not None:
            raw_port = data['port']
            p = as_int_or_none(raw_port)
            if p is None:
                raise ValueError(f"port must be a number (got {raw_port!r})")
            new['port'] = p
            current_app.logger.debug("runtime_post port field raw=%r int=%r", raw_port, p)

            b = (new.get('bind') or cur.get('bind') or os.getenv('BIND') or '0.0.0.0').strip()
            if ':' in b:
                host, _sep, _old = b.rpartition(':')
                host = host or '0.0.0.0'
                new['bind'] = f'{host}:{new["port"]}'
            else:
                new['bind'] = b
            current_app.logger.debug("runtime_post normalized bind=%r", new['bind'])

        if 'workers' in data and data['workers'] is not None:
            new['workers'] = as_int_or_none(data['workers']) or 0
        if 'threads' in data and data['threads'] is not None:
            new['threads'] = as_int_or_none(data['threads']) or 4
        if 'timeout' in data and data['timeout'] is not None:
            new['timeout'] = as_int_or_none(data['timeout']) or 60
        if 'graceful_timeout' in data and data['graceful_timeout'] is not None:
            new['graceful_timeout'] = as_int_or_none(data['graceful_timeout']) or 30
        if 'loglevel' in data and data['loglevel']:
            ll_raw = str(data['loglevel']).strip().lower()
            new['loglevel'] = ll_raw
            current_app.logger.debug("runtime_post loglevel raw=%r normalized=%r", data['loglevel'], ll_raw)

        if 'ssl_certfile' in data and data['ssl_certfile']:
            new['ssl_certfile'] = data['ssl_certfile'].strip()
        if 'ssl_keyfile' in data and data['ssl_keyfile']:
            new['ssl_keyfile'] = data['ssl_keyfile'].strip()

        current_app.logger.debug("runtime_post final new config=%r", new)

        _save_runtime(new)
        current_app.logger.info(
            "runtime_saved user=%s ip=%s from=%s to=%s",
            getattr(current_user, 'username', '?'),
            request.remote_addr,
            cur,
            new,
        )
        return jsonify(ok=True, saved=new, requires_restart=True)

    except Exception as exc:
        current_app.logger.warning(
            "runtime_post failed user=%s ip=%s error=%s payload=%r partial_new=%r",
            getattr(current_user, "username", "?"),
            request.remote_addr,
            exc,
            data,
            new,
            exc_info=True,
        )
        return jsonify(error=str(exc)), 400


@app.get('/api/telegram/status')
@login_required
def tg_status():
    hb = _json_load(TELEGRAM_HB_FILE, {})
    last = int(hb.get('ts') or 0)
    sec = int(current_app.config.get('TG_HEARTBEAT_SEC', 60) or 60)
    online = (now_ts() - last) <= max(120, sec * 2)
    return jsonify(
        bot_online=bool(online),
        last_seen= isoz(from_ts(last)) if last else None,
        pid=hb.get('pid'),
        version=hb.get('version')
    )

# ________ Heartbeat: API-key protected, CSRF-exempt (bot no login) _________
@csrf.exempt
@app.post('/api/telegram/heartbeat')
@require_api_key
def tg_heartbeat():
    data = request.get_json() or {}
    rec = {'ts': now_ts(), 'pid': data.get('pid'), 'version': data.get('version') or 'unknown'}
    _json_save(TELEGRAM_HB_FILE, rec)
    _extend_file(TELEGRAM_LOG_FILE,
                      f"[{isoz(from_ts(rec['ts']))}] heartbeat pid={rec['pid']} v={rec['version']}",
                      source='telegram')
    return jsonify(ok=True)

#______ Current time ________
def now_ts() -> int:
    return int(time.time())
#________Convert___________
def to_ts(dt):
    if not dt:
        return None
    return int(dt.timestamp())  
#_____Local > Native__________
def from_ts(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts))
#______ add Days to base ts_________
def add_days_ts(base_ts, days_float):
    if base_ts is None or not days_float:
        return None
    return int(base_ts + float(days_float) * 86400)
#_______ISO string for Clients_______
def isoz(dt):

    if not dt:
        return None
    ts = to_ts(dt)
    return datetime.utcfromtimestamp(ts).isoformat() + 'Z'

# -----------------
# WireGuard stuff
# _________________
def _host_peer(peer: Peer):
    import ipaddress as _ipa
    ip = _ipa.ip_interface(peer.address).ip
    mask = 32 if ip.version == 4 else 128
    return f"{ip}/{mask}"

def iface_devname(iface):
    import os
    name = iface.name or os.path.splitext(os.path.basename(iface.path))[0]
    return name.split(':')[-1]

def _wg_transfer(peer):
    rx, tx = _wg_rx_tx(peer)
    return rx + tx

def _wg_handshake(peer):
    try:
        dev = iface_devname(peer.iface)
        out = subprocess.check_output(
            ['wg', 'show', dev, 'latest-handshakes', peer.public_key],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().strip().split()[-1]
        return int(out) if out.isdigit() else 0
    except Exception:
        return 0

def _wg_enable(peer):
    dev = iface_devname(peer.iface)
    host_cidr = _host_peer(peer)
    cmd = ['wg', 'set', dev, 'peer', peer.public_key, 'allowed-ips', host_cidr]
    if peer.endpoint:
        cmd += ['endpoint', peer.endpoint]
    if peer.persistent_keepalive:
        cmd += ['persistent-keepalive', str(peer.persistent_keepalive)]
    subprocess.check_call(cmd, stderr=subprocess.DEVNULL)
    _unblackhole(host_cidr)

def _wg_disable(peer):
    dev = iface_devname(peer.iface)
    host_cidr = _host_peer(peer)
    subprocess.run(['wg', 'set', dev, 'peer', peer.public_key, 'remove'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _blackhole(host_cidr)

def _blackhole(host_cidr):
    subprocess.run(['ip', 'route', 'add', 'blackhole', host_cidr],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _unblackhole(host_cidr):
    subprocess.run(['ip', 'route', 'del', 'blackhole', host_cidr],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
def _iface_up(name: str) -> bool:
    try:
        subprocess.check_call(
            ['wg', 'show', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5
        )
        return True
    except Exception:
        return False

#___________________________________________________#    
"""
Check if -iface.name- exists and is up (LOCAL ONLY).
Node-backed ifaces are controlled by the node_agent.
"""
#____________________________________________________#
def _run_capture(cmd, timeout=20.0):
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False
    )
    out = (p.stdout or b'').decode('utf-8', 'ignore')
    return p.returncode, out


def _fix_route(iid: int, wgquick_output: str):
    """
    If wg-quick failed because 'ip route add ...' returned 'File exists',
    
    """
    if "RTNETLINK answers: File exists" not in (wgquick_output or ""):
        return False

    fixed_any = False
    for ln in (wgquick_output or "").splitlines():
        s = ln.strip()
        # ip -4 route add 176.66.66.3/32 dev wg0
        if not s.startswith("[#] ip "):
            continue
        if " route add " not in s:
            continue

        # ... route add ... > .. route replace ..
        cmdline = s.replace("[#] ", "", 1)
        cmdline = cmdline.replace(" route add ", " route replace ", 1)

        rc, out = _run_capture(shlex.split(cmdline), timeout=6.0)
        _iface_log(iid, f"$ {cmdline}\n{out}".rstrip())
        if rc == 0:
            fixed_any = True

    return fixed_any

def _check_iface_up(iface: InterfaceConfig):
    """
    Check if iface exists and is up (LOCAL ONLY).
    Node-backed ifaces are controlled by the node_agent.
    """
    if not iface:
        return
    if getattr(iface, 'node_id', None) is not None or (':' in (iface.name or '')):
        return

    dev = iface_devname(iface)
    iid = int(getattr(iface, "id", 0) or 0)

    cmd = ['wg-quick', 'up', dev]
    rc, out = _run_capture(cmd, timeout=20.0)
    _iface_log(iid, f"$ {' '.join(cmd)}\n{out}".rstrip())

    if rc == 0:
        return

    recovered = _fix_route(iid, out)
    if recovered and _iface_up(dev):
        _iface_log(iid, "Recovered from route-exists error; interface is up.")
        return

    current_app.logger.warning("wg-quick up %s failed (rc=%s); trying manual bring-up", dev, rc)

    steps = [
        (['ip', 'link', 'add', 'dev', dev, 'type', 'wireguard'], 6.0),
    ]

    for c, to in steps:
        rc2, o2 = _run_capture(c, timeout=to)
        _iface_log(iid, f"$ {' '.join(c)}\n{o2}".rstrip())

    if iface.path and os.path.isfile(iface.path):
        c = ['wg', 'setconf', dev, iface.path]
        rc2, o2 = _run_capture(c, timeout=10.0)
        _iface_log(iid, f"$ {' '.join(c)}\n{o2}".rstrip())

    c = ['ip', 'link', 'set', 'up', 'dev', dev]
    rc2, o2 = _run_capture(c, timeout=6.0)
    _iface_log(iid, f"$ {' '.join(c)}\n{o2}".rstrip())

    if not _iface_up(dev):
        raise RuntimeError(f"Interface {dev} bring-up failed; see Interface logs for details.")

# -----------------------------
# Endpoint & Interface presets 
# _____________________________
ENDPOINT_PRESETS_FILE = os.path.join(app.instance_path, 'endpoint_presets.json')
IFACE_LOG_DIR = os.path.join(app.instance_path, 'iface_logs')
os.makedirs(IFACE_LOG_DIR, exist_ok=True)

def _ifacelog_path(iid: int) -> str:
    return os.path.join(IFACE_LOG_DIR, f'{iid}.log')

def _iface_log(iid: int, text: str):
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    _extend_file(_ifacelog_path(iid), f"[{ts}] {text}")

@app.get('/api/iface/<int:iid>/status')
@login_required
def iface_status(iid):
    ret = _load_retention()["iface"]
    _may_autoclear(Path(_ifacelog_path(iid)), ret, persist_key="iface")
    iface = db.session.get(InterfaceConfig, iid) or abort(404)
    try:
        dev = iface_devname(iface)
    except Exception as e:
        current_app.logger.exception("iface_devname failed: %s", e)
        return jsonify(error="bad_iface_name"), 500

    try:
        up = _iface_up(dev) 
        return jsonify({'is_up': up, 'name': iface.name, 'dev': dev})
    except Exception as e:
        current_app.logger.exception("iface status failed: %s", e)
        return jsonify(error="iface_status_failed"), 500


@app.route('/api/iface/<int:iid>/logs', methods=['GET', 'DELETE'])
@login_required
def iface_logs(iid):
    p = _ifacelog_path(iid)

    if request.method == 'DELETE':
        try:
            Path(IFACE_LOG_DIR).mkdir(parents=True, exist_ok=True)
            if os.path.exists(p):
                open(p, 'w').close()          
            try:
                _last_cleared("iface")   
            except Exception:
                pass
        except Exception:
            current_app.logger.exception("Failed to clear iface log %s", iid)
            return jsonify(ok=False, error="clear_failed"), 500

        return jsonify(ok=True)
    
    # retention 
    ret = _load_retention()["iface"]
    _may_autoclear(Path(p), ret, persist_key="iface")

    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read()[-20000:] 
    except Exception:
        txt = ''

    if not txt.strip():
        iface = db.session.get(InterfaceConfig, iid) or abort(404)
        name = iface_devname(iface)

        def _run(cmd):
            try:
                out = subprocess.check_output(
                    shlex.split(cmd),
                    stderr=subprocess.DEVNULL,
                    timeout=6
                ).decode('utf-8', 'ignore')
                return out
            except Exception:
                return ''

        unit = f'wg-quick@{name}.service'
        txt = _run(f'journalctl -u {unit} -n 300 --no-pager --since "2 days ago"')
        if not txt.strip():

            k = _run('journalctl -k -n 300 --no-pager')
            txt = '\n'.join(
                ln for ln in k.splitlines()
                if ('wg' in ln.lower() or name in ln)
            )

    out = []
    for line in txt.splitlines():
        s = line.strip()
        ts = ''; msg = s; lvl = 'info'
        if s.startswith('[') and ']' in s:
            br = s.find(']')
            ts = s[1:br].strip()
            msg = s[br+1:].strip()
        out.append({'ts': ts, 'level': lvl, 'text': msg})

    return jsonify({'logs': out})

def _clear_retention():
    ret = _load_retention()["iface"]
    try:
        for p in Path(IFACE_LOG_DIR).glob('*.log'):
            _may_autoclear(p, ret, persist_key="iface")
    except Exception:
        pass

def _load_presets():
    try:
        with open(ENDPOINT_PRESETS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def _save_presets(presets):
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        with open(ENDPOINT_PRESETS_FILE, 'w') as f:
            json.dump(presets, f, indent=2)
            f.flush(); os.fsync(f.fileno())
    except Exception as e:
        current_app.logger.warning("Couldn't save endpoint presets: %s", e)

#-----------------
# Short Links
#_________________
SHORTLINKS_FILE = os.path.join(app.instance_path, 'short_links.json')

def _load_shortlinks():
    try:
        with open(SHORTLINKS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_shortlinks(m):
    os.makedirs(app.instance_path, exist_ok=True)
    with open(SHORTLINKS_FILE, 'w') as f:
        json.dump(m, f, indent=2)

def _token():
    return secrets.token_urlsafe(16)


@app.route('/api/peer/<int:pid>/shortlink', methods=['GET', 'POST'])
@require_api_key_or_login
def api_shortlink(pid):
    p = db.session.get(Peer, pid) or abort(404)
    m = _load_shortlinks()

    def _short_url(token: str) -> str:
        base = _panel_base()  # e.g https://panel.azumi.com:443/
        path = url_for('user_peer_page', token=token)  
        return urljoin(base, path.lstrip('/'))

    for t, obj in m.items():
        if obj.get('peer_id') == p.id:
            return jsonify(url=_short_url(t), token=t)

    t = _token()
    m[t] = {'peer_id': p.id}
    _save_shortlinks(m)
    return jsonify(url=_short_url(t), token=t)

#---------------------
# Setting Page
#____________________
@app.get('/settings')
@login_required
def settings_page():
    return render_template('settings.html')

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():

    if request.method == 'GET':
        s = _load_panel_settings() or {}
        xfp = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip().lower()
        detected_https = bool(_is_https())
        certp = (s.get("tls_cert_path") or "").strip()
        keyp  = (s.get("tls_key_path")  or "").strip()
        tls_cert_exists = bool(certp and os.path.isfile(certp))
        tls_key_exists  = bool(keyp and os.path.isfile(keyp))
        tls_effective   = bool(getattr(app, "_tls_enabled_effective", False))

        domain = (s.get('domain') or '').strip()
        if not domain:
            try:
                from urllib.parse import urlparse
                env_panel = (os.getenv('PANEL') or '').strip()
                if env_panel:
                    domain = (urlparse(env_panel).hostname or '').strip() or domain
            except Exception:
                pass
            if not domain:
                domain = (request.host or '').split(':', 1)[0].strip()

        def _to_int(v):
            try:
                if v is None or v == "":
                    return None
                return int(v)
            except Exception:
                return None

        s_out = dict(s)
        s_out["http_port"] = _to_int(s.get("http_port"))
        s_out["https_port"] = _to_int(s.get("https_port"))

        return jsonify({
        **s_out,
        "tls_enabled": bool(s.get("tls_enabled")),    
        "tls_effective": tls_effective,               
        "tls_cert_exists": tls_cert_exists,
        "tls_key_exists": tls_key_exists,
        "domain": domain,
        "current_scheme": "https" if detected_https else "http",
        "cookie_secure": bool(app.config.get("SESSION_COOKIE_SECURE", False)),
        "detected_https": bool(detected_https),
     })


    data = request.get_json(silent=True) or {}
    cur = _load_panel_settings() or {}

    def _port(v):
        if v in (None, ""):
            return None
        try:
            i = int(v)
        except Exception:
            return None
        return i if 1 <= i <= 65535 else None

    tls_enabled = bool(data.get("tls_enabled", False))
    domain      = (data.get("domain") or "").strip()

    force_https = bool(data.get("force_https_redirect", False))
    hsts        = bool(data.get("hsts", False))

    if not tls_enabled:
        force_https = False
        hsts = False

    http_port  = _port(data.get("http_port"))
    https_port = _port(data.get("https_port"))


    if tls_enabled and https_port is None:
        https_port = _port(cur.get("https_port"))
    if (not tls_enabled) and http_port is None:
        http_port = _port(cur.get("http_port"))

    tls_cert_path = (cur.get("tls_cert_path") or "").strip()
    tls_key_path  = (cur.get("tls_key_path")  or "").strip()

    payload = {
        "tls_enabled": tls_enabled,
        "domain": domain,
        "force_https_redirect": force_https,
        "hsts": hsts,
        "http_port": http_port,
        "https_port": https_port,
        "tls_cert_path": tls_cert_path,
        "tls_key_path": tls_key_path,
    }

    _save_panel_settings(payload)

    try:
        xfp = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        serving_https = (xfp == "https") or bool(request.is_secure)
        if serving_https:
            app.config.update(
                SESSION_COOKIE_SECURE=True,
                REMEMBER_COOKIE_SECURE=True,
                SESSION_COOKIE_SAMESITE="Lax",
            )
    except Exception:
        pass

    try:
        next_url = _panel_base()
    except Exception:
        next_url = None

    return jsonify(ok=True, settings=payload, next_url=next_url, requires_restart=True)



@app.get('/api/template_settings')
@login_required
def template_settings_get():
    return jsonify(_load_template_settings())

@app.post('/api/template_settings')
@login_required
def template_settings_post():
    data = request.get_json(silent=True) or {}
    cur = _load_template_settings()

    if 'selected' in data:
        sel = (data.get('selected') or '').strip().lower()
        if sel not in ('default','compact','minimal','pro'):
            return jsonify(error='invalid template'), 400
        cur['selected'] = sel

    if 'socials' in data:
        s = data.get('socials') or {}
        cur['socials'] = {
            'telegram':  (s.get('telegram') or '').strip(),
            'whatsapp':  (s.get('whatsapp') or '').strip(),
            'instagram': (s.get('instagram') or '').strip(),
            'phone':     (s.get('phone') or '').strip(),
            'website':   (s.get('website') or '').strip(),
            'email':     (s.get('email') or '').strip(),
        }

    _save_template_settings(cur)
    return jsonify(ok=True, settings=cur)

# _______Telegram Logs_________
HEARTBEAT_WORD = "heartbeat"

def _parse_tg(s: str):

    s = (s or '').rstrip('\n')
    m = re.match(r'^\[([0-9T:\-]{19}Z)\]\s*(.*)$', s)
    ts_iso, text = (m.group(1), m.group(2)) if m else (None, s)

    ts_dt = None
    if ts_iso:
        try:
            ts_dt = datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            ts_dt = None

    low = text.lower()
    if HEARTBEAT_WORD in low:
        kind = 'heartbeat'
    elif 'error' in low:
        kind = 'error'
    elif 'warn' in low:
        kind = 'warning'
    else:
        kind = 'info'

    return {'ts_iso': ts_iso, 'ts_dt': ts_dt, 'text': text, 'kind': kind, 'raw': s}

def _in_range(dt, from_s, to_s):
    if not dt:
        return True
    ok = True
    if from_s:
        try: ok = ok and dt >= datetime.fromisoformat(from_s.replace('Z',''))
        except: pass
    if to_s:
        try: ok = ok and dt <= datetime.fromisoformat(to_s.replace('Z',''))
        except: pass
    return ok

ret = _load_retention()["tg_admin"]
_may_autoclear(Path(TELEGRAM_ADMIN_LOG_FILE), ret, persist_key="tg_admin")

@app.get('/api/telegram/admin_logs')
@login_required
def tg_admin_logs():
    tail = _read_tail(TELEGRAM_ADMIN_LOG_FILE, 20000)
    rows = []
    for line in tail.splitlines():
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return jsonify({"logs": rows})

@app.delete('/api/telegram/admin_logs')
@login_required
def tg_adminlogs_clear():
    with open(TELEGRAM_ADMIN_LOG_FILE, 'w', encoding='utf-8') as f:
        pass
    return jsonify(ok=True)

#_____admin_id, admin_username, action, details____
@csrf.exempt
@app.post('/api/telegram/admin_log')
@require_api_key
def tg_adminlog():

    data = request.get_json(silent=True) or {}
    rec = {
        "ts": _now_iso(),
        "admin_id": str(data.get("admin_id") or ""),
        "admin_username": data.get("admin_username") or "",
        "action": data.get("action") or "",
        "details": data.get("details") or ""
    }
    _extend_file(TELEGRAM_ADMIN_LOG_FILE, json.dumps(rec, ensure_ascii=False))
    _extend_file(TELEGRAM_LOG_FILE, f"[{rec['ts']}] admin {rec['admin_id']} {rec['action']} {rec['details']}")
    return jsonify(ok=True, recorded=True)

# -------------
# Template
# _____________

@app.route('/u/<token>')
@require_api_key_or_login
def user_peer_page(token):
    m = _load_shortlinks()
    if token not in m:
        abort(404)

    ts = _load_template_settings() 
    sel = (ts.get('selected') or 'default').lower()
    s   = ts.get('socials') or {}

    tmap = {
        'default': 'user_peer.html',
        'compact': 'user_peer_compact.html',
        'minimal': 'user_peer_minimal.html',
        'pro':     'user_peer_pro.html',
    }
    tpl = tmap.get(sel, 'user_peer.html')

    return render_template(
        tpl,
        token=token,
        support_telegram = (s.get('telegram')  or ''),
        support_whatsapp = (s.get('whatsapp')  or ''),
        support_instagram= (s.get('instagram') or ''),
        support_phone    = (s.get('phone')     or ''),
        support_website  = (s.get('website')   or ''),
        support_email    = (s.get('email')     or ''),
    )


@app.get('/preview/template/<name>')
@login_required
def preview_template(name):
    name = (name or '').lower()
    tmap = {
        'default': 'user_peer.html',
        'compact': 'user_peer_compact.html',
        'minimal': 'user_peer_minimal.html',
        'pro':     'user_peer_pro.html',
    }
    tpl = tmap.get(name)
    if not tpl:
        abort(404)

    socials = {
        'telegram': '@preview',
        'whatsapp': '',
        'instagram': '',
        'phone': '',
        'website': '',
        'email': '',
    }

    html = render_template(
        tpl,
        token="PREVIEW_TOKEN",
        preview=True,  
        support_telegram=socials['telegram'],
        support_whatsapp=socials['whatsapp'],
        support_instagram=socials['instagram'],
        support_phone=socials['phone'],
        support_website=socials['website'],
        support_email=socials['email'],
    )

    #____ Live Preview ____
    stub = f"""
<script>
  (function() {{
    try {{
      window.PREVIEW = true;
      const now = Math.floor(Date.now()/1000);
      const mock = {{
        ok: true,
        name: "b1",
        address: "10.66.66.2/24",
        endpoint: "167.71.78.88:57015",
        status: "offline",
        unlimited: false,
        limit_unit: "Mi",
        data_limit: 1024,                
        used_bytes: 5632 * 1024 * 1024,  
        expires_at_ts: now + 14*24*3600,
        ttl_seconds:  14*24*3600
      }};
      const respond = (o) => Promise.resolve({{
        ok: true, status: 200,
        json: async () => o, text: async () => JSON.stringify(o)
      }});
      const originalFetch = window.fetch;
      window.fetch = function(url, opts) {{
        try {{
          const u = (typeof url === 'string') ? url : (url && url.url) || '';
          if (u.includes('/api/u/') || u.includes('/api/peer/')) return respond(mock);
        }} catch(_){{}}
        return respond({{}});
      }};
      document.addEventListener('click', function(e){{
        const a = e.target.closest('a[href]'); if (a) e.preventDefault();
      }}, true);
    }} catch(_){{}}
  }})();
</script>"""

    idx = html.rfind('</body>')
    html = html[:idx] + stub + html[idx:] if idx != -1 else html + stub
    resp = make_response(html)
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['Content-Security-Policy'] = (
    "frame-ancestors 'self'; "
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
    "font-src 'self' https://cdnjs.cloudflare.com data:; "
    "img-src 'self' data: blob:; "
    "connect-src 'none'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-src 'none'"
)

    return resp

@app.route('/api/u/<token>')
@require_api_key_or_login
def user_peer(token):
    m = _load_shortlinks()
    rec = m.get(token)
    if not rec:
        abort(404)
    p = db.session.get(Peer, rec['peer_id']) or abort(404)
    _expire()

    total = _wg_transfer(p)
    used_live = max(0, total - int(getattr(p, 'bytes_offset', 0) or 0))
    exp_ts = to_ts(getattr(p, 'expires_at', None))
    ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None
    used_db = int(getattr(p, 'used_bytes_total', 0) or 0)
    unit = getattr(p, 'data_limit_unit', 'Mi') or 'Mi'
    lim_val = int(getattr(p, 'data_limit_value', 0) or 0)
    lim_bytes = 0
    if lim_val and not getattr(p, 'unlimited', False):
        lim_bytes = lim_val * (1024*1024 if unit == 'Mi' else 1024*1024*1024)
    
    used_eff = used_live + used_db
    if lim_bytes:
        used_eff = min(used_eff, lim_bytes)
    
    if getattr(p, 'status', '') == 'blocked' and lim_bytes:
        used_eff = lim_bytes

    return jsonify({
    'name': p.name,
    'iface': p.iface.name,
    'address': p.address,
    'endpoint': p.endpoint or '',
    'status': p.status,
    'unlimited': bool(getattr(p, 'unlimited', False)),
    'limit_unit': unit,
    'data_limit': lim_val,
    'used_bytes': used_live,
    'used_bytes_db': used_db,                
    'used_effective_bytes': used_eff,         
    'time_limit_days': getattr(p, 'time_limit_days', None),
    'start_on_first_use': bool(getattr(p, 'start_on_first_use', False)),
    'first_used_at': isoz(getattr(p, 'first_used_at', None)),
    'expires_at': isoz(getattr(p, 'expires_at', None)),
    'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
    'expires_at_ts': exp_ts,
    'ttl_seconds': ttl_seconds,
    'allowed_ips': p.allowed_ips or '0.0.0.0/0, ::/0',
    'dns': p.dns or p.iface.dns or '',
    'mtu': p.mtu or p.iface.mtu or None
    })

@app.route('/api/u/<token>/config')
@require_api_key_or_login
def userpeer_config(token):
    m = _load_shortlinks()
    rec = m.get(token)
    if not rec:
        abort(404)
    p = db.session.get(Peer, rec['peer_id']) or abort(404)
    cfg = _client_conf_txt(p)
    return make_response(cfg, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': f'attachment; filename={p.name or "peer"}.conf'
    })

# ----------
# Login
# __________
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class Admin(UserMixin):
    def __init__(self, username='admin'):
        self.id = '1'
        self.username = username
        self.is_admin = True
        self.is_superuser = True

@login_manager.user_loader
def load_user(user_id):
    if user_id != '1':
        return None
    from models import AdminAccount
    acc = AdminAccount.query.first()
    if not acc:
        return None
    return Admin(acc.username)

# ---------------------
# Public IPv4 & IPV6 (cached)
# _____________________
_public_ip_cache = {'ip': None, 'ts': 0}
_ipv6_cache = {"ts": 0, "val": ""}

def _public_ipv4(force=False):
    now = time.time()
    if not force and _public_ip_cache['ip'] and (now - _public_ip_cache['ts'] < 3600):
        return _public_ip_cache['ip']
    try:
        ip = requests.get('https://api.ipify.org', timeout=2).text.strip()
        if ip:
            _public_ip_cache['ip'] = ip
            _public_ip_cache['ts'] = now
            return ip
    except Exception:
        pass
    return _public_ip_cache['ip']


def _public_ipv6():

    try:
        now = time.time()

        if _ipv6_cache["val"] and (now - _ipv6_cache["ts"] < 600):
            v = (_ipv6_cache["val"] or "").strip()
            try:
                ip = ipaddress.ip_address(v)
                if ip.version == 6 and ip.is_global:
                    return v
            except Exception:
                pass
            _ipv6_cache.update(ts=now, val="")

        r = requests.get("https://api64.ipify.org", timeout=1.5)
        if not r.ok:
            return _ipv6_cache["val"]

        v = (r.text or "").strip()

        try:
            ip = ipaddress.ip_address(v)
            if ip.version == 6 and ip.is_global:
                _ipv6_cache.update(ts=now, val=v)
                return v
        except Exception:
            pass

        _ipv6_cache.update(ts=now, val="")
        return ""
    except Exception:
        return _ipv6_cache.get("val") or ""
    
# ---------------------------
# WireGuard interface config
# ___________________________
def find_iface(path):
    post_up, post_down = [], []
    address = listen_port = private_key = mtu = dns = None
    in_iface = False
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('[') and line.endswith(']'):
                in_iface = (line[1:-1] == 'Interface')
                continue
            if not in_iface or '=' not in line:
                continue
            key, val = [s.strip() for s in line.split('=', 1)]
            lk = key.lower()
            if lk == 'address':
                address = val
            elif lk == 'listenport':
                try: listen_port = int(val)
                except: pass
            elif lk == 'privatekey':
                private_key = val
            elif lk == 'mtu':
                try: mtu = int(val)
                except: pass
            elif lk == 'dns':
                dns = val
            elif lk == 'postup':
                post_up.append(val)
            elif lk == 'postdown':
                post_down.append(val)
    if not (address and listen_port and private_key):
        return None
    return InterfaceConfig(
        name=os.path.splitext(os.path.basename(path))[0],
        path=path, address=address,
        listen_port=listen_port,
        private_key=private_key,
        mtu=mtu, dns=dns,
        post_up='\n'.join(post_up),
        post_down='\n'.join(post_down)
    )

# ------------------------------------
# IP helpers | Single Valid IPV4
# ____________________________________
def _first_cidr(address_field: str | None) -> str | None:

    if not address_field:
        return None
    parts = [p.strip() for p in re.split(r'[,\s]+', address_field) if p.strip()]
    v4, vX = None, None
    for p in parts:
        if '/' not in p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4 and not v4:
                v4 = p
            if not vX:
                vX = p
        except Exception:
            continue
    return v4 or vX

def _safe_ip(cidr):
    import ipaddress as _ipa
    try:
        return _ipa.ip_interface(cidr).ip
    except Exception:
        return None

def _wg_allowed_ips(iface):
    used = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', iface.name, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) != 2:
                continue
            for c in parts[1].split(','):
                h = _safe_ip(c.strip())
                if h is not None:
                    used.add(h)
    except Exception:
        pass
    return used

def _conf_allowed_ips(iface):
    used = set()
    p = iface.path
    if not (p and os.path.isfile(p)):
        return used
    try:
        with open(p, 'r') as f:
            in_peer, buf = False, []
            for raw in f:
                line = raw.strip()
                if line.startswith('[') and line.endswith(']'):
                    if in_peer:
                        for L in buf:
                            if L.lower().startswith('allowedips'):
                                for c in L.split('=', 1)[1].split(','):
                                    h = _safe_ip(c.strip())
                                    if h is not None:
                                        used.add(h)
                        buf = []
                    in_peer = (line[1:-1].lower() == 'peer')
                else:
                    if in_peer and '=' in line:
                        buf.append(line)
            if in_peer and buf:
                for L in buf:
                    if L.lower().startswith('allowedips'):
                        for c in L.split('=', 1)[1].split(','):
                            h = _safe_ip(c.strip())
                            if h is not None:
                                used.add(h)
    except Exception:
        pass
    return used

def _read_iface_conf(conf_path: str | None) -> str | None:

    if not conf_path or not os.path.isfile(conf_path):
        return None

    try:
        in_iface = False
        with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                if line.startswith("[") and line.endswith("]"):
                    in_iface = (line[1:-1].strip().lower() == "interface")
                    continue

                if not in_iface or "=" not in line:
                    continue

                k, v = [x.strip() for x in line.split("=", 1)]
                if k.lower() == "address":
                    return v
    except Exception:
        pass

    return None


def _available_ips(iface):
    """
    Available IPs are derived from the interface subnet (Address=...).
    For LOCAL interfaces: prefer reading Address from /etc/wireguard/<iface>.conf 

    """
    if not iface:
        return []

    import ipaddress as _ipa

    try:
        is_node_iface = (getattr(iface, "node_id", None) is not None) or (":" in (iface.name or ""))

        addr_field = None
        if not is_node_iface:
            addr_field = _read_iface_conf(getattr(iface, "path", None))

        if not addr_field:
            addr_field = getattr(iface, "address", None)

        addr = _first_cidr(addr_field)
        if not addr:
            return []

        if (not is_node_iface) and addr_field and (getattr(iface, "address", None) != addr_field):
            try:
                iface.address = addr_field
                db.session.add(iface)
                db.session.commit()
            except Exception:
                db.session.rollback()

        net = _ipa.ip_network(addr, strict=False)
        iface_ip = _ipa.ip_interface(addr).ip

        used_hosts = set()

        for p in (getattr(iface, "peers", None) or []):
            h = _safe_ip(getattr(p, "address", None))
            if h is not None:
                used_hosts.add(h)

        if not is_node_iface:
            used_hosts |= _wg_allowed_ips(iface)
            used_hosts |= _conf_allowed_ips(iface)

        return [
            f"{host}/{net.prefixlen}"
            for host in net.hosts()
            if host != iface_ip and host not in used_hosts
        ]

    except Exception as e:
        current_app.logger.exception("_available_ips failed for iface=%r: %s", getattr(iface, "name", None), e)
        return []


def log_event(peer, event, details=''):
    e = PeerEvent(peer_id=peer.id, event=event, details=details)
    db.session.add(e)
    db.session.commit()

def _conv_time_limit(payload):
    try:
        d = float(payload.get('time_limit_days') or 0)
        h = float(payload.get('time_limit_hours') or 0)
        h = max(0.0, min(23.0, h))
        ttl = d + (h / 24.0)
        return ttl if ttl > 0 else None
    except Exception:
        return None

def _peer_in_conf(conf_path, public_key):
    try:
        with open(conf_path, 'r') as f:
            lines = f.readlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip().lower()
            if line == '[peer]':
                block = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('['):
                    block.append(lines[i]); i += 1
                for L in block:
                    if L.strip().lower().startswith('publickey'):
                        if L.split('=', 1)[1].strip() == public_key:
                            return True
                continue
            i += 1
    except Exception:
        pass
    return False

def _norm_conftext(txt: str) -> str:
    import re
    if txt is None:
        return ''
    txt = txt.replace('\r\n', '\n').replace('\r', '\n')
    txt = re.sub(r'\n{3,}', '\n\n', txt)
    txt = txt.strip('\n') + '\n'
    return txt


def _peer_to_conf(peer: Peer):
    conf_path = getattr(peer.iface, 'path', None)
    if not conf_path:
        return
    try:
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)

        if _peer_in_conf(conf_path, peer.public_key):
            return

        host_cidr = _host_peer(peer)

        block_lines = [
            '[Peer]',
            f'PublicKey = {peer.public_key}',
            f'AllowedIPs = {host_cidr}',
        ]
        if peer.endpoint:
            block_lines.append(f'Endpoint = {peer.endpoint}')
        if peer.persistent_keepalive:
            block_lines.append(f'PersistentKeepalive = {peer.persistent_keepalive}')

        block_txt = '\n'.join(block_lines) + '\n'

        existing = ''
        if os.path.isfile(conf_path):
            with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
                existing = f.read()

        existing = (existing or '').replace('\r\n', '\n').replace('\r', '\n').rstrip('\n')

        if existing.strip() == '':
            combined = block_txt
        else:
            combined = existing + '\n\n' + block_txt

        combined = _norm_conftext(combined)

        import tempfile
        d = os.path.dirname(conf_path) or '.'
        fd, tmp_path = tempfile.mkstemp(prefix='.wgconf.', dir=d)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tf:
                tf.write(combined)
            os.replace(tmp_path, conf_path)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

    except Exception as e:
        current_app.logger.warning("Failed to append peer to conf %s: %s", conf_path, e)


def _remove_peer(peer: Peer):
    conf_path = getattr(peer.iface, 'path', None)
    if not (conf_path and os.path.isfile(conf_path)):
        return
    try:
        with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        out_lines, i = [], 0
        while i < len(lines):
            line = lines[i]
            if line.strip().lower() == '[peer]':
                block = [line]
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('['):
                    block.append(lines[i]); i += 1

                has_pk = any(
                    l.strip().lower().startswith('publickey')
                    and '=' in l
                    and l.split('=', 1)[1].strip() == peer.public_key
                    for l in block
                )
                if not has_pk:
                    out_lines.extend(block)
            else:
                out_lines.append(line); i += 1

        combined = _norm_conftext(''.join(out_lines))

        import tempfile
        d = os.path.dirname(conf_path) or '.'
        fd, tmp_path = tempfile.mkstemp(prefix='.wgconf.', dir=d)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tf:
                tf.write(combined)
            os.replace(tmp_path, conf_path)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

    except Exception as e:
        current_app.logger.warning("Failed to remove peer from conf %s: %s", conf_path, e)


def _sync_peer(peer: Peer):
    _remove_peer(peer)
    _peer_to_conf(peer)

# ----------------------
# Config export helpers
# ______________________

PANEL_SETTINGS_FILE = os.path.join(app.instance_path, 'panel_settings.json')

def _panel_base() -> str:
    """
    Return canonical base URL ending with '/', using panel_settings https_port when TLS is enabled.
    Examples:
      https://panel.azumi.com/
      https://panel.azumi.com:8443/
      http://203.10.113.20:8080/
    """
    s = _load_panel_settings() or {}
    tls_enabled = bool(s.get('tls_enabled'))
    domain = (s.get('domain') or '').strip()

    req_host = (request.host or '').split(':', 1)[0]
    host = domain or req_host or 'localhost'

    def _env_port() -> int | None:
        b = (os.getenv('BIND') or '').strip()
        if b and ':' in b:
            try:
                return int(b.rsplit(':', 1)[1])
            except Exception:
                pass
        p = (os.getenv('PORT') or os.getenv('HTTPS_PORT') or '').strip()
        try:
            return int(p) if p else None
        except Exception:
            return None

    if tls_enabled:
        cfg_port = s.get('https_port')
        try:
            cfg_port = int(cfg_port) if cfg_port else None
        except Exception:
            cfg_port = None

        port = cfg_port or _env_port() or 443
        netloc = f"{host}:{port}" if port and port != 443 else host
        return f"https://{netloc}/"

    rt = _load_runtime() or {}
    rport = None
    try:
        rport = int(rt.get('port') or 0) or None
    except Exception:
        rport = None

    pub_ip = _public_ipv4() or req_host or 'localhost'
    if rport and rport != 80:
        return f"http://{pub_ip}:{rport}/"
    return f"http://{pub_ip}/"

    
PANEL_SETTINGS_FILE = os.path.join(app.instance_path, "panel_settings.json")

def _load_panel_settings():
    os.makedirs(app.instance_path, exist_ok=True)
    try:
        with open(PANEL_SETTINGS_FILE, "r", encoding="utf-8") as f:
            j = json.load(f) or {}
    except Exception:
        j = {}

    def _port(v, default=None):
        if v in (None, ""):
            return default
        try:
            p = int(v)
            return p if 1 <= p <= 65535 else default
        except Exception:
            return default

    return {
        "tls_enabled": bool(j.get("tls_enabled", False)),
        "domain": (j.get("domain") or "").strip(),
        "force_https_redirect": bool(j.get("force_https_redirect", False)),
        "hsts": bool(j.get("hsts", False)),
        "http_port": _port(j.get("http_port"), None),
        "https_port": _port(j.get("https_port"), 443),
        "tls_cert_path": (j.get("tls_cert_path") or "").strip(),
        "tls_key_path": (j.get("tls_key_path") or "").strip(),
    }

def _is_https(req=None) -> bool:
    """
    Return True if the *current request* is effectively HTTPS.

    Trust only:
      - request.is_secure (direct TLS)
      - proxy/CDN headers indicating scheme:
        Forwarded, X-Forwarded-Proto, X-Forwarded-Ssl, X-Url-Scheme, CF-Visitor

    IMPORTANT:
    Do NOT treat tls_enabled / _tls_enabled_effective as "this request is HTTPS".
    """
    req = req or request
    try:
        if getattr(req, "is_secure", False):
            return True

        fwd = (req.headers.get("Forwarded") or "").lower()
        if "proto=https" in fwd:
            return True

        xfp = (req.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if xfp == "https":
            return True

        xssl = (req.headers.get("X-Forwarded-Ssl") or "").strip().lower()
        if xssl in ("on", "1", "true", "yes"):
            return True

        xsch = (req.headers.get("X-Url-Scheme") or "").strip().lower()
        if xsch == "https":
            return True

        cfv = (req.headers.get("CF-Visitor") or "")
        if "https" in cfv.lower():
            return True

    except Exception:
        pass
    return False


@app.before_request
def _cookie_scheme():
    """
    Force cookie flags to match the *current request* scheme.
    This prevents Secure cookies being set on HTTP responses.
    """
    secure_now = _is_https()
    current_app.config.update(
        SESSION_COOKIE_SECURE=secure_now,
        REMEMBER_COOKIE_SECURE=secure_now,
    )
    current_app.config["PREFERRED_URL_SCHEME"] = "https" if secure_now else "http"

def _save_panel_settings(j: dict):
    os.makedirs(app.instance_path, exist_ok=True)
    with open(PANEL_SETTINGS_FILE, 'w') as f:
        json.dump(j, f, indent=2)

def _server_host() -> str | None:
    s = _load_panel_settings()
    if s.get('tls_enabled') and s.get('domain'):
        return s['domain']
    try:
        return _public_ipv4()
    except Exception:
        return None

def _norm_hostport(host: str, port: int | None) -> str:
    if not host or not port:
        return ''
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f'[{host}]:{port}'
    except ValueError:
        pass
    return f'{host}:{port}'

def _endpoint_fallback(iface) -> str:

    host = _server_host()
    port = getattr(iface, 'listen_port', None)
    return _norm_hostport(host, port) if host and port else ''

def _server_publickey(iface):
    try:
        nid = getattr(iface, 'node_id', None)
        if nid is not None:
            from models import Node
            n = db.session.get(Node, nid)
            dev = iface_devname(iface)        
            try:
                j = node_get(n, f"/api/iface/{dev}/pubkey", timeout=6)
                pk = (j.get("public_key") or "").strip()
                if pk:
                    return pk
            except Exception:
                pass  
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ['wg', 'pubkey'],
            input=(iface.private_key + '\n').encode(),
            stderr=subprocess.DEVNULL, timeout=2.0
        )
        return out.decode().strip()
    except Exception:
        return ''
    
@app.route('/api/nodes/<int:nid>/peer/<path:pub>', methods=['DELETE'])
@admin_required
def node_peer_delete(nid, pub):
    n = Node.query.get_or_404(nid)
    try:
        node_delete(n, f'/api/peer/{pub}')
    except Exception as e:
        current_app.logger.exception("Node peer delete failed")
        return jsonify(error="node_delete_failed", detail=str(e)), 502

    try:
        p = (db.session.query(Peer)
             .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
             .filter(Peer.public_key == pub)
             .filter(or_(InterfaceConfig.name.like(f"n{nid}:%"),
                         InterfaceConfig.node_id == nid))
             .first())
        if p:
            db.session.delete(p)
            db.session.commit()
    except Exception:
        pass
    return jsonify(ok=True)

def _client_conf_txt(peer: Peer) -> str:

    iface = peer.iface
    server_pub = ""
    try:
        if iface is not None:
            server_pub = _server_publickey(iface)
    except Exception:
        server_pub = ""

    dns_val = ""
    try:
        dns_val = _effective_dns(peer) or ""
    except Exception:
        dns_val = (peer.dns or (iface.dns if iface is not None else "") or "")

    ep = peer.endpoint or ""
    if not ep:
        try:
            if iface is not None:
                ep = _endpoint_fallback(iface) or ""
        except Exception:
            ep = ""

    mtu_val = peer.mtu or (iface.mtu if iface is not None else None)

    lines = []
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {peer.private_key}")
    lines.append(f"Address = {peer.address}")
    if dns_val:
        lines.append(f"DNS = {dns_val}")
    if mtu_val:
        lines.append(f"MTU = {mtu_val}")
    lines.append("")
    lines.append("[Peer]")
    if server_pub:
        lines.append(f"PublicKey = {server_pub}")
    if ep:
        lines.append(f"Endpoint = {ep}")
    lines.append(f"AllowedIPs = {peer.allowed_ips or '0.0.0.0/0, ::/0'}")
    if peer.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
    lines.append("")

    return "\n".join(lines)

# ------------------------------------------------
# Template settings (selected template + socials)
# ________________________________________________
TEMPLATE_SETTINGS_FILE = os.path.join(app.instance_path, 'template_settings.json')

def _load_template_settings():
    os.makedirs(app.instance_path, exist_ok=True)
    try:
        with open(TEMPLATE_SETTINGS_FILE, 'r') as f:
            j = json.load(f)
    except Exception:
        j = {}
    j.setdefault('selected', 'default') 
    j.setdefault('socials', {
        'telegram': '',
        'whatsapp': '',
        'instagram': '',
        'phone': '',
        'website': '',
        'email': '',
    })
    return j

def _save_template_settings(j: dict):
    os.makedirs(app.instance_path, exist_ok=True)
    with open(TEMPLATE_SETTINGS_FILE, 'w') as f:
        json.dump(j, f, indent=2)

def _disable_peer(peer, reason: str, status: str = 'offline'):
    try:
        nid = getattr(peer.iface, 'node_id', None)
        if nid is not None:
            n = db.session.get(Node, nid)
            payload = {}
            try:
                payload['host_cidr'] = _host_peer(peer)
            except Exception:
                pass
            node_post(n, f'/api/peer/{peer.public_key}/disable', payload)
        else:
            _wg_disable(peer)
        peer.status = status
        log_event(peer, reason, f'status → {status}')
        return True
    except Exception:
        current_app.logger.exception("Disable failed for peer %s", getattr(peer, 'id', '?'))
        return False
# ----------------------
# Expiry  + total usage
# ______________________
def _expire():
    now = now_ts()
    changed = False

    for peer in Peer.query.all():

        if getattr(peer, 'start_on_first_use', False) and not getattr(peer, 'first_used_at', None):
            hs = _latest_handshake(peer)  
            if hs and hs > 0:
                peer.first_used_at = from_ts(now)
                if getattr(peer, 'time_limit_days', None) and not getattr(peer, 'unlimited', False):
                    exp_ts = add_days_ts(now, float(peer.time_limit_days))
                    peer.expires_at = from_ts(exp_ts)
                log_event(peer, 'first_use', 'Timer started on first handshake')
                changed = True

        if (not getattr(peer, 'start_on_first_use', False)
            and getattr(peer, 'time_limit_days', None)
            and not getattr(peer, 'expires_at', None)
            and not getattr(peer, 'unlimited', False)):
            anchor_ts = to_ts(getattr(peer, 'first_used_at', None)) or now
            peer.expires_at = from_ts(add_days_ts(anchor_ts, float(peer.time_limit_days)))
            changed = True

        offset   = int(getattr(peer, 'bytes_offset', 0) or 0)
        is_node  = getattr(getattr(peer, 'iface', None), 'node_id', None) is not None

        total_bytes = None            
        used_live   = 0               
        used_db     = int(getattr(peer, 'used_bytes_total', 0) or 0)  

        if not is_node:
            total_bytes = _wg_transfer(peer)
            used_live   = max(0, int(total_bytes) - offset)
        else:
            used_live = int(getattr(peer, 'used_runtime_bytes', 0) or 0)

        used_effective = used_db + used_live

        exp_ts = to_ts(getattr(peer, 'expires_at', None))
        if exp_ts and now >= exp_ts and peer.status != 'blocked':
            _disable_peer(peer, 'expired', status='blocked')
            log_event(peer, 'expired', f'Expired at {isoz(from_ts(exp_ts))}')
            changed = True

        limit_bytes = peer.limit_bytes() if hasattr(peer, 'limit_bytes') else None
        if limit_bytes is not None and peer.status != 'blocked':
            if used_effective >= limit_bytes:
                peer.used_bytes_total = used_db + used_live

                if not is_node:
                    if total_bytes is None:
                        total_bytes = _wg_transfer(peer)
                    peer.bytes_offset = int(total_bytes or 0)
                else:
                    if hasattr(peer, 'used_runtime_bytes'):
                        try:
                            setattr(peer, 'used_runtime_bytes', 0)
                        except Exception:
                            pass

                _disable_peer(peer, 'limit_reached', status='blocked')
                log_event(peer, 'limit_reached', f'Used {used_effective} bytes')
                changed = True

    if changed:
        db.session.commit()

@app.post('/api/peer/<int:pid>/clear_total')
@login_required   
def peer_clear_total(pid):
    p = Peer.query.get_or_404(pid)

    prev = int(getattr(p, 'used_bytes_total', 0) or 0)
    p.used_bytes_total = 0  
    db.session.commit()

    log_event(p, 'clear_total', f'Lifetime cleared (was {prev} bytes)')
    return jsonify(success=True, cleared=prev)

def _on_boot():
    for peer in Peer.query.all():
        try:
            if (peer.iface and
                (getattr(peer.iface, 'node_id', None) is not None or
                 ':' in (peer.iface.name or ''))):
                continue

            if peer.status in ('offline', 'blocked'):
                _wg_disable(peer)
            else:
                _wg_enable(peer)
            _sync_peer(peer)
        except Exception as e:
            current_app.logger.warning("Reconcile peer %s failed: %s", peer.name, e)
    db.session.commit()


# ------------------
# Last Public IP
# __________________
LAST_PUBLIC_IP_FILE = os.path.join(app.instance_path, 'last_public_ipv4.txt')

def _read_lastip():
    try:
        with open(LAST_PUBLIC_IP_FILE, 'r') as f:
            return (f.read() or '').strip()
    except Exception:
        return ''

def _write_lastip(ip):
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        with open(LAST_PUBLIC_IP_FILE, 'w') as f:
            f.write((ip or '').strip())
    except Exception:
        pass

def _host_port(ep: str):
    if not ep: return ('', None)
    s = ep.strip()
    if s.startswith('['):
        if ']' in s:
            host, rest = s[1:].split(']', 1)
            port = rest.lstrip(':') or None
            return (host, int(port) if port and port.isdigit() else None)
        return (s, None)
    if ':' in s:
        host, port = s.rsplit(':', 1)
        return (host, int(port) if port.isdigit() else None)
    return (s, None)

def repoint_endpoints():
    cur = _public_ipv4(force=True) or ''
    prev = _read_lastip()
    if not cur or not prev or cur == prev:
        if cur and cur != prev: _write_lastip(cur)
        return

    changed = 0
    for p in Peer.query.all():
        host, port = _host_port(p.endpoint or '')
        if host == prev:
            p.endpoint = f"{cur}:{port}" if port else cur
            changed += 1
    if changed:
        db.session.commit()
        current_app.logger.info("Repointed %s peer endpoints from %s to %s", changed, prev, cur)

    _write_lastip(cur)

# -----------
# Bootstrap
# ___________
def bootstrap():
    with app.app_context():
        try:
            db.create_all()
            _admin_columns()
            app.logger.info("DB initialized / migrated OK")
        except OperationalError:
            app.logger.exception("DB init failed")
        from models import InterfaceConfig 

        p = (app.config.get('WG_CONF_PATH')
             or app.config.get('WIREGUARD_CONF_PATH')
             or '/etc/wireguard')
        paths = glob.glob(os.path.join(p, '*.conf')) if os.path.isdir(p) \
              else ([p] if os.path.isfile(p) else [])
        for conf in paths:
            name = os.path.splitext(os.path.basename(conf))[0]
            if not InterfaceConfig.query.filter_by(name=name).first():
                iface = find_iface(conf)
                if iface:
                    db.session.add(iface)
        db.session.commit()

        _on_boot()
        repoint_endpoints()
        try:
            _clear_retention()
        except Exception:
            pass

# ------------
# Node proxy
# ____________
def node_get(n: Node, path: str, timeout=6):
    r = requests.get(f"{n.base_url}{path}",
                     headers={'Authorization': f'Bearer {_read_api_key(n)}'},
                     timeout=timeout)
    r.raise_for_status()
    return r.json() if r.headers.get('content-type','').startswith('application/json') else r.text

def node_post(n: Node, path: str, payload=None, timeout=8):
    r = requests.post(f"{n.base_url}{path}",
                      headers={'Authorization': f'Bearer {_read_api_key(n)}',
                               'Content-Type':'application/json'},
                      json=payload or {}, timeout=timeout)
    r.raise_for_status()
    return r.json() if r.headers.get('content-type','').startswith('application/json') else r.text

def node_delete(n: Node, path: str, timeout=8):
    r = requests.delete(f"{n.base_url}{path}",
                        headers={'Authorization': f'Bearer {_read_api_key(n)}'},
                        timeout=timeout)
    r.raise_for_status()
    return r.json() if r.headers.get('content-type','').startswith('application/json') else r.text


@app.route('/api/nodes/<int:nid>/health')
@admin_required
def node_health(nid):
    n = Node.query.get_or_404(nid)
    try:
        j = node_get(n, '/api/health')
        n.last_seen = datetime.utcnow(); db.session.commit()
        return jsonify(online=True, info=j)
    except Exception:
        return jsonify(online=False), 200
    
def _wg_rx_tx(peer):
    try:
        out = subprocess.check_output(
            ['wg', 'show', peer.iface.name, 'transfer'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().splitlines()
        for ln in out:
            parts = ln.split()
            if len(parts) >= 3 and parts[0] == peer.public_key:
                return int(parts[1]), int(parts[2])
    except Exception:
        pass
    return 0, 0

@app.route('/api/nodes/<int:nid>/summary')
@admin_required
def node_summary(nid):
    n = Node.query.get_or_404(nid)

    info = {}
    try:
        h = node_get(n, '/api/health', timeout=6) or {}
        n.last_seen = datetime.utcnow()
        db.session.commit()
        info = {
            'host':       h.get('host') or '',
            'public_ipv4': h.get('public_ipv4') or '',
            'version':    h.get('version') or '',
        }
    except Exception:
        pass

    iface_summary = {'count': 0, 'up': 0, 'names': []}
    try:
        data = node_get(n, '/api/interfaces?fast=1', timeout=10) or {}
        interfaces = data.get('interfaces') if isinstance(data, dict) else data
        names = []
        up_count = 0
        for it in interfaces or []:
            name = (it or {}).get('name')
            if not name:
                continue
            names.append(name)
            if it.get('is_up'):
                up_count += 1
        iface_summary = {'count': len(names), 'up': up_count, 'names': names}
    except Exception:
        pass

    peers_q = (db.session.query(Peer)
               .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
               .filter(or_(InterfaceConfig.name.like(f"n{nid}:%"),
                           InterfaceConfig.node_id == nid)))
    peers = peers_q.all()

    peer_counts = {'total': len(peers), 'online': 0, 'offline': 0, 'blocked': 0}
    for p in peers:
        st = (p.status or '').lower()
        if st in peer_counts:
            peer_counts[st] += 1

    last_seen = n.last_seen

    return jsonify({
        'id': n.id,
        'name': n.name,
        'enabled': n.enabled,
        'last_seen': last_seen.isoformat() + 'Z' if last_seen else None,
        'info': info,
        'interfaces': iface_summary,
        'peers': peer_counts,
    })

def _latest_handshake(peer):
    try:
        out = subprocess.check_output(
            ['wg', 'show', peer.iface.name, 'latest-handshakes'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().splitlines()
        for ln in out:
            parts = ln.split()
            if len(parts) >= 2 and parts[0] == peer.public_key:
                return int(parts[1]) if parts[1].isdigit() else 0
    except Exception:
        pass
    return 0

def _wg_transfer_bytes(peer):
    rx, tx = _wg_rx_tx(peer)
    return rx + tx


@app.route('/api/nodes/<int:nid>/interfaces')
@require_api_key_or_login
def node_ifaces(nid):
    n = Node.query.get_or_404(nid)

    data = node_get(n, '/api/interfaces', timeout=15) or {}
    base = data.get('interfaces') if isinstance(data, dict) else (data or [])
    if not isinstance(base, list):
        base = []

    out = []
    for it in base:
        name = (it or {}).get('name') or ''
        try:
            j = node_get(n, f'/api/iface/{name}/available_ips', timeout=8) or {}
            it['available_ips'] = j.get('available_ips', []) or []
        except Exception:
            it['available_ips'] = []
        out.append(it)

    try:
        h = node_get(n, '/api/health', timeout=6) or {}
        pub = (h.get('public_ipv4') or '').strip()
    except Exception:
        pub = ''

    return jsonify(interfaces=out, public_ipv4=pub)

@app.route('/api/nodes/<int:nid>/iface/<name>/available_ips')
@admin_required
def node_iface_available_ips(nid, name):
    n = Node.query.get_or_404(nid)
    return jsonify(node_get(n, f'/api/iface/{name}/available_ips', timeout=8))


@app.post('/api/nodes/<int:nid>/iface/<name>/<action>')
@login_required
def node_iface_toggle(nid, name, action):
    import requests
    n = Node.query.get_or_404(nid)
    if action not in ('up', 'down'):
        return jsonify(error='invalid_action'), 400
    try:
        node_post(n, f'/api/iface/{name}/{action}')
        return jsonify(ok=True)
    except requests.HTTPError as e:
        current_app.logger.exception("Node iface toggle failed: %s %s", n.base_url, e)
        code = getattr(getattr(e, 'response', None), 'status_code', None)
        return jsonify(error='node_toggle_failed', detail=str(e), status=code), 502

@app.route('/api/iface/<int:iid>', methods=['GET', 'POST'])
@login_required
def iface_settings(iid):
    iface = db.session.get(InterfaceConfig, iid) or abort(404)

    if request.method == 'GET':
        return jsonify({
            'id': iface.id,
            'name': iface.name,
            'path': iface.path,
            'address': iface.address,
            'listen_port': iface.listen_port,
            'dns': iface.dns,
            'mtu': iface.mtu,
            'is_up': _iface_up(iface_devname(iface)), 
        })

    data = request.get_json(silent=True) or {}
    to_update = {}
    if 'dns' in data:        to_update['dns'] = (data['dns'] or '').strip() or None
    if 'mtu' in data:        to_update['mtu'] = int(data['mtu']) if str(data['mtu']).strip() else None
    if 'listen_port' in data:
        try:
            to_update['listen_port'] = int(data['listen_port'])
        except Exception:
            return jsonify(error='invalid_listen_port'), 400

    dev = iface_devname(iface)
    if 'listen_port' in to_update and _iface_up(dev):
        try:
            subprocess.check_call(['wg', 'set', dev, 'listen-port', str(to_update['listen_port'])],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            return jsonify(error='wg_set_listen_port_failed', detail=str(e)), 500

    if 'mtu' in to_update and to_update['mtu'] and _iface_up(dev):
        subprocess.run(['ip', 'link', 'set', 'dev', dev, 'mtu', str(to_update['mtu'])],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    for k, v in to_update.items():
        setattr(iface, k, v)
    db.session.commit()

    try:
        if iface.path and os.path.isfile(iface.path):
            with open(iface.path, 'r') as f:
                lines = f.readlines()
            out, in_if = [], False
            for raw in lines:
                s = raw.strip()
                if s.startswith('[') and s.endswith(']'):
                    in_if = (s[1:-1].lower() == 'interface')
                    out.append(raw); continue
                if in_if and '=' in s:
                    k = s.split('=',1)[0].strip().lower()
                    if k in ('dns','mtu','listenport'):
                        continue
                out.append(raw)

            def _inject_after_interface(out_lines):
                injected = []
                i = 0
                while i < len(out_lines):
                    injected.append(out_lines[i])
                    if out_lines[i].strip().lower() == '[interface]':

                        if 'dns' in to_update:
                            injected.append(f"DNS = {to_update['dns']}\n" if to_update['dns'] else "")
                        if 'mtu' in to_update and to_update['mtu']:
                            injected.append(f"MTU = {to_update['mtu']}\n")
                        if 'listen_port' in to_update and to_update['listen_port']:
                            injected.append(f"ListenPort = {to_update['listen_port']}\n")
                    i += 1
                return [x for x in injected if x != ""]
            out = _inject_after_interface(out)
            with open(iface.path, 'w') as f:
                f.writelines(out)
    except Exception as e:
        current_app.logger.warning("Failed to persist iface edits to file: %s", e)

    return jsonify(ok=True)

@app.post('/api/iface/<int:iid>/<action>')
@login_required
def iface_updown(iid, action):
    iface = db.session.get(InterfaceConfig, iid) or abort(404)
    dev = iface_devname(iface)

    if action not in ('up', 'down'):
        return jsonify(ok=False, error='invalid_action'), 400

    cmd = ['wg-quick', action, dev]
    try:
        out = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20.0,          
            check=True
        )
        text = out.stdout.decode(errors='ignore')
        _iface_log(iid, f"$ {' '.join(cmd)}\n{text}")
        return jsonify(ok=True, is_up=_iface_up(dev))
    except subprocess.CalledProcessError as e:
        buf = b''
        if getattr(e, 'stdout', None): buf += e.stdout
        if getattr(e, 'stderr', None): buf += e.stderr
        text = (buf or b'').decode(errors='ignore') or str(e)
        _iface_log(iid, f"$ {' '.join(cmd)}\n{text}")
        return jsonify(
            ok=False,
            error='wg_quick_failed',
            detail=text,
            is_up=_iface_up(dev)
        ), 500
    except Exception as e:
        _iface_log(iid, f"$ {' '.join(cmd)}\n{str(e)}")
        return jsonify(
            ok=False,
            error='exception',
            detail=str(e),
            is_up=_iface_up(dev)
        ), 500


@app.route('/api/nodes/<int:nid>/peers', methods=['GET', 'POST'])
@admin_required
def node_peers(nid):
    n = Node.query.get_or_404(nid)

    if request.method == 'GET':
        iface = (request.args.get('iface') or '').strip()
        iface_id = (request.args.get('iface_id') or '').strip()
        try:
            _expire()
        except Exceptions:
            pass
        if not iface and iface_id:
            parts = iface_id.split(':', 1)
            if len(parts) == 2:
                iface = parts[1]

        try:
            node_data = node_get(n, '/api/peers' + (f'?iface={iface}' if iface else '')) or {}
            runtime = {p.get('public_key'): p for p in (node_data.get('peers') or [])}
        except Exception as e:
            current_app.logger.debug("node_get peers failed for node %s: %s", n.id, e)
            runtime = {}

        try:
            ifaces = node_get(n, '/api/interfaces') or []
            port_by_name = {i.get('name'): i.get('listen_port') for i in ifaces}
        except Exception:
            port_by_name = {}

        try:
            h = node_get(n, '/api/health') or {}
            node_pub_ip = (h.get('public_ipv4') or '').strip()
        except Exception:
            node_pub_ip = ''

        q = Peer.query.join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
        if iface:
            ns = f"n{nid}:{iface}"
            q = q.filter(or_(
                InterfaceConfig.name == ns,
                and_(InterfaceConfig.node_id == nid, InterfaceConfig.name == iface)
            ))
        else:
            q = q.filter(or_(
                InterfaceConfig.name.like(f"n{nid}:%"),
                InterfaceConfig.node_id == nid
            ))

        out, dirty = [], False
        for p in q.all():
            r  = runtime.get(p.public_key, {})  
            rs = (r.get('status') or '').strip()
            rx = r.get('rx_mib', 0) or 0
            tx = r.get('tx_mib', 0) or 0

            try: rx_mib = float(rx)
            except Exception: rx_mib = 0.0
            try: tx_mib = float(tx)
            except Exception: tx_mib = 0.0
            live_total = int((rx_mib + tx_mib) * 1024 * 1024)
            offset     = int(getattr(p, 'bytes_offset', 0) or 0)
            used_live  = max(0, live_total - offset)

            if getattr(p, 'start_on_first_use', False) and not getattr(p, 'first_used_at', None) and live_total > 0:
                p.first_used_at = datetime.utcnow()
                tl_days = getattr(p, 'time_limit_days', None)
                if tl_days:
                    try:
                        p.expires_at = p.first_used_at + timedelta(days=float(tl_days))
                    except Exception:
                        p.expires_at = None
                dirty = True

            if int(getattr(p, 'used_bytes_total', 0) or 0) != used_live:
                p.used_bytes_total = used_live
                dirty = True

            exp_ts      = to_ts(getattr(p, 'expires_at', None))
            ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None

            iface_raw  = p.iface.name if p.iface else ''
            iface_disp = iface_raw.split(':', 1)[1] if iface_raw.startswith(f"n{nid}:") else iface_raw

            if p.status == 'blocked':
                status = 'blocked'
            elif p.status == 'online':
                status = 'online'
            else:
                status = rs or (p.status or 'offline')

            out.append({
                'id': p.id,
                'node_id': nid,
                'iface': iface_disp,
                'iface_raw': iface_raw,
                'name': p.name,
                'listen_port': (p.iface.listen_port if p.iface else None) or port_by_name.get(iface_disp),
                'server_public_ip': node_pub_ip,
                'address': p.address,
                'endpoint': p.endpoint or '',
                'allowed_ips': p.allowed_ips or '',
                'persistent_keepalive': p.persistent_keepalive,
                'mtu': p.mtu,
                'dns': p.dns,
                'status': status,
                'data_limit': getattr(p, 'data_limit_value', None),
                'limit_unit': getattr(p, 'data_limit_unit', None),
                'unlimited': getattr(p, 'unlimited', False),
                'time_limit_days': getattr(p, 'time_limit_days', None),
                'start_on_first_use': getattr(p, 'start_on_first_use', False),
                'first_used_at': isoz(getattr(p, 'first_used_at', None)),
                'expires_at': isoz(getattr(p, 'expires_at', None)),
                'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
                'created_at': isoz(getattr(p, 'created_at', None)),
                'created_at_ts': to_ts(getattr(p, 'created_at', None)),
                'expires_at_ts': exp_ts,
                'ttl_seconds': ttl_seconds,
                'used_bytes': used_live,    
                'used_bytes_db': int(getattr(p, 'used_bytes_total', 0) or 0),
                'rx': str(rx_mib),
                'tx': str(tx_mib),
                'phone_number': getattr(p, 'phone_number', '') or '',
                'telegram_id': getattr(p, 'telegram_id', '') or '',
                'public_key': p.public_key,
            })

        if dirty:
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        return jsonify(peers=out), 200

    data = request.get_json() or {}
    priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
    pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()

    payload = {
        'iface': data['iface'],
        'public_key': pub,
        'host_cidr': data['address'],
        'endpoint': data.get('endpoint') or '',
        'persistent_keepalive': data.get('persistent_keepalive') or 0,
        'mtu': data.get('mtu'),
        'dns': data.get('dns'),
        'allowed_ips': (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip(),
    }
    node_post(n, '/api/peers/add', payload)

    db_iface_name = f"n{nid}:{data['iface']}"
    iface = InterfaceConfig.query.filter_by(name=db_iface_name).first()
    if not iface:
        iface = InterfaceConfig(
            name=db_iface_name,
            path=f"/etc/wireguard/{data['iface']}.conf",
            address=data.get('server_cidr') or '10.0.0.1/24',
            listen_port=int(data.get('listen_port') or 51820),
            private_key='(remote)',
            mtu=data.get('mtu'),
            dns=data.get('dns')
        )
        try:
            iface.node_id = n.id
        except Exception:
            pass
        db.session.add(iface)
        db.session.commit()
        _on_boot()

    def _conv_time_limit(d):
        try: dval = float(d.get('time_limit_days') or 0) or 0.0
        except Exception: dval = 0.0
        try: hval = float(d.get('time_limit_hours') or 0) or 0.0
        except Exception: hval = 0.0
        return (dval + hval/24.0) if (dval or hval) else None

    combined_days = _conv_time_limit(data)

    peer = Peer(
        iface_id=iface.id,
        name=(data.get('name') or ''),
        public_key=pub,
        private_key=priv,
        address=data['address'],
        allowed_ips=payload['allowed_ips'],
        endpoint=data.get('endpoint') or '',
        persistent_keepalive=data.get('persistent_keepalive') or None,
        mtu=data.get('mtu') or None,
        dns=data.get('dns') or None,
        status='online',
        data_limit_value=int(data.get('data_limit_value') or 0),
        data_limit_unit=data.get('data_limit_unit') or 'Mi',
        start_on_first_use=bool(data.get('start_on_first_use')),
        time_limit_days=combined_days,
        unlimited=bool(data.get('unlimited')),
        phone_number=data.get('phone_number') or '',
        telegram_id=data.get('telegram_id') or ''
    )
    db.session.add(peer)
    db.session.commit()
    return jsonify(ok=True, id=peer.id)


##############################################
@app.delete('/api/peer/<int:pid>/logs')
@login_required
def clear_peer_logs(pid):
    p = db.session.get(Peer, pid) or abort(404)
    try:
        cnt = (PeerEvent.query.filter_by(peer_id=pid).delete(synchronize_session=False) or 0)
        db.session.commit()
        logpanel_action("peer_logs_clear", f"pid={p.id}; {cnt} events")
        return jsonify(ok=True, deleted=int(cnt))
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Clear peer logs failed")
        return jsonify(ok=False, error="clear_failed", detail=str(e)), 500

# ------------
# Nodes View
# ____________
@app.route('/nodes', endpoint='nodes', methods=['GET'])
@login_required
def nodes():
    return render_template('nodes.html')

@app.route('/ui/nodes', methods=['GET'])
@login_required
def ui_nodes():
    rows = Node.query.order_by(Node.name).all()
    now = datetime.utcnow()
    FRESH_SEC = 180
    out = []
    for n in rows:
        last_seen = n.last_seen
        is_fresh = bool(last_seen and (now - last_seen).total_seconds() <= FRESH_SEC)
        out.append({
            'id': n.id,
            'name': n.name,
            'base_url': n.base_url,
            'enabled': n.enabled,
            'last_seen': last_seen.isoformat() + 'Z' if last_seen else None,
            'online': bool(n.enabled and is_fresh),
        })
    return jsonify(nodes=out)


@app.route('/api/nodes', methods=['GET', 'POST'])
@require_api_key_or_login
def api_nodes():

    if request.method == 'GET':
        rows = Node.query.order_by(Node.name).all()
        now = datetime.utcnow()
        FRESH_SEC = 180
        out = []
        for n in rows:
            last_seen = n.last_seen
            is_fresh = bool(last_seen and (now - last_seen).total_seconds() <= FRESH_SEC)
            out.append({
                'id': n.id,
                'name': n.name,
                'base_url': n.base_url,
                'enabled': n.enabled,
                'last_seen': last_seen.isoformat() + 'Z' if last_seen else None,
                'online': bool(n.enabled and is_fresh),
            })
        return jsonify(nodes=out)


    if not (getattr(current_user, "is_authenticated", False) and getattr(current_user, "is_admin", False)):
        return jsonify(error="admin required"), 403

    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    api_key = (data.get('api_key') or '').strip()

    base_url = _norm_base_url(data.get('base_url') or '')

    if not name or not api_key:
        return jsonify(error='Invalid input'), 400

    ok, reason = _validate_node_base_url(base_url)
    if not ok:
        return jsonify(error=reason), 400

    dup = (Node.query.filter_by(name=name).first() or
           Node.query.filter_by(base_url=base_url).first())
    if dup:
        return jsonify(error='Node name or base_url already exists'), 409

    n = Node(
        name=name,
        base_url=base_url,
        api_key=_probably_encrypt(api_key),
        enabled=True
    )
    db.session.add(n)
    db.session.commit()
    return jsonify(ok=True, id=n.id), 201


@app.route('/api/nodes/<int:nid>/peer/<path:pub>/disable', methods=['POST'])
@admin_required
def node_disable_peer(nid, pub):
    n = Node.query.get_or_404(nid)
    p = (db.session.query(Peer)
         .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
         .filter(Peer.public_key == pub)
         .filter(or_(InterfaceConfig.name.like(f"n{nid}:%"),
                     InterfaceConfig.node_id == nid))
         .first())

    payload = {}
    if p:
        try:
            payload['host_cidr'] = _host_peer(p)  
        except Exception:
            pass

    node_post(n, f'/api/peer/{pub}/disable', payload)

    if p:
        p.status = 'offline'
        log_event(p, 'disabled', 'Node: disabled (blackhole requested)')
        db.session.commit()
    return jsonify(ok=True)


@app.route('/api/nodes/<int:nid>/peer/<path:pub>/enable', methods=['POST'])
@admin_required
def node_enable_peer(nid, pub):
    n = Node.query.get_or_404(nid)
    p = (db.session.query(Peer)
         .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
         .filter(Peer.public_key == pub)
         .filter(or_(InterfaceConfig.name.like(f"n{nid}:%"),
                     InterfaceConfig.node_id == nid))
         .first())

    payload = {}
    if p:
        try:
            payload['host_cidr'] = _host_peer(p)
        except Exception:
            pass

    node_post(n, f'/api/peer/{pub}/enable', payload)

    if p:
        p.first_used_at = None
        p.expires_at = None
        p.bytes_offset = _wg_transfer(p)
        p.status = 'online'
        log_event(p, 'enabled', 'Node: enabled (timer+data reset)')
        logpanel_action("peer_enable", f"pid={p.id}; iface={p.iface}")
        db.session.commit()
    return jsonify(ok=True)

@app.route('/api/nodes/<int:nid>', methods=['DELETE', 'PUT', 'PATCH'])
@admin_required
def node_one(nid):
    n = Node.query.get_or_404(nid)

    if request.method == 'DELETE':
        db.session.delete(n)
        db.session.commit()
        return jsonify(ok=True)
    
    data = request.get_json(silent=True) or {}
    updated = False

    if 'enabled' in data:
        n.enabled = bool(data['enabled'])
        updated = True

    if 'name' in data:
        new_name = (data.get('name') or '').strip()
        if new_name:
            exists = Node.query.filter(Node.id != n.id, Node.name == new_name).first()
            if exists:
                return jsonify(error='name already exists'), 409
            n.name = new_name
            updated = True
        else:
            return jsonify(error='invalid name'), 400

    if 'base_url' in data:
        new_url = _norm_base_url(data.get('base_url') or '')
        ok, reason = _validate_node_base_url(new_url)
        if not ok:
            return jsonify(error=reason), 400


        exists = Node.query.filter(Node.id != n.id, Node.base_url == new_url).first()
        if exists:
            return jsonify(error='base_url already exists'), 409
        n.base_url = new_url
        updated = True

    if 'api_key' in data:
        new_key = (data.get('api_key') or '').strip()
        if not new_key:
            return jsonify(error='invalid api_key'), 400
        n.api_key = _probably_encrypt(new_key)
        updated = True

    if updated:
        db.session.commit()

    return jsonify(ok=True, id=n.id)

# -----------
# Login 2FA
#____________
@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import AdminAccount
    if not AdminAccount.query.first():
        return redirect(url_for('register'))

    if request.method == 'POST':
        u   = (request.form.get('username') or '').strip()
        pw  = (request.form.get('password') or '').strip()
        otp = (request.form.get('twofa_code') or request.form.get('otp_or_recovery') or '').strip().replace(' ', '')

        acc = AdminAccount.query.filter_by(username=u).first()
        if not acc or not acc.verify_pw(pw): 
            flash('Invalid username or password', 'error')
            return render_template('login.html')

        if acc.twofa_enabled:
            ok = False
            if acc.totp_secret and otp:
                totp = pyotp.TOTP(acc.totp_secret)
                if totp.verify(otp, valid_window=1):
                    ok = True

            if not ok and otp:
                codes = (acc.recovery_codes or '').splitlines()
                for i, stored in enumerate(codes):
                    if verify_recovery(otp, stored):
                        ok = True
                        codes.pop(i)
                        acc.recovery_codes = '\n'.join(codes)
                        db.session.commit()
                        break

            if not ok:
                flash('Enter your 6-digit code or a valid recovery code', 'error')
                return render_template('login.html')

        login_user(Admin(acc.username))
        nxt = request.form.get('next') or request.args.get('next')
        return redirect(nxt) if nxt and _safe_url(nxt) else redirect(url_for('index'))

    return render_template('login.html')

# --------------
# Register 2FA
#_______________
@app.route("/register/twofa_begin", methods=["POST"])
def register_twofa_begin():
    from models import AdminAccount
    if AdminAccount.query.first():
        return jsonify({"error": "Registration closed"}), 403

    payload = request.get_json(silent=True) or {}
    account = (payload.get("username") or "admin").strip() or "admin"
    issuer  = "WG Panel"

    secret = session.get("reg_totp_secret") or pyotp.random_base32()
    session["reg_totp_secret"] = secret
    session["reg_totp_confirmed"] = False
    session.pop("reg_recovery_codes_h", None)

    otp_uri = pyotp.TOTP(secret).provisioning_uri(name=f"{issuer}:{account}", issuer_name=issuer)
    session.modified = True
    return jsonify({"otp_uri": otp_uri, "secret": secret, "issuer": issuer, "account": account})

#--------------------
#Register 2FA Confirm
#_____________________
@app.route("/register/twofa_confirm", methods=["POST"])
def register_twofa_confirm():
    from models import AdminAccount
    if AdminAccount.query.first():
        return jsonify({"error": "Registration closed"}), 403

    data   = request.get_json(silent=True) or {}
    code   = (data.get("code") or "").strip()
    secret = session.get("reg_totp_secret")
    if not secret:
        return jsonify({"error": "Start 2FA first"}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid code"}), 400

    rec_plain = _gen_recovery()
    rec_h     = [hash_recovery(c) for c in rec_plain]

    session["reg_totp_confirmed"]   = True
    session["reg_recovery_codes_h"] = rec_h
    session.modified = True
    return jsonify({"recovery_codes": rec_plain})

@app.route('/register', methods=['GET', 'POST'])
def register():
    from models import AdminAccount

    if AdminAccount.query.first():
        return redirect(url_for('login'))

    setup_token   = (current_app.config.get('SETUP_TOKEN') or os.getenv('SETUP_TOKEN', '')).strip()
    require_token = bool(setup_token)

    if request.method == 'POST':
        u   = (request.form.get('username') or '').strip()
        p1  = request.form.get('password') or ''
        p2  = request.form.get('password2') or ''
        tok = (request.form.get('setup_token') or '').strip()

        if require_token and not secrets.compare_digest(tok, setup_token):
            flash('Invalid registration token.', 'error')
            return render_template('register.html', require_token=True)

        if not u:
            flash('Username is required.', 'error')
            return render_template('register.html', require_token=require_token)
        if p1 != p2:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', require_token=require_token)
        if len(p1) > 1024:
            flash('Password too long.', 'error')
            return render_template('register.html', require_token=require_token)
        if AdminAccount.query.filter_by(username=u).first():
            flash('That username is already taken.', 'error')
            return render_template('register.html', require_token=require_token)

        try:
            pw_hash = AdminAccount.hash_pw(p1)
            acc = AdminAccount(username=u, password_hash=pw_hash)

            if session.get('reg_totp_confirmed') and session.get('reg_totp_secret'):
                acc.twofa_enabled = True
                acc.totp_secret   = session['reg_totp_secret']
                rc_h = session.get('reg_recovery_codes_h') or []
                acc.recovery_codes = '\n'.join(rc_h)

            db.session.add(acc)
            db.session.commit()

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("register() failed at commit")
            current_app.logger.error("u=%r totp_confirmed=%r has_rc=%r",
                                     u, bool(session.get('reg_totp_confirmed')),
                                     bool(session.get('reg_recovery_codes_h')))
            flash("Internal error while creating the admin. See app.log.", "error")
            return render_template('register.html', require_token=require_token), 500

        for k in ('reg_totp_secret', 'reg_totp_confirmed', 'reg_recovery_codes_h'):
            session.pop(k, None)

        flash('Admin created. Please log in.' if len(p1) >= 12
              else 'Admin created. Tip: use 12+ characters for better security.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', require_token=require_token)



# ___ Admin status / updates ___
@app.get('/api/admin')
@login_required
def admin_status():
    from models import AdminAccount
    acc = AdminAccount.query.first()
    if not acc:
        return jsonify(error="no_admin"), 404
    rc = 0
    if (acc.recovery_codes or '').strip():
        rc = len([x for x in acc.recovery_codes.splitlines() if x.strip()])
    return jsonify({
        "username": acc.username,
        "twofa_enabled": bool(acc.twofa_enabled),
        "recovery_count": rc,
    }), 200


@app.post('/api/admin/password')
@login_required
def admin_change_password():
    data = request.get_json(silent=True) or {}
    cur = (data.get('current') or '').strip()
    new = (data.get('new') or '').strip()
    if not new:
        return jsonify(error="empty_new"), 400
    acc = AdminAccount.query.first()
    if not acc or not acc.verify_pw(cur):
        return jsonify(error="bad_current"), 400
    acc.password_hash = AdminAccount.hash_pw(new)
    db.session.commit()
    return jsonify(ok=True)

@app.post('/api/admin/rename')
@login_required
def admin_rename():
    data = request.get_json(silent=True) or {}
    newu = (data.get('username') or '').strip()
    if not newu:
        return jsonify(error="empty_username"), 400
    # multi-admin later
    if AdminAccount.query.filter_by(username=newu).first():
        return jsonify(error="taken"), 400
    acc = AdminAccount.query.first()
    acc.username = newu
    db.session.commit()
    return jsonify(ok=True)


@app.route('/api/admin', methods=['GET'])
@login_required
def admin_state():
    username = getattr(current_user, 'username', 'admin')
    rec = Admin2FA.query.filter_by(username=username).first()
    return jsonify(
        username=username,
        twofa_enabled=bool(rec and rec.enabled),
        recovery_count=len(json.loads(rec.recovery_hashes or "[]")) if rec else 0
    ), 200

@app.route('/api/admin/twofa_begin', methods=['POST'])
@login_required
def twofa_begin():
    username = getattr(current_user, 'username', 'admin')
    secret = pyotp.random_base32()
    session['twofa_pending_secret'] = secret  
    session.modified = True
    label = f"WG-Panel:{username}"
    issuer = "WG-Panel"
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
    return jsonify(secret=secret, otp_uri=otp_uri), 200

@app.route('/api/admin/twofa_confirm', methods=['POST'])
@login_required
def twofa_confirm():
    try:
        data = request.get_json(silent=True) or {}
        otp = (data.get('otp') or '').strip()
        username = getattr(current_user, 'username', 'admin')
        pending = session.get('twofa_pending_secret')

        if not pending:
            return jsonify(error='No 2FA setup in progress'), 400
        if not (otp.isdigit() and len(otp) == 6):
            return jsonify(error='Invalid code'), 400

        totp = pyotp.TOTP(pending)
        if not totp.verify(otp, valid_window=1):
            return jsonify(error='Incorrect or expired code'), 400

        rec = _create_twofa(username) 
        _set_secret(rec, pending)             

        recovery_plain = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(10)]
        rec.recovery_hashes = json.dumps([hash_recovery(c) for c in recovery_plain])
        rec.enabled = True
        db.session.commit()
        
        acc = AdminAccount.query.filter_by(username=username).first()
        if acc:
            acc.twofa_enabled = True
            acc.totp_secret = pending 
            acc.recovery_codes = '\n'.join(hash_recovery(c) for c in recovery_plain)
            db.session.commit()

        session.pop('twofa_pending_secret', None)
        session.modified = True

        return jsonify(ok=True, recovery_codes=recovery_plain), 200

    except Exception:
        app.logger.exception("twofa_confirm failed")
        return jsonify(error='Internal error while enabling 2FA'), 500

@app.route('/api/admin/twofa_disable', methods=['POST'])
@login_required
def twofa_disable():
    try:
        username = getattr(current_user, 'username', 'admin')
        rec = _create_twofa(username)
        rec.enabled = False
        rec.secret_enc = None
        rec.recovery_hashes = json.dumps([])
        db.session.commit()

        acc = AdminAccount.query.filter_by(username=username).first()
        if acc:
            acc.twofa_enabled = False
            acc.totp_secret = None
            acc.recovery_codes = ''
            db.session.commit()

        session.pop('twofa_pending_secret', None)
        session.modified = True

        return jsonify(ok=True), 200

    except Exception:
        app.logger.exception("twofa_disable failed")
        return jsonify(error='Internal error while disabling 2FA'), 500


#----------------------
# Logout, Index
#______________________
@app.route('/logout')
@login_required
def logout():
    logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# -------------------
# Peers
# ___________________
@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    form = PeerForm()
    ifaces = InterfaceConfig.query.order_by(InterfaceConfig.name.asc()).all()
    form.iface.choices = [(i.id, i.name) for i in ifaces]
    sel_iface = None
    if request.method == 'POST' and form.iface.data:
        sel_iface = db.session.get(InterfaceConfig, form.iface.data)
    else:
        arg_iface_id = request.args.get('iface_id', type=int)
        arg_iface_nm = (request.args.get('iface') or '').strip()
        if arg_iface_id:
            sel_iface = db.session.get(InterfaceConfig, arg_iface_id)
            if sel_iface:
                form.iface.data = sel_iface.id
        elif arg_iface_nm:
            sel_iface = InterfaceConfig.query.filter_by(name=arg_iface_nm).first()
            if sel_iface:
                form.iface.data = sel_iface.id
        if not sel_iface and form.iface.choices:
            sel_iface = db.session.get(InterfaceConfig, form.iface.choices[0][0])
            if sel_iface:
                form.iface.data = sel_iface.id

    form.address.choices = [(ip, ip) for ip in (_available_ips(sel_iface) if sel_iface else [])]

    if request.method == 'GET':
        if hasattr(form, 'time_limit_hours') and form.time_limit_hours.data is None:
            form.time_limit_hours.data = 0
        if sel_iface:
            if form.mtu.data is None:
                form.mtu.data = sel_iface.mtu
            if form.dns.data is None:
                form.dns.data = sel_iface.dns
            if not form.endpoint.data:
                fallback = _endpoint_fallback(sel_iface)
                if fallback:
                    form.endpoint.data = fallback

    if form.validate_on_submit():
        iface = sel_iface or (db.session.get(InterfaceConfig, form.iface.data) if form.iface.data else None)
        if not iface:
            flash('Please select an interface.', 'error')
            return render_template('users.html', form=form)

        priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
        pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()

        combined_days = _conv_time_limit({
            'time_limit_days': getattr(form, 'time_limit_days', None) and form.time_limit_days.data,
            'time_limit_hours': getattr(form, 'time_limit_hours', None) and form.time_limit_hours.data,
        })

        peer = Peer(
            iface_id=iface.id,
            name=form.name.data,
            public_key=pub,
            private_key=priv,
            address=form.address.data,
            allowed_ips=form.allowed_ips.data,
            endpoint=form.endpoint.data,
            persistent_keepalive=form.persistent_keepalive.data,
            mtu=form.mtu.data,
            dns=form.dns.data,
            status='offline',
            data_limit_value=int(getattr(form, 'data_limit', None) and (form.data_limit.data or 0)),
            data_limit_unit=getattr(form, 'limit_unit', None) and form.limit_unit.data,
            time_limit_days=combined_days,
            start_on_first_use=bool(getattr(form, 'start_on_first_use', None) and form.start_on_first_use.data),
            unlimited=bool(getattr(form, 'unlimited', None) and form.unlimited.data),
            phone_number=getattr(form, 'phone_number', None) and form.phone_number.data,
            telegram_id=getattr(form, 'telegram_id', None) and form.telegram_id.data,
        )

        if peer.time_limit_days and not peer.start_on_first_use and not peer.unlimited:
            exp_ts = add_days_ts(now_ts(), float(peer.time_limit_days))
            peer.expires_at = from_ts(exp_ts)

        db.session.add(peer)
        db.session.commit()

        try:
            _peer_to_conf(peer)
        except Exception:
            current_app.logger.exception("append to conf failed for peer %s", peer.id)

        try:
            _wg_enable(peer)
            peer.status = 'online'
            db.session.commit()
            log_event(
                peer, 'created',
                f"iface={iface.name}; "
                f"limit={getattr(peer,'data_limit_value',0)}{getattr(peer,'data_limit_unit','')}; "
                f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
            )
            flash('Peer created & enabled', 'success')
        except Exception as e:
            current_app.logger.exception("Enable failed for %s: %s", peer.name, e)
            peer.status = 'offline'
            db.session.commit()
            log_event(
                peer, 'created',
                f"(enable failed) iface={iface.name}; "
                f"limit={getattr(peer,'data_limit_value',0)}{getattr(peer,'data_limit_unit','')}; "
                f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
            )
            flash('Peer created, but interface was not up. It has been left offline—bring the interface up and click “Enable”.', 'error')

        return redirect(url_for('users'))

    return render_template('users.html', form=form)


@app.route('/api/endpoint_presets', methods=['GET', 'POST', 'DELETE'])
@require_api_key_or_login
def endpoint_presets():
    if request.method == 'GET':
        return jsonify(presets=_load_presets(), public_ipv4=_public_ipv4())

    if request.method == 'POST':
        data = request.get_json() or {}
        host = (data.get('host') or '').strip()
        port = int(data.get('port') or 0)
        label = (data.get('label') or '').strip() or f"{host}:{port}"
        if not host or port <= 0:
            return jsonify(error='host and port required'), 400
        presets = _load_presets()
        updated = False
        for p in presets:
            if p.get('host') == host and int(p.get('port') or 0) == port:
                p.update({'label': label}); updated = True; break
        if not updated:
            presets.append({'label': label, 'host': host, 'port': port})
        _save_presets(presets)
        return jsonify(success=True, presets=presets)

    data = request.get_json() or {}
    host = (data.get('host') or '').strip()
    port = int(data.get('port') or 0)
    presets = [p for p in _load_presets() if not (p.get('host') == host and int(p.get('port') or 0) == port)]
    _save_presets(presets)
    return jsonify(success=True, presets=presets)

# -------
# Stats
# _______

def _global_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global  
    except Exception:
        return False

def _wg_endpoint_ips(timeout=1.5):
    ips = set()
    try:
        p = subprocess.run(
            ["wg", "show", "all", "endpoints"],
            capture_output=True, text=True, timeout=timeout
        )
        if p.returncode != 0:
            return ips

        for line in p.stdout.splitlines():
            line = line.strip()
            if not line or "(none)" in line:
                continue
            tok = line.split()[-1]  
            host = tok
            if host.startswith('['):
                host = host.split(']')[0].lstrip('[')
            else:
                if ':' in host:
                    host = host.rsplit(':', 1)[0]
            if _global_ip(host):
                ips.add(host)
    except Exception:
        pass
    return ips


_prev_net = {"ts": 0, "rx": 0, "tx": 0}

def _rate_mb(cur_bytes, prev_bytes, dt):
    if dt <= 0:
        return 0.0
    return max(0.0, (cur_bytes - prev_bytes) / dt / (1024 * 1024))



@app.get('/api/peer_counts')
@login_required
def api_peer_counts():
    scope = (request.args.get('scope') or 'local').strip().lower()

    ACTIVE_WITHIN_SECONDS = 180  

    def _wg_dump_all():
        try:
            p = subprocess.run(
                ['wg', 'show', 'all', 'dump'],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if p.returncode != 0:
                return {}
            m = {}
            for raw in (p.stdout or '').splitlines():
                if not raw.strip():
                    continue
                parts = raw.split('\t')
                if len(parts) < 9:
                    continue
                iface = parts[0]
                pubkey = parts[1]
                try:
                    hs = int(parts[5] or '0')
                except Exception:
                    hs = 0
                m.setdefault(iface, {})[pubkey] = hs
            return m
        except Exception:
            return {}

    def _counts_peers(peer_rows, hs_map):
        now = int(time.time())
        out = {'online': 0, 'offline': 0, 'blocked': 0}
        for st, pubkey, ifname in peer_rows:
            st = (st or 'offline').lower()
            if st == 'blocked':
                out['blocked'] += 1
                continue

            hs = 0
            try:
                hs = int((hs_map.get(ifname) or {}).get(pubkey) or 0)
            except Exception:
                hs = 0

            if hs and (now - hs) <= ACTIVE_WITHIN_SECONDS:
                out['online'] += 1      
            else:
                out['offline'] += 1    
        return out

    base_rows = db.session.query(Peer.status, Peer.public_key, InterfaceConfig.name).join(InterfaceConfig)

    if scope not in ('local', 'nodes', 'total'):
        return jsonify(error="invalid_scope", allow=['local', 'nodes', 'total']), 400

    if scope == 'nodes':
        q = db.session.query(Peer.status, func.count(Peer.id)).join(InterfaceConfig)
        q = q.filter(InterfaceConfig.name.op('REGEXP')('^n[0-9]+:'))
        rows = q.group_by(Peer.status).all()
        counts = {'online': 0, 'offline': 0, 'blocked': 0}
        for st, c in rows:
            st = (st or '').lower()
            if st in counts:
                counts[st] = int(c)
        return jsonify(counts=counts), 200

    hs_map = _wg_dump_all()

    local_rows = base_rows.filter(~InterfaceConfig.name.op('REGEXP')('^n[0-9]+:')).all()
    local_counts = _counts_peers(local_rows, hs_map)

    if scope == 'local':
        return jsonify(counts=local_counts), 200

    qn = db.session.query(Peer.status, func.count(Peer.id)).join(InterfaceConfig)
    qn = qn.filter(InterfaceConfig.name.op('REGEXP')('^n[0-9]+:'))
    rowsn = qn.group_by(Peer.status).all()
    node_counts = {'online': 0, 'offline': 0, 'blocked': 0}
    for st, c in rowsn:
        st = (st or '').lower()
        if st in node_counts:
            node_counts[st] = int(c)

    counts = {
        'online':  int(local_counts['online']  + node_counts['online']),
        'offline': int(local_counts['offline'] + node_counts['offline']),
        'blocked': int(local_counts['blocked'] + node_counts['blocked']),
    }
    return jsonify(counts=counts), 200


@app.route('/api/nodes/<int:nid>/iface/<name>/logs', methods=['GET', 'DELETE'])
@admin_required
def node_iface_logs(nid, name):
    n = Node.query.get_or_404(nid)

    if request.method == 'DELETE':
        try:
            node_delete(n, f'/api/iface/{name}/logs', timeout=12)
            return jsonify(ok=True)
        except Exception as e:
            current_app.logger.warning(
                "node_iface_logs DELETE failed for %s on node %s: %s",
                name, nid, e
            )
            return jsonify(ok=False, error="node_clear_failed"), 502

    params = {
        'limit': request.args.get('limit', 500),
        'q': (request.args.get('q') or '').strip(),
    }
    try:
        data = node_get(n, f"/api/iface/{name}/logs", params=params, timeout=12)
    except Exception as e:
        current_app.logger.warning("node_iface_logs failed for %s on %s: %s", name, n, e)
        return jsonify(logs=[])

    return jsonify(logs=data.get('logs', []))


@app.route('/api/stats')
@login_required
def api_stats():
    # ___ CPU ___
    cpu_pct = psutil.cpu_percent(interval=None)
    cores   = psutil.cpu_count(logical=False) or psutil.cpu_count()
    threads = psutil.cpu_count(logical=True)
    try:
        l1, l5, l15 = os.getloadavg()
    except Exception:
        l1 = l5 = l15 = 0.0
    load_pct = round((l1 / max(1, threads)) * 100, 1)

    # __ Memory + Swap ___
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

    # ___ Disk ___
    du = psutil.disk_usage('/')
    disk = {
        "percent":  du.percent,
        "used_gb":  round(du.used  / (1024**3), 2),
        "free_gb":  round(du.free  / (1024**3), 2),
        "total_gb": round(du.total / (1024**3), 2),
    }

    # ___ Network (MB/s) ___
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

    # ___ Connections ___
    try:
        conns = psutil.net_connections(kind='inet')
        total_conn  = len(conns)
        uniq_remote = len({c.raddr.ip for c in conns if c.raddr})
    except Exception:
        conns = []
        total_conn = uniq_remote = 0

    # ___ Unique public IPs (only inbound clients) ___
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

    # ___ Peer counts ___
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

@app.get('/api/stats/mini')
@require_api_key
def stats_mini():
    try:
        cpu  = round(psutil.cpu_percent(interval=0.2) or 0.0, 1)
        mem  = round(psutil.virtual_memory().percent or 0.0, 1)
        disk = round(psutil.disk_usage('/').percent or 0.0, 1)
        uptime_secs = max(0, int(time.time() - psutil.boot_time()))
        if uptime_secs >= 48 * 3600:
            days  = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            uptime_value = int(days)
            uptime_unit  = "d"
            uptime_str   = f"{days}d" + (f" {hours}h" if hours else "")
        else:
            hours = uptime_secs // 3600
            uptime_value = int(hours)
            uptime_unit  = "h"
            uptime_str   = f"{hours}h"

        counts = {
            "online":  db.session.query(Peer).filter_by(status='online').count(),
            "offline": db.session.query(Peer).filter_by(status='offline').count(),
            "blocked": db.session.query(Peer).filter_by(status='blocked').count(),
        }

        return jsonify({
            "cpu": cpu,
            "mem": mem,
            "disk": disk,
            "uptime_value": uptime_value,  
            "uptime_unit":  uptime_unit,    
            "uptime_str":   uptime_str,    
            "counts": counts,
        }), 200
    except Exception:
        return jsonify({"error": "stats_unavailable"}), 503


# --------------
# Peers list[TG]
# ______________
@app.route('/api/peers', methods=['POST'])
@require_api_key_or_login
def peers_create():
    data = request.get_json(silent=True) or {}
    scope = (data.get('scope') or 'local').strip().lower()
    if scope not in ('local', 'node'):
        return jsonify(error='scope must be local or node'), 400

    if scope == 'node':
        nid = int(data.get('node_id') or 0)
        iface_name = (data.get('iface_name') or '').strip()
        if not nid or not iface_name:
            return jsonify(error='node_id and iface_name required for node scope'), 400

        n = Node.query.get_or_404(nid)

        priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
        pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()

        addr = (data.get('address') or '').strip()
        if not addr:
            try:
                avail = node_get(n, f"/api/iface/{iface_name}/available_ips")
                if isinstance(avail, dict):
                    avail = avail.get("available_ips", [])
                if not isinstance(avail, list) or not avail:
                     return jsonify(error="node_no_available_ip",
                                    detail="empty or invalid available_ips"), 409
                addr = avail[0]

            except Exception as e:
                current_app.logger.exception("node available_ips failed: %s", e)
                return jsonify(error="node_available_ips_failed"), 502

        try:
            node_post(n, f"/api/iface/{iface_name}/up", {})
        except Exception:
            pass  

        node_payload = {
            'iface': iface_name,
            'public_key': pub,
            'host_cidr': addr,  
            'endpoint':   (data.get('endpoint') or '').strip(),
            'persistent_keepalive': data.get('persistent_keepalive') or 0,
            'mtu':  data.get('mtu'),
            'dns':  data.get('dns'),
            'allowed_ips': (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip(),
        }

        try:
            node_post(n, '/api/peers/add', node_payload)
        except requests.HTTPError as e:
            body = getattr(e.response, 'text', '') if getattr(e, 'response', None) else ''
            return jsonify(error="node_create_failed", detail=str(e), body=(body[:800] if body else '')), 502

        db_iface_name = f"n{nid}:{iface_name}"
        iface = InterfaceConfig.query.filter_by(name=db_iface_name).first()
        if not iface:
            iface = InterfaceConfig(
                name=db_iface_name,
                path=f"/etc/wireguard/{iface_name}.conf",
                address=data.get('server_cidr') or '10.0.0.1/24',
                listen_port=int(data.get('listen_port') or 51820),
                private_key='(remote)',
                mtu=data.get('mtu'),
                dns=data.get('dns'),
            )
            try:
                iface.node_id = n.id
            except Exception:
                pass
            db.session.add(iface)
            db.session.commit()

        combined_days = _conv_time_limit(data)

        phone = (data.get('phone_number') or '').strip()
        tg    = (data.get('telegram_id')  or '').strip()

        peer = Peer(
            iface_id=iface.id,
            name=(data.get('name') or '').strip() or 'peer',
            public_key=pub, private_key=priv,
            address=node_payload['host_cidr'],
            allowed_ips=node_payload['allowed_ips'],
            endpoint=node_payload['endpoint'] or '',
            persistent_keepalive=data.get('persistent_keepalive') or None,
            mtu=data.get('mtu') or None,
            dns=data.get('dns') or None,
            status='online',
            data_limit_value=int(data.get('data_limit_value') or 0),
            data_limit_unit=(data.get('data_limit_unit') or 'Mi'),
            start_on_first_use=bool(data.get('start_on_first_use')),
            time_limit_days=combined_days,
            unlimited=bool(data.get('unlimited')),
            phone_number=phone or '',
            telegram_id=tg or '',
        )

        if peer.time_limit_days and not peer.start_on_first_use and not peer.unlimited:
            exp_ts = add_days_ts(now_ts(), float(peer.time_limit_days))
            peer.expires_at = from_ts(exp_ts)

        db.session.add(peer)
        db.session.commit()

        try:
            log_event(
                peer,
                'created(node)',
                f"Limit={getattr(peer,'data_limit_value',0)}{getattr(peer,'data_limit_unit','')}; "
                f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
            )
        except Exception:
            pass

        return jsonify(success=True, id=peer.id,
                       phone_number=peer.phone_number or '',
                       telegram_id=peer.telegram_id or ''), 200

    iface_id = data.get('iface_id')
    if not iface_id:
        return jsonify(error='iface_id required'), 400

    iface = db.session.get(InterfaceConfig, int(iface_id))
    if not iface:
        return jsonify(error='Interface not found'), 404

    priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
    pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()

    combined_days = _conv_time_limit(data)

    phone = (data.get('phone_number') or data.get('phone') or '').strip()
    tg    = (data.get('telegram_id')  or data.get('telegram') or '').strip()

    address = (data.get('address') or '').strip()
    if not address:
        try:
            avail = _available_ips(iface)
            if not avail:
                return jsonify(error='No available IPs for this interface'), 409
            address = avail[0]
        except Exception as e:
            current_app.logger.exception("Failed to get available IPs: %s", e)
            return jsonify(error='address_allocation_failed'), 500

    peer = Peer(
        iface_id=iface.id,
        name=(data.get('name') or '').strip() or 'peer',
        public_key=pub, private_key=priv,
        address=address,
        allowed_ips=(data.get('allowed_ips') or '').strip(),
        endpoint=(data.get('endpoint') or '').strip(),
        persistent_keepalive=data.get('persistent_keepalive'),
        mtu=data.get('mtu'),
        dns=data.get('dns'),
        status='online',
        data_limit_value=int(data.get('data_limit_value') or 0),
        data_limit_unit=(data.get('data_limit_unit') or 'Mi'),
        start_on_first_use=bool(data.get('start_on_first_use')),
        time_limit_days=combined_days,
        unlimited=bool(data.get('unlimited')),
        phone_number=phone or '',
        telegram_id=tg or '',
    )

    if peer.time_limit_days and not peer.start_on_first_use and not peer.unlimited:
        exp_ts = add_days_ts(now_ts(), float(peer.time_limit_days))
        peer.expires_at = from_ts(exp_ts)

    db.session.add(peer)
    db.session.commit()

    try:
        _peer_to_conf(peer)
        _check_iface_up(peer.iface)
        _wg_enable(peer)
    except Exception:
        current_app.logger.exception("enable failed for peer %s", peer.id)

    log_event(
        peer,
        'created',
        f"Limit={getattr(peer,'data_limit_value',0)}{getattr(peer,'data_limit_unit','')}; "
        f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
    )

    return jsonify(
        success=True,
        id=peer.id,
        phone_number=peer.phone_number or '',
        telegram_id=peer.telegram_id or ''
    ), 200

@app.route('/api/peers')
@require_api_key_or_login
def panel_peers():

    _expire()
    pub = _public_ipv4()
    out = []

    iface_id = request.args.get('iface_id', type=int)
    iface_name = (request.args.get('iface') or '').strip()

    try:
        q = Peer.query
        if iface_id is not None:
            q = q.filter(Peer.iface_id == iface_id)
        elif iface_name:
            q = q.join(InterfaceConfig).filter(InterfaceConfig.name == iface_name)
        peers = q.all()
    except Exception:
        current_app.logger.exception("Failed to query peers")
        return jsonify(peers=[]), 200

    for p in peers:
        try:
            total = _wg_transfer(p)
            used = max(0, total - int(getattr(p, 'bytes_offset', 0) or 0))

            rx = tx = '0'
            try:
                rx_b, tx_b = _wg_rx_tx(p)
                rx = str(round(rx_b/1024/1024, 2))
                tx = str(round(tx_b/1024/1024, 2))
            except Exception:
                rx = tx = '0'

            exp_ts = to_ts(getattr(p, 'expires_at', None))
            ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None

            out.append({
                'id': p.id,
                'name': p.name,
                'iface': p.iface.name,
                'listen_port': p.iface.listen_port,
                'server_public_ip': pub,
                'address': p.address,
                'endpoint': p.endpoint or '',
                'allowed_ips': p.allowed_ips or '',
                'persistent_keepalive': p.persistent_keepalive,
                'mtu': p.mtu,
                'dns': p.dns,
                'status': p.status,
                'data_limit': getattr(p, 'data_limit_value', None),
                'limit_unit': getattr(p, 'data_limit_unit', None),
                'unlimited': getattr(p, 'unlimited', False),
                'time_limit_days': getattr(p, 'time_limit_days', None),
                'start_on_first_use': getattr(p, 'start_on_first_use', False),
                'created_at': isoz(getattr(p, 'created_at', None)),
                'created_at_ts': to_ts(getattr(p, 'created_at', None)),
                'first_used_at': isoz(getattr(p, 'first_used_at', None)),
                'expires_at': isoz(getattr(p, 'expires_at', None)),
                'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
                'expires_at_ts': exp_ts,
                'ttl_seconds': ttl_seconds,
                'used_bytes': used,                                
                'used_bytes_db': getattr(p, 'used_bytes_total', 0), 
                'phone_number': getattr(p, 'phone_number', '') or '',
                'telegram_id': getattr(p, 'telegram_id', '') or '',
                'rx': rx,
                'tx': tx
            })
        except Exception:
            current_app.logger.exception("Failed to serialize peer %s", p.id)

    return jsonify(peers=out), 200


# ------------
# Bulk create 
# ____________
@csrf.exempt
@app.route('/api/peers/bulk', methods=['POST'])
@require_api_key_or_login
def panel_peers_bulk():
    data = request.get_json(silent=True) or {}

    scope = (data.get('scope') or 'local').strip().lower()
    if scope not in ('local', 'node'):
        return jsonify(error="scope must be 'local' or 'node'"), 400

    if scope == 'node':
        nid = data.get('node_id') or data.get('nodeId')
        iface_name = (data.get('iface_name') or data.get('ifaceName') or '').strip()
        if not nid or not iface_name:
            return jsonify(error="node_id and iface_name are required for node scope"), 400

        forward_payload = {k: v for k, v in data.items()
                           if k not in ('scope', 'iface_id', 'iface', 'ifaceId')}
        forward_payload['iface_name'] = iface_name

        try:
            n = Node.query.get_or_404(int(nid))
            res = node_post(n, '/api/peers/bulk', payload=forward_payload)
            return jsonify(res), 200
        except Exception as e:
            current_app.logger.exception("Bulk forward to node %s failed: %s", nid, e)
            return jsonify(error="node_proxy_failed", message=str(e)), 502

    iface_id = data.get('iface_id') or data.get('iface') or data.get('ifaceId')
    iface_name = (data.get('iface_name') or data.get('ifaceName') or '').strip()

    count = int(data.get('count') or data.get('bulkPeerCount') or 0)

    iface = None
    if iface_id:
        iface = db.session.get(InterfaceConfig, int(iface_id))
    elif iface_name:
        iface = db.session.query(InterfaceConfig).filter(InterfaceConfig.name == iface_name).first()

    if not iface or count < 1:
        if count < 1:
            return jsonify(error="count is required"), 400
        return jsonify(error="Interface not found"), 404

    iface_id = iface.id


    prefix = (data.get('prefix') or data.get('name_prefix') or 'b').strip() or 'b'

    combined_days = _conv_time_limit({
        'time_limit_days': data.get('time_limit_days'),
        'time_limit_hours': data.get('time_limit_hours'),
    })

    avail_ips = _available_ips(iface)
    if not avail_ips:
        return jsonify(error="No available IPs for this interface"), 409
    if count > len(avail_ips):
        count = len(avail_ips)

    rx = re.compile(rf'^{re.escape(prefix)}(\d+)$')
    existing = {
        m.group(1)
        for (nm,) in db.session.query(Peer.name)
                               .filter(Peer.iface_id == iface.id)
                               .all()
        for m in [rx.match(nm)] if m
    }
    next_num = 1
    if existing:
        try:
            next_num = max(int(x) for x in existing) + 1
        except ValueError:
            next_num = 1

    allowed_ips = (data.get('allowed_ips') or '').strip()
    endpoint = (data.get('endpoint') or '').strip()
    keepalive = data.get('persistent_keepalive')
    mtu = data.get('mtu')
    dns = data.get('dns')
    dlim_val = data.get('data_limit_value') or 0
    dlim_unit = data.get('data_limit_unit')
    start_on_first_use = bool(data.get('start_on_first_use') or False)
    unlimited = bool(data.get('unlimited') or False)

    def _social_list(val):
        if val is None:
            return []
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        return [s for s in (t.strip() for t in re.split(r'[\n,]+', str(val))) if s]

    phones = _social_list(
        data.get('phone_numbers') or
        data.get('phone_number')  or 
        data.get('phones') or
        data.get('mobile_numbers') or
        data.get('mobiles')
    )
    tgs = _social_list(
        data.get('telegram_ids') or
        data.get('telegram_id')   or
        data.get('telegrams') or
        data.get('telegram')
    )

    created, errors = [], []

    for i in range(count):
        try:
            priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
            pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()
            name = f"{prefix}{next_num + i}"
            addr = avail_ips[i]

            peer = Peer(
                iface_id=iface.id, name=name,
                public_key=pub, private_key=priv,
                address=addr, allowed_ips=allowed_ips,
                endpoint=endpoint,
                persistent_keepalive=keepalive,
                mtu=mtu, dns=dns,
                status='offline',
                data_limit_value=int(dlim_val) if dlim_val else 0,
                data_limit_unit=dlim_unit,
                time_limit_days=combined_days,
                start_on_first_use=start_on_first_use,
                unlimited=unlimited,
                phone_number=phones[i] if i < len(phones) else '',
                telegram_id=tgs[i] if i < len(tgs) else '',
            )

            if peer.time_limit_days and not peer.start_on_first_use and not peer.unlimited:
                exp_ts = add_days_ts(now_ts(), float(peer.time_limit_days))
                peer.expires_at = from_ts(exp_ts)

            db.session.add(peer)
            db.session.flush()  

            try:
                _peer_to_conf(peer)
            except Exception:
                current_app.logger.exception("append to conf failed for peer %s", peer.id)

            created.append(peer)

        except Exception as e:
            current_app.logger.exception("bulk create failed at index %s: %s", i, e)
            errors.append({'index': i, 'error': str(e)})

    db.session.commit()

    try:
        _check_iface_up(iface)
    except Exception as e:
        current_app.logger.warning("Could not bring up %s before enabling peers: %s", iface.name, e)

    for peer in created:
        try:
            _wg_enable(peer)
            peer.status = 'online'
            db.session.commit()
            log_event(peer, 'created',
                      f"bulk; Limit={peer.data_limit_value}{peer.data_limit_unit or ''}; "
                      f"days={peer.time_limit_days}; unlimited={peer.unlimited}")
            logpanel_action("peer_create", f"pid={peer.id}; iface={iface.name}; unlimited={peer.unlimited}; days={peer.time_limit_days}")

        except Exception as e:
            current_app.logger.exception("Enable failed for %s: %s", peer.name, e)
            peer.status = 'offline'
            db.session.commit()
            log_event(peer, 'created',
                      f"bulk (enable failed); Limit={peer.data_limit_value}{peer.data_limit_unit or ''}; "
                      f"days={peer.time_limit_days}; unlimited={peer.unlimited}")
            logpanel_action("peer_create", f"pid={peer.id}; iface={iface.name}; enable_failed=1; unlimited={peer.unlimited}; days={peer.time_limit_days}")


    return jsonify(
        ok=True,
        scope='local',
        iface=iface.name,
        created=len(created),
        errors=errors,
        first_name=created[0].name if created else None,
        last_name=created[-1].name if created else None,
        peers=[{
            'id': p.id,
            'name': p.name,
            'address': p.address,
            'phone_number': getattr(p, 'phone_number', '') or '',
            'telegram_id': getattr(p, 'telegram_id', '') or ''
        } for p in created]
    ), 200

@app.route('/api/iface/<int:iface_id>/available_ips')
@require_api_key_or_login
def iface_available_ips(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    return jsonify(available_ips=_available_ips(iface))

# ---------------
# Interfaces API 
# _______________

@app.get("/api/get-interfaces")
@require_api_key_or_login
def get_interfaces():
    paths = []
    p = app.config['WG_CONF_PATH']
    if os.path.isdir(p):
        paths = glob.glob(os.path.join(p, '*.conf'))
    elif os.path.isfile(p):
        paths = [p]

    for conf in paths:
        name = os.path.splitext(os.path.basename(conf))[0]
        parsed = find_iface(conf)
        if not parsed:
            continue
        
        existing = InterfaceConfig.query.filter_by(name=name).first()
        if not existing:
            db.session.add(parsed)
        else:
            existing.path        = conf
            existing.address     = parsed.address
            existing.listen_port = parsed.listen_port
            existing.private_key = parsed.private_key
            existing.mtu         = parsed.mtu
            existing.dns         = parsed.dns
            existing.post_up     = parsed.post_up
            existing.post_down   = parsed.post_down
            db.session.add(existing)
    db.session.commit()

    out = []
    for i in InterfaceConfig.query.all():
        if ':' in (i.name or ''):
            continue
        out.append({
            'id': i.id,
            'name': i.name,
            'listen_port': i.listen_port,
            'mtu': i.mtu,
            'dns': i.dns,
            'available_ips': _available_ips(i),
            'is_up': _iface_up(i.name),    
        })
    return jsonify({'interfaces': out})

def _iface_down(name: str):
    try:
        subprocess.check_call(
            ['wg-quick', 'down', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6.0
        )
        return
    except Exception:
        subprocess.run(
            ['ip', 'link', 'del', 'dev', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )

@app.route('/api/iface/<int:iface_id>/enable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def iface_enable(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    _check_iface_up(iface) 
    return jsonify(success=True, is_up=True)

@app.route('/api/iface/<int:iface_id>/disable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def iface_disable(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    _iface_down(iface.name)
    return jsonify(success=True, is_up=False)

# -------------
# Peer actions
# _____________
@app.route('/api/peer/<int:pid>/enable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def api_enable(pid):
    p = db.session.get(Peer, pid) or abort(404)
    p.first_used_at = None
    p.expires_at = None
    p.bytes_offset = _wg_transfer(p)
    try:
        _wg_enable(p)
        _sync_peer(p)
    except subprocess.CalledProcessError as e:
        dev = iface_devname(p.iface)
        current_app.logger.warning("wg set failed for %s on %s: %s", p.name, dev, e)
        return jsonify(
            error="wg_failed",
            message=str(e),
            hint=f"Is interface '{dev}' up? Try: systemctl start wg-quick@{dev}"
        ), 409
    p.status = 'online'
    db.session.commit()
    log_event(p, 'enabled', 'Timer+data reset on enable')
    return jsonify(success=True)


@app.route('/api/peer/<int:pid>/disable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def api_disable(pid):
    p = db.session.get(Peer, pid) or abort(404)
    _wg_disable(p)
    p.status = 'offline'; db.session.commit(); log_event(p, 'disabled')
    logpanel_action("peer_disable", f"pid={p.id}; iface={p.iface}")
    return jsonify(success=True)

@app.route('/api/peer/<int:pid>', methods=['PUT'])
@csrf.exempt
@require_api_key_or_login
def api_edit(pid):
    data = request.json or {}
    p = db.session.get(Peer, pid) or abort(404)

    if 'time_limit_days' in data or 'time_limit_hours' in data:
        data['time_limit_days'] = _conv_time_limit(data)
        data.pop('time_limit_hours', None)

    updated = []
    for f in ('name','address','allowed_ips','endpoint','persistent_keepalive','mtu','dns',
              'data_limit_value','data_limit_unit','time_limit_days','start_on_first_use','unlimited',
              'phone_number','telegram_id'):
        if f in data:
            setattr(p, f, data[f]); updated.append(f)

    if any(k in data for k in ('time_limit_days', 'start_on_first_use', 'unlimited')):
        if getattr(p, 'unlimited', False):
            p.expires_at = None
        elif getattr(p, 'time_limit_days', None):
            if getattr(p, 'start_on_first_use', False) and not getattr(p, 'first_used_at', None):
                p.expires_at = None
            else:
                anchor_ts = to_ts(getattr(p, 'first_used_at', None)) or now_ts()
                p.expires_at = from_ts(add_days_ts(anchor_ts, float(p.time_limit_days)))
        else:
            p.expires_at = None

    db.session.commit()
    try:
        _wg_enable(p); _sync_peer(p)
    except Exception:
        pass
    log_event(p, 'edited', f"Fields: {', '.join(updated)}")
    logpanel_action("peer_edit", f"pid={p.id}; fields={', '.join(updated)}")
    return jsonify(success=True)

@app.route('/api/peer/<int:pid>/reset_data', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def reset_data(pid):
    p = db.session.get(Peer, pid) or abort(404)
    current = _wg_transfer(p)
    prev_off = int(getattr(p, 'bytes_offset', 0) or 0)
    session_used = max(0, int(current) - prev_off)

    p.used_bytes_total = int(getattr(p, 'used_bytes_total', 0) or 0) + session_used
    p.bytes_offset = int(current)

    db.session.commit()
    log_event(p, 'reset_data', f'Offset set to {current}; +{session_used} bytes to lifetime')
    logpanel_action("peer_reset_data", f"pid={p.id}; new_offset={current}; add={session_used}")
    return jsonify(success=True)



@app.route('/api/peer/<int:pid>/reset_timer', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def api_reset_timer(pid):
    p = db.session.get(Peer, pid) or abort(404)

    now = now_ts()
    tl_days = getattr(p, 'time_limit_days', None)
    try:
        tl_days_f = float(tl_days) if tl_days is not None else None
    except Exception:
        tl_days_f = None

    p.first_used_at = None

    if getattr(p, 'unlimited', False) or not tl_days_f or tl_days_f <= 0:
        p.expires_at = None
        detail = 'Timer cleared (no time cap)'
    else:
        if getattr(p, 'start_on_first_use', False):
            p.expires_at = None
            detail = 'Timer cleared (will start on first use)'
        else:
            exp_ts = add_days_ts(now, tl_days_f)
            p.expires_at = from_ts(exp_ts)
            detail = f'Timer restarted for {tl_days_f} days'

    db.session.commit()
    log_event(p, 'reset_timer', detail)
    return jsonify(success=True)



@app.route('/api/peer/<int:pid>', methods=['DELETE'])
@csrf.exempt
@require_api_key_or_login
def api_delete(pid):
    p = db.session.get(Peer, pid) or abort(404)
    try: _wg_disable(p)
    except Exception: pass
    try: _remove_peer(p)
    except Exception: pass
    db.session.delete(p)
    db.session.commit()
    logpanel_action("peer_delete", f"pid={pid}")
    return jsonify(success=True)

@app.route('/api/peer/<int:pid>/logs')
@login_required
def peer_logs(pid):
    p = db.session.get(Peer, pid) or abort(404)
    rows = (PeerEvent.query
        .filter_by(peer_id=pid)
        .order_by(PeerEvent.timestamp.desc())
        .limit(500)
        .all())

    return jsonify(logs=[{'time': isoz(e.timestamp), 'event': e.event, 'details': e.details} 
                     for e in rows])

# ------------
# Config & QR
# ____________
@app.route('/api/peer/<int:pid>/config')
@csrf.exempt           
@require_api_key_or_login
def peer_config(pid):
    p = db.session.get(Peer, pid) or abort(404)
    text = _client_conf_txt(p)

    if request.args.get('download'):
        resp = make_response(text)
        fname = f"{p.name or 'peer'}-{p.id}.conf".replace(' ', '_')
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename="{fname}"'
        return resp

    return current_app.response_class(
        text,
        mimetype='text/plain; charset=utf-8'
    )


@app.route('/api/peer/<int:pid>/config_qr')
@csrf.exempt           
@require_api_key_or_login
def peer_config_qr(pid):
    p = db.session.get(Peer, pid) or abort(404)
    text = _client_conf_txt(p)
    if not text:
        abort(404)

    img = qrcode.make(text)
    bio = BytesIO()
    img.save(bio, format='PNG')
    bio.seek(0)

    return send_file(
        bio,
        mimetype='image/png',
        as_attachment=False,
        download_name=f"{p.name or 'peer'}-{p.id}.png",
    )


_start_retention()
if __name__ == "__main__":

    import multiprocessing, ssl

    use_gunicorn = os.getenv("USE_GUNICORN", "1") != "0"

    def _tls_paths():
        try:
            s = _load_panel_settings() or {}
        except Exception:
            s = {}
        cert = (s.get("tls_cert_path") or "").strip()
        key  = (s.get("tls_key_path")  or "").strip()
        return cert, key

    cert_path, key_path = _tls_paths()

    try:
        ps = _load_panel_settings() or {}
    except Exception:
        ps = {}

    def _valid_port(x, dflt):
        try:
            i = int(x)
            return i if 1 <= i <= 65535 else dflt
        except Exception:
            return dflt

    http_port  = _valid_port(ps.get("http_port")  or 8000, 8000)  
    https_port = _valid_port(ps.get("https_port") or 443, 443)   

    tls_toggle = bool(ps.get("tls_enabled"))
    tls_files  = bool(
        cert_path and key_path and
        os.path.isfile(cert_path) and os.path.isfile(key_path)
    )
    tls_enabled = bool(tls_toggle and tls_files)

    try:
        rt = _load_runtime() or {}
    except Exception:
        rt = {}

    bind_from_rt = (rt.get("bind") or "").strip()
    try:
        port_from_rt = int(rt.get("port") or 0)
    except Exception:
        port_from_rt = 0

    host = (os.getenv("BIND_HOST") or "0.0.0.0").strip()

    if tls_enabled:
        bind = f"{host}:{https_port}"
    else:
        if bind_from_rt:
            bind = bind_from_rt
        else:
            eff_http_port = port_from_rt if port_from_rt else http_port
            eff_http_port = _valid_port(eff_http_port, 8000)
            bind = f"{host}:{eff_http_port}"

    app._tls_enabled_effective = bool(tls_enabled)

    app.config["PREFERRED_URL_SCHEME"] = "https" if tls_enabled else "http"
    cookie_secure = bool(tls_enabled)
    app.config.update(
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if not use_gunicorn:
        ssl_ctx = (cert_path, key_path) if tls_enabled else None

        if tls_enabled:
            chosen_port = int(os.getenv("DEV_PORT", str(https_port)))
        else:
            try:
                rt2 = _load_runtime() or {}
                rt_port = int(rt2.get("port") or 0)
            except Exception:
                rt_port = 0
            http_base = rt_port if rt_port else http_port
            chosen_port = int(os.getenv("DEV_PORT", str(_valid_port(http_base, 8000))))

        app.run(
            host=os.getenv("DEV_HOST", "127.0.0.1"),
            port=chosen_port,
            debug=os.getenv("FLASK_DEBUG", "0") == "1",
            ssl_context=ssl_ctx,
        )
        sys.exit(0)

    from gunicorn.app.base import BaseApplication

    try:
        if int(rt.get("workers", 0)) > 0:
            os.environ["WORKERS"] = str(rt["workers"])
        if "threads" in rt:
            os.environ["THREADS"] = str(rt.get("threads", 4))
        if "timeout" in rt:
            os.environ["TIMEOUT"] = str(rt.get("timeout", 60))
        if "graceful_timeout" in rt:
            os.environ["GRACEFUL_TIMEOUT"] = str(rt.get("graceful_timeout", 30))
        if "loglevel" in rt:
            os.environ["LOGLEVEL"] = (rt.get("loglevel") or "info").lower()
    except Exception:
        pass

    class _Guni(BaseApplication):
        def __init__(self, wsgi_app, options=None):
            self.options = options or {}
            self.application = wsgi_app
            super().__init__()

        def load_config(self):
            cfg = {k: v for k, v in self.options.items()
                   if k in self.cfg.settings and v is not None}
            for k, v in cfg.items():
                self.cfg.set(k.lower(), v)

        def load(self):
            return self.application

    def _env_int(name, dflt):
        try:
            return int(os.getenv(name) or dflt)
        except Exception:
            return dflt

    cpu_based_default_workers = multiprocessing.cpu_count() * 2 + 1
    workers          = _env_int("WORKERS", cpu_based_default_workers)
    threads          = _env_int("THREADS", 4)
    timeout          = _env_int("TIMEOUT", 60)
    graceful_timeout = _env_int("GRACEFUL_TIMEOUT", 30)
    loglevel         = (os.getenv("LOGLEVEL") or "info").lower()

    app.logger.handlers[:] = []
    app.logger.propagate = True
    try:
        app.logger.setLevel(LOG_LEVEL)
    except Exception:
        pass
    try:
        _applymute_log()
    except Exception:
        pass

    APP_START_TS = int(time.time())
    app.logger.info("Panel started (TLS=%s, bind=%s)", "on" if tls_enabled else "off", bind)

    options = {
        "bind": bind,
        "workers": workers,
        "worker_class": "gthread",
        "threads": threads,
        "timeout": timeout,
        "graceful_timeout": graceful_timeout,
        "accesslog": "-",
        "errorlog": "-",
        "loglevel": loglevel,
        "preload_app": False,
        "capture_output": True,
    }

    if tls_enabled:
        if not os.path.isfile(cert_path):
            raise RuntimeError(f"TLS cert not found: {cert_path}")
        if not os.path.isfile(key_path):
            raise RuntimeError(f"TLS key not found: {key_path}")
        options["certfile"] = cert_path
        options["keyfile"]  = key_path

        app.config.update(
            SESSION_COOKIE_SECURE=True,
            REMEMBER_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE="Lax",
        )

    try:
        bootstrap()
    except Exception as e:
        app.logger.exception("bootstrap failed: %s", e)

    _Guni(app, options).run()


