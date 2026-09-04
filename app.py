import os, glob, subprocess, time, shlex, logging, ipaddress, psutil, requests, json, tempfile, sys, zipfile, datetime as dt, ipaddress, platform, re, qrcode, multiprocessing, threading, shutil
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
from sqlalchemy import or_, and_, text, inspect, func, event
from flask_wtf.csrf import CSRFProtect, generate_csrf
from urllib.parse import urlparse, urljoin
import secrets
import hashlib
import string
import pyotp
import bcrypt
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

# ----------------------------------
# Panel version / update checker
# ----------------------------------
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

def _migrate_shortlinks_json_to_db():
    """
    Move old instance/short_links.json into the short_link DB table.

    """
    legacy_file = os.path.join(app.instance_path, "short_links.json")

    if not os.path.isfile(legacy_file):
        return

    try:
        with open(legacy_file, "r", encoding="utf-8") as f:
            old = json.load(f)
    except Exception:
        app.logger.exception("Could not read legacy short_links.json")
        return

    if not isinstance(old, dict):
        return

    imported = 0
    skipped = 0

    for token, rec in old.items():
        token = (token or "").strip()

        if not token or not isinstance(rec, dict):
            skipped += 1
            continue

        try:
            peer_id = int(rec.get("peer_id") or 0)
        except Exception:
            peer_id = 0

        if peer_id <= 0:
            skipped += 1
            continue

        peer = db.session.get(Peer, peer_id)
        if not peer:
            skipped += 1
            continue

        existing_token = ShortLink.query.filter_by(token=token).first()
        if existing_token:
            skipped += 1
            continue

        existing_peer = ShortLink.query.filter_by(peer_id=peer_id).first()
        if existing_peer:
            skipped += 1
            continue

        db.session.add(ShortLink(token=token, peer_id=peer_id))
        imported += 1

    if imported:
        db.session.commit()

    try:
        migrated_path = legacy_file + ".migrated"
        if not os.path.exists(migrated_path):
            os.replace(legacy_file, migrated_path)
    except Exception:
        app.logger.warning("Could not rename migrated short_links.json", exc_info=True)

    app.logger.info(
        "Shortlink migration finished: imported=%s skipped=%s",
        imported,
        skipped,
    )


class SchemaMigrationError(RuntimeError):
    """The database could not be brought up to the schema this build maps.

    Fatal on purpose: see `_migrate_schema`.
    """


def _shortlink_schema():
    """
    short_link table & migrate old JSON links

    Loads `Peer` through the ORM, so it must run after `_peer_schema()`.
    """
    db.create_all()
    _migrate_shortlinks_json_to_db()


def _peer_schema():
    """Bring older databases up to the peer/subscription schema this build needs.

    Adds `peer.address_host` (canonical host for the uniqueness invariant),
    `peer.peer_endpoint` (explicit server-side peer endpoint) and
    `subscription_peer.owned` (whether the subscription created the peer).
    """
    insp = inspect(db.engine)

    if not insp.has_table('peer'):
        return

    statements = []

    peer_cols = {c['name'] for c in insp.get_columns('peer')}
    if 'address_host' not in peer_cols:
        statements.append('ALTER TABLE peer ADD COLUMN address_host VARCHAR(64)')
    if 'peer_endpoint' not in peer_cols:
        statements.append('ALTER TABLE peer ADD COLUMN peer_endpoint VARCHAR(128)')
    if 'timer_started_at' not in peer_cols:
        statements.append('ALTER TABLE peer ADD COLUMN timer_started_at DATETIME')

    if insp.has_table('subscription'):
        subscription_cols = {
            c['name'] for c in insp.get_columns('subscription')
        }
        if 'timer_started_at' not in subscription_cols:
            statements.append(
                'ALTER TABLE subscription ADD COLUMN timer_started_at DATETIME'
            )

    if insp.has_table('subscription_peer'):
        link_cols = {c['name'] for c in insp.get_columns('subscription_peer')}
        if 'owned' not in link_cols:
            # Legacy links get owned=0 on purpose: i cannot tell whether the
            # subscription created the peer, and deleting someone else's peer
            # is not recoverable.
            statements.append(
                'ALTER TABLE subscription_peer '
                'ADD COLUMN owned BOOLEAN NOT NULL DEFAULT 0'
            )

    if statements:
        with db.engine.begin() as conn:
            for sql in statements:
                conn.execute(text(sql))

    _backfill_peer_address_hosts()


def _backfill_peer_address_hosts():

    pending = (
        db.session.query(Peer)
        .filter(or_(Peer.address_host.is_(None), Peer.address_host == ''))
        .all()
    )
    for peer in pending:
        peer.address_host = peer_address_host(peer.address)

    if pending:
        db.session.commit()

    duplicates = (
        db.session.query(Peer.iface_id, Peer.address_host, func.count(Peer.id))
        .filter(Peer.address_host.isnot(None))
        .group_by(Peer.iface_id, Peer.address_host)
        .having(func.count(Peer.id) > 1)
        .all()
    )

    if duplicates:
        resolved = 0
        for iface_id, host, _count in duplicates:
            dup_peers = (
                db.session.query(Peer.id)
                .filter(Peer.iface_id == iface_id, Peer.address_host == host)
                .order_by(Peer.id.asc())
                .all()
            )
            loser_ids = [pid for (pid,) in dup_peers[1:]]
            if loser_ids:
                db.session.query(Peer).filter(Peer.id.in_(loser_ids)).update(
                    {Peer.address_host: None}, synchronize_session=False
                )
                resolved += len(loser_ids)
        db.session.commit()
        app.logger.warning(
            "Resolved %s duplicate peer address_host row(s) by blanking the "
            "newer duplicates (their `address` column is unchanged). "
            "Duplicates were: %s",
            resolved,
            '; '.join(
                f'iface_id={iface_id} address={host} peers={count}'
                for iface_id, host, count in duplicates
            ),
        )

    if 'uq_peer_iface_address_host' in {ix['name'] for ix in inspect(db.engine).get_indexes('peer')}:
        return

    try:
        with db.engine.begin() as conn:
            conn.execute(text(
                'CREATE UNIQUE INDEX uq_peer_iface_address_host '
                'ON peer (iface_id, address_host)'
            ))
    except Exception:
        app.logger.debug("Peer address uniqueness index not created", exc_info=True)


def _interface_schema():

    insp = inspect(db.engine)

    if not insp.has_table('interface_config'):
        return

    cols = {c['name'] for c in insp.get_columns('interface_config')}
    statements = []

    if 'endpoint_host' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN endpoint_host VARCHAR(255)'
        )
    if 'endpoint_port' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN endpoint_port INTEGER'
        )

    if statements:
        with db.engine.begin() as conn:
            for sql in statements:
                conn.execute(text(sql))

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
    'peer_endpoint': '',
    'data_limit_value': 0,
    'data_limit_unit': 'Gi',
    'start_on_first_use': False,
    'unlimited': False,
    'time_limit_days': 0,
    'time_limit_hours': 0,
    'time_limit_minutes': 0,
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

    raw_old = data.get('old')
    raw_new = data.get('new')

    if not isinstance(raw_old, str) or not isinstance(raw_new, str):
        return jsonify(
            ok=False,
            error='invalid_name',
            message='The old and new profile names must be text.',
        ), 400

    old = raw_old.strip()
    new = raw_new.strip()

    if not old or not new:
        return jsonify(
            ok=False,
            error='old_and_new_required',
            message='Both the current name and new name are required.',
        ), 400

    if len(new) > 80:
        return jsonify(
            ok=False,
            error='name_too_long',
            message='Profile names cannot exceed 80 characters.',
        ), 400

    data_store = _load_profiles()
    profiles = data_store.get('profiles') or {}

    if old not in profiles:
        return jsonify(
            ok=False,
            error='not_found',
            message='The selected profile was not found.',
        ), 404

    if new != old and new in profiles:
        return jsonify(
            ok=False,
            error='exists',
            message='A profile with that name already exists.',
        ), 409

    if new != old:
        profiles[new] = profiles.pop(old)

    if data_store.get('active') == old:
        data_store['active'] = new

    _save_profiles(data_store)

    return jsonify(
        ok=True,
        old_name=old,
        name=new,
        active=data_store.get('active') or 'Default',
        profiles=sorted(profiles.keys()),
    )

@app.route('/api/peer_profile', methods=['GET'])
@login_required
def get_apipeer_profile():
    name = (request.args.get('name') or '').strip() or None
    return jsonify(_get_profile(name))

@app.route('/api/peer_profile', methods=['POST'])
@login_required
def save_apipeer_profile():
    data = request.get_json(force=True, silent=True) or {}

    raw_name = data.get('name')

    if raw_name is None:
        raw_name = 'Default'

    if not isinstance(raw_name, str):
        return jsonify(
            ok=False,
            error='invalid_name',
            message='Profile name must be text.',
        ), 400

    name = raw_name.strip() or 'Default'

    if len(name) > 80:
        return jsonify(
            ok=False,
            error='name_too_long',
            message='Profile names cannot exceed 80 characters.',
        ), 400

    payload = {
        key: value
        for key, value in data.items()
        if key != 'name'
    }

    _set_profile(name, payload)

    return jsonify(
        ok=True,
        name=name,
        saved_name=name,
        saved=_get_profile(name),
    )

@app.route('/api/peer_profile/activate', methods=['POST'])
@login_required
def activate_apipeer_profile():
    data = request.get_json(force=True, silent=True) or {}

    raw_name = data.get('name')

    if raw_name is None:
        raw_name = 'Default'

    if not isinstance(raw_name, str):
        return jsonify(
            ok=False,
            error='invalid_name',
            message='Profile name must be text.',
        ), 400

    name = raw_name.strip() or 'Default'

    profiles_data = _load_profiles()

    if name not in (profiles_data.get('profiles') or {}):
        return jsonify(
            ok=False,
            error='not_found',
            message='The selected profile was not found.',
        ), 404

    _set_active_profile(name)

    return jsonify(
        ok=True,
        active=name,
    )

# Subscription profiles

SUBSCRIPTION_PROFILES_FILE = os.path.join(
    app.instance_path,
    'subscription_profiles.json',
)


def _load_subscription_profiles():

    os.makedirs(
        app.instance_path,
        exist_ok=True,
    )

    try:
        with open(
            SUBSCRIPTION_PROFILES_FILE,
            'r',
            encoding='utf-8',
        ) as profile_file:
            data = json.load(
                profile_file
            )

    except FileNotFoundError:
        data = {}

    except Exception:
        current_app.logger.warning(
            'Could not read subscription profiles.',
            exc_info=True,
        )
        data = {}

    if not isinstance(
        data,
        dict,
    ):
        data = {}

    profiles = data.get(
        'profiles'
    )

    if not isinstance(
        profiles,
        dict,
    ):
        profiles = {}

    cleaned_profiles = {}

    for profile_name, profile_data in profiles.items():
        clean_name = str(
            profile_name or ''
        ).strip()

        if not clean_name:
            continue

        cleaned_profiles[
            clean_name
        ] = (
            profile_data
            if isinstance(
                profile_data,
                dict,
            )
            else {}
        )

    active_name = str(
        data.get('active')
        or ''
    ).strip()

    if (
        active_name
        and active_name
        not in cleaned_profiles
    ):
        active_name = ''

    if (
        not active_name
        and cleaned_profiles
    ):
        active_name = next(
            iter(
                sorted(
                    cleaned_profiles.keys(),
                    key=str.lower,
                )
            )
        )

    return {
        'active': active_name,
        'profiles': cleaned_profiles,
    }


def _save_subscription_profiles(data):
    """
    Save subscription profiles atomically.
    """
    os.makedirs(
        app.instance_path,
        exist_ok=True,
    )

    profiles = (
        data.get('profiles')
        if isinstance(data, dict)
        else {}
    )

    if not isinstance(
        profiles,
        dict,
    ):
        profiles = {}

    active_name = str(
        (
            data.get('active')
            if isinstance(data, dict)
            else ''
        )
        or ''
    ).strip()

    payload = {
        'active': active_name,
        'profiles': profiles,
    }

    temporary_path = (
        SUBSCRIPTION_PROFILES_FILE
        + '.tmp'
    )

    with open(
        temporary_path,
        'w',
        encoding='utf-8',
    ) as profile_file:
        json.dump(
            payload,
            profile_file,
            indent=2,
            ensure_ascii=False,
        )

    os.replace(
        temporary_path,
        SUBSCRIPTION_PROFILES_FILE,
    )

    try:
        os.chmod(
            SUBSCRIPTION_PROFILES_FILE,
            0o600,
        )
    except Exception:
        pass


def _subscription_profile_rows(data=None):
    """
    Return profile metadata for the profile dropdown.
    """
    data = (
        data
        or _load_subscription_profiles()
    )

    active_name = str(
        data.get('active')
        or ''
    ).strip()

    profiles = (
        data.get('profiles')
        or {}
    )

    return [
        {
            'name': profile_name,
            'default': (
                profile_name
                == active_name
            ),
            'active': (
                profile_name
                == active_name
            ),
        }
        for profile_name in sorted(
            profiles.keys(),
            key=str.lower,
        )
    ]


def _sanitize_subscription_profile(profile):

    if not isinstance(
        profile,
        dict,
    ):
        profile = {}

    include = profile.get(
        'include'
    )

    if not isinstance(
        include,
        dict,
    ):
        include = {}

    cleaned = {
        'include': {
            'client': bool(
                include.get('client')
            ),
            'advanced': bool(
                include.get('advanced')
            ),
            'interfaces': bool(
                include.get('interfaces')
            ),
            'template': bool(
                include.get('template')
            ),
        }
    }

    for section_name in (
    'client',
    'advanced',
    'template',
    ):
        section = profile.get(section_name)

        if isinstance(section, dict):
            cleaned[section_name] = section


    interfaces = profile.get('interfaces')

    if isinstance(interfaces, list):
        cleaned['interfaces'] = [
            item
            for item in interfaces[:200]
            if isinstance(item, dict)
        ]

    return cleaned


@app.get('/api/subscription_profiles')
@login_required
def subscription_profiles_list():
    store = (
        _load_subscription_profiles()
    )

    return jsonify(
        ok=True,
        active=(
            store.get('active')
            or ''
        ),
        profiles=(
            _subscription_profile_rows(
                store
            )
        ),
    )


@app.post('/api/subscription_profiles')
@login_required
def subscription_profile_save():
    payload = (
        request.get_json(
            silent=True,
        )
        or {}
    )

    profile_name = str(
        payload.get('name')
        or ''
    ).strip()

    if not profile_name:
        return jsonify(
            ok=False,
            error='name_required',
            message='Enter a profile name.',
        ), 400

    if len(profile_name) > 80:
        return jsonify(
            ok=False,
            error='name_too_long',
            message=(
                'Profile names cannot exceed '
                '80 characters.'
            ),
        ), 400

    profile_payload = (
        payload.get('profile')
    )

    if not isinstance(
        profile_payload,
        dict,
    ):

        profile_payload = {
            key: value
            for key, value in payload.items()
            if key not in {
                'name',
                'activate',
                'set_active',
            }
        }

    cleaned_profile = (
        _sanitize_subscription_profile(
            profile_payload
        )
    )

    store = (
        _load_subscription_profiles()
    )

    profiles = store.setdefault(
        'profiles',
        {},
    )

    profiles[
        profile_name
    ] = cleaned_profile

    should_activate = bool(
        payload.get('activate')
        or payload.get('set_active')
        or not store.get('active')
    )

    if should_activate:
        store[
            'active'
        ] = profile_name

    _save_subscription_profiles(
        store
    )

    return jsonify(
        ok=True,
        name=profile_name,
        saved_name=profile_name,
        active=(
            store.get('active')
            or ''
        ),
        profiles=(
            _subscription_profile_rows(
                store
            )
        ),
    )


@app.get('/api/subscription_profiles/<path:profile_name>')
@login_required
def subscription_profile_get(profile_name):
    clean_name = str(
        profile_name or ''
    ).strip()

    store = (
        _load_subscription_profiles()
    )

    profile = (
        store.get('profiles')
        or {}
    ).get(
        clean_name
    )

    if not isinstance(
        profile,
        dict,
    ):
        return jsonify(
            ok=False,
            error='not_found',
            message='Subscription profile was not found.',
        ), 404

    return jsonify(
        ok=True,
        name=clean_name,
        active=(
            store.get('active')
            == clean_name
        ),
        profile=profile,
    )


@app.post(
    '/api/subscription_profiles/<path:profile_name>/activate'
)
@login_required
def subscription_profile_activate(profile_name):
    clean_name = str(
        profile_name or ''
    ).strip()

    store = (
        _load_subscription_profiles()
    )

    profiles = (
        store.get('profiles')
        or {}
    )

    if clean_name not in profiles:
        return jsonify(
            ok=False,
            error='not_found',
            message='Subscription profile was not found.',
        ), 404

    store[
        'active'
    ] = clean_name

    _save_subscription_profiles(
        store
    )

    return jsonify(
        ok=True,
        active=clean_name,
        profiles=(
            _subscription_profile_rows(
                store
            )
        ),
    )


@app.post(
    '/api/subscription_profiles/<path:profile_name>/rename'
)
@login_required
def subscription_profile_rename(profile_name):
    old_name = str(
        profile_name or ''
    ).strip()

    payload = (
        request.get_json(
            silent=True,
        )
        or {}
    )

    new_name = str(
        payload.get('name')
        or payload.get('new')
        or ''
    ).strip()

    if not new_name:
        return jsonify(
            ok=False,
            error='name_required',
            message='Enter the new profile name.',
        ), 400

    if len(new_name) > 80:
        return jsonify(
            ok=False,
            error='name_too_long',
            message=(
                'Profile names cannot exceed '
                '80 characters.'
            ),
        ), 400

    store = (
        _load_subscription_profiles()
    )

    profiles = (
        store.get('profiles')
        or {}
    )

    if old_name not in profiles:
        return jsonify(
            ok=False,
            error='not_found',
            message='Subscription profile was not found.',
        ), 404

    if (
        new_name != old_name
        and new_name in profiles
    ):
        return jsonify(
            ok=False,
            error='exists',
            message=(
                'A subscription profile with that '
                'name already exists.'
            ),
        ), 409

    if new_name != old_name:
        profiles[
            new_name
        ] = profiles.pop(
            old_name
        )

    if (
        store.get('active')
        == old_name
    ):
        store[
            'active'
        ] = new_name

    _save_subscription_profiles(
        store
    )

    return jsonify(
        ok=True,
        old_name=old_name,
        name=new_name,
        active=(
            store.get('active')
            or ''
        ),
        profiles=(
            _subscription_profile_rows(
                store
            )
        ),
    )


@app.delete(
    '/api/subscription_profiles/<path:profile_name>'
)
@login_required
def subscription_profile_delete(profile_name):
    clean_name = str(
        profile_name or ''
    ).strip()

    store = (
        _load_subscription_profiles()
    )

    profiles = (
        store.get('profiles')
        or {}
    )

    if clean_name not in profiles:
        return jsonify(
            ok=False,
            error='not_found',
            message='Subscription profile was not found.',
        ), 404

    profiles.pop(
        clean_name,
        None,
    )

    if (
        store.get('active')
        == clean_name
    ):
        remaining_names = sorted(
            profiles.keys(),
            key=str.lower,
        )

        store[
            'active'
        ] = (
            remaining_names[0]
            if remaining_names
            else ''
        )

    _save_subscription_profiles(
        store
    )

    return jsonify(
        ok=True,
        deleted=clean_name,
        active=(
            store.get('active')
            or ''
        ),
        profiles=(
            _subscription_profile_rows(
                store
            )
        ),
    )
def _effective_dns(peer):
    return (peer.dns or getattr(peer.iface, 'dns', None) or _panel_default_dns())

#---------------
# logging
#_______________
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
os.makedirs(app.instance_path, exist_ok=True)
APP_LOG_FILE = os.path.join(app.instance_path, 'app.log')


def _utc_log_formatter(pattern: str) -> logging.Formatter:
    """Create an unambiguous UTC formatter for every new application log."""
    formatter = logging.Formatter(
        pattern,
        datefmt='%Y-%m-%dT%H:%M:%SZ',
    )
    formatter.converter = time.gmtime
    return formatter

if not app.logger.handlers:
    handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    handler.setLevel(logging.INFO)
    fmt = _utc_log_formatter("%(asctime)s [%(levelname)s] %(message)s")
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

_formatter = _utc_log_formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
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

@app.context_processor
def inject_panel_timezone():
    try:
        timezone_name = (
            _panel_timezone_name()
            or 'UTC'
        )
    except Exception:
        timezone_name = 'UTC'

    return {
        'PANEL_TIMEZONE': timezone_name
    }
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
    if request.path == '/api/timezone':
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        resp.headers['Vary'] = 'Cookie, Authorization'
    elif resp.mimetype == 'text/html':
        # The base template contains the selected panel timezone.  Never let a
        # browser, reverse proxy or CDN reuse HTML rendered for an older zone.
        resp.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        resp.headers['Vary'] = 'Cookie'
    elif request.path.startswith('/static/') and (request.path.endswith('.css') or request.path.endswith('.js')):
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
      - must be a valid http:// or https:// URL
      - must not resolve to loopback/private/link-local/reserved/multicast/unspecified
    """
    base_url = (base_url or '').strip().rstrip('/')
    if not _http_url(base_url):
        return False, 'invalid base_url'

    try:
        p = urlparse(base_url)
        scheme = (p.scheme or '').lower()

        if scheme not in ('http', 'https'):
            return False, 'nodes must use http or https'

        host = (p.hostname or '').strip()
        if not host:
            return False, 'invalid host'

        if host in ('localhost', '127.0.0.1', '::1'):
            return False, 'loopback hosts are not allowed'

        infos = []
        try:
            infos = socket.getaddrinfo(host, p.port or (443 if scheme == 'https' else 80), type=socket.SOCK_STREAM)
        except Exception:
            infos = []

        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except Exception:
                continue

            if (
                ip.is_loopback or ip.is_private or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified
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

def _read_api_key(node) -> str:
    raw = (getattr(node, 'api_key', None) or '').strip()
    if not raw:
        return ''

    # Backward compatibility for older stored values like enc$...
    if raw.startswith('enc$'):
        token = raw[4:].strip()
        for f in (_fernet, fernet):
            if not f:
                continue
            try:
                return f.decrypt(token.encode()).decode()
            except Exception:
                pass

        try:
            current_app.logger.warning(
                "Failed to decrypt legacy node api_key (id=%s)",
                getattr(node, 'id', '?')
            )
        except Exception:
            pass
        return ''

    return _probably_decrypt(raw)

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
def _app_log_timestamp_utc(value: str) -> str:
    """Normalize new UTC log stamps and legacy host-local stamps to UTC."""
    raw = str(value or '').strip().replace(' ', 'T').replace(',', '.')
    if not raw:
        return ''

    try:
        has_explicit_zone = bool(
            raw.endswith(('Z', 'z'))
            or re.search(r'[+-]\d{2}:?\d{2}$', raw)
        )

        if raw.endswith(('Z', 'z')):
            parsed = datetime.fromisoformat(raw[:-1] + '+00:00')
        else:
            parsed = datetime.fromisoformat(raw)

        if not has_explicit_zone:
            # Python logging.Formatter used host-local time in older releases.
            # Attach that host timezone before converting; never label the
            # legacy wall clock as UTC directly.
            parsed = parsed.astimezone()
        elif parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return (
            parsed.astimezone(timezone.utc)
            .isoformat(timespec='seconds')
            .replace('+00:00', 'Z')
        )
    except Exception:
        return ''


def _app_log_line(s: str):
    s = (s or '').rstrip('\n')
    stamp = r'(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[,.]\d{1,6})?(?:Z|[+-]\d\d:?\d\d)?)'
    m = re.match(r'^' + stamp + r'\s+\[?([A-Z]+)\]?\s+([^:]+):\s*(.*)$', s)
    if m:
        ts, level, _name, msg = m.groups()
    else:
        m = re.match(r'^' + stamp + r'\s+\[?([A-Z]+)\]?\s+(.*)$', s)
        if m:
            ts, level, msg = m.group(1), m.group(2), m.group(3)
        else:
            m = re.search(r'\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b', s)
            level = (m.group(1) if m else 'INFO').upper()
            ts = ''
            msg = s
    if ts:
        ts = _app_log_timestamp_utc(ts)
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
    ts = _panel_filename_stamp()
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

def _version_tuple(v: str):
    """
    Converts versions like:
    1.0.0
    v1.0
    V1.2.3
    into comparable tuples.
    """
    import re

    s = str(v or "").strip()
    s = s.lstrip("vV")
    nums = re.findall(r"\d+", s)

    if not nums:
        return (0, 0, 0)

    parts = [int(x) for x in nums[:3]]
    while len(parts) < 3:
        parts.append(0)

    return tuple(parts)


def _update_source_marker(
    scope: str = "panel",
) -> Path:
    safe_scope = (
        "node"
        if str(scope).strip().lower() == "node"
        else "panel"
    )

    return (
        Path(INSTANCE_DIR)
        / f"update_source_{safe_scope}.json"
    )


def _read_update_source(
    scope: str = "panel",
) -> dict:
    try:
        payload = json.loads(
            _update_source_marker(scope)
            .read_text(
                encoding="utf-8",
            )
        )

        return (
            payload
            if isinstance(payload, dict)
            else {}
        )

    except Exception:
        return {}


def _github_latest_panel_version():

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "WG-Panel",
        "Cache-Control": "no-cache",
    }

    commit_sha = ""
    commit_url = ""
    commit_date = ""
    remote_version = None

    try:
        response = requests.get(
            (
                f"https://api.github.com/repos/"
                f"{PANEL_REPO}/commits/main"
            ),
            headers=headers,
            timeout=8,
        )

        response.raise_for_status()

        payload = response.json() or {}

        commit_sha = str(
            payload.get("sha")
            or ""
        ).strip()

        commit_url = str(
            payload.get("html_url")
            or f"https://github.com/{PANEL_REPO}"
        ).strip()

        commit = payload.get("commit") or {}
        author = commit.get("author") or {}

        commit_date = str(
            author.get("date")
            or ""
        ).strip()

    except Exception as exc:
        logging.getLogger(__name__).warning(
            "Could not read GitHub main commit: %s",
            exc,
        )

    try:
        response = requests.get(
            (
                f"https://raw.githubusercontent.com/"
                f"{PANEL_REPO}/main/VERSION"
            ),
            headers=headers,
            timeout=6,
        )

        if response.ok:
            candidate = (
                response.text
                .strip()
                .lstrip("vV")
            )

            if re.fullmatch(
                r"\d+(?:\.\d+){0,3}"
                r"(?:[-+][0-9A-Za-z.-]+)?",
                candidate,
            ):
                remote_version = candidate

    except Exception:
        pass

    if not commit_sha and not remote_version:
        return None

    return {
        "version": remote_version,
        "target": "main",
        "url": (
            commit_url
            or f"https://github.com/{PANEL_REPO}"
        ),
        "source": "main",
        "revision": commit_sha,
        "revision_short": commit_sha[:8],
        "commit_date": commit_date,
    }

@app.get("/api/panel/version")
@require_api_key_or_login
def api_panel_version():
    now = int(time.time())

    fresh = (
        str(
            request.args.get("fresh")
            or ""
        )
        .strip()
        .lower()
        in {
            "1",
            "true",
            "yes",
            "on",
        }
    )

    if (
        not fresh
        and _PANEL_UPDATE_CACHE.get("data")
        and now - int(
            _PANEL_UPDATE_CACHE.get("ts")
            or 0
        ) < PANEL_UPDATE_TTL
    ):
        return jsonify(
            _PANEL_UPDATE_CACHE["data"]
        )

    remote = (
        _github_latest_panel_version()
        or {}
    )

    installed = _read_update_source(
        "panel"
    )

    current_version = str(
        PANEL_VERSION
        or "0.0.0"
    ).strip().lstrip("vV")

    latest_version = str(
        remote.get("version")
        or current_version
        or "0.0.0"
    ).strip().lstrip("vV")

    remote_revision = str(
        remote.get("revision")
        or ""
    ).strip()

    installed_revision = str(
        installed.get("revision")
        or ""
    ).strip()

    version_update_available = (
        _version_tuple(latest_version)
        > _version_tuple(current_version)
    )

    revision_update_available = bool(
        remote_revision
        and installed_revision
        and remote_revision != installed_revision
    )

    if (
        version_update_available
        and revision_update_available
    ):
        update_reason = (
            "version_and_revision"
        )

    elif version_update_available:
        update_reason = "version"

    elif revision_update_available:
        update_reason = "revision"

    else:
        update_reason = "current"

    update_available = bool(
        version_update_available
        or revision_update_available
    )

    payload = {
        "ok": True,

        "current": current_version,
        "version_source": "VERSION",

        "repo": PANEL_REPO,

        "latest": latest_version,

        "latest_url": (
            remote.get("url")
            or f"https://github.com/{PANEL_REPO}"
        ),

        "source": "main",
        "target": "main",
        "update_source": "main",

        "current_revision": (
            installed_revision
        ),

        "current_revision_short": (
            installed_revision[:8]
        ),

        "latest_revision": (
            remote_revision
        ),

        "latest_revision_short": (
            remote_revision[:8]
        ),

        "commit_date": remote.get(
            "commit_date"
        ),

        "revision_tracked": bool(
            installed_revision
        ),

        "version_update_available": (
            version_update_available
        ),

        "revision_update_available": (
            revision_update_available
        ),

        "update_available": (
            update_available
        ),

        "update_reason": (
            update_reason
        ),

        "checked_at": (
            datetime.utcnow()
            .isoformat(
                timespec="seconds",
            )
            + "Z"
        ),
    }

    _PANEL_UPDATE_CACHE["ts"] = now
    _PANEL_UPDATE_CACHE["data"] = payload

    return jsonify(payload)

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
        if rec.get('ts'):
            rec['time_display'] = _panel_display_datetime(
                rec['ts'],
                seconds=True,
            )
        out.append(rec)
    return jsonify(
        logs=out[-limit:],
        display_timezone=_panel_timezone_name(),
        server_epoch=now_ts(),
    )


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

        from_dt = _panel_filter_datetime_utc_naive(from_s)
        to_dt = _panel_filter_datetime_utc_naive(to_s)

        def in_range(ts_iso: str) -> bool:
            t = _panel_filter_datetime_utc_naive(ts_iso)

            if t is None:
                return True

            if from_dt and t < from_dt:
                return False

            if to_dt and t > to_dt:
                return False

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
        visible = []

        for rec in out[:limit]:
            row = dict(rec)
            normalized = _utc_timestamp_iso(
                row.get('ts')
            )

            if normalized:
                row['ts'] = normalized
                row['time_display'] = _panel_display_datetime(
                    normalized,
                    seconds=True,
                )

            visible.append(row)

        return jsonify(
            logs=visible,
            display_timezone=_panel_timezone_name(),
            server_epoch=now_ts(),
        )

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
    notify = s.get('notify') or {}

    defaults = {
        'app_down': True,
        'app_up': True,
        'node_down': True,
        'node_up': True,
        'iface_down': True,
        'iface_up': True,
        'peer_expired': True,
        'peer_limit': True,
        'login_success': True,
        'login_fail': True,
        'suspicious_4xx': True,
        'security_block': True,
        'security_release': True,
        'security_auto_release': False,
        'traffic_policy_change': False,
        'traffic_apply_success': False,
        'traffic_apply_failed': True,
        'backup_success': False,
        'backup_failed': True,
        'update_success': True,
        'update_failed': True,
    }

    return {
        'enabled': bool(s.get('enabled', False)),
        'notify': {
            key: bool(notify.get(key, default))
            for key, default in defaults.items()
        },
        'bot_token': (s.get('bot_token') or '').strip(),
    }

_TG_EVENT_LOCK = threading.Lock()
_TG_EVENT_LAST = {}

def _tg_human_bytes(value) -> str:
    try:
        value = max(
            0,
            int(value or 0),
        )
    except Exception:
        return '0 B'

    units = (
        'B',
        'KiB',
        'MiB',
        'GiB',
        'TiB',
    )

    amount = float(value)

    for unit in units:
        if (
            amount < 1024
            or unit == units[-1]
        ):
            if unit == 'B':
                return f'{int(amount)} B'

            if amount >= 100:
                return f'{amount:.0f} {unit}'

            if amount >= 10:
                return f'{amount:.1f} {unit}'

            return f'{amount:.2f} {unit}'

        amount /= 1024.0

    return f'{value} B'

def _tg_human_duration(value) -> str:

    try:
        seconds = max(
            0,
            int(float(value or 0)),
        )
    except Exception:
        return ''

    days, rem = divmod(
        seconds,
        86400,
    )

    hours, rem = divmod(
        rem,
        3600,
    )

    minutes, secs = divmod(
        rem,
        60,
    )

    parts = []

    if days:
        parts.append(
            f"{days} day"
            + (
                ""
                if days == 1
                else "s"
            )
        )

    if hours:
        parts.append(
            f"{hours} hour"
            + (
                ""
                if hours == 1
                else "s"
            )
        )

    if minutes:
        parts.append(
            f"{minutes} minute"
            + (
                ""
                if minutes == 1
                else "s"
            )
        )

    if (
        secs
        and not days
        and not hours
    ):
        parts.append(
            f"{secs} second"
            + (
                ""
                if secs == 1
                else "s"
            )
        )

    if not parts:
        return "0 seconds"

    return " ".join(
        parts[:3]
    )


def _tg_system_timezone():
    """
    Telegram timestamps use the global panel timezone.

    All stored timestamps remain UTC.
    """
    try:
        return _panel_timezone()
    except Exception:
        return timezone.utc


def _tg_parse_datetime(value):
    if value in (None, "", "—"):
        return None

    if isinstance(value, datetime):
        parsed = value

    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
        except Exception:
            return None

    else:
        raw = str(value).strip()

        if not raw:
            return None

        try:
            if re.fullmatch(r"\d+(?:\.\d+)?", raw):
                parsed = datetime.fromtimestamp(
                    float(raw),
                    tz=timezone.utc,
                )
            else:
                normalized = raw

                if normalized.endswith("Z"):
                    normalized = normalized[:-1] + "+00:00"

                parsed = datetime.fromisoformat(normalized)

        except Exception:
            return None

    # Database/API datetimes without an offset are treated as UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _tg_human_delta(seconds: float) -> str:
    future = seconds < 0
    seconds = abs(int(seconds))

    if seconds < 10:
        return "in a moment" if future else "just now"

    if seconds < 60:
        value = seconds
        text = f"{value} second{'s' if value != 1 else ''}"

    elif seconds < 3600:
        value = max(1, seconds // 60)
        text = f"{value} minute{'s' if value != 1 else ''}"

    elif seconds < 86400:
        value = max(1, seconds // 3600)
        text = f"{value} hour{'s' if value != 1 else ''}"

    elif seconds < 604800:
        value = max(1, seconds // 86400)
        text = f"{value} day{'s' if value != 1 else ''}"

    elif seconds < 2592000:
        value = max(1, seconds // 604800)
        text = f"{value} week{'s' if value != 1 else ''}"

    elif seconds < 31536000:
        value = max(1, seconds // 2592000)
        text = f"{value} month{'s' if value != 1 else ''}"

    else:
        value = max(1, seconds // 31536000)
        text = f"{value} year{'s' if value != 1 else ''}"

    return f"in {text}" if future else f"{text} ago"


def _tg_human_datetime(
    value,
    *,
    relative: bool = False,
    seconds: bool = False,
    fallback: str = "—",
) -> str:
    """
    Human-friendly Telegram datetime in the saved panel timezone.

    Example:
        23 Aug 2026 · 22:31

    """
    parsed = _tg_parse_datetime(value)

    if parsed is None:
        return fallback if value in (None, "", "—") else str(value)

    local_tz = _tg_system_timezone()
    local_dt = parsed.astimezone(local_tz)
    now = datetime.now(timezone.utc).astimezone(local_tz)

    if seconds:
        absolute = local_dt.strftime("%d %b %Y · %H:%M:%S")
    else:
        absolute = local_dt.strftime("%d %b %Y · %H:%M")

    if not relative:
        return absolute

    delta = (now - local_dt).total_seconds()
    human = _tg_human_delta(delta)

    return f"{absolute} ({human})"


def _tg_now_text() -> str:
    return _tg_human_datetime(
        datetime.now(timezone.utc),
        relative=False,
        seconds=True,
    )

def _tg_event_escape(value) -> str:
    import html

    return html.escape(
        str(value or ''),
        quote=True,
    )


def _tg_event_enabled(event_key: str) -> bool:
    settings = _load_tg_settings() or {}

    if not settings.get('enabled'):
        return False

    notify = settings.get('notify') or {}

    return bool(
        notify.get(
            str(event_key or '').strip(),
            False,
        )
    )


def _send_telegram_event(
    event_key: str,
    title: str,
    *,
    status: str = '',
    details: list[tuple[str, object]] | None = None,
    dedupe_key: str = '',
    dedupe_seconds: int = 60,
) -> None:

    event_key = str(
        event_key or ''
    ).strip()

    if not event_key:
        return

    if not _tg_event_enabled(
        event_key
    ):
        return

    settings = (
        _load_tg_settings()
        or {}
    )

    bot_token = str(
        settings.get('bot_token')
        or ''
    ).strip()

    recipients = [
        str(
            admin.get('id')
            or ''
        ).strip()
        for admin in (
            _load_tg_admins()
            or []
        )
        if (
            str(
                admin.get('id')
                or ''
            ).strip()
            and not admin.get('muted')
        )
    ]

    if not bot_token or not recipients:
        return


    event_identity = (
        event_key,
        str(
            dedupe_key
            or title
            or event_key
        ).strip(),
    )

    monotonic_now = (
        time.monotonic()
    )

    with _TG_EVENT_LOCK:

        previous_time = float(
            _TG_EVENT_LAST.get(
                event_identity
            )
            or 0
        )

        if (
            dedupe_seconds > 0
            and previous_time
            and (
                monotonic_now
                - previous_time
                < dedupe_seconds
            )
        ):
            return

        _TG_EVENT_LAST[
            event_identity
        ] = monotonic_now

        if len(_TG_EVENT_LAST) > 1000:

            expiry_time = (
                monotonic_now
                - 86400
            )

            for old_key, old_time in list(
                _TG_EVENT_LAST.items()
            ):

                if (
                    float(
                        old_time
                        or 0
                    )
                    < expiry_time
                ):

                    _TG_EVENT_LAST.pop(
                        old_key,
                        None,
                    )

    # -----------------
    # Monochrome icons
    # -----------------

    icon_map = {
        'app_down': '⊘',
        'app_up': '●',

        'node_down': '○',
        'node_up': '●',

        'iface_down': '○',
        'iface_up': '●',

        'peer_expired': '◇',
        'peer_limit': '◆',

        'login_success': '●',
        'login_fail': '⊘',

        'suspicious_4xx': '◆',
        'security_block': '⊘',
        'security_release': '◇',
        'security_auto_release': '◇',

        'traffic_policy_change': '◇',
        'traffic_apply_success': '●',
        'traffic_apply_failed': '⊘',

        'backup_success': '●',
        'backup_failed': '⊘',

        'update_success': '●',
        'update_failed': '⊘',
    }

    icon = icon_map.get(
        event_key,
        '◇',
    )

    clean_title = re.sub(
        r'^[●○◆◇◷⌂⊘✦↥↻]+\s*',
        '',
        str(
            title or ''
        ).strip(),
    )

    clean_status = str(
        status or ''
    ).strip()

    # Footer timestamp uses the
    # global panel timezone.
    timestamp = _tg_now_text()

    hostname = str(
        socket.gethostname()
        or 'panel'
    ).strip()

    # -----------------
    # Datetime labels
    # -----------------

    time_labels = {
        'time',
        'timestamp',

        'created',
        'created at',

        'updated',
        'updated at',

        'started',
        'started at',

        'completed',
        'completed at',

        'failed at',

        'blocked at',
        'blocked until',

        'released at',

        'expires',
        'expires at',

        'last seen',
        'last run',

        'next run',
        'next check',

        'recovered at',

        'schedule time',
        'scheduled for',
    }

    rows = []

    for label, value in (
        details or []
    ):

        if value in (
            None,
            '',
        ):
            continue

        clean_label = str(
            label or ''
        ).strip()

        if not clean_label:
            continue

        label_key = (
            clean_label.lower()
        )

        if label_key in time_labels:

            clean_value = _tg_human_datetime(value,relative=False,seconds=False,fallback='—',)

        else:

            clean_value = str(
                value
                if value is not None
                else ''
            ).strip()

        if not clean_value:
            continue

        rows.append(
            (
                clean_label,
                clean_value,
            )
        )

    # -------------------------
    # Mobile-friendly layout
    # -------------------------

    message_lines = [
        (
            f'{icon} '
            f'<b>'
            f'{_tg_event_escape(clean_title)}'
            f'</b>'
        )
    ]

    if (
        clean_status
        or rows
    ):
        message_lines.append(
            ''
        )

    if clean_status:
        message_lines.append(
            (
                '<b>Status</b> · '
                f'{_tg_event_escape(clean_status)}'
            )
        )

    for label, value in rows:

        message_lines.append(
            (
                f'<b>'
                f'{_tg_event_escape(label)}'
                f'</b> · '
                f'{_tg_event_escape(value)}'
            )
        )

    # -----------------
    # Message footer
    # -----------------

    message_lines.extend([
        '',
        (
            '◷ '
            f'{_tg_event_escape(timestamp)}'
            ' · '
            f'{_tg_event_escape(hostname)}'
        ),
    ])

    message_text = '\n'.join(
        message_lines
    )

    # Keep a real Flask app reference
    # because sending happens in a thread.
    flask_app = (
        current_app
        ._get_current_object()
    )

    # -----------------
    # Background sender
    # -----------------

    def worker():

        with flask_app.app_context():

            for chat_id in recipients:

                try:

                    response = requests.post(
                        (
                            'https://api.telegram.org/'
                            f'bot{bot_token}/sendMessage'
                        ),
                        json={
                            'chat_id': chat_id,
                            'text': message_text,
                            'parse_mode': 'HTML',
                            'disable_web_page_preview': True,
                        },
                        timeout=8,
                    )

                    if not response.ok:

                        flask_app.logger.warning(
                            'Telegram event failed: '
                            'event=%s '
                            'chat_id=%s '
                            'status=%s '
                            'response=%s',
                            event_key,
                            chat_id,
                            response.status_code,
                            response.text[:300],
                        )

                except Exception:

                    flask_app.logger.debug(
                        'Telegram event failed: '
                        'event=%s '
                        'chat_id=%s',
                        event_key,
                        chat_id,
                        exc_info=True,
                    )

    threading.Thread(
        target=worker,
        name=(
            'telegram-event-'
            + event_key[:40]
        ),
        daemon=True,
    ).start()

# ========================
# HTTP security center
# ========================

_HTTP_4XX_STATE_FILE = os.path.join(app.instance_path, "suspicious_4xx_state.json")
_HTTP_4XX_LOCK_FILE = os.path.join(app.instance_path, "suspicious_4xx_state.lock")
_HTTP_SECURITY_SETTINGS_FILE = os.path.join(app.instance_path, "http_security_settings.json")
_HTTP_4XX_STATUSES = {401, 403, 404, 405, 429}

_HTTP_SECURITY_DEFAULTS = {
    "enabled": True,
    "response_mode": "monitor",       # monitor | block
    "ip_source": "direct",            # direct | effective
    "block_scope": "all",             # all | auth_admin
    "threshold": 20,
    "window_seconds": 60,
    "sensitive_threshold": 3,
    "rate_limit_threshold": 10,
    "login_threshold": 5,
    "login_window_seconds": 600,
    "cooldown_seconds": 600,
    "block_seconds": 900,
    "max_block_seconds": 86400,
    "escalate": True,
    "enrich_ip": False,
    "firewall_enabled": False,
    "firewall_after_offenses": 3,
    "trusted_networks": ["127.0.0.1/32", "::1/128"],
    "deny_networks": [],
}

_HTTP_SECURITY_OFFENSE_RESET_SEC = 7 * 24 * 60 * 60
_HTTP_SECURITY_HISTORY_LIMIT = 500
_HTTP_SECURITY_TEMP_ALLOW_MAX_SEC = 7 * 24 * 60 * 60
_HTTP_SECURITY_NFT_TABLE = "wgpanel_security"
_HTTP_SECURITY_NFT_V4_SET = "blocked_v4"
_HTTP_SECURITY_NFT_V6_SET = "blocked_v6"
_HTTP_SECURITY_CLEANUP_STARTED = False
_HTTP_SECURITY_GEO_CACHE = {}
_HTTP_SECURITY_GEO_CACHE_LOCK = threading.Lock()

_HTTP_SECURITY_SENSITIVE_RE = re.compile(
    r"(?:^|/)\.env(?:[./~_-]|$)|"
    r"(?:^|/)\.(?:git|svn|hg|aws|ssh)(?:/|$)|"
    r"(?:^|/)(?:wp-admin|wp-login\.php|phpmyadmin)(?:/|$)|"
    r"(?:^|/)(?:credentials?|secrets?|config|settings?)(?:\.(?:json|ya?ml|ini|conf|php|py|js|bak|old|orig|save|zip|tar|gz)|/|$)|"
    r"(?:^|/)(?:docker-?compose|compose)(?:\.[^/]+)?$|"
    r"\.(?:bak|old|orig|save|swp|sql|sqlite|db)(?:$|[?#])",
    re.IGNORECASE,
)


def _http_security_int(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except Exception:
        return default


def _http_security_normalize_networks(value):
    if isinstance(value, str):
        value = re.split(r"[\r\n,]+", value)
    if not isinstance(value, list):
        value = []

    cleaned = []
    for item in value:
        raw = str(item or "").strip()
        if not raw:
            continue
        try:
            if "/" not in raw:
                ip = ipaddress.ip_address(raw)
                raw = f"{ip}/{32 if ip.version == 4 else 128}"
            else:
                raw = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
        if raw not in cleaned:
            cleaned.append(raw)
    return cleaned


def _load_http_security_settings():
    raw = _json_load(_HTTP_SECURITY_SETTINGS_FILE, {})
    if not isinstance(raw, dict):
        raw = {}

    settings = dict(_HTTP_SECURITY_DEFAULTS)
    settings.update(raw)

    settings["enabled"] = bool(settings.get("enabled", True))
    settings["response_mode"] = (
        "block" if str(settings.get("response_mode") or "").lower() == "block" else "monitor"
    )
    settings["ip_source"] = (
        "effective" if str(settings.get("ip_source") or "").lower() == "effective" else "direct"
    )
    settings["block_scope"] = (
        "auth_admin" if str(settings.get("block_scope") or "").lower() == "auth_admin" else "all"
    )
    settings["threshold"] = _http_security_int(settings.get("threshold"), 20, 3, 500)
    settings["window_seconds"] = _http_security_int(settings.get("window_seconds"), 60, 10, 3600)
    settings["sensitive_threshold"] = _http_security_int(settings.get("sensitive_threshold"), 3, 1, 50)
    settings["rate_limit_threshold"] = _http_security_int(settings.get("rate_limit_threshold"), 10, 1, 200)
    settings["login_threshold"] = _http_security_int(settings.get("login_threshold"), 5, 2, 100)
    settings["login_window_seconds"] = _http_security_int(settings.get("login_window_seconds"), 600, 60, 86400)
    settings["cooldown_seconds"] = _http_security_int(settings.get("cooldown_seconds"), 600, 30, 86400)
    settings["block_seconds"] = _http_security_int(settings.get("block_seconds"), 900, 60, 604800)
    settings["max_block_seconds"] = _http_security_int(settings.get("max_block_seconds"), 86400, 60, 2592000)
    settings["max_block_seconds"] = max(settings["block_seconds"], settings["max_block_seconds"])
    settings["escalate"] = bool(settings.get("escalate", True))
    settings["enrich_ip"] = bool(settings.get("enrich_ip", False))
    settings["firewall_enabled"] = bool(settings.get("firewall_enabled", False))
    settings["firewall_after_offenses"] = _http_security_int(
        settings.get("firewall_after_offenses"), 3, 1, 20
    )
    settings["trusted_networks"] = _http_security_normalize_networks(settings.get("trusted_networks"))
    settings["deny_networks"] = _http_security_normalize_networks(settings.get("deny_networks"))
    return settings


def _save_http_security_settings(settings):
    normalized = _load_http_security_settings()
    normalized.update(settings or {})
    _json_save(_HTTP_SECURITY_SETTINGS_FILE, normalized)
    return _load_http_security_settings()


def _http_security_normalize_ip(value):
    value = str(value or "").strip()
    if not value:
        return "unknown"
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "unknown"


def _http_security_direct_ip():
    original = request.environ.get("werkzeug.proxy_fix.orig") or {}
    if isinstance(original, dict):
        value = _http_security_normalize_ip(original.get("REMOTE_ADDR"))
        if value != "unknown":
            return value
    return _http_security_normalize_ip(request.remote_addr)


def _http_security_effective_ip():
    candidates = [
        request.headers.get("CF-Connecting-IP"),
        request.headers.get("True-Client-IP"),
        request.headers.get("X-Real-IP"),
        (request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip(),
        request.remote_addr,
    ]
    for candidate in candidates:
        value = _http_security_normalize_ip(candidate)
        if value != "unknown":
            return value
    return "unknown"


def _http_security_client_ip(settings=None):
    settings = settings or _load_http_security_settings()
    return (
        _http_security_effective_ip()
        if settings.get("ip_source") == "effective"
        else _http_security_direct_ip()
    )


def _http_security_network_contains(client_ip, networks):
    try:
        address = ipaddress.ip_address(str(client_ip).strip())
    except ValueError:
        return False
    for value in networks or []:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def _http_security_is_trusted(client_ip, settings=None):
    settings = settings or _load_http_security_settings()
    return _http_security_network_contains(client_ip, settings.get("trusted_networks"))


def _http_security_is_denied(client_ip, settings=None):
    settings = settings or _load_http_security_settings()
    return _http_security_network_contains(client_ip, settings.get("deny_networks"))


def _http_security_temp_allows_locked(state, now=None):
    now = int(now or time.time())
    rows = state.get("temporary_allow") if isinstance(state, dict) else []
    if not isinstance(rows, list):
        rows = []
    active = []
    changed = False
    for row in rows:
        if not isinstance(row, dict):
            changed = True
            continue
        network = str(row.get("network") or "").strip()
        expires_at = int(row.get("expires_at") or 0)
        if not network or expires_at <= now:
            changed = True
            continue
        active.append({"network": network, "expires_at": expires_at})
    if changed:
        state["temporary_allow"] = active
    return active


def _http_security_is_temporarily_allowed(client_ip, state=None, now=None):
    now = int(now or time.time())
    if state is None:
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
    rows = _http_security_temp_allows_locked(state if isinstance(state, dict) else {}, now)
    return _http_security_network_contains(client_ip, [row.get("network") for row in rows])


def _suspicious_4xx_ignored_path(path):
    normalized = str(path or "").strip().lower()
    if normalized.startswith("/static/"):
        return True
    return normalized in {
        "/favicon.ico", "/robots.txt", "/api/healthz", "/api/telegram/heartbeat"
    }


def _http_security_sensitive_path(path):
    return bool(_HTTP_SECURITY_SENSITIVE_RE.search(str(path or "")))


def _http_security_classify(path, status_code=None):
    p = str(path or "").lower()
    if int(status_code or 0) == 429:
        return "rate_limit"
    if re.search(r"(?:^|/)\.env(?:[./~_-]|$)", p):
        return "environment_scan"
    if re.search(r"(?:^|/)\.(?:git|svn|hg)(?:/|$)", p):
        return "repository_scan"
    if re.search(r"(?:wp-admin|wp-login\.php|phpmyadmin)", p):
        return "admin_scanner"
    if re.search(r"(?:credentials?|secrets?|config|settings?)", p):
        return "credential_config_scan"
    if re.search(r"\.(?:bak|old|orig|save|swp|sql|sqlite|db)(?:$|[?#])", p):
        return "backup_database_scan"
    return "generic_4xx"


def _http_security_scope_applies(path, scope):
    if scope != "auth_admin":
        return True
    p = str(path or "").lower()
    prefixes = (
        "/login", "/logout", "/register", "/settings", "/users", "/nodes",
        "/logs", "/backup", "/api/", "/admin",
    )
    return p.startswith(prefixes)


def _http_security_add_history_locked(state, *, event_type, ip="", category="", action="", reason="", path="", status=0, details=None, now=None):
    now = int(now or time.time())
    history = state.get("history")
    if not isinstance(history, list):
        history = []
    row = {
        "ts": now,
        "type": str(event_type or "event")[:48],
        "ip": _http_security_normalize_ip(ip) if ip else "",
        "category": str(category or "")[:64],
        "action": str(action or "")[:64],
        "reason": str(reason or "")[:320],
        "path": str(path or "")[:300],
        "status": int(status or 0),
        "details": details if isinstance(details, dict) else {},
    }
    history.append(row)
    state["history"] = history[-_HTTP_SECURITY_HISTORY_LIMIT:]
    return row


def _http_security_stat_add_locked(state, now, ip, **counts):
    buckets = state.get("stats_hours")
    if not isinstance(buckets, dict):
        buckets = {}
    hour = str((int(now) // 3600) * 3600)
    bucket = buckets.get(hour)
    if not isinstance(bucket, dict):
        bucket = {"ips": []}
    for key, value in counts.items():
        bucket[key] = int(bucket.get(key) or 0) + int(value or 0)
    normalized_ip = _http_security_normalize_ip(ip)
    ips = bucket.get("ips")
    if not isinstance(ips, list):
        ips = []
    if normalized_ip != "unknown" and normalized_ip not in ips and len(ips) < 1000:
        ips.append(normalized_ip)
    bucket["ips"] = ips
    buckets[hour] = bucket
    cutoff = int(now) - (72 * 3600)
    for key in list(buckets.keys()):
        try:
            if int(key) < cutoff:
                buckets.pop(key, None)
        except Exception:
            buckets.pop(key, None)
    state["stats_hours"] = buckets


def _http_security_stats_24h(state=None, now=None):
    now = int(now or time.time())
    if state is None:
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
    buckets = state.get("stats_hours") if isinstance(state, dict) else {}
    if not isinstance(buckets, dict):
        buckets = {}
    totals = {
        "rejected": 0,
        "sensitive": 0,
        "blocks": 0,
        "monitor_triggers": 0,
        "releases": 0,
        "login_failures": 0,
        "rate_limited": 0,
        "unique_ips": 0,
    }
    ips = set()
    cutoff = now - 86400
    for key, bucket in buckets.items():
        try:
            if int(key) < cutoff or not isinstance(bucket, dict):
                continue
        except Exception:
            continue
        for name in ("rejected", "sensitive", "blocks", "monitor_triggers", "releases", "login_failures", "rate_limited"):
            totals[name] += int(bucket.get(name) or 0)
        for value in bucket.get("ips") or []:
            if _http_security_normalize_ip(value) != "unknown":
                ips.add(str(value))
    totals["unique_ips"] = len(ips)
    return totals


def _http_security_geo(ip, settings=None):
    settings = settings or _load_http_security_settings()
    if not settings.get("enrich_ip"):
        return {}
    ip = _http_security_normalize_ip(ip)
    if ip == "unknown":
        return {}
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return {}
    except Exception:
        return {}

    now = time.time()
    with _HTTP_SECURITY_GEO_CACHE_LOCK:
        cached = _HTTP_SECURITY_GEO_CACHE.get(ip)
        if isinstance(cached, dict) and now - float(cached.get("_ts") or 0) < 86400:
            return {k: v for k, v in cached.items() if k != "_ts"}

    result = {}
    try:
        response = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        if response.ok:
            payload = response.json() or {}
            if payload.get("success", True):
                connection = payload.get("connection") or {}
                result = {
                    "country": str(payload.get("country") or "")[:80],
                    "country_code": str(payload.get("country_code") or "")[:8],
                    "asn": str(connection.get("asn") or "")[:40],
                    "provider": str(connection.get("isp") or connection.get("org") or "")[:120],
                }
    except Exception:
        result = {}

    with _HTTP_SECURITY_GEO_CACHE_LOCK:
        _HTTP_SECURITY_GEO_CACHE[ip] = {"_ts": now, **result}
        if len(_HTTP_SECURITY_GEO_CACHE) > 500:
            oldest = sorted(_HTTP_SECURITY_GEO_CACHE.items(), key=lambda item: float((item[1] or {}).get("_ts") or 0))[:100]
            for key, _ in oldest:
                _HTTP_SECURITY_GEO_CACHE.pop(key, None)
    return result


def _http_security_nft_install_command():
    if shutil.which("apt-get"):
        return "sudo apt-get update && sudo apt-get install -y nftables"
    if shutil.which("dnf"):
        return "sudo dnf install -y nftables"
    if shutil.which("yum"):
        return "sudo yum install -y nftables"
    if shutil.which("pacman"):
        return "sudo pacman -S --needed nftables"
    return "Install the nftables package with your operating system package manager."


def _http_security_nft_status(settings=None):
    nft = shutil.which("nft")
    configured = bool((settings or {}).get("firewall_enabled")) if isinstance(settings, dict) else None

    base = {
        "backend": "nftables",
        "available": bool(nft),
        "usable": False,
        "privileged": False,
        "configured": configured,
        "effective": False,
        "table": _HTTP_SECURITY_NFT_TABLE,
        "reason": "not_installed" if not nft else "checking",
        "detail": "",
        "install_command": _http_security_nft_install_command(),
        "check_command": "sudo nft list ruleset",
        "automatic_install": False,
    }

    if not nft:
        base["detail"] = (
            "The nft executable was not found. "
            "Application-level blocking is still active."
        )
        return base

    try:
        proc = subprocess.run(
            [nft, "list", "ruleset"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception as exc:
        base["reason"] = "check_failed"
        base["detail"] = str(exc)[:300]
        return base

    if proc.returncode == 0:
        base["usable"] = True
        base["privileged"] = True
        base["reason"] = "ready"
        base["detail"] = (
            "WG Panel can read/manage nftables through "
            "the current service permissions."
        )
        base["effective"] = (
            bool(configured)
            if configured is not None
            else False
        )
        return base

    detail = (
        proc.stderr
        or "nft list ruleset failed"
    ).strip()[:300]

    low = detail.lower()

    base["reason"] = (
        "permission_denied"
        if (
            "operation not permitted" in low
            or "permission denied" in low
            or "must be root" in low
        )
        else "unusable"
    )
    base["detail"] = detail

    return base



def _http_security_nft_run_script(script):
    status = _http_security_nft_status()
    nft = shutil.which("nft")
    if not status.get("usable") or not nft:
        return False, "nftables is unavailable or the panel process lacks root/CAP_NET_ADMIN"
    try:
        proc = subprocess.run(
            [nft, "-f", "-"],
            input=str(script),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "nft failed").strip()[:300]
        return True, ""
    except Exception as exc:
        return False, str(exc)[:300]


def _http_security_nft_ensure():
    status = _http_security_nft_status()
    nft = shutil.which("nft")
    if not status.get("usable") or not nft:
        return False, "nftables is unavailable or the panel process lacks root/CAP_NET_ADMIN"
    check = subprocess.run(
        [nft, "list", "table", "inet", _HTTP_SECURITY_NFT_TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )
    if check.returncode == 0:
        return True, ""
    script = f"""
table inet {_HTTP_SECURITY_NFT_TABLE} {{
    set {_HTTP_SECURITY_NFT_V4_SET} {{ type ipv4_addr; flags timeout; }}
    set {_HTTP_SECURITY_NFT_V6_SET} {{ type ipv6_addr; flags timeout; }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @{_HTTP_SECURITY_NFT_V4_SET} drop
        ip6 saddr @{_HTTP_SECURITY_NFT_V6_SET} drop
    }}
}}
"""
    return _http_security_nft_run_script(script)


def _http_security_firewall_add(ip, seconds):
    ip = _http_security_normalize_ip(ip)
    if ip == "unknown":
        return False, "invalid IP"
    ok, detail = _http_security_nft_ensure()
    if not ok:
        return False, detail
    version = ipaddress.ip_address(ip).version
    set_name = _HTTP_SECURITY_NFT_V4_SET if version == 4 else _HTTP_SECURITY_NFT_V6_SET
    seconds = _http_security_int(seconds, 900, 60, 2592000)
    _http_security_nft_run_script(
        f"delete element inet {_HTTP_SECURITY_NFT_TABLE} {set_name} {{ {ip} }}\n"
    )
    return _http_security_nft_run_script(
        f"add element inet {_HTTP_SECURITY_NFT_TABLE} {set_name} {{ {ip} timeout {seconds}s }}\n"
    )


def _http_security_firewall_remove(ip):
    ip = _http_security_normalize_ip(ip)
    if ip == "unknown":
        return False, "invalid IP"
    status = _http_security_nft_status()
    if not status.get("usable"):
        return False, "nftables unavailable"
    version = ipaddress.ip_address(ip).version
    set_name = _HTTP_SECURITY_NFT_V4_SET if version == 4 else _HTTP_SECURITY_NFT_V6_SET
    return _http_security_nft_run_script(
        f"delete element inet {_HTTP_SECURITY_NFT_TABLE} {set_name} {{ {ip} }}\n"
    )


def _http_security_apply_block_locked(record, settings, now, reason):
    current_block = int(record.get("blocked_until") or 0)
    if current_block > now:
        return False, 0, int(record.get("offenses") or 1)

    last_offense = int(record.get("last_offense") or 0)
    if last_offense and now - last_offense >= _HTTP_SECURITY_OFFENSE_RESET_SEC:
        record["offenses"] = 0

    offenses = max(0, int(record.get("offenses") or 0)) + 1
    record["offenses"] = offenses
    record["last_offense"] = now
    multiplier = (2 ** max(0, offenses - 1)) if settings.get("escalate") else 1
    block_seconds = min(settings["max_block_seconds"], settings["block_seconds"] * multiplier)
    record["blocked_until"] = now + block_seconds
    record["block_started_at"] = now
    record["block_reason"] = reason
    record["block_active"] = True
    return True, block_seconds, offenses


def _http_security_active_blocks(state=None, current_epoch=None, settings=None):
    current_epoch = int(current_epoch or time.time())
    settings = settings or _load_http_security_settings()
    if state is None:
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
    clients = state.get("clients") if isinstance(state, dict) else {}
    if not isinstance(clients, dict):
        clients = {}

    rows = []
    for ip, record in clients.items():
        if not isinstance(record, dict):
            continue
        blocked_until = int(record.get("blocked_until") or 0)
        if blocked_until <= current_epoch:
            continue
        rows.append({
            "ip": ip,
            "reason": str(record.get("block_reason") or "Threshold reached"),
            "category": str(record.get("block_category") or ""),
            "offenses": int(record.get("offenses") or 1),
            "blocked_until": blocked_until,
            "remaining_seconds": max(0, blocked_until - current_epoch),
            "last_seen": int(record.get("last_seen") or 0),
            "firewall": bool(record.get("firewall_active")),
            "geo": _http_security_geo(ip, settings),
        })
    return sorted(rows, key=lambda row: row["blocked_until"], reverse=True)


def _http_security_cleanup_expired(send_notifications=True):
    now = int(time.time())
    released = []
    lock_handle = None
    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        _http_security_temp_allows_locked(state, now)
        clients = state.get("clients")
        if not isinstance(clients, dict):
            clients = {}

        for ip, record in clients.items():
            if not isinstance(record, dict):
                continue
            blocked_until = int(record.get("blocked_until") or 0)
            if blocked_until and blocked_until <= now and bool(record.get("block_active")):
                reason = str(record.get("block_reason") or "Temporary block expired")
                offenses = int(record.get("offenses") or 1)
                record["block_active"] = False
                record["blocked_until"] = 0
                record["block_reason"] = ""
                record["firewall_active"] = False
                _http_security_stat_add_locked(state, now, ip, releases=1)
                _http_security_add_history_locked(
                    state,
                    event_type="auto_release",
                    ip=ip,
                    category="release",
                    action="auto_release",
                    reason=reason,
                    details={"offenses": offenses},
                    now=now,
                )
                released.append((ip, reason, offenses))
        state["clients"] = clients
        state["updated_at"] = now
        _json_save(_HTTP_4XX_STATE_FILE, state)
    except Exception:
        app.logger.debug("HTTP security expiry cleanup failed", exc_info=True)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_handle.close()
            except Exception:
                pass

    if send_notifications:
        for ip, reason, offenses in released:
            _send_telegram_event(
                "security_auto_release",
                "◇ HTTP security block expired",
                status="Automatically released",
                details=[
                    ("Client IP", ip),
                    ("Previous reason", reason),
                    ("Offense level", offenses),
                ],
                dedupe_key=f"security-auto-release:{ip}:{now}",
                dedupe_seconds=0,
            )
    return released


def _http_security_cleanup_loop():
    while True:
        try:
            with app.app_context():
                _http_security_cleanup_expired(send_notifications=True)
        except Exception:
            pass
        time.sleep(30)


def _start_http_security_cleanup():
    global _HTTP_SECURITY_CLEANUP_STARTED
    if _HTTP_SECURITY_CLEANUP_STARTED:
        return
    _HTTP_SECURITY_CLEANUP_STARTED = True
    threading.Thread(
        target=_http_security_cleanup_loop,
        name="http-security-cleanup",
        daemon=True,
    ).start()


@app.before_request
def _http_security_enforce_temporary_block():
    settings = _load_http_security_settings()
    if not settings.get("enabled"):
        return None

    client_ip = _http_security_client_ip(settings)
    if client_ip == "unknown":
        return None

    # A permanent deny is deliberately stronger than all allow/temporary rules.
    if _http_security_is_denied(client_ip, settings):
        g.http_security_blocked = True
        return make_response(jsonify(
            ok=False,
            error="permanently_blocked",
            message="This client is denied by the panel security policy.",
        ), 403)

    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if _http_security_is_trusted(client_ip, settings):
        return None
    if _http_security_is_temporarily_allowed(client_ip, state=state):
        return None
    if settings.get("response_mode") != "block":
        return None
    if not _http_security_scope_applies(request.path, settings.get("block_scope")):
        return None

    clients = state.get("clients") if isinstance(state, dict) else {}
    record = clients.get(client_ip) if isinstance(clients, dict) else None
    blocked_until = int((record or {}).get("blocked_until") or 0)
    now = int(time.time())

    if blocked_until <= now:
        return None

    g.http_security_blocked = True
    retry_after = max(1, blocked_until - now)
    response = make_response(jsonify(
        ok=False,
        error="temporarily_blocked",
        message="This client is temporarily blocked by panel HTTP security.",
        retry_after=retry_after,
    ), 403)
    response.headers["Retry-After"] = str(retry_after)
    return response


def _record_suspicious_4xx(response):
    if getattr(g, "http_security_blocked", False):
        return

    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code not in _HTTP_4XX_STATUSES:
        return

    request_path = str(request.path or "")
    if _suspicious_4xx_ignored_path(request_path):
        return

    settings = _load_http_security_settings()
    if not settings.get("enabled"):
        return

    client_ip = _http_security_client_ip(settings)
    if client_ip == "unknown":
        return
    if _http_security_is_denied(client_ip, settings):
        return
    state_snapshot = _json_load(_HTTP_4XX_STATE_FILE, {})
    if _http_security_is_trusted(client_ip, settings) or _http_security_is_temporarily_allowed(client_ip, state_snapshot):
        return

    now = int(time.time())
    window_start = now - settings["window_seconds"]
    sensitive_now = _http_security_sensitive_path(request_path)
    category_now = _http_security_classify(request_path, status_code)
    lock_handle = None
    should_alert = False
    did_block = False
    block_seconds = 0
    offenses = 0
    reason = ""
    trigger_category = category_now
    request_count = 0
    sensitive_count = 0
    rate_limit_count = 0
    status_counts = {}
    recent_paths = []
    firewall_should_apply = False

    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        clients = state.get("clients")
        if not isinstance(clients, dict):
            clients = {}

        _http_security_temp_allows_locked(state, now)
        _http_security_stat_add_locked(
            state, now, client_ip,
            rejected=1,
            sensitive=(1 if sensitive_now else 0),
            rate_limited=(1 if status_code == 429 else 0),
        )

        stale_after = max(settings["cooldown_seconds"] * 4, settings["max_block_seconds"] * 2, 86400)
        for old_ip, old_record in list(clients.items()):
            if not isinstance(old_record, dict):
                clients.pop(old_ip, None)
                continue
            last_seen = int(old_record.get("last_seen") or 0)
            blocked_until = int(old_record.get("blocked_until") or 0)
            offenses_old = int(old_record.get("offenses") or 0)
            if blocked_until <= now and offenses_old <= 0 and now - last_seen > stale_after:
                clients.pop(old_ip, None)

        record = clients.get(client_ip)
        if not isinstance(record, dict):
            record = {"events": [], "login_events": [], "last_alert": 0, "last_seen": 0, "offenses": 0}

        events = record.get("events")
        if not isinstance(events, list):
            events = []
        events = [event for event in events if isinstance(event, dict) and int(event.get("ts") or 0) >= window_start]
        events.append({
            "ts": now,
            "status": status_code,
            "path": request_path[:240],
            "method": str(request.method or "")[:16],
            "sensitive": bool(sensitive_now),
            "category": category_now,
        })
        events = events[-300:]
        record["events"] = events
        record["last_seen"] = now

        request_count = len(events)
        sensitive_count = sum(1 for event in events if bool(event.get("sensitive")))
        rate_limit_count = sum(1 for event in events if int(event.get("status") or 0) == 429)
        for event in events:
            key = str(event.get("status") or "unknown")
            status_counts[key] = status_counts.get(key, 0) + 1
        for event in reversed(events):
            value = str(event.get("path") or "").strip()
            if value and value not in recent_paths:
                recent_paths.append(value)
            if len(recent_paths) >= 5:
                break

        triggered_sensitive = sensitive_count >= settings["sensitive_threshold"]
        triggered_rate = rate_limit_count >= settings["rate_limit_threshold"]
        triggered_generic = request_count >= settings["threshold"]
        triggered = triggered_sensitive or triggered_rate or triggered_generic
        if triggered:
            if triggered_sensitive:
                trigger_category = category_now if sensitive_now else "sensitive_scan"
                reason = f"Sensitive-path threshold reached ({sensitive_count}/{settings['sensitive_threshold']})"
            elif triggered_rate:
                trigger_category = "rate_limit"
                reason = f"429 threshold reached ({rate_limit_count}/{settings['rate_limit_threshold']})"
            else:
                trigger_category = "generic_4xx"
                reason = f"4xx threshold reached ({request_count}/{settings['threshold']})"

            last_alert = int(record.get("last_alert") or 0)
            if now - last_alert >= settings["cooldown_seconds"]:
                should_alert = True
                record["last_alert"] = now

            if settings.get("response_mode") == "block":
                did_block, block_seconds, offenses = _http_security_apply_block_locked(record, settings, now, reason)
                if did_block:
                    record["block_category"] = trigger_category
                    should_alert = True
                    record["last_alert"] = now
                    _http_security_stat_add_locked(state, now, client_ip, blocks=1)
                    _http_security_add_history_locked(
                        state,
                        event_type="block",
                        ip=client_ip,
                        category=trigger_category,
                        action="temporary_block",
                        reason=reason,
                        path=request_path,
                        status=status_code,
                        details={"duration_seconds": block_seconds, "offenses": offenses},
                        now=now,
                    )
                    firewall_should_apply = bool(
                        settings.get("firewall_enabled")
                        and offenses >= settings.get("firewall_after_offenses", 3)
                    )
            elif should_alert:
                _http_security_stat_add_locked(state, now, client_ip, monitor_triggers=1)
                _http_security_add_history_locked(
                    state,
                    event_type="monitor_trigger",
                    ip=client_ip,
                    category=trigger_category,
                    action="monitor",
                    reason=reason,
                    path=request_path,
                    status=status_code,
                    details={"requests": request_count, "sensitive": sensitive_count, "rate_limited": rate_limit_count},
                    now=now,
                )

        clients[client_ip] = record
        state["clients"] = clients
        state["updated_at"] = now
        _json_save(_HTTP_4XX_STATE_FILE, state)

    except Exception:
        app.logger.debug("HTTP security tracker failed", exc_info=True)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_handle.close()
            except Exception:
                pass

    firewall_detail = ""
    if did_block and firewall_should_apply:
        fw_ok, firewall_detail = _http_security_firewall_add(client_ip, block_seconds)
        if fw_ok:
            lock_handle = None
            try:
                lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                state = _json_load(_HTTP_4XX_STATE_FILE, {})
                clients = state.get("clients") if isinstance(state, dict) else {}
                if isinstance(clients, dict) and isinstance(clients.get(client_ip), dict):
                    clients[client_ip]["firewall_active"] = True
                    state["clients"] = clients
                    _json_save(_HTTP_4XX_STATE_FILE, state)
            finally:
                if lock_handle:
                    try:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                    lock_handle.close()
        else:
            app.logger.warning("HTTP security nftables escalation failed for %s: %s", client_ip, firewall_detail)

    if not should_alert:
        return

    event_key = "security_block" if did_block else "suspicious_4xx"
    details = [
        ("Client IP", client_ip),
        ("Category", trigger_category.replace("_", " ").title()),
        ("Requests", request_count),
        ("Sensitive requests", sensitive_count),
        ("429 responses", rate_limit_count),
        ("Window", _tg_human_duration(settings["window_seconds"])),
        ("Statuses", ", ".join(f"{k}×{v}" for k, v in sorted(status_counts.items()))),
        ("Reason", reason or "Threshold reached"),
        ("Action", (f"Blocked for {_tg_human_duration(block_seconds)}" if did_block else "Monitor only")),
        ("Recent paths", " | ".join(recent_paths)[:700]),
        ("Last method", request.method),
        ("User agent", str(request.headers.get("User-Agent") or "")[:300]),
    ]
    if did_block and settings.get("firewall_enabled"):
        details.append(("Host firewall", "Applied" if not firewall_detail else f"Not applied · {firewall_detail}"))
    geo = _http_security_geo(client_ip, settings)
    if geo:
        details.append(("Network", " · ".join(filter(None, [geo.get("country_code"), geo.get("asn"), geo.get("provider")]))))

    _send_telegram_event(
        event_key,
        "◆ Suspicious HTTP activity detected",
        status=("Temporarily blocked" if did_block else "Threshold reached"),
        details=details,
        dedupe_key=f"http-security:{event_key}:{client_ip}",
        dedupe_seconds=(0 if did_block else settings["cooldown_seconds"]),
    )


def _http_security_record_login_failure(username="", failure_type="credentials"):
    settings = _load_http_security_settings()
    if not settings.get("enabled"):
        return
    client_ip = _http_security_client_ip(settings)
    if client_ip == "unknown" or _http_security_is_denied(client_ip, settings):
        return
    state_snapshot = _json_load(_HTTP_4XX_STATE_FILE, {})
    if _http_security_is_trusted(client_ip, settings) or _http_security_is_temporarily_allowed(client_ip, state_snapshot):
        return

    now = int(time.time())
    window_start = now - settings["login_window_seconds"]
    lock_handle = None
    should_alert = False
    did_block = False
    block_seconds = 0
    offenses = 0
    count = 0
    reason = ""
    firewall_should_apply = False

    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        clients = state.get("clients")
        if not isinstance(clients, dict):
            clients = {}
        record = clients.get(client_ip)
        if not isinstance(record, dict):
            record = {"events": [], "login_events": [], "last_alert": 0, "last_seen": 0, "offenses": 0}

        login_events = record.get("login_events")
        if not isinstance(login_events, list):
            login_events = []
        login_events = [event for event in login_events if isinstance(event, dict) and int(event.get("ts") or 0) >= window_start]
        login_events.append({
            "ts": now,
            "type": str(failure_type or "credentials")[:32],
            "username": str(username or "")[:120],
        })
        login_events = login_events[-200:]
        record["login_events"] = login_events
        record["last_seen"] = now
        count = len(login_events)
        _http_security_stat_add_locked(state, now, client_ip, login_failures=1)

        if count >= settings["login_threshold"]:
            reason = f"Login-failure threshold reached ({count}/{settings['login_threshold']})"
            last_alert = int(record.get("last_login_alert") or 0)
            if now - last_alert >= settings["cooldown_seconds"]:
                should_alert = True
                record["last_login_alert"] = now

            if settings.get("response_mode") == "block":
                did_block, block_seconds, offenses = _http_security_apply_block_locked(record, settings, now, reason)
                if did_block:
                    record["block_category"] = "auth_bruteforce"
                    should_alert = True
                    record["last_login_alert"] = now
                    _http_security_stat_add_locked(state, now, client_ip, blocks=1)
                    _http_security_add_history_locked(
                        state,
                        event_type="block",
                        ip=client_ip,
                        category="auth_bruteforce",
                        action="temporary_block",
                        reason=reason,
                        details={"duration_seconds": block_seconds, "offenses": offenses, "username": str(username or "")[:120]},
                        now=now,
                    )
                    firewall_should_apply = bool(
                        settings.get("firewall_enabled")
                        and offenses >= settings.get("firewall_after_offenses", 3)
                    )
            elif should_alert:
                _http_security_stat_add_locked(state, now, client_ip, monitor_triggers=1)
                _http_security_add_history_locked(
                    state,
                    event_type="login_trigger",
                    ip=client_ip,
                    category="auth_bruteforce",
                    action="monitor",
                    reason=reason,
                    details={"username": str(username or "")[:120], "count": count},
                    now=now,
                )

        clients[client_ip] = record
        state["clients"] = clients
        state["updated_at"] = now
        _json_save(_HTTP_4XX_STATE_FILE, state)
    except Exception:
        app.logger.debug("HTTP security login tracker failed", exc_info=True)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()

    firewall_detail = ""
    if did_block and firewall_should_apply:
        fw_ok, firewall_detail = _http_security_firewall_add(client_ip, block_seconds)
        if not fw_ok:
            app.logger.warning("HTTP security nftables escalation failed for login offender %s: %s", client_ip, firewall_detail)

    if should_alert:
        _send_telegram_event(
            "security_block" if did_block else "suspicious_4xx",
            "◆ Repeated authentication failures",
            status=("Temporarily blocked" if did_block else "Threshold reached"),
            details=[
                ("Client IP", client_ip),
                ("Account", username or "unknown"),
                ("Failures", count),
                ("Window", _tg_human_duration(settings["login_window_seconds"])),
                ("Reason", reason),
                ("Action", f"Blocked for {_tg_human_duration(block_seconds)}" if did_block else "Monitor only"),
                ("Host firewall", "Requested" if did_block and firewall_should_apply else "Application only"),
            ],
            dedupe_key=f"security-login-threshold:{client_ip}",
            dedupe_seconds=(0 if did_block else settings["cooldown_seconds"]),
        )


@app.after_request
def _suspicious_4xx_after_request(response):
    try:
        _record_suspicious_4xx(response)
    except Exception:
        app.logger.debug("Could not inspect 4xx response", exc_info=True)
    return response

@app.get('/api/security/http-protection/capabilities')
@login_required
def http_security_capabilities_get():
    settings = _load_http_security_settings()

    return jsonify(
        ok=True,
        firewall=_http_security_nft_status(settings),
        geo={
            "enabled": bool(settings.get("enrich_ip")),
            "provider": "ipwho.is",
            "external_lookup": True,
            "display_only": True,
            "cache_seconds": 86400,
        },
    )



@app.get('/api/security/http-protection')
@require_api_key_or_login
def http_security_settings_get():
    _http_security_cleanup_expired(send_notifications=True)
    settings = _load_http_security_settings()
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    temporary_allow = _http_security_temp_allows_locked(state if isinstance(state, dict) else {})
    return jsonify(
        ok=True,
        settings=settings,
        active_blocks=_http_security_active_blocks(state, settings=settings),
        temporary_allow=temporary_allow,
        stats_24h=_http_security_stats_24h(state),
        firewall=_http_security_nft_status(settings),
    )


@app.post('/api/security/http-protection')
@require_api_key_or_login
def http_security_settings_post():
    payload = request.get_json(silent=True) or {}
    allowed = {
        "enabled", "response_mode", "ip_source", "block_scope", "threshold", "window_seconds",
        "sensitive_threshold", "rate_limit_threshold", "login_threshold", "login_window_seconds",
        "cooldown_seconds", "block_seconds", "max_block_seconds", "escalate", "enrich_ip",
        "firewall_enabled", "firewall_after_offenses", "trusted_networks", "deny_networks",
    }
    partial = {key: payload[key] for key in allowed if key in payload}

    if "response_mode" in partial and str(partial["response_mode"]).lower() not in {"monitor", "block"}:
        return jsonify(ok=False, error="invalid_response_mode"), 400
    if "ip_source" in partial and str(partial["ip_source"]).lower() not in {"direct", "effective"}:
        return jsonify(ok=False, error="invalid_ip_source"), 400
    if "block_scope" in partial and str(partial["block_scope"]).lower() not in {"all", "auth_admin"}:
        return jsonify(ok=False, error="invalid_block_scope"), 400

    for key in ("trusted_networks", "deny_networks"):
        if key not in partial:
            continue
        raw_values = partial[key]
        if isinstance(raw_values, str):
            raw_values = re.split(r"[\r\n,]+", raw_values)
        if not isinstance(raw_values, list):
            return jsonify(ok=False, error=f"invalid_{key}"), 400
        checked = []
        for item in raw_values:
            value = str(item or "").strip()
            if not value:
                continue
            try:
                if "/" not in value:
                    ip = ipaddress.ip_address(value)
                    value = f"{ip}/{32 if ip.version == 4 else 128}"
                else:
                    value = str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                return jsonify(ok=False, error="invalid_network", field=key, value=value), 400
            if value not in checked:
                checked.append(value)
        partial[key] = checked

    proposed = _load_http_security_settings()
    proposed.update(partial)
    proposed["trusted_networks"] = _http_security_normalize_networks(proposed.get("trusted_networks"))
    proposed["deny_networks"] = _http_security_normalize_networks(proposed.get("deny_networks"))

    current_ip = _http_security_client_ip(proposed)
    if current_ip != "unknown" and _http_security_network_contains(current_ip, proposed.get("deny_networks")):
        return jsonify(
            ok=False,
            error="would_block_current_admin",
            message="The permanent deny list contains your current client IP. Remove it before saving.",
            ip=current_ip,
        ), 409

    if bool(proposed.get("firewall_enabled")):
        firewall_status = _http_security_nft_status(proposed)

        if not firewall_status.get("usable"):
            return jsonify(
                ok=False,
                error="nftables_unavailable",
                message=(
                    "Host-firewall escalation cannot be enabled because nftables "
                    "is unavailable to the WG Panel service. Application-level "
                    "blocking is still active."
                ),
                firewall=firewall_status,
            ), 409

    _json_save(_HTTP_SECURITY_SETTINGS_FILE, proposed)
    settings = _load_http_security_settings()

    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    return jsonify(
        ok=True,
        settings=settings,
        active_blocks=_http_security_active_blocks(state, settings=settings),
        temporary_allow=_http_security_temp_allows_locked(state if isinstance(state, dict) else {}),
        stats_24h=_http_security_stats_24h(state),
        firewall=_http_security_nft_status(settings),
    )


@app.post('/api/security/http-protection/unban')
@require_api_key_or_login
def http_security_unban():
    payload = request.get_json(silent=True) or {}
    client_ip = _http_security_normalize_ip(payload.get("ip"))
    if client_ip == "unknown":
        return jsonify(ok=False, error="invalid_ip"), 400

    now = int(time.time())
    released = False
    reason = ""
    offenses = 0
    lock_handle = None
    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        clients = state.get("clients")
        if not isinstance(clients, dict):
            clients = {}
        record = clients.get(client_ip)
        if isinstance(record, dict):
            released = int(record.get("blocked_until") or 0) > now
            reason = str(record.get("block_reason") or "")
            offenses = int(record.get("offenses") or 0)
            record["blocked_until"] = 0
            record["block_active"] = False
            record["block_reason"] = ""
            record["firewall_active"] = False
            record["events"] = []
            clients[client_ip] = record
        if released:
            _http_security_stat_add_locked(state, now, client_ip, releases=1)
            _http_security_add_history_locked(
                state,
                event_type="manual_release",
                ip=client_ip,
                category="release",
                action="manual_release",
                reason=reason or "Released by administrator",
                details={"offenses": offenses},
                now=now,
            )
        state["clients"] = clients
        state["updated_at"] = now
        _json_save(_HTTP_4XX_STATE_FILE, state)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()

    _http_security_firewall_remove(client_ip)
    if released:
        _send_telegram_event(
            "security_release",
            "◇ HTTP security block released",
            status="Manually released",
            details=[("Client IP", client_ip), ("Previous reason", reason or "Temporary block"), ("Offense level", offenses)],
            dedupe_key=f"security-manual-release:{client_ip}:{now}",
            dedupe_seconds=0,
        )

    return jsonify(ok=True, ip=client_ip, active_blocks=_http_security_active_blocks())


@app.get('/api/security/http-protection/events')
@require_api_key_or_login
def http_security_events_get():
    settings = _load_http_security_settings()
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    history = state.get("history") if isinstance(state, dict) else []
    if not isinstance(history, list):
        history = []

    event_type = str(request.args.get("type") or "").strip().lower()
    category = str(request.args.get("category") or "").strip().lower()
    ip_filter = str(request.args.get("ip") or "").strip()
    limit = _http_security_int(request.args.get("limit"), 150, 1, 500)

    rows = []
    for row in reversed(history):
        if not isinstance(row, dict):
            continue
        if event_type and str(row.get("type") or "").lower() != event_type:
            continue
        if category and str(row.get("category") or "").lower() != category:
            continue
        if ip_filter and ip_filter not in str(row.get("ip") or ""):
            continue
        item = dict(row)
        if settings.get("enrich_ip") and item.get("ip"):
            item["geo"] = _http_security_geo(item.get("ip"), settings)
        rows.append(item)
        if len(rows) >= limit:
            break

    return jsonify(ok=True, events=rows, stats_24h=_http_security_stats_24h(state))


@app.delete('/api/security/http-protection/events')
@login_required
def http_security_events_clear():
    lock_handle = None
    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        state["history"] = []
        state["updated_at"] = int(time.time())
        _json_save(_HTTP_4XX_STATE_FILE, state)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()
    return jsonify(ok=True)


@app.post('/api/security/http-protection/temporary-allow')
@login_required
def http_security_temporary_allow_add():
    payload = request.get_json(silent=True) or {}
    raw = str(payload.get("network") or "").strip()
    duration = _http_security_int(payload.get("duration_seconds"), 3600, 60, _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC)
    normalized = _http_security_normalize_networks([raw])
    if not normalized:
        return jsonify(ok=False, error="invalid_network"), 400
    network = normalized[0]
    now = int(time.time())
    expires_at = now + duration

    lock_handle = None
    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        rows = _http_security_temp_allows_locked(state, now)
        rows = [row for row in rows if str(row.get("network")) != network]
        rows.append({"network": network, "expires_at": expires_at})
        state["temporary_allow"] = rows
        _http_security_add_history_locked(
            state,
            event_type="temporary_allow",
            category="access_list",
            action="allow",
            reason=f"Temporary allow added for {_tg_human_duration(duration)}",
            details={"network": network, "expires_at": expires_at},
            now=now,
        )
        _json_save(_HTTP_4XX_STATE_FILE, state)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()
    return jsonify(ok=True, network=network, expires_at=expires_at, temporary_allow=_http_security_temp_allows_locked(_json_load(_HTTP_4XX_STATE_FILE, {})))


@app.post('/api/security/http-protection/temporary-allow/remove')
@login_required
def http_security_temporary_allow_remove():
    payload = request.get_json(silent=True) or {}
    normalized = _http_security_normalize_networks([payload.get("network")])
    if not normalized:
        return jsonify(ok=False, error="invalid_network"), 400
    network = normalized[0]
    now = int(time.time())
    lock_handle = None
    try:
        lock_handle = open(_HTTP_4XX_LOCK_FILE, "a+")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        rows = _http_security_temp_allows_locked(state, now)
        state["temporary_allow"] = [row for row in rows if str(row.get("network")) != network]
        _http_security_add_history_locked(
            state,
            event_type="temporary_allow_removed",
            category="access_list",
            action="remove_allow",
            reason="Temporary allow removed",
            details={"network": network},
            now=now,
        )
        _json_save(_HTTP_4XX_STATE_FILE, state)
    finally:
        if lock_handle:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()
    return jsonify(ok=True, network=network, temporary_allow=_http_security_temp_allows_locked(_json_load(_HTTP_4XX_STATE_FILE, {})))


_start_http_security_cleanup()

# ==================================================
# Node and WG interface notification monitor
# ==================================================

_NODE_NOTIFY_MONITOR_STARTED = False
_NODE_NOTIFY_MONITOR_THREAD_LOCK = threading.Lock()

_NODE_NOTIFY_MONITOR_STATE_FILE = os.path.join(
    app.instance_path,
    'node_notification_state.json',
)

_NODE_NOTIFY_MONITOR_LOCK_FILE = os.path.join(
    app.instance_path,
    'node_notification_monitor.lock',
)

try:
    _NODE_NOTIFY_INTERVAL_SEC = max(
        15,
        int(
            os.getenv(
                'WG_NODE_NOTIFY_INTERVAL_SEC',
                '30',
            )
        ),
    )
except Exception:
    _NODE_NOTIFY_INTERVAL_SEC = 30


def _load_node_notification_state() -> dict:
    state = _json_load(
        _NODE_NOTIFY_MONITOR_STATE_FILE,
        {},
    )

    return (
        state
        if isinstance(state, dict)
        else {}
    )


def _save_node_notification_state(
    state: dict,
) -> None:
    _json_save(
        _NODE_NOTIFY_MONITOR_STATE_FILE,
        state,
    )


def _local_notification_states() -> dict:
    """
    Return:
        {
            "wg0": {
                "is_up": True,
                "address": "...",
                "listen_port": 51820
            }
        }
    """
    states = {}

    interfaces = (
        InterfaceConfig.query
        .filter(
            InterfaceConfig.node_id.is_(None)
        )
        .order_by(
            InterfaceConfig.id.asc()
        )
        .all()
    )

    for interface in interfaces:
        interface_name = (
            getattr(
                interface,
                'name',
                None,
            )
            or ''
        ).strip()

        if not interface_name:
            continue

        try:
            is_up = (
                subprocess.run(
                    [
                        'wg',
                        'show',
                        interface_name,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=4,
                    check=False,
                ).returncode
                == 0
            )
        except Exception:
            is_up = False

        states[interface_name] = {
            'is_up': bool(is_up),
            'address': (
                getattr(
                    interface,
                    'address',
                    None,
                )
                or ''
            ),
            'listen_port': (
                getattr(
                    interface,
                    'listen_port',
                    None,
                )
            ),
        }

    return states


def _check_local_notifications(
    state: dict,
) -> None:

    local_key = (
        '__local_interfaces__'
    )

    previous_interfaces = (
        state.get(
            local_key
        )
        or {}
    )

    current_interfaces = (
        _local_notification_states()
    )

    next_interfaces = {}

    confirmation_checks = 2

    for interface_name, current in (
        current_interfaces.items()
    ):
        observed_up = bool(
            current.get(
                'is_up'
            )
        )

        previous = (
            previous_interfaces.get(
                interface_name
            )
        )

        if not isinstance(
            previous,
            dict,
        ):
            next_interfaces[
                interface_name
            ] = {
                'is_up': observed_up,
                'pending_state': None,
                'pending_checks': 0,
                'address': (
                    current.get(
                        'address'
                    )
                    or ''
                ),
                'listen_port': (
                    current.get(
                        'listen_port'
                    )
                ),
            }

            continue

        confirmed_up = bool(
            previous.get(
                'is_up'
            )
        )

        pending_state = (
            previous.get(
                'pending_state'
            )
        )

        try:
            pending_checks = int(
                previous.get(
                    'pending_checks'
                )
                or 0
            )
        except Exception:
            pending_checks = 0

        if observed_up == confirmed_up:
            pending_state = None
            pending_checks = 0

        else:
            if (
                pending_state
                == observed_up
            ):
                pending_checks += 1

            else:
                pending_state = (
                    observed_up
                )

                pending_checks = 1

            if (
                pending_checks
                >= confirmation_checks
            ):
                old_up = confirmed_up

                confirmed_up = (
                    observed_up
                )

                pending_state = None
                pending_checks = 0

                if (
                    old_up
                    and not confirmed_up
                ):
                    _send_telegram_event(
                        'iface_down',
                        (
                            'WireGuard interface '
                            'went offline'
                        ),
                        status='Offline',
                        details=[
                            (
                                'Location',
                                'Local panel',
                            ),
                            (
                                'Interface',
                                interface_name,
                            ),
                            (
                                'Address',
                                current.get(
                                    'address'
                                ),
                            ),
                            (
                                'Listen port',
                                current.get(
                                    'listen_port'
                                ),
                            ),
                        ],
                        dedupe_key=(
                            'local-interface-down:'
                            f'{interface_name}'
                        ),
                        dedupe_seconds=300,
                    )

                elif (
                    not old_up
                    and confirmed_up
                ):
                    _send_telegram_event(
                        'iface_up',
                        (
                            'WireGuard interface '
                            'came online'
                        ),
                        status='Online',
                        details=[
                            (
                                'Location',
                                'Local panel',
                            ),
                            (
                                'Interface',
                                interface_name,
                            ),
                            (
                                'Address',
                                current.get(
                                    'address'
                                ),
                            ),
                            (
                                'Listen port',
                                current.get(
                                    'listen_port'
                                ),
                            ),
                        ],
                        dedupe_key=(
                            'local-interface-up:'
                            f'{interface_name}'
                        ),
                        dedupe_seconds=120,
                    )

        next_interfaces[
            interface_name
        ] = {
            'is_up': confirmed_up,
            'pending_state': (
                pending_state
            ),
            'pending_checks': (
                pending_checks
            ),
            'address': (
                current.get(
                    'address'
                )
                or ''
            ),
            'listen_port': (
                current.get(
                    'listen_port'
                )
            ),
        }

    state[
        local_key
    ] = next_interfaces


def _check_node_notifications(
    state: dict,
) -> None:
    current_epoch = int(
        time.time()
    )

    nodes = (
        Node.query
        .order_by(
            Node.id.asc()
        )
        .all()
    )

    for node in nodes:
        state_key = (f'node:{node.id}')

        if not node.enabled:
            state.pop(state_key,None,)
            continue

        previous = (
            state.get(state_key)
            or {}
        )

        previous_online = (
            previous.get('online')
        )

        previous_interfaces = (
            previous.get('interfaces')
            or {}
        )

        failed_checks = int(
            previous.get('failed_checks')
            or 0
        )

        health = {}
        interfaces = []
        online_now = False
        error_text = ''

        if node.enabled:
            try:
                health = (
                    node_get(
                        node,
                        '/api/health',
                        timeout=6,
                    )
                    or {}
                )

                online_now = bool(
                    isinstance(health, dict)
                    and health.get(
                        'ok',
                        True,
                    )
                )

                if online_now:
               # in /api/health. avoid response
                    if isinstance(health,dict,):
                        health_interfaces = (health.get("interfaces"))

                        if isinstance(health_interfaces,list,):
                            interfaces = (health_interfaces)

                    # fallback for older node agents
                    if not interfaces:
                        try:
                            interface_response = (node_get(node,"/api/interfaces?fast=1",timeout=10,)or {})
                            if isinstance(interface_response,dict,):
                                fallback_interfaces = (interface_response.get("interfaces")or [])

                            if isinstance(fallback_interfaces,list,):
                                interfaces = (fallback_interfaces)

                        except Exception as exc:
                            app.logger.debug(
                                "Could not load fallback interface "
                                "state for node %s: %s",
                                node.id,
                                exc,
                            )

            except Exception as exc:
                online_now = False
                error_text = str(exc)

        if online_now:
            failed_checks = 0
            confirmed_online = True
        else:
            failed_checks += 1

            confirmed_online = (
                failed_checks < 2
            )

        first_observation = (
            previous_online is None
        )

        if first_observation:
            previous_online = (
                confirmed_online
            )

        if (
            not first_observation
            and previous_online
            and not confirmed_online
        ):
            _send_telegram_event(
                'node_down',
                '● Node went offline',
                status='Offline',
                details=[
                    ('Node', node.name),
                    (
                        'Address',
                        node.base_url,
                    ),
                    (
                        'Failed checks',
                        failed_checks,
                    ),
                    (
                        'Error',
                        error_text[:240],
                    ),
                ],
                dedupe_key=(
                    f'node-down:{node.id}'
                ),
                dedupe_seconds=300,
            )

        elif (
            not first_observation
            and not previous_online
            and confirmed_online
        ):
            offline_since = int(
                previous.get(
                    'offline_since'
                )
                or current_epoch
            )

            outage_seconds = max(
                0,
                current_epoch
                - offline_since,
            )

            _send_telegram_event(
                'node_up',
                '● Node came online',
                status='Recovered',
                details=[
                    ('Node', node.name),
                    (
                        'Address',
                        node.base_url,
                    ),
                    (
                    'Outage',_tg_human_duration(outage_seconds),),
                    (
                        'Remote host',
                        (
                            health.get('host')
                            if isinstance(
                                health,
                                dict,
                            )
                            else ''
                        ),
                    ),
                    (
                        'Public IP',
                        (
                            health.get(
                                'public_ipv4'
                            )
                            if isinstance(
                                health,
                                dict,
                            )
                            else ''
                        ),
                    ),
                ],
                dedupe_key=(
                    f'node-up:{node.id}'
                ),
                dedupe_seconds=60,
            )

        current_interfaces = {}

        if confirmed_online:
            for interface in interfaces:
                if not isinstance(
                    interface,
                    dict,
                ):
                    continue

                interface_name = str(
                    interface.get('name')
                    or ''
                ).strip()

                if not interface_name:
                    continue

                is_up = bool(
                    interface.get('is_up')
                )

                current_interfaces[
                    interface_name
                ] = {
                    'is_up': is_up,
                    'address': (
                        interface.get('address')
                        or ''
                    ),
                    'listen_port': (
                        interface.get(
                            'listen_port'
                        )
                    ),
                }

                old_interface = (
                    previous_interfaces.get(
                        interface_name
                    )
                )

                if not isinstance(
                    old_interface,
                    dict,
                ):
                    continue

                old_up = bool(
                    old_interface.get(
                        'is_up'
                    )
                )

                if old_up and not is_up:
                    _send_telegram_event(
                        'iface_down',
                        '● WireGuard interface went down',
                        status='Down',
                        details=[
                            ('Node', node.name),
                            (
                                'Interface',
                                interface_name,
                            ),
                            (
                                'Address',
                                interface.get(
                                    'address'
                                ),
                            ),
                            (
                                'Listen port',
                                interface.get(
                                    'listen_port'
                                ),
                            ),
                        ],
                        dedupe_key=(
                            f'node-interface-down:'
                            f'{node.id}:'
                            f'{interface_name}'
                        ),
                        dedupe_seconds=180,
                    )

                elif not old_up and is_up:
                    _send_telegram_event(
                        'iface_up',
                        '● WireGuard interface came up',
                        status='Up',
                        details=[
                            ('Node', node.name),
                            (
                                'Interface',
                                interface_name,
                            ),
                            (
                                'Address',
                                interface.get(
                                    'address'
                                ),
                            ),
                            (
                                'Listen port',
                                interface.get(
                                    'listen_port'
                                ),
                            ),
                        ],
                        dedupe_key=(
                            f'node-interface-up:'
                            f'{node.id}:'
                            f'{interface_name}'
                        ),
                        dedupe_seconds=60,
                    )

        if confirmed_online:
            offline_since = 0
        else:
            offline_since = int(
                previous.get(
                    'offline_since'
                )
                or current_epoch
            )

        state[state_key] = {
            'online': bool(
                confirmed_online
            ),
            'failed_checks': (
                failed_checks
            ),
            'offline_since': (
                offline_since
            ),
            'interfaces': (
                current_interfaces
                if confirmed_online
                else previous_interfaces
            ),
            'checked_at': (
                current_epoch
            ),
        }

def _check_update_notifications(
    state: dict,
) -> None:
    update_state_key = (
        '__update_notifications__'
    )

    previous = (
        state.get(update_state_key)
        or {}
    )

    current = {}

    # --------------------------
    # Local panel update
    # --------------------------
    try:
        panel_status = (
            _read_update_status(
                UPDATE_STATUS_FILE
            )
            or {}
        )
    except Exception:
        panel_status = {}

    panel_state = str(
        panel_status.get('status')
        or ''
    ).strip().lower()

    panel_stage = str(
        panel_status.get('stage')
        or ''
    ).strip().lower()

    panel_identity = (
        panel_status.get('target')
        or panel_status.get('revision')
        or panel_status.get('message')
        or panel_state
    )

    current['panel'] = {
        'status': panel_state,
        'stage': panel_stage,
        'identity': str(
            panel_identity or ''
        ),
    }

    previous_panel = (
        previous.get('panel')
        or {}
    )

    previous_panel_state = str(
        previous_panel.get('status')
        or ''
    ).strip().lower()

    if (
        previous_panel_state
        and previous_panel_state
        != panel_state
    ):
        if panel_state in {
            'success',
            'succeeded',
            'complete',
            'completed',
            'done',
        }:
            _send_telegram_event(
                'update_success',
                '● Panel update completed',
                status='Completed',
                details=[
                    (
                        'Target',
                        panel_status.get(
                            'target'
                        ),
                    ),
                    (
                        'Message',
                        panel_status.get(
                            'message'
                        ),
                    ),
                ],
                dedupe_key=(
                    'panel-update-success:'
                    + str(panel_identity)
                ),
                dedupe_seconds=0,
            )

        elif panel_state in {
            'failed',
            'error',
            'rollback_failed',
        }:
            _send_telegram_event(
                'update_failed',
                '● Panel update or rollback failed',
                status='Failed',
                details=[
                    ('Stage', panel_stage),
                    (
                        'Message',
                        panel_status.get(
                            'message'
                        ),
                    ),
                    (
                        'Error',
                        panel_status.get(
                            'detail'
                        )
                        or panel_status.get(
                            'error'
                        ),
                    ),
                ],
                dedupe_key=(
                    'panel-update-failed:'
                    + str(panel_identity)
                ),
                dedupe_seconds=300,
            )

    # --------------------------
    # Remote node updates
    # --------------------------
    for node in (
        Node.query
        .filter_by(enabled=True)
        .order_by(Node.id.asc())
        .all()
    ):
        node_key = (
            f'node:{node.id}'
        )

        try:
            node_status = (
                node_get(
                    node,
                    '/api/system/update/status',
                    timeout=7,
                )
                or {}
            )
        except Exception:
            continue

        node_state = str(
            node_status.get('status')
            or ''
        ).strip().lower()

        node_stage = str(
            node_status.get('stage')
            or ''
        ).strip().lower()

        node_identity = (
            node_status.get('target')
            or node_status.get('revision')
            or node_status.get('message')
            or node_state
        )

        current[node_key] = {
            'status': node_state,
            'stage': node_stage,
            'identity': str(
                node_identity or ''
            ),
        }

        old_node = (
            previous.get(node_key)
            or {}
        )

        old_node_state = str(
            old_node.get('status')
            or ''
        ).strip().lower()

        if (
            not old_node_state
            or old_node_state
            == node_state
        ):
            continue

        if node_state in {
            'success',
            'succeeded',
            'complete',
            'completed',
            'done',
        }:
            _send_telegram_event(
                'update_success',
                '● Node update completed',
                status='Completed',
                details=[
                    ('Node', node.name),
                    (
                        'Target',
                        node_status.get(
                            'target'
                        ),
                    ),
                    (
                        'Message',
                        node_status.get(
                            'message'
                        ),
                    ),
                ],
                dedupe_key=(
                    f'node-update-success:'
                    f'{node.id}:'
                    f'{node_identity}'
                ),
                dedupe_seconds=0,
            )

        elif node_state in {
            'failed',
            'error',
            'rollback_failed',
        }:
            _send_telegram_event(
                'update_failed',
                '● Node update or rollback failed',
                status='Failed',
                details=[
                    ('Node', node.name),
                    ('Stage', node_stage),
                    (
                        'Message',
                        node_status.get(
                            'message'
                        ),
                    ),
                    (
                        'Error',
                        node_status.get(
                            'detail'
                        )
                        or node_status.get(
                            'error'
                        ),
                    ),
                ],
                dedupe_key=(
                    f'node-update-failed:'
                    f'{node.id}:'
                    f'{node_identity}'
                ),
                dedupe_seconds=300,
            )

    state[update_state_key] = current


def _node_monitor_once() -> None:
    state = (
        _load_node_notification_state()
    )

    _check_local_notifications(
        state
    )

    _check_node_notifications(
        state
    )

    _check_update_notifications(
        state
    )

    _save_node_notification_state(
        state
    )


def _node_monitor_loop() -> None:
    """
    Only one Gunicorn worker may run this monitor.

    The process-level boolean is not sufficient because Gunicorn has
    multiple workers. The file lock prevents duplicate monitors.
    """
    lock_handle = None

    try:
        lock_handle = open(
            _NODE_NOTIFY_MONITOR_LOCK_FILE,
            'a+',
        )

        fcntl.flock(
            lock_handle.fileno(),
            fcntl.LOCK_EX
            | fcntl.LOCK_NB,
        )

    except Exception:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass

        return

    while True:
        try:
            with app.app_context():
                _node_monitor_once()

        except Exception:
            app.logger.exception(
                'Node notification monitor failed'
            )

        time.sleep(
            _NODE_NOTIFY_INTERVAL_SEC
        )


def _node_notify_monitor() -> None:
    global _NODE_NOTIFY_MONITOR_STARTED

    with _NODE_NOTIFY_MONITOR_THREAD_LOCK:
        if _NODE_NOTIFY_MONITOR_STARTED:
            return

        _NODE_NOTIFY_MONITOR_STARTED = True

        monitor_thread = threading.Thread(
            target=(
                _node_monitor_loop
            ),
            name='node-notification-monitor',
            daemon=True,
        )

        monitor_thread.start()


def _save_tg_settings(partial):
    cur = _load_tg_settings()
    if 'bot_token' in partial and partial['bot_token'] is None:
        partial.pop('bot_token')
    cur.update({k:v for k,v in partial.items() if k != 'notify'})
    if 'notify' in partial:
        cur['notify'].update(partial['notify'])
    _json_save(TELEGRAM_SETTINGS_FILE, cur)


def _load_tg_admins():
    a = _json_load(
        TELEGRAM_ADMINS_FILE,
        [],
    )

    out = []

    for x in a:
        created_at = _utc_timestamp_iso(
            x.get('created_at')
        )

        out.append({
            'id': str(
                x.get('id')
                or x.get('tg_id')
                or ''
            ),
            'username': (
                x.get('username')
                or ''
            ).lstrip('@'),
            'note': x.get('note') or '',
            'muted': bool(
                x.get('muted', False)
            ),
            'created_at': created_at,
            'created_at_display': _panel_display_datetime(
                created_at
            ),
        })

    return [
        x
        for x in out
        if x['id']
    ]


def _save_tg_admins(admins):
    rows = []

    for admin in admins or []:
        rows.append({
            'id': str(
                admin.get('id')
                or admin.get('tg_id')
                or ''
            ),
            'username': (
                admin.get('username')
                or ''
            ).lstrip('@'),
            'note': admin.get('note') or '',
            'muted': bool(
                admin.get('muted', False)
            ),
            'created_at': _utc_timestamp_iso(
                admin.get('created_at')
            ),
        })

    _json_save(
        TELEGRAM_ADMINS_FILE,
        [
            row
            for row in rows
            if row['id']
        ],
    )

# -------------------------------------------------
# Telegram security notifications
# -------------------------------------------------

_SECURITY_NOTIFY_LOCK = threading.Lock()
_SECURITY_NOTIFY_LAST = {}


def _security_html_escape(value) -> str:
    import html

    return html.escape(
        str(value or ''),
        quote=True,
    )


def _request_client_ip() -> tuple[str, str]:
    """
    Return:
      1. Effective client IP
      2. Full proxy chain for diagnostics

    Proxy headers are useful only when the panel is behind a trusted
    proxy/CDN. ProxyFix is already enabled near app creation.
    """

    forwarded = (
        request.headers.get(
            'X-Forwarded-For'
        )
        or ''
    ).strip()

    proxy_chain = ', '.join(
        item.strip()
        for item in forwarded.split(',')
        if item.strip()
    )

    candidates = [
        request.headers.get(
            'CF-Connecting-IP'
        ),
        request.headers.get(
            'True-Client-IP'
        ),
        request.headers.get(
            'X-Real-IP'
        ),
        (
            proxy_chain.split(',', 1)[0].strip()
            if proxy_chain
            else None
        ),
        request.remote_addr,
    ]

    client_ip = next(
        (
            str(value).strip()
            for value in candidates
            if str(value or '').strip()
        ),
        'unknown',
    )

    return client_ip, proxy_chain


def _request_device_summary() -> tuple[str, str]:
    """
    Return:
      1. Friendly browser/OS summary
      2. Raw User-Agent
    """

    user_agent = (
        request.headers.get('User-Agent')
        or 'unknown'
    ).strip()

    lower = user_agent.lower()

    if 'edg/' in lower:
        browser = 'Microsoft Edge'

    elif 'opr/' in lower or 'opera' in lower:
        browser = 'Opera'

    elif 'firefox/' in lower:
        browser = 'Firefox'

    elif 'chrome/' in lower or 'crios/' in lower:
        browser = 'Chrome'

    elif 'safari/' in lower:
        browser = 'Safari'

    else:
        browser = 'Unknown browser'

    if 'windows nt' in lower:
        operating_system = 'Windows'

    elif 'android' in lower:
        operating_system = 'Android'

    elif (
        'iphone' in lower
        or 'ipad' in lower
        or 'ios' in lower
    ):
        operating_system = 'iOS/iPadOS'

    elif (
        'mac os x' in lower
        or 'macintosh' in lower
    ):
        operating_system = 'macOS'

    elif 'linux' in lower:
        operating_system = 'Linux'

    else:
        operating_system = 'Unknown OS'

    return (
        f'{browser} · {operating_system}',
        user_agent[:500],
    )


def _security_notify_enabled(event_type: str) -> bool:
    settings = _load_tg_settings()

    if not settings.get('enabled'):
        return False

    notify = settings.get('notify') or {}

    if event_type == 'login_success':
        return bool(notify.get('login_success', True))

    if event_type in {'login_failed', 'twofa_failed'}:
        return bool(notify.get('login_fail', True))

    return False



def _send_security_notification(
    event_type: str,
    username: str = '',
    reason: str = '',
) -> None:
    """
    Send panel login / 2FA security notifications

    Supported event types:
        login_success
        login_failed
        twofa_failed
        - Telegram bot token
        - Admin recipients
        - Muted admins
        - HTML escaping
        - notification timestamp
        - Background sending
        - Deduplication

    """

    if not _security_notify_enabled(
        event_type
    ):
        return

    # ----------------------------
    # Request/client information
    # ----------------------------
    client_ip, proxy_chain = (
        _request_client_ip()
    )

    device_summary, raw_user_agent = (
        _request_device_summary()
    )

    username = (
        username
        or 'unknown'
    ).strip()[:120]

    reason = (
        reason
        or ''
    ).strip()[:300]

    client_ip = (
        client_ip
        or 'unknown'
    ).strip()[:128]

    proxy_chain = (
        proxy_chain
        or ''
    ).strip()[:400]

    device_summary = (
        device_summary
        or 'Unknown device'
    ).strip()[:200]

    raw_user_agent = (
        raw_user_agent
        or ''
    ).strip()[:500]

    panel_host = (
        request.host
        or 'unknown'
    ).strip()[:255]

    scheme = (
        'HTTPS'
        if _is_https()
        else 'HTTP'
    )

    if event_type == 'login_success':
        event_key = (
            'login_success'
        )

        title = (
            'Panel login accepted'
        )

        status = (
            'Authenticated'
        )

        dedupe_seconds = 0

    elif event_type == 'twofa_failed':
        event_key = (
            'login_fail'
        )

        title = (
            'Two-factor verification rejected'
        )

        status = (
            'Access denied'
        )

        dedupe_seconds = 10

    elif event_type == 'login_failed':
        event_key = (
            'login_fail'
        )

        title = (
            'Panel login rejected'
        )

        status = (
            'Access denied'
        )

        dedupe_seconds = 10

    else:

        current_app.logger.debug(
            'Unknown security notification event: %s',
            event_type,
        )

        return

    # ---------------------
    # Notification details
    # ---------------------
    details = [
        (
            'Account',
            username,
        ),
        (
            'Client IP',
            client_ip,
        ),
        (
            'Device',
            device_summary,
        ),
        (
            'Panel address',
            (
                f'{panel_host} · {scheme}'
            ),
        ),
    ]

    if reason:
        details.append(
            (
                'Reason',
                reason,
            )
        )

    if (
        proxy_chain
        and proxy_chain != client_ip
    ):
        details.append(
            (
                'Proxy chain',
                proxy_chain,
            )
        )

    if raw_user_agent:
        details.append(
            (
                'User agent',
                raw_user_agent,
            )
        )

    _send_telegram_event(
        event_key,
        title,
        status=status,
        details=details,

        dedupe_key=(
            f'{event_type}:'
            f'{client_ip}:'
            f'{username}:'
            f'{reason}'
        ),

        dedupe_seconds=(
            dedupe_seconds
        ),
    )

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
@require_api_key_or_login
def tg_admins_get():
    return jsonify(
        admins=_load_tg_admins(),
        display_timezone=_panel_timezone_name(),
        server_epoch=now_ts(),
    )

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
        found.update({
            'username': username,
            'note': note,
            'muted': muted,
        })
    else:
        admins.append({
            'id': tg_id,
            'username': username,
            'note': note,
            'muted': muted,
            'created_at': _now_iso(),
        })
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

    for row in out:
        if row.get('ts'):
            row['time_display'] = _panel_display_datetime(
                row['ts'],
                seconds=True,
            )

    return jsonify(
        logs=out,
        display_timezone=_panel_timezone_name(),
        server_epoch=now_ts(),
    )


@app.delete('/api/telegram/logs')
@login_required
def tg_logs_del():
    try:
        open(TELEGRAM_LOG_FILE, 'w').close()
        _last_cleared("tg_app")
    except Exception:
        pass
    return jsonify(ok=True)


# ============================
# Panel + node update center
# ============================

UPDATE_HELPER = Path(BASE_DIR) / "scripts" / "panel_update.py"
UPDATE_STATUS_FILE = Path(app.instance_path) / "update_status.json"
UPDATE_LOCK_FILE = Path(app.instance_path) / "update.lock"


def _read_update_status(path=UPDATE_STATUS_FILE):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {
            "status": "idle",
            "stage": "idle",
            "percent": 0,
            "message": "No update is running.",
            "log": [],
        }


def _update_is_busy(status):
    return str(
        (status or {}).get("status")
        or ""
    ).lower() in {
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
        "rollback_restart",
    }

def _update_lock_active(root) -> bool:
    lock_path = (
        Path(root)
        / "instance"
        / "update.lock"
    )

    if not lock_path.exists():
        return False

    try:
        pid_text = lock_path.read_text(
            encoding="utf-8",
        ).strip()

        pid = int(pid_text)

        if pid <= 1:
            raise ValueError(
                "Invalid updater PID."
            )

        os.kill(pid, 0)
        return True

    except ProcessLookupError:
        try:
            lock_path.unlink(
                missing_ok=True,
            )
        except Exception:
            pass

        return False

    except PermissionError:
        return True

    except Exception:
        try:
            lock_age = (
                time.time()
                - lock_path.stat().st_mtime
            )
        except Exception:
            lock_age = 999999

        if lock_age > 300:
            try:
                lock_path.unlink(
                    missing_ok=True,
                )
            except Exception:
                pass

            return False

        return True


def _write_update_status(
    path,
    payload,
):
    target = Path(path)

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = target.with_suffix(
        target.suffix + ".tmp"
    )

    temporary.write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    os.replace(
        temporary,
        target,
    )


def _norm_update_status(
    root,
    status_file,
):
    status = _read_update_status(
        status_file
    )

    if (
        _update_is_busy(status)
        and not _update_lock_active(root)
    ):
        recovered = {
            "status": "idle",
            "stage": "idle",
            "percent": 0,
            "message": (
                "Previous interrupted update state "
                "was cleared."
            ),
            "previous_status": status.get(
                "status"
            ),
            "previous_message": status.get(
                "message"
            ),
            "recovered": True,
            "log": list(
                status.get("log")
                or []
            )[-20:],
        }

        try:
            _write_update_status(
                status_file,
                recovered,
            )
        except Exception:
            pass

        return recovered

    return status


def _launch_update(
    *,
    cmd,
    root,
    scope,
    log_path,
):
    systemd_run = shutil.which(
        "systemd-run"
    )

    if systemd_run:
        unit_name = (
            f"wg-panel-update-{scope}-"
            f"{int(time.time())}-"
            f"{os.getpid()}"
        )

        launch_command = [
            systemd_run,
            "--unit",
            unit_name,
            "--collect",
            "--quiet",
            "--property=Type=exec",
            "--property=KillMode=process",
            "--property=TimeoutStopSec=10min",
            f"--working-directory={root}",
            "--",
            *cmd,
        ]

        result = subprocess.run(
            launch_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Could not create the independent "
                "updater service: "
                + (
                    result.stdout.strip()
                    or (
                        "systemd-run exited with "
                        f"code {result.returncode}"
                    )
                )
            )

        return {
            "launcher": "systemd-run",
            "unit": f"{unit_name}.service",
        }

    stream = open(
        log_path,
        "ab",
        buffering=0,
    )

    process = subprocess.Popen(
        cmd,
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )

    return {
        "launcher": "subprocess",
        "pid": process.pid,
    }

def _queue_safe_update(
    *,
    root,
    service,
    status_file,
    scope,
    target="latest",
):
    root = Path(root).resolve()

    helper = (
        root
        / "scripts"
        / "panel_update.py"
    )

    if not helper.is_file():
        raise RuntimeError(
            f"Update helper is missing: {helper}"
        )

    current = _norm_update_status(
        root,
        status_file,
    )

    if (
        _update_is_busy(current)
        or _update_lock_active(root)
    ):
        raise RuntimeError(
            "An update is already running "
            "for this target."
        )

    cmd = [
        sys.executable,
        str(helper),
        "--root",
        str(root),
        "--repo",
        PANEL_REPO,
        "--service",
        service,
        "--status",
        str(status_file),
        "--scope",
        scope,
        "--target",
        str(target or "latest"),
    ]

    log_path = (
        root
        / "instance"
        / "update_runner.log"
    )

    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    queued = {
        "status": "queued",
        "stage": "queued",
        "percent": 2,
        "message": "Update is starting…",
        "target": str(target or "latest"),
        "launcher": "pending",
        "unit": None,
        "pid": None,
        "log": [],
    }

    _write_update_status(
        status_file,
        queued,
    )

    try:
        launch_info = _launch_update(
            cmd=cmd,
            root=root,
            scope=scope,
            log_path=log_path,
        )

    except Exception as exc:
        failed = dict(queued)

        failed.update({
            "status": "failed",
            "stage": "failed",
            "percent": 100,
            "message": (
                "The updater could not be started."
            ),
            "detail": str(exc),
        })

        _write_update_status(
            status_file,
            failed,
        )

        raise

    latest_status = _read_update_status(
        status_file
    )

    latest_state = str(
        latest_status.get("status")
        or ""
    ).strip().lower()

    if latest_state in {
        "",
        "idle",
        "queued",
    }:
        latest_status.update({
            "status": "queued",
            "stage": "queued",
            "percent": max(
                2,
                int(
                    latest_status.get("percent")
                    or 0
                ),
            ),
            "message": (
                latest_status.get("message")
                or "Update is starting…"
            ),
            "target": str(
                target or "latest"
            ),
            "launcher": launch_info.get(
                "launcher"
            ),
            "unit": launch_info.get(
                "unit"
            ),
            "pid": launch_info.get(
                "pid"
            ),
            "log": list(
                latest_status.get("log")
                or []
            ),
        })

        _write_update_status(
            status_file,
            latest_status,
        )

        queued = latest_status

    else:
        queued = latest_status

    return queued


@app.get("/api/panel/update/status")
@require_api_key_or_login
def api_panel_update_status():
    return jsonify(
        _norm_update_status(
            BASE_DIR,
            UPDATE_STATUS_FILE,
        )
    )


@app.post("/api/panel/update")
@require_api_key_or_login
def api_panel_update_start():
    data = request.get_json(silent=True) or {}
    target = "main"

    try:
        status = _queue_safe_update(
            root=BASE_DIR,
            service="auto",
            status_file=UPDATE_STATUS_FILE,
            scope="panel",
            target=target,
        )
        return jsonify(
            ok=True,
            message="Local panel update queued.",
            status=status,
        ), 202
    except RuntimeError as exc:
        return jsonify(ok=False, error="update_not_started", detail=str(exc)), 409
    except Exception as exc:
        current_app.logger.exception("Could not queue local update")
        return jsonify(ok=False, error="update_queue_failed", detail=str(exc)), 500


@app.get("/api/panel/update/targets")
@require_api_key_or_login
def api_panel_update_targets():
    remote = (
        _github_latest_panel_version()
        or {}
    )

    latest_version = (
        remote.get("version")
        or PANEL_VERSION
    )

    latest_revision = str(
        remote.get("revision")
        or ""
    ).strip()

    rows = []

    for node in Node.query.order_by(
        Node.id.asc()
    ).all():
        row = {
            "id": node.id,
            "name": node.name,
            "base_url": node.base_url,
            "online": False,

            "version": {
                "current": None,
                "latest": latest_version,
                "target": "main",
                "source": "main",

                "latest_revision": (
                    latest_revision
                ),

                "latest_revision_short": (
                    latest_revision[:8]
                ),

                "update_available": False,
            },

            "update": {
                "status": "idle",
            },
        }

        if not node.enabled:
            row["update"] = {
                "status": "disabled",
            }

            rows.append(row)
            continue

        try:
            version = (
                node_get(
                    node,
                    "/api/system/version",
                    timeout=8,
                )
                or {}
            )

            status = (
                node_get(
                    node,
                    "/api/system/update/status",
                    timeout=6,
                )
                or {}
            )

            row["online"] = True

            row["version"] = {
                "current": (
                    str(
                        version.get("current")
                        or ""
                    ).strip()
                    or None
                ),

                "latest": (
                    str(
                        version.get("latest")
                        or latest_version
                        or ""
                    ).strip()
                    or None
                ),

                "target": "main",
                "source": "main",

                "current_revision": str(
                    version.get(
                        "current_revision"
                    )
                    or ""
                ),

                "current_revision_short": str(
                    version.get(
                        "current_revision_short"
                    )
                    or ""
                ),

                "latest_revision": str(
                    version.get(
                        "latest_revision"
                    )
                    or latest_revision
                    or ""
                ),

                "latest_revision_short": str(
                    version.get(
                        "latest_revision_short"
                    )
                    or latest_revision[:8]
                    or ""
                ),

                "revision_tracked": bool(
                    version.get(
                        "revision_tracked"
                    )
                ),

                "update_available": bool(
                    version.get(
                        "update_available"
                    )
                ),
            }

            row["update"] = (
                status
                if isinstance(status, dict)
                else {
                    "status": "idle",
                }
            )

        except Exception as exc:
            row["update"] = {
                "status": "offline",
                "message": str(exc),
            }

        rows.append(row)

    return jsonify(
        ok=True,
        latest=latest_version,
        target="main",
        update_source="main",

        latest_revision=latest_revision,
        latest_revision_short=(
            latest_revision[:8]
        ),

        nodes=rows,
    )

@app.post("/api/nodes/<int:nid>/update")
@require_api_key_or_login
def api_node_update_start(nid):
    node = db.session.get(Node, nid) or abort(404)
    data = request.get_json(silent=True) or {}

    try:
        response = node_post(
           node,
           "/api/system/update",
           {"target": "main"},
           timeout=12,
        )
        return jsonify(response if isinstance(response, dict) else {
            "ok": True,
            "message": str(response),
        }), 202
    except requests.HTTPError as exc:
        body = getattr(getattr(exc, "response", None), "text", "") or ""
        return jsonify(
            ok=False,
            error="node_update_rejected",
            detail=body[:1000] or str(exc),
        ), 502
    except Exception as exc:
        return jsonify(
            ok=False,
            error="node_update_failed",
            detail=str(exc),
        ), 502


@app.get("/api/nodes/<int:nid>/update/status")
@require_api_key_or_login
def api_node_update_status(nid):
    node = db.session.get(Node, nid) or abort(404)
    try:
        data = node_get(node, "/api/system/update/status", timeout=8) or {}
        return jsonify(data if isinstance(data, dict) else {
            "status": "unknown",
            "message": str(data),
        })
    except Exception as exc:
        return jsonify(
            status="offline",
            message=str(exc),
            percent=0,
            log=[],
        ), 200

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

    ts = _panel_filename_stamp()
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

def _env_bundle(z: zipfile.ZipFile):
    """
    Include the panel .env in full backups for migration.

    Important: this contains FERNET_KEY/API_KEY/secret values.
    Keep full backup ZIPs private.
    """
    try:
        env_path = Path(BASE_DIR) / ".env"
        if env_path.is_file():
            z.write(env_path, arcname="env/.env")
    except Exception as e:
        current_app.logger.warning("ENV bundle skipped: %s", e)

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
    import tempfile
    import zipfile
    from pathlib import Path
    from datetime import datetime

    f = request.files.get('file')

    if not f or not (f.filename or "").lower().endswith('.zip'):
        return jsonify(
            ok=False,
            error='no_file',
            message='Please upload a .zip backup file.'
        ), 400

    kind_req = (request.form.get('kind') or 'auto').lower().strip()
    restore_wg = (request.form.get('restore_wg') or '0') == '1'
    server_settings_mode = (request.form.get('server_settings_mode') or 'keep').lower().strip()
    if server_settings_mode not in ('keep', 'saved', 'custom'):
        server_settings_mode = 'keep'

    def _form_int(name, default=None):
        try:
            v = request.form.get(name)
            if v in (None, ''):
                return default
            i = int(v)
            return i if 1 <= i <= 65535 else default
        except Exception:
            return default

    custom_port = _form_int('custom_port')
    custom_http_port = _form_int('custom_http_port')
    custom_https_port = _form_int('custom_https_port')
    custom_bind = (request.form.get('custom_bind') or '').strip()
    custom_domain = (request.form.get('custom_domain') or '').strip()
    custom_scheme = (request.form.get('custom_scheme') or 'http').lower().strip()
    custom_wg_path = (request.form.get('custom_wg_path') or '').strip()

    if custom_scheme not in ('http', 'https'):
        custom_scheme = 'http'

    tmp = tempfile.NamedTemporaryFile(delete=False)

    try:
        f.save(tmp)
        tmp.flush()
        tmp.close()

        try:
            z = zipfile.ZipFile(tmp.name, 'r')
        except Exception:
            return jsonify(
                ok=False,
                error='invalid_zip',
                message='File is not a valid ZIP backup.'
            ), 400

        try:
            names = z.namelist()

            has_db = any(
                n.startswith('db/') and not n.endswith('/')
                for n in names
            )

            has_inst = any(
                n.startswith('instance/') and not n.endswith('/')
                for n in names
            )

            has_wg = any(
                n.startswith('wg/') and n.endswith('.conf')
                for n in names
            )

            has_node_wg = any(
                n.startswith('nodes/') and '/wg/' in n and n.endswith('.conf')
                for n in names
            )

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

            if kind not in ('db', 'settings', 'full'):
                return jsonify(
                    ok=False,
                    error='invalid_restore_kind',
                    message='Restore kind must be auto, db, settings, or full.'
                ), 400

            inst = Path(app.instance_path)
            db_dir = inst / "restore_tmp_db"
            inst_dir = inst
            if server_settings_mode == 'custom' and custom_wg_path:
                wg_dir = Path(custom_wg_path)
            else:
                wg_dir = Path(app.config.get('WG_CONF_PATH') or '/etc/wireguard/')

            restored = {
                "db": False,
                "settings": False,
                "wg": False,
                "node_wg": False,
            }

            warnings = []
            node_restore_results = []

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

                except Exception as e:
                    warnings.append(f"snapshot_failed:{dest}:{e}")

            def _safe_extract_tail(member: str) -> str:
                _, _, tail = member.partition('/')
                tail = tail.strip().lstrip('/')

                parts = Path(tail).parts

                if not tail:
                    raise ValueError('empty member path')

                if any(part in ('', '.', '..') for part in parts):
                    raise ValueError('unsafe member path')

                return tail

            def _extract(member: str, dest_root: Path, kind_name: str):
                if member.endswith('/'):
                    return

                tail = _safe_extract_tail(member)

                dest_root.mkdir(parents=True, exist_ok=True)
                dest = dest_root / tail

                root_resolved = dest_root.resolve()
                dest_resolved = dest.resolve() if dest.exists() else dest.parent.resolve() / dest.name

                if not str(dest_resolved).startswith(str(root_resolved)):
                    raise ValueError(f'unsafe restore path: {member}')

                _backup_existing(dest, kind_name=kind_name, rel_tail=tail)

                dest.parent.mkdir(parents=True, exist_ok=True)

                with z.open(member) as src, open(dest, 'wb') as out:
                    out.write(src.read())

                try:
                    if dest.suffix == '.conf':
                        os.chmod(dest, 0o600)
                except Exception:
                    pass

            # -----------------------------
            # Restore database
            # -----------------------------
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
                        return jsonify(
                            ok=False,
                            error="db_restore_failed",
                            message=str(e)
                        ), 500
                else:
                    warnings.append("db_requested_but_no_db_file_found")

            # -----------------------------
            # Restore instance settings/json
            # -----------------------------
            if kind in ("settings", "full"):
                if has_inst:

                    server_local_files = {
                    "runtime.json",
                    "panel_settings.json",
                    "backup_schedule.json",
                    "backup_settings.json",
                    "backup_last.json",
                    "auto_backup.json",
                }

                    skipped_server_files = []
                    restored_server_files = []

                    for n in names:
                        if not n.startswith("instance/") or n.endswith("/"):
                            continue

                        fname = os.path.basename(n)

                        if fname in server_local_files:
                            if server_settings_mode == "saved":
                                _extract(n, inst_dir, kind_name="instance")
                                restored_server_files.append(fname)
                            else:
                                skipped_server_files.append(fname)
                            continue

                        _extract(n, inst_dir, kind_name="instance")

                    restored["settings"] = True

                    if skipped_server_files:
                        warnings.append(
                        "server_local_settings_protected: " +
                        ", ".join(sorted(set(skipped_server_files)))
                    )

                    if restored_server_files:
                        warnings.append(
                        "server_local_settings_restored: " +
                        ", ".join(sorted(set(restored_server_files)))
                    )

                    if server_settings_mode == "custom":
                        runtime_path = Path(app.instance_path) / "runtime.json"
                        panel_path = Path(app.instance_path) / "panel_settings.json"

                        port = custom_port or custom_http_port or custom_https_port
                        bind_host = custom_bind or "0.0.0.0"

                        if ":" in bind_host:
                            host_part, _, port_part = bind_host.rpartition(":")
                            bind_host = host_part or "0.0.0.0"
                            try:
                                port = int(port_part)
                            except Exception:
                                pass

                        if not port:
                            port = 443 if custom_scheme == "https" else 8000

                        runtime_payload = {
                        "bind": f"{bind_host}:{int(port)}",
                        "port": int(port),
                        "workers": 0,
                        "threads": 4,
                        "timeout": 60,
                        "graceful_timeout": 30,
                        "loglevel": "info",
                    }

                        panel_payload = {
                        "tls_enabled": custom_scheme == "https",
                        "domain": custom_domain,
                        "force_https_redirect": False,
                        "hsts": False,
                        "http_port": custom_http_port or (int(port) if custom_scheme == "http" else None),
                        "https_port": custom_https_port or (int(port) if custom_scheme == "https" else 443),
                        "tls_cert_path": "",
                        "tls_key_path": "",
                    }

                        runtime_path.write_text(json.dumps(runtime_payload, indent=2), encoding="utf-8")
                        panel_path.write_text(json.dumps(panel_payload, indent=2), encoding="utf-8")

                        warnings.append(
                        "custom_server_settings_written: runtime.json, panel_settings.json"
                        )
                else:
                    warnings.append("settings_requested_but_no_instance_files_found")

            # -----------------------------
            # Restore local WG configs
            # -----------------------------
            if restore_wg and has_wg and kind in ("settings", "full"):
                for n in names:
                    if n.startswith("wg/") and n.endswith(".conf"):
                        _extract(n, wg_dir, kind_name="wg")

                restored["wg"] = True

            elif has_wg and not restore_wg:
                warnings.append("wg_present_but_not_restored")

            # -----------------------------
            # Restore remote node WG configs
            # -----------------------------
            if restore_wg and has_node_wg and kind in ("settings", "full"):
                try:
                    node_restore_results = _restore_node_wg_zip(z, names)
                    restored["node_wg"] = any(
                        bool(x.get("ok"))
                        for x in node_restore_results
                    )

                    if not restored["node_wg"]:
                        warnings.append("node_wg_present_but_no_node_restore_success")

                except Exception as e:
                    warnings.append(f"node_wg_restore_failed:{e}")

            elif has_node_wg and not restore_wg:
                warnings.append("node_wg_present_but_not_restored")

            try:
                _norm_adminlog({
                    "action": "backup_restore",
                    "details": (
                        f"kind={kind}; restore_wg={int(restore_wg)}; "
                        f"db={int(restored['db'])}; settings={int(restored['settings'])}; "
                        f"wg={int(restored['wg'])}; node_wg={int(restored['node_wg'])}"
                    ),
                    "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web",
                })
            except Exception:
                pass

            return jsonify(
                ok=True,
                kind=kind,
                server_settings_mode=server_settings_mode,
                detected={
                    "db": bool(has_db),
                    "settings": bool(has_inst),
                    "wg": bool(has_wg),
                    "node_wg": bool(has_node_wg),
                },
                restored=restored,
                warnings=warnings,
                node_restore_results=node_restore_results,
                message="Restore completed. Restart may be required."
            )

        finally:
            try:
                z.close()
            except Exception:
                pass

    finally:
        try:
            Path(tmp.name).unlink(missing_ok=True)
        except Exception:
            pass

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

    Detects:
      - db/
      - instance/
      - wg/                            local WireGuard configs
      - env/.env                       panel .env
      - nodes/<node_id>/wg/*.conf      remote node WireGuard configs
      - nodes/<node_id>/env/.env       remote node .env files
      - meta/manifest.json
      - meta/node_wg_backup.json
    """
    import tempfile
    import zipfile
    from pathlib import Path

    f = request.files.get('file')

    if not f or not (f.filename or '').lower().endswith('.zip'):
        return jsonify(
            ok=False,
            error='no_file',
            message='Please upload a .zip backup file.'
        ), 400

    tmp = tempfile.NamedTemporaryFile(delete=False)

    try:
        f.save(tmp)
        tmp.flush()
        tmp.close()

        try:
            z = zipfile.ZipFile(tmp.name, 'r')
        except Exception:
            return jsonify(
                ok=False,
                error='invalid_zip',
                message='File is not a valid ZIP backup.'
            ), 400

        try:
            names = z.namelist()

            has_db = any(
                n.startswith('db/') and not n.endswith('/')
                for n in names
            )

            has_inst = any(
                n.startswith('instance/') and not n.endswith('/')
                for n in names
            )

            has_wg = any(
                n.startswith('wg/') and n.endswith('.conf')
                for n in names
            )

            has_node_wg = any(
                n.startswith('nodes/') and '/wg/' in n and n.endswith('.conf')
                for n in names
            )

            has_env = any(
                n == 'env/.env'
                for n in names
            )

            has_node_env = any(
                n.startswith('nodes/') and n.endswith('/env/.env')
                for n in names
            )

            local_wg_files = sorted([
                os.path.basename(n)
                for n in names
                if n.startswith('wg/') and n.endswith('.conf')
            ])

            node_wg_files = []
            node_wg_nodes = {}
            node_env_files = []
            node_env_nodes = {}

            for n in names:
                m = re.match(r'^nodes/(\d+)/wg/([^/]+\.conf)$', n)
                if m:
                    node_id = int(m.group(1))
                    filename = os.path.basename(m.group(2))

                    node_wg_files.append({
                        'node_id': node_id,
                        'file': filename,
                        'path': n,
                    })

                    node_wg_nodes.setdefault(str(node_id), 0)
                    node_wg_nodes[str(node_id)] += 1
                    continue

                m_env = re.match(r'^nodes/(\d+)/env/\.env$', n)
                if m_env:
                    node_id = int(m_env.group(1))

                    node_env_files.append({
                        'node_id': node_id,
                        'file': '.env',
                        'path': n,
                    })

                    node_env_nodes.setdefault(str(node_id), 0)
                    node_env_nodes[str(node_id)] += 1
                    continue

            def _read_text(member):
                try:
                    with z.open(member) as fh:
                        return fh.read().decode('utf-8', 'replace').strip()
                except Exception:
                    return None

            def _read_json(member):
                txt = _read_text(member)
                if not txt:
                    return None
                try:
                    return json.loads(txt)
                except Exception:
                    return None

            created = _read_text('meta/created.txt')
            host = _read_text('meta/host.txt')
            manifest = _read_json('meta/manifest.json')
            node_wg_backup = _read_json('meta/node_wg_backup.json')

            runtime_settings = _read_json('instance/runtime.json') or {}
            panel_settings = _read_json('instance/panel_settings.json') or {}
            app_meta = _read_json('meta/app.json') or {}

            kind = 'unknown'

            if has_db and has_inst:
                kind = 'full'
            elif has_db:
                kind = 'db'
            elif has_inst:
                kind = 'settings'

            contains = {
                'database': bool(has_db),
                'settings': bool(has_inst),
                'local_wireguard_conf': bool(has_wg),
                'remote_node_wireguard_conf': bool(has_node_wg),
                'env_file': bool(has_env),
                'remote_node_env': bool(has_node_env),
                'short_links': any(n == 'instance/short_links.json' for n in names),
                'manifest': bool(manifest),
            }

            counts = {
                'local_wg_files': len(local_wg_files),
                'node_wg_files': len(node_wg_files),
                'node_wg_nodes': len(node_wg_nodes),
                'node_env_files': len(node_env_files),
                'node_env_nodes': len(node_env_nodes),
                'instance_files': len([
                    n for n in names
                    if n.startswith('instance/') and not n.endswith('/')
                ]),
                'db_files': len([
                    n for n in names
                    if n.startswith('db/') and not n.endswith('/')
                ]),
            }

            return jsonify(
                ok=True,
                kind=kind,

                has_db=has_db,
                has_settings=has_inst,
                has_wg=has_wg,
                has_node_wg=has_node_wg,
                has_env=has_env,
                has_node_env=has_node_env,

                contains=contains,
                counts=counts,

                local_wg_files=local_wg_files,
                node_wg_files=node_wg_files,
                node_wg_nodes=node_wg_nodes,
                node_env_files=node_env_files,
                node_env_nodes=node_env_nodes,

                created=created,
                host=host,

                manifest=manifest,
                node_wg_backup=node_wg_backup,

                runtime=runtime_settings,
                panel_settings=panel_settings,
                app_meta=app_meta,
            )

        finally:
            try:
                z.close()
            except Exception:
                pass

    finally:
        try:
            Path(tmp.name).unlink(missing_ok=True)
        except Exception:
            pass

@app.get('/api/backup/node-agent/install-command')
@login_required
@admin_required
def backup_node_agent_install_command():
    """
    restore/migration.

    This does not SSH into the node.
    It gives the admin the official WG_Panel node installer command.
    """
    node_id = request.args.get('node_id', type=int)
    node = db.session.get(Node, node_id) if node_id else None

    api_key = ''
    base_url = ''

    if node:
        try:
            api_key = _read_api_key(node)
        except Exception:
            api_key = ''
        base_url = getattr(node, 'base_url', '') or ''

    command = """sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.sh)"'"""

    return jsonify(
        ok=True,
        node_id=node_id,
        node_name=getattr(node, 'name', None) if node else None,
        base_url=base_url,
        has_api_key=bool(api_key),
        command=command,
        next_command="node",
        notes=[
            "Run the install command on the node server as root.",
            "After installation, open the node menu by running: node",
            "Use the same API key and port as the node record in this panel.",
            "Return to the panel, test the node, then restore node WireGuard configs."
        ],
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


@app.route(
    '/api/backups/file/<path:fname>',
    methods=['GET', 'DELETE'],
)
@require_api_key_or_login
def backups_auto(fname):
    safe_name = os.path.basename(
        str(fname or '')
    )

    if (
        not safe_name
        or not safe_name.lower().endswith('.zip')
    ):
        return jsonify(
            ok=False,
            error='invalid_filename',
            message='Invalid backup filename.',
        ), 400

    backup_root = Path(
        BACKUP_AUTO_DIR
    ).resolve()

    backup_path = (
        backup_root / safe_name
    ).resolve()

    try:
        backup_path.relative_to(
            backup_root
        )
    except ValueError:
        return jsonify(
            ok=False,
            error='invalid_path',
            message='Invalid backup path.',
        ), 400

    if not backup_path.is_file():
        return jsonify(
            ok=False,
            error='not_found',
            message='The saved backup was not found.',
        ), 404

    if request.method == 'DELETE':
        try:
            file_size = backup_path.stat().st_size

            backup_path.unlink()

            current_app.logger.info(
                'Automatic backup deleted: '
                'file=%s size=%s',
                safe_name,
                file_size,
            )

            try:
                _norm_adminlog({
                    'action': 'auto_backup_delete',
                    'details': (
                        f'file={safe_name}; '
                        f'size={file_size}'
                    ),
                    'channel': (
                        'api'
                        if (
                            request.headers.get(
                                'Authorization'
                            )
                            or request.headers.get(
                                'X-API-KEY'
                            )
                        )
                        else 'web'
                    ),
                })
            except Exception:
                pass

            return jsonify(
                ok=True,
                deleted=safe_name,
                size=file_size,
                message='Automatic backup deleted.',
            )

        except PermissionError:
            return jsonify(
                ok=False,
                error='permission_denied',
                message=(
                    'The panel does not have permission '
                    'to delete this backup.'
                ),
            ), 403

        except Exception as exc:
            current_app.logger.exception(
                'Could not delete automatic backup '
                '%s: %s',
                safe_name,
                exc,
            )

            return jsonify(
                ok=False,
                error='delete_failed',
                message=str(exc),
            ), 500

    download = (
        request.args.get('download')
        == '1'
    )

    return send_file(
        str(backup_path),
        mimetype='application/zip',
        as_attachment=download,
        download_name=backup_path.name,
        conditional=True,
    )


@app.get('/api/backups/inspect/<path:fname>')
@require_api_key_or_login
def inspect_saved_auto_backup(fname):
    """
    Inspect a saved automatic backup directly on the server.

    The ZIP is read on the panel server instead of being downloaded
    through the browser first.
    """
    safe_name = os.path.basename(
        str(fname or '')
    )

    if (
        not safe_name
        or not safe_name.lower().endswith('.zip')
    ):
        return jsonify(
            ok=False,
            error='invalid_filename',
            message='Invalid backup filename.',
        ), 400

    backup_root = Path(BACKUP_AUTO_DIR).resolve()
    backup_path = (
        backup_root / safe_name
    ).resolve()

    try:
        backup_path.relative_to(backup_root)
    except ValueError:
        return jsonify(
            ok=False,
            error='invalid_path',
            message='Invalid backup path.',
        ), 400

    if not backup_path.is_file():
        return jsonify(
            ok=False,
            error='not_found',
            message=(
                'The saved backup file was not found.'
            ),
        ), 404

    try:
        with zipfile.ZipFile(
            backup_path,
            'r',
        ) as archive:
            names = archive.namelist()

            def existing_files(prefix):
                return [
                    name
                    for name in names
                    if (
                        name.startswith(prefix)
                        and not name.endswith('/')
                    )
                ]

            def read_text(member):
                if member not in names:
                    return None

                try:
                    return (
                        archive.read(member)
                        .decode(
                            'utf-8',
                            'replace',
                        )
                        .strip()
                    )
                except Exception:
                    return None

            def read_json(member):
                text = read_text(member)

                if not text:
                    return None

                try:
                    return json.loads(text)
                except Exception:
                    return None

            db_files = existing_files('db/')
            instance_files = existing_files(
                'instance/'
            )

            local_wg_files = sorted([
                os.path.basename(name)
                for name in names
                if (
                    name.startswith('wg/')
                    and name.endswith('.conf')
                )
            ])

            node_wg_files = []
            node_wg_nodes = {}

            node_env_files = []
            node_env_nodes = {}

            for member in names:
                match = re.match(
                    r'^nodes/(\d+)/wg/'
                    r'([^/]+\.conf)$',
                    member,
                )

                if match:
                    node_id = int(
                        match.group(1)
                    )

                    filename = os.path.basename(
                        match.group(2)
                    )

                    node_wg_files.append({
                        'node_id': node_id,
                        'file': filename,
                        'path': member,
                    })

                    node_key = str(node_id)

                    node_wg_nodes[node_key] = (
                        node_wg_nodes.get(
                            node_key,
                            0,
                        )
                        + 1
                    )

                    continue

                match = re.match(
                    r'^nodes/(\d+)/env/\.env$',
                    member,
                )

                if match:
                    node_id = int(
                        match.group(1)
                    )

                    node_env_files.append({
                        'node_id': node_id,
                        'file': '.env',
                        'path': member,
                    })

                    node_key = str(node_id)

                    node_env_nodes[node_key] = (
                        node_env_nodes.get(
                            node_key,
                            0,
                        )
                        + 1
                    )

            has_db = bool(db_files)
            has_settings = bool(
                instance_files
            )
            has_wg = bool(
                local_wg_files
            )
            has_node_wg = bool(
                node_wg_files
            )
            has_env = (
                'env/.env'
                in names
            )
            has_node_env = bool(
                node_env_files
            )

            if has_db and has_settings:
                kind = 'full'
            elif has_db:
                kind = 'db'
            elif has_settings:
                kind = 'settings'
            else:
                kind = 'unknown'

            manifest = (
                read_json(
                    'meta/manifest.json'
                )
                or {}
            )

            node_backup_results = (
                read_json(
                    'meta/node_wg_backup.json'
                )
                or []
            )

            runtime_settings = (
                read_json(
                    'instance/runtime.json'
                )
                or {}
            )

            panel_settings = (
                read_json(
                    'instance/panel_settings.json'
                )
                or {}
            )

            app_meta = (
                read_json(
                    'meta/app.json'
                )
                or {}
            )

            contains = {
                'database': has_db,
                'settings': has_settings,
                'env_file': has_env,
                'local_wireguard_conf': (
                    has_wg
                ),
                'remote_node_wireguard_conf': (
                    has_node_wg
                ),
                'remote_node_env': (
                    has_node_env
                ),
                'short_links': (
                    'instance/short_links.json'
                    in names
                ),
                'manifest': bool(manifest),
            }

            counts = {
                'db_files': len(
                    db_files
                ),
                'instance_files': len(
                    instance_files
                ),
                'local_wg_files': len(
                    local_wg_files
                ),
                'node_wg_files': len(
                    node_wg_files
                ),
                'node_wg_nodes': len(
                    node_wg_nodes
                ),
                'node_env_files': len(
                    node_env_files
                ),
                'node_env_nodes': len(
                    node_env_nodes
                ),
            }

            stat = backup_path.stat()

            return jsonify(
                ok=True,
                filename=backup_path.name,
                size=stat.st_size,
                modified=int(
                    stat.st_mtime
                ),
                kind=kind,
                created=read_text(
                    'meta/created.txt'
                ),
                host=read_text(
                    'meta/host.txt'
                ),

                has_db=has_db,
                has_settings=has_settings,
                has_wg=has_wg,
                has_node_wg=has_node_wg,
                has_env=has_env,
                has_node_env=has_node_env,

                contains=contains,
                counts=counts,

                local_wg_files=(
                    local_wg_files
                ),
                node_wg_files=(
                    node_wg_files
                ),
                node_wg_nodes=(
                    node_wg_nodes
                ),
                node_env_files=(
                    node_env_files
                ),
                node_env_nodes=(
                    node_env_nodes
                ),

                manifest=manifest,
                node_wg_backup=(
                    node_backup_results
                ),
                runtime=runtime_settings,
                panel_settings=(
                    panel_settings
                ),
                app_meta=app_meta,
            )

    except zipfile.BadZipFile:
        return jsonify(
            ok=False,
            error='invalid_zip',
            message=(
                'The saved file is not a valid '
                'ZIP backup.'
            ),
        ), 400

    except Exception as exc:
        app.logger.exception(
            'Saved auto-backup inspection '
            'failed for %s: %s',
            safe_name,
            exc,
        )

        return jsonify(
            ok=False,
            error='inspection_failed',
            message=str(exc),
        ), 500
    
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


def _send_zip_telegram(
    data_bytes: bytes,
    filename: str,
    chat_id: str | None = None,
    caption: str | None = None,
) -> tuple[bool, str]:
    settings = _load_tg_settings()

    if not settings.get("enabled"):
        return False, "Telegram disabled."

    token = (
        settings.get("bot_token")
        or ""
    ).strip()

    if not token:
        return False, "Telegram token missing."

    selected_chat_id = str(
        chat_id
        or _tg_chatid()
        or ""
    ).strip()

    if not selected_chat_id:
        return False, (
            "No active Telegram administrator selected."
        )

    active_admin_ids = {
        str(
            admin.get("id")
            or ""
        ).strip()
        for admin in (
            _load_tg_admins()
            or []
        )
        if (
            not admin.get("muted")
            and str(
                admin.get("id")
                or ""
            ).strip()
        )
    }

    if selected_chat_id not in active_admin_ids:
        return False, (
            "Selected Telegram recipient is not an "
            "active panel administrator."
        )

    size_bytes = len(
        data_bytes
        or b""
    )

    if not caption:
        try:
            size_text = _tg_human_bytes(
                size_bytes
            )
        except Exception:
            size_text = (
                f"{size_bytes} bytes"
            )

        created_at = _tg_now_text()

        caption = "\n".join([
            "<b>WG Panel backup</b>",
            "",
            "<b>Status</b> · Completed",
            (
                "<b>File</b> · "
                f"<code>{_tg_event_escape(filename)}</code>"
            ),
            (
                "<b>Size</b> · "
                f"{_tg_event_escape(size_text)}"
            ),
            (
                "<b>Created</b> · "
                f"{_tg_event_escape(created_at)}"
            ),
        ])

    if len(caption) > 1000:
        caption = caption[:997] + "..."

    try:
        response = requests.post(
            (
                "https://api.telegram.org/bot"
                f"{token}/sendDocument"
            ),
            data={
                "chat_id": selected_chat_id,
                "disable_notification": "true",
                "caption": caption,
                "parse_mode": "HTML",
            },
            files={
                "document": (
                    filename,
                    data_bytes,
                    "application/zip",
                )
            },
            timeout=60,
        )

        try:
            payload = (
                response.json()
                or {}
            )
        except Exception:
            payload = {}

        if (
            response.ok
            and payload.get("ok")
        ):
            return (
                True,
                "Backup document sent to Telegram.",
            )

        description = str(
            payload.get("description")
            or response.text
            or ""
        )[:300]

        return (
            False,
            (
                "Telegram error "
                f"{response.status_code}: "
                f"{description}"
            ),
        )

    except Exception as exc:
        return (
            False,
            f"Telegram exception: {exc}",
        )

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

    ts = _panel_filename_stamp()
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

    ts = _panel_filename_stamp()
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

# ------------------------------------------------------------
# Remote node WireGuard .conf backup / restore helpers
# ------------------------------------------------------------
def _node_backup_wg_zip(node: Node, timeout: int = 25) -> bytes:
    url = f"{node.base_url.rstrip('/')}/api/backup/wg"

    r = requests.get(
        url,
        headers={'Authorization': f'Bearer {_read_api_key(node)}'},
        timeout=timeout,
    )

    r.raise_for_status()
    return r.content or b''


def _bundle_node_wg_backups(z: zipfile.ZipFile) -> list[dict]:
    """
    Pull each enabled node_agent backup and store it inside the panel full backup.

    The node_agent backup can contain:
      wg/<iface>.conf
      env/.env
      meta/node.json

    Panel full backup layout:
      nodes/<node_id>/meta.json
      nodes/<node_id>/wg/<iface>.conf
      nodes/<node_id>/env/.env
    """
    results = []

    nodes = Node.query.order_by(Node.id.asc()).all()

    for node in nodes:
        rec = {
            "node_id": node.id,
            "name": node.name,
            "base_url": node.base_url,
            "ok": False,
            "files": [],
            "env_file": False,
            "error": "",
        }

        try:
            z.writestr(
                f"nodes/{node.id}/meta.json",
                json.dumps(
                    {
                        "node_id": node.id,
                        "name": node.name,
                        "base_url": node.base_url,
                        "enabled": bool(node.enabled),
                        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    },
                    indent=2,
                ),
            )

            if not node.enabled:
                rec["error"] = "node_disabled"
                results.append(rec)
                continue

            raw = _node_backup_wg_zip(node)

            if not raw:
                rec["error"] = "empty_node_backup"
                results.append(rec)
                continue

            try:
                with zipfile.ZipFile(BytesIO(raw), "r") as nz:
                    members = nz.namelist()

                    for member in members:
                        # Node WireGuard configs:
                        # node_agent layout: wg/<iface>.conf
                        # panel layout:     nodes/<node_id>/wg/<iface>.conf
                        if member.startswith("wg/") and member.endswith(".conf"):
                            filename = os.path.basename(member)
                            if not filename:
                                continue

                            data = nz.read(member)
                            z.writestr(f"nodes/{node.id}/wg/{filename}", data)
                            rec["files"].append(filename)
                            continue


                        if member == "env/.env":
                            try:
                                data = nz.read(member)
                                if data:
                                    z.writestr(f"nodes/{node.id}/env/.env", data)
                                    rec["env_file"] = True
                            except Exception as e:
                                current_app.logger.warning(
                                    "Node env backup skipped node=%s url=%s error=%s",
                                    getattr(node, "id", "?"),
                                    getattr(node, "base_url", ""),
                                    e,
                                )
                            continue

                rec["files"] = sorted(set(rec["files"]))
                rec["ok"] = bool(rec["files"] or rec["env_file"])

                if not rec["ok"]:
                    rec["error"] = "node_backup_had_no_wg_or_env"

            except zipfile.BadZipFile:
                rec["error"] = "node_backup_not_zip"
            except Exception as e:
                rec["error"] = f"node_backup_read_failed: {e}"

        except Exception as e:
            rec["error"] = str(e)
            current_app.logger.warning(
                "Node backup failed node=%s url=%s error=%s",
                getattr(node, "id", "?"),
                getattr(node, "base_url", ""),
                e,
            )

        results.append(rec)

    return results


def _node_wg_payloads_zip(
    z: zipfile.ZipFile,
    names: list[str],
) -> dict[int, dict]:
    """
    Read node WireGuard files and optional node .env
    from a full panel backup.
    """
    payloads: dict[int, dict] = {}

    for member in names:
        # Node WireGuard configuration
        match = re.match(
            r'^nodes/(\d+)/wg/([^/]+\.conf)$',
            member,
        )

        if match:
            node_id = int(match.group(1))
            filename = os.path.basename(
                match.group(2)
            )

            try:
                text = z.read(member).decode(
                    'utf-8',
                    'replace',
                )
            except Exception:
                continue

            payload = payloads.setdefault(
                node_id,
                {
                    'files': {},
                    'env_file': None,
                },
            )

            payload['files'][filename] = text
            continue

        # Node-agent .env
        match = re.match(
            r'^nodes/(\d+)/env/\.env$',
            member,
        )

        if match:
            node_id = int(match.group(1))

            try:
                text = z.read(member).decode(
                    'utf-8',
                    'replace',
                )
            except Exception:
                continue

            payload = payloads.setdefault(
                node_id,
                {
                    'files': {},
                    'env_file': None,
                },
            )

            payload['env_file'] = text

    return payloads


def _restore_node_wg_zip(
    z: zipfile.ZipFile,
    names: list[str],
) -> list[dict]:
    """
    Restore node WireGuard configs and node-agent .env.
    """
    payloads = _node_wg_payloads_zip(
        z,
        names,
    )

    results = []

    for node_id, payload in payloads.items():
        node = db.session.get(
            Node,
            node_id,
        )

        files = payload.get('files') or {}
        env_file = payload.get('env_file')

        rec = {
            'node_id': node_id,
            'ok': False,
            'files': sorted(files.keys()),
            'env_file': bool(env_file),
            'error': '',
        }

        if not node:
            rec['error'] = (
                'node_not_found_in_current_db'
            )
            results.append(rec)
            continue

        try:
            url = (
                f"{node.base_url.rstrip('/')}"
                "/api/backup/wg/restore"
            )

            response = requests.post(
                url,
                headers={
                    'Authorization': (
                        f'Bearer {_read_api_key(node)}'
                    ),
                    'Content-Type': 'application/json',
                },
                json={
                    'files': files,
                    'env_file': env_file,
                    'bring_up': False,
                },
                timeout=35,
            )

            try:
                body = response.json()
            except Exception:
                body = {
                    'raw': response.text[:500]
                }

            if not response.ok:
                rec['error'] = (
                    f'HTTP {response.status_code}: '
                    f'{str(body)[:500]}'
                )
            else:
                rec['ok'] = bool(
                    body.get('ok', True)
                )
                rec['result'] = body

        except Exception as exc:
            rec['error'] = str(exc)

        results.append(rec)

    return results

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

    include_wg = (
        request.args.get('wg') or
        ('1' if prefs.get('include_wg') else '0')
    ) == '1'

    send_tg = (
        request.args.get('tg') or
        ('1' if prefs.get('send_to_telegram') else '0')
    ) == '1'

    auto_flag = (request.args.get('auto') or '0') == '1'
    selected_chat_id = (request.args.get("chat_id")or "").strip()

    node_wg_results = []
    saved_auto_backup = None

    mem = BytesIO()

    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        # -----------------------------
        # Database
        # -----------------------------
        # Includes peers, nodes, interfaces, subscriptions,
        # subscription links, limits, counters, etc.
        dbp = _db_path()

        if dbp and os.path.isfile(dbp):
            z.write(dbp, arcname=f'db/{os.path.basename(dbp)}')

        # -----------------------------
        # Instance JSON / JSONL
        # -----------------------------
        # Includes short_links.json, panel settings, Telegram settings,
        # template settings, backup settings, logs settings, peer profiles, etc.
        _jsonl_bundle(z)

        # -----------------------------
        # Panel .env
        # -----------------------------
        # Includes panel FERNET_KEY/API_KEY/secrets.
        # Required for migration/decrypting encrypted panel values.
        _env_bundle(z)

        # -----------------------------
        # Local + remote WireGuard backup
        # -----------------------------
        if include_wg:
            # Local panel server WireGuard configs.
            wgdir = app.config.get('WG_CONF_PATH') or '/etc/wireguard/'

            try:
                for p in Path(wgdir).glob('*.conf'):
                    if p.is_file():
                        z.write(p, arcname=f'wg/{p.name}')
            except Exception as e:
                current_app.logger.debug("Local WG bundle skipped: %s", e)

            # Remote node backups.
            #
            # _bundle_node_wg_backups() now pulls:
            #   nodes/<node_id>/wg/<iface>.conf
            #   nodes/<node_id>/env/.env
            # from each node_agent backup.
            try:
                node_wg_results = _bundle_node_wg_backups(z)
            except Exception as e:
                current_app.logger.warning("Node backup bundle skipped: %s", e)
                node_wg_results = [{
                    'ok': False,
                    'files': [],
                    'env_file': False,
                    'error': str(e),
                }]

        created_at = datetime.utcnow().isoformat(timespec='seconds') + 'Z'

        z.writestr('meta/created.txt', created_at)
        z.writestr('meta/host.txt', socket.gethostname())

        z.writestr(
            'meta/app.json',
            json.dumps({
                'db_uri': app.config.get('SQLALCHEMY_DATABASE_URI', ''),
                'wg_conf_path': app.config.get('WG_CONF_PATH') or '/etc/wireguard/',
            }, indent=2)
        )

        z.writestr(
            'meta/node_wg_backup.json',
            json.dumps(node_wg_results, indent=2)
        )

        try:
            manifest_counts = {
                'nodes': Node.query.count(),
                'interfaces': InterfaceConfig.query.count(),
                'peers': Peer.query.count(),
                'subscriptions': Subscription.query.count(),
                'subscription_peers': SubscriptionPeer.query.count(),
                'short_links': ShortLink.query.count(),
            }
        except Exception:
            manifest_counts = {}

        try:
            local_wg_count = 0
            if include_wg:
                wgdir = app.config.get('WG_CONF_PATH') or '/etc/wireguard/'
                local_wg_count = len([
                    p for p in Path(wgdir).glob('*.conf')
                    if p.is_file()
                ])
        except Exception:
            local_wg_count = 0

        node_wg_count = 0
        node_env_count = 0

        try:
            for rec in node_wg_results or []:
                node_wg_count += len(rec.get('files') or [])
                if rec.get('env_file'):
                    node_env_count += 1
        except Exception:
            node_wg_count = 0
            node_env_count = 0

        panel_env_exists = bool((Path(BASE_DIR) / '.env').is_file())

        z.writestr(
            'meta/manifest.json',
            json.dumps({
                'created_at': created_at,
                'kind': 'full',
                'panel_version': PANEL_VERSION,
                'contains': {
                    'database': bool(dbp and os.path.isfile(dbp)),
                    'instance_json': True,
                    'env_file': bool(panel_env_exists),
                    'remote_node_env': bool(node_env_count > 0),
                    'short_links': True,
                    'subscriptions': True,
                    'nodes_metadata': True,
                    'local_wireguard_conf': bool(include_wg and local_wg_count > 0),
                    'remote_node_wireguard_conf': bool(include_wg and node_wg_count > 0),
                },
                'counts': {
                    **manifest_counts,
                    'local_wg_files': int(local_wg_count or 0),
                    'node_wg_files': int(node_wg_count or 0),
                    'node_env_files': int(node_env_count or 0),
                },
                'node_wg_backup': node_wg_results,
            }, indent=2)
        )

    mem.seek(0)

    ts = _panel_filename_stamp()
    fname = f'wgpanel_full_backup_{ts}.zip'
    data = mem.getvalue()

    # -----------------------------
    # Save automatic backup copy
    # -----------------------------
    if auto_flag:
        try:
            schedule = (_load_backup_schedule())
            keep = int(schedule.get("keep",7,))
        except Exception:
            keep = 7

        try:
            saved_auto_backup = (_save_autobackup(data,keep=keep,))
        except Exception as e:
            saved_auto_backup = None
            current_app.logger.exception("Automatic backup storage failed: %s",exc,)

    # -----------------------------
    # Send to Telegram
    # -----------------------------
    telegram_ok = None
    telegram_message = ""

    if send_tg:
        telegram_ok, telegram_message = (
            _send_zip_telegram(data,fname,chat_id=selected_chat_id or None,))

    if send_tg and telegram_ok is False:
        current_app.logger.warning("Backup Telegram send failed: %s",telegram_message,)

    # -----------------------------
    # Admin log
    # -----------------------------
    try:
        node_wg_count = 0
        node_env_count = 0

        for rec in node_wg_results or []:
            node_wg_count += len(rec.get('files') or [])
            if rec.get('env_file'):
                node_env_count += 1

        _norm_adminlog({
            "action": "backup_full",
            "details": (
                f"file={fname} size={len(data)}B "
                f"wg={int(include_wg)} tg={int(send_tg)} auto={int(auto_flag)} "
                f"node_wg_nodes={len(node_wg_results or [])} "
                f"node_wg_files={node_wg_count} "
                f"node_env_files={node_env_count}"
            ),
            "channel": (
                "api"
                if request.headers.get('Authorization') or request.headers.get('X-API-KEY')
                else "web"
            ),
        })
    except Exception:
        pass

    try:
        _record_backup('full')
    except Exception as e:
        current_app.logger.debug("record_backup(full) failed: %s", e)

    out = BytesIO(data)
    out.seek(0)

    resp = send_file(
        out,
        mimetype='application/zip',
        as_attachment=True,
        download_name=fname,
    )

    try:
        node_env_count = sum(
            1 for rec in (node_wg_results or [])
            if rec.get('env_file')
        )
    except Exception:
        node_env_count = 0

    resp.headers['X-Backup-Kind'] = 'full'
    resp.headers['X-Backup-Timestamp'] = ts
    resp.headers['X-Backup-WG'] = (
        '1'
        if include_wg
        else '0'
    )
    resp.headers['X-Backup-TG'] = (
       '1'
       if send_tg
       else '0'
    )
    resp.headers['X-Backup-AUTO'] = (
        '1'
        if auto_flag
        else '0'
    )
    resp.headers['X-Backup-Node-WG'] = str(
        len(
            node_wg_results
            or []
        )
    )
    resp.headers['X-Backup-Node-ENV'] = str(
        node_env_count
    ) 

    if isinstance(
        saved_auto_backup,
        dict,
    ):
        saved_name = str(
            saved_auto_backup.get(
                'name'
            )
            or ''
        ).strip()

        try:
            saved_size = int(
                saved_auto_backup.get(
                    'size'
                )
                or 0
            )
        except Exception:
            saved_size = 0

        try:
            saved_timestamp = int(saved_auto_backup.get('ts')or 0)
        except Exception:
            saved_timestamp = 0

        if saved_name:
            resp.headers[
                'X-Backup-Saved-Name'
            ] = saved_name

        resp.headers[
            'X-Backup-Saved-Size'
        ] = str(
            saved_size
        )

        resp.headers[
            'X-Backup-Saved-Timestamp'
        ] = str(
            saved_timestamp
        )

    return resp

def _load_backup_schedule():
    d = _json_load(
        BACKUP_SCHEDULE_FILE,
        {},
    )

    return {
        "enabled": bool(
            d.get("enabled", False)
        ),
        "freq": d.get(
            "freq",
            "daily",
        ),
        "time": d.get(
            "time",
            "03:00",
        ),

        "timezone": _panel_timezone_name(),

        "dow": list(
            map(
                str,
                d.get("dow", []),
            )
        ),
        "dom": int(
            d.get("dom", 1)
        ),
        "cron": d.get(
            "cron",
            "",
        ),
        "keep": int(
            d.get("keep", 7)
        ),
        "include_wg": bool(
            d.get("include_wg", True)
        ),
        "send_to_telegram": bool(
            d.get(
                "send_to_telegram",
                False,
            )
        ),

        "telegram_chat_id": str(
            d.get(
                "telegram_chat_id",
                "",
            )
            or ""
        ).strip(),
    }


def _save_backup_schedule(partial: dict):
    cur = _load_backup_schedule()

    cur.update({
        "enabled": bool(
            partial.get(
                "enabled",
                cur["enabled"],
            )
        ),
        "freq": (
            partial.get("freq")
            or cur["freq"]
        ).lower(),
        "time": (
            partial.get("time")
            or cur["time"]
        ),

        "timezone": _panel_timezone_name(),

        "dow": [
            str(x)
            for x in (
                partial.get("dow")
                or cur["dow"]
                or []
            )
        ],
        "dom": int(
            partial.get("dom")
            or cur["dom"]
            or 1
        ),
        "cron": (
            partial.get("cron")
            or cur["cron"]
        ).strip(),
        "keep": max(
            1,
            int(
                partial.get("keep")
                or cur["keep"]
                or 7
            ),
        ),
        "include_wg": bool(
            partial.get(
                "include_wg",
                cur["include_wg"],
            )
        ),
        "send_to_telegram": bool(
            partial.get(
                "send_to_telegram",
                cur["send_to_telegram"],
            )
        ),

        "telegram_chat_id": str(
            partial.get(
                "telegram_chat_id",
                cur.get(
                    "telegram_chat_id",
                    "",
                ),
            )
            or ""
        ).strip(),
    })

    if not cur["send_to_telegram"]:
        cur["telegram_chat_id"] = ""

    _json_save(
        BACKUP_SCHEDULE_FILE,
        cur,
    )

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


_BACKUP_SCHEDULER_STARTED = False
_BACKUP_SCHEDULER_INTERVAL_SEC = 30

_BACKUP_SCHEDULER_STATE_FILE = os.path.join(
    app.instance_path,
    'backup_scheduler_state.json',
)

_BACKUP_SCHEDULER_LOCK_FILE = os.path.join(
    app.instance_path,
    'backup_scheduler.lock',
)


def _cron_field_match(
    value: int,
    expr: str,
    minimum: int,
    maximum: int,
) -> bool:
    """
    Match basic cron syntax:

    *
    */5
    1,2,3
    1-5
    1-10/2
    """
    expr = (expr or '*').strip()

    for part in expr.split(','):
        part = part.strip()

        if not part:
            continue

        step = 1

        if '/' in part:
            base, raw_step = part.split('/', 1)

            try:
                step = max(
                    1,
                    int(raw_step),
                )
            except Exception:
                return False
        else:
            base = part

        if base == '*':
            low = minimum
            high = maximum

        elif '-' in base:
            try:
                low, high = map(
                    int,
                    base.split('-', 1),
                )
            except Exception:
                return False

        else:
            try:
                low = high = int(base)
            except Exception:
                return False

        low = max(minimum, low)
        high = min(maximum, high)

        if (
            low <= value <= high
            and (value - low) % step == 0
        ):
            return True

    return False


def _backup_due_slot(
    sched: dict,
    now_utc=None,
) -> str | None:
    """
    Return a unique schedule slot only when a backup is due.
    """
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo

    if not sched.get('enabled'):
        return None

    now_utc = (
        now_utc
        or datetime.now(timezone.utc)
    )

    try:
        timezone_name = (
            sched.get('timezone')
            or 'UTC'
        ).strip() or 'UTC'

        timezone_info = ZoneInfo(
            timezone_name
        )
    except Exception:
        timezone_info = ZoneInfo('UTC')

    local_time = now_utc.astimezone(
        timezone_info
    )

    frequency = (
        sched.get('freq')
        or 'daily'
    ).lower()

    # minute hour day month weekday
    if frequency == 'custom':
        fields = (
            sched.get('cron')
            or ''
        ).split()

        if len(fields) != 5:
            return None

        minute, hour, day, month, weekday = fields

        # Python: Monday=0
        # Cron: Sunday=0 or 7
        cron_weekday = (
            local_time.weekday() + 1
        ) % 7

        matched = all((
            _cron_field_match(
                local_time.minute,
                minute,
                0,
                59,
            ),
            _cron_field_match(
                local_time.hour,
                hour,
                0,
                23,
            ),
            _cron_field_match(
                local_time.day,
                day,
                1,
                31,
            ),
            _cron_field_match(
                local_time.month,
                month,
                1,
                12,
            ),
            (
                _cron_field_match(
                    cron_weekday,
                    weekday,
                    0,
                    7,
                )
                or (
                    cron_weekday == 0
                    and _cron_field_match(
                        7,
                        weekday,
                        0,
                        7,
                    )
                )
            ),
        ))

        if not matched:
            return None

        return (
            f"custom:"
            f"{local_time:%Y-%m-%dT%H:%M}"
        )

    try:
        hour, minute = map(
            int,
            (
                sched.get('time')
                or '03:00'
            ).split(':', 1),
        )
    except Exception:
        hour, minute = 3, 0

    if (
        local_time.hour != hour
        or local_time.minute != minute
    ):
        return None

    if frequency == 'weekly':
        selected_days = [
            int(value)
            for value in (
                sched.get('dow')
                or []
            )
        ] or [1]

        if (
            local_time.weekday()
            not in selected_days
        ):
            return None

    elif frequency == 'monthly':
        from calendar import monthrange

        selected_day = max(
            1,
            min(
                31,
                int(sched.get('dom') or 1),
            ),
        )

        final_day = min(
            selected_day,
            monthrange(
                local_time.year,
                local_time.month,
            )[1],
        )

        if local_time.day != final_day:
            return None

    elif frequency != 'daily':
        return None

    return (
        f"{frequency}:"
        f"{local_time:%Y-%m-%dT%H:%M}"
    )


def _run_scheduled_backup(
    sched: dict,
    slot: str,
) -> dict:

    from urllib.parse import urlencode

    send_to_telegram = bool(
        sched.get(
            "send_to_telegram",
            False,
        )
    )

    telegram_chat_id = str(
        sched.get(
            "telegram_chat_id",
            "",
        )
        or ""
    ).strip()

    query = {
        "auto": "1",
        "wg": (
            "1"
            if sched.get(
                "include_wg",
                True,
            )
            else "0"
        ),
        "tg": "0",
    }

    request_path = (
        "/api/backup/full?"
        + urlencode(query)
    )

    with app.test_request_context(
        request_path
    ):
        backup_function = backup_full

        while hasattr(
            backup_function,
            "__wrapped__",
        ):
            backup_function = (
                backup_function.__wrapped__
            )

        response = backup_function()

        if isinstance(response, tuple):
            flask_response = response[0]
            tuple_status = (
                response[1]
                if len(response) > 1
                else None
            )
        else:
            flask_response = response
            tuple_status = None

        status_code = int(
            tuple_status
            or getattr(
                flask_response,
                "status_code",
                200,
            )
            or 200
        )

        if status_code >= 400:
            raise RuntimeError(
                "backup endpoint returned "
                f"HTTP {status_code}"
            )

        headers = getattr(
            flask_response,
            "headers",
            {},
        )

        saved_name = str(
            headers.get(
                "X-Backup-Saved-Name"
            )
            or ""
        ).strip()

        try:
            saved_size = int(
                headers.get(
                    "X-Backup-Saved-Size"
                )
                or 0
            )
        except Exception:
            saved_size = 0

        try:
            saved_timestamp = int(
                headers.get(
                    "X-Backup-Saved-Timestamp"
                )
                or 0
            )
        except Exception:
            saved_timestamp = 0

    if not saved_name:
        raise RuntimeError(
            "The backup response did not confirm "
            "a locally saved automatic archive."
        )

    backup_root = Path(
        BACKUP_AUTO_DIR
    ).resolve()

    backup_path = (
        backup_root
        / os.path.basename(saved_name)
    ).resolve()

    try:
        backup_path.relative_to(
            backup_root
        )
    except ValueError:
        raise RuntimeError(
            "Automatic backup path validation failed."
        )

    if not backup_path.is_file():
        raise RuntimeError(
            "Automatic backup was created but the stored "
            f"ZIP could not be found: {saved_name}"
        )

    try:
        data_bytes = backup_path.read_bytes()
    except Exception as exc:
        raise RuntimeError(
            "Could not read the stored automatic backup: "
            f"{exc}"
        ) from exc

    if not data_bytes:
        raise RuntimeError(
            "The stored automatic backup is empty."
        )

    if not data_bytes.startswith(b"PK"):
        raise RuntimeError(
            "The stored automatic backup is not a valid ZIP."
        )

    saved_size = len(data_bytes)

    completed_at = (
        datetime.utcnow()
        .isoformat(
            timespec="seconds"
        )
        + "Z"
    )

    telegram_sent = False
    telegram_message = ""

    if send_to_telegram:
        if not telegram_chat_id:
            raise RuntimeError(
                "Telegram delivery is enabled, but no "
                "Telegram administrator is selected."
            )

        scheduled_dt = _backup_slot_datetime(
            slot,
            sched,
        )

        schedule_text = _tg_human_datetime(
            scheduled_dt,
            seconds=False,
        )

        completed_text = _tg_human_datetime(
            completed_at,
            seconds=False,
        )

        try:
            size_text = _tg_human_bytes(
                saved_size
            )
        except Exception:
            size_text = (
                f"{saved_size} bytes"
            )

        caption = "\n".join([
            "<b>Automatic backup completed</b>",
            "",
            "<b>Status</b> · Completed",
            (
                "<b>Schedule time</b> · "
                f"{_tg_event_escape(schedule_text)}"
            ),
            (
                "<b>Completed at</b> · "
                f"{_tg_event_escape(completed_text)}"
            ),
            (
                "<b>File</b> · "
                f"<code>{_tg_event_escape(saved_name)}</code>"
            ),
            (
                "<b>Size</b> · "
                f"{_tg_event_escape(size_text)}"
            ),
        ])

        telegram_sent, telegram_message = (
            _send_zip_telegram(
                data_bytes,
                saved_name,
                chat_id=telegram_chat_id,
                caption=caption,
            )
        )

        if not telegram_sent:
            raise RuntimeError(
                "Backup was stored locally, but Telegram "
                "document delivery failed: "
                f"{telegram_message}"
            )

        app.logger.info(
            "Automatic backup delivered to Telegram: "
            "file=%s chat_id=%s size=%s",
            saved_name,
            telegram_chat_id,
            saved_size,
        )

    backup_metadata = {
        "filename": saved_name,
        "name": saved_name,
        "size": saved_size,
        "size_bytes": saved_size,
        "timestamp": saved_timestamp,
        "telegram_requested": send_to_telegram,
        "telegram_sent": telegram_sent,
        "telegram_message": telegram_message,
    }

    state = _json_load(
        _BACKUP_SCHEDULER_STATE_FILE,
        {},
    )

    if not isinstance(
        state,
        dict,
    ):
        state = {}

    state.update({
        "last_slot": slot,
        "last_success": completed_at,
        "last_success_at": completed_at,
        "last_file": saved_name,
        "last_size": saved_size,
        "last_error": "",
        "last_error_at": "",
        "last_telegram_sent": (
            telegram_sent
            if send_to_telegram
            else None
        ),
        "last_telegram_message": (
            telegram_message
            if send_to_telegram
            else ""
        ),
    })

    _json_save(
        _BACKUP_SCHEDULER_STATE_FILE,
        state,
    )

    return backup_metadata

def _backup_slot_datetime(
    slot: str,
    schedule: dict,
):
    """
    Convert a scheduler slot such as:

        daily:2026-08-25T06:30

    into a timezone-aware datetime.

    Scheduler slot clock values are in panel timezone.
    """
    raw = str(
        slot or ""
    ).strip()

    if ":" not in raw:
        return None

    _frequency, timestamp_text = (
        raw.split(
            ":",
            1,
        )
    )

    try:
        parsed = datetime.fromisoformat(
            timestamp_text
        )
    except Exception:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=_panel_timezone()
        )

    return parsed

def _backup_scheduler_loop():

    lock_handle = None

    try:
        lock_handle = open(
            _BACKUP_SCHEDULER_LOCK_FILE,
            "a+",
        )

        fcntl.flock(
            lock_handle.fileno(),
            fcntl.LOCK_EX
            | fcntl.LOCK_NB,
        )

    except Exception:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass

        return

    while True:
        try:
            with app.app_context():
                schedule = _load_backup_schedule()

                slot = _backup_due_slot(
                    schedule
                )

                state = _json_load(
                    _BACKUP_SCHEDULER_STATE_FILE,
                    {},
                )

                if not isinstance(
                    state,
                    dict,
                ):
                    state = {}

                if (
                    slot
                    and state.get("last_slot")
                    != slot
                ):
                    try:

                        backup_result = (
                            _run_scheduled_backup(
                                schedule,
                                slot,
                            )
                        )

                        completed_at = (
                            datetime.utcnow()
                            .isoformat(
                                timespec="seconds"
                            )
                            + "Z"
                        )

                        app.logger.info(
                            "Automatic backup completed: "
                            "slot=%s",
                            slot,
                        )

                        notification_details = [
                            (
                                "Schedule time",
                                _backup_slot_datetime(
                                    slot,
                                    schedule,
                                )
                                or slot,
                            ),
                            (
                                "Completed at",
                                completed_at,
                            ),
                        ]

                        if isinstance(
                            backup_result,
                            dict,
                        ):
                            backup_filename = str(
                                backup_result.get(
                                    "filename"
                                )
                                or backup_result.get(
                                    "file"
                                )
                                or backup_result.get(
                                    "name"
                                )
                                or ""
                            ).strip()

                            backup_size = (
                                backup_result.get(
                                    "size"
                                )
                                or backup_result.get(
                                    "size_bytes"
                                )
                            )

                            if backup_filename:
                                notification_details.append(
                                    (
                                        "File",
                                        backup_filename,
                                    )
                                )

                            if backup_size not in (
                                None,
                                "",
                            ):
                                notification_details.append(
                                    (
                                        "Size bytes",
                                        backup_size,
                                    )
                                )

                        if not schedule.get(
                            "send_to_telegram",
                            False,
                        ):
                            _send_telegram_event(
                                "backup_success",
                                (
                                    "● Automatic backup "
                                    "completed"
                                ),
                                status="Completed",
                                details=(
                                    notification_details
                                ),
                                dedupe_key=(
                                    f"backup-success:{slot}"
                                ),
                                dedupe_seconds=0,
                            )

                        # _run_scheduled_backup() 
                        #
                        # - last_slot
                        # - last_success
                        # - last_success_at
                        # - last_file
                        # - last_size
                        # - last_error
                        # - last_error_at
                        # - last_telegram_sent
                        # - last_telegram_message

                    except Exception as exc:
                        failed_at = (
                            datetime.utcnow()
                            .isoformat(
                                timespec="seconds"
                            )
                            + "Z"
                        )

                        failure_state = _json_load(
                            _BACKUP_SCHEDULER_STATE_FILE,
                            {},
                        )

                        if not isinstance(
                            failure_state,
                            dict,
                        ):
                            failure_state = {}

                        failure_state.update({

                            "last_slot": slot,

                            "last_error": str(
                                exc
                            ),

                            "last_error_at": (
                                failed_at
                            ),
                        })

                        _json_save(
                            _BACKUP_SCHEDULER_STATE_FILE,
                            failure_state,
                        )

                        app.logger.exception(
                            "Automatic backup failed: "
                            "slot=%s error=%s",
                            slot,
                            exc,
                        )

                        _send_telegram_event(
                            "backup_failed",
                            (
                                "● Automatic backup "
                                "failed"
                            ),
                            status="Failed",
                            details=[
                                (
                                    "Schedule time",
                                    _backup_slot_datetime(
                                        slot,
                                        schedule,
                                    )
                                    or slot,
                                ),
                                (
                                    "Failed at",
                                    failed_at,
                                ),
                                (
                                    "Error",
                                    str(
                                        exc
                                    )[:300],
                                ),
                            ],
                            dedupe_key=(
                                f"backup-failed:{slot}"
                            ),
                            dedupe_seconds=300,
                        )

        except Exception as exc:
            try:
                app.logger.exception(
                    "Backup scheduler sweep failed: %s",
                    exc,
                )
            except Exception:
                pass

        time.sleep(
            _BACKUP_SCHEDULER_INTERVAL_SEC
        )

def _start_backup_scheduler():
    global _BACKUP_SCHEDULER_STARTED

    if _BACKUP_SCHEDULER_STARTED:
        return

    _BACKUP_SCHEDULER_STARTED = True

    thread = threading.Thread(
        target=_backup_scheduler_loop,
        name='auto-backup-scheduler',
        daemon=True,
    )

    thread.start()

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
    hb = _json_load(
        TELEGRAM_HB_FILE,
        {},
    )

    last = int(
        hb.get('ts')
        or 0
    )

    sec = max(
        15,
        int(
            current_app.config.get(
                'TG_HEARTBEAT_SEC',
                60,
            )
            or 60
        ),
    )

    heartbeat_age = (
        max(
            0,
            now_ts() - last,
        )
        if last
        else None
    )

    heartbeat_fresh = bool(
        last
        and heartbeat_age
        <= max(
            180,
            sec * 4,
        )
    )
    process_alive = False

    try:
        pid = int(
            hb.get('pid')
            or 0
        )

        if pid > 1:
            os.kill(
                pid,
                0,
            )
            process_alive = True

    except ProcessLookupError:
        process_alive = False

    except PermissionError:
        process_alive = True

    except Exception:
        process_alive = False

    online = bool(
        heartbeat_fresh
        or process_alive
    )

    if heartbeat_fresh:
        state = 'online'

    elif process_alive:
        state = 'running_heartbeat_stale'

    else:
        state = 'offline'

    return jsonify(
        bot_online=online,
        state=state,
        heartbeat_fresh=heartbeat_fresh,
        process_alive=process_alive,
        heartbeat_age_seconds=heartbeat_age,
        heartbeat_interval_seconds=sec,
        last_seen=(
            isoz(
                from_ts(last)
            )
            if last
            else None
        ),
        pid=hb.get('pid'),
        version=hb.get('version'),
    )

# ________ Heartbeat: API-key protected, CSRF-exempt (bot no login) _________
@csrf.exempt
@app.post('/api/telegram/heartbeat')
@require_api_key
def tg_heartbeat():
    data = (
        request.get_json(
            silent=True,
        )
        or {}
    )

    rec = {
        'ts': now_ts(),
        'pid': data.get('pid'),
        'version': (
            data.get('version')
            or 'unknown'
        ),
        'panel': (
            data.get('panel')
            or ''
        ),
        'service': (
            data.get('service')
            or 'telegram-bot'
        ),
    }

    _json_save(
        TELEGRAM_HB_FILE,
        rec,
    )

    _extend_file(
        TELEGRAM_LOG_FILE,
        (
            f"[{isoz(from_ts(rec['ts']))}] "
            f"heartbeat "
            f"pid={rec['pid']} "
            f"v={rec['version']} "
            f"service={rec['service']}"
        ),
        source='telegram',
    )

    return jsonify(
        ok=True,
        server_ts=rec['ts'],
    )

# -------------------------------------------------
# Database DateTime values are stored as naive UTC.
# Unix timestamps are always absolute UTC instants.
# Regional timezone is ONLY used when displaying time.
# -------------------------------------------------

def now_ts() -> int:
    return int(time.time())


def to_ts(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    if not isinstance(value, datetime):
        return None

    # server's local timezone.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return int(value.timestamp())


def from_ts(ts):
    if ts is None:
        return None

    # Database columns are DateTime without timezone=True,
    return (
        datetime
        .fromtimestamp(int(ts), tz=timezone.utc)
        .replace(tzinfo=None)
    )


def add_days_ts(base_ts, days_float):
    if base_ts is None or days_float in (None, ''):
        return None

    try:
        duration_seconds = int(round(float(days_float) * 86400.0))
    except (TypeError, ValueError, OverflowError):
        return None

    if duration_seconds <= 0:
        return None

    return int(base_ts) + duration_seconds


def _timer_duration_days(record):
    """Return a valid positive timer duration, otherwise ``None``."""
    try:
        days = float(getattr(record, 'time_limit_days', 0) or 0)
    except (TypeError, ValueError, OverflowError):
        return None
    return days if days > 0 else None


def _timer_anchor_ts(record):
    """Return the one UTC anchor for the record's current timer cycle."""
    if bool(getattr(record, 'start_on_first_use', False)):
        return to_ts(getattr(record, 'first_used_at', None))

    return (
        to_ts(getattr(record, 'timer_started_at', None))
        or to_ts(getattr(record, 'created_at', None))
    )


def _effective_expiry_ts(record):
    """Calculate expiry from one anchor and one duration.

    ``expires_at`` remains stored for compatibility, but it is never trusted
    as a second source of truth.  This is what keeps enforcement, countdowns,
    detail cards, logs and subscriptions on the same instant.
    """
    if bool(getattr(record, 'unlimited', False)):
        return None

    days = _timer_duration_days(record)
    anchor_ts = _timer_anchor_ts(record)
    if not days or not anchor_ts:
        return None

    return add_days_ts(anchor_ts, days)


def _sync_effective_expiry(record):
    """Persist the canonical expiry and report whether the row changed."""
    expected_ts = _effective_expiry_ts(record)
    current_ts = to_ts(getattr(record, 'expires_at', None))
    if current_ts == expected_ts:
        return False

    record.expires_at = from_ts(expected_ts)
    return True


def _start_timer_cycle(record, anchor_ts=None):
    """Start/restart an immediate timer at an absolute UTC instant."""
    anchor_ts = int(anchor_ts or now_ts())
    record.timer_started_at = from_ts(anchor_ts)
    return _sync_effective_expiry(record)


def _clear_timer_cycle(record):
    record.timer_started_at = None
    record.expires_at = None


def isoz(value):
    if value is None:
        return None

    ts = to_ts(value)

    if ts is None:
        return None

    return (
        datetime
        .fromtimestamp(ts, tz=timezone.utc)
        .isoformat(timespec='seconds')
        .replace('+00:00', 'Z')
    )

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

def _wg_runtime_snapshot(iface_names):

    transfers = {}
    handshakes = {}

    names = {
        str(name or '').strip()
        for name in iface_names
        if str(name or '').strip()
    }

    for iface_name in sorted(names):
        try:
            dev = iface_name.split(':')[-1]

            lines = subprocess.check_output(
                ['wg', 'show', dev, 'dump'],
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            ).decode(
                errors='replace'
            ).splitlines()

            for line in lines[1:]:
                columns = line.split('\t')

                if len(columns) < 8:
                    columns = line.split()

                if len(columns) < 8:
                    continue

                public_key = columns[0].strip()

                if not public_key:
                    continue

                try:
                    latest_handshake = int(columns[4] or 0)
                except (TypeError, ValueError):
                    latest_handshake = 0

                try:
                    rx_bytes = int(columns[5] or 0)
                    tx_bytes = int(columns[6] or 0)
                except (TypeError, ValueError):
                    rx_bytes = 0
                    tx_bytes = 0

                key = (iface_name, public_key)

                transfers[key] = (rx_bytes, tx_bytes)
                handshakes[key] = latest_handshake

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
            OSError,
        ):
            continue

        except Exception:
            current_app.logger.debug(
                "WireGuard runtime snapshot failed for %s",
                iface_name,
                exc_info=True,
            )

    return transfers, handshakes

def _accumulate_peer_usage(peer, live_total=None):
    """
    Persist Wireلuard traffic across server/interface/node reboots.

    Returns:
        used_total_bytes, live_delta_bytes, changed
    """
    changed = False

    try:
        if live_total is None:
            live = int(_wg_transfer(peer) or 0)
        else:
            live = int(live_total or 0)
    except (TypeError, ValueError):
        live = 0
    except Exception:
        current_app.logger.debug(
            "Could not read live traffic for peer %s",
            getattr(peer, 'id', '?'),
            exc_info=True,
        )
        live = 0

    live = max(0, live)

    try:
        offset = int(
            getattr(peer, 'bytes_offset', 0) or 0
        )
    except (TypeError, ValueError):
        offset = 0

    try:
        persisted = int(
            getattr(peer, 'used_bytes_total', 0) or 0
        )
    except (TypeError, ValueError):
        persisted = 0

    offset = max(0, offset)
    persisted = max(0, persisted)

    if live < offset:
        offset = 0

        if int(getattr(peer, 'bytes_offset', 0) or 0) != 0:
            peer.bytes_offset = 0
            changed = True

    delta = max(0, live - offset)

    if delta > 0:
        persisted += delta

        peer.used_bytes_total = persisted
        peer.bytes_offset = live
        changed = True

    else:
        if getattr(peer, 'used_bytes_total', None) is None:
            peer.used_bytes_total = persisted
            changed = True

        if getattr(peer, 'bytes_offset', None) is None:
            peer.bytes_offset = live
            changed = True

    return (
        int(persisted),
        int(delta),
        bool(changed),
    )

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

def _wireguard_endpoint(value: str) -> str:
    """
    Accepted:
        1.2.3.4:51820
        example.com:51820
        [2001:db8::1]:51820
        DNS resolution belongs to the runtime
    """

    raw = str(value or '').strip()

    if not raw:
        return ''

    try:
        host, port = _host_port(raw)

        host = str(host or '').strip()
        port = str(port or '').strip()

        if not host or not port:
            raise ValueError(
                'Fixed client endpoint must use host:port format.'
            )

        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                'Fixed client endpoint port must be a number.'
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                'Fixed client endpoint port must be between 1 and 65535.'
            )


        try:
            address = ipaddress.ip_address(
                host.strip('[]')
            )

            return _norm_hostport(
                address.compressed,
                port,
            )

        except ValueError:
            pass

        hostname = host.rstrip('.')

        if (
            not hostname
            or len(hostname) > 253
        ):
            raise ValueError(
                'Fixed client endpoint hostname is invalid.'
            )

        labels = hostname.split('.')

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?',
                    label,
                )
            ):
                raise ValueError(
                    'Fixed client endpoint hostname is invalid.'
                )

        # Preserve hostname instead of converting it to an IP.
        return _norm_hostport(
            hostname,
            port,
        )

    except Exception as exc:
        raise RuntimeError(
            f'Invalid fixed client endpoint: {raw}. {exc}'
        ) from exc

def _wireguard_runtime_endpoint(value: str) -> str:
    """
    Resolve a fixed WG endpoint

    Persistent/database value remains the original hostname.

    Example:
        stored:
            vpn.example.com:51820

        runtime:
            203.0.113.20:51820
    """

    endpoint = _wireguard_endpoint(
        value
    )

    if not endpoint:
        return ''

    host, port = _host_port(
        endpoint
    )

    host = str(
        host or ''
    ).strip().strip('[]')

    port = int(port)

    # Already an IP address.
    try:
        address = ipaddress.ip_address(
            host
        )

        return _norm_hostport(
            address.compressed,
            port,
        )

    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_DGRAM,
        )

    except socket.gaierror as exc:
        raise RuntimeError(
            (
                'Fixed client endpoint DNS lookup failed: '
                f'{host}. {exc}'
            )
        ) from exc

    if not results:
        raise RuntimeError(
            f'Fixed client endpoint DNS lookup returned no addresses: {host}'
        )

    ipv4 = next(
        (
            result[4][0]
            for result in results
            if result[0] == socket.AF_INET
        ),
        None,
    )

    resolved = (
        ipv4
        or results[0][4][0]
    )

    return _norm_hostport(
        resolved,
        port,
    )

def _wg_enable(peer):

    dev = iface_devname(peer.iface)
    host_cidr = _host_peer(peer)

    if not dev:
        raise RuntimeError('Peer interface device name is missing.')

    if not host_cidr:
        raise RuntimeError('Peer WireGuard address is missing.')

    cmd = [
        'wg',
        'set',
        dev,
        'peer',
        peer.public_key,
        'allowed-ips',
        host_cidr,
    ]

    # Only an explicitly configured fixed remote-client endpoint belongs here.
    # peer.endpoint is the server's own address exported to the client and must
    # never be applied to the server-side peer.
    fixed_endpoint = (getattr(peer, "peer_endpoint", None)or "").strip()

    if fixed_endpoint:
        cmd += [
        'endpoint',
        _wireguard_runtime_endpoint(
            fixed_endpoint
        ),
    ]

    if peer.persistent_keepalive:
        cmd += [
            'persistent-keepalive',
            str(int(peer.persistent_keepalive)),
        ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        error_text = (
            result.stderr or
            result.stdout or
            'WireGuard command failed.'
        ).strip()

        raise RuntimeError(
            f'Could not enable peer on {dev}: {error_text}'
        )

    _unblackhole(host_cidr)

def _wg_disable(peer):
    dev = iface_devname(peer.iface)
    host_cidr = _host_peer(peer)

    if not dev:
        raise RuntimeError(
            'Peer interface device name is missing.'
        )

    if not host_cidr:
        raise RuntimeError(
            'Peer WireGuard address is missing.'
        )

    result = subprocess.run(
        [
            'wg',
            'set',
            dev,
            'peer',
            peer.public_key,
            'remove',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=12,
        check=False,
    )

    if result.returncode != 0:
        detail = (
            result.stderr
            or result.stdout
            or 'WireGuard peer removal failed.'
        ).strip()

        raise RuntimeError(
            f'Could not disable peer on {dev}: {detail}'
        )

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

    First tries wg-quick up.
      - ip link add dev <name> type wireguard
      - wg set private-key/listen-port
      - ip address add <address>
      - ip link set mtu <mtu>
      - ip link set up dev <name>

    """
    if not iface:
        return

    if getattr(iface, 'node_id', None) is not None or (':' in (iface.name or '')):
        return

    dev = iface_devname(iface)
    iid = int(getattr(iface, "id", 0) or 0)

    if _iface_up(dev):
        return

    cmd = ['wg-quick', 'up', dev]
    rc, out = _run_capture(cmd, timeout=20.0)
    _iface_log(iid, f"$ {' '.join(cmd)}\n{out}".rstrip())

    if rc == 0 and _iface_up(dev):
        return

    recovered = _fix_route(iid, out)
    if recovered and _iface_up(dev):
        _iface_log(iid, "Recovered from route-exists error; interface is up.")
        return

    current_app.logger.warning(
        "wg-quick up %s failed (rc=%s); trying manual bring-up",
        dev,
        rc
    )

    # Clean possible half-created interface from failed wg-quick/manual attempts.
    rc0, out0 = _run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
    _iface_log(iid, f"$ ip link del dev {dev}\n{out0}".rstrip())

    c = ['ip', 'link', 'add', 'dev', dev, 'type', 'wireguard']
    rc1, out1 = _run_capture(c, timeout=6.0)
    _iface_log(iid, f"$ {' '.join(c)}\n{out1}".rstrip())
    if rc1 != 0:
        raise RuntimeError(f"Could not create interface {dev}: {out1.strip() or 'ip link add failed'}")

    # Apply private key and listen port without using wg setconf on a wg-quick config.
    private_key = (getattr(iface, 'private_key', None) or '').strip()

    if not private_key and iface.path and os.path.isfile(iface.path):
        try:
            with open(iface.path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip().lower().startswith('privatekey'):
                        private_key = line.split('=', 1)[1].strip()
                        break
        except Exception:
            private_key = ''

    if not private_key:
        _run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
        raise RuntimeError(f"Missing private key for interface {dev}")

    key_file = None
    try:
        fd, key_file = tempfile.mkstemp(prefix=f'{dev}_key_', text=True)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(private_key + '\n')
        os.chmod(key_file, 0o600)

        listen_port = int(getattr(iface, 'listen_port', 0) or 0)
        if not (1 <= listen_port <= 65535):
            listen_port = 51820

        c = ['wg', 'set', dev, 'private-key', key_file, 'listen-port', str(listen_port)]
        rc2, out2 = _run_capture(c, timeout=10.0)
        _iface_log(iid, f"$ wg set {dev} private-key <hidden> listen-port {listen_port}\n{out2}".rstrip())
        if rc2 != 0:
            _run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
            raise RuntimeError(f"Could not configure WireGuard interface {dev}: {out2.strip() or 'wg set failed'}")
    finally:
        if key_file:
            try:
                os.remove(key_file)
            except Exception:
                pass

    # Add interface address.
    address = (getattr(iface, 'address', None) or '').strip()

    if not address and iface.path and os.path.isfile(iface.path):
        try:
            with open(iface.path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip().lower().startswith('address'):
                        address = line.split('=', 1)[1].strip()
                        break
        except Exception:
            address = ''

    if address:
        for addr in [x.strip() for x in address.split(',') if x.strip()]:
            c = ['ip', 'address', 'add', addr, 'dev', dev]
            rc3, out3 = _run_capture(c, timeout=6.0)
            _iface_log(iid, f"$ {' '.join(c)}\n{out3}".rstrip())

            if rc3 != 0 and 'File exists' not in out3:
                _run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
                raise RuntimeError(f"Could not add address {addr} to {dev}: {out3.strip() or 'ip address add failed'}")

    # Optional MTU.
    mtu = getattr(iface, 'mtu', None)
    try:
        mtu = int(mtu) if mtu not in (None, '') else None
    except Exception:
        mtu = None

    if mtu:
        c = ['ip', 'link', 'set', 'mtu', str(mtu), 'dev', dev]
        rc4, out4 = _run_capture(c, timeout=6.0)
        _iface_log(iid, f"$ {' '.join(c)}\n{out4}".rstrip())

    # Bring link up.
    c = ['ip', 'link', 'set', 'up', 'dev', dev]
    rc5, out5 = _run_capture(c, timeout=6.0)
    _iface_log(iid, f"$ {' '.join(c)}\n{out5}".rstrip())

    if rc5 != 0:
        _run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
        raise RuntimeError(f"Could not bring interface {dev} up: {out5.strip() or 'ip link set up failed'}")

    if not _iface_up(dev):
        _run_capture(['ip', 'link', 'del', 'dev', dev], timeout=6.0)
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

    for row in out:
        if row.get('ts'):
            row['time_display'] = _panel_display_datetime(
                row['ts'],
                seconds=True,
            )

    return jsonify({
        'logs': out,
        'display_timezone': _panel_timezone_name(),
        'server_epoch': now_ts(),
    })

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

def _token():
    return secrets.token_urlsafe(16)


def _shortlink_url(token):
    return url_for('user_peer_page', token=token, _external=True)


def _peer_from_shortlink_token(token):
    token = (token or "").strip()
    if not token:
        abort(404)

    link = ShortLink.query.filter_by(token=token).first()
    if not link:
        abort(404)

    try:
        link.last_used_at = datetime.utcnow()
        db.session.commit()
    except Exception:
        db.session.rollback()

    return db.session.get(Peer, link.peer_id) or abort(404)


def _delete_shortlinks_for_peer_ids(peer_ids):
    ids = []
    for x in peer_ids or []:
        try:
            ids.append(int(x))
        except Exception:
            pass

    if not ids:
        return 0

    removed = (
        ShortLink.query
        .filter(ShortLink.peer_id.in_(ids))
        .delete(synchronize_session=False)
    )
    db.session.flush()
    return int(removed or 0)

def _shortlink_from_peer_id(pid):
    """
    Return an existing DB shortlink for a peer id.
    Does not create a new link.
    Used by /api/peers list output.
    """
    try:
        pid = int(pid)
    except Exception:
        return None, None

    link = ShortLink.query.filter_by(peer_id=pid).first()
    if not link:
        return None, None

    return link.token, _shortlink_url(link.token)


def _shortlink_for_peer(peer: Peer):
    """
    Create or return an existing DB shortlink for a Peer row.
    """
    if not peer or not getattr(peer, "id", None):
        return None, None

    existing = ShortLink.query.filter_by(peer_id=peer.id).first()
    if existing:
        return existing.token, _shortlink_url(existing.token)

    token = None
    for _ in range(12):
        candidate = _token()
        if not ShortLink.query.filter_by(token=candidate).first():
            token = candidate
            break

    if not token:
        token = secrets.token_urlsafe(24)

    link = ShortLink(token=token, peer_id=peer.id)
    db.session.add(link)
    db.session.commit()

    return token, _shortlink_url(token)


def _shortlink_response_for_peer(peer: Peer):
    token, url = _shortlink_for_peer(peer)
    if not token or not url:
        abort(404)
    return jsonify(url=url, token=token)


@app.route('/api/peer/<int:pid>/shortlink', methods=['GET', 'POST'])
@require_api_key_or_login
def api_shortlink(pid):
    p = db.session.get(Peer, pid) or abort(404)
    return _shortlink_response_for_peer(p)

@app.route('/api/peer/<path:public_key>/shortlink', methods=['GET', 'POST'])
@require_api_key_or_login
def api_shortlink_by_public_key(public_key):
    public_key = (public_key or '').strip()
    if not public_key:
        abort(404)

    peer = Peer.query.filter_by(public_key=public_key).first()
    if not peer:
        abort(404)

    return _shortlink_response_for_peer(peer)

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
    requested_timezone = (
        data.get("timezone")
        if "timezone" in data
        else cur.get("timezone")
        )

    panel_timezone = _valid_timezone_name(
        requested_timezone
    )

    if not panel_timezone:
        return jsonify(
            ok=False,
            error="invalid_timezone",
            message=(
            "Timezone must be a valid "
            "IANA timezone such as "
            "Asia/Tehran or Europe/Amsterdam."
            ),
        ), 400

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
        "timezone": panel_timezone,
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

    return jsonify(ok=True, settings=payload, next_url=next_url, requires_restart=False)

@app.get("/api/timezone")
@require_api_key_or_login
def api_timezone():
    tz_name = _panel_timezone_name()
    tz = _panel_timezone()

    now_utc = datetime.now(
        timezone.utc
    )

    now_local = now_utc.astimezone(
        tz
    )

    return jsonify(
        ok=True,
        build="20260904-v9",
        timezone=tz_name,
        server_epoch=now_ts(),
        utc_now=now_utc.isoformat(
            timespec="seconds"
        ).replace(
            "+00:00",
            "Z",
        ),
        local_now=now_local.isoformat(
            timespec="seconds"
        ),
        utc_offset=now_local.strftime(
            "%z"
        ),
    )

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

    if dt.tzinfo is not None:
        dt = dt.astimezone(
            timezone.utc
        ).replace(
            tzinfo=None
        )

    ok = True

    if from_s:
        boundary = _panel_filter_datetime_utc_naive(
            from_s
        )

        if boundary is not None:
            ok = ok and dt >= boundary

    if to_s:
        boundary = _panel_filter_datetime_utc_naive(
            to_s
        )

        if boundary is not None:
            ok = ok and dt <= boundary

    return ok

ret = _load_retention()["tg_admin"]
_may_autoclear(Path(TELEGRAM_ADMIN_LOG_FILE), ret, persist_key="tg_admin")

@app.get('/api/telegram/admin_logs')
@login_required
def tg_admin_logs():
    tail = _read_tail(
        TELEGRAM_ADMIN_LOG_FILE,
        20000,
    )

    rows = []

    for line in tail.splitlines():
        try:
            row = json.loads(line)

            normalized = _utc_timestamp_iso(
                row.get('ts')
            )

            if normalized:
                row['ts'] = normalized
                row['time_display'] = _panel_display_datetime(
                    normalized,
                    seconds=True,
                )

            rows.append(row)

        except Exception:
            continue

    return jsonify({
        'logs': rows,
        'display_timezone': _panel_timezone_name(),
        'server_epoch': now_ts(),
    })

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
def user_peer_page(token):
    _peer_from_shortlink_token(token)

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
def user_peer(token):
    p = _peer_from_shortlink_token(token)
    _expire()

    total = _wg_transfer(p)
    used_total, _delta, usage_changed = _accumulate_peer_usage(p, total)
    if usage_changed:
        db.session.commit()
    used_live = 0
    exp_ts = _effective_expiry_ts(p)
    ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None
    used_db = int(getattr(p, 'used_bytes_total', 0) or 0)
    unit = getattr(p, 'data_limit_unit', 'Mi') or 'Mi'
    lim_val = int(getattr(p, 'data_limit_value', 0) or 0)
    lim_bytes = 0
    if lim_val and not getattr(p, 'unlimited', False):
        lim_bytes = lim_val * (1024*1024 if unit == 'Mi' else 1024*1024*1024)

    used_eff = used_db
    if lim_bytes:
        used_eff = min(used_eff, lim_bytes)

    if getattr(p, 'status', '') == 'blocked' and lim_bytes:
        used_eff = lim_bytes

    return jsonify({
    'name': p.name,
    'iface': p.iface.name,
    'address': p.address,
    'endpoint': _effective_client_endpoint(p),
    'peer_endpoint': getattr(p, 'peer_endpoint', None) or '',
    'status': p.status,
    'unlimited': bool(getattr(p, 'unlimited', False)),
    'limit_unit': unit,
    'data_limit': lim_val,
    'used_bytes': used_eff,
    'used_bytes_db': used_db,
    'used_effective_bytes': used_eff,
    'time_limit_days': getattr(p, 'time_limit_days', None),
    'display_timezone': _panel_timezone_name(),
    'start_on_first_use': bool(getattr(p, 'start_on_first_use', False)),
    'first_used_at': isoz(getattr(p, 'first_used_at', None)),
    'first_used_at_display': _panel_display_datetime(getattr(p, 'first_used_at', None)),
    'expires_at': isoz(from_ts(exp_ts)),
    'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
    'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
    'expires_at_ts': exp_ts,
    'ttl_seconds': ttl_seconds,
    'allowed_ips': p.allowed_ips or '0.0.0.0/0, ::/0',
    'dns': p.dns or p.iface.dns or '',
    'mtu': p.mtu or p.iface.mtu or None
    })

@app.route('/api/u/<token>/config')
def userpeer_config(token):
    p = _peer_from_shortlink_token(token)

    cfg = _client_conf_txt(p)

    safe_name = re.sub(
        r'[^A-Za-z0-9_.-]+',
        '_',
        p.name or f'peer-{p.id}',
    ).strip('._') or f'peer-{p.id}'

    mem = BytesIO(
        cfg.encode('utf-8')
    )

    response = send_file(
        mem,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'{safe_name}.conf',
        max_age=0,
    )

    response.headers[
        'X-Content-Type-Options'
    ] = 'nosniff'

    response.headers[
        'Cache-Control'
    ] = (
        'private, no-store, no-cache, '
        'must-revalidate, max-age=0'
    )

    return response

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


# ---------------------------
# Address allocation
# ---------------------------
MAX_ENUMERATED_HOSTS = 8192


class AddressAllocationError(Exception):
    """Base class for peer address allocation problems."""

    http_status = 400
    error_code = 'address_error'


class AddressInvalid(AddressAllocationError):

    http_status = 400
    error_code = 'invalid_address'


class AddressConflict(AddressAllocationError):

    http_status = 409
    error_code = 'address_conflict'


class AddressPoolExhausted(AddressConflict):

    error_code = 'address_pool_exhausted'


def _iface_is_node(iface) -> bool:
    name = getattr(iface, 'name', '') or ''
    return getattr(iface, 'node_id', None) is not None or (':' in name)


def interface_ip_interface(iface):

    if not iface:
        return None

    addr_field = None
    if not _iface_is_node(iface):
        addr_field = _read_iface_conf(getattr(iface, 'path', None))

    if not addr_field:
        addr_field = getattr(iface, 'address', None)

    cidr = _first_cidr(addr_field)
    if not cidr:
        return None

    if (not _iface_is_node(iface)) and addr_field and getattr(iface, 'address', None) != addr_field:
        try:
            iface.address = addr_field
            db.session.add(iface)
            db.session.commit()
        except Exception:
            db.session.rollback()

    try:
        return ipaddress.ip_interface(cidr)
    except ValueError:
        return None


def _usable_hosts(net):

    for index, host in enumerate(net.hosts()):
        if index >= MAX_ENUMERATED_HOSTS:
            return
        yield host


def _db_peer_hosts(iface, exclude_peer_id=None):

    hosts = set()
    iface_id = getattr(iface, 'id', None)
    if not iface_id:
        return hosts

    for address, address_host in db.session.query(Peer.address, Peer.address_host).filter(
        Peer.iface_id == iface_id,
        Peer.id != exclude_peer_id if exclude_peer_id else True,
    ):
        host = _safe_ip(address_host) or _safe_ip(address)
        if host is not None:
            hosts.add(host)

    return hosts


def _reserved_hosts(iface, ip_iface, *, exclude_peer_id=None, exclude_address=None, extra=()):

    net = ip_iface.network
    reserved = {ip_iface.ip}

    point_to_point = 31 if net.version == 4 else 127
    if net.prefixlen < point_to_point:
        reserved.add(net.network_address)
        if net.version == 4:
            reserved.add(net.broadcast_address)

    reserved |= _db_peer_hosts(iface, exclude_peer_id=exclude_peer_id)

    if not _iface_is_node(iface):
        reserved |= _wg_allowed_ips(iface)
        reserved |= _conf_allowed_ips(iface)

    for value in extra or ():
        host = _safe_ip(value)
        if host is not None:
            reserved.add(host)

    own_host = _safe_ip(exclude_address)
    if own_host is not None and own_host != ip_iface.ip:
        reserved.discard(own_host)

    return reserved


def _validate_requested_host(ip_iface, requested):
    text = str(requested or '').strip()
    if not text:
        return None

    try:
        candidate = ipaddress.ip_interface(text)
    except ValueError:
        raise AddressInvalid(f'{text} is not a valid IP address.')

    host = candidate.ip
    net = ip_iface.network

    if host.version != net.version:
        raise AddressInvalid(
            f'{host} is IPv{host.version} but the interface network is IPv{net.version}.'
        )

    if host not in net:
        raise AddressInvalid(f'{host} is outside the interface network {net}.')

    point_to_point = 31 if net.version == 4 else 127
    if net.prefixlen < point_to_point:
        if host == net.network_address:
            raise AddressInvalid(f'{host} is the network address of {net}.')
        if net.version == 4 and host == net.broadcast_address:
            raise AddressInvalid(f'{host} is the broadcast address of {net}.')

    return host


def allocate_peer_address(iface, requested=None, *, exclude_peer_id=None,
                          exclude_address=None, extra_reserved=()):

    ip_iface = interface_ip_interface(iface)
    if ip_iface is None:
        raise AddressInvalid(
            f'Interface {getattr(iface, "name", "?")} has no usable Address= setting.'
        )

    net = ip_iface.network
    reserved = _reserved_hosts(
        iface, ip_iface,
        exclude_peer_id=exclude_peer_id,
        exclude_address=exclude_address,
        extra=extra_reserved,
    )

    host = _validate_requested_host(ip_iface, requested)
    if host is not None:
        if host in reserved:
            raise AddressConflict(
                f'{host} is already in use on {getattr(iface, "name", "?")}.'
            )
        return f'{host}/{net.prefixlen}'

    for candidate in _usable_hosts(net):
        if candidate not in reserved:
            return f'{candidate}/{net.prefixlen}'

    raise AddressPoolExhausted(f'No free client address left in {net}.')


def address_error_response(exc: AddressAllocationError):
    return jsonify(error=exc.error_code, detail=str(exc)), exc.http_status


def client_address_on(iface, value):

    host = _safe_ip(value)
    if host is None:
        return None

    ip_iface = interface_ip_interface(iface)
    if ip_iface is None:
        return str(value).strip()

    return f'{host}/{ip_iface.network.prefixlen}'


class NodePeerInstallError(Exception):


    def __init__(self, code, status=502, detail='', message=None):
        super().__init__(message or code)
        self.code = code
        self.status = status
        self.detail = detail


def node_install_peer(node, iface_name, mirror, *, public_key, requested_address=None,
                      peer_endpoint='', keepalive=0, mtu=None, dns=None,
                      allowed_ips='0.0.0.0/0, ::/0', attempts=3):

    host_cidr = None
    if requested_address:
        # Raises AddressInvalid / AddressConflict, which the caller maps to 400/409.
        host_cidr = allocate_peer_address(mirror, requested=requested_address)

    last_error = None

    for attempt in range(max(1, attempts)):
        payload = {
            'iface': iface_name,
            'public_key': public_key,
            'endpoint': (peer_endpoint or '').strip(),
            'persistent_keepalive': keepalive or 0,
            'mtu': mtu,
            'dns': dns,
            'allowed_ips': allowed_ips,
        }
        if host_cidr:
            payload['host_cidr'] = host_cidr

        try:
            response = node_post(node, '/api/peers/add', payload) or {}
        except requests.HTTPError as e:
            status = getattr(getattr(e, 'response', None), 'status_code', 0)
            body = getattr(getattr(e, 'response', None), 'text', '') or ''
            agent_code = _node_agent_error_code(getattr(e, 'response', None))

            if (
                agent_code == 'address_pool_exhausted'
                or (status == 409 and not host_cidr and 'pool' in body)
            ):
                raise NodePeerInstallError(
                    'address_pool_exhausted', 409,
                    f'The node interface {iface_name} has no free client address.',
                )

            if requested_address and status in (400, 409):
                raise NodePeerInstallError(
                    'address_conflict', 409,
                    f'The requested address is not available on {iface_name}.',
                )

            needs_panel_side_address = (
                status == 400 and not host_cidr and 'host_cidr' in body
            )
            retryable_conflict = (
                agent_code == 'host_cidr_already_used'
                and not requested_address
                and attempt + 1 < attempts
            )

            if needs_panel_side_address or retryable_conflict:
                host_cidr = _node_pick_available_ip(node, iface_name, mirror)
                last_error = e
                continue

            raise NodePeerInstallError('node_create_failed', 502, body[:800] or str(e))
        except NodePeerInstallError:
            raise
        except AddressAllocationError:
            raise
        except Exception as e:
            raise NodePeerInstallError('node_create_failed', 502, str(e))

        assigned = ''
        if isinstance(response, dict):
            assigned = str(response.get('host_cidr') or '').strip()

        assigned = assigned or host_cidr
        if not assigned:
            raise NodePeerInstallError(
                'node_create_failed', 502,
                'The node did not report the address it assigned.'
            )

        address = client_address_on(mirror, assigned)
        if not address:
            raise NodePeerInstallError(
                'node_create_failed', 502, f'The node returned an unusable address {assigned!r}.'
            )
        return address

    raise NodePeerInstallError(
        'node_create_failed', 502,
        f'Could not reserve an address on {iface_name}: {last_error}'
    )


def node_reapply_peer(peer):
    iface = getattr(peer, 'iface', None)
    node = getattr(iface, 'node', None)
    if iface is None or node is None:
        raise NodePeerInstallError(
            'node_update_failed', 500, 'The peer node or interface is unavailable.'
        )

    payload = {
        'iface': iface_devname(iface),
        'public_key': peer.public_key,
        'host_cidr': _host_peer(peer),
        'endpoint': (getattr(peer, 'peer_endpoint', None) or '').strip(),
        'persistent_keepalive': getattr(peer, 'persistent_keepalive', None) or 0,
        'mtu': getattr(peer, 'mtu', None),
        'dns': getattr(peer, 'dns', None),
    }

    try:
        response = node_post(node, '/api/peers/add', payload) or {}
    except requests.HTTPError as exc:
        body = getattr(getattr(exc, 'response', None), 'text', '') or ''
        raise NodePeerInstallError('node_update_failed', 502, body[:800] or str(exc))
    except Exception as exc:
        raise NodePeerInstallError('node_update_failed', 502, str(exc))

    if isinstance(response, dict) and response.get('ok') is False:
        raise NodePeerInstallError(
            'node_update_failed', 502,
            str(response.get('detail') or response.get('error') or 'The node rejected the update.'),
        )

    if isinstance(response, dict) and response.get('duplicate') and response.get('updated') is not True:
        raise NodePeerInstallError(
            'node_update_unsupported', 502,
            'The node agent does not support full peer updates; update the node agent first.',
        )

    return response


def _node_agent_error_code(response):

    if response is None:
        return ''
    try:
        body = response.json()
    except Exception:
        return ''
    if isinstance(body, dict):
        return str(body.get('error') or '').strip().lower()
    return ''


def _node_pick_available_ip(node, iface_name, mirror):
    try:
        available = node_get(node, f'/api/iface/{iface_name}/available_ips')
        if isinstance(available, dict):
            available = available.get('available_ips') or []
        if isinstance(available, list) and available:
            return available[0]
    except Exception:
        current_app.logger.warning(
            'Could not read available_ips from node %s iface %s',
            getattr(node, 'id', '?'), iface_name, exc_info=True,
        )

    if mirror is not None:
        return allocate_peer_address(mirror)

    raise NodePeerInstallError('node_no_available_ip', 409, f'No free address on {iface_name}.')


def ensure_node_mirror_iface(node, iface_name, remote_iface=None, *, mtu=None, dns=None,
                             listen_port=None, server_cidr=None):
    remote_iface = remote_iface or {}
    db_iface_name = f'n{node.id}:{iface_name}'
    iface = InterfaceConfig.query.filter_by(name=db_iface_name).first()

    address = (remote_iface.get('address') or server_cidr or '').strip()

    try:
        port = int(remote_iface.get('listen_port') or listen_port or 51820)
    except Exception:
        port = 51820

    if not iface:
        iface = InterfaceConfig(
            name=db_iface_name,
            path=f'/etc/wireguard/{iface_name}.conf',
            address=address or '10.0.0.1/24',
            listen_port=port,
            private_key='(remote)',
            mtu=remote_iface.get('mtu') or mtu,
            dns=remote_iface.get('dns') or dns,
            node_id=node.id,
        )
        db.session.add(iface)
        db.session.flush()
        return iface

    changed = False
    if address and iface.address != address:
        iface.address = address
        changed = True
    if remote_iface.get('listen_port') and iface.listen_port != port:
        iface.listen_port = port
        changed = True
    if remote_iface.get('mtu') and iface.mtu != remote_iface.get('mtu'):
        iface.mtu = remote_iface.get('mtu')
        changed = True
    if remote_iface.get('dns') and iface.dns != remote_iface.get('dns'):
        iface.dns = remote_iface.get('dns')
        changed = True
    if getattr(iface, 'node_id', None) != node.id:
        iface.node_id = node.id
        changed = True

    if changed:
        db.session.flush()

    return iface


def resolve_requested_peer_address(iface, value, *, allow_legacy_interface_address=False):

    text = str(value or '').strip()
    if not text:
        return None

    try:
        candidate = ipaddress.ip_interface(text)
    except ValueError:
        raise AddressInvalid(f'{text} is not a valid IP address.')

    ip_iface = interface_ip_interface(iface)
    if (
        allow_legacy_interface_address
        and ip_iface is not None
        and candidate.ip == ip_iface.ip
    ):
        return None

    return text


def requested_peer_address_from_target(iface, target):
    explicit = str((target or {}).get('peer_address') or '').strip()
    if explicit:
        return resolve_requested_peer_address(iface, explicit)

    return resolve_requested_peer_address(
        iface,
        (target or {}).get('address'),
        allow_legacy_interface_address=True,
    )


def peer_address_host(address):
    host = _safe_ip(address)
    return str(host) if host is not None else None


@event.listens_for(Peer, 'before_insert')
@event.listens_for(Peer, 'before_update')
def _keep_peer_address_host_in_sync(mapper, connection, target):
  
    target.address_host = peer_address_host(target.address)


_ALLOC_LOCK_DIR = os.path.join(app.instance_path, 'locks')


@contextmanager
def interface_allocation_lock(iface):
 
    name = re.sub(r'[^A-Za-z0-9_.:-]+', '_', str(getattr(iface, 'name', '') or 'iface'))
    handle = None
    try:
        os.makedirs(_ALLOC_LOCK_DIR, exist_ok=True)
        handle = open(os.path.join(_ALLOC_LOCK_DIR, f'{name}.alloc.lock'), 'w')
        fcntl.flock(handle, fcntl.LOCK_EX)
    except Exception:
        current_app.logger.warning('Could not take allocation lock for %s', name, exc_info=True)
        handle = None

    try:
        yield
    finally:
        if handle is not None:
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            except Exception:
                pass
            handle.close()


def _available_ips(iface, limit=MAX_ENUMERATED_HOSTS):

    if not iface:
        return []

    try:
        ip_iface = interface_ip_interface(iface)
        if ip_iface is None:
            return []

        net = ip_iface.network
        reserved = _reserved_hosts(iface, ip_iface)

        out = []
        for host in _usable_hosts(net):
            if host in reserved:
                continue
            out.append(f'{host}/{net.prefixlen}')
            if len(out) >= limit:
                break
        return out

    except Exception as e:
        current_app.logger.exception(
            "_available_ips failed for iface=%r: %s", getattr(iface, "name", None), e
        )
        return []


def log_event(peer, event, details=''):
    e = PeerEvent(
        peer_id=peer.id,
        timestamp=from_ts(now_ts()),
        event=event,
        details=details,
    )
    db.session.add(e)
    db.session.commit()

def _conv_time_limit(payload):
    """Return the requested duration as fractional days.

    Browser forms send separate day/hour/minute components.  Older profiles
    can contain a fractional ``time_limit_days`` value *and* a separate hours
    value.  Adding both reproduces the old timezone-looking bug (for example a
    hidden two-hour fraction plus one entered hour becomes three hours).  When
    component fields are present, only the whole-day part of the day field is
    used.  API callers that send only ``time_limit_days`` may still send a
    fractional value.
    """
    try:
        raw_days = max(0.0, float(payload.get('time_limit_days') or 0))

        has_components = (
            'time_limit_hours' in payload
            or 'time_limit_minutes' in payload
        )

        days = float(int(raw_days)) if has_components else raw_days

        hours = max(
            0.0,
            min(
                23.0,
                float(
                    payload.get(
                        'time_limit_hours'
                    )
                    or 0
                ),
            ),
        )

        minutes = max(
            0.0,
            min(
                59.0,
                float(
                    payload.get(
                        'time_limit_minutes'
                    )
                    or 0
                ),
            ),
        )

        total_minutes = int(round(days * 1440.0 + hours * 60.0 + minutes))

        return (
            total_minutes / 1440.0
            if total_minutes > 0
            else None
        )

    except (TypeError, ValueError, OverflowError):
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


def _write_conf_atomic(conf_path: str, text_body: str):
    directory = os.path.dirname(conf_path) or '.'
    os.makedirs(directory, exist_ok=True)

    try:
        mode = os.stat(conf_path).st_mode & 0o777
    except OSError:
        mode = 0o600

    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix='.wgconf.', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text_body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, conf_path)
        tmp_path = None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _peer_to_conf(peer: Peer):
    conf_path = getattr(peer.iface, 'path', None)
    if not conf_path:
        raise RuntimeError('The interface has no configuration file path.')

    if _peer_in_conf(conf_path, peer.public_key):
        return

    block_lines = [
        '[Peer]',
        f'PublicKey = {peer.public_key}',
        f'AllowedIPs = {_host_peer(peer)}',
    ]

    fixed_endpoint = (getattr(peer, 'peer_endpoint', None) or '').strip()
    if fixed_endpoint:
        block_lines.append(f'Endpoint = {fixed_endpoint}')
    if peer.persistent_keepalive:
        block_lines.append(f'PersistentKeepalive = {peer.persistent_keepalive}')

    block_txt = '\n'.join(block_lines) + '\n'

    existing = ''
    if os.path.isfile(conf_path):
        with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
            existing = f.read()

    existing = (existing or '').replace('\r\n', '\n').replace('\r', '\n').rstrip('\n')
    combined = block_txt if existing.strip() == '' else existing + '\n\n' + block_txt

    _write_conf_atomic(conf_path, _norm_conftext(combined))

    if not _peer_in_conf(conf_path, peer.public_key):
        raise RuntimeError(f'Peer block was not persisted to {conf_path}.')


def _remove_peer(peer: Peer):

    conf_path = getattr(peer.iface, 'path', None)
    if not conf_path:
        return
    if not os.path.isfile(conf_path):
        return

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

    _write_conf_atomic(conf_path, _norm_conftext(''.join(out_lines)))

    if _peer_in_conf(conf_path, peer.public_key):
        raise RuntimeError(f'Peer block is still present in {conf_path}.')


def _sync_peer(peer: Peer):
    _remove_peer(peer)
    _peer_to_conf(peer)


def _wg_disable_quiet(peer: Peer):
    try:
        _wg_disable(peer)
    except Exception:
        current_app.logger.warning(
            "Could not roll back runtime peer %s on %s",
            getattr(peer, 'public_key', '?'),
            getattr(getattr(peer, 'iface', None), 'name', '?'),
            exc_info=True,
        )


def _remove_peer_quiet(peer: Peer):
    try:
        _remove_peer(peer)
    except Exception:
        current_app.logger.warning(
            "Could not roll back config peer %s",
            getattr(peer, 'public_key', '?'),
            exc_info=True,
        )


def _rollback_local_created_peer(peer: Peer):
    errors = []
    dev = iface_devname(peer.iface) if getattr(peer, 'iface', None) else ''
    if dev and _iface_up(dev):
        try:
            _wg_disable(peer)
            if peer.public_key in _wg_peer_keys(dev):
                raise RuntimeError(f'{peer.public_key} is still present in {dev}.')
        except Exception as exc:
            errors.append(f'runtime: {exc}')

    try:
        _remove_peer(peer)
    except Exception as exc:
        errors.append(f'config: {exc}')

    if errors:
        raise RuntimeError('; '.join(errors))


def _rollback_node_created_peer(node, public_key):
    response = node_delete(node, f'/api/peer/{public_key}') or {}
    if isinstance(response, dict) and response.get('ok') is False:
        raise RuntimeError(
            str(response.get('detail') or response.get('error') or 'node cleanup failed')
        )


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


class PeerRemovalError(Exception):

    def __init__(self, phase, message, status=500):
        super().__init__(message)
        self.phase = phase
        self.status = status


def _peer_is_on_node(peer: Peer) -> bool:
    iface = getattr(peer, 'iface', None)
    if iface is None:
        return False
    return _iface_is_node(iface)


def reapply_peer_external(peer: Peer):
    if _peer_is_on_node(peer):
        node_reapply_peer(peer)
        return

    _wg_enable(peer)
    _sync_peer(peer)


def remove_peer_everywhere(peer: Peer):

    if _peer_is_on_node(peer):
        _remove_node_peer(peer)
    else:
        _remove_local_peer_runtime_and_config(peer)

    return _delete_peer_rows(peer)


def _remove_local_peer_runtime_and_config(peer: Peer):
    dev = iface_devname(peer.iface) if getattr(peer, 'iface', None) else ''

    if dev and _iface_up(dev):
        try:
            _wg_disable(peer)
        except Exception as e:
            raise PeerRemovalError('runtime', str(e), 502)

        if peer.public_key in _wg_peer_keys(dev):
            raise PeerRemovalError(
                'runtime',
                f'{peer.public_key} is still present in the {dev} runtime.',
                502,
            )

    try:
        _remove_peer(peer)
    except Exception as e:
        raise PeerRemovalError('config', str(e), 500)


def _remove_node_peer(peer: Peer):
    node = getattr(getattr(peer, 'iface', None), 'node', None)
    if node is None:
        raise PeerRemovalError('node', 'The node for this peer is unknown.', 500)

    try:
        response = node_delete(node, f'/api/peer/{peer.public_key}') or {}
    except Exception as e:
        raise PeerRemovalError('node', str(e), 502)

    if not isinstance(response, dict):
        return

    if response.get('ok') is False:
        raise PeerRemovalError(
            'node', str(response.get('error') or 'The node reported a failure.'), 502
        )

    for key, phase in (('runtime_removed', 'runtime'), ('config_removed', 'config')):
        if key in response and not response.get(key):
            raise PeerRemovalError(
                phase,
                f'The node did not confirm {phase} removal of {peer.public_key}.',
                502,
            )


def _wg_peer_keys(dev: str) -> set:
    keys = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', dev, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
    except Exception:
        return keys

    for line in out.splitlines():
        key = line.split('\t', 1)[0].strip()
        if key:
            keys.add(key)
    return keys


def _delete_peer_rows(peer: Peer):

    try:
        removed_shortlinks = _delete_shortlinks_for_peer_ids([peer.id])
        SubscriptionPeer.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
        PeerEvent.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
        db.session.delete(peer)
        db.session.commit()
        return int(removed_shortlinks or 0)
    except Exception as e:
        db.session.rollback()
        raise PeerRemovalError('database', str(e), 500)


def peer_removal_response(exc: PeerRemovalError, peer_id=None):
    return jsonify(
        ok=False,
        error='peer_removal_failed',
        phase=exc.phase,
        detail=str(exc),
        peer_id=peer_id,
        recoverable=True,
    ), exc.status


def install_local_peer(peer: Peer):

    _check_iface_up(peer.iface)
    _wg_enable(peer)

    try:
        _sync_peer(peer)
    except Exception:
        _wg_disable_quiet(peer)
        raise

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

def _valid_timezone_name(value: str) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None

    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(value)
        return value
    except Exception:
        return None


def _detect_system_timezone_name() -> str:

    try:
        backup_file = globals().get("BACKUP_SCHEDULE_FILE")
        if backup_file and os.path.isfile(backup_file):
            data = _json_load(backup_file, {})
            candidate = _valid_timezone_name(
                data.get("timezone")
            )
            if candidate:
                return candidate
    except Exception:
        pass

    try:
        with open(
            "/etc/timezone",
            "r",
            encoding="utf-8",
        ) as timezone_file:
            candidate = _valid_timezone_name(
                timezone_file.read().strip()
            )
            if candidate:
                return candidate
    except Exception:
        pass

    try:
        target = os.path.realpath(
            "/etc/localtime"
        )

        marker = "/zoneinfo/"

        if marker in target:
            candidate = _valid_timezone_name(
                target.split(
                    marker,
                    1,
                )[1]
            )

            if candidate:
                return candidate
    except Exception:
        pass

    try:
        tzinfo = (
            datetime.now()
            .astimezone()
            .tzinfo
        )

        candidate = _valid_timezone_name(
            getattr(
                tzinfo,
                "key",
                "",
            )
        )

        if candidate:
            return candidate
    except Exception:
        pass

    return "UTC"


def _panel_timezone_name() -> str:
    """
    Single timezone source for the whole panel.
    """
    try:
        settings = _load_panel_settings() or {}

        candidate = _valid_timezone_name(
            settings.get("timezone")
        )

        if candidate:
            return candidate
    except Exception:
        pass

    return _detect_system_timezone_name()


def _panel_timezone():
    from zoneinfo import ZoneInfo

    try:
        return ZoneInfo(
            _panel_timezone_name()
        )
    except Exception:
        return ZoneInfo("UTC")


def _panel_local_datetime(value):

    parsed = _tg_parse_datetime(
        value
    )

    if parsed is None:
        return None

    return parsed.astimezone(
        _panel_timezone()
    )


def _panel_display_datetime(value, *, seconds=False):
    """Format one UTC instant in the saved panel timezone on the server.

    Browser code receives this alongside the epoch value.  Human-facing panel
    screens prefer this field, so a browser/HTML cache cannot silently replace
    Asia/Tehran with the device timezone.
    """
    local_value = _panel_local_datetime(value)
    if local_value is None:
        return None
    return local_value.strftime(
        '%Y-%m-%d %H:%M:%S' if seconds else '%Y-%m-%d %H:%M'
    )

def _panel_filename_stamp(value=None):
    """human timestamp in the panel timezone."""
    parsed = _tg_parse_datetime(
        value if value is not None else datetime.now(timezone.utc)
    )
    if parsed is None:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(_panel_timezone()).strftime('%Y%m%d_%H%M%S')


def _utc_timestamp_iso(value):
    """Return a canonical UTC API instant without changing stored data."""
    parsed = _tg_parse_datetime(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(
        timespec='seconds'
    ).replace('+00:00', 'Z')


def _panel_filter_datetime_utc_naive(value):
    """Convert an API filter value to a naive UTC datetime for comparison.
    """
    if value in (None, ''):
        return None

    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            parsed = datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
        else:
            raw = str(value).strip()

            if not raw:
                return None

            if re.fullmatch(r'\d+(?:\.\d+)?', raw):
                parsed = datetime.fromtimestamp(
                    float(raw),
                    tz=timezone.utc,
                )
            else:
                if raw.endswith('Z'):
                    raw = raw[:-1] + '+00:00'

                parsed = datetime.fromisoformat(raw)

    except Exception:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=_panel_timezone()
        )

    return parsed.astimezone(
        timezone.utc
    ).replace(
        tzinfo=None
    )

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

    timezone_name = _valid_timezone_name(
    j.get("timezone")
)

    if not timezone_name:
        timezone_name = (_detect_system_timezone_name())

    return {"tls_enabled": bool(j.get("tls_enabled",False,)),

        "domain": (j.get("domain")or "").strip(),

        "force_https_redirect": bool(j.get("force_https_redirect",False,)),

        "hsts": bool(j.get("hsts",False,)),

        "http_port": _port(j.get("http_port"),None,),

        "https_port": _port(j.get("https_port"),443,),

        "tls_cert_path": (j.get("tls_cert_path")or "").strip(),

        "tls_key_path": (j.get("tls_key_path")or "").strip(),

        "timezone": timezone_name,
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

def _node_endpoint_fallback(
    node,
    iface_name: str,
    remote_iface=None,
    interfaces_payload=None,
) -> str:

    remote_iface = (
        remote_iface
        if isinstance(remote_iface, dict)
        else {}
    )

    interfaces_payload = (
        interfaces_payload
        if isinstance(interfaces_payload, dict)
        else {}
    )

    host = str(
        interfaces_payload.get('public_ipv4') or ''
    ).strip()

    if not host:
        try:
            health = node_get(
                node,
                '/api/health',
                timeout=6,
            ) or {}

            if isinstance(health, dict):
                host = str(
                    health.get('public_ipv4') or ''
                ).strip()

        except Exception:
            host = ''

    if not host:
        try:
            parsed = urlparse(
                (
                    getattr(node, 'base_url', '')
                    or ''
                ).strip()
            )

            host = (
                parsed.hostname
                or ''
            ).strip()

        except Exception:
            host = ''

    try:
        port = int(
            remote_iface.get('listen_port') or 0
        )
    except Exception:
        port = 0

    if not port and iface_name:
        try:
            data = node_get(
                node,
                '/api/interfaces',
                timeout=10,
            ) or {}

            rows = (
                data.get('interfaces', [])
                if isinstance(data, dict)
                else data
            )

            for row in rows or []:
                if str(
                    (row or {}).get('name') or ''
                ) == str(iface_name):

                    port = int(
                        (row or {}).get('listen_port')
                        or 0
                    )
                    break

        except Exception:
            port = 0

    if not host or not port:
        return ''

    return _norm_hostport(host, port)

class EndpointValidationError(ValueError):
    """A rejected endpoint override. ``code`` is the API error code."""

    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code
        self.detail = detail


_DNS_LABEL_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
_HOST_FORBIDDEN = ('://', '/', '@', '?', '#', '\\')


def _parse_endpoint_host(value):
    """Return a normalised host, or raise EndpointValidationError."""
    if any(ch.isspace() for ch in value):
        raise EndpointValidationError(
            'endpoint_host_whitespace',
            'The host may not contain whitespace.',
        )

    for token in _HOST_FORBIDDEN:
        if token in value:
            raise EndpointValidationError(
                'endpoint_host_not_a_host',
                'The host must be a bare name or IP address, without a scheme, '
                'path, credentials or query string.',
            )

    bracketed = value.startswith('[') and value.endswith(']')
    candidate = value[1:-1] if bracketed else value

    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    if bracketed:
        raise EndpointValidationError(
            'endpoint_host_invalid',
            'Bracketed hosts must be valid IPv6 addresses.',
        )

    if ':' in candidate:
        raise EndpointValidationError(
            'endpoint_host_has_port',
            'Put the port in the port field; the host must not contain one.',
        )

    name = candidate[:-1] if candidate.endswith('.') else candidate

    if not name or len(name) > 253:
        raise EndpointValidationError(
            'endpoint_host_invalid',
            'The host must be between 1 and 253 characters long.',
        )

    for label in name.split('.'):
        if not _DNS_LABEL_RE.match(label):
            raise EndpointValidationError(
                'endpoint_host_invalid',
                'Each DNS label must be 1 to 63 letters, digits or hyphens, and '
                'may not start or end with a hyphen.',
            )

    return name.lower()


def _parse_endpoint_port(value):
    """Return a port in 1..65535, or raise EndpointValidationError."""
    if isinstance(value, bool):
        raise EndpointValidationError(
            'endpoint_port_invalid', 'The port must be a whole number.'
        )

    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise EndpointValidationError(
            'endpoint_port_invalid', 'The port must be a whole number.'
        )

    if not 1 <= port <= 65535:
        raise EndpointValidationError(
            'endpoint_port_range', 'The port must be between 1 and 65535.'
        )

    return port


def parse_endpoint_override(host, port):

    host_raw = '' if host is None else str(host).strip()
    port_raw = '' if port is None else str(port).strip()

    if not host_raw and not port_raw:
        return (None, None)

    if not host_raw or not port_raw:
        raise EndpointValidationError(
            'endpoint_partial',
            'Send host and port together, or send both empty to clear the override.',
        )

    return (_parse_endpoint_host(host_raw), _parse_endpoint_port(port_raw))


def parse_endpoint_string(value):

    text_value = (value or '').strip()
    if not text_value:
        return ''

    host, port = _host_port(text_value)
    if not host or not port:
        raise EndpointValidationError(
            'endpoint_invalid',
            'The endpoint must be host:port, for example vpn.example.com:51820.',
        )

    host, port = parse_endpoint_override(host, port)
    return _norm_hostport(host, port)


def remote_iface_name(iface):
    """'wg0' from a node mirror row named 'n3:wg0'; the plain name otherwise."""
    name = (getattr(iface, 'name', '') or '').strip()
    return name.split(':', 1)[1] if ':' in name else name


def iface_endpoint_override(iface):
    """The interface's saved client endpoint override, or '' when unset."""
    if iface is None:
        return ''

    host = (getattr(iface, 'endpoint_host', None) or '').strip()
    port = getattr(iface, 'endpoint_port', None)

    if not host or not port:
        if host or port:

            current_app.logger.warning(
                'Interface %s has an incomplete endpoint override '
                '(host=%r port=%r); ignoring it.',
                getattr(iface, 'name', '?'), host, port,
            )
        return ''

    return _norm_hostport(host, int(port))


def resolve_client_endpoint(iface, explicit=None, *, node=None, remote_iface=None):

    explicit = (explicit or '').strip()
    if explicit:
        return explicit

    if iface is None:
        return ''

    override = iface_endpoint_override(iface)
    if override:

        return override

    try:
        if getattr(iface, 'node_id', None) is not None:
            return (_node_endpoint_fallback(
                node or getattr(iface, 'node', None),
                remote_iface_name(iface),
                remote_iface,
            ) or '').strip()

        return (_endpoint_fallback(iface) or '').strip()

    except Exception:
        current_app.logger.warning(
            'Endpoint auto-detection failed for interface %s',
            getattr(iface, 'name', '?'), exc_info=True,
        )
        return ''


def resolve_client_endpoint_cheap(iface, explicit=None):

    explicit = (explicit or '').strip()
    if explicit:
        return explicit

    if iface is None:
        return ''

    override = iface_endpoint_override(iface)
    if override:
        return override

    if getattr(iface, 'node_id', None) is not None:
        return ''

    try:
        return (_endpoint_fallback(iface) or '').strip()
    except Exception:
        current_app.logger.warning(
            'Endpoint auto-detection failed for interface %s',
            getattr(iface, 'name', '?'), exc_info=True,
        )
        return ''


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

# ------------------------------------------------------------
# Node peer config / QR export
# ------------------------------------------------------------
def _node_peer_by_publickey(nid: int, pub: str):
    pub = (pub or "").strip()

    if not pub:
        abort(404)

    q = (
        db.session.query(Peer)
        .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
        .filter(or_(
            InterfaceConfig.name.like(f"n{nid}:%"),
            InterfaceConfig.node_id == nid
        ))
    )

    if pub.isdigit():
        peer = q.filter(Peer.id == int(pub)).first()
    else:
        peer = q.filter(Peer.public_key == pub).first()

    if not peer:
        abort(404)

    return peer


@app.get("/api/nodes/<int:nid>/peer/<path:pub>/config")
@csrf.exempt
@require_api_key_or_login
def node_peer_config(nid, pub):
    peer = _node_peer_by_publickey(nid, pub)

    text = _client_conf_txt(peer)

    if request.args.get("download"):
        resp = make_response(text)
        fname = f"{peer.name or 'peer'}-{peer.id}.conf".replace(" ", "_")
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
        return resp

    return current_app.response_class(
        text,
        mimetype="text/plain; charset=utf-8"
    )


@app.get("/api/nodes/<int:nid>/peer/<path:pub>/config_qr")
@csrf.exempt
@require_api_key_or_login
def node_peer_config_qr(nid, pub):
    peer = _node_peer_by_publickey(nid, pub)

    text = _client_conf_txt(peer)

    if not text:
        abort(404)

    img = qrcode.make(text)
    bio = BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)

    return send_file(
        bio,
        mimetype="image/png",
        as_attachment=False,
        download_name=f"{peer.name or 'peer'}-{peer.id}.png",
    )

@app.route('/api/nodes/<int:nid>/peer/<path:pub>/shortlink', methods=['GET', 'POST'])
@require_api_key_or_login
def node_peer_shortlink(nid, pub):
    pub = (pub or '').strip()

    if not pub:
        abort(404)

    peer = (
        db.session.query(Peer)
        .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
        .filter(Peer.public_key == pub)
        .filter(or_(
            InterfaceConfig.name.like(f"n{nid}:%"),
            InterfaceConfig.node_id == nid
        ))
        .first()
    )

    if not peer:
        abort(404)

    return _shortlink_response_for_peer(peer)

# ------------------------------------------------------------
# Node peer logs
# ------------------------------------------------------------
@app.route('/api/nodes/<int:nid>/peer/<path:pub>/logs', methods=['GET', 'DELETE'])
@require_api_key_or_login
def node_peer_logs(nid, pub):
    pub = (pub or '').strip()

    if not pub:
        abort(404)

    peer = (
        db.session.query(Peer)
        .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
        .filter(Peer.public_key == pub)
        .filter(or_(
            InterfaceConfig.name.like(f"n{nid}:%"),
            InterfaceConfig.node_id == nid
        ))
        .first()
    )

    if not peer:
        abort(404)

    if request.method == 'DELETE':
        try:
            cnt = PeerEvent.query.filter_by(peer_id=peer.id).delete(
                synchronize_session=False
            )
            db.session.commit()

            try:
                logpanel_action(
                    "node_peer_logs_clear",
                    f"node={nid}; pid={peer.id}; deleted={int(cnt or 0)}"
                )
            except Exception:
                pass

            return jsonify(ok=True, deleted=int(cnt or 0))

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Failed to clear node peer logs")
            return jsonify(ok=False, error="clear_failed", detail=str(e)), 500

    try:
        rows = (
            PeerEvent.query
            .filter_by(peer_id=peer.id)
            .order_by(PeerEvent.timestamp.desc())
            .limit(500)
            .all()
        )

        logs = []
        for e in reversed(rows):
            ts = getattr(e, 'timestamp', None)
            event = getattr(e, 'event', '') or ''
            details = getattr(e, 'details', '') or ''

            logs.append({
                'time': isoz(ts) if ts else '',
                'ts': isoz(ts) if ts else '',
                'level': 'info',
                'event': event,
                'details': details,
                'text': f"{event}: {details}".strip(': ')
            })

        return jsonify(logs=logs)

    except Exception as e:
        current_app.logger.exception("Node peer logs failed")
        return jsonify(ok=False, error="logs_failed", detail=str(e)), 500

@app.route('/api/nodes/<int:nid>/peer/<path:pub>', methods=['DELETE'])
@admin_required
def node_peer_delete(nid, pub):
    n = Node.query.get_or_404(nid)

    p = (
        db.session.query(Peer)
        .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
        .filter(Peer.public_key == pub)
        .filter(or_(
            InterfaceConfig.name.like(f"n{nid}:%"),
            InterfaceConfig.node_id == nid
        ))
        .first()
    )

    if p is None:
        # No panel row: still ask the node to clean up, then report idempotently.
        try:
            node_delete(n, f'/api/peer/{pub}')
        except Exception as e:
            current_app.logger.exception("Node peer delete failed")
            return jsonify(error="node_delete_failed", detail=str(e)), 502
        return jsonify(ok=True, shortlinks_removed=0)

    peer_id = p.id
    try:
        removed_shortlinks = remove_peer_everywhere(p)
    except PeerRemovalError as e:
        current_app.logger.error(
            "node peer delete failed at %s stage for node_id=%s pub=%s: %s", e.phase, nid, pub, e
        )
        return peer_removal_response(e, peer_id=peer_id)

    return jsonify(ok=True, shortlinks_removed=removed_shortlinks)

def _effective_client_endpoint(peer: Peer) -> str:

    return resolve_client_endpoint(
        getattr(peer, 'iface', None),
        explicit=getattr(peer, 'endpoint', None),
    )


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

    ep = _effective_client_endpoint(peer)

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

def _client_config_txt(peer: Peer) -> str:
    return _client_conf_txt(peer)

# ------------------------------------------------------------------
# Config / QR fallback by public key
# ------------------------------------------------------------------
def _peer_by_public_key_or_404(public_key: str):
    public_key = (public_key or "").strip()

    if not public_key:
        abort(404)

    if public_key.isdigit():
        peer = db.session.get(Peer, int(public_key))
    else:
        peer = Peer.query.filter_by(public_key=public_key).first()

    if not peer:
        abort(404)

    return peer


@app.get("/api/peer/<path:public_key>/config")
@csrf.exempt
@require_api_key_or_login
def api_peer_config_by_public_key(public_key):
    peer = _peer_by_public_key_or_404(public_key)

    cfg = _client_conf_txt(peer)

    if not cfg or not cfg.strip():
        return jsonify(
            ok=False,
            error="config_empty",
            message="The peer configuration is empty.",
        ), 404

    safe_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        peer.name or f"peer-{peer.id}",
    ).strip("._") or f"peer-{peer.id}"

    response = make_response(cfg.strip() + "\n", 200)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = (
        "private, no-store, no-cache, must-revalidate, max-age=0"
    )

    if request.args.get("download") == "1":
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{safe_name}.conf"'
        )

    return response


@app.get("/api/peer/<path:public_key>/config_qr")
@csrf.exempt
@require_api_key_or_login
def api_peer_config_qr_by_public_key(public_key):
    peer = _peer_by_public_key_or_404(public_key)

    cfg = _client_conf_txt(peer)

    if not cfg or not cfg.strip():
        return jsonify(
            ok=False,
            error="config_empty",
            message="The peer configuration is empty.",
        ), 404

    safe_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        peer.name or f"peer-{peer.id}",
    ).strip("._") or f"peer-{peer.id}"

    img = qrcode.make(cfg)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    response = send_file(
        buf,
        mimetype="image/png",
        as_attachment=False,
        download_name=f"{safe_name}.png",
        max_age=0,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = (
        "private, no-store, no-cache, must-revalidate, max-age=0"
    )
    return response
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

    # Queue Telegram messages commit succeeds
    pending_notifications = []

    for peer in Peer.query.all():

        should_track_first_use = True

        if (
            should_track_first_use
            and not getattr(
                peer,
                'first_used_at',
                None,
            )
        ):
            hs = _latest_handshake(
                peer
            )

            if hs and hs > 0:
                peer.first_used_at = from_ts(
                    hs
                )
                peer.timer_started_at = from_ts(hs)

                if (
                    getattr(
                        peer,
                        'start_on_first_use',
                        False,
                    )
                    and getattr(
                        peer,
                        'time_limit_days',
                        None,
                    )
                    and not getattr(
                        peer,
                        'unlimited',
                        False,
                    )
                ):
                    first_use_expiry_ts = add_days_ts(
                        hs,
                        float(
                            peer.time_limit_days
                        ),
                    )

                    peer.expires_at = from_ts(first_use_expiry_ts)

                log_event(
                    peer,
                    'first_use',
                    (
                        'First WireGuard '
                        'handshake recorded'
                    ),
                )

                changed = True

        if (
            not getattr(
                peer,
                'start_on_first_use',
                False,
            )
            and getattr(
                peer,
                'time_limit_days',
                None,
            )
            and not getattr(
                peer,
                'expires_at',
                None,
            )
            and not getattr(
                peer,
                'unlimited',
                False,
            )
        ):
            if not getattr(peer, 'timer_started_at', None):
                peer.timer_started_at = (
                    getattr(peer, 'created_at', None)
                    or from_ts(now)
                )
            _sync_effective_expiry(peer)

            changed = True

        interface = getattr(
            peer,
            'iface',
            None,
        )

        is_node = bool(
            getattr(
                interface,
                'node_id',
                None,
            )
            is not None
        )

        total_bytes = None

        if not is_node:
            total_bytes = _wg_transfer(
                peer
            )

            (
                used_effective,
                _delta,
                usage_changed,
            ) = _accumulate_peer_usage(
                peer,
                total_bytes,
            )

            if usage_changed:
                changed = True

        else:
            used_effective = int(
                getattr(
                    peer,
                    'used_bytes_total',
                    0,
                )
                or 0
            )

        # -----------
        # Time-limit 
        # -----------

        # Enforce the same derived value returned to every UI/API consumer.
        expiry_ts = _effective_expiry_ts(peer)
        if to_ts(getattr(peer, 'expires_at', None)) != expiry_ts:
            peer.expires_at = from_ts(expiry_ts)
            changed = True

        if (
            expiry_ts
            and now >= expiry_ts
            and peer.status != 'blocked'
        ):
            disabled = _disable_peer(
                peer,
                'expired',
                status='blocked',
            )

            log_event(
                peer,
                'expired',
                (
                    'Expired at '
                    f'{isoz(from_ts(expiry_ts))}'
                ),
            )

            if disabled:
                peer_name = (
                    getattr(
                        peer,
                        'name',
                        None,
                    )
                    or getattr(
                        peer,
                        'friendly_name',
                        None,
                    )
                    or f'Peer {peer.id}'
                )

                interface_name = (
                    getattr(
                        interface,
                        'name',
                        None,
                    )
                    or ''
                )

                node_name = ''

                if is_node:
                    node = getattr(
                        interface,
                        'node',
                        None,
                    )

                    node_name = (
                        getattr(
                            node,
                            'name',
                            None,
                        )
                        or ''
                    )

                pending_notifications.append({
                'event_key': 'peer_expired',
                'title': 'Peer expired',
                'status': 'Disabled',
 
                'details': [('Peer',f'{peer_name} · ID {peer.id}',),
                ('Location',node_name or 'Local panel',),
                ('Interface',interface_name,),
                ('Address',getattr(peer,'address','',) or '',),
                ('Phone',getattr(peer,'phone_number','',) or '',),
                ('Telegram',getattr(peer,'telegram_id','',) or '',),
                ('Active since',_tg_human_datetime(getattr(peer,'first_used_at',None,)),),
                ('Expired at',_tg_human_datetime(from_ts(expiry_ts)),),],

                'dedupe_key': (f'peer-expired:{peer.id}'),
                'dedupe_seconds': 0,})

            changed = True

        # --------------
        # Traffic-limit 
        # --------------

        limit_bytes = (
            peer.limit_bytes()
            if hasattr(
                peer,
                'limit_bytes',
            )
            else None
        )

        if (
            limit_bytes is not None
            and peer.status != 'blocked'
            and used_effective >= limit_bytes
        ):
            if not is_node:
                if total_bytes is None:
                    total_bytes = _wg_transfer(
                        peer
                    )

                _accumulate_peer_usage(
                    peer,
                    total_bytes,
                )

            disabled = _disable_peer(
                peer,
                'limit_reached',
                status='blocked',
            )

            log_event(
                peer,
                'limit_reached',
                (
                    f'Used {used_effective} bytes'
                ),
            )

            if disabled:
                peer_name = (
                    getattr(
                        peer,
                        'name',
                        None,
                    )
                    or getattr(
                        peer,
                        'friendly_name',
                        None,
                    )
                    or f'Peer {peer.id}'
                )

                interface_name = (
                    getattr(
                        interface,
                        'name',
                        None,
                    )
                    or ''
                )

                node_name = ''

                if is_node:
                    node = getattr(
                        interface,
                        'node',
                        None,
                    )

                    node_name = (
                        getattr(
                            node,
                            'name',
                            None,
                        )
                        or ''
                    )

                pending_notifications.append({
                'event_key': 'peer_limit',
                'title': 'Peer traffic limit reached',
                'status': 'Disabled',

                'details': [('Peer',f'{peer_name} · ID {peer.id}',),
                ('Location',node_name or 'Local panel',),
                ('Interface',interface_name,),
                ('Address',getattr(peer,'address','',) or '',),
                ('Phone',getattr(peer,'phone_number','',) or '',),
                ('Telegram',getattr(peer,'telegram_id','',) or '',),
                ('Usage',_tg_human_bytes(used_effective),),
                ('Data limit',_tg_human_bytes(limit_bytes),),
                ('Active since',_tg_human_datetime(getattr(peer,'first_used_at',None,)),),],

                'dedupe_key': (f'peer-limit:{peer.id}'),
                'dedupe_seconds': 0,})
            changed = True

    if not changed:
        return

    try:
        db.session.commit()

    except Exception:
        db.session.rollback()

        app.logger.exception(
            'Peer expiry and limit enforcement '
            'could not be committed'
        )

        return

    # Send only after the database state is safely committed.
    for notification in pending_notifications:
        try:
            _send_telegram_event(
                notification['event_key'],
                notification['title'],
                status=notification.get(
                    'status',
                    '',
                ),
                details=notification.get(
                    'details',
                    [],
                ),
                dedupe_key=notification.get(
                    'dedupe_key',
                    '',
                ),
                dedupe_seconds=int(
                    notification.get(
                        'dedupe_seconds',
                        60,
                    )
                ),
            )

        except Exception:
            app.logger.exception(
                'Could not queue Telegram peer '
                'enforcement notification: %s',
                notification.get(
                    'event_key',
                ),
            )

_EXPIRY_THREAD_STARTED = False
_EXPIRY_LOCK = threading.Lock()
_EXPIRY_LAST_TS = 0.0

try:
    _EXPIRY_INTERVAL_SEC = max(5, int(os.getenv('WG_EXPIRY_INTERVAL_SEC', '15')))
except Exception:
    _EXPIRY_INTERVAL_SEC = 15


def _run_expiry_once(source: str = 'manual') -> bool:
    """Run peer expiry/limit enforcement once, safely and non-overlapping."""
    if not _EXPIRY_LOCK.acquire(blocking=False):
        return False

    try:
        _expire()
        return True

    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass

        try:
            current_app.logger.exception(
                'Expiry enforcement failed (%s): %s',
                source,
                exc
            )
        except Exception:
            pass

        return False

    finally:
        try:
            _EXPIRY_LOCK.release()
        except Exception:
            pass


def _expiry_enforcer_loop():
    while True:
        try:
            with app.app_context():
                _run_expiry_once('background')
        except Exception:
            pass

        time.sleep(_EXPIRY_INTERVAL_SEC)


def _start_expiry_enforcer():
    """Start background expiry enforcement once per process/worker."""
    global _EXPIRY_THREAD_STARTED

    if _EXPIRY_THREAD_STARTED:
        return

    _EXPIRY_THREAD_STARTED = True

    t = threading.Thread(
        target=_expiry_enforcer_loop,
        name='peer-expiry-enforcer',
        daemon=True,
    )
    t.start()


@app.before_request
def _expiry_tick_on_requests():
    """
    Fallback : any panel/API activity can enforce expiry,
    not only the Peers tab.
    """
    global _EXPIRY_LAST_TS

    try:
        if (request.path or '').startswith('/static/'):
            return

        now = time.time()
        if (now - _EXPIRY_LAST_TS) < _EXPIRY_INTERVAL_SEC:
            return

        _EXPIRY_LAST_TS = now
        _run_expiry_once('request')

    except Exception:
        pass

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

        override = iface_endpoint_override(getattr(p, 'iface', None))
        if override and (p.endpoint or '').strip() == override:
            continue

        host, port = _host_port(p.endpoint or '')
        if host == prev:
            p.endpoint = f"{cur}:{port}" if port else cur
            changed += 1
    if changed:
        db.session.commit()
        current_app.logger.info("Repointed %s peer endpoints from %s to %s", changed, prev, cur)

    _write_lastip(cur)


_TIME_REPAIR_BACKUP = os.path.join(
    app.instance_path,
    'wg_panel.db.pre-time-fix-v5.bak',
)


def _latest_peer_timer_event_ts(peer_id, event_names, *, details_needles=()):
    """Return the newest canonical UTC timestamp for a timer-anchor event."""
    try:
        rows = (
            PeerEvent.query
            .filter(PeerEvent.peer_id == int(peer_id))
            .filter(PeerEvent.event.in_(tuple(event_names)))
            .order_by(PeerEvent.timestamp.desc())
            .limit(20)
            .all()
        )
    except Exception:
        return None

    for row in rows:
        if details_needles:
            details = str(getattr(row, 'details', '') or '').lower()
            if not any(needle in details for needle in details_needles):
                continue
        timestamp = to_ts(getattr(row, 'timestamp', None))
        if timestamp:
            return timestamp
    return None


def _assign_repaired_expiry(record, expected_ts):
    current_ts = to_ts(getattr(record, 'expires_at', None))
    if expected_ts is None:
        if current_ts is None:
            return False
        record.expires_at = None
        return True

    expected_ts = int(expected_ts)
    if current_ts is not None and abs(int(current_ts) - expected_ts) <= 2:
        return False

    record.expires_at = from_ts(expected_ts)
    return True


def _repair_legacy_timer_rows():
    """Repair old peer/subscription expiries without applying a timezone shift.

    Timezones change presentation only.  A timer is reconstructed from its
    canonical UTC anchor plus its exact duration.  Reset/enable audit events
    are used as the anchor when a timer was intentionally restarted.
    """
    repaired_peers = 0
    repaired_subscriptions = 0

    # Preserve the original database before the first automatic repair.
    try:
        if (
            os.path.isfile(DB_PATH)
            and not os.path.exists(_TIME_REPAIR_BACKUP)
        ):
            shutil.copy2(DB_PATH, _TIME_REPAIR_BACKUP)
    except Exception:
        app.logger.warning(
            'Could not create pre-time-fix database backup',
            exc_info=True,
        )

    for peer in Peer.query.order_by(Peer.id.asc()).all():
        if list(getattr(peer, 'subscription_links', []) or []):
            continue

        try:
            duration_days = float(getattr(peer, 'time_limit_days', 0) or 0)
        except (TypeError, ValueError, OverflowError):
            duration_days = 0.0

        expected_ts = None
        anchor_ts = None
        if not bool(getattr(peer, 'unlimited', False)) and duration_days > 0:
            if bool(getattr(peer, 'start_on_first_use', False)):
                anchor_ts = to_ts(getattr(peer, 'first_used_at', None))
            else:
                anchor_ts = to_ts(getattr(peer, 'created_at', None))

                restarted_ts = _latest_peer_timer_event_ts(
                    peer.id,
                    ('enabled', 'reset_timer'),
                )
                edited_ts = _latest_peer_timer_event_ts(
                    peer.id,
                    ('edited',),
                    details_needles=(
                        'time_limit_days',
                        'start_on_first_use',
                        'unlimited',
                    ),
                )
                anchor_ts = max(
                    [value for value in (anchor_ts, restarted_ts, edited_ts) if value]
                    or [0]
                ) or None

            expected_ts = add_days_ts(anchor_ts, duration_days)

        if to_ts(getattr(peer, 'timer_started_at', None)) != anchor_ts:
            peer.timer_started_at = from_ts(anchor_ts)
            repaired_peers += 1

        if _assign_repaired_expiry(peer, expected_ts):
            repaired_peers += 1

        if (
            expected_ts
            and expected_ts <= now_ts()
            and str(getattr(peer, 'status', '') or '') == 'blocked'
        ):
            latest_expired = (
                PeerEvent.query
                .filter_by(peer_id=peer.id, event='expired')
                .order_by(PeerEvent.timestamp.desc())
                .first()
            )
            if (
                latest_expired
                and (to_ts(getattr(latest_expired, 'timestamp', None)) or 0)
                >= int(anchor_ts or 0)
            ):
                corrected_detail = f'Expired at {isoz(from_ts(expected_ts))}'
                if str(latest_expired.details or '') != corrected_detail:
                    latest_expired.details = corrected_detail
                    repaired_peers += 1

    for sub in Subscription.query.order_by(Subscription.id.asc()).all():
        try:
            duration_days = float(getattr(sub, 'time_limit_days', 0) or 0)
        except (TypeError, ValueError, OverflowError):
            duration_days = 0.0

        expected_ts = None
        anchor_ts = None
        if not bool(getattr(sub, 'unlimited', False)) and duration_days > 0:
            if bool(getattr(sub, 'start_on_first_use', False)):
                anchor_ts = to_ts(getattr(sub, 'first_used_at', None))
            else:
                anchor_ts = to_ts(getattr(sub, 'created_at', None))
                peer_ids = [
                    int(link.peer_id)
                    for link in (getattr(sub, 'links', []) or [])
                    if getattr(link, 'peer_id', None)
                ]
                if peer_ids:
                    reset_event = (
                        PeerEvent.query
                        .filter(PeerEvent.peer_id.in_(peer_ids))
                        .filter(PeerEvent.event == 'subscription_reset_timer')
                        .order_by(PeerEvent.timestamp.desc())
                        .first()
                    )
                    reset_ts = to_ts(
                        getattr(reset_event, 'timestamp', None)
                    ) if reset_event else None
                    if reset_ts:
                        anchor_ts = max(anchor_ts or 0, reset_ts)

            expected_ts = add_days_ts(anchor_ts, duration_days)

        if to_ts(getattr(sub, 'timer_started_at', None)) != anchor_ts:
            sub.timer_started_at = from_ts(anchor_ts)
            repaired_subscriptions += 1

        if _assign_repaired_expiry(sub, expected_ts):
            repaired_subscriptions += 1

        for link in (getattr(sub, 'links', []) or []):
            peer = getattr(link, 'peer', None)
            if not peer:
                continue
            peer_changed = False
            desired_days = duration_days or None
            desired_start = bool(getattr(sub, 'start_on_first_use', False))
            desired_unlimited = bool(getattr(sub, 'unlimited', False))
            desired_first_used = getattr(sub, 'first_used_at', None)
            desired_timer_started = getattr(sub, 'timer_started_at', None)

            if getattr(peer, 'time_limit_days', None) != desired_days:
                peer.time_limit_days = desired_days
                peer_changed = True
            if bool(getattr(peer, 'start_on_first_use', False)) != desired_start:
                peer.start_on_first_use = desired_start
                peer_changed = True
            if bool(getattr(peer, 'unlimited', False)) != desired_unlimited:
                peer.unlimited = desired_unlimited
                peer_changed = True
            if to_ts(getattr(peer, 'first_used_at', None)) != to_ts(desired_first_used):
                peer.first_used_at = desired_first_used
                peer_changed = True
            if to_ts(getattr(peer, 'timer_started_at', None)) != to_ts(desired_timer_started):
                peer.timer_started_at = desired_timer_started
                peer_changed = True
            if _assign_repaired_expiry(peer, expected_ts):
                peer_changed = True

            if peer_changed:
                repaired_peers += 1

    if repaired_peers or repaired_subscriptions:
        db.session.commit()
        app.logger.warning(
            'Canonical UTC timer repair completed: peers=%s subscriptions=%s',
            repaired_peers,
            repaired_subscriptions,
        )
    else:
        db.session.rollback()

    return {
        'peers': repaired_peers,
        'subscriptions': repaired_subscriptions,
    }

# -----------
# Bootstrap
# ___________
def _migrate_schema():
    try:
        db.create_all()
        _admin_columns()
        _peer_schema()
        _interface_schema()
        _shortlink_schema()
        _repair_legacy_timer_rows()
    except Exception as exc:
        raise SchemaMigrationError(str(exc)) from exc

    app.logger.info("DB initialized / migrated OK")


def bootstrap():
    with app.app_context():
        _migrate_schema()
        from models import InterfaceConfig
        firewall_summary = (
            local_firewall_rules()
        )
        app.logger.info("Legacy local firewall migration: %s",firewall_summary,)
        p = (
            app.config.get("WG_CONF_PATH")
            or app.config.get(
                "WIREGUARD_CONF_PATH"
            )
            or "/etc/wireguard")

        paths = (
            glob.glob(os.path.join(p,"*.conf",))
            if os.path.isdir(p)
            else (
                [p]
                if os.path.isfile(p)
                else []
            )
        )
        for conf in paths:
            parsed = find_iface(conf)
            if not parsed:
                continue
            name = os.path.splitext(os.path.basename(conf))[0]
            existing = (InterfaceConfig.query.filter_by(name=name).first())
            if not existing:
                db.session.add(parsed)
                continue
            existing.path = parsed.path
            existing.address = parsed.address
            existing.listen_port = (
                parsed.listen_port
            )
            existing.private_key = (
                parsed.private_key
            )
            existing.mtu = parsed.mtu
            existing.dns = parsed.dns
            existing.post_up = parsed.post_up
            existing.post_down = parsed.post_down
        db.session.commit()


        _on_boot()
        _run_expiry_once('boot')
        _start_expiry_enforcer()
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

def node_delete(n: Node, path: str, payload=None, timeout=8):
    headers = {
        'Authorization': f'Bearer {_read_api_key(n)}'
    }

    kwargs = {
        'headers': headers,
        'timeout': timeout,
    }

    if payload is not None:
        headers['Content-Type'] = 'application/json'
        kwargs['json'] = payload

    r = requests.delete(f"{n.base_url}{path}", **kwargs)
    r.raise_for_status()
    return r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text

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

def _peer_ip_plain(peer) -> str:
    try:
        return str(ipaddress.ip_interface(peer.address).ip)
    except Exception:
        return ''


def _peer_ping_ok(peer, timeout_sec: float = 0.8) -> bool:

    ip = _peer_ip_plain(peer)
    if not ip:
        return False

    try:
        dev = iface_devname(peer.iface)
    except Exception:
        dev = getattr(getattr(peer, 'iface', None), 'name', '') or ''

    if not dev:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            cmd = ['ping', '-6', '-I', dev, '-c', '1', '-W', '1', ip]
        else:
            cmd = ['ping', '-I', dev, '-c', '1', '-W', '1', ip]

        return subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, float(timeout_sec) + 0.5)
        ).returncode == 0
    except Exception:
        return False


def _peer_conn_status(
    peer,
    *,
    live_total: int | None = None,
    latest_handshake: int | None = None,
    handshake_window: int | None = None,
    allow_probe: bool = True,
) -> dict:
    """
    Determine the peer's live WireGuard connection state.

    Parameters:
        peer:
            Peer database object.

        live_total:
            Current RX + TX WireGuard counter.

        latest_handshake:
            Latest handshake from Wireguard snapshot.

        handshake_window:
            Maximum handshake age

        allow_probe:
            When True, an enabled peer may be actively pinged.
            Automatic peer-list refresh must pass False so it doesn't launch ping process

    """
    now = now_ts()

    try:
        if handshake_window is None:
            handshake_window = int(
                os.environ.get(
                    'WG_ONLINE_HANDSHAKE_WINDOW',
                    '45',
                )
            )
        else:
            handshake_window = int(handshake_window)
    except (TypeError, ValueError):
        handshake_window = 45

    handshake_window = max(5, handshake_window)

    probe_first = str(
        os.environ.get(
            'WG_ONLINE_PROBE_FIRST',
            '1',
        )
    ).strip().lower() not in (
        '0',
        'false',
        'no',
        'off',
    )

    handshake_fallback = str(
        os.environ.get(
            'WG_ONLINE_HANDSHAKE_FALLBACK',
            '1',
        )
    ).strip().lower() in (
        '1',
        'true',
        'yes',
        'on',
    )

    try:
        if latest_handshake is None:
            handshake = int(
                _latest_handshake(peer) or 0
            )
        else:
            handshake = int(
                latest_handshake or 0
            )
    except (TypeError, ValueError):
        handshake = 0
    except Exception:
        current_app.logger.debug(
            "Could not read handshake for peer %s",
            getattr(peer, 'id', '?'),
            exc_info=True,
        )
        handshake = 0

    handshake = max(0, handshake)

    handshake_age = (
        max(0, now - handshake)
        if handshake > 0
        else None
    )

    handshake_fresh = bool(
        handshake > 0
        and handshake_age is not None
        and handshake_age <= handshake_window
    )

    try:
        if live_total is None:
            live = int(
                _wg_transfer(peer) or 0
            )
        else:
            live = int(
                live_total or 0
            )
    except (TypeError, ValueError):
        live = 0
    except Exception:
        current_app.logger.debug(
            "Could not read live transfer counter for peer %s",
            getattr(peer, 'id', '?'),
            exc_info=True,
        )
        live = 0

    live = max(0, live)

    try:
        offset = int(
            getattr(peer, 'bytes_offset', 0) or 0
        )
    except (TypeError, ValueError):
        offset = 0

    offset = max(0, offset)

    traffic_now = live > offset

    panel_status = str(
        getattr(peer, 'status', '') or ''
    ).strip().lower()

    panel_enabled = panel_status == 'online'
    panel_blocked = panel_status == 'blocked'

    ping_ok = False
    probed = False

    if (
        allow_probe
        and panel_enabled
        and probe_first
    ):
        probed = True

        try:
            ping_ok = bool(
                _peer_ping_ok(peer)
            )
        except Exception:
            ping_ok = False

        if ping_ok:
            online = True
            reason = 'probe'

        elif handshake_fallback and handshake_fresh:
            online = True
            reason = 'handshake'

        elif traffic_now:
            online = True
            reason = 'traffic'

        else:
            online = False
            reason = 'probe_failed'

    else:
        if panel_blocked:
            online = False
            reason = 'blocked'

        elif handshake_fresh:
            online = True
            reason = 'handshake'

        elif traffic_now:
            online = True
            reason = 'traffic'

        elif not panel_enabled:
            online = False
            reason = 'disabled'

        else:
            online = False
            reason = 'no_recent_activity'

    connection_status = (
        'online'
        if online
        else 'offline'
    )

    return {
        'conn_status': connection_status,
        'connection_status': connection_status,

        'latest_handshake': handshake,
        'latest_handshake_age': handshake_age,

        'conn_reason': reason,
        'conn_probe': bool(probed),
        'probe_ok': bool(ping_ok),

        'traffic_now': bool(traffic_now),
        'live_total': int(live),

        'handshake_fresh': bool(handshake_fresh),
        'handshake_window': int(handshake_window),
    }

def _wg_transfer_bytes(peer):
    rx, tx = _wg_rx_tx(peer)
    return rx + tx


@app.route(
    '/api/nodes/<int:nid>/interfaces',
    methods=['GET', 'POST'],
)
@require_api_key_or_login
def node_ifaces(nid):
    node = db.session.get(Node, nid)

    if not node:
        return jsonify(
            ok=False,
            error='node_not_found',
            detail=f'Node {nid} was not found.',
        ), 404

    if request.method == 'POST':
        payload = request.get_json(
            silent=True,
        ) or {}

        if not isinstance(payload, dict):
            return jsonify(
                ok=False,
                error='invalid_payload',
                detail='The request body must be a JSON object.',
            ), 400

        requested_name = str(
            payload.get('name')
            or payload.get('iface')
            or ''
        ).strip()

        if not requested_name:
            return jsonify(
                ok=False,
                error='interface_name_required',
                detail='Interface name is required.',
            ), 400

        try:
            created = node_post(
                node,
                '/api/interfaces/create',
                payload,
                timeout=30,
            )

        except requests.HTTPError as exc:
            response = getattr(
                exc,
                'response',
                None,
            )

            status_code = getattr(
                response,
                'status_code',
                None,
            )

            response_text = str(
                getattr(
                    response,
                    'text',
                    '',
                )
                or ''
            ).strip()

            current_app.logger.exception(
                (
                    'Node interface creation failed: '
                    'node_id=%s interface=%s '
                    'upstream_status=%s'
                ),
                nid,
                requested_name,
                status_code,
            )

            return jsonify(
                ok=False,
                error='node_interface_create_failed',
                detail=(
                    response_text[:1200]
                    or str(exc)
                ),
                node_id=nid,
                node_name=node.name,
                interface=requested_name,
                upstream_status=status_code,
            ), 502

        except requests.RequestException as exc:
            current_app.logger.exception(
                (
                    'Node interface creation connection failed: '
                    'node_id=%s interface=%s'
                ),
                nid,
                requested_name,
            )

            return jsonify(
                ok=False,
                error='node_unreachable',
                detail=str(exc),
                node_id=nid,
                node_name=node.name,
                interface=requested_name,
            ), 502

        except Exception as exc:
            current_app.logger.exception(
                (
                    'Unexpected node interface creation failure: '
                    'node_id=%s interface=%s'
                ),
                nid,
                requested_name,
            )

            return jsonify(
                ok=False,
                error='node_interface_create_failed',
                detail=str(exc),
                node_id=nid,
                node_name=node.name,
                interface=requested_name,
            ), 500

        created_iface = None

        if isinstance(created, dict):
            candidate = (
                created.get('interface')
                or created.get('iface')
                or created
            )

            if isinstance(candidate, dict):
                created_iface = candidate

        if not isinstance(created_iface, dict):
            created_iface = {}

        iface_name = str(
            created_iface.get('name')
            or created_iface.get('iface')
            or requested_name
        ).strip()

        if not iface_name:
            return jsonify(
                ok=False,
                error='node_interface_create_invalid_response',
                detail=(
                    'The node reported success but did not return '
                    'an interface name.'
                ),
                result=created,
            ), 502

        address = str(
            created_iface.get('address')
            or created_iface.get('server_cidr')
            or payload.get('address')
            or payload.get('server_cidr')
            or '10.0.0.1/24'
        ).strip()

        try:
            listen_port = int(
                created_iface.get('listen_port')
                or payload.get('listen_port')
                or 51820
            )
        except (TypeError, ValueError):
            listen_port = 51820

        if not 1 <= listen_port <= 65535:
            listen_port = 51820

        mtu = (
            created_iface.get('mtu')
            if created_iface.get('mtu') not in (None, '')
            else payload.get('mtu')
        )

        try:
            mtu = (
                int(mtu)
                if mtu not in (None, '')
                else None
            )
        except (TypeError, ValueError):
            mtu = None

        dns = str(
            created_iface.get('dns')
            or payload.get('dns')
            or ''
        ).strip() or None

        db_iface_name = f'n{nid}:{iface_name}'

        try:
            iface = (
                InterfaceConfig.query
                .filter_by(
                    name=db_iface_name,
                )
                .first()
            )

            if not iface:
                iface = (
                    InterfaceConfig.query
                    .filter_by(
                        node_id=node.id,
                        name=iface_name,
                    )
                    .first()
                )

            if not iface:
                iface = InterfaceConfig(
                    name=db_iface_name,
                    path=f'/etc/wireguard/{iface_name}.conf',
                    address=address,
                    listen_port=listen_port,
                    private_key='(remote)',
                    mtu=mtu,
                    dns=dns,
                )

                try:
                    iface.node_id = node.id
                except Exception:
                    pass

                db.session.add(iface)

            else:
                iface.name = db_iface_name
                iface.path = (
                    created_iface.get('path')
                    or f'/etc/wireguard/{iface_name}.conf'
                )
                iface.address = address
                iface.listen_port = listen_port
                iface.mtu = mtu
                iface.dns = dns

                if not getattr(
                    iface,
                    'private_key',
                    None,
                ):
                    iface.private_key = '(remote)'

                try:
                    iface.node_id = node.id
                except Exception:
                    pass

            db.session.commit()

        except Exception as exc:
            db.session.rollback()

            current_app.logger.exception(
                (
                    'Remote interface was created but local '
                    'database synchronization failed: '
                    'node_id=%s interface=%s'
                ),
                nid,
                iface_name,
            )

            return jsonify(
                ok=False,
                error='node_interface_created_db_sync_failed',
                detail=str(exc),
                node_id=nid,
                interface=iface_name,
                remote_result=created,
            ), 500

        response_body = (
            dict(created)
            if isinstance(created, dict)
            else {
                'result': created,
            }
        )

        response_body.update({
            'ok': True,
            'interface_name': iface_name,
            'db_interface_name': db_iface_name,
            'node_id': nid,
        })

        return jsonify(
            response_body
        ), 201

    try:
        data = node_get(
            node,
            '/api/interfaces',
            timeout=15,
        ) or {}

    except requests.HTTPError as exc:
        response = getattr(
            exc,
            'response',
            None,
        )

        status_code = getattr(
            response,
            'status_code',
            None,
        )

        response_text = str(
            getattr(
                response,
                'text',
                '',
            )
            or ''
        ).strip()

        current_app.logger.exception(
            (
                'Node interface list failed: '
                'node_id=%s node=%s upstream_status=%s'
            ),
            nid,
            node.name,
            status_code,
        )

        return jsonify(
            ok=False,
            error='node_interfaces_failed',
            detail=(
                response_text[:1200]
                or str(exc)
            ),
            node_id=nid,
            node_name=node.name,
            upstream_status=status_code,
        ), 502

    except requests.RequestException as exc:
        current_app.logger.exception(
            (
                'Could not connect to node interface API: '
                'node_id=%s node=%s'
            ),
            nid,
            node.name,
        )

        return jsonify(
            ok=False,
            error='node_unreachable',
            detail=str(exc),
            node_id=nid,
            node_name=node.name,
        ), 502

    except Exception as exc:
        current_app.logger.exception(
            (
                'Unexpected node interface list failure: '
                'node_id=%s node=%s'
            ),
            nid,
            node.name,
        )

        return jsonify(
            ok=False,
            error='node_interfaces_failed',
            detail=str(exc),
            node_id=nid,
            node_name=node.name,
        ), 500

    if isinstance(data, dict):
        base = (
            data.get('interfaces')
            or []
        )

        node_scope_networks = (
            data.get('scope_networks')
            or []
        )

        remote_public_ipv4 = str(
            data.get('public_ipv4')
            or ''
        ).strip()

    elif isinstance(data, list):
        base = data
        node_scope_networks = []
        remote_public_ipv4 = ''

    else:
        base = []
        node_scope_networks = []
        remote_public_ipv4 = ''

    if not isinstance(base, list):
        current_app.logger.warning(
            (
                'Node interface API returned an invalid '
                'interfaces value: node_id=%s type=%s'
            ),
            nid,
            type(base).__name__,
        )

        base = []

    if not isinstance(
        node_scope_networks,
        list,
    ):
        node_scope_networks = [
            value.strip()
            for value in str(
                node_scope_networks
                or ''
            ).split(',')
            if value.strip()
        ]

    node_scope_networks = list(
        dict.fromkeys(
            str(value).strip()
            for value in node_scope_networks
            if str(value).strip()
        )
    )

    interfaces = []

    for raw_item in base:
        if not isinstance(
            raw_item,
            dict,
        ):
            continue

        item = dict(
            raw_item
        )

        name = str(
            item.get('name')
            or item.get('iface')
            or ''
        ).strip()

        if not name:
            continue

        item_scope_networks = (
            item.get('scope_networks')
            or node_scope_networks
            or []
        )

        if not isinstance(
            item_scope_networks,
            list,
        ):
            item_scope_networks = [
                value.strip()
                for value in str(
                    item_scope_networks
                    or ''
                ).split(',')
                if value.strip()
            ]

        item_scope_networks = list(
            dict.fromkeys(
                str(value).strip()
                for value in item_scope_networks
                if str(value).strip()
            )
        )

        interface_address = str(
            item.get('address')
            or item.get('server_cidr')
            or item.get('interface_address')
            or ''
        ).strip()

        item.update({
            'name': name,
            'iface': name,
            'address': interface_address,
            'server_cidr': interface_address,
            'scope_networks': item_scope_networks,
        })

        mirror = InterfaceConfig.query.filter_by(name=f'n{nid}:{name}').first()

        if mirror is not None:

            override = iface_endpoint_override(mirror)
            host = (getattr(mirror, 'endpoint_host', None) or '').strip() or None
            port = getattr(mirror, 'endpoint_port', None)

            item.update({
                'endpoint_host': host,
                'endpoint_port': int(port) if port else None,
                'endpoint_override': override,
                'auto_endpoint': '',
                'effective_endpoint': override,
                'endpoint_source': 'override' if override else 'auto',
            })
        else:

            item.update({
                'endpoint_host': None,
                'endpoint_port': None,
                'endpoint_override': '',
                'auto_endpoint': '',
                'effective_endpoint': '',
                'endpoint_source': 'auto',
            })

        try:
            available_result = node_get(
                node,
                (
                    f'/api/iface/'
                    f'{name}/available_ips'
                ),
                timeout=8,
            ) or {}

            if isinstance(
                available_result,
                dict,
            ):
                available_ips = (
                    available_result.get(
                        'available_ips',
                        [],
                    )
                    or []
                )
            else:
                available_ips = []

            item['available_ips'] = (
                available_ips
                if isinstance(
                    available_ips,
                    list,
                )
                else []
            )

        except Exception as exc:
            current_app.logger.debug(
                (
                    'Could not load available IPs for '
                    'node_id=%s interface=%s: %s'
                ),
                nid,
                name,
                exc,
            )

            item['available_ips'] = []

        interfaces.append(
            item
        )

    public_ipv4 = remote_public_ipv4

    if not public_ipv4:
        try:
            health = node_get(
                node,
                '/api/health',
                timeout=6,
            ) or {}

            if isinstance(
                health,
                dict,
            ):
                public_ipv4 = str(
                    health.get('public_ipv4')
                    or ''
                ).strip()

        except Exception:
            public_ipv4 = ''

    if not public_ipv4:
        try:
            parsed_node_url = urlparse(
                str(
                    getattr(
                        node,
                        'base_url',
                        '',
                    )
                    or ''
                ).strip()
            )

            public_ipv4 = str(
                parsed_node_url.hostname
                or ''
            ).strip()

        except Exception:
            public_ipv4 = ''

    return jsonify(
        ok=True,
        node_id=nid,
        node_name=node.name,
        interfaces=interfaces,
        public_ipv4=public_ipv4,
        scope_networks=node_scope_networks,
    )

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

@app.route('/api/nodes/<int:nid>/iface/<name>', methods=['DELETE'])
@login_required
def node_iface_delete(nid, name):
    n = Node.query.get_or_404(nid)
    data = request.get_json(silent=True) or {}
    delete_peers = _sub_bool(
        data.get('delete_peers')
        if 'delete_peers' in data
        else request.args.get('delete_peers')
    )

    try:
        res = node_delete(
            n,
            f'/api/iface/{name}',
            payload={'delete_peers': bool(delete_peers), 'force': bool(delete_peers)},
            timeout=30
        )
    except requests.HTTPError as e:
        body = getattr(e.response, 'text', '') if getattr(e, 'response', None) else ''
        code = getattr(getattr(e, 'response', None), 'status_code', None)
        try:
            j = e.response.json()
        except Exception:
            j = {}

        if code == 409:
            return jsonify(j or {
                'error': 'interface_has_peers',
                'detail': body[:800] if body else ''
            }), 409

        current_app.logger.exception("Node interface delete failed")
        return jsonify(
            error='node_interface_delete_failed',
            detail=str(e),
            status=code,
            body=body[:800] if body else ''
        ), 502
    except Exception as e:
        current_app.logger.exception("Node interface delete failed")
        return jsonify(error='node_interface_delete_failed', detail=str(e)), 502

    db_iface_names = [
        f'n{nid}:{name}',
        name,
    ]

    q = InterfaceConfig.query.filter(
        or_(
            InterfaceConfig.name.in_(db_iface_names),
            and_(InterfaceConfig.node_id == nid, InterfaceConfig.name == name)
        )
    )

    iface = q.first()
    deleted_local_peers = 0
    subscription_link_count = 0
    affected_subs = set()

    try:
        if iface:
            peers = Peer.query.filter_by(iface_id=iface.id).all()
            deleted_local_peers = len(peers)
            peer_ids = [p.id for p in peers]

            if peer_ids:
                try:
                    _delete_shortlinks_for_peer_ids(peer_ids)
                except Exception:
                    current_app.logger.exception(
                        "shortlink cleanup failed during node interface delete"
                    )

                links = SubscriptionPeer.query.filter(
                    SubscriptionPeer.peer_id.in_(peer_ids)
                ).all()

                subscription_link_count = len(links)

                for link in links:
                    if link.subscription:
                        affected_subs.add(link.subscription)

                SubscriptionPeer.query.filter(
                    SubscriptionPeer.peer_id.in_(peer_ids)
                ).delete(synchronize_session=False)

            for p in peers:
                try:
                    db.session.delete(p)
                except Exception:
                    pass

            db.session.delete(iface)
            db.session.flush()

            for sub in affected_subs:
                try:
                    _sync_all_subscription_peers(sub, rename=True)
                except Exception:
                    current_app.logger.exception(
                        "Failed to sync subscription after node interface delete: %s",
                        getattr(sub, 'id', '?')
                    )

            db.session.commit()

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to clean local DB after node interface delete")
        return jsonify(
            error='node_interface_deleted_but_db_cleanup_failed',
            detail=str(e),
            node_result=res
        ), 500

    try:
        logpanel_action(
            "node_interface_delete",
            f"node={nid}; iface={name}; delete_peers={bool(delete_peers)}; peers={deleted_local_peers}"
        )
    except Exception:
        pass

    return jsonify(
        ok=True,
        node_result=res,
        deleted_interface=name,
        deleted_local_peers=deleted_local_peers,
        subscription_link_count=subscription_link_count
    )

@app.route('/api/iface/<int:iid>', methods=['GET', 'POST'])
@login_required
def iface_settings(iid):
    iface = db.session.get(InterfaceConfig, iid) or abort(404)

    if (
        getattr(iface, 'node_id', None) is not None
        or ':' in (getattr(iface, 'name', '') or '')
    ):
        return jsonify(
            ok=False,
            error='remote_interface',
            detail=(
                'This interface belongs to a remote node. '
                'Use the node interface API instead.'
            ),
        ), 400

    dev = iface_devname(iface)

    if request.method == 'GET':
        return jsonify(
            ok=True,
            id=iface.id,
            name=iface.name,
            path=iface.path,
            address=iface.address,
            listen_port=iface.listen_port,
            dns=iface.dns,
            mtu=iface.mtu,
            is_up=_iface_up(dev),
            **{
                k: v for k, v in _endpoint_default_payload(iface).items()
                if k not in ('iface_id', 'iface', 'listen_port', 'scope')
            },
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(
            ok=False,
            error='invalid_payload',
            detail='The request body must be a JSON object.',
        ), 400

    def optional_int(value, field, minimum, maximum):

        if value is None:
            return None

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None

        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                f'{field} must be an integer between '
                f'{minimum} and {maximum}.'
            )

        if not minimum <= number <= maximum:
            raise ValueError(
                f'{field} must be between {minimum} and {maximum}.'
            )

        return number

    try:
        updates = {}

        if 'dns' in data:
            dns_value = data.get('dns')
            updates['dns'] = (
                str(dns_value).strip()
                if dns_value not in (None, '')
                else None
            )

        if 'mtu' in data:
            updates['mtu'] = optional_int(
                data.get('mtu'),
                'MTU',
                576,
                9000,
            )

        if 'listen_port' in data:
            listen_port = optional_int(
                data.get('listen_port'),
                'Listen port',
                1,
                65535,
            )

            if listen_port is None:
                return jsonify(
                    ok=False,
                    error='listen_port_required',
                    detail='Listen port cannot be empty.',
                ), 400

            updates['listen_port'] = listen_port

    except ValueError as exc:
        return jsonify(
            ok=False,
            error='invalid_interface_setting',
            detail=str(exc),
        ), 400

    if not updates:
        return jsonify(
            ok=True,
            changed=False,
            message='No interface settings changed.',
            interface={
                'id': iface.id,
                'name': iface.name,
                'listen_port': iface.listen_port,
                'dns': iface.dns,
                'mtu': iface.mtu,
                'is_up': _iface_up(dev),
            },
        )

    is_up = _iface_up(dev)

    if is_up and 'listen_port' in updates:
        result = subprocess.run(
            [
                'wg',
                'set',
                dev,
                'listen-port',
                str(updates['listen_port']),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12,
            check=False,
        )

        if result.returncode != 0:
            detail = (
                result.stderr
                or result.stdout
                or 'wg set listen-port failed.'
            ).strip()

            _iface_log(
                iid,
                f'Failed to set ListenPort on {dev}: {detail}',
            )

            return jsonify(
                ok=False,
                error='wg_set_listen_port_failed',
                detail=detail,
                interface=dev,
                is_up=True,
            ), 409

    if is_up and 'mtu' in updates and updates['mtu'] is not None:
        result = subprocess.run(
            [
                'ip',
                'link',
                'set',
                'dev',
                dev,
                'mtu',
                str(updates['mtu']),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12,
            check=False,
        )

        if result.returncode != 0:
            detail = (
                result.stderr
                or result.stdout
                or 'ip link set MTU failed.'
            ).strip()

            _iface_log(
                iid,
                f'Failed to set MTU on {dev}: {detail}',
            )

            return jsonify(
                ok=False,
                error='ip_set_mtu_failed',
                detail=detail,
                interface=dev,
                is_up=True,
            ), 409

    old_values = {
        key: getattr(iface, key, None)
        for key in updates
    }

    try:
        for key, value in updates.items():
            setattr(iface, key, value)

        db.session.flush()

        conf_path = Path(iface.path) if iface.path else None

        if conf_path and conf_path.is_file():
            original = conf_path.read_text(
                encoding='utf-8',
                errors='replace',
            )

            lines = original.splitlines(keepends=True)
            output = []
            in_interface = False
            found_interface = False

            managed_keys = {
                'dns': 'DNS',
                'mtu': 'MTU',
                'listenport': 'ListenPort',
            }

            for raw in lines:
                stripped = raw.strip()

                if stripped.startswith('[') and stripped.endswith(']'):
                    if in_interface:
                    
                        if 'mtu' in updates and updates['mtu'] is not None:
                            output.append(f"MTU = {updates['mtu']}\n")
                        if 'listen_port' in updates:
                            output.append(
                                f"ListenPort = {updates['listen_port']}\n"
                            )

                    in_interface = (
                        stripped[1:-1].strip().lower()
                        == 'interface'
                    )
                    found_interface = found_interface or in_interface
                    output.append(raw)
                    continue

                if in_interface and '=' in stripped:
                    key = stripped.split('=', 1)[0].strip().lower()

                    remove = (
                        (key == 'dns' and 'dns' in updates)
                        or (key == 'mtu' and 'mtu' in updates)
                        or (
                            key == 'listenport'
                            and 'listen_port' in updates
                        )
                    )

                    if remove:
                        continue

                output.append(raw)

            if in_interface:
            
                if 'mtu' in updates and updates['mtu'] is not None:
                    output.append(f"MTU = {updates['mtu']}\n")
                if 'listen_port' in updates:
                    output.append(
                        f"ListenPort = {updates['listen_port']}\n"
                    )

            if not found_interface:
                raise RuntimeError(
                    f'{conf_path} does not contain an [Interface] section.'
                )

            new_text = ''.join(output)

            fd, temp_name = tempfile.mkstemp(
                prefix=f'.{conf_path.name}.',
                dir=str(conf_path.parent),
                text=True,
            )

            try:
                with os.fdopen(
                    fd,
                    'w',
                    encoding='utf-8',
                ) as handle:
                    handle.write(new_text)
                    handle.flush()
                    os.fsync(handle.fileno())

                os.chmod(temp_name, 0o600)
                os.replace(temp_name, conf_path)

            finally:
                try:
                    if os.path.exists(temp_name):
                        os.unlink(temp_name)
                except OSError:
                    pass

        db.session.commit()

    except Exception as exc:
        db.session.rollback()

        try:
            if is_up and 'listen_port' in old_values:
                old_port = old_values.get('listen_port')
                if old_port:
                    subprocess.run(
                        [
                            'wg',
                            'set',
                            dev,
                            'listen-port',
                            str(old_port),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                        check=False,
                    )

            if is_up and 'mtu' in old_values:
                old_mtu = old_values.get('mtu')
                if old_mtu:
                    subprocess.run(
                        [
                            'ip',
                            'link',
                            'set',
                            'dev',
                            dev,
                            'mtu',
                            str(old_mtu),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                        check=False,
                    )
        except Exception:
            pass

        current_app.logger.exception(
            'Failed to save interface settings: '
            'interface_id=%s device=%s',
            iid,
            dev,
        )

        _iface_log(
            iid,
            f'Interface settings save failed: {exc}',
        )

        return jsonify(
            ok=False,
            error='interface_save_failed',
            detail=str(exc),
            interface=dev,
            is_up=_iface_up(dev),
        ), 500

    _iface_log(
        iid,
        (
            'Interface settings saved: '
            + ', '.join(
                f'{key}={value!r}'
                for key, value in updates.items()
            )
        ),
    )

    return jsonify(
        ok=True,
        changed=True,
        message='Interface settings saved.',
        interface={
            'id': iface.id,
            'name': iface.name,
            'path': iface.path,
            'address': iface.address,
            'listen_port': iface.listen_port,
            'dns': iface.dns,
            'mtu': iface.mtu,
            'is_up': _iface_up(dev),
        },
    )


def _endpoint_default_payload(iface, *, scope=None, node=None, remote_iface=None):

    if scope is None:
        scope = 'node' if getattr(iface, 'node_id', None) is not None else 'local'

    host = (getattr(iface, 'endpoint_host', None) or '').strip() or None
    port = getattr(iface, 'endpoint_port', None)
    override = iface_endpoint_override(iface)

    auto = ''
    try:
        if scope == 'node':
            auto = (_node_endpoint_fallback(
                node or getattr(iface, 'node', None),
                remote_iface_name(iface),
                remote_iface,
            ) or '').strip()
        else:
            auto = (_endpoint_fallback(iface) or '').strip()
    except Exception:
        current_app.logger.debug(
            'Endpoint auto-detection unavailable for %s',
            getattr(iface, 'name', '?'), exc_info=True,
        )
        auto = ''

    effective = override or auto

    payload = {
        'scope': scope,
        'iface_id': iface.id,
        'iface': remote_iface_name(iface) if scope == 'node' else (iface.name or ''),
        'listen_port': iface.listen_port,
        'endpoint_host': host,
        'endpoint_port': int(port) if port else None,
        'endpoint_override': override,
        'auto_endpoint': auto,
        'effective_endpoint': effective,
        'endpoint_source': 'override' if override else ('auto' if auto else 'none'),
    }

    if scope == 'node':
        payload['node_id'] = getattr(iface, 'node_id', None)

    if not effective:
        payload['warning'] = (
            'No endpoint could be determined. Exported configs will have no '
            'Endpoint line until an override is saved.'
        )

    return payload


@app.get('/api/iface/<int:iid>/endpoint-default')
@require_api_key_or_login
def api_iface_endpoint_default_get(iid):
    iface = db.session.get(InterfaceConfig, iid)

    if iface is None:
        return jsonify(
            ok=False,
            error='iface_not_found',
            detail=f'Interface {iid} was not found.',
        ), 404

    return jsonify(ok=True, **_endpoint_default_payload(iface))


@app.put('/api/iface/<int:iid>/endpoint-default')
@require_api_key_or_login
def api_iface_endpoint_default_put(iid):
    iface = db.session.get(InterfaceConfig, iid)

    if iface is None:
        return jsonify(
            ok=False,
            error='iface_not_found',
            detail=f'Interface {iid} was not found.',
        ), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(
            ok=False,
            error='invalid_payload',
            detail='The request body must be a JSON object.',
        ), 400

    try:
        host, port = parse_endpoint_override(data.get('host'), data.get('port'))
    except EndpointValidationError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), 400

    iface.endpoint_host = host
    iface.endpoint_port = port
    db.session.commit()

    current_app.logger.info(
        'Endpoint default %s for local interface %s: host=%s port=%s',
        'cleared' if host is None else 'saved',
        iface.name, host or '-', port or '-',
    )

    return jsonify(ok=True, **_endpoint_default_payload(iface))


class NodeIfaceLookupError(Exception):
    """A node interface could not be resolved into a panel mirror row."""

    def __init__(self, code, status, detail):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


def _node_mirror_for_endpoint_default(node, name):

    db_name = f'n{node.id}:{name}'
    iface = InterfaceConfig.query.filter_by(name=db_name).first()

    if iface is not None:
        return iface, {}

    try:
        listing = node_get(node, '/api/interfaces', timeout=10) or {}
    except Exception as exc:
        raise NodeIfaceLookupError(
            'node_unreachable', 502,
            f'Node {node.id} could not be reached: {exc}',
        )

    rows = listing.get('interfaces') if isinstance(listing, dict) else listing

    remote = next(
        (
            row for row in (rows or [])
            if isinstance(row, dict)
            and str(row.get('name') or row.get('iface') or '').strip() == name
        ),
        None,
    )

    if remote is None:
        raise NodeIfaceLookupError(
            'node_iface_not_found', 404,
            f'Node {node.id} has no interface named {name}.',
        )

    iface = ensure_node_mirror_iface(node, name, remote_iface=remote)
    db.session.commit()

    return iface, remote


@app.get('/api/nodes/<int:nid>/iface/<name>/endpoint-default')
@require_api_key_or_login
def api_node_iface_endpoint_default_get(nid, name):
    node = db.session.get(Node, nid)

    if node is None:
        return jsonify(
            ok=False, error='node_not_found', detail=f'Node {nid} was not found.'
        ), 404

    iface = InterfaceConfig.query.filter_by(name=f'n{nid}:{name}').first()

    if iface is not None:
        return jsonify(
            ok=True,
            **_endpoint_default_payload(iface, scope='node', node=node),
        )

    try:
        auto = (_node_endpoint_fallback(node, name) or '').strip()
    except Exception:
        auto = ''

    return jsonify(
        ok=True,
        scope='node',
        node_id=nid,
        iface=name,
        iface_id=None,
        listen_port=None,
        endpoint_host=None,
        endpoint_port=None,
        endpoint_override='',
        auto_endpoint=auto,
        effective_endpoint=auto,
        endpoint_source='auto' if auto else 'none',
    )


@app.put('/api/nodes/<int:nid>/iface/<name>/endpoint-default')
@require_api_key_or_login
def api_node_iface_endpoint_default_put(nid, name):
    node = db.session.get(Node, nid)

    if node is None:
        return jsonify(
            ok=False, error='node_not_found', detail=f'Node {nid} was not found.'
        ), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(
            ok=False,
            error='invalid_payload',
            detail='The request body must be a JSON object.',
        ), 400

    try:
        host, port = parse_endpoint_override(data.get('host'), data.get('port'))
    except EndpointValidationError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), 400

    try:
        iface, remote = _node_mirror_for_endpoint_default(node, name)
    except NodeIfaceLookupError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status

    iface.endpoint_host = host
    iface.endpoint_port = port
    db.session.commit()

    current_app.logger.info(
        'Endpoint default %s for node %s interface %s: host=%s port=%s',
        'cleared' if host is None else 'saved',
        nid, name, host or '-', port or '-',
    )

    return jsonify(
        ok=True,
        **_endpoint_default_payload(
            iface, scope='node', node=node, remote_iface=remote
        ),
    )


class EndpointApplyError(Exception):
    """Applying an endpoint default to existing peers could not start."""

    def __init__(self, code, status, detail):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


def _apply_endpoint_default(iface, *, dry_run, overwrite_explicit,
                            scope='local', node=None, remote_iface=None):

    effective = resolve_client_endpoint(iface, node=node, remote_iface=remote_iface)

    if not effective:
        raise EndpointApplyError(
            'endpoint_unavailable', 409,
            'No endpoint could be determined for this interface, so there is '
            'nothing to apply.',
        )

    peers = Peer.query.filter_by(iface_id=iface.id).all()
    explicit = [p for p in peers if (p.endpoint or '').strip()]
    candidates = peers if overwrite_explicit else [
        p for p in peers if not (p.endpoint or '').strip()
    ]

    targets = [p for p in candidates if (p.endpoint or '').strip() != effective]

    result = {
        'scope': scope,
        'iface': remote_iface_name(iface) if scope == 'node' else (iface.name or ''),
        'effective_endpoint': effective,
        'total_peers': len(peers),
        'eligible': len(targets),
        'skipped_explicit': 0 if overwrite_explicit else len(explicit),
        'dry_run': bool(dry_run),
    }

    if dry_run:
        result['would_update'] = len(targets)
        return result

    for peer in targets:
        peer.endpoint = effective

    db.session.commit()

    current_app.logger.info(
        'Applied endpoint %s to %s peers on interface %s',
        effective, len(targets), iface.name,
    )

    result['updated'] = len(targets)
    return result


def _apply_request_flags(data):
    data = data if isinstance(data, dict) else {}
    return (
        _sub_bool(data.get('dry_run')),
        _sub_bool(data.get('overwrite_explicit')),
    )


@app.post('/api/iface/<int:iid>/endpoint-default/apply')
@require_api_key_or_login
def api_iface_endpoint_default_apply(iid):
    iface = db.session.get(InterfaceConfig, iid)

    if iface is None:
        return jsonify(
            ok=False, error='iface_not_found',
            detail=f'Interface {iid} was not found.',
        ), 404

    dry_run, overwrite_explicit = _apply_request_flags(
        request.get_json(silent=True)
    )

    try:
        result = _apply_endpoint_default(
            iface, dry_run=dry_run, overwrite_explicit=overwrite_explicit,
        )
    except EndpointApplyError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Applying the endpoint default failed')
        return jsonify(
            ok=False, error='endpoint_apply_failed', detail=str(exc)
        ), 500

    return jsonify(ok=True, **result)


@app.post('/api/nodes/<int:nid>/iface/<name>/endpoint-default/apply')
@require_api_key_or_login
def api_node_iface_endpoint_default_apply(nid, name):
    node = db.session.get(Node, nid)

    if node is None:
        return jsonify(
            ok=False, error='node_not_found', detail=f'Node {nid} was not found.'
        ), 404

    dry_run, overwrite_explicit = _apply_request_flags(
        request.get_json(silent=True)
    )

    remote = None

    if dry_run:

        iface = InterfaceConfig.query.filter_by(name=f'n{nid}:{name}').first()

        if iface is None:
            try:
                auto = (_node_endpoint_fallback(node, name) or '').strip()
            except Exception:
                auto = ''

            return jsonify(
                ok=True,
                scope='node',
                iface=name,
                effective_endpoint=auto,
                total_peers=0,
                eligible=0,
                skipped_explicit=0,
                dry_run=True,
                would_update=0,
            )
    else:
        try:
            iface, remote = _node_mirror_for_endpoint_default(node, name)
        except NodeIfaceLookupError as exc:
            return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status

    try:
        result = _apply_endpoint_default(
            iface, dry_run=dry_run, overwrite_explicit=overwrite_explicit,
            scope='node', node=node, remote_iface=remote,
        )
    except EndpointApplyError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Applying the node endpoint default failed')
        return jsonify(
            ok=False, error='endpoint_apply_failed', detail=str(exc)
        ), 500

    return jsonify(ok=True, **result)


@app.post('/api/iface/<int:iid>/<action>')
@login_required
def iface_updown(iid, action):
    iface = (
        db.session.get(
            InterfaceConfig,
            iid,
        )
        or abort(404)
    )

    if action not in ('up', 'down'):
        return jsonify(
            ok=False,
            error='invalid_action',
            detail='Action must be up or down.',
        ), 400

    if (
        getattr(
            iface,
            'node_id',
            None,
        )
        is not None
        or ':' in (
            getattr(
                iface,
                'name',
                '',
            )
            or ''
        )
    ):
        return jsonify(
            ok=False,
            error='remote_interface',
            detail=(
                'This interface belongs to a node. '
                'Use the node interface endpoint.'
            ),
        ), 400

    dev = iface_devname(
        iface
    )

    try:
        if action == 'up':

            _check_iface_up(
                iface
            )

            is_up = _iface_up(
                dev
            )

            if not is_up:
                raise RuntimeError(
                    f'Interface {dev} did not become active.'
                )

            try:
                subprocess.run(
                    [
                        'systemctl',
                        'enable',
                        f'wg-quick@{dev}.service',
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except Exception:
                current_app.logger.warning(
                    'Could not enable wg-quick@%s at boot',
                    dev,
                    exc_info=True,
                )

            _iface_log(
                iid,
                (
                    f'Interface {dev} brought up '
                    'from Settings.'
                ),
            )

            return jsonify(
                ok=True,
                action='up',
                name=dev,
                is_up=True,
                message=(
                    f'Interface {dev} is active.'
                ),
            )

        if not _iface_up(dev):
            return jsonify(
                ok=True,
                action='down',
                name=dev,
                is_up=False,
                message=(
                    f'Interface {dev} is already down.'
                ),
            )

        proc = subprocess.run(
            [
                'wg-quick',
                'down',
                dev,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )

        output = (
            proc.stdout
            or ''
        ).strip()

        _iface_log(
            iid,
            (
                f'$ wg-quick down {dev}\n'
                f'{output}'
            ).rstrip(),
        )

        is_up = _iface_up(
            dev
        )

        if (
            proc.returncode != 0
            and is_up
        ):
            return jsonify(
                ok=False,
                error='wg_quick_down_failed',
                detail=(
                    output
                    or f'wg-quick down {dev} failed.'
                ),
                is_up=True,
            ), 409

        try:
            subprocess.run(
                [
                    'systemctl',
                    'disable',
                    f'wg-quick@{dev}.service',
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except Exception:
            current_app.logger.warning(
                'Could not disable wg-quick@%s at boot',
                dev,
                exc_info=True,
            )

        return jsonify(
            ok=True,
            action='down',
            name=dev,
            is_up=False,
            message=(
                f'Interface {dev} is down.'
            ),
        )

    except subprocess.TimeoutExpired as exc:
        current_app.logger.exception(
            'Interface %s timed out: %s',
            action,
            dev,
        )

        _iface_log(
            iid,
            (
                f'Interface {action} timed out: '
                f'{exc}'
            ),
        )

        return jsonify(
            ok=False,
            error='interface_command_timeout',
            detail=str(exc),
            name=dev,
            is_up=_iface_up(dev),
        ), 504

    except RuntimeError as exc:
        current_app.logger.exception(
            'Interface %s failed for %s',
            action,
            dev,
        )

        _iface_log(
            iid,
            (
                f'Interface {action} failed: '
                f'{exc}'
            ),
        )

        return jsonify(
            ok=False,
            error=f'interface_{action}_failed',
            detail=str(exc),
            name=dev,
            is_up=_iface_up(dev),
            hint=(
                'Open Interface Logs for the complete '
                'wg-quick and manual recovery output.'
            ),
        ), 409

    except Exception as exc:
        current_app.logger.exception(
            'Unexpected interface %s failure for %s',
            action,
            dev,
        )

        _iface_log(
            iid,
            (
                f'Unexpected interface {action} error: '
                f'{exc}'
            ),
        )

        return jsonify(
            ok=False,
            error='interface_action_failed',
            detail=str(exc),
            name=dev,
            is_up=_iface_up(dev),
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
        except Exception:
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
            r = runtime.get(p.public_key)
            rs = ((r or {}).get('conn_status') or (r or {}).get('connection_status') or (r or {}).get('status') or '').strip()

            if r:
                rx = r.get('rx_mib', 0) or 0
                tx = r.get('tx_mib', 0) or 0

                try:
                    rx_mib = float(rx)
                except Exception:
                    rx_mib = 0.0

                try:
                    tx_mib = float(tx)
                except Exception:
                    tx_mib = 0.0

                live_total = int((rx_mib + tx_mib) * 1024 * 1024)
                used_total, _delta, usage_changed = _accumulate_peer_usage(p, live_total)
                if usage_changed:
                    dirty = True
                used_live = used_total
            else:
                rx_mib = 0.0
                tx_mib = 0.0
                live_total = int(getattr(p, 'bytes_offset', 0) or 0)
                used_live = int(getattr(p, 'used_bytes_total', 0) or 0)

            if not getattr(p, 'first_used_at', None):

                try:
                    handshake_ts = int((r or {}).get('latest_handshake')or 0)
                except Exception:
                    handshake_ts = 0

                if handshake_ts > 0:
                    p.first_used_at = from_ts(
                        handshake_ts
                    )
                    p.timer_started_at = from_ts(handshake_ts)

                    if (
                        getattr(p,'start_on_first_use',False,)
                        and getattr(p,'time_limit_days',None,)
                        and not getattr(p,'unlimited',False,)):
                        p.expires_at = from_ts(
                            add_days_ts(
                                handshake_ts,
                                float(
                                    p.time_limit_days
                                ),
                            )
                        )

                    dirty = True


            exp_ts      = _effective_expiry_ts(p)
            ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None

            p_iface    = p.iface
            iface_raw  = p_iface.name if p_iface else ''
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
                'panel_status': p.status,
                'conn_status': rs if rs in ('online', 'offline') else 'offline',
                'connection_status': rs if rs in ('online', 'offline') else 'offline',
                'latest_handshake': (r or {}).get('latest_handshake'),
                'latest_handshake_age': (r or {}).get('latest_handshake_age'),
                'conn_reason': (r or {}).get('conn_reason') or 'none',
                'iface': iface_disp,
                'iface_raw': iface_raw,
                'name': p.name,
                'listen_port': (p_iface.listen_port if p_iface else None) or port_by_name.get(iface_disp),
                'server_public_ip': node_pub_ip,
                'address': p.address,
                'endpoint': resolve_client_endpoint_cheap(p_iface, explicit=p.endpoint),
                'endpoint_saved': p.endpoint or '',
                'peer_endpoint': getattr(p, 'peer_endpoint', None) or '',
                'allowed_ips': p.allowed_ips or '',
                'persistent_keepalive': p.persistent_keepalive,
                'mtu': p.mtu,
                'dns': p.dns,
                'status': status,
                'data_limit': getattr(p, 'data_limit_value', None),
                'limit_unit': getattr(p, 'data_limit_unit', None),
                'unlimited': getattr(p, 'unlimited', False),
                'time_limit_days': getattr(p, 'time_limit_days', None),
                'display_timezone': _panel_timezone_name(),
                'start_on_first_use': getattr(p, 'start_on_first_use', False),
                'first_used_at': isoz(getattr(p, 'first_used_at', None)),
                'first_used_at_display': _panel_display_datetime(getattr(p, 'first_used_at', None)),
                'expires_at': isoz(from_ts(exp_ts)),
                'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
                'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
                'created_at': isoz(getattr(p, 'created_at', None)),
                'created_at_display': _panel_display_datetime(getattr(p, 'created_at', None)),
                'created_at_ts': to_ts(getattr(p, 'created_at', None)),
                'expires_at_ts': exp_ts,
                'ttl_seconds': ttl_seconds,
                'used_bytes': used_live,
                'used_bytes_db': used_live,
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

    data = request.get_json(silent=True) or {}
    iface_name = (data.get('iface') or '').strip()
    if not iface_name:
        return jsonify(error='iface is required'), 400

    try:
        priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
        pub = subprocess.check_output(
            ['wg', 'pubkey'], input=(priv + '\n').encode()
        ).strip().decode()
    except Exception as exc:
        return jsonify(error='key_generation_failed', detail=str(exc)), 500

    remote_iface = {}
    try:
        remote_payload = node_get(n, '/api/interfaces', timeout=10) or {}
        rows = remote_payload.get('interfaces') or [] if isinstance(remote_payload, dict) else remote_payload
        remote_iface = next(
            (row for row in (rows or []) if str((row or {}).get('name') or '') == iface_name),
            {},
        ) or {}
    except Exception:
        current_app.logger.warning(
            'Could not refresh node %s interface %s before peer create',
            nid, iface_name, exc_info=True,
        )

    iface = ensure_node_mirror_iface(
        n, iface_name, remote_iface,
        listen_port=data.get('listen_port'),
        server_cidr=data.get('server_cidr'),
        mtu=data.get('mtu'),
        dns=data.get('dns'),
    )
    peer_endpoint = (data.get('peer_endpoint') or '').strip()
    allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()

    try:
        address = node_install_peer(
            n, iface_name, iface,
            public_key=pub,
            requested_address=(data.get('address') or '').strip(),
            peer_endpoint=peer_endpoint,
            keepalive=data.get('persistent_keepalive') or 0,
            mtu=data.get('mtu'),
            dns=data.get('dns'),
            allowed_ips=allowed_ips,
        )
    except AddressAllocationError as exc:
        db.session.rollback()
        return address_error_response(exc)
    except NodePeerInstallError as exc:

        try:
            _rollback_node_created_peer(n, pub)
        except Exception:
            current_app.logger.exception('Ambiguous node create cleanup failed for %s', pub)
        db.session.rollback()
        return jsonify(error=exc.code, detail=exc.detail), exc.status

    compensation = PeerCreateCompensation()
    compensation.register_node(n, pub)
    created_ts = now_ts()
    try:
        peer = Peer(
            iface_id=iface.id,
            name=(data.get('name') or '').strip() or 'peer',
            public_key=pub,
            private_key=priv,
            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),
            address=address,
            allowed_ips=allowed_ips,
            endpoint=(data.get('endpoint') or '').strip() or None,
            peer_endpoint=peer_endpoint or None,
            persistent_keepalive=data.get('persistent_keepalive') or None,
            mtu=data.get('mtu') or None,
            dns=(data.get('dns') or '').strip() or None,
            status='online',
            data_limit_value=int(data.get('data_limit_value') or 0),
            data_limit_unit=data.get('data_limit_unit') or 'Mi',
            start_on_first_use=_sub_bool(data.get('start_on_first_use')),
            time_limit_days=_conv_time_limit(data),
            unlimited=_sub_bool(data.get('unlimited')),
            phone_number=(data.get('phone_number') or '').strip(),
            telegram_id=(data.get('telegram_id') or '').strip(),
        )

        if (
            peer.time_limit_days
            and not peer.start_on_first_use
            and not peer.unlimited
        ):
            peer.expires_at = from_ts(
                add_days_ts(created_ts, peer.time_limit_days)
            )

        db.session.add(peer)
        db.session.commit()
    except Exception as exc:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        current_app.logger.exception('DB save failed after legacy node peer create')
        return jsonify(
            error='db_save_failed', detail=str(exc),
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else 500

    return jsonify(
        ok=True, id=peer.id, address=peer.address,
        endpoint=_effective_client_endpoint(peer),
        peer_endpoint=peer.peer_endpoint or '',
    )


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

@app.get('/api-docs')
@login_required
def api_docs_page():
    return render_template('api_docs.html')

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

    p = (
        db.session.query(Peer)
        .join(
            InterfaceConfig,
            Peer.iface_id == InterfaceConfig.id
        )
        .filter(Peer.public_key == pub)
        .filter(or_(
            InterfaceConfig.name.like(f"n{nid}:%"),
            InterfaceConfig.node_id == nid
        ))
        .first()
    )

    if not p:
        return jsonify(
            success=False,
            error='peer_not_found'
        ), 404

    payload = {}

    try:
        payload['host_cidr'] = _host_peer(p)
    except Exception:
        pass

    try:
        node_post(
            n,
            f'/api/peer/{pub}/enable',
            payload,
            timeout=15
        )

        current_live_total = int(
            _node_peer_live_total_bytes(n, p) or 0
        )
        current_live_total = max(0, current_live_total)

        p.bytes_offset = current_live_total
        p.used_bytes_total = 0
        p.first_used_at = None
        p.timer_started_at = None

        try:
            time_limit_days = float(
                getattr(p, 'time_limit_days', 0) or 0
            )
        except (TypeError, ValueError):
            time_limit_days = 0.0

        if getattr(p, 'unlimited', False):
            p.expires_at = None

        elif getattr(p, 'start_on_first_use', False):
            p.expires_at = None

        elif time_limit_days > 0:
            _start_timer_cycle(p)

        else:
            p.expires_at = None

        p.status = 'online'

        db.session.commit()

        try:
            log_event(
                p,
                'enabled',
                (
                    'Node peer enabled; timer and data reset; '
                    f'new traffic offset={current_live_total}'
                )
            )

            logpanel_action(
                'node_peer_enable',
                (
                    f'node={nid}; pid={p.id}; '
                    f'timer_reset=1; data_reset=1; '
                    f'unlimited={int(bool(getattr(p, "unlimited", False)))}; '
                    f'offset={current_live_total}'
                )
            )
        except Exception:
            pass

        return jsonify(
            success=True,
            ok=True,
            status='online',
            timer_reset=True,
            data_reset=True,
            unlimited=bool(getattr(p, 'unlimited', False)),
            used_bytes_total=0,
            bytes_offset=current_live_total
        )

    except requests.HTTPError as exc:
        db.session.rollback()

        response = getattr(exc, 'response', None)
        upstream_status = getattr(response, 'status_code', None)
        upstream_body = getattr(response, 'text', '') or ''

        current_app.logger.exception(
            'Node peer enable failed: node=%s peer=%s',
            nid,
            pub
        )

        return jsonify(
            success=False,
            error='node_enable_failed',
            detail=str(exc),
            upstream_status=upstream_status,
            upstream_body=upstream_body[:800]
        ), 502

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Node peer enable failed: node=%s peer=%s',
            nid,
            pub
        )

        return jsonify(
            success=False,
            error='node_enable_failed',
            detail=str(exc)
        ), 502


def _node_peer_live_total_bytes(node, peer):

    try:
        iface_raw = peer.iface.name if peer.iface else ''
        iface_name = iface_raw.split(':', 1)[1] if ':' in iface_raw else iface_raw

        data = node_get(node, '/api/peers' + (f'?iface={iface_name}' if iface_name else ''), timeout=8) or {}
        rows = data.get('peers') if isinstance(data, dict) else []
        for row in rows or []:
            if row.get('public_key') == peer.public_key:
                rx_mib = float(row.get('rx_mib') or 0)
                tx_mib = float(row.get('tx_mib') or 0)
                return int((rx_mib + tx_mib) * 1024 * 1024)
    except Exception:
        current_app.logger.debug("Could not read node live transfer for peer %s", getattr(peer, 'id', '?'))

    return 0


@app.route('/api/nodes/<int:nid>/peer/<path:pub>/reset_data', methods=['POST'])
@login_required
def node_reset_peer_data_only(nid, pub):
    """
    Reset node peer traffic counters only
    """
    n = Node.query.get_or_404(nid)
    p = _node_peer_by_publickey(nid,pub,)

    current = _node_peer_live_total_bytes(n, p)

    p.bytes_offset = int(current or 0)
    p.used_bytes_total = 0

    db.session.commit()

    try:
        log_event(p, 'reset_data', f'Node: offset set to {current}; status kept as {p.status}')
        logpanel_action("node_peer_reset_data", f"node={nid}; pid={p.id}; new_offset={current}; status_kept={p.status}")
    except Exception:
        pass

    return jsonify(ok=True, success=True, status=p.status)


@app.route('/api/nodes/<int:nid>/peer/<path:pub>/reset_timer', methods=['POST'])
@login_required
def node_reset_peer_timer_only(nid, pub):
    """
    Reset node peer timer and re-enable
    """
    n = Node.query.get_or_404(nid)
    p = _node_peer_by_publickey(nid,pub,)

    tl_days = getattr(p, 'time_limit_days', None)
    try:
        tl_days_f = float(tl_days) if tl_days is not None else 0.0
    except Exception:
        tl_days_f = 0.0

    p.first_used_at = None
    p.timer_started_at = None

    if getattr(p, 'unlimited', False) or tl_days_f <= 0:
        p.expires_at = None
        detail = 'Node timer cleared; peer re-enabled'
    elif getattr(p, 'start_on_first_use', False):
        p.expires_at = None
        detail = 'Node timer cleared; will start on first use; peer re-enabled'
    else:
        _start_timer_cycle(p)
        detail = f'Node timer restarted for {tl_days_f} days; peer re-enabled'

    payload = {}
    try:
        payload['host_cidr'] = _host_peer(p)
    except Exception:
        pass

    try:
        node_post(n, f'/api/peer/{pub}/enable', payload)
        p.status = 'online'
    except Exception as e:
        db.session.commit()
        current_app.logger.exception("Node reset timer enable failed")
        return jsonify(error="node_reset_timer_failed", detail=str(e)), 502

    db.session.commit()

    try:
        log_event(p, 'reset_timer', detail)
        logpanel_action("node_peer_reset_timer", f"node={nid}; pid={p.id}; {detail}")
    except Exception:
        pass

    return jsonify(ok=True, success=True, status=p.status)

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
@app.route(
    '/login',
    methods=['GET', 'POST'],
)
def login():
    from models import AdminAccount

    if not AdminAccount.query.first():
        return redirect(
            url_for('register')
        )

    if request.method == 'POST':
        username = (
            request.form.get('username')
            or ''
        ).strip()

        password = (
            request.form.get('password')
            or ''
        ).strip()

        otp = (
            request.form.get('twofa_code')
            or request.form.get(
                'otp_or_recovery'
            )
            or ''
        ).strip().replace(' ', '')

        account = (
            AdminAccount.query
            .filter_by(
                username=username
            )
            .first()
        )

        if (
            not account
            or not account.verify_pw(
                password
            )
        ):
            _send_security_notification(
                'login_failed',
                username=(
                    username
                    or 'unknown'
                ),
                reason=(
                    'Invalid username or password'
                ),
            )
            _http_security_record_login_failure(
                username=(username or 'unknown'),
                failure_type='credentials',
            )

            try:
                client_ip, _ = (
                    _request_client_ip()
                )

                _norm_adminlog({
                    'action': 'login_failed',
                    'admin_username': (
                        username
                        or ''
                    ),
                    'details': (
                        f'ip={client_ip}; '
                        'reason=invalid_credentials'
                    ),
                    'result': 'denied',
                    'channel': 'web',
                })
            except Exception:
                pass

            flash(
                'Invalid username or password',
                'error',
            )

            return render_template(
                'login.html'
            )

        if account.twofa_enabled:
            verified = False

            if (
                account.totp_secret
                and otp
            ):
                totp = pyotp.TOTP(
                    account.totp_secret
                )

                if totp.verify(
                    otp,
                    valid_window=1,
                ):
                    verified = True

            if not verified and otp:
                recovery_codes = (
                    account.recovery_codes
                    or ''
                ).splitlines()

                for index, stored in enumerate(
                    recovery_codes
                ):
                    if verify_recovery(
                        otp,
                        stored,
                    ):
                        verified = True

                        recovery_codes.pop(
                            index
                        )

                        account.recovery_codes = (
                            '\n'.join(
                                recovery_codes
                            )
                        )

                        db.session.commit()
                        break

            if not verified:
                _send_security_notification(
                    'twofa_failed',
                    username=account.username,
                    reason=(
                        'Invalid TOTP or recovery code'
                    ),
                )
                _http_security_record_login_failure(
                    username=account.username,
                    failure_type='twofa',
                )

                try:
                    client_ip, _ = (
                        _request_client_ip()
                    )

                    _norm_adminlog({
                        'action': 'twofa_failed',
                        'admin_username': (
                            account.username
                        ),
                        'details': (
                            f'ip={client_ip}; '
                            'reason=invalid_twofa'
                        ),
                        'result': 'denied',
                        'channel': 'web',
                    })
                except Exception:
                    pass

                flash(
                    (
                        'Enter your 6-digit code '
                        'or a valid recovery code'
                    ),
                    'error',
                )

                return render_template(
                    'login.html'
                )

        login_user(
            Admin(
                account.username
            )
        )

        _send_security_notification(
            'login_success',
            username=account.username,
            reason=(
                (
                    'Password and two-factor '
                    'checks passed'
                )
                if account.twofa_enabled
                else 'Password accepted'
            ),
        )

        try:
            client_ip, _ = (
                _request_client_ip()
            )

            _norm_adminlog({
                'action': 'login_success',
                'admin_username': (
                    account.username
                ),
                'details': (
                    f'ip={client_ip}; '
                    f'scheme='
                    f'{"https" if _is_https() else "http"}'
                ),
                'result': 'ok',
                'channel': 'web',
            })
        except Exception:
            pass

        next_url = (
            request.form.get('next')
            or request.args.get('next')
        )

        if (
            next_url
            and _safe_url(next_url)
        ):
            return redirect(
                next_url
            )

        return redirect(
            url_for('index')
        )

    return render_template(
        'login.html'
    )

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

    if form.validate_on_submit():
        iface = sel_iface or (db.session.get(InterfaceConfig, form.iface.data) if form.iface.data else None)
        if not iface:
            flash('Please select an interface.', 'error')
            return render_template('users.html', form=form)

        priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
        pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()

        combined_days = _conv_time_limit({
            'time_limit_days': (
                getattr(
                    form,
                    'time_limit_days',
                    None,
                )
                and form.time_limit_days.data
            ),

            'time_limit_hours': (
                getattr(
                    form,
                    'time_limit_hours',
                    None,
                )
                and form.time_limit_hours.data
            ),

            'time_limit_minutes': (
                getattr(
                    form,
                    'time_limit_minutes',
                    None,
                )
                and form.time_limit_minutes.data
            ),
        })
        created_ts = now_ts()

        peer = Peer(
            iface_id=iface.id,
            name=form.name.data,
            public_key=pub,
            private_key=priv,
            allowed_ips=form.allowed_ips.data,
            endpoint=form.endpoint.data,
            peer_endpoint=(form.peer_endpoint.data or '').strip() or None,
            persistent_keepalive=form.persistent_keepalive.data,
            mtu=form.mtu.data,
            dns=form.dns.data,
            status='offline',
            data_limit_value=int(getattr(form, 'data_limit', None) and (form.data_limit.data or 0)),
            data_limit_unit=getattr(form, 'limit_unit', None) and form.limit_unit.data,
            time_limit_days=combined_days,
            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),
            start_on_first_use=bool(getattr(form, 'start_on_first_use', None) and form.start_on_first_use.data),
            unlimited=bool(getattr(form, 'unlimited', None) and form.unlimited.data),
            phone_number=getattr(form, 'phone_number', None) and form.phone_number.data,
            telegram_id=getattr(form, 'telegram_id', None) and form.telegram_id.data,
        )

        if (
            peer.time_limit_days
            and not peer.start_on_first_use
            and not peer.unlimited
        ):
            peer.expires_at = from_ts(
                add_days_ts(
                    created_ts,
                    float(
                         peer.time_limit_days
                    ),
                )
            )

        installed = False

        with interface_allocation_lock(iface):
            try:
                peer.address = allocate_peer_address(iface, requested=form.address.data)
            except AddressAllocationError as e:
                flash(str(e), 'error')
                return render_template('users.html', form=form)

            try:
                db.session.add(peer)
                db.session.flush()

                install_local_peer(peer)
                installed = True
                peer.status = 'online'

                db.session.add(
                    PeerEvent(
                        peer_id=peer.id,

                        timestamp=peer.created_at,

                        event='created',

                        details=(
                            f"iface={iface.name}; "
                            f"limit={getattr(peer,'data_limit_value',0)}"
                            f"{getattr(peer,'data_limit_unit','')}; "
                            f"days={peer.time_limit_days}; "
                            f"unlimited={peer.unlimited}"
                        ),
                    )
                )
                db.session.commit()
                flash('Peer created & enabled', 'success')

            except Exception as e:
                if installed:
                    _wg_disable_quiet(peer)
                    _remove_peer_quiet(peer)
                db.session.rollback()
                current_app.logger.exception("Peer create failed for %s: %s", form.name.data, e)
                flash(
                    'Peer was not created: the interface could not accept it. '
                    'Bring the interface up and try again.',
                    'error',
                )
                return render_template('users.html', form=form)

        try:
            _shortlink_for_peer(peer)
        except Exception:
            current_app.logger.exception("shortlink create failed for local peer %s", peer.id)

        return redirect(url_for('users'))

    return render_template('users.html', form=form)


@app.route('/api/endpoint_presets', methods=['GET', 'POST', 'DELETE'])
@require_api_key_or_login
def endpoint_presets():
    if request.method == 'GET':
        return jsonify(presets=_load_presets(), public_ipv4=_public_ipv4())

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
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

    data = request.get_json(silent=True) or {}
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
    from urllib.parse import urlencode
    params = {
        'limit': request.args.get('limit', 500),
        'q': (request.args.get('q') or '').strip(),
    }
    qs = urlencode({k: v for k, v in params.items() if str(v or '').strip()})
    node_path = f"/api/iface/{name}/logs" + (f"?{qs}" if qs else "")

    try:
        data = node_get(n, node_path, timeout=12)
    except Exception as e:
        current_app.logger.warning("node_iface_logs failed for %s on %s: %s", name, n, e)
        return jsonify(logs=[])
    return jsonify(logs=(data.get('logs', []) if isinstance(data, dict) else []))


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
        cpu = round(
            psutil.cpu_percent(
                interval=0.2,
            )
            or 0.0,
            1,
        )

        mem = round(
            psutil.virtual_memory().percent
            or 0.0,
            1,
        )

        disk = round(
            psutil.disk_usage('/').percent
            or 0.0,
            1,
        )

        uptime_secs = max(
            0,
            int(
                time.time()
                - psutil.boot_time()
            ),
        )

        if uptime_secs >= 48 * 3600:
            days = (
                uptime_secs
                // 86400
            )

            hours = (
                uptime_secs
                % 86400
            ) // 3600

            uptime_value = int(days)
            uptime_unit = 'd'

            uptime_str = (
                f'{days}d'
                + (
                    f' {hours}h'
                    if hours
                    else ''
                )
            )

        else:
            hours = (
                uptime_secs
                // 3600
            )

            uptime_value = int(hours)
            uptime_unit = 'h'
            uptime_str = f'{hours}h'

        active_within_seconds = 180
        now_epoch = int(
            time.time()
        )

        handshake_map = {}

        try:
            process = subprocess.run(
                [
                    'wg',
                    'show',
                    'all',
                    'latest-handshakes',
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )

            if process.returncode == 0:
                for raw_line in (
                    process.stdout
                    or ''
                ).splitlines():

                    parts = (
                        raw_line.split()
                    )

                    if len(parts) < 3:
                        continue

                    iface_name = parts[0]
                    public_key = parts[1]
                    raw_timestamp = parts[2]

                    try:
                        timestamp = int(
                            raw_timestamp
                            or 0
                        )

                    except Exception:
                        timestamp = 0

                    handshake_map[
                        (
                            iface_name,
                            public_key,
                        )
                    ] = timestamp

        except Exception:
            handshake_map = {}

        activity = {
            'active': 0,
            'idle': 0,
            'blocked': 0,
            'total': 0,
        }

        rows = (
            db.session.query(
                Peer.status,
                Peer.public_key,
                InterfaceConfig.name,
            )
            .join(
                InterfaceConfig,
                Peer.iface_id
                == InterfaceConfig.id,
            )
            .all()
        )

        for (
            stored_status,
            public_key,
            iface_name,
        ) in rows:

            activity['total'] += 1

            stored_status = str(
                stored_status
                or ''
            ).lower()

            iface_name = str(
                iface_name
                or ''
            )

            if stored_status == 'blocked':
                activity['blocked'] += 1
                continue

            is_node = bool(
                re.match(
                    r'^n\d+:',
                    iface_name,
                )
            )

            if is_node:
                if stored_status == 'online':
                    activity['active'] += 1

                else:
                    activity['idle'] += 1

                continue

            device_name = (
                iface_name
                .split(':')[-1]
            )

            handshake = int(
                handshake_map.get(
                    (
                        device_name,
                        public_key,
                    )
                )
                or handshake_map.get(
                    (
                        iface_name,
                        public_key,
                    )
                )
                or 0
            )

            if (
                handshake
                and now_epoch - handshake
                <= active_within_seconds
            ):
                activity['active'] += 1

            else:
                activity['idle'] += 1

        counts = {
            'active': activity['active'],
            'idle': activity['idle'],
            'blocked': activity['blocked'],
            'total': activity['total'],
            'activity_window_seconds': (
                active_within_seconds
            ),

            'online': activity['active'],
            'offline': activity['idle'],
        }

        return jsonify({
            'cpu': cpu,
            'mem': mem,
            'disk': disk,
            'uptime_value': uptime_value,
            'uptime_unit': uptime_unit,
            'uptime_str': uptime_str,
            'counts': counts,
        }), 200

    except Exception:
        current_app.logger.exception(
            'Mini stats failed'
        )

        return jsonify(
            error='stats_unavailable',
        ), 503

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

    def _as_int(v, default=None):
        try:
            if v is None or v == '':
                return default
            return int(v)
        except Exception:
            return default

    def _as_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        return str(v or '').strip().lower() in ('1', 'true', 'yes', 'on')

    def _clean_keepalive(v):
        n = _as_int(v, None)
        return n if n and n > 0 else None

    def _clean_mtu(v):
        n = _as_int(v, None)
        return n if n and n > 0 else None

    # --------------------
    # NODE PEER CREATE
    # --------------------
    if scope == 'node':
        nid = _as_int(data.get('node_id') or data.get('nodeId'), 0)
        iface_name = (
            data.get('iface_name') or
            data.get('ifaceName') or
            data.get('iface') or
            ''
        ).strip()

        if not nid or not iface_name:
            return jsonify(error='node_id and iface_name required for node scope'), 400

        n = Node.query.get_or_404(nid)

        name = (data.get('name') or '').strip() or 'peer'
        endpoint = (data.get('endpoint') or '').strip()
        allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()
        keepalive = _clean_keepalive(data.get('persistent_keepalive'))
        mtu = _clean_mtu(data.get('mtu'))
        dns = (data.get('dns') or '').strip() or None

        phone = (data.get('phone_number') or data.get('phone') or '').strip()
        tg = (data.get('telegram_id') or data.get('telegram') or '').strip()

        combined_days = _conv_time_limit(data)
        created_ts = now_ts()

        data_limit_value = _as_int(
            data.get('data_limit_value') if data.get('data_limit_value') is not None else data.get('data_limit'),
            0
        )
        data_limit_unit = (
            data.get('data_limit_unit') or
            data.get('limit_unit') or
            'Mi'
        )

        start_on_first_use = _as_bool(data.get('start_on_first_use'))
        unlimited = _as_bool(data.get('unlimited'))

        node_ifaces = {}
        remote_iface = {}
        try:
            node_ifaces = node_get(
                n,
                "/api/interfaces",
                timeout=10,
            ) or {}

            if isinstance(node_ifaces, dict):
                rows = node_ifaces.get("interfaces") or []
            else:
                rows = node_ifaces or []

            if not isinstance(rows, list):
                rows = []

            remote_iface = next(
                (
                    row
                    for row in rows
                    if str((row or {}).get("name") or "") == iface_name
                ),
                {},
            ) or {}

        except Exception:
            current_app.logger.exception(
                "Failed to fetch node interfaces for node_id=%s",
                nid,
            )
            node_ifaces = {}
            remote_iface = {}

        try:
            node_post(n, f"/api/iface/{iface_name}/up", {})
        except Exception:
            pass

        try:
            priv = subprocess.check_output(
                ['wg', 'genkey'],
                stderr=subprocess.DEVNULL,
                timeout=3
            ).strip().decode()

            pub = subprocess.check_output(
                ['wg', 'pubkey'],
                input=(priv + '\n').encode(),
                stderr=subprocess.DEVNULL,
                timeout=3
            ).strip().decode()
        except Exception as e:
            current_app.logger.exception("key generation failed")
            return jsonify(error="key_generation_failed", detail=str(e)), 500

        iface = ensure_node_mirror_iface(
            n, iface_name, remote_iface,
            mtu=mtu, dns=dns,
            listen_port=data.get('listen_port'),
            server_cidr=data.get('server_cidr'),
        )

        try:
            addr = node_install_peer(
                n, iface_name, iface,
                public_key=pub,
                requested_address=(data.get('address') or '').strip(),
                peer_endpoint=(data.get('peer_endpoint') or '').strip(),
                keepalive=keepalive or 0,
                mtu=mtu,
                dns=dns,
                allowed_ips=allowed_ips,
            )
        except AddressAllocationError as e:
            db.session.rollback()
            return address_error_response(e)
        except NodePeerInstallError as e:
            cleanup_failures = []
            try:
                _rollback_node_created_peer(n, pub)
            except Exception as cleanup_exc:
                cleanup_failures.append({
                    'scope': 'node', 'public_key': pub, 'detail': str(cleanup_exc),
                })
                current_app.logger.exception(
                    'Ambiguous node create cleanup failed for %s', pub
                )
            db.session.rollback()
            current_app.logger.warning(
                "node_create_failed node_id=%s iface=%s: %s", nid, iface_name, e.detail
            )
            return jsonify(
                error=e.code, detail=e.detail,
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else e.status

        compensation = PeerCreateCompensation()
        compensation.register_node(n, pub)
        try:
            peer = Peer(
                iface_id=iface.id,
                name=name,
                public_key=pub,
                private_key=priv,
                created_at=from_ts(created_ts),
                timer_started_at=from_ts(created_ts),
                address=addr,
                allowed_ips=allowed_ips,
                endpoint=endpoint or None,
                peer_endpoint=(data.get('peer_endpoint') or '').strip() or None,
                persistent_keepalive=keepalive,
                mtu=mtu,
                dns=dns,
                status='online',
                data_limit_value=data_limit_value,
                data_limit_unit=data_limit_unit,
                start_on_first_use=start_on_first_use,
                time_limit_days=combined_days,
                unlimited=unlimited,
                phone_number=phone or '',
                telegram_id=tg or '',
            )

            if (
                peer.time_limit_days
                and not peer.start_on_first_use
                and not peer.unlimited
            ):
                peer.expires_at = from_ts(
                    add_days_ts(
                        created_ts,
                        float(
                            peer.time_limit_days
                        ),
                    )
                )
        except Exception as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            return jsonify(
                error='peer_prepare_failed', detail=str(e),
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else 400

        short_token = None
        short_url = None
        try:
            db.session.add(peer)
            db.session.flush()
            try:
                short_token, short_url = _shortlink_for_peer(peer)
            except Exception:
                current_app.logger.exception(
                    "shortlink create failed for node peer %s",
                    getattr(peer, "id", "?")
                )
            try:
                log_event(
                    peer,
                    'created',
                    f"node create; node_id={nid}; iface={iface_name}; "
                    f"Limit={peer.data_limit_value}{peer.data_limit_unit or ''}; "
                    f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
                )
            except Exception:
                pass

            try:
                logpanel_action(
                    "peer_create",
                    f"pid={peer.id}; scope=node; node_id={nid}; iface={iface_name}; "
                    f"unlimited={peer.unlimited}; days={peer.time_limit_days}"
                )
            except Exception:
                pass

            db.session.commit()

        except Exception as e:
            cleanup_failures = compensation.rollback()
            db.session.rollback()
            current_app.logger.exception("DB save failed after node peer create: %s", e)
            return jsonify(
                error="db_save_failed", detail=str(e),
                cleanup_complete=not cleanup_failures,
                cleanup_failures=cleanup_failures,
            ), 502 if cleanup_failures else 500

        return jsonify(
            success=True,
            ok=True,
            scope='node',
            node_id=nid,
            iface=iface_name,
            id=peer.id,
            public_key=peer.public_key,
            shortlink=short_url or '',
            shortlink_token=short_token or '',
            address=peer.address,
            endpoint=_effective_client_endpoint(peer),
            peer_endpoint=peer.peer_endpoint or '',
            phone_number=peer.phone_number or '',
            telegram_id=peer.telegram_id or ''
        ), 200

    # ---------------------
    # LOCAL PEER CREATE
    # ---------------------
    iface_id = data.get('iface_id')
    if not iface_id:
        return jsonify(error='iface_id required'), 400

    try:
        iface_id = int(iface_id)
    except Exception:
        return jsonify(error='invalid iface_id'), 400

    iface = db.session.get(InterfaceConfig, iface_id)
    if not iface:
        return jsonify(error='Interface not found'), 404

    try:
        priv = subprocess.check_output(
            ['wg', 'genkey'],
            stderr=subprocess.DEVNULL,
            timeout=3
        ).strip().decode()

        pub = subprocess.check_output(
            ['wg', 'pubkey'],
            input=(priv + '\n').encode(),
            stderr=subprocess.DEVNULL,
            timeout=3
        ).strip().decode()
    except Exception as e:
        current_app.logger.exception("key generation failed")
        return jsonify(error="key_generation_failed", detail=str(e)), 500

    combined_days = _conv_time_limit(data)
    created_ts = now_ts()

    phone = (data.get('phone_number') or data.get('phone') or '').strip()
    tg = (data.get('telegram_id') or data.get('telegram') or '').strip()

    allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()
    endpoint = (data.get('endpoint') or '').strip()
    peer_endpoint = (data.get('peer_endpoint') or '').strip()
    keepalive = _clean_keepalive(data.get('persistent_keepalive'))
    mtu = _clean_mtu(data.get('mtu'))
    dns = (data.get('dns') or '').strip() or None

    data_limit_value = _as_int(
        data.get('data_limit_value') if data.get('data_limit_value') is not None else data.get('data_limit'),
        0
    )
    data_limit_unit = (
        data.get('data_limit_unit') or
        data.get('limit_unit') or
        'Mi'
    )

    peer = Peer(
        iface_id=iface.id,
        name=(data.get('name') or '').strip() or 'peer',
        public_key=pub,
        private_key=priv,
        created_at=from_ts(created_ts),
        timer_started_at=from_ts(created_ts),
        allowed_ips=allowed_ips,
        endpoint=endpoint or None,
        peer_endpoint=peer_endpoint or None,
        persistent_keepalive=keepalive,
        mtu=mtu,
        dns=dns,
        status='online',
        data_limit_value=data_limit_value,
        data_limit_unit=data_limit_unit,
        start_on_first_use=_as_bool(data.get('start_on_first_use')),
        time_limit_days=combined_days,
        unlimited=_as_bool(data.get('unlimited')),
        phone_number=phone or '',
        telegram_id=tg or '',
    )

    if peer.time_limit_days and not peer.start_on_first_use and not peer.unlimited:
        exp_ts = add_days_ts(created_ts, float(peer.time_limit_days))
        peer.expires_at = from_ts(exp_ts)

    short_token = None
    short_url = None
    installed = False

    with interface_allocation_lock(iface):
        try:
            peer.address = allocate_peer_address(iface, requested=data.get('address'))
        except AddressAllocationError as e:
            return address_error_response(e)

        try:
            db.session.add(peer)
            db.session.flush()

            install_local_peer(peer)
            installed = True

            try:
                log_event(
                    peer,
                    'created',
                    f"Limit={peer.data_limit_value}{peer.data_limit_unit or ''}; "
                    f"days={peer.time_limit_days}; unlimited={peer.unlimited}"
                )
            except Exception:
                pass

            try:
                logpanel_action(
                    "peer_create",
                    f"pid={peer.id}; scope=local; iface={iface.name}; "
                    f"unlimited={peer.unlimited}; days={peer.time_limit_days}"
                )
            except Exception:
                pass

            db.session.commit()

        except Exception as e:
            if installed:
                _wg_disable_quiet(peer)
                _remove_peer_quiet(peer)
            db.session.rollback()
            current_app.logger.exception("local peer create failed: %s", e)
            return jsonify(error="local_create_failed", detail=str(e)), 500

    try:
        short_token, short_url = _shortlink_for_peer(peer)
    except Exception:
        current_app.logger.exception(
            "shortlink create failed for local peer %s", getattr(peer, "id", "?")
        )

    return jsonify(
        success=True,
        ok=True,
        scope='local',
        id=peer.id,
        public_key=peer.public_key,
        shortlink=short_url or '',
        shortlink_token=short_token or '',
        address=peer.address,
        endpoint=_effective_client_endpoint(peer),
        peer_endpoint=peer.peer_endpoint or '',
        phone_number=peer.phone_number or '',
        telegram_id=peer.telegram_id or ''
    ), 200

@app.route('/api/peers')
@require_api_key_or_login
def panel_peers():

    try:
        _expire()
    except Exception:
        current_app.logger.exception(
            "Peer expiration processing failed during refresh"
        )

    try:
        server_public_ip = _public_ipv4()
    except Exception:
        server_public_ip = ''

    output = []

    interface_id = request.args.get(
        'iface_id',
        type=int,
    )

    interface_name_filter = (
        request.args.get('iface') or ''
    ).strip()

    try:
        query = Peer.query

        if interface_id is not None:
            query = query.filter(
                Peer.iface_id == interface_id
            )

        elif interface_name_filter:
            query = (
                query
                .join(InterfaceConfig)
                .filter(
                    InterfaceConfig.name
                    == interface_name_filter
                )
            )

        peers = query.all()

    except Exception:
        current_app.logger.exception(
            "Failed to query peers"
        )

        return jsonify(
            peers=[],
            error='peer_query_failed',
        ), 200

    transfer_map, handshake_map = _wg_runtime_snapshot(
        [
            getattr(
                getattr(peer, 'iface', None),
                'name',
                '',
            )
            for peer in peers
        ]
    )

    usage_dirty = False
    current_timestamp = now_ts()

    for peer in peers:
        try:
            interface = getattr(
                peer,
                'iface',
                None,
            )

            database_interface_name = (
                getattr(interface, 'name', '') or ''
            ).strip()

            runtime_key = (
                database_interface_name,
                peer.public_key,
            )

            rx_bytes, tx_bytes = transfer_map.get(
                runtime_key,
                (0, 0),
            )

            try:
                rx_bytes = max(0, int(rx_bytes or 0))
            except (TypeError, ValueError):
                rx_bytes = 0

            try:
                tx_bytes = max(0, int(tx_bytes or 0))
            except (TypeError, ValueError):
                tx_bytes = 0

            live_total = rx_bytes + tx_bytes

            (
                used_bytes,
                _new_usage,
                usage_changed,
            ) = _accumulate_peer_usage(
                peer,
                live_total=live_total,
            )

            if usage_changed:
                usage_dirty = True

            connection = _peer_conn_status(
                peer,
                live_total=live_total,
                latest_handshake=handshake_map.get(
                    runtime_key,
                    0,
                ),
                allow_probe=False,
            )

            rx_mib = str(
                round(
                    rx_bytes / 1024 / 1024,
                    2,
                )
            )

            tx_mib = str(
                round(
                    tx_bytes / 1024 / 1024,
                    2,
                )
            )

            expires_timestamp = _effective_expiry_ts(peer)
            expires_at = from_ts(expires_timestamp)

            ttl_seconds = (
                max(
                    0,
                    expires_timestamp - current_timestamp,
                )
                if expires_timestamp
                else None
            )

            shortlink_token = ''
            shortlink_url = ''

            try:
                (
                    shortlink_token,
                    shortlink_url,
                ) = _shortlink_from_peer_id(
                    peer.id
                )

                if not shortlink_token or not shortlink_url:
                    (
                        shortlink_token,
                        shortlink_url,
                    ) = _shortlink_for_peer(
                        peer
                    )

            except Exception:
                current_app.logger.exception(
                    "Shortlink attach failed while listing peer %s",
                    getattr(peer, 'id', '?'),
                )

            output.append({
                'id': peer.id,

                'shortlink': shortlink_url or '',
                'shortlink_token': shortlink_token or '',

                'name': peer.name,
                'iface': database_interface_name,
                'listen_port': getattr(
                    interface,
                    'listen_port',
                    None,
                ),

                'server_public_ip': server_public_ip,

                'address': peer.address,
                'endpoint': resolve_client_endpoint_cheap(interface, explicit=peer.endpoint),
                'endpoint_saved': peer.endpoint or '',
                'peer_endpoint': getattr(peer, 'peer_endpoint', None) or '',
                'allowed_ips': peer.allowed_ips or '',

                'persistent_keepalive':
                    peer.persistent_keepalive,

                'mtu': peer.mtu,
                'dns': peer.dns,

                'status': peer.status,
                'panel_status': peer.status,

                'conn_status':
                    connection['conn_status'],

                'connection_status':
                    connection['connection_status'],

                'latest_handshake':
                    connection['latest_handshake'],

                'latest_handshake_age':
                    connection['latest_handshake_age'],

                'conn_reason':
                    connection['conn_reason'],

                'conn_probe':
                    connection.get(
                        'conn_probe',
                        False,
                    ),

                'data_limit': getattr(
                    peer,
                    'data_limit_value',
                    None,
                ),

                'limit_unit': getattr(
                    peer,
                    'data_limit_unit',
                    None,
                ),

                'unlimited': bool(
                    getattr(
                        peer,
                        'unlimited',
                        False,
                    )
                ),

                'time_limit_days': getattr(
                    peer,
                    'time_limit_days',
                    None,
                ),

                'start_on_first_use': bool(
                    getattr(
                        peer,
                        'start_on_first_use',
                        False,
                    )
                ),

                'created_at': isoz(
                    getattr(
                        peer,
                        'created_at',
                        None,
                    )
                ),

                'display_timezone': _panel_timezone_name(),

                'created_at_display': _panel_display_datetime(
                    getattr(peer, 'created_at', None)
                ),

                'created_at_ts': to_ts(
                    getattr(
                        peer,
                        'created_at',
                        None,
                    )
                ),

                'first_used_at': isoz(
                    getattr(
                        peer,
                        'first_used_at',
                        None,
                    )
                ),

                'first_used_at_display': _panel_display_datetime(
                    getattr(peer, 'first_used_at', None)
                ),

                'first_used_at_ts': to_ts(
                    getattr(
                        peer,
                        'first_used_at',
                        None,
                    )
                ),

                'expires_at': isoz(
                    expires_at
                ),

                'expires_at_display': _panel_display_datetime(
                    expires_at
                ),

                'expires_at_ts':
                    expires_timestamp,

                'ttl_seconds':
                    ttl_seconds,

                'used_bytes':
                    used_bytes,

                'used_bytes_db':
                    used_bytes,

                'phone_number': (
                    getattr(
                        peer,
                        'phone_number',
                        '',
                    ) or ''
                ),

                'telegram_id': (
                    getattr(
                        peer,
                        'telegram_id',
                        '',
                    ) or ''
                ),

                'rx': rx_mib,
                'tx': tx_mib,
            })

        except Exception:
            current_app.logger.exception(
                "Failed to serialize peer %s",
                getattr(peer, 'id', '?'),
            )

    if usage_dirty:
        try:
            db.session.commit()

        except Exception:
            db.session.rollback()

            current_app.logger.exception(
                "Failed to persist peer usage after refresh"
            )

    return jsonify(
        peers=output,
    ), 200

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

        try:
            nid = int(nid)
        except Exception:
            return jsonify(error="invalid node_id"), 400

        try:
            count = int(data.get('count') or data.get('bulkPeerCount') or 0)
        except Exception:
            count = 0

        if count < 1:
            return jsonify(error="count is required"), 400

        n = Node.query.get_or_404(nid)

        prefix = (data.get('prefix') or data.get('name_prefix') or 'b').strip() or 'b'

        combined_days = _conv_time_limit({
            'time_limit_days': data.get('time_limit_days'),
            'time_limit_hours': data.get('time_limit_hours'),
            'time_limit_minutes': data.get('time_limit_minutes'),
        })

        allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()
        endpoint = (data.get('endpoint') or '').strip()

        try:
            keepalive = int(data.get('persistent_keepalive') or 0)
        except Exception:
            keepalive = 0

        try:
            mtu = int(data.get('mtu')) if str(data.get('mtu') or '').strip() else None
        except Exception:
            mtu = None

        dns = (data.get('dns') or '').strip() or None

        try:
            dlim_val = int(data.get('data_limit_value') or data.get('data_limit') or 0)
        except Exception:
            dlim_val = 0

        dlim_unit = data.get('data_limit_unit') or data.get('limit_unit') or 'Mi'

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
            data.get('phone_number') or
            data.get('phones') or
            data.get('mobile_numbers') or
            data.get('mobiles')
        )

        tgs = _social_list(
            data.get('telegram_ids') or
            data.get('telegram_id') or
            data.get('telegrams') or
            data.get('telegram')
        )

        node_ifaces = {}
        remote_iface = {}
        try:
            node_ifaces = node_get(
                n,
                "/api/interfaces",
                timeout=10,
            ) or {}

            if isinstance(node_ifaces, dict):
                rows = node_ifaces.get("interfaces") or []
            else:
                rows = node_ifaces or []

            if not isinstance(rows, list):
                rows = []

            remote_iface = next(
                (
                    row
                    for row in rows
                    if str((row or {}).get("name") or "") == iface_name
                ),
                {},
            ) or {}

        except Exception:
            current_app.logger.exception(
                "Failed to fetch node interfaces for node_id=%s",
                nid,
            )
            node_ifaces = {}
            remote_iface = {}


        try:
            avail = node_get(n, f"/api/iface/{iface_name}/available_ips", timeout=10)
            if isinstance(avail, dict):
                avail_ips = avail.get("available_ips", []) or []
            else:
                avail_ips = avail or []

            if not isinstance(avail_ips, list):
                avail_ips = []
        except Exception as e:
            current_app.logger.exception(
                "node bulk available_ips failed node_id=%s iface=%s",
                nid,
                iface_name
            )
            return jsonify(error="node_available_ips_failed", detail=str(e)), 502

        if not avail_ips:
            return jsonify(error="No available IPs for this node interface"), 409

        requested_count = count

        try:
            node_post(n, f"/api/iface/{iface_name}/up", {})
        except Exception:
            pass

        iface = ensure_node_mirror_iface(
            n, iface_name, remote_iface,
            mtu=mtu, dns=dns,
            listen_port=data.get('listen_port'),
            server_cidr=data.get('server_cidr'),
        )

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
            except Exception:
                next_num = 1

        created, errors = [], []
        shortlinks_by_id = {}
        pool_exhausted = False

        for i in range(count):
            pub = ''
            try:
                priv = subprocess.check_output(
                    ['wg', 'genkey'],
                    stderr=subprocess.DEVNULL,
                    timeout=3
                ).strip().decode()

                pub = subprocess.check_output(
                    ['wg', 'pubkey'],
                    input=(priv + '\n').encode(),
                    stderr=subprocess.DEVNULL,
                    timeout=3
                ).strip().decode()

                name = f"{prefix}{next_num + i}"
                created_ts = now_ts()

                try:
                    addr = node_install_peer(
                        n, iface_name, iface,
                        public_key=pub,
                        peer_endpoint=(data.get('peer_endpoint') or '').strip(),
                        keepalive=keepalive or 0,
                        mtu=mtu,
                        dns=dns,
                        allowed_ips=allowed_ips,
                    )
                except NodePeerInstallError as e:
                    if e.code == 'address_pool_exhausted':

                        pool_exhausted = True
                        break
                    raise

                peer = Peer(
                    iface_id=iface.id,
                    name=name,
                    public_key=pub,
                    private_key=priv,
                    created_at=from_ts(created_ts),
                    timer_started_at=from_ts(created_ts),
                    address=addr,
                    allowed_ips=allowed_ips,
                    endpoint=endpoint or None,
                    peer_endpoint=(data.get('peer_endpoint') or '').strip() or None,
                    persistent_keepalive=keepalive if keepalive > 0 else None,
                    mtu=mtu,
                    dns=dns,
                    status='online',
                    data_limit_value=dlim_val,
                    data_limit_unit=dlim_unit,
                    time_limit_days=combined_days,
                    start_on_first_use=start_on_first_use,
                    unlimited=unlimited,
                    phone_number=phones[i] if i < len(phones) else '',
                    telegram_id=tgs[i] if i < len(tgs) else '',
                )

                if (
                    peer.time_limit_days
                    and not peer.start_on_first_use
                    and not peer.unlimited
                ):
                    peer.expires_at = from_ts(
                        add_days_ts(
                            created_ts,
                            float(
                                peer.time_limit_days
                            ), 
                        )
                    )

                db.session.add(peer)
                db.session.flush()

                try:
                    token, url = _shortlink_for_peer(peer)
                    shortlinks_by_id[int(peer.id)] = {
                        "token": token or "",
                        "url": url or "",
                    }
                except Exception:
                    current_app.logger.exception(
                        "shortlink create failed for node bulk peer %s",
                        getattr(peer, "id", "?")
                    )

                try:
                    db.session.add(
                        PeerEvent(
                            peer_id=peer.id,

                            timestamp=peer.created_at,

                            event='created',

                            details=(
                                f"node bulk; "
                                f"node_id={nid}; "
                                f"iface={iface_name}; "
                                f"Limit={peer.data_limit_value}"
                                f"{peer.data_limit_unit or ''}; "
                                f"days={peer.time_limit_days}; "
                                f"unlimited={peer.unlimited}"
                        ),
                    )
                )
                except Exception:
                    pass

                created.append(peer)

            except requests.HTTPError as e:

                body = getattr(e.response, 'text', '') if getattr(e, 'response', None) else ''
                current_app.logger.exception(
                    "node bulk create failed node_id=%s iface=%s index=%s",
                    nid,
                    iface_name,
                    i
                )
                errors.append({
                    'index': i,
                    'error': str(e),
                    'body': body[:800] if body else '',
                })

                if pub:
                    try:
                        node_delete(n, f"/api/peer/{pub}")
                    except Exception:
                        pass

            except NodePeerInstallError as e:

                current_app.logger.exception(
                    "node bulk create failed node_id=%s iface=%s index=%s code=%s",
                    nid, iface_name, i, e.code
                )
                errors.append({
                    'index': i,
                    'error': e.code,
                    'detail': e.detail,
                })

                if pub:
                    try:
                        node_delete(n, f"/api/peer/{pub}")
                    except Exception:
                        pass

            except Exception as e:
                current_app.logger.exception(
                    "node bulk create failed node_id=%s iface=%s index=%s",
                    nid,
                    iface_name,
                    i
                )
                errors.append({'index': i, 'error': str(e)})

                if pub:
                    try:
                        node_delete(n, f"/api/peer/{pub}")
                    except Exception:
                        pass

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("node bulk DB commit failed: %s", e)

            for peer in created:
                try:
                    node_delete(n, f"/api/peer/{peer.public_key}")
                except Exception:
                    pass

            return jsonify(error="node_bulk_db_commit_failed", detail=str(e)), 500

        for peer in created:
            try:
                logpanel_action(
                    "peer_create",
                    f"pid={peer.id}; scope=node_bulk; node_id={nid}; iface={iface_name}; "
                    f"unlimited={peer.unlimited}; days={peer.time_limit_days}"
                )
            except Exception:
                pass

        return jsonify(
            ok=True,
            success=True,
            scope='node',
            node_id=nid,
            iface=iface_name,
            created=len(created),
            errors=errors,
            requested_count=requested_count,
            pool_exhausted=pool_exhausted,
            first_name=created[0].name if created else None,
            last_name=created[-1].name if created else None,
            peers=[{
                'id': p.id,
                'node_id': nid,
                'name': p.name,
                'iface': iface_name,
                'public_key': p.public_key,
                'address': p.address,
                'shortlink': (shortlinks_by_id.get(int(p.id)) or {}).get('url', ''),
                'shortlink_token': (shortlinks_by_id.get(int(p.id)) or {}).get('token', ''),
                'phone_number': getattr(p, 'phone_number', '') or '',
                'telegram_id': getattr(p, 'telegram_id', '') or '',
            } for p in created]
        ), 200

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
        'time_limit_minutes': data.get('time_limit_minutes'),
    })

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

    peer_endpoint = (data.get('peer_endpoint') or '').strip()

    created, errors = [], []
    shortlinks_by_id = {}
    pool_exhausted = False

    with interface_allocation_lock(iface):
        for i in range(count):
            peer = None
            installed = False
            try:
                addr = allocate_peer_address(iface)

                priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
                pub  = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()
                name = f"{prefix}{next_num + i}"
                created_ts = now_ts()

                peer = Peer(
                    iface_id=iface.id, name=name,
                    public_key=pub, private_key=priv,
                    created_at=from_ts(created_ts),
                    timer_started_at=from_ts(created_ts),
                    address=addr, allowed_ips=allowed_ips,
                    endpoint=endpoint or None,
                    peer_endpoint=peer_endpoint or None,
                    persistent_keepalive=keepalive,
                    mtu=mtu, dns=dns,
                    status='online',
                    data_limit_value=int(dlim_val) if dlim_val else 0,
                    data_limit_unit=dlim_unit,
                    time_limit_days=combined_days,
                    start_on_first_use=start_on_first_use,
                    unlimited=unlimited,
                    phone_number=phones[i] if i < len(phones) else '',
                    telegram_id=tgs[i] if i < len(tgs) else '',
                )

                if (
                    peer.time_limit_days
                    and not peer.start_on_first_use
                    and not peer.unlimited
                ):
                    peer.expires_at = from_ts(
                        add_days_ts(
                            created_ts,
                            float(
                                peer.time_limit_days
                            ),
                        )
                    )

                db.session.add(peer)
                db.session.flush()

                install_local_peer(peer)
                installed = True

                db.session.add(
                    PeerEvent(
                        peer_id=peer.id,

                        timestamp=peer.created_at,

                        event='created',

                        details=(
                            f"bulk; "
                            f"Limit={peer.data_limit_value}"
                            f"{peer.data_limit_unit or ''}; "
                            f"days={peer.time_limit_days}; "
                            f"unlimited={peer.unlimited}"
                        ),
                    )
                )
                db.session.commit()
                created.append(peer)

            except AddressPoolExhausted:
                db.session.rollback()
                pool_exhausted = True
                break
            except Exception as e:
                if installed and peer is not None:
                    _wg_disable_quiet(peer)
                    _remove_peer_quiet(peer)
                db.session.rollback()
                current_app.logger.exception("bulk create failed at index %s: %s", i, e)
                errors.append({'index': i, 'error': str(e)})

    for peer in created:
        try:
            token, url = _shortlink_for_peer(peer)
            shortlinks_by_id[int(peer.id)] = {"token": token or "", "url": url or ""}
        except Exception:
            current_app.logger.exception(
                "shortlink create failed for bulk peer %s", getattr(peer, "id", "?")
            )

        try:
            logpanel_action(
                "peer_create",
                f"pid={peer.id}; iface={iface.name}; unlimited={peer.unlimited}; "
                f"days={peer.time_limit_days}"
            )
        except Exception:
            pass


    return jsonify(
        ok=True,
        scope='local',
        iface=iface.name,
        created=len(created),
        errors=errors,
        requested_count=count,
        pool_exhausted=pool_exhausted,
        first_name=created[0].name if created else None,
        last_name=created[-1].name if created else None,
        peers=[{
            'id': p.id,
            'name': p.name,
            'address': p.address,
            'shortlink': (shortlinks_by_id.get(int(p.id)) or {}).get('url', ''),
            'shortlink_token': (shortlinks_by_id.get(int(p.id)) or {}).get('token', ''),
            'phone_number': getattr(p, 'phone_number', '') or '',
            'telegram_id': getattr(p, 'telegram_id', '') or ''
        } for p in created]
    ), 200

@app.route('/api/iface/<int:iface_id>/available_ips')
@require_api_key_or_login
def iface_available_ips(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    return jsonify(available_ips=_available_ips(iface))

def _private_networks():

    networks = []

    try:
        for interface_name, addresses in psutil.net_if_addrs().items():
            if interface_name == 'lo':
                continue

            for address in addresses:
                if getattr(address, 'family', None) != socket.AF_INET:
                    continue

                ip_value = (
                    getattr(address, 'address', '')
                    or ''
                ).split('%', 1)[0]

                netmask = getattr(address, 'netmask', None)

                if not ip_value or not netmask:
                    continue

                try:
                    interface = ipaddress.ip_interface(
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
        current_app.logger.exception(
            'Failed to detect local private networks'
        )

    return networks
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

    scope_networks = _private_networks()

    for i in InterfaceConfig.query.all():
        if ':' in (i.name or ''):
            continue

        row = {
            'id': i.id,
            'name': i.name,
            'address': i.address or '',
            'server_cidr': i.address or '',
            'scope_networks': scope_networks,
            'listen_port': i.listen_port,
            'mtu': i.mtu,
            'dns': i.dns,
            'available_ips': _available_ips(i),
            'is_up': _iface_up(i.name),
        }

        override = iface_endpoint_override(i)
        row.update({
            'endpoint_host': (getattr(i, 'endpoint_host', None) or '').strip() or None,
            'endpoint_port': int(i.endpoint_port) if getattr(i, 'endpoint_port', None) else None,
            'endpoint_override': override,
            'auto_endpoint': '',
            'effective_endpoint': override,
            'endpoint_source': 'override' if override else 'auto',
        })
        out.append(row)

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

def _egress_interface() -> str:
    """
    Detect the server's real outbound IPv4 interface.

    Avoid selecting WireGuard/tunnel/container interfaces as
    the MASQUERADE egress device.
    """

    try:
        output = subprocess.check_output(
            [
                'ip',
                '-4',
                'route',
                'get',
                '1.1.1.1',
            ],
            stderr=subprocess.DEVNULL,
            timeout=4,
        ).decode(
            'utf-8',
            'replace',
        )

        matches = re.findall(
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

            if re.match(
                r'^(wg|tun|tap|docker|br-|veth)',
                candidate,
                re.IGNORECASE,
            ):
                continue

            return candidate

    except Exception:
        current_app.logger.exception(
            'Could not detect the default '
            'IPv4 egress interface'
        )

    # Fallback: inspect the IPv4 default route.
    try:
        output = subprocess.check_output(
            [
                'ip',
                '-4',
                'route',
                'show',
                'default',
            ],
            stderr=subprocess.DEVNULL,
            timeout=4,
        ).decode(
            'utf-8',
            'replace',
        )

        matches = re.findall(
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

            if re.match(
                r'^(wg|tun|tap|docker|br-|veth)',
                candidate,
                re.IGNORECASE,
            ):
                continue

            return candidate

    except Exception:
        current_app.logger.exception(
            'Could not detect IPv4 egress '
            'from the default route'
        )

    return ''


def _wireguard_network(address_field: str) -> str:

    for raw_value in re.split(
        r"[\s,]+",
        str(address_field or "").strip(),
    ):
        value = raw_value.strip()

        if not value or "/" not in value:
            continue

        try:
            interface = ipaddress.ip_interface(value)
        except ValueError:
            continue

        if (
            interface.version == 4
            and interface.ip.is_private
        ):
            return str(interface.network)

    return ""


def _wg_firewall_rules(
    interface_name: str,
    address_field: str,
) -> tuple[str, str]:

    network = _wireguard_network(
        address_field
    )

    if not network:
        raise ValueError(
            "Automatic forwarding requires a private IPv4 "
            "WireGuard subnet."
        )

    egress = _egress_interface()

    if not egress:
        raise ValueError(
            "The default IPv4 network interface "
            "could not be detected."
        )

    if not re.fullmatch(
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

@app.post("/api/interfaces")
@login_required
def create_local_interface():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        try:
            raw = request.get_data(cache=True, as_text=True).strip()
            data = json.loads(raw) if raw else None
        except (TypeError, ValueError, json.JSONDecodeError):
            data = None

    if not isinstance(data, dict):
        current_app.logger.warning(
            "Invalid interface-create payload: "
            "content_type=%r mimetype=%r body=%r",
            request.content_type,
            request.mimetype,
            request.get_data(cache=True, as_text=True)[:500],
        )

        return jsonify(
            ok=False,
            error="invalid_payload",
            detail="The request body must be a JSON object.",
        ), 400

    name = str(
        data.get("name")
        or data.get("iface")
        or data.get("interface_name")
        or ""
    ).strip()

    address = str(
        data.get("address")
        or ""
    ).strip()

    dns = str(
        data.get("dns")
        or ""
    ).strip() or None

    auto_up = bool(
        data.get("auto_up", True)
    )

    auto_firewall = bool(
        data.get("auto_firewall", True)
    )

    if not name:
        return jsonify(
            ok=False,
            error="interface_name_required",
            detail="Interface name is required.",
        ), 400

    if not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,32}",
        name,
    ):
        return jsonify(
            ok=False,
            error="invalid_name",
            detail=(
                f"Invalid interface name {name!r}. "
                "Use 1-32 characters: letters, numbers, "
                "underscore, dot, or dash."
            ),
        ), 400

    if not address:
        return jsonify(
            ok=False,
            error="address_required",
            detail=(
                "WireGuard interface address is required. "
                "Example: 10.77.0.1/24"
            ),
        ), 400

    address_parts = [
        value.strip()
        for value in re.split(r"[\s,]+", address)
        if value.strip()
    ]

    if not address_parts:
        return jsonify(
            ok=False,
            error="invalid_address",
            detail="No valid WireGuard address was supplied.",
        ), 400

    parsed_addresses = []

    for value in address_parts:
        try:
            parsed_addresses.append(
                ipaddress.ip_interface(value)
            )
        except ValueError:
            return jsonify(
                ok=False,
                error="invalid_address",
                detail=(
                    f"{value!r} is not a valid CIDR. "
                    "Example: 10.77.0.1/24"
                ),
            ), 400

    address = ", ".join(
        str(value)
        for value in parsed_addresses
    )

    try:
        listen_port = int(
            data.get("listen_port")
        )
    except (TypeError, ValueError):
        return jsonify(
            ok=False,
            error="invalid_listen_port",
            detail="Listen port must be a number between 1 and 65535.",
        ), 400

    if not 1 <= listen_port <= 65535:
        return jsonify(
            ok=False,
            error="invalid_listen_port",
            detail="Listen port must be between 1 and 65535.",
        ), 400

    raw_mtu = data.get("mtu")

    try:
        mtu = (
            int(raw_mtu)
            if raw_mtu not in (None, "")
            and str(raw_mtu).strip()
            else None
        )
    except (TypeError, ValueError):
        return jsonify(
            ok=False,
            error="invalid_mtu",
            detail="MTU must be a number between 576 and 9000.",
        ), 400

    if mtu is not None and not 576 <= mtu <= 9000:
        return jsonify(
            ok=False,
            error="invalid_mtu",
            detail="MTU must be between 576 and 9000.",
        ), 400

    existing = (
        InterfaceConfig.query
        .filter_by(name=name)
        .first()
    )

    if existing:
        return jsonify(
            ok=False,
            error="interface_exists",
            detail=f"Interface {name} already exists in the panel.",
        ), 409

    wg_dir = (
        app.config.get("WG_CONF_PATH")
        or "/etc/wireguard"
    )

    if os.path.isfile(wg_dir):
        wg_dir = os.path.dirname(wg_dir)

    try:
        os.makedirs(
            wg_dir,
            exist_ok=True,
        )
    except Exception as exc:
        return jsonify(
            ok=False,
            error="wireguard_directory_failed",
            detail=str(exc),
        ), 500

    conf_path = os.path.join(
        wg_dir,
        f"{name}.conf",
    )

    if os.path.exists(conf_path):
        return jsonify(
            ok=False,
            error="config_exists",
            detail=f"{conf_path} already exists.",
        ), 409

    if _iface_up(name):
        return jsonify(
            ok=False,
            error="interface_exists_system",
            detail=(
                f"Interface {name} already exists "
                "on the operating system."
            ),
        ), 409

    try:
        for iface in InterfaceConfig.query.all():
            if (
                int(iface.listen_port or 0)
                == listen_port
            ):
                return jsonify(
                    ok=False,
                    error="listen_port_in_use",
                    detail=(
                        f"Listen port {listen_port} is already "
                        f"used by {iface.name}."
                    ),
                ), 409
    except Exception:
        current_app.logger.exception(
            "Could not validate existing interface ports"
        )

    post_up = ""
    post_down = ""
    egress_interface = ""

    if auto_firewall:
        try:
            post_up, post_down = _wg_firewall_rules(
                name,
                address,
            )

            egress_interface = _egress_interface()

        except ValueError as exc:
            return jsonify(
                ok=False,
                error="auto_firewall_failed",
                detail=str(exc),
                hint=(
                    "Disable automatic firewall rules if you "
                    "want to create the interface without "
                    "PostUp/PostDown forwarding rules."
                ),
            ), 400

        except Exception as exc:
            current_app.logger.exception(
                "Automatic firewall generation failed for %s",
                name,
            )

            return jsonify(
                ok=False,
                error="auto_firewall_failed",
                detail=str(exc),
            ), 500

    try:
        private_key = (
            subprocess.check_output(
                ["wg", "genkey"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            .decode()
            .strip()
        )

    except Exception as exc:
        current_app.logger.exception(
            "wg genkey failed"
        )

        return jsonify(
            ok=False,
            error="wg_genkey_failed",
            detail=str(exc),
        ), 500

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]

    if mtu is not None:
        lines.append(
            f"MTU = {mtu}"
        )

    for command in str(
        post_up or "").splitlines():

        command = command.strip()

        if command:
            lines.append(f"PostUp = {command}")


    for command in str(
        post_down or "").splitlines():

        command = command.strip()

        if command:
            lines.append(f"PostDown = {command}")

    lines.append("")

    config_text = "\n".join(lines)

    temp_path = (
        conf_path
        + ".tmp"
    )

    try:
        with open(
            temp_path,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                config_text
            )

            handle.flush()
            os.fsync(
                handle.fileno()
            )

        os.chmod(
            temp_path,
            0o600,
        )

        os.replace(
            temp_path,
            conf_path,
        )

    except Exception as exc:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

        return jsonify(
            ok=False,
            error="write_config_failed",
            detail=str(exc),
        ), 500

    iface = InterfaceConfig(
        name=name,
        path=conf_path,
        address=address,
        listen_port=listen_port,
        private_key=private_key,
        mtu=mtu,
        dns=dns,
        post_up=post_up or None,
        post_down=post_down or None,
    )

    try:
        db.session.add(iface)
        db.session.commit()

    except Exception as exc:
        db.session.rollback()

        try:
            os.remove(conf_path)
        except Exception:
            pass

        current_app.logger.exception(
            "Could not save interface %s",
            name,
        )

        return jsonify(
            ok=False,
            error="database_save_failed",
            detail=str(exc),
        ), 500

    up_error = None

    if auto_up:
        try:
            proc = subprocess.run(
                [
                    "wg-quick",
                    "up",
                    name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )

            if proc.returncode != 0:
                up_error = (
                    proc.stderr
                    or proc.stdout
                    or f"wg-quick up {name} failed"
                ).strip()

            else:
                try:
                    subprocess.run(
                        [
                            "systemctl",
                            "enable",
                            f"wg-quick@{name}.service",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )
                except Exception:
                    current_app.logger.warning(
                        "Could not enable wg-quick@%s",
                        name,
                        exc_info=True,
                    )

        except Exception as exc:
            up_error = str(exc)

    return jsonify(
        ok=True,

        interface={
            "id": iface.id,
            "name": iface.name,
            "path": iface.path,
            "address": iface.address,
            "listen_port": iface.listen_port,
            "dns": iface.dns,
            "mtu": iface.mtu,
            "available_ips": _available_ips(iface),
            "is_up": _iface_up(name),
            "post_up": post_up,
            "post_down": post_down,
            "auto_firewall": auto_firewall,
            "egress_interface": egress_interface,
        },

        up_error=up_error,
    ), 201

def _inject_firewall_rules(
    config_path: str,
    interface_name: str,
    address_field: str,
) -> dict:


    if not os.path.isfile(config_path):
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
        post_up, post_down = _wg_firewall_rules(
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
        os.path.dirname(config_path)
        or "."
    )

    fd, temporary_path = tempfile.mkstemp(
        prefix=".wg-panel-firewall.",
        dir=directory,
    )

    try:
        try:
            original_mode = (
                os.stat(config_path).st_mode
                & 0o777
            )
        except OSError:
            original_mode = 0o600

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(
            temporary_path,
            original_mode,
        )

        os.replace(
            temporary_path,
            config_path,
        )

        temporary_path = ""

    finally:
        if (
            temporary_path
            and os.path.exists(temporary_path)
        ):
            try:
                os.unlink(
                    temporary_path
                )
            except OSError:
                pass

    runtime_applied = False
    runtime_error = ""

    if _iface_up(interface_name):
        runtime_applied = False
        runtime_error = ""

    if _iface_up(
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
                        shlex.quote(
                            interface_name
                        ),
                    )
                )

                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
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
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    command,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
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
    """
    upgrade old local Wg configs postup/down

    """
    configured_path = (
        app.config.get("WG_CONF_PATH")
        or app.config.get(
            "WIREGUARD_CONF_PATH"
        )
        or "/etc/wireguard"
    )

    if os.path.isdir(configured_path):
        paths = sorted(
            glob.glob(
                os.path.join(
                    configured_path,
                    "*.conf",
                )
            )
        )
    elif os.path.isfile(configured_path):
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
        parsed = find_iface(config_path)

        if not parsed:
            summary["skipped"] += 1
            continue

        summary["checked"] += 1

        result = _inject_firewall_rules(
            config_path,
            parsed.name,
            parsed.address,
        )

        if result.get("changed"):
            summary["updated"] += 1

            app.logger.info(
                "Added automatic firewall rules to "
                "legacy interface %s; runtime_applied=%s",
                parsed.name,
                result.get("runtime_applied"),
            )

            if result.get("runtime_error"):
                app.logger.warning(
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

            app.logger.warning(
                "Could not add firewall rules to "
                "legacy interface %s: %s",
                parsed.name,
                result,
            )

    return summary

@app.route('/api/iface/<int:iface_id>/enable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def iface_enable(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)

    try:
        _check_iface_up(iface)
    except Exception as e:
        current_app.logger.exception("Interface enable failed for %s", iface.name)
        return jsonify(
            success=False,
            error="interface_enable_failed",
            detail=str(e),
            hint="Open the interface logs in the panel, or run: journalctl -u wg-quick@%s -n 80 --no-pager" % iface_devname(iface)
        ), 409

    return jsonify(success=True, is_up=True)

@app.route('/api/iface/<int:iface_id>/disable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def iface_disable(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    _iface_down(iface.name)
    return jsonify(success=True, is_up=False)

@app.route('/api/iface/<int:iface_id>', methods=['DELETE'])
@csrf.exempt
@require_api_key_or_login
def iface_delete(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)

    if getattr(iface, 'node_id', None) is not None or ':' in (iface.name or ''):
        return jsonify(
            success=False,
            error='node_interface_delete_not_supported_here',
            detail='Delete node interfaces through the node interface API.'
        ), 400

    data = request.get_json(silent=True) or {}
    delete_peers = _sub_bool(
        data.get('delete_peers')
        if 'delete_peers' in data
        else request.args.get('delete_peers')
    )

    peers = Peer.query.filter_by(iface_id=iface.id).all()
    peer_count = len(peers)

    peer_ids = [p.id for p in peers]
    subscription_link_count = 0
    affected_subs = set()

    if peer_ids:
        links = SubscriptionPeer.query.filter(SubscriptionPeer.peer_id.in_(peer_ids)).all()
        subscription_link_count = len(links)
        for link in links:
            if link.subscription:
                affected_subs.add(link.subscription)

    if peer_count and not delete_peers:
        return jsonify(
            success=False,
            error='interface_has_peers',
            detail=f'Interface {iface.name} has {peer_count} peer(s).',
            peer_count=peer_count,
            subscription_link_count=subscription_link_count,
            require_delete_peers=True
        ), 409

    dev = iface_devname(iface)
    conf_path = iface.path or ''

    try:
        try:
            _iface_down(dev)
        except Exception:
            current_app.logger.exception("Failed to bring interface down before delete: %s", dev)

        if _iface_up(dev):
            current_app.logger.warning(
                "%s is still up after bringing it down; removing its peers individually",
                dev,
            )
            for peer in peers:
                try:
                    _wg_disable(peer)
                except Exception:
                    current_app.logger.exception(
                        "Failed to remove peer %s from the %s runtime",
                        getattr(peer, 'id', '?'), dev,
                    )

            still_live = _wg_peer_keys(dev) & {p.public_key for p in peers if p}
            if still_live:
                db.session.rollback()
                return jsonify(
                    success=False,
                    error='interface_still_up',
                    detail=(
                        f'{dev} could not be brought down and {len(still_live)} of its '
                        f'peer(s) are still live in the runtime. Nothing was deleted; '
                        f'bring the interface down manually and retry.'
                    ),
                    live_peers=len(still_live),
                ), 502

        _delete_shortlinks_for_peer_ids([p.id for p in peers if p])

        deleted_peers = 0
        if delete_peers:
            for peer in peers:
                SubscriptionPeer.query.filter_by(peer_id=peer.id).delete(
                    synchronize_session=False
                )
                db.session.delete(peer)
                deleted_peers += 1
            db.session.flush()

        if conf_path:
            try:
                wg_dir = app.config.get("WG_CONF_PATH") or "/etc/wireguard"
                allowed_dir = wg_dir if os.path.isdir(wg_dir) else os.path.dirname(wg_dir)
                allowed_dir = os.path.abspath(allowed_dir)
                real_conf = os.path.abspath(conf_path)

                if real_conf.startswith(allowed_dir + os.sep) and os.path.isfile(real_conf):
                    os.remove(real_conf)
            except Exception:
                current_app.logger.exception("Could not remove interface config file: %s", conf_path)

        try:
            log_path = _ifacelog_path(iface.id)
            if log_path and os.path.isfile(log_path):
                os.remove(log_path)
        except Exception:
            pass

        db.session.delete(iface)
        db.session.flush()

        for sub in affected_subs:
            try:
                _sync_all_subscription_peers(sub, rename=True)
            except Exception:
                current_app.logger.exception(
                    "Failed to sync subscription after interface delete: %s",
                    getattr(sub, 'id', '?')
                )

        db.session.commit()

        try:
            logpanel_action(
                "interface_delete",
                f"iface={dev}; delete_peers={bool(delete_peers)}; peers={peer_count}"
            )
        except Exception:
            pass

        return jsonify(
            success=True,
            deleted_interface=dev,
            deleted_peers=deleted_peers
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Interface delete failed for %s", iface.name)
        return jsonify(
            success=False,
            error='interface_delete_failed',
            detail=str(e)
        ), 500

# -----------------------------
# Peer enable / reset actions
# -----------------------------

@app.route('/api/peer/<int:pid>/enable', methods=['POST'])
@csrf.exempt
@require_api_key_or_login
def api_enable(pid):

    p = db.session.get(Peer, pid) or abort(404)
    iface = getattr(p, 'iface', None)

    if not iface:
        return jsonify(
            success=False,
            error='peer_interface_missing',
            detail='This peer is not attached to a WireGuard interface.'
        ), 409

    if getattr(iface, 'node_id', None) is not None:
        return jsonify(
            success=False,
            error='remote_peer',
            detail='This peer belongs to a remote node.'
        ), 409

    dev = ''
    host_cidr = ''

    try:
        dev = iface_devname(iface)
        host_cidr = _host_peer(p)

        if not dev:
            raise RuntimeError(
                'The peer interface has no valid device name.'
            )

        if not host_cidr:
            raise RuntimeError(
                'The peer has no valid WireGuard host address.'
            )

        if not _iface_up(dev):
            _check_iface_up(iface)

        if not _iface_up(dev):
            return jsonify(
                success=False,
                error='interface_down',
                detail=f"WireGuard interface '{dev}' is not running.",
                interface=dev,
                hint=(
                    f"Run: systemctl status "
                    f"wg-quick@{dev} --no-pager"
                )
            ), 409

        try:
            _unblackhole(host_cidr)
        except Exception:
            current_app.logger.warning(
                'Could not remove blackhole route for peer %s, route %s',
                pid,
                host_cidr,
                exc_info=True
            )

        _wg_enable(p)
        _sync_peer(p)

        try:
            live_total = int(_wg_transfer(p) or 0)
        except Exception:
            current_app.logger.warning(
                'Could not read WireGuard transfer value for peer %s',
                pid,
                exc_info=True
            )
            live_total = 0

        live_total = max(0, live_total)

        p.bytes_offset = live_total
        p.used_bytes_total = 0
        p.first_used_at = None
        p.timer_started_at = None

        try:
            time_limit_days = float(
                getattr(p, 'time_limit_days', 0) or 0
            )
        except (TypeError, ValueError):
            time_limit_days = 0.0

        unlimited = bool(
            getattr(p, 'unlimited', False)
        )

        start_on_first_use = bool(
            getattr(p, 'start_on_first_use', False)
        )

        if unlimited:
            p.expires_at = None

        elif start_on_first_use:
            p.expires_at = None

        elif time_limit_days > 0:
            _start_timer_cycle(p)

        else:
            p.expires_at = None

        p.status = 'online'

        db.session.commit()

        try:
            log_event(
                p,
                'enabled',
                (
                    'Peer enabled; timer and data reset; '
                    f'unlimited={int(unlimited)}; '
                    f'offset={live_total}'
                )
            )

            logpanel_action(
                'peer_enable',
                (
                    f'pid={p.id}; '
                    f'iface={dev}; '
                    f'host_cidr={host_cidr}; '
                    f'timer_reset=1; '
                    f'data_reset=1; '
                    f'unlimited={int(unlimited)}; '
                    f'offset={live_total}'
                )
            )
        except Exception:
            current_app.logger.warning(
                'Peer %s was enabled, but enable logging failed',
                pid,
                exc_info=True
            )

        return jsonify(
            success=True,
            ok=True,
            message='Peer enabled. Timer and data usage were reset.',
            status='online',
            interface=dev,
            host_cidr=host_cidr,
            timer_reset=True,
            data_reset=True,
            unlimited=unlimited,
            used_bytes_total=0,
            bytes_offset=live_total
        )

    except RuntimeError as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Peer enable failed for peer %s on interface %s',
            pid,
            dev or 'unknown'
        )

        return jsonify(
            success=False,
            error='peer_enable_failed',
            detail=str(exc),
            interface=dev,
            host_cidr=host_cidr,
            hint=(
                f"Run: wg show {dev}; "
                f"ip route show {host_cidr}; "
                f"systemctl status wg-quick@{dev} --no-pager"
            ) if dev else ''
        ), 409

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Unexpected enable failure for peer %s',
            pid
        )

        return jsonify(
            success=False,
            error='peer_enable_unexpected_error',
            detail=str(exc),
            interface=dev,
            host_cidr=host_cidr
        ), 500

@app.route('/api/peer/<int:pid>/reset_data', methods=['POST'])
@require_api_key
def reset_data(pid):
    """
    Reset traffic counters
    This does NOT re-enable the peer and does NOT change timer fields.
    """
    p = db.session.get(Peer, pid) or abort(404)

    try:
        current = int(_wg_transfer(p) or 0)
    except Exception:
        current = 0

    try:
        p.bytes_offset = max(0, current)
        p.used_bytes_total = 0

        db.session.commit()

        try:
            log_event(
                p,
                'reset_data',
                (
                    f'Traffic usage reset; runtime offset={current}; '
                    f'status preserved as {p.status}'
                )
            )
            logpanel_action(
                'peer_reset_data',
                (
                    f'pid={p.id}; offset={current}; '
                    f'status_preserved={p.status}; timer_preserved=1'
                )
            )
        except Exception:
            pass

        return jsonify(
            success=True,
            status=p.status,
            timer_preserved=True,
            data_reset=True
        )

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Data reset failed for peer %s',
            pid
        )

        return jsonify(
            success=False,
            error='reset_data_failed',
            detail=str(exc)
        ), 500


@app.route('/api/peer/<int:pid>/reset_timer', methods=['POST'])
@require_api_key
def api_reset_timer(pid):
    """
    Reset the peer timer only.

    The peer is re-enabled when necessary, but traffic usage is preserved.

    """
    p = db.session.get(Peer, pid) or abort(404)

    iface = getattr(p, 'iface', None)
    if not iface:
        return jsonify(
            success=False,
            error='peer_interface_missing',
            detail='This peer is not attached to a WireGuard interface.'
        ), 409

    original_bytes_offset = int(
        getattr(p, 'bytes_offset', 0) or 0
    )
    original_used_total = int(
        getattr(p, 'used_bytes_total', 0) or 0
    )

    try:
        time_limit = float(
            getattr(p, 'time_limit_days', 0) or 0
        )
    except (TypeError, ValueError):
        time_limit = 0.0

    try:
        p.first_used_at = None
        p.timer_started_at = None

        if getattr(p, 'unlimited', False) or time_limit <= 0:
            p.expires_at = None
            detail = 'Timer cleared'

        elif getattr(p, 'start_on_first_use', False):
            p.expires_at = None
            detail = 'Timer cleared; timer will start on first use'

        else:
            _start_timer_cycle(p)
            detail = f'Timer restarted for {time_limit:g} days'

        is_node_peer = (
            getattr(iface, 'node_id', None) is not None
            or ':' in str(getattr(iface, 'name', '') or '')
        )

        if is_node_peer:
            node = db.session.get(
                Node,
                getattr(iface, 'node_id', None)
            )

            if not node:
                return jsonify(
                    success=False,
                    error='node_not_found',
                    detail='The node for this peer was not found.'
                ), 404

            node_post(
                node,
                f'/api/peer/{p.public_key}/enable',
                {
                    'host_cidr': _host_peer(p),
                    'reset_timer': False,
                    'reset_data': False,
                    'preserve_usage': True,
                },
                timeout=15
            )

        else:
            dev = iface_devname(iface)

            if not _iface_up(dev):
                _check_iface_up(iface)

            if not _iface_up(dev):
                raise RuntimeError(
                    f"WireGuard interface '{dev}' is not running."
                )

            _wg_enable(p)
            _sync_peer(p)

        p.status = 'online'
        p.bytes_offset = original_bytes_offset
        p.used_bytes_total = original_used_total

        db.session.commit()

        try:
            log_event(
                p,
                'reset_timer',
                (
                    f'{detail}; peer enabled; '
                    f'data usage preserved at {original_used_total} bytes'
                )
            )
            logpanel_action(
                'peer_reset_timer',
                (
                    f'pid={p.id}; {detail}; '
                    f'data_preserved=1; used={original_used_total}; '
                    f'offset={original_bytes_offset}'
                )
            )
        except Exception:
            pass

        return jsonify(
            success=True,
            status=p.status,
            timer_reset=True,
            data_preserved=True,
            used_bytes_total=original_used_total
        )

    except requests.HTTPError as exc:
        db.session.rollback()

        response = getattr(exc, 'response', None)
        status_code = getattr(response, 'status_code', None)
        response_text = getattr(response, 'text', '') or ''

        current_app.logger.exception(
            'Node timer reset enable failed for peer %s',
            pid
        )

        return jsonify(
            success=False,
            error='node_enable_failed',
            detail=str(exc),
            node_status=status_code,
            node_body=response_text[:800]
        ), 502

    except subprocess.CalledProcessError as exc:
        db.session.rollback()

        try:
            dev = iface_devname(iface)
        except Exception:
            dev = ''

        current_app.logger.exception(
            'Timer reset enable failed for peer %s',
            pid
        )

        return jsonify(
            success=False,
            error='wg_failed',
            detail='The timer was not reset because the peer could not be enabled.',
            interface=dev,
            returncode=getattr(exc, 'returncode', None),
            data_preserved=True
        ), 409

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Timer reset failed for peer %s',
            pid
        )

        return jsonify(
            success=False,
            error='reset_timer_failed',
            detail=str(exc),
            data_preserved=True
        ), 500


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
    data = request.get_json(silent=True) or {}

    if not isinstance(data, dict):
        return jsonify(
            success=False,
            ok=False,
            error='invalid_payload',
            detail='The request body must be a JSON object.',
        ), 400

    p = db.session.get(Peer, pid) or abort(404)

    original = {
        'name': p.name,
        'address': p.address,
        'allowed_ips': p.allowed_ips,
        'endpoint': p.endpoint,
        'peer_endpoint': p.peer_endpoint,
        'persistent_keepalive': p.persistent_keepalive,
        'mtu': p.mtu,
        'dns': p.dns,
        'data_limit_value': p.data_limit_value,
        'data_limit_unit': p.data_limit_unit,
        'time_limit_days': p.time_limit_days,
        'start_on_first_use': p.start_on_first_use,
        'unlimited': p.unlimited,
        'phone_number': p.phone_number,
        'telegram_id': p.telegram_id,
    }


    if (
        'time_limit_days' in data
        or 'time_limit_hours' in data
    ):
        data['time_limit_days'] = _conv_time_limit(
            data
        )

        data.pop(
            'time_limit_hours',
            None,
        )

    for field in (
        'name',
        'allowed_ips',
        'endpoint',
        'peer_endpoint',
        'dns',
        'phone_number',
        'telegram_id',
    ):
        if field in data:
            value = data.get(field)

            data[field] = (
                str(value).strip()
                if value is not None
                else ''
            )

    for field in (
        'persistent_keepalive',
        'mtu',
    ):
        if field in data:
            raw = data.get(field)

            if raw in (
                '',
                None,
            ):
                data[field] = None

            else:
                try:
                    data[field] = int(raw)

                except Exception:
                    return jsonify(
                        success=False,
                        ok=False,
                        error='invalid_number',
                        detail=(
                            f'{field} must be a number.'
                        ),
                    ), 400

    # Data limit
    if 'data_limit_value' in data:
        raw = data.get(
            'data_limit_value'
        )

        try:
            data[
                'data_limit_value'
            ] = (
                int(float(raw))
                if str(raw or '').strip()
                else 0
            )

        except Exception:
            return jsonify(
                success=False,
                ok=False,
                error='invalid_data_limit',
                detail='Traffic limit must be numeric.',
            ), 400

    for field in (
        'start_on_first_use',
        'unlimited',
    ):
        if field in data:
            value = data.get(field)

            if isinstance(
                value,
                bool,
            ):
                data[field] = value

            else:
                data[field] = (
                    str(value)
                    .strip()
                    .lower()
                    in (
                        '1',
                        'true',
                        'yes',
                        'on',
                    )
                )

    if 'address' in data:
        requested_address = str(
            data.get('address')
            or ''
        ).strip()

        if not requested_address:
            return jsonify(
                success=False,
                ok=False,
                error='invalid_address',
                detail=(
                    'address may not be empty; '
                    'omit the field to leave it unchanged.'
                ),
            ), 400

        if (
            requested_address
            != str(
                original.get('address')
                or ''
            ).strip()
        ):
            try:
                data['address'] = (
                    allocate_peer_address(
                        p.iface,
                        requested=requested_address,
                        exclude_peer_id=p.id,
                        exclude_address=p.address,
                    )
                )

            except AddressAllocationError as exc:
                return address_error_response(
                    exc
                )

        else:
            data['address'] = (
                original.get('address')
            )

    if 'peer_endpoint' in data:
        submitted_peer_endpoint = str(
            data.get('peer_endpoint')
            or ''
        ).strip()

        original_peer_endpoint = str(
            original.get('peer_endpoint')
            or ''
        ).strip()

        if (
            submitted_peer_endpoint
            and submitted_peer_endpoint
            != original_peer_endpoint
        ):
            try:
                data['peer_endpoint'] = _wireguard_endpoint(
                    submitted_peer_endpoint
                )

            except Exception as exc:
                return jsonify(
                success=False,
                ok=False,
                error='invalid_fixed_endpoint',
                detail=str(exc),
                field='peer_endpoint',
            ), 400

        else:
            data['peer_endpoint'] = (
            submitted_peer_endpoint
            if submitted_peer_endpoint != original_peer_endpoint
            else original_peer_endpoint
        )

    supported_fields = (
        'name',
        'address',
        'allowed_ips',
        'endpoint',
        'peer_endpoint',
        'persistent_keepalive',
        'mtu',
        'dns',
        'data_limit_value',
        'data_limit_unit',
        'time_limit_days',
        'start_on_first_use',
        'unlimited',
        'phone_number',
        'telegram_id',
    )

    changed = []

    for field in supported_fields:
        if field not in data:
            continue

        new_value = data[field]
        old_value = original.get(
            field
        )

        if field in (
            'endpoint',
            'peer_endpoint',
            'dns',
            'phone_number',
            'telegram_id',
            'allowed_ips',
            'name',
        ):
            old_cmp = str(
                old_value or ''
            ).strip()

            new_cmp = str(
                new_value or ''
            ).strip()

        elif field in (
            'persistent_keepalive',
            'mtu',
        ):
            old_cmp = (
                int(old_value)
                if old_value not in (
                    None,
                    '',
                )
                else None
            )

            new_cmp = (
                int(new_value)
                if new_value not in (
                    None,
                    '',
                )
                else None
            )

        else:
            old_cmp = old_value
            new_cmp = new_value

        if old_cmp == new_cmp:
            continue

        setattr(
            p,
            field,
            new_value,
        )

        changed.append(
            field
        )

    if not changed:
        return jsonify(
            success=True,
            ok=True,
            changed=[],
            message='No changes were necessary.',
        ), 200

    if any(
        field in changed
        for field in (
            'time_limit_days',
            'start_on_first_use',
            'unlimited',
        )
    ):
        if getattr(
            p,
            'unlimited',
            False,
        ):
            _clear_timer_cycle(p)

        elif getattr(
            p,
            'time_limit_days',
            None,
        ):
            if (
                getattr(
                    p,
                    'start_on_first_use',
                    False,
                )
                and not getattr(
                    p,
                    'first_used_at',
                    None,
                )
            ):
                _clear_timer_cycle(p)

            else:
                if getattr(p, 'start_on_first_use', False):
                    p.timer_started_at = getattr(p, 'first_used_at', None)
                    _sync_effective_expiry(p)
                else:
                    _start_timer_cycle(p)

        else:
            _clear_timer_cycle(p)

    external_fields = {
        'address',
        'peer_endpoint',
        'persistent_keepalive',
    }

    external_changed = bool(
        external_fields.intersection(
            changed
        )
    )

    external_attempted = False

    try:
        db.session.flush()

        if external_changed:
            external_attempted = True

            reapply_peer_external(
                p
            )

        db.session.commit()

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Peer %s edit failed; '
            'restoring previous state',
            pid,
        )

        recovery_error = None

        if external_attempted:
            previous = db.session.get(
                Peer,
                pid,
            )

            if previous is not None:
                try:
                    reapply_peer_external(
                        previous
                    )

                except Exception as restore_exc:
                    recovery_error = str(
                        restore_exc
                    )

                    current_app.logger.exception(
                        'Could not restore peer %s '
                        'after failed edit',
                        pid,
                    )

        if recovery_error:
            return jsonify(
                success=False,
                ok=False,
                error='peer_edit_recovery_failed',
                detail=str(exc),
                recovery_detail=recovery_error,
                saved_fields=[],
                recoverable=True,
            ), 502

        if isinstance(
            exc,
            IntegrityError,
        ):
            status = 409

        elif external_attempted:
            status = 502

        else:
            status = 500

        return jsonify(
            success=False,
            ok=False,
            error=(
                'peer_reapply_failed'
                if external_attempted
                else 'peer_edit_failed'
            ),
            detail=str(exc),
            saved_fields=[],
            rolled_back=True,
        ), status

    try:
        log_event(
            p,
            'edited',
            (
                'Fields: '
                + ', '.join(
                    changed
                )
            ),
        )

        logpanel_action(
            'peer_edit',
            (
                f'pid={p.id}; fields='
                + ', '.join(
                    changed
                )
            ),
        )

    except Exception:
        current_app.logger.warning(
            'Peer %s was edited but '
            'audit logging failed',
            pid,
            exc_info=True,
        )

    return jsonify(
        success=True,
        ok=True,
        changed=changed,
        runtime_reapplied=(
            external_changed
        ),
    )

@app.route('/api/nodes/<int:nid>/peer/<path:pub>', methods=['PUT'])
@csrf.exempt
@require_api_key_or_login
def api_edit_node_peer(nid, pub):
    """
    Edit a peer that belongs to a remote node.

    """
    Node.query.get_or_404(nid)

    pub = (pub or '').strip()

    if not pub:
        return jsonify(
            success=False,
            ok=False,
            error='peer_not_found',
            detail='Peer public key is required.',
        ), 404

    p = (
        db.session.query(Peer)
        .join(
            InterfaceConfig,
            Peer.iface_id == InterfaceConfig.id,
        )
        .filter(Peer.public_key == pub)
        .filter(
            or_(
                InterfaceConfig.name.like(f'n{nid}:%'),
                InterfaceConfig.node_id == nid,
            )
        )
        .first()
    )

    if p is None:
        return jsonify(
            success=False,
            ok=False,
            error='peer_not_found',
            detail='No peer with that public key exists on this node.',
        ), 404

    return api_edit(p.id)

@app.route('/api/peer/<int:pid>', methods=['DELETE'])
@csrf.exempt
@require_api_key_or_login
def api_delete(pid):
    p = db.session.get(Peer, pid) or abort(404)

    try:
        remove_peer_everywhere(p)
    except PeerRemovalError as e:
        current_app.logger.error(
            "peer delete failed at %s stage for pid=%s: %s",
            e.phase,
            pid,
            e,
        )
        return peer_removal_response(
            e,
            peer_id=pid,
        )

    logpanel_action(
        "peer_delete",
        f"pid={pid}",
    )

    return jsonify(
        success=True,
        ok=True,
    )

@app.route('/api/peer/<int:pid>/logs')
@login_required
def peer_logs(pid):
    p = db.session.get(Peer, pid) or abort(404)

    rows = (
        PeerEvent.query
        .filter_by(peer_id=pid)
        .order_by(PeerEvent.timestamp.desc())
        .limit(500)
        .all()
    )

    def event_level(event_name):
        name = str(event_name or '').strip().lower()

        if any(word in name for word in (
            'error',
            'failed',
            'failure',
        )):
            return 'error'

        if any(word in name for word in (
            'blocked',
            'expired',
            'limit',
            'disabled',
            'warning',
        )):
            return 'warning'

        return 'info'

    logs = []

    for event in rows:
        timestamp = isoz(
            getattr(
                event,
                'timestamp',
                None,
            )
        )

        event_name = str(
            getattr(
                event,
                'event',
                '',
            )
            or ''
        ).strip()

        details = str(
            getattr(
                event,
                'details',
                '',
            )
            or ''
        ).strip()

        logs.append({
            'time': timestamp,
            'ts': timestamp,
            'timestamp': timestamp,
            'time_display': _panel_display_datetime(
                getattr(event, 'timestamp', None)
            ),

            'event': event_name,
            'details': details,

            'level': event_level(
                event_name
            ),

            'text': (
                details
                or event_name
                or 'Peer event'
            ),
        })

    try:
        runtime = _subscription_peer_runtime(
            p
        )
    except Exception:
        current_app.logger.debug(
            'Could not load live runtime for peer log pid=%s',
            pid,
            exc_info=True,
        )

        runtime = {
            'connected': False,
            'conn_status': 'offline',
            'connection_status': 'disconnected',
            'connection_label': 'Disconnected',
            'latest_handshake': 0,
            'latest_handshake_age': None,
            'last_activity_at': None,
            'runtime_available': False,
        }

    iface = getattr(
        p,
        'iface',
        None,
    )

    iface_raw = str(
        getattr(
            iface,
            'name',
            '',
        )
        or ''
    ).strip()

    node = (
        getattr(
            iface,
            'node',
            None,
        )
        if iface
        else None
    )

    is_node = bool(
        iface
        and (
            getattr(
                iface,
                'node_id',
                None,
            )
            is not None
            or re.match(
                r'^n\d+:',
                iface_raw,
            )
        )
    )

    interface_name = (
        iface_raw.split(
            ':',
            1,
        )[1]
        if (
            is_node
            and ':' in iface_raw
        )
        else iface_raw
    )

    return jsonify(
        ok=True,

        peer={
            'id': p.id,
            'name': p.name or '',
            'display_timezone': _panel_timezone_name(),

            'created_at': isoz(
                getattr(
                    p,
                    'created_at',
                    None,
                )
            ),

            'created_at_ts': to_ts(getattr(p,'created_at',None,)),

            'created_at_display': _panel_display_datetime(
                getattr(p, 'created_at', None)
            ),

            'first_used_at': isoz(getattr(p,'first_used_at',None,)),

            'first_used_at_ts': to_ts(getattr(p,'first_used_at',None,)),

            'first_used_at_display': _panel_display_datetime(
                getattr(p, 'first_used_at', None)
            ),

            'expires_at': isoz(from_ts(_effective_expiry_ts(p))),

            'expires_at_display': _panel_display_datetime(
                from_ts(_effective_expiry_ts(p))
            ),

            'expires_at_ts': _effective_expiry_ts(p),

            'ttl_seconds': (
                max(0, _effective_expiry_ts(p) - now_ts())
                if _effective_expiry_ts(p)
                else None
            ),

            'time_limit_days': getattr(p, 'time_limit_days', None),

            'start_on_first_use': bool(
                getattr(p, 'start_on_first_use', False)
            ),

            'panel_status': (p.status or 'offline'),

            'scope': (
                'node'
                if is_node
                else 'local'
            ),

            'node_id': (
                getattr(
                    iface,
                    'node_id',
                    None,
                )
                if iface
                else None
            ),

            'node_name': (
                getattr(
                    node,
                    'name',
                    '',
                )
                or ''
            ),

            'iface': interface_name,

            'connected': bool(
                runtime.get(
                    'connected'
                )
            ),

            'connection_label': (
                runtime.get(
                    'connection_label'
                )
                or 'Disconnected'
            ),

            'latest_handshake': int(
                runtime.get(
                    'latest_handshake'
                )
                or 0
            ),

            'latest_handshake_age': (
                runtime.get(
                    'latest_handshake_age'
                )
            ),

            'last_activity_at': (
                runtime.get(
                    'last_activity_at'
                )
            ),
        },

        runtime=runtime,

        logs=logs,
    )

SUBSCRIPTION_SETTINGS_FILE = os.path.join(
    app.instance_path,
    'subscription_settings.json',
)

SUBSCRIPTION_PORTAL_OVERRIDES_FILE = os.path.join(
    app.instance_path,
    'subscription_portal_overrides.json',
)


SUBSCRIPTION_LAYOUTS = {
    'ps5',
    'mac',
    'app',
    'compact',
    'minimal',
    'showcase',
}

SUBSCRIPTION_LAYOUT_ALIASES = {
    'aurora': 'ps5',
    'cards': 'mac',
    'console': 'app',
    'split': 'showcase',
    'profile': 'showcase',
    'executive': 'mac',
    'flow': 'minimal',
}


def _sub_bool(v):
    if isinstance(v, bool):
        return v

    if v is None:
        return False

    return str(v).strip().lower() in {
        '1',
        'true',
        'yes',
        'on',
    }


def _sub_float(v, default=0.0):
    try:
        return float(v or default)
    except Exception:
        return float(default)


def _sub_int(v, default=0):
    try:
        return int(float(v or default))
    except Exception:
        return int(default)


def _subscription_settings_default():
    return {

        'layout': 'ps5',

        'hero_style': 'banner',
        'page_width': 'wide',
        'density': 'comfortable',

        'config_style': 'cards',
        'config_columns': 'two',
        'section_order': 'usage_first',

        'module_order': [
            'configs',
            'usage',
            'install',
            'support',
        ],
        'module_enabled': {
            'configs': True,
            'usage': True,
            'install': True,
            'support': True,
        },

        'module_sizes': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_mobile': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_surface': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

                'module_spacing': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },


        'module_radius': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },


        'module_heading': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_mobile_position': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_gap': 'standard',

        'background': 'orbits',
        'accent': 'mint',

        'primary_color': '#3addaa',
        'secondary_color': '#63a5ff',

        'online_color': '#22c55e',
        'offline_color': '#94a3b8',
        'warning_color': '#f59e0b',
        'danger_color': '#ef4444',
        'pill_color': '#64748b',
        'action_color': '#3addaa',

        'theme_default': 'auto',

        'surface': 'glass',
        'radius': 'rounded',
        'shadow': 'deep',
        'button_style': 'solid',
        'font_scale': 'standard',

        'background_intensity': 86,
        'card_opacity': 82,

        'display_mode': 'hybrid',
        'stat_size': 'standard',

        'show_percentage': True,
        'show_used_detail': True,

        'animation': 'cinematic',
        'entrance_animation': 'stagger',
        'hover_animation': 'lift',
        'toast_style': 'pill',
        'toast_position': 'bottom_center',
        'toast_motion': 'slide',
        'toast_duration': 2200,
        'motion_speed': 125,
        'motion_intensity': 150,
        'particle_density': 90,

        'show_quick_stats': True,
        'show_install': True,
        'show_support': True,
        'show_live_badge': True,
        'show_status_badge': True,

        'show_location_country': True,
        'show_download_action': True,
        'show_copy_action': True,
        'show_theme_action': True,
        'show_section_descriptions': True,

        'show_admin_notice': False,

        'show_account_details': False,
        'show_connection_overview': False,

        'notice_title': 'Service notice',
        'notice_text': '',

        'notice_tone': 'info',
        'notice_style': 'banner',
        'notice_position': 'after_summary',

        'portal_label': 'Secure WireGuard portal',
        'portal_icon': 'fas fa-bolt',

        'portal_title': '',
        'portal_subtitle': (
            'Your account is ready. Install WireGuard, '
            'then scan QR or import a config.'
        ),

        'title_align': 'left',
        'logo_size': 'medium',

        'usage_title': 'Usage overview',
        'configs_title': 'Configs',
        'install_title': 'Install WireGuard',
        'support_title': 'Support',

        'support_style': 'buttons',

        'support': {
            'telegram': '',
            'whatsapp': '',
            'phone': '',
            'email': '',
            'website': '',
            'instagram': '',
        },
    }


def _subscription_portal_icons():
    return {
        'fas fa-bolt',
        'fas fa-shield-halved',
        'fas fa-store',
        'fas fa-crown',
        'fas fa-rocket',
        'fas fa-globe',
        'fas fa-headset',
        'fas fa-wifi',
        'fas fa-gamepad',
        'fas fa-server',
        'fas fa-link',
        'fas fa-signal',
        'fas fa-gem',
        'fas fa-building',
        'fas fa-cloud',
        'fas fa-network-wired',
        'fas fa-lock',
        'fas fa-star',
    }


def _subscription_portal_icon(value):
    value = str(
        value or ''
    ).strip()

    return (
        value
        if value in _subscription_portal_icons()
        else 'fas fa-bolt'
    )


def _subscription_text(
    value,
    default='',
    max_len=160,
):
    value = str(
        value or ''
    ).strip()

    if not value:
        return default

    return value[:max_len]


def _subscription_choice(
    value,
    allowed,
    default,
):
    value = str(
        value or ''
    ).strip().lower()

    return (
        value
        if value in allowed
        else default
    )


def _subscription_number(
    value,
    default,
    minimum,
    maximum,
):
    try:
        number = int(
            float(value)
        )
    except Exception:
        number = int(default)

    return max(
        minimum,
        min(
            maximum,
            number,
        ),
    )


def _normalize_subscription_settings(
    incoming=None,
    *,
    base=None,
):
    incoming = (
        incoming
        if isinstance(incoming, dict)
        else {}
    )

    defaults = (
        dict(base)
        if isinstance(base, dict)
        else _subscription_settings_default()
    )

    d = _subscription_settings_default()

    for key, value in defaults.items():
        if key == 'support':
            continue

        d[key] = value

    d['support'] = dict(
        defaults.get('support')
        or d['support']
    )


    layout = str(
        incoming.get('layout')
        or incoming.get('selected')
        or d['layout']
    ).strip().lower()


    layout = SUBSCRIPTION_LAYOUT_ALIASES.get(
        layout,
        layout,
    )

    d['layout'] = (
        layout
        if layout in SUBSCRIPTION_LAYOUTS
        else 'ps5'
    )

    d['hero_style'] = _subscription_choice(
        incoming.get(
            'hero_style',
            d['hero_style'],
        ),
        {
            'panel',
            'banner',
            'minimal',
        },
        'panel',
    )

    d['page_width'] = _subscription_choice(
        incoming.get(
            'page_width',
            d['page_width'],
        ),
        {
            'narrow',
            'standard',
            'wide',
        },
        'standard',
    )

    d['density'] = _subscription_choice(
        incoming.get(
            'density',
            d['density'],
        ),
        {
            'comfortable',
            'compact',
        },
        'comfortable',
    )

    d['config_style'] = _subscription_choice(
        incoming.get(
            'config_style',
            d['config_style'],
        ),
        {
            'cards',
            'list',
            'compact',
        },
        'cards',
    )

    d['config_columns'] = _subscription_choice(
        incoming.get(
            'config_columns',
            d['config_columns'],
        ),
        {
            'auto',
            'one',
            'two',
        },
        'auto',
    )

    d['section_order'] = _subscription_choice(
        incoming.get(
            'section_order',
            d['section_order'],
        ),
        {
            'standard',
            'configs_first',
            'usage_first',
        },
        'standard',
    )

    allowed_modules = (
        'configs',
        'usage',
        'install',
        'support',
    )

    default_module_order = [
        'configs',
        'usage',
        'install',
        'support',
    ]

    incoming_module_order = incoming.get(
        'module_order',
        d.get(
            'module_order',
            default_module_order,
        ),
    )

    if not isinstance(
        incoming_module_order,
        (list, tuple),
    ):
        incoming_module_order = []

    normalized_module_order = []

    for module_name in incoming_module_order:
        module_name = str(
            module_name or ''
        ).strip().lower()

        if (
            module_name in allowed_modules
            and module_name
            not in normalized_module_order
        ):
            normalized_module_order.append(
                module_name
            )

    for module_name in default_module_order:
        if (
            module_name
            not in normalized_module_order
        ):
            normalized_module_order.append(
                module_name
            )

    d['module_order'] = (
        normalized_module_order[:4]
    )

    module_keys = (
        'configs',
        'usage',
        'install',
        'support',
    )

    current_enabled = (
        d.get('module_enabled')
        if isinstance(
            d.get('module_enabled'),
            dict,
        )
        else {}
    )

    incoming_enabled = (
        incoming.get('module_enabled')
        if isinstance(
            incoming.get('module_enabled'),
            dict,
        )
        else {}
    )

    normalized_enabled = {}

    for module_name in module_keys:

        if module_name in incoming_enabled:
            value = incoming_enabled.get(
                module_name
            )
        else:
            value = current_enabled.get(
                module_name,
                True,
            )

        normalized_enabled[
            module_name
        ] = _sub_bool(
            value
        )

    if not any(
        normalized_enabled.values()
    ):
        normalized_enabled[
            'configs'
        ] = True

    d['module_enabled'] = (
        normalized_enabled
    )

    allowed_module_sizes = {
        'auto',
        'small',
        'medium',
        'large',
        'full',
    }

    current_sizes = (
        d.get('module_sizes')
        if isinstance(
            d.get('module_sizes'),
            dict,
        )
        else {}
    )

    incoming_sizes = (
        incoming.get('module_sizes')
        if isinstance(
            incoming.get('module_sizes'),
            dict,
        )
        else {}
    )

    normalized_sizes = {}

    for module_name in module_keys:

        value = str(
            incoming_sizes.get(
                module_name,
                current_sizes.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_module_sizes:
            value = 'auto'

        normalized_sizes[
            module_name
        ] = value

    d['module_sizes'] = (
        normalized_sizes
    )

    allowed_mobile_sizes = {
        'auto',
        'half',
        'full',
    }

    current_mobile = (
        d.get('module_mobile')
        if isinstance(
            d.get('module_mobile'),
            dict,
        )
        else {}
    )

    incoming_mobile = (
        incoming.get('module_mobile')
        if isinstance(
            incoming.get('module_mobile'),
            dict,
        )
        else {}
    )

    normalized_mobile = {}

    for module_name in module_keys:

        value = str(
            incoming_mobile.get(
                module_name,
                current_mobile.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_mobile_sizes:
            value = 'auto'

        normalized_mobile[
            module_name
        ] = value

    d['module_mobile'] = (
        normalized_mobile
    )

    allowed_surfaces = {
        'auto',
        'panel',
        'soft',
        'outline',
        'flat',
        'accent',
    }

    current_surfaces = (
        d.get('module_surface')
        if isinstance(
            d.get('module_surface'),
            dict,
        )
        else {}
    )

    incoming_surfaces = (
        incoming.get('module_surface')
        if isinstance(
            incoming.get('module_surface'),
            dict,
        )
        else {}
    )

    normalized_surfaces = {}

    for module_name in module_keys:

        value = str(
            incoming_surfaces.get(
                module_name,
                current_surfaces.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_surfaces:
            value = 'auto'

        normalized_surfaces[
            module_name
        ] = value

    d['module_surface'] = (
        normalized_surfaces
    )

    allowed_spacing = {
        'auto',
        'compact',
        'comfortable',
        'roomy',
    }

    current_spacing = (
        d.get('module_spacing')
        if isinstance(
            d.get('module_spacing'),
            dict,
        )
        else {}
    )

    incoming_spacing = (
        incoming.get('module_spacing')
        if isinstance(
            incoming.get('module_spacing'),
            dict,
        )
        else {}
    )

    normalized_spacing = {}

    for module_name in module_keys:

        value = str(
            incoming_spacing.get(
                module_name,
                current_spacing.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_spacing:
            value = 'auto'

        normalized_spacing[
            module_name
        ] = value

    d['module_spacing'] = (
        normalized_spacing
    )

    def normalize_module_option_map(
        setting_key,
        allowed_values,
        default_value='auto',
        *,
        unique_non_default=False,
    ):
        current_values = (
            d.get(setting_key)
            if isinstance(
                d.get(setting_key),
                dict,
            )
            else {}
        )

        incoming_values = (
            incoming.get(setting_key)
            if isinstance(
                incoming.get(setting_key),
                dict,
            )
            else {}
        )

        normalized_values = {}
        used_values = set()

        for module_name in module_keys:

            value = str(
                incoming_values.get(
                    module_name,
                    current_values.get(
                        module_name,
                        default_value,
                    ),
                )
                or default_value
            ).strip().lower()

            if value not in allowed_values:
                value = default_value

            if (
                unique_non_default
                and value != default_value
            ):
                if value in used_values:
                    value = default_value
                else:
                    used_values.add(
                        value
                    )

            normalized_values[
                module_name
            ] = value

        return normalized_values


    d['module_radius'] = (
        normalize_module_option_map(
            'module_radius',
            {
                'auto',
                'square',
                'soft',
                'round',
            },
        )
    )


    d['module_heading'] = (
        normalize_module_option_map(
            'module_heading',
            {
                'auto',
                'standard',
                'compact',
                'accent',
                'hidden',
            },
        )
    )

    d['module_mobile_position'] = (
        normalize_module_option_map(
            'module_mobile_position',
            {
                'auto',
                '1',
                '2',
                '3',
                '4',
            },
            unique_non_default=True,
        )
    )

    d['module_gap'] = _subscription_choice(
        incoming.get(
            'module_gap',
            d.get(
                'module_gap',
                'auto',
            ),
        ),
        {
            'auto',
            'tight',
            'standard',
            'roomy',
        },
        'auto',
    )

    d['background'] = _subscription_choice(
        incoming.get(
            'background',
            d['background'],
        ),
        {
            'aurora',
            'waves',
            'network',
            'orbits',
            'mesh',
            'nebula',
            'lines',
            'constellation',
            'prism',
            'circuit',
            'pulse',
            'none',
        },
        'aurora',
    )

    d['accent'] = _subscription_choice(
        incoming.get(
            'accent',
            d['accent'],
        ),
        {
            'mint',
            'blue',
            'violet',
            'coral',
            'amber',
            'mono',
            'custom',
        },
        'mint',
    )

    d['theme_default'] = _subscription_choice(
        incoming.get(
            'theme_default',
            d['theme_default'],
        ),
        {
            'auto',
            'light',
            'dark',
        },
        'auto',
    )

    d['surface'] = _subscription_choice(
        incoming.get(
            'surface',
            d['surface'],
        ),
        {
            'glass',
            'solid',
            'soft',
        },
        'glass',
    )

    d['radius'] = _subscription_choice(
        incoming.get(
            'radius',
            d['radius'],
        ),
        {
            'rounded',
            'medium',
            'square',
        },
        'rounded',
    )

    d['shadow'] = _subscription_choice(
        incoming.get(
            'shadow',
            d['shadow'],
        ),
        {
            'none',
            'soft',
            'deep',
        },
        'soft',
    )

    d['button_style'] = _subscription_choice(
        incoming.get(
            'button_style',
            d['button_style'],
        ),
        {
            'solid',
            'outline',
            'soft',
        },
        'solid',
    )

    d['font_scale'] = _subscription_choice(
        incoming.get(
            'font_scale',
            d['font_scale'],
        ),
        {
            'small',
            'standard',
            'large',
        },
        'standard',
    )

    color_fields = (
        ('primary_color', 'custom_primary', '#3addaa'),
        ('secondary_color', 'custom_secondary', '#63a5ff'),
        ('online_color', None, '#22c55e'),
        ('offline_color', None, '#94a3b8'),
        ('warning_color', None, '#f59e0b'),
        ('danger_color', None, '#ef4444'),
        ('pill_color', None, '#64748b'),
        ('action_color', None, '#3addaa'),
    )

    for key, legacy_key, fallback in color_fields:
        candidate = incoming.get(key)

        if candidate in (None, '') and legacy_key:
            candidate = incoming.get(legacy_key)

        if candidate in (None, ''):
            candidate = d.get(key) or fallback

        value = str(candidate or '').strip()

        if not re.fullmatch(r'#[0-9A-Fa-f]{6}', value):
            value = fallback

        d[key] = value.lower()

    d['background_intensity'] = (
        _subscription_number(
            incoming.get(
                'background_intensity',
                d['background_intensity'],
            ),
            86,
            0,
            100,
        )
    )

    d['card_opacity'] = (
        _subscription_number(
            incoming.get(
                'card_opacity',
                d['card_opacity'],
            ),
            82,
            50,
            100,
        )
    )

    d['display_mode'] = _subscription_choice(
        incoming.get(
            'display_mode',
            incoming.get(
                'stats_style',
                d['display_mode'],
            ),
        ),
        {
            'bars',
            'rings',
            'hybrid',
            'focus',
            'minimal',
            'segments',
        },
        'hybrid',
    )

    d['stat_size'] = _subscription_choice(
        incoming.get(
            'stat_size',
            d['stat_size'],
        ),
        {
            'compact',
            'standard',
            'large',
        },
        'standard',
    )

    d['animation'] = _subscription_choice(
        incoming.get(
            'animation',
            incoming.get(
                'motion',
                d['animation'],
            ),
        ),
        {
            'cinematic',
            'immersive',
            'rich',
            'balanced',
            'soft',
            'drift',
            'minimal',
            'off',
        },
        'cinematic',
    )

    d['entrance_animation'] = _subscription_choice(
        incoming.get(
            'entrance_animation',
            d['entrance_animation'],
        ),
        {'stagger', 'slide', 'fade', 'scale', 'none'},
        'stagger',
    )

    d['hover_animation'] = _subscription_choice(
        incoming.get(
            'hover_animation',
            d['hover_animation'],
        ),
        {'lift', 'glow', 'scale', 'none'},
        'lift',
    )

    d['toast_style'] = _subscription_choice(
        incoming.get('toast_style', d['toast_style']),
        {'pill', 'card', 'glass', 'terminal', 'minimal'},
        'pill',
    )

    d['toast_position'] = _subscription_choice(
        incoming.get('toast_position', d['toast_position']),
        {'bottom_center', 'bottom_right', 'top_right', 'top_center'},
        'bottom_center',
    )

    d['toast_motion'] = _subscription_choice(
        incoming.get('toast_motion', d['toast_motion']),
        {'slide', 'pop', 'fade', 'bounce'},
        'slide',
    )

    d['toast_duration'] = _subscription_number(
        incoming.get('toast_duration', d['toast_duration']),
        2200,
        1200,
        6000,
    )

    d['motion_speed'] = _subscription_number(
        incoming.get('motion_speed', d['motion_speed']),
        125,
        50,
        180,
    )

    d['motion_intensity'] = _subscription_number(
        incoming.get('motion_intensity', d['motion_intensity']),
        150,
        40,
        200,
    )

    d['particle_density'] = _subscription_number(
        incoming.get('particle_density', d['particle_density']),
        90,
        0,
        120,
    )

    for key in (
        'show_percentage',
        'show_used_detail',
        'show_quick_stats',
        'show_install',
        'show_support',
        'show_live_badge',
        'show_status_badge',
        'show_location_country',
        'show_download_action',
        'show_copy_action',
        'show_theme_action',
        'show_section_descriptions',
        'show_admin_notice',
        'show_account_details',
        'show_connection_overview',
    ):
        if key in incoming:
            d[key] = _sub_bool(
                incoming.get(key)
            )

    identity = (
        incoming.get('identity')
        if isinstance(
            incoming.get('identity'),
            dict,
        )
        else {}
    )

    public = (
        incoming.get('public')
        if isinstance(
            incoming.get('public'),
            dict,
        )
        else {}
    )

    def pick(
        *keys,
        default=None,
    ):
        for source in (
            incoming,
            identity,
            public,
        ):
            if not isinstance(
                source,
                dict,
            ):
                continue

            for key in keys:
                if key in source:
                    return source.get(key)

        return default

    d['portal_label'] = _subscription_text(
        pick(
            'portal_label',
            'badge_label',
            'label',
            default=d['portal_label'],
        ),
        d['portal_label'],
        80,
    )

    d['portal_icon'] = (
        _subscription_portal_icon(
            pick(
                'portal_icon',
                'badge_icon',
                'icon',
                default=d['portal_icon'],
            )
        )
    )

    d['portal_title'] = _subscription_text(
        pick(
            'portal_title',
            'title',
            default=d['portal_title'],
        ),
        '',
        90,
    )

    d['portal_subtitle'] = _subscription_text(
        pick(
            'portal_subtitle',
            'subtitle',
            default=d['portal_subtitle'],
        ),
        d['portal_subtitle'],
        180,
    )

    d['title_align'] = _subscription_choice(
        incoming.get(
            'title_align',
            d['title_align'],
        ),
        {
            'left',
            'center',
        },
        'left',
    )

    d['logo_size'] = _subscription_choice(
        incoming.get(
            'logo_size',
            d['logo_size'],
        ),
        {
            'small',
            'medium',
            'large',
        },
        'medium',
    )

    d['usage_title'] = _subscription_text(
        incoming.get(
            'usage_title',
            d['usage_title'],
        ),
        'Usage overview',
        80,
    )

    d['configs_title'] = _subscription_text(
        incoming.get(
            'configs_title',
            d['configs_title'],
        ),
        'Configs',
        80,
    )

    d['install_title'] = _subscription_text(
        incoming.get(
            'install_title',
            d['install_title'],
        ),
        'Install WireGuard',
        80,
    )

    d['support_title'] = _subscription_text(
        incoming.get(
            'support_title',
            d['support_title'],
        ),
        'Support',
        80,
    )

    d['notice_title'] = _subscription_text(
        incoming.get(
            'notice_title',
            d.get(
                'notice_title',
                'Service notice',
            ),
        ),
        'Service notice',
        60,
    )

    d['notice_text'] = _subscription_text(
        incoming.get(
            'notice_text',
            d.get(
                'notice_text',
                '',
            ),
        ),
        '',
        240,
    )
    d['notice_tone'] = _subscription_choice(
        incoming.get(
            'notice_tone',
            d.get(
                'notice_tone',
                'info',
            ),
        ),
        {
            'info',
            'maintenance',
            'warning',
            'success',
            'neutral',
        },
        'info',
    )

    d['notice_style'] = _subscription_choice(
        incoming.get(
            'notice_style',
            d.get(
                'notice_style',
                'banner',
            ),
        ),
        {
            'banner',
            'card',
            'strip',
        },
        'banner',
    )

    d['notice_position'] = _subscription_choice(
        incoming.get(
            'notice_position',
            d.get(
                'notice_position',
                'after_summary',
            ),
        ),
        {
            'after_summary',
            'before_modules',
            'after_modules',
        },
        'after_summary',
    )

    d['support_style'] = _subscription_choice(
        incoming.get(
            'support_style',
            d['support_style'],
        ),
        {
            'buttons',
            'list',
            'compact',
        },
        'buttons',
    )

    support = (
        incoming.get('support')
        if isinstance(
            incoming.get('support'),
            dict,
        )
        else {}
    )

    socials = (
        incoming.get('socials')
        if isinstance(
            incoming.get('socials'),
            dict,
        )
        else {}
    )

    existing_support = (
        d.get('support')
        or {}
    )

    normalized_support = {}

    for key in (
        'telegram',
        'whatsapp',
        'phone',
        'email',
        'website',
        'instagram',
    ):
        if key in support:
            value = support.get(key)

        elif key in socials:
            value = socials.get(key)

        else:
            value = existing_support.get(
                key,
                '',
            )

        normalized_support[key] = str(
            value or ''
        ).strip()[:500]

    d['support'] = normalized_support

    return d


def _write_json_atomic(
    path,
    payload,
):
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    temporary = (
        path
        + '.tmp'
    )

    with open(
        temporary,
        'w',
        encoding='utf-8',
    ) as handle:
        json.dump(
            payload,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    os.replace(
        temporary,
        path,
    )


def _load_subscription_settings():
    os.makedirs(
        app.instance_path,
        exist_ok=True,
    )

    try:
        with open(
            SUBSCRIPTION_SETTINGS_FILE,
            'r',
            encoding='utf-8',
        ) as handle:
            payload = (
                json.load(handle)
                or {}
            )

    except Exception:
        payload = {}

    return _normalize_subscription_settings(
        payload
    )


def _save_subscription_settings(data):
    current = (
        _load_subscription_settings()
    )

    saved = (
        _normalize_subscription_settings(
            data,
            base=current,
        )
    )

    _write_json_atomic(
        SUBSCRIPTION_SETTINGS_FILE,
        saved,
    )

    return saved


def _load_subscription_portal_overrides():
    try:
        with open(
            SUBSCRIPTION_PORTAL_OVERRIDES_FILE,
            'r',
            encoding='utf-8',
        ) as handle:
            payload = (
                json.load(handle)
                or {}
            )

        return (
            payload
            if isinstance(payload, dict)
            else {}
        )

    except Exception:
        return {}


def _save_subscription_portal_overrides(
    data,
):
    if not isinstance(data, dict):
        data = {}

    _write_json_atomic(
        SUBSCRIPTION_PORTAL_OVERRIDES_FILE,
        data,
    )


def _subscription_portal_override(
    sub,
):
    if not sub:
        return {}

    store = (
        _load_subscription_portal_overrides()
    )

    value = store.get(
        str(
            getattr(
                sub,
                'id',
                '',
            )
        )
    )

    return (
        value
        if isinstance(value, dict)
        else {}
    )


def _effective_subscription_settings(
    sub=None,
):
    global_settings = (
        _load_subscription_settings()
    )

    if sub is None:
        return global_settings

    override = (
        _subscription_portal_override(
            sub
        )
    )

    if not override:
        return global_settings

    return _normalize_subscription_settings(
        override,
        base=global_settings,
    )

def _sub_limit_bytes(sub):
    try:
        return sub.limit_bytes()
    except Exception:
        if not getattr(sub, 'data_limit_value', 0) or getattr(sub, 'unlimited', False):
            return None
        mult = 1024**2 if (getattr(sub, 'data_limit_unit', None) or 'Mi') == 'Mi' else 1024**3
        return int(sub.data_limit_value) * mult

def _sub_used_bytes(sub):
    total = 0
    dirty = False

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue

        try:
            iface = getattr(peer, 'iface', None)
            is_node = bool(
                iface and (
                    getattr(iface, 'node_id', None) is not None or
                    re.match(r'^n\d+:', getattr(iface, 'name', '') or '')
                )
            )

            if is_node:
                used = int(getattr(peer, 'used_bytes_total', 0) or 0)
            else:
                live = _wg_transfer(peer)
                used, _delta, changed = _accumulate_peer_usage(peer, live)
                if changed:
                    dirty = True

        except Exception:
            used = int(getattr(peer, 'used_bytes_total', 0) or 0)

        total += int(used or 0)

    if dirty:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    return int(total)

def _sub_ttl_seconds(sub):
    exp_ts = _effective_expiry_ts(sub)
    return max(0, exp_ts - now_ts()) if exp_ts else None

def _sub_public_url(sub):
    return url_for('subscription_public_page', token=sub.token, _external=True)

def _sub_config_url(sub):
    return url_for('subscription_public_config', token=sub.token, _external=True)

def _apply_subscription_timer(sub, *, restart=False):

    unlimited = bool(
        getattr(
            sub,
            'unlimited',
            False,
        )
    )

    days = _sub_float(
        getattr(
            sub,
            'time_limit_days',
            0,
        )
    )

    if unlimited or not days:
        _clear_timer_cycle(sub)
        return

    start_on_first_use = bool(
        getattr(
            sub,
            'start_on_first_use',
            False,
        )
    )

    if start_on_first_use:

        first_used_at = getattr(
            sub,
            'first_used_at',
            None,
        )

        if not first_used_at:
            _clear_timer_cycle(sub)
            return

        sub.timer_started_at = first_used_at
        _sync_effective_expiry(sub)

        return

    if restart:
        _start_timer_cycle(sub)
    else:
        if not getattr(sub, 'timer_started_at', None):
            sub.timer_started_at = (
                getattr(sub, 'created_at', None)
                or from_ts(now_ts())
            )
        _sync_effective_expiry(sub)

def _sync_peer_subscription(peer, sub, idx=None, rename=True):
    if rename:
        total = len(getattr(sub, 'links', []) or []) or 1
        base = (sub.name or 'subscription').strip() or 'subscription'
        if idx is not None and total > 1:
            peer.name = f'{base}-{idx + 1}'
        else:
            peer.name = base
    peer.data_limit_value = int(getattr(sub, 'data_limit_value', 0) or 0)
    peer.data_limit_unit = getattr(sub, 'data_limit_unit', None) or 'Gi'
    peer.time_limit_days = _sub_float(getattr(sub, 'time_limit_days', 0)) or None
    peer.start_on_first_use = bool(getattr(sub, 'start_on_first_use', False))
    peer.unlimited = bool(getattr(sub, 'unlimited', False))
    peer.phone_number = getattr(sub, 'phone_number', '') or ''
    peer.telegram_id = getattr(sub, 'telegram_id', '') or ''
    peer.timer_started_at = getattr(sub, 'timer_started_at', None)
    peer.expires_at = getattr(sub, 'expires_at', None)
    return peer

def _sync_all_subscription_peers(sub, rename=True):
    links = sorted(list(getattr(sub, 'links', []) or []), key=lambda l: (l.sort_order or 0, l.id or 0))
    for idx, link in enumerate(links):
        if link.peer:
            _sync_peer_subscription(link.peer, sub, idx=idx, rename=rename)

def _block_subscription_runtime(sub, reason='subscription_blocked'):
    """
    Block every runtime inbound attached to a subscription.

    """
    changed = False

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue

        if getattr(peer, 'status', None) == 'blocked':
            continue

        ok = False
        try:
            ok = bool(_disable_peer(peer, reason, status='blocked'))
        except Exception:
            ok = False

        if not ok:
            peer.status = 'blocked'
            try:
                log_event(peer, reason, 'status → blocked')
            except Exception:
                pass

        changed = True

    if changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    return changed

def _subscription_peer_runtime(peer):
    """
    Return actual WireGuard activity for one subscription peer.

    This is intentionally separate from Peer.status:

        Peer.status
            = administrative state
              online / offline / blocked

        connected
            = recent WireGuard handshake

    Local peers are read directly from the local WireGuard runtime.

    Node peers are read from the node agent's /api/peers endpoint.

    Runtime data is cached on Flask ``g`` for the current HTTP request so:
        - each local WireGuard interface is inspected once
        - each remote node is contacted once
    """

    iface = getattr(
        peer,
        'iface',
        None,
    )

    raw_iface_name = str(
        getattr(
            iface,
            'name',
            '',
        )
        or ''
    ).strip()

    public_key = str(
        getattr(
            peer,
            'public_key',
            '',
        )
        or ''
    ).strip()

    current_epoch = now_ts()

    try:
        handshake_window = max(
            30,
            int(
                os.environ.get(
                    'WG_SUBSCRIPTION_CONNECTED_WINDOW',
                    '180',
                )
                or 180
            ),
        )

    except Exception:
        handshake_window = 180

    result = {
        'connected': False,

        'conn_status': 'offline',

        'connection_status': (
            'disconnected'
        ),

        'connection_label': (
            'Disconnected'
        ),

        'conn_reason': (
            'no_recent_activity'
        ),

        'latest_handshake': 0,

        'latest_handshake_age': None,

        'last_activity_at': None,

        'runtime_available': True,

        'handshake_window': (
            handshake_window
        ),
    }

    if (
        not iface
        or not public_key
    ):
        result[
            'runtime_available'
        ] = False

        result[
            'conn_reason'
        ] = 'peer_runtime_missing'

        return result

    node_id = getattr(
        iface,
        'node_id',
        None,
    )

    legacy_node_match = (
        re.match(
            r'^n(\d+):(.+)$',
            raw_iface_name,
        )
    )

    if (
        node_id is None
        and legacy_node_match
    ):
        try:
            node_id = int(
                legacy_node_match.group(
                    1
                )
            )
        except Exception:
            node_id = None

    is_node = bool(
        node_id is not None
        or legacy_node_match
    )

    if is_node:
        node = getattr(
            iface,
            'node',
            None,
        )

        if (
            node is None
            and node_id is not None
        ):
            node = db.session.get(
                Node,
                int(node_id),
            )

        if node is None:
            result[
                'runtime_available'
            ] = False

            result[
                'conn_reason'
            ] = 'node_missing'

            return result

        cache = getattr(
            g,
            '_subscription_node_runtime_cache',
            None,
        )

        if cache is None:
            cache = {}

            g._subscription_node_runtime_cache = (
                cache
            )

        cache_key = int(
            node.id
        )

        if cache_key not in cache:
            try:
                payload = (
                    node_get(
                        node,
                        '/api/peers',
                        timeout=8,
                    )
                    or {}
                )

                rows = (
                    payload.get(
                        'peers'
                    )
                    if isinstance(
                        payload,
                        dict,
                    )
                    else []
                )

                runtime_by_key = {}

                for row in (
                    rows or []
                ):
                    if not isinstance(
                        row,
                        dict,
                    ):
                        continue

                    row_public_key = str(
                        row.get(
                            'public_key'
                        )
                        or row.get(
                            'id'
                        )
                        or ''
                    ).strip()

                    if row_public_key:
                        runtime_by_key[
                            row_public_key
                        ] = row

                cache[
                    cache_key
                ] = {
                    'ok': True,
                    'rows': runtime_by_key,
                }

            except Exception as exc:
                current_app.logger.debug(
                    'Subscription runtime: node %s unavailable: %s',
                    getattr(
                        node,
                        'id',
                        '?',
                    ),
                    exc,
                )

                cache[
                    cache_key
                ] = {
                    'ok': False,
                    'rows': {},
                }

        node_cache = (
            cache.get(
                cache_key
            )
            or {}
        )

        if not node_cache.get(
            'ok'
        ):
            result[
                'runtime_available'
            ] = False

            result[
                'conn_reason'
            ] = 'node_unavailable'

            return result

        row = (
            node_cache.get(
                'rows'
            )
            or {}
        ).get(
            public_key
        )

        if not isinstance(
            row,
            dict,
        ):
            result[
                'conn_reason'
            ] = 'peer_not_in_runtime'

            return result

        try:
            latest_handshake = max(
                0,
                int(
                    row.get(
                        'latest_handshake'
                    )
                    or 0
                ),
            )

        except Exception:
            latest_handshake = 0

        try:
            handshake_age = (
                row.get(
                    'latest_handshake_age'
                )
            )

            if handshake_age is not None:
                handshake_age = max(
                    0,
                    int(
                        handshake_age
                    ),
                )

            elif latest_handshake > 0:
                handshake_age = max(
                    0,
                    current_epoch
                    - latest_handshake,
                )

            else:
                handshake_age = None

        except Exception:
            handshake_age = (
                max(
                    0,
                    current_epoch
                    - latest_handshake,
                )
                if latest_handshake > 0
                else None
            )

        connected = bool(
            latest_handshake > 0
            and handshake_age is not None
            and handshake_age
            <= handshake_window
        )

        try:
            rx_mib = float(
                row.get(
                    'rx_mib'
                )
                or 0
            )

        except Exception:
            rx_mib = 0.0

        try:
            tx_mib = float(
                row.get(
                    'tx_mib'
                )
                or 0
            )

        except Exception:
            tx_mib = 0.0

        result.update({
            'connected': connected,

            'conn_status': (
                'online'
                if connected
                else 'offline'
            ),

            'connection_status': (
                'connected'
                if connected
                else 'disconnected'
            ),

            'connection_label': (
                'Connected'
                if connected
                else 'Disconnected'
            ),

            'conn_reason': (
                'handshake'
                if connected
                else (
                    'stale_handshake'
                    if latest_handshake > 0
                    else 'no_handshake'
                )
            ),

            'latest_handshake': (
                latest_handshake
            ),

            'latest_handshake_age': (
                handshake_age
            ),

            'last_activity_at': (
                datetime.utcfromtimestamp(
                    latest_handshake
                ).isoformat()
                + 'Z'
                if latest_handshake > 0
                else None
            ),

            'rx_bytes': int(
                rx_mib
                * 1024
                * 1024
            ),

            'tx_bytes': int(
                tx_mib
                * 1024
                * 1024
            ),

            'node_reported_conn_status': (
                row.get(
                    'conn_status'
                )
                or row.get(
                    'connection_status'
                )
                or row.get(
                    'status'
                )
                or ''
            ),

            'node_reported_conn_reason': (
                row.get(
                    'conn_reason'
                )
                or ''
            ),
        })

        return result

    interface_name = raw_iface_name

    if not interface_name:
        result[
            'runtime_available'
        ] = False

        result[
            'conn_reason'
        ] = 'interface_missing'

        return result

    cache = getattr(
        g,
        '_subscription_local_runtime_cache',
        None,
    )

    if cache is None:
        cache = {}

        g._subscription_local_runtime_cache = (
            cache
        )

    if interface_name not in cache:
        try:
            transfers, handshakes = (
                _wg_runtime_snapshot(
                    [
                        interface_name
                    ]
                )
            )

            cache[
                interface_name
            ] = {
                'ok': True,
                'transfers': transfers,
                'handshakes': handshakes,
            }

        except Exception as exc:
            current_app.logger.debug(
                'Subscription runtime: local interface %s unavailable: %s',
                interface_name,
                exc,
            )

            cache[
                interface_name
            ] = {
                'ok': False,
                'transfers': {},
                'handshakes': {},
            }

    local_cache = (
        cache.get(
            interface_name
        )
        or {}
    )

    if not local_cache.get(
        'ok'
    ):
        result[
            'runtime_available'
        ] = False

        result[
            'conn_reason'
        ] = 'wireguard_unavailable'

        return result

    transfers = (
        local_cache.get(
            'transfers'
        )
        or {}
    )

    handshakes = (
        local_cache.get(
            'handshakes'
        )
        or {}
    )

    latest_handshake = int(
        handshakes.get(
            (
                interface_name,
                public_key,
            ),
            0,
        )
        or 0
    )

    handshake_age = (
        max(
            0,
            current_epoch
            - latest_handshake,
        )
        if latest_handshake > 0
        else None
    )

    connected = bool(
        latest_handshake > 0
        and handshake_age is not None
        and handshake_age
        <= handshake_window
    )

    rx_bytes, tx_bytes = (
        transfers.get(
            (
                interface_name,
                public_key,
            ),
            (
                0,
                0,
            ),
        )
    )

    result.update({
        'connected': connected,

        'conn_status': (
            'online'
            if connected
            else 'offline'
        ),

        'connection_status': (
            'connected'
            if connected
            else 'disconnected'
        ),

        'connection_label': (
            'Connected'
            if connected
            else 'Disconnected'
        ),

        'conn_reason': (
            'handshake'
            if connected
            else (
                'stale_handshake'
                if latest_handshake > 0
                else 'no_handshake'
            )
        ),

        'latest_handshake': (
            latest_handshake
        ),

        'latest_handshake_age': (
            handshake_age
        ),

        'last_activity_at': (
            datetime.utcfromtimestamp(
                latest_handshake
            ).isoformat()
            + 'Z'
            if latest_handshake > 0
            else None
        ),

        'rx_bytes': int(
            rx_bytes
            or 0
        ),

        'tx_bytes': int(
            tx_bytes
            or 0
        ),
    })

    return result

def _subscription_row(sub):

    used = int(
        _sub_used_bytes(sub)
        or 0
    )

    unlimited = bool(
        getattr(
            sub,
            'unlimited',
            False,
        )
    )

    subscription_changed = False
    linked_first_use = []

    for link in (
        getattr(
            sub,
            'links',
            [],
        )
        or []
    ):
        peer = getattr(
            link,
            'peer',
            None,
        )

        if not peer:
            continue

        peer_first_used = getattr(
            peer,
            'first_used_at',
            None,
        )

        if peer_first_used:
            linked_first_use.append(
                peer_first_used
            )

    current_first_used = getattr(
        sub,
        'first_used_at',
        None,
    )

    if (
        not current_first_used
        and linked_first_use
    ):
        sub.first_used_at = min(
            linked_first_use
        )

        current_first_used = (
            sub.first_used_at
        )

        subscription_changed = True

    if (
        not current_first_used
        and used > 0
    ):
        sub.first_used_at = from_ts(
            now_ts()
        )

        current_first_used = (
            sub.first_used_at
        )

        subscription_changed = True

    if subscription_changed:
        if unlimited:
            try:
                _clear_timer_cycle(sub)
            except Exception:
                pass

        else:
            _apply_subscription_timer(
                sub
            )

        _sync_all_subscription_peers(
            sub,
            rename=False,
        )

        try:
            db.session.commit()

        except Exception:
            db.session.rollback()

            current_app.logger.exception(
                (
                    'Failed to save subscription first-use date '
                    'for subscription_id=%s'
                ),
                getattr(
                    sub,
                    'id',
                    '?',
                ),
            )

    limit = _sub_limit_bytes(
        sub
    )

    remaining = (
        None
        if limit is None
        else max(
            0,
            int(limit) - used,
        )
    )

    expired = (
        False
        if unlimited
        else _subscription_time_expired(
            sub
        )
    )

    if (
        limit
        and used >= int(limit)
    ):
        _block_subscription_runtime(
            sub,
            'subscription_limit_reached',
        )

    elif expired:
        _block_subscription_runtime(
            sub,
            'subscription_expired',
        )

    locs = []

    links = sorted(
        list(
            getattr(
                sub,
                'links',
                [],
            )
            or []
        ),
        key=lambda link: (
            getattr(
                link,
                'sort_order',
                0,
            )
            or 0,
            getattr(
                link,
                'id',
                0,
            )
            or 0,
        ),
    )

    runtime_counts = {
        'total': 0,
        'enabled': 0,
        'disabled': 0,
        'blocked': 0,
    }

    for link in links:
        peer = getattr(
            link,
            'peer',
            None,
        )

        if not peer:
            continue

        iface = getattr(
            peer,
            'iface',
            None,
        )

        raw_name = (
            getattr(
                iface,
                'name',
                '',
            )
            or ''
        )

        node_id = (
            getattr(
                iface,
                'node_id',
                None,
            )
            if iface
            else None
        )

        is_legacy_node_name = bool(
            raw_name.startswith('n')
            and ':' in raw_name
        )

        scope = (
            'node'
            if (
                node_id is not None
                or is_legacy_node_name
            )
            else 'local'
        )

        interface_name = (
            raw_name.split(
                ':',
                1,
            )[1]
            if is_legacy_node_name
            else raw_name
        )

        peer_status = str(
            getattr(
                peer,
                'status',
                None,
            )
            or 'offline'
        ).lower()

        runtime_counts['total'] += 1

        if peer_status == 'blocked':
            runtime_counts['blocked'] += 1

        elif peer_status == 'online':
            runtime_counts['enabled'] += 1

        else:
            runtime_counts['disabled'] += 1

        peer_first_used = getattr(
            peer,
            'first_used_at',
            None,
        )

        node = (
            getattr(
                iface,
                'node',
                None,
            )
            if iface
            else None
        )
        try:
            live = _subscription_peer_runtime(
                peer
            )

        except Exception:
            current_app.logger.debug(
                (
                    'Could not read subscription runtime '
                    'for peer_id=%s'
                ),
                getattr(
                    peer,
                    'id',
                    '?',
                ),
                exc_info=True,
            )

            live = {
                'connected': False,
                'conn_status': 'offline',
                'connection_status': (
                    'disconnected'
                ),
                'connection_label': (
                    'Disconnected'
                ),
                'conn_reason': (
                    'runtime_error'
                ),
                'latest_handshake': 0,
                'latest_handshake_age': None,
                'last_activity_at': None,
                'runtime_available': False,
            }

        locs.append({
            'link_id': getattr(
                link,
                'id',
                None,
            ),

            'peer_id': getattr(
                peer,
                'id',
                None,
            ),

            'scope': scope,
            'node_id': node_id,

            'node_name': (
                getattr(
                    node,
                    'name',
                    '',
                )
                or ''
            ),

            'iface': interface_name,

            'name': (
                getattr(
                    peer,
                    'name',
                    '',
                )
                or ''
            ),

            'address': (
                getattr(
                    peer,
                    'address',
                    '',
                )
                or ''
            ),

            'endpoint': (
                getattr(
                    peer,
                    'endpoint',
                    '',
                )
                or ''
            ),

            'allowed_ips': (
                getattr(
                    peer,
                    'allowed_ips',
                    '',
                )
                or ''
            ),

            'dns': (
                getattr(
                    peer,
                    'dns',
                    '',
                )
                or ''
            ),

                        'status': peer_status,

            'panel_status': (
                peer_status
            ),

            'connected': bool(
                live.get(
                    'connected'
                )
            ),

            'conn_status': (
                live.get(
                    'conn_status'
                )
                or 'offline'
            ),

            'connection_status': (
                live.get(
                    'connection_status'
                )
                or 'disconnected'
            ),

            'connection_label': (
                live.get(
                    'connection_label'
                )
                or 'Disconnected'
            ),

            'conn_reason': (
                live.get(
                    'conn_reason'
                )
                or 'no_recent_activity'
            ),

            'latest_handshake': int(
                live.get(
                    'latest_handshake'
                )
                or 0
            ),

            'latest_handshake_age': (
                live.get(
                    'latest_handshake_age'
                )
            ),

            'last_activity_at': (
                live.get(
                    'last_activity_at'
                )
            ),

            'runtime_available': bool(
                live.get(
                    'runtime_available',
                    True,
                )
            ),

            'used_bytes': int(
                getattr(
                    peer,
                    'used_bytes_total',
                    0,
                )
                or 0
            ),

            'first_used_at': isoz(
                peer_first_used
            ),

            'first_used_at_display': _panel_display_datetime(
                peer_first_used
            ),

            'first_used_at_ts': to_ts(
                peer_first_used
            ),

            'location_label': (
                getattr(
                    link,
                    'location_label',
                    '',
                )
                or ''
            ),

            'country_code': (
                getattr(
                    link,
                    'country_code',
                    '',
                )
                or ''
            ),

            'flag': (
                getattr(
                    link,
                    'flag',
                    '',
                )
                or ''
            ),
        })


    connected_locations = [
        location
        for location in locs
        if bool(
            location.get(
                'connected'
            )
        )
    ]

    runtime_locations = [
        location
        for location in locs
        if bool(
            location.get(
                'runtime_available',
                True,
            )
        )
    ]

    activity_locations = [
        location
        for location in locs
        if int(
            location.get(
                'latest_handshake'
            )
            or 0
        ) > 0
    ]

    active_location = None

    if connected_locations:
        active_location = max(
            connected_locations,
            key=lambda location: int(
                location.get(
                    'latest_handshake'
                )
                or 0
            ),
        )

    elif activity_locations:
        active_location = max(
            activity_locations,
            key=lambda location: int(
                location.get(
                    'latest_handshake'
                )
                or 0
            ),
        )

    connection = {
        'connected': bool(
            connected_locations
        ),

        'status': (
            'connected'
            if connected_locations
            else 'disconnected'
        ),

        'label': (
            'Connected'
            if connected_locations
            else 'Disconnected'
        ),

        'connected_count': len(
            connected_locations
        ),

        'runtime_count': len(
            runtime_locations
        ),

        'total_count': len(
            locs
        ),

        'active_peer_id': (
            (
                active_location
                or {}
            ).get(
                'peer_id'
            )
        ),

        'active_peer_name': (
            (
                active_location
                or {}
            ).get(
                'name'
            )
            or ''
        ),

        'active_scope': (
            (
                active_location
                or {}
            ).get(
                'scope'
            )
            or ''
        ),

        'active_node_id': (
            (
                active_location
                or {}
            ).get(
                'node_id'
            )
        ),

        'active_node_name': (
            (
                active_location
                or {}
            ).get(
                'node_name'
            )
            or ''
        ),

        'active_iface': (
            (
                active_location
                or {}
            ).get(
                'iface'
            )
            or ''
        ),

        'latest_handshake': int(
            (
                (
                    active_location
                    or {}
                ).get(
                    'latest_handshake'
                )
                or 0
            )
        ),

        'last_activity_at': (
            (
                active_location
                or {}
            ).get(
                'last_activity_at'
            )
        ),

        'last_activity_age': (
            (
                active_location
                or {}
            ).get(
                'latest_handshake_age'
            )
        ),
    }

    first_used_at = getattr(
        sub,
        'first_used_at',
        None,
    )

    created_at = getattr(
        sub,
        'created_at',
        None,
    )

    expires_at = from_ts(_effective_expiry_ts(sub)) if not unlimited else None

    ttl_seconds = (
        None
        if unlimited
        else _sub_ttl_seconds(
            sub
        )
    )

    return {
        'id': sub.id,
        'name': sub.name,
        'token': sub.token,
        'note': sub.note or '',
        'display_timezone': _panel_timezone_name(),

        'data_limit_value': int(
            getattr(
                sub,
                'data_limit_value',
                0,
            )
            or 0
        ),

        'data_limit_unit': (
            getattr(
                sub,
                'data_limit_unit',
                None,
            )
            or 'Gi'
        ),

        'limit_bytes': limit,
        'used_bytes': used,
        'remaining_bytes': remaining,

        'usage_pct': (
            round(
                (
                    used
                    / int(limit)
                )
                * 100,
                2,
            )
            if limit
            else 0
        ),

        'time_limit_days': _sub_float(
            getattr(
                sub,
                'time_limit_days',
                0,
            )
        ),

        'ttl_seconds': ttl_seconds,

        'start_on_first_use': bool(
            getattr(
                sub,
                'start_on_first_use',
                False,
            )
        ),

        'created_at': isoz(
            created_at
        ),

        'created_at_display': _panel_display_datetime(
            created_at
        ),

        'created_at_ts': to_ts(
            created_at
        ),

        'first_used_at': isoz(
            first_used_at
        ),

        'first_used_at_display': _panel_display_datetime(
            first_used_at
        ),

        'first_used_at_ts': to_ts(
            first_used_at
        ),

        'expires_at': isoz(
            expires_at
        ),

        'expires_at_display': _panel_display_datetime(
            expires_at
        ),

        'expires_at_ts': to_ts(
            expires_at
        ),

        'unlimited': unlimited,

        'phone_number': (
            getattr(
                sub,
                'phone_number',
                '',
            )
            or ''
        ),

        'telegram_id': (
            getattr(
                sub,
                'telegram_id',
                '',
            )
            or ''
        ),

        'enabled': bool(
            getattr(
                sub,
                'enabled',
                True,
            )
        ),

                'runtime_counts': runtime_counts,

        'connection': connection,

        'connected': bool(
            connection.get(
                'connected'
            )
        ),

        'connection_status': (
            connection.get(
                'status'
            )
            or 'disconnected'
        ),

        'connection_label': (
            connection.get(
                'label'
            )
            or 'Disconnected'
        ),

        'public_url': _sub_public_url(
            sub
        ),

        'config_url': _sub_config_url(
            sub
        ),

        'locations': locs,
    }

def _network_int_cidr(value):

    raw = str(value or '').split(',', 1)[0].strip()

    if not raw:
        return ''

    try:
        return str(
            ipaddress.ip_interface(
                raw
            ).network
        )
    except Exception:
        return ''


def _apnd_allowed_route(allowed_ips, route):
    values = [
        item.strip()
        for item in str(
            allowed_ips or ''
        ).split(',')
        if item.strip()
    ]

    route = str(route or '').strip()

    if not route:
        return ', '.join(values)

    if route not in values:
        values.append(route)

    return ', '.join(values)

def _peer_payload_subscription(sub,target,data,idx=0,total=1,):

    name = (target.get('peer_name')or '').strip()

    if not name:
        base = (
            sub.name
            or data.get('name')
            or 'subscription'
        ).strip() or 'subscription'

        name = (
            base
            if total <= 1
            else f'{base}-{idx + 1}')

    allowed_ips = (data.get('allowed_ips')or '0.0.0.0/0, ::/0').strip()

    if bool(data.get('include_internal_network',False,)):
        interface_cidr = (target.get('server_cidr')or target.get('interface_address')or target.get('iface_address')or target.get('address')or '')
        internal_network = (_network_int_cidr(interface_cidr))
        allowed_ips = _apnd_allowed_route(allowed_ips,internal_network,)

    return {
        'name': name,
        'allowed_ips': allowed_ips,
        'endpoint': (data.get('endpoint')or '').strip(),
        'peer_endpoint': (data.get('peer_endpoint')or '').strip(),
        'persistent_keepalive':data.get('persistent_keepalive') or None,
        'mtu':data.get('mtu') or None,
        'dns':data.get('dns') or None,
        'data_limit_value': int(getattr(sub,'data_limit_value',0,) or 0),
        'data_limit_unit': (getattr(sub,'data_limit_unit',None,)or 'Gi'),
        'time_limit_days': (_sub_float(getattr(sub,'time_limit_days',0,))or None),
        'start_on_first_use': bool(getattr(sub,'start_on_first_use',False,)),
        'unlimited': bool(getattr(sub,'unlimited',False,)),
        'phone_number': (getattr(sub,'phone_number','',)or ''),
        'telegram_id': (getattr(sub,'telegram_id','',)or ''),}

def _create_subscription_peer(target, payload, compensation=None):
    """Create one subscription inbound through the shared allocation contract.

    A target's generic `address` field is treated as a hint only: older
    browsers put the interface's own CIDR there, and that is not a client
    address. Everything else goes through `allocate_peer_address`, so a
    subscription can never assign the server host or a duplicate.
    """
    scope = (target.get('scope') or 'local').lower()
    priv = subprocess.check_output(['wg', 'genkey']).strip().decode()
    pub = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).strip().decode()
    payload = dict(payload)
    peer_endpoint = (payload.pop('peer_endpoint', '') or '').strip()
    created_ts = now_ts()

    if scope == 'node':
        nid = _sub_int(target.get('node_id'))
        iface_name = (target.get('iface') or '').strip()
        if not nid or not iface_name:
            raise ValueError('node_id and iface are required for node target')

        node = db.session.get(Node, nid) or abort(404)

        iface = ensure_node_mirror_iface(
            node, iface_name,
            listen_port=_sub_int(target.get('listen_port'), 51820),
            server_cidr=target.get('server_cidr') or target.get('interface_address'),
            mtu=payload.get('mtu'),
            dns=payload.get('dns'),
        )

        if compensation is not None:
            compensation.register_node(node, pub)

        addr = node_install_peer(
            node, iface_name, iface,
            public_key=pub,
            requested_address=requested_peer_address_from_target(iface, target),
            peer_endpoint=peer_endpoint,
            keepalive=payload.get('persistent_keepalive') or 0,
            mtu=payload.get('mtu'),
            dns=payload.get('dns'),
            allowed_ips=payload.get('allowed_ips') or '0.0.0.0/0, ::/0',
        )
        peer = Peer(
            iface_id=iface.id,

            public_key=pub,
            private_key=priv,

            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),

            address=addr,

            peer_endpoint=(peer_endpoint or None),

            status='online',

            **payload,
        )
        db.session.add(peer)
        db.session.flush()
        return peer

    iface_id = _sub_int(target.get('iface_id'))
    iface = db.session.get(InterfaceConfig, iface_id) if iface_id else None
    if not iface and target.get('iface'):
        iface = InterfaceConfig.query.filter_by(name=(target.get('iface') or '').strip()).first()
    if not iface:
        raise ValueError('iface_id is required for local target')

    with interface_allocation_lock(iface):
        requested = requested_peer_address_from_target(iface, target)
        addr = allocate_peer_address(iface, requested=requested)

        peer = Peer(
            iface_id=iface.id,

            public_key=pub,
            private_key=priv,

            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),

            address=addr,

            peer_endpoint=(peer_endpoint or None),

            status='online',

            **payload,
        )
        db.session.add(peer)
        db.session.flush()
        install_local_peer(peer)
        if compensation is not None:
            compensation.register_local(peer)

    return peer

def _attach_subscription_target(sub, target, data, idx=0, total=1, compensation=None):
    if target.get('peer_id'):
        peer = db.session.get(Peer, int(target.get('peer_id'))) or abort(404)
        existing = SubscriptionPeer.query.filter_by(peer_id=peer.id).first()
        if existing and existing.subscription_id != sub.id:
            raise ValueError(f'Peer {peer.name} is already attached to another subscription')
        if existing:
            link = existing
        else:
            link = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id, owned=False)
            db.session.add(link)
            db.session.flush()
    else:
        payload = _peer_payload_subscription(sub, target, data, idx=idx, total=total)
        peer = _create_subscription_peer(target, payload, compensation=compensation)
        link = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id, owned=True)
        db.session.add(link)
        db.session.flush()
    link.sort_order = idx
    link.location_label = (target.get('location_label') or target.get('label') or target.get('location') or '').strip()
    link.country_code = (target.get('country_code') or '').strip()[:2].upper()
    link.flag = (target.get('flag') or '').strip()[:8]
    _sync_peer_subscription(link.peer, sub, idx=idx, rename=True)
    return link

def _update_subscription_payload(sub, data, reset_timer=False):
    old_name = sub.name
    if 'name' in data:
        sub.name = (data.get('name') or sub.name or 'Subscription').strip()
    if 'note' in data:
        sub.note = (data.get('note') or '').strip()
    if 'data_limit_value' in data:
        sub.data_limit_value = _sub_int(data.get('data_limit_value'), 0)
    if 'data_limit_unit' in data:
        sub.data_limit_unit = (data.get('data_limit_unit') or 'Gi')
    if 'time_limit_days' in data:
        sub.time_limit_days = _sub_float(data.get('time_limit_days'), 0)
    if 'start_on_first_use' in data:
        sub.start_on_first_use = _sub_bool(data.get('start_on_first_use'))
    if 'unlimited' in data:
        sub.unlimited = _sub_bool(data.get('unlimited'))
    if 'phone_number' in data:
        sub.phone_number = (data.get('phone_number') or '').strip()
    if 'telegram_id' in data:
        sub.telegram_id = (data.get('telegram_id') or '').strip()
    if 'enabled' in data:
        sub.enabled = _sub_bool(data.get('enabled'))
    timer_policy_changed = any(
        k in data for k in ('time_limit_days', 'start_on_first_use', 'unlimited')
    )
    if reset_timer or timer_policy_changed:
        if reset_timer or not getattr(sub, 'start_on_first_use', False):
            sub.first_used_at = None
        _apply_subscription_timer(sub, restart=True)
    else:
        _apply_subscription_timer(sub)
    _sync_all_subscription_peers(sub, rename=True)

def _reset_subscription_data(sub):

    result = {
        'reset_peers': 0,
        'reactivated': 0,
        'still_blocked': 0,
        'enable_failed': 0,
        'errors': [],
    }

    timer_expired = _subscription_time_expired(sub)

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)

        if not peer:
            continue

        result['reset_peers'] += 1

        try:
            if getattr(peer.iface, 'node_id', None) is not None:
                node = peer.iface.node

                response = node_post(
                    node,
                    f'/api/peer/{peer.public_key}/reset_data',
                    {},
                    timeout=12,
                ) or {}

                if not isinstance(response, dict):
                    raise RuntimeError(
                        'Node returned an invalid reset-data response'
                    )

                if response.get('ok') is False:
                    raise RuntimeError(
                        response.get('detail')
                        or response.get('error')
                        or 'Node reset-data request failed'
                    )

                current_total = response.get('total_bytes')

                if current_total is None:
                    rx_bytes = int(response.get('rx_bytes') or 0)
                    tx_bytes = int(response.get('tx_bytes') or 0)
                    current_total = rx_bytes + tx_bytes

                peer.bytes_offset = max(0, int(current_total or 0))

            else:
                peer.bytes_offset = max(
                    0,
                    int(_wg_transfer(peer) or 0),
                )

            peer.used_bytes_total = 0

        except Exception as exc:
            current_app.logger.exception(
                'Subscription data reset failed for peer %s',
                getattr(peer, 'id', '?'),
            )

            result['errors'].append({
                'peer_id': getattr(peer, 'id', None),
                'peer_name': getattr(peer, 'name', '') or '',
                'detail': str(exc),
            })

            continue

        if peer.status == 'blocked':
            if timer_expired:
                result['still_blocked'] += 1
            elif _enable_subscription(peer):
                result['reactivated'] += 1
            else:
                result['enable_failed'] += 1

        try:
            log_event(
                peer,
                'subscription_reset_data',
                (
                    'Shared subscription data reset; '
                    f'new offset={int(peer.bytes_offset or 0)}'
                ),
            )
        except Exception:
            pass

    return result


def _reset_subscription_timer(sub):

    result = {
        'reset_peers': 0,
        'reactivated': 0,
        'still_blocked': 0,
        'enable_failed': 0,
        'errors': [],
    }

    sub.first_used_at = None
    _apply_subscription_timer(sub, restart=True)

    data_exhausted = _subscription_data_exhausted(sub)

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)

        if not peer:
            continue

        result['reset_peers'] += 1

        try:
            _sync_peer_subscription(
                peer,
                sub,
                rename=False,
            )
        except Exception as exc:
            current_app.logger.exception(
                'Subscription timer sync failed for peer %s',
                getattr(peer, 'id', '?'),
            )

            result['errors'].append({
                'peer_id': getattr(peer, 'id', None),
                'peer_name': getattr(peer, 'name', '') or '',
                'detail': str(exc),
            })

        if peer.status == 'blocked':
            if data_exhausted:
                result['still_blocked'] += 1
            elif _enable_subscription(peer):
                result['reactivated'] += 1
            else:
                result['enable_failed'] += 1

        try:
            log_event(
                peer,
                'subscription_reset_timer',
                'Shared subscription timer reset',
            )
        except Exception:
            pass

    return result


def _subscription_data_exhausted(sub):
    limit = _sub_limit_bytes(sub)

    return bool(
        limit
        and _sub_used_bytes(sub) >= limit
    )


def _subscription_time_expired(sub):
    ttl = _sub_ttl_seconds(sub)

    return bool(
        ttl is not None
        and ttl <= 0
    )


def _enable_subscription(peer):

    try:
        iface = getattr(
            peer,
            'iface',
            None,
        )

        if not iface:
            raise RuntimeError(
                'Peer interface is missing.'
            )

        if getattr(
            iface,
            'node_id',
            None,
        ) is not None:
            node = getattr(
                iface,
                'node',
                None,
            )

            if not node:
                raise RuntimeError(
                    'Peer node is missing.'
                )

            response = node_post(
                node,
                (
                    f'/api/peer/'
                    f'{peer.public_key}/enable'
                ),
                {
                    'host_cidr': _host_peer(peer),
                },
                timeout=15,
            ) or {}

            if not isinstance(
                response,
                dict,
            ):
                raise RuntimeError(
                    'Node returned an invalid enable response.'
                )

            if response.get('ok') is False:
                raise RuntimeError(
                    response.get('detail')
                    or response.get('error')
                    or 'Node peer enable failed.'
                )

        else:
            dev = iface_devname(iface)

            if not _iface_up(dev):
                _check_iface_up(iface)

            if not _iface_up(dev):
                raise RuntimeError(
                    f"WireGuard interface '{dev}' is not running."
                )

            _wg_enable(peer)
            _sync_peer(peer)

        peer.status = 'online'

        return True

    except Exception:
        current_app.logger.exception(
            'Failed enabling subscription peer %s',
            getattr(peer, 'id', '?'),
        )

        return False

def _disable_subscription(peer):

    try:
        iface = getattr(
            peer,
            'iface',
            None,
        )

        if not iface:
            raise RuntimeError(
                'Peer interface is missing.'
            )

        if getattr(
            iface,
            'node_id',
            None,
        ) is not None:
            node = getattr(
                iface,
                'node',
                None,
            )

            if not node:
                raise RuntimeError(
                    'Peer node is missing.'
                )

            response = node_post(
                node,
                (
                    f'/api/peer/'
                    f'{peer.public_key}/disable'
                ),
                {
                    'host_cidr': _host_peer(peer),
                },
                timeout=15,
            ) or {}

            if not isinstance(
                response,
                dict,
            ):
                raise RuntimeError(
                    'Node returned an invalid disable response.'
                )

            if response.get('ok') is False:
                raise RuntimeError(
                    response.get('detail')
                    or response.get('error')
                    or 'Node peer disable failed.'
                )

        else:
            _wg_disable(peer)

        peer.status = 'offline'

        return True

    except Exception:
        current_app.logger.exception(
            'Failed disabling subscription peer %s',
            getattr(peer, 'id', '?'),
        )

        return False
    

def _subscription_enabled(sub,enabled: bool,):
    result = {
        'total': 0,
        'changed': 0,
        'failed': 0,
        'failed_peer_ids': [],
        'errors': [],
    }

    enabled = bool(enabled)

    for link in list(
        getattr(sub, 'links', []) or []
    ):
        peer = getattr(
            link,
            'peer',
            None,
        )

        if not peer:
            continue

        result['total'] += 1

        if enabled:
            success = (
                _enable_subscription(
                    peer
                )
            )
        else:
            success = (
                _disable_subscription(
                    peer
                )
            )

        if success:
            result['changed'] += 1

            try:
                log_event(
                    peer,
                    (
                        'subscription_enabled'
                        if enabled
                        else 'subscription_disabled'
                    ),
                    (
                        'Subscription enabled'
                        if enabled
                        else 'Subscription disabled'
                    ),
                )
            except Exception:
                pass

        else:
            result['failed'] += 1
            result['failed_peer_ids'].append(
                getattr(peer, 'id', None)
            )

            result['errors'].append({
                'peer_id': getattr(
                    peer,
                    'id',
                    None,
                ),
                'peer_name': (
                    getattr(peer, 'name', '')
                    or ''
                ),
            })

    return result
    
@app.get('/subscriptions')
@login_required
def subscriptions_page():
    return render_template('subscriptions.html')

@app.route('/api/subscriptions/settings', methods=['GET', 'POST'])
@require_api_key_or_login
def api_subscription_settings():
    if request.method == 'GET':
        return jsonify(_load_subscription_settings())
    saved = _save_subscription_settings(request.get_json(silent=True) or {})
    return jsonify(ok=True, settings=saved)

@app.post('/api/subscriptions/template-preview')
@require_api_key_or_login
def api_subscription_template_preview():
    """
    Render the real public subscription template for Template Studio.

    Nothing is saved here. The submitted settings exist only for this
    preview response.
    """

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    raw_settings = (
        payload.get('settings')
        if isinstance(
            payload.get('settings'),
            dict,
        )
        else {}
    )

    subscription_id = payload.get(
        'subscription_id'
    )

    sub = None

    if subscription_id not in (
        None,
        '',
        0,
        '0',
    ):
        try:
            subscription_id = int(
                subscription_id
            )

            sub = db.session.get(
                Subscription,
                subscription_id,
            )

        except Exception:
            sub = None

    if sub is not None:
        base_settings = (
            _effective_subscription_settings(
                sub
            )
        )
    else:
        base_settings = (
            _load_subscription_settings()
        )

    cfg = (
        _normalize_subscription_settings(
            raw_settings,
            base=base_settings,
        )
    )

    if sub is not None:
        preview_sub = sub

        try:
            preview_data = (
                _subscription_public_payload(
                    sub
                )
            )
        except Exception:
            preview_data = {}

    else:
        from types import SimpleNamespace

        preview_sub = SimpleNamespace(
            id=0,
            name='premium-user',
            token='preview',
        )

        gib = 1024 ** 3

        preview_data = {
            'id': 0,
            'name': 'premium-user',
            'token': 'preview',

            'enabled': True,
            'unlimited': False,

            'limit_bytes': 10 * gib,
            'used_bytes': int(
                2.4 * gib
            ),

            'data_limit_value': 10,
            'data_limit_unit': 'Gi',

            'start_on_first_use': False,

            'first_used_at': (
                '2026-08-07T09:30:00Z'
            ),

            'expires_at': (
                '2026-08-31T18:00:00Z'
            ),

            'expires_at_ts': None,

            'ttl_seconds': (
                12 * 86400
                + 4 * 3600
            ),

            'access': {
                'allowed': True,
                'reason': '',
                'message': '',
                'has_inbounds': True,
            },

            'locations': [
                {
                    'link_id': 1,
                    'peer_id': 1,
                    'name': 'Amsterdam',
                    'status': 'online',
                    'endpoint': '',
                    'public_host': '',
                    'location_label': (
                        'Netherlands'
                    ),
                    'country_code': 'NL',
                    'flag': '🇳🇱',
                },
                {
                    'link_id': 2,
                    'peer_id': 2,
                    'name': 'Frankfurt',
                    'status': 'online',
                    'endpoint': '',
                    'public_host': '',
                    'location_label': (
                        'Germany'
                    ),
                    'country_code': 'DE',
                    'flag': '🇩🇪',
                },
                {
                    'link_id': 3,
                    'peer_id': 3,
                    'name': 'Backup',
                    'status': 'offline',
                    'endpoint': '',
                    'public_host': '',
                    'location_label': (
                        'Netherlands'
                    ),
                    'country_code': 'NL',
                    'flag': '🇳🇱',
                },
            ],
        }

    support = (
        cfg.get('support')
        or {}
    )

    portal_title = (
        cfg.get('portal_title')
        or preview_sub.name
    )

    return render_template(
        'subscription_public.html',

        preview_mode=True,

        sub=preview_sub,
        data=preview_data,

        portal_settings=cfg,

        sub_layout=cfg.get(
            'layout',
            'aurora',
        ),

        sub_display_mode=cfg.get(
            'display_mode',
            'hybrid',
        ),

        sub_animation=cfg.get(
            'animation',
            'balanced',
        ),

        sub_background=cfg.get(
            'background',
            'aurora',
        ),

        portal_label=cfg.get(
            'portal_label',
            'Secure WireGuard portal',
        ),

        portal_icon=cfg.get(
            'portal_icon',
            'fas fa-bolt',
        ),

        portal_title=portal_title,

        portal_subtitle=cfg.get(
            'portal_subtitle',
            (
                'Your account is ready. '
                'Install WireGuard, then '
                'scan QR or import a config.'
            ),
        ),

        support_portal_label=cfg.get(
            'portal_label',
            'Secure WireGuard portal',
        ),

        support_portal_icon=cfg.get(
            'portal_icon',
            'fas fa-bolt',
        ),

        support_portal_title=(
            portal_title
        ),

        support_portal_subtitle=cfg.get(
            'portal_subtitle',
            (
                'Your account is ready. '
                'Install WireGuard, then '
                'scan QR or import a config.'
            ),
        ),

        support_telegram=support.get(
            'telegram',
            '',
        ),

        support_whatsapp=support.get(
            'whatsapp',
            '',
        ),

        support_instagram=support.get(
            'instagram',
            '',
        ),

        support_phone=support.get(
            'phone',
            '',
        ),

        support_website=support.get(
            'website',
            '',
        ),

        support_email=support.get(
            'email',
            '',
        ),
    )

@app.route(
    '/api/subscriptions/<int:sid>/portal-settings',
    methods=[
        'GET',
        'POST',
        'DELETE',
    ],
)
@require_api_key_or_login
def api_subscription_portal_settings(
    sid,
):
    sub = (
        db.session.get(
            Subscription,
            sid,
        )
        or abort(404)
    )

    store = (
        _load_subscription_portal_overrides()
    )

    key = str(
        sub.id
    )

    if request.method == 'GET':
        override = (
            store.get(key)
            if isinstance(
                store.get(key),
                dict,
            )
            else {}
        )

        return jsonify(
            ok=True,
            subscription_id=sub.id,
            subscription_name=sub.name,

            has_override=bool(
                override
            ),

            override=override,

            settings=(
                _effective_subscription_settings(
                    sub
                )
            ),

            global_settings=(
                _load_subscription_settings()
            ),
        )

    if request.method == 'DELETE':
        existed = (
            key in store
        )

        store.pop(
            key,
            None,
        )

        _save_subscription_portal_overrides(
            store
        )

        return jsonify(
            ok=True,
            removed=existed,
            subscription_id=sub.id,
            settings=(
                _load_subscription_settings()
            ),
        )

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    global_settings = (
        _load_subscription_settings()
    )

    normalized = (
        _normalize_subscription_settings(
            payload,
            base=global_settings,
        )
    )

    override = {}

    for field in payload.keys():

        if (
            field == 'support'
            and isinstance(
                payload.get('support'),
                dict,
            )
        ):
            override['support'] = {
                support_key: (
                    normalized[
                        'support'
                    ].get(
                        support_key,
                        '',
                    )
                )
                for support_key
                in payload['support'].keys()
                if support_key
                in normalized['support']
            }

        elif (
            field in normalized
            and field != 'socials'
        ):
            override[
                field
            ] = normalized[
                field
            ]

    store[
        key
    ] = override

    _save_subscription_portal_overrides(
        store
    )

    return jsonify(
        ok=True,
        subscription_id=sub.id,
        subscription_name=sub.name,
        has_override=True,
        override=override,

        settings=(
            _effective_subscription_settings(
                sub
            )
        ),
    )

@app.get('/api/subscriptions/locations')
@require_api_key_or_login
def api_subscriptions_locations():

    local_locations = []

    for iface in InterfaceConfig.query.order_by(
        InterfaceConfig.name
    ).all():

        iface_name = (
            getattr(iface, 'name', '')
            or ''
        )

        is_node_interface = (
            getattr(iface, 'node_id', None)
            is not None
            or (
                iface_name.startswith('n')
                and ':' in iface_name
            )
        )

        if is_node_interface:
            continue

        interface_address = (
            getattr(iface, 'address', None)
            or ''
        )

        endpoint_override = iface_endpoint_override(iface)
        endpoint_value = resolve_client_endpoint(iface)

        local_locations.append({
            'scope': 'local',
            'iface_id': iface.id,
            'iface': iface_name,
            'label': iface_name,
            'interface_address': interface_address,
            'server_cidr': interface_address,
            'endpoint': endpoint_value,
            'endpoint_override': endpoint_override,
            'endpoint_source': (
                'override' if endpoint_override
                else ('auto' if endpoint_value else 'none')
            ),
            'scope_networks': _private_networks(),
            'listen_port': iface.listen_port,
            'dns': iface.dns or '',
            'mtu': iface.mtu,
            'available': len(
                _available_ips(iface)
            ),
        })

    node_locations = []

    for node in Node.query.order_by(
        Node.name
    ).all():

        interfaces = []

        try:
            remote_payload = node_get(
                node,
                '/api/interfaces',
                timeout=10,
            ) or {}

            if isinstance(remote_payload, dict):
                node_scope_networks = (
                remote_payload.get('scope_networks')
                or []
            )
            else:
                node_scope_networks = []

            if not isinstance(node_scope_networks, list):
                node_scope_networks = [
                    value.strip()
                    for value in str(
                        node_scope_networks or ''
                    ).split(',')
                    if value.strip()
                ]

            node_scope_networks = list(
                dict.fromkeys(node_scope_networks)
            )

            if isinstance(remote_payload, dict):
                remote_interfaces = (
                    remote_payload.get('interfaces')
                    or []
                )
            else:
                remote_interfaces = (
                    remote_payload
                    or []
                )

            if not isinstance(
                remote_interfaces,
                list,
            ):
                remote_interfaces = []

            for item in remote_interfaces:
                if not isinstance(item, dict):
                    continue

                remote_name = (
                    item.get('name')
                    or item.get('iface')
                    or ''
                ).strip()

                if not remote_name:
                    continue

                mirror_name = (
                    f'n{node.id}:{remote_name}'
                )

                mirror = (
                    InterfaceConfig.query
                    .filter_by(name=mirror_name)
                    .first()
                )

                interface_address = (
                    item.get('address')
                    or (
                        mirror.address
                        if mirror
                        else ''
                    )
                    or ''
                )

                endpoint_override = (
                    iface_endpoint_override(mirror)
                    if mirror is not None
                    else ''
                )

                interfaces.append({
                    'scope': 'node',
                    'node_id': node.id,
                    'node_name': node.name,

                    'iface_id': (
                        mirror.id
                        if mirror
                        else None
                    ),

                    'iface': remote_name,

                    'label': (
                        f'{node.name} · '
                        f'{remote_name}'
                    ),

                    'interface_address': interface_address,
                    'server_cidr': interface_address,
                    'scope_networks': list(dict.fromkeys((item.get('scope_networks')if isinstance(item.get('scope_networks'),list,)else node_scope_networks)or node_scope_networks)),

                    'listen_port': (
                        item.get('listen_port')
                    ),

                    'dns': (
                        item.get('dns')
                        or ''
                    ),

                    'mtu': item.get('mtu'),
                    'endpoint': endpoint_override,
                    'endpoint_override': endpoint_override,
                    'endpoint_source': 'override' if endpoint_override else 'auto',

                    'available': len(
                        item.get('available_ips')
                        or []
                    ),
                })

        except Exception:
            current_app.logger.exception(
                'Failed to load subscription '
                'interfaces from node_id=%s',
                node.id,
            )

            mirrored_interfaces = (
                InterfaceConfig.query
                .filter(
                    InterfaceConfig.name.like(
                        f'n{node.id}:%'
                    )
                )
                .all()
            )

            for iface in mirrored_interfaces:
                stored_name = (
                    iface.name
                    or ''
                )

                remote_name = (
                    stored_name.split(':', 1)[1]
                    if ':' in stored_name
                    else stored_name
                )

                interface_address = (
                    iface.address
                    or ''
                )

                endpoint_override = iface_endpoint_override(iface)

                interfaces.append({
                    'scope': 'node',
                    'node_id': node.id,
                    'node_name': node.name,
                    'iface_id': iface.id,
                    'iface': remote_name,

                    'label': (
                        f'{node.name} · '
                        f'{remote_name}'
                    ),

                    'interface_address': interface_address,
                    'server_cidr': interface_address,

                    'listen_port': (
                        iface.listen_port
                    ),

                    'dns': iface.dns or '',
                    'mtu': iface.mtu,

                    'endpoint': endpoint_override,
                    'endpoint_override': endpoint_override,
                    'endpoint_source': 'override' if endpoint_override else 'auto',

                    'available': len(
                        _available_ips(iface)
                    ),
                })

        node_locations.append({
            'id': node.id,
            'name': node.name,
            'online': bool(node.enabled),
            'interfaces': interfaces,
        })

    return jsonify(
        local=local_locations,
        nodes=node_locations,
    )

@app.get('/api/subscriptions/inbounds_catalog')
@require_api_key_or_login
def api_subscriptions_inbounds_catalog():
    inbounds = []
    for p in Peer.query.order_by(Peer.name).all():
        iface = p.iface
        raw = iface.name if iface else ''
        node_id = getattr(iface, 'node_id', None) if iface else None
        linked = SubscriptionPeer.query.filter_by(peer_id=p.id).first()
        inbounds.append({
            'peer_id': p.id,
            'scope': 'node' if node_id is not None or raw.startswith('n') and ':' in raw else 'local',
            'node_id': node_id,
            'node_name': (getattr(iface.node, 'name', '') if getattr(iface, 'node', None) else ''),
            'iface': raw.split(':',1)[1] if raw.startswith('n') and ':' in raw else raw,
            'name': p.name,
            'address': p.address,
            'endpoint': resolve_client_endpoint_cheap(iface, explicit=p.endpoint),
            'allowed_ips': p.allowed_ips or '',
            'dns': p.dns or '',
            'status': p.status or 'offline',
            'used_bytes': int(getattr(p, 'used_bytes_total', 0) or 0),
            'phone_number': p.phone_number or '',
            'telegram_id': p.telegram_id or '',
            'already_linked': bool(linked),
            'subscription_id': linked.subscription_id if linked else None,
            'location_label': linked.location_label if linked else '',
        })
    return jsonify(inbounds=inbounds)

@app.route('/api/subscriptions', methods=['GET', 'POST'])
@require_api_key_or_login
def api_subscriptions():
    if request.method == 'GET':
        rows = Subscription.query.order_by(Subscription.created_at.desc()).all()
        db.session.commit()
        return jsonify(subscriptions=[_subscription_row(s) for s in rows])
    data = request.get_json(silent=True) or {}
    created_ts = now_ts()
    sub = Subscription(
        name=(data.get('name')or 'Subscription').strip(),

        token=_token(),

        created_at=from_ts(created_ts),
        timer_started_at=from_ts(created_ts),

        note=(data.get('note')or '').strip(),

        data_limit_value=_sub_int(data.get('data_limit_value'),0,),

        data_limit_unit=(data.get('data_limit_unit')or 'Gi'),

        time_limit_days=_sub_float(data.get('time_limit_days'),0,),

        start_on_first_use=_sub_bool(data.get('start_on_first_use')),

        unlimited=_sub_bool(data.get('unlimited')),

        phone_number=(data.get('phone_number')or '').strip(),

        telegram_id=(data.get('telegram_id')or '').strip(),

        enabled=True,
    )
    _apply_subscription_timer(sub)
    db.session.add(sub)
    db.session.flush()
    targets = data.get('targets') or []
    compensation = PeerCreateCompensation()
    try:
        for idx, target in enumerate(targets):
            _attach_subscription_target(
                sub, target or {}, data, idx=idx, total=len(targets),
                compensation=compensation,
            )
        _sync_all_subscription_peers(sub, rename=True)
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub)), 201
    except AddressAllocationError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        if cleanup_failures:
            return jsonify(
                error='subscription_create_cleanup_failed',
                detail=str(e),
                address_error=e.error_code,
                cleanup_complete=False,
                cleanup_failures=cleanup_failures,
            ), 502
        return address_error_response(e)
    except NodePeerInstallError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        return jsonify(
            error=e.code,
            detail=e.detail,
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else e.status
    except Exception as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        current_app.logger.exception('subscription create failed')
        return jsonify(
            error='subscription_create_failed',
            detail=str(e),
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else 500

@app.get('/api/subscriptions/<int:sid>')
@require_api_key_or_login
def api_subscription_get(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    return jsonify(subscription=_subscription_row(sub))

@app.put('/api/subscriptions/<int:sid>')
@require_api_key_or_login
def api_subscription_update(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    data = request.get_json(silent=True) or {}
    try:
        _update_subscription_payload(sub, data, reset_timer=_sub_bool(data.get('reset_timer')))
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub))
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception('subscription update failed')
        return jsonify(error='subscription_update_failed', detail=str(e)), 500

@app.post('/api/subscriptions/<int:sid>/inbounds')
@require_api_key_or_login
def api_subscription_add_inbounds(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    data = request.get_json(silent=True) or {}
    targets = data.get('targets') or []
    compensation = PeerCreateCompensation()
    try:
        base = db.session.query(func.max(SubscriptionPeer.sort_order)).filter_by(subscription_id=sub.id).scalar() or 0
        for off, target in enumerate(targets):
            _attach_subscription_target(
                sub, target or {}, data,
                idx=base + off + 1,
                total=len(getattr(sub, 'links', []) or []) + len(targets),
                compensation=compensation,
            )
        _sync_all_subscription_peers(sub, rename=True)
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub))
    except AddressAllocationError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        if cleanup_failures:
            return jsonify(
                error='subscription_add_inbound_cleanup_failed',
                detail=str(e),
                address_error=e.error_code,
                cleanup_complete=False,
                cleanup_failures=cleanup_failures,
            ), 502
        return address_error_response(e)
    except NodePeerInstallError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        return jsonify(
            error=e.code,
            detail=e.detail,
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else e.status
    except Exception as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        current_app.logger.exception('subscription add inbound failed')
        return jsonify(
            error='subscription_add_inbound_failed',
            detail=str(e),
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else 500

@app.patch('/api/subscriptions/<int:sid>/inbounds/<int:link_id>')
@require_api_key_or_login
def api_subscription_patch_inbound(sid, link_id):
    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sid).first() or abort(404)
    data = request.get_json(silent=True) or {}
    link.location_label = (data.get('location_label') or '').strip()
    db.session.commit()
    return jsonify(ok=True, subscription=_subscription_row(link.subscription))

@app.delete('/api/subscriptions/<int:sid>/inbounds/<int:link_id>')
@require_api_key_or_login
def api_subscription_remove_inbound(sid, link_id):
    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sid).first() or abort(404)
    sub = link.subscription
    delete_peer = _sub_bool(request.args.get('delete_peer'))
    peer = link.peer

    if delete_peer and peer:
        if not bool(getattr(link, 'owned', False)):
            return jsonify(
                ok=False,
                error='peer_not_owned',
                detail=(
                    f'Peer {peer.name} was attached to this subscription, not created '
                    f'by it. Detach it here and delete it from the peers page instead.'
                ),
            ), 409

        try:
            remove_peer_everywhere(peer)
        except PeerRemovalError as e:
            current_app.logger.error(
                'subscription inbound peer delete failed at %s stage: %s', e.phase, e
            )
            return peer_removal_response(e, peer_id=peer.id)
    else:
        db.session.delete(link)
        db.session.flush()

    _sync_all_subscription_peers(sub, rename=True)
    db.session.commit()
    return jsonify(ok=True, subscription=_subscription_row(sub))

@app.delete('/api/subscriptions/<int:sid>')
@require_api_key_or_login
def api_subscription_delete(sid):
    """Delete a subscription.

    Peers the subscription created are deleted; peers that were merely
    attached are detached and left running. `delete_peers=0` detaches
    everything instead.
    """
    sub = db.session.get(Subscription, sid) or abort(404)

    delete_peers = request.args.get('delete_peers')
    delete_peers = True if delete_peers is None else _sub_bool(delete_peers)

    owned, attached = [], []
    for link in list(sub.links or []):
        if not link.peer:
            continue
        if delete_peers and bool(getattr(link, 'owned', False)):
            owned.append(link.peer)
        else:
            attached.append(link.peer)

    deleted, failures = 0, []

    for peer in owned:
        peer_id = peer.id
        peer_name = peer.name
        try:
            remove_peer_everywhere(peer)
            deleted += 1
        except PeerRemovalError as e:
            current_app.logger.error(
                'subscription %s: peer %s could not be removed at the %s stage: %s',
                sid, peer_id, e.phase, e,
            )
            failures.append({'peer_id': peer_id, 'name': peer_name, 'phase': e.phase,
                             'detail': str(e)})

    if failures:
        db.session.rollback()
        return jsonify(
            ok=False,
            error='subscription_delete_incomplete',
            deleted=deleted,
            detached=0,
            failed=len(failures),
            failures=failures,
        ), 502

    try:
        db.session.delete(sub)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception('subscription delete failed')
        return jsonify(error='subscription_delete_failed', detail=str(e)), 500

    return jsonify(
        ok=True,
        deleted_peers=bool(delete_peers),
        deleted=deleted,
        detached=len(attached),
        failed=0,
    )

@app.post('/api/subscriptions/<int:sid>/disable')
@require_api_key_or_login
def api_subscription_disable(sid):

    sub = (
        db.session.get(
            Subscription,
            sid,
        )
        or abort(404)
    )

    try:
        result = (
            _subscription_enabled(
                sub,
                False,
            )
        )

        if (
            result['total'] > 0
            and result['changed'] == 0
        ):
            db.session.rollback()

            return jsonify(
                ok=False,
                error='subscription_disable_failed',
                detail=(
                    'None of the attached configs '
                    'could be disabled.'
                ),
                result=result,
            ), 409

        sub.enabled = False

        db.session.commit()

        partial = result['failed'] > 0

        if partial:
            message = (
                'Subscription was disabled, but one or more '
                'attached configs could not be stopped.'
            )
        elif result['changed']:
            message = (
                'Subscription and all attached configs '
                'were disabled.'
            )
        else:
            message = (
                'Subscription was disabled. '
                'It has no attached configs.'
            )

        try:
            logpanel_action(
                'subscription_disable',
                (
                    f'sid={sub.id}; '
                    f'total={result["total"]}; '
                    f'disabled={result["changed"]}; '
                    f'failed={result["failed"]}; '
                    'data_preserved=1; timer_preserved=1'
                ),
            )
        except Exception:
            pass

        return jsonify(
            ok=not partial,
            partial=partial,
            enabled=False,
            data_reset=False,
            timer_reset=False,
            message=message,
            result=result,
            subscription=_subscription_row(sub),
        ), 207 if partial else 200

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Subscription disable failed: %s',
            sid,
        )

        return jsonify(
            ok=False,
            error='subscription_disable_failed',
            detail=str(exc),
        ), 500

@app.post('/api/subscriptions/<int:sid>/enable')
@require_api_key_or_login
def api_subscription_enable(sid):

    sub = (
        db.session.get(
            Subscription,
            sid,
        )
        or abort(404)
    )

    try:
        runtime_result = (
            _subscription_enabled(
                sub,
                True,
            )
        )

        if (
            runtime_result['total'] > 0
            and runtime_result['changed'] == 0
        ):
            db.session.rollback()

            return jsonify(
                ok=False,
                error='subscription_enable_failed',
                detail=(
                    'None of the attached configs '
                    'could be enabled.'
                ),
                result={
                    'runtime': runtime_result,
                },
            ), 409

        data_result = (
            _reset_subscription_data(
                sub
            )
        )

        timer_result = (
            _reset_subscription_timer(
                sub
            )
        )

        sub.enabled = True

        db.session.commit()

        failure_count = (
            int(
                runtime_result.get(
                    'failed',
                    0,
                )
                or 0
            )
            + int(
                data_result.get(
                    'enable_failed',
                    0,
                )
                or 0
            )
            + int(
                timer_result.get(
                    'enable_failed',
                    0,
                )
                or 0
            )
            + len(
                data_result.get(
                    'errors',
                    [],
                )
                or []
            )
            + len(
                timer_result.get(
                    'errors',
                    [],
                )
                or []
            )
        )

        partial = failure_count > 0

        if partial:
            message = (
                'Subscription was enabled and its timer and data '
                'were reset, but one or more attached configs '
                'reported an error.'
            )
        elif runtime_result['changed']:
            message = (
                'Subscription and all attached configs were enabled. '
                'Data usage and timer were reset.'
            )
        else:
            message = (
                'Subscription was enabled. '
                'Data usage and timer were reset.'
            )

        try:
            logpanel_action(
                'subscription_enable',
                (
                    f'sid={sub.id}; '
                    f'total={runtime_result["total"]}; '
                    f'enabled={runtime_result["changed"]}; '
                    f'failed={failure_count}; '
                    'data_reset=1; timer_reset=1'
                ),
            )
        except Exception:
            pass

        return jsonify(
            ok=not partial,
            partial=partial,
            enabled=True,
            data_reset=True,
            timer_reset=True,
            message=message,
            result={
                'runtime': runtime_result,
                'data': data_result,
                'timer': timer_result,
            },
            subscription=_subscription_row(sub),
        ), 207 if partial else 200

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Subscription enable failed: %s',
            sid,
        )

        return jsonify(
            ok=False,
            error='subscription_enable_failed',
            detail=str(exc),
        ), 500
        
@app.post('/api/subscriptions/<int:sid>/reset_data')
@require_api_key_or_login
def api_subscription_reset_data(sid):
    sub = db.session.get(Subscription, sid) or abort(404)

    try:
        result = _reset_subscription_data(sub)
        db.session.commit()

        timer_expired = _subscription_time_expired(sub)

        if result['errors']:
            message = (
                'Data was reset for some configs, but one or more node '
                'counters could not be read.'
            )
        elif timer_expired and result['still_blocked']:
            message = (
                'Data was reset, but the subscription remains blocked '
                'because its timer is expired. Reset the timer as well.'
            )
        elif result['enable_failed']:
            message = (
                'Data was reset, but one or more configs could not be '
                're-enabled.'
            )
        elif result['reactivated']:
            message = 'Data was reset and blocked configs were re-enabled.'
        else:
            message = 'Subscription data was reset.'

        return jsonify(
            ok=not bool(result['errors']),
            partial=bool(result['errors']),
            message=message,
            reason=(
                'timer_expired'
                if timer_expired and result['still_blocked']
                else (
                    'enable_failed'
                    if result['enable_failed']
                    else None
                )
            ),
            result=result,
            subscription=_subscription_row(sub),
        ), 207 if result['errors'] else 200

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Subscription reset data failed'
        )

        return jsonify(
            error='subscription_reset_data_failed',
            detail=str(exc),
        ), 500


@app.post('/api/subscriptions/<int:sid>/reset_timer')
@require_api_key_or_login
def api_subscription_reset_timer(sid):
    sub = db.session.get(Subscription, sid) or abort(404)

    try:
        result = _reset_subscription_timer(sub)
        db.session.commit()

        data_exhausted = _subscription_data_exhausted(sub)

        if data_exhausted and result['still_blocked']:
            message = (
                'Timer was reset, but the subscription remains blocked '
                'because its data allowance is exhausted. Reset data as well.'
            )
        elif result['enable_failed']:
            message = (
                'Timer was reset, but one or more configs could not be '
                're-enabled.'
            )
        elif result['reactivated']:
            message = 'Timer was reset and blocked configs were re-enabled.'
        else:
            message = 'Subscription timer was reset.'

        return jsonify(
            ok=not bool(result['errors']),
            partial=bool(result['errors']),
            message=message,
            reason=(
                'data_exhausted'
                if data_exhausted and result['still_blocked']
                else (
                    'enable_failed'
                    if result['enable_failed']
                    else None
                )
            ),
            result=result,
            subscription=_subscription_row(sub),
        ), 207 if result['errors'] else 200

    except Exception as exc:
        db.session.rollback()

        current_app.logger.exception(
            'Subscription reset timer failed'
        )

        return jsonify(
            error='subscription_reset_timer_failed',
            detail=str(exc),
        ), 500

@app.get('/api/subscriptions/<int:sid>/shortlink')
@require_api_key_or_login
def api_subscription_shortlink(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    return jsonify(url=_sub_public_url(sub), config_url=_sub_config_url(sub), token=sub.token)


GEO_CACHE_FILE = os.path.join(app.instance_path, 'subscription_geo_cache.json')
GEO_CACHE_TTL = 7 * 24 * 3600


def _flag_from_cc(cc: str) -> str:
    cc = (cc or '').strip().upper()
    if not re.match(r'^[A-Z]{2}$', cc):
        return '🌐'
    return ''.join(chr(127397 + ord(ch)) for ch in cc)


def _load_geo_cache() -> dict:
    try:
        with open(GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_geo_cache(data: dict):
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        with open(GEO_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _i_public_host(host: str) -> bool:
    host = (host or '').strip().strip('[]')
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_global)
    except Exception:
        low = host.lower()
        return low not in ('localhost',) and not low.endswith('.local')


def _endpoint_host(endpoint: str) -> str:
    endpoint = (endpoint or '').strip()
    if not endpoint:
        return ''
    if endpoint.startswith('[') and ']' in endpoint:
        return endpoint[1:].split(']', 1)[0]
    if ':' in endpoint:
        return endpoint.rsplit(':', 1)[0]
    return endpoint


def _node_public_host(iface) -> str:
    try:
        nid = getattr(iface, 'node_id', None)
        if nid is None:
            nm = getattr(iface, 'name', '') or ''
            m = re.match(r'^n(\d+):', nm)
            nid = int(m.group(1)) if m else None
        if nid is None:
            return ''
        n = db.session.get(Node, int(nid))
        if not n:
            return ''
        try:
            h = node_get(n, '/api/health', timeout=5) or {}
            pub = (h.get('public_ipv4') or h.get('ipv4') or h.get('public_ip') or '').strip()
            if pub:
                return pub
        except Exception:
            pass
        return (_geo_urlparse(n.base_url or '').hostname or '').strip()
    except Exception:
        return ''


def _public_host_peer(peer) -> str:
    """
    Return the public host of the SERVER where this WG interface is active.

    """
    try:
        iface = peer.iface
    except Exception:
        iface = None

    iface_name = getattr(iface, 'name', '') or ''
    is_node = bool(
        iface and (
            getattr(iface, 'node_id', None) is not None or
            re.match(r'^n\d+:', iface_name)
        )
    )

    if is_node:
        host = _node_public_host(iface)
        if _i_public_host(host):
            return host

        try:
            nid = getattr(iface, 'node_id', None)
            if nid is None:
                m = re.match(r'^n(\d+):', iface_name)
                nid = int(m.group(1)) if m else None
            n = db.session.get(Node, int(nid)) if nid is not None else None
            if n:
                host = _endpoint_host(getattr(n, 'base_url', '') or '')
                if _i_public_host(host):
                    return host
        except Exception:
            pass

        return ''

    try:
        host = _public_ipv4(force=True)
    except TypeError:
        host = _public_ipv4()
    except Exception:
        host = ''

    if _i_public_host(host):
        return host

    if iface:
        host = _endpoint_host(_endpoint_fallback(iface))
        if _i_public_host(host):
            return host

    return ''

def _lookup_geo(host: str) -> dict:
    host = (host or '').strip().strip('[]')
    if not _i_public_host(host):
        return {'country': '', 'country_code': '', 'flag': '🌐'}

    now = int(_geo_time.time())
    cache = _load_geo_cache()
    old = cache.get(host) or {}
    if old and (now - int(old.get('ts') or 0) < GEO_CACHE_TTL):
        return old

    headers = {'User-Agent': 'WG-Panel/1.0 (+subscription geo)'}
    providers = [
        ('ipwho', f'https://ipwho.is/{host}'),
        ('ipapi', f'https://ipapi.co/{host}/json/'),
        ('ipapi2', f'http://ip-api.com/json/{host}?fields=status,country,countryCode'),
    ]

    for provider, url in providers:
        try:
            r = requests.get(url, headers=headers, timeout=4)
            if not r.ok:
                continue
            j = r.json() or {}
            country = ''
            cc = ''
            if provider == 'ipwho':
                if j.get('success') is False:
                    continue
                country = (j.get('country') or '').strip()
                cc = (j.get('country_code') or '').strip().upper()
            elif provider == 'ipapi':
                country = (j.get('country_name') or '').strip()
                cc = (j.get('country_code') or j.get('country') or '').strip().upper()
            else:
                if j.get('status') != 'success':
                    continue
                country = (j.get('country') or '').strip()
                cc = (j.get('countryCode') or '').strip().upper()

            if cc or country:
                geo = {'country': country or cc, 'country_code': cc, 'flag': _flag_from_cc(cc), 'ts': now}
                cache[host] = geo
                _save_geo_cache(cache)
                return geo
        except Exception:
            continue

    return {'country': '', 'country_code': '', 'flag': '🌐', 'ts': now}


def _peer_used_for_subscription(peer) -> int:
    try:
        iface = getattr(peer, 'iface', None)
        is_node = bool(
            iface and (
                getattr(iface, 'node_id', None) is not None or
                re.match(r'^n\d+:', getattr(iface, 'name', '') or '')
            )
        )

        if is_node:
            return int(getattr(peer, 'used_bytes_total', 0) or 0)

        total = _wg_transfer(peer)
        used, _delta, changed = _accumulate_peer_usage(peer, total)
        if changed:
            db.session.commit()
        return int(used)

    except Exception:
        return int(getattr(peer, 'used_bytes_total', 0) or 0)

def subscription_access(sub, used_bytes=None) -> dict:
    """Whether this subscription may still hand out working configs.

    The public page always renders and explains the state; the config, ZIP and
    QR endpoints refuse when access is revoked, so a saved link cannot keep
    working after the subscription is disabled, expires or runs out of data.
    """
    if not bool(getattr(sub, 'enabled', True)):
        return {
            'allowed': False,
            'reason': 'disabled',
            'message': 'This subscription has been disabled. Please contact support.',
        }

    if bool(getattr(sub, 'unlimited', False)):
        return {'allowed': True, 'reason': '', 'message': ''}

    expires_ts = _effective_expiry_ts(sub)
    if expires_ts and expires_ts <= now_ts():
        return {
            'allowed': False,
            'reason': 'expired',
            'message': 'This subscription has expired. Please renew it to continue.',
        }

    limit = sub.limit_bytes() if hasattr(sub, 'limit_bytes') else None
    if limit:
        try:
            used = int(_sub_used_bytes(sub) if used_bytes is None else used_bytes)
        except Exception:
            used = 0
        if used >= int(limit):
            return {
                'allowed': False,
                'reason': 'data_exhausted',
                'message': 'This subscription has used all of its data allowance.',
            }

    return {'allowed': True, 'reason': '', 'message': ''}


def _subscription_inbound_state(sub):
    """A non-blocking signal for the portal: are there any usable inbounds?
    """
    links = getattr(sub, 'links', None) or []
    usable = sum(
        1 for link in links
        if getattr(link, 'peer', None) is not None
        and str(getattr(getattr(link, 'peer', None), 'status', '') or '').lower() != 'removed'
    )
    return {'inbound_count': usable, 'has_inbounds': usable > 0}


def _subscription_access_or_403(sub):
    """Return a 403 response when access is revoked, otherwise ``None``."""
    access = subscription_access(sub)
    if access['allowed']:
        return None

    return jsonify(
        ok=False,
        error='subscription_access_revoked',
        reason=access['reason'],
        message=access['message'],
    ), 403


def _subscription_public_payload(sub) -> dict:
    try:
        _expire()
    except Exception:
        pass

    links = sorted(list(getattr(sub, 'links', []) or []), key=lambda x: (x.sort_order or 0, x.id or 0))
    limit_bytes = sub.limit_bytes() if hasattr(sub, 'limit_bytes') else None
    used_bytes = 0
    locs = []
    dirty = False

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        used_bytes += _peer_used_for_subscription(peer)

    access = subscription_access(sub, used_bytes=used_bytes)
    access.update(_subscription_inbound_state(sub))
    may_disclose_topology = bool(access['allowed'])

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue

        host = _public_host_peer(peer) if may_disclose_topology else ''

        cc = (getattr(link, 'country_code', '') or '').strip().upper()
        flag = (getattr(link, 'flag', '') or '').strip()
        label = (getattr(link, 'location_label', '') or '').strip()
        if host:
            geo = _lookup_geo(host)
            new_cc = (geo.get('country_code') or '').strip().upper()
            new_flag = geo.get('flag') or _flag_from_cc(new_cc)
            new_label = geo.get('country') or new_cc or ''
            if new_cc and new_cc != cc:
                cc = new_cc
                flag = new_flag
                label = new_label
                link.country_code = cc
                link.flag = flag
                link.location_label = label
                dirty = True
            elif new_cc and not cc:
                cc = new_cc
                flag = new_flag
                label = new_label
                link.country_code = cc
                link.flag = flag
                link.location_label = label
                dirty = True

        endpoint = ''
        if may_disclose_topology and getattr(peer, 'iface', None):
            endpoint = resolve_client_endpoint_cheap(
                peer.iface, explicit=getattr(peer, 'endpoint', '')
            )
        elif may_disclose_topology:
            endpoint = getattr(peer, 'endpoint', '') or ''

        locs.append({
            'link_id': link.id,
            'peer_id': peer.id,
            'name': peer.name,
            'status': peer.status,
            'endpoint': endpoint,
            'public_host': host,
            'location_label': label,
            'country_code': cc,
            'flag': flag or _flag_from_cc(cc),
        })

    if dirty:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    exp_ts = _effective_expiry_ts(sub)
    ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None

    if limit_bytes is not None:
        used_bytes = min(int(used_bytes), int(limit_bytes))

    return {
        'id': sub.id,
        'name': sub.name,
        'token': sub.token,
        'display_timezone': _panel_timezone_name(),
        'enabled': bool(getattr(sub, 'enabled', True)),
        'unlimited': bool(getattr(sub, 'unlimited', False)),
        'limit_bytes': limit_bytes,
        'used_bytes': int(used_bytes),
        'data_limit_value': getattr(sub, 'data_limit_value', 0) or 0,
        'data_limit_unit': getattr(sub, 'data_limit_unit', 'Gi') or 'Gi',
        'start_on_first_use': bool(getattr(sub, 'start_on_first_use', False)),
        'first_used_at': isoz(getattr(sub, 'first_used_at', None)),
        'first_used_at_display': _panel_display_datetime(getattr(sub, 'first_used_at', None)),
        'expires_at': isoz(from_ts(exp_ts)),
        'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
        'expires_at_ts': exp_ts,
        'ttl_seconds': ttl_seconds,
        'access': access,
        'locations': locs,
    }


def _subscription_settings_public(
    sub=None,
):
    settings = (
        _effective_subscription_settings(
            sub
        )
    )

    support = (
        settings.get('support')
        or {}
    )

    result = dict(
        settings
    )

    result[
        'socials'
    ] = {
        'telegram': support.get(
            'telegram',
            '',
        ),

        'whatsapp': support.get(
            'whatsapp',
            '',
        ),

        'instagram': support.get(
            'instagram',
            '',
        ),

        'phone': support.get(
            'phone',
            '',
        ),

        'website': support.get(
            'website',
            '',
        ),

        'email': support.get(
            'email',
            '',
        ),
    }

    result[
        'has_override'
    ] = bool(
        sub
        and _subscription_portal_override(
            sub
        )
    )

    return result

@app.get('/s/<token>')
def subscription_public_page(
    token,
):
    sub = (
        Subscription.query
        .filter_by(
            token=token
        )
        .first()
        or abort(404)
    )

    cfg = (
        _subscription_settings_public(
            sub
        )
    )

    socials = (
        cfg.get(
            'socials'
        )
        or {}
    )

    portal_title = (
        cfg.get(
            'portal_title'
        )
        or sub.name
    )

    return render_template(
        'subscription_public.html',

        sub=sub,

        data=(
            _subscription_public_payload(
                sub
            )
        ),

        portal_settings=cfg,

        sub_layout=cfg.get(
            'layout',
            'aurora',
        ),

        sub_display_mode=cfg.get(
            'display_mode',
            'hybrid',
        ),

        sub_animation=cfg.get(
            'animation',
            'balanced',
        ),

        sub_background=cfg.get(
            'background',
            'aurora',
        ),

        portal_label=cfg.get(
            'portal_label',
            'Secure WireGuard portal',
        ),

        portal_icon=cfg.get(
            'portal_icon',
            'fas fa-bolt',
        ),

        portal_title=portal_title,

        portal_subtitle=cfg.get(
            'portal_subtitle',
            (
                'Your account is ready. '
                'Install WireGuard, then '
                'scan QR or import a config.'
            ),
        ),

        support_portal_label=cfg.get(
            'portal_label',
            'Secure WireGuard portal',
        ),

        support_portal_icon=cfg.get(
            'portal_icon',
            'fas fa-bolt',
        ),

        support_portal_title=(
            portal_title
        ),

        support_portal_subtitle=cfg.get(
            'portal_subtitle',
            (
                'Your account is ready. '
                'Install WireGuard, then '
                'scan QR or import a config.'
            ),
        ),

        support_telegram=socials.get(
            'telegram',
            '',
        ),

        support_whatsapp=socials.get(
            'whatsapp',
            '',
        ),

        support_instagram=socials.get(
            'instagram',
            '',
        ),

        support_phone=socials.get(
            'phone',
            '',
        ),

        support_website=socials.get(
            'website',
            '',
        ),

        support_email=socials.get(
            'email',
            '',
        ),
    )

@app.get('/s/<token>/api', endpoint='subscription_public_api')
def subscription_public_api(token):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    return jsonify(subscription=_subscription_public_payload(sub))


@app.get('/s/<token>/config', endpoint='subscription_public_config')
def subscription_public_config(token):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)

    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    mem = BytesIO()
    used_names = set()

    with zipfile.ZipFile(
        mem,
        'w',
        zipfile.ZIP_DEFLATED,
    ) as z:

        for index, link in enumerate(
            sorted(
                sub.links,
                key=lambda x: (
                    x.sort_order or 0,
                    x.id or 0,
                ),
            ),
            start=1,
        ):
            peer = getattr(link, 'peer', None)

            if not peer:
                continue

            safe_peer = re.sub(
                r'[^A-Za-z0-9_.-]+',
                '_',
                peer.name or f'peer-{peer.id}',
            ).strip('._')

            base = safe_peer or f'peer-{peer.id}'

            safe_location = re.sub(
                r'[^A-Za-z0-9_.-]+',
                '_',
                (
                    getattr(
                        link,
                        'location_label',
                        '',
                    )
                    or ''
                ),
            ).strip('._')

            if safe_location:
                candidate = (
                    f'{base}-{safe_location}'
                )
            else:
                candidate = base

            entry = f'{candidate}.conf'

            normalized = entry.lower()

            if normalized in used_names:
                entry = (
                    f'{candidate}-{index}.conf'
                )
                normalized = entry.lower()

            if normalized in used_names:
                entry = (
                    f'{base}-peer{peer.id}.conf'
                )
                normalized = entry.lower()

            suffix = 2

            while normalized in used_names:
                entry = (
                    f'{base}-peer{peer.id}-{suffix}.conf'
                )
                normalized = entry.lower()
                suffix += 1

            used_names.add(normalized)

            z.writestr(
                entry,
                _client_config_txt(peer),
            )

    mem.seek(0)

    fname = re.sub(
        r'[^A-Za-z0-9_.-]+',
        '_',
        sub.name or 'subscription',
    ).strip('._') or 'subscription'

    return send_file(
        mem,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{fname}.zip',
    )

@app.get(
    '/s/<token>/inbound/<int:link_id>/config'
)
def subscription_public_inbound_config(
    token,
    link_id,
):
    sub = (
        Subscription.query
        .filter_by(token=token)
        .first()
        or abort(404)
    )

    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    link = (
        SubscriptionPeer.query
        .filter_by(
            id=link_id,
            subscription_id=sub.id,
        )
        .first()
        or abort(404)
    )

    peer = link.peer or abort(404)

    cfg = _client_config_txt(peer)

    safe_name = re.sub(
        r'[^A-Za-z0-9_.-]+',
        '_',
        peer.name or f'peer-{peer.id}',
    ).strip('._') or f'peer-{peer.id}'

    mem = BytesIO(
        cfg.encode('utf-8')
    )

    response = send_file(
        mem,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'{safe_name}.conf',
        max_age=0,
    )

    response.headers[
        'X-Content-Type-Options'
    ] = 'nosniff'

    response.headers[
        'Cache-Control'
    ] = (
        'private, no-store, no-cache, '
        'must-revalidate, max-age=0'
    )

    return response


@app.get('/s/<token>/inbound/<int:link_id>/qr')
def subscription_public_inbound_qr(token, link_id):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)

    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
    peer = link.peer or abort(404)
    img = qrcode.make(_client_config_txt(peer))
    bio = BytesIO()
    img.save(bio, format='PNG')
    bio.seek(0)
    return send_file(bio, mimetype='image/png')


@app.get('/s/<token>/inbound/<int:link_id>/geo')
def subscription_public_inbound_geo(token, link_id):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
    peer = link.peer or abort(404)

    host = _public_host_peer(peer)
    geo = _lookup_geo(host)

    cc = (geo.get('country_code') or '').strip().upper()
    flag = geo.get('flag') or _flag_from_cc(cc)
    country = geo.get('country') or cc or ''

    changed = False

    if cc and (link.country_code or '').strip().upper() != cc:
        link.country_code = cc
        changed = True

    if flag and flag != '🌐' and (link.flag or '').strip() != flag:
        link.flag = flag
        changed = True

    if country and (link.location_label or '').strip() != country:
        link.location_label = country
        changed = True

    if changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    return jsonify(
        country=country,
        country_code=cc,
        flag=flag,
        public_host=host
    )

_start_retention()
_start_expiry_enforcer()
_start_backup_scheduler()
_node_notify_monitor()
# ========================================
# Traffic Control / WG forwarding policy
# ========================================
TRAFFIC_POLICY_FILE = os.path.join(INSTANCE_DIR, "traffic_policies.json")
TRAFFIC_GEO_DIR = os.path.join(INSTANCE_DIR, "traffic_geo")
TRAFFIC_NFT_TABLE = "wgpanel_traffic"
TRAFFIC_GEO_MAX_AGE = 86400


def _traffic_default_config():
    return {
        "enabled": True,
        "policies": [],
    }


def _traffic_load_config():
    data = _json_load(TRAFFIC_POLICY_FILE, _traffic_default_config())
    if not isinstance(data, dict):
        data = _traffic_default_config()
    policies = data.get("policies")
    if not isinstance(policies, list):
        policies = []
    return {
        "enabled": bool(data.get("enabled", True)),
        "policies": policies,
    }


def _traffic_save_config(data):
    payload = {
        "enabled": bool((data or {}).get("enabled", True)),
        "policies": list((data or {}).get("policies") or []),
    }
    _json_save(TRAFFIC_POLICY_FILE, payload)
    return payload


def _traffic_nft_capability():
    nft = shutil.which("nft")
    if not nft:
        return {
            "available": False,
            "usable": False,
            "reason": "not_installed",
            "detail": "The nft command was not found.",
        }
    try:
        result = subprocess.run(
            [nft, "list", "ruleset"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        if result.returncode == 0:
            return {
                "available": True,
                "usable": True,
                "reason": "ready",
                "detail": "nftables is available and the panel can read the ruleset.",
            }
        return {
            "available": True,
            "usable": False,
            "reason": "permission_denied",
            "detail": (result.stderr or result.stdout or "nft list ruleset failed").strip()[:500],
        }
    except Exception as exc:
        return {
            "available": True,
            "usable": False,
            "reason": "nft_error",
            "detail": str(exc),
        }


def _traffic_clean_iface(value):
    value = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value):
        raise ValueError("Invalid WireGuard interface name.")
    return value


def _traffic_host_addresses(value):
    out = []
    for raw in re.split(r"[\s,]+", str(value or "").strip()):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = ipaddress.ip_interface(raw) if "/" in raw else ipaddress.ip_address(raw)
            ip_obj = obj.ip if hasattr(obj, "ip") else obj
            text = str(ip_obj)
            if text not in out:
                out.append(text)
        except Exception:
            continue
    return out


def _traffic_normalize_destination(raw):
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        if "://" in raw:
            host = urlparse(raw).hostname or ""
        else:
            host = raw.split("/", 1)[0]
            if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
                host = host.rsplit(":", 1)[0]
        host = host.strip().strip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        if not host or len(host) > 253:
            return None
        if not re.fullmatch(r"[a-z0-9._-]+", host):
            return None
        return host
    except Exception:
        return None


def _traffic_resolve_domains(domains):
    v4, v6, warnings = set(), set(), []
    resolved = {}
    for raw in list(domains or []):
        host = _traffic_normalize_destination(raw)
        if not host:
            warnings.append(f"Invalid domain: {raw}")
            continue
        found = []
        try:
            for family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                candidate = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                except Exception:
                    continue
                if ip_obj.version == 4:
                    v4.add(str(ip_obj))
                else:
                    v6.add(str(ip_obj))
                if str(ip_obj) not in found:
                    found.append(str(ip_obj))
        except Exception as exc:
            warnings.append(f"Could not resolve {host}: {exc}")
        resolved[host] = found
    return v4, v6, resolved, warnings


def _traffic_parse_cidrs(values):
    v4, v6, warnings = set(), set(), []
    for raw in list(values or []):
        raw = str(raw or "").strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                ip_obj = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(f"{ip_obj}/{32 if ip_obj.version == 4 else 128}", strict=False)
            (v4 if net.version == 4 else v6).add(str(net))
        except Exception:
            warnings.append(f"Invalid IP/CIDR: {raw}")
    return v4, v6, warnings


def _traffic_geo_cache_path(country, version):
    os.makedirs(TRAFFIC_GEO_DIR, exist_ok=True)
    return os.path.join(TRAFFIC_GEO_DIR, f"{country.lower()}-v{version}.zone")


def _traffic_geo_url(country, version):
    cc = country.lower()
    if version == 4:
        return f"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
    return f"https://www.ipdeny.com/ipv6/ipaddresses/blocks/{cc}.zone"


def _traffic_geo_networks(country, version, *, force=False):
    cc = str(country or "").strip().lower()
    if not re.fullmatch(r"[a-z]{2}", cc):
        raise ValueError(f"Invalid country code: {country}")
    path = _traffic_geo_cache_path(cc, version)
    fresh = False
    try:
        fresh = os.path.isfile(path) and (time.time() - os.path.getmtime(path) < TRAFFIC_GEO_MAX_AGE)
    except Exception:
        fresh = False
    if force or not fresh:
        try:
            response = requests.get(_traffic_geo_url(cc, version), timeout=12)
            response.raise_for_status()
            text_body = response.text
            valid = []
            for line in text_body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.version == version:
                        valid.append(str(net))
                except Exception:
                    continue
            if not valid:
                raise ValueError("Downloaded country list was empty or invalid.")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write("\n".join(valid) + "\n")
            os.replace(tmp, path)
        except Exception:
            if not os.path.isfile(path):
                raise
    networks = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.version == version:
                    networks.append(str(net))
            except Exception:
                continue
    return networks


def _traffic_set_elements(values):
    return ", ".join(sorted(set(values)))


def _traffic_apply_local(policies):
    capability = _traffic_nft_capability()
    if not capability.get("usable"):
        raise RuntimeError(
            capability.get("detail")
            or "nftables is unavailable"
        )

    nft = shutil.which("nft")
    if not nft:
        raise RuntimeError("The nft command was not found.")

    active = [
        p for p in list(policies or [])
        if isinstance(p, dict)
        and p.get("enabled", True)
    ]

    warnings = []
    domain_map = {}
    country_sets = {}
    policy_data = []

    for p in active:
        pid = str(
            p.get("id")
            or secrets.token_hex(6)
        )[:32]

        iface = _traffic_clean_iface(
            p.get("interface")
        )

        source_mode = str(
            p.get("source_mode")
            or "interface"
        )

        source_ips = (
            _traffic_host_addresses(
                p.get("source_ip")
            )
            if source_mode == "peer"
            else []
        )

        cidr4, cidr6, cidr_warn = (
            _traffic_parse_cidrs(
                p.get("cidrs") or []
            )
        )

        dom4, dom6, resolved, dom_warn = (
            _traffic_resolve_domains(
                p.get("domains") or []
            )
        )

        warnings.extend([
            f"{p.get('name') or pid}: {warning}"
            for warning in (
                cidr_warn + dom_warn
            )
        ])

        domain_map[pid] = resolved

        direct4 = set(cidr4) | set(dom4)
        direct6 = set(cidr6) | set(dom6)

        countries = []

        for raw_cc in list(
            p.get("countries") or []
        ):
            cc = str(
                raw_cc or ""
            ).strip().lower()

            if not re.fullmatch(
                r"[a-z]{2}",
                cc,
            ):
                warnings.append(
                    f"{p.get('name') or pid}: "
                    f"invalid country code {raw_cc}"
                )
                continue

            countries.append(cc)

            if cc not in country_sets:
                try:
                    country_sets[cc] = {
                        4: _traffic_geo_networks(
                            cc,
                            4,
                        ),
                        6: _traffic_geo_networks(
                            cc,
                            6,
                        ),
                    }

                except Exception as exc:
                    warnings.append(
                        f"Country {cc.upper()}: {exc}"
                    )
                    country_sets[cc] = {
                        4: [],
                        6: [],
                    }

        policy_data.append({
            "id": pid,
            "name": str(
                p.get("name")
                or "Traffic policy"
            ),
            "interface": iface,
            "source_mode": source_mode,
            "source_ips": source_ips,
            "direct4": sorted(direct4),
            "direct6": sorted(direct6),
            "countries": countries,
        })

    set_lines = []
    rule_lines = []

    for cc, versions in sorted(
        country_sets.items()
    ):
        for version, values in (
            (4, versions.get(4) or []),
            (6, versions.get(6) or []),
        ):
            if not values:
                continue

            nft_type = (
                "ipv4_addr"
                if version == 4
                else "ipv6_addr"
            )

            set_name = (
                f"geo_{cc}_v{version}"
            )

            set_lines.append(
                f"  set {set_name} {{ "
                f"type {nft_type}; "
                "flags interval; auto-merge; "
                "elements = { "
                f"{_traffic_set_elements(values)}"
                " } }"
            )

    for row in policy_data:
        safe_id = (
            re.sub(
                r"[^A-Za-z0-9_]",
                "",
                row["id"],
            )[:18]
            or secrets.token_hex(4)
        )

        for version, values in (
            (4, row["direct4"]),
            (6, row["direct6"]),
        ):
            if not values:
                continue

            nft_type = (
                "ipv4_addr"
                if version == 4
                else "ipv6_addr"
            )

            set_name = (
                f"p_{safe_id}_v{version}"
            )

            set_lines.append(
                f"  set {set_name} {{ "
                f"type {nft_type}; "
                "flags interval; auto-merge; "
                "elements = { "
                f"{_traffic_set_elements(values)}"
                " } }"
            )

        source_by_version = {
            4: [],
            6: [],
        }

        for src in row["source_ips"]:
            try:
                version = (
                    ipaddress.ip_address(src)
                    .version
                )
                source_by_version[
                    version
                ].append(src)
            except Exception:
                pass

        for version in (4, 6):
            family = (
                "ip"
                if version == 4
                else "ip6"
            )

            source_clause = ""

            if row["source_mode"] == "peer":
                sources = (
                    source_by_version[
                        version
                    ]
                )

                if not sources:
                    warnings.append(
                        f"{row['name']}: no IPv{version} "
                        "peer address, so IPv"
                        f"{version} peer-scoped blocking "
                        "was skipped"
                    )
                    continue

                if len(sources) == 1:
                    source_clause = (
                        f" {family} saddr "
                        f"{sources[0]}"
                    )
                else:
                    source_clause = (
                        f" {family} saddr {{ "
                        f"{', '.join(sources)} }}"
                    )

            base = (
                f'    iifname "{row["interface"]}"'
                f"{source_clause}"
            )

            direct = row[
                f"direct{version}"
            ]

            if direct:
                set_name = (
                    f"p_{safe_id}_v{version}"
                )

                rule_lines.append(
                    f"{base} {family} daddr "
                    f"@{set_name} counter drop "
                    f'comment "wgpanel:{row["id"]}:'
                    f'direct:v{version}"'
                )

            for cc in row["countries"]:
                if not (
                    country_sets
                    .get(cc, {})
                    .get(version)
                ):
                    continue

                rule_lines.append(
                    f"{base} {family} daddr "
                    f"@geo_{cc}_v{version} "
                    "counter drop "
                    f'comment "wgpanel:{row["id"]}:'
                    f'geo:{cc}:v{version}"'
                )

    table_exists = (
        subprocess.run(
            [
                nft,
                "list",
                "table",
                "inet",
                TRAFFIC_NFT_TABLE,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        ).returncode
        == 0
    )

    lines = []

    if table_exists:
        lines.append(
            f"delete table inet "
            f"{TRAFFIC_NFT_TABLE}"
        )

    lines.append(
        f"table inet {TRAFFIC_NFT_TABLE} {{"
    )

    lines.extend(set_lines)

    lines.extend([
        "  chain forward {",
        (
            "    type filter hook forward "
            "priority -10; policy accept;"
        ),
    ])

    lines.extend(rule_lines)

    lines.extend([
        "  }",
        "}",
    ])

    script = "\n".join(lines) + "\n"

    result = subprocess.run(
        [nft, "-f", "-"],
        input=script,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        detail = (
            result.stderr
            or result.stdout
            or "nftables apply failed"
        ).strip()

        raise RuntimeError(detail)

    return {
        "ok": True,
        "policies": len(policy_data),
        "rules": len(rule_lines),
        "warnings": warnings,
        "resolved_domains": domain_map,
    }


def _traffic_local_status():
    capability = _traffic_nft_capability()
    result = {
        "capability": capability,
        "loaded": False,
        "counters": {},
    }
    if not capability.get("usable"):
        return result
    nft = shutil.which("nft")
    proc = subprocess.run(
        [nft, "list", "table", "inet", TRAFFIC_NFT_TABLE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )
    if proc.returncode != 0:
        return result
    result["loaded"] = True
    text_body = proc.stdout or ""
    for line in text_body.splitlines():
        m_comment = re.search(r'comment\s+"wgpanel:([^\"]+)"', line)
        m_counter = re.search(r'counter packets\s+(\d+)\s+bytes\s+(\d+)', line)
        if m_comment and m_counter:
            key = m_comment.group(1)
            result["counters"][key] = {
                "packets": int(m_counter.group(1)),
                "bytes": int(m_counter.group(2)),
            }
    return result


def _traffic_targets_payload():
    interfaces = []
    for iface in InterfaceConfig.query.order_by(InterfaceConfig.node_id.asc().nullsfirst(), InterfaceConfig.name.asc()).all():
        peers = []
        for peer in Peer.query.filter(Peer.iface_id == iface.id).order_by(Peer.name.asc()).all():
            peers.append({
                "id": peer.id,
                "name": peer.name,
                "address": peer.address,
                "public_key": peer.public_key,
            })
        interfaces.append({
            "id": iface.id,
            "name": iface.name,
            "address": iface.address,
            "node_id": iface.node_id,
            "node_name": iface.node.name if iface.node else "Local panel",
            "location": "node" if iface.node_id else "local",
            "peers": peers,
        })
    return interfaces


def _traffic_normalize_policy(data):
    data = data or {}
    policy_id = str(data.get("id") or secrets.token_hex(8)).strip()[:32]
    name = str(data.get("name") or "Traffic policy").strip()[:80]
    location = str(data.get("location") or "local").strip().lower()
    if location not in {"local", "node"}:
        raise ValueError("location must be local or node")
    node_id = int(data.get("node_id") or 0) or None
    iface = _traffic_clean_iface(data.get("interface"))
    source_mode = str(data.get("source_mode") or "interface").strip().lower()
    if source_mode not in {"interface", "peer"}:
        raise ValueError("source_mode must be interface or peer")
    source_ip = str(data.get("source_ip") or "").strip()
    if source_mode == "peer" and not _traffic_host_addresses(source_ip):
        raise ValueError("A peer/source address is required for peer scope.")

    def clean_list(key, max_items=100):
        raw = data.get(key) or []
        if isinstance(raw, str):
            raw = re.split(r"[\n,]+", raw)
        return [str(x).strip() for x in list(raw) if str(x).strip()][:max_items]

    return {
        "id": policy_id,
        "name": name,
        "enabled": bool(data.get("enabled", True)),
        "location": location,
        "node_id": node_id if location == "node" else None,
        "interface": iface,
        "source_mode": source_mode,
        "source_ip": source_ip if source_mode == "peer" else "",
        "domains": clean_list("domains", 100),
        "cidrs": clean_list("cidrs", 200),
        "countries": [x.upper() for x in clean_list("countries", 50)],
    }


@app.get("/api/traffic-control")
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

@app.post("/api/traffic-control")
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


@app.post("/api/traffic-control/apply")
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

@app.get("/api/traffic-control/status")
@login_required
def traffic_control_status():
    return jsonify(ok=True, **_traffic_local_status())

def _traffic_nft_set_text(set_name):
    nft = shutil.which("nft")
    if not nft:
        return ""
    proc = subprocess.run(
        [nft, "list", "set", "inet", TRAFFIC_NFT_TABLE, str(set_name)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def _traffic_test_policy_local(policy):
    policy = dict(policy or {})
    pid = str(policy.get("id") or "").strip()
    name = str(policy.get("name") or "Traffic policy").strip()
    iface = _traffic_clean_iface(policy.get("interface"))
    source_mode = str(policy.get("source_mode") or "interface").strip().lower()
    source_ips = _traffic_host_addresses(policy.get("source_ip")) if source_mode == "peer" else []
    checks = []

    def add(key, label, status, detail):
        checks.append({
            "key": key,
            "label": label,
            "status": status,
            "detail": str(detail or ""),
        })

    capability = _traffic_nft_capability()
    if not capability.get("usable"):
        add("nftables", "nftables engine", "fail", capability.get("detail") or "nftables is unavailable.")
        return {
            "ok": False,
            "policy_id": pid,
            "policy_name": name,
            "checks": checks,
            "counters": {"packets": 0, "bytes": 0},
        }

    nft = shutil.which("nft")
    table_proc = subprocess.run(
        [nft, "list", "table", "inet", TRAFFIC_NFT_TABLE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )
    table_text = table_proc.stdout or ""
    if table_proc.returncode != 0:
        add("table", "Live policy table", "fail", "inet wgpanel_traffic is not loaded. Re-apply the policy rules.")
        return {
            "ok": False,
            "policy_id": pid,
            "policy_name": name,
            "checks": checks,
            "counters": {"packets": 0, "bytes": 0},
        }
    add("table", "Live policy table", "pass", "inet wgpanel_traffic is loaded in the kernel.")

    iface_proc = subprocess.run(
        ["wg", "show", iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    add(
        "interface",
        "WireGuard interface",
        "pass" if iface_proc.returncode == 0 else "fail",
        f"{iface} is active." if iface_proc.returncode == 0 else f"{iface} is not active in the WireGuard runtime.",
    )

    versions = {4, 6}
    if source_mode == "peer":
        versions = set()
        for src in source_ips:
            try:
                versions.add(ipaddress.ip_address(src).version)
            except Exception:
                pass
        if source_ips:
            add("scope", "Peer source scope", "pass", f"Live policy is expected to match only {', '.join(source_ips)} on {iface}.")
        else:
            add("scope", "Peer source scope", "fail", "The policy has no usable peer/source address.")

    safe_id = re.sub(r"[^A-Za-z0-9_]", "", pid)[:18]
    configured_domains = list(policy.get("domains") or [])
    configured_cidrs = list(policy.get("cidrs") or [])
    configured_countries = [str(x or "").strip().lower() for x in list(policy.get("countries") or []) if str(x or "").strip()]

    def rule_line(comment):
        marker = f'comment "{comment}"'
        for line in table_text.splitlines():
            if marker in line:
                return line.strip()
        return ""

    def scope_matches(line, version):
        if not line or f'iifname "{iface}"' not in line:
            return False
        if source_mode != "peer":
            return True
        family = "ip" if version == 4 else "ip6"
        candidates = [s for s in source_ips if ipaddress.ip_address(s).version == version]
        return bool(candidates) and all((f"{family} saddr {s}" in line) or (s in line and f"{family} saddr" in line) for s in candidates)

    direct_needed = bool(configured_domains or configured_cidrs)
    for version in (4, 6):
        if version not in versions:
            if direct_needed:
                add(f"direct_v{version}", f"IPv{version} direct rule", "info", f"Skipped because this peer has no IPv{version} WireGuard source address.")
            continue
        if not direct_needed:
            continue
        comment = f"wgpanel:{pid}:direct:v{version}"
        line = rule_line(comment)
        set_name = f"p_{safe_id}_v{version}"
        set_text = _traffic_nft_set_text(set_name)
        if line and scope_matches(line, version) and set_text:
            add(f"direct_v{version}", f"IPv{version} domain/IP rule", "pass", f"DROP rule and @{set_name} are loaded with the expected {iface} scope.")
        else:
            add(f"direct_v{version}", f"IPv{version} domain/IP rule", "fail", "The expected live DROP rule or destination set is missing. Save & apply again.")

    if configured_domains:
        dom4, dom6, resolved, warnings = _traffic_resolve_domains(configured_domains)
        for warning in warnings:
            add("domain_dns", "Domain resolution", "warn", warning)
        for version, values in ((4, sorted(dom4)), (6, sorted(dom6))):
            if version not in versions:
                continue
            if not values:
                continue
            set_name = f"p_{safe_id}_v{version}"
            set_text = _traffic_nft_set_text(set_name)
            present = [ip for ip in values if ip in set_text]
            missing = [ip for ip in values if ip not in set_text]
            if present and not missing:
                add(f"domain_v{version}", f"IPv{version} domain addresses", "pass", f"Current DNS addresses are present in the live set: {', '.join(present[:4])}{'…' if len(present) > 4 else ''}")
            elif present:
                add(f"domain_v{version}", f"IPv{version} domain addresses", "warn", f"DNS changed partially. {len(present)} current address(es) are loaded and {len(missing)} are not. Re-apply the policy.")
            else:
                add(f"domain_v{version}", f"IPv{version} domain addresses", "fail", "Current DNS addresses are not in the live set. The domain changed since the last apply; refresh the live policy rules.")

    for cc in configured_countries:
        if not re.fullmatch(r"[a-z]{2}", cc):
            add(f"geo_{cc}", "Geo country", "fail", f"Invalid country code: {cc}")
            continue
        for version in (4, 6):
            if version not in versions:
                continue
            set_name = f"geo_{cc}_v{version}"
            set_text = _traffic_nft_set_text(set_name)
            comment = f"wgpanel:{pid}:geo:{cc}:v{version}"
            line = rule_line(comment)
            if set_text and line and scope_matches(line, version):
                add(f"geo_{cc}_v{version}", f"{cc.upper()} Geo IPv{version}", "pass", f"@{set_name} and its scoped DROP rule are loaded.")
            else:
                add(f"geo_{cc}_v{version}", f"{cc.upper()} Geo IPv{version}", "fail", "The country set or its scoped DROP rule is missing.")

    status = _traffic_local_status()
    packets = 0
    byte_count = 0
    for key, counter in (status.get("counters") or {}).items():
        if str(key).startswith(pid + ":"):
            packets += int((counter or {}).get("packets") or 0)
            byte_count += int((counter or {}).get("bytes") or 0)
    add(
        "counters",
        "Live hit counters",
        "pass" if packets > 0 else "info",
        f"This policy has blocked {packets} packet(s) / {byte_count} byte(s)." if packets > 0 else "Rules are loaded but no real forwarded packet has matched them yet.",
    )

    if not (configured_domains or configured_cidrs or configured_countries):
        add("destinations", "Policy destinations", "fail", "The policy has no domains, IP/CIDR entries, or countries to block.")

    overall = not any(row.get("status") == "fail" for row in checks)
    return {
        "ok": overall,
        "policy_id": pid,
        "policy_name": name,
        "checks": checks,
        "counters": {"packets": packets, "bytes": byte_count},
    }


@app.post("/api/traffic-control/test")
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

def _traffic_live_set_contains(set_name, address):
    """
    Return True when *address* is covered by a live nftables set.

    Exact addresses are checked directly through nftables first.
    The fallback parser handles CIDRs / interval Geo sets and works
    with both one-line and multiline `nft list set` output.
    """
    try:
        wanted = ipaddress.ip_address(
            str(address or '').strip()
        )
    except Exception:
        return False

    clean_set_name = str(
        set_name or ''
    ).strip()

    if not re.fullmatch(
        r'[A-Za-z0-9_.:-]{1,128}',
        clean_set_name,
    ):
        return False

    nft = shutil.which("nft")

    if nft:
        try:
            script = (
                f"get element inet "
                f"{TRAFFIC_NFT_TABLE} "
                f"{clean_set_name} "
                f"{{ {wanted} }}\n"
            )

            result = subprocess.run(
                [nft, "-f", "-"],
                input=script,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=8,
                check=False,
            )

            if result.returncode == 0:
                return True

        except Exception:
            pass

    text_body = _traffic_nft_set_text(
        clean_set_name
    )

    if not text_body:
        return False

    match = re.search(
        r'elements\s*=\s*\{(.*?)\}',
        text_body,
        re.S,
    )

    if not match:
        return False

    for raw_token in match.group(1).split(','):
        token = ' '.join(
            raw_token.strip().split()
        )

        if not token:
            continue

        try:
            if (
                '-' in token
                and '/' not in token
            ):
                first, last = [
                    part.strip()
                    for part in token.split(
                        '-',
                        1,
                    )
                ]

                start_ip = ipaddress.ip_address(
                    first
                )
                end_ip = ipaddress.ip_address(
                    last
                )

                if (
                    start_ip.version
                    == wanted.version
                    and int(start_ip)
                    <= int(wanted)
                    <= int(end_ip)
                ):
                    return True

                continue

            if '/' in token:
                network = ipaddress.ip_network(
                    token,
                    strict=False,
                )

                if (
                    network.version
                    == wanted.version
                    and wanted in network
                ):
                    return True

                continue

            if (
                ipaddress.ip_address(token)
                == wanted
            ):
                return True

        except Exception:
            continue

    return False


def _traffic_manual_target_addresses(target):
    raw = str(target or '').strip()
    if not raw:
        raise ValueError('Enter a domain, URL, IPv4 or IPv6 address.')

    candidate = raw.strip('[]')
    try:
        return raw, '', [str(ipaddress.ip_address(candidate))]
    except Exception:
        pass

    host = _traffic_normalize_destination(raw)
    if not host:
        raise ValueError('The destination is not a valid domain, URL, IPv4 or IPv6 address.')

    found = []
    try:
        for _family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
            if not sockaddr:
                continue
            try:
                value = str(ipaddress.ip_address(sockaddr[0]))
            except Exception:
                continue
            if value not in found:
                found.append(value)
    except Exception as exc:
        raise ValueError(f'Could not resolve {host}: {exc}') from exc

    if not found:
        raise ValueError(f'{host} did not resolve to a usable IP address.')

    return raw, host, found


def _traffic_manual_test_local(policy, target):
    policy = dict(policy or {})
    pid = str(policy.get('id') or '').strip()
    iface = _traffic_clean_iface(policy.get('interface'))
    source_mode = str(policy.get('source_mode') or 'interface').strip().lower()
    source_ips = _traffic_host_addresses(policy.get('source_ip')) if source_mode == 'peer' else []

    capability = _traffic_nft_capability()
    if not capability.get('usable'):
        raise RuntimeError(capability.get('detail') or 'nftables is unavailable.')

    nft = shutil.which('nft')
    table_proc = subprocess.run(
        [nft, 'list', 'table', 'inet', TRAFFIC_NFT_TABLE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
        check=False,
    )
    if table_proc.returncode != 0:
        raise RuntimeError('inet wgpanel_traffic is not loaded. Re-apply the policy rules.')
    table_text = table_proc.stdout or ''

    original_target, hostname, addresses = _traffic_manual_target_addresses(target)
    safe_id = re.sub(r'[^A-Za-z0-9_]', '', pid)[:18]
    countries = [
        str(value or '').strip().lower()
        for value in list(policy.get('countries') or [])
        if re.fullmatch(r'[A-Za-z]{2}', str(value or '').strip())
    ]

    source_versions = {4, 6}
    if source_mode == 'peer':
        source_versions = set()
        for source in source_ips:
            try:
                source_versions.add(ipaddress.ip_address(source).version)
            except Exception:
                pass

    def rule_line(comment):
        marker = f'comment "{comment}"'
        for line in table_text.splitlines():
            if marker in line:
                return line.strip()
        return ''

    def scoped_rule_exists(comment, version):
        line = rule_line(comment)
        if not line or f'iifname "{iface}"' not in line:
            return False
        if source_mode != 'peer':
            return True
        family = 'ip' if version == 4 else 'ip6'
        candidates = []
        for source in source_ips:
            try:
                if ipaddress.ip_address(source).version == version:
                    candidates.append(source)
            except Exception:
                pass
        return bool(candidates) and all(source in line and f'{family} saddr' in line for source in candidates)

    results = []
    for address in addresses:
        ip_obj = ipaddress.ip_address(address)
        version = ip_obj.version
        applicable = version in source_versions
        matches = []

        if applicable:
            direct_set = f'p_{safe_id}_v{version}'
            direct_comment = f'wgpanel:{pid}:direct:v{version}'
            if (
                _traffic_live_set_contains(direct_set, address)
                and scoped_rule_exists(direct_comment, version)
            ):
                matches.append({
                    'kind': 'direct',
                    'label': 'Domain/IP set',
                    'set': direct_set,
                    'comment': direct_comment,
                })

            for cc in countries:
                geo_set = f'geo_{cc}_v{version}'
                geo_comment = f'wgpanel:{pid}:geo:{cc}:v{version}'
                if (
                    _traffic_live_set_contains(geo_set, address)
                    and scoped_rule_exists(geo_comment, version)
                ):
                    matches.append({
                        'kind': 'geo',
                        'label': f'Geo {cc.upper()}',
                        'set': geo_set,
                        'comment': geo_comment,
                    })

        results.append({
            'ip': address,
            'version': version,
            'applicable': applicable,
            'blocked': bool(applicable and matches),
            'matches': matches,
            'note': (
                '' if applicable
                else f'This peer has no IPv{version} WireGuard source address.'
            ),
        })

    applicable_rows = [row for row in results if row.get('applicable')]
    blocked_rows = [row for row in applicable_rows if row.get('blocked')]

    if not applicable_rows:
        verdict = 'not_applicable'
    elif len(blocked_rows) == len(applicable_rows):
        verdict = 'blocked'
    elif blocked_rows:
        verdict = 'partial'
    else:
        verdict = 'not_blocked'

    scope = (
        f'{iface} · peer source {", ".join(source_ips)}'
        if source_mode == 'peer'
        else f'{iface} · entire interface'
    )

    return {
        'ok': True,
        'policy_id': pid,
        'policy_name': str(policy.get('name') or 'Traffic policy'),
        'target': original_target,
        'hostname': hostname,
        'resolved': addresses,
        'verdict': verdict,
        'scope': scope,
        'results': results,
        'note': (
            'This evaluates the live nftables sets and exact scoped DROP rules. '
            'It does not generate traffic as the WireGuard peer.'
        ),
    }


@app.post('/api/traffic-control/test-destination')
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
    except SchemaMigrationError as e:
        app.logger.critical(
            "Refusing to start: the database schema could not be migrated: %s", e
        )
        raise SystemExit(1)
    except Exception as e:
        app.logger.exception("bootstrap failed: %s", e)

    _Guni(app, options).run()


