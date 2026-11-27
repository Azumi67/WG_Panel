"""Peer and subscription profile persistence + API routes"""
from __future__ import annotations
import json
import os
from pathlib import Path

from flask import current_app, jsonify, request
from flask_login import login_required

_CONFIGURED_INSTANCE_PATH = None

def _instance_path():
    try:
        return current_app.instance_path
    except RuntimeError:
        if _CONFIGURED_INSTANCE_PATH:
            return _CONFIGURED_INSTANCE_PATH
        raise

PEER_PROFILE_FILE = ''
PEER_PROFILES_FILE = ''

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
    os.makedirs(_instance_path(), exist_ok=True)
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
    os.makedirs(_instance_path(), exist_ok=True)
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
    os.makedirs(_instance_path(), exist_ok=True)
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

@login_required
def list_apipeer_profiles():
    d = _load_profiles()
    names = sorted((d.get('profiles') or {}).keys())
    return jsonify(profiles=names, active=d.get('active') or 'Default')

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

@login_required
def get_apipeer_profile():
    name = (request.args.get('name') or '').strip() or None
    return jsonify(_get_profile(name))

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

SUBSCRIPTION_PROFILES_FILE = ''


def _load_subscription_profiles():

    os.makedirs(
        _instance_path(),
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
        _instance_path(),
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

def panel_default_dns():
    return _panel_default_dns()


def register_profile_routes(app):
    """Register profile APIs while preserving the legacy endpoint names."""
    global _CONFIGURED_INSTANCE_PATH, PEER_PROFILE_FILE, PEER_PROFILES_FILE, SUBSCRIPTION_PROFILES_FILE
    _CONFIGURED_INSTANCE_PATH = app.instance_path
    PEER_PROFILE_FILE = os.path.join(app.instance_path, 'peer_profile.json')
    PEER_PROFILES_FILE = os.path.join(app.instance_path, 'peer_profiles.json')
    SUBSCRIPTION_PROFILES_FILE = os.path.join(app.instance_path, 'subscription_profiles.json')

    rules = [
        ('/api/peer_profile', 'delete_apipeer_profile', delete_apipeer_profile, ['DELETE']),
        ('/api/peer_profiles', 'list_apipeer_profiles', list_apipeer_profiles, ['GET']),
        ('/api/peer_profile/rename', 'rename_apipeer_profile', rename_apipeer_profile, ['POST']),
        ('/api/peer_profile', 'get_apipeer_profile', get_apipeer_profile, ['GET']),
        ('/api/peer_profile', 'save_apipeer_profile', save_apipeer_profile, ['POST']),
        ('/api/peer_profile/activate', 'activate_apipeer_profile', activate_apipeer_profile, ['POST']),
        ('/api/subscription_profiles', 'subscription_profiles_list', subscription_profiles_list, ['GET']),
        ('/api/subscription_profiles', 'subscription_profile_save', subscription_profile_save, ['POST']),
        ('/api/subscription_profiles/<path:profile_name>', 'subscription_profile_get', subscription_profile_get, ['GET']),
        ('/api/subscription_profiles/<path:profile_name>/activate', 'subscription_profile_activate', subscription_profile_activate, ['POST']),
        ('/api/subscription_profiles/<path:profile_name>/rename', 'subscription_profile_rename', subscription_profile_rename, ['POST']),
        ('/api/subscription_profiles/<path:profile_name>', 'subscription_profile_delete', subscription_profile_delete, ['DELETE']),
    ]
    for rule, endpoint, view_func, methods in rules:
        app.add_url_rule(rule, endpoint=endpoint, view_func=view_func, methods=methods)

