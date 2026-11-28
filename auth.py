from functools import wraps
from flask import request, jsonify, current_app, abort
from flask_login import current_user
from panel_core.auth_security import match_secret


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not (getattr(current_user, 'is_admin', False) or getattr(current_user, 'is_superuser', False)):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def require_api_key_or_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            if not (getattr(current_user, 'is_admin', False) or getattr(current_user, 'is_superuser', False)):
                abort(403)
            return fn(*args, **kwargs)
        want = (current_app.config.get('API_KEY') or '').strip()
        auth = (request.headers.get('Authorization') or '').strip().split(None, 1)
        bearer = auth[1].strip() if len(auth) == 2 and auth[0].lower() == 'bearer' else ''
        alternative = (request.headers.get('X-API-KEY') or '').strip()
        if bearer and alternative and not match_secret(bearer, alternative):
            return jsonify(error='Unauthorized'), 401
        if match_secret(bearer or alternative, want):
            return fn(*args, **kwargs)
        return jsonify(error='Unauthorized'), 401
    return wrapper



require_api_key = require_api_key_or_login
