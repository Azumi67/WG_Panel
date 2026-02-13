from functools import wraps
from flask import request, jsonify, current_app, abort
from flask_login import current_user
import hmac

def admin_required(fn):
    @wraps(fn)
    def _w(*a, **kw):
        if not current_user.is_authenticated:
            abort(401)
        is_admin = getattr(current_user, 'is_admin', False) or getattr(current_user, 'is_superuser', False)
        if not is_admin:
            abort(403)
        return fn(*a, **kw)
    return _w

def require_api_key_or_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if getattr(current_user, "is_authenticated", False):
            return fn(*args, **kwargs)

        want = (current_app.config.get("API_KEY") or "").strip()
        if not want:
            return jsonify({"error": "Unauthorized"}), 401

        # Accept API key ONLY via headers (prevents leakage in logs/referrers/history)
        auth = (request.headers.get("Authorization") or "").strip()
        bearer = ""
        if auth.lower().startswith("bearer "):
            bearer = auth.split(None, 1)[1].strip() if len(auth.split(None, 1)) == 2 else ""

        xhdr = (request.headers.get("X-API-KEY") or "").strip()

        supplied = bearer or xhdr
        if supplied and hmac.compare_digest(supplied, want):
            return fn(*args, **kwargs)

        return jsonify({"error": "Unauthorized"}), 401
    return wrapper


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(current_user, "is_authenticated", False):
            return f(*args, **kwargs)

        want = (current_app.config.get("API_KEY") or "").strip()
        if not want:
            return jsonify({'error': 'Unauthorized'}), 401

        auth = (request.headers.get('Authorization') or '').strip()
        bearer = auth.split(None, 1)[1].strip() if auth.startswith('Bearer ') else ''
        xhdr = (request.headers.get('X-API-KEY') or '').strip()

        supplied = bearer or xhdr
        if supplied and hmac.compare_digest(supplied, want):
            return f(*args, **kwargs)

        return jsonify({'error': 'Unauthorized'}), 401
    return decorated
