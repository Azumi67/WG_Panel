"""presentation profile, stored outside the application code"""
import base64
import hashlib
import json
import os
import struct
from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required
from .templates import atomic_save

profile_bp = Blueprint('account_profile', __name__)
PRESETS = ('orbit', 'mountain', 'wave', 'forest', 'sunrise', 'initials', 'astronaut', 'fox', 'robot', 'owl', 'cat', 'prism')

def validate_profile(data):
    if not isinstance(data, dict):
        raise ValueError('Expected a JSON object')
    preset = data.get('preset', 'orbit')
    if preset not in PRESETS:
        raise ValueError('Choose a valid avatar')
    image = data.get('image', '')
    if not isinstance(image, str) or len(image) > 180000:
        raise ValueError('Avatar must be smaller than 128 KiB')
    if image:
        prefix = 'data:image/png;base64,'
        if not image.startswith(prefix):
            raise ValueError('Avatar must be PNG')
        try:
            raw = base64.b64decode(image[len(prefix):], validate=True)
            if len(raw) < 33 or len(raw) > 131072 or raw[:8] != b'\x89PNG\r\n\x1a\n' or raw[12:16] != b'IHDR':
                raise ValueError()
            width, height = struct.unpack('>II', raw[16:24])
            if not (1 <= width <= 256 and 1 <= height <= 256):
                raise ValueError()
        except (ValueError, struct.error):
            raise ValueError('Invalid PNG avatar; maximum size is 256 × 256')
    return {'preset': preset, 'image': image}

@profile_bp.route('/api/account/profile', methods=['GET', 'PUT'])
@login_required
def account_profile():
    identity = hashlib.sha256(str(current_user.get_id()).encode()).hexdigest()
    path = os.path.join(current_app.instance_path, 'account_profiles', identity + '.json')
    if request.method == 'GET':
        try:
            with open(path, encoding='utf-8') as handle:
                return jsonify(validate_profile(json.load(handle)))
        except FileNotFoundError:
            return jsonify(preset='orbit', image='')
        except (ValueError, OSError):
            return jsonify(error='Profile could not be read'), 500
    if request.content_length and request.content_length > 190000:
        return jsonify(error='Avatar is too large'), 413
    try:
        data = validate_profile(request.get_json(silent=True))
    except ValueError as error:
        return jsonify(error=str(error)), 400
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    atomic_save(path, data)
    return jsonify(data)
