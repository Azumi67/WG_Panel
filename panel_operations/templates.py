"""Validated peer presentation settings; no executable CSS or HTML is accepted."""
import json
import os
import re
import tempfile
from urllib.parse import urlsplit

DEFAULTS = dict(brand='Secure WireGuard profile', accent='indigo', theme='auto',
                show_apps=True, show_support=True, show_guide=True, animated=True, font_family='rounded', text_size='standard', density='comfortable', corners='rounded', page_width='wide', button_style='solid', background_pattern='none', primary_color='#7661ed', secondary_color='#5895ee', custom_colors=False, surface='soft', shadow='subtle', hero_align='left', icon='shield', usage_style='cards', show_status=True, show_usage=True, show_download=True, show_copy=True, show_activation=True, show_theme_toggle=True, welcome_text='', notice_text='', notice_tone='info', section_order='usage_first', show_endpoint=True, show_address=True, show_qr=True)

def validate(data, current):
    if not isinstance(data, dict):
        raise ValueError('Expected a JSON object')
    result = dict(current)
    if 'selected' in data:
        if data['selected'] not in ('default', 'compact', 'minimal', 'pro'):
            raise ValueError('Invalid template')
        result['selected'] = data['selected']
    if 'appearance' in data:
        incoming = data['appearance']
        if not isinstance(incoming, dict) or set(incoming) - set(DEFAULTS):
            raise ValueError('Invalid appearance settings')
        appearance = {**DEFAULTS, **current.get('appearance', {}), **incoming}
        if not isinstance(appearance['brand'], str) or len(appearance['brand']) > 80:
            raise ValueError('Brand must contain at most 80 characters')
        if appearance['accent'] not in ('indigo', 'teal', 'rose', 'amber'):
            raise ValueError('Invalid accent')
        if appearance['theme'] not in ('auto', 'light', 'dark'):
            raise ValueError('Invalid theme')
        for key, allowed in {'font_family': ('rounded', 'system', 'humanist'), 'text_size': ('small', 'standard', 'large'), 'density': ('compact', 'comfortable', 'airy'), 'corners': ('square', 'rounded', 'pill'), 'page_width': ('narrow', 'wide', 'full'), 'button_style': ('solid', 'outline', 'soft'), 'background_pattern': ('none', 'grid', 'dots')}.items():
            if appearance[key] not in allowed:
                raise ValueError('Invalid appearance: ' + key)
        for key in ('show_apps', 'show_support', 'show_guide', 'animated', 'show_endpoint', 'show_address', 'show_qr'):
            if type(appearance[key]) is not bool:
                raise ValueError('Visibility settings must be booleans')
        for key in ('primary_color', 'secondary_color'):
            if not isinstance(appearance[key], str) or not re.fullmatch(r'#[0-9a-fA-F]{6}', appearance[key]):
                raise ValueError('Invalid color: ' + key)
        for key in ('welcome_text', 'notice_text'):
            if not isinstance(appearance[key], str) or len(appearance[key]) > 300:
                raise ValueError('Text must contain at most 300 characters')
        for key, allowed in {'surface': ['soft', 'solid', 'outline'], 'shadow': ['none', 'subtle', 'deep'], 'hero_align': ['left', 'center'], 'icon': ['shield', 'bolt', 'globe', 'network', 'lock'], 'usage_style': ['cards', 'compact'], 'notice_tone': ['info', 'warning'], 'section_order': ['usage_first', 'config_first']}.items():
            if appearance[key] not in allowed:
                raise ValueError('Invalid appearance: ' + key)
        for key in ('custom_colors', 'show_status', 'show_usage', 'show_download', 'show_copy', 'show_activation', 'show_theme_toggle'):
            if type(appearance[key]) is not bool:
                raise ValueError('Expected boolean: ' + key)
        result['appearance'] = appearance
    if 'socials' in data:
        incoming = data['socials']
        if not isinstance(incoming, dict):
            raise ValueError('Invalid support links')
        socials = dict(current.get('socials', {}))
        for key in ('telegram', 'whatsapp', 'instagram', 'phone', 'website', 'email'):
            value = incoming.get(key, socials.get(key, ''))
            if not isinstance(value, str) or len(value) > 300 or re.search(r'[\x00-\x1f\x7f]', value):
                raise ValueError('Invalid support value: ' + key)
            value = value.strip()
            if value and (':' in value or key == 'website'):
                parsed = urlsplit(value)
                if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError('Use an http:// or https:// link for ' + key)
            socials[key] = value
        result['socials'] = socials
    return result

def atomic_save(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.template-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def preview_fonts(root):
    """Embed bundled fonts for the opaque-origin preview sandbox only."""
    import base64
    from pathlib import Path
    fonts = [('Poppins', 400, 'fonts/Poppins-Regular.woff2'),
             ('Poppins', 600, 'fonts/Poppins-SemiBold.woff2'),
             ('Poppins', 700, 'fonts/Poppins-Bold.woff2'),
             ('Font Awesome 7 Free', 900, 'vendor/fa/webfonts/fa-solid-900.woff2'),
             ('Font Awesome 7 Brands', 400, 'vendor/fa/webfonts/fa-brands-400.woff2')]
    rules = []
    for family, weight, name in fonts:
        path = Path(root)/'static'/name
        if path.is_file() and path.stat().st_size < 1024*1024:
            encoded = base64.b64encode(path.read_bytes()).decode('ascii')
            rules.append(f"@font-face{{font-family:'{family}';font-weight:{weight};font-style:normal;src:url(data:font/woff2;base64,{encoded}) format('woff2');font-display:swap}}")
    return '<style>' + ''.join(rules) + '</style>'


def prepare_preview(html, root):
    html = re.sub(r'<link\b[^>]*>', lambda m: '' if 'as="font"' in m.group(0) else m.group(0), html)
    return html.replace('</head>', preview_fonts(root) + '</head>', 1)
