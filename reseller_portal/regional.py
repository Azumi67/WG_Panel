
from datetime import datetime,timezone
from flask import g, has_request_context
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

def zone_name():
    from . import HOST
    if has_request_context() and hasattr(g, '_rp_zone'):
        return g._rp_zone
    try:
        name=HOST['_panel_timezone_name']()
        ZoneInfo(name)
    except (KeyError,TypeError,ValueError,ZoneInfoNotFoundError):
        name='UTC'
    if has_request_context():
        g._rp_zone=name
    return name

def display(value):
    if not value:return '—'
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00')) if isinstance(value,str) else value
        if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
        name=zone_name()
        return parsed.astimezone(ZoneInfo(name)).strftime('%Y-%m-%d %H:%M')+' '+name
    except (TypeError,ValueError,AttributeError):return 'Unavailable'


def parse(value):
    if not value:return None
    try:
        result=datetime.fromisoformat(value.replace('Z','+00:00')) if isinstance(value,str) else value
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (TypeError,ValueError,AttributeError):return None

def human(value, reference=None):
    parsed=parse(value)
    if not parsed:return '—'
    zone=ZoneInfo(zone_name());local=parsed.astimezone(zone)
    today=(reference or datetime.now(timezone.utc)).astimezone(zone).date()
    delta=(local.date()-today).days
    label={0:'Today',-1:'Yesterday',1:'Tomorrow'}.get(delta)
    return (label or local.strftime('%d %b %Y').lstrip('0'))+', '+local.strftime('%H:%M')

def time_html(value):
    from markupsafe import Markup,escape
    parsed=parse(value)
    if not parsed:return '—'
    iso=parsed.astimezone(timezone.utc).isoformat()
    return Markup('<time data-rp-time datetime="{}" title="{}">{}</time>').format(escape(iso),escape(display(value)),escape(human(value)))
