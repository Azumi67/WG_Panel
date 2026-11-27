from datetime import datetime, timezone
import re


def _app_log_timestamp_utc(value: str) -> str:
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
