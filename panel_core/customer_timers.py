import time
from datetime import datetime, timezone


def now_ts() -> int:
    return int(time.time())


def to_ts(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    if not isinstance(value, datetime):
        return None


    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return int(value.timestamp())


def from_ts(ts):
    if ts is None:
        return None

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
    try:
        days = float(getattr(record, 'time_limit_days', 0) or 0)
    except (TypeError, ValueError, OverflowError):
        return None
    return days if days > 0 else None


def _timer_anchor_ts(record):
    if bool(getattr(record, 'start_on_first_use', False)):
        return to_ts(getattr(record, 'first_used_at', None))

    return (
        to_ts(getattr(record, 'timer_started_at', None))
        or to_ts(getattr(record, 'created_at', None))
    )


def _effective_expiry_ts(record):
    if bool(getattr(record, 'unlimited', False)):
        return None

    days = _timer_duration_days(record)
    anchor_ts = _timer_anchor_ts(record)
    if not days or not anchor_ts:
        return None

    return add_days_ts(anchor_ts, days)


def _sync_effective_expiry(record):
    expected_ts = _effective_expiry_ts(record)
    current_ts = to_ts(getattr(record, 'expires_at', None))
    if current_ts == expected_ts:
        return False

    record.expires_at = from_ts(expected_ts)
    return True


def _start_timer_cycle(record, anchor_ts=None):
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


def _conv_time_limit(payload):
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
