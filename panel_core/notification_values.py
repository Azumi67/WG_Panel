from datetime import datetime, timezone
import re


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
