

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


def _cron_field_match(
    value: int,
    expr: str,
    minimum: int,
    maximum: int,
) -> bool:
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


    if frequency == 'custom':
        fields = (
            sched.get('cron')
            or ''
        ).split()

        if len(fields) != 5:
            return None

        minute, hour, day, month, weekday = fields


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
