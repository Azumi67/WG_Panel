
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import os
import re

NAMES = {"reseller": "reseller-telegram-runtime.log", "shop": "plan-shop-telegram-runtime.log"}
MAX_BYTES = 4 * 1024 * 1024
RETAIN_BYTES = 2 * 1024 * 1024


def log_path(instance_path, stream):
    if stream not in NAMES:
        raise ValueError("Unknown bot log stream")
    return Path(instance_path) / NAMES[stream]


def _safe_word(value):

    return re.sub(r"[^A-Za-z0-9_-]", "_", str(value))[:48]


def record(instance_path, stream, level, event, *, account_id=None, update_id=None, kind=None, error=None):
    if stream not in NAMES or level not in ("INFO", "WARNING", "ERROR"):
        raise ValueError("Unknown bot log stream or level")
    parts = [_safe_word(event)]
    if account_id is not None:
        parts.append("account=" + str(int(account_id)))
    if update_id is not None:
        parts.append("update=" + str(int(update_id)))
    if kind is not None:
        parts.append("action=" + _safe_word(kind))
    if error is not None:

        parts.append("error=" + _safe_word(error if isinstance(error, str) else type(error).__name__))
        tb = getattr(error, '__traceback__', None)
        if tb is not None:
            frames = []
            while tb is not None:
                frame = tb.tb_frame
                if 'reseller_portal' in Path(frame.f_code.co_filename).parts:
                    frames.append((Path(frame.f_code.co_filename).stem, frame.f_code.co_name, tb.tb_lineno))
                tb = tb.tb_next
            if frames:
                module, function, lineno = frames[-1]
                parts.append('at=' + _safe_word(module) + '.' + _safe_word(function) + ':' + str(lineno))
        original = getattr(error, 'orig', error)
        state = getattr(original, 'sqlstate', None) or getattr(original, 'pgcode', None)
        if isinstance(state, str) and re.fullmatch(r'[0-9A-Z]{5}', state):
            parts.append('sqlstate=' + state)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    line = (ts + " [" + level + "] " + stream + "-bot: " + " ".join(parts) + "\n").encode("utf-8")
    path = log_path(instance_path, stream)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(fd, "r+b", buffering=0) as file:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX)
            length = os.fstat(file.fileno()).st_size
            if length + len(line) > MAX_BYTES:

                file.seek(max(0, length - RETAIN_BYTES))
                tail = file.read()
                if length > RETAIN_BYTES and b"\n" in tail:
                    tail = tail.split(b"\n", 1)[1]
                file.seek(0)
                file.truncate(0)
                file.write(tail)
            file.seek(0, os.SEEK_END)
            file.write(line)
    except Exception:

        pass


def event(stream, level, action, *, account_id=None, update_id=None, kind=None, error=None):
    try:
        from flask import current_app
        record(current_app.instance_path, stream, level, action, account_id=account_id,
               update_id=update_id, kind=kind, error=error)
    except Exception:
        pass
