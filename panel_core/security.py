"""Authentication helpers that do not depend on Flask application state."""
from __future__ import annotations
import hashlib
import secrets
import string


def hash_recovery(code: str) -> str:
    return "sha256$" + hashlib.sha256(code.encode("utf-8")).hexdigest()


def verify_recovery(code: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("sha256$"):
        return secrets.compare_digest(stored, hash_recovery(code))
    try:
        import bcrypt as pybcrypt
        if stored.startswith("$2") or stored.startswith("$bcrypt$"):
            return pybcrypt.checkpw(code.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        pass
    return False


def generate_recovery_codes(n: int = 10, length: int = 10) -> list[str]:
    alphabet = string.ascii_uppercase + string.digits
    return ["".join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]
