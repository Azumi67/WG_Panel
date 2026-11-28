import ipaddress
import re


def _http_security_int(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except Exception:
        return default

def _http_security_normalize_networks(value):
    if isinstance(value, str):
        value = re.split(r"[\r\n,]+", value)
    if not isinstance(value, list):
        value = []

    cleaned = []
    for item in value:
        raw = str(item or "").strip()
        if not raw:
            continue
        try:
            if "/" not in raw:
                ip = ipaddress.ip_address(raw)
                raw = f"{ip}/{32 if ip.version == 4 else 128}"
            else:
                raw = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
        if raw not in cleaned:
            cleaned.append(raw)
    return cleaned

def _http_security_normalize_ip(value):
    value = str(value or "").strip()
    if not value:
        return "unknown"
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "unknown"

def _http_security_network_contains(client_ip, networks):
    try:
        address = ipaddress.ip_address(str(client_ip).strip())
    except ValueError:
        return False
    for value in networks or []:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False

def _suspicious_4xx_ignored_path(path):
    normalized = str(path or "").strip().lower()
    if normalized.startswith("/static/"):
        return True
    return normalized in {
        "/favicon.ico", "/robots.txt", "/api/healthz", "/api/telegram/heartbeat"
    }

def _http_security_classify(path, status_code=None):
    p = str(path or "").lower()
    if int(status_code or 0) == 429:
        return "rate_limit"
    if re.search(r"(?:^|/)\.env(?:[./~_-]|$)", p):
        return "environment_scan"
    if re.search(r"(?:^|/)\.(?:git|svn|hg)(?:/|$)", p):
        return "repository_scan"
    if re.search(r"(?:wp-admin|wp-login\.php|phpmyadmin)", p):
        return "admin_scanner"
    if re.search(r"(?:credentials?|secrets?|config|settings?)", p):
        return "credential_config_scan"
    if re.search(r"\.(?:bak|old|orig|save|swp|sql|sqlite|db)(?:$|[?#])", p):
        return "backup_database_scan"
    return "generic_4xx"

def _http_security_scope_applies(path, scope):
    if scope != "auth_admin":
        return True
    p = str(path or "").lower()
    prefixes = (
        "/login", "/logout", "/register", "/settings", "/users", "/nodes",
        "/logs", "/backup", "/api/", "/admin",
    )
    return p.startswith(prefixes)
