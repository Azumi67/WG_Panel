"""Host platform detection and OS-aware command suggestions for Operations"""
from __future__ import annotations
import os
import platform as py_platform
import shlex
import shutil
from pathlib import Path


_PACKAGE_CANDIDATES = (
    ("apt", "apt-get"),
    ("dnf", "dnf"),
    ("yum", "yum"),
    ("zypper", "zypper"),
    ("pacman", "pacman"),
    ("apk", "apk"),
)

_PACKAGE_NAMES = {
    "wireguard_tools": {
        "apt": "wireguard-tools",
        "dnf": "wireguard-tools",
        "yum": "wireguard-tools",
        "zypper": "wireguard-tools",
        "pacman": "wireguard-tools",
        "apk": "wireguard-tools",
    },
    "nftables": {
        "apt": "nftables",
        "dnf": "nftables",
        "yum": "nftables",
        "zypper": "nftables",
        "pacman": "nftables",
        "apk": "nftables",
    },
    "iproute": {
        "apt": "iproute2",
        "dnf": "iproute",
        "yum": "iproute",
        "zypper": "iproute2",
        "pacman": "iproute2",
        "apk": "iproute2",
    },
}


def _read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    path = Path("/etc/os-release")
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip().strip('"').strip("'")
            if key in {"ID", "ID_LIKE", "NAME", "PRETTY_NAME", "VERSION_ID", "VERSION_CODENAME"}:
                values[key] = value[:160]
    except Exception:
        pass
    return values


def detect_platform() -> dict:
    release = _read_os_release()
    manager = ""
    executable = ""
    for key, binary in _PACKAGE_CANDIDATES:
        found = shutil.which(binary)
        if found:
            manager, executable = key, found
            break

    systemctl = shutil.which("systemctl")
    sysctl = shutil.which("sysctl")
    pretty = release.get("PRETTY_NAME") or release.get("NAME") or py_platform.system() or "Linux"
    return {
        "hostname": (py_platform.node() or os.getenv("HOSTNAME") or "local-server")[:120],
        "os": pretty,
        "id": (release.get("ID") or "linux").lower(),
        "id_like": (release.get("ID_LIKE") or "").lower(),
        "version": release.get("VERSION_ID") or "",
        "codename": release.get("VERSION_CODENAME") or "",
        "kernel": py_platform.release()[:120],
        "architecture": py_platform.machine()[:80],
        "package_manager": manager,
        "package_manager_path": executable,
        "systemd": bool(systemctl),
        "sysctl": bool(sysctl),
        "nftables": bool(shutil.which("nft")),
        "wireguard": bool(shutil.which("wg")),
        "wg_quick": bool(shutil.which("wg-quick")),
        "iproute": bool(shutil.which("ip")),
        "panel_service": (os.getenv("PANEL_SERVICE_NAME") or "wg-panel.service").strip() or "wg-panel.service",
    }


def package_name(package_key: str, profile: dict | None = None) -> str | None:
    profile = profile or detect_platform()
    manager = profile.get("package_manager") or ""
    return _PACKAGE_NAMES.get(package_key, {}).get(manager)


def package_install_argv(package_key: str, profile: dict | None = None) -> list[list[str]] | None:
    """Return fixed argv steps for one supported package family.

    The caller still decides whether to execute them.  Returning argv instead of
    a shell command prevents user-controlled shell syntax from entering repairs.
    """
    profile = profile or detect_platform()
    manager = profile.get("package_manager") or ""
    binary = profile.get("package_manager_path") or shutil.which(manager)
    package = package_name(package_key, profile)
    if not (manager and binary and package):
        return None
    if manager == "apt":
        return [[binary, "update"], [binary, "install", "-y", package]]
    if manager in {"dnf", "yum"}:
        return [[binary, "install", "-y", package]]
    if manager == "zypper":
        return [[binary, "--non-interactive", "install", package]]
    if manager == "pacman":
        return [[binary, "-Syu", "--noconfirm", "--needed", package]]
    if manager == "apk":
        return [[binary, "add", package]]
    return None


def argv_display(argv: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in argv)


def package_install_commands(package_key: str, profile: dict | None = None) -> list[str]:
    steps = package_install_argv(package_key, profile)
    return [argv_display(step) for step in steps] if steps else []


def command_guide(profile: dict | None = None) -> list[dict]:
    profile = profile or detect_platform()
    service = profile.get("panel_service") or "wg-panel.service"
    package_commands: list[dict] = []
    for key, label in (
        ("wireguard_tools", "WireGuard tools"),
        ("nftables", "nftables"),
        ("iproute", "iproute tools"),
    ):
        commands = package_install_commands(key, profile)
        if commands:
            package_commands.append({"label": f"Install {label}", "commands": commands})

    groups = []
    if package_commands:
        groups.append({
            "id": "packages",
            "title": "Packages",
            "description": f"Package commands detected for {profile.get('os') or 'this Linux host'}. Installing nftables does not enable, flush, or replace a ruleset.",
            "items": package_commands,
        })

    groups.extend([
        {
            "id": "system",
            "title": "Host overview",
            "description": "Read-only commands to confirm OS, kernel, load, memory, storage, and process state before changing anything.",
            "items": [
                {"label": "OS and kernel", "commands": ["cat /etc/os-release", "uname -a"]},
                {"label": "Load and memory", "commands": ["uptime", "free -h"]},
                {"label": "Storage", "commands": ["df -hT", "df -ih"]},
                {"label": "Top resource consumers", "commands": ["ps aux --sort=-%mem | head -20", "ps aux --sort=-%cpu | head -20"]},
            ],
        },
        {
            "id": "panel",
            "title": "Panel service",
            "description": f"The configured service name is {service}. Inspect status and the first error before restarting it.",
            "items": [
                {"label": "Service status", "commands": [f"systemctl status {service} --no-pager -l", f"systemctl show {service} -p WorkingDirectory -p ExecStart -p User -p Group --no-pager"]},
                {"label": "Recent panel logs", "commands": [f"journalctl -u {service} -n 150 --no-pager", f"journalctl -u {service} -p warning..alert --since '2 hours ago' --no-pager"]},
                {"label": "Restart after fixing the cause", "commands": [f"systemctl restart {service}", f"systemctl is-active {service}"]},
            ],
        },
        {
            "id": "wireguard",
            "title": "WireGuard",
            "description": "Inspect interfaces, handshakes, addresses, and configuration permissions. Replace <iface> only after confirming the intended interface name.",
            "items": [
                {"label": "Interfaces and handshakes", "commands": ["wg show interfaces", "wg show"]},
                {"label": "Network links and addresses", "commands": ["ip -brief link", "ip -brief address"]},
                {"label": "One interface", "commands": ["wg show <iface>", "systemctl status wg-quick@<iface>.service --no-pager -l"]},
                {"label": "Validate file permissions", "commands": ["find /etc/wireguard -maxdepth 1 -type f -name '*.conf' -printf '%m %u:%g %p\\n'"]},
            ],
        },
        {
            "id": "routing",
            "title": "Routing & forwarding",
            "description": "A WireGuard gateway normally needs forwarding and a valid route/NAT path. Do not enable forwarding on a host that is intentionally not a router.",
            "items": [
                {"label": "Routes", "commands": ["ip route", "ip -6 route", "ip route get 1.1.1.1"]},
                {"label": "Check forwarding", "commands": ["sysctl net.ipv4.ip_forward", "sysctl net.ipv6.conf.all.forwarding"]},
                {"label": "Enable IPv4 now", "commands": ["sysctl -w net.ipv4.ip_forward=1"]},
                {"label": "Persist IPv4 forwarding", "commands": ["printf '%s\\n' 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wg-panel-forwarding.conf", "sysctl --system"]},
            ],
        },
        {
            "id": "firewall",
            "title": "Firewall / nftables",
            "description": "Inspect only. Never use a blanket flush while connected remotely; preserve SSH, panel, WireGuard, tunnel, and established-connection rules.",
            "items": [
                {"label": "nftables", "commands": ["nft --version", "nft list ruleset"]},
                {"label": "UFW if installed", "commands": ["ufw status verbose", "ufw status numbered"]},
                {"label": "Legacy iptables if used", "commands": ["iptables -S", "iptables -t nat -S"]},
                {"label": "Forwarding counters", "commands": ["nft list ruleset -a", "ip -s link"]},
            ],
        },
        {
            "id": "ports",
            "title": "Listeners & connectivity",
            "description": "Confirm which processes own listening sockets and whether the expected WireGuard UDP listener exists.",
            "items": [
                {"label": "Listening sockets", "commands": ["ss -lntup", "ss -lnup"]},
                {"label": "Established TCP sessions", "commands": ["ss -tnp state established"]},
                {"label": "Neighbor table", "commands": ["ip neigh show"]},
            ],
        },
        {
            "id": "dns",
            "title": "DNS",
            "description": "Check resolver state separately from WireGuard client DNS settings.",
            "items": [
                {"label": "Resolver configuration", "commands": ["cat /etc/resolv.conf", "resolvectl status 2>/dev/null || true"]},
                {"label": "Resolve a test name", "commands": ["getent ahosts example.com"]},
            ],
        },
        {
            "id": "security",
            "title": "Panel security",
            "description": "Inspect permissions and exposure without printing secret values. Do not cat .env, private keys, or token files into support chats.",
            "items": [
                {"label": "Environment permissions", "commands": ["stat -c '%a %U:%G %n' .env 2>/dev/null || true"]},
                {"label": "WireGuard directory permissions", "commands": ["stat -c '%a %U:%G %n' /etc/wireguard 2>/dev/null || true", "find /etc/wireguard -maxdepth 1 -type f -printf '%m %u:%g %p\\n' 2>/dev/null"]},
                {"label": "Failed SSH logins", "commands": ["journalctl -u ssh -u sshd --since '2 hours ago' --no-pager | tail -120"]},
            ],
        },
        {
            "id": "database",
            "title": "Database",
            "description": "For the default SQLite deployment, integrity_check is read-only. Back up the database before any repair or migration.",
            "items": [
                {"label": "SQLite file", "commands": ["ls -lh instance/wg_panel.db 2>/dev/null || true", "stat -c '%a %U:%G %s bytes %n' instance/wg_panel.db 2>/dev/null || true"]},
                {"label": "SQLite integrity", "commands": ["python3 -c \"import sqlite3; c=sqlite3.connect('instance/wg_panel.db'); print(c.execute('PRAGMA integrity_check').fetchone()[0]); c.close()\""]},
            ],
        },
        {
            "id": "tls",
            "title": "TLS / reverse proxy",
            "description": "Use the panel's configured certificate paths/domain. Replace placeholders before running certificate-specific commands.",
            "items": [
                {"label": "Local HTTPS listener", "commands": ["ss -lntp | grep -E ':(443|8443|8000|5080)\\b' || true"]},
                {"label": "Certificate dates", "commands": ["openssl x509 -in <fullchain.pem> -noout -subject -issuer -dates"]},
                {"label": "Remote TLS handshake", "commands": ["openssl s_client -connect <panel-domain>:443 -servername <panel-domain> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates"]},
            ],
        },
        {
            "id": "storage",
            "title": "Logs, storage & backups",
            "description": "Find large files before deleting anything. Prefer the panel Backup page and keep at least one verified off-server copy.",
            "items": [
                {"label": "Largest application/log paths", "commands": ["du -xh /opt /var/log 2>/dev/null | sort -h | tail -40"]},
                {"label": "Journal usage", "commands": ["journalctl --disk-usage"]},
                {"label": "Recent backup files", "commands": ["find instance -maxdepth 3 -type f \\( -name '*.zip' -o -name '*.sqlite3' -o -name '*.db' \\) -printf '%TY-%Tm-%Td %TH:%TM %10s %p\\n' 2>/dev/null | sort | tail -40"]},
            ],
        },
    ])
    return groups
