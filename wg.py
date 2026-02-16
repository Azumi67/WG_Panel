#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import re
import sys
import json
import time
import sqlite3
import getpass
import base64
import secrets
import shutil
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional


def _exit(code: int = 130):
    print()
    print(left_margin() + c("[INFO] ", BR_CYN) + c("Interrupted (Ctrl+C). Exiting.", BR_YEL))
    raise SystemExit(code)

def _sigint(signum, frame):
    _exit(130)

signal.signal(signal.SIGINT, _sigint)


def _isatty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

NO_COLOR = (os.environ.get("NO_COLOR") is not None) or (not _isatty())
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def ansi(code: str) -> str:
    return "" if NO_COLOR else f"\033[{code}m"

def _ansi(s: str) -> str:
    return ANSI_RE.sub("", s)

RESET = ansi("0")
BOLD  = ansi("1")
DIM   = ansi("2")

BR_RED = ansi("91")
BR_GRN = ansi("92")
BR_YEL = ansi("93")
BR_BLU = ansi("94")
BR_CYN = ansi("96")
BR_WHT = ansi("97")

def c(text: str, color: str) -> str:
    if NO_COLOR:
        return text
    return f"{color}{text}{RESET}"

TAG_INFO = "[INFO]"
TAG_OK   = "[SUCCESS]"
TAG_WARN = "[WARN]"
TAG_ERR  = "[ERROR]"
TAG_RUN  = "[RUN]"


REPO_URL = "https://github.com/Azumi67/WG_Panel"
REPO_DIRNAME_DEFAULT = "WG_Panel"


UI_MAX_WIDTH = 92
UI_MIN_WIDTH = 64

def term(default: int = 96) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default

def ui() -> int:
    w = term()
    return max(UI_MIN_WIDTH, min(UI_MAX_WIDTH, w))

def left_margin() -> str:
    return ""  

def hr(char: str = "─", color: str = DIM) -> str:
    return left_margin() + c(char * ui(), color)

def clear():
    if NO_COLOR:
        print("\n" * 2)
        return
    os.system("clear")

def _paths(s: str) -> str:
    if NO_COLOR:
        return s
    return s.replace("/", c("/", BR_YEL))

def _wrap(s: str, width: int) -> List[str]:
    s = str(s).replace("\t", "    ")
    raw = _ansi(s)
    if len(raw) <= width:
        return [s]
    out: List[str] = []
    buf = s
    while buf:
        r = _ansi(buf)
        if len(r) <= width:
            out.append(buf)
            break
        chunk_raw = r[:width]
        sp = chunk_raw.rfind(" ")
        cut = sp if sp >= max(10, width // 3) else width
        out.append(buf[:cut].rstrip())
        buf = buf[cut:].lstrip()
    return out or [""]

def box(title: str, lines: List[str], border_color: str = BR_CYN) -> str:
    w = ui()
    inner = w - 2
    lm = left_margin()

    t = f" {_ansi(title)} "
    if len(t) > inner - 6:
        t = t[: inner - 9] + "… "

    left_pad = 2
    top_fill = inner - left_pad - len(t)
    top = "┌" + ("─" * left_pad) + t + ("─" * max(0, top_fill)) + "┐"

    out = [lm + c(top, border_color)]
    for line in lines:
        for part in str(line).splitlines() or [""]:
            for wpart in _wrap(part, inner):
                vis = len(_ansi(wpart))
                pad = " " * max(0, inner - vis)
                out.append(lm + c("│", border_color) + wpart + pad + c("│", border_color))
    out.append(lm + c("└" + "─" * inner + "┘", border_color))
    return "\n".join(out)

def box_text(title: str, text: str, border_color: str = BR_CYN) -> str:
    return box(title, (text.rstrip("\n").splitlines() or [""]), border_color)

def header(title_left: str, title_right: str = ""):
    lm = left_margin()
    print(lm + c(title_left, BR_YEL + BOLD) + (("  " + c(title_right, DIM)) if title_right else ""))
    print(hr("═", DIM))


def info(msg: str):
    print(left_margin() + c(f"{TAG_INFO} ", BR_CYN) + c(msg, BR_WHT))

def ok(msg: str):
    print(left_margin() + c(f"{TAG_OK} ", BR_GRN) + c(msg, BR_WHT))

def warn(msg: str):
    print(left_margin() + c(f"{TAG_WARN} ", BR_YEL) + c(msg, BR_WHT))

def err(msg: str):
    print(left_margin() + c(f"{TAG_ERR} ", BR_RED) + c(msg, BR_WHT))

def pause(msg: str = "Press Enter to continue..."):
    try:
        input(left_margin() + c(msg, DIM))
    except (KeyboardInterrupt, EOFError):
        _exit()


def _prompt(prefix: str, default: Optional[str] = None, show_default: bool = True) -> str:
    lm = left_margin()
    d = ""
    if show_default and default not in (None, ""):
        d = " " + c(f"[{default}]", BR_YEL)
    return f"{lm}{c(prefix, BR_CYN)}{d}{c(': ', BR_YEL)}{BR_WHT}"


def ask(label: str, default: Optional[str] = None, show_default: bool = True) -> str:
    try:
        v = input(_prompt(label, default if default is not None else "", show_default)).strip()
        if v == "" and default is not None:
            return default
        return v
    except (KeyboardInterrupt, EOFError):
        _exit()

def ask_int(label: str, default: Optional[int] = None, allow_blank: bool = False, show_default: bool = True) -> Optional[int]:
    d = "" if default is None else str(default)
    while True:
        s = ask(label, default=d if show_default else None, show_default=show_default).strip()
        if s == "" and allow_blank:
            return None
        if s == "" and default is not None:
            return default
        if s.isdigit():
            return int(s)
        warn("Please enter a number.")

def confirm(label: str, default_yes: bool = True) -> bool:
    default = "y" if default_yes else "n"
    while True:
        s = ask(f"{label} ({c('Y', BR_GRN)}/{c('n', BR_RED)})", default=default, show_default=True).lower().strip()
        if s in ("y", "yes"):
            return True
        if s in ("n", "no"):
            return False
        warn("Please answer y or n.")


def _cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def isitroot() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False

def _live(cmd: List[str], title: str, timeout: Optional[int] = None, env: Optional[Dict[str, str]] = None) -> int:
    lm = left_margin()
    print(hr("═", DIM))
    print(lm + c(f"{TAG_RUN} {title}", BR_CYN))
    print(lm + c(f"$ {' '.join(cmd)}", DIM))
    print(hr("─", DIM))

    noisy = cmd and cmd[0] in {"apt", "apt-get", "pip", "pip3"}
    if noisy and _isatty():
        try:
            rc = subprocess.run(cmd, env=env, timeout=timeout).returncode
            if rc == 0:
                ok("Done.")
            else:
                err(f"Failed (rc={rc}).")
            return int(rc)
        except FileNotFoundError:
            err(f"Command not found: {cmd[0]}")
            return 127
        except subprocess.TimeoutExpired:
            err("Timeout.")
            return 124
        except KeyboardInterrupt:
            _exit()

    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    except FileNotFoundError:
        err(f"Command not found: {cmd[0]}")
        return 127

    start = time.time()
    try:
        while True:
            if timeout is not None and (time.time() - start) > timeout:
                try:
                    p.terminate()
                    time.sleep(0.2)
                    p.kill()
                except Exception:
                    pass
                err("Timeout.")
                return 124

            chunk = p.stdout.readline() if p.stdout else ""
            if chunk:
                chunk = chunk.replace("\r", "\n")
                for line in chunk.splitlines():
                    if line.strip() == "":
                        continue
                    print(lm + c(line, BR_WHT))

            if not chunk and p.poll() is not None:
                break

        rc = int(p.wait())
        if rc == 0:
            ok("Done.")
        else:
            err(f"Failed (rc={rc}).")
        return rc

    except KeyboardInterrupt:
        _exit()

def _quick_bar(cmd: List[str], title: str, width: int = 18) -> Tuple[int, str]:

    lm = left_margin()
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        err(f"{title}: command not found: {cmd[0]}")
        return 127, ""

    pos = 0
    direction = 1
    out: List[str] = []

    try:
        while True:
            if p.stdout:
                line = p.stdout.readline()
                if line:
                    out.append(line.rstrip("\n"))

            if p.poll() is not None:
                break

            bar = [" "] * width
            bar[pos] = "█"
            bar[max(0, pos - 1)] = "▓"
            bar[min(width - 1, pos + 1)] = "▓"

            sys.stdout.write(
                "\r" + lm +
                c(f"{TAG_RUN} {title} ", BR_CYN) +
                c("[", DIM) + c("".join(bar), BR_CYN) + c("]", DIM)
            )
            sys.stdout.flush()

            pos += direction
            if pos <= 0:
                pos = 0
                direction = 1
            elif pos >= width - 1:
                pos = width - 1
                direction = -1

            time.sleep(0.015)

        sys.stdout.write("\r" + lm + " " * (width + len(title) + 14) + "\r")
        sys.stdout.flush()

        rc = int(p.wait())
        return rc, "\n".join(out).strip()

    except KeyboardInterrupt:
        _exit()


ROOT_MARKER = Path.home() / ".wg_panel_root.json"

def set_project(p: Path):
    p = p.expanduser().resolve()
    ROOT_MARKER.write_text(json.dumps({"root": str(p)}, indent=2), encoding="utf-8")

def get_project() -> Path:
    cwd = Path.cwd()
    if (cwd / "app.py").exists() and (cwd / "requirements.txt").exists():
        return cwd
    if ROOT_MARKER.exists():
        try:
            d = json.loads(ROOT_MARKER.read_text(encoding="utf-8"))
            p = Path(d.get("root") or "").expanduser()
            if p.exists():
                return p
        except Exception:
            pass
    return Path(f"/usr/local/bin/{REPO_DIRNAME_DEFAULT}")


def readtext(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""

def load_json(path: Path, default):
    try:
        if not path.exists():
            return default
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default

def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)

def _writejson(path: Path, obj):
    _write(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


PANEL_SETTINGS_DEFAULT = {
    "tls_enabled": False,
    "domain": "",
    "force_https_redirect": True,
    "hsts": False,
    "http_port": None,
    "https_port": 443,
    "tls_cert_path": "",
    "tls_key_path": "",
}

RUNTIME_DEFAULT = {
    "bind": "",
    "port": 0,
    "workers": 0,
    "threads": 4,
    "timeout": 60,
    "graceful_timeout": 30,
    "loglevel": "info",
}

TELEGRAM_SETTINGS_DEFAULT = {
    "bot_token": "",
    "enabled": False,
    "notify": {
        "app_down": True,
        "iface_down": True,
        "login_fail": True,
        "suspicious_4xx": True
    }
}

def python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

def git_status(root: Path) -> str:
    if not _cmd("git"):
        return c("git missing", BR_YEL)
    if not root.exists() or not (root / ".git").exists():
        return c("not a git repo", DIM)
    try:
        r1 = subprocess.run(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        r2 = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r1.returncode == 0 and r2.returncode == 0:
            b = (r1.stdout or "").strip().splitlines()[-1]
            s = (r2.stdout or "").strip().splitlines()[-1]
            if b and s:
                return c(b, BR_WHT) + " " + c(s, DIM)
        return c("git status unavailable", BR_YEL)
    except Exception:
        return c("git status unavailable", BR_YEL)

def _svc_active(name: str) -> str:
    if not _cmd("systemctl"):
        return "unknown"
    r = subprocess.run(["systemctl", "is-active", name], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return (r.stdout or "").strip()

def service_state(name: str) -> str:
    st = _svc_active(name)
    if st == "active":
        return c("active", BR_GRN)
    if st == "inactive":
        return c("inactive", BR_YEL)
    if st == "failed":
        return c("failed", BR_RED)
    if st:
        return c(st, BR_BLU)
    return c("unknown", DIM)

def panel_mode(root: Path) -> str:
    ps = load_json(root / "instance" / "panel_settings.json", {})
    tls_toggle = bool(ps.get("tls_enabled"))
    cert = (ps.get("tls_cert_path") or "").strip()
    key = (ps.get("tls_key_path") or "").strip()
    tls_files = bool(cert and key and Path(cert).is_file() and Path(key).is_file())
    tls_eff = bool(tls_toggle and tls_files)
    if tls_toggle and not tls_files:
        return c("TLS configured but missing cert/key", BR_YEL)
    return c("TLS ON", BR_GRN) if tls_eff else c("TLS OFF (HTTP)", BR_YEL)

def telegram_mode(root: Path) -> str:
    tg = load_json(root / "instance" / "telegram_settings.json", {})
    enabled = bool(tg.get("enabled"))
    token = (tg.get("bot_token") or "").strip()
    if enabled and token:
        return c("Telegram enabled", BR_GRN)
    if enabled and not token:
        return c("Telegram enabled but token empty", BR_YEL)
    return c("Telegram disabled", BR_RED)

def render_status(root: Path) -> str:
    venv_dir = root / "venv"
    req_file = root / "requirements.txt"
    app_py = root / "app.py"
    bot_py = root / "telegram_bot.py"

    env_path = root / ".env"
    panel_json_path = root / "instance" / "panel_settings.json"
    tg_json_path = root / "instance" / "telegram_settings.json"
    rt_json_path = root / "instance" / "runtime.json"

    rows: List[str] = []
    rows.append(f"{TAG_INFO} Time:   {c(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), BR_WHT)}")
    rows.append(f"{TAG_INFO} Root:   {c(_paths(str(root)), BR_CYN)}")
    rows.append(f"{TAG_INFO} Python: {c(python_version(), BR_WHT)}")
    rows.append(f"{TAG_INFO} Git:    {git_status(root)}")

    rows.append("")
    rows.append(f"{('✓' if req_file.exists() else '✗')} requirements.txt: " +
                (c("found", BR_GRN) if req_file.exists() else c("missing", BR_RED)))
    rows.append(f"{('✓' if app_py.exists() else '✗')} app.py: " +
                (c("found", BR_GRN) if app_py.exists() else c("missing", BR_RED)))
    rows.append(f"{('✓' if bot_py.exists() else '!')} telegram_bot.py: " +
                (c("found", BR_GRN) if bot_py.exists() else c("missing", BR_YEL)))
    rows.append(f"{('✓' if venv_dir.exists() else '!')} venv: " +
                (c("exists", BR_GRN) if venv_dir.exists() else c("not created", BR_YEL)))

    rows.append("")
    rows.append(f"{('✓' if env_path.exists() else '!')} .env: " +
                (c("exists", BR_GRN) if env_path.exists() else c("not created", BR_YEL)))
    rows.append(f"{('✓' if panel_json_path.exists() else '!')} panel_settings.json: " +
                (c("exists", BR_GRN) if panel_json_path.exists() else c("not created", BR_YEL)))
    rows.append(f"{('✓' if rt_json_path.exists() else '!')} runtime.json: " +
                (c("exists", BR_GRN) if rt_json_path.exists() else c("not created", BR_YEL)))
    rows.append(f"{('✓' if tg_json_path.exists() else '!')} telegram_settings.json: " +
                (c("exists", BR_GRN) if tg_json_path.exists() else c("not created", BR_YEL)))

    rows.append("")
    rows.append(f"{TAG_INFO} Modes:  {panel_mode(root)}  |  {telegram_mode(root)}")
    rows.append("")
    rows.append(f"{TAG_INFO} Services:")
    rows.append(f"  - wg-panel.service:     {service_state('wg-panel.service')}")
    rows.append(f"  - wg-panel-bot.service: {service_state('wg-panel-bot.service')}")

    return box("Project Status", rows, border_color=BR_CYN)


APT_PACKAGES = [
    "ca-certificates", "curl", "git", "jq",
    "python3", "python3-venv", "python3-pip", "python3-dev",
    "build-essential", "libffi-dev", "libssl-dev",
    "wireguard", "wireguard-tools", "iptables",
]

def _debian() -> bool:
    if not _cmd("apt-get"):
        print(box("Unsupported OS", [
            c(f"{TAG_ERR} apt-get not found.", BR_RED),
            "This installer targets Debian/Ubuntu.",
        ], border_color=BR_RED))
        return False
    return True

def install_requirements():
    if not isitroot():
        err("Run with sudo for apt install.")
        pause()
        return
    if not _debian():
        pause()
        return

    clear()
    header("System Requirements", "apt")
    print(box("Tips", [
        c("This installs system packages required by WG_Panel.", BR_WHT),
    ], border_color=BR_YEL))

    if not confirm("Install system requirements now?", default_yes=True):
        warn("Canceled.")
        pause()
        return

    apt_env = os.environ.copy()
    apt_env["DEBIAN_FRONTEND"] = "noninteractive"
    apt_env["TERM"] = "dumb"

    if _live(
        ["apt-get", "update",
         "-o", "Dpkg::Use-Pty=0",
         "-o", "Acquire::Retries=3"],
        "apt-get update",
        env=apt_env
    ) != 0:
        pause()
        return

    rc = _live(
        ["apt-get", "install", "-y",
         "-o", "Dpkg::Use-Pty=0",
         "--no-install-recommends"] + APT_PACKAGES,
        "apt-get install requirements",
        env=apt_env
    )

    if rc == 0:
        ok("System requirements finished.")
    else:
        err("System requirements failed.")
    pause()


def clone_repo():
    if not _cmd("git"):
        err("git not installed. Run system requirements first.")
        pause()
        return

    default_target = f"/usr/local/bin/{REPO_DIRNAME_DEFAULT}"

    clear()
    header("Git Clone", REPO_URL)
    print(box("Tips", [
        c("Choose the FULL target folder path.", BR_WHT),
        c("Git clones into the folder you specify (no folder-in-folder).", BR_GRN),
        "",
        c("Recommended:", BR_YEL) + " " + c(_paths(default_target), BR_CYN),
    ], border_color=BR_YEL))

    target_in = ask("Install path (full)", default=default_target, show_default=True).strip()
    if not target_in:
        warn("Canceled.")
        pause()
        return

    target = Path(target_in).expanduser()

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        err("Cannot create parent directory.")
        pause()
        return

    if target.exists() and (target / ".git").exists():
        info(f"Repo already exists: {_paths(str(target))}")
        set_project(target)
        ok("Project root updated.")
        if confirm("Run git pull now?", default_yes=False):
            _live(["git", "-C", str(target), "pull", "--ff-only"], "git pull --ff-only")
        pause()
        return

    if target.exists():
        try:
            if any(target.iterdir()):
                err("Target exists and is not empty. Choose another path.")
                pause()
                return
        except Exception:
            err("Cannot access target directory.")
            pause()
            return

    if not confirm(f"Clone into {_paths(str(target))} ?", default_yes=True):
        warn("Canceled.")
        pause()
        return

    rc = _live(["git", "clone", REPO_URL, str(target)], "git clone")
    if rc == 0 and (target / "app.py").exists():
        set_project(target)
        ok(f"Project root set: {_paths(str(target))}")
    else:
        warn("Clone finished but app.py not found. Check your target path.")
    pause()

def _venv_requirements(root: Path):
    req = root / "requirements.txt"
    if not req.exists():
        err("requirements.txt not found. Clone repo first.")
        pause()
        return

    venv_dir = root / "venv"

    clear()
    header("Python Dependencies", "venv + pip")
    print(box("Tips", [
        c("This creates venv and installs requirements.txt.", BR_WHT),
    ], border_color=BR_YEL))

    if not confirm("Create venv + install requirements?", default_yes=True):
        warn("Canceled.")
        pause()
        return

    if not venv_dir.exists():
        if _live(["python3", "-m", "venv", str(venv_dir)], "Create virtual environment") != 0:
            pause()
            return
    else:
        info("venv already exists (skipping create).")

    vpy = venv_dir / "bin" / "python"
    if not vpy.exists():
        err("venv is broken (python missing). Remove venv and re-run.")
        pause()
        return

    _live([str(vpy), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], "Upgrade pip tooling")
    _live([str(vpy), "-m", "pip", "install", "-r", str(req)], "pip install -r requirements.txt")
    ok("Python dependencies finished.")
    pause()


def _read_env(path: Path) -> Dict[str, str]:
    try:
        if not path.exists():
            return {}
        return parse_env(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}

def wg_dir(root: Optional[Path] = None) -> Path:

    if root is not None:
        env = _read_env(root / ".env")
        raw = (env.get("WIREGUARD_CONF_PATH") or "").strip()
        if raw:
            raw = raw.split("#", 1)[0].strip()


    return Path("/etc/wireguard")

def _list_confs(conf_dir: Path) -> List[Path]:
    try:
        if conf_dir.exists():
            return sorted(conf_dir.glob("*.conf"))
    except Exception:
        pass
    return []

def _default_iface() -> str:
    try:
        p = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        if p.returncode == 0:
            m = re.search(r"\bdev\s+(\S+)", p.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "eth0"

def _wg_path() -> str:

    if Path("/usr/bin/wg").exists():
        return "/usr/bin/wg"

    p = shutil.which("wg") or ""
    if p.strip() == "/usr/local/bin/wg" and Path("/usr/bin/wg").exists():
        return "/usr/bin/wg"
    return p or ""


def _wg_keypair() -> Tuple[str, str]:

    wg_bin = _wg_path()
    if not wg_bin:
        raise RuntimeError("wg not found (install wireguard-tools)")

    def pub_from_priv(priv: str) -> str:
        p2 = subprocess.run(
            [wg_bin, "pubkey"],
            input=priv + "\n",
            capture_output=True,
            text=True,
            timeout=8,
        )
        if p2.returncode != 0:
            raise RuntimeError((p2.stderr or p2.stdout or "wg pubkey failed").strip())
        pub = (p2.stdout or "").strip()
        if not pub:
            raise RuntimeError("wg pubkey returned empty output")
        return pub

    try:
        p1 = subprocess.run([wg_bin, "genkey"], capture_output=True, text=True, timeout=3)
        if p1.returncode == 0:
            priv = (p1.stdout or "").strip()
            if priv:
                return priv, pub_from_priv(priv)
    except subprocess.TimeoutExpired:
        pass

    warn("Low entropy or wg genkey stalled. Using /dev/urandom fallback.")
    key_bytes = Path("/dev/urandom").read_bytes()[:32]
    priv = base64.b64encode(key_bytes).decode("ascii")
    return priv, pub_from_priv(priv)
    
def __wg_serverconf(
    iface: str,
    address: str,
    listen_port: int,
    privkey: str,
    wan_iface: Optional[str],
    enable_nat: bool,
    enable_ipv6_fwd: bool,
) -> str:
    lines: List[str] = []
    lines.append("[Interface]")
    lines.append(f"Address = {address}")
    lines.append(f"ListenPort = {listen_port}")
    lines.append(f"PrivateKey = {privkey}")

    if enable_nat and wan_iface:
        lines.append("")
        lines.append("# NAT + forwarding (auto-generated)")
        lines.append(f"PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE")
        lines.append(f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {wan_iface} -j MASQUERADE")
        if enable_ipv6_fwd and _cmd("ip6tables"):
            lines.append(f"PostUp   = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT")
            lines.append(f"PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT")

    lines.append("")
    return "\n".join(lines) + "\n"

def _sysctl_forwarding(enable_ipv6: bool = False) -> bool:
    if not _cmd("sysctl"):
        return False
    ok_all = True
    try:
        p = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True, text=True)
        ok_all = ok_all and (p.returncode == 0)
    except Exception:
        ok_all = False
    if enable_ipv6:
        try:
            p6 = subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], capture_output=True, text=True)
            ok_all = ok_all and (p6.returncode == 0)
        except Exception:
            ok_all = False
    return ok_all

def wireguard_setup(root: Optional[Path] = None):
    if not isitroot():
        err("Run with sudo to create WireGuard configs and start wg-quick.")
        pause()
        return
    if not _debian():
        pause()
        return

    clear()
    header("WireGuard Setup", "create / edit interface config")
    conf_dir = wg_dir(root)
    print(box("Location", [
    f"{c('Config directory:', BR_WHT)} {c(_paths(str(conf_dir)), BR_CYN)}",
    ], border_color=BR_YEL))


    if not conf_dir.exists():
        try:
            conf_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            err("Cannot create WireGuard directory.")
            pause()
            return

    confs = _list_confs(conf_dir)
    existing = [p.stem for p in confs]  

    lines: List[str] = []
    if existing:
        lines.append(c("Existing configs:", BR_WHT))
        for i, name in enumerate(existing[:12], start=1):
            lines.append(f"  {c(str(i)+')', BR_CYN)} {c(name + '.conf', BR_WHT)}")
        if len(existing) > 12:
            lines.append(c(f"  ... (+{len(existing) - 12} more)", DIM))
        lines.append("")
        lines.append(f"  {c('N)', BR_GRN)} Create a new config")
    else:
        lines.append(c("No configs found in this directory.", DIM))
        lines.append("")
        lines.append(f"  {c('N)', BR_GRN)} Create a new config")

    print(box("WireGuard Interfaces", lines, border_color=BR_GRN))

    sel = ask("Select (number or N)", default="N", show_default=True).strip().lower()

    iface = ""
    if sel in ("n", "new"):
        iface = ask("New interface name", default="wg0", show_default=True).strip() or "wg0"
    elif sel.isdigit() and existing:
        idx = int(sel)
        if 1 <= idx <= len(existing):
            iface = existing[idx - 1]
        else:
            warn("Invalid selection. Using new config.")
            iface = ask("New interface name", default="wg0", show_default=True).strip() or "wg0"
    else:
        if sel and sel not in ("n", "new"):
            iface = sel
        else:
            iface = "wg0"

    conf_path = conf_dir / f"{iface}.conf"


    address = ask("Server Address (CIDR)", default="10.66.66.1/24").strip() or "10.66.66.1/24"
    listen_port = ask_int("ListenPort", default=51820) or 51820

    enable_nat = confirm("Add iptables NAT (MASQUERADE) + FORWARD rules?", default_yes=True)
    wan_iface = None
    if enable_nat:
        wan_iface = ask("Outbound interface for NAT", default=_default_iface()).strip() or _default_iface()

    enable_ipv6_fwd = confirm("Enable IPv6 forwarding rules too (if you use IPv6)?", default_yes=False)
    print()
    info("Generating WireGuard keys...")
    sys.stdout.flush()

    try:
        priv, pub = _wg_keypair()
    except Exception as e:
        err(f"Key generation failed: {e}")
        pause()
        return

    conf_text = __wg_serverconf(
        iface=iface,
        address=address,
        listen_port=int(listen_port),
        privkey=priv,
        wan_iface=wan_iface,
        enable_nat=enable_nat,
        enable_ipv6_fwd=enable_ipv6_fwd,
    )

    print()
    print(box("Ready", [
        c("Server PublicKey (share with clients):", BR_WHT) + " " + c(pub, BR_GRN),
        c("Config path:", BR_WHT) + " " + c(_paths(str(conf_path)), BR_CYN),
        c("Action:", BR_WHT) + " " + c("Create/Update WireGuard config", BR_YEL),
    ], border_color=BR_CYN))

    if conf_path.exists() and not confirm("File exists. Overwrite?", default_yes=False):
        warn("Canceled.")
        pause()
        return

    if not confirm("Save this config now?", default_yes=True):
        warn("Canceled.")
        pause()
        return

    try:
        conf_path.write_text(conf_text, encoding="utf-8")
        os.chmod(conf_path, 0o600)
    except Exception:
        err("Failed to write config file.")
        pause()
        return

    ok(f"Saved: {_paths(str(conf_path))}")

    if enable_nat:
        if _sysctl_forwarding(enable_ipv6=enable_ipv6_fwd):
            ok("Kernel forwarding enabled (sysctl).")
        else:
            warn("Could not apply sysctl forwarding automatically.")

    if confirm("Enable + start this interface now (wg-quick@...)?", default_yes=True):
        if _cmd("systemctl"):
            _live(["systemctl", "daemon-reload"], "systemd daemon-reload")
            _live(["systemctl", "enable", "--now", f"wg-quick@{iface}"], f"systemctl enable --now wg-quick@{iface}")
            _live(["systemctl", "status", "--no-pager", "-l", f"wg-quick@{iface}"], f"Status wg-quick@{iface}")
        else:
            _live(["wg-quick", "up", iface], f"wg-quick up {iface}")

    pause()

def _editor(path: Path):
    editor = (os.environ.get("EDITOR") or "").strip()
    candidates = [editor] if editor else []
    candidates += ["nano", "vim", "vi"]
    ed = None
    for cand in candidates:
        if cand and _cmd(cand):
            ed = cand
            break
    if ed is None:
        err("No editor found (set $EDITOR or install nano/vim).")
        return

    try:
        subprocess.call([ed, str(path)])
        ok("Editor closed.")
    except Exception:
        err("Failed to open editor.")

def wireguard_edit(root: Optional[Path] = None):
    while True:
        conf_dir = wg_dir(root)
        clear()
        header("WireGuard Config", str(conf_dir))

        confs = []
        try:
            if conf_dir.exists():
                confs = sorted(conf_dir.glob("*.conf"))
        except Exception:
            confs = []

        lines: List[str] = []
        lines.append(c("1) Create new config (guided)", BR_GRN))
        lines.append(c("2) Edit existing config", BR_CYN))
        lines.append(c("3) Add/import config file (copy)", BR_CYN))
        lines.append("")
        if confs:
            lines.append(c("Detected:", BR_YEL))
            for p in confs[:12]:
                lines.append("  - " + c(p.name, BR_WHT))
            if len(confs) > 12:
                lines.append(c(f"  ... (+{len(confs) - 12} more)", DIM))
        else:
            lines.append(c("No .conf files found.", DIM))
        lines.append("")
        lines.append(c("0) Back", DIM))
        print(box("WireGuard", lines, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
            wireguard_setup(root)
        elif ch == "2":
            if not confs:
                warn("No configs to edit.")
                time.sleep(0.35)
                continue
            name = ask("Config filename to edit (e.g. wg0.conf)", default=confs[0].name).strip()
            if not name:
                continue
            p = conf_dir / name
            if not p.exists():
                warn("File not found.")
                time.sleep(0.35)
                continue
            _editor(p)
            pause()
        elif ch == "3":
            src = ask("Full path of existing .conf to import", default="").strip()
            if not src:
                continue
            sp = Path(src).expanduser()
            if not sp.exists() or not sp.is_file():
                warn("Source file not found.")
                time.sleep(0.35)
                continue
            dst_name = ask("Destination filename", default=sp.name).strip() or sp.name
            dp = conf_dir / dst_name
            if dp.exists() and not confirm("Destination exists. Overwrite?", default_yes=False):
                continue
            try:
                conf_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(sp), str(dp))
                os.chmod(dp, 0o600)
                ok(f"Imported: {_paths(str(dp))}")
            except Exception:
                err("Import failed.")
            pause()
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)


def _gen_flask_secret() -> str:
    return secrets.token_urlsafe(48)

def _gen_api_key() -> str:
    return secrets.token_urlsafe(32)

def _gen_fernet_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")

def parse_env(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def _env_text(values: Dict[str, str]) -> str:

    def g(k: str, default: str = "") -> str:
        v = values.get(k)
        return default if v is None else str(v)

    lines: List[str] = []

    lines.append(f"FLASK_SECRET_KEY={g('FLASK_SECRET_KEY','')}")
    lines.append(f"FERNET_KEY={g('FERNET_KEY','')}")
    lines.append(f"API_KEY={g('API_KEY','')}")
    lines.append(f"DATABASE_URL={g('DATABASE_URL','sqlite:///instance/wg_panel.db')}")
    lines.append("")

    lines.append(f"LOG_LEVEL={g('LOG_LEVEL','INFO')}")
    lines.append(f"SECURE_COOKIES={g('SECURE_COOKIES','1')}")
    lines.append(f"WIREGUARD_CONF_PATH={g('WIREGUARD_CONF_PATH','/etc/wireguard')}")
    lines.append("")

    lines.append(f"SETUP_TOKEN={g('SETUP_TOKEN','')}")
    lines.append(f"TG_HEARTBEAT_SEC={g('TG_HEARTBEAT_SEC','60')}")

    return "\n".join(lines) + "\n"


def env_setup(root: Path):
    env_path = root / ".env"
    existing = parse_env(readtext(env_path))

    vals: Dict[str, str] = {}
    vals["FLASK_SECRET_KEY"] = existing.get("FLASK_SECRET_KEY") or _gen_flask_secret()
    vals["FERNET_KEY"] = existing.get("FERNET_KEY") or _gen_fernet_key()
    vals["API_KEY"] = existing.get("API_KEY") or _gen_api_key()
    vals["DATABASE_URL"] = existing.get("DATABASE_URL") or "sqlite:///instance/wg_panel.db"
    vals["LOG_LEVEL"] = (existing.get("LOG_LEVEL") or "INFO").upper()
    vals["SECURE_COOKIES"] = existing.get("SECURE_COOKIES") or "1"
    vals["WIREGUARD_CONF_PATH"] = existing.get("WIREGUARD_CONF_PATH") or "/etc/wireguard"
    vals["SETUP_TOKEN"] = existing.get("SETUP_TOKEN") or ""
    vals["TG_HEARTBEAT_SEC"] = existing.get("TG_HEARTBEAT_SEC") or "60"

    clear()
    header("Create/Update .env", _paths(str(env_path)))

    print(box("Tips", [
        c("Press Enter to accept defaults.", BR_WHT),
        c("Keys are generated if missing.", BR_WHT),
        c("Input typing is white.", BR_GRN),
    ], border_color=BR_YEL))

    print(box("Variable hints", [
        c("LOG_LEVEL", BR_CYN) + c(" → ", DIM) + c("DEBUG | INFO | WARNING | ERROR", BR_WHT),
        c("SECURE_COOKIES", BR_CYN) + c(" → ", DIM) + c("1=HTTPS/prod, 0=dev", BR_WHT),
        c("WIREGUARD_CONF_PATH", BR_CYN) + c(" → ", DIM) + c("folder or single .conf path", BR_WHT),
        c("SETUP_TOKEN", BR_CYN) + c(" → ", DIM) + c("optional gate for /register", BR_WHT),
        c("TG_HEARTBEAT_SEC", BR_CYN) + c(" → ", DIM) + c("bot heartbeat window seconds", BR_WHT),
    ], border_color=BR_CYN))

    vals["FLASK_SECRET_KEY"] = ask("FLASK_SECRET_KEY", default=vals["FLASK_SECRET_KEY"], show_default=True)
    vals["FERNET_KEY"] = ask("FERNET_KEY", default=vals["FERNET_KEY"], show_default=True)
    vals["API_KEY"] = ask("API_KEY", default=vals["API_KEY"], show_default=True)
    vals["DATABASE_URL"] = ask("DATABASE_URL", default=vals["DATABASE_URL"], show_default=True)
    vals["LOG_LEVEL"] = ask("LOG_LEVEL", default=vals["LOG_LEVEL"], show_default=True).upper()
    vals["SECURE_COOKIES"] = ask("SECURE_COOKIES", default=vals["SECURE_COOKIES"], show_default=True)
    vals["WIREGUARD_CONF_PATH"] = ask("WIREGUARD_CONF_PATH", default=vals["WIREGUARD_CONF_PATH"], show_default=True)
    vals["SETUP_TOKEN"] = ask("SETUP_TOKEN", default=vals["SETUP_TOKEN"], show_default=True)
    vals["TG_HEARTBEAT_SEC"] = ask("TG_HEARTBEAT_SEC", default=vals["TG_HEARTBEAT_SEC"], show_default=True)

    env_text = _env_text(vals)

    clear()
    header("Preview .env", "Review before saving")
    print(box_text(".env Preview", c(env_text.rstrip("\n"), BR_WHT), border_color=BR_CYN))

    if confirm("Save .env now?", default_yes=True):
        _write(env_path, env_text)
        ok(f"Saved: {_paths(str(env_path))}")
    else:
        warn("Skipped saving .env.")
    pause()

def _apt_install(pkgs: List[str], title: str = "apt-get install"):
    apt_env = os.environ.copy()
    apt_env["DEBIAN_FRONTEND"] = "noninteractive"
    apt_env["TERM"] = "dumb"

    _live(["apt-get", "update",
           "-o", "Dpkg::Use-Pty=0",
           "-o", "Acquire::Retries=3"],
          "apt-get update", env=apt_env)

    return _live(["apt-get", "install", "-y",
                  "-o", "Dpkg::Use-Pty=0",
                  "--no-install-recommends"] + pkgs,
                 title, env=apt_env)

def _certbot() -> bool:
    if _cmd("certbot"):
        return True
    if not isitroot():
        err("certbot install requires sudo.")
        return False
    if not _debian():
        return False
    info("certbot not found. Installing certbot...")
    rc = _apt_install(["certbot"], "Install certbot")
    return rc == 0 and _cmd("certbot")

def _le_paths(domain: str) -> Tuple[str, str]:
    d = domain.strip().lower().rstrip(".")
    live = Path("/etc/letsencrypt/live") / d
    return str(live / "fullchain.pem"), str(live / "privkey.pem")

def _le_cert_exists(domain: str) -> bool:
    cert, key = _le_paths(domain)
    return Path(cert).is_file() and Path(key).is_file()

def _obtain_cert(domain: str, email: str, staging: bool = False) -> bool:

    if not _certbot():
        return False

    d = domain.strip()
    e = (email or "").strip()
    if not d:
        return False
    if not e:
        e = f"admin@{d}"

    args = [
        "certbot", "certonly",
        "--standalone",
        "-d", d,
        "--agree-tos",
        "--non-interactive",
        "--keep-until-expiring",
        "--email", e,
    ]
    if staging:
        args.append("--staging")

    info("Requesting/renewing certificate with certbot (standalone, port 80)...")
    rc = _live(args, "certbot certonly --standalone", timeout=900)
    if rc != 0:
        err("certbot failed. Make sure port 80 is open and not used by another service.")
        return False
    return _le_cert_exists(d)


def panel_settings(root: Path):
    instance_dir = root / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    path = instance_dir / "panel_settings.json"

    ps = dict(PANEL_SETTINGS_DEFAULT)
    cur = load_json(path, {})
    if isinstance(cur, dict):
        ps.update(cur)

    clear()
    header("Panel Settings", _paths("instance/panel_settings.json"))
    print(box("Tips", [
        c("TLS ON will automatically obtain/renew a Let’s Encrypt certificate using certbot.", BR_WHT),
        c("Requires: domain DNS → this server, inbound port 80 open (HTTP-01 challenge).", BR_YEL),
    ], border_color=BR_YEL))

    tls_enabled = confirm("Enable TLS (HTTPS)?", default_yes=bool(ps.get("tls_enabled", False)))
    ps["tls_enabled"] = tls_enabled

    if tls_enabled:
        domain = ask("Domain (panel.example.com)", default=str(ps.get("domain") or ""), show_default=True).strip()
        if not domain:
            err("Domain is required for TLS.")
            pause()
            return

        ps["domain"] = domain
        ps["https_port"] = ask_int("HTTPS port", default=int(ps.get("https_port") or 443), allow_blank=False, show_default=True) or 443
        ps["http_port"] = 80
        ps["force_https_redirect"] = True
        ps["hsts"] = bool(ps.get("hsts", False))  

        cert_path, key_path = _le_paths(domain)
        ps["tls_cert_path"] = cert_path
        ps["tls_key_path"] = key_path

        if not _le_cert_exists(domain):
            email_default = f"admin@{domain}"
            email = ask("Certbot email (for renewal notices)", default=email_default, show_default=True).strip() or email_default
            if not isitroot():
                err("TLS certificate obtain requires sudo.")
                pause()
                return
            if not _debian():
                pause()
                return

            if not _obtain_cert(domain, email=email, staging=False):
                warn("TLS enabled but certificate was not obtained.")
                warn("You can retry later after fixing DNS/port 80, or place certs manually in /etc/letsencrypt.")
        else:
            ok("Existing Let’s Encrypt certificate detected (reusing).")

    else:
        ps["domain"] = ""
        ps["https_port"] = int(ps.get("https_port") or 443)
        ps["force_https_redirect"] = False
        ps["hsts"] = False
        ps["tls_cert_path"] = ""
        ps["tls_key_path"] = ""
        ps["http_port"] = ask_int("HTTP port (blank=null)", default=ps.get("http_port"), allow_blank=True, show_default=True)

    clear()
    header("Preview panel_settings.json", "Review before saving")
    print(box("panel_settings.json Preview", [c(json.dumps(ps, indent=2, ensure_ascii=False), BR_WHT)], border_color=BR_CYN))

    if confirm("Save panel_settings.json now?", default_yes=True):
        _writejson(path, ps)
        ok(f"Saved: {_paths(str(path))}")
    else:
        warn("Skipped saving panel_settings.json.")
    pause()


def _panel_tls(root: Path) -> Tuple[bool, int, int]:
    ps = load_json(root / "instance" / "panel_settings.json", {})
    tls_toggle = bool(ps.get("tls_enabled"))
    cert = (ps.get("tls_cert_path") or "").strip()
    key = (ps.get("tls_key_path") or "").strip()
    tls_files = bool(cert and key and Path(cert).is_file() and Path(key).is_file())
    tls_eff = bool(tls_toggle and tls_files)

    def _valid_port(x, dflt):
        try:
            i = int(x)
            return i if 1 <= i <= 65535 else dflt
        except Exception:
            return dflt

    http_port = _valid_port(ps.get("http_port") or 8000, 8000)
    https_port = _valid_port(ps.get("https_port") or 443, 443)
    return tls_eff, http_port, https_port

def runtime(root: Path):
    instance_dir = root / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    path = instance_dir / "runtime.json"

    rt = dict(RUNTIME_DEFAULT)
    cur = load_json(path, {})
    if isinstance(cur, dict):
        rt.update({k: cur.get(k, rt.get(k)) for k in RUNTIME_DEFAULT.keys()})

    tls_eff, http_port, https_port = _panel_tls(root)
    default_port = https_port if tls_eff else http_port

    clear()
    header("Runtime Settings", _paths("instance/runtime.json"))
    print(box("Tips", [
        c("This controls internal gunicorn launched by app.py.", BR_WHT),
        c("If unsure, keep defaults.", BR_GRN),
    ], border_color=BR_YEL))

    auto = confirm("Auto-configure bind based on panel TLS settings?", default_yes=True)

    if auto:
        host = "0.0.0.0"
        port = default_port
        ok(f"Auto bind set to {host}:{port}")
        workers = int(rt.get("workers") or 0)
        threads = int(rt.get("threads") or 4)
        timeout = int(rt.get("timeout") or 60)
        gtimeout = int(rt.get("graceful_timeout") or 30)
        loglevel = str(rt.get("loglevel") or "info").strip().lower() or "info"
    else:
        host = ask("Bind host", default="0.0.0.0", show_default=True).strip() or "0.0.0.0"
        port = ask_int("Bind port", default=int(rt.get("port") or default_port), allow_blank=False, show_default=True) or default_port
        workers = ask_int("Workers (0 = app default)", default=int(rt.get("workers") or 0), allow_blank=False, show_default=True) or 0
        threads = ask_int("Threads", default=int(rt.get("threads") or 4), allow_blank=False, show_default=True) or 4
        timeout = ask_int("Timeout (sec)", default=int(rt.get("timeout") or 60), allow_blank=False, show_default=True) or 60
        gtimeout = ask_int("Graceful timeout (sec)", default=int(rt.get("graceful_timeout") or 30), allow_blank=False, show_default=True) or 30
        loglevel = ask("Loglevel (debug/info/warning/error)", default=str(rt.get("loglevel") or "info"), show_default=True).strip().lower() or "info"

    rt_out = {
        "bind": f"{host}:{port}",
        "port": int(port),
        "workers": int(max(0, min(workers, 64))),
        "threads": int(max(1, min(threads, 64))),
        "timeout": int(max(10, min(timeout, 600))),
        "graceful_timeout": int(max(5, min(gtimeout, 600))),
        "loglevel": loglevel,
    }

    clear()
    header("Preview runtime.json", "Review before saving")
    print(box("runtime.json Preview", [c(json.dumps(rt_out, indent=2, ensure_ascii=False), BR_WHT)], border_color=BR_CYN))

    if confirm("Save runtime.json now?", default_yes=True):
        _writejson(path, rt_out)
        ok(f"Saved: {_paths(str(path))}")
    else:
        warn("Skipped saving runtime.json.")
    pause()


def telegram_settings(root: Path):
    instance_dir = root / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    path = instance_dir / "telegram_settings.json"

    tg = json.loads(json.dumps(TELEGRAM_SETTINGS_DEFAULT))
    cur = load_json(path, {})
    if isinstance(cur, dict):
        tg["enabled"] = bool(cur.get("enabled", tg["enabled"]))
        tg["bot_token"] = str(cur.get("bot_token", tg["bot_token"]) or "")
        if isinstance(cur.get("notify"), dict):
            tg["notify"].update(cur["notify"])

    clear()
    header("Telegram Settings", _paths("instance/telegram_settings.json"))
    print(box("Tips", [
        c("Telegram is optional; you can configure later.", BR_WHT),
        c("Bot service requires: enabled=true AND bot_token set.", BR_GRN),
    ], border_color=BR_YEL))

    tg["enabled"] = confirm("Enable Telegram integration?", default_yes=bool(tg.get("enabled", False)))
    if tg["enabled"]:
        tg["bot_token"] = ask("Bot token", default=str(tg.get("bot_token") or ""), show_default=True).strip()
        tg["notify"]["app_down"] = confirm("Notify: app_down?", default_yes=bool(tg["notify"]["app_down"]))
        tg["notify"]["iface_down"] = confirm("Notify: iface_down?", default_yes=bool(tg["notify"]["iface_down"]))
        tg["notify"]["login_fail"] = confirm("Notify: login_fail?", default_yes=bool(tg["notify"]["login_fail"]))
        tg["notify"]["suspicious_4xx"] = confirm("Notify: suspicious_4xx?", default_yes=bool(tg["notify"]["suspicious_4xx"]))
        if not tg["bot_token"]:
            warn("Telegram enabled but token is empty. Bot service cannot run.")
    else:
        info("Telegram disabled.")

    clear()
    header("Preview telegram_settings.json", "Review before saving")
    print(box("telegram_settings.json Preview", [c(json.dumps(tg, indent=2, ensure_ascii=False), BR_WHT)], border_color=BR_CYN))

    if confirm("Save telegram_settings.json now?", default_yes=True):
        _writejson(path, tg)
        ok(f"Saved: {_paths(str(path))}")
    else:
        warn("Skipped saving telegram_settings.json.")
    pause()


def _project_ready(root: Path) -> bool:
    if not root.exists():
        err("Project root not found. Clone first.")
        return False
    if not (root / "app.py").exists():
        err("app.py missing in project root.")
        return False
    if not (root / "venv" / "bin" / "python").exists():
        err("venv missing. Create venv first.")
        return False
    if not (root / ".env").exists():
        err(".env missing. Create .env first.")
        return False
    return True

def _panel_service(root: Path) -> bool:
    panel_settings_path = root / "instance" / "panel_settings.json"
    runtime_path = root / "instance" / "runtime.json"
    if not panel_settings_path.exists():
        err("panel_settings.json missing. Create it first.")
        return False
    if not runtime_path.exists():
        err("runtime.json missing. Create it first.")
        return False

    vpy = root / "venv" / "bin" / "python"
    svc_user = ask("Service user", default="root", show_default=True).strip() or "root"
    svc_group = ask("Service group", default="root", show_default=True).strip() or "root"

    unit = f"""[Unit]
Description=WG Panel (app.py launcher)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
EnvironmentFile={root}/.env
ExecStart={vpy} {root}/app.py
Restart=always
RestartSec=2
User={svc_user}
Group={svc_group}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""
    path = Path("/etc/systemd/system/wg-panel.service")
    _write(path, unit)
    ok(f"Wrote: {_paths(str(path))}")
    return True

def _bot_service(root: Path) -> bool:
    tg_path = root / "instance" / "telegram_settings.json"
    bot_py = root / "telegram_bot.py"

    if not tg_path.exists():
        err("telegram_settings.json missing. Create it first.")
        return False
    tg = load_json(tg_path, {})
    enabled = bool(tg.get("enabled"))
    token_ok = bool((tg.get("bot_token") or "").strip())
    if not enabled:
        err("Telegram is disabled in telegram_settings.json.")
        return False
    if not token_ok:
        err("bot_token is empty in telegram_settings.json.")
        return False
    if not bot_py.exists():
        err("telegram_bot.py missing in project root.")
        return False

    vpy = root / "venv" / "bin" / "python"
    svc_user = ask("Service user", default="root", show_default=True).strip() or "root"
    svc_group = ask("Service group", default="root", show_default=True).strip() or "root"

    unit = f"""[Unit]
Description=WG Panel Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
EnvironmentFile={root}/.env
ExecStart={vpy} {root}/telegram_bot.py
Restart=always
RestartSec=2
User={svc_user}
Group={svc_group}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""
    path = Path("/etc/systemd/system/wg-panel-bot.service")
    _write(path, unit)
    ok(f"Wrote: {_paths(str(path))}")
    return True

def _service_option(root: Path):
    if not isitroot():
        err("Service setup requires sudo.")
        pause()
        return
    if not _project_ready(root):
        pause()
        return

    clear()
    header("PANEL Service", "create/restart + verify")
    print(box("Plan", [
        c("Creates/updates: ", BR_WHT) + c("/etc/systemd/system/wg-panel.service", BR_CYN),
        c("Uses: ", BR_WHT) + c("instance/panel_settings.json", BR_CYN) + " + " + c("instance/runtime.json", BR_CYN),
    ], border_color=BR_YEL))

    if not confirm("Continue?", default_yes=True):
        warn("Canceled.")
        pause()
        return

    if not _panel_service(root):
        pause()
        return

    _quick_bar(["systemctl", "daemon-reload"], "systemctl daemon-reload")
    _quick_bar(["systemctl", "enable", "wg-panel.service"], "Enable wg-panel.service")
    _quick_bar(["systemctl", "restart", "wg-panel.service"], "Restart wg-panel.service")
    rc, out = _quick_bar(["systemctl", "is-active", "wg-panel.service"], "Check wg-panel.service")
    st = (out.strip().splitlines()[-1] if out else _svc_active("wg-panel.service"))

    if st == "active":
        ok("wg-panel.service is active.")
    else:
        warn(f"wg-panel.service is {st}.")
        info("Logs: journalctl -u wg-panel --no-pager -n 160")
    pause()

def telegram_option(root: Path):
    if not isitroot():
        err("Telegram service setup requires sudo.")
        pause()
        return
    if not _project_ready(root):
        pause()
        return

    clear()
    header("TELEGRAM Service", "create/restart + verify")
    print(box("Plan", [
        c("Creates/updates: ", BR_WHT) + c("/etc/systemd/system/wg-panel-bot.service", BR_CYN),
        c("Requires: ", BR_WHT) + c("instance/telegram_settings.json (enabled+token)", BR_CYN),
    ], border_color=BR_YEL))

    if not confirm("Continue?", default_yes=True):
        warn("Canceled.")
        pause()
        return

    if not _bot_service(root):
        pause()
        return

    _quick_bar(["systemctl", "daemon-reload"], "systemctl daemon-reload")
    _quick_bar(["systemctl", "enable", "wg-panel-bot.service"], "Enable wg-panel-bot.service")
    _quick_bar(["systemctl", "restart", "wg-panel-bot.service"], "Restart wg-panel-bot.service")
    rc, out = _quick_bar(["systemctl", "is-active", "wg-panel-bot.service"], "Check wg-panel-bot.service")
    st = (out.strip().splitlines()[-1] if out else _svc_active("wg-panel-bot.service"))

    if st == "active":
        ok("wg-panel-bot.service is active.")
    else:
        warn(f"wg-panel-bot.service is {st}.")
        info("Logs: journalctl -u wg-panel-bot --no-pager -n 160")
    pause()


def _quick_setup():
    root = get_project()  
    clear()
    header("Panel Quick Setup", "recommended")
    print(box("What this will do", [
        c("1) Create venv + pip install (if missing)", BR_WHT),
        c("2) .env wizard", BR_WHT),
        c("3) panel_settings wizard", BR_WHT),
        c("4) runtime wizard", BR_WHT),
        c("5) Create/restart PANEL service + verify", BR_GRN),
    ], border_color=BR_YEL))

    if not confirm("Continue?", True):
        warn("Canceled.")
        pause()
        return

    if not (root / "requirements.txt").exists():
        warn("requirements.txt not found. Clone the repo first.")
        pause()
        return

    if not (root / "venv" / "bin" / "python").exists():
        _venv_requirements(root)
        root = get_project()

    env_setup(root)
    panel_settings(root)
    runtime(root)
    _service_option(root)

def telegram_setup():
    root = get_project()
    clear()
    header("Telegram Quick Setup", "optional")
    print(box("What this will do", [
        c("1) telegram_settings wizard", BR_WHT),
        c("2) Create/restart TELEGRAM service + verify", BR_GRN),
    ], border_color=BR_YEL))

    if not confirm("Continue?", True):
        warn("Canceled.")
        pause()
        return

    telegram_settings(root)
    telegram_option(root)

def install_everything():
    clear()
    header("Install Everything", "guided flow")
    print(box("Tips", [
        c("This runs a complete setup in the correct order.", BR_WHT),
        c("After clone, the chosen directory becomes your active project root.", BR_GRN),
        c("You can skip any step by answering n.", BR_YEL),
    ], border_color=BR_CYN))

    if not confirm("Continue?", True):
        warn("Canceled.")
        pause()
        return

    if confirm("Step 1: Install system requirements (apt)?", True):
        install_requirements()

    if confirm("Step 2: Git clone + set project directory?", True):
        clone_repo()

    root = get_project()  

    if confirm("Step 3: Create venv + pip install?", True):
        _venv_requirements(root)
        root = get_project()

    if confirm("Step 4: Create/Update .env?", True):
        env_setup(root)

    if confirm("Step 4b: Setup WireGuard interface now (create .conf + NAT)?", False):
        wireguard_setup(get_project())

    if confirm("Step 5: Create/Update panel_settings.json?", True):
        panel_settings(root)

    if confirm("Step 6: Create/Update runtime.json?", True):
        runtime(root)

    if confirm("Step 7: Create/Restart PANEL service + verify?", True):
        _service_option(root)

    if confirm("Optional: Configure Telegram now?", False):
        telegram_settings(root)
        if confirm("Optional: Create/Restart TELEGRAM service + verify?", True):
            telegram_option(root)

    ok("Install Everything flow completed.")
    pause()


def _menu_input(prompt: str = "Select option") -> str:
    return ask(prompt, default=None, show_default=False).strip()

def _edit_actions() -> List[str]:
    return [
        c("Actions:", BR_WHT),
        f"  {c('S', BR_GRN)} = Save & Exit",
        f"  {c('W', BR_CYN)} = Save (keep editing)",
        f"  {c('Q', BR_RED)} = Quit without saving",
    ]

def edit_env(root: Path):
    env_path = root / ".env"
    values = parse_env(readtext(env_path))
    values.setdefault("FLASK_SECRET_KEY", _gen_flask_secret())
    values.setdefault("FERNET_KEY", _gen_fernet_key())
    values.setdefault("API_KEY", _gen_api_key())
    values.setdefault("DATABASE_URL", "sqlite:///instance/wg_panel.db")
    values.setdefault("LOG_LEVEL", "INFO")
    values.setdefault("SECURE_COOKIES", "1")
    values.setdefault("WIREGUARD_CONF_PATH", "/etc/wireguard")
    values.setdefault("SETUP_TOKEN", "")
    values.setdefault("TG_HEARTBEAT_SEC", "60")

    def preview() -> str:
        return _env_text(values)

    while True:
        clear()
        header("Edit .env", _paths(str(env_path)))
        print(box_text("Live Preview", c(preview().rstrip("\n"), BR_WHT), border_color=BR_CYN))

        items = [
            c("Choose a field:", BR_WHT),
            f"{c('1)', BR_CYN)} FLASK_SECRET_KEY   {c('(regen)', BR_GRN)}",
            f"{c('2)', BR_CYN)} FERNET_KEY         {c('(regen)', BR_GRN)}",
            f"{c('3)', BR_CYN)} API_KEY            {c('(regen)', BR_GRN)}",
            f"{c('4)', BR_CYN)} DATABASE_URL",
            f"{c('5)', BR_CYN)} LOG_LEVEL",
            f"{c('6)', BR_CYN)} SECURE_COOKIES",
            f"{c('7)', BR_CYN)} WIREGUARD_CONF_PATH",
            f"{c('8)', BR_CYN)} SETUP_TOKEN",
            f"{c('9)', BR_CYN)} TG_HEARTBEAT_SEC",
            "",
            c("Extra:", BR_WHT),
            f"{c('R', BR_GRN)} Regenerate a key (1/2/3)",
            "",
        ] + _edit_actions()

        print(box("Edit .env", items, border_color=BR_YEL))
        ch = _menu_input().lower()

        if ch == "q":
            warn("Exited without saving.")
            pause()
            return

        if ch in ("s", "w"):
            _write(env_path, preview())
            ok(f"Saved: {_paths(str(env_path))}")
            if ch == "s":
                pause()
                return
            time.sleep(0.15)
            continue

        if ch == "r":
            which = _menu_input("Regenerate which key (1/2/3)")
            if which == "1":
                values["FLASK_SECRET_KEY"] = _gen_flask_secret()
                ok("Regenerated FLASK_SECRET_KEY.")
            elif which == "2":
                values["FERNET_KEY"] = _gen_fernet_key()
                ok("Regenerated FERNET_KEY.")
            elif which == "3":
                values["API_KEY"] = _gen_api_key()
                ok("Regenerated API_KEY.")
            else:
                warn("Invalid selection.")
            time.sleep(0.25)
            continue

        mapping = {
            "1": "FLASK_SECRET_KEY",
            "2": "FERNET_KEY",
            "3": "API_KEY",
            "4": "DATABASE_URL",
            "5": "LOG_LEVEL",
            "6": "SECURE_COOKIES",
            "7": "WIREGUARD_CONF_PATH",
            "8": "SETUP_TOKEN",
            "9": "TG_HEARTBEAT_SEC",
        }
        if ch in mapping:
            k = mapping[ch]
            values[k] = ask(f"Set {k}", default=values.get(k, ""), show_default=True)
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def _edit_json(title: str, path: Path, obj: dict, schema_fields: List[Tuple[str, str]]):
    def getp(d: dict, key_path: str):
        cur = d
        parts = key_path.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        return cur, parts[-1]

    def render_preview() -> str:
        return json.dumps(obj, indent=2, ensure_ascii=False)

    while True:
        clear()
        header(title, _paths(str(path)))
        print(box("Live Preview", [c(render_preview(), BR_WHT)], border_color=BR_CYN))

        lines: List[str] = [c("Choose a field (number):", BR_WHT)]
        for idx, (kp, th) in enumerate(schema_fields, start=1):
            parent, k = getp(obj, kp)
            v = parent.get(k)
            if th == "bool":
                v_txt = c("true", BR_GRN) if bool(v) else c("false", BR_RED)
            else:
                v_txt = c(str(v), BR_WHT)
            lines.append(f"{c(str(idx)+')', BR_CYN)} {kp} = {v_txt}")

        lines.append("")
        lines += _edit_actions()
        print(box("Edit", lines, border_color=BR_YEL))

        ch = _menu_input().lower()

        if ch == "q":
            warn("Exited without saving.")
            pause()
            return

        if ch in ("s", "w"):
            _writejson(path, obj)
            ok(f"Saved: {_paths(str(path))}")
            if ch == "s":
                pause()
                return
            time.sleep(0.15)
            continue

        if ch.isdigit():
            n = int(ch)
            if 1 <= n <= len(schema_fields):
                kp, th = schema_fields[n - 1]
                parent, k = getp(obj, kp)
                cur = parent.get(k)

                if th == "bool":
                    parent[k] = not bool(cur)
                    ok(f"Toggled {kp}.")
                    time.sleep(0.15)
                    continue
                if th == "int":
                    parent[k] = ask_int(f"Set {kp}", default=int(cur or 0), allow_blank=False, show_default=True) or 0
                    continue
                if th == "nullable_int":
                    v = ask_int(f"Set {kp} (blank=null)", default=None if cur is None else int(cur),
                                allow_blank=True, show_default=True)
                    parent[k] = v
                    continue
                parent[k] = ask(f"Set {kp}", default=str(cur or ""), show_default=True)
                continue

        warn("Invalid option.")
        time.sleep(0.25)

def edit_panelsettings(root: Path):
    path = root / "instance" / "panel_settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    obj = dict(PANEL_SETTINGS_DEFAULT)
    cur = load_json(path, {})
    if isinstance(cur, dict):
        obj.update(cur)

    schema = [
        ("tls_enabled", "bool"),
        ("domain", "str"),
        ("force_https_redirect", "bool"),
        ("hsts", "bool"),
        ("http_port", "nullable_int"),
        ("https_port", "int"),
        ("tls_cert_path", "str"),
        ("tls_key_path", "str"),
    ]
    _edit_json("Edit panel_settings.json", path, obj, schema)

def edit_runtime(root: Path):
    path = root / "instance" / "runtime.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    obj = dict(RUNTIME_DEFAULT)
    cur = load_json(path, {})
    if isinstance(cur, dict):
        obj.update(cur)

    schema = [
        ("bind", "str"),
        ("port", "int"),
        ("workers", "int"),
        ("threads", "int"),
        ("timeout", "int"),
        ("graceful_timeout", "int"),
        ("loglevel", "str"),
    ]
    _edit_json("Edit runtime.json", path, obj, schema)

def edit_telegramsettings(root: Path):
    path = root / "instance" / "telegram_settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    obj = json.loads(json.dumps(TELEGRAM_SETTINGS_DEFAULT))
    cur = load_json(path, {})
    if isinstance(cur, dict):
        obj["enabled"] = bool(cur.get("enabled", obj["enabled"]))
        obj["bot_token"] = str(cur.get("bot_token", obj["bot_token"]) or "")
        if isinstance(cur.get("notify"), dict):
            obj["notify"].update(cur["notify"])

    schema = [
        ("enabled", "bool"),
        ("bot_token", "str"),
        ("notify.app_down", "bool"),
        ("notify.iface_down", "bool"),
        ("notify.login_fail", "bool"),
        ("notify.suspicious_4xx", "bool"),
    ]
    _edit_json("Edit telegram_settings.json", path, obj, schema)


def preclone():
    notes = []
    if not isitroot():
        notes.append(c(f"{TAG_WARN} Not running as root. apt/services require sudo.", BR_YEL))
    if not _cmd("git"):
        notes.append(c(f"{TAG_WARN} git missing. Clone/update won’t work.", BR_YEL))
    if not _cmd("systemctl"):
        notes.append(c(f"{TAG_WARN} systemctl missing. Services menu won’t work.", BR_YEL))

    if notes:
        clear()
        header("Preflight", "Quick checks")
        print(box("Notes", notes, border_color=BR_YEL))
        pause()

def install_menu():
    while True:
        root = get_project()  
        clear()
        header("Install / Setup", "guided + advanced")
        print(render_status(root))
        print()

        print(box("Tips", [
            c("Recommended path:", BR_WHT) + " " + c("/usr/local/bin/WG_Panel", BR_CYN),
            c("Fastest start:", BR_WHT) + " " + c("Panel Quick Setup", BR_GRN),
            c("Telegram:", BR_WHT) + " " + c("do later with Telegram Quick Setup", BR_GRN),
        ], border_color=BR_CYN))
        print()

        items = [
            c("GUIDED (recommended)", BR_GRN),
            c("  1) Install Everything (full guided)", BR_GRN),
            c("  2) Panel Quick Setup (configure + service)", BR_GRN),
            c("  3) Telegram Quick Setup (optional)", BR_GRN),
            "",
            c("BASICS", BR_CYN),
            c("  4) Git clone + set project directory", BR_CYN),
            c("  5) Install system requirements (apt)", BR_CYN),
            c("  6) Create venv + pip install requirements.txt", BR_CYN),
            c("  7)  WireGuard: create/update .conf ", BR_CYN),
            "",
            c("CONFIG", BR_BLU),
            c("  8) Create/Update .env", BR_BLU),
            c("  9) Create/Update panel_settings.json", BR_BLU),
            c(" 10) Create/Update runtime.json", BR_BLU),
            c(" 11) Create/Update telegram_settings.json", BR_BLU),
            "",
            c("SERVICES", BR_YEL),
            c(" 12) PANEL service: create/restart + verify", BR_YEL),
            c(" 13) TELEGRAM service: create/restart + verify", BR_YEL),
            "",
            c("  0) Back", DIM),
        ]
        print(box("Install Menu", items, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
            install_everything()
        elif ch == "2":
            _quick_setup()
        elif ch == "3":
            telegram_setup()
        elif ch == "4":
            clone_repo()
        elif ch == "5":
            install_requirements()
        elif ch == "6":
            _venv_requirements(root)
        elif ch == "7":
            wireguard_setup(root)
        elif ch == "8":
            env_setup(root)
        elif ch == "9":
            panel_settings(root)
        elif ch == "10":
            runtime(root)
        elif ch == "11":
            telegram_settings(root)
        elif ch == "12":
            _service_option(root)
        elif ch == "13":
            telegram_option(root)
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def edit_menu():
    while True:
        root = get_project()
        clear()
        header("Edit", "live preview editors")
        print(render_status(root))
        print()

        items = [
            c("1) Edit .env (regenerate keys, live preview)", BR_CYN),
            c("2) Edit panel_settings.json", BR_CYN),
            c("3) Edit runtime.json", BR_CYN),
            c("4) Edit telegram_settings.json", BR_CYN),
            c("5) WireGuard configs (edit existing / add new)", BR_CYN),
            "",
            c("0) Back", DIM),
        ]
        print(box("Edit Menu", items, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
            edit_env(root)
        elif ch == "2":
            edit_panelsettings(root)
        elif ch == "3":
            edit_runtime(root)
        elif ch == "4":
            edit_telegramsettings(root)
        elif ch == "5":
            wireguard_edit(root)
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def _detect_svcuser() -> str:
    unit = Path("/etc/systemd/system/wg-panel.service")
    if unit.exists():
        try:
            for ln in unit.read_text(encoding="utf-8").splitlines():
                if ln.strip().startswith("User="):
                    return ln.split("=", 1)[1].strip() or "root"
        except Exception:
            pass
    return "root"

def _runtime_bind(root: Path) -> str:
    rt = load_json(root / "instance" / "runtime.json", {})
    bind = (rt.get("bind") or "").strip()
    if bind:
        return bind
    return "0.0.0.0:8000"

def _tls(root: Path) -> bool:
    ps = load_json(root / "instance" / "panel_settings.json", {})
    tls_enabled = bool(ps.get("tls_enabled"))
    cert = str(ps.get("tls_cert_path") or "").strip()
    key  = str(ps.get("tls_key_path") or "").strip()
    if not tls_enabled:
        return False
    if not cert or not key:
        return False
    return Path(cert).is_file() and Path(key).is_file()


def _panel_urls(root: Path) -> dict:
    rt = load_json(root / "instance" / "runtime.json", {})
    bind = (rt.get("bind") or "").strip() or "0.0.0.0:8000"
    host, port = (bind.split(":", 1) + ["8000"])[:2]
    host = host.strip() or "0.0.0.0"
    port = port.strip() or "8000"

    ps = load_json(root / "instance" / "panel_settings.json", {})
    domain = (ps.get("domain") or "").strip()
    tls_eff = _tls(root)
    scheme = "https" if tls_eff else "http"

    if domain:
        browse_host = domain
    else:
        browse_host = "127.0.0.1" if host in ("0.0.0.0", "*") else host

    show_port = True
    try:
        p = int(port)
        if (scheme == "https" and p == 443) or (scheme == "http" and p == 80):
            show_port = False
    except Exception:
        pass

    base = f"{scheme}://{browse_host}" + (f":{port}" if show_port else "")
    return {
        "scheme": scheme,
        "bind": bind,
        "base": base,
        "login": f"{base}/login",
        "settings": f"{base}/settings",
    }


def _admin_usernames(root: Path) -> list[str]:

    db = root / "instance" / "wg_panel.db"
    if not db.exists():
        return []
    try:
        import sqlite3
        con = sqlite3.connect(str(db))
        cur = con.cursor()

        for q in (
            "SELECT username FROM user WHERE is_admin=1 OR is_superuser=1",
            "SELECT username FROM users WHERE is_admin=1 OR is_superuser=1",
            "SELECT username FROM user",
            "SELECT username FROM users",
        ):
            try:
                cur.execute(q)
                rows = [r[0] for r in cur.fetchall() if r and r[0]]
                if rows:
                    con.close()
                    out = []
                    for x in rows:
                        if x not in out:
                            out.append(x)
                    return out
            except Exception:
                continue
        con.close()
        return []
    except Exception:
        return []


def _svc_action(name: str, action: str):
    if not _cmd("systemctl"):
        err("systemctl not available.")
        return
    _quick_bar(["systemctl", action, name], f"{action} {name}")

def _svc_logs(name: str, lines: int = 160):
    if not _cmd("journalctl"):
        err("journalctl not available.")
        return
    clear()
    header("Service Logs", name)
    _live(["journalctl", "-u", name, "--no-pager", "-n", str(lines)], f"journalctl -u {name} -n {lines}")
    pause()

def _sys_status(name: str) -> str:
    if not _cmd("systemctl"):
        return "systemctl not available"
    try:
        out = subprocess.check_output(["systemctl", "is-active", name], text=True).strip()
        return out
    except Exception:
        return "unknown"


def _svc_detail(svc: str):
    while True:
        clear()
        header("Service", svc)

        state = _sys_status(svc)
        st_color = BR_GRN if state == "active" else (BR_YEL if state in ("activating", "reloading") else BR_RED)

        lines = [
            f"{TAG_INFO} Status: {c(state, st_color)}",
            "",
            c("Actions", BR_YEL),
            c("  1) Restart", BR_YEL),
            c("  2) Stop", BR_YEL),
            "",
            c("Logs", BR_CYN),
            c("  3) Show last 160 lines", BR_CYN),
            c("  4) Follow (live) logs", BR_CYN),
            "",
            c("  0) Back", DIM),
        ]
        print(box("Service Control", lines, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
            _svc_action(svc, "restart")
            time.sleep(0.2)
        elif ch == "2":
            _svc_action(svc, "stop")
            time.sleep(0.2)
        elif ch == "3":
            _svc_logs(svc, lines=160)
        elif ch == "4":
            clear()
            header("Service Logs (follow)", svc)
            try:
                subprocess.run(["journalctl", "-u", svc, "-f", "--no-pager"])
            except KeyboardInterrupt:
                pass
            pause()
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)


def services_status(root: Path):
    while True:
        clear()
        header("Status", "choose service")
        print(render_status(root))
        print()

        s1 = _sys_status("wg-panel.service")
        s2 = _sys_status("wg-panel-bot.service")

        items = [
            c("1) wg-panel.service", BR_YEL) + "  " + c(f"[{s1}]", BR_GRN if s1=="active" else BR_RED),
            c("2) wg-panel-bot.service", BR_YEL) + "  " + c(f"[{s2}]", BR_GRN if s2=="active" else BR_RED),
            "",
            c("0) Back", DIM),
        ]
        print(box("Status Menu", items, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
            _svc_detail("wg-panel.service")
        elif ch == "2":
            _svc_detail("wg-panel-bot.service")
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def _admin_table(cur) -> str | None:

    try:
        rows = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names = [r[0] for r in rows if r and r[0]]
    except Exception:
        return None

    for cand in ("admin_account", "AdminAccount", "admin_accounts", "admins", "admin"):
        if cand in names:
            return cand

    for n in names:
        ln = n.lower()
        if "admin" in ln and "account" in ln:
            return n

    return None


def _list_usernames(root: Path) -> list[str]:
    db = root / "instance" / "wg_panel.db"
    if not db.exists():
        return []
    try:
        con = sqlite3.connect(str(db))
        cur = con.cursor()
        tbl = _admin_table(cur)
        if not tbl:
            con.close()
            return []
        rows = cur.execute(f"SELECT username FROM {tbl}").fetchall()
        con.close()
        out = []
        for r in rows:
            if r and r[0] and r[0] not in out:
                out.append(str(r[0]))
        return out
    except Exception:
        return []


def reset_password(root: Path):

    db = root / "instance" / "wg_panel.db"
    if not db.exists():
        err(f"Database not found: {_paths(str(db))}")
        warn("Start the panel once to initialize the DB, or verify DATABASE_URL points to this file.")
        pause()
        return

    clear()
    header("Reset Admin Password", _paths(str(db)))

    admins = _list_usernames(root)

    if admins:
        print(box("Detected admin usernames", [f" - {c(u, BR_WHT)}" for u in admins], border_color=BR_CYN))
    else:
        print(box("Detected admin usernames", [
            c("None detected (table name may differ, or DB not initialized).", BR_YEL),
            c("You can still type the username manually.", BR_WHT),
        ], border_color=BR_YEL))

    default_user = admins[0] if admins else ""
    username = ask("Admin username", default=default_user, show_default=bool(default_user)).strip()
    if not username:
        warn("Canceled (no username).")
        pause()
        return

    print()
    info("Enter a NEW password (input hidden).")
    p1 = getpass.getpass(f"{BR_YEL}New password:{BR_WHT} ")
    p2 = getpass.getpass(f"{BR_YEL}Confirm password:{BR_WHT} ")

    if not p1 or p1 != p2:
        err("Password empty or mismatch.")
        pause()
        return

    try:
        from passlib.context import CryptContext
        pwd_ctx = CryptContext(
            schemes=["pbkdf2_sha256", "bcrypt_sha256", "bcrypt"],
            deprecated="auto"
        )
        new_hash = pwd_ctx.hash(p1.strip())
    except Exception as e:
        err(f"Hashing failed: {e}")
        pause()
        return

    try:
        con = sqlite3.connect(str(db))
        cur = con.cursor()
        tbl = _admin_table(cur)
        if not tbl:
            con.close()
            err("Could not find admin accounts table in DB.")
            warn("Your schema may differ. Paste sqlite schema and I’ll adapt it.")
            pause()
            return

        row = cur.execute(f"SELECT id FROM {tbl} WHERE username = ?", (username,)).fetchone()

        if not row:
            con.close()
            err(f"Admin username not found: {username}")
            pause()
            return

        cur.execute(f"UPDATE {tbl} SET password_hash = ? WHERE username = ?", (new_hash, username))
        con.commit()
        con.close()

        ok(f"Password reset for: {c(username, BR_WHT)}")
        print()
        if confirm("Restart panel services now?", default_yes=True):
            if _cmd("systemctl"):
                _quick_bar(["systemctl", "restart", "wg-panel.service"], "Restart wg-panel.service")
                _quick_bar(["systemctl", "restart", "wg-panel-bot.service"], "Restart wg-panel-bot.service")
            else:
                warn("systemctl not available. Restart services manually.")
        pause()
    except Exception as e:
        err(f"DB update failed: {e}")
        pause()

def info_menu():
    while True:
        root = get_project()
        clear()
        header("Status & Information", "overview + controls")
        print(render_status(root))
        print()

        items = [
            c("1) Information (URLs, scheme, admin users)", BR_BLU),
            c("2) Status (pick service → actions + logs)", BR_GRN),
            c("3) Reset admin password", BR_RED),
            "",
            c("0) Back", DIM),
        ]
        print(box("Status & Information", items, border_color=BR_CYN))

        ch = _menu_input()
        if ch == "1":
            information_page(root)
        elif ch == "2":
            services_status(root)
        elif ch == "3":
            reset_password(root)
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)


def information_page(root: Path):
    clear()
    header("Information", "panel + access") 

    urls = _panel_urls(root)
    admins = _admin_usernames(root)

    svc_user = _detect_svcuser()

    bind = str(urls.get("bind") or "")
    try:
        port = (bind.split(":", 1) + ["8000"])[1].strip() or "8000"
    except Exception:
        port = "8000"
    tunnel = f"ssh -L {port}:127.0.0.1:{port} root@YOUR_SERVER_IP"

    scheme = str(urls.get("scheme") or "http").lower()
    scheme_badge = c("HTTPS", BR_GRN) if scheme == "https" else c("HTTP", BR_YEL)

    lines: list[str] = []
    lines.append(f"{TAG_INFO} Project root: {c(_paths(str(root)), BR_CYN)}")
    lines.append(f"{TAG_INFO} Service user: {c(svc_user, BR_WHT)}")
    lines.append("")

    lines.append(f"{TAG_INFO} Bind:   {c(str(urls.get('bind') or 'unknown'), BR_WHT)}")
    lines.append(f"{TAG_INFO} URL:    {scheme_badge}  " + c(str(urls.get("base") or ""), BR_WHT))
    lines.append("")

    lines.append(c("Panel URLs (local):", BR_GRN))
    base = str(urls.get("base") or "")
    if base:
        lines.append("  - " + c(base + "/", BR_WHT))
    login = str(urls.get("login") or "")
    if login:
        lines.append("  - " + c(login, BR_WHT))
    settings = str(urls.get("settings") or "")
    if settings:
        lines.append("  - " + c(settings, BR_WHT))
    lines.append("")

    lines.append(c("Admin accounts:", BR_CYN))
    if admins:
        for u in admins:
            lines.append("  - " + c(u, BR_WHT))
    else:
        lines.append("  - " + c("Not detected (DB schema may differ).", DIM))

    lines.append("  - " + c("Password cannot be displayed (stored hashed).", DIM))
    lines.append("  - " + c("Use: Status & Information → Reset admin password", BR_YEL))
    lines.append("")

    lines.append(c("Recommended access from your PC (SSH tunnel):", BR_YEL))
    lines.append("  " + c(tunnel, BR_WHT))

    print(box("Information", lines, border_color=BR_CYN))

    print()
    if confirm("Reset admin password now?", default_yes=False):
        reset_password(root)
    else:
        pause()


def update_menu():
    while True:
        root = get_project()
        clear()
        header("Update", "safe git updates")
        print(render_status(root))
        print()

        items = [
            c("1) Git pull project (fast-forward only)", BR_YEL),
            c("2) Show git status", BR_CYN),
            "",
            c("0) Back", DIM),
        ]
        print(box("Update Menu", items, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
            if not _cmd("git"):
                err("git not installed.")
                pause()
                continue
            if not (root / ".git").exists():
                err("Project root is not a git repo. Clone first.")
                pause()
                continue
            _live(["git", "-C", str(root), "pull", "--ff-only"], "git pull --ff-only")
            pause()
        elif ch == "2":
            if not _cmd("git") or not (root / ".git").exists():
                warn("Not a git repo.")
                pause()
                continue
            _live(["git", "-C", str(root), "status"], "git status")
            pause()
        elif ch == "0":
            return
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def _disable_remove_service(name: str):
    if not _cmd("systemctl"):
        warn("systemctl not available.")
        return
    _quick_bar(["systemctl", "stop", name], f"Stop {name}")
    _quick_bar(["systemctl", "disable", name], f"Disable {name}")
    unit = Path("/etc/systemd/system") / name
    if unit.exists():
        try:
            unit.unlink()
            ok(f"Removed unit: {_paths(str(unit))}")
        except Exception:
            warn(f"Could not remove unit: {_paths(str(unit))}")
    _quick_bar(["systemctl", "daemon-reload"], "systemctl daemon-reload")

def uninstall_menu():
    while True:
        root = get_project()
        clear()
        header("Uninstall", "remove parts or everything")
        print(render_status(root))
        print()

        items = [
            c("DANGEROUS", BR_RED),
            c("  1) Uninstall EVERYTHING (services + project folder + root marker)", BR_RED),
            "",
            c("PARTIAL", BR_YEL),
            c("  2) Remove services only", BR_YEL),
            c("  3) Remove project folder only", BR_YEL),
            c("  4) Remove venv only", BR_YEL),
            c("  5) Remove instance configs only (instance/*.json)", BR_YEL),
            c("  6) Clear saved root marker (~/.wg_panel_root.json)", BR_YEL),
            "",
            c("  0) Back", DIM),
        ]
        print(box("Uninstall Menu", items, border_color=BR_RED))

        ch = _menu_input()

        if ch == "0":
            return

        if ch == "2" or ch == "1":
            if not isitroot():
                err("Service removal requires sudo.")
                pause()
                continue
            if confirm("Remove wg-panel.service and wg-panel-bot.service?", default_yes=True):
                _disable_remove_service("wg-panel.service")
                _disable_remove_service("wg-panel-bot.service")
            pause()
            if ch == "2":
                continue

        if ch == "4":
            venv_dir = root / "venv"
            if venv_dir.exists() and confirm(f"Delete {_paths(str(venv_dir))} ?", True):
                shutil.rmtree(venv_dir, ignore_errors=True)
                ok("venv removed.")
            pause()
            continue

        if ch == "5":
            inst = root / "instance"
            if inst.exists() and confirm(f"Delete instance configs in {_paths(str(inst))} ?", False):
                for p in ["panel_settings.json", "runtime.json", "telegram_settings.json", "backup_schedule.json", "tg_backup_state.json"]:
                    try:
                        fp = inst / p
                        if fp.exists():
                            fp.unlink()
                    except Exception:
                        pass
                ok("Instance config files removed (where present).")
            pause()
            continue

        if ch == "6":
            if ROOT_MARKER.exists() and confirm(f"Delete {_paths(str(ROOT_MARKER))} ?", True):
                try:
                    ROOT_MARKER.unlink()
                    ok("Root marker removed.")
                except Exception:
                    err("Could not remove root marker.")
            pause()
            continue

        if ch == "3" or ch == "1":
            if root.exists():
                if confirm(f"Delete project folder {_paths(str(root))} ?", default_yes=False):
                    shutil.rmtree(root, ignore_errors=True)
                    ok("Project folder removed.")
                else:
                    warn("Canceled.")
            else:
                warn("Project folder not found.")
            if ch == "1":
                try:
                    if ROOT_MARKER.exists():
                        ROOT_MARKER.unlink()
                except Exception:
                    pass
                ok("Uninstall EVERYTHING completed.")
            pause()
            continue

        warn("Invalid option.")
        time.sleep(0.25)


def _already_installed(target: Path, script_path: Path) -> bool:
    if not target.exists():
        return False
    try:
        txt = target.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return True  
    return str(script_path) in txt


def _wg_binary():

    try:
        p = Path("/usr/local/bin/wg")
        if not p.exists():
            return
        txt = ""
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        script_path = str(Path(__file__).resolve())
        if script_path in txt:
            bak = Path("/usr/local/bin/wgpanel-legacy-wg-wrapper")
            try:
                if bak.exists():
                    bak.unlink()
                p.rename(bak)
                warn("Detected poisoned /usr/local/bin/wg (wrapper). Moved to wgpanel-legacy-wg-wrapper.")
                warn("WireGuard `wg` will now use the real binary (usually /usr/bin/wg).")
            except Exception:
                pass
    except Exception:
        pass


def _wgpanel_command(root: Path):

    target = Path("/usr/local/bin/wgpanel")
    script_path = Path(__file__).resolve()

    if _already_installed(target, script_path):
        return

    if not isitroot():
        return

    vpy = root / "venv" / "bin" / "python"
    py = str(vpy) if vpy.exists() else "/usr/bin/env python3"

    wrapper = f"""#!/usr/bin/env bash
exec "{py}" "{script_path}" "$@"
"""

    try:
        _write(target, wrapper)
        target.chmod(0o755)
    except Exception:
        return


def main_menu():
    while True:
        root = get_project()
        clear()
        print(c("WG Panel Control", BR_WHT + BOLD) + "  " + c("Azumi67/WG_Panel", BR_CYN))
        print(hr("═", BR_CYN))
        print(render_status(root))
        print()

        items = [
        c("1) Status & Information", BR_BLU),
        c("2) Install / Setup", BR_GRN),
        c("3) Edit", BR_CYN),
        c("4) Update", BR_YEL),
        c("5) Uninstall", BR_RED),
        c("0) Exit", DIM),
        ]
        print(box("Main Menu", items, border_color=BR_YEL))

        ch = _menu_input()
        if ch == "1":
           info_menu()
        elif ch == "2":
           install_menu()
        elif ch == "3":
            edit_menu()
        elif ch == "4":
            update_menu()
        elif ch == "5":
            uninstall_menu()
        elif ch == "0":
            clear()
            info("Exiting..")
            return
        else:
            warn("Wrong option")
            time.sleep(0.25)



if __name__ == "__main__":
    root = get_project()

    _wg_binary()
    _wgpanel_command(root)
    preclone()
    main_menu()

