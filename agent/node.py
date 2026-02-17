#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import io
import re
import sys
import json
import time
import shutil
import signal
import socket
import tarfile
import ssl
import threading
import http.server
import socketserver
from datetime import datetime
import subprocess
import base64
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
        s = input(_prompt(label, default, show_default)).strip()
        return s if s else (default or "")
    except (KeyboardInterrupt, EOFError):
        _exit()

def confirm(label: str, default_yes: bool = True) -> bool:
    try:
        lm = left_margin()
        yn = (f"{c('Y', BR_GRN)}/{c('n', BR_RED)}" if default_yes else f"{c('y', BR_GRN)}/{c('N', BR_RED)}")
        d  = (c("[Y]", BR_GRN) if default_yes else c("[N]", BR_RED))
        prompt = f"{lm}{c(label, BR_CYN)} ({yn}) {d}{c(': ', BR_YEL)}{BR_WHT}"
        s = input(prompt).strip().lower()
        if not s:
            return default_yes
        return s.startswith('y')
    except (KeyboardInterrupt, EOFError):
        _exit()


def _action(title: str, fn):
    try:
        fn()
    except SystemExit:
        raise
    except Exception as e:
        err(f"{title} failed: {type(e).__name__}: {e}")
        print(box("Tips", [
            c("Run as root (sudo) for install/uninstall/service actions.", BR_WHT),
            c("Check required commands (git, python3, systemctl, wg-quick).", BR_WHT),
            c("Verify paths and permissions.", BR_WHT),
        ], BR_CYN))
        pause()



AGENT_DIR = Path(__file__).resolve().parent
ROOT_MARKER = Path.home() / ".wg_node_root.json"

DEFAULT_CLONE_DIR = Path("/usr/local/bin/wg_panel")
DEFAULT_GIT_URL = "https://github.com/Azumi67/WG_Panel.git"

def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(p)

def _root() -> Path:
    if ROOT_MARKER.exists():
        try:
            d = json.loads(ROOT_MARKER.read_text(encoding="utf-8"))
            p = Path(d.get("root", "")).expanduser().resolve()
            if p.exists():
                return p
        except Exception:
            pass
    return AGENT_DIR.parent

def set_root(p: Path):
    _write(ROOT_MARKER, json.dumps({"root": str(p.resolve())}, indent=2) + "\n")

def agent_dir(root: Path) -> Path:
    return (root / "agent").resolve()

def _cmd(x: str) -> bool:
    return shutil.which(x) is not None

def _live(cmd: List[str], title: str = "", timeout: int | None = None) -> int:
    if title:
        print(left_margin() + c(f"{TAG_RUN} ", BR_CYN) + c(title, BR_WHT))

    env = os.environ.copy()
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("NEEDRESTART_MODE", "a")
    env.setdefault("GIT_TERMINAL_PROMPT", "0")

    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
            bufsize=1,
            universal_newlines=True,
        )
        start = time.time()
        assert p.stdout is not None
        for line in p.stdout:
            print(left_margin() + c(line.rstrip("\n"), BR_WHT))
            if timeout and (time.time() - start) > timeout:
                p.kill()
                err(f"Timeout after {timeout}s: {' '.join(cmd)}")
                return 124
        return p.wait()
    except Exception as e:
        err(f"runing live failed: {e}")
        return 1

def run(cmd: List[str], title: str = "") -> int:
    if title:
        print(left_margin() + c(f"{TAG_RUN} ", BR_CYN) + c(title, BR_WHT))

    env = os.environ.copy()
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("NEEDRESTART_MODE", "a")  

    return subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL).returncode


def run_out(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr

def git_quick(root: Path) -> str:
    try:
        if not (root / ".git").exists() or not _cmd("git"):
            return "N/A"
        rc1, branch, _ = run_out(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"])
        rc2, sha, _    = run_out(["git", "-C", str(root), "rev-parse", "--short", "HEAD"])
        rc3, dirty, _  = run_out(["git", "-C", str(root), "status", "--porcelain"])
        if rc1 != 0 or rc2 != 0:
            return "N/A"
        branch = (branch or "").strip()
        sha = (sha or "").strip()
        is_dirty = bool((dirty or "").strip())
        state = c("dirty", BR_YEL) if is_dirty else c("clean", BR_GRN)
        return f"{c(branch, BR_WHT)}@{c(sha, BR_WHT)} {state}"
    except Exception:
        return "N/A"

def isitroot() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def git_clone_to(dest: Path, url: str):
    dest = dest.expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        try:
            if dest.is_dir() and any(dest.iterdir()):
                warn(f"Destination not empty: {dest}")
                return
        except Exception:
            warn(f"Cannot read destination: {dest}")
            return

    run(["git", "clone", url, str(dest)], "git clone")


def install_requirements(root: Path):
    if not isitroot():
        err("Install requires sudo/root.")
        pause()
        return

    a = agent_dir(root)
    req = a / "requirements.txt"
    if not req.exists():
        err(f"Missing: {_paths(str(req))}")
        warn("TIP: Clone the repo correctly first (Install -> option 1).")
        pause()
        return

    run(["apt-get","update","-y"], "apt-get update")
    run(["apt-get","install","-y",
     "-o","Dpkg::Options::=--force-confnew",
     "git","curl","ca-certificates","python3-venv","python3-pip","iptables","iproute2"],
    "system deps")

    venv = a / "venv"
    pip  = venv / "bin" / "pip"
    if not venv.exists():
        run(["python3","-m","venv",str(venv)], "create agent venv")

    run([str(pip),"install","-U","pip","wheel"], "pip upgrade")
    rc = _live([str(pip), "install", "-r", str(req)], "pip install (live)", timeout=1200)
    if rc != 0:
        err("pip install failed.")
        warn("TIP: Check output above. Often fixed by: pip install -U pip wheel setuptools")
        pause()
        return

    ok("Requirements installed.")
    pause()


def _wireguard_installed() -> bool:
    if _cmd("wg") and _cmd("wg-quick"):
        return True
    if not isitroot():
        err("WireGuard install requires sudo/root.")
        return False
    run(["apt-get","update","-y"], "apt-get update")
    run(["apt-get","install","-y","wireguard","wireguard-tools"], "install wireguard")
    return _cmd("wg") and _cmd("wg-quick")

def _ip_forwarding():
    if not isitroot():
        return
    sysctl = Path("/etc/sysctl.d/99-wg-node.conf")
    _write(sysctl, "net.ipv4.ip_forward=1\n")
    subprocess.run(["sysctl","-p",str(sysctl)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def gen_keypair() -> Tuple[str,str]:
    priv = subprocess.check_output(["wg","genkey"]).decode().strip()
    pub  = subprocess.check_output(["wg","pubkey"], input=(priv+"\n").encode()).decode().strip()
    return priv, pub

def _default_iface() -> str:
    try:
        rc,out,_ = run_out(["sh","-lc","ip route show default 0.0.0.0/0 | awk '{print $5}' | head -n1"])
        d = out.strip()
        return d if d else "eth0"
    except Exception:
        return "eth0"

def wg_dir() -> Path:
    return Path("/etc/wireguard")

def list_confs() -> List[Path]:
    d = wg_dir()
    if not d.exists():
        return []
    return sorted([p for p in d.glob("*.conf") if p.is_file()])

def _wg_conf(address: str, listen_port: str, privkey: str, egress: str, dns: str = "", mtu: str = "") -> str:
    post_up   = f"iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {egress} -j MASQUERADE"
    post_down = f"iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {egress} -j MASQUERADE"
    lines = ["[Interface]",
             f"Address = {address}",
             f"ListenPort = {listen_port}",
             f"PrivateKey = {privkey}"]
    if mtu.strip(): lines.append(f"MTU = {mtu.strip()}")
    if dns.strip(): lines.append(f"DNS = {dns.strip()}")
    lines += [f"PostUp = {post_up}",
              f"PostDown = {post_down}",
              ""]
    return "\n".join(lines)

def wg_flow():
    if not _wireguard_installed():
        pause()
        return
    _ip_forwarding()
    d = wg_dir()
    d.mkdir(parents=True, exist_ok=True)

    confs = list_confs()
    clear()
    header("Wireguard", "add new or edit existing")
    lines = [f"Config dir: {c(_paths(str(d)), BR_WHT)}"]
    if confs:
        lines += ["", c("Existing configs:", BR_CYN)]
        for p in confs[:10]:
            lines.append(" - " + c(p.name, BR_WHT))
    else:
        lines += ["", c("No configs found.", BR_YEL)]
    print(box("Wireguard", lines, BR_CYN))
    print()

    while True:
        print(left_margin() + c("1)", BR_WHT) + " " + c("Add new", BR_GRN) + "   " +
              c("2)", BR_WHT) + " " + c("Edit existing", BR_CYN))
        mode = input(left_margin() + c("Select option", BR_YEL) + c(": ", BR_YEL) + BR_WHT).strip()
        if mode in ("1","2"):
            break
        warn("Please enter 1 or 2 (no default).")


    if mode == "1":
        iface = ask("Interface name (e.g. wg0, wg1)", "wg0", True).strip()
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}", iface):
            err("Invalid interface name.")
            pause()
            return
        conf_path = d / f"{iface}.conf"
        if conf_path.exists():
            err("Config already exists.")
            pause()
            return

        print(hr("─", DIM))
        info("Enter interface settings")
        addr = ask("Address (e.g. 10.10.10.1/24)", "10.10.10.1/24", True)
        port = ask("ListenPort", "51820", True)
        dns  = ask("DNS (optional)", "", True)
        mtu  = ask("MTU (optional)", "", True)
        egr  = ask("Interface for NAT", _default_iface(), True)

        priv, pub = gen_keypair()
        ok(f"PublicKey: {pub}")

        conf_text = _wg_conf(addr, port, priv, egr, dns, mtu)

        clear()
        header("Preview", conf_path.name)
        print(box_text("wg conf", c(conf_text.rstrip("\n"), BR_WHT), BR_CYN))

        if not confirm("Save this config?", True):
            warn("Canceled.")
            pause()
            return

        _write(conf_path, conf_text + "\n")
        try: conf_path.chmod(0o600)
        except Exception: pass
        ok(f"Saved: {_paths(str(conf_path))}")

        if confirm(f"wg-quick up {iface} now?", True):
            run(["wg-quick","up",iface], f"wg-quick up {iface}")
            if _cmd("systemctl") and confirm(f"Enable wg-quick@{iface} at boot?", True):
                run(["systemctl","enable",f"wg-quick@{iface}.service"], "systemctl enable")
        pause()
        return

    if not confs:
        err("No existing configs.")
        pause()
        return

    for i,p in enumerate(confs, 1):
        print(left_margin() + c(f"{i}) ", BR_YEL) + c(p.name, BR_WHT))
    while True:
        sel = input(left_margin() + c("Select number", BR_YEL) + c(": ", BR_YEL) + BR_WHT).strip()
        if sel and sel.isdigit() and 1 <= int(sel) <= len(confs):
            break
        warn("Enter a valid number (no default).")
    try:
        conf_path = confs[int(sel)-1]
    except Exception:
        err("Invalid selection.")
        pause()
        return

    iface = conf_path.stem
    if confirm(f"wg-quick down {iface} before edit?", True):
        run(["wg-quick","down",iface], f"wg-quick down {iface}")

    editor = os.getenv("EDITOR") or "nano"
    clear()
    header("Editing", _paths(str(conf_path)))
    info(f"Editor: {editor}")
    time.sleep(0.3)

    try:
        subprocess.run([editor, str(conf_path)])
    except Exception as e:
        err(f"Could not open editor: {e}")
        warn("TIP: Install nano/vim or set EDITOR.")
        pause()
        return

    if confirm(f"wg-quick up {iface} now?", True):
        run(["wg-quick","up",iface], f"wg-quick up {iface}")
    pause()


AGENT_ENV_KEYS = [
    "API_KEY",
    "WIREGUARD_CONF_PATH",
    "BIND",
    "AGENT_SSL_CERT",
    "AGENT_SSL_KEY",
    "AGENT_SSL_CA",
    "WORKERS",
    "THREADS",
    "TIMEOUT",
    "GRACEFUL_TIMEOUT",
    "LOGLEVEL",
]

def _env(text: str) -> Dict[str, str]:
    out: Dict[str,str] = {}
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k,v = s.split("=", 1)
        out[k.strip()] = v.strip()
    return out

_BIND_RE = re.compile(
    r"^(?:(\[[0-9a-fA-F:]+\])|((?:\d{1,3}\.){3}\d{1,3})):(\d{1,5})$"
)

def _bind(s: str) -> bool:
    m = _BIND_RE.match((s or "").strip())
    if not m:
        return False
    try:
        port = int(m.group(3))
    except Exception:
        return False
    return 1 <= port <= 65535



def make_env(v: Dict[str, str]) -> str:

    order = [
        "API_KEY",
        "WIREGUARD_CONF_PATH",
        "BIND",
        "AGENT_SSL_CERT",
        "AGENT_SSL_KEY",
        "AGENT_SSL_CA",
        "WORKERS",
        "THREADS",
        "TIMEOUT",
        "GRACEFUL_TIMEOUT",
        "LOGLEVEL",
    ]

    lines: List[str] = []
    for k in order:
        val = (v.get(k, "") or "").strip()
        lines.append(f"{k}={val}")
    return "\n".join(lines) + "\n"

def _certbot() -> bool:
    if _cmd("certbot"):
        return True
    if not isitroot():
        return False

    info("Installing certbot (required for automatic TLS)...")
    rc = _live(["apt-get", "update", "-y"], "apt-get update (live)", timeout=900)
    if rc != 0:
        err("apt-get update failed.")
        warn("TIP: Check DNS / network / apt sources. Try: apt-get update -y (manual).")
        return False

    rc = _live(["apt-get", "install", "-y", "certbot"], "apt-get install certbot (live)", timeout=1200)
    if rc != 0:
        err("certbot install failed.")
        warn("TIP: Try: apt-get install -y certbot (manual) to see the exact error.")
        return False

    if not _cmd("certbot"):
        err("certbot still not found after install.")
        warn("TIP: On some distros, certbot may be packaged differently. Search: apt-cache search certbot")
        return False

    ok("certbot installed.")
    return True

def tls_certbot(root: Path):
    if not isitroot():
        err("TLS setup requires sudo/root.")
        pause()
        return

    a = agent_dir(root)
    env_path = a / ".env"
    cur = _env(env_path.read_text(encoding="utf-8") if env_path.exists() else "")

    clear()
    header("TLS", "certbot standalone (port 80 must be free)")
    print(box("Tips", [
        "• Stop nginx/apache if they use port 80",
        "• Ensure DNS A record points to this node",
        "• We'll write fullchain.pem/privkey.pem into agent/.env",
    ], BR_CYN))
    print()

    domain = ask("Domain", "", False).strip()
    email  = ask("Email", "", False).strip()
    if not domain or not email:
        warn("Domain/email required.")
        pause()
        return

    if not _certbot():
        err("certbot not available.")
        warn("TIP: Install certbot or run Install requirements first.")
        pause()
        return

    if not confirm("Run certbot now?", True):
        return

    rc = _live(["certbot","certonly","--standalone","-d",domain,"-m",email,"--agree-tos","--non-interactive"], "certbot (live)", timeout=900)
    _live(["bash","-lc","tail -n 25 /var/log/letsencrypt/letsencrypt.log 2>/dev/null || true"], "certbot log tail", timeout=30)
    if rc != 0:
        err("Certbot failed.")
        warn("TIP: Ensure port 80 is free (stop nginx/apache), DNS A/AAAA points to this server, and firewall allows inbound 80.")
        warn("TIP: See logs: /var/log/letsencrypt/letsencrypt.log")
        pause()
        return

    cur["AGENT_SSL_CERT"] = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    cur["AGENT_SSL_KEY"]  = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    cur.setdefault("AGENT_SSL_CA","")
    b = cur.get("BIND", "0.0.0.0:9898")
    if b.endswith(":9898"):
        cur["BIND"] = b.replace(":9898", ":8443")

    _write(env_path, make_env(cur) + "\n")
    ok("TLS paths written to agent/.env")
    pause()

def _wizard(root: Path) -> dict:
    a = agent_dir(root)
    env_path = a / ".env"
    cur = _env(env_path.read_text(encoding="utf-8") if env_path.exists() else "")

    v = {k: cur.get(k, "") for k in AGENT_ENV_KEYS}

    v["WIREGUARD_CONF_PATH"] = (v.get("WIREGUARD_CONF_PATH") or "/etc/wireguard").strip()

    api_raw = (v.get("API_KEY") or "").strip()
    api_low = api_raw.lower().lstrip("#").strip()
    api_is_placeholder = (
        (not api_raw)
        or api_low in {"your-node-api-key", "changeme", "change-me"}
        or api_raw.strip().startswith("#")
    )
    if api_is_placeholder:
        v["API_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

    tls_paths_set = bool((v.get("AGENT_SSL_CERT") or "").strip() and (v.get("AGENT_SSL_KEY") or "").strip())
    certbot_done = False

    clear()
    header("Agent Env", "minimal + correct")
    print(box("Tips", [
        "• Panel uses: Authorization: Bearer API_KEY",
        "• BIND must be entered by you (host:port).",
        "• TLS is optional. If enabled, certs can be obtained via certbot.",
    ], BR_CYN))
    print()

    info("REQUIRED")
    v["API_KEY"] = ask("API_KEY", (v.get("API_KEY") or "").strip(), True)
    v["WIREGUARD_CONF_PATH"] = ask("WIREGUARD_CONF_PATH", v["WIREGUARD_CONF_PATH"], True)

    print(hr("─", DIM))
    tls_on = confirm("Enable TLS (HTTPS)?", tls_paths_set)

    print(hr("─", DIM))
    info("RUN")

    tip_port = "443" if tls_on else "9898"
    tip_scheme = "https" if tls_on else "http"
    print(box("Warnings", [
        f"• BIND format: host:port  (examples: 0.0.0.0:{tip_port}, 127.0.0.1:{tip_port}, [::]:{tip_port})",
        f"• In {tip_scheme} mode many users pick port {tip_port}, but any free port works.",
        "• If you use a reverse-proxy, bind to 127.0.0.1:PORT instead of 0.0.0.0:PORT.",
    ], BR_YEL))

    bind_cur = (v.get("BIND") or "").strip()
    while True:
        v["BIND"] = ask("BIND", bind_cur, True).strip()
        if v["BIND"] and _bind(v["BIND"]):
            break
        err("BIND is required and must be host:port (port: 1-65535).")
        bind_cur = v["BIND"]

    print(hr("─", DIM))
    if tls_on:
        info("TLS")

        auto = confirm("Obtain certificate automatically with certbot?", True)
        if auto and not isitroot():
            err("Certbot automation requires sudo/root.")
            print(box("Warnings", [
                "• Re-run as root (sudo) OR choose manual certificate paths.",
            ], BR_YEL))
            auto = False

        domain = ""
        email = ""
        if auto:
            domain = ask("Domain", "", False).strip()
            email = ask("Email", "", False).strip()
            if not domain or not email:
                warn("Domain/email required. Switching to manual paths.")
                auto = False

        if auto and not _certbot():
            err("certbot not available.")
            print(box("Warnings", [
                "• Fix apt errors and retry, or choose manual certificate paths.",
            ], BR_YEL))
            auto = False

        if auto:
            print(box("Warnings", [
                "• Certbot uses standalone mode.",
                "• Port 80 must be FREE (stop nginx/apache).",
                "• DNS A/AAAA must point to this server.",
                "• Firewall must allow inbound 80.",
            ], BR_YEL))
            if confirm("Run certbot now?", True):
                rc = _live([
                    "certbot", "certonly", "--standalone",
                    "-d", domain,
                    "-m", email,
                    "--agree-tos", "--non-interactive", "--verbose",
                ], "certbot (live)", timeout=900)

                _live(
                    ["bash", "-lc", "tail -n 25 /var/log/letsencrypt/letsencrypt.log 2>/dev/null || true"],
                    "certbot log tail",
                    timeout=30
                )

                if rc == 0:
                    v["AGENT_SSL_CERT"] = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
                    v["AGENT_SSL_KEY"] = f"/etc/letsencrypt/live/{domain}/privkey.pem"
                    v["AGENT_SSL_CA"] = (v.get("AGENT_SSL_CA") or "").strip()
                    tls_paths_set = True
                    certbot_done = True
                    ok("Certificate OK. Paths filled automatically.")
                else:
                    err("Certbot failed. Switching to manual paths.")
                    print(box("Warnings", [
                        "• Check: /var/log/letsencrypt/letsencrypt.log",
                        "• Provide full paths to your certificate and key files.",
                    ], BR_YEL))
                    auto = False
            else:
                auto = False

        if not auto:
            print(box("Warnings", [
                "• Provide full paths to your certificate and key files.",
            ], BR_YEL))
            v["AGENT_SSL_CERT"] = ask("AGENT_SSL_CERT", (v.get("AGENT_SSL_CERT") or "").strip(), True)
            v["AGENT_SSL_KEY"] = ask("AGENT_SSL_KEY", (v.get("AGENT_SSL_KEY") or "").strip(), True)
            v["AGENT_SSL_CA"] = ask("AGENT_SSL_CA (optional)", (v.get("AGENT_SSL_CA") or "").strip(), True)
            tls_paths_set = bool((v.get("AGENT_SSL_CERT") or "").strip() and (v.get("AGENT_SSL_KEY") or "").strip())
    else:
        v["AGENT_SSL_CERT"] = ""
        v["AGENT_SSL_KEY"] = ""
        v["AGENT_SSL_CA"] = ""
        tls_paths_set = False

    print(hr("─", DIM))
    tune_guni = confirm("Configure Gunicorn options?", False)
    if tune_guni:
        info("GUNICORN")

        print(box("Tips", [
            "• WORKERS can be empty to auto-pick based on CPU.",
            "• THREADS is per worker.",
        ], BR_CYN))

        d_workers = (v.get("WORKERS") or "").strip()     
        d_threads = (v.get("THREADS") or "4").strip()
        d_timeout = (v.get("TIMEOUT") or "60").strip()
        d_grace   = (v.get("GRACEFUL_TIMEOUT") or "30").strip()
        d_level   = (v.get("LOGLEVEL") or "info").strip()

        v["WORKERS"] = (ask("WORKERS (optional)", d_workers, True) or "").strip()
        v["THREADS"] = (ask("THREADS", d_threads, True) or d_threads).strip()
        v["TIMEOUT"] = (ask("TIMEOUT", d_timeout, True) or d_timeout).strip()
        v["GRACEFUL_TIMEOUT"] = (ask("GRACEFUL_TIMEOUT", d_grace, True) or d_grace).strip()
        v["LOGLEVEL"] = (ask("LOGLEVEL", d_level, True) or d_level).strip()
    else:
        v["WORKERS"] = (v.get("WORKERS") or "").strip()
        v["THREADS"] = (v.get("THREADS") or "").strip()
        v["TIMEOUT"] = (v.get("TIMEOUT") or "").strip()
        v["GRACEFUL_TIMEOUT"] = (v.get("GRACEFUL_TIMEOUT") or "").strip()
        v["LOGLEVEL"] = (v.get("LOGLEVEL") or "").strip()

    text_out = make_env(v)

    clear()
    header("Preview", "agent/.env")
    print(box_text("agent/.env", c(text_out.rstrip("\n"), BR_WHT), BR_CYN))
    print()

    _tmp = v.copy()
    bind = (_tmp.get("BIND") or "").strip()
    cert = (_tmp.get("AGENT_SSL_CERT") or "").strip()
    key  = (_tmp.get("AGENT_SSL_KEY")  or "").strip()
    tls_guess = bool(tls_on and cert and key)

    host, port = _parse_bind(bind, "0.0.0.0:9898")
    scheme = "https" if tls_guess else "http"
    if tls_guess:
        h = _cert_domain(cert) or host
    else:
        h = _public_ipv4() or host
    if h in ("0.0.0.0", "*"):
        h = "127.0.0.1"

    show_port = True
    try:
        p = int(port)
        if (scheme == "https" and p == 443) or (scheme == "http" and p == 80):
            show_port = False
    except Exception:
        pass
    preview_url = f"{scheme}://{h}" + (f":{port}" if show_port else "")

    print(box("Node URL (add to main panel)", [
        f"Base URL: {c(preview_url, BR_WHT)}",
        f"API key:  {c('API_KEY value above', BR_WHT)}",
        "Tip: In panel -> Nodes -> Add node -> paste Base URL + API key",
    ], BR_CYN))
    print()

    if confirm("Save agent/.env now?", True):
        _write(env_path, text_out)
        ok(f"Saved: {_paths(str(env_path))}")
    else:
        warn("Skipped saving.")

    result = {
        "tls_on": bool(tls_on),
        "tls_paths_set": bool(tls_paths_set),
        "certbot_done": bool(certbot_done),
    }

    pause()
    return result


def install_agent(root: Path):
    if not isitroot():
        err("Service install requires sudo/root.")
        pause()
        return

    a = agent_dir(root)
    env_path = a / ".env"
    node_agent = a / "node_agent.py"
    vpy = a / "venv" / "bin" / "python"

    if not env_path.exists():
        err("agent/.env missing.")
        warn("TIP: Run Install -> option 2 to configure env.")
        pause()
        return
    if not node_agent.exists():
        err("agent/node_agent.py missing.")
        warn("TIP: Clone the repo correctly first.")
        pause()
        return
    if not vpy.exists():
        err("agent/venv missing.")
        warn("TIP: Run Install -> option 1 to install requirements.")
        pause()
        return

    unit = Path("/etc/systemd/system/wg-node-agent.service")
    text = f"""[Unit]
Description=WG Node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={a}
EnvironmentFile={env_path}
ExecStart={vpy} {node_agent}
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
"""
    _write(unit, text)
    run(["systemctl","daemon-reload"], "daemon-reload")
    run(["systemctl","enable","--now","wg-node-agent.service"], "enable --now")
    ok("wg-node-agent.service installed + started.")
    pause()

def install_step_1():
    if not isitroot():
        err("Run as sudo/root for install.")
        warn("TIP: sudo node")
        pause()
        return

    clear()
    header("Install: Step 1", "Clone + Requirements")

    root_now = _root()
    if (root_now / ".git").exists() and _cmd("git"):
        info("Git status")
        rc, out, _ = run_out(["git", "-C", str(root_now), "status", "-sb"])
        if rc == 0 and out.strip():
            print(box("Repository", [c(line, BR_WHT) for line in out.strip().splitlines()[:6]], BR_CYN))
        print()

    dest = ask("Clone directory", str(DEFAULT_CLONE_DIR), True).strip()
    if not dest:
        warn("Canceled.")
        pause()
        return

    dest_path = Path(dest).expanduser().resolve()
    url = DEFAULT_GIT_URL  

    print(hr("─", DIM))
    info("Clone project")

    if not _cmd("git"):
        run(["apt-get","update","-y"], "apt-get update")
        run(["apt-get","install","-y","git"], "install git")

    if dest_path.exists() and any(dest_path.iterdir()):
        warn("Destination exists and is not empty.")
        if confirm("Use it as root (no clone)?", True):
            set_root(dest_path)
            ok(f"Root set: {_paths(str(dest_path))}")
        pause()
        return

    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")

    print(left_margin() + c(f"{TAG_RUN} ", BR_CYN) + c("git clone (quiet)", BR_WHT))
    p = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest_path)],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        err("git clone failed.")
        if (p.stderr or "").strip():
            warn(p.stderr.strip()[:400])
        pause()
        return

    set_root(dest_path)
    ok(f"Cloned and set root: {_paths(str(dest_path))}")

    print(hr("─", DIM))
    info("Install requirements")
    install_requirements(_root())


def install_step_2():
    root = _root()
    if not isitroot():
        err("Run as sudo/root for this step.")
        pause()
        return

    clear()
    header("Install: Step 2", "WireGuard + Env + TLS + Service")
    print(box("Flow", [
        "1) Install/check WireGuard",
        "2) Add/Edit WireGuard config (down/up as needed)",
        "3) Configure agent/.env",
        "4) Optional TLS via certbot",
        "5) Create + enable wg-node-agent.service",
    ], BR_CYN))
    pause("Press Enter to start...")

    print(hr("─", DIM))
    info("WireGuard install/check")
    if not _wireguard_installed():
        err("WireGuard not available.")
        warn("TIP: apt-get update; ensure repositories work; try again.")
        pause()
        return
    _ip_forwarding()
    ok("WireGuard OK + IP forwarding enabled.")

    print(hr("─", DIM))
    info("WireGuard config")
    wg_flow()

    print(hr("─", DIM))

    print(hr("─", DIM))
    info("Agent env")
    env_res = _wizard(root) or {}
    
    print(hr("─", DIM))
    if env_res.get("tls_on") and not env_res.get("tls_paths_set"):
        warn("TLS is enabled but cert/key paths are missing.")
        warn("TIP: Use certbot now, or edit agent/.env later and add AGENT_SSL_CERT/AGENT_SSL_KEY.")
        if confirm("Run TLS certbot now?", True):
            tls_certbot(root)
        else:
            ok("TLS certbot skipped.")
    else:
        ok("TLS step OK (no extra certbot prompt).")

    print(hr("─", DIM))
    info("Service")
    install_agent(root)


def svc_state(name: str) -> str:
    if not _cmd("systemctl"):
        return "unknown"
    rc,out,_ = run_out(["systemctl","is-active",name])
    return out.strip() if rc == 0 else "inactive"

def service_menu():
    while True:
        clear()
        header("Service", "wg-node-agent.service")
        st = svc_state("wg-node-agent.service")
        col = BR_GRN if st == "active" else BR_RED

        print(box("Service", [
            f"Status: {c(st, col)}",
            "",
            "1) Restart",
            "2) Stop",
            "3) Logs (last 200)",
            "4) Follow logs (Ctrl+C to stop following)",
            "",
            "0) Back",
        ], BR_CYN))

        ch = ask("Select", "", False).strip()
        if ch == "0":
            return
        elif ch == "1":
            run(["systemctl","restart","wg-node-agent.service"], "restart")
            time.sleep(0.2)
        elif ch == "2":
            run(["systemctl","stop","wg-node-agent.service"], "stop")
            time.sleep(0.2)
        elif ch == "3":
            subprocess.run(["journalctl","-u","wg-node-agent.service","-n","200","--no-pager"])
            pause()
        elif ch == "4":
            clear()
            header("Follow logs", "wg-node-agent.service")
            try:
                subprocess.run(["journalctl","-u","wg-node-agent.service","-f","--no-pager"])
            except KeyboardInterrupt:
                pass
            pause()
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def wg_up_interfaces() -> List[str]:
    if not _cmd("wg"):
        return []
    rc,out,_ = run_out(["wg","show","interfaces"])
    if rc != 0:
        return []
    return [x for x in out.strip().split() if x.strip()]

def status_page(root: Path):
    a = agent_dir(root)
    env_path = a / ".env"
    env = _env(env_path.read_text(encoding="utf-8") if env_path.exists() else "")

    add = node_add_url(root)
    base = add.get("base") or ""
    tls = bool(add.get("tls"))
    bind = add.get("bind") or ""
    key = (env.get("API_KEY") or "").strip()

    confs = list_confs()
    ups = wg_up_interfaces()

    clear()
    header("Status", "panel + wireguard + service")

    print(box("Panel-facing info", [
        f"Root: {c(_paths(str(root)), BR_WHT)}",
        f"Node URL (add to panel): {c(base if base else 'N/A', BR_GRN if base else BR_YEL)}",
        f"Node API key: {c(key if key else 'MISSING', BR_GRN if key else BR_RED)}",
        f"Scheme: {c('HTTPS', BR_GRN) if tls else c('HTTP', BR_YEL)}",
        f"Bind: {c(bind, BR_WHT) if bind else c('N/A', BR_YEL)}",
        last_backup_line(root),
        "Tip: Panel uses Authorization: Bearer API_KEY",
    ], BR_CYN))
    print()

    print(box("WireGuard", [
        f"Installed: {c('YES', BR_GRN) if (_cmd('wg') and _cmd('wg-quick')) else c('NO', BR_RED)}",
        f"Config dir: {c(_paths(str(wg_dir())), BR_WHT)}",
        f"Configs: {c(', '.join([p.name for p in confs[:6]]), BR_WHT) if confs else c('none', BR_YEL)}",
        f"Interfaces UP: {c(', '.join(ups), BR_GRN) if ups else c('none', BR_RED)}",
    ], BR_CYN))
    print()

    st = svc_state("wg-node-agent.service")
    print(box("Service", [
        f"wg-node-agent.service: {c(st, BR_GRN) if st == 'active' else c(st, BR_RED)}",
        "Tip: Open Service menu to restart/stop/logs.",
    ], BR_CYN))
    print()

    if confirm("Open Service menu now?", False):
        service_menu()
    else:
        pause()


def remove_unit(unit_name: str, unit_path: Path):
    if not _cmd("systemctl"):
        return
    subprocess.run(["systemctl","disable","--now",unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if unit_path.exists():
        try: unit_path.unlink()
        except Exception: pass
    subprocess.run(["systemctl","daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def uninstall_wireguard_confs():
    confs = list_confs()
    if not confs:
        warn("No WireGuard configs found.")
        pause()
        return

    clear()
    header("Uninstall WG Config", "remove one config")
    for i,p in enumerate(confs, 1):
        print(left_margin() + c(f"{i}) ", BR_YEL) + c(p.name, BR_WHT))
    print()

    sel = ask("Select config number", "", False).strip()
    try:
        conf = confs[int(sel)-1]
    except Exception:
        warn("Invalid selection.")
        pause()
        return

    iface = conf.stem
    if confirm(f"wg-quick down {iface} first?", True):
        run(["wg-quick","down",iface], f"wg-quick down {iface}")
    if _cmd("systemctl") and confirm(f"Disable wg-quick@{iface} on boot?", True):
        run(["systemctl","disable",f"wg-quick@{iface}.service"], "systemctl disable")

    if confirm(f"Delete {conf.name} ?", True):
        try:
            conf.unlink()
            ok("Config deleted.")
        except Exception as e:
            err(f"Delete failed: {e}")
            warn("TIP: You may need sudo/root.")
    pause()

def wg_cleanup(delete_confs: bool = False):

    confs = list_confs()
    if not confs:
        warn("No WireGuard configs found.")
        return

    for conf in confs:
        iface = conf.stem

        if _cmd("wg-quick"):
            run(["wg-quick", "down", iface], f"wg-quick down {iface}")

        if _cmd("systemctl"):
            run(["systemctl", "disable", "--now", f"wg-quick@{iface}.service"], f"Disable wg-quick@{iface}")

        if delete_confs:
            try:
                conf.unlink()
            except Exception:
                pass


def uninstall_all(root: Path):
    if not isitroot():
        err("Uninstall requires sudo/root.")
        pause()
        return

    clear()
    header("Uninstall EVERYTHING", "service + venv + optional project")
    print(box("Warning", [
        "This removes wg-node-agent.service and agent/venv.",
        "You can also remove WireGuard configs and the project folder (optional).",
    ], BR_CYN))
    print()

    if not confirm("Continue?", False):
        return

    remove_unit("wg-node-agent.service", Path("/etc/systemd/system/wg-node-agent.service"))
    shutil.rmtree(agent_dir(root)/"venv", ignore_errors=True)
    ok("Service + venv removed.")

    if confirm("Also remove WireGuard configs (*.conf) from /etc/wireguard?", False):
        info("Stopping wg-quick interfaces and disabling wg-quick@ units...")
        wg_cleanup(delete_confs=True)
        ok("WireGuard interfaces + configs removed.")

    if confirm(f"Also delete project folder: {root} ?", False):
        shutil.rmtree(root, ignore_errors=True)
        ok("Project folder removed.")

    if confirm("Clear saved root marker?", True):
        try:
            if ROOT_MARKER.exists():
                ROOT_MARKER.unlink()
        except Exception:
            pass
        ok("Root marker cleared.")

    pause()

def update_menu(root: Path):
    while True:
        clear()
        header("Update", "safe project updates")
        print(box("Quick Status", status_lines(root), BR_CYN))
        print()

        items = [
            c("1) Show git status", BR_CYN),
            c("2) Safe update (git pull --ff-only)", BR_GRN),
            c("3) Force update (overwrite code, keep backups)", BR_YEL),
            "",
            c("0) Back", DIM),
        ]
        print(box("Update Menu", items, BR_CYN))

        ch = ask("Select", "", False).strip()
        if ch == "0":
            return

        if not _cmd("git") or not (root / ".git").exists():
            err("This root is not a git repository.")
            warn("TIP: Run Install -> Step 1 first.")
            pause()
            continue

        if ch == "1":
            rc, out, errt = run_out(["git", "-C", str(root), "status", "-sb"])
            if rc == 0:
                print(box("git status -sb", [c(x, BR_WHT) for x in out.strip().splitlines()[:12]] or ["(empty)"], BR_CYN))
            else:
                err("git status failed.")
                if errt.strip():
                    warn(errt.strip()[:400])
            pause()

        elif ch == "2":
            _live(["git", "-C", str(root), "pull", "--ff-only"], "git pull --ff-only", timeout=300)
            pause()

        elif ch == "3":
            warn("This overwrites tracked code with the remote version.")
            warn("Your backups and local data folders will be preserved.")
            if not confirm("Continue?", False):
                continue

            excludes = [
                "backups", "instance", ".env",
                "agent/.env", "agent/venv",
                "venv", "__pycache__",
            ]

            _live(["git", "-C", str(root), "fetch", "--all", "--prune"], "git fetch", timeout=300)

            rc, branch, _ = run_out(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"])
            branch = (branch or "main").strip() if rc == 0 else "main"
            _live(["git", "-C", str(root), "reset", "--hard", f"origin/{branch}"], "git reset --hard", timeout=300)

            cmd = ["git", "-C", str(root), "clean", "-fd"]
            for e in excludes:
                cmd += ["-e", e]
            _live(cmd, "git clean -fd (preserve local data)", timeout=300)

            ok("Force update completed.")
            pause()

        else:
            warn("Invalid option.")
            time.sleep(0.25)

def uninstall_menu(root: Path):
    while True:
        clear()
        header("Uninstall", "everything or parts")
        print(box("Uninstall Menu", [
            "1) Uninstall EVERYTHING",
            "2) Remove node service only",
            "3) Remove agent venv only",
            "4) Remove WireGuard config (choose .conf)",
            "0) Back",
        ], BR_CYN))

        ch = ask("Select", "", False).strip()
        if ch == "0":
            return
        elif ch == "1":
            _action("Uninstall all", lambda: uninstall_all(root))
        elif ch == "2":
            _action("Remove service", lambda: remove_unit("wg-node-agent.service", Path("/etc/systemd/system/wg-node-agent.service")) or ok("Service removed.") or pause())
        elif ch == "3":
            _action("Remove venv", lambda: shutil.rmtree(agent_dir(root)/"venv", ignore_errors=True) or ok("agent/venv removed.") or pause())
        elif ch == "4":
            _action("Remove wg conf", uninstall_wireguard_confs)
        else:
            warn("Invalid option.")
            time.sleep(0.25)


def install_menu():
    while True:
        clear()
        header("Install", "two steps")
        print(box("Install Menu", [
            "1) Clone project + install requirements",
            "2) Configure WireGuard + Env + TLS + create service",
            "0) Back",
        ], BR_CYN))

        ch = ask("Select", "", False).strip()
        if ch == "0":
            return
        elif ch == "1":
            _action("Install step 1", install_step_1)
        elif ch == "2":
            _action("Install step 2", install_step_2)
        else:
            warn("Invalid option.")
            time.sleep(0.25)


def svc_quick() -> str:
    st = svc_state("wg-node-agent.service")
    return st

def _re_bind(bind: str, fallback: str = "0.0.0.0:9898") -> tuple[str, str]:
    b = (bind or "").strip() or fallback
    if b.startswith("["): 
        try:
            host = b.split("]", 1)[0].lstrip("[")
            port = b.split("]:", 1)[1]
            return host.strip(), port.strip()
        except Exception:
            return "0.0.0.0", fallback.split(":")[-1]
    host, port = (b.split(":", 1) + [fallback.split(":")[-1]])[:2]
    return (host.strip() or "0.0.0.0"), (port.strip() or fallback.split(":")[-1])


def _cert_domain(cert_path: str) -> str:

    p = (cert_path or "").strip()
    if not p:
        return ""
    try:
        parts = Path(p).parts
        if "letsencrypt" in parts and "live" in parts:
            i = parts.index("live")
            if i + 1 < len(parts):
                return parts[i + 1].strip()
    except Exception:
        pass
    return ""


def _public_ipv4() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def node_add_url(root: Path) -> dict:

    a = agent_dir(root)
    env_path = a / ".env"
    env = _env(env_path.read_text(encoding="utf-8") if env_path.exists() else "")

    bind = (env.get("BIND") or "0.0.0.0:9898").strip()
    host, port = _re_bind(bind, "0.0.0.0:9898")

    cert = (env.get("AGENT_SSL_CERT") or "").strip()
    key  = (env.get("AGENT_SSL_KEY")  or "").strip()
    tls = bool(cert and key and Path(cert).is_file() and Path(key).is_file())

    scheme = "https" if tls else "http"

    if tls:
        dom = _cert_domain(cert)  
        browse_host = dom or host
    else:
        browse_host = _public_ipv4() or host

    if browse_host in ("0.0.0.0", "*"):
        browse_host = "127.0.0.1"

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
        "tls": tls,
        "bind": bind,
        "host": browse_host,
        "port": port,
        "base": base,
    }

def _mask_key(s: str, keep: int = 6) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "…" + s[-keep:]


def node_api_key(root: Path) -> str:
    a = agent_dir(root)
    env_path = a / ".env"
    env = _env(env_path.read_text(encoding="utf-8") if env_path.exists() else "")
    return (env.get("API_KEY") or "").strip()

def _now_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _human_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown"


def backups_dir(root: Path) -> Path:
    d = root / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def backup_statuspath(root: Path) -> Path:
    return backups_dir(root) / "node_backup_state.json"


def load_backupstate(root: Path) -> dict:
    p = backup_statuspath(root)
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"ok": False, "when": 0, "file": "", "size": 0, "msg": "never"}


def save_backupstate(root: Path, st: dict) -> None:
    p = backup_statuspath(root)
    try:
        p.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def last_backup_line(root: Path) -> str:
    st = load_backupstate(root)
    when = st.get("when") or 0
    okk = bool(st.get("ok"))
    msg = st.get("msg") or ""
    if not when:
        return f"Last backup: {c('never', BR_YEL)}"
    dt = _human_ts(when)
    status = c("OK", BR_GRN) if okk else c("FAIL", BR_RED)
    extra = f" — {msg}" if msg else ""
    return f"Last backup: {status} {c(dt, BR_WHT)}{extra}"


def list_backup_files(root: Path) -> List[Path]:
    d = backups_dir(root)
    files = sorted(d.glob("node-backup-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files


class _OneFileHandler(http.server.BaseHTTPRequestHandler):
    FILE_PATH: Path = Path("/")
    TOKEN: str = ""

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        want = "/" + (self.TOKEN or "")
        if self.path != want:
            self.send_response(404)
            self.end_headers()
            return

        p = self.FILE_PATH
        if not p.exists() or not p.is_file():
            self.send_response(404)
            self.end_headers()
            return

        try:
            data = p.read_bytes()
        except Exception:
            self.send_response(500)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Disposition", f'attachment; filename="{p.name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def _serve_backup_link(root: Path, backup_file: Path, seconds: int = 300) -> dict:
    a = agent_dir(root)
    env_path = a / ".env"
    env = _env(env_path.read_text(encoding="utf-8") if env_path.exists() else "")

    cert = (env.get("AGENT_SSL_CERT") or "").strip()
    key  = (env.get("AGENT_SSL_KEY")  or "").strip()
    tls = bool(cert and key and Path(cert).is_file() and Path(key).is_file())
    scheme = "https" if tls else "http"

    token = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")

    Handler = type("OneFileHandler", (_OneFileHandler,), {})
    Handler.FILE_PATH = backup_file
    Handler.TOKEN = token

    class _TCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]

    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    def _stop_later():
        time.sleep(max(10, int(seconds)))
        try:
            httpd.shutdown()
        except Exception:
            pass

    threading.Thread(target=_stop_later, daemon=True).start()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    url = f"{scheme}://127.0.0.1:{port}/{token}"
    return {"url": url, "scheme": scheme, "port": port, "token": token, "seconds": int(seconds)}


def _node_backup(root: Path) -> Path:

    if not isitroot():
        raise RuntimeError("Backup requires sudo/root (needs /etc/wireguard).")

    d = backups_dir(root)
    ts = time.time()
    name = datetime.fromtimestamp(ts).strftime("node-backup-%Y%m%d-%H%M%S.tar.gz")
    out = d / name

    a = agent_dir(root)
    env_file = a / ".env"

    wgconf_dir = Path("/etc/wireguard")
    unit_file = Path("/etc/systemd/system/wg-node-agent.service")

    with tarfile.open(out, "w:gz") as tar:
        if env_file.exists():
            tar.add(env_file, arcname="agent/.env")

        if wgconf_dir.exists():
            for p in sorted(wgconf_dir.glob("*.conf")):
                tar.add(p, arcname=f"wireguard/{p.name}")

        if unit_file.exists():
            tar.add(unit_file, arcname="systemd/wg-node-agent.service")

        meta = {
            "created_at": _now_stamp(),
            "root": str(root),
            "includes": [
                "agent/.env",
                "wireguard/*.conf",
                "systemd/wg-node-agent.service",
            ],
        }
        meta_bytes = json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8")
        ti = tarfile.TarInfo("meta.json")
        ti.size = len(meta_bytes)
        ti.mtime = int(ts)
        tar.addfile(ti, io.BytesIO(meta_bytes))  

    return out


def restore_backup(root: Path, backup_file: Path) -> None:

    if not isitroot():
        raise RuntimeError("Restore requires sudo/root.")

    if not backup_file.exists():
        raise FileNotFoundError(str(backup_file))

    a = agent_dir(root)
    a.mkdir(parents=True, exist_ok=True)
    wgconf_dir = Path("/etc/wireguard")
    wgconf_dir.mkdir(parents=True, exist_ok=True)
    unit_file = Path("/etc/systemd/system/wg-node-agent.service")

    with tarfile.open(backup_file, "r:gz") as tar:
        members = tar.getmembers()

        m_env = next((m for m in members if m.name == "agent/.env"), None)
        if m_env:
            data = tar.extractfile(m_env).read().decode("utf-8", errors="ignore")
            (a / ".env").write_text(data, encoding="utf-8")
            ok("Restored agent/.env")

        wg_members = [m for m in members if m.name.startswith("wireguard/") and m.name.endswith(".conf")]
        if wg_members:
            if confirm("Restore WireGuard configs to /etc/wireguard (overwrite if exists)?", False):
                for m in wg_members:
                    fn = Path(m.name).name
                    data = tar.extractfile(m).read()
                    (wgconf_dir / fn).write_bytes(data)
                ok("Restored WireGuard configs.")

        m_unit = next((m for m in members if m.name == "systemd/wg-node-agent.service"), None)
        if m_unit:
            if confirm("Restore wg-node-agent.service (overwrite if exists)?", False):
                data = tar.extractfile(m_unit).read()
                unit_file.write_bytes(data)
                run(["systemctl", "daemon-reload"], "systemctl daemon-reload")
                ok("Restored wg-node-agent.service (daemon-reload done).")

def _public_ip() -> str:

    ip = _public_ipv4()  
    if ip:
        return ip

    try:
        out = subprocess.check_output(["bash", "-lc", "hostname -I 2>/dev/null | awk '{print $1}'"]).decode().strip()
        return out.split()[0] if out else ""
    except Exception:
        return ""

def backup_menu(root: Path):
    while True:
        clear()
        header("Backup", "node essentials + wireguard configs")

        print(box("Backup Status", [
            last_backup_line(root),
            f"Backup folder: {c(_paths(str(backups_dir(root))), BR_WHT)}",
        ], BR_CYN))
        print()

        items = [
            c("1) Create backup (agent/.env + wireguard + service unit)", BR_GRN),
            c("2) List backups", BR_CYN),
            c("3) Download backup", BR_YEL),
            c("4) Restore backup", BR_RED),
            "",
            c("0) Back", DIM),
        ]
        print(box("Backup Menu", items, BR_CYN))

        ch = ask("Select", "", False).strip()
        if ch == "0":
            return

        if ch == "1":
            if not isitroot():
                err("Backup requires sudo/root.")
                pause()
                continue

            info("Creating backup...")
            try:
                fp = _node_backup(root)
                size = fp.stat().st_size if fp.exists() else 0
                st = {"ok": True, "when": time.time(), "file": str(fp), "size": int(size), "msg": ""}
                save_backupstate(root, st)
                ok(f"Backup created: {_paths(str(fp))}")
            except Exception as e:
                st = {"ok": False, "when": time.time(), "file": "", "size": 0, "msg": str(e)}
                save_backupstate(root, st)
                err(f"Backup failed: {e}")

            pause()
            continue

        if ch == "2":
            files = list_backup_files(root)
            if not files:
                warn("No backups found.")
                pause()
                continue

            lines = []
            for p in files[:10]:
                dt = _human_ts(p.stat().st_mtime)
                sz_mib = round(p.stat().st_size / 1024 / 1024, 2)
                lines.append(
                    f"{c(p.name, BR_WHT)}  —  {c(dt, BR_WHT)}  —  {c(str(sz_mib) + ' MiB', BR_YEL)}"
                )

            print(box("Backups (latest)", lines, BR_CYN))
            pause()
            continue

        if ch == "3":
            files = list_backup_files(root)
            if not files:
                warn("No backups found.")
                pause()
                continue

            p = files[0]
            st = load_backupstate(root)
            if st.get("file"):
                sp = Path(st["file"])
                if sp.exists():
                    p = sp

            print(box("Download Method", [
                c("1) SCP (download the file to your PC)", BR_GRN),
                c("2) Browser link (safe via SSH tunnel)", BR_YEL),
                "",
                c("0) Back", DIM),
            ], BR_CYN))

            m = ask("Select method", "1", True).strip()
            if m == "0":
                continue

            pub_ip = _public_ip()
            default_server = f"root@{pub_ip}" if pub_ip else "root@SERVER_IP"
            server_hint = ask("Server (ssh/scp)", default_server, True).strip()

            if m == "1":
                print(box("Tip", [
                    "Local path = a folder ON YOUR PC where the file will be saved.",
                    "Examples (Linux/macOS): .   ~/Downloads   /home/user/backups",
                    "Examples (Windows):     .   C:\\Users\\You\\Downloads",
                ], BR_CYN))

                local_dir = ask("Save to (your PC path)", "~/Downloads", True).strip()

                print(box("SCP (run on your PC)", [
                    c(f"scp {server_hint}:{p} {local_dir}/", BR_WHT),
                ], BR_YEL))
                pause()
                continue

            if m == "2":
                try:
                    ttl = 300
                    link = _serve_backup_link(root, p, seconds=ttl)

                    scheme = (link.get("scheme") or "http").strip()
                    srv_port = int(link.get("port") or 0)
                    token = (link.get("token") or "").strip()
                    ttl = int(link.get("seconds") or ttl)

                    if not srv_port or not token:
                        raise RuntimeError("Internal error: missing port/token from link server.")

                    local_port_s = ask("Local port on your PC (browser)", str(srv_port), True).strip()
                    try:
                        local_port = int(local_port_s)
                        if not (1 <= local_port <= 65535):
                            raise ValueError()
                    except Exception:
                        warn("Invalid port. Using default.")
                        local_port = srv_port

                    ssh_port_s = ask("SSH port", "22", True).strip()
                    try:
                        ssh_port = int(ssh_port_s)
                        if not (1 <= ssh_port <= 65535):
                            raise ValueError()
                    except Exception:
                        warn("Invalid SSH port. Using 22.")
                        ssh_port = 22

                    ssh_cmd = f"ssh -p {ssh_port} -L {local_port}:127.0.0.1:{srv_port} {server_hint}"
                    pc_url = f"{scheme}://127.0.0.1:{local_port}/{token}"

                    print(box("Browser download (safe)", [
                        c("Step 1 (on your PC): run this and keep it open:", BR_WHT),
                        c(ssh_cmd, BR_WHT),
                        "",
                        c("Step 2 (on your PC): open this in your browser:", BR_WHT),
                        c(pc_url, BR_GRN if scheme == "https" else BR_YEL),
                        "",
                        c(f"Countdown started. Link expires in {ttl} seconds.", BR_YEL),
                        c("Windows: if 'ssh' is not recognized, install OpenSSH Client or use Git Bash.", DIM),
                        c("Note: 127.0.0.1 is your PC localhost forwarded through SSH.", DIM),
                    ], BR_YEL))

                    for i in range(ttl, 0, -1):
                        print(f"\r{c('Expires in', DIM)} {c(str(i)+'s', BR_YEL)}", end="", flush=True)
                        time.sleep(1)

                    print()
                    warn("Link expired. Create a new link from Download menu.")

                except Exception as e:
                    err(f"Could not create link: {e}")

                pause()
                continue

            warn("Invalid method.")
            time.sleep(0.25)
            continue

        if ch == "4":
            if not isitroot():
                err("Restore requires sudo/root.")
                pause()
                continue

            files = list_backup_files(root)
            if not files:
                warn("No backups found.")
                pause()
                continue

            default_name = files[0].name
            name = ask("Backup file name", default_name, True).strip()
            target = backups_dir(root) / name

            if not target.exists():
                err("Backup file not found in backups folder.")
                pause()
                continue

            if not confirm("Restore from this backup now?", False):
                continue

            info("Restoring...")
            try:
                restore_backup(root, target)
                ok("Restore completed.")
            except Exception as e:
                err(f"Restore failed: {e}")

            pause()
            continue

        warn("Invalid option.")
        time.sleep(0.25)



def status_lines(root: Path) -> List[str]:
    a = agent_dir(root)
    wg_ok = _cmd("wg") and _cmd("wg-quick")
    env_ok = (a / ".env").exists()
    venv_ok = (a / "venv/bin/python").exists()
    svc = svc_quick()
    git = git_quick(root)

    add = node_add_url(root)
    key = node_api_key(root)

    url_txt = add.get("base") or ""
    key_txt = key or ""

    return [
        f"Root: {c(_paths(str(root)), BR_WHT)}",
        f"Git: {git}",
        f"Node URL: {c(url_txt if url_txt else 'N/A', BR_GRN if url_txt else BR_YEL)}",
        f"Node API key: {c(key_txt if key_txt else 'MISSING', BR_GRN if key_txt else BR_RED)}",
        f"WireGuard: {c('OK', BR_GRN) if wg_ok else c('MISSING', BR_RED)}",
        f"Agent .env: {c('OK', BR_GRN) if env_ok else c('MISSING', BR_RED)}",
        f"Agent venv: {c('OK', BR_GRN) if venv_ok else c('MISSING', BR_RED)}",
        f"Service: {c(svc, BR_GRN) if svc == 'active' else c(svc, BR_RED)}",
        last_backup_line(root),
    ]


def node_command():
    if not isitroot():
        return
    target = Path("/usr/local/bin/node")
    script = Path(__file__).resolve()
    if target.exists():
        try:
            if str(script) in target.read_text(encoding="utf-8", errors="ignore"):
                return
        except Exception:
            return
    _write(target, f"""#!/usr/bin/env bash
exec /usr/bin/env python3 "{script}" "$@"
""")
    try: target.chmod(0o755)
    except Exception: pass

def main_menu():
    while True:
        root = _root()
        clear()
        header("WG Node Installer", "agent + wireguard")

        print(box("Quick Status", status_lines(root), BR_CYN))
        print()
        print(box("Main Menu", [
        c("1) Status (panel + wireguard + service)", BR_BLU),
        c("2) Install", BR_YEL),
        c("3) Add/Edit WireGuard conf", BR_CYN),
        c("4) Update", BR_GRN),
        c("5) Backup", BR_YEL),
        c("6) Uninstall", BR_RED),
        "0) Exit",
        ], BR_CYN))

        ch = ask("Select", "", False).strip()
        if ch == "0":
            return
        elif ch == "1":
            _action("Status [Panel Information]", lambda: status_page(root))
        elif ch == "2":
            _action("Install menu", install_menu)
        elif ch == "3":
            _action("WireGuard", wg_flow)
        elif ch == "4":
            _action("Update", lambda: update_menu(root))
        elif ch == "5":
            _action("Backup", lambda: backup_menu(root))
        elif ch == "6":
            _action("Uninstall", lambda: uninstall_menu(root))
        else:
            warn("Invalid option.")
            time.sleep(0.25)

def main():
    node_command()
    main_menu()

if __name__ == "__main__":
    main()
