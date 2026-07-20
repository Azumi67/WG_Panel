#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${WG_PANEL_DIR:-/usr/local/bin/WG_Panel}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
NODE_PY="$SCRIPT_DIR/node.py"
VENV_DIR="$SCRIPT_DIR/venv"
PY="$VENV_DIR/bin/python"

NO_APT=0
KEEP_EXISTING=0
STAGED_RUN="${WG_PANEL_STAGED_RUN:-0}"

log()  { printf '\033[96m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[92m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[93m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[91m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF_USAGE
Usage: $0 [options] [-- node.py args...]

Options:
  --no-apt          Skip apt installation of operating-system dependencies
  --keep-existing   Do not remove an existing $INSTALL_DIR installation
  -h, --help        Show this help

Environment:
  WG_PANEL_DIR      Override installation directory (default: $INSTALL_DIR)

Example:
  sudo ./node.sh
EOF_USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-apt) NO_APT=1; shift ;;
    --keep-existing) KEEP_EXISTING=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this installer as root: sudo $0"
}

stage_if_running_from_install_dir() {
  [ "$STAGED_RUN" = "1" ] && return 0
  [ "$KEEP_EXISTING" -eq 0 ] || return 0
  [ -d "$INSTALL_DIR" ] || return 0

  local install_real
  install_real="$(cd "$INSTALL_DIR" 2>/dev/null && pwd -P || true)"
  [ -n "$install_real" ] || return 0
  [ "$SCRIPT_DIR" = "$install_real" ] || return 0

  [ -f "$NODE_PY" ] || die "node.py not found beside installer: $NODE_PY"

  local stage
  stage="$(mktemp -d /tmp/wg-panel-installer.XXXXXX)"
  trap 'rm -rf -- "$stage"' EXIT

  log "Installer is running from $INSTALL_DIR; staging temporary copies before cleanup."
  cp -a -- "${BASH_SOURCE[0]}" "$stage/node.sh"
  cp -a -- "$NODE_PY" "$stage/node.py"
  chmod +x "$stage/node.sh"

  WG_PANEL_STAGED_RUN=1 WG_PANEL_DIR="$INSTALL_DIR" \
    exec "$stage/node.sh" \
      $([ "$NO_APT" -eq 1 ] && printf '%s' '--no-apt') \
      -- "$@"
}

remove_existing_install() {
  [ "$KEEP_EXISTING" -eq 0 ] || {
    warn "Keeping existing installation: $INSTALL_DIR"
    return 0
  }

  [ -e "$INSTALL_DIR" ] || return 0
  require_root

  case "$INSTALL_DIR" in
    /|/usr|/usr/local|/usr/local/bin|/bin|/sbin|/etc|/var|/home|/root)
      die "Refusing to remove unsafe installation path: $INSTALL_DIR"
      ;;
  esac

  log "Removing previous WG Panel installation: $INSTALL_DIR"
  rm -rf --one-file-system -- "$INSTALL_DIR"
  ok "Previous installation removed."
}

apt_install() {
  if [ "$NO_APT" -eq 1 ]; then
    warn "Skipping apt dependency installation (--no-apt)."
    return 0
  fi

  command -v apt-get >/dev/null 2>&1 || {
    warn "apt-get not found; skipping OS dependencies."
    return 0
  }
  require_root

  log "Installing Debian/Ubuntu dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    openssl \
    jq \
    zip \
    unzip \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    build-essential \
    pkg-config \
    libffi-dev \
    libssl-dev \
    wireguard-tools \
    iproute2 \
    iptables \
    nftables \
    procps \
    systemd
  ok "Operating-system dependencies installed."
}

_venv() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found."
  if [ ! -x "$PY" ]; then
    log "Creating virtual environment: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created."
  fi
}

_imports() {
  python3 - "$NODE_PY" <<'PY'
import ast
import sys

path = sys.argv[1]
src = open(path, "r", encoding="utf-8", errors="ignore").read()
tree = ast.parse(src, filename=path)
mods = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            mods.add(alias.name.split(".")[0])
    elif isinstance(node, ast.ImportFrom) and node.module:
        mods.add(node.module.split(".")[0])
for mod in sorted(mods):
    print(mod)
PY
}

pip__node() {
  log "Inspecting Python imports in: $NODE_PY"

  mapfile -t mods < <(_imports || true)
  if [ "${#mods[@]}" -eq 0 ]; then
    warn "No imports detected; skipping package discovery."
    return 0
  fi

  local_exclude=(auth config models forms telegram_bot app)
  stdlib_exclude=(
    argparse ast base64 binascii collections contextlib csv ctypes datetime errno
    functools getpass glob hashlib hmac http importlib io ipaddress json logging
    math os pathlib platform queue random re secrets shutil signal socket ssl
    sqlite3 string subprocess sys tempfile textwrap threading time traceback typing
    urllib uuid warnings zipfile socketserver tarfile selectors struct concurrent
    dataclasses enum fractions heapq inspect itertools multiprocessing pickle
    sched statistics types weakref xml email mimetypes shlex fnmatch copy
  
  )

  declare -A pip_map=(
    [yaml]="PyYAML"
    [dotenv]="python-dotenv"
    [PIL]="Pillow"
    [Crypto]="pycryptodome"
    [cryptography]="cryptography"
    [requests]="requests"
    [flask]="Flask"
    [werkzeug]="Werkzeug"
    [jinja2]="Jinja2"
    [sqlalchemy]="SQLAlchemy"
    [psutil]="psutil"
    [telegram]="python-telegram-bot"
    [gunicorn]="gunicorn"
  )

  pkgs=()
  for m in "${mods[@]}"; do
    skip=0
    for x in "${local_exclude[@]}"; do [ "$m" = "$x" ] && skip=1; done
    for x in "${stdlib_exclude[@]}"; do [ "$m" = "$x" ] && skip=1; done
    [ "$skip" -eq 1 ] && continue

    if [ -n "${pip_map[$m]+x}" ]; then
      pkgs+=("${pip_map[$m]}")
    else
      pkgs+=("$m")
    fi
  done

  uniq_pkgs=()
  for p in "${pkgs[@]}"; do
    found=0
    for q in "${uniq_pkgs[@]}"; do [ "$p" = "$q" ] && found=1; done
    [ "$found" -eq 0 ] && uniq_pkgs+=("$p")
  done

  if [ "${#uniq_pkgs[@]}" -eq 0 ]; then
    ok "No third-party Python packages detected."
    return 0
  fi

  log "Installing Python packages: ${uniq_pkgs[*]}"
  "$PY" -m pip install --upgrade pip setuptools wheel
  "$PY" -m pip install "${uniq_pkgs[@]}"
  ok "Python dependencies installed."
}

main() {
  stage_if_running_from_install_dir "$@"
  [ -f "$NODE_PY" ] || die "node.py not found: $NODE_PY"

  apt_install
  remove_existing_install

  if [ "$STAGED_RUN" = "1" ] && [ ! -d "$SCRIPT_DIR" ]; then
    die "Temporary staging directory disappeared unexpectedly."
  fi

  _venv
  pip__node

  log "Starting node.py..."
  exec "$PY" "$NODE_PY" "$@"
}

main "$@"
