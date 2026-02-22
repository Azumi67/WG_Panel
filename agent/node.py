#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PY="$VENV_DIR/bin/python"

DEFAULT_NODE_URL="https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.py"

NO_APT=0
FORCE_FETCH=0

log()  { printf '\033[96m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[92m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[93m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[91m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [options] [NODE_PY_RAW_URL] [-- node.py args...]

Options:
  --no-apt       Skip apt install of python3/venv/pip/curl
  --force-fetch  Always re-download node.py even if cached
  -h, --help     Show help

Examples:
  sudo ./node.sh
  sudo ./node.sh --force-fetch
  sudo ./node.sh https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.py
EOF
}

is_url() { [[ "${1:-}" =~ ^https?:// ]]; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-apt) NO_APT=1; shift ;;
    --force-fetch) FORCE_FETCH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

apt_install() {
  if [ "$NO_APT" -eq 1 ]; then
    warn "Skipping apt (--no-apt)."
    return 0
  fi
  command -v apt-get >/dev/null 2>&1 || { warn "apt-get not found; skipping OS deps."; return 0; }
  [ "$(id -u)" -eq 0 ] || die "Run with sudo (or use --no-apt)."

  log "Installing OS deps (python3, venv, pip, curl)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates curl
  ok "OS deps installed."
}

_venv() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found."
  if [ ! -x "$PY" ]; then
    log "Creating venv: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    ok "Venv created."
  fi
}

_fetch_node_py() {
  local url="$1"
  local cache_dir="$SCRIPT_DIR/.cache"
  mkdir -p "$cache_dir"
  local out="$cache_dir/node.py"

  if [ "$FORCE_FETCH" -eq 0 ] && [ -s "$out" ]; then
    printf '\033[92m[ OK ]\033[0m %s\n' "Using cached node.py: $out" >&2
    echo "$out"
    return 0
  fi

  command -v curl >/dev/null 2>&1 || die "curl not found (install it or run without --no-apt)."

  printf '\033[96m[INFO]\033[0m %s\n' "Downloading node.py from: $url" >&2
  curl -fsSL "$url" -o "$out" || die "Failed to download node.py from URL."
  printf '\033[92m[ OK ]\033[0m %s\n' "Downloaded node.py -> $out" >&2

  echo "$out"
}

_imports() {
  python3 - "$1" <<'PY'
import ast, sys
path = sys.argv[1]
src = open(path, "r", encoding="utf-8", errors="ignore").read()
t = ast.parse(src, filename=path)
mods = set()
for n in ast.walk(t):
    if isinstance(n, ast.Import):
        for a in n.names:
            mods.add(a.name.split(".")[0])
    elif isinstance(n, ast.ImportFrom):
        if n.module:
            mods.add(n.module.split(".")[0])
for m in sorted(mods):
    print(m)
PY
}

pip__node() {
  local node_py="$1"

  log "Inspecting imports in: $node_py"
  mapfile -t mods < <(_imports "$node_py" || true)

  if [ "${#mods[@]}" -eq 0 ]; then
    warn "Could not detect imports (or none found). Skipping pip install."
    return 0
  fi

  local_exclude=(auth config models forms telegram_bot app)
  stdlib_exclude=(
    argparse ast base64 binascii collections contextlib csv ctypes datetime errno
    functools getpass glob hashlib hmac http importlib io ipaddress json
    logging math os pathlib queue random re secrets shutil signal socket ssl
    sqlite3 string subprocess sys tempfile textwrap threading time traceback
    typing urllib uuid warnings zipfile
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

  if [ "${#pkgs[@]}" -eq 0 ]; then
    ok "No third-party imports detected. Nothing to pip install."
    return 0
  fi

  uniq_pkgs=()
  for p in "${pkgs[@]}"; do
    found=0
    for q in "${uniq_pkgs[@]}"; do [ "$p" = "$q" ] && found=1; done
    [ "$found" -eq 0 ] && uniq_pkgs+=("$p")
  done

  log "Installing node.py imports: ${uniq_pkgs[*]}"
  "$PY" -m pip install -U pip setuptools wheel
  "$PY" -m pip install "${uniq_pkgs[@]}" || warn "Some packages failed to install; node.py may still run if they weren't needed."
  ok "Pip install step completed."
}

main() {
  apt_install
  _venv

  local url="${NODE_PY_URL:-$DEFAULT_NODE_URL}"

  if is_url "${1:-}"; then
    url="$1"
    shift
  fi

  local node_py
  node_py="$(_fetch_node_py "$url")"

  pip__node "$node_py"

  log "Starting node.py..."
  exec "$PY" "$node_py" "$@"
}

main "$@"
