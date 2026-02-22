#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/venv}"
PY="$VENV_DIR/bin/python"

DEFAULT_WG_URL="https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/wg.py"

APT_PKGS=(python3 python3-venv python3-pip ca-certificates curl)
c_info="\033[96m"; c_ok="\033[92m"; c_warn="\033[93m"; c_err="\033[91m"; c_reset="\033[0m"
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then c_info=""; c_ok=""; c_warn=""; c_err=""; c_reset=""; fi
log()  { echo -e "${c_info}[INFO]${c_reset} $*"; }
ok()   { echo -e "${c_ok}[ OK ]${c_reset} $*"; }
warn() { echo -e "${c_warn}[WARN]${c_reset} $*" >&2; }
die()  { echo -e "${c_err}[FAIL]${c_reset} $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [options] [WG_PY_RAW_URL] [-- wg.py args...]

Options:
  --no-apt         Do not install OS packages
  --venv PATH      Venv directory (default: $VENV_DIR)
  --force-fetch    Always re-download wg.py even if cached
  -h, --help       Show help

Examples:
  sudo $0
  sudo $0 --force-fetch
  sudo $0 https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/wg.py
  sudo $0 -- --no-color
EOF
}

DO_APT=1
FORCE_FETCH=0

is_url() { [[ "${1:-}" =~ ^https?:// ]]; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-apt) DO_APT=0; shift ;;
    --venv) VENV_DIR="${2:-}"; [ -n "$VENV_DIR" ] || die "Missing value for --venv"; shift 2 ;;
    --force-fetch) FORCE_FETCH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

PY="$VENV_DIR/bin/python"

install_stuff() {
  if [ "$DO_APT" -eq 0 ]; then
    warn "Skipping apt install (--no-apt)."
    return 0
  fi
  command -v apt-get >/dev/null 2>&1 || { warn "apt-get not found; skipping OS deps."; return 0; }

  if [ "$(id -u)" -ne 0 ]; then
    die "apt install needs root. Re-run: sudo $0 (or use --no-apt)"
  fi

  log "Installing minimal OS dependencies (python3/venv/pip/curl)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "${APT_PKGS[@]}"
  ok "OS dependencies installed."
}

_venv() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found."
  if [ ! -x "$PY" ]; then
    log "Creating venv: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    ok "Venv created."
  fi
}

_fetch_wg_py() {
  local url="$1"
  local cache_dir="$SCRIPT_DIR/.cache"
  mkdir -p "$cache_dir"
  local out="$cache_dir/wg.py"

  if [ "$FORCE_FETCH" -eq 0 ] && [ -s "$out" ]; then
    echo -e "${c_ok}[ OK ]${c_reset} Using cached wg.py: $out" >&2
    echo "$out"
    return 0
  fi

  command -v curl >/dev/null 2>&1 || die "curl not found (install it or run with --no-apt and install curl)."

  echo -e "${c_info}[INFO]${c_reset} Downloading wg.py from: $url" >&2
  curl -fsSL "$url" -o "$out" || die "Failed to download wg.py from URL."
  echo -e "${c_ok}[ OK ]${c_reset} Downloaded wg.py -> $out" >&2

  echo "$out"
}

install_requirements() {
  local wg_py="$1"
  [ -f "$wg_py" ] || die "wg.py not found at: $wg_py"

  log "Updating pip tools..."
  "$PY" -m pip install -U pip setuptools wheel

  local pkgs=()

  if grep -qE '(^|[[:space:]])from[[:space:]]+passlib\.|(^|[[:space:]])import[[:space:]]+passlib\b' "$wg_py"; then
    pkgs+=("passlib[bcrypt]>=1.7" "bcrypt>=4.1")
  fi

  if [ "${#pkgs[@]}" -eq 0 ]; then
    ok "wg.py has no external pip dependencies detected by this installer."
    return 0
  fi

  log "Installing wg.py requirements: ${pkgs[*]}"
  "$PY" -m pip install -U "${pkgs[@]}"
  ok "wg.py imports installed."
}

_run_wg() {
  local wg_py="$1"; shift
  [ -f "$wg_py" ] || die "wg.py not found at: $wg_py"
  log "Running wg.py..."
  exec "$PY" "$wg_py" "$@"
}

main() {
  install_stuff
  _venv

  local url="${WG_PY_URL:-$DEFAULT_WG_URL}"

  if is_url "${1:-}"; then
    url="$1"
    shift
  fi

  local wg_py
  wg_py="$(_fetch_wg_py "$url")"

  install_requirements "$wg_py"
  _run_wg "$wg_py" "$@"
}

main "$@"
