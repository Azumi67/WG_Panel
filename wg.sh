#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WG_PY="${WG_PY:-$SCRIPT_DIR/wg.py}"
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/venv}"
PY="$VENV_DIR/bin/python"

APT_PKGS=(python3 python3-venv python3-pip git rsync ca-certificates)
c_info="\033[96m"; c_ok="\033[92m"; c_warn="\033[93m"; c_err="\033[91m"; c_reset="\033[0m"
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then c_info=""; c_ok=""; c_warn=""; c_err=""; c_reset=""; fi
log()  { echo -e "${c_info}[INFO]${c_reset} $*"; }
ok()   { echo -e "${c_ok}[ OK ]${c_reset} $*"; }
warn() { echo -e "${c_warn}[WARN]${c_reset} $*" >&2; }
die()  { echo -e "${c_err}[FAIL]${c_reset} $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [options] [-- wg.py args...]

Options:
  --no-apt          Do not install OS packages
  --venv PATH       Venv directory (default: $VENV_DIR)
  --wg PATH         Path to wg.py (default: $WG_PY)
  -h, --help        Show help

Examples:
  sudo $0
  $0 --no-apt
  $0 -- --no-color
EOF
}

DO_APT=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-apt) DO_APT=0; shift ;;
    --venv) VENV_DIR="${2:-}"; [ -n "$VENV_DIR" ] || die "Missing value for --venv"; shift 2 ;;
    --wg) WG_PY="${2:-}"; [ -n "$WG_PY" ] || die "Missing value for --wg"; shift 2 ;;
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

  log "Installing minimal OS dependencies..."
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

install_requirements() {
  local req="$SCRIPT_DIR/requirements.txt"
  if [ ! -f "$req" ]; then
    warn "requirements.txt not found in $SCRIPT_DIR (skipping pip install)."
    return 0
  fi

  log "Updating pip tools..."
  "$PY" -m pip install -U pip setuptools wheel

  log "Installing/updating requirements.txt..."
  "$PY" -m pip install -r "$req"
  ok "Requirements installed."
}

_wg() {
  [ -f "$WG_PY" ] || die "wg.py not found at: $WG_PY"
  log "Running wg.py..."
  exec "$PY" "$WG_PY" "$@"
}

main() {
  install_stuff
  _venv
  install_requirements
  _wg "$@"
}

main "$@"
