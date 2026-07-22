#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/venv}"
PY="$VENV_DIR/bin/python"

DEFAULT_WG_URL="https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/wg.py"

APT_PKGS=(
  sudo
  ca-certificates
  curl
  wget
  git
  jq
  rsync
  unzip
  openssl
  python3
  python3-venv
  python3-pip
  python3-dev
  build-essential
  pkg-config
  libffi-dev
  libssl-dev
  wireguard
  wireguard-tools
  iproute2
  iptables
  procps
)
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

  command -v apt-get >/dev/null 2>&1 || {
    die "apt-get not found. This launcher supports Debian/Ubuntu."
  }

  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      die "apt install needs root. Re-run: sudo bash $0"
    fi

    die "Root is required and sudo is not installed. Run: su -  then  bash $0"
  fi

  if [ -r /etc/os-release ]; then
    . /etc/os-release

    case "${ID:-}" in
      debian)
        case "${VERSION_ID:-}" in
          12|13)
            log "Detected ${PRETTY_NAME:-Debian}."
            ;;
          *)
            warn "Detected Debian ${VERSION_ID:-unknown}; continuing with Debian-compatible packages."
            ;;
        esac
        ;;
      ubuntu)
        log "Detected ${PRETTY_NAME:-Ubuntu}."
        ;;
      *)
        warn "Detected ${PRETTY_NAME:-unknown OS}; apt compatibility is not guaranteed."
        ;;
    esac
  fi

  log "Installing Debian 13 / Ubuntu OS requirements..."
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a

  apt-get update \
    -o Dpkg::Use-Pty=0 \
    -o Acquire::Retries=3

  apt-get install -y \
    -o Dpkg::Use-Pty=0 \
    --no-install-recommends \
    "${APT_PKGS[@]}"

  ok "OS dependencies installed."

  local missing=()
  local cmd

  for cmd in python3 git curl rsync unzip wg ip iptables; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    die "Required commands are still missing: ${missing[*]}"
  fi

  ok "Required commands verified."
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

  echo -e "${c_info}[INFO]${c_reset} Downloading wg.py from: $url" >&2

  local tmp="${out}.download"
  rm -f "$tmp"

  if command -v curl >/dev/null 2>&1; then
    curl \
      --fail \
      --silent \
      --show-error \
      --location \
      --retry 3 \
      --retry-delay 2 \
      --connect-timeout 15 \
      --max-time 180 \
      "$url" \
      -o "$tmp" || die "Failed to download wg.py with curl."

  elif command -v wget >/dev/null 2>&1; then
    wget \
      --quiet \
      --tries=3 \
      --timeout=30 \
      -O "$tmp" \
      "$url" || die "Failed to download wg.py with wget."

  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$url" "$tmp" <<'PY'
import pathlib
import sys
import urllib.request

url = sys.argv[1]
target = pathlib.Path(sys.argv[2])

request = urllib.request.Request(
    url,
    headers={"User-Agent": "WG-Panel-Bootstrap"},
)

with urllib.request.urlopen(request, timeout=180) as response:
    target.write_bytes(response.read())
PY
  else
    die "No downloader found. Install curl, wget, or python3."
  fi

  [ -s "$tmp" ] || die "Downloaded wg.py is empty."

  python3 -m py_compile "$tmp" ||
    die "Downloaded wg.py failed Python syntax validation."

  mv -f "$tmp" "$out"
  chmod 755 "$out"

  echo -e "${c_ok}[ OK ]${c_reset} Downloaded and validated wg.py -> $out" >&2
  echo "$out"
}

install_requirements() {
  local wg_py="$1"
  [ -f "$wg_py" ] || die "wg.py not found at: $wg_py"

  log "Updating pip tools..."
  "$PY" -m pip install -U pip setuptools wheel

  local pkgs=(
    "passlib[bcrypt]>=1.7.4"
    "bcrypt>=4.1"
  )

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
