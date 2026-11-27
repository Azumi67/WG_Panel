#!/usr/bin/env bash
set -euo pipefail

NODE_URL="${WG_NODE_PY_URL:-https://raw.githubusercontent.com/Azumi67/WG_Panel/main/agent/node.py}"
BOOTSTRAP_DIR="${WG_NODE_BOOTSTRAP_DIR:-/usr/local/lib/wg-panel-node-bootstrap}"
NODE_PY="$BOOTSTRAP_DIR/node.py"

log()  { printf '\033[96m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[92m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[93m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[91m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this installer as root (or with sudo)."
}

install_bootstrap_dependencies() {
  local need=0

  command -v python3 >/dev/null 2>&1 || need=1
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    need=1
  fi

  [ "$need" -eq 1 ] || return 0

  command -v apt-get >/dev/null 2>&1 || \
    die "python3 and curl/wget are required, and apt-get is not available."

  log "Installing bootstrap dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    python3

  command -v python3 >/dev/null 2>&1 || die "python3 installation failed."
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "curl/wget installation failed."
  fi

  ok "Bootstrap dependencies are ready."
}

download_node_py() {
  mkdir -p "$BOOTSTRAP_DIR"

  local tmp
  tmp="$(mktemp /tmp/wg-node-py.XXXXXX)"
  trap 'rm -f -- "$tmp"' EXIT

  log "Downloading WG Panel node.py..."

  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 15 --max-time 120 \
      "$NODE_URL" -o "$tmp"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=120 --tries=3 -O "$tmp" "$NODE_URL"
  else
    die "Neither curl nor wget is available."
  fi

  [ -s "$tmp" ] || die "Downloaded node.py is empty."

  log "Validating downloaded node.py..."
  python3 -m py_compile "$tmp" || die "Downloaded node.py failed Python syntax validation."

  install -m 0755 "$tmp" "$NODE_PY"
  ok "node.py saved to: $NODE_PY"
}

main() {
  require_root
  install_bootstrap_dependencies
  download_node_py

  log "Starting WG Node Installer..."
  exec python3 "$NODE_PY" "$@"
}

main "$@"
