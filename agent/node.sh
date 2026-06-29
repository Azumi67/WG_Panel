#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/Azumi67/WG_Panel.git"
RAW_BASE="https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main"
INSTALL_DIR="/usr/local/bin/wg_panel"
AGENT_DIR="$INSTALL_DIR/agent"
NODE_PY="$AGENT_DIR/node.py"
VENV_DIR="$AGENT_DIR/venv"
PY="$VENV_DIR/bin/python"

NO_APT=0

log()  { printf '\033[96m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[92m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[93m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[91m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
WG Panel Node Installer

Usage:
  sudo bash node.sh [options]

Options:
  --dir PATH     Install/update WG_Panel in PATH
  --no-apt       Skip apt package installation
  -h, --help     Show this help

Examples:
  sudo bash node.sh
  sudo bash node.sh --dir /opt/wg_panel
EOF
}

while [ "${1:-}" != "" ]; do
  case "$1" in
    --dir)
      shift
      [ "${1:-}" != "" ] || die "--dir requires a path"
      INSTALL_DIR="$1"
      AGENT_DIR="$INSTALL_DIR/agent"
      NODE_PY="$AGENT_DIR/node.py"
      VENV_DIR="$AGENT_DIR/venv"
      PY="$VENV_DIR/bin/python"
      ;;
    --no-apt)
      NO_APT=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
  shift
done

apt_install() {
  [ "$NO_APT" -eq 1 ] && return 0

  command -v apt-get >/dev/null 2>&1 || {
    warn "apt-get not found; skipping OS deps."
    return 0
  }

  [ "$(id -u)" -eq 0 ] || die "Run with sudo/root, or use --no-apt."

  log "Installing OS dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    git curl ca-certificates python3 python3-venv python3-pip wireguard-tools iproute2 iptables

  ok "OS dependencies installed."
}

fetch_repo() {
  mkdir -p "$(dirname "$INSTALL_DIR")"

  if [ -d "$INSTALL_DIR/.git" ]; then
    log "Updating existing repository: $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --all --prune
    git -C "$INSTALL_DIR" reset --hard origin/main
    ok "Repository updated."
    return 0
  fi

  if [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null || true)" ]; then
    die "Install directory exists and is not empty: $INSTALL_DIR"
  fi

  log "Cloning WG_Panel into: $INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
  ok "Repository cloned."
}

fallback_download_agent() {
  mkdir -p "$AGENT_DIR"

  if [ ! -f "$NODE_PY" ]; then
    log "Downloading node.py directly..."
    curl -fsSL "$RAW_BASE/agent/node.py" -o "$NODE_PY"
  fi

  if [ -f "$RAW_BASE/agent/requirements.txt" ]; then
    :
  fi
}

validate_files() {
  [ -f "$NODE_PY" ] || die "node.py not found: $NODE_PY"

  python3 -m py_compile "$NODE_PY" || {
    die "node.py has a Python syntax error. Check that the file was uploaded to GitHub with proper line breaks."
  }

  ok "node.py found and syntax check passed."
}

venv_install() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found."

  if [ ! -x "$PY" ]; then
    log "Creating Python venv: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    ok "Venv created."
  fi

  log "Upgrading pip..."
  "$PY" -m pip install -U pip setuptools wheel

  if [ -f "$AGENT_DIR/requirements.txt" ]; then
    log "Installing agent requirements..."
    "$PY" -m pip install -r "$AGENT_DIR/requirements.txt"
  elif [ -f "$INSTALL_DIR/requirements.txt" ]; then
    log "Installing project requirements..."
    "$PY" -m pip install -r "$INSTALL_DIR/requirements.txt"
  else
    warn "No requirements.txt found. Installing common agent dependencies."
    "$PY" -m pip install requests psutil flask werkzeug cryptography python-dotenv
  fi

  ok "Python dependencies installed."
}

create_launcher() {
  cat >/usr/local/bin/node <<EOF
#!/usr/bin/env bash
exec "$PY" "$NODE_PY" "\$@"
EOF

  chmod +x /usr/local/bin/node
  ok "Command installed: node"
}

main() {
  apt_install
  fetch_repo
  validate_files
  venv_install
  create_launcher

  log "Starting node menu..."
  exec "$PY" "$NODE_PY"
}

main "$@"
