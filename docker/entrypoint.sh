#!/usr/bin/env bash
set -Eeuo pipefail

cd /app
umask 077
mkdir -p /app/instance /etc/wireguard

ROLE="${WG_CONTAINER_ROLE:-panel}"
PANEL_SECRET_FILE="/app/instance/docker-secrets.env"
AGENT_SECRET_FILE="/app/instance/docker-agent-secrets.env"

truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

load_saved_env() {
  local file="$1"
  if [ -f "$file" ]; then
    . "$file"
  fi
}

write_panel_secrets() {
  local secret="${FLASK_SECRET_KEY:-}"
  local fernet="${FERNET_KEY:-}"
  local api="${API_KEY:-}"

  if [ -z "$secret" ]; then
    secret="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  fi
  if [ -z "$fernet" ]; then
    fernet="$(python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"
  fi
  if [ -z "$api" ]; then
    api="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  fi

  export FLASK_SECRET_KEY="$secret"
  export FERNET_KEY="$fernet"
  export API_KEY="$api"

  {
    printf 'FLASK_SECRET_KEY=%q\n' "$FLASK_SECRET_KEY"
    printf 'FERNET_KEY=%q\n' "$FERNET_KEY"
    printf 'API_KEY=%q\n' "$API_KEY"
  } > "$PANEL_SECRET_FILE"
  chmod 0600 "$PANEL_SECRET_FILE"
}

write_agent_secret() {
  local api="${API_KEY:-}"
  if [ -z "$api" ]; then
    api="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  fi
  export API_KEY="$api"
  printf 'API_KEY=%q\n' "$API_KEY" > "$AGENT_SECRET_FILE"
  chmod 0600 "$AGENT_SECRET_FILE"
}

case "$ROLE" in
  panel)
    saved_flask="${FLASK_SECRET_KEY:-}"
    saved_fernet="${FERNET_KEY:-}"
    saved_api="${API_KEY:-}"
    load_saved_env "$PANEL_SECRET_FILE"
    [ -n "$saved_flask" ] && FLASK_SECRET_KEY="$saved_flask"
    [ -n "$saved_fernet" ] && FERNET_KEY="$saved_fernet"
    [ -n "$saved_api" ] && API_KEY="$saved_api"
    write_panel_secrets

    export DATABASE_URL="${DATABASE_URL:-sqlite:///instance/wg_panel.db}"
    export LOG_LEVEL="${LOG_LEVEL:-INFO}"
    export SECURE_COOKIES="${SECURE_COOKIES:-0}"
    export WIREGUARD_CONF_PATH="${WIREGUARD_CONF_PATH:-/etc/wireguard}"
    export BIND="${BIND:-0.0.0.0:8000}"
    export USE_GUNICORN="${USE_GUNICORN:-1}"
    ;;
  bot)
    saved_api="${API_KEY:-}"
    if [ -z "$saved_api" ]; then
      for _ in $(seq 1 60); do
        [ -f "$PANEL_SECRET_FILE" ] && break
        sleep 0.5
      done
      load_saved_env "$PANEL_SECRET_FILE"
    fi
    [ -n "$saved_api" ] && API_KEY="$saved_api"
    if [ -z "${API_KEY:-}" ]; then
      echo "ERROR: panel API key unavailable; start the panel first or set API_KEY." >&2
      exit 78
    fi
    export API_KEY
    export PANEL_API_KEY="${PANEL_API_KEY:-$API_KEY}"
    export LOG_LEVEL="${LOG_LEVEL:-INFO}"
    ;;
  agent)
    saved_api="${API_KEY:-}"
    load_saved_env "$AGENT_SECRET_FILE"
    [ -n "$saved_api" ] && API_KEY="$saved_api"
    write_agent_secret

    export WIREGUARD_CONF_PATH="${WIREGUARD_CONF_PATH:-/etc/wireguard}"
    export BIND="${BIND:-0.0.0.0:9898}"
    export USE_GUNICORN="${USE_GUNICORN:-1}"
    ;;
  *)
    echo "ERROR: unsupported WG_CONTAINER_ROLE=$ROLE (use panel, bot, or agent)" >&2
    exit 64
    ;;
esac

if [ "$ROLE" = "bot" ] && [ "$#" -eq 0 ]; then
  set -- python telegram_bot.py
elif [ "$ROLE" = "agent" ] && [ "$#" -eq 0 ]; then
  set -- python agent/node_agent.py
elif [ "$ROLE" = "panel" ] && [ "$#" -eq 0 ]; then
  set -- python app.py
fi

exec "$@"
