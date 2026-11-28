#!/usr/bin/env bash
set -euo pipefail
role="${1:?role required}"
case "$role" in
  panel) file=/app/instance/docker-secrets.env ;;
  agent) file=/app/instance/docker-agent-secrets.env ;;
  *) exit 1 ;;
esac
[ -s "$file" ] || exit 1
. "$file"
export API_KEY
exec python /app/docker/healthcheck.py "$role"
