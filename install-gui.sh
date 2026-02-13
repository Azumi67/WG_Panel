#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f "app.py" ]]; then
  echo "Run from project root (where app.py exists)."
  exit 1
fi

sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip

python3 -m venv .installer-venv
.installer-venv/bin/pip install --upgrade pip wheel
.installer-venv/bin/pip install flask

export INSTALLER_BIND="${INSTALLER_BIND:-0.0.0.0}"
export INSTALLER_PORT="${INSTALLER_PORT:-8888}"

echo "Open:"
echo "  http://<SERVER-IP>:${INSTALLER_PORT}"

exec sudo -E .installer-venv/bin/python installer/installer_web.py
