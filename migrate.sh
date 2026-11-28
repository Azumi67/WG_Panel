#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  printf '%s\n' 'Usage: sudo bash migrate.sh [--project /path/to/WGPanel] [--upgrade] [--check | --inspect | --writers | --no-install]' \
    'For an older installation, run this script from the extracted complete release with --upgrade --project /path/to/WGPanel.' \
    'The migration requires interactive MIGRATE confirmation and keeps the SQLite source.'
}

project=''
upgrade=0
inspect=0
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
args=()
while (($#)); do
  case "$1" in
    --project)
      if (($# < 2)); then usage >&2; exit 2; fi
      project="$2"; shift 2 ;;
    --upgrade) upgrade=1; shift ;;
    --inspect) inspect=1; shift ;;
    --check|--writers|--no-install) args+=("$1"); shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [[ -z "$project" ]]; then
  candidates=()
  for dir in "$here" "$PWD" /usr/local/bin/WGPanel /usr/local/bin/WG_Panel; do
    if [[ -f "$dir/app.py" && -f "$dir/.env" ]]; then
      resolved=$(cd -- "$dir" && pwd -P)
      duplicate=0
      for found in "${candidates[@]}"; do [[ "$found" == "$resolved" ]] && duplicate=1; done
      if ((duplicate == 0)); then candidates+=("$resolved"); fi
    fi
  done
  if ((${#candidates[@]} != 1)); then
    printf '%s\n' 'Cannot uniquely identify the installed panel. Specify --project /path/to/WGPanel.' >&2
    exit 2
  fi
  project=${candidates[0]}
fi
cd -- "$project"
project=$(pwd -P)
source="$project"
if ((upgrade)); then source="$here"; fi
if [[ ! -f .env || ! -f app.py || ! -x venv/bin/python || ! -f "$source/scripts/easy_postgres_migrate.py" || ! -f "$source/scripts/migrate_sqlite_to_postgres.py" || ! -f "$source/scripts/check_postgresql.py" || ! -f "$source/requirements-postgres.txt" ]]; then
  printf '%s\n' 'Existing panel, virtual environment or updated migration files are missing. For old versions, extract the complete new release and use --upgrade. Never replace .env or the database.' >&2
  exit 2
fi
if ((EUID != 0)); then
  printf '%s\n' 'Run this launcher with sudo.' >&2
  exit 2
fi
if ((inspect)); then
  if ((${#args[@]})); then usage >&2; exit 2; fi
  exec ./venv/bin/python -u "$source/scripts/migrate_sqlite_to_postgres.py" --sqlite instance/wg_panel.db --inspect-source-only
fi
if ((upgrade)); then
  args+=(--project "$project")
fi
exec ./venv/bin/python -u "$source/scripts/easy_postgres_migrate.py" "${args[@]}"
