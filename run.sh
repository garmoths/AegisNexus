#!/usr/bin/env bash
set -euo pipefail
cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

discovery_mode=false
if [ "${1:-}" = "--crawler" ]; then discovery_mode=true; shift; fi
if [ "${1:-}" = "--connected" ]; then shift; fi  # eski bayrak; artık varsayılan

if ! .venv/bin/python -c 'import sys; assert (3,11) <= sys.version_info < (3,14)' 2>/dev/null; then
  selected_python=""
  for candidate in python3.12 python3.11 python3.13 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; assert (3,11) <= sys.version_info < (3,14)' 2>/dev/null; then
      selected_python="$candidate"
      break
    fi
  done
  if [ -z "$selected_python" ]; then
    echo 'Python 3.12 gerekli. macOS: brew install python@3.12 | Ubuntu: sudo apt install python3 python3-venv' >&2
    exit 1
  fi
  echo 'Python ortamı hazırlanıyor…'
  "$selected_python" -m venv --clear .venv
fi
if [ "$discovery_mode" = true ]; then
  exec .venv/bin/python scripts/run_discovery.py "$@"
fi
exec .venv/bin/python scripts/run_local.py "$@"
