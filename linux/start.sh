#!/usr/bin/env bash
# Start Maldoc Triage Workbench:  linux/start.sh [sample]
cd "$(dirname "$0")/.."         # the app folder
if [ -x .venv/bin/python ]; then
  exec .venv/bin/python run.py "$@"
fi
exec python3 run.py "$@"
