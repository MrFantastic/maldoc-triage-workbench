#!/usr/bin/env bash
# Start Maldoc Triage Workbench (REMnux edition):  ./start.sh [sample]
cd "$(dirname "$0")"
if [ -x .venv/bin/python ]; then
  exec .venv/bin/python run.py "$@"
fi
exec python3 run.py "$@"
