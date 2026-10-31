#!/bin/sh
# ASK — one-command run for anyone, on any system with Python.
# No computer knowledge needed:
#   ./run.sh            -> starts the dashboard, prints the link to open
#   ./run.sh --log x.log -> processes x.log first, then starts the dashboard
# It creates its own folder (.venv) the first time, installs only
# duckdb + networkx + pyyaml, and never touches your system Python.
set -e
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Sorry — Python 3 is not installed on this computer."
  echo "Install Python 3 from python.org, then run ./run.sh again."
  exit 1
fi
if [ ! -x ".venv/bin/python" ]; then
  echo "First run: setting up ASK (this takes a minute, only once)..."
  python3 -m venv .venv
  .venv/bin/pip install -q duckdb networkx pyyaml
fi
LOG_ARGS=""
for arg in "$@"; do
  case "$arg" in
    --log) ;;
    *) if [ -f "$arg" ]; then LOG_ARGS="--log $arg"; fi ;;
  esac
done
echo ""
echo "ASK is starting. Open this link in your browser:"
echo "  http://127.0.0.1:8001/app"
echo "If that port is busy, ASK will print the next free port instead."
echo "To stop it, press Ctrl+C in this window."
echo ""
if [ -n "$LOG_ARGS" ]; then
  .venv/bin/python main.py run $LOG_ARGS --db ask.duckdb
fi
.venv/bin/python main.py serve --db ask.duckdb --port 8001
