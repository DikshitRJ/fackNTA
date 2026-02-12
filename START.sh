#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$DIR/.venv/bin/python"

if [ ! -f "$PY" ]; then
    echo "Virtual environment not found at $PY"
    echo "Create it with: python3 -m venv .venv"
    exit 1
fi

# Run scripts in the background
"$PY" "$DIR/jee_results_monitor.py" &
"$PY" "$DIR/Main_tracker.py" &
wait
