#!/usr/bin/env bash
set -euo pipefail

# run_all.sh — start ML engine, dashboard, and optional agent simulator
# Usage: ./run_all.sh [--no-agent]

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Detect venv python path for Unix or Windows
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  VENV_PY="$ROOT_DIR/.venv/bin/python"
elif [ -x "$ROOT_DIR/.venv/Scripts/python.exe" ]; then
  VENV_PY="$ROOT_DIR/.venv/Scripts/python.exe"
else
  VENV_PY="python3"
fi

LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"

echo "Starting ML engine (ml-engine) on port 5001..."
(
  cd "$ROOT_DIR/ml-engine"
  nohup "$VENV_PY" -m uvicorn app.main:app --host 0.0.0.0 --port 5001 > "$LOG_DIR/ml-engine.log" 2>&1 &
)

sleep 1

echo "Starting Dashboard (dashboard-api) on port 8000..."
(
  cd "$ROOT_DIR/dashboard-api"
  nohup "$VENV_PY" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/dashboard.log" 2>&1 &
)

sleep 1

# Optional: start the demo agent (tools/demo_agent.py)
if [ "${1:-}" != "--no-agent" ]; then
  if [ -f "$ROOT_DIR/tools/demo_agent.py" ]; then
    echo "Starting demo agent..."
    (
      cd "$ROOT_DIR/tools"
      nohup "$VENV_PY" demo_agent.py --dashboard http://127.0.0.1:8000 --duration 300 > "$LOG_DIR/demo_agent.log" 2>&1 &
    )
  else
    echo "No demo agent found; skipping agent startup"
  fi
else
  echo "Agent startup skipped by flag"
fi

echo "All services started. Logs -> $LOG_DIR"
echo "Open Dashboard UI: http://localhost:8000/ (use API key 'secret-token' in UI)"
