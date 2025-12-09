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

# Optional: start a lightweight agent simulator if present
if [ "${1:-}" != "--no-agent" ]; then
  if [ -f "$ROOT_DIR/agent/run_agent_simulator.py" ]; then
    echo "Starting agent simulator..."
    (
      cd "$ROOT_DIR/agent"
      nohup "$VENV_PY" run_agent_simulator.py > "$LOG_DIR/agent.log" 2>&1 &
    )
  else
    echo "No agent simulator found; skipping agent startup"
  fi
else
  echo "Agent startup skipped by flag"
fi

echo "All services started. Logs -> $LOG_DIR"
echo "Open Dashboard UI: http://localhost:8000/ (use API key 'secret-token' in UI)"
