#!/usr/bin/env bash
set -euo pipefail

# start_demo.sh - create venv, install deps, start ML engine, Dashboard, demo agent, and run integration tests
# Usage: ./scripts/start_demo.sh [--no-demo] [--no-tests]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
PY="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"
LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"

NO_DEMO=0
NO_TESTS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-demo) NO_DEMO=1; shift ;;
    --no-tests) NO_TESTS=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Create virtualenv if missing
if [ ! -x "$PY" ]; then
  echo "Creating virtualenv..."
  python3 -m venv "$VENV_DIR"
  echo "Installing requirements into venv..."
  "$PIP" install --upgrade pip
  "$PIP" install -r "$ROOT_DIR/requirements.txt"
else
  echo "Using existing virtualenv at $VENV_DIR"
fi

# Start ML engine if not already running
echo "Ensuring ML engine is running on port 5001..."
if ss -ltnp 2>/dev/null | grep -q ':5001'; then
  echo "ML engine appears to be already running on port 5001; skipping start"
else
  echo "Starting ML engine (port 5001)..."
  (
    cd "$ROOT_DIR/AI-Driven-Autonomous-and-Adaptive-Firewall/ml-engine"
    nohup "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port 5001 > "$LOG_DIR/ml_engine.log" 2>&1 &
  )
fi
(
  cd "$ROOT_DIR/AI-Driven-Autonomous-and-Adaptive-Firewall/ml-engine"
  nohup "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port 5001 > "$LOG_DIR/ml_engine.log" 2>&1 &
)

# Start Dashboard if not already running
echo "Ensuring Dashboard is running on port 8000..."
if ss -ltnp 2>/dev/null | grep -q ':8000'; then
  echo "Dashboard appears to be already running on port 8000; skipping start"
else
  echo "Starting Dashboard (port 8000)..."
  (
    cd "$ROOT_DIR/AI-Driven-Autonomous-and-Adaptive-Firewall/dashboard-api"
    nohup "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/dashboard.log" 2>&1 &
  )
fi
(
  cd "$ROOT_DIR/AI-Driven-Autonomous-and-Adaptive-Firewall/dashboard-api"
  nohup "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/dashboard.log" 2>&1 &
)

# Wait for services to be ready
wait_for_http() {
  local url=$1
  local timeout=${2:-30}
  local start=$(date +%s)
  echo -n "Waiting for $url to be ready... "
  while true; do
    "$PY" - <<PY >/dev/null 2>&1 || true
import requests, sys
try:
    r = requests.get('$url', timeout=2)
    sys.exit(0 if r.status_code < 500 else 2)
except Exception:
    sys.exit(1)
PY
    rc=$?
    if [ "$rc" = "0" ]; then
      echo "OK"
      return 0
    fi
    now=$(date +%s)
    if [ $((now - start)) -ge $timeout ]; then
      echo "TIMEOUT"
      return 1
    fi
    sleep 1
  done
}

wait_for_http "http://127.0.0.1:5001/models/active" 45 || (echo "ML engine did not start in time. Check $LOG_DIR/ml_engine.log"; exit 1)
wait_for_http "http://127.0.0.1:8000/live-stats" 45 || (echo "Dashboard did not start in time. Check $LOG_DIR/dashboard.log"; exit 1)

# Start demo agent (optional)
if [ $NO_DEMO -eq 0 ]; then
  echo "Starting demo agent (tools/demo_agent.py)..."
  (
    cd "$ROOT_DIR/AI-Driven-Autonomous-and-Adaptive-Firewall/tools"
    nohup "$PY" demo_agent.py --dashboard http://127.0.0.1:8000 --duration 300 > "$LOG_DIR/demo_agent.log" 2>&1 &
  )
else
  echo "Demo agent startup skipped (--no-demo)"
fi

# Run integration tests (optional)
if [ $NO_TESTS -eq 0 ]; then
  echo "Running integration tests..."
  "$PY" tests/integration/run_integration.py || (echo "Integration tests failed; see logs"; exit 1)
else
  echo "Skipping integration tests (--no-tests)"
fi

echo "All done. Logs are in $LOG_DIR"
echo "Browse the dashboard: http://127.0.0.1:8000 (API key: secret-token)"
