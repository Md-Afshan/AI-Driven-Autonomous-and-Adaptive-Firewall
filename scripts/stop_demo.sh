#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"

echo "Stopping demo services..."

# Stop demo agent
pgrep -f demo_agent.py >/dev/null 2>&1 && pkill -f demo_agent.py && echo "Stopped demo_agent"

# Stop enforcer (if started with pidfile)
if [ -f "$LOG_DIR/enforcer.pid" ]; then
  pid=$(cat "$LOG_DIR/enforcer.pid")
  if ps -p $pid >/dev/null 2>&1; then
    sudo kill $pid && echo "Stopped saas_enforcer pid $pid"
  fi
  rm -f "$LOG_DIR/enforcer.pid"
else
  # Fallback: pkill by process name
  if pgrep -f 'saas_enforcer.py' >/dev/null 2>&1; then
    sudo pkill -f 'saas_enforcer.py' && echo "Stopped saas_enforcer via pkill"
  fi
fi

# Stop uvicorn processes started by scripts (ML engine and Dashboard)
pkill -f "uvicorn app.main:app --port 5001" || true
pkill -f "uvicorn app.main:app --port 8000" || true
pkill -f "uvicorn app.main:app --port 8002" || true

echo "Stopped uvicorn processes (if any). Check logs in $LOG_DIR for details."

echo "Done."
