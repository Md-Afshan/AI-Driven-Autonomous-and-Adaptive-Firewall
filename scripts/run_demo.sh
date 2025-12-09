#!/usr/bin/env bash
# Run the ML engine, dashboard and the demo agent locally (non-root, dev mode)
set -e
WORKDIR=$(dirname "$(realpath "$0")")/..
cd "$WORKDIR"
# Ensure venv is activated; use the project's .venv if available
PY="$WORKDIR/.venv/bin/python"
if [ ! -x "$PY" ]; then
  PY=$(which python3 || true)
fi
# Start ML engine
cd "$WORKDIR/AI-Driven-Autonomous-and-Adaptive-Firewall/ml-engine"
$PY -m uvicorn app.main:app --port 5001 > /tmp/demo_ml.log 2>&1 &
ML_PID=$!
sleep 1
# Start dashboard
cd "$WORKDIR/AI-Driven-Autonomous-and-Adaptive-Firewall/dashboard-api"
$PY -m uvicorn app.main:app --port 8000 > /tmp/demo_dashboard.log 2>&1 &
DASH_PID=$!
sleep 1
# Start demo agent feeder
cd "$WORKDIR/AI-Driven-Autonomous-and-Adaptive-Firewall/tools"
$PY demo_agent.py --dashboard http://127.0.0.1:8000 --api-key secret-token --rate 5 --duration 60 > /tmp/demo_agent.log 2>&1 &
AG_PID=$!

echo "ML engine PID: $ML_PID"
echo "Dashboard PID: $DASH_PID"
echo "Demo agent PID: $AG_PID"
echo "Tail logs: tail -f /tmp/demo_dashboard.log /tmp/demo_ml.log /tmp/demo_agent.log"

# Wait for processes to exit
wait $AG_PID || true
# Kill web servers
kill $ML_PID $DASH_PID || true
