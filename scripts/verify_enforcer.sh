#!/usr/bin/env bash
set -euo pipefail

# verify_enforcer.sh
# Quick verification tool to check saas_enforcer is posting packets to the Dashboard
# Usage: ./scripts/verify_enforcer.sh [--iface IFACE] [--dashboard URL] [--target IP] [--duration SEC]

DURATION=10
IFACE=""
DASHBOARD_URL="http://127.0.0.1:8000"
TARGET_IP="8.8.8.8"
API_KEY="${API_KEY:-secret-token}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2;;
    --dashboard) DASHBOARD_URL="$2"; shift 2;;
    --target) TARGET_IP="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    -h|--help) echo "Usage: $0 [--iface IFACE] [--dashboard URL] [--target IP] [--duration SEC]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done

if [[ -z "$IFACE" ]]; then
  # choose the first non-loopback, non-virtual interface
  IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | grep -v '^vir' | head -n1 || true)
  if [[ -z "$IFACE" ]]; then
    echo "Could not auto-detect an interface. Please pass --iface." >&2
    exit 2
  fi
fi

echo "Using interface: $IFACE"
echo "Dashboard URL: $DASHBOARD_URL"
echo "Target IP (for traffic generation): $TARGET_IP"
echo "Capture duration: ${DURATION}s"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump is required. Install it (sudo apt install tcpdump)" >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required. Install it (sudo apt install curl)" >&2
  exit 2
fi

# parse host and port from DASHBOARD_URL
DASHBOARD_HOST=$(echo "$DASHBOARD_URL" | sed -E 's#^https?://([^/:]+).*#\1#')
DASHBOARD_PORT=$(echo "$DASHBOARD_URL" | sed -E 's#^https?://[^:]+:([0-9]+).*#\1#')
if [[ -z "$DASHBOARD_PORT" ]]; then DASHBOARD_PORT=80; fi

TMP_OUT=$(mktemp)
echo "Starting tcpdump (writing to $TMP_OUT) ..."

# run tcpdump for DURATION seconds and capture ASCII (-A) to help spot HTTP posts
sudo timeout "$DURATION" tcpdump -n -i "$IFACE" -s 0 -A "tcp and host $DASHBOARD_HOST and port $DASHBOARD_PORT" > "$TMP_OUT" 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

echo "Sending a test /log-packet POST to the Dashboard (X-API-Key: $API_KEY)..."
TEST_JSON='{"timestamp": 0, "source_ip":"9.9.9.9","destination_ip":"1.2.3.4","protocol":"TCP","verdict":"allow","ml_sql_prob":0.42}'
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$DASHBOARD_URL/log-packet" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d "$TEST_JSON" --max-time 5 || true)
echo "Dashboard /log-packet HTTP response: $HTTP_CODE"

echo "Generating a few packets toward $TARGET_IP to make the enforcer see traffic..."
if command -v hping3 >/dev/null 2>&1; then
  sudo timeout 3 hping3 -S -p 80 -c 5 "$TARGET_IP" >/dev/null 2>&1 || true
elif python3 -c "import scapy.all as s; s.send(s.IP(dst='$TARGET_IP')/s.TCP(dport=80), count=5)" >/dev/null 2>&1; then
  true
else
  ping -c 5 "$TARGET_IP" >/dev/null 2>&1 || true
fi

echo "Waiting ${DURATION}s for capture to complete..."
sleep $((DURATION + 1))

# ensure tcpdump is gone
if ps -p $TCPDUMP_PID >/dev/null 2>&1; then
  sudo kill $TCPDUMP_PID >/dev/null 2>&1 || true
fi

echo "--- tcpdump output (filtered) ---"
grep -E "POST|HTTP/1.|9.9.9.9|log-packet|Content-Type: application/json" "$TMP_OUT" || true

echo "Checking enforcer logs for evidence of posting or packet events..."
if [[ -f logs/enforcer.log ]]; then
  echo "--- last 50 lines of logs/enforcer.log ---"
  tail -n 50 logs/enforcer.log | sed -n '1,200p'
  echo "--- grep for 9.9.9.9 or /log-packet ---"
  grep -E "9.9.9.9|/log-packet|log-packet" logs/enforcer.log || true
else
  echo "No enforcer log found at logs/enforcer.log (is saas_enforcer running?)"
fi

echo "Summary:" 
if grep -q -E "POST|HTTP/1.|9.9.9.9|log-packet|Content-Type: application/json" "$TMP_OUT"; then
  echo "  - Observed HTTP POSTs to Dashboard on interface $IFACE (tcpdump saw traffic). ✅"
else
  echo "  - Did NOT observe HTTP POSTs to Dashboard on interface $IFACE. ⚠️"
fi

if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" || "$HTTP_CODE" == "202" ]]; then
  echo "  - Dashboard accepted test POST (HTTP $HTTP_CODE). ✅"
else
  echo "  - Dashboard did not accept test POST or returned HTTP $HTTP_CODE. ⚠️"
fi

rm -f "$TMP_OUT"

exit 0
