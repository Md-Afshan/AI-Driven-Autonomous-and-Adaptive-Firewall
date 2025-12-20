#!/usr/bin/env bash
set -euo pipefail

# reset_dashboard.sh
# Call the admin reset endpoint to clear alerts, stats and logs

URL=${1:-http://127.0.0.1:8000}
API_KEY=${API_KEY:-${2:-secret-token}}

echo "Calling $URL/admin/reset with API key..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL/admin/reset" -H "X-API-Key: $API_KEY" || true)
if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "202" ]]; then
  echo "Dashboard reset OK (HTTP $HTTP_CODE)."
else
  echo "Dashboard reset failed or returned HTTP $HTTP_CODE."
fi
