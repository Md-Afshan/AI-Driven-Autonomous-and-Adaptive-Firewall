#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
3-VM Demo Runbook - Kali (attacker) , Firewall (agent) , Dashboard (server)

Overview:
- Dashboard: runs at http://<dashboard-ip>:8000 (start on Dashboard VM)
- Firewall: run `saas_enforcer.py` there to capture/act on packets
- Kali: generate traffic (curl/hping3) to verify live monitoring and enforcement

Commands (Dashboard VM):
  cd /path/to/AI-Firwall/AI-Driven-Autonomous-and-Adaptive-Firewall
  # Start ML engine (5001) and Dashboard (8000) using start_demo.sh
  ./scripts/start_demo.sh --no-tests

Commands (Firewall VM):
  # Determine external interface (e.g., enp0s8)
  ip -o link show | awk -F': ' '{print $2}'
  # Run enforcer (ensure dashboard reachable from firewall)
  sudo python agent/saas_enforcer.py --mode local --iface <your-iface> --dashboard-url http://<dashboard-ip>:8000

Commands (Kali attacker VM):
  # Simple HTTP request (try SQL-like payload to trigger WAF)
  curl "http://<victim-ip>/?q=' OR 1=1 --"

  # SYN flood (DDoS demo) - be careful, only use in lab
  sudo hping3 -S -p 80 --flood <victim-ip>

Validation:
  - Watch Dashboard Live Packet Stream for per-packet rows
  - Watch the Alerts list for SQL Injection or DDoS alerts
  - On Firewall, check blocked IPs: sudo ipset list blacklist

Stopping:
  - On Dashboard machine: ./scripts/stop_demo.sh
  - On Firewall machine: find saas_enforcer process (ps aux | grep saas_enforcer) and kill it

EOF

echo "Runbook displayed. Edit the file to customize hostnames and interfaces for your lab."
