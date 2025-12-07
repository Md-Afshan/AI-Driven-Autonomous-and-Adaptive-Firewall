Quick start (Linux host, docker required):

1. Build and start services from `infra` folder:

```powershell
cd C:\Users\admin\OneDrive\Desktop\PROJECT\infra
docker-compose up --build
```

2. ML Engine listens on `5001` and expects alerts at `/alerts`.
	The `dashboard-api` forwards incoming alerts to ML Engine and requires header `x-api-key: secret-token` by default.

3. For testing, run the simulator container then exec into it and run the `simulate_attack.py` script (requires scapy installed):

```powershell
docker-compose run --rm simulator bash
pip install scapy
python /opt/tools/simulate_attack.py <target_ip> <port> <pps> <duration>
```

Caveats:
- Running packet capture and iptables manipulation requires root privileges. Use a controlled lab environment.
- The code is a prototype; review and harden before production.
See `infra/docker-compose.yml` for how services are orchestrated.

Quick start (Linux host, docker required):

1. Build and start services from `infra` folder:

```powershell
cd C:\Users\admin\OneDrive\Desktop\PROJECT\infra
docker-compose up --build
```

2. ML Engine listens on `5001` and expects alerts at `/alerts`.
	The `dashboard-api` forwards incoming alerts to ML Engine and requires header `x-api-key: secret-token` by default.

3. For testing, run the simulator container then exec into it and run the `simulate_attack.py` script (requires scapy installed):

```powershell
docker-compose run --rm simulator bash
pip install scapy
python /opt/tools/simulate_attack.py <target_ip> <port> <pps> <duration>
```

Caveats:
- Running packet capture and iptables manipulation requires root privileges. Use a controlled lab environment.
- The code is a prototype; review and harden before production.
Autonomous AI Firewall - Prototype
=================================

This repository contains a prototype SaaS-style Autonomous AI Firewall focusing on Layer 3/4 detection and mitigation using an RL-based "brain".

Structure:
- `agent/packet_engine/go` - Packet capture and detectors (Go preferred for production; Python prototypes included).
- `agent/packet_engine/python` - Python prototype using scapy for rapid testing.
- `agent/controls` - Firewall control helpers (Python wrapper for `iptables`).
- `ml-engine` - RL agent and training/serving scaffolding (Python, PyTorch/stable-baselines3 compatible skeleton).
- `dashboard-api` - FastAPI backend for alerts and operator controls.
- `infra/docker-compose.yml` - Compose file to orchestrate services.

Notes:
- Running packet capture and firewall controls requires root privileges.
- This code is structural/pseudocode and intended for prototyping and architecture discussion.

Next steps:
- Implement full packet parsing and high-performance datapath.
- Train RL agent with realistic simulated traffic environments.
- Integrate safe enforcement hooks (dry-run, policy simulation).
