"""
Lightweight Enforcer Simulator
Sends benign and malicious alerts to the dashboard for demo purposes without requiring root.
Run: python3 agent/enforcer_simulator.py --duration 30
"""
import time
import requests
import argparse
import random
from datetime import datetime

API = "http://127.0.0.1:8000/alerts"
HEADERS = {"Content-Type": "application/json", "X-API-Key": "secret-token"}

ATTACKS = [
    ("SQL Injection", 0.92, "' OR 1=1 --"),
    ("DDoS", 0.88, "SYN Flood"),
    ("Benign", 0.0, "GET /index.html")
]


def send_alert(a_type, conf, payload):
    data = {
        "source_ip": f"192.168.10.{random.randint(2,250)}",
        "destination_ip": "10.0.0.5",
        "attack_type": a_type,
        "confidence_score": conf,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "payload_sample": payload
    }
    try:
        r = requests.post(API, json=data, headers=HEADERS, timeout=3)
        print(f"Sent: {a_type} -> {r.status_code}")
    except Exception as e:
        print(f"Error sending alert: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--duration', type=int, default=30, help='Duration in seconds')
    args = parser.parse_args()

    end = time.time() + args.duration
    while time.time() < end:
        # Send a benign and an attack every cycle
        send_alert(*ATTACKS[2])
        time.sleep(0.8)
        send_alert(*ATTACKS[random.randint(0,1)])
        time.sleep(0.8)

    print('Simulator finished')
