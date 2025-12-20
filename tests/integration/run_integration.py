"""
Simple integration test that starts the dashboard API and sends traffic + alerts while
confirming that WebSocket clients receive messages.

NOTE: Requires `uvicorn` and `websockets` Python modules installed in the environment.
Run this script from the repo root:

python tests/integration/run_integration.py

"""

import asyncio
import subprocess
import time
import os
import requests
import json
import signal

try:
    import websockets
except Exception as e:
    print('Please install dependency: pip install websockets')
    raise

DASHBOARD_ROOT = os.path.join(os.path.dirname(__file__), '../../AI-Driven-Autonomous-and-Adaptive-Firewall/dashboard-api')
import sys

# Use the current Python executable to ensure the same environment is used
PY_EXE = sys.executable
# Allow overriding host/port (so tests can target a remote dashboard)
DASHBOARD_HOST = os.environ.get('DASHBOARD_HOST', '127.0.0.1')
DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', '8002'))
UVICORN_CMD = [PY_EXE, '-m', 'uvicorn', 'app.main:app', '--port', str(DASHBOARD_PORT)]
API_KEY = os.environ.get('API_KEY', 'secret-token')
BASE_URL = f'http://{DASHBOARD_HOST}:{DASHBOARD_PORT}'

async def ws_listen(uri, recv_count=3, timeout=8):
    events = []
    try:
        async with websockets.connect(uri) as ws:
            start = time.time()
            while len(events) < recv_count and time.time() - start < timeout:
                try:
                    m = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    events.append(json.loads(m) if isinstance(m, str) else m)
                except asyncio.TimeoutError:
                    break
    except Exception as e:
        print('Websocket error:', e)
    return events


async def main():
    print('Starting dashboard (uvicorn)...')
    proc = subprocess.Popen(UVICORN_CMD, cwd=DASHBOARD_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Wait for the server to start
        started = False
        for i in range(30):
            try:
                r = requests.get(f'{BASE_URL}/')
                if r.status_code == 200:
                    started = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if not started:
            raise RuntimeError('Failed to start dashboard within timeout')

        # Start websocket listeners
        alerts_uri = f'ws://{DASHBOARD_HOST}:{DASHBOARD_PORT}/ws/alerts?api_key='+API_KEY
        packets_uri = f'ws://{DASHBOARD_HOST}:{DASHBOARD_PORT}/ws/packet-stream?api_key='+API_KEY
        listen_alerts = asyncio.ensure_future(ws_listen(alerts_uri, recv_count=2, timeout=10))
        listen_packets = asyncio.ensure_future(ws_listen(packets_uri, recv_count=1, timeout=10))

        # Give listeners a brief moment to fully connect before sending messages
        time.sleep(1.0)

        # Send some traffic + alerts
        headers = {'X-API-Key': API_KEY, 'Content-Type': 'application/json'}
        traffic_template = lambda i: {
            'timestamp': datetime.utcnow().isoformat()+'Z',
            'source_ip': f'10.0.0.{i}',
            'destination_ip': '192.168.1.10',
            'protocol': 'TCP',
            'length': 150,
            'verdict': 'ALLOW'
        }
        # Send traffic
        for i in range(3):
            requests.post(f'{BASE_URL}/traffic', headers=headers, json=traffic_template(i))
            time.sleep(0.2)

        # Post an alert
        alert = {
            'source_ip': '10.0.0.99',
            'destination_ip': '192.168.1.10',
            'attack_type': 'DDoS',
            'confidence_score': 0.95,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'payload_sample': ''
        }
        requests.post(f'{BASE_URL}/alerts', headers=headers, json=alert)

        alerts = await listen_alerts
        packets = await listen_packets

        print('Alerts received:', alerts)
        print('Packets received:', packets)

        # A quick stats check
        r1 = requests.get(f'{BASE_URL}/alerts')
        print('Alerts total (GET):', len(r1.json()))

    finally:
        print('Stopping dashboard...')
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == '__main__':
    from datetime import datetime
    asyncio.run(main())
