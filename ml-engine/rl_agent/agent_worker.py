"""
Agent worker: loop that receives alerts from packet engine and invokes RLModel decisions.
This is a simple structural event loop.
"""
import time
from .rl_model import RLModel

class AgentWorker:
    def __init__(self):
        self.model = RLModel()

    def handle_alert(self, alert):
        # alert expected to contain keys: 'type', 'ip', 'metrics'
        state = {
            'bandwidth': alert.get('metrics', {}).get('bandwidth', 0),
            'packet_rate': alert.get('metrics', {}).get('packet_rate', 0),
            'cpu_load': alert.get('metrics', {}).get('cpu_load', 0),
            'conn_table_size': alert.get('metrics', {}).get('conn_table_size', 0),
            'suspect_ip': alert.get('ip')
        }
        # Try to get action from RL policy served at /act; fallback to predictor and rule-based
        action = None
        try:
            import requests
            payload = {
                'packet_rate': state['packet_rate'],
                'syn_ack_ratio': alert.get('metrics', {}).get('syn_ack_ratio', 0),
                'cpu_load': state['cpu_load'],
                'conn_table_size': state['conn_table_size']
            }
            resp = requests.post('http://localhost:5001/act', json=payload, timeout=2)
            if resp.status_code == 200 and 'action' in resp.json():
                action = int(resp.json().get('action', 0))
        except Exception:
            action = None

        if action is None:
            # fallback to supervised predictor mapping
            try:
                import requests
                resp = requests.post('http://localhost:5001/predict', json={
                    'packet_rate': state['packet_rate'],
                    'syn_ack_ratio': alert.get('metrics', {}).get('syn_ack_ratio', 0),
                    'cpu_load': state['cpu_load'],
                    'conn_table_size': state['conn_table_size']
                }, timeout=2)
                if resp.status_code == 200 and 'probability' in resp.json():
                    prob = resp.json()['probability']
                    if prob > 0.9:
                        action = 3
                    elif prob > 0.6:
                        action = 2
                    elif prob > 0.3:
                        action = 1
                    else:
                        action = 0
                else:
                    action = self.select_action(state)
            except Exception:
                action = self.select_action(state)

        reward = self.model.step(action, state)
        print(f"Action {action} taken for {state['suspect_ip']}, reward={reward}")
        # Report action back to dashboard for UI visibility (best-effort)
        try:
            import requests, os
            dashboard_url = os.getenv('DASHBOARD_URL', 'http://localhost:8000')
            api_key = os.getenv('DASHBOARD_API_KEY', 'secret-token')
            headers = {'x-api-key': api_key}
            # dashboard exposes /action/{action}?ip=...
            try:
                requests.post(f"{dashboard_url}/action/{action}?ip={state['suspect_ip']}", headers=headers, timeout=1)
            except Exception:
                # fallback: post to the ml proxy act endpoint if the other route fails
                try:
                    requests.post(f"{dashboard_url}/ml/act", json={'action': action, 'ip': state['suspect_ip']}, headers=headers, timeout=1)
                except Exception:
                    pass
        except Exception:
            pass

    def select_action(self, state):
        # Simple rule-based selection as placeholder
        if state['packet_rate'] > 10000:
            return 3  # Hard block
        if state['conn_table_size'] > 10000:
            return 2  # Enable SYN cookies
        return 0


if __name__ == '__main__':
    worker = AgentWorker()
    # In a real system you'd subscribe to alerts (socket, HTTP, queue)
    # Example: simulate periodic alerts
    while True:
        # simulate
        sample_alert = {'type':'syn_flood','ip':'1.2.3.4','metrics':{'packet_rate':15000,'cpu_load':80,'conn_table_size':12000}}
        worker.handle_alert(sample_alert)
        time.sleep(10)
