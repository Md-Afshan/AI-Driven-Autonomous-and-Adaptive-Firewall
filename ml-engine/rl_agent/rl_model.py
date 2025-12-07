"""
RLModel: Structural RL agent class implementing action/reward loop.
This is pseudocode-style Python suitable for integrating with stable-baselines3 or a custom agent.
"""
import time
from typing import Dict, Any
import os
import sys

# Import FirewallController from the top-level agent package if available.
# If running inside the ml-engine package context without workspace on sys.path,
# add the workspace root to sys.path so imports succeed when modules are imported
# from other packages or tests.
try:
    from agent.controls.firewall_controller import FirewallController
except Exception:
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    if workspace_root not in sys.path:
        sys.path.insert(0, workspace_root)
    from agent.controls.firewall_controller import FirewallController

class RLModel:
    # Actions:
    # 0: Do nothing
    # 1: Rate limit IP (Layer 3)
    # 2: Enable SYN Cookies (Layer 4)
    # 3: Hard Block IP

    def __init__(self):
        self.fw = FirewallController()

    def step(self, action: int, state: Dict[str, Any]) -> float:
        """
        Execute action based on state, then compute reward.

        state keys expected: 'bandwidth', 'packet_rate', 'cpu_load', 'conn_table_size', 'suspect_ip'
        Returns reward float.
        """
        prev_metrics = {k: state.get(k) for k in ('bandwidth','packet_rate','cpu_load','conn_table_size')}
        suspect_ip = state.get('suspect_ip')

        # Execute action
        if action == 0:
            # Do nothing
            pass
        elif action == 1 and suspect_ip:
            # Rate limit IP - typically via tc or iptables with hashlimit
            self._rate_limit_ip(suspect_ip)
        elif action == 2:
            # Enable SYN cookies
            self._enable_syn_cookies()
        elif action == 3 and suspect_ip:
            # Hard block
            self.fw.add_block(suspect_ip)

        # Wait a short time to observe new metrics (in real system this is async)
        time.sleep(1)

        # In practice, the environment would provide new_state; here we expect caller to fetch it.
        new_metrics = self._fetch_metrics_snapshot()

        reward = self._compute_reward(prev_metrics, new_metrics)
        return reward

    def _compute_reward(self, prev, new):
        # +1 if traffic normalizes and cpu drops, -1 if legitimate traffic dropped
        reward = 0.0
        # CPU drop
        if new['cpu_load'] < prev['cpu_load']:
            reward += 0.5
        # bandwidth/packet rate drop indicates mitigation
        if new['packet_rate'] < prev['packet_rate']:
            reward += 0.5
        # false positive heuristic: if conn_table_size drops but application-level healthy==false, penalize (placeholder)
        # For now, no negative unless explicit signal
        return reward

    def _rate_limit_ip(self, ip):
        # placeholder - implement tc or iptables hashlimit calls
        pass

    def _enable_syn_cookies(self):
        # wrapper to enable kernel syncookies
        import subprocess
        subprocess.run(['sysctl','-w','net.ipv4.tcp_syncookies=1'])

    def _fetch_metrics_snapshot(self):
        # Placeholder: gather metrics from system (psutil, netstat, etc.)
        # Example structure:
        return {
            'bandwidth': 0.0,
            'packet_rate': 0.0,
            'cpu_load': 0.0,
            'conn_table_size': 0,
        }
