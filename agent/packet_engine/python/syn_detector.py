import time
import subprocess
from collections import defaultdict, deque

class SynDetector:
    def __init__(self, window_seconds=1):
        self.window = window_seconds
        # per-ip deque of (timestamp, type) where type is 'SYN' or 'ACK'
        self.data = defaultdict(lambda: deque())

    def record_packet(self, src_ip, is_syn, is_ack):
        now = time.time()
        if is_syn:
            self.data[src_ip].append((now, 'SYN'))
        if is_ack:
            self.data[src_ip].append((now, 'ACK'))

    def detect(self):
        cutoff = time.time() - self.window
        alerts = []
        for ip, dq in list(self.data.items()):
            # drop old
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            syn_count = sum(1 for _, t in dq if t == 'SYN')
            ack_count = sum(1 for _, t in dq if t == 'ACK')
            ratio = float(syn_count) / (ack_count or 1)
            if syn_count >= 20 and (ack_count == 0 or ratio > 10.0):
                alerts.append((ip, syn_count, ack_count, ratio))
                # Example mitigation: enable syncookies
                self.enable_tcp_syncookies()
        return alerts

    def enable_tcp_syncookies(self):
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_syncookies=1'], check=True)
        except Exception as e:
            print('Failed to enable syncookies:', e)
