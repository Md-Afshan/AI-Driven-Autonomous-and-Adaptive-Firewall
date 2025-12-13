#!/usr/bin/env python3
"""
Demo agent that simulates packet capture and sends traffic and alerts to the Dashboard API.
This allows developers to run the agent's reporting & detection logic without needing root or NFQUEUE.
"""
import argparse
import random
import time
from datetime import datetime
import requests
import json


def gen_packet():
    p = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source_ip': f'10.0.0.{random.randint(2,254)}',
        'destination_ip': '192.168.1.10',
        'protocol': random.choice(['TCP','UDP','ICMP']),
        'length': random.randint(32,1500),
        'verdict': random.choice(['ALLOW','DROP'])
    }
    # Occasionally include a payload sample (to trigger ML per-packet SQL scanning)
    if random.random() < 0.15:
        # random SQL-like payloads vs benign samples
        if random.random() < 0.2:
            p['payload'] = "' OR 1=1 -- SELECT * FROM users WHERE id = 1"
        else:
            p['payload'] = 'normal benign GET /index.html HTTP/1.1'
    return p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dashboard', default='http://127.0.0.1:8000')
    parser.add_argument('--api-key', default='secret-token')
    parser.add_argument('--rate', type=float, default=2.0)
    parser.add_argument('--duration', type=float, default=30.0)
    args = parser.parse_args()

    headers = {'X-API-Key': args.api_key, 'Content-Type': 'application/json'}
    interval = 1.0 / args.rate
    start = time.time()
    while time.time() - start < args.duration:
        p = gen_packet()
        # best-effort post with a short retry to handle transient dashboard slowness
        for attempt in range(2):
            try:
                requests.post(args.dashboard + '/traffic', headers=headers, json=p, timeout=5)
                break
            except Exception as e:
                if attempt == 1:
                    print('traffic post error', e)
        # randomly send an alert
        if random.random() < 0.1:
            alert = {
                'source_ip': p['source_ip'],
                'destination_ip': p['destination_ip'],
                'attack_type': random.choice(['DDoS','SQL Injection','Benign']),
                'confidence_score': round(random.random(), 2),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'payload_sample': 'demo'
            }
            try:
                requests.post(args.dashboard + '/alerts', headers=headers, json=alert, timeout=5)
            except Exception as e:
                print('alert post error', e)
        time.sleep(interval)

    print('demo done')


if __name__ == '__main__':
    main()
