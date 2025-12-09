#!/usr/bin/env python3
"""
Simple traffic feeder for testing the Dashboard.
Sends periodic HTTP POSTs to /traffic and compressed batches to /traffic/batch; optionally sends UDP compressed batches to the UDP sink.
"""
import argparse
import time
import json
import gzip
import random
import requests
import socket
from datetime import datetime


def gen_packet(i):
    return {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source_ip': f'10.0.0.{random.randint(2,250)}',
        'destination_ip': '192.168.1.10',
        'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
        'length': random.randint(40,1500),
        'verdict': random.choice(['ALLOW', 'DROP'])
    }


def send_http(host, api_key):
    url = host.rstrip('/') + '/traffic'
    headers = {'X-API-Key': api_key, 'Content-Type': 'application/json'}
    return requests.post(url, json=gen_packet(0), headers=headers, timeout=2)


def send_http_batch(host, api_key, batch):
    url = host.rstrip('/') + '/traffic/batch'
    headers = {'X-API-Key': api_key, 'Content-Encoding': 'gzip', 'Content-Type': 'application/json'}
    compressed = gzip.compress(json.dumps(batch).encode('utf-8'))
    return requests.post(url, data=compressed, headers=headers, timeout=4)


def send_udp(batch, udp_host, udp_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packed = gzip.compress(json.dumps(batch).encode('utf-8'))
    s.sendto(packed, (udp_host, udp_port))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='http://127.0.0.1:8000')
    parser.add_argument('--api-key', default='secret-token')
    parser.add_argument('--rate', type=float, default=2.0, help='packets per second')
    parser.add_argument('--duration', type=float, default=30.0, help='seconds')
    parser.add_argument('--batch-size', type=int, default=5)
    parser.add_argument('--use-udp', action='store_true')
    parser.add_argument('--udp-host', default='127.0.0.1')
    parser.add_argument('--udp-port', type=int, default=9999)
    args = parser.parse_args()

    interval = 1.0 / args.rate
    start = time.time()
    batch = []
    while time.time() - start < args.duration:
        p = gen_packet(0)
        if args.use_udp:
            batch.append(p)
            if len(batch) >= args.batch_size:
                send_udp(batch, args.udp_host, args.udp_port)
                batch = []
        else:
            # Send HTTP for each packet
            try:
                r = send_http(args.host, args.api_key)
                # print('http status', r.status_code)
            except Exception as e:
                print('http send error', e)
            batch.append(p)
            if len(batch) >= args.batch_size:
                try:
                    r = send_http_batch(args.host, args.api_key, batch)
                    # print('batch status', r.status_code)
                except Exception as e:
                    print('batch error', e)
                batch = []
        time.sleep(interval)

    # flush remaining
    if batch:
        try:
            if args.use_udp:
                send_udp(batch, args.udp_host, args.udp_port)
            else:
                send_http_batch(args.host, args.api_key, batch)
        except Exception as e:
            print('final send error', e)

    print('done')
