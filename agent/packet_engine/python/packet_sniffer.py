"""
Python prototype packet sniffer using scapy for rapid testing.
Requires: pip install scapy
Run as root for raw sockets.
"""
from scapy.all import sniff, TCP, IP
from syn_detector import SynDetector

detector = SynDetector()

def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        ip = pkt[IP].src
        flags = pkt[TCP].flags
        is_syn = flags & 0x02 != 0
        is_ack = flags & 0x10 != 0
        detector.record_packet(ip, is_syn, is_ack)

if __name__ == '__main__':
    sniff(filter='tcp', prn=handle_pkt, store=0)
