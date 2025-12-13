"""
AI-Driven Autonomous and Adaptive Firewall - SaaS Enforcer Agent
Root-privileged packet sniffer with hybrid CNN+RF detection for SQL Injection and DDoS attacks.
Supports both Local (single host) and Gateway (3-VM) deployment modes.
"""

import os
import sys
import json
import pickle
import logging
import argparse
import requests
import threading
import queue
import time
import subprocess
import gzip
import socket
import random
from datetime import datetime
from typing import Optional, Dict, Any
from collections import defaultdict

import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
from scapy.all import IP, TCP, UDP, Raw, sniff
from netfilterqueue import NetfilterQueue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'ml-engine', 'models')
DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL', 'http://localhost:8000')
MAX_SEQ_LENGTH = 200
DETECTION_THRESHOLD_CNN = 0.7
DETECTION_THRESHOLD_RF = 0.6
ALERT_TIMEOUT = 300  # seconds
NFQUEUE_NUM = 1
TRAFFIC_USE_UDP = os.getenv('TRAFFIC_USE_UDP', 'false').lower() in ('1', 'true', 'yes')
DASHBOARD_UDP_HOST = os.getenv('DASHBOARD_UDP_HOST', '127.0.0.1')
DASHBOARD_UDP_PORT = int(os.getenv('DASHBOARD_UDP_PORT', '9999'))
TRAFFIC_BATCH_MAX = int(os.getenv('TRAFFIC_BATCH_MAX', '50'))
TRAFFIC_FLUSH_INTERVAL = float(os.getenv('TRAFFIC_FLUSH_INTERVAL', '0.5'))
TRAFFIC_RETRY_MAX = int(os.getenv('TRAFFIC_RETRY_MAX', '5'))


class ModelLoader:
    """Load and manage ML models"""
    
    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.waf_model = None
        self.nids_model = None
        self.tokenizer = None
        self.scaler = None
        self._load_models()
    
    def _load_models(self):
        """Load all required models"""
        try:
            # Load WAF CNN model and tokenizer
            waf_model_path = os.path.join(self.model_dir, 'waf_cnn.h5')
            tokenizer_path = os.path.join(self.model_dir, 'tokenizer.pkl')
            
            if os.path.exists(waf_model_path):
                self.waf_model = tf.keras.models.load_model(waf_model_path)
                logger.info(f"Loaded WAF model from {waf_model_path}")
            else:
                logger.warning(f"WAF model not found at {waf_model_path}")
            
            if os.path.exists(tokenizer_path):
                with open(tokenizer_path, 'rb') as f:
                    self.tokenizer = pickle.load(f)
                logger.info(f"Loaded tokenizer from {tokenizer_path}")
            else:
                logger.warning(f"Tokenizer not found at {tokenizer_path}")
            
            # Load NIDS Random Forest model and scaler
            nids_model_path = os.path.join(self.model_dir, 'nids_rf.pkl')
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            
            if os.path.exists(nids_model_path):
                with open(nids_model_path, 'rb') as f:
                    self.nids_model = pickle.load(f)
                logger.info(f"Loaded NIDS model from {nids_model_path}")
            else:
                logger.warning(f"NIDS model not found at {nids_model_path}")
            
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info(f"Loaded scaler from {scaler_path}")
            else:
                logger.warning(f"Scaler not found at {scaler_path}")
        
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            raise
    
    def predict_waf(self, payload: str) -> tuple:
        """Predict SQL injection using CNN (returns is_malicious, confidence)"""
        if not self.waf_model or not self.tokenizer:
            return False, 0.0
        
        try:
            sequences = self.tokenizer.texts_to_sequences([payload])
            padded = pad_sequences(sequences, maxlen=MAX_SEQ_LENGTH, padding='post')
            prediction = self.waf_model.predict(padded, verbose=0)[0][0]
            is_malicious = prediction >= DETECTION_THRESHOLD_CNN
            return is_malicious, float(prediction)
        except Exception as e:
            logger.error(f"Error in WAF prediction: {str(e)}")
            return False, 0.0
    
    def predict_nids(self, features: np.ndarray) -> tuple:
        """Predict DDoS using Random Forest (returns is_malicious, confidence)"""
        if not self.nids_model or not self.scaler:
            return False, 0.0
        
        try:
            features_scaled = self.scaler.transform([features])
            prediction = self.nids_model.predict(features_scaled)[0]
            probability = self.nids_model.predict_proba(features_scaled)[0][1]
            is_malicious = prediction == 1 and probability >= DETECTION_THRESHOLD_RF
            return is_malicious, float(probability)
        except Exception as e:
            logger.error(f"Error in NIDS prediction: {str(e)}")
            return False, 0.0


class PacketAnalyzer:
    """Analyze packets for threats"""
    
    def __init__(self, models: ModelLoader):
        self.models = models
        self.src_ip_counts = defaultdict(int)  # Rate limiting for alerts
        self.src_ip_last_alert = defaultdict(float)
    
    def extract_payload(self, packet) -> Optional[str]:
        """Extract HTTP/Raw payload from packet"""
        if packet.haslayer(Raw):
            try:
                payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
                return payload[:1000]  # Limit to 1000 chars
            except Exception as e:
                logger.debug(f"Error extracting payload: {str(e)}")
                return None
        return None
    
    def extract_flow_features(self, packet) -> Optional[np.ndarray]:
        """Extract network flow features for NIDS"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            # Basic flow features (simplified for demo)
            packet_count = 1  # Would aggregate in real implementation
            packet_rate = 1.0  # Would calculate from time windows
            packet_size = len(packet)
            flow_duration = 0.1  # Would calculate from flow state
            bytes_sent = packet_size
            protocol_variety = 1  # Would count unique protocols
            
            features = np.array([
                packet_count,
                packet_rate,
                packet_size,
                flow_duration,
                bytes_sent,
                protocol_variety
            ], dtype=np.float32)
            
            return features
        except Exception as e:
            logger.debug(f"Error extracting flow features: {str(e)}")
            return None
    
    def analyze_packet(self, packet) -> Dict[str, Any]:
        """Analyze packet and return detection results"""
        result = {
            'is_malicious': False,
            'attack_type': None,
            'confidence': 0.0,
            'details': {}
        }
        
        try:
            if not packet.haslayer(IP):
                return result
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            result['details']['source_ip'] = src_ip
            result['details']['destination_ip'] = dst_ip
            
            # Check for HTTP payload (WAF - SQL Injection detection)
            payload = self.extract_payload(packet)
            if payload:
                is_sql_injection, waf_confidence = self.models.predict_waf(payload)
                if is_sql_injection:
                    result['is_malicious'] = True
                    result['attack_type'] = 'SQL Injection'
                    result['confidence'] = waf_confidence
                    result['details']['payload_sample'] = payload[:200]
                    return result
            
            # Check flow features (NIDS - DDoS detection)
            flow_features = self.extract_flow_features(packet)
            if flow_features is not None:
                is_ddos, nids_confidence = self.models.predict_nids(flow_features)
                if is_ddos:
                    result['is_malicious'] = True
                    result['attack_type'] = 'DDoS'
                    result['confidence'] = nids_confidence
                    return result
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {str(e)}")
        
        return result


class AlertManager:
    """Manage alerts and blocking"""
    
    def __init__(self, dashboard_url: str, session: Optional[requests.Session] = None):
        self.dashboard_url = dashboard_url
        self.blocked_ips = set()
        self.alert_cache = {}  # Prevent duplicate alerts
        self.api_headers = {'X-API-Key': os.getenv('API_KEY', 'secret-token')}
        self.session = session or requests.Session()
    
    def block_ip(self, ip: str) -> bool:
        """Add IP to ipset blacklist"""
        try:
            if ip in self.blocked_ips:
                return True
            
            # Add to ipset blacklist
            subprocess.run(
                ['ipset', 'add', 'blacklist', ip],
                check=True,
                capture_output=True
            )
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error adding IP to blacklist: {str(e)}")
            return False
        except FileNotFoundError:
            logger.warning("ipset command not found. Skipping IP blocking.")
            return False
    
    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert to Dashboard API"""
        try:
            # Check if we already sent an alert for this IP recently
            cache_key = f"{alert_data['source_ip']}_{alert_data['attack_type']}"
            now = datetime.now().timestamp()
            
            if cache_key in self.alert_cache:
                last_alert_time = self.alert_cache[cache_key]
                if now - last_alert_time < ALERT_TIMEOUT:
                    return True  # Skip sending duplicate alert
            
            response = self.session.post(
                f"{self.dashboard_url}/alerts",
                json=alert_data,
                headers=self.api_headers,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Alert sent successfully: {alert_data['source_ip']} - {alert_data['attack_type']}")
                self.alert_cache[cache_key] = now
                return True
            else:
                logger.warning(f"Alert API returned {response.status_code}: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error sending alert to dashboard: {str(e)}")
            return False
    
    def handle_threat(self, packet, analysis: Dict[str, Any]) -> bool:
        """Block IP and send alert"""
        if not analysis['is_malicious']:
            return False
        
        src_ip = analysis['details']['source_ip']
        dst_ip = analysis['details']['destination_ip']
        attack_type = analysis['attack_type']
        confidence = analysis['confidence']
        
        # Block the attacker IP
        self.block_ip(src_ip)
        
        # Send alert to dashboard
        alert_data = {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'attack_type': attack_type,
            'confidence_score': float(confidence),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'payload_sample': analysis['details'].get('payload_sample', '')
        }
        
        # Send alert asynchronously to avoid blocking packet processing
        try:
            t = threading.Thread(target=self.send_alert, args=(alert_data,), daemon=True)
            t.start()
        except Exception:
            # fallback to sync send
            self.send_alert(alert_data)
        
        logger.warning(f"THREAT DETECTED: {attack_type} from {src_ip} to {dst_ip} (confidence: {confidence:.2f})")
        
        return True


class SaaSEnforcer:
    """Main SaaS Firewall Enforcer
    Supports two runtime modes: 'nfqueue' (default) which requires root and binds NetfilterQueue, and
    'sniff' (dev) which uses scapy.sniff to gather packets and works for quick developer testing. Use
    the CLI flag --dev to enable sniff mode (non-root friendly though sniff may still require root in some systems).
    """
    
    def __init__(self, mode: str, target_ip: Optional[str] = None, dev_mode: bool = False, iface: Optional[str] = None, dashboard_url: Optional[str] = None):
        self.mode = mode
        self.target_ip = target_ip
        self.nfqueue = None
        self.models = ModelLoader(MODEL_DIR)
        self.analyzer = PacketAnalyzer(self.models)
        # Dashboard URL override (from CLI)
        self.dashboard_url = dashboard_url or DASHBOARD_API_URL
        # Persistent requests session (ensure created before passing to AlertManager)
        self.session = requests.Session()
        self.alerts = AlertManager(self.dashboard_url, session=self.session)
        # UDP socket for traffic sink
        self.udp_sock = None
        if TRAFFIC_USE_UDP:
            try:
                self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except Exception as e:
                logger.warning(f'Failed to create UDP socket: {e}')
        # Traffic reporting queue & worker (non-blocking)
        self.traffic_queue = queue.Queue(maxsize=10000)
        self._stop_traffic_worker = threading.Event()
        self.traffic_worker = threading.Thread(target=self._traffic_worker, daemon=True)
        self.traffic_worker.start()
        self.packet_count = 0
        self.threat_count = 0
        # Developer sniff mode
        self.dev_mode = dev_mode
        self.sniff_iface = iface or 'any'
        self._sniff_thread = None
    
    def check_root_privilege(self):
        """Ensure script is running as root"""
        if os.geteuid() != 0:
            logger.error("This script must be run as root!")
            sys.exit(1)
    
    def setup_iptables_rules(self):
        """Setup iptables rules to redirect packets to NFQUEUE"""
        try:
            if self.mode == 'local':
                # Protect local host
                logger.info("Setting up iptables rules for LOCAL mode (INPUT chain)")
                cmd = ['iptables', '-I', 'INPUT']
                if self.sniff_iface and self.sniff_iface != 'any':
                    cmd += ['-i', self.sniff_iface]
                cmd += ['-j', 'NFQUEUE', '--queue-num', str(NFQUEUE_NUM)]
                subprocess.run(cmd, check=True, capture_output=True)
            elif self.mode == 'gateway':
                # Protect victim VM behind gateway
                if not self.target_ip:
                    raise ValueError("--target-ip is required for gateway mode")
                
                logger.info(f"Setting up iptables rules for GATEWAY mode (FORWARD chain to {self.target_ip})")
                cmd = ['iptables', '-I', 'FORWARD']
                if self.sniff_iface and self.sniff_iface != 'any':
                    cmd += ['-i', self.sniff_iface]
                cmd += ['-d', self.target_ip, '-j', 'NFQUEUE', '--queue-num', str(NFQUEUE_NUM)]
                subprocess.run(cmd, check=True, capture_output=True)
            
            logger.info("iptables rules configured successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error setting up iptables rules: {str(e)}")
            raise
    
    def packet_callback(self, payload):
        """Callback function for each packet in NFQUEUE"""
        self.packet_count += 1
        
        try:
            # Get the packet from nfqueue
            pkt = IP(payload.get_payload())
            
            # Analyze the packet
            analysis = self.analyzer.analyze_packet(pkt)

            # Build traffic summary and enqueue for reporting
            try:
                proto = 'OTHER'
                if pkt.haslayer(TCP): proto = 'TCP'
                elif pkt.haslayer(UDP): proto = 'UDP'
                traffic = {
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'source_ip': pkt.src,
                    'destination_ip': pkt.dst,
                    'protocol': proto,
                    'length': len(pkt),
                    'verdict': 'DROP' if analysis['is_malicious'] else 'ALLOW'
                }
                # include optional payload snippet if found so dashboard can perform extra analysis (WAF)
                if analysis.get('details') and analysis['details'].get('payload_sample'):
                    traffic['payload_sample'] = analysis['details'].get('payload_sample')
                try:
                    # post immediate packet to dashboard (best-effort, non-blocking)
                    t = threading.Thread(target=self._post_single_packet, args=(traffic,), daemon=True)
                    t.start()
                    self.traffic_queue.put_nowait(traffic)
                except queue.Full:
                    logger.debug('Traffic queue full, dropping traffic report')
            except Exception:
                pass
            
            # Handle threats
            if self.alerts.handle_threat(pkt, analysis):
                self.threat_count += 1
                # Drop malicious packet
                payload.drop()
                logger.debug(f"Dropped malicious packet from {analysis['details']['source_ip']}")
            else:
                # Accept benign packet
                payload.accept()
            
            # Log stats periodically
            if self.packet_count % 100 == 0:
                logger.info(f"Processed {self.packet_count} packets, Threats detected: {self.threat_count}")
        
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            # Accept on error to prevent blocking legitimate traffic
            payload.accept()
    
    def start(self):
        """Start the enforcer"""
        logger.info("=" * 80)
        logger.info("AI-Driven Autonomous and Adaptive Firewall - SaaS Enforcer Starting")
        logger.info("=" * 80)
        logger.info(f"Mode: {self.mode.upper()}")
        if self.target_ip:
            logger.info(f"Target IP: {self.target_ip}")
        
        # If running in dev sniff mode, skip root-check and NFQUEUE config and start scapy sniffing
        if self.dev_mode:
            logger.warning('Starting in DEV sniff mode — scapy will capture packets and we will forward to dashboard')
            # Start sniffing thread and skip NFQUEUE setup
            self._start_sniffing()
            return

        # Check root privilege
        self.check_root_privilege()
        
        # Setup iptables
        self.setup_iptables_rules()
        
        # Setup NFQUEUE
        try:
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(NFQUEUE_NUM, self.packet_callback)
            logger.info(f"NFQUEUE bound to queue {NFQUEUE_NUM}")
            
            logger.info("Enforcer started, listening for packets...")
            self.nfqueue.run()
        
        except KeyboardInterrupt:
            logger.info("\nStopping enforcer...")
            self._cleanup()
        except Exception as e:
            logger.error(f"Error starting enforcer: {str(e)}")
            self._cleanup()
            sys.exit(1)

    def _start_sniffing(self):
        """Start a background scapy.sniff thread to capture packets and handle them via analyzer/alerts."""
        try:
            def _sniff_loop():
                # prn handler receives scapy pkt; use store=False to avoid memory buildup
                # Resolve 'any' to a concrete interface if necessary
                iface = self.sniff_iface
                if iface == 'any':
                    # choose first non-loopback interface
                    try:
                        ifaces = [i for i in os.listdir('/sys/class/net') if i != 'lo' and not i.startswith('docker') and not i.startswith('veth')]
                        if ifaces:
                            iface = ifaces[0]
                    except Exception:
                        iface = 'lo'
                sniff(prn=self._handle_sniffed_packet, iface=iface, store=False)

            self._sniff_thread = threading.Thread(target=_sniff_loop, daemon=True)
            self._sniff_thread.start()
            logger.info(f"Sniffing on interface {self.sniff_iface} started (DEV mode)")
            # Keep main thread alive while sniffing
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info('Stopping sniffing...')
            # There is no direct clean way to stop sniff from another thread using scapy; rely on process SIGINT
            self._cleanup()
        except Exception as e:
            logger.error(f'Error while sniffing: {e}')
            self._cleanup()

    def _handle_sniffed_packet(self, pkt):
        """Handle a scapy sniffed packet similarly to the NFQUEUE callback (but we cannot accept/drop)."""
        try:
            # Count
            self.packet_count += 1

            # Analyze packet
            analysis = self.analyzer.analyze_packet(pkt)

            # Build traffic summary and enqueue for reporting
            try:
                proto = 'OTHER'
                if pkt.haslayer(TCP): proto = 'TCP'
                elif pkt.haslayer(UDP): proto = 'UDP'
                traffic = {
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'source_ip': pkt[IP].src if pkt.haslayer(IP) else '0.0.0.0',
                    'destination_ip': pkt[IP].dst if pkt.haslayer(IP) else '0.0.0.0',
                    'protocol': proto,
                    'length': len(pkt),
                    'verdict': 'DROP' if analysis['is_malicious'] else 'ALLOW'
                }
                try:
                    # best-effort immediate POST to dashboard
                    t = threading.Thread(target=self._post_single_packet, args=(traffic,), daemon=True)
                    t.start()
                    self.traffic_queue.put_nowait(traffic)
                except queue.Full:
                    logger.debug('Traffic queue full, dropping traffic report')
            except Exception:
                pass

            # Handle threats (best-effort — we can't accept/drop packets with scapy sniff)
            if self.alerts.handle_threat(pkt, analysis):
                self.threat_count += 1
                logger.debug(f"Detected malicious packet from {analysis['details'].get('source_ip')}")

            # Log stats periodically
            if self.packet_count % 100 == 0:
                logger.info(f"Processed {self.packet_count} packets, Threats detected: {self.threat_count}")

        except Exception as e:
            logger.error(f"Error processing sniffed packet: {e}")
    
    def _cleanup(self):
        """Clean up resources"""
        if self.nfqueue:
            self.nfqueue.unbind()
        
        # Remove iptables rules
        try:
            if self.mode == 'local':
                subprocess.run(
                    ['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', str(NFQUEUE_NUM)],
                    capture_output=True
                )
            elif self.mode == 'gateway' and self.target_ip:
                subprocess.run(
                    ['iptables', '-D', 'FORWARD', '-d', self.target_ip, '-j', 'NFQUEUE', '--queue-num', str(NFQUEUE_NUM)],
                    capture_output=True
                )
            logger.info("iptables rules removed")
        except Exception as e:
            logger.warning(f"Error removing iptables rules: {str(e)}")
        
        logger.info(f"Final stats: {self.packet_count} packets processed, {self.threat_count} threats detected")
        logger.info("Enforcer stopped")
        # Stop traffic worker
        try:
            self._stop_traffic_worker.set()
        except Exception:
            pass

    def _traffic_worker(self):
        """Background worker that batches and sends traffic summaries to the dashboard API"""
        batch = []
        max_batch = TRAFFIC_BATCH_MAX
        flush_interval = TRAFFIC_FLUSH_INTERVAL
        last_flush = time.time()
        while not self._stop_traffic_worker.is_set():
            try:
                item = self.traffic_queue.get(timeout=flush_interval)
                batch.append(item)
                # flush if batch full or time exceeded
                if len(batch) >= max_batch or (time.time() - last_flush) >= flush_interval:
                    try:
                        # Send as compressed batch via UDP or HTTP POST
                        self._flush_traffic_batch(batch)
                    except Exception as e:
                        logger.debug(f"Failed to send traffic batch: {e}")
                    batch = []
                    last_flush = time.time()
            except queue.Empty:
                # flush any pending batch on timeout
                if batch:
                    try:
                        self._flush_traffic_batch(batch)
                    except Exception as e:
                        logger.debug(f"Failed to send traffic batch: {e}")
                    batch = []
                    last_flush = time.time()
                continue
        # flush before exit
        if batch:
            try:
                self._flush_traffic_batch(batch)
            except Exception:
                pass

    def _flush_traffic_batch(self, batch):
        """Send a batch of traffic entries either over UDP or compressed HTTP POST."""
        if not batch:
            return
        # Use UDP if configured
        if TRAFFIC_USE_UDP and self.udp_sock:
            try:
                data = json.dumps(batch).encode('utf-8')
                compressed = gzip.compress(data)
                # For UDP we send the compressed bytes; receiver will decompress.
                self.udp_sock.sendto(compressed, (DASHBOARD_UDP_HOST, DASHBOARD_UDP_PORT))
                logger.debug(f'Sent UDP traffic batch of {len(batch)} to {DASHBOARD_UDP_HOST}:{DASHBOARD_UDP_PORT}')
                return True
            except Exception as e:
                logger.debug(f'Failed to send UDP batch: {e}')
                # Fall back to HTTP POST if UDP fails

        # Otherwise, send compressed HTTP POST
        try:
            data = json.dumps(batch).encode('utf-8')
            compressed = gzip.compress(data)
            url = f"{self.alerts.dashboard_url.rstrip('/')}/traffic/batch"
            headers = dict(self.alerts.api_headers)
            headers.update({'Content-Encoding': 'gzip', 'Content-Type': 'application/json'})
            self._send_with_retries(url, compressed, headers)
            logger.debug(f'HTTP traffic batch sent to {url} size={len(compressed)}')
            return True
        except Exception as e:
            logger.debug(f'HTTP batch send failed: {e}')
            return False

    def _send_with_retries(self, url, data, headers):
        """Send data with retries and exponential backoff + jitter."""
        base = 0.5
        for attempt in range(TRAFFIC_RETRY_MAX):
            try:
                resp = self.session.post(url, data=data, headers=headers, timeout=3)
                if resp.status_code in (200, 201):
                    return True
                else:
                    logger.debug(f'HTTP batch returned {resp.status_code}: {resp.text}')
            except Exception as e:
                logger.debug(f'HTTP batch attempt {attempt} failed: {e}')

            # Backoff with jitter
            backoff = min(base * (2 ** attempt), 8)
            sleep_time = backoff + random.uniform(0, backoff)
            time.sleep(sleep_time)
        return False

    def _post_single_packet(self, traffic):
        """Send a single packet as a JSON HTTP POST to the dashboard's /log-packet endpoint (best effort)."""
        try:
            url = f"{self.dashboard_url.rstrip('/')}/log-packet"
            # Use agent session for persistent connection
            headers = dict(self.alerts.api_headers)
            headers.update({'Content-Type': 'application/json'})
            resp = self.session.post(url, json=traffic, headers=headers, timeout=1)
            if resp.status_code not in (200, 201):
                logger.debug(f'log-packet returned {resp.status_code}: {resp.text}')
            return True
        except Exception as e:
            logger.debug(f'Failed to post packet to dashboard: {e}')
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Driven SaaS Firewall Enforcer - Real-time threat detection and blocking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python saas_enforcer.py --mode local              # Protect local host
  sudo python saas_enforcer.py --mode gateway --target-ip 192.168.1.10  # Protect VM
        """
    )
    
    parser.add_argument(
        '--mode',
        type=str,
        choices=['local', 'gateway'],
        default='local',
        help='Deployment mode: local (protect host) or gateway (protect VM)'
    )
    
    parser.add_argument(
        '--target-ip',
        type=str,
        help='Target IP for gateway mode (required when mode=gateway)'
    )
    parser.add_argument('--dev', action='store_true', help='Run in dev sniff mode using scapy.sniff() (no NFQUEUE, no root required for some setups)')
    parser.add_argument('--iface', type=str, default='any', help='Interface for scapy sniff when --dev is used')
    
    parser.add_argument(
        '--dashboard-url',
        type=str,
        default='http://localhost:8000',
        help='Dashboard API URL'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode == 'gateway' and not args.target_ip:
        parser.error("--target-ip is required when mode is 'gateway'")
    
    # Start enforcer
    enforcer = SaaSEnforcer(mode=args.mode, target_ip=args.target_ip, dev_mode=args.dev, iface=args.iface, dashboard_url=args.dashboard_url)
    enforcer.start()


if __name__ == '__main__':
    main()
