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
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any
from collections import defaultdict

import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
from scapy.all import IP, TCP, UDP, Raw, sniff
from netfilterqueue import NetfilterQueue
import threading
import queue
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'ml-engine', 'models')
DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL', 'http://localhost:8000')
DASHBOARD_API_KEY = os.getenv('DASHBOARD_API_KEY', 'secret-token')
MAX_SEQ_LENGTH = 200
DETECTION_THRESHOLD_CNN = 0.7
DETECTION_THRESHOLD_RF = 0.6
ALERT_TIMEOUT = 300  # seconds
NFQUEUE_NUM = 1


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
                else:
                    # Payload was analyzed but safe - mark as benign
                    result['attack_type'] = 'Benign'
                    result['confidence'] = 0.0
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
                else:
                    # Flow was analyzed but safe - mark as benign
                    result['attack_type'] = 'Benign'
                    result['confidence'] = 0.0
                    return result
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {str(e)}")
        
        return result


class AlertManager:
    """Manage alerts and blocking"""
    
    def __init__(self, dashboard_url: str):
        self.dashboard_url = dashboard_url
        self.blocked_ips = set()
        self.alert_cache = {}  # Prevent duplicate alerts
    
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
            
            headers = {'Content-Type': 'application/json', 'X-API-Key': DASHBOARD_API_KEY}
            response = requests.post(
                f"{self.dashboard_url}/alerts",
                json=alert_data,
                headers=headers,
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
        """Handle both threats and benign traffic"""
        src_ip = analysis['details'].get('source_ip', 'unknown')
        dst_ip = analysis['details'].get('destination_ip', 'unknown')
        attack_type = analysis['attack_type']
        confidence = analysis['confidence']
        
        # If malicious, block the attacker IP
        if analysis['is_malicious']:
            self.block_ip(src_ip)
            logger.warning(f"THREAT DETECTED: {attack_type} from {src_ip} to {dst_ip} (confidence: {confidence:.2f})")
        
        # Send alert to dashboard for both benign and malicious traffic
        alert_data = {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'attack_type': attack_type,
            'confidence_score': float(confidence),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'payload_sample': analysis['details'].get('payload_sample', '')
        }
        
        self.send_alert(alert_data)
        
        return analysis['is_malicious']


class TrafficReporter(threading.Thread):
    """Background thread to batch and send traffic metadata to dashboard to avoid blocking packet processing."""

    def __init__(self, dashboard_url: str, api_key: str, interval: float = 0.5):
        super().__init__(daemon=True)
        self.dashboard_url = dashboard_url.rstrip('/')
        self.api_key = api_key
        self.interval = interval
        self.q = queue.Queue()
        self.running = True

    def enqueue(self, item: Dict[str, Any]):
        try:
            self.q.put_nowait(item)
        except queue.Full:
            logger.debug('Traffic queue full, dropping packet metadata')

    def run(self):
        headers = {'Content-Type': 'application/json', 'X-API-Key': self.api_key}
        while self.running:
            batch = []
            try:
                # collect up to N items quickly
                while len(batch) < 50:
                    item = self.q.get_nowait()
                    batch.append(item)
            except queue.Empty:
                pass

            # send each item but do not block long
            for item in batch:
                try:
                    requests.post(f"{self.dashboard_url}/traffic", json=item, headers=headers, timeout=1)
                except Exception:
                    # suppress to avoid spamming logs
                    pass

            time.sleep(self.interval)

    def stop(self):
        self.running = False


class SaaSEnforcer:
    """Main SaaS Firewall Enforcer"""
    
    def __init__(self, mode: str, target_ip: Optional[str] = None):
        self.mode = mode
        self.target_ip = target_ip
        self.nfqueue = None
        self.models = ModelLoader(MODEL_DIR)
        self.analyzer = PacketAnalyzer(self.models)
        self.alerts = AlertManager(DASHBOARD_API_URL)
        # Start background traffic reporter to avoid blocking packet thread
        self.traffic_reporter = TrafficReporter(DASHBOARD_API_URL, DASHBOARD_API_KEY)
        try:
            self.traffic_reporter.start()
        except Exception:
            logger.warning('Failed to start traffic reporter thread')
        self.packet_count = 0
        self.threat_count = 0
    
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
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', str(NFQUEUE_NUM)],
                    check=True,
                    capture_output=True
                )
            elif self.mode == 'gateway':
                # Protect victim VM behind gateway
                if not self.target_ip:
                    raise ValueError("--target-ip is required for gateway mode")
                
                logger.info(f"Setting up iptables rules for GATEWAY mode (FORWARD chain to {self.target_ip})")
                subprocess.run(
                    ['iptables', '-I', 'FORWARD', '-d', self.target_ip, '-j', 'NFQUEUE', '--queue-num', str(NFQUEUE_NUM)],
                    check=True,
                    capture_output=True
                )
            
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

            # Prepare and enqueue traffic metadata (non-blocking)
            try:
                proto = 'OTHER'
                if pkt.haslayer(TCP): proto = 'TCP'
                elif pkt.haslayer(UDP): proto = 'UDP'
                meta = {
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'source_ip': pkt.src,
                    'destination_ip': pkt.dst,
                    'protocol': proto,
                    'length': len(pkt),
                    'verdict': 'DROP' if analysis.get('is_malicious') else 'ALLOW'
                }
                try:
                    self.traffic_reporter.enqueue(meta)
                except Exception:
                    pass
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
    enforcer = SaaSEnforcer(mode=args.mode, target_ip=args.target_ip)
    enforcer.start()


if __name__ == '__main__':
    main()
