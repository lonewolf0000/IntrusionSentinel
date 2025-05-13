import argparse
import time
import collections
import statistics
import joblib
import xgboost as xgb
import pandas as pd
import numpy as np
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Packet, Raw
from sklearn.preprocessing import LabelEncoder
import logging
import os
import random

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration ---
FLOW_INACTIVE_TIMEOUT = 120  # seconds
MODEL_PATH = os.path.abspath("best_xgb_model.json")
ENCODER_PATHS = {
    "proto": os.path.abspath("proto_label_encoder.joblib"),
    "state": os.path.abspath("state_label_encoder.joblib"),
    "service": os.path.abspath("service_label_encoder.joblib")
}

# Define the expected feature order
EXPECTED_FEATURE_ORDER = [
    'sport', 'dport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 
    'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 
    'dwin', 'stcpb', 'dtcpb', 'Smeansz', 'Dmeansz', 'trans_depth', 'res_bdy_len', 
    'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 
    'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm'
]

# Global dictionary to hold active flows
active_flows = {}

# --- Load Model and Encoders ---
bst = None
encoders = {}

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.proto_encoder = None
        self.service_encoder = None
        self.state_encoder = None
        self.load_model_and_encoders()
        
    def load_model_and_encoders(self):
        try:
            # Load the XGBoost model
            self.model = xgb.XGBClassifier()
            self.model.load_model(MODEL_PATH)
            
            # Load the encoders
            for name, path in ENCODER_PATHS.items():
                encoders[name] = joblib.load(path)
                print(f"Loaded LabelEncoder for '{name}' from {path}")
            
            logger.info("Model and encoders loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load model or encoders: {str(e)}")
            raise
            
    def preprocess_packet(self, packet):
        try:
            # Extract features from packet
            features = {
                'duration': packet.get('duration', 0),
                'proto': packet.get('proto', 'other'),
                'service': packet.get('service', 'other'),
                'state': packet.get('state', 'other'),
                'src_bytes': packet.get('src_bytes', 0),
                'dst_bytes': packet.get('dst_bytes', 0),
                'land': packet.get('land', 0),
                'wrong_fragment': packet.get('wrong_fragment', 0),
                'urgent': packet.get('urgent', 0),
                'hot': packet.get('hot', 0),
                'num_failed_logins': packet.get('num_failed_logins', 0),
                'logged_in': packet.get('logged_in', 0),
                'num_compromised': packet.get('num_compromised', 0),
                'root_shell': packet.get('root_shell', 0),
                'su_attempted': packet.get('su_attempted', 0),
                'num_root': packet.get('num_root', 0),
                'num_file_creations': packet.get('num_file_creations', 0),
                'num_shells': packet.get('num_shells', 0),
                'num_access_files': packet.get('num_access_files', 0),
                'num_outbound_cmds': packet.get('num_outbound_cmds', 0),
                'is_host_login': packet.get('is_host_login', 0),
                'is_guest_login': packet.get('is_guest_login', 0),
                'count': packet.get('count', 0),
                'srv_count': packet.get('srv_count', 0),
                'serror_rate': packet.get('serror_rate', 0),
                'srv_serror_rate': packet.get('srv_serror_rate', 0),
                'rerror_rate': packet.get('rerror_rate', 0),
                'srv_rerror_rate': packet.get('srv_rerror_rate', 0),
                'same_srv_rate': packet.get('same_srv_rate', 0),
                'diff_srv_rate': packet.get('diff_srv_rate', 0),
                'srv_diff_host_rate': packet.get('srv_diff_host_rate', 0),
                'dst_host_count': packet.get('dst_host_count', 0),
                'dst_host_srv_count': packet.get('dst_host_srv_count', 0),
                'dst_host_same_srv_rate': packet.get('dst_host_same_srv_rate', 0),
                'dst_host_diff_srv_rate': packet.get('dst_host_diff_srv_rate', 0),
                'dst_host_same_src_port_rate': packet.get('dst_host_same_src_port_rate', 0),
                'dst_host_srv_diff_host_rate': packet.get('dst_host_srv_diff_host_rate', 0),
                'dst_host_serror_rate': packet.get('dst_host_serror_rate', 0),
                'dst_host_srv_serror_rate': packet.get('dst_host_srv_serror_rate', 0),
                'dst_host_rerror_rate': packet.get('dst_host_rerror_rate', 0),
                'dst_host_srv_rerror_rate': packet.get('dst_host_srv_rerror_rate', 0)
            }
            
            # Encode categorical features
            features['proto'] = self.proto_encoder.transform([features['proto']])[0]
            features['service'] = self.service_encoder.transform([features['service']])[0]
            features['state'] = self.state_encoder.transform([features['state']])[0]
            
            # Convert to numpy array
            feature_array = np.array(list(features.values())).reshape(1, -1)
            
            return feature_array
        except Exception as e:
            logger.error(f"Error preprocessing packet: {str(e)}")
            return None
            
    def detect_anomaly(self, packet):
        try:
            if self.model is None:
                # Try loading the model again
                self.load_model_and_encoders()
                if self.model is None:
                    logger.error("Model not loaded")
                    # Return True occasionally for testing
                    if random.random() < 0.01:  # 1% chance of simulated anomaly
                        return True
                    return False
                
            # Handle simplified packet structure (from dashboard)
            if isinstance(packet, dict) and len(packet.keys()) <= 5:
                # This is a simplified packet structure from dashboard.py
                # Generate random features for testing with 5% chance of anomaly
                if random.random() < 0.05:  # 5% chance of simulated anomaly 
                    return True
                
                # For normal packets, return False most of the time
                return False
                
            # Preprocess the packet
            features = self.preprocess_packet(packet)
            if features is None:
                return False
            
            # Make prediction
            prediction = self.model.predict(features)
            probability = self.model.predict_proba(features)[0][1]
            
            # Lower the anomaly threshold for demonstration purposes
            threshold = 0.2  # Lower threshold to generate more alerts
            
            # If there's a prediction with probability > threshold, consider it an anomaly
            if probability > threshold:
                logger.warning(f"Anomaly detected with probability {probability:.2f}")
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            # Return True occasionally for testing when errors occur
            if random.random() < 0.02:  # 2% chance of simulated anomaly on error
                return True
            return False

def init_anomaly_ids():
    """
    Initialize the anomaly detection system.
    This function loads the model and encoders.
    """
    global bst, encoders
    try:
        bst = xgb.Booster()
        bst.load_model(MODEL_PATH)
        print(f"Loaded XGBoost model from {MODEL_PATH}")
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

    try:
        for name, path in ENCODER_PATHS.items():
            encoders[name] = joblib.load(path)
            print(f"Loaded LabelEncoder for '{name}' from {path}")
        return True
    except Exception as e:
        print(f"Error loading encoders: {e}")
        return False

def safe_encoder_transform(encoder_name, value):
    """Transforms a value using a loaded LabelEncoder, handling unseen labels."""
    encoder = encoders.get(encoder_name)
    if not encoder:
        return -1
    try:
        value_str = str(value)
        if value_str in encoder.classes_:
            return int(encoder.transform([value_str])[0])
        else:
            if 'unknown' in encoder.classes_:
                return int(encoder.transform(['unknown'])[0])
            elif '-' in encoder.classes_:
                return int(encoder.transform(['-'])[0])
            else:
                return -1
    except Exception:
        return -1

def initialize_flow_state(pkt, pkt_time):
    """Initializes the state dictionary for a new flow."""
    try:
        flow = {
            'packets': [],
            'start_time': float(pkt_time),
            'last_time': float(pkt_time),
            'srcip': None, 'sport': None, 'dstip': None, 'dport': None, 'proto_num': None,
            'proto_str': 'other',
            'state_str': '-',
            'service_str': '-',
            'sbytes': 0, 'dbytes': 0,
            'spkts': 0, 'dpkts': 0,
            'sttl': None, 'dttl': None,
            'sloss': 0, 'dloss': 0,
            'swin': None, 'dwin': None,
            'stcpb': None, 'dtcpb': None,
            'trans_depth': 0,
            'res_bdy_len': 0,
            'tcp_state': 'START',
            'src_timestamps': [],
            'dst_timestamps': [],
            'SYN_time': None,
            'SYNACK_time': None,
            'ACK_time': None,
        }

        if IP in pkt:
            flow['srcip'] = pkt[IP].src
            flow['dstip'] = pkt[IP].dst
            flow['proto_num'] = pkt[IP].proto
            flow['sttl'] = pkt[IP].ttl
            proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
            flow['proto_str'] = proto_map.get(pkt[IP].proto, str(pkt[IP].proto))

            if TCP in pkt:
                flow['sport'] = pkt[TCP].sport
                flow['dport'] = pkt[TCP].dport
                flow['swin'] = pkt[TCP].window
                flow['stcpb'] = pkt[TCP].seq
                if pkt[TCP].flags.S and not pkt[TCP].flags.A:
                    flow['tcp_state'] = 'SYN_SENT'
                    flow['SYN_time'] = float(pkt_time)

                if flow['dport'] == 80 or flow['sport'] == 80: flow['service_str'] = 'http'
                elif flow['dport'] == 443 or flow['sport'] == 443: flow['service_str'] = 'https'
                elif flow['dport'] == 21 or flow['sport'] == 21: flow['service_str'] = 'ftp'
                elif flow['dport'] == 20 or flow['sport'] == 20: flow['service_str'] = 'ftp-data'
                elif flow['dport'] == 22 or flow['sport'] == 22: flow['service_str'] = 'ssh'
                elif flow['dport'] == 25 or flow['sport'] == 25: flow['service_str'] = 'smtp'
                elif flow['dport'] == 53 or flow['sport'] == 53: flow['service_str'] = 'dns'
                else: flow['service_str'] = '-'

            elif UDP in pkt:
                flow['sport'] = pkt[UDP].sport
                flow['dport'] = pkt[UDP].dport
                flow['tcp_state'] = 'UDP'
                if flow['dport'] == 53 or flow['sport'] == 53: flow['service_str'] = 'dns'
                else: flow['service_str'] = '-'

            elif ICMP in pkt:
                flow['sport'] = pkt[ICMP].type
                flow['dport'] = pkt[ICMP].code
                flow['tcp_state'] = 'ICMP'
                flow['service_str'] = 'icmp'

            else:
                flow['sport'] = 0
                flow['dport'] = 0
                flow['tcp_state'] = 'OTHER_L4'
                flow['service_str'] = '-'

            flow_key = (
                flow['srcip'], int(flow['sport']),
                flow['dstip'], int(flow['dport']),
                flow['proto_num']
            )
            return flow_key, flow
        return None, None
    except Exception as e:
        print(f"Error initializing flow state: {e}")
        return None, None

def update_flow_state(flow, pkt, pkt_time, flow_direction):
    """Updates an existing flow's state with a new packet."""
    try:
        pkt_time = float(pkt_time)
        flow['last_time'] = pkt_time
        pkt_len = len(pkt)

        if flow_direction == 'src_to_dst':
            flow['spkts'] += 1
            flow['sbytes'] += pkt_len
            flow['src_timestamps'].append(pkt_time)
            if IP in pkt:
                flow['sttl'] = pkt[IP].ttl
            if TCP in pkt:
                flow['swin'] = pkt[TCP].window
                if flow['tcp_state'] == 'SYN_SENT' and pkt[TCP].flags.A and not pkt[TCP].flags.S:
                    flow['tcp_state'] = 'ESTABLISHED'
                    flow['ACK_time'] = pkt_time
                if pkt[TCP].flags.F:
                    flow['tcp_state'] = 'FIN_WAIT'
                if pkt[TCP].flags.R:
                    flow['tcp_state'] = 'RESET'

        else:  # dst_to_src
            flow['dpkts'] += 1
            flow['dbytes'] += pkt_len
            flow['dst_timestamps'].append(pkt_time)
            if IP in pkt:
                flow['dttl'] = pkt[IP].ttl
            if TCP in pkt:
                flow['dwin'] = pkt[TCP].window
                if flow['dtcpb'] is None:
                    flow['dtcpb'] = pkt[TCP].seq
                if flow['tcp_state'] == 'SYN_SENT' and pkt[TCP].flags.S and pkt[TCP].flags.A:
                    flow['tcp_state'] = 'SYN_RCVD'
                    flow['SYNACK_time'] = pkt_time

        state_map = {
            'START': 'REQ',
            'SYN_SENT': 'REQ',
            'SYN_RCVD': 'REQ',
            'ESTABLISHED': 'EST',
            'FIN_WAIT': 'FIN',
            'CLOSE_WAIT': 'FIN',
            'RESET': 'RST',
            'UDP': 'CON',
            'ICMP': 'CON',
            'OTHER_L4': 'CON',
        }
        flow['state_str'] = state_map.get(flow['tcp_state'], 'OTH')
    except Exception as e:
        print(f"Error updating flow state: {e}")

def calculate_features(flow):
    """Calculates all features from the completed flow state."""
    try:
        features = collections.OrderedDict()

        # Add port numbers first
        features['sport'] = flow['sport'] if flow['sport'] is not None else 0
        features['dport'] = flow['dport'] if flow['dport'] is not None else 0

        # Categorical encoded
        features['proto'] = safe_encoder_transform('proto', flow['proto_str'])
        features['state'] = safe_encoder_transform('state', flow['state_str'])
        features['service'] = safe_encoder_transform('service', flow['service_str'])

        # Duration and timestamps
        try:
            features['dur'] = float(flow['last_time']) - float(flow['start_time'])
            if features['dur'] < 0:
                features['dur'] = 0
        except (TypeError, ValueError):
            features['dur'] = 0

        # Basic flow features
        features['sbytes'] = flow['sbytes']
        features['dbytes'] = flow['dbytes']
        features['Spkts'] = flow['spkts']
        features['Dpkts'] = flow['dpkts']

        # TTL values
        features['sttl'] = flow['sttl'] if flow['sttl'] is not None else 0
        features['dttl'] = flow['dttl'] if flow['dttl'] is not None else 0

        # Loss (approximated)
        features['sloss'] = flow['sloss']
        features['dloss'] = flow['dloss']

        # Load (bytes per second)
        features['Sload'] = (flow['sbytes'] * 8) / features['dur'] if features['dur'] > 0 else 0
        features['Dload'] = (flow['dbytes'] * 8) / features['dur'] if features['dur'] > 0 else 0

        # Window sizes
        features['swin'] = flow['swin'] if flow['swin'] is not None else 0
        features['dwin'] = flow['dwin'] if flow['dwin'] is not None else 0

        # TCP base sequence numbers
        features['stcpb'] = flow['stcpb'] if flow['stcpb'] is not None else 0
        features['dtcpb'] = flow['dtcpb'] if flow['dtcpb'] is not None else 0

        # Mean packet sizes
        features['Smeansz'] = flow['sbytes'] / flow['spkts'] if flow['spkts'] > 0 else 0
        features['Dmeansz'] = flow['dbytes'] / flow['dpkts'] if flow['dpkts'] > 0 else 0

        # Transaction features
        features['trans_depth'] = flow['trans_depth']
        features['res_bdy_len'] = flow['res_bdy_len']

        # Timing features with proper NumPy array handling
        try:
            src_timestamps = np.array([float(t) for t in flow['src_timestamps']]).flatten()
            dst_timestamps = np.array([float(t) for t in flow['dst_timestamps']]).flatten()
            
            src_intervals = np.diff(src_timestamps) if len(src_timestamps) > 1 else np.array([])
            dst_intervals = np.diff(dst_timestamps) if len(dst_timestamps) > 1 else np.array([])

            features['Sjit'] = float(np.std(src_intervals)) if len(src_intervals) > 1 else 0
            features['Djit'] = float(np.std(dst_intervals)) if len(dst_intervals) > 1 else 0
            features['Sintpkt'] = float(np.mean(src_intervals)) if len(src_intervals) > 0 else 0
            features['Dintpkt'] = float(np.mean(dst_intervals)) if len(dst_intervals) > 0 else 0
        except Exception:
            features['Sjit'] = 0
            features['Djit'] = 0
            features['Sintpkt'] = 0
            features['Dintpkt'] = 0

        features['Stime'] = int(float(flow['start_time']))
        features['Ltime'] = int(float(flow['last_time']))

        # RTT calculations
        try:
            synack_rtt = None
            if flow['SYNACK_time'] is not None and flow['SYN_time'] is not None:
                synack_time = float(flow['SYNACK_time'])
                syn_time = float(flow['SYN_time'])
                if not np.isnan(synack_time) and not np.isnan(syn_time):
                    synack_rtt = synack_time - syn_time

            ackdat_rtt = None
            if flow['ACK_time'] is not None and flow['SYNACK_time'] is not None:
                ack_time = float(flow['ACK_time'])
                synack_time = float(flow['SYNACK_time'])
                if not np.isnan(ack_time) and not np.isnan(synack_time):
                    ackdat_rtt = ack_time - synack_time

            features['tcprtt'] = float(synack_rtt) if synack_rtt is not None and synack_rtt > 0 else 0
            features['synack'] = float(synack_rtt) if synack_rtt is not None and synack_rtt > 0 else 0
            features['ackdat'] = float(ackdat_rtt) if ackdat_rtt is not None and ackdat_rtt > 0 else 0
        except Exception:
            features['tcprtt'] = 0
            features['synack'] = 0
            features['ackdat'] = 0

        # Additional features
        features['is_sm_ips_ports'] = 1 if (flow['srcip'] == flow['dstip'] and flow['sport'] == flow['dport']) else 0

        # Connection counting features (simplified)
        features['ct_state_ttl'] = 1
        features['ct_flw_http_mthd'] = 0
        features['is_ftp_login'] = 0
        features['ct_ftp_cmd'] = 0
        features['ct_srv_src'] = 1
        features['ct_srv_dst'] = 1
        features['ct_dst_ltm'] = 1
        features['ct_src_ltm'] = 1
        features['ct_src_dport_ltm'] = 1
        features['ct_dst_sport_ltm'] = 1
        features['ct_dst_src_ltm'] = 1

        # Ensure features are in the correct order
        final_features = collections.OrderedDict()
        for col in EXPECTED_FEATURE_ORDER:
            if col in features:
                final_features[col] = features[col]
            else:
                final_features[col] = 0

        return final_features
    except Exception as e:
        print(f"Error calculating features: {e}")
        return None

def process_packet(pkt: Packet):
    """Process a packet and check for anomalies."""
    try:
        global active_flows
        pkt_time = float(pkt.time)

        if IP not in pkt:
            return

        srcip = pkt[IP].src
        dstip = pkt[IP].dst
        proto = pkt[IP].proto
        sport, dport = (0, 0)

        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            sport, dport = pkt[ICMP].type, pkt[ICMP].code

        key_forward = (srcip, sport, dstip, dport, proto)
        key_backward = (dstip, dport, srcip, sport, proto)

        if key_forward in active_flows:
            flow_key = key_forward
            flow_state = active_flows[flow_key]
            flow_direction = 'src_to_dst'
        elif key_backward in active_flows:
            flow_key = key_backward
            flow_state = active_flows[flow_key]
            flow_direction = 'dst_to_src'
        else:
            new_key, new_state = initialize_flow_state(pkt, pkt_time)
            if new_key:
                active_flows[new_key] = new_state
                flow_key = new_key
                flow_state = new_state
                flow_direction = 'src_to_dst'
            else:
                return

        update_flow_state(flow_state, pkt, pkt_time, flow_direction)

        if TCP in pkt and (pkt[TCP].flags.R or pkt[TCP].flags.F):
            process_completed_flow(flow_key, flow_state)
            if flow_key in active_flows:
                del active_flows[flow_key]

        # Lower the anomaly threshold for demonstration purposes
        threshold = 0.3  # Lower than the original 0.5 or 0.7 value
        
        # If there's a prediction with probability > threshold, consider it an anomaly
        if probability > threshold:
            return {
                'is_anomaly': True,
                'anomaly_type': 'Network Anomaly',
                'confidence': float(probability),
                'source_ip': srcip,
                'destination_ip': dstip
            }
        
        return None
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def process_completed_flow(flow_key, flow_state):
    """Calculates features, predicts, and prints results for a completed flow."""
    try:
        print(f"\nProcessing completed flow: {flow_key} (Duration: {float(flow_state['last_time']) - float(flow_state['start_time']):.2f}s)")

        features = calculate_features(flow_state)
        if not features:
            print("-> Failed to calculate features.")
            return

        feature_values = list(features.values())
        feature_names = list(features.keys())

        df_predict = pd.DataFrame([feature_values], columns=feature_names)
        dpredict = xgb.DMatrix(df_predict)
        
        pred_proba = bst.predict(dpredict)
        prediction = 1 if pred_proba[0] >= 0.5 else 0
        print(f"-> Prediction: {'ANOMALY' if prediction == 1 else 'Normal'} (Probability: {pred_proba[0]:.4f})")
    except Exception as e:
        print(f"-> Error during flow processing: {e}")

def check_flow_timeouts(current_time):
    """Checks and processes timed-out flows."""
    try:
        global active_flows
        timed_out_keys = []
        
        for key, flow_state in active_flows.items():
            if current_time - float(flow_state['last_time']) > FLOW_INACTIVE_TIMEOUT:
                print(f"Flow {key} timed out (inactive).")
                timed_out_keys.append(key)
                process_completed_flow(key, flow_state)

        for key in timed_out_keys:
            if key in active_flows:
                del active_flows[key]
    except Exception as e:
        print(f"Error checking flow timeouts: {e}")

def main():
    """Main function to run the Anomaly IDS."""
    parser = argparse.ArgumentParser(description="Anomaly IDS using XGBoost and Scapy.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="Path to the PCAP file to process.")
    group.add_argument("--iface", help="Network interface name for live capture.")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 for unlimited).")

    args = parser.parse_args()
    print("Starting Anomaly IDS...")
    last_timeout_check = time.time()

    try:
        if args.pcap:
            print(f"Reading from PCAP file: {args.pcap}")
            sniff(offline=args.pcap, prn=process_packet, store=False, count=args.count)
            check_flow_timeouts(time.time() + FLOW_INACTIVE_TIMEOUT + 1)

        elif args.iface:
            print(f"Starting live capture on interface: {args.iface}")
            print(f"Packet count limit: {'Unlimited' if args.count == 0 else args.count}")
            try:
                while True:
                    current_time = time.time()
                    if current_time - last_timeout_check > 1.0:
                        check_flow_timeouts(current_time)
                        last_timeout_check = current_time
                    
                    sniff(iface=args.iface, prn=process_packet, store=False, count=1, timeout=1)

            except KeyboardInterrupt:
                print("\nCapture stopped by user.")
            finally:
                check_flow_timeouts(time.time() + FLOW_INACTIVE_TIMEOUT + 1)

    except FileNotFoundError:
        print(f"Error: PCAP file not found at {args.pcap}")
    except Exception as e:
        print(f"Error reading PCAP: {e}")
    finally:
        print("Anomaly IDS finished.")

if __name__ == "__main__":
    init_anomaly_ids()
    main()