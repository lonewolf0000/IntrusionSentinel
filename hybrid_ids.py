import argparse
import time
import threading
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, Packet, Raw, rdpcap
import logging
from datetime import datetime
import requests
import json
from signature_ids import SignatureDetector
from anomaly_ids import AnomalyDetector
import collections
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

FLOW_INACTIVE_TIMEOUT = 120  # seconds

class HybridIDS:
    def __init__(self):
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.active_flows = {}  # key: (srcip, sport, dstip, dport, proto), value: flow_state
        self.packet_count = 0
        self.start_time = time.time()
        self.last_stats_update = 0
        self.dashboard_url = "http://localhost:5000"
        self.lock = threading.Lock()
        # --- Real-time alert deduplication and stats ---
        self.recent_alerts = collections.OrderedDict()  # key: alert_hash, value: timestamp
        self.alert_expiry = 60  # seconds to keep alert hashes
        self.alert_counts = collections.defaultdict(int)  # alert_type -> count
        self.recent_alerts_list = collections.deque(maxlen=50)  # for dashboard display
        # --- Optional: WebSocket support (see send_alert_to_dashboard) ---
        # self.ws = None  # Placeholder for websocket connection

    def _alert_hash(self, alert_type, description, source_ip, destination_ip):
        # Create a unique hash for deduplication
        key = f"{alert_type}|{description}|{source_ip}|{destination_ip}"
        return hashlib.sha256(key.encode()).hexdigest()

    def _cleanup_old_alerts(self):
        # Remove old alerts from deduplication dict
        now = time.time()
        to_delete = [h for h, ts in self.recent_alerts.items() if now - ts > self.alert_expiry]
        for h in to_delete:
            del self.recent_alerts[h]

    def send_alert_to_dashboard(self, alert_type, severity, description, source_ip, destination_ip):
        self._cleanup_old_alerts()
        alert_hash = self._alert_hash(alert_type, description, source_ip, destination_ip)
        now = time.time()
        if alert_hash in self.recent_alerts:
            return  # Deduplicate
        self.recent_alerts[alert_hash] = now
        self.alert_counts[alert_type] += 1
        alert = {
            "type": alert_type,
            "severity": severity,
            "description": description,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "timestamp": datetime.now().isoformat()
        }
        self.recent_alerts_list.appendleft(alert)
        try:
            response = requests.post(f"{self.dashboard_url}/api/alerts", json=alert, timeout=2)
            if response.status_code != 200:
                logger.error(f"Failed to send alert to dashboard: {response.text}")
        except Exception as e:
            logger.error(f"Error sending alert to dashboard: {str(e)}")
        # --- Optional: WebSocket push (if dashboard supports it) ---
        # if self.ws:
        #     try:
        #         self.ws.send(json.dumps(alert))
        #     except Exception as e:
        #         logger.error(f"WebSocket send error: {e}")

    def send_stats_to_dashboard(self):
        try:
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            packets_per_second = self.packet_count / elapsed_time if elapsed_time > 0 else 0
            stats = {
                "packets_per_second": packets_per_second,
                "blocked_ips": len(self.signature_detector.blocked_ips),
                "total_alerts": sum(self.alert_counts.values()),
                "alert_counts": dict(self.alert_counts),
                "recent_alerts": list(self.recent_alerts_list),
            }
            response = requests.post(f"{self.dashboard_url}/api/stats", json=stats, timeout=2)
            if response.status_code != 200:
                logger.error(f"Failed to send stats to dashboard: {response.text}")
        except Exception as e:
            logger.error(f"Error sending stats to dashboard: {str(e)}")

    def _get_flow_key(self, pkt):
        if IP not in pkt:
            return None
        srcip = pkt[IP].src
        dstip = pkt[IP].dst
        proto = pkt[IP].proto
        sport, dport = 0, 0
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            sport, dport = pkt[ICMP].type, pkt[ICMP].code
        return (srcip, sport, dstip, dport, proto)

    def _initialize_flow_state(self, pkt, pkt_time):
        # This is a simplified version; you may want to match anomaly_ids.py for full feature support
        flow = {
            'packets': [],
            'start_time': float(pkt_time),
            'last_time': float(pkt_time),
            'srcip': pkt[IP].src if IP in pkt else None,
            'sport': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'dstip': pkt[IP].dst if IP in pkt else None,
            'dport': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'proto_num': pkt[IP].proto if IP in pkt else None,
            'proto_str': {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(pkt[IP].proto, str(pkt[IP].proto)) if IP in pkt else 'other',
            'state_str': '-',
            'service_str': '-',
            'sbytes': 0, 'dbytes': 0,
            'spkts': 0, 'dpkts': 0,
            'sttl': pkt[IP].ttl if IP in pkt else 0,
            'dttl': 0,
            'sloss': 0, 'dloss': 0,
            'swin': pkt[TCP].window if TCP in pkt else 0,
            'dwin': 0,
            'stcpb': pkt[TCP].seq if TCP in pkt else 0,
            'dtcpb': 0,
            'trans_depth': 0,
            'res_bdy_len': 0,
            'tcp_state': 'START',
            'src_timestamps': [float(pkt_time)],
            'dst_timestamps': [],
            'SYN_time': float(pkt_time) if (TCP in pkt and pkt[TCP].flags.S and not pkt[TCP].flags.A) else None,
            'SYNACK_time': None,
            'ACK_time': None,
        }
        return flow

    def _update_flow_state(self, flow, pkt, pkt_time, flow_direction):
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
        else:
            flow['dpkts'] += 1
            flow['dbytes'] += pkt_len
            flow['dst_timestamps'].append(pkt_time)
            if IP in pkt:
                flow['dttl'] = pkt[IP].ttl
            if TCP in pkt:
                flow['dwin'] = pkt[TCP].window
                if flow['dtcpb'] == 0:
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

    def _process_completed_flow(self, flow_key, flow_state):
        # Use the anomaly detector on the completed flow
        try:
            is_anomaly = self.anomaly_detector.detect_anomaly(flow_state)
            if is_anomaly:
                # User-friendly, actionable description
                description = f"Anomalous flow from {flow_state['srcip']} to {flow_state['dstip']} detected. Possible suspicious activity."
                self.send_alert_to_dashboard(
                    alert_type="Anomaly",
                    severity="high",
                    description=description,
                    source_ip=flow_state['srcip'],
                    destination_ip=flow_state['dstip']
                )
        except Exception as e:
            logger.error(f"Error in anomaly detection for flow {flow_key}: {str(e)}")

    def check_flow_timeouts(self, current_time):
        timed_out_keys = []
        with self.lock:
            for key, flow_state in list(self.active_flows.items()):
                if current_time - float(flow_state['last_time']) > FLOW_INACTIVE_TIMEOUT:
                    logger.info(f"Flow {key} timed out (inactive). Processing for anomaly detection.")
                    self._process_completed_flow(key, flow_state)
                    timed_out_keys.append(key)
            for key in timed_out_keys:
                if key in self.active_flows:
                    del self.active_flows[key]

    def process_packet(self, packet):
        try:
            if not packet.haslayer(IP):
                return
            self.packet_count += 1
            pkt_time = float(packet.time)
            # --- Signature-based detection (per packet) ---
            signature_result = self.signature_detector.process_packet(packet)
            if signature_result:
                alert_type, severity, description = signature_result
                # User-friendly, actionable description
                description = f"{description} (from {packet[IP].src} to {packet[IP].dst})"
                self.send_alert_to_dashboard(
                    alert_type=alert_type,
                    severity=severity,
                    description=description,
                    source_ip=packet[IP].src,
                    destination_ip=packet[IP].dst
                )
            # --- Anomaly-based detection (per flow) ---
            flow_key = self._get_flow_key(packet)
            if flow_key is None:
                return
            with self.lock:
                if flow_key in self.active_flows:
                    flow_state = self.active_flows[flow_key]
                    flow_direction = 'src_to_dst'
                else:
                    flow_state = self._initialize_flow_state(packet, pkt_time)
                    self.active_flows[flow_key] = flow_state
                    flow_direction = 'src_to_dst'
                self._update_flow_state(flow_state, packet, pkt_time, flow_direction)
                # If TCP FIN or RST, process completed flow
                if TCP in packet and (packet[TCP].flags.F or packet[TCP].flags.R):
                    self._process_completed_flow(flow_key, flow_state)
                    del self.active_flows[flow_key]
            # Send stats update every 100 packets
            if self.packet_count % 100 == 0:
                self.send_stats_to_dashboard()
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def start_monitoring(self, pcap_file=None):
        try:
            last_timeout_check = time.time()
            if pcap_file:
                logger.info(f"Processing pcap file: {pcap_file}")
                packets = rdpcap(pcap_file)
                for packet in packets:
                    self.process_packet(packet)
                    # Periodically check for flow timeouts
                    now = time.time()
                    if now - last_timeout_check > 1.0:
                        self.check_flow_timeouts(now)
                        last_timeout_check = now
                # After all packets, flush remaining flows
                self.check_flow_timeouts(time.time() + FLOW_INACTIVE_TIMEOUT + 1)
            else:
                logger.info("Starting live packet monitoring...")
                sniff(prn=self.process_packet, store=0)
        except Exception as e:
            logger.error(f"Error in monitoring: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Hybrid Intrusion Detection System")
    parser.add_argument("--pcap", help="Path to pcap file for offline analysis")
    args = parser.parse_args()

    ids = HybridIDS()
    ids.start_monitoring(args.pcap)

if __name__ == "__main__":
    main()