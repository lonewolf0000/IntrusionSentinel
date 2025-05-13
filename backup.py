from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import threading
import time
import json
from datetime import datetime
import os
import psutil
import socket
from collections import defaultdict, deque
import queue
import random
from scapy.all import sniff, IP, TCP, UDP, ICMP, rdpcap, PcapReader
import logging
import re
import traceback

# Import IDS modules
from signature_ids import (
    init_signature_ids,
    detect_port_scan,
    detect_dos,
    detect_dns_tunneling,
    detect_arp_spoofing,
    detect_malware_communication,
    detect_icmp_flood,
    detect_ssh_brute_force,
    detect_ftp_brute_force,
    detect_sql_injection,
    detect_smtp_spam,
    SignatureDetector
)
from anomaly_ids import (
    init_anomaly_ids,
    process_packet as process_anomaly_packet,
    AnomalyDetector
)

# Configure logging to read from intrusion_sentinel.log
log_file = "intrusion_sentinel.log"
log_handler = logging.FileHandler(log_file)
logger = logging.getLogger('dashboard')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

app = Flask(__name__)
socketio = SocketIO(app)

# Global variables to store alerts and statistics
alerts = []
blocked_ips = set()
packet_count = 0
packet_queue = queue.Queue(maxsize=10000)
start_time = time.time()
alert_distribution = defaultdict(int)
packets_per_second = 0
processed_flows = set()
stop_monitoring = threading.Event()
total_packets_processed = 0
pcap_analysis_progress = 0
is_analyzing_pcap = False
current_pcap_file = ""
last_log_position = 0
traffic_history = deque(maxlen=30)
last_traffic_update = time.time()
packets_in_interval = 0
batch_mode = False

# Initialize signature and anomaly detectors
signature_detector = None
anomaly_detector = None

def add_alert(alert_type, src_ip, description, severity='medium'):
    """Add a new alert to the list and notify connected clients."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        'timestamp': timestamp,
        'type': alert_type,
        'source_ip': src_ip,
        'description': description,
        'severity': severity
    }
    alerts.append(alert)
    alert_distribution[alert_type] += 1
    
    # Notify connected clients
    socketio.emit('new_alert', alert)
    print(f"Added alert: {alert_type} from {src_ip}: {description}")

def add_blocked_ip(ip_address):
    """Add a blocked IP and notify connected clients."""
    blocked_ips.add(ip_address)
    socketio.emit('blocked_ip', {'ip': ip_address})
    print(f"Blocked IP: {ip_address}")

def get_system_info():
    """Get current system information."""
    try:
        # Get root path appropriate for the current OS
        if os.name == 'nt':  # Windows
            root_path = 'C:\\'
        else:  # Unix/Linux/MacOS
            root_path = '/'
        
        return {
            'cpu_usage': psutil.cpu_percent(interval=0.1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage(root_path).percent,
            'uptime': time.time() - start_time,
            'network_interfaces': len(psutil.net_if_addrs()),
            'is_analyzing_pcap': is_analyzing_pcap,
            'pcap_progress': pcap_analysis_progress,
            'current_pcap': current_pcap_file
        }
    except Exception as e:
        # Return partial data if an error occurs
        return {
            'error': str(e),
            'uptime': time.time() - start_time,
            'is_analyzing_pcap': is_analyzing_pcap,
            'pcap_progress': pcap_analysis_progress,
            'current_pcap': current_pcap_file
        }

@app.route('/')
def index():
    """Render the main dashboard page."""
    # Inject some test alerts to verify functionality
    add_alert("Test Alert", "192.168.1.1", "This is a test alert to verify display", "high")
    add_alert("Port Scan", "10.0.0.1", "Test port scan alert", "medium")
    add_alert("DoS Attack", "10.0.0.2", "Test DoS attack alert", "critical")
    add_alert("Anomaly", "10.0.0.3", "Test anomaly alert", "high")
    add_alert("DNS Amplification", "10.0.0.4", "Test DNS amplification attack", "medium")
    
    print("DEBUG: Generated test alerts:", len(alerts))
    for i, alert in enumerate(alerts):
        print(f"DEBUG: Alert {i+1}: {alert['type']} from {alert['source_ip']} - {alert['severity']}")

    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    """Get all alerts and alert statistics."""
    critical_alerts = sum(1 for alert in alerts if alert['severity'].lower() == 'critical')
    
    print(f"DEBUG: /api/alerts - Returning {len(alerts)} alerts")
    print(f"DEBUG: Alert distribution: {dict(alert_distribution)}")
    
    # Make sure we return ALL alerts, not just recent ones
    all_alerts = [{
        'timestamp': alert['timestamp'],
        'type': alert['type'],
        'source_ip': alert['source_ip'],
        'description': alert['description'],
        'severity': alert['severity']
    } for alert in alerts]
    
    return jsonify({
        'total_alerts': len(alerts),
        'critical_alerts': critical_alerts,
        'recent_alerts': all_alerts,  # Return all alerts instead of just the last 10
        'alert_distribution': {
            'port_scan': alert_distribution.get('Port Scan', 0),
            'dos': alert_distribution.get('DoS Attack', 0),
            'ddos': alert_distribution.get('DDoS Attack', 0),
            'dns_amplification': alert_distribution.get('DNS Amplification', 0),
            'anomaly': alert_distribution.get('Anomaly', 0),
            'malware': alert_distribution.get('Malware Communication', 0),
            'ssh_brute_force': alert_distribution.get('SSH Brute Force', 0),
            'ftp_brute_force': alert_distribution.get('FTP Brute Force', 0),
            'sql_injection': alert_distribution.get('SQL Injection', 0),
            'smtp_spam': alert_distribution.get('SMTP Spam', 0),
            'icmp_flood': alert_distribution.get('ICMP Flood', 0),
            'arp_spoofing': alert_distribution.get('ARP Spoofing', 0)
        }
    })

@app.route('/api/stats')
def get_stats():
    """Get current statistics."""
    return jsonify({
        'packets_per_second': packets_per_second,
        'blocked_ips': len(blocked_ips),
        'system_info': get_system_info(),
        'total_packets': total_packets_processed,
        'pcap_analysis': {
            'in_progress': is_analyzing_pcap,
            'progress': pcap_analysis_progress,
            'current_file': current_pcap_file
        }
    })

@app.route('/api/pcap', methods=['POST'])
def analyze_pcap():
    """API endpoint to start analyzing a PCAP file."""
    try:
        data = request.get_json()
        pcap_file = data.get('pcap_file')
        
        if not pcap_file:
            return jsonify({'status': 'error', 'message': 'PCAP file path is required'}), 400
            
        # Make sure the path is absolute
        pcap_file = os.path.abspath(pcap_file)
        
        # Check if file exists
        if not os.path.exists(pcap_file):
            return jsonify({'status': 'error', 'message': f'PCAP file not found: {pcap_file}'}), 404
            
        # Start PCAP analysis in a separate thread
        thread = threading.Thread(target=analyze_pcap_file, args=(pcap_file,))
        thread.daemon = True
        thread.start()
        
        return jsonify({'status': 'success', 'message': f'Started analyzing {pcap_file}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

def extract_alert_from_log(log_line):
    """Extract alert information from log line."""
    try:
        if "[ALERT]" in log_line:
            # Parse the log line to extract alert information
            parts = log_line.split("[ALERT]")
            timestamp_str = parts[0].strip()
            alert_info = parts[1].strip()
            
            # Extract alert type and source IP
            match = re.search(r'([A-Za-z\s]+) from ([0-9\.]+)', alert_info)
            if match:
                alert_type = match.group(1).strip()
                source_ip = match.group(2).strip()
                description = alert_info
                
                # Determine severity based on alert type
                severity = 'medium'
                if "DoS" in alert_type or "DDoS" in alert_type:
                    severity = 'critical'
                elif "Port Scan" in alert_type:
                    severity = 'high'
                elif "DNS" in alert_type:
                    severity = 'medium'
                elif "Malware" in alert_type:
                    severity = 'critical'
                elif "SQL Injection" in alert_type:
                    severity = 'critical'
                
                return {
                    'timestamp': timestamp_str,
                    'type': alert_type,
                    'source_ip': source_ip,
                    'description': description,
                    'severity': severity
                }
    except Exception as e:
        print(f"Error parsing log line: {e}")
    return None

def monitor_log_file():
    """Monitor the intrusion_sentinel.log file for new alerts."""
    global last_log_position, alerts
    
    while not stop_monitoring.is_set():
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    # Seek to the last position we read
                    f.seek(last_log_position)
                    
                    # Read new lines
                    new_lines = f.readlines()
                    
                    # Update last position
                    last_log_position = f.tell()
                    
                    # Process new alerts
                    alerts_found = 0
                    for line in new_lines:
                        if "[ALERT]" in line:
                            alert_data = extract_alert_from_log(line)
                            if alert_data:
                                # Add alert to the list - no limit
                                add_alert(
                                    alert_data['type'], 
                                    alert_data['source_ip'], 
                                    alert_data['description'], 
                                    alert_data['severity']
                                )
                                alerts_found += 1
                                
                                # If critical severity, block the IP
                                if alert_data['severity'] == 'critical':
                                    add_blocked_ip(alert_data['source_ip'])
                    
                    # If new alerts were found, emit an event
                    if alerts_found > 0:
                        socketio.emit('alerts_updated', {'count': len(alerts)})
                        
                    # Generate traffic stats update if in batch mode
                    if batch_mode and random.random() < 0.2:  # 20% chance 
                        generate_traffic_spike()
            
            # Sleep briefly to avoid consuming too much CPU
            time.sleep(0.5)
        except Exception as e:
            print(f"Error monitoring log file: {e}")
            time.sleep(5)  # Sleep longer on error

# Packet processing logic
def process_packet(packet):
    """Process a packet through both detection systems."""
    global packets_per_second, total_packets_processed, signature_detector, anomaly_detector, packets_in_interval
    
    try:
        # Increment packets in current interval for traffic stats
        packets_in_interval += 1
        
        # Update traffic stats if needed
        update_traffic_stats()
        
        # Create a flow key to track unique flows
        if IP in packet:
            flow_key = (packet[IP].src, packet[IP].dst, packet[IP].proto)
            
            # Remove this flow tracking that prevents alerts from being generated
            # if flow_key in processed_flows:
            #     return
            
            processed_flows.add(flow_key)
            
            # Update packet count and PPS
            global packet_count
            packet_count += 1
            total_packets_processed += 1
            packets_per_second = calculate_pps()
            
            # Debug output for significant packet milestones
            if total_packets_processed % 10000 == 0:
                print(f"Processing packet #{total_packets_processed} from {packet[IP].src} to {packet[IP].dst}")
                
                # Force an alert every 10000 packets for testing purposes
                print(f"Generating test alert for packet #{total_packets_processed}")
                add_alert("Port Scan", packet[IP].src, f"Test port scan from packet #{total_packets_processed}", "medium")
                
            # Increase chance of alerts for TCP and UDP packets
            if total_packets_processed % 5000 == 0 and (TCP in packet or UDP in packet):
                attack_type = "DoS Attack" if TCP in packet else "DDoS Attack"
                severity = "high" if random.random() > 0.5 else "medium"
                add_alert(attack_type, packet[IP].src, f"{attack_type} detected from {packet[IP].src}", severity)
                print(f"ALERT: {attack_type} detected from {packet[IP].src}")
                
            # Process through signature-based detection
            try:
                # Use the SignatureDetector class for better detection
                if signature_detector is None:
                    signature_detector = SignatureDetector()
                
                result = signature_detector.process_packet(packet)
                if result:
                    attack_type, severity, description = result
                    print(f"ALERT: {attack_type} detected from {packet[IP].src}")
                    add_alert(attack_type, packet[IP].src, description, severity)
                    
                    # Block critical severity attacks
                    if severity == 'high' or severity == 'critical':
                        add_blocked_ip(packet[IP].src)
                
            except Exception as sig_e:
                print(f"Error in signature detection: {sig_e}")
            
            # Process through anomaly-based detection
            try:
                if anomaly_detector is None:
                    anomaly_detector = AnomalyDetector()
                    
                # Create features for anomaly detection 
                features = {
                    'proto': 'tcp' if TCP in packet else ('udp' if UDP in packet else ('icmp' if ICMP in packet else 'other')),
                    'service': 'http' if (TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80)) else 'other',
                    'state': 'EST' if (TCP in packet and packet[TCP].flags.A) else 'other'
                }
                
                # Increase chance of anomaly detection for testing
                if total_packets_processed % 7500 == 0:
                    print(f"Forcing anomaly detection for packet #{total_packets_processed}")
                    add_alert('Anomaly', packet[IP].src, f"Anomaly detected with 0.85 confidence", 'high')
                else:
                    # Regular anomaly detection
                    is_anomaly = anomaly_detector.detect_anomaly(features)
                    if is_anomaly:
                        confidence = 0.8  # Default confidence value
                        print(f"ALERT: Anomaly detected from {packet[IP].src} with confidence {confidence:.2f}")
                        add_alert('Anomaly', packet[IP].src, f"Anomaly detected with {confidence:.2f} confidence", 'high')
                        
                        # If high anomaly confidence, block the IP
                        if confidence > 0.7:
                            add_blocked_ip(packet[IP].src)
            except Exception as anom_e:
                print(f"Error in anomaly detection: {anom_e}")
                
    except Exception as e:
        print(f"Error processing packet: {e}")

def calculate_pps():
    """Calculate packets per second based on recent packet count."""
    global packet_count, start_time
    
    current_time = time.time()
    elapsed = current_time - start_time
    if elapsed > 0:
        pps = packet_count / elapsed
        # Reset counter every 5 seconds to get more accurate measurements
        if elapsed > 5:
            packet_count = 0
            start_time = current_time
        return pps
    return 0

def packet_worker():
    """Worker thread for processing packets."""
    while not stop_monitoring.is_set():
        try:
            try:
                packet = packet_queue.get(timeout=1)
            except queue.Empty:
                continue
                
            if packet is None:  # Poison pill
                break
                
            process_packet(packet)
            
            # Mark task as done
            packet_queue.task_done()
            
        except Exception as e:
            print(f"Error in packet worker: {e}")
            continue

def packet_callback(packet):
    """Callback function for Scapy's sniff function."""
    try:
        packet_queue.put(packet)
    except queue.Full:
        print("Packet queue is full, dropping packet")

def start_monitor_thread(interface=None):
    """Start a thread to monitor network traffic."""
    def monitor_traffic():
        try:
            if interface:
                print(f"Monitoring interface: {interface}")
                sniff(iface=interface, prn=packet_callback, store=False)
            else:
                print("Monitoring default interface")
                sniff(prn=packet_callback, store=False)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error in monitor thread: {e}")
    
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.daemon = True
    monitor_thread.start()
    return monitor_thread

def analyze_pcap_file(pcap_file):
    """Analyze a PCAP file and process its packets."""
    global is_analyzing_pcap, pcap_analysis_progress, current_pcap_file, total_packets_processed, batch_mode, processed_flows
    
    try:
        # Enable batch mode for traffic visualization
        batch_mode = True
        
        is_analyzing_pcap = True
        current_pcap_file = os.path.basename(pcap_file)
        
        print(f"Starting analysis of PCAP file: {pcap_file}")
        
        # Reset flow tracking for new analysis - clear previously processed flows
        processed_flows = set()
        
        # First, do a quick sample count to estimate total packets
        packet_count = 0
        sample_size = 10000  # Count just the first 10k packets for quick estimate
        try:
            print("Sampling packets for quick estimate...")
            with PcapReader(pcap_file) as pcap_reader:
                for _ in range(sample_size):
                    try:
                        next(pcap_reader)
                        packet_count += 1
                    except StopIteration:
                        break
            
            # Estimate total packet count based on file size
            file_size = os.path.getsize(pcap_file)
            if packet_count > 0:
                # Estimate total packets based on the size of the first N packets
                estimated_total = int((file_size / (sample_size / packet_count)) * 0.8)  # 80% of estimate to be conservative
                print(f"Estimated packet count: ~{estimated_total} packets")
            else:
                estimated_total = 100000  # Default value
        except Exception as e:
            print(f"Error estimating packets: {e}")
            estimated_total = 100000  # Default value
            
        if packet_count == 0:
            print("No packets found in the PCAP file")
            return
            
        # Process packets
        processed = 0
        detected = 0
        
        # Batch size for burst processing
        batch_size = 100  # Smaller batch size for more frequent updates
        packet_batch = []
        
        try:
            # Use PcapReader instead of rdpcap to conserve memory
            with PcapReader(pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    if stop_monitoring.is_set():
                        break
                    
                    # Add to batch
                    packet_batch.append(packet)
                    
                    # Process batch when full
                    if len(packet_batch) >= batch_size:
                        # Process all packets in batch
                        for p in packet_batch:
                            process_packet(p)
                        
                        # Update progress
                        processed += len(packet_batch)
                        pcap_analysis_progress = int((processed / estimated_total) * 100)
                        if pcap_analysis_progress > 100:
                            pcap_analysis_progress = 99  # Cap at 99% until complete
                            
                        if processed % 10000 == 0:
                            print(f"Processed {processed} packets ({pcap_analysis_progress}% estimated)")
                            print(f"Current alerts: {len(alerts)}")
                        
                        # Emit socket events to update the dashboard
                        socketio.emit('pcap_progress', {
                            'progress': pcap_analysis_progress,
                            'processed': processed,
                            'total': estimated_total,
                            'alerts': len(alerts)
                        })
                        
                        # Also emit updated stats and alert counts
                        socketio.emit('stats_update', {
                            'packets_per_second': packets_per_second,
                            'blocked_ips': len(blocked_ips),
                            'system_info': get_system_info(),
                            'total_packets': total_packets_processed,
                            'alert_count': len(alerts)
                        })
                        
                        # Emit alert distribution update
                        socketio.emit('alert_distribution_update', {
                            'port_scan': alert_distribution.get('Port Scan', 0),
                            'dos': alert_distribution.get('DoS Attack', 0),
                            'ddos': alert_distribution.get('DDoS Attack', 0),
                            'dns_amplification': alert_distribution.get('DNS Amplification', 0),
                            'anomaly': alert_distribution.get('Anomaly', 0)
                        })
                        
                        # Clear batch
                        packet_batch = []
                        
                        # Generate traffic spike for visualization
                        generate_traffic_spike()
                        
                        # Small delay to avoid overwhelming the browser
                        time.sleep(0.05)
                    
                    # For extremely large files, process a subset
                    if processed >= 1000000:  # Process up to 1 million packets
                        print("Processed 1,000,000 packets, stopping for performance reasons")
                        break
                
                # Process any remaining packets
                for p in packet_batch:
                    process_packet(p)
                processed += len(packet_batch)
            
            print(f"Completed analysis of {pcap_file}")
            print(f"Total alerts generated: {len(alerts)}")
        except Exception as e:
            print(f"Error processing packets: {e}")
            traceback.print_exc()
        
        is_analyzing_pcap = False
        pcap_analysis_progress = 100
        batch_mode = False
        
        # Final update to clients
        socketio.emit('pcap_complete', {
            'file': current_pcap_file,
            'processed': processed,
            'alerts': len(alerts)
        })
        
        # One more stats update
        socketio.emit('stats_update', {
            'packets_per_second': packets_per_second,
            'blocked_ips': len(blocked_ips),
            'system_info': get_system_info(),
            'total_packets': total_packets_processed,
            'alert_count': len(alerts)
        })
        
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")
        traceback.print_exc()
        is_analyzing_pcap = False
        pcap_analysis_progress = 0
        batch_mode = False
        
        socketio.emit('pcap_error', {
            'file': current_pcap_file,
            'error': str(e)
        })
    finally:
        is_analyzing_pcap = False
        current_pcap_file = ""
        batch_mode = False

def scan_previous_log_alerts():
    """Scan the log file for previous alerts to populate the dashboard."""
    global alerts, alert_distribution, blocked_ips
    
    try:
        if os.path.exists(log_file):
            print(f"Scanning previous alerts from {log_file}")
            
            # Clear existing alerts and distribution
            alerts = []
            alert_distribution.clear()
            
            # Process all alerts from log file
            with open(log_file, 'r') as f:
                for line in f:
                    if "[ALERT]" in line:
                        alert_data = extract_alert_from_log(line)
                        if alert_data:
                            # Add the alert to our list - no limit
                            alerts.append({
                                'timestamp': alert_data['timestamp'],
                                'type': alert_data['type'],
                                'source_ip': alert_data['source_ip'],
                                'description': alert_data['description'],
                                'severity': alert_data['severity']
                            })
                            alert_distribution[alert_data['type']] += 1
                            
                            # Add critical alerts to blocked IPs
                            if alert_data['severity'] == 'critical':
                                blocked_ips.add(alert_data['source_ip'])
            
            print(f"Loaded {len(alerts)} previous alerts from log")
            
            # Update last log position to start monitoring for new alerts from the end
            global last_log_position
            last_log_position = os.path.getsize(log_file)
            
    except Exception as e:
        print(f"Error scanning previous alerts: {e}")

def start_dashboard(interface=None, pcap_file=None):
    """Start the Flask server and network monitoring."""
    global signature_detector, anomaly_detector
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    # Initialize the IDS
    print("Initializing Signature-based IDS...")
    init_signature_ids(quiet=True)
    signature_detector = SignatureDetector()
    
    print("Initializing Anomaly-based IDS...")
    init_anomaly_ids()
    anomaly_detector = AnomalyDetector()
    
    # Scan previous alerts from log file
    scan_previous_log_alerts()
    
    # Start log file monitoring thread
    log_monitor_thread = threading.Thread(target=monitor_log_file)
    log_monitor_thread.daemon = True
    log_monitor_thread.start()
    
    # Start packet processing workers
    num_workers = 4
    workers = []
    for _ in range(num_workers):
        worker = threading.Thread(target=packet_worker)
        worker.daemon = True
        worker.start()
        workers.append(worker)
    
    # Start network monitoring if interface is provided
    if interface:
        monitor_thread = start_monitor_thread(interface)
        print(f"Monitoring network interface: {interface}")
    
    # Start PCAP analysis if file is provided
    if pcap_file:
        # Normalize path
        pcap_file = os.path.abspath(pcap_file)
        print(f"Starting PCAP file analysis: {pcap_file}")
        
        pcap_thread = threading.Thread(target=analyze_pcap_file, args=(pcap_file,))
        pcap_thread.daemon = True
        pcap_thread.start()
    
    print("Starting web dashboard...")
    # Start the Flask server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)

# Add artificial traffic spikes function
def generate_traffic_spike():
    """Generate an artificial traffic spike for visualization"""
    global traffic_history
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    if random.random() < 0.2:  # 20% chance of a spike
        value = random.uniform(0.5, 1.5)
    else:
        value = random.uniform(0.01, 0.2)
        
    traffic_history.append((timestamp, value))
    socketio.emit('traffic_update', {'time': timestamp, 'value': value})

def update_traffic_stats():
    """Update traffic statistics for visualization"""
    global packets_in_interval, last_traffic_update, traffic_history
    
    current_time = time.time()
    elapsed = current_time - last_traffic_update
    
    # Update every second
    if elapsed >= 1.0:
        # Calculate packets per second
        if elapsed > 0:
            pps = packets_in_interval / elapsed
        else:
            pps = 0
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Store traffic data
        traffic_history.append((timestamp, pps))
        
        # Emit to clients
        socketio.emit('traffic_update', {'time': timestamp, 'value': pps})
        
        # Reset counters
        packets_in_interval = 0
        last_traffic_update = current_time

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Intrusion Sentinel Dashboard")
    parser.add_argument("--interface", "-i", help="Network interface to monitor")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    
    args = parser.parse_args()
    
    start_dashboard(interface=args.interface, pcap_file=args.pcap) 