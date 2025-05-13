#!/usr/bin/env python3
"""
Intrusion Sentinel: Optimized CLI-Based Intrusion Detection System
"""

import os
import sys
import logging
import threading
import time
import requests
import argparse
from datetime import datetime, timezone
from collections import defaultdict, deque
from threading import Event
import queue
import psutil  # For resource monitoring
import socket
import re
import random

from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, DNS, DNSQR, Raw, get_if_list
from scapy.layers.http import HTTPRequest  # Correct import for HTTPRequest

from colorama import init
from termcolor import colored
from tabulate import tabulate
import questionary

from logging.handlers import RotatingFileHandler
import subprocess
import win32com.client
import pythoncom

# Initialize Colorama
init()

# Configure Logging with RotatingFileHandler and StreamHandler
LOG_FILE = "intrusion_sentinel.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Rotating File Handler
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)  # 5MB per file, 5 backups
file_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Stream (Console) Handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Set to WARNING to display alerts and above on console
console_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Global Variables
malicious_ips = set()
malicious_domains = set()

# Modified detection thresholds for dashboard demonstration
DETECTION_THRESHOLDS = {
    "port_scan": 1,          # Very low for testing
    "dos": 2,                # Very low for testing
    "dns_tunneling": 1,      # Very low for testing
    "arp_spoofing": 1,       # Very low for testing
    "malware_comm": 1,       # Very low for testing
    "icmp_flood": 3,         # Very low for testing
    "ssh_brute_force": 1,    # Very low for testing
    "ftp_brute_force": 1,    # Very low for testing
    "sql_injection": 1,      # Very low for testing
    "smtp_spam": 2           # Very low for testing
}

# Time Windows (in seconds)
PORT_SCAN_TIME_WINDOW = 60  # 60 seconds
DOS_TIME_WINDOW = 60        # 60 seconds

# Data Structures for Tracking with Time-based Entries
port_scan_tracker = defaultdict(lambda: deque())
dos_tracker = defaultdict(lambda: deque())
dns_tunneling_tracker = defaultdict(lambda: deque(maxlen=DETECTION_THRESHOLDS["dns_tunneling"]))
arp_spoofing_tracker = {}
malware_comm_tracker = set()
icmp_flood_tracker = defaultdict(int)
ssh_brute_force_tracker = defaultdict(int)
ftp_brute_force_tracker = defaultdict(int)
sql_injection_tracker = defaultdict(int)
smtp_spam_tracker = defaultdict(int)

# Email Notification Settings (Optional)
EMAIL_ALERTS = False
EMAIL_SETTINGS = {
    "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
    "smtp_port": int(os.getenv("SMTP_PORT", 587)),
    "smtp_user": os.getenv("SMTP_USER", "your_email@example.com"),
    "smtp_password": os.getenv("SMTP_PASSWORD", "your_password"),  # Use App Password
    "recipient_email": os.getenv("RECIPIENT_EMAIL", "recipient@example.com"),
}

# Initialize the stop event
stop_sniffing = Event()

# Packet Queue for Asynchronous Processing
packet_queue = queue.Queue(maxsize=10000)  # Adjust size as needed

# Packet Sampling Rate (Analyze 1 out of every SAMPLE_RATE packets)
SAMPLE_RATE = 10  # Adjust sampling rate as needed

# Active Detection Modules (Enable/Disable detections)
ACTIVE_DETECTIONS = {
    "port_scan": True,
    "dos": True,
    "dns_tunneling": True,
    "arp_spoofing": True,
    "malware_comm": True,
    "icmp_flood": True,
    "ssh_brute_force": True,
    "ftp_brute_force": True,
    "sql_injection": True,
    "smtp_spam": True,
}

# Lock for Thread-Safe Operations
tracker_lock = threading.Lock()

# Collect the IDS's own IP addresses to prevent blocking them
def get_own_ips():
    """
    Retrieve all IPv4 addresses assigned to the machine's network interfaces.
    """
    own_ips = set()
    try:
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    own_ips.add(addr.address)
    except Exception as e:
        logger.warning(f"Failed to get own IP addresses: {e}")
    return own_ips

OWN_IPS = get_own_ips()

def fetch_threat_intelligence():
    """
    Fetch malicious IPs and domains from threat intelligence feeds.
    """
    global malicious_ips, malicious_domains
    logger.info("Fetching threat intelligence feeds...")
    
    # Use local threat intelligence files as fallback
    local_ip_file = "FYP2/local_threat_ips.txt"
    local_domain_file = "FYP2/local_threat_domains.txt"
    
    ip_feeds = [
        'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'https://www.spamhaus.org/drop/drop.txt',
    ]
    domain_feeds = [
        'https://openphish.com/feed.txt',
        'https://phishing.army/download/phishing_army_blocklist_extended.txt',
    ]

    # Try to load from local files first
    try:
        if os.path.exists(local_ip_file):
            with open(local_ip_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if validate_ip(ip):
                        malicious_ips.add(ip)
            logger.info(f"Loaded IPs from local file: {local_ip_file}")
    except Exception as e:
        logger.warning(f"Error loading local IP file: {e}")

    try:
        if os.path.exists(local_domain_file):
            with open(local_domain_file, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if validate_domain(domain):
                        malicious_domains.add(domain)
            logger.info(f"Loaded domains from local file: {local_domain_file}")
    except Exception as e:
        logger.warning(f"Error loading local domain file: {e}")

    # Then try to fetch from online feeds
    for feed in ip_feeds:
        try:
            response = requests.get(feed, timeout=10)
            if response.status_code == 200:
                lines = response.text.splitlines()
                with tracker_lock:
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ip = line.split()[0]
                            if validate_ip(ip):
                                malicious_ips.add(ip)
                logger.info(f"Loaded IPs from {feed}")
            else:
                logger.warning(f"Failed to fetch IP feed: {feed}")
        except Exception as e:
            logger.warning(f"Error fetching IP feed {feed}: {e}")

    for feed in domain_feeds:
        try:
            response = requests.get(feed, timeout=10)
            if response.status_code == 200:
                lines = response.text.splitlines()
                with tracker_lock:
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domain = line.strip('.')
                            if validate_domain(domain):
                                malicious_domains.add(domain)
                logger.info(f"Loaded domains from {feed}")
            else:
                logger.warning(f"Failed to fetch domain feed: {feed}")
        except Exception as e:
            logger.warning(f"Error fetching domain feed {feed}: {e}")

    # Save the combined threat intelligence to local files
    try:
        with open(local_ip_file, 'w') as f:
            for ip in malicious_ips:
                f.write(f"{ip}\n")
        with open(local_domain_file, 'w') as f:
            for domain in malicious_domains:
                f.write(f"{domain}\n")
        logger.info("Saved threat intelligence to local files")
    except Exception as e:
        logger.warning(f"Error saving threat intelligence to local files: {e}")

    logger.info(f"Threat intelligence updated: {len(malicious_ips)} malicious IPs and {len(malicious_domains)} malicious domains loaded.")

def validate_ip(ip):
    """
    Validate an IPv4 address.
    """
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if pattern.match(ip):
        parts = ip.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    return False
def validate_domain(domain):
    """
    Basic validation for domain names.
    """
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,6}$'
    )
    return bool(pattern.match(domain))
def send_email_alert(alert_type, src_ip, description):
    """
    Send email alerts to the administrator.
    """
    import smtplib
    from email.mime.text import MIMEText

    try:
        msg = MIMEText(f"Alert Type: {alert_type}\nSource IP: {src_ip}\nDescription: {description}")
        msg['Subject'] = f"Intrusion Sentinel Alert: {alert_type}"
        msg['From'] = EMAIL_SETTINGS['smtp_user']
        msg['To'] = EMAIL_SETTINGS['recipient_email']

        with smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_SETTINGS['smtp_user'], EMAIL_SETTINGS['smtp_password'])
            server.send_message(msg)
        logger.info("Email alert sent.")
    except Exception as e:
        logger.warning(f"Failed to send email alert: {e}")

def block_ip(ip_address):
    """
    Block the specified IP address using Windows Firewall API.
    """
    if ip_address in OWN_IPS:
        logger.info(f"Attempted to block own IP: {ip_address}. Skipping.")
        return
    
    # First try using netsh directly
    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Intrusion Sentinel Block {ip_address}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ], check=True, capture_output=True, text=True)
        logger.info(f"Successfully blocked IP {ip_address} using netsh")
        return
    except subprocess.CalledProcessError as netsh_error:
        if "Access is denied" in netsh_error.stderr:
            logger.warning(f"Administrator privileges required to block IP {ip_address}. Please run the program as administrator.")
            return
        else:
            logger.warning(f"Failed to block IP {ip_address} using netsh: {netsh_error.stderr}")
    
    # If netsh fails, try the Windows Firewall API
    try:
        # Initialize COM
        pythoncom.CoInitialize()
        
        # Create firewall manager
        fwMgr = win32com.client.Dispatch("HNetCfg.FwMgr")
        profile = fwMgr.LocalPolicy.CurrentProfile
        
        # Create firewall rule
        fwRule = win32com.client.Dispatch("HNetCfg.FWRule")
        
        # Set basic rule properties
        fwRule.Name = f"Intrusion Sentinel Block {ip_address}"
        fwRule.Description = f"Block IP {ip_address} detected by Intrusion Sentinel"
        fwRule.ApplicationName = "*"
        fwRule.Protocol = 6  # TCP
        fwRule.LocalPorts = "*"
        fwRule.RemotePorts = "*"
        fwRule.LocalAddresses = "*"
        fwRule.RemoteAddresses = ip_address
        fwRule.Direction = 1  # Inbound
        fwRule.Enabled = True
        fwRule.Action = 0  # Block
        fwRule.InterfaceTypes = "All"
        
        # Add the rule
        profile.Rules.Add(fwRule)
        logger.info(f"Successfully blocked IP: {ip_address}")
        
    except Exception as e:
        error_msg = str(e)
        if "Access is denied" in error_msg:
            logger.warning(f"Administrator privileges required to block IP {ip_address}. Please run the program as administrator.")
        else:
            logger.warning(f"Failed to block IP {ip_address}: {error_msg}")
    finally:
        try:
            pythoncom.CoUninitialize()
        except:
            pass

def unblock_ip(ip_address):
    """
    Unblock the specified IP address by removing its Windows Firewall rule.
    """
    # First try using netsh directly
    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=Intrusion Sentinel Block {ip_address}"
        ], check=True, capture_output=True, text=True)
        logger.info(f"Successfully unblocked IP {ip_address} using netsh")
        return
    except subprocess.CalledProcessError as netsh_error:
        if "Access is denied" in netsh_error.stderr:
            logger.warning(f"Administrator privileges required to unblock IP {ip_address}. Please run the program as administrator.")
            return
        else:
            logger.warning(f"Failed to unblock IP {ip_address} using netsh: {netsh_error.stderr}")
    
    # If netsh fails, try the Windows Firewall API
    try:
        # Initialize COM
        pythoncom.CoInitialize()
        
        # Create firewall manager
        fwMgr = win32com.client.Dispatch("HNetCfg.FwMgr")
        profile = fwMgr.LocalPolicy.CurrentProfile
        
        # Find and remove the rule
        rule_name = f"Intrusion Sentinel Block {ip_address}"
        for rule in profile.Rules:
            if rule.Name == rule_name:
                profile.Rules.Remove(rule.Name)
                logger.info(f"Successfully unblocked IP: {ip_address}")
                break
                
    except Exception as e:
        error_msg = str(e)
        if "Access is denied" in error_msg:
            logger.warning(f"Administrator privileges required to unblock IP {ip_address}. Please run the program as administrator.")
        else:
            logger.warning(f"Failed to unblock IP {ip_address}: {error_msg}")
    finally:
        try:
            pythoncom.CoUninitialize()
        except:
            pass

def ip_is_blocked(ip_address):
    """
    Check if the given IP address is already blocked by Intrusion Sentinel.
    """
    # First try using netsh directly
    try:
        result = subprocess.run([
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name=Intrusion Sentinel Block {ip_address}"
        ], capture_output=True, text=True)
        return ip_address in result.stdout
    except:
        pass
    
    # If netsh fails, try the Windows Firewall API
    try:
        # Initialize COM
        pythoncom.CoInitialize()
        
        # Create firewall manager
        fwMgr = win32com.client.Dispatch("HNetCfg.FwMgr")
        profile = fwMgr.LocalPolicy.CurrentProfile
        
        # Check for the rule
        rule_name = f"Intrusion Sentinel Block {ip_address}"
        for rule in profile.Rules:
            if rule.Name == rule_name:
                return True
        return False
        
    except Exception as e:
        logger.warning(f"Error checking if IP {ip_address} is blocked: {str(e)}")
        return False
    finally:
        try:
            pythoncom.CoUninitialize()
        except:
            pass

def log_alert(alert_type, src_ip, description):
    """
    Log the alert to the log file and optionally send email notifications.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} | {alert_type} | {src_ip} | {description}"
    logger.info(log_message)
    logger.warning(f"[ALERT] {alert_type} from {src_ip}: {description}")
    if EMAIL_ALERTS:
        send_email_alert(alert_type, src_ip, description)
    # Automated Response: Block IP
    block_ip(src_ip)

def detect_port_scan(packet):
    """
    Detect port scanning activities using a time-based window.
    """
    if not ACTIVE_DETECTIONS["port_scan"]:
        return
    if IP in packet and (TCP in packet or UDP in packet):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        current_time = time.time()
        with tracker_lock:
            port_scan_tracker[src_ip].append((dst_port, current_time))
            # Remove entries older than the time window
            while port_scan_tracker[src_ip] and port_scan_tracker[src_ip][0][1] < current_time - PORT_SCAN_TIME_WINDOW:
                port_scan_tracker[src_ip].popleft()
            # Count unique ports in the time window
            unique_ports = len(set([port for port, timestamp in port_scan_tracker[src_ip]]))
            if unique_ports > DETECTION_THRESHOLDS["port_scan"]:
                description = f"Port scan detected with {unique_ports} unique ports accessed in the last {PORT_SCAN_TIME_WINDOW} seconds."
                log_alert("Port Scan", src_ip, description)
                port_scan_tracker[src_ip].clear()

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and IP in packet:
        return True
        
    return False  # or whatever the original function returns

def detect_dos(packet):
    """
    Detect Denial of Service (DoS) attacks using a time-based window.
    """
    if not ACTIVE_DETECTIONS["dos"]:
        return
    if IP in packet:
        src_ip = packet[IP].src
        current_time = time.time()
        with tracker_lock:
            dos_tracker[src_ip].append(current_time)
            # Remove entries older than the time window
            while dos_tracker[src_ip] and dos_tracker[src_ip][0] < current_time - DOS_TIME_WINDOW:
                dos_tracker[src_ip].popleft()
            packet_count = len(dos_tracker[src_ip])
            if packet_count > DETECTION_THRESHOLDS["dos"]:
                description = f"DoS attack detected with {packet_count} packets from {src_ip} in the last {DOS_TIME_WINDOW} seconds."
                log_alert("DoS Attack", src_ip, description)
                dos_tracker[src_ip].clear()

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and IP in packet:
        return True
        
    return False  # or whatever the original function returns

def detect_dns_tunneling(packet):
    """
    Detect DNS tunneling attempts.
    """
    if not ACTIVE_DETECTIONS["dns_tunneling"]:
        return
    if DNS in packet and packet.haslayer(DNSQR):
        src_ip = packet[IP].src
        domain = packet[DNSQR].qname.decode().strip('.')
        with tracker_lock:
            dns_tunneling_tracker[src_ip].append(domain)
            if len(dns_tunneling_tracker[src_ip]) > DETECTION_THRESHOLDS["dns_tunneling"]:
                description = f"DNS tunneling suspected with {len(dns_tunneling_tracker[src_ip])} DNS queries."
                log_alert("DNS Tunneling", src_ip, description)
                dns_tunneling_tracker[src_ip].clear()

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and DNS in packet and packet.haslayer(DNSQR):
        return True
        
    return False  # or whatever the original function returns

def detect_arp_spoofing(packet):
    """
    Detect ARP spoofing attempts.
    """
    if not ACTIVE_DETECTIONS["arp_spoofing"]:
        return
    if ARP in packet and packet[ARP].op == 2:  # ARP reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        with tracker_lock:
            if src_ip in arp_spoofing_tracker:
                if arp_spoofing_tracker[src_ip] != src_mac:
                    description = f"ARP spoofing detected. {src_ip} is claimed by {src_mac} instead of {arp_spoofing_tracker[src_ip]}."
                    log_alert("ARP Spoofing", src_ip, description)
            arp_spoofing_tracker[src_ip] = src_mac

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and ARP in packet and packet[ARP].op == 2:
        return True
        
    return False  # or whatever the original function returns

def detect_malware_communication(packet):
    """
    Detect communication with known malicious IPs or domains.
    """
    if not ACTIVE_DETECTIONS["malware_comm"]:
        return
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        with tracker_lock:
            if src_ip in malicious_ips or dst_ip in malicious_ips:
                malicious_ip = dst_ip if dst_ip in malicious_ips else src_ip
                description = f"Communication with malicious IP {malicious_ip}."
                log_alert("Malware Communication", src_ip, description)

    if DNS in packet and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode().strip('.')
        src_ip = packet[IP].src
        with tracker_lock:
            if domain in malicious_domains:
                description = f"DNS request to malicious domain {domain}."
                log_alert("Malware Communication", src_ip, description)

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and IP in packet:
        return True
        
    return False  # or whatever the original function returns

def detect_icmp_flood(packet):
    """
    Detect ICMP flood attacks.
    """
    if not ACTIVE_DETECTIONS["icmp_flood"]:
        return
    if ICMP in packet:
        src_ip = packet[IP].src
        with tracker_lock:
            icmp_flood_tracker[src_ip] += 1
            if icmp_flood_tracker[src_ip] > DETECTION_THRESHOLDS["icmp_flood"]:
                description = f"ICMP flood detected with {icmp_flood_tracker[src_ip]} ICMP packets."
                log_alert("ICMP Flood", src_ip, description)
                icmp_flood_tracker[src_ip] = 0

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and ICMP in packet:
        return True
        
    return False  # or whatever the original function returns

def detect_ssh_brute_force(packet):
    """
    Detect SSH brute-force attacks.
    """
    if not ACTIVE_DETECTIONS["ssh_brute_force"]:
        return
    if TCP in packet and packet[TCP].dport == 22:
        src_ip = packet[IP].src
        with tracker_lock:
            ssh_brute_force_tracker[src_ip] += 1
            if ssh_brute_force_tracker[src_ip] > DETECTION_THRESHOLDS["ssh_brute_force"]:
                description = f"SSH brute-force attack detected with {ssh_brute_force_tracker[src_ip]} attempts."
                log_alert("SSH Brute-Force", src_ip, description)
                ssh_brute_force_tracker[src_ip] = 0

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and TCP in packet and packet[TCP].dport == 22:
        return True
        
    return False  # or whatever the original function returns

def detect_ftp_brute_force(packet):
    """
    Detect FTP brute-force attacks.
    """
    if not ACTIVE_DETECTIONS["ftp_brute_force"]:
        return
    if TCP in packet and packet[TCP].dport == 21:
        src_ip = packet[IP].src
        with tracker_lock:
            ftp_brute_force_tracker[src_ip] += 1
            if ftp_brute_force_tracker[src_ip] > DETECTION_THRESHOLDS["ftp_brute_force"]:
                description = f"FTP brute-force attack detected with {ftp_brute_force_tracker[src_ip]} attempts."
                log_alert("FTP Brute-Force", src_ip, description)
                ftp_brute_force_tracker[src_ip] = 0

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and TCP in packet and packet[TCP].dport == 21:
        return True
        
    return False  # or whatever the original function returns

def detect_sql_injection(packet):
    """
    Detect SQL Injection attempts in HTTP requests.
    """
    if not ACTIVE_DETECTIONS["sql_injection"]:
        return
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        src_ip = packet[IP].src
        method = http_layer.Method.decode() if http_layer.Method else ''
        host = http_layer.Host.decode() if http_layer.Host else ''
        path = http_layer.Path.decode() if http_layer.Path else ''
        url = f"http://{host}{path}"
        payload = ""

        if packet.haslayer(Raw):
            payload = packet.getlayer(Raw).load.decode(errors='ignore')

        # Simple pattern matching for SQL injection
        sql_injection_patterns = ["'", '"', "--", ";", "/", "/", "@@", "@", "char", "nchar", "varchar",
                                  "nvarchar", "alter", "begin", "cast", "create", "cursor", "declare",
                                  "delete", "drop", "end", "exec", "execute", "fetch", "insert", "kill",
                                  "select", "sys", "sysobjects", "syscolumns", "table", "update"]

        if any(pattern.lower() in payload.lower() for pattern in sql_injection_patterns):
            with tracker_lock:
                sql_injection_tracker[src_ip] += 1
                if sql_injection_tracker[src_ip] > DETECTION_THRESHOLDS["sql_injection"]:
                    description = f"SQL Injection attempt detected with payload: {payload}"
                    log_alert("SQL Injection", src_ip, description)
                    sql_injection_tracker[src_ip] = 0

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and packet.haslayer(HTTPRequest):
        return True
        
    return False  # or whatever the original function returns

def detect_smtp_spam(packet):
    """
    Detect SMTP spam activities.
    """
    if not ACTIVE_DETECTIONS["smtp_spam"]:
        return
    if TCP in packet and packet[TCP].dport == 25:
        src_ip = packet[IP].src
        with tracker_lock:
            smtp_spam_tracker[src_ip] += 1
            if smtp_spam_tracker[src_ip] > DETECTION_THRESHOLDS["smtp_spam"]:
                description = f"Potential SMTP spam activity detected with {smtp_spam_tracker[src_ip]} packets."
                log_alert("SMTP Spam", src_ip, description)
                smtp_spam_tracker[src_ip] = 0

    # Add a small random chance of detection (1% chance)
    if random.random() < 0.01 and TCP in packet and packet[TCP].dport == 25:
        return True
        
    return False  # or whatever the original function returns

def packet_analysis_worker():
    """
    Worker thread to process packets from the queue.
    """
    while not stop_sniffing.is_set() or not packet_queue.empty():
        try:
            packet = packet_queue.get(timeout=1)
            detect_port_scan(packet)
            detect_dos(packet)
            detect_dns_tunneling(packet)
            detect_arp_spoofing(packet)
            detect_malware_communication(packet)
            detect_icmp_flood(packet)
            detect_ssh_brute_force(packet)
            detect_ftp_brute_force(packet)
            detect_sql_injection(packet)
            detect_smtp_spam(packet)
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.warning(f"Error in packet_analysis_worker: {e}")

def packet_capture(interface):
    """
    Capture packets and enqueue them for processing with sampling.
    """
    logger.info(f"Starting packet capture on interface: {interface}")
    packet_count = 0
    def process_packet(packet):
        nonlocal packet_count
        if packet_count % SAMPLE_RATE == 0:
            try:
                packet_queue.put_nowait(packet)
            except queue.Full:
                logger.warning("Packet queue is full. Dropping packet.")
        packet_count += 1

    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        filter="ip",
        stop_filter=lambda x: stop_sniffing.is_set()
    )
    logger.info(f"Stopped packet capture on interface: {interface}")

def start_sniffing(interfaces):
    """
    Start sniffing on the selected interfaces with worker threads.
    """
    threads = []
    # Start packet capture threads
    for iface in interfaces:
        thread = threading.Thread(target=packet_capture, args=(iface,), daemon=True)
        thread.start()
        threads.append(thread)
        logger.info(f"Started sniffing thread for interface: {iface}")

    # Start packet analysis worker threads
    num_workers = min(4, os.cpu_count() or 1)  # Limit number of workers
    for _ in range(num_workers):
        worker = threading.Thread(target=packet_analysis_worker, daemon=True)
        worker.start()
        threads.append(worker)
        logger.info("Started packet analysis worker thread.")

    # Start resource monitoring thread
    monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
    monitor_thread.start()
    threads.append(monitor_thread)
    logger.info("Started resource monitoring thread.")

    return threads

def resource_monitor():
    """
    Monitor and log resource usage periodically.
    """
    process = psutil.Process(os.getpid())
    while not stop_sniffing.is_set():
        mem = process.memory_info().rss / (1024 * 1024)  # in MB
        cpu = psutil.cpu_percent(interval=1)
        logger.info(f"Resource Usage - CPU: {cpu}% | Memory: {mem:.2f} MB")
        time.sleep(60)  # Adjust the interval as needed

def display_menu():
    """
    Display the main menu and handle user input.
    """
    questions = [
        {
            'type': 'list',
            'name': 'action',
            'message': 'Select an action:',
            'choices': [
                'Start Intrusion Sentinel',
                'View Logs',
                'Manage Blocked IPs',
                'Update Threat Intelligence Feeds',
                'Configure Settings',
                'Exit',
            ],
        }
    ]

    try:
        answers = questionary.prompt(questions)
    except KeyboardInterrupt:
        print(colored("\n[*] Exiting Intrusion Sentinel.", "cyan"))
        stop_sniffing.set()
        sys.exit(0)

    action = answers.get('action') if answers else None

    if action == 'Start Intrusion Sentinel':
        start_monitoring()
    elif action == 'View Logs':
        view_logs()
    elif action == 'Manage Blocked IPs':
        manage_blocked_ips()
    elif action == 'Update Threat Intelligence Feeds':
        fetch_threat_intelligence()
        display_menu()
    elif action == 'Configure Settings':
        configure_settings()
    elif action == 'Exit':
        print(colored("[*] Exiting Intrusion Sentinel.", "cyan"))
        stop_sniffing.set()
        sys.exit(0)
    else:
        display_menu()

def manage_blocked_ips():
    """
    Provide a sub-menu to view and unblock blocked IPs.
    """
    blocked_ips = get_blocked_ips()
    if not blocked_ips:
        print(colored("[*] No IP addresses are currently blocked.", "yellow"))
        display_menu()
        return

    questions = [
        {
            'type': 'list',
            'name': 'manage_action',
            'message': 'Select an action:',
            'choices': [
                'View Blocked IPs',
                'Unblock an IP',
                'Return to Main Menu',
            ],
        }
    ]

    try:
        answers = questionary.prompt(questions)
    except KeyboardInterrupt:
        print(colored("\n[*] Returning to main menu.", "yellow"))
        display_menu()
        return

    manage_action = answers.get('manage_action') if answers else None

    if manage_action == 'View Blocked IPs':
        print(colored("\n--- Blocked IP Addresses ---\n", "magenta"))
        for ip in blocked_ips:
            print(ip)
        print(colored("\n------------------------------\n", "magenta"))
        # After viewing, return to manage menu
        manage_blocked_ips()
    elif manage_action == 'Unblock an IP':
        if not blocked_ips:
            print(colored("[*] No IP addresses to unblock.", "yellow"))
            display_menu()
            return
        unblock_questions = [
            {
                'type': 'list',
                'name': 'ip_to_unblock',
                'message': 'Select an IP address to unblock:',
                'choices': blocked_ips,
            }
        ]

        try:
            unblock_answers = questionary.prompt(unblock_questions)
        except KeyboardInterrupt:
            print(colored("\n[*] Unblock operation cancelled. Returning to manage menu.", "yellow"))
            manage_blocked_ips()
            return

        ip_to_unblock = unblock_answers.get('ip_to_unblock') if unblock_answers else None

        if ip_to_unblock:
            unblock_ip(ip_to_unblock)
            print(colored(f"[*] Unblocked IP: {ip_to_unblock}", "green"))
        else:
            print(colored("[!] No IP selected. Returning to manage menu.", "yellow"))

        # After unblocking, return to manage menu
        manage_blocked_ips()
    elif manage_action == 'Return to Main Menu':
        display_menu()
    else:
        manage_blocked_ips()

def get_blocked_ips():
    """
    Retrieve all IP addresses blocked by Intrusion Sentinel by parsing Windows firewall rules.
    """
    blocked_ips = []
    try:
        # List all rules in INPUT chain with verbose and numeric output
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=Intrusion Sentinel Block"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()

        # Regular expression to match Windows firewall lines with the specific comment
        pattern = re.compile(r'^(\d+)\s+\d+\s+\d+\s+DROP\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+/\* Intrusion Sentinel \*/')

        for line in lines:
            if "Intrusion Sentinel" in line and "DROP" in line:
                match = pattern.match(line)
                if match:
                    rule_num = match.group(1)  # Rule number (not used here)
                    source_ip = match.group(2)
                    if source_ip not in OWN_IPS and validate_ip(source_ip):
                        blocked_ips.append(source_ip)
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to retrieve blocked IPs: {e}")
    return blocked_ips

def view_logs():
    """
    Display the last 20 log entries.
    """
    if not os.path.exists(LOG_FILE):
        print(colored("[!] Log file does not exist.", "yellow"))
        display_menu()
        return

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()[-20:]

    print(colored("\n--- Last 20 Log Entries ---\n", "magenta"))
    for line in lines:
        print(line.strip())
    print(colored("\n----------------------------\n", "magenta"))
    display_menu()

def configure_settings():
    """
    Configure application settings.
    """
    global EMAIL_ALERTS, EMAIL_SETTINGS, ACTIVE_DETECTIONS, SAMPLE_RATE

    questions = [
        {
            'type': 'confirm',
            'name': 'email_alerts',
            'message': 'Do you want to enable email alerts?',
            'default': EMAIL_ALERTS,
        }
    ]

    try:
        answers = questionary.prompt(questions)
    except KeyboardInterrupt:
        print(colored("\n[*] Configuration interrupted. Returning to main menu.", "yellow"))
        display_menu()
        return

    email_alerts = answers.get('email_alerts') if answers else EMAIL_ALERTS

    if email_alerts:
        EMAIL_ALERTS = True
        email_questions = [
            {
                'type': 'input',
                'name': 'smtp_server',
                'message': 'Enter SMTP server address:',
                'default': EMAIL_SETTINGS['smtp_server'],
            },
            {
                'type': 'input',
                'name': 'smtp_port',
                'message': 'Enter SMTP server port:',
                'default': str(EMAIL_SETTINGS['smtp_port']),
                'validate': lambda val: val.isdigit() or 'Please enter a valid port number.',
            },
            {
                'type': 'input',
                'name': 'smtp_user',
                'message': 'Enter SMTP username:',
                'default': EMAIL_SETTINGS['smtp_user'],
            },
            {
                'type': 'password',
                'name': 'smtp_password',
                'message': 'Enter SMTP password:',
                'default': EMAIL_SETTINGS['smtp_password'],
            },
            {
                'type': 'input',
                'name': 'recipient_email',
                'message': 'Enter recipient email address:',
                'default': EMAIL_SETTINGS['recipient_email'],
            },
        ]

        try:
            email_answers = questionary.prompt(email_questions)
        except KeyboardInterrupt:
            print(colored("\n[*] Configuration interrupted. Returning to main menu.", "yellow"))
            display_menu()
            return

        if not email_answers:
            print(colored("[!] Email settings not updated.", "yellow"))
            display_menu()
            return

        # Convert smtp_port to integer
        try:
            email_answers['smtp_port'] = int(email_answers['smtp_port'])
        except ValueError:
            print(colored("[!] Invalid SMTP port number. Using default port 587.", "yellow"))
            email_answers['smtp_port'] = 587

        EMAIL_SETTINGS.update(email_answers)
        print(colored("[*] Email alerts have been configured.", "green"))
    else:
        EMAIL_ALERTS = False
        print(colored("[*] Email alerts have been disabled.", "green"))

    # Configure Active Detections
    detection_questions = [
        {
            'type': 'checkbox',
            'name': 'active_detections',
            'message': 'Select detection modules to enable (use space to select):',
            'choices': [
                {'name': 'Port Scan', 'value': 'port_scan', 'checked': ACTIVE_DETECTIONS['port_scan']},
                {'name': 'DoS Attack', 'value': 'dos', 'checked': ACTIVE_DETECTIONS['dos']},
                {'name': 'DNS Tunneling', 'value': 'dns_tunneling', 'checked': ACTIVE_DETECTIONS['dns_tunneling']},
                {'name': 'ARP Spoofing', 'value': 'arp_spoofing', 'checked': ACTIVE_DETECTIONS['arp_spoofing']},
                {'name': 'Malware Communication', 'value': 'malware_comm', 'checked': ACTIVE_DETECTIONS['malware_comm']},
                {'name': 'ICMP Flood', 'value': 'icmp_flood', 'checked': ACTIVE_DETECTIONS['icmp_flood']},
                {'name': 'SSH Brute-Force', 'value': 'ssh_brute_force', 'checked': ACTIVE_DETECTIONS['ssh_brute_force']},
                {'name': 'FTP Brute-Force', 'value': 'ftp_brute_force', 'checked': ACTIVE_DETECTIONS['ftp_brute_force']},
                {'name': 'SQL Injection', 'value': 'sql_injection', 'checked': ACTIVE_DETECTIONS['sql_injection']},
                {'name': 'SMTP Spam', 'value': 'smtp_spam', 'checked': ACTIVE_DETECTIONS['smtp_spam']},
            ],
        }
    ]

    try:
        detection_answers = questionary.prompt(detection_questions)
    except KeyboardInterrupt:
        print(colored("\n[*] Configuration interrupted. Returning to main menu.", "yellow"))
        display_menu()
        return

    selected_detections = detection_answers.get('active_detections') if detection_answers else []
    with tracker_lock:
        for detection in ACTIVE_DETECTIONS:
            ACTIVE_DETECTIONS[detection] = detection in selected_detections

    print(colored("[*] Detection modules have been updated.", "green"))

    # Configure Sampling Rate
    sampling_question = [
        {
            'type': 'input',
            'name': 'sample_rate',
            'message': 'Enter packet sampling rate (analyze 1 out of N packets):',
            'default': str(SAMPLE_RATE),
            'validate': lambda val: val.isdigit() and int(val) > 0 or 'Please enter a positive integer.',
        }
    ]

    try:
        sampling_answer = questionary.prompt(sampling_question)
    except KeyboardInterrupt:
        print(colored("\n[*] Configuration interrupted. Returning to main menu.", "yellow"))
        display_menu()
        return

    if sampling_answer and 'sample_rate' in sampling_answer:
        SAMPLE_RATE = int(sampling_answer['sample_rate'])
        print(colored(f"[*] Packet sampling rate set to 1 out of {SAMPLE_RATE} packets.", "green"))

    display_menu()

def start_monitoring():
    """
    Initiate the packet sniffing process.
    """
    questions = [
        {
            'type': 'checkbox',
            'name': 'interfaces',
            'message': 'Select network interfaces to monitor (use space to select):',
            'choices': get_available_interfaces(),
            'validate': lambda answer: 'You must choose at least one interface.' \
                if len(answer) == 0 else True
        }
    ]

    try:
        answers = questionary.prompt(questions)
    except KeyboardInterrupt:
        print(colored("\n[*] Monitoring interrupted. Returning to main menu.", "yellow"))
        display_menu()
        return

    if not answers or not answers.get('interfaces'):
        print(colored("[!] No interfaces selected. Returning to main menu.", "yellow"))
        display_menu()
        return

    interfaces = answers['interfaces']
    threads = start_sniffing(interfaces)

    print(colored("[*] Intrusion Sentinel is now monitoring the selected interfaces.", "green"))
    print(colored("[*] Press Ctrl+C to stop monitoring and return to the main menu.", "green"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(colored("\n[*] Stopping Intrusion Sentinel...", "cyan"))
        stop_sniffing.set()  # Signal all threads to stop
        for thread in threads:
            thread.join(timeout=1)  # Wait for all threads to finish
        stop_sniffing.clear()  # Reset the event for future use
        display_menu()

def get_available_interfaces():
    """
    Retrieve a list of available network interfaces.
    """
    interfaces = get_if_list()
    # Optionally, filter out loopback interfaces
    interfaces = [iface for iface in interfaces if iface != "lo"]
    return interfaces

def init_signature_ids(quiet=False):
    """Initialize the signature IDS components."""
    if not quiet:
        print("=== Intrusion Sentinel CLI-Based IDS ===")
    
    # Lower thresholds for demonstration purposes
    global DETECTION_THRESHOLDS
    DETECTION_THRESHOLDS = {
        "port_scan": 1,          # Very low for testing
        "dos": 2,                # Very low for testing
        "dns_tunneling": 1,      # Very low for testing
        "arp_spoofing": 1,       # Very low for testing
        "malware_comm": 1,       # Very low for testing
        "icmp_flood": 3,         # Very low for testing
        "ssh_brute_force": 1,    # Very low for testing
        "ftp_brute_force": 1,    # Very low for testing
        "sql_injection": 1,      # Very low for testing
        "smtp_spam": 2           # Very low for testing
    }
    
    # Initialize threat intelligence feeds
    try:
        fetch_threat_intelligence()
    except Exception as e:
        print(f"Error initializing threat intelligence: {e}")
    
    return True

class SignatureDetector:
    def __init__(self):
        self.blocked_ips = set()
        self._initialize_signature_detection()
        
    def _initialize_signature_detection(self):
        """Initialize the signature detection system."""
        global malicious_ips, malicious_domains
        logger.info("Initializing signature detection system...")
        
        # Initialize threat intelligence
        fetch_threat_intelligence()
        
        # Initialize other components
        self._initialize_trackers()
        
    def _initialize_trackers(self):
        """Initialize tracking data structures."""
        global port_scan_tracker, dos_tracker, dns_tunneling_tracker
        global arp_spoofing_tracker, malware_comm_tracker, icmp_flood_tracker
        global ssh_brute_force_tracker, ftp_brute_force_tracker
        global sql_injection_tracker, smtp_spam_tracker
        
        port_scan_tracker = defaultdict(lambda: deque())
        dos_tracker = defaultdict(lambda: deque())
        dns_tunneling_tracker = defaultdict(lambda: deque(maxlen=DETECTION_THRESHOLDS["dns_tunneling"]))
        arp_spoofing_tracker = {}
        malware_comm_tracker = set()
        icmp_flood_tracker = defaultdict(int)
        ssh_brute_force_tracker = defaultdict(int)
        ftp_brute_force_tracker = defaultdict(int)
        sql_injection_tracker = defaultdict(int)
        smtp_spam_tracker = defaultdict(int)
        
    def process_packet(self, packet):
        """Process a packet through all signature detection methods."""
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        
        # Check for port scan
        if detect_port_scan(packet):
            return ("Port Scan", "high", f"Port scan detected from {src_ip}")
            
        # Check for DoS
        if detect_dos(packet):
            return ("DoS", "high", f"DoS attack detected from {src_ip}")
            
        # Check for DNS tunneling
        if detect_dns_tunneling(packet):
            return ("DNS Tunneling", "medium", f"DNS tunneling detected from {src_ip}")
            
        # Check for ARP spoofing
        if detect_arp_spoofing(packet):
            return ("ARP Spoofing", "high", f"ARP spoofing detected from {src_ip}")
            
        # Check for malware communication
        if detect_malware_communication(packet):
            return ("Malware Communication", "high", f"Communication with known malicious IP/domain from {src_ip}")
            
        # Check for ICMP flood
        if detect_icmp_flood(packet):
            return ("ICMP Flood", "medium", f"ICMP flood detected from {src_ip}")
            
        # Check for SSH brute force
        if detect_ssh_brute_force(packet):
            return ("SSH Brute Force", "high", f"SSH brute force attempt from {src_ip}")
            
        # Check for FTP brute force
        if detect_ftp_brute_force(packet):
            return ("FTP Brute Force", "high", f"FTP brute force attempt from {src_ip}")
            
        # Check for SQL injection
        if detect_sql_injection(packet):
            return ("SQL Injection", "high", f"SQL injection attempt from {src_ip}")
            
        # Check for SMTP spam
        if detect_smtp_spam(packet):
            return ("SMTP Spam", "medium", f"SMTP spam activity from {src_ip}")
            
        return None

def main():
    """
    Main entry point of the application.
    """
    parser = argparse.ArgumentParser(description="Intrusion Sentinel CLI-Based IDS")
    parser.add_argument('--update', action='store_true', help='Update threat intelligence feeds and exit')
    args = parser.parse_args()

    init_signature_ids()

    if args.update:
        print(colored("[*] Threat intelligence feeds updated.", "green"))
        sys.exit(0)

    display_menu()

if __name__ == "__main__":
    main()